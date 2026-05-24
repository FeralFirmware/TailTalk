use dashmap::DashMap;
use im::hashmap::HashMap;
use rand::Rng;
use std::sync::Arc;
use std::{io::Error, time::Duration};
use tailtalk_packets::aarp::*;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{DataLinkPacket, DataLinkProtocol, OutboundHandle};

#[derive(Debug, Copy, Clone)]
pub enum Node {
    EtherTalkPhase1(EthernetMac),
    EtherTalkPhase2(EthernetMac),
    LocalTalk(u8), // Node number
}

struct AarpRequest {
    addr: AppleTalkAddress,
    chan: oneshot::Sender<Result<Node, Error>>,
}

struct SelfAddress {
    chan: oneshot::Sender<AppleTalkAddress>,
}

enum AarpCommand {
    Lookup(AarpRequest),
    OurAddr(SelfAddress),
}

pub struct Addressing {
    packet_recv: mpsc::Receiver<(AarpPacket, AddressSource)>,
    request_recv: mpsc::Receiver<AarpCommand>,
    lt_ack_recv: mpsc::Receiver<u8>,
    lt_enq_recv: mpsc::Receiver<u8>,
    pending: HashMap<AppleTalkAddress, Vec<Arc<AarpRequest>>>,
    cache: Arc<DashMap<AppleTalkAddress, Node>>,
    outbound: OutboundHandle,
    our_mac: Option<EthernetMac>,
    cancel: CancellationToken,
}

impl Addressing {
    const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

    /// Spawn the addressing actor.
    ///
    /// If `fixed_addr` is `Some(addr)`, that AppleTalk address is used immediately
    /// without any AARP probe — useful when the caller wants a specific node number.
    /// If `None`, a random node in network 1 is chosen and confirmed via AARP probe.
    pub fn spawn(
        our_mac: Option<EthernetMac>,
        outbound: OutboundHandle,
        fixed_addr: Option<AppleTalkAddress>,
    ) -> AddressingHandle {
        let (request_send, request_recv) = mpsc::channel(100);
        let (packet_send, packet_recv) = mpsc::channel(100);
        let (lt_ack_send, lt_ack_recv) = mpsc::channel(16);
        let (lt_enq_send, lt_enq_recv) = mpsc::channel(16);
        let cache = Arc::new(DashMap::new());
        let token = CancellationToken::new();
        let handle_token = token.clone();

        let us = Self {
            pending: HashMap::new(),
            cache: cache.clone(),
            cancel: token,
            request_recv,
            packet_recv,
            lt_ack_recv,
            lt_enq_recv,
            our_mac,
            outbound,
        };

        tokio::spawn(async move { us.run(fixed_addr).await });

        AddressingHandle {
            _cancel: Arc::new(handle_token.drop_guard()),
            request_send,
            packet_send,
            lt_ack_send,
            lt_enq_send,
            cache,
        }
    }

    fn create_packet(
        &self,
        target: AppleTalkAddress,
        target_mac: EthernetMac,
        our_addr: AppleTalkAddress,
        opcode: AarpOpcode,
        source_type: AddressSource,
    ) -> DataLinkPacket {
        let our_mac = self.our_mac.expect("AARP requires an Ethernet MAC");
        let aarp_header = AarpPacket {
            hardware_type: 1,      // Ethernet
            protocol_type: 0x809b, // AppleTalk
            hardware_size: 6,
            protocol_size: 4,
            opcode,
            sender_addr: our_mac,
            sender_protocol: our_addr,
            target_addr: target_mac,
            target_protocol: target,
        };
        let mut payload = [0u8; AarpPacket::LEN];
        aarp_header.to_bytes(&mut payload);

        let dest_node = match source_type {
            AddressSource::EtherTalkPhase2 => Node::EtherTalkPhase2(target_mac),
            AddressSource::EtherTalkPhase1 => Node::EtherTalkPhase1(target_mac),
            AddressSource::LocalTalk => unimplemented!("AARP not used on LocalTalk"),
        };

        DataLinkPacket {
            dest_node,
            protocol: DataLinkProtocol::Aarp,
            payload: payload.into(),
            src_node_id: 0, // AARP is never sent to LocalTalk destinations
        }
    }

    async fn run(mut self, fixed_addr: Option<AppleTalkAddress>) {
        let our_addr = if self.our_mac.is_none() {
            // LocalTalk: probe via LLAP ENQ. Send ENQ with dst=tentative, src=tentative;
            // if any node ACKs within 10 ms the address is taken — pick a new one and retry.
            let mut node_num = fixed_addr
                .map(|a| a.node_number)
                .unwrap_or_else(|| rand::rng().random_range(1..=253));

            'enq: loop {
                tracing::info!("LocalTalk: probing node {node_num}");

                let enq = DataLinkPacket {
                    dest_node: Node::LocalTalk(node_num),
                    protocol: DataLinkProtocol::LlapEnq,
                    payload: Box::new([]),
                    src_node_id: node_num,
                };
                self.outbound.send(enq).await.expect("failed to dispatch LLAP ENQ");

                let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => {
                            tracing::info!("LocalTalk: node {node_num} confirmed");
                            break 'enq AppleTalkAddress { network_number: 0, node_number: node_num };
                        }
                        ack = self.lt_ack_recv.recv() => {
                            if matches!(ack, Some(src) if src == node_num) {
                                tracing::warn!("LocalTalk: node {node_num} in use, retrying");
                                node_num = rand::rng().random_range(1..=253);
                                continue 'enq;
                            }
                        }
                        _ = self.cancel.cancelled() => return,
                    }
                }
            }
        } else if let Some(addr) = fixed_addr {
            tracing::info!(
                "addressing: Using fixed address {}.{}",
                addr.network_number,
                addr.node_number
            );
            addr
        } else {
            // EtherTalk: probe via AARP. Retry with a new random address on conflict.
            'probe: loop {
                let node_num = rand::rng().random_range(1..=254);
                let addr = AppleTalkAddress {
                    network_number: 1,
                    node_number: node_num,
                };

                tracing::info!("addressing: Selecting 1.{node_num} as our address");

                let probe = self.create_packet(
                    addr,
                    Self::BROADCAST_MAC,
                    addr,
                    AarpOpcode::Probe,
                    AddressSource::EtherTalkPhase2,
                );
                self.outbound
                    .send(probe)
                    .await
                    .expect("failed to dispatch probe packet");

                let probe_deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(probe_deadline) => {
                            tracing::info!("No response, address 1.{node_num} confirmed");
                            break 'probe addr;
                        }
                        pkt = self.packet_recv.recv() => {
                            if let Some((pkt, _source)) = pkt
                                && pkt.opcode == AarpOpcode::Probe && pkt.target_protocol == addr {
                                    tracing::warn!("Address conflict for 1.{node_num}, re-selecting");
                                    continue 'probe;
                                }
                        }
                    }
                }
            }
        };

        // Main event loop — address is now settled.
        loop {
            tokio::select! {
                pkt = self.packet_recv.recv() => {
                    if let Some((pkt, source)) = pkt {
                        match pkt.opcode {
                            AarpOpcode::Request => {
                                if pkt.target_protocol.node_number == our_addr.node_number {
                                    self.send_response(pkt, our_addr, source).await;
                                }
                            },
                            AarpOpcode::Response => {
                                if let Some(reqs) = self.pending.remove(&pkt.sender_protocol) {
                                    for req in reqs {
                                        let inner_req = Arc::<AarpRequest>::into_inner(req).unwrap();

                                        let node = match source {
                                            AddressSource::EtherTalkPhase2 => {
                                                Node::EtherTalkPhase2(pkt.sender_addr)
                                            },
                                            AddressSource::EtherTalkPhase1 => {
                                                Node::EtherTalkPhase1(pkt.sender_addr)
                                            }
                                            AddressSource::LocalTalk => {
                                                continue;
                                            },
                                        };

                                        if let Err(e) = inner_req.chan.send(Ok(node)) {
                                            tracing::error!("error responding to AarpRequest: {e:?}");
                                        }
                                        self.cache.insert(pkt.sender_protocol, node);
                                    }
                                }
                            },
                            AarpOpcode::Probe => {
                                if pkt.target_protocol == our_addr {
                                    self.send_response(pkt, our_addr, source).await;
                                    tracing::info!("send response to probe that matched our addr");
                                }
                            },
                        }
                    }
                }
                req = self.request_recv.recv() => {
                    if let Some(command) = req {
                        match command {
                            AarpCommand::Lookup(lookup) => {
                                let packet = self.create_packet(lookup.addr, Self::BROADCAST_MAC, our_addr, AarpOpcode::Request, AddressSource::EtherTalkPhase2);
                                self.outbound.send(packet).await.expect("failed to dispatch request");
                                self.pending.entry(lookup.addr).or_default().push(Arc::new(lookup));
                            },
                            AarpCommand::OurAddr(req) => {
                                req.chan.send(our_addr).expect("failed to send our_addr");
                            },
                        }
                    }
                }
                enq_node = self.lt_enq_recv.recv() => {
                    if let Some(node) = enq_node
                        && node == our_addr.node_number
                    {
                        tracing::debug!("LocalTalk: sending ACK for ENQ on node {node}");
                        let ack = DataLinkPacket {
                            dest_node: Node::LocalTalk(node),
                            protocol: DataLinkProtocol::LlapAck,
                            payload: Box::new([]),
                            src_node_id: our_addr.node_number,
                        };
                        let _ = self.outbound.send(ack).await;
                    }
                }
                _ = self.cancel.cancelled() => {
                    break;
                }
            }
        }
    }

    async fn send_response(
        &self,
        pkt: AarpPacket,
        our_addr: AppleTalkAddress,
        source_type: AddressSource,
    ) {
        let target_mac = pkt.sender_addr;
        // Response: we are the sender, requester is the target
        let packet = self.create_packet(
            pkt.sender_protocol, // Target AppleTalk address (requester)
            target_mac,          // Target MAC (requester)
            our_addr,            // Our AppleTalk address (sender)
            AarpOpcode::Response,
            source_type,
        );
        self.outbound
            .send(packet)
            .await
            .expect("failed to dispatch response");
    }
}

#[derive(Clone)]
pub struct AddressingHandle {
    request_send: mpsc::Sender<AarpCommand>,
    packet_send: mpsc::Sender<(AarpPacket, AddressSource)>,
    lt_ack_send: mpsc::Sender<u8>,
    lt_enq_send: mpsc::Sender<u8>,
    cache: Arc<DashMap<AppleTalkAddress, Node>>,
    _cancel: Arc<DropGuard>,
}

impl AddressingHandle {
    pub fn received_llap_ack(&self, src_node: u8) {
        let _ = self.lt_ack_send.try_send(src_node);
    }

    pub fn received_llap_enq(&self, dst_node: u8) {
        let _ = self.lt_enq_send.try_send(dst_node);
    }

    pub fn learn(&self, addr: AppleTalkAddress, node: Node) {
        self.cache.insert(addr, node);
    }

    pub fn try_lookup(&self, addr: &AppleTalkAddress) -> Option<Node> {
        // Network 0 is LocalTalk — node number is the link-layer address directly.
        if addr.network_number == 0 {
            return Some(Node::LocalTalk(addr.node_number));
        }

        if addr.node_number == 255 {
            return Some(Node::EtherTalkPhase2(Addressing::BROADCAST_MAC));
        }
        self.cache.get(addr).map(|v| *v)
    }

    pub async fn lookup(&self, addr: AppleTalkAddress) -> Result<Node, Error> {
        if let Some(mac) = self.try_lookup(&addr) {
            return Ok(mac);
        }

        let (tx, rx) = oneshot::channel();

        let request = AarpCommand::Lookup(AarpRequest { addr, chan: tx });

        if let Err(e) = self.request_send.send(request).await {
            return Err(Error::other(e));
        }

        match rx.await {
            Ok(res) => res,
            Err(e) => Err(Error::other(e)),
        }
    }

    pub async fn addr(&self) -> Result<AppleTalkAddress, Error> {
        let (tx, rx) = oneshot::channel();
        let request = AarpCommand::OurAddr(SelfAddress { chan: tx });

        if let Err(e) = self.request_send.send(request).await {
            return Err(Error::other(e));
        }

        match rx.await {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::other(e)),
        }
    }

    pub fn received_pkt(&self, pkt: &[u8], source: AddressSource) -> Result<(), Error> {
        let headers = AarpPacket::parse(pkt).unwrap();

        let node = match source {
            AddressSource::EtherTalkPhase2 => Node::EtherTalkPhase2(headers.sender_addr),
            AddressSource::EtherTalkPhase1 => Node::EtherTalkPhase1(headers.sender_addr),
            // AARP is not used on LocalTalk; address assignment uses LLAP ENQ/ACK instead.
            AddressSource::LocalTalk => return Ok(()),
        };
        self.cache.insert(headers.sender_protocol, node);

        self.packet_send
            .try_send((headers, source))
            .map_err(Error::other)?;

        Ok(())
    }
}
