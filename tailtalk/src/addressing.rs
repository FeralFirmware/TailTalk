use dashmap::DashMap;
use im::hashmap::HashMap;
use rand::RngExt;
use std::sync::Arc;
use std::{io::Error, time::Duration};
use tailtalk_packets::aarp::*;
use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::remote::RemoteClient;
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

struct SetAddress {
    addr: AppleTalkAddress,
    chan: oneshot::Sender<()>,
}

enum AarpCommand {
    Lookup(AarpRequest),
    OurAddr(SelfAddress),
    SetAddr(SetAddress),
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
    phase: AddressSource,
    cancel: CancellationToken,
    /// Publishes the settled address (and later changes via `SetAddr`) so the
    /// data link layer can react, e.g. reprogram TashTalk node ID bits.
    addr_tx: watch::Sender<Option<AppleTalkAddress>>,
}

impl Addressing {
    const BROADCAST_MAC: [u8; 6] = [0xFF; 6];
    pub const APPLETALK_BROADCAST_MULTICAST: [u8; 6] = [0x09, 0x00, 0x07, 0xFF, 0xFF, 0xFF];

    fn broadcast_mac(phase: AddressSource) -> EthernetMac {
        match phase {
            AddressSource::EtherTalkPhase2 => Self::APPLETALK_BROADCAST_MULTICAST,
            _ => Self::BROADCAST_MAC,
        }
    }

    /// Returns `true` if `mac` is the correct broadcast address for the given
    /// EtherTalk phase: `FF:FF:FF:FF:FF:FF` for Phase 1,
    /// `09:00:07:FF:FF:FF` for Phase 2.
    pub fn is_broadcast_mac(mac: EthernetMac, phase: AddressSource) -> bool {
        match phase {
            AddressSource::EtherTalkPhase1 => mac == Self::BROADCAST_MAC,
            AddressSource::EtherTalkPhase2 => mac == Self::APPLETALK_BROADCAST_MULTICAST,
            AddressSource::LocalTalk => false,
        }
    }

    /// Spawn the addressing actor.
    ///
    /// If `fixed_addr` is `Some(addr)`, that AppleTalk address is used immediately
    /// without any AARP probe — useful when the caller wants a specific node number.
    /// If `None`, a random node in network 1 is chosen and confirmed via AARP probe.
    pub fn spawn(
        our_mac: Option<EthernetMac>,
        outbound: OutboundHandle,
        fixed_addr: Option<AppleTalkAddress>,
        phase: AddressSource,
    ) -> AddressingHandle {
        let (request_send, request_recv) = mpsc::channel(100);
        let (packet_send, packet_recv) = mpsc::channel(100);
        let (lt_ack_send, lt_ack_recv) = mpsc::channel(16);
        let (lt_enq_send, lt_enq_recv) = mpsc::channel(16);
        let (addr_tx, addr_rx) = watch::channel(None);
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
            phase,
            outbound,
            addr_tx,
        };

        tokio::spawn(async move { us.run(fixed_addr).await });

        AddressingHandle {
            phase,
            inner: AddressingInner::Local {
                _cancel: Arc::new(handle_token.drop_guard()),
                request_send,
                packet_send,
                lt_ack_send,
                lt_enq_send,
                addr_watch: addr_rx,
                cache,
            },
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
        let mut our_addr = if self.our_mac.is_none() {
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
                    Self::broadcast_mac(self.phase),
                    addr,
                    AarpOpcode::Probe,
                    self.phase,
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
        let _ = self.addr_tx.send(Some(our_addr));
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
                                let packet = self.create_packet(lookup.addr, Self::broadcast_mac(self.phase), our_addr, AarpOpcode::Request, self.phase);
                                self.outbound.send(packet).await.expect("failed to dispatch request");
                                self.pending.entry(lookup.addr).or_default().push(Arc::new(lookup));
                            },
                            AarpCommand::OurAddr(req) => {
                                req.chan.send(our_addr).expect("failed to send our_addr");
                            },
                            AarpCommand::SetAddr(req) => {
                                tracing::info!(
                                    "addressing: address changed to {}.{}",
                                    req.addr.network_number,
                                    req.addr.node_number
                                );
                                our_addr = req.addr;
                                let _ = self.addr_tx.send(Some(our_addr));
                                let _ = req.chan.send(());
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

/// Handle to interface addressing.
#[derive(Clone)]
pub struct AddressingHandle {
    pub phase: AddressSource,
    inner: AddressingInner,
}

#[derive(Clone)]
enum AddressingInner {
    Local {
        request_send: mpsc::Sender<AarpCommand>,
        packet_send: mpsc::Sender<(AarpPacket, AddressSource)>,
        lt_ack_send: mpsc::Sender<u8>,
        lt_enq_send: mpsc::Sender<u8>,
        addr_watch: watch::Receiver<Option<AppleTalkAddress>>,
        cache: Arc<DashMap<AppleTalkAddress, Node>>,
        _cancel: Arc<DropGuard>,
    },
    Remote {
        client: RemoteClient,
        /// Daemon-side interface name this handle queries.
        interface: String,
    },
}

impl AddressingHandle {
    /// Create a handle backed by a remote daemon's interface.
    pub(crate) fn remote(client: RemoteClient, interface: String, phase: AddressSource) -> Self {
        Self {
            phase,
            inner: AddressingInner::Remote { client, interface },
        }
    }

    /// Watch the settled interface address; `None` until acquisition completes.
    ///
    /// Only available for locally-owned interfaces (used by the data link
    /// layer to reprogram hardware when the address changes).
    pub fn addr_watch(&self) -> Option<watch::Receiver<Option<AppleTalkAddress>>> {
        match &self.inner {
            AddressingInner::Local { addr_watch, .. } => Some(addr_watch.clone()),
            AddressingInner::Remote { .. } => None,
        }
    }

    pub fn received_llap_ack(&self, src_node: u8) {
        if let AddressingInner::Local { lt_ack_send, .. } = &self.inner {
            let _ = lt_ack_send.try_send(src_node);
        }
    }

    pub fn received_llap_enq(&self, dst_node: u8) {
        if let AddressingInner::Local { lt_enq_send, .. } = &self.inner {
            let _ = lt_enq_send.try_send(dst_node);
        }
    }

    pub fn learn(&self, addr: AppleTalkAddress, node: Node) {
        if let AddressingInner::Local { cache, .. } = &self.inner {
            cache.insert(addr, node);
        }
    }

    pub fn try_lookup(&self, addr: &AppleTalkAddress) -> Option<Node> {
        // Node 255 is always the cable-wide broadcast for this handle's phase,
        // regardless of network number (network 0 = network-wide broadcast).
        if addr.node_number == 255 {
            return Some(match self.phase {
                AddressSource::EtherTalkPhase2 => {
                    Node::EtherTalkPhase2(Addressing::APPLETALK_BROADCAST_MULTICAST)
                }
                AddressSource::EtherTalkPhase1 => Node::EtherTalkPhase1(Addressing::BROADCAST_MAC),
                AddressSource::LocalTalk => Node::LocalTalk(255),
            });
        }

        // Network 0 unicast: on a LocalTalk handle, the node number is the
        // link-layer address directly. Nonextended EtherTalk (Phase 1) nodes
        // also address themselves on network 0, so an EtherTalk handle can't
        // take this shortcut — it must fall through to the learned-address
        // cache below like any other lookup.
        if addr.network_number == 0 && self.phase == AddressSource::LocalTalk {
            return Some(Node::LocalTalk(addr.node_number));
        }

        match &self.inner {
            AddressingInner::Local { cache, .. } => cache.get(addr).map(|v| *v),
            // Link-layer resolution happens inside the daemon.
            AddressingInner::Remote { .. } => None,
        }
    }

    pub async fn lookup(&self, addr: AppleTalkAddress) -> Result<Node, Error> {
        if let Some(mac) = self.try_lookup(&addr) {
            return Ok(mac);
        }

        let request_send = match &self.inner {
            AddressingInner::Local { request_send, .. } => request_send,
            AddressingInner::Remote { .. } => {
                return Err(Error::new(
                    std::io::ErrorKind::Unsupported,
                    "link-layer lookup is performed by the daemon",
                ));
            }
        };

        let (tx, rx) = oneshot::channel();

        let request = AarpCommand::Lookup(AarpRequest { addr, chan: tx });

        if let Err(e) = request_send.send(request).await {
            return Err(Error::other(e));
        }

        match rx.await {
            Ok(res) => res,
            Err(e) => Err(Error::other(e)),
        }
    }

    pub async fn addr(&self) -> Result<AppleTalkAddress, Error> {
        match &self.inner {
            AddressingInner::Local { request_send, .. } => {
                let (tx, rx) = oneshot::channel();
                let request = AarpCommand::OurAddr(SelfAddress { chan: tx });

                if let Err(e) = request_send.send(request).await {
                    return Err(Error::other(e));
                }

                match rx.await {
                    Ok(res) => Ok(res),
                    Err(e) => Err(Error::other(e)),
                }
            }
            AddressingInner::Remote { client, interface } => {
                client.interface_addr(interface).await
            }
        }
    }

    /// Force this interface to the given address, without probing.
    ///
    /// On LocalTalk the data link layer reprograms the TashTalk node ID bits
    /// to match.
    pub async fn set_addr(&self, addr: AppleTalkAddress) -> Result<(), Error> {
        match &self.inner {
            AddressingInner::Local { request_send, .. } => {
                let (tx, rx) = oneshot::channel();
                let request = AarpCommand::SetAddr(SetAddress { addr, chan: tx });

                if let Err(e) = request_send.send(request).await {
                    return Err(Error::other(e));
                }

                rx.await.map_err(Error::other)
            }
            AddressingInner::Remote { client, interface } => {
                client.set_interface_addr(interface, addr).await
            }
        }
    }

    pub fn received_pkt(&self, pkt: &[u8], source: AddressSource) -> Result<(), Error> {
        let AddressingInner::Local { cache, packet_send, .. } = &self.inner else {
            return Ok(());
        };

        let headers = AarpPacket::parse(pkt).unwrap();

        let node = match source {
            AddressSource::EtherTalkPhase2 => Node::EtherTalkPhase2(headers.sender_addr),
            AddressSource::EtherTalkPhase1 => Node::EtherTalkPhase1(headers.sender_addr),
            // AARP is not used on LocalTalk; address assignment uses LLAP ENQ/ACK instead.
            AddressSource::LocalTalk => return Ok(()),
        };
        cache.insert(headers.sender_protocol, node);

        packet_send
            .try_send((headers, source))
            .map_err(Error::other)?;

        Ok(())
    }
}
