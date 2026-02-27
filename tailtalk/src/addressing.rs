use dashmap::DashMap;
use im::hashmap::HashMap;
use rand::Rng;
use std::sync::Arc;
use std::{io::Error, time::Duration};
use tailtalk_packets::{aarp::*, ethertalk::EtherTalkType};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::{EtherTalkPacket, OutboundHandle};

struct AarpRequest {
    addr: AppleTalkAddress,
    chan: oneshot::Sender<Result<EthernetMac, Error>>,
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
    pending: HashMap<AppleTalkAddress, Vec<Arc<AarpRequest>>>,
    cache: Arc<DashMap<AppleTalkAddress, (EthernetMac, AddressSource)>>,
    outbound: OutboundHandle,
    our_mac: EthernetMac,
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
        our_mac: EthernetMac,
        outbound: OutboundHandle,
        fixed_addr: Option<AppleTalkAddress>,
    ) -> AddressingHandle {
        let (request_send, request_recv) = mpsc::channel(100);
        let (packet_send, packet_recv) = mpsc::channel(100);
        let cache = Arc::new(DashMap::new());
        let token = CancellationToken::new();
        let handle_token = token.clone();

        let us = Self {
            pending: HashMap::new(),
            cache: cache.clone(),
            cancel: token,
            request_recv,
            packet_recv,
            our_mac,
            outbound,
        };

        tokio::spawn(async move { us.run(fixed_addr).await });

        AddressingHandle {
            _cancel: Arc::new(handle_token.drop_guard()),
            request_send,
            packet_send,
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
    ) -> EtherTalkPacket {
        let aarp_header = AarpPacket {
            hardware_type: 1,      // Ethernet
            protocol_type: 0x809b, // Appletalk LLAP Bridging
            hardware_size: 6,
            protocol_size: 4,
            opcode,
            sender_addr: self.our_mac,
            sender_protocol: our_addr,
            target_addr: target_mac, // Use requester's MAC for responses
            target_protocol: target,
        };
        let mut payload = [0u8; AarpPacket::LEN];
        aarp_header.to_bytes(&mut payload);

        EtherTalkPacket {
            dst_mac: target_mac, // Use requester's MAC for responses
            protocol: EtherTalkType::Aarp,
            payload: payload.into(),
            source_type,
        }
    }

    async fn run(mut self, fixed_addr: Option<AppleTalkAddress>) {
        let our_addr = if let Some(addr) = fixed_addr {
            tracing::info!(
                "addressing: Using fixed address {}.{}",
                addr.network_number,
                addr.node_number
            );
            addr
        } else {
            // Outer loop retries with a new random address on conflict.
            'probe: loop {
                let node_num = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(1..=254)
                };
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
                    AddressSource::EtherTalk,
                );
                self.outbound
                    .send(probe)
                    .await
                    .expect("failed to dispatch probe packet");

                // Wait up to 1 second for a conflicting probe.
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
                                        if let Err(e) = inner_req.chan.send(Ok(pkt.sender_addr)) {
                                            tracing::error!("error responding to AarpRequest: {e:?}");
                                        }
                                        self.cache.insert(pkt.sender_protocol, (pkt.sender_addr, AddressSource::EtherTalk));
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
                                let packet = self.create_packet(lookup.addr, Self::BROADCAST_MAC, our_addr, AarpOpcode::Request, AddressSource::EtherTalk);
                                self.outbound.send(packet).await.expect("failed to dispatch request");
                                self.pending.entry(lookup.addr).or_default().push(Arc::new(lookup));
                            },
                            AarpCommand::OurAddr(req) => {
                                req.chan.send(our_addr).expect("failed to send our_addr");
                            },
                        }
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
        // Response: we are the sender, requester is the target
        let packet = self.create_packet(
            pkt.sender_protocol, // Target AppleTalk address (requester)
            pkt.sender_addr,     // Target MAC (requester)
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
    pub(crate) cache: Arc<DashMap<AppleTalkAddress, (EthernetMac, AddressSource)>>,
    _cancel: Arc<DropGuard>,
}

impl AddressingHandle {
    pub fn try_lookup(&self, addr: &AppleTalkAddress) -> Option<(EthernetMac, AddressSource)> {
        if addr.node_number == 255 {
            // Broadcast - default to EtherTalk
            return Some((
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                AddressSource::EtherTalk,
            ));
        }
        self.cache.get(addr).map(|v| *v)
    }

    pub async fn lookup(
        &self,
        addr: AppleTalkAddress,
    ) -> Result<(EthernetMac, AddressSource), Error> {
        if let Some(mac) = self.try_lookup(&addr) {
            return Ok(mac);
        }

        let (tx, rx) = oneshot::channel();

        let request = AarpCommand::Lookup(AarpRequest { addr, chan: tx });

        if let Err(e) = self.request_send.send(request).await {
            return Err(Error::other(e));
        }

        match rx.await {
            Ok(res) => {
                // The channel returns just the MAC, but we need the tuple
                // Re-check the cache which should now have the full (MAC, AddressSource) tuple
                match res {
                    Ok(_mac) => {
                        if let Some(cached) = self.try_lookup(&addr) {
                            Ok(cached)
                        } else {
                            // Fallback shouldn't happen, but return EtherTalk default
                            Ok((_mac, AddressSource::EtherTalk))
                        }
                    }
                    Err(e) => Err(e),
                }
            }
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

        // Cache the sender's address with the provided source type
        self.cache
            .insert(headers.sender_protocol, (headers.sender_addr, source));

        self.packet_send
            .try_send((headers, source))
            .map_err(Error::other)?;

        Ok(())
    }
}
