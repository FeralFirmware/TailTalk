//! The LocalTalk-facing AppleTalk stack: LLAP address acquisition, DDP
//! framing and socket dispatch, and the always-on responders (NBP, AEP,
//! RTMP listener).
//!
//! Drive it with [`Stack::handle_frame`] and [`Stack::poll`]; drain
//! [`Stack::poll_transmit`] and [`Stack::poll_event`].

use alloc::collections::BTreeSet;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::{DdpPacket, DdpProtocolType};
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tailtalk_packets::nbp::EntityName;

use crate::addressing::{AcquireEvent, Acquisition, NodeClass};
use crate::ddp::{DYNAMIC_SOCKET_HI, DYNAMIC_SOCKET_LO, Datagram, MAX_DDP_PAYLOAD, encode_ddp};
use crate::link::OutFrame;
use crate::nbp::{NBP_SOCKET, NbpRegistry};
use crate::rtmp::observe;
use crate::{Micros, Rand, aep, rtmp};

/// The well-known RTMP socket (also exported by tailtalk-packets).
const RTMP_SOCKET: u8 = tailtalk_packets::rtmp::RTMP_SOCKET;

#[derive(Debug, Clone)]
pub struct StackConfig {
    /// Printers are server nodes (candidates 128..=254).
    pub node_class: NodeClass,
    /// PRNG seed; feed ROSC entropy on the RP2040.
    pub seed: u32,
    /// Answer ENQs for our node in software. Leave off when the wire
    /// engine's auto-reply node bitmap already does this (InkTalk core 1);
    /// on when the link is a dumb pipe (host tests, plain TashTalk).
    pub auto_ack_enq: bool,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            node_class: NodeClass::Server,
            seed: 1,
            auto_ack_enq: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StackEvent {
    /// The LLAP probe finished. Program the wire engine's auto-reply node
    /// bitmap with this node now, not earlier: doing it before the claim
    /// would make the engine ACK our own probes.
    AddressAcquired(AppleTalkAddress),
    /// A router's RTMP broadcast revealed the cable's real network number.
    NetworkNumberChanged(u16),
    /// A datagram arrived for a socket opened with [`Stack::open_socket`].
    Datagram(Datagram),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// No node address yet; the probe is still running.
    NoAddress,
    /// Payload exceeds the 586-byte DDP maximum.
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketError {
    InUse,
    Exhausted,
}

pub struct Stack {
    auto_ack_enq: bool,
    acquire: Option<Acquisition>,
    node: Option<u8>,
    network: u16,
    router: Option<AppleTalkAddress>,
    nbp: NbpRegistry,
    sockets: BTreeSet<u8>,
    rng: Rand,
    outbox: VecDeque<OutFrame>,
    events: VecDeque<StackEvent>,
}

impl Stack {
    pub fn new(cfg: StackConfig, now: Micros) -> Self {
        Self {
            auto_ack_enq: cfg.auto_ack_enq,
            acquire: Some(Acquisition::new(cfg.node_class, cfg.seed, now)),
            node: None,
            network: 0,
            router: None,
            nbp: NbpRegistry::new(),
            sockets: BTreeSet::new(),
            rng: Rand::new(cfg.seed ^ 0xA5A5_5A5A),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Our settled DDP address; `None` while the probe runs. The network
    /// number is 0 until a router's RTMP broadcast supplies the real one.
    pub fn our_address(&self) -> Option<AppleTalkAddress> {
        self.node.map(|node_number| AppleTalkAddress {
            network_number: self.network,
            node_number,
        })
    }

    /// Whether a router has been seen (switches DDP to long form).
    pub fn router_seen(&self) -> bool {
        self.router.is_some()
    }

    /// Deadline of the next timed action, for schedulers that sleep.
    pub fn next_deadline(&self) -> Option<Micros> {
        self.acquire.as_ref().and_then(|a| a.next_deadline())
    }

    /// Advance timers. Call whenever `next_deadline` passes.
    pub fn poll(&mut self, now: Micros) {
        let Some(acquire) = &mut self.acquire else {
            return;
        };
        while let Some(ev) = acquire.poll(now) {
            match ev {
                AcquireEvent::SendEnq(candidate) => {
                    self.outbox.push_back(OutFrame {
                        dst: candidate,
                        src: candidate,
                        kind: LlapType::Enquiry,
                        payload: Vec::new(),
                    });
                }
                AcquireEvent::Claimed(node) => {
                    self.node = Some(node);
                    self.acquire = None;
                    self.events.push_back(StackEvent::AddressAcquired(AppleTalkAddress {
                        network_number: self.network,
                        node_number: node,
                    }));
                    return;
                }
            }
        }
    }

    /// Feed one received LLAP frame (dst, src, type, payload - no FCS).
    pub fn handle_frame(&mut self, data: &[u8], now: Micros) {
        let Ok(llap) = LlapPacket::parse(data) else {
            return;
        };
        // Self-echo: the full-duplex transceiver hears our own transmissions
        // when the connector box joins the pairs. The wire engine filters
        // these already; filtering again here keeps host embeddings honest.
        // Our own ENQ probes (src == candidate, not yet our node) must NOT
        // be filtered - the acquisition loop listens through them for ACKs.
        if Some(llap.src_node) == self.node && llap.type_ != LlapType::Acknowledge {
            return;
        }

        match llap.type_ {
            LlapType::Acknowledge => {
                if let Some(acquire) = &mut self.acquire {
                    acquire.on_ack(llap.src_node, now);
                }
            }
            LlapType::Enquiry => {
                if self.auto_ack_enq
                    && let Some(node) = self.node
                    && llap.dst_node == node
                    && self.acquire.is_none()
                {
                    // Defend our address: lapACK with dst = src = our
                    // node, as LLAP requires - the probe being defended
                    // carries dst == src == candidate.
                    self.outbox.push_back(OutFrame {
                        dst: node,
                        src: node,
                        kind: LlapType::Acknowledge,
                        payload: Vec::new(),
                    });
                }
            }
            LlapType::DdpShort => {
                if let Ok(headers) = DdpPacket::parse_short(&data[3..], llap.dst_node, llap.src_node)
                {
                    let end = (3 + headers.len).min(data.len());
                    if end >= 8 {
                        let payload = data[8..end].to_vec();
                        self.dispatch(headers, payload);
                    }
                }
            }
            LlapType::DdpLong => {
                if let Ok(headers) = DdpPacket::parse(&data[3..]) {
                    let end = (3 + headers.len).min(data.len());
                    if end >= 3 + DdpPacket::LEN {
                        let payload = data[3 + DdpPacket::LEN..end].to_vec();
                        self.dispatch(headers, payload);
                    }
                }
            }
            LlapType::Other(_) => {}
        }
    }

    fn dispatch(&mut self, headers: DdpPacket, payload: Vec<u8>) {
        let Some(node) = self.node else {
            // No address yet: nothing above LLAP is running.
            return;
        };
        // LocalTalk address match is by node number only: network numbers
        // on a nonextended cable are advisory.
        let for_us = headers.dest_node_id == 255 || headers.dest_node_id == node;
        if !for_us {
            return;
        }

        let src = AppleTalkAddress {
            network_number: headers.src_network_num,
            node_number: headers.src_node_id,
        };

        match headers.dest_sock_num {
            RTMP_SOCKET => self.handle_rtmp(&payload, src),
            NBP_SOCKET => {
                if let Some(our_addr) = self.our_address()
                    && let Some(reply) = self.nbp.handle_packet(&payload, our_addr)
                {
                    let _ = self.send_ddp(
                        reply.dest,
                        reply.dest_socket,
                        NBP_SOCKET,
                        DdpProtocolType::Nbp,
                        &reply.payload,
                    );
                }
            }
            aep::AEP_SOCKET => {
                if let Some(reply) = aep::respond(&payload) {
                    let _ = self.send_ddp(
                        src,
                        headers.src_sock_num,
                        aep::AEP_SOCKET,
                        DdpProtocolType::Aep,
                        &reply,
                    );
                }
            }
            sock if self.sockets.contains(&sock) => {
                self.events.push_back(StackEvent::Datagram(Datagram {
                    src,
                    src_socket: headers.src_sock_num,
                    dst_socket: sock,
                    proto: headers.protocol_typ,
                    payload,
                }));
            }
            _ => {}
        }
    }

    fn handle_rtmp(&mut self, payload: &[u8], src: AppleTalkAddress) {
        let Some(rtmp::RtmpObservation {
            router,
            cable_network,
        }) = observe(payload, src.network_number, src.node_number)
        else {
            return;
        };
        self.router = Some(router);
        if let Some(net) = cable_network
            && net != self.network
        {
            self.network = net;
            self.events.push_back(StackEvent::NetworkNumberChanged(net));
        }
    }

    /// Open a DDP socket whose datagrams surface as [`StackEvent::Datagram`].
    /// `Some(n)` claims a specific (well-known) socket; `None` picks a free
    /// dynamic one.
    pub fn open_socket(&mut self, socket: Option<u8>) -> Result<u8, SocketError> {
        let reserved = [RTMP_SOCKET, NBP_SOCKET, aep::AEP_SOCKET];
        match socket {
            Some(n) => {
                if reserved.contains(&n) || !self.sockets.insert(n) {
                    Err(SocketError::InUse)
                } else {
                    Ok(n)
                }
            }
            None => {
                for _ in 0..=(DYNAMIC_SOCKET_HI - DYNAMIC_SOCKET_LO) as usize * 2 {
                    let n = self.rng.in_range(DYNAMIC_SOCKET_LO, DYNAMIC_SOCKET_HI);
                    if self.sockets.insert(n) {
                        return Ok(n);
                    }
                }
                Err(SocketError::Exhausted)
            }
        }
    }

    pub fn close_socket(&mut self, socket: u8) {
        self.sockets.remove(&socket);
    }

    /// Register an NBP name answering lookups on `socket`.
    pub fn nbp_register(&mut self, name: EntityName, socket: u8) -> Result<(), &'static str> {
        self.nbp.register(name, socket)
    }

    pub fn nbp_unregister(&mut self, name: &EntityName, socket: u8) -> bool {
        self.nbp.unregister(name, socket)
    }

    /// Send a DDP datagram. Short-form headers while the cable is unrouted,
    /// long form (with checksum) once a router has been seen.
    pub fn send_ddp(
        &mut self,
        dest: AppleTalkAddress,
        dest_socket: u8,
        src_socket: u8,
        proto: DdpProtocolType,
        payload: &[u8],
    ) -> Result<(), SendError> {
        let Some(our) = self.our_address() else {
            return Err(SendError::NoAddress);
        };
        if payload.len() > MAX_DDP_PAYLOAD {
            return Err(SendError::TooLarge);
        }

        // A datagram to ourselves never comes back off the wire, so loop
        // it back to the local socket here.
        let on_cable = dest.network_number == 0 || dest.network_number == self.network;
        if dest.node_number == our.node_number && on_cable {
            let headers_proto = proto;
            if self.sockets.contains(&dest_socket) {
                self.events.push_back(StackEvent::Datagram(Datagram {
                    src: our,
                    src_socket,
                    dst_socket: dest_socket,
                    proto: headers_proto,
                    payload: payload.to_vec(),
                }));
            }
            return Ok(());
        }

        let use_short = self.router.is_none();
        let body = encode_ddp(
            use_short,
            our,
            src_socket,
            dest,
            dest_socket,
            proto,
            payload,
        );

        // Link-level destination: broadcasts go to 0xFF; an off-cable
        // network routes via the A-Router; anything else is the node itself.
        let llap_dst = if dest.node_number == 255 {
            0xFF
        } else if !on_cable && let Some(router) = self.router {
            router.node_number
        } else {
            dest.node_number
        };

        self.outbox.push_back(OutFrame {
            dst: llap_dst,
            src: our.node_number,
            kind: if use_short {
                LlapType::DdpShort
            } else {
                LlapType::DdpLong
            },
            payload: body,
        });
        Ok(())
    }

    /// Next frame to put on the wire, if any.
    pub fn poll_transmit(&mut self) -> Option<OutFrame> {
        self.outbox.pop_front()
    }

    /// Next application-visible event, if any.
    pub fn poll_event(&mut self) -> Option<StackEvent> {
        self.events.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settle(stack: &mut Stack, now: &mut Micros) -> u8 {
        loop {
            stack.poll(*now);
            while stack.poll_transmit().is_some() {}
            if let Some(StackEvent::AddressAcquired(addr)) = stack.poll_event() {
                return addr.node_number;
            }
            match stack.next_deadline() {
                Some(deadline) => *now = deadline,
                None => panic!("no deadline and no address"),
            }
        }
    }

    fn frame(dst: u8, src: u8, kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = alloc::vec![dst, src, kind];
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn acquires_a_server_node_and_emits_enqs_first() {
        let mut stack = Stack::new(StackConfig::default(), 0);
        stack.poll(0);
        let enq = stack.poll_transmit().expect("first ENQ");
        assert_eq!(enq.kind, LlapType::Enquiry);
        assert_eq!(enq.dst, enq.src);
        assert!(stack.our_address().is_none());

        let mut now = 0;
        let node = settle(&mut stack, &mut now);
        assert!((128..=254).contains(&node));
        assert_eq!(stack.our_address().unwrap().network_number, 0);
    }

    #[test]
    fn defended_candidate_is_abandoned() {
        let mut stack = Stack::new(StackConfig::default(), 0);
        stack.poll(0);
        let first = stack.poll_transmit().unwrap().dst;
        // Someone defends the candidate.
        stack.handle_frame(&frame(first, first, 0x82, &[]), 10);
        let mut now = 10;
        let node = settle(&mut stack, &mut now);
        assert_ne!(node, first);
    }

    #[test]
    fn aep_round_trip_short_form() {
        let mut stack = Stack::new(StackConfig::default(), 0);
        let mut now = 0;
        let node = settle(&mut stack, &mut now);

        // LLAP header + short DDP header + AEP request payload.
        let ddp = crate::ddp::encode_ddp(
            true,
            AppleTalkAddress { network_number: 0, node_number: 77 },
            4,
            AppleTalkAddress { network_number: 0, node_number: node },
            4,
            DdpProtocolType::Aep,
            &[1, 0xAA],
        );
        let data = frame(node, 77, 1, &ddp);
        stack.handle_frame(&data, now);

        let reply = stack.poll_transmit().expect("AEP reply");
        assert_eq!(reply.dst, 77);
        assert_eq!(reply.kind, LlapType::DdpShort);
        // Short header is 5 bytes; then the AEP function byte flipped to 2.
        assert_eq!(reply.payload[5], 2);
        assert_eq!(reply.payload[6], 0xAA);
    }

    #[test]
    fn rtmp_switches_to_long_form_and_gleans_network() {
        let mut stack = Stack::new(StackConfig::default(), 0);
        let mut now = 0;
        let node = settle(&mut stack, &mut now);

        // Before the router: sends are short form.
        let dest = AppleTalkAddress { network_number: 0, node_number: 9 };
        stack.send_ddp(dest, 2, 2, DdpProtocolType::Nbp, &[0]).unwrap();
        assert_eq!(stack.poll_transmit().unwrap().kind, LlapType::DdpShort);

        // AsanteTalk-style broadcast to the RTMP socket.
        let rtmp_payload: &[u8] = &[
            0x00, 0x02, 0x08, 0xfe, 0x00, 0x00, 0x82, 0x00, 0x02, 0x00,
        ];
        let ddp = crate::ddp::encode_ddp(
            true,
            AppleTalkAddress { network_number: 0, node_number: 254 },
            1,
            AppleTalkAddress { network_number: 0, node_number: 255 },
            1,
            DdpProtocolType::RtmpResponse,
            rtmp_payload,
        );
        stack.handle_frame(&frame(0xFF, 254, 1, &ddp), now);

        assert_eq!(
            stack.poll_event(),
            Some(StackEvent::NetworkNumberChanged(2))
        );
        assert!(stack.router_seen());
        assert_eq!(stack.our_address().unwrap().network_number, 2);

        // After the router: long form, and our source network is real.
        stack.send_ddp(dest, 2, 2, DdpProtocolType::Nbp, &[0]).unwrap();
        let out = stack.poll_transmit().unwrap();
        assert_eq!(out.kind, LlapType::DdpLong);
        let hdr = DdpPacket::parse(&out.payload).unwrap();
        assert_eq!(hdr.src_network_num, 2);
        assert_eq!(hdr.src_node_id, node);

        // Off-cable destinations route via the router's node.
        let far = AppleTalkAddress { network_number: 7, node_number: 3 };
        stack.send_ddp(far, 2, 2, DdpProtocolType::Nbp, &[0]).unwrap();
        assert_eq!(stack.poll_transmit().unwrap().dst, 254);
    }

    #[test]
    fn nbp_lookup_answered_end_to_end() {
        use tailtalk_packets::nbp::{NbpOperation, NbpPacket, NbpTuple};

        let mut stack = Stack::new(StackConfig::default(), 0);
        let mut now = 0;
        let node = settle(&mut stack, &mut now);
        stack
            .nbp_register("Inky:ImageWriter@*".try_into().unwrap(), 190)
            .unwrap();

        let mut tuples = tailtalk_packets::heapless::Vec::new();
        // `push` returns Err(the rejected value), and NbpTuple is not
        // Debug, so assert on the result rather than unwrapping it.
        assert!(
            tuples
                .push(NbpTuple {
                    network_number: 0,
                    node_id: 41,
                    socket_number: 2,
                    enumerator: 0,
                    entity_name: "=:ImageWriter@*".try_into().unwrap(),
                })
                .is_ok(),
            "one tuple fits"
        );
        let lookup = NbpPacket {
            operation: NbpOperation::Lookup,
            transaction_id: 3,
            tuples,
        };
        let mut buf = [0u8; 600];
        let n = lookup.to_bytes(&mut buf).unwrap();
        let ddp = crate::ddp::encode_ddp(
            true,
            AppleTalkAddress { network_number: 0, node_number: 41 },
            2,
            AppleTalkAddress { network_number: 0, node_number: 255 },
            2,
            DdpProtocolType::Nbp,
            &buf[..n],
        );
        stack.handle_frame(&frame(0xFF, 41, 1, &ddp), now);

        let out = stack.poll_transmit().expect("LkUp-Reply");
        assert_eq!(out.dst, 41);
        let reply = NbpPacket::from_bytes(&out.payload[5..]).unwrap();
        assert!(matches!(reply.operation, NbpOperation::LookupReply));
        assert_eq!(reply.tuples[0].node_id, node);
        assert_eq!(reply.tuples[0].socket_number, 190);
    }

    #[test]
    fn datagrams_reach_open_sockets_and_loop_back() {
        let mut stack = Stack::new(StackConfig::default(), 0);
        let mut now = 0;
        let node = settle(&mut stack, &mut now);
        let sock = stack.open_socket(Some(190)).unwrap();

        let ddp = crate::ddp::encode_ddp(
            true,
            AppleTalkAddress { network_number: 0, node_number: 41 },
            65,
            AppleTalkAddress { network_number: 0, node_number: node },
            sock,
            DdpProtocolType::Atp,
            &[1, 2, 3],
        );
        stack.handle_frame(&frame(node, 41, 1, &ddp), now);
        match stack.poll_event() {
            Some(StackEvent::Datagram(d)) => {
                assert_eq!(d.src.node_number, 41);
                assert_eq!(d.src_socket, 65);
                assert_eq!(d.payload, alloc::vec![1, 2, 3]);
            }
            other => panic!("expected datagram, got {other:?}"),
        }

        // Loopback: sending to our own node reaches the local socket.
        let us = stack.our_address().unwrap();
        stack
            .send_ddp(us, sock, 65, DdpProtocolType::Atp, &[9])
            .unwrap();
        assert!(stack.poll_transmit().is_none());
        assert!(matches!(
            stack.poll_event(),
            Some(StackEvent::Datagram(d)) if d.payload == alloc::vec![9]
        ));
    }
}
