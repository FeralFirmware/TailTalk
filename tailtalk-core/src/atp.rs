//! ATP endpoint: requestor and responder on one DDP socket.
//!
//! The responder implements exactly-once (XO) transactions - inbound dedup
//! and a reply cache for retransmits, released by the requestor's TRel or
//! by a timer - as well as at-least-once (ALO).

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use tailtalk_packets::atp::{AtpFunction, AtpPacket};
use tailtalk_packets::nbp::ServiceAddress;

use crate::Micros;

/// Maximum data bytes per ATP packet: 586-byte DDP payload minus the 8-byte
/// ATP header.
pub const ATP_MAX_DATA_PER_PACKET: usize = 578;

/// Requestor retransmit schedule: 2 s between tries, 8 tries.
const RETRY_INTERVAL: Micros = 2_000_000;
const MAX_RETRIES: u8 = 8;

/// How long an XO reply-cache entry lives without a TRel. Inside AppleTalk's
/// release timer default is 30 seconds.
const RELEASE_TIMEOUT: Micros = 30_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtpEvent {
    /// An inbound transaction request. Answer with [`AtpEndpoint::respond`],
    /// echoing `source` and `tid`. `bitmap` is the number of response
    /// packets the requester will accept, already normalised (a classic Mac
    /// OS bitmap of 0x00 means "no restriction", handled here).
    Request {
        source: ServiceAddress,
        tid: u16,
        user_bytes: [u8; 4],
        data: Vec<u8>,
        bitmap: u8,
        /// Exactly-once: a response will be cached for retransmits until the
        /// peer's TRel arrives.
        xo: bool,
    },
    /// A complete response to one of our requests.
    Response {
        handle: u16,
        user_bytes: [u8; 4],
        data: Vec<u8>,
    },
    /// One of our requests exhausted its retries.
    RequestFailed { handle: u16 },
}

struct PendingRequest {
    dest: ServiceAddress,
    raw_packet: Vec<u8>,
    requested_bitmap: u8,
    received: BTreeMap<u8, Vec<u8>>,
    user_bytes: Option<[u8; 4]>,
    eom_seq: Option<u8>,
    retries: u8,
    retry_at: Micros,
}

struct CachedResponse {
    source: ServiceAddress,
    tid: u16,
    /// The fully framed response datagrams, resent verbatim on a duplicate
    /// TReq.
    packets: Vec<Vec<u8>>,
    expires_at: Micros,
}

pub struct AtpEndpoint {
    local_socket: u8,
    next_tid: u16,
    pending: BTreeMap<u16, PendingRequest>,
    reply_cache: VecDeque<CachedResponse>,
    /// TIDs of in-progress inbound XO transactions (request delivered, no
    /// response given yet), so a retransmitted TReq is not re-delivered.
    in_progress: VecDeque<(ServiceAddress, u16)>,
    outbox: VecDeque<(ServiceAddress, Vec<u8>)>,
    events: VecDeque<AtpEvent>,
}

/// How many reply-cache entries to keep. PAP's flow quantum caps outstanding
/// requests at 8 per direction; 16 leaves slack for status traffic.
const REPLY_CACHE_LEN: usize = 16;

impl AtpEndpoint {
    pub fn new(local_socket: u8) -> Self {
        Self {
            local_socket,
            next_tid: 1,
            pending: BTreeMap::new(),
            reply_cache: VecDeque::new(),
            in_progress: VecDeque::new(),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    pub fn local_socket(&self) -> u8 {
        self.local_socket
    }

    /// Send an XO request. Returns the handle carried by the later
    /// [`AtpEvent::Response`] / [`AtpEvent::RequestFailed`].
    pub fn request(
        &mut self,
        dest: ServiceAddress,
        user_bytes: [u8; 4],
        data: &[u8],
        bitmap: u8,
        now: Micros,
    ) -> u16 {
        let tid = self.allocate_tid();
        let packet = AtpPacket {
            function: AtpFunction::Request,
            xo: true,
            eom: false,
            sts: false,
            bitmap_seq_num: bitmap,
            tid,
            user_bytes,
        };
        let mut buf = vec![0u8; AtpPacket::HEADER_LEN + data.len()];
        packet.to_bytes(&mut buf).expect("sized buffer");
        buf[AtpPacket::HEADER_LEN..].copy_from_slice(data);
        self.outbox.push_back((dest, buf.clone()));
        self.pending.insert(
            tid,
            PendingRequest {
                dest,
                raw_packet: buf,
                requested_bitmap: bitmap,
                received: BTreeMap::new(),
                user_bytes: None,
                eom_seq: None,
                retries: 0,
                retry_at: now + RETRY_INTERVAL,
            },
        );
        tid
    }

    /// Send a fire-and-forget ALO packet (PAP tickles). No transaction is
    /// registered; any response is discarded.
    pub fn send_alo(&mut self, dest: ServiceAddress, user_bytes: [u8; 4]) {
        let tid = self.allocate_tid();
        let packet = AtpPacket {
            function: AtpFunction::Request,
            xo: false,
            eom: false,
            sts: false,
            bitmap_seq_num: 0xFF,
            tid,
            user_bytes,
        };
        let mut buf = [0u8; AtpPacket::HEADER_LEN];
        packet.to_bytes(&mut buf).expect("sized buffer");
        self.outbox.push_back((dest, buf.to_vec()));
    }

    /// Answer an inbound request: `data` is split into packets of at most
    /// `chunk_size` bytes (each with sequence number, EOM on the last), all
    /// carrying `user_bytes`. PAP passes 512 here; see
    /// `tailtalk/src/pap.rs:14` for why (a real LaserWriter misbehaves above
    /// that). At least one packet is sent even for empty data. The framed
    /// packets are cached for XO retransmits until TRel or timeout.
    pub fn respond(
        &mut self,
        source: ServiceAddress,
        tid: u16,
        user_bytes: [u8; 4],
        data: &[u8],
        chunk_size: usize,
        now: Micros,
    ) {
        let chunks: Vec<(
            [u8; 4],
            Vec<u8>,
        )> = if data.is_empty() {
            vec![(user_bytes, Vec::new())]
        } else {
            data.chunks(chunk_size.max(1))
                .take(8)
                .map(|c| (user_bytes, c.to_vec()))
                .collect()
        };
        self.respond_packets(source, tid, &chunks, now);
    }

    /// Answer an inbound request with pre-split packets, each carrying its
    /// own user bytes. At most 8; EOM is set on the last. Cached for XO
    /// retransmits like `respond`.
    pub fn respond_packets(
        &mut self,
        source: ServiceAddress,
        tid: u16,
        chunks: &[([u8; 4], Vec<u8>)],
        now: Micros,
    ) {
        let count = chunks.len().clamp(1, 8);
        let mut packets = Vec::with_capacity(count);
        for (i, (user_bytes, chunk)) in chunks.iter().take(8).enumerate() {
            let packet = AtpPacket {
                function: AtpFunction::Response,
                xo: false,
                eom: i == count - 1,
                sts: false,
                bitmap_seq_num: i as u8,
                tid,
                user_bytes: *user_bytes,
            };
            let mut buf = vec![0u8; AtpPacket::HEADER_LEN + chunk.len()];
            packet.to_bytes(&mut buf).expect("sized buffer");
            buf[AtpPacket::HEADER_LEN..].copy_from_slice(chunk);
            self.outbox.push_back((source, buf.clone()));
            packets.push(buf);
        }

        self.in_progress.retain(|(s, t)| !(*s == source && *t == tid));
        if self.reply_cache.len() == REPLY_CACHE_LEN {
            self.reply_cache.pop_front();
        }
        self.reply_cache.push_back(CachedResponse {
            source,
            tid,
            packets,
            expires_at: now + RELEASE_TIMEOUT,
        });
    }

    /// Feed a received DDP payload addressed to our socket.
    pub fn handle_datagram(&mut self, src: ServiceAddress, payload: &[u8], now: Micros) {
        let Ok(packet) = AtpPacket::parse(payload) else {
            return;
        };
        let data = &payload[AtpPacket::HEADER_LEN..];

        match packet.function {
            AtpFunction::Request => {
                // XO dedup: a request we already answered is a retransmit
                // whose response (or part of it) was lost - resend the cached
                // framing verbatim. One still being processed is not
                // re-delivered.
                if let Some(cached) = self
                    .reply_cache
                    .iter()
                    .find(|c| c.source == src && c.tid == packet.tid)
                {
                    let packets = cached.packets.clone();
                    for p in packets {
                        self.outbox.push_back((src, p));
                    }
                    return;
                }
                if packet.xo {
                    if self.in_progress.iter().any(|(s, t)| *s == src && *t == packet.tid) {
                        return;
                    }
                    if self.in_progress.len() >= REPLY_CACHE_LEN {
                        self.in_progress.pop_front();
                    }
                    self.in_progress.push_back((src, packet.tid));
                }
                // Classic Mac OS sends bitmap 0x00 meaning "no
                // restriction", so widen it to all eight slots rather than
                // treating it as a request for none.
                let bitmap = if packet.bitmap_seq_num == 0 {
                    0xFF
                } else {
                    packet.bitmap_seq_num
                };
                self.events.push_back(AtpEvent::Request {
                    source: src,
                    tid: packet.tid,
                    user_bytes: packet.user_bytes,
                    data: data.to_vec(),
                    bitmap,
                    xo: packet.xo,
                });
            }
            AtpFunction::Response => {
                let Some(state) = self.pending.get_mut(&packet.tid) else {
                    return;
                };
                state.received.insert(packet.bitmap_seq_num, data.to_vec());
                if state.user_bytes.is_none() {
                    state.user_bytes = Some(packet.user_bytes);
                }
                if packet.eom {
                    state.eom_seq = Some(packet.bitmap_seq_num);
                }
                let complete = if let Some(eom) = state.eom_seq {
                    (0..=eom).all(|i| state.received.contains_key(&i))
                } else {
                    // Filled every requested slot: complete without EOM, per
                    // the ATP spec.
                    !state.received.is_empty()
                        && state.received.len() == state.requested_bitmap.count_ones() as usize
                };
                if complete {
                    let state = self.pending.remove(&packet.tid).unwrap();
                    let expected = state
                        .eom_seq
                        .map(|e| e as usize + 1)
                        .unwrap_or(state.received.len());
                    let mut full = Vec::new();
                    for i in 0..expected as u8 {
                        match state.received.get(&i) {
                            Some(p) => full.extend_from_slice(p),
                            None => return, // hole; cannot happen per the check above
                        }
                    }
                    // TRel closes out our XO transaction so the responder can
                    // drop its cache entry.
                    let rel = AtpPacket {
                        function: AtpFunction::Release,
                        xo: false,
                        eom: false,
                        sts: false,
                        bitmap_seq_num: 0,
                        tid: packet.tid,
                        user_bytes: [0; 4],
                    };
                    let mut buf = [0u8; AtpPacket::HEADER_LEN];
                    rel.to_bytes(&mut buf).expect("sized buffer");
                    self.outbox.push_back((src, buf.to_vec()));

                    self.events.push_back(AtpEvent::Response {
                        handle: packet.tid,
                        user_bytes: state.user_bytes.unwrap_or([0; 4]),
                        data: full,
                    });
                }
            }
            AtpFunction::Release => {
                self.reply_cache
                    .retain(|c| !(c.source == src && c.tid == packet.tid));
            }
        }
        let _ = now;
    }

    pub fn next_deadline(&self) -> Option<Micros> {
        let retries = self.pending.values().map(|p| p.retry_at).min();
        let expiries = self.reply_cache.iter().map(|c| c.expires_at).min();
        match (retries, expiries) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Drive retransmission and cache expiry.
    pub fn poll(&mut self, now: Micros) {
        let mut failed = Vec::new();
        let mut resend = Vec::new();
        for (&tid, p) in self.pending.iter_mut() {
            if now < p.retry_at {
                continue;
            }
            p.retries += 1;
            p.retry_at = now + RETRY_INTERVAL;
            if p.retries > MAX_RETRIES {
                failed.push(tid);
            } else {
                resend.push((p.dest, p.raw_packet.clone()));
            }
        }
        for tid in failed {
            self.pending.remove(&tid);
            self.events.push_back(AtpEvent::RequestFailed { handle: tid });
        }
        for entry in resend {
            self.outbox.push_back(entry);
        }
        self.reply_cache.retain(|c| c.expires_at > now);
    }

    /// Next outgoing DDP payload `(destination, atp bytes)`, sent from
    /// `local_socket` with DDP type ATP.
    pub fn poll_transmit(&mut self) -> Option<(ServiceAddress, Vec<u8>)> {
        self.outbox.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<AtpEvent> {
        self.events.pop_front()
    }

    fn allocate_tid(&mut self) -> u16 {
        loop {
            let tid = self.next_tid;
            self.next_tid = self.next_tid.wrapping_add(1);
            if tid != 0 && !self.pending.contains_key(&tid) {
                return tid;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(node: u8, socket: u8) -> ServiceAddress {
        ServiceAddress {
            network_number: 0,
            node_number: node,
            socket_number: socket,
        }
    }

    fn shuttle(a: &mut AtpEndpoint, a_addr: ServiceAddress, b: &mut AtpEndpoint, b_addr: ServiceAddress, now: Micros) {
        loop {
            let mut progressed = false;
            while let Some((_, p)) = a.poll_transmit() {
                b.handle_datagram(a_addr, &p, now);
                progressed = true;
            }
            while let Some((_, p)) = b.poll_transmit() {
                a.handle_datagram(b_addr, &p, now);
                progressed = true;
            }
            if !progressed {
                return;
            }
        }
    }

    #[test]
    fn request_response_round_trip_with_release() {
        let ca = addr(1, 70);
        let sa = addr(2, 80);
        let mut client = AtpEndpoint::new(70);
        let mut server = AtpEndpoint::new(80);

        let handle = client.request(sa, [1, 2, 3, 4], b"query", 0xFF, 0);
        let (_, req_pkt) = client.poll_transmit().unwrap();
        server.handle_datagram(ca, &req_pkt, 0);

        let (source, tid) = match server.poll_event() {
            Some(AtpEvent::Request { source, tid, user_bytes, data, xo, .. }) => {
                assert_eq!(user_bytes, [1, 2, 3, 4]);
                assert_eq!(data, b"query");
                assert!(xo);
                (source, tid)
            }
            other => panic!("{other:?}"),
        };

        // Multi-packet response: 1300 bytes at 578 = 3 packets.
        let big = vec![7u8; 1300];
        server.respond(source, tid, [9, 9, 9, 9], &big, ATP_MAX_DATA_PER_PACKET, 0);
        shuttle(&mut client, ca, &mut server, sa, 10);

        match client.poll_event() {
            Some(AtpEvent::Response { handle: h, user_bytes, data }) => {
                assert_eq!(h, handle);
                assert_eq!(user_bytes, [9, 9, 9, 9]);
                assert_eq!(data, big);
            }
            other => panic!("{other:?}"),
        }
        // The TRel released the server's cache entry.
        assert!(server.reply_cache.is_empty());
    }

    #[test]
    fn duplicate_request_replays_cached_response_without_redelivery() {
        let ca = addr(1, 70);
        let sa = addr(2, 80);
        let mut client = AtpEndpoint::new(70);
        let mut server = AtpEndpoint::new(80);

        client.request(sa, [0; 4], b"once", 0x01, 0);
        let (_, req_pkt) = client.poll_transmit().unwrap();

        server.handle_datagram(ca, &req_pkt, 0);
        assert!(matches!(server.poll_event(), Some(AtpEvent::Request { .. })));

        // Retransmit before the response exists: not re-delivered.
        server.handle_datagram(ca, &req_pkt, 100);
        assert!(server.poll_event().is_none(), "in-progress dedup failed");

        let (source, tid) = (ca, 1);
        server.respond(source, tid, [0; 4], b"answer", 512, 100);
        let first: Vec<_> = core::iter::from_fn(|| server.poll_transmit()).collect();
        assert_eq!(first.len(), 1);

        // Retransmit after the response: replayed verbatim, not re-delivered.
        server.handle_datagram(ca, &req_pkt, 200);
        assert!(server.poll_event().is_none());
        let replay = server.poll_transmit().expect("cached replay").1;
        assert_eq!(replay, first[0].1);
    }

    #[test]
    fn requestor_retransmits_then_gives_up() {
        let sa = addr(2, 80);
        let mut client = AtpEndpoint::new(70);
        let handle = client.request(sa, [0; 4], &[], 0x01, 0);
        assert!(client.poll_transmit().is_some());

        let mut now;
        let mut resends = 0;
        loop {
            now = client.next_deadline().unwrap();
            client.poll(now);
            if client.poll_transmit().is_some() {
                resends += 1;
                continue;
            }
            match client.poll_event() {
                Some(AtpEvent::RequestFailed { handle: h }) => {
                    assert_eq!(h, handle);
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(resends, MAX_RETRIES as usize);
    }

    #[test]
    fn bitmap_full_completes_without_eom() {
        // A response that fills exactly the requested slots completes even
        // if the EOM-carrying packet was lost.
        let _ca = addr(1, 70);
        let sa = addr(2, 80);
        let mut client = AtpEndpoint::new(70);
        client.request(sa, [0; 4], &[], 0x03, 0); // two slots
        let _ = client.poll_transmit();

        // Hand-build two response packets WITHOUT EOM.
        for i in 0..2u8 {
            let pkt = AtpPacket {
                function: AtpFunction::Response,
                xo: false,
                eom: false,
                sts: false,
                bitmap_seq_num: i,
                tid: 1,
                user_bytes: [0; 4],
            };
            let mut buf = vec![0u8; AtpPacket::HEADER_LEN + 1];
            pkt.to_bytes(&mut buf).unwrap();
            buf[AtpPacket::HEADER_LEN] = i;
            client.handle_datagram(sa, &buf, 0);
        }
        match client.poll_event() {
            Some(AtpEvent::Response { data, .. }) => assert_eq!(data, vec![0, 1]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reply_cache_expires_on_timer() {
        let ca = addr(1, 70);
        let mut server = AtpEndpoint::new(80);
        server.respond(ca, 5, [0; 4], b"x", 512, 0);
        while server.poll_transmit().is_some() {}
        assert_eq!(server.reply_cache.len(), 1);
        server.poll(RELEASE_TIMEOUT + 1);
        assert!(server.reply_cache.is_empty());
    }
}
