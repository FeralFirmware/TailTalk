//! ADSP endpoint: connection handshake, sequenced data with EOM, receive
//! window flow control, attentions, and close.
//!
//! One [`AdspEndpoint`] owns every connection on a single DDP socket.
//!
//! Callers should set the advertised receive window
//! ([`AdspEndpoint::set_recv_window`]) rather than take the default: it is
//! the back pressure on a peer, and can be driven down to zero as the
//! caller's own output fills. [`DEFAULT_RECV_WINDOW`] is deliberately small,
//! so a host with memory to spare wants a larger one.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use byteorder_shim::{read_u16_be, write_u16_be};
use tailtalk_packets::adsp::{AdspDescriptor, AdspPacket};
use tailtalk_packets::nbp::ServiceAddress;

use crate::{Micros, Rand};

/// Max stream bytes per ADSP data packet: 586 bytes of DDP payload less the
/// 13-byte ADSP header, rounded down.
pub const ADSP_MAX_DATA: usize = 572;

/// Default advertised receive window. Small by design; hosts with memory to
/// spare should call [`AdspEndpoint::set_recv_window`] instead of taking it.
pub const DEFAULT_RECV_WINDOW: u16 = 1024;

const RETRANSMIT_TIMEOUT: Micros = 3_000_000;
const MAX_RETRIES: u8 = 5;
const OPEN_RETRY_INTERVAL: Micros = 1_000_000;
const MAX_OPEN_RETRIES: u8 = 5;
/// Attention retransmission, on the same schedule as stream data.
const ATTN_RETRY_INTERVAL: Micros = 1_000_000;
const MAX_ATTN_RETRIES: u8 = 5;

/// Minimal big-endian helpers so this module does not need the byteorder
/// crate's traits in scope everywhere.
mod byteorder_shim {
    pub fn read_u16_be(buf: &[u8]) -> u16 {
        u16::from_be_bytes([buf[0], buf[1]])
    }
    pub fn write_u16_be(buf: &mut [u8], v: u16) {
        buf[..2].copy_from_slice(&v.to_be_bytes());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdspEvent {
    /// A connection is established. `conn` keys every later call and event
    /// for it. `inbound` is true for connections a peer opened to us, false
    /// for our own connects completing.
    Opened {
        conn: u16,
        remote: ServiceAddress,
        inbound: bool,
        /// For outbound connections, the handle [`AdspEndpoint::connect`]
        /// returned, so a driver with several connects in flight can match
        /// them up. `None` for inbound connections.
        pending: Option<u16>,
    },
    /// An outbound connect gave up (retries exhausted or OpenConnDeny).
    OpenFailed { conn: u16 },
    /// In-sequence stream data arrived.
    Data { conn: u16, data: Vec<u8>, eom: bool },
    /// An attention message arrived (already acked at the ADSP level).
    Attention { conn: u16, code: u16, data: Vec<u8> },
    /// An attention we sent was acknowledged by the peer.
    AttentionAcked { conn: u16 },
    /// An attention we sent went unacknowledged through every retry.
    AttentionFailed { conn: u16 },
    /// The peer closed, or retransmission gave up.
    Closed { conn: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdspError {
    NoSuchConnection,
    /// Only one attention may be outstanding per connection (spec 12).
    AttentionInFlight,
}

struct PendingWrite {
    data: Vec<u8>,
    offset: usize,
    eom: bool,
}

/// An attention message awaiting its acknowledgement.
struct AttnInFlight {
    /// The attention sequence this message was sent with.
    seq: u32,
    /// The framed packet, resent verbatim on each retry.
    packet: Vec<u8>,
    last_tx: Micros,
    retries: u8,
}

struct PendingOpen {
    remote: ServiceAddress,
    last_tx: Micros,
    retries: u8,
}

struct Connection {
    /// Our ConnID, placed in every outgoing packet. Inbound packets carry
    /// the peer's ConnID, which is the map key.
    our_conn_id: u16,
    remote: ServiceAddress,
    send_seq: u32,
    oldest_unacked_seq: u32,
    recv_seq: u32,
    send_window: u16,
    flight_buffer: Vec<u8>,
    /// Marks EOM positions in the flight buffer + queue are implicit; EOM
    /// packets are cut when a PendingWrite with eom completes.
    pending_writes: VecDeque<PendingWrite>,
    last_tx: Micros,
    retries: u8,
    /// Our attention sequence space (spec: AttnSendSeq). Attentions ride a
    /// sequence space of their own, separate from the data stream's.
    attn_send_seq: u32,
    /// The attention sequence we expect next from the peer (AttnRecvSeq).
    /// A message arriving with any other sequence is a retransmission whose
    /// ack was lost: ack it again, but do not deliver it twice.
    attn_recv_seq: u32,
    /// An attention we sent and have not seen acked, kept for retransmission.
    attn_in_flight: Option<AttnInFlight>,
    /// Monotonic ids for queued writes; a write is "complete" once fully
    /// cut into packets (in flight, not necessarily acked). Callers that
    /// promise write-completion - an `AsyncWrite` flush, say - key off
    /// these.
    writes_submitted: u64,
    writes_completed: u64,
}

pub struct AdspEndpoint {
    local_socket: u8,
    /// Accept inbound OpenConnRequests. Off by default for pure clients.
    listening: bool,
    recv_window: u16,
    connections: BTreeMap<u16, Connection>,
    pending_opens: BTreeMap<u16, PendingOpen>,
    rng: Rand,
    outbox: VecDeque<(ServiceAddress, Vec<u8>)>,
    events: VecDeque<AdspEvent>,
}

impl AdspEndpoint {
    pub fn new(local_socket: u8, seed: u32) -> Self {
        Self {
            local_socket,
            listening: false,
            recv_window: DEFAULT_RECV_WINDOW,
            connections: BTreeMap::new(),
            pending_opens: BTreeMap::new(),
            rng: Rand::new(seed),
            outbox: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    pub fn local_socket(&self) -> u8 {
        self.local_socket
    }

    /// The remote address of an established connection.
    pub fn remote_of(&self, conn: u16) -> Option<ServiceAddress> {
        self.connections.get(&conn).map(|c| c.remote)
    }

    /// Accept inbound connections (a listener). Off by default.
    pub fn set_listening(&mut self, on: bool) {
        self.listening = on;
    }

    /// Set the advertised receive window. Track free space in the data sink
    /// and shrink toward zero rather than dropping; every outgoing packet
    /// carries the current value.
    ///
    /// Reopening a closed window is announced with an ack on every
    /// connection. A peer told zero stops sending, so nothing it sends will
    /// prompt a reply carrying the new window; a receiver with no data of
    /// its own would otherwise leave it waiting forever.
    pub fn set_recv_window(&mut self, window: u16) {
        let reopened = self.recv_window == 0 && window > 0;
        self.recv_window = window;
        if reopened {
            let keys: Vec<u16> = self.connections.keys().copied().collect();
            for key in keys {
                self.send_ack(key);
            }
        }
    }

    /// Begin an outbound connect. Returns the handle (our ConnID) that
    /// [`AdspEvent::Opened`] or [`AdspEvent::OpenFailed`] will later carry.
    pub fn connect(&mut self, remote: ServiceAddress, now: Micros) -> u16 {
        let conn_id = loop {
            let id = (self.rng.next_u32() & 0xFFFF) as u16;
            if id != 0 && !self.pending_opens.contains_key(&id) {
                break id;
            }
        };
        self.pending_opens.insert(
            conn_id,
            PendingOpen {
                remote,
                last_tx: now,
                retries: 0,
            },
        );
        self.send_open_request(conn_id, remote);
        conn_id
    }

    /// Bytes queued (window-blocked or unacked) toward the peer. Callers
    /// pacing a stream should hold off while this is large.
    pub fn tx_backlog(&self, conn: u16) -> usize {
        self.conn_by_handle(conn)
            .map(|c| {
                c.flight_buffer.len()
                    + c.pending_writes
                        .iter()
                        .map(|w| w.data.len() - w.offset)
                        .sum::<usize>()
            })
            .unwrap_or(0)
    }

    /// Queue stream data. `eom` marks a record boundary after the last byte.
    /// Returns this write's id; it counts as complete (fully cut into
    /// packets, see [`Self::writes_completed`]) once the peer's window has
    /// admitted every byte.
    pub fn send(&mut self, conn: u16, data: &[u8], eom: bool) -> Result<u64, AdspError> {
        let key = self.key_by_handle(conn).ok_or(AdspError::NoSuchConnection)?;
        let c = self.connections.get_mut(&key).unwrap();
        c.writes_submitted += 1;
        let id = c.writes_submitted;
        c.pending_writes.push_back(PendingWrite {
            data: data.to_vec(),
            offset: 0,
            eom,
        });
        self.pump(key, None);
        Ok(id)
    }

    /// How many of this connection's writes have been fully cut into
    /// packets. `None` when the connection no longer exists.
    pub fn writes_completed(&self, conn: u16) -> Option<u64> {
        self.connections.get(&conn).map(|c| c.writes_completed)
    }

    /// Send an out-of-band attention message.
    ///
    /// Only one attention may be outstanding per connection (spec 12,
    /// "Attention messages"), so this fails while a previous one is still
    /// unacknowledged. It is retransmitted until the peer acks it or the
    /// retry budget runs out, which surfaces as [`AdspEvent::AttentionFailed`].
    pub fn send_attention(
        &mut self,
        conn: u16,
        code: u16,
        data: &[u8],
        now: Micros,
    ) -> Result<(), AdspError> {
        let key = self.key_by_handle(conn).ok_or(AdspError::NoSuchConnection)?;
        let c = self.connections.get_mut(&key).unwrap();
        if c.attn_in_flight.is_some() {
            return Err(AdspError::AttentionInFlight);
        }
        let packet = build_attention(c.our_conn_id, c.attn_send_seq, c.attn_recv_seq, code, data);
        c.attn_in_flight = Some(AttnInFlight {
            seq: c.attn_send_seq,
            packet: packet.clone(),
            last_tx: now,
            retries: 0,
        });
        let remote = c.remote;
        self.outbox.push_back((remote, packet));
        Ok(())
    }

    /// Close a connection: send CloseAdvice and forget it.
    pub fn close(&mut self, conn: u16) {
        let Some(key) = self.key_by_handle(conn) else {
            return;
        };
        let c = self.connections.remove(&key).unwrap();
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::CloseAdvice,
            connection_id: c.our_conn_id,
            first_byte_seq: c.send_seq,
            next_recv_seq: c.recv_seq,
            recv_window: 0,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        pkt.to_bytes(&mut buf).expect("sized buffer");
        self.outbox.push_back((c.remote, buf.to_vec()));
    }

    /// Feed a received DDP payload addressed to our socket.
    pub fn handle_datagram(&mut self, src: ServiceAddress, payload: &[u8], now: Micros) {
        let Ok(packet) = AdspPacket::parse(payload) else {
            return;
        };
        let data = &payload[AdspPacket::HEADER_LEN..];

        if packet.flags & AdspPacket::FLAG_ATTENTION != 0 {
            // Two packets share the Attention flag: a message (a data packet
            // whose payload is a 2-byte code plus body) and an acknowledgement
            // (a control packet retiring one we sent). Acking an ack would
            // bounce forever, and delivering an ack as a message would hand
            // the application a phantom attention.
            if packet.flags & AdspPacket::FLAG_CONTROL != 0
                || packet.descriptor == AdspDescriptor::ControlPacket
            {
                self.handle_attention_ack(packet);
            } else {
                self.handle_attention(packet, data);
            }
            return;
        }

        match packet.descriptor {
            AdspDescriptor::OpenConnRequest => self.handle_open_request(src, packet, now),
            AdspDescriptor::OpenConnAck | AdspDescriptor::OpenConnReqAck => {
                self.handle_open_ack(src, packet, payload, now)
            }
            AdspDescriptor::OpenConnDeny => {
                // DestConnID in the params echoes our pending ConnID.
                let our_id = if payload.len() >= 17 {
                    read_u16_be(&payload[15..17])
                } else {
                    packet.connection_id
                };
                if self.pending_opens.remove(&our_id).is_some() {
                    self.events.push_back(AdspEvent::OpenFailed { conn: our_id });
                }
            }
            AdspDescriptor::DataPacket | AdspDescriptor::ControlPacket => {
                self.handle_data(packet, data, now)
            }
            AdspDescriptor::RetransmitAdvice => {
                let key = packet.connection_id;
                self.apply_ack(packet, now);
                self.resend_unacked(key, now);
            }
            AdspDescriptor::CloseAdvice
                if self.connections.remove(&packet.connection_id).is_some() =>
            {
                self.events.push_back(AdspEvent::Closed {
                    conn: packet.connection_id,
                });
            }
            _ => {}
        }
    }

    /// Deadline of the next timed action.
    pub fn next_deadline(&self) -> Option<Micros> {
        let retrans = self
            .connections
            .values()
            .filter(|c| !c.flight_buffer.is_empty())
            .map(|c| c.last_tx + RETRANSMIT_TIMEOUT)
            .min();
        let opens = self
            .pending_opens
            .values()
            .map(|o| o.last_tx + OPEN_RETRY_INTERVAL)
            .min();
        let attns = self
            .connections
            .values()
            .filter_map(|c| c.attn_in_flight.as_ref())
            .map(|a| a.last_tx + ATTN_RETRY_INTERVAL)
            .min();
        [retrans, opens, attns]
            .into_iter()
            .flatten()
            .min()
    }

    /// Drive retransmission timers.
    pub fn poll(&mut self, now: Micros) {
        // Open request retries.
        let mut failed: Vec<u16> = Vec::new();
        let mut retry: Vec<(u16, ServiceAddress)> = Vec::new();
        for (&id, open) in self.pending_opens.iter_mut() {
            if now.saturating_sub(open.last_tx) < OPEN_RETRY_INTERVAL {
                continue;
            }
            open.retries += 1;
            if open.retries > MAX_OPEN_RETRIES {
                failed.push(id);
            } else {
                open.last_tx = now;
                retry.push((id, open.remote));
            }
        }
        for id in failed {
            self.pending_opens.remove(&id);
            self.events.push_back(AdspEvent::OpenFailed { conn: id });
        }
        for (id, remote) in retry {
            self.send_open_request(id, remote);
        }

        // Attention retransmission. Only one attention can be outstanding
        // per connection, so this is at most one packet each.
        let keys: Vec<u16> = self.connections.keys().copied().collect();
        for key in keys {
            let c = self.connections.get_mut(&key).unwrap();
            let Some(attn) = c.attn_in_flight.as_mut() else {
                continue;
            };
            if now.saturating_sub(attn.last_tx) < ATTN_RETRY_INTERVAL {
                continue;
            }
            attn.retries += 1;
            if attn.retries > MAX_ATTN_RETRIES {
                c.attn_in_flight = None;
                self.events.push_back(AdspEvent::AttentionFailed { conn: key });
                continue;
            }
            attn.last_tx = now;
            let packet = attn.packet.clone();
            let remote = c.remote;
            self.outbox.push_back((remote, packet));
        }

        // Data retransmission.
        let keys: Vec<u16> = self.connections.keys().copied().collect();
        for key in keys {
            let c = self.connections.get_mut(&key).unwrap();
            if c.flight_buffer.is_empty() || now.saturating_sub(c.last_tx) < RETRANSMIT_TIMEOUT {
                continue;
            }
            // Saturating because `retries` is a `u8`: a give-up branch
            // that only set a flag would let the tick re-enter every second
            // until the counter wrapped. Removal below makes that
            // unreachable here; the
            // saturation keeps it unreachable if the removal ever moves.
            c.retries = c.retries.saturating_add(1);
            if c.retries > MAX_RETRIES {
                self.connections.remove(&key);
                self.events.push_back(AdspEvent::Closed { conn: key });
                continue;
            }
            self.resend_unacked(key, now);
        }
    }

    /// Next outgoing DDP payload: `(destination, adsp packet bytes)`. The
    /// caller sends it from `local_socket` with DDP type ADSP.
    pub fn poll_transmit(&mut self) -> Option<(ServiceAddress, Vec<u8>)> {
        self.outbox.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<AdspEvent> {
        self.events.pop_front()
    }

    // Connections are keyed by the peer's ConnID (what inbound packets
    // carry). Events and API calls use the same key, so the handle IS the
    // key; pending outbound opens use our ConnID until the ack arrives.
    fn conn_by_handle(&self, handle: u16) -> Option<&Connection> {
        self.connections.get(&handle)
    }

    fn key_by_handle(&self, handle: u16) -> Option<u16> {
        self.connections.contains_key(&handle).then_some(handle)
    }

    fn send_open_request(&mut self, conn_id: u16, remote: ServiceAddress) {
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::OpenConnRequest,
            connection_id: conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: self.recv_window,
            flags: 0,
        };
        // Header + 8-byte open-conn params (Inside AppleTalk Figure 12-11):
        // version 0x0100, DestConnID 0 (unknown yet), attention recv seq.
        let mut buf = [0u8; AdspPacket::HEADER_LEN + 8];
        pkt.to_bytes(&mut buf).expect("sized buffer");
        write_u16_be(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
        self.outbox.push_back((remote, buf.to_vec()));
    }

    fn handle_open_request(&mut self, src: ServiceAddress, packet: AdspPacket, now: Micros) {
        if !self.listening {
            return;
        }
        let client_conn_id = packet.connection_id;
        if self.connections.contains_key(&client_conn_id) {
            // Retransmitted open (our ReqAck was lost): re-ack, don't reopen.
            let our_id = self.connections[&client_conn_id].our_conn_id;
            self.send_open_reply(
                AdspDescriptor::OpenConnReqAck,
                our_id,
                client_conn_id,
                src,
            );
            return;
        }
        let our_conn_id = (self.rng.next_u32() & 0xFFFF) as u16 | 1;
        self.connections.insert(
            client_conn_id,
            Connection::new(our_conn_id, src, packet.recv_window, now),
        );
        self.send_open_reply(
            AdspDescriptor::OpenConnReqAck,
            our_conn_id,
            client_conn_id,
            src,
        );
        self.events.push_back(AdspEvent::Opened {
            conn: client_conn_id,
            remote: src,
            inbound: true,
            pending: None,
        });
    }

    fn handle_open_ack(&mut self, src: ServiceAddress, packet: AdspPacket, payload: &[u8], now: Micros) {
        // Our ConnID is echoed in the open-conn params' DestConnID field
        // (bytes 2-3 of the 8-byte block after the header).
        let server_conn_id = packet.connection_id;
        let our_conn_id = if payload.len() >= 17 {
            read_u16_be(&payload[15..17])
        } else {
            server_conn_id
        };
        // Only an OpenConnReqAck (the second leg) is answered. The third
        // leg, OpenConnAck, completes the handshake and must never be
        // replied to: both ends would see an established connection and
        // acknowledge each other's acknowledgement forever.
        let is_req_ack = packet.descriptor == AdspDescriptor::OpenConnReqAck;

        if self.connections.contains_key(&server_conn_id) {
            // Already established under this key. If the peer is repeating
            // its OpenConnReqAck, repeat our OpenConnAck; otherwise this is
            // the peer completing the handshake and there is nothing to do.
            if is_req_ack {
                self.send_open_reply(
                    AdspDescriptor::OpenConnAck,
                    our_conn_id,
                    server_conn_id,
                    src,
                );
            }
            return;
        }

        if self.pending_opens.remove(&our_conn_id).is_none() {
            // No pending open, yet the peer says this answers one of ours.
            // That happens when a peer answers our retransmitted
            // OpenConnRequest by opening a SECOND connection instead of
            // re-acknowledging the first: two OpenConnReqAcks arrive with
            // the same DestConnID but different peer ConnIDs, and the peer
            // then talks only on the newer one. Connections are keyed by
            // the peer's ConnID, so keeping the first leaves us deaf to
            // every packet that follows - the open completes and then
            // nothing works.
            //
            // tailtalk's own ADSP no longer does this (it re-acks the
            // existing connection), but that is a courtesy from one
            // implementation, not a guarantee from the wire, so move the
            // connection to the key the peer is actually using.
            let stale = self
                .connections
                .iter()
                .find(|(_, c)| c.our_conn_id == our_conn_id)
                .map(|(k, _)| *k);
            let Some(stale) = stale else {
                return; // not ours at all
            };
            let conn = self.connections.remove(&stale).expect("just found");
            self.connections.insert(server_conn_id, conn);
            self.send_open_reply(AdspDescriptor::OpenConnAck, our_conn_id, server_conn_id, src);
            // Re-announce so the application re-latches onto the new key.
            self.events.push_back(AdspEvent::Opened {
                conn: server_conn_id,
                remote: src,
                inbound: false,
                pending: Some(our_conn_id),
            });
            return;
        }

        self.connections.insert(
            server_conn_id,
            Connection::new(our_conn_id, src, packet.recv_window, now),
        );
        // Complete the 3-way handshake, but only if this was the second
        // leg; see is_req_ack above.
        if is_req_ack {
            self.send_open_reply(AdspDescriptor::OpenConnAck, our_conn_id, server_conn_id, src);
        }
        self.events.push_back(AdspEvent::Opened {
            conn: server_conn_id,
            remote: src,
            inbound: false,
            pending: Some(our_conn_id),
        });
    }

    fn send_open_reply(
        &mut self,
        descriptor: AdspDescriptor,
        our_conn_id: u16,
        dest_conn_id: u16,
        remote: ServiceAddress,
    ) {
        let pkt = AdspPacket {
            descriptor,
            connection_id: our_conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: self.recv_window,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN + 8];
        pkt.to_bytes(&mut buf).expect("sized buffer");
        write_u16_be(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
        write_u16_be(&mut buf[AdspPacket::HEADER_LEN + 2..], dest_conn_id);
        self.outbox.push_back((remote, buf.to_vec()));
    }

    /// An inbound attention *message*: deliver it if fresh, then ack.
    fn handle_attention(&mut self, packet: AdspPacket, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let key = packet.connection_id;
        let Some(c) = self.connections.get_mut(&key) else {
            return;
        };
        let code = read_u16_be(&data[0..2]);

        // Attentions ride their own sequence space. A message whose sequence
        // is the one we expect is new; anything else is the peer resending
        // after a lost ack, so ack again without delivering twice.
        let fresh = packet.first_byte_seq == c.attn_recv_seq;
        if fresh {
            c.attn_recv_seq = c.attn_recv_seq.wrapping_add(1);
        }

        // Attention-control packet: descriptor 0x90 = Control | Attention,
        // carrying our attention sequence numbers. Per spec it must not set
        // AckReq (acking an ack would loop) and its window must be 0, since
        // only one attention may be outstanding. The peer retires its message
        // by checking that next_recv_seq is one past the sequence it sent,
        // which is exactly what attn_recv_seq now holds.
        let ack = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: c.our_conn_id,
            first_byte_seq: c.attn_send_seq,
            next_recv_seq: c.attn_recv_seq,
            recv_window: 0,
            flags: AdspPacket::FLAG_ATTENTION,
        };
        let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 2];
        ack.to_bytes(&mut buf).expect("sized buffer");
        write_u16_be(&mut buf[AdspPacket::HEADER_LEN..], code);
        let remote = c.remote;

        self.outbox.push_back((remote, buf));
        if fresh {
            self.events.push_back(AdspEvent::Attention {
                conn: key,
                code,
                data: data[2..].to_vec(),
            });
        }
    }

    /// An inbound attention *acknowledgement*: retire the message it names.
    ///
    /// It must not touch data-stream flow control: attention packets carry a
    /// zero window by spec, so feeding one through the data ack path would
    /// clobber the peer's real window and wedge every later write.
    fn handle_attention_ack(&mut self, packet: AdspPacket) {
        let Some(c) = self.connections.get_mut(&packet.connection_id) else {
            return;
        };
        let Some(in_flight) = c.attn_in_flight.as_ref() else {
            return;
        };
        // The peer counts the message it accepted, so a valid ack names one
        // past the sequence we sent. Anything else is stale or duplicate.
        if packet.next_recv_seq != in_flight.seq.wrapping_add(1) {
            return;
        }
        c.attn_in_flight = None;
        c.attn_send_seq = c.attn_send_seq.wrapping_add(1);
        self.events
            .push_back(AdspEvent::AttentionAcked { conn: packet.connection_id });
    }

    fn handle_data(&mut self, packet: AdspPacket, data: &[u8], now: Micros) {
        let key = packet.connection_id;
        let Some(c) = self.connections.get_mut(&key) else {
            return;
        };

        // EOM consumes one byte of sequence space even with no payload,
        // like a TCP FIN.
        let eom = packet.flags & AdspPacket::FLAG_EOM != 0;
        let eom_seq_bump: u32 = if eom { 1 } else { 0 };
        let total_len = data.len() as u32 + eom_seq_bump;
        if total_len > 0 {
            // Sequence-validate before delivering: duplicates must not
            // deliver twice, and data beyond a hole must not be acked or the
            // peer never resends the hole.
            let diff = c.recv_seq.wrapping_sub(packet.first_byte_seq) as i32;
            if diff < 0 {
                // Beyond a hole: drop; our ack below restates recv_seq.
            } else if (diff as u32) < total_len {
                let skip = (diff as usize).min(data.len());
                let fresh = &data[skip..];
                c.recv_seq = packet.first_byte_seq.wrapping_add(total_len);
                if !fresh.is_empty() || eom {
                    self.events.push_back(AdspEvent::Data {
                        conn: key,
                        data: fresh.to_vec(),
                        eom,
                    });
                }
            }
            // else: pure duplicate, drop.
        }

        let wants_ack = packet.flags & AdspPacket::FLAG_ACK != 0;
        self.apply_ack(packet, now);

        // Reply with an ack only when asked (AckReq), per spec. Acking
        // unconditionally turns two of these endpoints facing each other
        // into an ack storm.
        if wants_ack {
            self.send_ack(key);
        }
        self.pump(key, Some(now));
    }

    fn apply_ack(&mut self, packet: AdspPacket, now: Micros) {
        let Some(c) = self.connections.get_mut(&packet.connection_id) else {
            return;
        };
        c.send_window = packet.recv_window;
        // Valid ack range is bounded by send_seq (which counts EOM's phantom
        // byte), not the flight buffer length.
        let max_valid = c.send_seq.wrapping_sub(c.oldest_unacked_seq) as usize;
        let acked = packet.next_recv_seq.wrapping_sub(c.oldest_unacked_seq) as usize;
        if acked > 0 && acked <= max_valid {
            let drain = acked.min(c.flight_buffer.len());
            c.flight_buffer.drain(..drain);
            c.oldest_unacked_seq = packet.next_recv_seq;
            c.retries = 0;
        }
        let key = packet.connection_id;
        self.pump(key, Some(now));
    }

    fn send_ack(&mut self, key: u16) {
        let Some(c) = self.connections.get(&key) else {
            return;
        };
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: c.our_conn_id,
            first_byte_seq: c.send_seq,
            next_recv_seq: c.recv_seq,
            recv_window: self.recv_window,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        pkt.to_bytes(&mut buf).expect("sized buffer");
        self.outbox.push_back((c.remote, buf.to_vec()));
    }

    /// Push queued writes into the window: cut data packets while the peer's
    /// receive window has room.
    fn pump(&mut self, key: u16, now: Option<Micros>) {
        loop {
            let Some(c) = self.connections.get_mut(&key) else {
                return;
            };
            let Some(front) = c.pending_writes.front_mut() else {
                return;
            };
            let in_flight = c.send_seq.wrapping_sub(c.oldest_unacked_seq);
            let available = (c.send_window as u32).saturating_sub(in_flight) as usize;

            let remaining = front.data.len() - front.offset;
            if remaining == 0 && front.eom {
                // Bare EOM: consumes a phantom sequence byte, no window need.
                let pkt = AdspPacket {
                    descriptor: AdspDescriptor::DataPacket,
                    connection_id: c.our_conn_id,
                    first_byte_seq: c.send_seq,
                    next_recv_seq: c.recv_seq,
                    recv_window: self.recv_window,
                    flags: AdspPacket::FLAG_ACK | AdspPacket::FLAG_EOM,
                };
                let mut buf = [0u8; AdspPacket::HEADER_LEN];
                pkt.to_bytes(&mut buf).expect("sized buffer");
                let remote = c.remote;
                c.send_seq = c.send_seq.wrapping_add(1);
                if let Some(now) = now {
                    c.last_tx = now;
                }
                c.pending_writes.pop_front();
                c.writes_completed += 1;
                self.outbox.push_back((remote, buf.to_vec()));
                continue;
            }
            if remaining == 0 {
                c.pending_writes.pop_front();
                c.writes_completed += 1;
                continue;
            }
            if available == 0 {
                return;
            }

            let take = remaining.min(available).min(ADSP_MAX_DATA);
            let is_last_chunk = take == remaining;
            let eom_flag = if front.eom && is_last_chunk {
                AdspPacket::FLAG_EOM
            } else {
                0
            };
            let chunk = front.data[front.offset..front.offset + take].to_vec();
            front.offset += take;
            let done = front.offset == front.data.len();

            let pkt = AdspPacket {
                descriptor: AdspDescriptor::DataPacket,
                connection_id: c.our_conn_id,
                first_byte_seq: c.send_seq,
                next_recv_seq: c.recv_seq,
                recv_window: self.recv_window,
                flags: AdspPacket::FLAG_ACK | eom_flag,
            };
            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
            pkt.to_bytes(&mut buf).expect("sized buffer");
            buf[AdspPacket::HEADER_LEN..].copy_from_slice(&chunk);

            c.flight_buffer.extend_from_slice(&chunk);
            let eom_seq_bump = if eom_flag != 0 { 1 } else { 0 };
            c.send_seq = c.send_seq.wrapping_add(chunk.len() as u32 + eom_seq_bump);
            if let Some(now) = now {
                c.last_tx = now;
            }
            if done {
                c.pending_writes.pop_front();
                c.writes_completed += 1;
            }
            let remote = c.remote;
            self.outbox.push_back((remote, buf));
        }
    }

    fn resend_unacked(&mut self, key: u16, now: Micros) {
        let Some(c) = self.connections.get_mut(&key) else {
            return;
        };
        if c.flight_buffer.is_empty() {
            return;
        }
        let data = c.flight_buffer.clone();
        let oldest = c.oldest_unacked_seq;
        for (i, chunk) in data.chunks(ADSP_MAX_DATA).enumerate() {
            let pkt = AdspPacket {
                descriptor: AdspDescriptor::DataPacket,
                connection_id: c.our_conn_id,
                first_byte_seq: oldest.wrapping_add((i * ADSP_MAX_DATA) as u32),
                next_recv_seq: c.recv_seq,
                recv_window: self.recv_window,
                flags: AdspPacket::FLAG_ACK,
            };
            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
            pkt.to_bytes(&mut buf).expect("sized buffer");
            buf[AdspPacket::HEADER_LEN..].copy_from_slice(chunk);
            let remote = c.remote;
            self.outbox.push_back((remote, buf));
        }
        c.last_tx = now;
    }
}

/// Frame an attention message: header plus the 2-byte code and body.
///
/// Per spec the header carries the attention sequence space (not the data
/// stream's) and a zero window, and sets AckReq so the peer answers.
fn build_attention(
    our_conn_id: u16,
    attn_send_seq: u32,
    attn_recv_seq: u32,
    code: u16,
    data: &[u8],
) -> Vec<u8> {
    let pkt = AdspPacket {
        descriptor: AdspDescriptor::DataPacket,
        connection_id: our_conn_id,
        first_byte_seq: attn_send_seq,
        next_recv_seq: attn_recv_seq,
        recv_window: 0,
        flags: AdspPacket::FLAG_ACK | AdspPacket::FLAG_ATTENTION,
    };
    let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 2 + data.len()];
    pkt.to_bytes(&mut buf).expect("sized buffer");
    write_u16_be(&mut buf[AdspPacket::HEADER_LEN..], code);
    buf[AdspPacket::HEADER_LEN + 2..].copy_from_slice(data);
    buf
}

impl Connection {
    fn new(our_conn_id: u16, remote: ServiceAddress, peer_window: u16, now: Micros) -> Self {
        Self {
            our_conn_id,
            remote,
            send_seq: 0,
            oldest_unacked_seq: 0,
            recv_seq: 0,
            send_window: peer_window,
            flight_buffer: Vec::new(),
            pending_writes: VecDeque::new(),
            last_tx: now,
            retries: 0,
            attn_send_seq: 0,
            attn_recv_seq: 0,
            attn_in_flight: None,
            writes_submitted: 0,
            writes_completed: 0,
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

    /// Pipe every queued transmit from `a` into `b` and vice versa until
    /// both are drained. Returns the number of packets moved.
    fn shuttle(a: &mut AdspEndpoint, a_addr: ServiceAddress, b: &mut AdspEndpoint, b_addr: ServiceAddress, now: Micros) -> usize {
        let mut moved = 0;
        loop {
            let mut progressed = false;
            while let Some((dest, payload)) = a.poll_transmit() {
                assert_eq!(dest.node_number, b_addr.node_number);
                b.handle_datagram(a_addr, &payload, now);
                moved += 1;
                progressed = true;
            }
            while let Some((dest, payload)) = b.poll_transmit() {
                assert_eq!(dest.node_number, a_addr.node_number);
                a.handle_datagram(b_addr, &payload, now);
                moved += 1;
                progressed = true;
            }
            if !progressed {
                return moved;
            }
        }
    }

    fn connect_pair() -> (AdspEndpoint, ServiceAddress, AdspEndpoint, ServiceAddress, u16, u16) {
        let ca = addr(10, 70);
        let sa = addr(20, 80);
        let mut client = AdspEndpoint::new(70, 111);
        let mut server = AdspEndpoint::new(80, 222);
        server.set_listening(true);

        client.connect(sa, 0);
        shuttle(&mut client, ca, &mut server, sa, 0);

        let server_conn = match server.poll_event() {
            Some(AdspEvent::Opened { conn, remote, .. }) => {
                assert_eq!(remote.node_number, 10);
                conn
            }
            other => panic!("server expected Opened, got {other:?}"),
        };
        let client_conn = match client.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("client expected Opened, got {other:?}"),
        };
        (client, ca, server, sa, client_conn, server_conn)
    }

    #[test]
    fn handshake_data_eom_and_close() {
        let (mut client, ca, mut server, sa, client_conn, server_conn) = connect_pair();

        client.send(client_conn, b"hello printer", true).unwrap();
        shuttle(&mut client, ca, &mut server, sa, 1000);
        match server.poll_event() {
            Some(AdspEvent::Data { conn, data, eom }) => {
                assert_eq!(conn, server_conn);
                assert_eq!(data, b"hello printer");
                assert!(eom);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // Reply the other way.
        server.send(server_conn, b"ok", false).unwrap();
        shuttle(&mut client, ca, &mut server, sa, 2000);
        assert!(matches!(
            client.poll_event(),
            Some(AdspEvent::Data { data, eom: false, .. }) if data == b"ok"
        ));

        // Flight buffers drained by the acks: nothing left to retransmit.
        assert_eq!(client.tx_backlog(client_conn), 0);
        assert_eq!(server.tx_backlog(server_conn), 0);

        server.close(server_conn);
        shuttle(&mut client, ca, &mut server, sa, 3000);
        assert!(matches!(client.poll_event(), Some(AdspEvent::Closed { .. })));
    }

    #[test]
    fn attention_is_delivered_acked_and_deduped() {
        let (mut client, ca, mut server, _sa, client_conn, server_conn) = connect_pair();

        client
            .send_attention(client_conn, 0x000B, &[0, 0, 0, 72, 3, b'B', b'o', b'b'], 0)
            .unwrap();
        // Capture the attention packet so we can replay it (a retransmit).
        let (dest, attn_pkt) = client.poll_transmit().unwrap();
        assert_eq!(dest.node_number, 20);
        server.handle_datagram(ca, &attn_pkt, 100);

        match server.poll_event() {
            Some(AdspEvent::Attention { conn, code, data }) => {
                assert_eq!(conn, server_conn);
                assert_eq!(code, 0x000B);
                assert_eq!(data[3], 72);
            }
            other => panic!("expected Attention, got {other:?}"),
        }
        // The ack went out.
        let (_, ack) = server.poll_transmit().unwrap();
        let hdr = AdspPacket::parse(&ack).unwrap();
        assert_ne!(hdr.flags & AdspPacket::FLAG_ATTENTION, 0);
        assert_eq!(hdr.descriptor, AdspDescriptor::ControlPacket);

        // Retransmitted attention (same seq): acked again, delivered once.
        server.handle_datagram(ca, &attn_pkt, 200);
        assert!(server.poll_transmit().is_some(), "retransmit still acked");
        assert!(server.poll_event().is_none(), "no duplicate delivery");
    }

    /// The sender has to learn its attention landed, not just that it did
    /// not fail. A driver that resolves a caller's `send_attention` future
    /// has nothing else to resolve it on: success is silent otherwise, and
    /// the only other signal, `AttentionFailed`, arrives a retry budget
    /// later.
    #[test]
    fn an_acknowledged_attention_is_reported_to_the_sender() {
        let (mut client, ca, mut server, sa, client_conn, _server_conn) = connect_pair();

        client
            .send_attention(client_conn, 0x0006, &[0x00], 0)
            .unwrap();
        shuttle(&mut client, ca, &mut server, sa, 100);

        let acked = core::iter::from_fn(|| client.poll_event())
            .any(|e| e == AdspEvent::AttentionAcked { conn: client_conn });
        assert!(acked, "the ack must surface as an event");

        // And a second attention is now permitted, the first being settled.
        assert!(client.send_attention(client_conn, 0x0006, &[0x00], 200).is_ok());
    }

    /// An attention that is never acknowledged must not report success.
    #[test]
    fn an_unacknowledged_attention_reports_only_failure() {
        let (mut client, _ca, _server, _sa, client_conn, _sc) = connect_pair();

        client
            .send_attention(client_conn, 0x0006, &[0x00], 0)
            .unwrap();
        // Never deliver it; run past the whole retry budget.
        let mut now = 0;
        for _ in 0..(MAX_ATTN_RETRIES as u64 + 2) {
            now += ATTN_RETRY_INTERVAL + 1;
            client.poll(now);
            while client.poll_transmit().is_some() {}
        }

        let events: Vec<_> = core::iter::from_fn(|| client.poll_event()).collect();
        assert!(
            !events.iter().any(|e| matches!(e, AdspEvent::AttentionAcked { .. })),
            "an unacknowledged attention must never report success: {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(e, AdspEvent::AttentionFailed { .. })),
            "it must report failure instead: {events:?}"
        );
    }

    /// Unacknowledged data must eventually give up, and giving up must
    /// remove the connection rather than flag it - a connection left in the
    /// map with a full flight buffer is re-examined on every tick forever.
    #[test]
    fn unacknowledged_data_gives_up_and_removes_the_connection() {
        let (mut client, _ca, _server, _sa, client_conn, _sc) = connect_pair();

        client.send(client_conn, b"never acked", false).unwrap();
        let mut now = 0;
        for _ in 0..(MAX_RETRIES as u64 + 2) {
            now += RETRANSMIT_TIMEOUT + 1;
            client.poll(now);
            while client.poll_transmit().is_some() {}
        }

        let closed = core::iter::from_fn(|| client.poll_event())
            .any(|e| e == AdspEvent::Closed { conn: client_conn });
        assert!(closed, "giving up must report the connection closed");
        assert_eq!(
            client.writes_completed(client_conn),
            None,
            "and must not leave the connection in the map"
        );

        // Further ticks must find nothing to do, rather than re-entering
        // the give-up branch on a connection that never went away.
        now += RETRANSMIT_TIMEOUT + 1;
        client.poll(now);
        assert!(client.poll_event().is_none(), "teardown must happen once");
    }

    #[test]
    fn zero_window_blocks_until_reopened() {
        let (mut client, ca, mut server, sa, client_conn, server_conn) = connect_pair();

        // Server slams its window shut and tells the client (via an ack).
        server.set_recv_window(0);
        server.send(server_conn, b"", false).unwrap(); // no-op, no packet
        // Provoke a window update: send data client->server; server acks
        // with window 0.
        client.send(client_conn, b"x", false).unwrap();
        shuttle(&mut client, ca, &mut server, sa, 100);
        while server.poll_event().is_some() {}

        // Client queues more data; window 0 means nothing may fly.
        client.send(client_conn, b"blocked bytes", false).unwrap();
        assert!(client.poll_transmit().is_none(), "window is closed");
        assert_eq!(client.tx_backlog(client_conn), 13);

        // Server reopens the window and acks; client resumes.
        server.set_recv_window(512);
        server.send(server_conn, b"go", false).unwrap();
        shuttle(&mut client, ca, &mut server, sa, 200);
        assert!(matches!(
            server.poll_event(),
            Some(AdspEvent::Data { data, .. }) if data == b"blocked bytes"
        ));
        assert_eq!(client.tx_backlog(client_conn), 0);
    }

    #[test]
    fn reopened_window_is_announced_without_data() {
        let (mut client, ca, mut server, sa, client_conn, _server_conn) = connect_pair();

        // Server closes its window and the client hears about it.
        server.set_recv_window(0);
        client.send(client_conn, b"x", false).unwrap();
        shuttle(&mut client, ca, &mut server, sa, 100);
        while server.poll_event().is_some() {}
        client.send(client_conn, b"blocked", false).unwrap();
        assert!(client.poll_transmit().is_none(), "window is closed");

        // The server reopens and has nothing of its own to say. The reopen
        // alone must get the client moving again.
        server.set_recv_window(512);
        shuttle(&mut client, ca, &mut server, sa, 200);
        assert!(matches!(
            server.poll_event(),
            Some(AdspEvent::Data { data, .. }) if data == b"blocked"
        ));
        assert_eq!(client.tx_backlog(client_conn), 0);
    }

    #[test]
    fn lost_data_is_retransmitted() {
        let (mut client, ca, mut server, sa, client_conn, _server_conn) = connect_pair();

        client.send(client_conn, b"lost", false).unwrap();
        // Drop the packet on the floor.
        let _ = client.poll_transmit().unwrap();
        assert_eq!(client.tx_backlog(client_conn), 4);

        // Time passes; the retransmit timer fires.
        let deadline = client.next_deadline().expect("retransmit scheduled");
        client.poll(deadline);
        shuttle(&mut client, ca, &mut server, sa, deadline);
        assert!(matches!(
            server.poll_event(),
            Some(AdspEvent::Data { data, .. }) if data == b"lost"
        ));
        assert_eq!(client.tx_backlog(client_conn), 0, "ack drained flight buffer");
    }

    #[test]
    fn duplicate_data_is_not_delivered_twice() {
        let (mut client, ca, mut server, _sa, client_conn, _sc) = connect_pair();

        client.send(client_conn, b"once", false).unwrap();
        let (_, pkt) = client.poll_transmit().unwrap();
        server.handle_datagram(ca, &pkt, 100);
        assert!(matches!(server.poll_event(), Some(AdspEvent::Data { .. })));

        server.handle_datagram(ca, &pkt, 200);
        assert!(server.poll_event().is_none(), "duplicate delivered");
    }

    /// A peer that answers a retransmitted OpenConnRequest by opening a
    /// SECOND connection sends two OpenConnReqAcks with the same
    /// DestConnID but different peer ConnIDs, then talks only on the newer
    /// one. Connections are keyed by the peer's ConnID, so tracking the
    /// first leaves the endpoint deaf to everything after the handshake -
    /// observed on real hardware as a connection that opens and then
    /// silently carries nothing.
    #[test]
    fn duplicate_open_ack_rekeys_to_the_connection_the_peer_uses() {
        let sa = addr(20, 80);
        let mut client = AdspEndpoint::new(70, 3);
        let our_conn = client.connect(sa, 0);
        let _ = client.poll_transmit().expect("OpenConnRequest");

        // Hand-build the two OpenConnReqAcks the peer would send.
        let req_ack = |peer_conn: u16| {
            let pkt = AdspPacket {
                descriptor: AdspDescriptor::OpenConnReqAck,
                connection_id: peer_conn,
                first_byte_seq: 0,
                next_recv_seq: 0,
                recv_window: 1024,
                flags: 0,
            };
            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 8];
            pkt.to_bytes(&mut buf).unwrap();
            write_u16_be(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
            write_u16_be(&mut buf[AdspPacket::HEADER_LEN + 2..], our_conn);
            buf
        };

        client.handle_datagram(sa, &req_ack(0x919C), 10);
        let first = match client.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("expected Opened, got {other:?}"),
        };
        assert_eq!(first, 0x919C);

        client.handle_datagram(sa, &req_ack(0x9511), 20);
        match client.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => assert_eq!(conn, 0x9511),
            other => panic!("expected re-announced Opened, got {other:?}"),
        }

        // The peer now sends on the connection it kept. Before the re-key
        // this was dropped outright.
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::DataPacket,
            connection_id: 0x9511,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 1024,
            flags: AdspPacket::FLAG_ACK,
        };
        let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 1];
        pkt.to_bytes(&mut buf).unwrap();
        buf[AdspPacket::HEADER_LEN] = b'?';
        client.handle_datagram(sa, &buf, 30);

        match client.poll_event() {
            Some(AdspEvent::Data { conn, data, .. }) => {
                assert_eq!(conn, 0x9511);
                assert_eq!(data, b"?");
            }
            other => panic!("expected the peer's data, got {other:?}"),
        }
    }

    /// The third leg of the handshake must never be answered: two endpoints
    /// that acknowledge each other's OpenConnAck trade packets forever.
    #[test]
    fn open_conn_ack_is_not_answered() {
        let ca = addr(10, 70);
        let sa = addr(20, 80);
        let mut client = AdspEndpoint::new(70, 111);
        let mut server = AdspEndpoint::new(80, 222);
        server.set_listening(true);

        client.connect(sa, 0);
        // shuttle() returns once neither side has anything left to send; if
        // the handshake looped it would never return.
        let moved = shuttle(&mut client, ca, &mut server, sa, 0);
        assert!(moved <= 4, "handshake should settle in a few packets, moved {moved}");
        assert!(client.poll_transmit().is_none());
        assert!(server.poll_transmit().is_none());
    }

    /// An ack goes out only in reply to a packet that asked for one.
    ///
    /// Acking unconditionally turns two of these endpoints facing each other
    /// into an ack storm, since each ack is itself a packet to be acked.
    #[test]
    fn an_ack_is_sent_only_when_the_peer_asks() {
        let (mut client, _ca, mut server, sa, _client_conn, server_conn) = connect_pair();

        // A real data packet, used as the base for both halves so the
        // connection id and sequence numbers are the ones this client
        // expects - a lookup miss would pass the first assertion for the
        // wrong reason. `send` sets AckReq itself, so clear it here.
        server.send(server_conn, b"payload", false).unwrap();
        let (_dest, base) = server.poll_transmit().expect("server sends the data");

        let mut buf = base.clone();
        let parsed = AdspPacket::parse(&buf).expect("valid packet");
        AdspPacket { flags: parsed.flags & !AdspPacket::FLAG_ACK, ..parsed }
            .to_bytes(&mut buf)
            .expect("sized buffer");
        client.handle_datagram(sa, &buf, 1000);
        while client.poll_event().is_some() {}
        assert!(
            client.poll_transmit().is_none(),
            "AckReq was clear, so nothing should go back"
        );

        // The same packet asking for an ack is answered, duplicate or not:
        // a retransmission means the previous ack was lost.
        let mut buf = base.clone();
        AdspPacket { flags: parsed.flags | AdspPacket::FLAG_ACK, ..parsed }
            .to_bytes(&mut buf)
            .expect("sized buffer");
        client.handle_datagram(sa, &buf, 2000);
        assert!(
            client.poll_transmit().is_some(),
            "an AckReq packet must be answered"
        );
    }

    #[test]
    fn open_retries_then_fails() {
        let mut client = AdspEndpoint::new(70, 5);
        let conn = client.connect(addr(20, 80), 0);
        let _ = client.poll_transmit().unwrap();

        let mut now;
        let mut sends = 0;
        loop {
            now = match client.next_deadline() {
                Some(d) => d,
                None => break,
            };
            client.poll(now);
            while client.poll_transmit().is_some() {
                sends += 1;
            }
            if let Some(ev) = client.poll_event() {
                assert_eq!(ev, AdspEvent::OpenFailed { conn });
                break;
            }
        }
        assert_eq!(sends, MAX_OPEN_RETRIES as usize);
    }
}
