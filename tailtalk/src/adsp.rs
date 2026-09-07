use crate::ddp::{DdpAddress, DdpHandle, DdpSocket};
use byteorder::ByteOrder;
use bytes::{Buf, BytesMut};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tailtalk_packets::{
    adsp::{AdspDescriptor, AdspPacket},
    ddp::DdpProtocolType,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

const ADSP_MAX_DATA: usize = 572;
/// Largest client attention payload, excluding the 2-byte code (spec §12).
const ADSP_MAX_ATTN_DATA: usize = 570;
/// Highest attention code available to clients; $F000 and above are reserved
/// for future expansion of ADSP itself (spec §12).
const ADSP_MAX_CLIENT_ATTN_CODE: u16 = 0xEFFF;
/// Attention retransmissions before the send is failed.
///
/// The spec retransmits until acknowledged or the connection is torn down;
/// bounding it keeps a caller's `send_attention` from hanging forever on a
/// peer that has silently gone away, and matches the data path's own cap.
const ATTN_MAX_RETRIES: u8 = 5;
const ADSP_RECV_WINDOW: u16 = 4096;

/// ADSP network address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdspAddress {
    pub network_number: u16,
    pub node_number: u8,
    pub socket_number: u8,
}

impl From<tailtalk_packets::nbp::ServiceAddress> for AdspAddress {
    fn from(a: tailtalk_packets::nbp::ServiceAddress) -> Self {
        AdspAddress {
            network_number: a.network_number,
            node_number: a.node_number,
            socket_number: a.socket_number,
        }
    }
}

fn ddp_dest(addr: AdspAddress) -> DdpAddress {
    DdpAddress::new(
        tailtalk_packets::aarp::AppleTalkAddress {
            network_number: addr.network_number,
            node_number: addr.node_number,
        },
        addr.socket_number,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Open,
    Closing,
}

/// One blocked `write_eom` / `write_all` + flush waiting for window space.
struct PendingWrite {
    data: Vec<u8>,
    /// Bytes of `data` already transmitted.
    offset: usize,
    eom: bool,
    reply: oneshot::Sender<io::Result<()>>,
}

/// An attention message sent but not yet acknowledged.
///
/// Spec §12: "When sending an attention message, the end starts a timer. If
/// the timer expires, the end retransmits the attention message and restarts
/// the timer", continuing "until it receives the appropriate attention-message
/// acknowledgment or until the connection is torn down". The payload is kept
/// so the retransmit tick can resend it verbatim.
struct AttnInFlight {
    /// Sequence number this message was sent with (its PktAttnSendSeq).
    seq: u32,
    code: u16,
    data: Vec<u8>,
    sent_at: std::time::Instant,
    retries: u8,
    /// Completes the caller's `send_attention` once the peer acknowledges.
    reply: Option<oneshot::Sender<io::Result<()>>>,
    /// Sends queued behind this one, oldest first.
    queued: std::collections::VecDeque<QueuedAttn>,
}

/// An attention message waiting for the in-flight one to be acknowledged.
struct QueuedAttn {
    code: u16,
    data: Vec<u8>,
    reply: oneshot::Sender<io::Result<()>>,
}

/// Fail the connection's in-flight attention and everything queued behind it.
///
/// Called when a connection goes away: those callers are waiting on an
/// acknowledgement that can no longer arrive.
fn fail_pending_attentions(conn: &mut AdspConnection, reason: &str) {
    let Some(mut in_flight) = conn.attn_in_flight.take() else { return };
    let err = || io::Error::new(io::ErrorKind::NotConnected, reason.to_string());
    if let Some(reply) = in_flight.reply.take() {
        let _ = reply.send(Err(err()));
    }
    for queued in in_flight.queued.drain(..) {
        let _ = queued.reply.send(Err(err()));
    }
}

struct AdspConnection {
    /// Our own ConnID — placed in every outgoing packet's connection_id field.
    /// The HashMap key is the peer's ConnID (what arrives in inbound packets).
    our_conn_id: u16,
    state: ConnectionState,
    remote_addr: AdspAddress,
    send_seq: u32,
    oldest_unacked_seq: u32,
    recv_seq: u32,
    send_window: u16,
    /// Bytes sent but not yet ACKed by the peer.
    flight_buffer: Vec<u8>,
    last_tx: std::time::Instant,
    retries: u8,
    /// Sequence number of the next attention message to send.
    attn_send_seq: u32,
    /// The attention message awaiting acknowledgement, if any.
    ///
    /// The spec allows only one outstanding at a time, so this doubles as the
    /// interlock: while it is `Some`, a further send must wait.
    attn_in_flight: Option<AttnInFlight>,
    /// Sequence number expected on the next inbound attention message.
    ///
    /// Attention messages carry their own sequence space, independent of the
    /// data stream's. Peers retransmit an unacked attention on their own
    /// timer, so without this the same message would be delivered twice and
    /// desynchronise request/reply pairing.
    attn_recv_seq: u32,
    /// Delivers received attention messages to the AdspStream reader.
    attn_tx: mpsc::Sender<(u16, Vec<u8>)>,
    /// Delivers received data to the AdspStream reader.
    data_tx: mpsc::Sender<Vec<u8>>,
    /// Writes blocked on the peer's receive window.
    pending_writes: std::collections::VecDeque<PendingWrite>,
    /// Deferred close: fires after all pending_writes have been sent.
    pending_close: Option<oneshot::Sender<io::Result<()>>>,
}

// ── Actor command channel ─────────────────────────────────────────────────────
//
// All AdspStream instances share a clone of the same mpsc::Sender<ActorCmd>.
// This replaces the old per-connection command_rx on each connection, which
// required busy-polling every connection's channel before each select! tick.

enum ActorCmd {
    SendData {
        conn_id: u16,
        data: Vec<u8>,
        eom: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SendAttention {
        conn_id: u16,
        code: u16,
        data: Vec<u8>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Close {
        conn_id: u16,
        reply: oneshot::Sender<io::Result<()>>,
    },
}

// ── Adsp actor ────────────────────────────────────────────────────────────────

pub struct Adsp {
    sock: DdpSocket,
    connections: HashMap<u16, AdspConnection>,
    accept_tx: Option<mpsc::Sender<AdspStream>>,
    pending_opens: HashMap<u16, oneshot::Sender<io::Result<AdspStream>>>,
    cmd_rx: mpsc::Receiver<ActorCmd>,
    /// Cloned into each AdspStream so they can send commands back.
    cmd_tx: mpsc::Sender<ActorCmd>,
}

impl Adsp {
    pub async fn bind(ddp: &DdpHandle, socket_number: Option<u8>) -> io::Result<(u8, AdspListener)> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, socket_number)
            .await
            .map_err(io::Error::other)?;
        let actual_socket = sock.socket_num();
        let (accept_tx, accept_rx) = mpsc::channel(10);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let adsp = Adsp {
            sock,
            connections: HashMap::new(),
            accept_tx: Some(accept_tx),
            pending_opens: HashMap::new(),
            cmd_rx,
            cmd_tx,
        };

        tokio::spawn(async move { adsp.run().await });

        Ok((actual_socket, AdspListener { local_socket: actual_socket, accept_rx }))
    }

    pub async fn connect(ddp: &DdpHandle, remote_addr: AdspAddress) -> io::Result<AdspStream> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, None)
            .await
            .map_err(io::Error::other)?;
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let conn_id: u16 = rand::random();

        let mut adsp = Adsp {
            sock,
            connections: HashMap::new(),
            accept_tx: None,
            pending_opens: [(conn_id, ready_tx)].into(),
            cmd_rx,
            cmd_tx,
        };

        adsp.send_open_request(conn_id, remote_addr).await;
        tokio::spawn(async move { adsp.run().await });

        ready_rx.await.map_err(io::Error::other)?
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_stream(
        &self,
        conn_id: u16,
        remote_addr: AdspAddress,
        data_rx: mpsc::Receiver<Vec<u8>>,
        attn_rx: mpsc::Receiver<(u16, Vec<u8>)>,
    ) -> AdspStream {
        AdspStream {
            conn_id,
            remote_addr,
            cmd_tx: self.cmd_tx.clone(),
            read: std::sync::Mutex::new(ReadState {
                rx: data_rx,
                leftover: BytesMut::new(),
            }),
            attn_rx: std::sync::Mutex::new(attn_rx),
            write_buf: BytesMut::new(),
            pending_flush: None,
        }
    }

    // Connections are always keyed by the peer's ConnID: that is the value carried in the
    // connection_id field of every inbound packet, so it is what we must dispatch on.
    // `our_conn_id` (placed in every outbound packet) is stored separately per connection.
    fn open_connection(
        &mut self,
        map_key: u16,
        our_conn_id: u16,
        remote_addr: AdspAddress,
        peer_window: u16,
    ) -> AdspStream {
        let (data_tx, data_rx) = mpsc::channel(32);
        let (attn_tx, attn_rx) = mpsc::channel(8);
        self.connections.insert(map_key, AdspConnection {
            our_conn_id,
            state: ConnectionState::Open,
            remote_addr,
            send_seq: 0,
            oldest_unacked_seq: 0,
            recv_seq: 0,
            send_window: peer_window,
            flight_buffer: Vec::new(),
            last_tx: std::time::Instant::now(),
            retries: 0,
            attn_send_seq: 0,
            attn_in_flight: None,
            attn_recv_seq: 0,
            attn_tx,
            data_tx,
            pending_writes: std::collections::VecDeque::new(),
            pending_close: None,
        });
        self.make_stream(map_key, remote_addr, data_rx, attn_rx)
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    async fn run(mut self) {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                pkt = self.sock.recv() => {
                    match pkt {
                        Ok(mut p) => self.handle_packet(p.headers, &mut p.payload).await,
                        Err(e) => {
                            tracing::error!("ADSP socket error: {e}");
                            break;
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_cmd(c).await,
                        None => break,
                    }
                }
                _ = tick.tick() => {
                    self.tick().await;
                }
            }
        }
    }

    async fn handle_cmd(&mut self, cmd: ActorCmd) {
        match cmd {
            ActorCmd::SendData { conn_id, data, eom, reply } => {
                self.send_data(conn_id, data, eom, reply).await;
            }
            ActorCmd::SendAttention { conn_id, code, data, reply } => {
                // Completes the reply itself: an attention send resolves on
                // the peer's acknowledgement, not on transmission.
                self.send_attention_msg(conn_id, code, data, reply).await;
            }
            ActorCmd::Close { conn_id, reply } => {
                self.close_or_defer(conn_id, reply).await;
            }
        }
    }

    // ── Retransmit tick ───────────────────────────────────────────────────────

    async fn tick(&mut self) {
        let now = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(3);

        let conn_ids: Vec<u16> = self.connections.keys().copied().collect();
        for conn_id in conn_ids {
            // Attention retransmit (spec §12): resend on timer expiry and
            // restart the timer, "until it receives the appropriate
            // attention-message acknowledgment or until the connection is torn
            // down". This runs on its own sequence space, so it is independent
            // of the data-stream retransmit below.
            if let Some(in_flight) = self
                .connections
                .get_mut(&conn_id)
                .and_then(|c| c.attn_in_flight.as_mut())
                && now.duration_since(in_flight.sent_at) > timeout
            {
                in_flight.retries += 1;
                let retries = in_flight.retries;
                if retries > ATTN_MAX_RETRIES {
                    tracing::error!(
                        "ADSP conn {} attention unacknowledged after {} attempts, failing it",
                        conn_id,
                        retries
                    );
                    let err = io::Error::new(
                        io::ErrorKind::TimedOut,
                        "attention message was never acknowledged",
                    );
                    self.complete_attention(conn_id, Err(err)).await;
                } else {
                    tracing::warn!(
                        "ADSP attention retransmit on conn {}, attempt {}",
                        conn_id,
                        retries
                    );
                    self.transmit_attention(conn_id).await;
                }
            }

            let Some(conn) = self.connections.get_mut(&conn_id) else { continue };

            if conn.flight_buffer.is_empty()
                || now.duration_since(conn.last_tx) <= timeout
            {
                continue;
            }

            conn.retries += 1;
            if conn.retries > 5 {
                tracing::error!("ADSP conn {} max retries reached, closing", conn_id);
                conn.state = ConnectionState::Closing;
                continue;
            }

            tracing::warn!(
                "ADSP retransmit on conn {}, attempt {}",
                conn_id,
                conn.retries
            );

            self.resend_unacked(conn_id).await;
        }
    }

    /// Resend everything in the flight buffer from `oldest_unacked_seq`.
    /// Called from the retransmit tick and on peer RetransmitAdvice.
    async fn resend_unacked(&mut self, conn_id: u16) {
        let Some(conn) = self.connections.get_mut(&conn_id) else { return };
        if conn.flight_buffer.is_empty() {
            return;
        }

        let data: Vec<u8> = conn.flight_buffer.clone();
        let remote_addr = conn.remote_addr;
        let oldest_seq = conn.oldest_unacked_seq;
        let recv_seq = conn.recv_seq;
        let our_conn_id = conn.our_conn_id;

        for (i, chunk) in data.chunks(ADSP_MAX_DATA).enumerate() {
            let chunk_seq = oldest_seq.wrapping_add((i * ADSP_MAX_DATA) as u32);
            let pkt = AdspPacket {
                descriptor: AdspDescriptor::DataPacket,
                connection_id: our_conn_id,
                first_byte_seq: chunk_seq,
                next_recv_seq: recv_seq,
                recv_window: ADSP_RECV_WINDOW,
                flags: AdspPacket::FLAG_ACK,
            };
            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
            if pkt.to_bytes(&mut buf).is_ok() {
                buf[AdspPacket::HEADER_LEN..].copy_from_slice(chunk);
                let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
            }
        }

        if let Some(c) = self.connections.get_mut(&conn_id) {
            c.last_tx = std::time::Instant::now();
        }
    }

    // ── Inbound packet dispatch ───────────────────────────────────────────────

    async fn handle_packet(
        &mut self,
        ddp: tailtalk_packets::ddp::DdpPacket,
        payload: &mut [u8],
    ) {
        let packet = match AdspPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse ADSP packet: {:?}", e);
                return;
            }
        };

        tracing::debug!(
            "ADSP {:?} conn={} from {}.{}",
            packet.descriptor,
            packet.connection_id,
            ddp.src_network_num,
            ddp.src_node_id,
        );

        if packet.flags & AdspPacket::FLAG_ATTENTION != 0 {
            self.handle_attention(packet, &payload[AdspPacket::HEADER_LEN..]).await;
            return;
        }

        match packet.descriptor {
            AdspDescriptor::OpenConnRequest => {
                self.handle_open_request(ddp, packet).await;
            }
            AdspDescriptor::OpenConnAck | AdspDescriptor::OpenConnReqAck => {
                self.handle_open_ack(ddp, packet, payload).await;
            }
            // DataPacket (bit7=0): data from peer. ControlPacket (0x80): probe/ack, may carry data.
            AdspDescriptor::DataPacket | AdspDescriptor::ControlPacket => {
                self.handle_data(packet, &payload[AdspPacket::HEADER_LEN..]).await;
            }
            AdspDescriptor::RetransmitAdvice => {
                // Peer is missing data from packet.next_recv_seq onward:
                // apply the ack state (which rolls oldest_unacked back to
                // exactly what the peer has), then resend immediately
                // instead of waiting for the retransmit tick.
                let conn_id = packet.connection_id;
                self.handle_ack(packet).await;
                self.resend_unacked(conn_id).await;
            }
            AdspDescriptor::CloseAdvice => {
                self.handle_close(packet).await;
            }
            _ => {
                tracing::debug!("Unhandled ADSP descriptor: {:?}", packet.descriptor);
            }
        }
    }

    /// Handle an inbound packet carrying the Attention flag.
    ///
    /// Two distinct packets share that flag. An attention *message* is a data
    /// packet whose payload is a 2-byte code plus the message body; an
    /// attention *acknowledgement* is a control packet the peer sends back to
    /// retire one we transmitted. Both must be recognised: acking an ack
    /// would bounce a packet back to a peer that acks it in turn, and
    /// delivering an ack as a message would hand callers a phantom.
    async fn handle_attention(&mut self, packet: AdspPacket, data: &[u8]) {
        if packet.flags & AdspPacket::FLAG_CONTROL != 0 {
            // Acknowledgement of an attention we sent.
            //
            // It must not touch data-stream flow control: attention packets
            // carry PktAttnRecvWdw = 0 by spec, so feeding one to handle_ack
            // would clobber the peer's real window and wedge every later write.
            //
            // The spec's rule for retiring the message (§12, "Attention
            // messages"): "Before updating AttnSendSeq, end A must ensure that
            // the value of PktAttnRecvSeq equals AttnSendSeq+1." Our
            // attn_send_seq already points past the message in flight, so the
            // ack we are waiting for names exactly that value.
            let Some(conn) = self.connections.get(&packet.connection_id) else { return };
            let Some(in_flight) = conn.attn_in_flight.as_ref() else { return };

            // "Before updating AttnSendSeq, end A must ensure that the value of
            // PktAttnRecvSeq equals AttnSendSeq+1" — the peer counts the
            // message it just accepted, so the ack names one past the sequence
            // we sent. Anything else is a stale or duplicate ack.
            if packet.next_recv_seq != in_flight.seq.wrapping_add(1) {
                tracing::debug!(
                    "ADSP conn {} stale attention ack (got {}, expected {})",
                    packet.connection_id,
                    packet.next_recv_seq,
                    in_flight.seq.wrapping_add(1)
                );
                return;
            }

            tracing::debug!(
                "ADSP conn {} attention {} acknowledged",
                packet.connection_id,
                in_flight.seq
            );
            self.complete_attention(packet.connection_id, Ok(())).await;
            return;
        }

        // Spec §12: "The Control code in the ADSP descriptor field of an ADSP
        // Attention packet must always be set to 0. An Attention packet
        // received with a Control code number other than 0 should be discarded
        // as invalid." The parser maps any descriptor without the Control bit
        // to DataPacket without inspecting the low nibble, so check it here.
        if packet.descriptor as u8 & 0x0F != 0 {
            tracing::warn!(
                "ADSP conn {} attention with non-zero control code, discarding",
                packet.connection_id
            );
            return;
        }

        if data.len() < 2 {
            tracing::warn!(
                "ADSP conn {} attention with {}-byte payload, need 2 for the code",
                packet.connection_id,
                data.len()
            );
            return;
        }
        let attention_code = byteorder::BigEndian::read_u16(&data[0..2]);
        let body = &data[2..];

        let Some(conn) = self.connections.get_mut(&packet.connection_id) else { return };
        let remote_addr = conn.remote_addr;
        let our_conn_id = conn.our_conn_id;

        // Attention messages occupy their own sequence space, one per message.
        // A peer that did not see our ack retransmits, so only deliver the
        // message when it is the one we are expecting; the ack below is sent
        // either way, since a duplicate means the previous ack was lost.
        if packet.first_byte_seq == conn.attn_recv_seq {
            match conn.attn_tx.try_send((attention_code, body.to_vec())) {
                Ok(()) => {
                    conn.attn_recv_seq = conn.attn_recv_seq.wrapping_add(1);
                    tracing::info!(
                        "ADSP attention 0x{:04X} ({} byte body) on conn {}",
                        attention_code,
                        body.len(),
                        packet.connection_id
                    );
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Withhold both the delivery and the sequence bump so the
                    // peer's retransmission gets another chance, rather than
                    // the message being lost. Withholding the ack too is what
                    // prompts that retransmission.
                    tracing::warn!(
                        "ADSP conn {} attention queue full, deferring 0x{:04X}",
                        packet.connection_id,
                        attention_code
                    );
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // The application dropped its AdspStream. Retransmissions
                    // can never be delivered, so consume the message and ack
                    // it below instead of asking the peer to send it forever.
                    conn.attn_recv_seq = conn.attn_recv_seq.wrapping_add(1);
                    tracing::debug!(
                        "ADSP conn {} attention 0x{:04X} discarded, no reader",
                        packet.connection_id,
                        attention_code
                    );
                }
            }
        } else {
            tracing::debug!(
                "ADSP conn {} duplicate attention 0x{:04X} (seq {}, expected {})",
                packet.connection_id,
                attention_code,
                packet.first_byte_seq,
                conn.attn_recv_seq
            );
        }

        let attn_send_seq = conn.attn_send_seq;
        let attn_recv_seq = conn.attn_recv_seq;

        // Attention-control packet: descriptor 0x90 = Control(0x80) | Attention(0x10).
        //
        // Attention packets ride the attention sequence space, not the data
        // stream's (spec §12, "Attention messages"), so PktAttnSendSeq and
        // PktAttnRecvSeq carry attn_send_seq/attn_recv_seq. The spec also says
        // an attention-control packet "should not have the Ack Request bit
        // set" — acking an ack would loop — and that PktAttnRecvWdw "must
        // always be set to 0", since only one attention may be outstanding.
        let ack = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: our_conn_id,
            first_byte_seq: attn_send_seq,
            next_recv_seq: attn_recv_seq,
            recv_window: 0,
            flags: AdspPacket::FLAG_ATTENTION,
        };
        let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 2];
        if ack.to_bytes(&mut buf).is_ok() {
            byteorder::BigEndian::write_u16(
                &mut buf[AdspPacket::HEADER_LEN..],
                attention_code,
            );
            let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
        }
    }

    async fn handle_open_request(
        &mut self,
        ddp: tailtalk_packets::ddp::DdpPacket,
        packet: AdspPacket,
    ) {
        let client_conn_id = packet.connection_id;
        let our_conn_id: u16 = rand::random();
        let remote_addr = AdspAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        };

        tracing::info!("ADSP accepting conn {} from {:?}", client_conn_id, remote_addr);

        let stream = self.open_connection(client_conn_id, our_conn_id, remote_addr, packet.recv_window);

        // OpenConnReqAck carries 8-byte open-conn params (spec §12, Figure 12-11).
        let ack = AdspPacket {
            descriptor: AdspDescriptor::OpenConnReqAck,
            connection_id: our_conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: ADSP_RECV_WINDOW,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN + 8];
        if ack.to_bytes(&mut buf).is_ok() {
            byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
            byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN + 2..], client_conn_id);
            let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
        }

        if let Some(tx) = &self.accept_tx {
            let _ = tx.send(stream).await;
        }
    }

    async fn handle_open_ack(
        &mut self,
        ddp: tailtalk_packets::ddp::DdpPacket,
        packet: AdspPacket,
        payload: &[u8],
    ) {
        // Our ConnID echoed back in the open-conn params at payload[15..17]
        // (DestConnID field, bytes 2-3 of the 8-byte block following the header).
        let server_conn_id = packet.connection_id;
        let our_conn_id = if payload.len() >= 17 {
            u16::from_be_bytes([payload[15], payload[16]])
        } else {
            server_conn_id
        };

        let Some(ready_tx) = self.pending_opens.remove(&our_conn_id) else { return };

        let remote_addr = AdspAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        };

        tracing::info!(
            "ADSP conn established: our={} server={} remote={:?}",
            our_conn_id, server_conn_id, remote_addr
        );

        let stream = self.open_connection(server_conn_id, our_conn_id, remote_addr, packet.recv_window);

        // OpenConnAck completes the 3-way handshake; carries 8-byte open-conn params
        // like the other two handshake packets (spec §12, Figure 12-11).
        let ack = AdspPacket {
            descriptor: AdspDescriptor::OpenConnAck,
            connection_id: our_conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: ADSP_RECV_WINDOW,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN + 8];
        if ack.to_bytes(&mut buf).is_ok() {
            byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
            byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN + 2..], server_conn_id);
            let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
        }

        let _ = ready_tx.send(Ok(stream));
    }

    async fn handle_data(&mut self, packet: AdspPacket, data: &[u8]) {
        let Some(conn) = self.connections.get_mut(&packet.connection_id) else { return };

        // EOM consumes one byte of sequence space even with no payload (like
        // TCP FIN) — must advance recv_seq even when data is empty, or our
        // own ack of the peer's EOM packet will look short by one to them.
        let eom_seq_bump: u32 = if packet.flags & AdspPacket::FLAG_EOM != 0 { 1 } else { 0 };
        let total_len = data.len() as u32 + eom_seq_bump;
        if total_len > 0 {
            // Sequence-validate before delivering: peers retransmit on their own
            // timers, so both duplicates and (after a lost packet) data beyond a
            // hole occur. Delivering a duplicate corrupts request/reply pairing;
            // acking past a hole makes the peer never resend it, deadlocking the
            // stream.
            let diff = conn.recv_seq.wrapping_sub(packet.first_byte_seq) as i32;
            if diff < 0 {
                // Data beyond a hole: discard; the ack below re-states our
                // recv_seq so the peer rolls back and retransmits.
                tracing::warn!(
                    "ADSP conn {} out-of-order data (seq {}, expected {}), discarding",
                    packet.connection_id,
                    packet.first_byte_seq,
                    conn.recv_seq
                );
            } else if (diff as u32) < total_len {
                // In order (diff == 0), or a retransmission overlapping our
                // position: deliver only the bytes we haven't seen yet.
                let skip = (diff as usize).min(data.len());
                let fresh = &data[skip..];
                if fresh.is_empty() || conn.data_tx.try_send(fresh.to_vec()).is_ok() {
                    conn.recv_seq = packet.first_byte_seq.wrapping_add(total_len);
                } else {
                    // Receive buffer full: leave recv_seq (and thus our ack)
                    // where it is so the peer retransmits instead of the
                    // bytes being silently lost.
                    tracing::warn!(
                        "ADSP conn {} receive buffer full, deferring data",
                        packet.connection_id
                    );
                }
            } else {
                // Pure duplicate of already-delivered data: drop it. The ack
                // below tells the peer where we really are.
                tracing::debug!(
                    "ADSP conn {} dropping duplicate retransmission (seq {}, {} bytes)",
                    packet.connection_id,
                    packet.first_byte_seq,
                    total_len
                );
            }
        }

        // All ADSP packets (data and control) carry ACK state — apply sender flow control.
        conn.send_window = packet.recv_window;
        // Valid ack range is bounded by our own send_seq (which already
        // accounts for EOM's phantom byte), not flight_buffer.len() directly —
        // an EOM-terminated send acks 1 higher than its real byte count.
        let max_valid_acked = conn.send_seq.wrapping_sub(conn.oldest_unacked_seq) as usize;
        let acked = packet.next_recv_seq.wrapping_sub(conn.oldest_unacked_seq) as usize;
        if acked > 0 && acked <= max_valid_acked {
            conn.flight_buffer.drain(..acked.min(conn.flight_buffer.len()));
            conn.oldest_unacked_seq = packet.next_recv_seq;
            conn.retries = 0;
        }

        let conn_id = packet.connection_id;
        let _ = self.send_ack(conn_id).await;
        self.drain_pending(conn_id).await;
    }

    async fn handle_ack(&mut self, packet: AdspPacket) {
        let Some(conn) = self.connections.get_mut(&packet.connection_id) else { return };

        conn.send_window = packet.recv_window;

        let max_valid_acked = conn.send_seq.wrapping_sub(conn.oldest_unacked_seq) as usize;
        let acked = packet
            .next_recv_seq
            .wrapping_sub(conn.oldest_unacked_seq) as usize;
        if acked > 0 && acked <= max_valid_acked {
            conn.flight_buffer.drain(..acked.min(conn.flight_buffer.len()));
            conn.oldest_unacked_seq = packet.next_recv_seq;
            conn.retries = 0;
        }

        let conn_id = packet.connection_id;
        self.drain_pending(conn_id).await;
    }

    async fn handle_close(&mut self, packet: AdspPacket) {
        if let Some(mut conn) = self.connections.remove(&packet.connection_id) {
            tracing::info!("ADSP conn {} closed by peer", packet.connection_id);
            // The spec retransmits an attention "until it receives the
            // appropriate attention-message acknowledgment or until the
            // connection is torn down" — this is that teardown, so fail the
            // in-flight message and everything queued behind it rather than
            // leaving their callers waiting on an ack that cannot come.
            fail_pending_attentions(&mut conn, "connection closed by peer");
            // Dropping both senders is what unblocks a reader: data_tx gives
            // AsyncRead its EOF, attn_tx makes a waiting attention() call
            // return None rather than hang for a message that can no longer
            // arrive.
            drop(conn.data_tx);
            drop(conn.attn_tx);
        }
    }

    // ── Outbound helpers ──────────────────────────────────────────────────────

    async fn send_open_request(&mut self, conn_id: u16, remote_addr: AdspAddress) {
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::OpenConnRequest,
            connection_id: conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: ADSP_RECV_WINDOW,
            flags: 0,
        };
        // Header + 8-byte open-conn params (spec §12, Figure 12-11).
        // DestConnID is 0 — we don't know the server's ConnID yet.
        let mut buf = [0u8; AdspPacket::HEADER_LEN + 8];
        if pkt.to_bytes(&mut buf).is_ok() {
            byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN..], 0x0100);
            let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
        }
    }

    async fn send_data(
        &mut self,
        conn_id: u16,
        data: Vec<u8>,
        eom: bool,
        reply: oneshot::Sender<io::Result<()>>,
    ) {
        let Some(conn) = self.connections.get_mut(&conn_id) else {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::NotConnected, "no such connection")));
            return;
        };

        if conn.state != ConnectionState::Open {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::NotConnected, "connection closing")));
            return;
        }

        // If earlier writes are still queued, preserve order by appending.
        if !conn.pending_writes.is_empty() {
            conn.pending_writes.push_back(PendingWrite { data, offset: 0, eom, reply });
            return;
        }

        // Empty EOM (no payload — just marks a record boundary, doesn't consume window).
        if data.is_empty() && eom {
            let result = self.send_eom_only(conn_id).await;
            let _ = reply.send(result);
            return;
        }

        // How many bytes fit in the peer's receive window right now?
        let in_flight = conn.send_seq.wrapping_sub(conn.oldest_unacked_seq);
        let available = (conn.send_window as u32).saturating_sub(in_flight) as usize;

        if available == 0 {
            conn.pending_writes.push_back(PendingWrite { data, offset: 0, eom, reply });
            return;
        }

        let to_send = data.len().min(available);
        let all_sent = to_send == data.len();
        let result = self.send_raw(conn_id, &data[..to_send], eom && all_sent).await;

        if result.is_err() || all_sent {
            let _ = reply.send(result);
        } else {
            let conn = self.connections.get_mut(&conn_id).unwrap();
            conn.pending_writes.push_back(PendingWrite { data, offset: to_send, eom, reply });
        }
    }

    /// Send raw data bytes on a connection without any queuing or window checks.
    /// Updates flight_buffer and send_seq.
    async fn send_raw(&mut self, conn_id: u16, data: &[u8], eom: bool) -> io::Result<()> {
        let conn = self
            .connections
            .get_mut(&conn_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such connection"))?;

        let last_idx = data.chunks(ADSP_MAX_DATA).count().saturating_sub(1);
        for (i, chunk) in data.chunks(ADSP_MAX_DATA).enumerate() {
            let eom_flag = if eom && i == last_idx { AdspPacket::FLAG_EOM } else { 0 };
            let pkt = AdspPacket {
                descriptor: AdspDescriptor::DataPacket,
                connection_id: conn.our_conn_id,
                first_byte_seq: conn.send_seq,
                next_recv_seq: conn.recv_seq,
                recv_window: ADSP_RECV_WINDOW,
                flags: AdspPacket::FLAG_ACK | eom_flag,
            };
            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
            pkt.to_bytes(&mut buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            buf[AdspPacket::HEADER_LEN..].copy_from_slice(chunk);
            self.sock.send_to(&buf, ddp_dest(conn.remote_addr)).await.map_err(io::Error::other)?;
            conn.flight_buffer.extend_from_slice(chunk);
            // EOM consumes one extra byte of sequence space (like TCP FIN),
            // even though it carries no payload of its own. Omitting this
            // makes the peer's legitimate cumulative ack look like an
            // over-ack, which handle_data/handle_ack then silently reject —
            // stalling oldest_unacked_seq and retransmitting forever.
            let eom_seq_bump = if eom_flag != 0 { 1 } else { 0 };
            conn.send_seq = conn.send_seq.wrapping_add(chunk.len() as u32 + eom_seq_bump);
        }
        conn.last_tx = std::time::Instant::now();
        Ok(())
    }

    async fn send_eom_only(&mut self, conn_id: u16) -> io::Result<()> {
        let conn = self
            .connections
            .get_mut(&conn_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such connection"))?;
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::DataPacket,
            connection_id: conn.our_conn_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: ADSP_RECV_WINDOW,
            flags: AdspPacket::FLAG_ACK | AdspPacket::FLAG_EOM,
        };
        let remote_addr = conn.remote_addr;
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        pkt.to_bytes(&mut buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.sock.send_to(&buf, ddp_dest(remote_addr)).await.map_err(io::Error::other)?;
        // EOM consumes one byte of sequence space even with no payload (see send_raw).
        conn.send_seq = conn.send_seq.wrapping_add(1);
        conn.last_tx = std::time::Instant::now();
        Ok(())
    }

    /// Drain as much of the pending write queue as the current window allows.
    /// Fires deferred replies for completed writes, and a deferred close when the
    /// queue empties.
    async fn drain_pending(&mut self, conn_id: u16) {
        loop {
            // Extract what we need without holding a reference across the await.
            enum Task { Eom, Data { chunk: Vec<u8>, eom: bool, all_sent: bool } }

            let task = {
                let Some(conn) = self.connections.get_mut(&conn_id) else { return };
                let Some(front) = conn.pending_writes.front() else { break };

                if front.data.is_empty() && front.eom {
                    Task::Eom
                } else {
                    let in_flight = conn.send_seq.wrapping_sub(conn.oldest_unacked_seq);
                    let available = (conn.send_window as u32).saturating_sub(in_flight) as usize;
                    if available == 0 {
                        break;
                    }
                    let remaining_len = front.data.len() - front.offset;
                    let to_send = remaining_len.min(available);
                    let chunk = front.data[front.offset..front.offset + to_send].to_vec();
                    let all_sent = to_send == remaining_len;
                    Task::Data { chunk, eom: front.eom && all_sent, all_sent }
                }
            };

            match task {
                Task::Eom => {
                    let result = self.send_eom_only(conn_id).await;
                    if let Some(conn) = self.connections.get_mut(&conn_id)
                        && let Some(pw) = conn.pending_writes.pop_front()
                    {
                        let _ = pw.reply.send(result);
                    }
                }
                Task::Data { chunk, eom, all_sent } => {
                    let chunk_len = chunk.len();
                    let result = self.send_raw(conn_id, &chunk, eom).await;
                    let Some(conn) = self.connections.get_mut(&conn_id) else { return };
                    if result.is_err() || all_sent {
                        if let Some(pw) = conn.pending_writes.pop_front() {
                            let _ = pw.reply.send(result);
                        }
                    } else {
                        if let Some(front) = conn.pending_writes.front_mut() {
                            front.offset += chunk_len;
                        }
                        break;
                    }
                }
            }
        }

        // If queue is now empty and a close was deferred, execute it.
        let needs_close = self.connections.get(&conn_id)
            .map(|c| c.pending_writes.is_empty() && c.pending_close.is_some())
            .unwrap_or(false);
        if needs_close {
            let reply = self.connections.get_mut(&conn_id).unwrap().pending_close.take().unwrap();
            let result = self.do_close(conn_id).await;
            let _ = reply.send(result);
        }
    }

    async fn close_or_defer(&mut self, conn_id: u16, reply: oneshot::Sender<io::Result<()>>) {
        let Some(conn) = self.connections.get_mut(&conn_id) else {
            let _ = reply.send(Ok(())); // already gone
            return;
        };
        if conn.pending_writes.is_empty() {
            let result = self.do_close(conn_id).await;
            let _ = reply.send(result);
        } else {
            conn.pending_close = Some(reply);
        }
    }

    async fn send_ack(&mut self, conn_id: u16) -> io::Result<()> {
        let conn = self
            .connections
            .get(&conn_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such connection"))?;

        // Plain acks are control code 0 (probe/ack, 0x80), not RetransmitAdvice
        // (0x88) — that's a rollback command and must only be sent in response
        // to an actual gap in the peer's stream.
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: conn.our_conn_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: ADSP_RECV_WINDOW,
            flags: 0,
        };

        let remote_addr = conn.remote_addr;
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        pkt.to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.sock
            .send_to(&buf, ddp_dest(remote_addr))
            .await
            .map_err(io::Error::other)
    }

    /// Accept a client attention message: validate it, then either put it on
    /// the wire or queue it behind one already awaiting acknowledgement.
    ///
    /// The caller's `reply` is deliberately not completed here. Spec §12 allows
    /// only one attention outstanding at a time, so `send_attention` resolves
    /// when the peer acknowledges, which is also what makes the caller's next
    /// send legal.
    async fn send_attention_msg(
        &mut self,
        conn_id: u16,
        code: u16,
        data: Vec<u8>,
        reply: oneshot::Sender<io::Result<()>>,
    ) {
        // Spec §12: an attention message carries "a 2-byte (16-bit) attention
        // code and from 0 to 570 bytes of client attention data".
        if data.len() > ADSP_MAX_ATTN_DATA {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "attention data is {} bytes, limit is {ADSP_MAX_ATTN_DATA}",
                    data.len()
                ),
            )));
            return;
        }
        // Codes $F000-$FFFF are reserved for future expansion of ADSP itself;
        // $0000-$EFFF are the client's to use.
        if code > ADSP_MAX_CLIENT_ATTN_CODE {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("attention code 0x{code:04X} is reserved by ADSP"),
            )));
            return;
        }

        let Some(conn) = self.connections.get_mut(&conn_id) else {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no such connection",
            )));
            return;
        };

        // One outstanding at a time: queue this one and send it when the
        // current message is acknowledged.
        if let Some(in_flight) = conn.attn_in_flight.as_mut() {
            in_flight.queued.push_back(QueuedAttn { code, data, reply });
            return;
        }

        let seq = conn.attn_send_seq;
        conn.attn_in_flight = Some(AttnInFlight {
            seq,
            code,
            data,
            sent_at: std::time::Instant::now(),
            retries: 0,
            reply: Some(reply),
            queued: std::collections::VecDeque::new(),
        });

        self.transmit_attention(conn_id).await;
    }

    /// Put the connection's in-flight attention message on the wire.
    ///
    /// Used for both the first transmission and every retransmission, so the
    /// bytes are identical each time — the peer dedups on PktAttnSendSeq.
    async fn transmit_attention(&mut self, conn_id: u16) {
        let Some(conn) = self.connections.get_mut(&conn_id) else { return };
        let Some(in_flight) = conn.attn_in_flight.as_mut() else { return };

        in_flight.sent_at = std::time::Instant::now();
        let (seq, code) = (in_flight.seq, in_flight.code);
        let data = in_flight.data.clone();
        let (remote_addr, attn_recv_seq, our_conn_id) =
            (conn.remote_addr, conn.attn_recv_seq, conn.our_conn_id);

        // Attention packet (spec §12, Figure 12-7): desc byte 0x50 — Control
        // clear and Ack Request set, which "forces the receiver to immediately
        // send an acknowledgment of the attention data". PktAttnRecvSeq
        // piggybacks our own attention receive state, since "an
        // acknowledgment is implicit in any Attention packet sent".
        let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 2 + data.len()];
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::DataPacket,
            connection_id: our_conn_id,
            first_byte_seq: seq,
            next_recv_seq: attn_recv_seq,
            recv_window: 0, // must be 0 for attention per spec
            flags: AdspPacket::FLAG_ACK | AdspPacket::FLAG_ATTENTION,
        };
        if pkt.to_bytes(&mut buf).is_err() {
            return;
        }
        byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN..], code);
        buf[AdspPacket::HEADER_LEN + 2..].copy_from_slice(&data);

        let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
    }

    /// Retire the in-flight attention message and start any queued successor.
    async fn complete_attention(&mut self, conn_id: u16, result: io::Result<()>) {
        let Some(conn) = self.connections.get_mut(&conn_id) else { return };
        let Some(mut in_flight) = conn.attn_in_flight.take() else { return };

        if let Some(reply) = in_flight.reply.take() {
            let _ = reply.send(result);
        }

        // Only a delivered message consumes a sequence number.
        conn.attn_send_seq = conn.attn_send_seq.wrapping_add(1);

        let Some(next) = in_flight.queued.pop_front() else { return };
        let seq = conn.attn_send_seq;
        conn.attn_in_flight = Some(AttnInFlight {
            seq,
            code: next.code,
            data: next.data,
            sent_at: std::time::Instant::now(),
            retries: 0,
            reply: Some(next.reply),
            queued: in_flight.queued,
        });
        self.transmit_attention(conn_id).await;
    }

    async fn do_close(&mut self, conn_id: u16) -> io::Result<()> {
        let Some(conn) = self.connections.get(&conn_id) else {
            return Ok(()); // already gone
        };

        let pkt = AdspPacket {
            descriptor: AdspDescriptor::CloseAdvice,
            connection_id: conn.our_conn_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: 0,
            flags: 0,
        };
        let remote_addr = conn.remote_addr;

        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        pkt.to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        self.sock
            .send_to(&buf, ddp_dest(remote_addr))
            .await
            .map_err(io::Error::other)?;

        if let Some(mut conn) = self.connections.remove(&conn_id) {
            fail_pending_attentions(&mut conn, "connection closed");
        }
        Ok(())
    }
}

// ── AdspStream ────────────────────────────────────────────────────────────────
//
// AdspStream: Unpin — all fields are Unpin (Box<T>: Unpin unconditionally, so
// Pin<Box<dyn Future>>: Unpin), which lets us use Pin::get_mut() freely in the
// poll_* impls and store a boxed future across poll_flush invocations.

/// The receive half of an [`AdspStream`]: the channel carrying chunks from the
/// actor, plus whatever a short read left over from the last chunk.
///
/// These two are one lock rather than two because every read touches both, and
/// splitting them would mean a lock ordering that a later edit could get
/// wrong. One mutex makes that class of bug unrepresentable.
///
/// The lock is only ever held across a `poll_recv` and a buffer copy, never
/// across an `.await`, so it is uncontended in practice and cannot stall the
/// runtime.
struct ReadState {
    rx: mpsc::Receiver<Vec<u8>>,
    /// Bytes from a chunk that was larger than the caller's buffer.
    leftover: BytesMut,
}

/// An open ADSP connection: a byte stream plus an out-of-band attention queue.
///
/// Read the byte stream with [`read_data`](Self::read_data) or the
/// [`AsyncRead`] impl, write with the [`AsyncWrite`] impl (and
/// [`write_eom`](Self::write_eom) for record framing), and take out-of-band
/// messages with [`attention`](Self::attention).
///
/// # Cancel safety
///
/// [`read_data`](Self::read_data) and [`attention`](Self::attention) both take
/// `&self` and are cancel-safe, so a `select!` can await both at once and drop
/// the loser each iteration without losing data:
///
/// ```no_run
/// # async fn f(stream: &tailtalk::adsp::AdspStream) -> std::io::Result<()> {
/// let mut buf = [0u8; 512];
/// loop {
///     tokio::select! {
///         n = stream.read_data(&mut buf) => { let n = n?; }
///         Some((code, body)) = stream.attention() => {}
///     }
/// }
/// # }
/// ```
pub struct AdspStream {
    conn_id: u16,
    remote_addr: AdspAddress,
    cmd_tx: mpsc::Sender<ActorCmd>,
    /// The receive queue and its leftover buffer under one lock, so the two
    /// can never be acquired in conflicting orders. See [`ReadState`].
    read: std::sync::Mutex<ReadState>,
    /// Behind a mutex so [`AdspStream::attention`] can take `&self` and
    /// therefore share a `tokio::select!` with [`AdspStream::read_data`].
    /// Uncontended in practice: the lock is held only for the duration of a
    /// single non-blocking poll.
    attn_rx: std::sync::Mutex<mpsc::Receiver<(u16, Vec<u8>)>>,
    write_buf: BytesMut,
    /// Boxed future for an in-progress flush. Stored so poll_flush can be
    /// called repeatedly until the actor has processed the send command.
    pending_flush: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>,
}

impl AdspStream {
    pub fn remote_addr(&self) -> AdspAddress {
        self.remote_addr
    }

    /// Send an ADSP attention message with the given 16-bit code and payload.
    ///
    /// Attention messages are out-of-band from the normal data stream; they
    /// are delivered to the peer using a separate sequence number space and
    /// a dedicated descriptor (Control=0, AckReq=1, Attn=1).
    pub async fn send_attention(&mut self, code: u16, data: &[u8]) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ActorCmd::SendAttention {
                conn_id: self.conn_id,
                code,
                data: data.to_vec(),
                reply: tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?
    }

    /// The body of [`AsyncRead::poll_read`], written against `&self` so both
    /// the trait impl and [`read`](Self::read) can share it.
    fn poll_read_shared(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut read = self.read.lock().expect("read state poisoned");

        if !read.leftover.is_empty() {
            let to_copy = read.leftover.len().min(buf.remaining());
            buf.put_slice(&read.leftover[..to_copy]);
            read.leftover.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        match read.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    read.leftover.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF — data_tx was dropped
            Poll::Pending => Poll::Pending,
        }
    }

    /// Read stream bytes into `buf`, returning the number read (`0` at EOF).
    ///
    /// Equivalent to [`AsyncReadExt::read`](tokio::io::AsyncReadExt::read) but
    /// takes `&self`, so it can share a `tokio::select!` with
    /// [`attention`](Self::attention).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: a future dropped before it resolves leaves the stream
    /// exactly as it found it, so a read that loses a `select!` race costs no
    /// data and a later read returns the same bytes. Data arriving while no
    /// read is outstanding stays queued.
    ///
    /// A read whose buffer is smaller than the available data keeps the
    /// remainder for the next call rather than discarding it, so a small
    /// buffer costs extra calls, never bytes.
    ///
    /// As with any async fn, a future dropped *after* it resolves has already
    /// done its work — the bytes it returned are consumed even if the caller
    /// discards them. `select!` cannot do this (it always runs the handler of
    /// a branch that resolves); only a hand-written poll loop can.
    ///
    /// Named distinctly rather than `read` so it does not shadow the
    /// `AsyncReadExt` method for existing callers, which would silently change
    /// which function a bare `.read(..)` resolves to.
    pub async fn read_data(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Wait for readable data *without* taking it, so that dropping this
        // future (the losing branch of every select! iteration) cannot strand
        // bytes that were consumed but never returned.
        std::future::poll_fn(|cx| {
            let mut read = self.read.lock().expect("read state poisoned");
            if !read.leftover.is_empty() {
                return Poll::Ready(());
            }
            match read.rx.poll_recv(cx) {
                // Bank the chunk and report readiness in the same critical
                // section: an await point between the two would reintroduce
                // the cancellation hole this exists to close.
                Poll::Ready(Some(chunk)) => {
                    read.leftover.extend_from_slice(&chunk);
                    Poll::Ready(())
                }
                Poll::Ready(None) => Poll::Ready(()), // EOF
                Poll::Pending => Poll::Pending,
            }
        })
        .await;

        // Past the await: copying out is synchronous, so it cannot be cancelled.
        let mut read = self.read.lock().expect("read state poisoned");
        let to_copy = read.leftover.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&read.leftover[..to_copy]);
        read.leftover.advance(to_copy);
        Ok(to_copy)
    }

    /// Receive the next ADSP attention message from the peer, as
    /// `(code, body)`.
    ///
    /// Attention messages are out-of-band: they arrive on their own sequence
    /// space and are queued separately from the byte stream, so this never
    /// consumes or reorders data that [`AsyncRead`] would return. Waits until
    /// one arrives, yielding `None` once the connection is gone and no queued
    /// messages remain.
    ///
    /// Takes `&self`, as does [`read_data`](Self::read_data), so the two compose
    /// directly in a single `tokio::select!` with no splitting — the shape a
    /// server needs when it must react to out-of-band messages while a
    /// transfer is in progress (the StyleWriter adapter protocol interleaves
    /// both on one connection):
    ///
    /// ```no_run
    /// # async fn f(stream: &tailtalk::adsp::AdspStream) -> std::io::Result<()> {
    /// let mut buf = [0u8; 512];
    /// loop {
    ///     tokio::select! {
    ///         n = stream.read_data(&mut buf) => { let n = n?; /* raster bytes */ }
    ///         Some((code, body)) = stream.attention() => { /* 0x000b, 0x0006, ... */ }
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: a message leaves the queue only on a poll that resolves,
    /// so a future dropped before then — the losing branch of a `select!` —
    /// costs nothing, and the message is still waiting for the next call.
    ///
    /// As with [`read_data`](Self::read_data), a future dropped after it
    /// resolves has already taken its message. `select!` never does this; only
    /// a hand-written poll loop can.
    pub async fn attention(&self) -> Option<(u16, Vec<u8>)> {
        std::future::poll_fn(|cx| {
            let mut rx = self.attn_rx.lock().expect("attention queue poisoned");
            rx.poll_recv(cx)
        })
        .await
    }

    /// Receive the next attention message if one is already queued, without
    /// waiting.
    ///
    /// `None` covers both "nothing pending" and "connection gone"; use
    /// [`attention`](Self::attention) when that distinction matters.
    ///
    /// Synchronous, so cancellation does not apply.
    pub fn try_attention(&self) -> Option<(u16, Vec<u8>)> {
        self.attn_rx
            .lock()
            .expect("attention queue poisoned")
            .try_recv()
            .ok()
    }

    /// Flush the write buffer and mark the message boundary with the EOM flag.
    /// This is the ADSP-specific alternative to a bare flush — use it when the
    /// peer expects record-oriented framing (e.g. PAP / StyleWriter).
    pub async fn write_eom(&mut self) -> io::Result<()> {
        let data = self.write_buf.split().to_vec();
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ActorCmd::SendData {
                conn_id: self.conn_id,
                data,
                eom: true,
                reply: tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?
    }

    /// Send a CloseAdvice and shut down the connection.
    pub async fn close(self) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ActorCmd::Close { conn_id: self.conn_id, reply: tx })
            .await;
        rx.await.unwrap_or(Ok(()))
    }
}

impl AsyncRead for AdspStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_shared(cx, buf)
    }
}

impl AsyncWrite for AdspStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If a send is already in-flight, poll it to completion.
        if let Some(fut) = this.pending_flush.as_mut() {
            let result = fut.as_mut().poll(cx);
            if result.is_ready() {
                this.pending_flush = None;
            }
            return result;
        }

        if this.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        // Drain the write buffer and ship it to the actor.
        let data = this.write_buf.split().to_vec();
        let cmd_tx = this.cmd_tx.clone();
        let conn_id = this.conn_id;

        let fut: Pin<Box<dyn Future<Output = io::Result<()>> + Send>> = Box::pin(async move {
            let (tx, rx) = oneshot::channel();
            cmd_tx
                .send(ActorCmd::SendData { conn_id, data, eom: false, reply: tx })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?;
            rx.await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?
        });

        this.pending_flush = Some(fut);

        // Poll it immediately — will often complete in one shot.
        let fut = this.pending_flush.as_mut().unwrap();
        let result = fut.as_mut().poll(cx);
        if result.is_ready() {
            this.pending_flush = None;
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any buffered data, then the actor will handle the close.
        self.poll_flush(cx)
    }
}

// ── AdspListener ──────────────────────────────────────────────────────────────

pub struct AdspListener {
    local_socket: u8,
    accept_rx: mpsc::Receiver<AdspStream>,
}

impl AdspListener {
    pub async fn accept(&mut self) -> io::Result<AdspStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "listener closed"))
    }

    pub fn local_addr(&self) -> u8 {
        self.local_socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a stream fed by the returned sender, with no actor or socket
    /// behind it, so a test drives the receive queue directly.
    fn test_stream() -> (AdspStream, mpsc::Sender<Vec<u8>>) {
        let (data_tx, data_rx) = mpsc::channel(8);
        let (_attn_tx, attn_rx) = mpsc::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let stream = AdspStream {
            conn_id: 1,
            remote_addr: AdspAddress { network_number: 1, node_number: 2, socket_number: 3 },
            cmd_tx,
            read: std::sync::Mutex::new(ReadState {
                rx: data_rx,
                leftover: BytesMut::new(),
            }),
            attn_rx: std::sync::Mutex::new(attn_rx),
            write_buf: BytesMut::new(),
            pending_flush: None,
        };
        (stream, data_tx)
    }

    /// A read whose buffer is smaller than the arriving chunk must keep the
    /// remainder reachable.
    ///
    /// This also covers the cancellation contract: `read_data` waits without
    /// consuming and only takes bytes after it resolves, so the remainder has
    /// to survive in `ReadState::leftover` between calls. A `select!`-based
    /// test cannot add to this — the macro always runs the handler of a branch
    /// that resolves, so a dropped losing branch has taken nothing to lose.
    #[tokio::test]
    async fn read_data_preserves_partial_chunk_remainder() {
        let (stream, data_tx) = test_stream();
        data_tx.send(b"ABCDEFGH".to_vec()).await.expect("send failed");

        let mut first = [0u8; 4];
        let n = stream.read_data(&mut first).await.expect("read failed");
        assert_eq!(&first[..n], b"ABCD");

        let mut second = [0u8; 8];
        let n2 = stream.read_data(&mut second).await.expect("read failed");
        assert_eq!(&second[..n2], b"EFGH", "the chunk remainder was stranded");
    }
}
