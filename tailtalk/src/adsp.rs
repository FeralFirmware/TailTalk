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
    ) -> AdspStream {
        AdspStream {
            conn_id,
            remote_addr,
            cmd_tx: self.cmd_tx.clone(),
            data_rx,
            read_buf: BytesMut::new(),
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
            data_tx,
            pending_writes: std::collections::VecDeque::new(),
            pending_close: None,
        });
        self.make_stream(map_key, remote_addr, data_rx)
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
                let result = self.send_attention_msg(conn_id, code, &data).await;
                let _ = reply.send(result);
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

    async fn handle_attention(&mut self, packet: AdspPacket, data: &[u8]) {
        if data.len() < 2 {
            return;
        }
        let attention_code = byteorder::BigEndian::read_u16(&data[0..2]);
        tracing::info!(
            "ADSP attention 0x{:04X} on conn {}",
            attention_code,
            packet.connection_id
        );

        let Some(conn) = self.connections.get(&packet.connection_id) else { return };
        let remote_addr = conn.remote_addr;
        let send_seq = conn.send_seq;
        let recv_seq = conn.recv_seq;
        let our_conn_id = conn.our_conn_id;

        // Attention ack: descriptor 0x90 = ControlPacket(0x80) | Attention(0x10).
        let ack = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: our_conn_id,
            first_byte_seq: send_seq,
            next_recv_seq: recv_seq,
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
        if let Some(conn) = self.connections.remove(&packet.connection_id) {
            tracing::info!("ADSP conn {} closed by peer", packet.connection_id);
            drop(conn.data_tx); // causes the reader to see EOF
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

    async fn send_attention_msg(&mut self, conn_id: u16, code: u16, data: &[u8]) -> io::Result<()> {
        let (remote_addr, attn_send_seq, recv_seq, our_conn_id) = {
            let conn = self.connections.get_mut(&conn_id).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no such connection")
            })?;
            let seq = conn.attn_send_seq;
            conn.attn_send_seq = conn.attn_send_seq.wrapping_add(1);
            (conn.remote_addr, seq, conn.recv_seq, conn.our_conn_id)
        };

        // Attention packet (spec §12, Figure 12-7): desc byte 0x50.
        let mut buf = vec![0u8; AdspPacket::HEADER_LEN + 2 + data.len()];
        let pkt = AdspPacket {
            descriptor: AdspDescriptor::DataPacket,
            connection_id: our_conn_id,
            first_byte_seq: attn_send_seq,
            next_recv_seq: recv_seq,
            recv_window: 0, // must be 0 for attention per spec
            flags: AdspPacket::FLAG_ACK | AdspPacket::FLAG_ATTENTION,
        };
        pkt.to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        byteorder::BigEndian::write_u16(&mut buf[AdspPacket::HEADER_LEN..], code);
        buf[AdspPacket::HEADER_LEN + 2..].copy_from_slice(data);

        self.sock
            .send_to(&buf, ddp_dest(remote_addr))
            .await
            .map_err(io::Error::other)
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

        self.connections.remove(&conn_id);
        Ok(())
    }
}

// ── AdspStream ────────────────────────────────────────────────────────────────
//
// AdspStream: Unpin — all fields are Unpin (Box<T>: Unpin unconditionally, so
// Pin<Box<dyn Future>>: Unpin), which lets us use Pin::get_mut() freely in the
// poll_* impls and store a boxed future across poll_flush invocations.

pub struct AdspStream {
    conn_id: u16,
    remote_addr: AdspAddress,
    cmd_tx: mpsc::Sender<ActorCmd>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: BytesMut,
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
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let to_copy = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..to_copy]);
            this.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        match this.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    this.read_buf.extend_from_slice(&data[to_copy..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF — data_tx was dropped
            Poll::Pending => Poll::Pending,
        }
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
