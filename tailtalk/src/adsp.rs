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

struct AdspConnection {
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
    /// Delivers received data to the AdspStream reader.
    data_tx: mpsc::Sender<Vec<u8>>,
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

    /// Register a new open connection and return the user-facing stream.
    fn open_connection(
        &mut self,
        conn_id: u16,
        remote_addr: AdspAddress,
        peer_window: u16,
    ) -> AdspStream {
        let (data_tx, data_rx) = mpsc::channel(32);
        self.connections.insert(conn_id, AdspConnection {
            state: ConnectionState::Open,
            remote_addr,
            send_seq: 0,
            oldest_unacked_seq: 0,
            recv_seq: 0,
            send_window: peer_window,
            flight_buffer: Vec::new(),
            last_tx: std::time::Instant::now(),
            retries: 0,
            data_tx,
        });
        self.make_stream(conn_id, remote_addr, data_rx)
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
                let result = self.send_data(conn_id, &data, eom).await;
                let _ = reply.send(result);
            }
            ActorCmd::Close { conn_id, reply } => {
                let result = self.close_connection(conn_id).await;
                let _ = reply.send(result);
            }
        }
    }

    // ── Retransmit tick ───────────────────────────────────────────────────────

    async fn tick(&mut self) {
        let now = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(3);

        let conn_ids: Vec<u16> = self.connections.keys().copied().collect();
        for conn_id in conn_ids {
            let conn = match self.connections.get_mut(&conn_id) {
                Some(c) => c,
                None => continue,
            };

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

            let data: Vec<u8> = conn.flight_buffer.clone();
            let remote_addr = conn.remote_addr;
            let oldest_seq = conn.oldest_unacked_seq;
            let recv_seq = conn.recv_seq;

            for (i, chunk) in data.chunks(ADSP_MAX_DATA).enumerate() {
                let chunk_seq = oldest_seq.wrapping_add((i * ADSP_MAX_DATA) as u32);
                let pkt = AdspPacket {
                    descriptor: AdspDescriptor::ControlPacket,
                    connection_id: conn_id,
                    first_byte_seq: chunk_seq,
                    next_recv_seq: recv_seq,
                    recv_window: ADSP_RECV_WINDOW,
                    flags: 0,
                };
                let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
                if pkt.to_bytes(&mut buf).is_ok() {
                    buf[AdspPacket::HEADER_LEN..].copy_from_slice(chunk);
                    let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
                }
            }

            if let Some(c) = self.connections.get_mut(&conn_id) {
                c.last_tx = now;
            }
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
                self.handle_open_ack(ddp, packet).await;
            }
            AdspDescriptor::ControlPacket => {
                self.handle_data(packet, &payload[AdspPacket::HEADER_LEN..]).await;
            }
            AdspDescriptor::Acknowledgment => {
                self.handle_ack(packet).await;
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

        let ack = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: packet.connection_id,
            first_byte_seq: send_seq,
            next_recv_seq: recv_seq,
            recv_window: ADSP_RECV_WINDOW,
            flags: AdspPacket::FLAG_ATTENTION | AdspPacket::FLAG_ACK,
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
        let conn_id = packet.connection_id;
        let remote_addr = AdspAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        };

        tracing::info!("ADSP accepting conn {} from {:?}", conn_id, remote_addr);

        let stream = self.open_connection(conn_id, remote_addr, packet.recv_window);

        let ack = AdspPacket {
            descriptor: AdspDescriptor::OpenConnAck,
            connection_id: conn_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: ADSP_RECV_WINDOW,
            flags: 0,
        };
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        if ack.to_bytes(&mut buf).is_ok() {
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
    ) {
        let conn_id = packet.connection_id;
        let Some(ready_tx) = self.pending_opens.remove(&conn_id) else { return };

        let remote_addr = AdspAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        };

        tracing::info!("ADSP conn {} established to {:?}", conn_id, remote_addr);

        let stream = self.open_connection(conn_id, remote_addr, packet.recv_window);
        let _ = ready_tx.send(Ok(stream));
    }

    async fn handle_data(&mut self, packet: AdspPacket, data: &[u8]) {
        let Some(conn) = self.connections.get_mut(&packet.connection_id) else { return };

        if !data.is_empty() {
            conn.recv_seq = packet.first_byte_seq.wrapping_add(data.len() as u32);
            if conn.data_tx.try_send(data.to_vec()).is_err() {
                tracing::warn!("ADSP conn {} receive buffer full, dropping data", packet.connection_id);
            }
        }

        let _ = self.send_ack(packet.connection_id).await;
    }

    async fn handle_ack(&mut self, packet: AdspPacket) {
        let Some(conn) = self.connections.get_mut(&packet.connection_id) else { return };

        conn.send_window = packet.recv_window;

        let acked = packet
            .next_recv_seq
            .wrapping_sub(conn.oldest_unacked_seq) as usize;
        if acked > 0 && acked <= conn.flight_buffer.len() {
            conn.flight_buffer.drain(..acked);
            conn.oldest_unacked_seq = packet.next_recv_seq;
            conn.retries = 0;
        }
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
        let mut buf = [0u8; AdspPacket::HEADER_LEN];
        if pkt.to_bytes(&mut buf).is_ok() {
            let _ = self.sock.send_to(&buf, ddp_dest(remote_addr)).await;
        }
    }

    async fn send_data(
        &mut self,
        conn_id: u16,
        data: &[u8],
        eom: bool,
    ) -> io::Result<()> {
        let conn = self
            .connections
            .get_mut(&conn_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such connection"))?;

        if conn.state != ConnectionState::Open {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "connection closing"));
        }

        // Empty EOM flush (just a control packet with EOM set, no data).
        if data.is_empty() && eom {
            let pkt = AdspPacket {
                descriptor: AdspDescriptor::ControlPacket,
                connection_id: conn_id,
                first_byte_seq: conn.send_seq,
                next_recv_seq: conn.recv_seq,
                recv_window: ADSP_RECV_WINDOW,
                flags: AdspPacket::FLAG_EOM,
            };
            let mut buf = [0u8; AdspPacket::HEADER_LEN];
            pkt.to_bytes(&mut buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            return self
                .sock
                .send_to(&buf, ddp_dest(conn.remote_addr))
                .await
                .map_err(io::Error::other);
        }

        let chunks: Vec<&[u8]> = data.chunks(ADSP_MAX_DATA).collect();
        let last_idx = chunks.len().saturating_sub(1);

        for (i, chunk) in chunks.iter().enumerate() {
            let flags = if eom && i == last_idx { AdspPacket::FLAG_EOM } else { 0 };

            let pkt = AdspPacket {
                descriptor: AdspDescriptor::ControlPacket,
                connection_id: conn_id,
                first_byte_seq: conn.send_seq,
                next_recv_seq: conn.recv_seq,
                recv_window: ADSP_RECV_WINDOW,
                flags,
            };

            let mut buf = vec![0u8; AdspPacket::HEADER_LEN + chunk.len()];
            pkt.to_bytes(&mut buf)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            buf[AdspPacket::HEADER_LEN..].copy_from_slice(chunk);

            self.sock
                .send_to(&buf, ddp_dest(conn.remote_addr))
                .await
                .map_err(io::Error::other)?;

            conn.flight_buffer.extend_from_slice(chunk);
            conn.send_seq = conn.send_seq.wrapping_add(chunk.len() as u32);
        }
        conn.last_tx = std::time::Instant::now();

        Ok(())
    }

    async fn send_ack(&mut self, conn_id: u16) -> io::Result<()> {
        let conn = self
            .connections
            .get(&conn_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no such connection"))?;

        let pkt = AdspPacket {
            descriptor: AdspDescriptor::Acknowledgment,
            connection_id: conn_id,
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

    async fn close_connection(&mut self, conn_id: u16) -> io::Result<()> {
        let Some(conn) = self.connections.get(&conn_id) else {
            return Ok(()); // already gone
        };

        let pkt = AdspPacket {
            descriptor: AdspDescriptor::CloseAdvice,
            connection_id: conn_id,
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
