use crate::ddp::{DdpHandle, DdpSocket};
use bytes::{Buf, BytesMut};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tailtalk_packets::{
    adsp::{AdspDescriptor, AdspPacket},
    ddp::DdpProtocolType,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// ADSP network address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdspAddress {
    pub network_number: u16,
    pub node_number: u8,
    pub socket_number: u8,
}

/// Connection state for ADSP state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ConnectionState {
    Closed,
    Opening,
    Open,
    Closing,
}

/// Internal connection tracking
struct AdspConnection {
    state: ConnectionState,
    remote_addr: AdspAddress,
    send_seq: u32,
    recv_seq: u32,
    recv_window: u16,
    send_window: u16,
    // Channel to send received data to the stream
    data_tx: mpsc::Sender<Vec<u8>>,
    // Channel to receive commands from the stream
    command_rx: mpsc::Receiver<AdspCommand>,
}

/// Commands sent from AdspStream to the Adsp actor
enum AdspCommand {
    SendData {
        data: Vec<u8>,
        result: oneshot::Sender<io::Result<()>>,
    },
    Close {
        result: oneshot::Sender<io::Result<()>>,
    },
}

/// ADSP protocol handler actor
pub struct Adsp {
    sock: DdpSocket,
    connections: HashMap<u16, AdspConnection>,
    accept_tx: Option<mpsc::Sender<AdspStream>>,
    pending_opens: HashMap<u16, oneshot::Sender<io::Result<AdspStream>>>,
}

impl Adsp {
    /// Spawn an ADSP listener on the specified socket
    pub async fn bind(
        ddp: &DdpHandle,
        socket_number: Option<u8>,
    ) -> io::Result<(u8, AdspListener)> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, socket_number)
            .await
            .map_err(io::Error::other)?;

        let actual_socket = sock.socket_num();
        let (accept_tx, accept_rx) = mpsc::channel(10);

        let adsp = Adsp {
            sock,
            connections: HashMap::new(),
            accept_tx: Some(accept_tx),
            pending_opens: HashMap::new(),
        };

        tokio::spawn(async move {
            adsp.run().await;
        });

        let listener = AdspListener {
            local_socket: actual_socket,
            accept_rx,
        };

        Ok((actual_socket, listener))
    }

    /// Create a new ADSP socket for connecting to a remote endpoint
    pub async fn connect(ddp: &DdpHandle, remote_addr: AdspAddress) -> io::Result<AdspStream> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, None)
            .await
            .map_err(io::Error::other)?;

        let (ready_tx, ready_rx) = oneshot::channel();
        let connection_id = 1; // Will be assigned by actor

        let adsp = Adsp {
            sock,
            connections: HashMap::new(),
            accept_tx: None,
            pending_opens: [(connection_id, ready_tx)].into(),
        };

        tokio::spawn(async move {
            let mut adsp = adsp;
            // Send OpenConnRequest
            adsp.initiate_connection(connection_id, remote_addr).await;
            adsp.run().await;
        });

        // Wait for connection to be established
        ready_rx.await.map_err(io::Error::other)?
    }

    async fn initiate_connection(&mut self, connection_id: u16, remote_addr: AdspAddress) {
        let packet = AdspPacket {
            descriptor: AdspDescriptor::OpenConnRequest,
            connection_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 4096,
        };

        let mut buf = [0u8; 600];
        if let Ok(len) = packet.to_bytes(&mut buf) {
            let dest = crate::ddp::DdpAddress::new(
                tailtalk_packets::aarp::AppleTalkAddress {
                    network_number: remote_addr.network_number,
                    node_number: remote_addr.node_number,
                },
                remote_addr.socket_number,
            );

            if let Err(e) = self.sock.send_to(&buf[..len], dest).await {
                tracing::error!("Failed to send OpenConnRequest: {}", e);
            } else {
                tracing::info!("Sent ADSP OpenConnRequest to {:?}", remote_addr);
            }
        }
    }

    async fn run(mut self) {
        loop {
            // Collect commands from all connections
            let mut commands_to_process = Vec::new();
            for (conn_id, conn) in &mut self.connections {
                while let Ok(cmd) = conn.command_rx.try_recv() {
                    commands_to_process.push((*conn_id, cmd));
                }
            }

            // Process collected commands
            for (conn_id, cmd) in commands_to_process {
                self.handle_command(conn_id, cmd).await;
            }

            tokio::select! {
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => {
                            self.handle_packet(pkt.headers, &mut pkt.payload).await;
                        }
                        Err(e) => {
                            tracing::error!("ADSP socket error: {}", e);
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {
                    // Periodic tick for command processing
                }
            }
        }
    }

    async fn handle_packet(&mut self, ddp: tailtalk_packets::ddp::DdpPacket, payload: &mut [u8]) {
        let packet = match AdspPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse ADSP packet: {:?}", e);
                return;
            }
        };

        tracing::debug!(
            "ADSP received {:?} from {}.{} conn_id={}",
            packet.descriptor,
            ddp.src_network_num,
            ddp.src_node_id,
            packet.connection_id
        );

        match packet.descriptor {
            AdspDescriptor::OpenConnRequest => {
                self.handle_open_request(ddp, packet).await;
            }
            AdspDescriptor::OpenConnAck | AdspDescriptor::OpenConnReqAck => {
                self.handle_open_ack(ddp, packet).await;
            }
            AdspDescriptor::ControlPacket => {
                self.handle_data(packet, &payload[AdspPacket::HEADER_LEN..])
                    .await;
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

    async fn handle_open_request(
        &mut self,
        ddp: tailtalk_packets::ddp::DdpPacket,
        packet: AdspPacket,
    ) {
        // Server side: accept incoming connection
        let connection_id = packet.connection_id;
        let remote_addr = AdspAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        };

        tracing::info!("ADSP accepting connection from {:?}", remote_addr);

        // Create channels for this connection
        let (data_tx, data_rx) = mpsc::channel(100);
        let (command_tx, command_rx) = mpsc::channel(10);

        // Create connection state
        let connection = AdspConnection {
            state: ConnectionState::Open,
            remote_addr,
            send_seq: 0,
            recv_seq: 0,
            recv_window: 4096,
            send_window: packet.recv_window,
            data_tx,
            command_rx,
        };

        self.connections.insert(connection_id, connection);

        // Send OpenConnAck
        let ack_packet = AdspPacket {
            descriptor: AdspDescriptor::OpenConnAck,
            connection_id,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 4096,
        };

        let mut buf = [0u8; 600];
        if let Ok(len) = ack_packet.to_bytes(&mut buf) {
            let dest = crate::ddp::DdpAddress::new(
                tailtalk_packets::aarp::AppleTalkAddress {
                    network_number: remote_addr.network_number,
                    node_number: remote_addr.node_number,
                },
                remote_addr.socket_number,
            );

            let _ = self.sock.send_to(&buf[..len], dest).await;
        }

        // Create stream and send to listener
        let stream = AdspStream {
            connection_id,
            remote_addr,
            command_tx,
            data_rx,
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
        };

        if let Some(accept_tx) = &self.accept_tx {
            let _ = accept_tx.send(stream).await;
        }
    }

    async fn handle_open_ack(&mut self, ddp: tailtalk_packets::ddp::DdpPacket, packet: AdspPacket) {
        // Client side: connection established
        let connection_id = packet.connection_id;

        if let Some(ready_tx) = self.pending_opens.remove(&connection_id) {
            let remote_addr = AdspAddress {
                network_number: ddp.src_network_num,
                node_number: ddp.src_node_id,
                socket_number: ddp.src_sock_num,
            };

            tracing::info!("ADSP connection established to {:?}", remote_addr);

            let (data_tx, data_rx) = mpsc::channel(100);
            let (command_tx, command_rx) = mpsc::channel(10);

            let connection = AdspConnection {
                state: ConnectionState::Open,
                remote_addr,
                send_seq: 0,
                recv_seq: 0,
                recv_window: 4096,
                send_window: packet.recv_window,
                data_tx,
                command_rx,
            };

            self.connections.insert(connection_id, connection);

            let stream = AdspStream {
                connection_id,
                remote_addr,
                command_tx,
                data_rx,
                read_buf: BytesMut::new(),
                write_buf: BytesMut::new(),
            };

            let _ = ready_tx.send(Ok(stream));
        }
    }

    async fn handle_data(&mut self, packet: AdspPacket, data: &[u8]) {
        if let Some(conn) = self.connections.get_mut(&packet.connection_id) {
            // Update sequence numbers
            conn.recv_seq = packet.first_byte_seq.wrapping_add(data.len() as u32);

            // Send data to stream
            if !data.is_empty() {
                let _ = conn.data_tx.send(data.to_vec()).await;
            }

            // Send acknowledgment
            let _ = self.send_ack(packet.connection_id).await;
        }
    }

    async fn handle_ack(&mut self, packet: AdspPacket) {
        if let Some(conn) = self.connections.get_mut(&packet.connection_id) {
            // Update send window
            conn.send_window = packet.recv_window;
            tracing::debug!("ADSP ack recv_window={}", packet.recv_window);
        }
    }

    async fn handle_close(&mut self, packet: AdspPacket) {
        if let Some(mut conn) = self.connections.remove(&packet.connection_id) {
            conn.state = ConnectionState::Closed;
            tracing::info!("ADSP connection {} closed by peer", packet.connection_id);
        }
    }

    async fn handle_command(&mut self, connection_id: u16, command: AdspCommand) {
        match command {
            AdspCommand::SendData { data, result } => {
                let res = self.send_data(connection_id, &data).await;
                let _ = result.send(res);
            }
            AdspCommand::Close { result } => {
                let res = self.close_connection(connection_id).await;
                let _ = result.send(res);
            }
        }
    }

    async fn send_data(&mut self, connection_id: u16, data: &[u8]) -> io::Result<()> {
        let conn = self
            .connections
            .get_mut(&connection_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection closed"))?;

        let packet = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: conn.recv_window,
        };

        let mut buf = [0u8; 600];
        let header_len = packet
            .to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let total_len = header_len + data.len();
        if total_len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "data too large",
            ));
        }

        buf[header_len..total_len].copy_from_slice(data);

        let dest = crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: conn.remote_addr.network_number,
                node_number: conn.remote_addr.node_number,
            },
            conn.remote_addr.socket_number,
        );

        self.sock
            .send_to(&buf[..total_len], dest)
            .await
            .map_err(io::Error::other)?;

        conn.send_seq = conn.send_seq.wrapping_add(data.len() as u32);

        Ok(())
    }

    async fn send_ack(&mut self, connection_id: u16) -> io::Result<()> {
        let conn = self
            .connections
            .get(&connection_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection closed"))?;

        let packet = AdspPacket {
            descriptor: AdspDescriptor::Acknowledgment,
            connection_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: conn.recv_window,
        };

        let mut buf = [0u8; 600];
        let len = packet
            .to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let dest = crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: conn.remote_addr.network_number,
                node_number: conn.remote_addr.node_number,
            },
            conn.remote_addr.socket_number,
        );

        self.sock
            .send_to(&buf[..len], dest)
            .await
            .map_err(io::Error::other)?;

        Ok(())
    }

    async fn close_connection(&mut self, connection_id: u16) -> io::Result<()> {
        let conn = self
            .connections
            .get(&connection_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection closed"))?;

        let packet = AdspPacket {
            descriptor: AdspDescriptor::CloseAdvice,
            connection_id,
            first_byte_seq: conn.send_seq,
            next_recv_seq: conn.recv_seq,
            recv_window: 0,
        };

        let mut buf = [0u8; 600];
        let len = packet
            .to_bytes(&mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let dest = crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: conn.remote_addr.network_number,
                node_number: conn.remote_addr.node_number,
            },
            conn.remote_addr.socket_number,
        );

        self.sock
            .send_to(&buf[..len], dest)
            .await
            .map_err(io::Error::other)?;

        self.connections.remove(&connection_id);

        Ok(())
    }
}

/// ADSP stream - similar to TcpStream
pub struct AdspStream {
    connection_id: u16,
    remote_addr: AdspAddress,
    command_tx: mpsc::Sender<AdspCommand>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: BytesMut,
    write_buf: BytesMut,
}

impl AdspStream {
    /// Get the local connection ID
    pub fn local_addr(&self) -> u16 {
        self.connection_id
    }

    /// Get the remote address
    pub fn peer_addr(&self) -> AdspAddress {
        self.remote_addr
    }

    /// Close the connection gracefully
    pub async fn close(self) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        // If sending fails, the actor is already gone (connection closed)
        if self
            .command_tx
            .send(AdspCommand::Close { result: tx })
            .await
            .is_err()
        {
            // Actor is gone, connection already closed - this is OK
            return Ok(());
        }
        // Wait for response - if it fails, connection was already closed
        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) if e.kind() == io::ErrorKind::NotConnected => {
                // Connection already closed - this is OK
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Channel dropped - connection already closed
                Ok(())
            }
        }
    }
}

impl AsyncRead for AdspStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data
        if !self.read_buf.is_empty() {
            let to_read = std::cmp::min(self.read_buf.len(), buf.remaining());
            buf.put_slice(&self.read_buf[..to_read]);
            self.read_buf.advance(to_read);
            return Poll::Ready(Ok(()));
        }

        // Try to receive new data
        match self.data_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);

                // Buffer any remaining data
                if to_read < data.len() {
                    self.read_buf.extend_from_slice(&data[to_read..]);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AdspStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Add data to write buffer
        self.write_buf.extend_from_slice(buf);

        // Try to flush
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Ready(Ok(buf.len())), // Buffered for later
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        // Send all buffered data
        let data = self.write_buf.split().to_vec();
        let (tx, _rx) = oneshot::channel();

        let command_tx = self.command_tx.clone();
        tokio::spawn(async move {
            let _ = command_tx
                .send(AdspCommand::SendData { data, result: tx })
                .await;
        });

        // For simplicity, assume it completes immediately
        // In a real implementation, we'd need to track pending writes
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any pending data, then close
        match self.poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                // Connection will be closed when AdspStream is dropped
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// ADSP listener - similar to TcpListener
pub struct AdspListener {
    local_socket: u8,
    accept_rx: mpsc::Receiver<AdspStream>,
}

impl AdspListener {
    /// Accept an incoming connection
    pub async fn accept(&mut self) -> io::Result<AdspStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "listener closed"))
    }

    /// Get the local socket number
    pub fn local_addr(&self) -> u8 {
        self.local_socket
    }
}
