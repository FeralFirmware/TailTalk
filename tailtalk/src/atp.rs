use crate::ddp::{DdpHandle, DdpSocket};
use std::collections::HashMap;
use std::io;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_core::Micros;
use tailtalk_core::atp::{AtpEndpoint, AtpEvent};
use tokio::sync::{mpsc, oneshot};

fn service_addr(addr: AtpAddress) -> tailtalk_packets::nbp::ServiceAddress {
    tailtalk_packets::nbp::ServiceAddress {
        network_number: addr.network_number,
        node_number: addr.node_number,
        socket_number: addr.socket_number,
    }
}

fn ddp_dest(addr: AtpAddress) -> crate::ddp::DdpAddress {
    addr.into()
}

/// Maximum data bytes per ATP packet.
/// DDP max datagram = 599 bytes; minus 13-byte DDP header = 586 bytes DDP payload;
/// minus 8-byte ATP header = 578 bytes of ATP data per packet.
pub const ATP_MAX_DATA_PER_PACKET: usize = 578;

// Type aliases for complex channel types
type AtpResponseChannel = oneshot::Sender<Result<(Vec<u8>, [u8; 4]), io::Error>>;





// Helper struct since DdpAddress might be ambiguous if not imported carefully
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AtpAddress {
    pub network_number: u16,
    pub node_number: u8,
    pub socket_number: u8,
}

impl From<tailtalk_packets::nbp::ServiceAddress> for AtpAddress {
    fn from(a: tailtalk_packets::nbp::ServiceAddress) -> Self {
        AtpAddress {
            network_number: a.network_number,
            node_number: a.node_number,
            socket_number: a.socket_number,
        }
    }
}

impl From<AtpAddress> for crate::ddp::DdpAddress {
    fn from(a: AtpAddress) -> Self {
        crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: a.network_number,
                node_number: a.node_number,
            },
            a.socket_number,
        )
    }
}

impl AtpAddress {
}

#[derive(Debug)]
pub struct AtpSendRequest {
    pub address: AtpAddress,
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
    pub bitmap: u8,
    pub chan: AtpResponseChannel,
}

#[derive(Debug)]
pub struct AtpResponse {
    pub data: Vec<u8>,
    pub user_bytes: [u8; 4],
}

#[derive(Debug)]
pub struct AtpSendResponse {
    pub destination: AtpAddress,
    pub tid: u16,
    pub packets: Vec<AtpResponse>,
}


/// A fire-and-forget ALO (at-least-once) packet — no pending transaction is registered
/// and no response is waited on. Any response that arrives will be silently discarded.
/// Used for ASP tickles.
#[derive(Debug)]
pub struct AtpSendAlo {
    pub address: AtpAddress,
    pub user_bytes: [u8; 4],
}

pub enum AtpCommand {
    SendRequest(AtpSendRequest),
    SendResponse(AtpSendResponse),
    SendAlo(AtpSendAlo),
}

pub struct AtpReceivedRequest {
    pub transaction_id: u16,
    pub source: AtpAddress,
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
    pub response_sender: mpsc::Sender<AtpCommand>,
    /// The ATP bitmap from the request: each set bit = one response packet the client will accept.
    /// bit 0 = packet 0, bit 1 = packet 1, ..., bit 7 = packet 7 (max 8 packets).
    pub bitmap: u8,
}

impl AtpReceivedRequest {
    /// Number of response packets this request's bitmap allows us to send (1-8).
    ///
    /// IMPORTANT: Classic Mac OS sends bitmap=0x00 in ASP SPCommand TReqs, which is
    /// non-standard per the ATP spec (0x00 means "no buffers"), but in practice it means
    /// "no restriction": treat it the same as 0xFF (all 8 packets allowed). Clamping it
    /// to 1 packet would silently truncate multi-packet responses and corrupt the
    /// client's file offset.
    pub fn max_packets(&self) -> usize {
        let effective_bitmap = if self.bitmap == 0x00 { 0xFF } else { self.bitmap };
        (effective_bitmap.count_ones() as usize).clamp(1, 8)
    }

    /// Returns the maximum number of response data bytes this request can accept,
    /// derived from the client's ATP bitmap. Use this to cap response payloads
    /// before calling send_response so AFP/ASP layers can truncate cleanly.
    pub fn max_response_bytes(&self) -> usize {
        self.max_packets() * ATP_MAX_DATA_PER_PACKET
    }

    /// Send a response with automatic fragmentation at the ATP packet limit.
    ///
    /// Respects the client's ATP bitmap: only sends as many packets as the client
    /// declared it can receive. Sending more packets than the bitmap allows causes
    /// ASP error -1067 (aspBufTooSmall).
    pub async fn send_response(
        &self,
        data: impl AsRef<[u8]>,
        user_bytes: [u8; 4],
    ) -> Result<(), io::Error> {
        self.send_response_chunked(data, user_bytes, ATP_MAX_DATA_PER_PACKET)
            .await
    }

    /// Send a response fragmented at `chunk_size` bytes per ATP packet.
    ///
    /// Use this when the protocol layer imposes a stricter per-packet limit than
    /// `ATP_MAX_DATA_PER_PACKET`. PAP, for example, caps each packet at 512 bytes.
    pub async fn send_response_chunked(
        &self,
        data: impl AsRef<[u8]>,
        user_bytes: [u8; 4],
        chunk_size: usize,
    ) -> Result<(), io::Error> {
        let data = data.as_ref();
        assert!(chunk_size > 0, "chunk_size must be positive");
        let max_packets = self.max_packets();
        let max_data = max_packets * chunk_size;

        if data.len() > max_data {
            tracing::warn!(
                "ATP response truncated: {} bytes requested but client bitmap 0x{:02x} only allows {} bytes ({} packets of {})",
                data.len(),
                self.bitmap,
                max_data,
                max_packets,
                chunk_size
            );
        }

        let mut packets: Vec<AtpResponse> = data[..data.len().min(max_data)]
            .chunks(chunk_size)
            .map(|chunk| AtpResponse { data: chunk.to_vec(), user_bytes })
            .collect();

        // ATP requires at least one TResp even for zero-length data.
        if packets.is_empty() {
            packets.push(AtpResponse { data: vec![], user_bytes });
        }

        self.send_response_internal(packets).await
    }

    /// Internal method for sending pre-split packets.
    async fn send_response_internal(&self, packets: Vec<AtpResponse>) -> Result<(), io::Error> {
        if packets.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot send more than 8 response packets",
            ));
        }
        let cmd = AtpCommand::SendResponse(AtpSendResponse {
            destination: self.source,
            tid: self.transaction_id,
            packets,
        });
        self.response_sender
            .send(cmd)
            .await
            .map_err(io::Error::other)
    }
}

#[derive(Clone, Debug)]
pub struct AtpRequestor {
    pub cmd_tx: mpsc::Sender<AtpCommand>,
    pub socket_number: u8,
}

impl AtpRequestor {
    /// Send an ALO (at-least-once) packet with no pending transaction registered.
    /// Returns immediately after queueing — no response is awaited.
    pub async fn send_alo(
        &self,
        address: AtpAddress,
        user_bytes: [u8; 4],
    ) -> Result<(), io::Error> {
        let cmd = AtpCommand::SendAlo(AtpSendAlo { address, user_bytes });
        self.cmd_tx.send(cmd).await.map_err(io::Error::other)
    }

    /// Send a request and await its response, accepting up to 8 response packets
    /// (bitmap `0xff`). Use [`send_request_with_bitmap`](Self::send_request_with_bitmap)
    /// when the reply is known to always fit in fewer packets.
    pub async fn send_request(
        &self,
        address: AtpAddress,
        user_bytes: [u8; 4],
        data: Vec<u8>,
    ) -> Result<(Vec<u8>, [u8; 4]), io::Error> {
        self.send_request_with_bitmap(address, user_bytes, data, 0xff).await
    }

    /// Send a request, advertising exactly which response packet slots (0-7) we'll
    /// accept via `bitmap`. A responder that fills every requested slot is
    /// recognized as complete immediately, without waiting for EOM — per ATP spec,
    /// EOM only matters when the responder sends *fewer* packets than requested.
    /// Pass `0x01` for requests whose reply is known to always be a single packet
    /// (e.g. PAP OpenConn/CloseConn) to skip the stalled-retransmit fallback in
    /// `retransmit_pending` for responders that never set EOM.
    pub async fn send_request_with_bitmap(
        &self,
        address: AtpAddress,
        user_bytes: [u8; 4],
        data: Vec<u8>,
        bitmap: u8,
    ) -> Result<(Vec<u8>, [u8; 4]), io::Error> {
        let (tx, rx) = oneshot::channel();
        let cmd = AtpCommand::SendRequest(AtpSendRequest {
            address,
            user_bytes,
            data,
            bitmap,
            chan: tx,
        });

        self.cmd_tx.send(cmd).await.map_err(io::Error::other)?;

        rx.await.map_err(io::Error::other)?
    }
}

#[derive(Debug)]
pub struct AtpResponder {
    incoming_rx: mpsc::Receiver<AtpReceivedRequest>,
    /// The requesting half of the same socket. ATP sockets are symmetric: ASP
    /// serves commands on its socket while sending tickles from it. Bundling it
    /// here also means a server handed only a responder still owns the socket,
    /// which is what keeps `PapServer` alive.
    requestor: AtpRequestor,
}

impl AtpResponder {
    pub async fn next(&mut self) -> Option<AtpReceivedRequest> {
        self.incoming_rx.recv().await
    }

    /// The requesting half of this socket, for sending requests from the same
    /// socket number that serves them.
    pub fn requestor(&self) -> &AtpRequestor {
        &self.requestor
    }
}

pub struct Atp {
    sock: DdpSocket,
    /// The protocol state machine, shared with the embedded firmware:
    /// transaction ids, the requestor's retransmit schedule, and the
    /// exactly-once reply cache all live in here.
    endpoint: AtpEndpoint,
    request_recv: mpsc::Receiver<AtpCommand>,
    incoming_req_tx: mpsc::Sender<AtpReceivedRequest>,
    /// Weak on purpose: a strong clone here would keep the command channel's
    /// sender count above zero forever, so `run` could never return and the
    /// [`DdpSocket`] it owns would never be dropped, leaking its socket
    /// number. Liveness comes from the [`AtpRequestor`]s held outside the
    /// actor, including the one inside [`AtpResponder`].
    ///
    /// Upgraded only to stamp a reply channel onto an inbound request. That
    /// gives the resulting [`AtpReceivedRequest`] a strong sender, so a
    /// socket cannot be recycled while a reply on it is still owed.
    cmd_tx: mpsc::WeakSender<AtpCommand>,
    /// Callers awaiting a response, keyed by the handle `request` returned.
    waiting: HashMap<u16, AtpResponseChannel>,
    /// The endpoint takes monotonic microseconds; this is their zero point.
    epoch: std::time::Instant,
}

impl Atp {
    pub async fn spawn(
        ddp: &DdpHandle,
        socket_number: Option<u8>,
    ) -> (u8, AtpRequestor, AtpResponder) {
        let sock = ddp
            .new_sock(DdpProtocolType::Atp, socket_number) // Use provided or dynamic socket
            .await
            .expect("failed to create ATP sock");

        let actual_socket = sock.socket_num();

        let (request_send, request_recv) = mpsc::channel(100);
        let (incoming_req_tx, incoming_req_rx) = mpsc::channel(32);

        let atp = Atp {
            sock,
            endpoint: AtpEndpoint::new(actual_socket),
            request_recv,
            incoming_req_tx,
            cmd_tx: request_send.downgrade(),
            waiting: HashMap::new(),
            epoch: std::time::Instant::now(),
        };

        tokio::spawn(async move {
            tracing::debug!("ATP actor starting");
            atp.run().await;
            tracing::debug!("ATP actor stopped");
        });

        let requestor = AtpRequestor {
            cmd_tx: request_send,
            socket_number: actual_socket,
        };

        (
            actual_socket,
            requestor.clone(),
            AtpResponder {
                incoming_rx: incoming_req_rx,
                requestor,
            },
        )
    }

    fn now(&self) -> Micros {
        self.epoch.elapsed().as_micros() as Micros
    }

    async fn run(mut self) {
        loop {
            // The endpoint says exactly when it next needs waking - a
            // retransmit deadline or a reply-cache expiry - so there is no
            // polling tick to round deadlines to.
            let wait = self.endpoint.next_deadline().map(|deadline| {
                std::time::Duration::from_micros(deadline.saturating_sub(self.now()))
            });

            tokio::select! {
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(pkt) => {
                            let src = tailtalk_packets::nbp::ServiceAddress {
                                network_number: pkt.headers.src_network_num,
                                node_number: pkt.headers.src_node_id,
                                socket_number: pkt.headers.src_sock_num,
                            };
                            let now = self.now();
                            self.endpoint.handle_datagram(src, &pkt.payload, now);
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                            tracing::debug!("ATP socket closed, shutting down");
                            break;
                        },
                        Err(e) => {
                            tracing::error!("ATP socket error: {}", e);
                            break;
                        },
                    }
                },
                req = self.request_recv.recv() => {
                    if let Some(command) = req {
                        self.handle_cmd(command);
                    } else {
                        // Returning drops `self.sock`, which deregisters the
                        // socket number for reuse.
                        tracing::debug!("ATP: all handles dropped, releasing socket");
                        break;
                    }
                }
                _ = async {
                    match wait {
                        Some(d) => tokio::time::sleep(d).await,
                        // Nothing pending: park until another branch wakes
                        // us and recomputes the deadline.
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let now = self.now();
                    self.endpoint.poll(now);
                }
            }

            self.pump().await;
        }
    }

    fn handle_cmd(&mut self, cmd: AtpCommand) {
        let now = self.now();
        match cmd {
            AtpCommand::SendRequest(req) => {
                let handle = self.endpoint.request(
                    service_addr(req.address),
                    req.user_bytes,
                    &req.data,
                    req.bitmap,
                    now,
                );
                self.waiting.insert(handle, req.chan);
            }
            AtpCommand::SendResponse(resp) => {
                let chunks: Vec<([u8; 4], Vec<u8>)> = resp
                    .packets
                    .into_iter()
                    .map(|p| (p.user_bytes, p.data))
                    .collect();
                self.endpoint.respond_packets(
                    service_addr(resp.destination),
                    resp.tid,
                    &chunks,
                    now,
                );
            }
            AtpCommand::SendAlo(alo) => {
                self.endpoint.send_alo(service_addr(alo.address), alo.user_bytes);
            }
        }
    }

    /// Drain the endpoint until quiescent: packets onto the wire, events to
    /// their waiters.
    async fn pump(&mut self) {
        loop {
            let mut progressed = false;

            while let Some((dest, payload)) = self.endpoint.poll_transmit() {
                progressed = true;
                if let Err(e) = self.sock.send_to(&payload, ddp_dest(dest.into())).await {
                    tracing::warn!("ATP send failed: {e}");
                }
            }

            while let Some(event) = self.endpoint.poll_event() {
                progressed = true;
                self.handle_event(event).await;
            }

            if !progressed {
                break;
            }
        }
    }

    async fn handle_event(&mut self, event: AtpEvent) {
        match event {
            AtpEvent::Request { source, tid, user_bytes, data, bitmap, .. } => {
                // A strong sender on the request is what keeps this socket
                // alive while a reply is still owed; see `cmd_tx`.
                let Some(response_sender) = self.cmd_tx.upgrade() else {
                    tracing::debug!("ATP request arrived after every handle was dropped");
                    return;
                };
                let received = AtpReceivedRequest {
                    transaction_id: tid,
                    source: source.into(),
                    user_bytes,
                    data,
                    response_sender,
                    bitmap,
                };
                if self.incoming_req_tx.send(received).await.is_err() {
                    tracing::debug!("ATP: no responder listening, dropping request");
                }
            }
            AtpEvent::Response { handle, user_bytes, data } => {
                if let Some(chan) = self.waiting.remove(&handle) {
                    let _ = chan.send(Ok((data, user_bytes)));
                }
            }
            AtpEvent::RequestFailed { handle } => {
                if let Some(chan) = self.waiting.remove(&handle) {
                    let _ = chan.send(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "ATP request went unanswered through every retry",
                    )));
                }
            }
        }
    }
}
