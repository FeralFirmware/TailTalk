use crate::ddp::{DdpHandle, DdpSocket};
use std::collections::HashMap;
use std::io;
use tailtalk_packets::{
    atp::{AtpFunction, AtpPacket},
    ddp::{DdpPacket, DdpProtocolType},
};
use tokio::sync::{mpsc, oneshot};

/// Maximum data bytes per ATP packet.
/// DDP max datagram = 599 bytes; minus 13-byte DDP header = 586 bytes DDP payload;
/// minus 8-byte ATP header = 578 bytes of ATP data per packet.
pub const ATP_MAX_DATA_PER_PACKET: usize = 578;

// Type aliases for complex channel types
type AtpResponseChannel = oneshot::Sender<Result<(Vec<u8>, [u8; 4]), io::Error>>;

/// How long to wait for a response before retransmitting a pending request.
const ATP_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the actor wakes to check for expired retransmit deadlines. Finer than
/// [`ATP_RETRY_INTERVAL`] so each transaction's deadline is honoured to within a tick
/// rather than being rounded to the shared timer's phase.
const ATP_RETRY_TICK: std::time::Duration = std::time::Duration::from_millis(250);

pub struct PendingRequestState {
    pub chan: AtpResponseChannel,
    pub xo: bool,
    pub received_packets: std::collections::BTreeMap<u8, Vec<u8>>,
    pub user_bytes: Option<[u8; 4]>,
    pub eom_seq: Option<u8>,
    pub raw_packet: Vec<u8>,
    pub destination: AtpAddress,
    /// The bitmap we sent in the request, i.e. which response packet slots we
    /// said we'd accept. Per ATP spec, a responder that fills exactly this
    /// many slots doesn't need to set EOM - we already know it's done.
    pub requested_bitmap: u8,
    /// Number of retransmissions sent so far (not counting the initial send).
    pub retry_count: u8,
    /// When this request next becomes eligible for retransmission. Tracked per
    /// transaction so a request registered just before a timer tick still gets a
    /// full [`ATP_RETRY_INTERVAL`] before its first retry.
    pub retry_at: tokio::time::Instant,
}

type AtpTransactionMap = HashMap<u16, PendingRequestState>;

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
    /// Build an address from the source fields of a received DDP packet.
    fn from_ddp_source(ddp: &DdpPacket) -> Self {
        Self {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
            socket_number: ddp.src_sock_num,
        }
    }
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

#[derive(Debug)]
pub struct AtpSendRelease {
    pub destination: AtpAddress,
    pub tid: u16,
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
    SendRelease(AtpSendRelease),
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
    pub incoming_rx: mpsc::Receiver<AtpReceivedRequest>,
}

impl AtpResponder {
    pub async fn next(&mut self) -> Option<AtpReceivedRequest> {
        self.incoming_rx.recv().await
    }
}

pub struct Atp {
    sock: DdpSocket,
    request_recv: mpsc::Receiver<AtpCommand>,
    incoming_req_tx: mpsc::Sender<AtpReceivedRequest>,
    cmd_tx: mpsc::Sender<AtpCommand>,
    // Map Transaction ID to pending request channel and XO status
    pending_transactions: AtpTransactionMap,
    next_tid: u16,
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
            request_recv,
            incoming_req_tx,
            cmd_tx: request_send.clone(),
            pending_transactions: HashMap::new(),
            next_tid: 1, // Start TID at 1
        };

        tokio::spawn(async move {
            tracing::debug!("ATP actor starting");
            atp.run().await;
            tracing::debug!("ATP actor stopped");
        });

        (
            actual_socket,
            AtpRequestor {
                cmd_tx: request_send,
                socket_number: actual_socket,
            },
            AtpResponder {
                incoming_rx: incoming_req_rx,
            },
        )
    }

    async fn run(mut self) {
        let mut retry_interval = tokio::time::interval(ATP_RETRY_TICK);
        retry_interval.tick().await; // skip the immediate first tick

        loop {
            tokio::select! {
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => {
                            self.handle_packet(pkt.headers, &mut pkt.payload).await;
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
                        match command {
                            AtpCommand::SendRequest(req) => self.handle_send_request(req).await,
                            AtpCommand::SendResponse(resp) => self.handle_send_response(resp).await,
                            AtpCommand::SendRelease(rel) => self.handle_send_release(rel).await,
                            AtpCommand::SendAlo(alo) => self.handle_send_alo(alo).await,
                        }
                    } else {
                        tracing::info!("ATP command channel closed");
                        break;
                    }
                }
                _ = retry_interval.tick() => {
                    self.retransmit_pending().await;
                }
            }
        }
    }

    async fn retransmit_pending(&mut self) {
        if self.pending_transactions.is_empty() {
            return;
        }

        // ATP spec: give up after 8 retransmits (9 total attempts).
        const MAX_RETRIES: u8 = 8;

        let now = tokio::time::Instant::now();
        let mut to_evict: Vec<u16> = Vec::new();
        let mut to_resend: Vec<(u16, Vec<u8>, AtpAddress)> = Vec::new();

        // Only touch transactions whose own deadline has elapsed, so a request
        // registered just before a tick still gets its full retry interval.
        for (tid, state) in &mut self.pending_transactions {
            if now < state.retry_at {
                continue;
            }
            state.retry_count += 1;
            state.retry_at = now + ATP_RETRY_INTERVAL;
            if state.retry_count > MAX_RETRIES {
                to_evict.push(*tid);
            } else {
                to_resend.push((*tid, state.raw_packet.clone(), state.destination));
            }
        }

        for tid in to_evict {
            if let Some(state) = self.pending_transactions.remove(&tid) {
                tracing::warn!("ATP: TID {} got no response after {} retransmits, giving up", tid, MAX_RETRIES);
                let _ = state.chan.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ATP: no response after maximum retransmits",
                )));
            }
        }

        for (tid, packet, dest_addr) in to_resend {
            if let Err(e) = self.sock.send_to(&packet, dest_addr.into()).await {
                tracing::warn!("ATP retransmit failed for TID {}: {}", tid, e);
            } else {
                tracing::debug!("ATP retransmitting TID {}", tid);
            }
        }
    }

    /// Allocate a transaction ID that is not currently in flight.
    ///
    /// Skips any TID still in `pending_transactions` to prevent aliasing a live
    /// transaction on wrapping, since a late response for a reused TID would otherwise be
    /// misrouted into the wrong transaction's reassembly buffer. A freed TID is
    /// naturally eligible for reuse. Returns `None` if all 65536 IDs are in flight.
    fn allocate_tid(&mut self) -> Option<u16> {
        let start = self.next_tid;
        loop {
            let candidate = self.next_tid;
            self.next_tid = self.next_tid.wrapping_add(1);
            if !self.pending_transactions.contains_key(&candidate) {
                return Some(candidate);
            }
            if self.next_tid == start {
                return None;
            }
        }
    }

    async fn handle_send_request(&mut self, req: AtpSendRequest) {
        let Some(tid) = self.allocate_tid() else {
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "ATP: all transaction IDs in use",
            )));
            return;
        };

        let packet = AtpPacket {
            function: AtpFunction::Request,
            xo: true,   // internal assumption: always exactly once for now
            eom: false, // EOM must be 0 for TReq packets according to AppleTalk specs
            sts: false,
            bitmap_seq_num: req.bitmap,
            tid,
            user_bytes: req.user_bytes,
        };

        // Check the length before serializing: the copy below would otherwise panic
        // on an out-of-range slice for oversized data.
        if req.data.len() > ATP_MAX_DATA_PER_PACKET {
            tracing::error!(
                "ATP request data too large: {} (max {})",
                req.data.len(),
                ATP_MAX_DATA_PER_PACKET
            );
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("data too large (max {})", ATP_MAX_DATA_PER_PACKET),
            )));
            return;
        }

        let mut buf = [0u8; 600]; // DDP max is 586

        let header_len = packet
            .to_bytes(&mut buf)
            .expect("failed to serialize ATP header");

        let total_len = header_len + req.data.len();
        buf[header_len..total_len].copy_from_slice(&req.data);

        let raw_packet = buf[..total_len].to_vec();

        if let Err(e) = self.sock.send_to(&buf[..total_len], req.address.into()).await {
            let _ = req.chan.send(Err(io::Error::other(e)));
        } else {
            self.pending_transactions.insert(
                tid,
                PendingRequestState {
                    chan: req.chan,
                    xo: true,
                    received_packets: std::collections::BTreeMap::new(),
                    user_bytes: None,
                    eom_seq: None,
                    raw_packet,
                    destination: req.address,
                    requested_bitmap: req.bitmap,
                    retry_count: 0,
                    retry_at: tokio::time::Instant::now() + ATP_RETRY_INTERVAL,
                },
            );
        }
    }

    async fn handle_send_response(&mut self, resp: AtpSendResponse) {
        for (i, node) in resp.packets.iter().enumerate() {
            let packet = AtpPacket {
                function: AtpFunction::Response,
                xo: false,                        // Responses don't set XO
                eom: i == resp.packets.len() - 1, // Set EOM on last packet
                sts: false,
                bitmap_seq_num: i as u8,
                tid: resp.tid,
                user_bytes: node.user_bytes,
            };

            let mut buf = [0u8; 600];
            let header_len = packet
                .to_bytes(&mut buf)
                .expect("failed to serialize ATP response header");

            let total_len = header_len + node.data.len();
            if total_len > buf.len() {
                tracing::error!("Response chunk too large: {}", node.data.len());
                continue;
            }

            buf[header_len..total_len].copy_from_slice(&node.data);

            if let Err(e) = self.sock.send_to(&buf[..total_len], resp.destination.into()).await {
                tracing::error!("Failed to send ATP response packet {}: {}", i, e);
            }
        }
    }

    async fn handle_send_alo(&mut self, alo: AtpSendAlo) {
        // Allocate through the same collision-checked path as real requests: a TID
        // that aliased a live transaction would let a stray response for this ALO be
        // reassembled into that transaction's buffer.
        let Some(tid) = self.allocate_tid() else {
            tracing::warn!("ATP: no free TID for ALO packet, dropping");
            return;
        };

        let packet = AtpPacket {
            function: AtpFunction::Request,
            xo: false, // ALO — no TRelease expected
            eom: false,
            sts: false,
            bitmap_seq_num: 0xff,
            tid,
            user_bytes: alo.user_bytes,
        };

        let mut buf = [0u8; 600];
        let header_len = packet
            .to_bytes(&mut buf)
            .expect("failed to serialize ATP ALO header");

        if let Err(e) = self.sock.send_to(&buf[..header_len], alo.address.into()).await {
            tracing::warn!("Failed to send ATP ALO packet: {}", e);
        }
        // No pending transaction registered — any response is silently discarded.
    }

    async fn handle_send_release(&mut self, rel: AtpSendRelease) {
        let packet = AtpPacket {
            function: AtpFunction::Release,
            xo: false,
            eom: false,
            sts: false,
            bitmap_seq_num: 0,
            tid: rel.tid,
            user_bytes: [0; 4],
        };

        tracing::debug!(
            "ATP Sending Release to {:?} tid={}",
            rel.destination,
            rel.tid
        );

        let mut buf = [0u8; 600];
        let header_len = packet
            .to_bytes(&mut buf)
            .expect("failed to serialize ATP release header");

        if let Err(e) = self.sock.send_to(&buf[..header_len], rel.destination.into()).await {
            tracing::error!("Failed to send ATP Release: {}", e);
        }
    }

    /// Remove a pending transaction, hand its accumulated data to the caller, and
    /// (for XO transactions) send the Release that tells the responder it can
    /// drop its retry cache entry for this TID.
    async fn complete_transaction(&mut self, tid: u16, source: AtpAddress) {
        let Some(mut state) = self.pending_transactions.remove(&tid) else {
            return;
        };

        let expected_count = state
            .eom_seq
            .map(|e| e as usize + 1)
            .unwrap_or(state.received_packets.len());

        // Reassemble in sequence order. The caller is only signalled complete once every
        // slot below EOM has arrived, so a gap here means the completion check let a
        // partial transaction through. Report it rather than silently handing back a
        // short buffer, which upper layers would read as a truncated (but successful) reply.
        let mut full_data = Vec::new();
        let mut missing = None;
        for i in 0..expected_count as u8 {
            match state.received_packets.remove(&i) {
                Some(p) => full_data.extend_from_slice(&p),
                None => {
                    missing = Some(i);
                    break;
                }
            }
        }

        let result = match missing {
            Some(i) => {
                debug_assert!(false, "ATP: completed TID {tid} missing response packet {i}");
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ATP: incomplete response, missing packet {i} of {expected_count}"),
                ))
            }
            None => Ok((full_data, state.user_bytes.unwrap_or([0; 4]))),
        };

        let xo = state.xo;
        let _ = state.chan.send(result);

        if xo {
            let rel = AtpSendRelease { destination: source, tid };
            self.handle_send_release(rel).await;
        }
    }

    async fn handle_packet(&mut self, ddp: DdpPacket, payload: &mut [u8]) {
        let packet = match AtpPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse ATP packet: {}", e);
                return;
            }
        };

        match packet.function {
            AtpFunction::Request => {
                // Server-side: dispatch to responder
                let request_data = if payload.len() > AtpPacket::HEADER_LEN {
                    payload[AtpPacket::HEADER_LEN..].to_vec()
                } else {
                    Vec::new()
                };

                let req = AtpReceivedRequest {
                    transaction_id: packet.tid,
                    source: AtpAddress::from_ddp_source(&ddp),
                    user_bytes: packet.user_bytes,
                    data: request_data,
                    response_sender: self.cmd_tx.clone(),
                    bitmap: packet.bitmap_seq_num,
                };

                if let Err(e) = self.incoming_req_tx.try_send(req) {
                    tracing::warn!("Dropping incoming ATP request (queue full): {}", e);
                }
            }
            AtpFunction::Response => {
                // Client-side: handle response to our request
                let mut is_complete = false;
                if let std::collections::hash_map::Entry::Occupied(mut entry) =
                    self.pending_transactions.entry(packet.tid)
                {
                    if payload.len() >= AtpPacket::HEADER_LEN {
                        let data = payload[AtpPacket::HEADER_LEN..].to_vec();
                        let state = entry.get_mut();

                        state.received_packets.insert(packet.bitmap_seq_num, data);
                        if state.user_bytes.is_none() {
                            state.user_bytes = Some(packet.user_bytes);
                        }
                        if packet.eom {
                            state.eom_seq = Some(packet.bitmap_seq_num);
                        }

                        // Check if complete
                        if let Some(eom) = state.eom_seq {
                            // if we have all packets from 0 to eom
                            if (0..=eom).all(|i| state.received_packets.contains_key(&i)) {
                                is_complete = true;
                            }
                        } else if !state.received_packets.is_empty()
                            && state.received_packets.len()
                                == state.requested_bitmap.count_ones() as usize
                        {
                            // Filled every slot we asked for — per ATP spec, EOM isn't
                            // required in this case since we already know the count.
                            is_complete = true;
                        }
                    } else {
                        tracing::warn!("ATP Response payload too short");
                        // We do not remove the transaction here, just ignore the bad packet
                    }
                }
                // `entry` (and its borrow of pending_transactions) is dropped here,
                // so complete_transaction is free to remove it.
                if is_complete {
                    self.complete_transaction(packet.tid, AtpAddress::from_ddp_source(&ddp))
                        .await;
                }
            }
            AtpFunction::Release => {
                // We send TRel to close out our own XO requests, but nothing in this
                // stack waits on an inbound one: responders here build each reply on
                // demand rather than keeping a retry cache to be released. Log and drop.
                tracing::debug!(
                    "Received ATP Release packet from {:?} tid={}",
                    AtpAddress::from_ddp_source(&ddp),
                    packet.tid
                );
            }
        }
    }
}
