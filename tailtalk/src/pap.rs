use crate::atp::{Atp, AtpAddress, AtpRequestor, AtpResponder};
use crate::ddp::DdpHandle;
use anyhow::{Result, anyhow};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tailtalk_packets::pap::{PapFunction, PapPacket};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, interval};

/// My LaserWriter seems to get very upset over LocalTalk if the individual ATP packets
/// are any larger than 512 bytes. Not quite sure why, but if kept to 512 this then allows
/// us to respond with 8 (i.e quantum size) ATP fragments per SendData request.
pub const PAP_MAX_DATA_PER_PACKET: usize = 512;

/// Default cap on how much printer stdout [`PapClient::read_response`] will accumulate
/// before giving up. A printer stuck in a PostScript error loop can emit output forever;
/// without a bound the read never returns and the buffer grows unchecked.
pub const PAP_DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// How many recent replies to keep for answering printer retransmits. The PAP flow
/// quantum caps outstanding SendData requests at 8, so 8 covers every request that can
/// still be in flight.
const PAP_REPLY_CACHE_LEN: usize = 8;

/// Advance a PAP sequence number.
///
/// Spec: sequence numbers run 1–65535 then wrap back to 1; 0 is reserved to mean
/// "unsequenced" and must never be produced by normal advancement.
fn next_pap_seq(seq: u16) -> u16 {
    if seq == u16::MAX { 1 } else { seq + 1 }
}

/// A reply we sent, kept so an identical retransmit gets the identical answer.
type CachedReply = (u16, [u8; 4], Vec<u8>);

/// Look up a cached reply by sequence number.
fn cached_reply(cache: &std::collections::VecDeque<CachedReply>, seq: u16) -> Option<&CachedReply> {
    cache.iter().find(|(s, _, _)| *s == seq)
}

/// Record a reply, evicting the oldest once the cache is full.
fn remember_reply(
    cache: &mut std::collections::VecDeque<CachedReply>,
    seq: u16,
    user_bytes: [u8; 4],
    data: Vec<u8>,
) {
    if cache.len() == PAP_REPLY_CACHE_LEN {
        cache.pop_front();
    }
    cache.push_back((seq, user_bytes, data));
}

/// [`PapClient::chunk_size`] for the ImageWriter II/LQ LocalTalk Option Card:
/// one ATP packet's worth per SendData cycle. The card handles the full
/// bitmap-derived capacity poorly, and this is the size verified against real
/// hardware.
pub const IMAGEWRITER_CHUNK_SIZE: usize = 512;

#[derive(Debug)]
pub struct PapClient {
    atp_requestor: AtpRequestor,
    atp_responder: AtpResponder,
    connection_id: u8,
    flow_quantum: u8,
    remote_addr: AtpAddress,
    /// The printer's connection socket from OpenConnReply — used for all post-connect traffic.
    server_addr: AtpAddress,
    /// Next SendData (read) sequence number. Reset by [`connect`](Self::connect), then
    /// continues across every job for that connection's lifetime. Restarting it
    /// mid-connection makes papd-style servers see stale retransmits.
    read_seq: u16,
    /// Override the read buffer size per SendData cycle. When `None`, capacity is
    /// `bitmap_count × PAP_MAX_DATA_PER_PACKET` derived from the printer's per-request bitmap.
    pub chunk_size: Option<usize>,
    /// Cap on bytes accumulated by [`read_response`](Self::read_response).
    /// Defaults to [`PAP_DEFAULT_MAX_RESPONSE_BYTES`].
    pub max_response_bytes: usize,
    /// Overall deadline for a single [`read_response`](Self::read_response) call.
    /// Defaults to 60 s; `None` waits indefinitely for the printer's EOF.
    pub response_timeout: Option<Duration>,
}

impl PapClient {
    pub fn new(atp_requestor: AtpRequestor, atp_responder: AtpResponder) -> Self {
        Self {
            atp_requestor,
            atp_responder,
            connection_id: 0,
            flow_quantum: 8,
            remote_addr: AtpAddress::default(),
            server_addr: AtpAddress::default(),
            read_seq: 1,
            chunk_size: None,
            max_response_bytes: PAP_DEFAULT_MAX_RESPONSE_BYTES,
            response_timeout: Some(Duration::from_secs(60)),
        }
    }

    pub async fn connect(&mut self, address: AtpAddress) -> Result<()> {
        self.connect_with_timeout(address, Duration::from_secs(60)).await
    }

    /// Per PAP spec, retry every 2 seconds on a non-zero result code (server busy).
    pub async fn connect_with_timeout(&mut self, address: AtpAddress, timeout: Duration) -> Result<()> {
        self.remote_addr = address;

        let open_packet = PapPacket {
            connection_id: self.atp_requestor.socket_number,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: vec![self.atp_requestor.socket_number, 0x08, 0x00, 0x00],
        };
        let (user_bytes, data) = open_packet.to_atp_parts();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Check before sending too: the ATP retry budget alone runs ~16 s, which
            // would otherwise blow past a shorter caller-supplied timeout.
            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow!("PAP OpenConn timed out after {:?}", timeout));
            }

            tracing::info!("PAP: Sending OpenConn to {:?}", address);
            let request = self.atp_requestor.send_request_with_bitmap(
                address,
                user_bytes,
                data.to_vec(),
                0x01,
            );
            let (resp_data, resp_user_bytes) = tokio::time::timeout_at(deadline, request)
                .await
                .map_err(|_| anyhow!("PAP OpenConn timed out after {:?}", timeout))??;

            let reply = PapPacket::parse_from_atp(resp_user_bytes, &resp_data)?;

            if reply.function != PapFunction::OpenConnReply {
                return Err(anyhow!("Unexpected response function: {:?}", reply.function));
            }

            self.connection_id = reply.connection_id;

            if reply.data.len() < 4 {
                return Err(anyhow!("PAP OpenConnReply too short ({} bytes)", reply.data.len()));
            }

            let server_socket = reply.data[0];
            self.flow_quantum = reply.data[1];
            let result = ((reply.data[2] as u16) << 8) | (reply.data[3] as u16);

            if result != 0 {
                // Per PAP spec, retry every 2 seconds, but never sleep past the deadline.
                let retry_at = tokio::time::Instant::now() + Duration::from_secs(2);
                if retry_at >= deadline {
                    return Err(anyhow!("PAP OpenConn failed with result code: {} (server busy)", result));
                }
                tracing::info!("PAP: Server busy (result={}), retrying in 2s", result);
                tokio::time::sleep_until(retry_at).await;
                continue;
            }

            self.server_addr = AtpAddress {
                network_number: address.network_number,
                node_number: address.node_number,
                socket_number: server_socket,
            };
            self.read_seq = 1;

            tracing::info!("PAP connected! ID={}, Quantum={}", self.connection_id, self.flow_quantum);
            return Ok(());
        }
    }

    pub async fn print(&mut self, data: &[u8]) -> Result<()> {
        self.print_stream(std::io::Cursor::new(data)).await
    }

    /// Stream `source` to the printer.  Call [`read_response`] afterwards to
    /// collect any printer stdout output (errors, page stats) buffered until job end.
    pub async fn print_stream<R: AsyncRead + Unpin>(&mut self, mut source: R) -> Result<()> {
        tracing::info!("PAP: Starting streaming print job");

        let mut last_activity = tokio::time::Instant::now();
        let mut tickle_interval = interval(Duration::from_secs(30));
        tickle_interval.tick().await; // skip the immediate first tick

        // Once EOF is sent the job is delivered; all that remains is draining SendData
        // requests the printer already had in flight, each of which holds an XO slot open
        // until answered. `drain_deadline` bounds that wait so we never sit through the
        // 30-s Tickle cycle for a printer that has nothing more to send.
        let mut drain_deadline: Option<tokio::time::Instant> = None;

        // A retransmit must get the byte-identical reply, never fresh source bytes:
        // answering a duplicate with new data silently drops a chunk of the job. The
        // printer may have up to `flow_quantum` (max 8) requests outstanding, so keep
        // more than just the most recent reply.
        let mut reply_cache: std::collections::VecDeque<CachedReply> =
            std::collections::VecDeque::with_capacity(PAP_REPLY_CACHE_LEN);

        loop {
            tokio::select! {
                maybe_req = self.atp_responder.next() => {
                    let Some(req) = maybe_req else {
                        return Err(anyhow!("ATP responder closed unexpectedly"));
                    };

                    let pap_req = PapPacket::parse_from_atp(req.user_bytes, &req.data)?;

                    if pap_req.connection_id != self.connection_id {
                        tracing::warn!("Ignored PAP packet with mismatched ID: {}", pap_req.connection_id);
                        continue;
                    }

                    last_activity = tokio::time::Instant::now();

                    match pap_req.function {
                        PapFunction::SendData => {
                            let seq_num = pap_req.sequence_num;

                            // A sequence number we have already answered is a retransmit
                            // (our reply was lost). Replay the identical bytes, since reading
                            // fresh ones from `source` would silently drop a chunk of the
                            // job. Cache membership is the test rather than an ordering
                            // comparison, so this stays correct across the 65535→1 wrap.
                            if seq_num != 0
                                && let Some((_, ub, chunk)) = cached_reply(&reply_cache, seq_num)
                            {
                                let _ = req
                                    .send_response_chunked(chunk, *ub, PAP_MAX_DATA_PER_PACKET)
                                    .await;
                                continue;
                            }

                            let capacity = self
                                .chunk_size
                                .unwrap_or(req.max_packets() * PAP_MAX_DATA_PER_PACKET);

                            let buf = if drain_deadline.is_some() {
                                // Post-EOF: answer in-flight requests with another EOF so the
                                // printer can release its XO slots. Never touch `source` again.
                                Vec::new()
                            } else {
                                tracing::info!("PAP received SendData seq={}", seq_num);
                                let mut buf = vec![0u8; capacity];
                                let n = source.read(&mut buf).await?;
                                buf.truncate(n);
                                buf
                            };

                            let eof = buf.is_empty();
                            let pap_resp = PapPacket {
                                connection_id: self.connection_id,
                                function: PapFunction::Data,
                                sequence_num: seq_num,
                                eof,
                                data: buf,
                            };
                            let (user_bytes, chunk_data) = pap_resp.to_atp_parts();
                            req.send_response_chunked(chunk_data, user_bytes, PAP_MAX_DATA_PER_PACKET).await?;
                            if seq_num != 0 {
                                remember_reply(&mut reply_cache, seq_num, user_bytes, chunk_data.to_vec());
                            }

                            match (eof, drain_deadline) {
                                // First EOF: the job is delivered. Give the printer a brief
                                // window to drain anything already in flight, then finish.
                                (true, None) => {
                                    tracing::info!("PAP: EOF sent");
                                    drain_deadline =
                                        Some(tokio::time::Instant::now() + Duration::from_millis(500));
                                }
                                // Answered an in-flight request after EOF; nothing left to drain.
                                (_, Some(_)) => return Ok(()),
                                (false, None) => {}
                            }
                        }
                        PapFunction::Tickle => {
                            tracing::debug!("PAP: Received Tickle from printer");
                            // A Tickle is not a SendData, so it says nothing about whether the
                            // printer still has requests in flight. Let `drain_deadline` decide.
                        }
                        PapFunction::CloseConn => {
                            let reply = PapPacket {
                                connection_id: self.connection_id,
                                function: PapFunction::CloseConnReply,
                                sequence_num: 0,
                                eof: false,
                                data: vec![],
                            };
                            let (ub, d) = reply.to_atp_parts();
                            let _ = req.send_response(d, ub).await;
                            if drain_deadline.is_some() {
                                return Ok(());
                            }
                            return Err(anyhow!("Printer closed the connection before the job completed"));
                        }
                        _ => {}
                    }
                }

                _ = tickle_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(120) {
                        return Err(anyhow!("PAP session timed out after 120 seconds of inactivity"));
                    }
                    tracing::debug!("PAP: Sending Tickle to printer");
                    let tickle = PapPacket {
                        connection_id: self.connection_id,
                        function: PapFunction::Tickle,
                        sequence_num: 0,
                        eof: false,
                        data: vec![],
                    };
                    let (ub, _) = tickle.to_atp_parts();
                    let _ = self.atp_requestor.send_alo(self.server_addr, ub).await;
                }

                // Fires only after EOF; `pending()` parks this arm for the rest of the job.
                _ = async {
                    match drain_deadline {
                        Some(d) => tokio::time::sleep_until(d).await,
                        None => std::future::pending().await,
                    }
                } => {
                    // Nothing further arrived after EOF, so the printer had no requests
                    // left in flight and the job is done.
                    return Ok(());
                }
            }
        }
    }

    /// Pull the printer's PS stdout by issuing SendData requests until the printer sends EOF.
    ///
    /// Bounded by [`max_response_bytes`](Self::max_response_bytes) and
    /// [`response_timeout`](Self::response_timeout). A printer stuck emitting output,
    /// a PostScript error loop for instance, would otherwise never yield EOF.
    pub async fn read_response(&mut self) -> Result<Vec<u8>> {
        match self.response_timeout {
            Some(t) => tokio::time::timeout(t, self.read_response_inner())
                .await
                .map_err(|_| anyhow!("PAP: printer sent no EOF within {:?}", t))?,
            None => self.read_response_inner().await,
        }
    }

    async fn read_response_inner(&mut self) -> Result<Vec<u8>> {
        let mut response = Vec::new();

        loop {
            let pkt = PapPacket {
                connection_id: self.connection_id,
                function: PapFunction::SendData,
                sequence_num: self.read_seq,
                eof: false,
                data: vec![],
            };
            let (ub, d) = pkt.to_atp_parts();
            let (resp_data, resp_ub) = self.atp_requestor
                .send_request(self.server_addr, ub, d.to_vec())
                .await?;
            let data_pkt = PapPacket::parse_from_atp(resp_ub, &resp_data)?;

            if data_pkt.function != PapFunction::Data {
                return Err(anyhow!("Expected PAP Data response, got {:?}", data_pkt.function));
            }

            self.read_seq = next_pap_seq(self.read_seq);

            response.extend_from_slice(&data_pkt.data);
            if data_pkt.eof {
                break;
            }

            if response.len() > self.max_response_bytes {
                return Err(anyhow!(
                    "PAP: printer output exceeded {} bytes without EOF",
                    self.max_response_bytes
                ));
            }
        }

        Ok(response)
    }

    pub async fn close(&mut self) -> Result<()> {
        let close_pkt = PapPacket {
            connection_id: self.connection_id,
            function: PapFunction::CloseConn,
            sequence_num: 0,
            eof: false,
            data: vec![],
        };
        let (ub, d) = close_pkt.to_atp_parts();
        // Must go to server_addr (per-connection socket), not remote_addr (NBP listening socket).
        let (resp_data, resp_ub) = self
            .atp_requestor
            .send_request_with_bitmap(self.server_addr, ub, d.to_vec(), 0x01)
            .await?;

        let reply = PapPacket::parse_from_atp(resp_ub, &resp_data)?;
        if reply.function != PapFunction::CloseConnReply {
            return Err(anyhow!(
                "Expected PAP CloseConnReply, got {:?}",
                reply.function
            ));
        }
        Ok(())
    }

    pub async fn get_status(atp: AtpRequestor, address: AtpAddress) -> Result<String> {
        let buf = Self::get_status_bytes(atp, address).await?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }

    /// The raw contents of the PAP status buffer, with the length byte already
    /// consumed but no assumption that the payload is text.
    ///
    /// LaserWriters put a PostScript status comment here, which is what
    /// [`get_status`](Self::get_status) returns. An ImageWriter II/LQ LocalTalk
    /// Option Card instead answers with a two-byte packed `statusBits` word
    /// that a lossy UTF-8 conversion would mangle (see [`crate::imagewriter`]).
    pub async fn get_status_bytes(atp: AtpRequestor, address: AtpAddress) -> Result<Vec<u8>> {
        let pkt = PapPacket {
            connection_id: 0,
            function: PapFunction::SendStatus,
            sequence_num: 0,
            eof: false,
            data: vec![],
        };
        let (ub, d) = pkt.to_atp_parts();
        let (resp_data, resp_ub) = atp
            .send_request_with_bitmap(address, ub, d.to_vec(), 0x01)
            .await?;

        let reply = PapPacket::parse_from_atp(resp_ub, &resp_data)?;
        if reply.function != PapFunction::Status {
            return Err(anyhow!("Expected PAP Status reply, got {:?}", reply.function));
        }

        // Status reply: 4 unused bytes, then a pascal string (length byte then content).
        // A well-formed reply with an empty string is exactly 5 bytes, so anything
        // shorter is malformed rather than merely empty.
        let Some(&len) = reply.data.get(4) else {
            return Err(anyhow!(
                "PAP Status reply too short ({} bytes, need at least 5)",
                reply.data.len()
            ));
        };
        let end = (5 + len as usize).min(reply.data.len());
        Ok(reply.data[5..end].to_vec())
    }
}

/// A dedicated ATP socket for PAP `SendStatus` calls.
///
/// `SendStatus` is connectionless: it carries connection ID 0 to the printer's
/// NBP-advertised socket rather than the per-connection socket a job streams
/// over, so it needs no PAP connection and is answered even mid-job.
///
/// Giving it a socket of its own is what makes polling during a print safe. The
/// poll shares no transaction state with the job, cannot interleave with the
/// printer's `SendData` traffic, and the handle can outlive the session that
/// created it. Reusing one handle also beats a socket per poll.
///
/// The reply's meaning is printer-specific: a LaserWriter puts a PostScript
/// status comment here, so use [`read_text`](Self::read_text); an ImageWriter
/// option card puts a packed status word, which [`crate::imagewriter`] decodes
/// on top of [`read_bytes`](Self::read_bytes).
#[derive(Clone)]
pub struct PapStatusHandle {
    atp: AtpRequestor,
    address: AtpAddress,
}

impl PapStatusHandle {
    /// Allocate a status socket for the printer at `address`. Opens no PAP
    /// connection, so this works against a printer that is busy or printing.
    pub async fn new(ddp: &DdpHandle, address: AtpAddress) -> Self {
        let (_, atp, _) = Atp::spawn(ddp, None).await;
        Self { atp, address }
    }

    /// The printer this handle reads from.
    pub fn address(&self) -> AtpAddress {
        self.address
    }

    /// The raw status buffer, for printers whose reply is not text.
    pub async fn read_bytes(&self) -> Result<Vec<u8>> {
        PapClient::get_status_bytes(self.atp.clone(), self.address).await
    }

    /// The status buffer as text, for PostScript printers.
    pub async fn read_text(&self) -> Result<String> {
        PapClient::get_status(self.atp.clone(), self.address).await
    }
}

// ── PAP server (printer emulator) ────────────────────────────────────────────

/// Paper size supported by the printer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaperSize {
    Letter,
    A4,
    Legal,
    A3,
    B5,
    Executive,
}

impl PaperSize {
    pub fn ppd_name(&self) -> &'static str {
        match self {
            Self::Letter => "Letter",
            Self::A4 => "A4",
            Self::Legal => "Legal",
            Self::A3 => "A3",
            Self::B5 => "B5",
            Self::Executive => "Executive",
        }
    }
}

/// Printer capability attributes used to answer PQP queries and for IPP translation.
///
/// Set at construction via [`PapServer::new`] or [`TalkStack::add_printer`], and
/// updateable at runtime via [`PapServer::update_attributes`].
#[derive(Debug, Clone)]
pub struct PrinterAttributes {
    /// PAP status string returned to clients before a connection is opened.
    /// Should be a PS status comment, e.g. `%%[ status: idle; source: EtherTalk ]%%`.
    pub status: String,
    /// Product name returned to the Mac driver's `*Product` PQP query.
    /// Should match the name advertised in NBP, e.g. `"Color LaserWriter 12/600"`.
    pub product_name: String,
    /// PostScript language level (1 or 2). Returned for `*LanguageLevel` queries.
    pub language_level: u8,
    /// Whether the printer supports color output.
    pub color: bool,
    /// Supported output resolutions in DPI (e.g. `vec![600]`).
    pub resolutions_dpi: Vec<u32>,
    /// Supported paper sizes.
    pub paper_sizes: Vec<PaperSize>,
}

impl Default for PrinterAttributes {
    fn default() -> Self {
        Self {
            status: "%%[ status: idle; source: EtherTalk ]%%".to_string(),
            product_name: "TailTalk LaserWriter".to_string(),
            language_level: 2,
            color: false,
            resolutions_dpi: vec![300],
            paper_sizes: vec![PaperSize::Letter],
        }
    }
}

/// A received print job ready for processing by a [`PrintSink`].
pub struct PrintJob {
    /// Source AppleTalk address (network/node of the client).
    pub client_addr: AtpAddress,
    /// Raw PostScript data received from the client.
    pub data: Vec<u8>,
}

/// A sink that consumes incoming print jobs.
///
/// Implement this trait to define what happens with received jobs:
/// saving to disk, forwarding to an IPP printer, format conversion, etc.
///
/// Implementations must be `Send + Sync` so the [`PapServer`] can hold them
/// across async awaits.
pub trait PrintSink: Send + Sync {
    fn receive_job(&self, job: PrintJob) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>>;
}

/// A [`PrintSink`] that saves each job as a numbered `.ps` file in a directory.
///
/// Files are named `job_{N:04}_{unix_timestamp}.ps`.
pub struct FileSink {
    dir: std::path::PathBuf,
    counter: std::sync::atomic::AtomicU32,
}

impl FileSink {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            counter: std::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl PrintSink for FileSink {
    fn receive_job(&self, job: PrintJob) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let dir = self.dir.clone();
        let n = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        Box::pin(async move {
            use std::time::{SystemTime, UNIX_EPOCH};
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let path = dir.join(format!("job_{n:04}_{ts}.ps"));
            tokio::fs::create_dir_all(&dir).await?;
            tokio::fs::write(&path, &job.data).await?;
            tracing::info!(
                "PAP: saved job {} ({} bytes) → {}",
                n,
                job.data.len(),
                path.display()
            );
            Ok(())
        })
    }
}

/// A PAP printer emulator.
///
/// Accepts incoming PAP connections, handles PQP capability queries automatically
/// using the configured [`PrinterAttributes`], and forwards real print jobs to
/// the configured [`PrintSink`].
///
/// Create via [`TalkStack::add_printer`] (handles NBP registration) or directly
/// with [`PapServer::new`] for manual control.
pub struct PapServer {
    responder: AtpResponder,
    ddp: DdpHandle,
    /// The socket number to advertise in NBP.
    pub socket_number: u8,
    attributes: Arc<tokio::sync::RwLock<PrinterAttributes>>,
    sink: Box<dyn PrintSink + Send + Sync>,
}

impl PapServer {
    pub fn new(
        responder: AtpResponder,
        ddp: DdpHandle,
        socket_number: u8,
        attributes: PrinterAttributes,
        sink: Box<dyn PrintSink + Send + Sync>,
    ) -> Self {
        Self {
            responder,
            ddp,
            socket_number,
            attributes: Arc::new(tokio::sync::RwLock::new(attributes)),
            sink,
        }
    }

    /// Replace the current printer attributes.
    pub async fn update_attributes(&self, attrs: PrinterAttributes) {
        *self.attributes.write().await = attrs;
    }

    /// Return a cloned handle to the attributes lock for updating from another task.
    pub fn attributes_handle(&self) -> Arc<tokio::sync::RwLock<PrinterAttributes>> {
        self.attributes.clone()
    }

    fn make_status_payload(status: &str) -> Vec<u8> {
        let bytes = status.as_bytes();
        let len = bytes.len().min(255) as u8;
        let mut out = vec![0u8, 0u8, 0u8, 0u8, len];
        out.extend_from_slice(&bytes[..len as usize]);
        out
    }

    /// Build the status payload; with `busy`, rewrites `status: idle` to `status: busy`
    /// so the client's print monitor reflects an active session.
    async fn status_payload(&self, busy: bool) -> Vec<u8> {
        let attrs = self.attributes.read().await;
        if busy {
            Self::make_status_payload(&attrs.status.replace("status: idle", "status: busy"))
        } else {
            Self::make_status_payload(&attrs.status)
        }
    }

    /// Accept one incoming PAP connection.
    ///
    /// PQP capability queries (e.g. `RBIUAMListQuery`) are detected and answered
    /// automatically from the current [`PrinterAttributes`].  Real print jobs are
    /// forwarded to the [`PrintSink`]; PQP probes are silently discarded.
    pub async fn accept(&mut self) -> anyhow::Result<()> {
        // ── Phase 1: wait for OpenConn, answer status queries in the meantime ──
        let (open_req, client_data_addr, conn_id) = loop {
            let req = self
                .responder
                .next()
                .await
                .ok_or_else(|| anyhow!("PAP listener socket closed"))?;

            let pap = match PapPacket::parse_from_atp(req.user_bytes, &req.data) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!("PAP: ignoring malformed packet on listener socket: {e}");
                    continue;
                }
            };

            match pap.function {
                PapFunction::SendStatus => {
                    let status_payload = self.status_payload(false).await;
                    let reply = PapPacket {
                        connection_id: 0,
                        function: PapFunction::Status,
                        sequence_num: 0,
                        eof: false,
                        data: status_payload,
                    };
                    let (ub, d) = reply.to_atp_parts();
                    let _ = req.send_response(d, ub).await;
                }
                PapFunction::OpenConn => {
                    if pap.data.len() < 2 {
                        tracing::warn!("PAP: OpenConn payload too short, ignoring");
                        continue;
                    }
                    let client_socket = pap.data[0];
                    // Spec: server echoes the client's ConnID in OpenConnReply.
                    let conn_id = pap.connection_id;
                    let addr = AtpAddress {
                        network_number: req.source.network_number,
                        node_number: req.source.node_number,
                        socket_number: client_socket,
                    };
                    break (req, addr, conn_id);
                }
                _ => {}
            }
        };

        // ── Phase 2: allocate per-connection socket, send OpenConnReply ────────
        let (conn_socket_num, conn_requestor, mut conn_responder) =
            Atp::spawn(&self.ddp, None).await;

        tracing::info!(
            "PAP: OpenConn from {:?}, conn_id={}, conn_socket={}",
            client_data_addr,
            conn_id,
            conn_socket_num
        );

        let reply_data = {
            let attrs = self.attributes.read().await;
            let sp = Self::make_status_payload(&attrs.status);
            let mut d = vec![conn_socket_num, 8, 0, 0];
            d.extend_from_slice(&sp[4..]);
            d
        };
        let reply = PapPacket {
            connection_id: conn_id,
            function: PapFunction::OpenConnReply,
            sequence_num: 0,
            eof: false,
            data: reply_data,
        };
        let (ub, d) = reply.to_atp_parts();
        if let Err(e) = open_req.send_response(d, ub).await {
            tracing::warn!("PAP: failed to send OpenConnReply: {e}");
            return Ok(());
        }

        // ── Phase 3: papd-style session loop ───────────────────────────────────
        // A connection carries a sequence of jobs (each PQP query is its own job,
        // followed by the real print job) — keep one SendData pull outstanding at
        // all times, and never close the connection ourselves: a server-initiated
        // CloseConn makes the driver abort its query session and restart discovery.
        let make_pull = |seq: u16| {
            let requestor = conn_requestor.clone();
            async move {
                let send_data = PapPacket {
                    connection_id: conn_id,
                    function: PapFunction::SendData,
                    sequence_num: seq,
                    eof: false,
                    data: vec![],
                };
                let (ub, d) = send_data.to_atp_parts();
                requestor.send_request(client_data_addr, ub, d.to_vec()).await
            }
        };

        let mut seq: u16 = 1;
        let mut pull = Box::pin(make_pull(seq));

        let mut job_data: Vec<u8> = Vec::new();
        // Printer stdout queued for the client's reads: the query answer, or empty for a print job.
        let mut stdout: Vec<u8> = Vec::new();
        let mut stdout_pos: usize = 0;
        let mut response_ready = false;
        // A client read waiting for job output, with its sequence number.
        let mut pending_read: Option<(crate::atp::AtpReceivedRequest, u16)> = None;
        // Next expected client read sequence number, for spotting retransmits.
        let mut read_seq: u16 = 1;
        // Re-sent verbatim if the client retransmits a read (reply lost on the wire).
        let mut read_reply_cache: std::collections::VecDeque<CachedReply> =
            std::collections::VecDeque::with_capacity(PAP_REPLY_CACHE_LEN);

        let mut last_activity = tokio::time::Instant::now();
        let mut tickle_interval = interval(Duration::from_secs(30));
        tickle_interval.tick().await; // skip immediate tick

        loop {
            tokio::select! {
                res = &mut pull => {
                    match res {
                        Ok((resp_data, resp_ub)) => {
                            last_activity = tokio::time::Instant::now();

                            let data_pkt = match PapPacket::parse_from_atp(resp_ub, &resp_data) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::warn!("PAP: malformed Data response, dropping connection: {e}");
                                    return Ok(());
                                }
                            };
                            if data_pkt.function != PapFunction::Data {
                                tracing::warn!("PAP: expected Data, got {:?}; dropping connection", data_pkt.function);
                                return Ok(());
                            }

                            tracing::debug!(
                                "PAP: received Data len={} eof={}",
                                data_pkt.data.len(),
                                data_pkt.eof
                            );
                            job_data.extend_from_slice(&data_pkt.data);

                            if data_pkt.eof && job_data.is_empty() {
                                // A zero-byte job (PapClient's post-EOF drain sends one)
                                // would otherwise clobber a still-unread query answer.
                                tracing::debug!("PAP: ignoring empty job");
                            } else if data_pkt.eof {
                                let job = std::mem::take(&mut job_data);
                                let is_pqp = job.starts_with(b"%!PS-Adobe-3.0 Query");
                                if is_pqp {
                                    let attrs = self.attributes.read().await;
                                    stdout = pqp_stdout(&attrs, &job);
                                    tracing::info!(
                                        "PAP: PQP query from {:?}, answering with {} bytes",
                                        client_data_addr,
                                        stdout.len()
                                    );
                                } else {
                                    stdout = Vec::new();
                                    tracing::info!("PAP: job complete, {} bytes received", job.len());
                                    if let Err(e) = self
                                        .sink
                                        .receive_job(PrintJob {
                                            client_addr: client_data_addr,
                                            data: job,
                                        })
                                        .await
                                    {
                                        tracing::error!("PAP: sink error: {e}");
                                    }
                                }
                                stdout_pos = 0;
                                response_ready = true;
                            }

                            seq = next_pap_seq(seq);
                            pull = Box::pin(make_pull(seq));
                        }
                        Err(_) => {
                            // A timeout usually just means the client is idle (composing
                            // its next query); re-issue the same read, like papd's
                            // infinite-retry PAP_READ.
                            if last_activity.elapsed() > Duration::from_secs(120) {
                                tracing::warn!("PAP: connection timed out after 120s of inactivity");
                                return Ok(());
                            }
                            pull = Box::pin(make_pull(seq));
                        }
                    }
                }

                maybe_req = conn_responder.next() => {
                    let Some(req) = maybe_req else {
                        tracing::warn!("PAP: connection socket closed");
                        return Ok(());
                    };
                    let Ok(pap) = PapPacket::parse_from_atp(req.user_bytes, &req.data) else {
                        continue;
                    };
                    if pap.connection_id != conn_id {
                        tracing::warn!("PAP: ignoring packet with mismatched conn ID {}", pap.connection_id);
                        continue;
                    }
                    last_activity = tokio::time::Instant::now();

                    match pap.function {
                        PapFunction::SendData => {
                            // A retransmit of an already-answered read means our reply
                            // was lost; anything else out of sequence is stale (papd's rseq check).
                            if pap.sequence_num != 0 && pap.sequence_num != read_seq {
                                match cached_reply(&read_reply_cache, pap.sequence_num) {
                                    Some((_, ub, chunk)) => {
                                        let _ = req
                                            .send_response_chunked(chunk, *ub, PAP_MAX_DATA_PER_PACKET)
                                            .await;
                                    }
                                    None => {
                                        tracing::debug!("PAP: ignoring stale client read seq={}", pap.sequence_num);
                                    }
                                }
                            } else {
                                let this_seq = pap.sequence_num;
                                pending_read = Some((req, this_seq));
                            }
                        }
                        PapFunction::Tickle => {
                            tracing::debug!("PAP: received Tickle from client");
                        }
                        PapFunction::CloseConn => {
                            let reply = PapPacket {
                                connection_id: conn_id,
                                function: PapFunction::CloseConnReply,
                                sequence_num: 0,
                                eof: false,
                                data: vec![],
                            };
                            let (ub, d) = reply.to_atp_parts();
                            let _ = req.send_response(d, ub).await;
                            if !job_data.is_empty() {
                                tracing::warn!(
                                    "PAP: client closed mid-job, discarding {} partial bytes",
                                    job_data.len()
                                );
                            }
                            tracing::info!("PAP: connection closed by client");
                            return Ok(());
                        }
                        _ => {}
                    }
                }

                // The Mac polls SendStatus on the listener every ~500 ms while printing;
                // must keep draining it during a session or its ATP queue fills and every
                // request gets dropped (papd's parent answers status while a child prints).
                listener_req = self.responder.next() => {
                    let Some(req) = listener_req else {
                        return Err(anyhow!("PAP listener socket closed"));
                    };
                    let Ok(pap) = PapPacket::parse_from_atp(req.user_bytes, &req.data) else {
                        continue;
                    };
                    match pap.function {
                        PapFunction::SendStatus => {
                            let status_payload = self.status_payload(true).await;
                            let reply = PapPacket {
                                connection_id: 0,
                                function: PapFunction::Status,
                                sequence_num: 0,
                                eof: false,
                                data: status_payload,
                            };
                            let (ub, d) = reply.to_atp_parts();
                            let _ = req.send_response(d, ub).await;
                        }
                        PapFunction::OpenConn => {
                            // Single-session server: refuse with a busy result; the driver retries every 2s.
                            let sp = self.status_payload(true).await;
                            let mut reply_data = vec![0, 8, 0xFF, 0xFF];
                            reply_data.extend_from_slice(&sp[4..]);
                            let reply = PapPacket {
                                connection_id: pap.connection_id,
                                function: PapFunction::OpenConnReply,
                                sequence_num: 0,
                                eof: false,
                                data: reply_data,
                            };
                            let (ub, d) = reply.to_atp_parts();
                            let _ = req.send_response(d, ub).await;
                        }
                        _ => {}
                    }
                }

                _ = tickle_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(120) {
                        tracing::warn!("PAP: connection timed out after 120s of inactivity");
                        return Ok(());
                    }
                    let tickle = PapPacket {
                        connection_id: conn_id,
                        function: PapFunction::Tickle,
                        sequence_num: 0,
                        eof: false,
                        data: vec![],
                    };
                    let (tub, _) = tickle.to_atp_parts();
                    let _ = conn_requestor.send_alo(client_data_addr, tub).await;
                }
            }

            // Answer a waiting client read once this job's output is ready; eof on the
            // final chunk tells the driver we're done, then we reset for the next job.
            if response_ready && let Some((req, this_seq)) = pending_read.take() {
                let remaining = stdout.len().saturating_sub(stdout_pos);
                let take = remaining.min(req.max_packets() * PAP_MAX_DATA_PER_PACKET);
                let chunk = stdout[stdout_pos..stdout_pos + take].to_vec();
                let eof = stdout_pos + take >= stdout.len();
                stdout_pos += take;
                let reply = PapPacket {
                    connection_id: conn_id,
                    function: PapFunction::Data,
                    sequence_num: 0,
                    eof,
                    data: chunk,
                };
                let (ub, d) = reply.to_atp_parts();
                let _ = req
                    .send_response_chunked(d, ub, PAP_MAX_DATA_PER_PACKET)
                    .await;
                if this_seq != 0 {
                    read_seq = next_pap_seq(read_seq);
                    remember_reply(&mut read_reply_cache, this_seq, ub, d.to_vec());
                }
                if eof {
                    // This job's output is fully served; ready for the next job.
                    response_ready = false;
                    stdout = Vec::new();
                    stdout_pos = 0;
                }
            }
        }
    }

    /// Run forever, accepting connections in sequence.
    ///
    /// Returns only if the listener socket closes or a fatal protocol error occurs.
    /// Per-connection errors (timeouts, malformed packets) are logged and skipped.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            if let Err(e) = self.accept().await {
                tracing::error!("PAP: {e}");
                return Err(e);
            }
        }
    }
}

// ── PQP helpers ───────────────────────────────────────────────────────────────

/// Build the printer stdout payload for a PQP query job.
///
/// Handles three DSC comment forms, any number of blocks per job:
/// - `%%?BeginFeatureQuery:` / `%%?EndFeatureQuery:` — PPD feature lookups (`*LanguageLevel`, etc.)
/// - `%%?BeginQuery:` / `%%?EndQuery:` — general/vendor queries (`ADOSpooler`, `RBIUAMListQuery`, etc.)
/// - `%%?BeginFontQuery:` / `%%?EndFontQuery:` — font availability queries
///
/// Each block's answer is emitted followed by `\r`; no end-of-output marker —
/// the driver detects completion via the PAP eof flag, like papd.
fn pqp_stdout(attrs: &PrinterAttributes, job_data: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(job_data).unwrap_or("");

    enum Block {
        Query(String),
        Font(String),
    }

    let mut out = String::new();
    let mut current: Option<Block> = None;

    for line in text.split(['\r', '\n']) {
        if let Some(rest) = line
            .strip_prefix("%%?BeginFeatureQuery:")
            .or_else(|| line.strip_prefix("%%?BeginQuery:"))
        {
            // The Mac driver sometimes appends inline PS code on the same line:
            //   "RBIUAMListQuery(*)= flush"  →  we want just "RBIUAMListQuery"
            // Strip everything from the first `(` or whitespace onward.
            let rest = rest.trim();
            let name = rest.split(['(', ' ', '\t']).next().unwrap_or(rest);
            current = Some(Block::Query(name.to_string()));
        } else if let Some(rest) = line.strip_prefix("%%?BeginFontQuery:") {
            current = Some(Block::Font(rest.trim().to_string()));
        } else if let Some(rest) = line
            .strip_prefix("%%?EndFeatureQuery")
            .or_else(|| line.strip_prefix("%%?EndFontQuery"))
            .or_else(|| line.strip_prefix("%%?EndQuery"))
        {
            // The End comment carries the driver's fallback answer: "%%?EndQuery: *"
            let default_val = rest.trim_start_matches(':').trim();
            let answer = match current.take() {
                Some(Block::Font(fonts)) => pqp_font_answer(&fonts),
                Some(Block::Query(name)) => pqp_answer(attrs, &name, default_val),
                None => default_val.to_string(),
            };
            out.push_str(&answer);
            out.push('\r');
        }
    }

    out.into_bytes()
}

/// Return the answer to a named PQP query, falling back to `default` for
/// unrecognised queries.
fn pqp_answer(attrs: &PrinterAttributes, query: &str, default: &str) -> String {
    match query {
        // ── RBI spooler queries (%%?BeginQuery:, Netatalk extension) ─────────

        // UAM (user authentication method) list for print authentication.
        // We do no authentication, so answer "*" (no UAMs) exactly like papd —
        // answering anything else makes the LaserWriter driver believe a login
        // is required and abort the query session.
        "RBIUAMListQuery" => "*".to_string(),

        // Spooler identification string, papd-style "(name) version" format.
        "RBISpoolerID" => "(TailTalk Spooler) 1.0".to_string(),

        // ── Standard PPD feature queries (%%?BeginFeatureQuery:) ─────────────

        // PostScript language level: "1" or "2".
        "*LanguageLevel" => attrs.language_level.to_string(),

        // PS interpreter version: "(versnum) revnum" format.
        // We emulate a LaserWriter running PS 2010 (a common PS Level 2 build).
        "*PSVersion" => "(2010.020) 0".to_string(),

        // Product name in PS string literal form: "(name)".
        "*Product" => format!("({})", attrs.product_name),

        // Current resolution; same source as RBResolution but different query key.
        "*?Resolution" => attrs
            .resolutions_dpi
            .first()
            .map(|dpi| format!("{dpi}dpi"))
            .unwrap_or_else(|| default.to_string()),

        // Color capability.
        "*ColorDevice" => {
            if attrs.color { "True".to_string() } else { "False".to_string() }
        }

        // Free PostScript VM in bytes. We report a plausible amount.
        "*FreeVM" => "4194304".to_string(),

        // TrueType rasterizer: Type42 means built-in TrueType support.
        // Returning Type42 lets the Mac driver use TrueType fonts directly.
        "*TTRasterizer" => "Type42".to_string(),

        // PostScript fax support: we're a print spooler, not a fax machine.
        "*FaxSupport" => "None".to_string(),

        // ── ADO general queries (%%?BeginQuery:) ─────────────────────────────

        // Identify ourselves as a spooler so the Mac driver adheres to DSC.
        "ADOSpooler" => "spooler".to_string(),

        // Installed RAM: we don't track this, Unknown is a safe fallback.
        "ADORamSize" => "Unknown".to_string(),

        // Binary comms: AppleTalk supports binary transmission.
        "ADOIsBinaryOK?" => "True".to_string(),

        _ => default.to_string(),
    }
}

/// Return the answer to a font availability query.
///
/// The query lists font names (space-separated) in the `%%?BeginFontQuery:` line.
/// Since we're a spooler without a PS interpreter, we report all fonts as unavailable,
/// which causes the Mac driver to embed fonts in the print job — the safest behaviour.
///
/// Response format (DSC 2.1+): `/FontName:Yes` or `/FontName:No` per line, then `*`.
fn pqp_font_answer(font_list: &str) -> String {
    let mut lines: Vec<String> = font_list
        .split_whitespace()
        .filter(|f| !f.is_empty())
        .map(|f| {
            let name = f.trim_start_matches('/');
            format!("/{name}:No")
        })
        .collect();
    lines.push("*".to_string());
    lines.join("\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn seq_wraps_past_zero() {
        assert_eq!(next_pap_seq(1), 2);
        assert_eq!(next_pap_seq(65534), 65535);
        // 0 is reserved for "unsequenced" and must be skipped on wrap.
        assert_eq!(next_pap_seq(65535), 1);
    }

    #[test]
    fn reply_cache_answers_retransmits_out_of_order() {
        let mut cache: VecDeque<CachedReply> = VecDeque::new();
        for seq in 1..=4u16 {
            remember_reply(&mut cache, seq, [0, 4, 0, 0], vec![seq as u8]);
        }

        // A retransmit of any still-cached seq must replay its own bytes, not the
        // most recent reply; answering with fresh data would drop part of the job.
        for seq in 1..=4u16 {
            let (_, _, data) = cached_reply(&cache, seq).expect("reply should be cached");
            assert_eq!(data, &vec![seq as u8]);
        }
        assert!(cached_reply(&cache, 9).is_none());
    }

    #[test]
    fn reply_cache_evicts_oldest_when_full() {
        let mut cache: VecDeque<CachedReply> = VecDeque::new();
        for seq in 1..=(PAP_REPLY_CACHE_LEN as u16 + 2) {
            remember_reply(&mut cache, seq, [0, 4, 0, 0], vec![seq as u8]);
        }

        assert_eq!(cache.len(), PAP_REPLY_CACHE_LEN);
        // The two oldest aged out; everything within the flow quantum is retained.
        assert!(cached_reply(&cache, 1).is_none());
        assert!(cached_reply(&cache, 2).is_none());
        assert!(cached_reply(&cache, 3).is_some());
        assert!(cached_reply(&cache, PAP_REPLY_CACHE_LEN as u16 + 2).is_some());
    }

    #[test]
    fn reply_cache_survives_sequence_wrap() {
        // Around the 65535→1 wrap the cache holds both high and low numbers at once.
        // Lookup is by membership, not ordering, so a fresh seq=1 after the wrap is
        // only treated as a retransmit if it is genuinely still cached.
        let mut cache: VecDeque<CachedReply> = VecDeque::new();
        remember_reply(&mut cache, 65534, [0, 4, 0, 0], vec![0xAA]);
        remember_reply(&mut cache, 65535, [0, 4, 0, 0], vec![0xBB]);

        assert!(cached_reply(&cache, 1).is_none(), "post-wrap seq=1 is new, not a retransmit");
        assert_eq!(cached_reply(&cache, 65535).unwrap().2, vec![0xBB]);
    }

    #[test]
    fn pqp_answers_uam_query_with_no_authentication() {
        let attrs = PrinterAttributes::default();
        // Answering anything but "*" makes the LaserWriter driver believe a login is
        // required and abort the query session.
        assert_eq!(pqp_answer(&attrs, "RBIUAMListQuery", "fallback"), "*");
        // Unrecognised queries fall back to the driver's own default.
        assert_eq!(pqp_answer(&attrs, "SomeUnknownQuery", "fallback"), "fallback");
    }

    #[test]
    fn pqp_stdout_answers_each_block_with_trailing_cr() {
        let attrs = PrinterAttributes::default();
        let job = b"%!PS-Adobe-3.0 Query\r\
                    %%?BeginQuery: RBIUAMListQuery\r(*)= flush\r%%?EndQuery: *\r\
                    %%?BeginFeatureQuery: *LanguageLevel\r%%?EndFeatureQuery: 1\r";
        assert_eq!(pqp_stdout(&attrs, job), b"*\r2\r".to_vec());
    }
}
