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
    /// statusdict `version`, the interpreter's ROM version, e.g. `"47.0"` on a
    /// LaserWriter Plus. Reported for `%%?BeginPrinterQuery` and `*PSVersion`.
    pub ps_version: String,
    /// statusdict `revision`, paired with [`ps_version`](Self::ps_version).
    pub ps_revision: u32,
    /// Fonts resident in the printer, listed for `%%?BeginFontListQuery`.
    /// [`LASERWRITER_35`] by default; narrow it where the renderer lacks a face,
    /// but do not empty it. A driver that cannot embed, like the Apple IIgs
    /// LaserWriter one, abandons the job rather than print to a printer with none.
    pub resident_fonts: Vec<String>,
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
            // A common PostScript Level 2 build, matching what we report for *PSVersion.
            ps_version: "2010.020".to_string(),
            ps_revision: 0,
            resident_fonts: LASERWRITER_35.iter().map(|f| (*f).to_string()).collect(),
            color: false,
            resolutions_dpi: vec![300],
            paper_sizes: vec![PaperSize::Letter],
        }
    }
}

/// Identifies the PAP connection a job arrived on, for the life of the server.
///
/// The PAP connection ID on the wire is only a byte and gets reused, so this is a
/// counter of our own. A sink that has to carry something from one job to the next
/// (a downloaded prologue, say) can key it on this and know it will never mistake
/// the next driver's conversation for the one it was talking to.
///
/// Numbering starts at 1, so a fabricated `ConnectionId(0)` matches no real
/// connection.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnectionId(pub u64);

/// A received print job ready for processing by a [`PrintSink`].
pub struct PrintJob {
    /// Source AppleTalk address (network/node of the client).
    pub client_addr: AtpAddress,
    /// The connection this job and its siblings arrived on.
    pub connection: ConnectionId,
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
    /// Hands out a fresh [`ConnectionId`] to each connection accepted.
    connections: u64,
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
            connections: 0,
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
        self.connections += 1;
        let connection = ConnectionId(self.connections);
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

        let mut job = JobBuffer::default();
        let mut stdout = PrinterStdout::default();
        // Whether this job's output may be handed to a waiting read. False while a
        // job is still arriving, since a driver that reads early has to wait.
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
                            job.push(&data_pkt.data);

                            if data_pkt.eof && job.is_empty() {
                                // A zero-byte job (PapClient's post-EOF drain sends one)
                                // would otherwise clobber a still-unread query answer.
                                tracing::debug!("PAP: ignoring empty job");
                            } else if data_pkt.eof {
                                let (data, answered) = job.take();
                                if pqp_query_style(&data).is_some() {
                                    let attrs = self.attributes.read().await;
                                    let writes = pqp_writes(&attrs, &data[answered..]);
                                    tracing::info!(
                                        "PAP: PQP query from {:?}, answering with {} writes",
                                        client_data_addr,
                                        writes.len()
                                    );
                                    // Behind whatever is still unread, never in place of it: a
                                    // block answered earlier may not have been collected yet, and
                                    // dropping it leaves the driver waiting on an answer that has
                                    // been thrown away.
                                    stdout.queue(writes);
                                } else {
                                    tracing::info!("PAP: job complete, {} bytes received", data.len());
                                    if let Err(e) = self
                                        .sink
                                        .receive_job(PrintJob {
                                            client_addr: client_data_addr,
                                            connection,
                                            data,
                                        })
                                        .await
                                    {
                                        tracing::error!("PAP: sink error: {e}");
                                    }
                                }
                                response_ready = true;
                            } else if pqp_query_style(job.as_slice()).is_some()
                                && let Some(end) = pqp_answerable_prefix(job.unanswered())
                            {
                                // Pre-3.0 drivers never set eof on a query job: they write it and
                                // block on the read, waiting for the printer to speak first. So
                                // answer as soon as the text is answerable, the way a real
                                // interpreter's `flush` would, rather than waiting for an eof
                                // that is never coming.
                                let block = &job.unanswered()[..end];
                                let writes = {
                                    let attrs = self.attributes.read().await;
                                    pqp_writes(&attrs, block)
                                };
                                tracing::info!(
                                    "PAP: PQP query from {:?} (no eof), answering with {} writes",
                                    client_data_addr,
                                    writes.len()
                                );
                                let job_over = job_ends_at_eof(block);
                                stdout.queue(writes);
                                response_ready = true;
                                job.mark_answered(end);
                                if job_over {
                                    // %%EOF closes the query job outright, so let the buffer go
                                    // now rather than waiting for the next job's header to say
                                    // so. Matters for a print job that opens with raw
                                    // PostScript, which `pqp_resync` has no header to sync on.
                                    job.clear();
                                }
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
                            // A query we already answered in full is not an unfinished job,
                            // so only what is still unanswered counts as one.
                            if !job.unanswered().is_empty() {
                                let (data, answered) = job.take();
                                // A PostScript job is self-delimiting, so a buffer ending in
                                // %%EOF is a whole job whose driver simply closed instead of
                                // setting the PAP eof flag, the same omission the pre-3.0
                                // drivers make on queries. Anything else really is a job cut
                                // short, and printing half of it helps nobody.
                                if pqp_query_style(&data).is_none() && job_ends_at_eof(&data) {
                                    tracing::info!(
                                        "PAP: client closed without eof, printing the complete {} byte job",
                                        data.len()
                                    );
                                    if let Err(e) = self
                                        .sink
                                        .receive_job(PrintJob {
                                            client_addr: client_data_addr,
                                            connection,
                                            data,
                                        })
                                        .await
                                    {
                                        tracing::error!("PAP: sink error: {e}");
                                    }
                                } else {
                                    tracing::warn!(
                                        "PAP: client closed mid-job, discarding {} partial bytes",
                                        data.len() - answered
                                    );
                                }
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

            // Answer a waiting client read once this job's output is ready. One printer
            // write per response, so a font list arrives one name at a time; eof on the
            // last one tells the driver we're done, then we reset for the next job.
            if response_ready && let Some((req, this_seq)) = pending_read.take() {
                let (chunk, eof) =
                    stdout.next_chunk(req.max_packets() * PAP_MAX_DATA_PER_PACKET);
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

// ── Session buffers ───────────────────────────────────────────────────────────

/// The job arriving from the driver, and how much of it has been answered.
///
/// Answered text stays in the buffer rather than being consumed, so the
/// `%!PS-Adobe-…` header keeps saying what the job is after some of its blocks have
/// been replied to. Only [`Self::push`] drops anything, and only what
/// [`pqp_resync`] calls finished business.
#[derive(Default)]
struct JobBuffer {
    data: Vec<u8>,
    answered: usize,
}

impl JobBuffer {
    /// Append what a Data packet carried, dropping whatever is now spent.
    fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
        let spent = pqp_resync(&self.data, self.answered);
        if spent > 0 {
            tracing::debug!("PAP: dropping {spent} bytes ahead of the job header");
            self.data.drain(..spent);
            self.answered = self.answered.saturating_sub(spent);
        }
    }

    fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// What no answer has covered yet.
    fn unanswered(&self) -> &[u8] {
        &self.data[self.answered.min(self.data.len())..]
    }

    /// Note that `len` more bytes, counted from the front of [`Self::unanswered`],
    /// have been answered.
    fn mark_answered(&mut self, len: usize) {
        self.answered += len;
    }

    /// Empty the buffer, returning everything in it and where its unanswered part
    /// begins.
    fn take(&mut self) -> (Vec<u8>, usize) {
        let answered = self.answered.min(self.data.len());
        self.answered = 0;
        (std::mem::take(&mut self.data), answered)
    }

    fn clear(&mut self) {
        self.data.clear();
        self.answered = 0;
    }
}

/// The printer's stdout: the writes a real interpreter would have flushed, waiting
/// for the driver to read them.
///
/// One write per PAP Data response and never two in one, because a font list has to
/// arrive one name per packet and the drivers that ask for one notice if it does
/// not. A write too big for a single response is spread over as many as it needs.
#[derive(Default)]
struct PrinterStdout {
    writes: std::collections::VecDeque<Vec<u8>>,
    /// How far into `writes.front()` the last response got.
    pos: usize,
}

impl PrinterStdout {
    fn queue(&mut self, writes: impl IntoIterator<Item = Vec<u8>>) {
        self.writes.extend(writes);
    }

    /// The next response body, and whether it is the last for this job.
    ///
    /// Empty and final when nothing is queued, which is the answer a print job gets:
    /// it produced no output, and the eof says so.
    fn next_chunk(&mut self, max: usize) -> (Vec<u8>, bool) {
        let mut chunk = Vec::new();
        if let Some(write) = self.writes.front() {
            let take = (write.len() - self.pos).min(max);
            chunk.extend_from_slice(&write[self.pos..self.pos + take]);
            self.pos += take;
            if self.pos >= write.len() {
                self.writes.pop_front();
                self.pos = 0;
            }
        }
        (chunk, self.writes.is_empty())
    }
}

/// The 35 fonts every PostScript printer has carried since the LaserWriter Plus,
/// in the names a driver asks for them by.
///
/// The default for [`PrinterAttributes::resident_fonts`]. Safe to claim wholesale:
/// Ghostscript ships URW equivalents under exactly these names, and any real
/// PostScript printer has them too, so it holds for a job we render and one we hand
/// on. `lw_bridge::resident_fonts` trims it to what Ghostscript actually has.
pub const LASERWRITER_35: [&str; 35] = [
    "AvantGarde-Book",
    "AvantGarde-BookOblique",
    "AvantGarde-Demi",
    "AvantGarde-DemiOblique",
    "Bookman-Demi",
    "Bookman-DemiItalic",
    "Bookman-Light",
    "Bookman-LightItalic",
    "Courier",
    "Courier-Bold",
    "Courier-BoldOblique",
    "Courier-Oblique",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-BoldOblique",
    "Helvetica-Narrow",
    "Helvetica-Narrow-Bold",
    "Helvetica-Narrow-BoldOblique",
    "Helvetica-Narrow-Oblique",
    "Helvetica-Oblique",
    "NewCenturySchlbk-Bold",
    "NewCenturySchlbk-BoldItalic",
    "NewCenturySchlbk-Italic",
    "NewCenturySchlbk-Roman",
    "Palatino-Bold",
    "Palatino-BoldItalic",
    "Palatino-Italic",
    "Palatino-Roman",
    "Symbol",
    "Times-Bold",
    "Times-BoldItalic",
    "Times-Italic",
    "Times-Roman",
    "ZapfChancery-MediumItalic",
    "ZapfDingbats",
];

/// The 13 fonts of the original 1985 LaserWriter, for emulating one of those.
/// A subset of [`LASERWRITER_35`].
pub const LASERWRITER_13: [&str; 13] = [
    "Courier",
    "Courier-Bold",
    "Courier-BoldOblique",
    "Courier-Oblique",
    "Helvetica",
    "Helvetica-Bold",
    "Helvetica-BoldOblique",
    "Helvetica-Oblique",
    "Symbol",
    "Times-Bold",
    "Times-BoldItalic",
    "Times-Italic",
    "Times-Roman",
];

// ── PQP helpers ───────────────────────────────────────────────────────────────
//
// All of these work on the bytes rather than on a decoded string, and split lines
// themselves rather than borrowing `str::lines`. A query is not necessarily text:
// the LaserWriter 7.x PatchPrep query wraps an eexec-encrypted ProcSet in its
// PostScript, so anything that starts by decoding the whole job reads it as no
// query at all, and any offset taken from a lossy decode of it points somewhere
// else. The DSC comments are ASCII whatever sits between them, so a line at a time
// is decoded, lossily, purely to compare it against a prefix.

/// Split a `%%?Begin<kind>Query` line into its kind and any argument after it.
///
/// `%%?BeginFeatureQuery: *Product` → `("Feature", "*Product")`, the plain
/// `%%?BeginQuery:` form yields an empty kind, and the argument-less kinds
/// (`%%?BeginPrinterQuery`, `%%?BeginFontListQuery`) an empty argument. The colon
/// is optional precisely because those two never carry one. `None` for other lines.
fn pqp_begin_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("%%?Begin")?;
    let (kind, rest) = rest.split_once("Query")?;
    Some((kind, rest.trim_start_matches(':').trim()))
}

/// Split a `%%?End<kind>Query` line into its kind and the driver's fallback answer.
///
/// The End comment carries the answer to use when the printer says nothing:
/// `%%?EndQuery: *` → `("", "*")`.
fn pqp_end_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("%%?End")?;
    let (kind, rest) = rest.split_once("Query")?;
    Some((kind, rest.trim_start_matches(':').trim()))
}

/// Whether a buffered job ends at its own `%%EOF` trailer, ignoring trailing
/// whitespace and the `^D` some drivers append.
fn job_ends_at_eof(job_data: &[u8]) -> bool {
    let tail = job_data
        .iter()
        .rposition(|b| !b.is_ascii_whitespace() && *b != 0x04)
        .map_or(&[][..], |end| &job_data[..=end]);
    tail.ends_with(b"%%EOF")
}

/// How a driver marks a job as a PostScript query.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum QueryStyle {
    /// `%!PS-Adobe-3.0 Query`: LaserWriter 8, which sets the PAP eof flag.
    Dsc3,
    /// Pre-3.0 (LaserWriter 7.x, Color LaserWriter): never sets eof.
    Legacy,
}

/// Offset of the `%!` job header in a buffer, or `None` if there isn't one yet.
fn pqp_magic_offset(job_data: &[u8]) -> Option<usize> {
    job_data.windows(2).position(|w| w == b"%!")
}

/// How many leading bytes of the job buffer are finished business and can go.
///
/// The buffer holds one job, but drivers do not hand over one job at a time:
/// - they preface a job with loose PostScript belonging to no job at all, a
///   `statusdict/jobname(…)put` naming the document being the one we have seen.
///   Left in place it hides the `%!PS-Adobe` header behind it, and passed to the
///   interpreter it is stray code either way.
/// - and having had a query answered in full, the next `%!` they send is the next
///   job, not more of the one just finished. Pre-3.0 drivers close a query job with
///   neither a PAP eof nor a `%%EOF`, so this is the only thing that separates the
///   query from the print job that follows it on the same connection.
///
/// Both are text sitting in front of a header that starts no job of its own, so
/// both are the same rule. Text belonging to a job still being received is never
/// touched, which is what stops an EPS `%!` embedded in a print job truncating it.
fn pqp_resync(job_data: &[u8], answered: usize) -> usize {
    let answered = answered.min(job_data.len());
    if answered == 0 && job_data.starts_with(b"%!") {
        return 0; // Mid-job with the header already at the front.
    }
    match pqp_magic_offset(&job_data[answered..]) {
        Some(magic) => answered + magic,
        // No header in what is left. Either a job is still arriving and its header
        // is yet to turn up, or a query has been answered to the last byte and what
        // is buffered is spent.
        None if answered == job_data.len() => answered,
        None => 0,
    }
}

/// Classify a job from its `%!PS-Adobe-…` header line, or `None` if it is not a query.
///
/// Version-agnostic on purpose: LaserWriter 8 sends `%!PS-Adobe-3.0 Query`, the
/// LaserWriter 7.x-era drivers send `%!PS-Adobe-2.0 Query`, and a few send a bare
/// `%!PS-Adobe Query`.
fn pqp_query_style(job_data: &[u8]) -> Option<QueryStyle> {
    let first = job_data.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(&[]);
    let first = String::from_utf8_lossy(first);
    let rest = first.trim_end().strip_prefix("%!PS-Adobe")?;
    let rest = rest.strip_suffix("Query")?.trim();

    // "-3.0" → 3.0; a bare "%!PS-Adobe Query" has no version and is pre-3.0.
    let version: f32 = rest.trim_start_matches('-').parse().unwrap_or(0.0);
    Some(if version >= 3.0 { QueryStyle::Dsc3 } else { QueryStyle::Legacy })
}

/// Length of the prefix of a still-open query job that can already be answered,
/// or `None` if there is nothing complete to answer yet.
///
/// A block becomes answerable at its `%%?End…Query` line, and the job's `%%EOF` is
/// swallowed with it so nothing is left dangling. Answering as soon as we can is
/// what a real interpreter does, and it is the only thing that works for the
/// pre-3.0 drivers, which write a query and then block on the read without ever
/// setting the PAP eof flag we would otherwise wait for.
fn pqp_answerable_prefix(job_data: &[u8]) -> Option<usize> {
    // Byte offset just past the newest line that closes a block, or ends the job.
    let mut end = None;
    let mut depth = 0usize;
    let mut pos = 0usize;
    for line in job_data.split_inclusive(|&b| b == b'\r' || b == b'\n') {
        pos += line.len();
        let line = String::from_utf8_lossy(line);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if pqp_begin_line(trimmed).is_some() {
            depth += 1;
        } else if pqp_end_line(trimmed).is_some() {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                end = Some(pos);
            }
        } else if depth == 0 && end.is_some() && trimmed.trim() == "%%EOF" {
            end = Some(pos);
        }
    }
    end
}

/// Build the printer's stdout for a PQP query job, as the sequence of writes a real
/// interpreter would have flushed. Each one goes back in its own PAP Data response.
///
/// Handles any `%%?Begin<kind>Query` / `%%?End<kind>Query` pair, any number of
/// blocks per job. Drivers do put several in a single PAP packet, and while that is
/// off-spec, Netatalk and Apple's own spoolers accept it, so we do too. The kinds
/// we answer specially are:
/// - `Feature`: PPD feature lookups (`*LanguageLevel`, `*Product`, …)
/// - *(empty)*: general/vendor queries (`ADOSpooler`, `RBIUAMListQuery`, …)
/// - `Printer`: the pre-3.0 identity query, `revision`/`version`/`product`
/// - `FontList`: everything resident, one write per name
/// - `Font`: font availability queries
/// - `ProcSet`: "is this ProcSet already downloaded?", always no for a spooler
///
/// Anything else falls back to the answer the driver put in its own End comment.
fn pqp_writes(attrs: &PrinterAttributes, job_data: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut current: Option<(String, String)> = None;

    for line in job_data.split(|&b| b == b'\r' || b == b'\n') {
        let line = String::from_utf8_lossy(line);
        let line = line.as_ref();
        if let Some((kind, rest)) = pqp_begin_line(line) {
            // The Mac driver sometimes appends inline PS code on the same line:
            //   "RBIUAMListQuery(*)= flush"  →  we want just "RBIUAMListQuery"
            // Strip everything from the first `(` or whitespace onward.
            let name = match kind {
                "Font" | "ProcSet" => rest,
                _ => rest.split(['(', ' ', '\t']).next().unwrap_or(rest),
            };
            current = Some((kind.to_string(), name.to_string()));
        } else if let Some((_, default_val)) = pqp_end_line(line) {
            // The `\r` on most answers and the `\n` on two of them are not a slip:
            // `=` and `==` end their output with a newline, and the queries that go
            // through them are exactly the two below.
            let block = current.take();
            match block.as_ref().map(|(kind, name)| (kind.as_str(), name.as_str())) {
                // `statusdict begin revision == version == product == end flush` is
                // one flush after three `==`, so one write of three lines. The space
                // after the revision is what a real LaserWriter emits; keep it.
                Some(("Printer", _)) => out.push(
                    format!(
                        "{} \n({})\n({})\n",
                        attrs.ps_revision, attrs.ps_version, attrs.product_name
                    )
                    .into_bytes(),
                ),
                // `FontDirectory{pop = flush}forall/* = flush` flushes inside the
                // loop, so every name is its own write and `*` terminates the list.
                // `=` prints a name without its slash, which is why the terminator
                // comes out as `*` and not `/*`; the font names match that.
                Some(("FontList", _)) => {
                    for font in &attrs.resident_fonts {
                        out.push(format!("{}\n", font.trim_start_matches('/')).into_bytes());
                    }
                    out.push(b"*\n".to_vec());
                }
                Some(("Font", fonts)) => {
                    out.push(format!("{}\r", pqp_font_answer(attrs, fonts)).into_bytes())
                }
                // 0 = not resident. We have no interpreter and keep no state between
                // jobs, so the driver must download the ProcSet itself. Its End
                // comment says "unknown", which is not a usable answer.
                Some(("ProcSet", _)) => out.push(b"0\r".to_vec()),
                Some((_, name)) => {
                    out.push(format!("{}\r", pqp_answer(attrs, name, default_val)).into_bytes())
                }
                // An End with no Begin in front of it: the driver's own fallback is
                // the only answer there is.
                None => out.push(format!("{default_val}\r").into_bytes()),
            }
        }
    }

    out
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

        // PS interpreter version: "(versnum) revnum" format, the same pair the
        // pre-3.0 %%?BeginPrinterQuery reports.
        "*PSVersion" => format!("({}) {}", attrs.ps_version, attrs.ps_revision),

        // Product name in PS string literal form: "(name)".
        "*Product" => format!("({})", attrs.product_name),

        // Current resolution. A driver asks by the PPD's main keyword, `*Resolution`;
        // `*?Resolution` is what the PPD calls the query entry that answers it, and
        // some drivers do send that instead, so take either.
        "*Resolution" | "*?Resolution" => attrs
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
/// Answered from [`PrinterAttributes::resident_fonts`], the same source as the font
/// list query, so a driver that asks both ways is told the same thing twice.
/// Anything not on the list is a `No`, and the driver embeds it.
///
/// Response format (DSC 2.1+): `/FontName:Yes` or `/FontName:No` per line, then `*`.
fn pqp_font_answer(attrs: &PrinterAttributes, font_list: &str) -> String {
    let mut lines: Vec<String> = font_list
        .split_whitespace()
        .filter(|f| !f.is_empty())
        .map(|f| {
            let name = f.trim_start_matches('/');
            let resident = attrs
                .resident_fonts
                .iter()
                .any(|r| r.trim_start_matches('/') == name);
            format!("/{name}:{}", if resident { "Yes" } else { "No" })
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
    fn pqp_writes_answer_each_block_with_trailing_cr() {
        let attrs = PrinterAttributes::default();
        let job = b"%!PS-Adobe-3.0 Query\r\
                    %%?BeginQuery: RBIUAMListQuery\r(*)= flush\r%%?EndQuery: *\r\
                    %%?BeginFeatureQuery: *LanguageLevel\r%%?EndFeatureQuery: 1\r";
        assert_eq!(pqp_writes(&attrs, job), vec![b"*\r".to_vec(), b"2\r".to_vec()]);
    }

    /// Verbatim from a System 7 Mac printing to us through the Color LaserWriter
    /// 12/600 driver. It never sets the PAP eof flag on this, so recognising the
    /// 2.0 header and the ProcSet block is what keeps the session from deadlocking.
    const LW7_PROCSET_QUERY: &[u8] = b"%!PS-Adobe-2.0 Query\r\
        %%Title: Query for PatchPrep\r\
        %%?BeginProcSetQuery: \"(AppleDict md)\" 71 0\r\
        userdict/PV known{userdict begin PV 1 ge{(1)}{(2)}ifelse end}\
        {/md where{pop(2)}{(0)}ifelse}ifelse = flush\r\
        %%?EndProcSetQuery: unknown\r";

    /// The LaserWriter 7.1.2 PatchPrep query, from a LocalTalk capture (the eexec
    /// string is shortened, nothing else). Its `{eexec}` branch carries an encrypted
    /// ProcSet, so the job is binary and decoding the whole buffer as UTF-8 fails.
    /// Everything here has to work on the bytes: read as "not a query", the driver is
    /// left blocked on a read that never comes and the print never starts.
    const LW7_BINARY_PROCSET_QUERY: &[u8] = b"%!PS-Adobe-2.0 Query\r\
        %%Title: Query for PatchPrep\r\
        %%?BeginProcSetQuery: \"(AppleDict md)\" 71 0\r\
        /L{load def}def/I/ifelse L/D/dup L/P/pop L\r\
        D 0 eq{P vmstatus exch sub exch P 1.8e5\r\
        gt{save false(\x18\x61\xae\xda\xe1\x18\xa9\xf9\x5f\x16\x5c\x29\xc0\x13\
        \x7f\x8f\xe6\x56\x81\x1d\xd9\x3d\xfb\xea)\
        {eexec}stopped{D type/stringtype eq{P}if}if\r\
        exch restore{20}{0}I}{0}I}if\r\
        = flush\r\
        %%?EndProcSetQuery: unknown\r";

    /// The other pre-3.0 shape, from a IIgs-era driver over EtherTalk: two blocks in
    /// one PAP packet, argument-less Begin comments, and a `%%EOF` in place of the
    /// PAP eof flag the driver never sets.
    const LW7_PRINTER_QUERY: &[u8] = b"%!PS-Adobe-2.0 Query\r\
        %%?BeginPrinterQuery\r\
        statusdict begin revision == version == product == end flush\r\
        %%?EndPrinterQuery: Unknown\r\
        %%?BeginFontListQuery\r\
        FontDirectory{pop = flush}forall/* = flush\r\
        %%?EndFontListQuery: /*\r\
        %%EOF\r";

    #[test]
    fn pqp_recognises_query_jobs_of_every_dsc_vintage() {
        use QueryStyle::*;
        assert_eq!(pqp_query_style(b"%!PS-Adobe-3.0 Query\r"), Some(Dsc3));
        assert_eq!(pqp_query_style(LW7_PROCSET_QUERY), Some(Legacy));
        assert_eq!(pqp_query_style(LW7_PRINTER_QUERY), Some(Legacy));
        assert_eq!(pqp_query_style(b"%!PS-Adobe Query\r"), Some(Legacy));
        // Real print jobs and partial first lines must never be taken for queries.
        assert_eq!(pqp_query_style(b"%!PS-Adobe-3.0\rshowpage\r"), None);
        assert_eq!(pqp_query_style(b"%!PS-Adobe-2.0 Q"), None);
        assert_eq!(pqp_query_style(b""), None);
    }

    #[test]
    fn pqp_answers_procset_query_as_not_resident() {
        let attrs = PrinterAttributes::default();
        // The driver's own fallback is the useless word "unknown"; 0 means "not in
        // the printer", which makes it download the ProcSet as part of the job.
        assert_eq!(pqp_writes(&attrs, LW7_PROCSET_QUERY), vec![b"0\r".to_vec()]);
    }

    #[test]
    fn pqp_answers_a_query_carrying_binary() {
        assert!(
            String::from_utf8(LW7_BINARY_PROCSET_QUERY.to_vec()).is_err(),
            "the point of this fixture is that it is not text"
        );

        let attrs = PrinterAttributes::default();
        assert_eq!(pqp_query_style(LW7_BINARY_PROCSET_QUERY), Some(QueryStyle::Legacy));

        // No eof is coming, so the End comment is the only thing that says the block
        // can be answered; the offset it reports has to be a byte offset into the
        // original job, not into some re-encoded copy of it.
        let end = pqp_answerable_prefix(LW7_BINARY_PROCSET_QUERY)
            .expect("the block ends at its %%?EndProcSetQuery");
        assert_eq!(end, LW7_BINARY_PROCSET_QUERY.len());
        assert_eq!(
            pqp_writes(&attrs, &LW7_BINARY_PROCSET_QUERY[..end]),
            vec![b"0\r".to_vec()]
        );
    }

    #[test]
    fn pqp_answers_printer_and_font_list_queries() {
        let attrs = PrinterAttributes {
            product_name: "LaserWriter Plus".to_string(),
            ps_version: "47.0".to_string(),
            ps_revision: 1,
            ..PrinterAttributes::default()
        };
        // One flush after the three `==`, so the identity is a single write. The
        // space after the revision is deliberate.
        let writes = pqp_writes(&attrs, LW7_PRINTER_QUERY);
        assert_eq!(writes[0], b"1 \n(47.0)\n(LaserWriter Plus)\n".to_vec());

        // Then the default font list, one write per name and `*` to end it.
        let mut expected: Vec<Vec<u8>> = LASERWRITER_35
            .iter()
            .map(|f| format!("{f}\n").into_bytes())
            .collect();
        expected.push(b"*\n".to_vec());
        assert_eq!(&writes[1..], expected.as_slice());
    }

    #[test]
    fn pqp_font_query_agrees_with_the_font_list() {
        let attrs = PrinterAttributes {
            resident_fonts: vec!["Times-Roman".to_string(), "/Helvetica".to_string()],
            ..PrinterAttributes::default()
        };
        // Slash or no slash on either side, the names still have to match up.
        assert_eq!(
            pqp_font_answer(&attrs, "/Times-Roman Helvetica /Bookman-Light"),
            "/Times-Roman:Yes\r/Helvetica:Yes\r/Bookman-Light:No\r*",
        );
    }

    #[test]
    fn pqp_font_list_sends_one_unslashed_write_per_name() {
        // `FontDirectory{pop = flush}forall` flushes inside the loop, so the driver
        // expects each name in its own PAP packet, then `*` in one of its own. The
        // names carry no slash: `=` prints a name without one, which is exactly why
        // the driver's own `/* = flush` terminator comes back as plain `*`.
        let attrs = PrinterAttributes {
            resident_fonts: vec!["Times-Roman".to_string(), "/Helvetica".to_string()],
            ..PrinterAttributes::default()
        };
        let writes = pqp_writes(&attrs, LW7_PRINTER_QUERY);
        assert_eq!(
            &writes[1..],
            &[b"Times-Roman\n".to_vec(), b"Helvetica\n".to_vec(), b"*\n".to_vec()],
        );
    }

    #[test]
    fn laserwriter_font_sets_are_the_documented_ones() {
        // The 13 of the 1985 LaserWriter are a strict subset of the Plus's 35.
        for font in LASERWRITER_13 {
            assert!(LASERWRITER_35.contains(&font), "{font} missing from the 35");
        }
        // No duplicates, and no stray slashes: these go on the wire as written.
        let mut sorted = LASERWRITER_35;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(deduped.len(), LASERWRITER_35.len(), "duplicate font name");
        assert!(LASERWRITER_35.iter().all(|f| !f.starts_with('/')));
    }

    #[test]
    fn pqp_resync_drops_the_prologue_before_a_job_header() {
        // The jobname prologue arrives in its own PAP packet ahead of the query and
        // has to go, or the header never lands at the front of the buffer.
        let prologue = b"statusdict/jobname(User - Byte Knight)put\r";
        let mut buf = prologue.to_vec();
        buf.extend_from_slice(LW7_PRINTER_QUERY);
        assert_eq!(pqp_resync(&buf, 0), prologue.len());
        assert_eq!(pqp_query_style(&buf[prologue.len()..]), Some(QueryStyle::Legacy));

        // Until the header turns up there is nothing to sync to, so keep buffering.
        assert_eq!(pqp_resync(prologue, 0), 0);
        // And a job already sitting at its header is left alone, embedded EPS and all.
        assert_eq!(pqp_resync(LW7_PRINTER_QUERY, 0), 0);
        let with_eps = b"%!PS-Adobe-3.0\r%%BeginDocument\r%!PS-Adobe-3.0 EPSF-3.0\r".to_vec();
        assert_eq!(pqp_resync(&with_eps, 0), 0, "an embedded EPS must not truncate a job");
    }

    #[test]
    fn pqp_resync_separates_an_answered_query_from_the_next_job() {
        // Pre-3.0 drivers close a query with neither a PAP eof nor a %%EOF, so once
        // the print job's header arrives everything before it is spent. Without this
        // the buffer still reads as a query and the print job is silently dropped.
        let answered = LW7_PROCSET_QUERY.len();
        let mut buf = LW7_PROCSET_QUERY.to_vec();
        buf.extend_from_slice(b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r");
        assert_eq!(pqp_resync(&buf, answered), answered);
        assert_eq!(pqp_query_style(&buf[answered..]), None, "what is left is a print job");

        // A header-less continuation of the same query is not a new job: keep it, and
        // keep the header in front of it that says what it is.
        let mut more = LW7_PROCSET_QUERY.to_vec();
        more.extend_from_slice(b"%%?BeginFeatureQuery: *LanguageLevel\r%%?EndFeatureQuery: 1\r");
        assert_eq!(pqp_resync(&more, answered), 0);
        assert_eq!(pqp_query_style(&more), Some(QueryStyle::Legacy));

        // Answered to the last byte with nothing new behind it: the buffer is spent.
        assert_eq!(pqp_resync(LW7_PROCSET_QUERY, answered), answered);
    }

    #[test]
    fn pqp_answerable_prefix_waits_for_a_closed_block() {
        // Nothing to answer until the End comment lands.
        let open = &LW7_PROCSET_QUERY[..LW7_PROCSET_QUERY.len() - 30];
        assert_eq!(pqp_answerable_prefix(open), None);

        // Once it does, the whole block is consumable and nothing is left over.
        assert_eq!(pqp_answerable_prefix(LW7_PROCSET_QUERY), Some(LW7_PROCSET_QUERY.len()));

        // A second block half-arrived: answer the first, keep the rest buffered.
        let mut two = LW7_PROCSET_QUERY.to_vec();
        two.extend_from_slice(b"%%?BeginFeatureQuery: *LanguageLevel\r");
        assert_eq!(pqp_answerable_prefix(&two), Some(LW7_PROCSET_QUERY.len()));

        // Both blocks and the trailing %%EOF go in one pass, so no scrap of the job
        // is left behind to be mistaken for the start of the next one.
        assert_eq!(pqp_answerable_prefix(LW7_PRINTER_QUERY), Some(LW7_PRINTER_QUERY.len()));
        assert!(job_ends_at_eof(LW7_PRINTER_QUERY), "the %%EOF goes with the block");
        assert!(!job_ends_at_eof(LW7_PROCSET_QUERY));
    }

    #[test]
    fn stdout_serves_one_write_per_response() {
        let mut stdout = PrinterStdout::default();
        stdout.queue(vec![b"Times-Roman\n".to_vec(), b"*\n".to_vec()]);

        // Two writes, two responses, however much room the reader offers: a driver
        // reading a font list counts packets, not bytes.
        assert_eq!(stdout.next_chunk(512), (b"Times-Roman\n".to_vec(), false));
        assert_eq!(stdout.next_chunk(512), (b"*\n".to_vec(), true));
        // Drained, and an extra read is answered with a final empty response rather
        // than anything left over.
        assert_eq!(stdout.next_chunk(512), (Vec::new(), true));
    }

    #[test]
    fn stdout_splits_a_write_too_big_for_one_response() {
        let mut stdout = PrinterStdout::default();
        stdout.queue(vec![vec![b'x'; 5], b"tail".to_vec()]);

        // Not the last response: the rest of the write is still to come.
        assert_eq!(stdout.next_chunk(2), (vec![b'x'; 2], false));
        assert_eq!(stdout.next_chunk(2), (vec![b'x'; 2], false));
        assert_eq!(stdout.next_chunk(2), (vec![b'x'; 1], false));
        assert_eq!(stdout.next_chunk(2), (b"ta".to_vec(), false));
        assert_eq!(stdout.next_chunk(2), (b"il".to_vec(), true));
    }

    #[test]
    fn stdout_with_nothing_queued_answers_a_print_job() {
        // A print job produces no output, and the driver still gets one response
        // with eof to say the job is done.
        assert_eq!(PrinterStdout::default().next_chunk(512), (Vec::new(), true));
    }

    #[test]
    fn job_buffer_keeps_answered_text_and_drops_spent_text() {
        let mut job = JobBuffer::default();
        job.push(b"statusdict/jobname(Doc)put\r");
        job.push(LW7_PROCSET_QUERY);
        // The prologue went, so the header is at the front where it identifies the job.
        assert_eq!(job.as_slice(), LW7_PROCSET_QUERY);

        let end = pqp_answerable_prefix(job.unanswered()).unwrap();
        job.mark_answered(end);
        assert!(job.unanswered().is_empty(), "nothing left to answer");
        assert_eq!(
            pqp_query_style(job.as_slice()),
            Some(QueryStyle::Legacy),
            "the answered text stays, so the buffer still knows what it is"
        );

        // The print job that follows displaces the query it followed.
        job.push(b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r");
        assert_eq!(job.as_slice(), b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r");
        let (data, answered) = job.take();
        assert_eq!(answered, 0, "none of the print job has been answered");
        assert_eq!(data, b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r");
        assert!(job.is_empty());
    }

    #[test]
    fn job_ends_at_eof_separates_whole_jobs_from_truncated_ones() {
        assert!(job_ends_at_eof(b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r"));
        // Some drivers pad the trailer with ^D and blank lines.
        assert!(job_ends_at_eof(b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r\x04"));
        // Cut off mid-job: printing this would waste a page.
        assert!(!job_ends_at_eof(b"%!PS-Adobe-3.0\rshowpage\r"));
        assert!(!job_ends_at_eof(b"%%EOF is not a trailer here"));
        assert!(!job_ends_at_eof(b""));
    }
}
