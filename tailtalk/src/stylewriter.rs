use crate::{
    adsp::{Adsp, AdspAddress, AdspStream},
    ddp::DdpHandle,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Native printable width / row-byte-count for the Color StyleWriter 2200
/// (lpstyl `printerSetup()` for KIND_SW2200).
pub const SW2200_PRINT_WIDTH: usize = 2919;
pub const SW2200_PRINT_ROWBYTES: usize = SW2200_PRINT_WIDTH.div_ceil(8); // 365

/// Max compressed bytes in one rect+G band.
///
/// The printer's raster buffer holds 0x8000 bytes (lpstyl's `MAX_BUFFER` for
/// the CS family). Hand it a block that size or larger and it stalls with
/// 'B' = 0x00 and ejects a blank page — we saw this with a 32863-byte block —
/// so a band has to stay under 0x8000. We cap well under it, at 8 KB, to match
/// the native Mac driver, whose bands never run much larger. Dense pages just
/// split into more bands; sparse ones hit the row cap first (see
/// [`MAX_BAND_ROWS`]).
///
/// A band also has to cover many rows. One block per row is byte-correct but
/// never actually prints.
pub const MAX_BATCH_BYTES: usize = 0x2000;

/// Max scanlines in one rect+G band.
///
/// [`MAX_BATCH_BYTES`] only limits the compressed size. The native Mac driver
/// also caps mono bands at 400 rows, so we do the same.
pub const MAX_BAND_ROWS: usize = 400;

// SW2200 is idle when 'B' has both 0x80 and 0x20 set: 0xA2 (no paper) and
// 0xA3 (paper loaded) are the observed idle values; mid-page 'B' is a
// buffer-drain gauge that climbs through values like 0x23/0x25 while a band
// drains. Testing bit 0x20 alone matches those transient gauge values,
// releasing the next band before the previous one has fully drained and
// wedging the printer (B=0x00). lpstyl only waits for 0xA3; the mask here
// also accepts 0xA2 since the low bits vary with paper presence.
const SW2200_IDLE_MASK: u8 = 0xA0;

/// Real inkjet mechanics (paper feed motor, ink deposition) can report an
/// idle-looking status bit before they've actually finished moving — confirmed
/// by observing the eject command fire while paper was visibly still being
/// pulled in. A short fixed settle delay avoids racing ahead of the hardware.
const MECHANISM_SETTLE_DELAY: Duration = Duration::from_secs(3);

/// The printer answered the 0x000b print request with a "busy" result:
/// another host holds the print connection. Retry later. Carried inside the
/// `anyhow::Error` returned by [`StyleWriterSession::connect`] so callers can
/// distinguish "queue behind someone else" from a hard failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrinterBusy(pub u16);

impl std::fmt::Display for PrinterBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Printer busy (result 0x{:04X}); retry later", self.0)
    }
}

impl std::error::Error for PrinterBusy {}

/// Print quality selector, mapped onto the mode string sent during `setup()`.
///
/// Verified against real SW2200 captures: mono-normal is `"m2nZAH"` and colour
/// is `"m2sAH"`. A native Mac driver capture shows Best-quality sends
/// byte-identical raster to Normal — the printer just runs more/slower passes —
/// so Best only flips the quality character in the mode string, not the raster.
///
/// Mode-string grammar: `m2 <n|s> [Z] A <B|H>`. `n`=normal / `s`=superior
/// (best), `Z` marks the mono/K path, and the final letter is head direction:
/// `H`=unidirectional (ink only on the left→right pass), `B`=bidirectional
/// (ink both ways, with the right→left rows reversed pixel-wise). We always
/// use `H`, so no row reversal is needed. Mono-best `"m2sZAH"` is derived from
/// this grammar and not yet hardware-confirmed; mono-normal and colour are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintQuality {
    #[default]
    Normal,
    Best,
}

/// Identity of the attached printer, gathered by [`StyleWriterSession::query_info`].
#[derive(Debug, Clone)]
pub struct StyleWriterInfo {
    /// Raw reply to the `?` identify command ("IJ10", "SW", "SW3", "CS", …).
    pub identity: String,
    /// CS-family submodel from status query 'p' (0x01=2400, 0x02=2200,
    /// 0x04=1500, 0x05=2500); `None` for non-CS printers or no reply.
    pub submodel: Option<u8>,
    /// Status 'H' bit 0x80: a color ink cartridge is installed.
    pub color_cartridge: bool,
}

impl StyleWriterInfo {
    /// Human-readable model name (lpstyl's identify tables).
    pub fn model_name(&self) -> &'static str {
        match self.identity.as_str() {
            "IJ10" => "Apple StyleWriter",
            "SW" => "Apple StyleWriter II",
            "SW3" => "Apple StyleWriter 1200",
            "CS" => match self.submodel {
                Some(0x01) => "Apple Color StyleWriter 2400",
                Some(0x02) => "Apple Color StyleWriter 2200",
                Some(0x04) => "Apple Color StyleWriter 1500",
                Some(0x05) => "Apple Color StyleWriter 2500",
                _ => "Apple Color StyleWriter",
            },
            _ => "Apple StyleWriter",
        }
    }

    /// CS-family printers are the only ones that can print color at all
    /// (and only with a color cartridge installed).
    pub fn color_capable(&self) -> bool {
        self.identity == "CS" && self.color_cartridge
    }
}

/// Build the attention payload for the 0x000b print-request message
/// (lpstyl §at_printer_open): `struct printRequest { u_int32_t port; char string[66]; }`.
fn build_print_request(socket_num: u8, username: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(70);
    payload.extend_from_slice(&(socket_num as u32).to_be_bytes());
    let name = username.as_bytes();
    let name_len = name.len().min(64);
    payload.push(name_len as u8);
    payload.extend_from_slice(&name[..name_len]);
    payload.resize(70, 0);
    payload
}

/// Write bytes and flush immediately — `AdspStream::poll_write` only buffers
/// into an internal write_buf; nothing reaches the wire until flushed.
async fn write_flush(data: &mut AdspStream, bytes: &[u8]) -> anyhow::Result<()> {
    data.write_all(bytes).await?;
    data.flush().await?;
    Ok(())
}

/// A live ADSP connection to a StyleWriter printer, past the initial
/// two-connection handshake and ready for `setup()` / `write_batch()` / `finish()`.
///
/// Protocol notes (reverse-engineered from a real Mac OS driver capture, since
/// this goes further than lpstyl's own reimplementation covers):
/// - `setup()` sends the minimal sequence that reliably triggers paper feed.
///   lpstyl-style extras ('I' reset, '?' identify, 'p' submodel, and two
///   further writes the printer never acknowledges) actively regressed paper
///   feed in testing — likely because 'I' resets the printer into a state
///   that expects those follow-ups to complete, and they never do.
/// - Raster data must be batched (`write_batch`) as one rect+G block spanning
///   many rows, not one block per row — the latter looked byte-correct but
///   the printer silently never printed anything.
/// - Both colour ('c'/"m2sAH") and mono ('R'/"m2nZAH") scanlines are XOR-delta
///   encoded against the previous row, restarting from absolute at each rect+G
///   block. The printer XOR-reconstructs each row, so a non-delta'd row prints
///   as cumulative-XOR noise. See `encode_page_batches`.
/// - `finish()`'s teardown replicates lpstyl's `at_printer_kill(), whose own
///   comment warns: "If you don't get it just right, after the disconnect
///   the printer tries to open a new connection to the original control
///   socket" — confirmed by observation when this was skipped.
pub struct StyleWriterSession {
    data: AdspStream,
}

impl StyleWriterSession {
    /// Perform the two-connection StyleWriter ADSP handshake (lpstyl
    /// `at_printer_open`): connect to the printer's control socket, send the
    /// ATTN 0x000b print request, close the control connection on success,
    /// then accept the printer's reverse connection on our data socket.
    pub async fn connect(
        ddp: &DdpHandle,
        printer_addr: AdspAddress,
        username: &str,
    ) -> anyhow::Result<Self> {
        let (data_socket_num, mut data_listener) = Adsp::bind(ddp, None).await?;

        let mut ctrl = Adsp::connect(ddp, printer_addr).await?;
        let req_payload = build_print_request(data_socket_num, username);
        ctrl.send_attention(0x000b, &req_payload).await?;

        let mut result_buf = [0u8; 2];
        ctrl.read_exact(&mut result_buf).await?;
        let result = u16::from_be_bytes(result_buf);
        match result {
            0 => ctrl.close().await?,
            0xFFFF => anyhow::bail!("Printer rejected the print request (0xFFFF)"),
            _ => return Err(anyhow::Error::new(PrinterBusy(result))),
        }

        let data = data_listener.accept().await?;
        Ok(Self { data })
    }

    /// Discard bytes already buffered from the printer. `poll_status`
    /// re-sends its query after a timeout, so a merely-late reply would
    /// otherwise answer the *next* query instead — permanently off by one.
    async fn drain_stale_input(&mut self) {
        let mut buf = [0u8; 16];
        while let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(5), self.data.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            tracing::debug!("discarded {} stale printer reply byte(s)", n);
        }
    }

    /// Send a single `\xFF\xFF\xFF<query>` status request and read the 1-byte
    /// reply. Returns `None` on a fatal write/read error (caller should give
    /// up); a read timeout is treated as "not ready yet" and retried,
    /// matching lpstyl's `comm_printer_getc_block()` / `waitStatus()`.
    async fn poll_status(&mut self, query: u8, deadline: tokio::time::Instant) -> Option<u8> {
        loop {
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            self.drain_stale_input().await;
            if write_flush(&mut self.data, &[0xFF, 0xFF, 0xFF, query]).await.is_err() {
                return None;
            }
            let mut s = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(5), self.data.read_exact(&mut s)).await {
                Ok(Ok(_)) => return Some(s[0]),
                Ok(Err(_)) => return None,
                Err(_) => {} // no reply yet, retry
            }
        }
    }

    /// Identify the attached printer and its cartridge without starting a
    /// page (no 'L' is sent, so no paper feeds). Mirrors lpstyl's
    /// `printerSetup()` identify path: write `?`, read the CR-terminated
    /// identity string, then for CS-family printers query submodel ('p') and
    /// cartridge ('D' + 'H').
    ///
    /// Intended for a dedicated capability-probe session: connect, call
    /// this, then `abort()` (whose 'I' reset is a no-op with no page loaded).
    pub async fn query_info(&mut self) -> anyhow::Result<StyleWriterInfo> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);

        self.drain_stale_input().await;
        write_flush(&mut self.data, b"?").await?;
        let mut identity = Vec::new();
        loop {
            let mut b = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(5), self.data.read_exact(&mut b)).await {
                Ok(Ok(_)) if b[0] == 0x0D => break,
                Ok(Ok(_)) if identity.len() < 32 => identity.push(b[0]),
                Ok(Ok(_)) => break,
                Ok(Err(e)) => return Err(e.into()),
                // lpstyl's identify reply is CR-terminated, but tolerate a
                // printer that stops without the CR.
                Err(_) if !identity.is_empty() => break,
                Err(_) => anyhow::bail!("No reply to printer identify query '?'"),
            }
        }
        let identity = String::from_utf8_lossy(&identity).trim().to_string();

        let submodel = if identity == "CS" {
            self.poll_status(b'p', deadline).await
        } else {
            None
        };

        // 'D' then 'H' is lpstyl's cartridge probe; non-CS printers have no
        // color cartridge to report, so skip the query (and its 'D') there.
        let color_cartridge = if identity == "CS" {
            write_flush(&mut self.data, b"D").await?;
            let h = self
                .poll_status(b'H', deadline)
                .await
                .ok_or_else(|| anyhow::anyhow!("No reply to cartridge query 'H'"))?;
            h & 0x80 != 0
        } else {
            false
        };

        Ok(StyleWriterInfo { identity, submodel, color_cartridge })
    }

    /// Poll until status 'B' reports idle (lpstyl `waitStatus()`/`waitNonBusy()`),
    /// polling '1'/'2'/'B' each round. Used before raster data and after the
    /// form feed, since a full page (paper pull + print + eject) can take
    /// well over a minute.
    ///
    /// '2' == 0x04 (out of paper) gets lpstyl's retry handling: send
    /// `FF FF FF 'S'` and keep waiting. Other non-0x00/0x80 values are only
    /// logged, since the full set of benign codes on this adapter isn't known.
    pub async fn wait_ready(&mut self) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        let mut last = None;
        loop {
            let (Some(c1), Some(c2), Some(cb)) = (
                self.poll_status(b'1', deadline).await,
                self.poll_status(b'2', deadline).await,
                self.poll_status(b'B', deadline).await,
            ) else {
                match last {
                    Some((c1, c2, cb)) => anyhow::bail!(
                        "Printer did not become ready in time (last status: 1=0x{c1:02X} 2=0x{c2:02X} B=0x{cb:02X})"
                    ),
                    None => anyhow::bail!("No reply to printer status queries"),
                }
            };
            last = Some((c1, c2, cb));
            if c2 == 0x04 {
                tracing::warn!("Printer is out of paper; sending retry ('S') and waiting...");
                write_flush(&mut self.data, &[0xFF, 0xFF, 0xFF, b'S']).await?;
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            if c2 != 0x00 && c2 != 0x80 {
                tracing::warn!(
                    "Unexpected printer error status: 2=0x{c2:02X} (1=0x{c1:02X} B=0x{cb:02X})"
                );
            }
            if cb & SW2200_IDLE_MASK == SW2200_IDLE_MASK {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // lpstyl's AppleTalk waitNonBusy() follows the idle wait with two
        // ADSP attention 0x0006 "buffer ready" queries, each answered by two
        // in-band bytes (0xFFFF per a native Mac driver capture); the native
        // driver sends the same pairs before each band. A missing reply is
        // non-fatal, and a late reply is harmless too: drain_stale_input
        // discards it before the next status poll, so it can't desync the
        // query/reply pairing.
        for _ in 0..2 {
            self.data.send_attention(0x0006, &[0x00]).await?;
            let mut reply = [0u8; 2];
            if tokio::time::timeout(Duration::from_secs(3), self.data.read_exact(&mut reply))
                .await
                .is_err()
            {
                tracing::debug!("no reply to buffer-ready attention 0x0006");
                break; // don't stack a second unanswered query
            }
        }
        Ok(())
    }

    /// Minimal setup that reliably triggers paper feed: 'D', cartridge query
    /// 'H', quality string, 'L' (page start), then wait for paper feed to
    /// settle and the printer to report idle.
    ///
    /// `color` and `quality` select the mode string: mono-normal `"m2nZAH"`,
    /// mono-best `"m2sZAH"`, colour `"m2sAH"` (colour ignores quality). Its tag
    /// must match the raster tag ('R' for mono, 'c' for colour) or the printer
    /// misreconstructs every row. See [`PrintQuality`] for the grammar.
    pub async fn setup(&mut self, color: bool, quality: PrintQuality) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);

        write_flush(&mut self.data, b"D").await?;
        self.poll_status(b'B', deadline).await;

        // 'H' reports the installed cartridge: bit 0x80 set = color (lpstyl
        // `printerSetup()`). A color job with a black cartridge would be
        // silently accepted and misprinted, so fail it up front. Mono jobs
        // print fine with either cartridge.
        let cartridge = self.poll_status(b'H', deadline).await;
        if color {
            let h = cartridge
                .ok_or_else(|| anyhow::anyhow!("No reply to cartridge query 'H'"))?;
            anyhow::ensure!(
                h & 0x80 != 0,
                "Color job, but a black ink cartridge is installed (H=0x{h:02X})"
            );
        }

        // Only the mode string changes between normal and best; the raster is
        // byte-identical (per a native Mac driver capture), the printer just
        // runs more passes. See [`PrintQuality`] for the grammar.
        let mode_string: &[u8] = match (color, quality) {
            (true, _) => b"m2sAH",                       // colour (verified)
            (false, PrintQuality::Best) => b"m2sZAH",    // mono best (derived, HW-unverified)
            (false, PrintQuality::Normal) => b"m2nZAH",  // mono normal (verified)
        };
        write_flush(&mut self.data, mode_string).await?;
        write_flush(&mut self.data, b"L").await?;

        tokio::time::sleep(MECHANISM_SETTLE_DELAY).await;

        self.wait_ready()
            .await
            .map_err(|e| e.context("waiting for printer to become ready after page start"))
    }

    /// Send one rect+G batch spanning rows `top..=bottom`. The rect's bottom
    /// coordinate is *inclusive* (confirmed against lpstyl and real driver
    /// captures), so `encoded_planes` must hold exactly `bottom - top + 1`
    /// rows' worth of already-RLE-encoded plane(s) — claiming more rows than
    /// supplied leaves the printer waiting for the missing scanlines.
    ///
    /// Does a light paper/error check between bands (like the native driver)
    /// but does NOT wait for full idle. Flow control is the ADSP receive
    /// window: `flush()` blocks until the whole band has been accepted into the
    /// printer's buffer, and the printer advertises a shrinking window (down to
    /// 0) as its buffer fills, so we can never overflow it. The native driver
    /// streams bands back-to-back the same way; with bands capped well under
    /// the buffer ([`MAX_BATCH_BYTES`]) it always has several buffered ahead.
    pub async fn write_batch(
        &mut self,
        top: u16,
        bottom: u16,
        encoded_planes: &[u8],
        color: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            encoded_planes.len() < MAX_BATCH_BYTES,
            "G block of {} bytes would overflow the printer's {} byte buffer and stall it",
            encoded_planes.len(),
            MAX_BATCH_BYTES
        );
        self.check_paper()
            .await
            .map_err(|e| e.context("checking printer status before raster block"))?;
        let rect = StyleWriterEncoder::encode_rect(top, 0, bottom, SW2200_PRINT_WIDTH as u16, color);
        let g_block = StyleWriterEncoder::wrap_raster_chunk(encoded_planes);
        self.data.write_all(&rect).await?;
        self.data.write_all(&g_block).await?;
        self.data.flush().await?;
        Ok(())
    }

    /// Light between-band status check matching the real driver, which polls
    /// '1' and '2' once each and moves straight on — no wait for idle. '2' ==
    /// 0x04 means out of paper: send the `S` retry and wait, as
    /// [`Self::wait_ready`] does. Everything else proceeds immediately; the
    /// ADSP window (not a status poll) paces delivery to the printer's drain
    /// rate.
    async fn check_paper(&mut self) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        loop {
            let _c1 = self.poll_status(b'1', deadline).await;
            match self.poll_status(b'2', deadline).await {
                Some(0x04) => {
                    tracing::warn!("Printer is out of paper; sending retry ('S') and waiting...");
                    write_flush(&mut self.data, &[0xFF, 0xFF, 0xFF, b'S']).await?;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Some(c2) if c2 != 0x00 && c2 != 0x80 => {
                    tracing::warn!("Unexpected printer error status 2=0x{c2:02X}");
                    return Ok(());
                }
                _ => return Ok(()),
            }
        }
    }

    /// Finish the page: wait for the last raster batch to fully drain, form
    /// feed, wait for the print engine to settle and report idle, send the
    /// real eject trigger (`"El"` — present in every real driver capture but
    /// commented out as "may not be necessary" in lpstyl), then tear down
    /// the connection.
    ///
    /// The pre-form-feed wait matters: `write_batch` only confirms drain
    /// *before* the next batch, so without it here the form feed could fire
    /// while the last band is still printing, cutting off the bottom of the
    /// page. lpstyl calls `waitNonBusy(0)` right before its form-feed/eject
    /// sequence for the same reason.
    pub async fn finish(mut self) -> anyhow::Result<()> {
        self.wait_ready()
            .await
            .map_err(|e| e.context("waiting for last raster batch to drain before form feed"))?;

        self.data.write_all(b"\x0C").await?;
        self.data.write_eom().await?;

        tokio::time::sleep(MECHANISM_SETTLE_DELAY).await;
        if let Err(e) = self.wait_ready().await {
            // Still worth ejecting and closing cleanly; 'El'/'I' below force it.
            tracing::warn!("Printer not idle after form feed ({e}); ejecting anyway");
        }

        write_flush(&mut self.data, b"El").await?;
        self.teardown().await
    }

    /// Abort mid-page: skip the form-feed/'El' finish sequence and go
    /// straight to the teardown, whose `FF FF FF 'I'` ejects any loaded page
    /// and resets the printer (lpstyl's `ejectAndReset()` is exactly that
    /// code). Without this, a failed job leaves paper sitting in the feed
    /// path until the next job's 'L'.
    pub async fn abort(self) -> anyhow::Result<()> {
        self.teardown().await
    }

    /// lpstyl's `at_printer_kill()` sequence (null byte, 'I' eject/reset,
    /// ATTN 0x0012, read reply), minus adsp_fwd_reset (not implemented in
    /// our ADSP stack) and the non-blocking input drain (defensive only) —
    /// skipping this teardown causes the printer to repeatedly try to
    /// reopen a connection to us after we disconnect.
    async fn teardown(mut self) -> anyhow::Result<()> {
        self.data.write_all(&[0x00]).await?;
        self.data.flush().await?;
        write_flush(&mut self.data, &[0xFF, 0xFF, 0xFF, b'I']).await?;
        self.data.send_attention(0x0012, &[0x00]).await?;
        let mut kill_reply = [0u8; 2];
        let _ = tokio::time::timeout(Duration::from_secs(5), self.data.read_exact(&mut kill_reply)).await;

        self.data.close().await?;
        Ok(())
    }
}

/// One rect+G raster band covering scanlines `top..=bottom`, ready for
/// [`StyleWriterSession::write_batch`].
#[derive(Debug, Clone)]
pub struct RasterBatch {
    pub top: u16,
    pub bottom: u16,
    /// Concatenated RLE-encoded plane data for every row in the band.
    pub data: Vec<u8>,
}

/// Unpack one chunky (4bpp, nibble bits 8=C 4=M 2=Y 1=K) scanline into raw
/// (pre-RLE) CMYK planar bytes.
pub fn chunky_to_planes(chunky: &[u8], planar_input_len: usize) -> [Vec<u8>; 4] {
    let mut planes = [
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
    ];

    for chunk_block in chunky.chunks(4) {
        let mut c = 0u8;
        let mut m = 0u8;
        let mut y = 0u8;
        let mut k = 0u8;
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            c = (c << 2) | ((b >> 6) & 2) | ((b >> 3) & 1);
            m = (m << 2) | ((b >> 5) & 2) | ((b >> 2) & 1);
            y = (y << 2) | ((b >> 4) & 2) | ((b >> 1) & 1);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        planes[0].push(c);
        planes[1].push(m);
        planes[2].push(y);
        planes[3].push(k);
    }
    planes
}

/// Unpack one chunky scanline's K-nibble bit only into a raw (pre-RLE) plane.
pub fn chunky_to_mono_plane(chunky: &[u8], planar_input_len: usize) -> Vec<u8> {
    let mut plane = Vec::with_capacity(planar_input_len);
    for chunk_block in chunky.chunks(4) {
        let mut k = 0u8;
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        plane.push(k);
    }
    plane
}

/// Encode one row's plane(s) into concatenated RLE bytes. `use_delta` XORs
/// each plane against the previous row's raw plane first (lpstyl's
/// `appendEncode()` differencing).
///
/// Delta is not optional: both colour ('c'/"m2sAH") and mono ('R'/"m2nZAH")
/// mode reconstruct each row by XORing against the previous one, so a
/// non-delta'd row prints as cumulative-XOR garbage.
///
/// `use_delta` must be false for the first row of every rect+G block, since
/// the printer's differencing state resets per block. Does not mutate
/// `last` — the caller updates it once per source row, so a row re-encoded
/// after a batch flush still deltas correctly.
fn encode_row(planes: &[Vec<u8>], last: &[Vec<u8>], use_delta: bool, mono: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, plane) in planes.iter().enumerate() {
        let delta;
        let src = if use_delta {
            delta = plane.iter().zip(last[i].iter()).map(|(c, l)| c ^ l).collect::<Vec<u8>>();
            &delta
        } else {
            plane
        };
        // Whether a blank row can collapse to a single 0x80 ("rest of the row
        // is white") depends on the path, matching the native Mac driver:
        //  - mono 'R': yes. The driver encodes almost all of its white rows
        //    that way, so we do too.
        //  - colour 'c': yes for C/M/Y, but not the K plane (index 3), which
        //    the driver always spells out even when it's blank.
        let allow_shortcut = mono || i != 3;
        out.extend_from_slice(&StyleWriterEncoder::encode_scanline(src, SW2200_PRINT_ROWBYTES, allow_shortcut));
    }
    out
}

/// Encode a whole page of raw planar scanlines into rect+G bands.
///
/// `rows` holds one entry per scanline: 4 CMYK planes for color, 1 K plane
/// for mono (all planes the same length, at most [`SW2200_PRINT_ROWBYTES`];
/// shorter planes are padded to the printable width with white). Handles the
/// XOR-delta chain (restarting it at each band boundary, where the printer's
/// differencing state resets) and splits bands so each stays strictly below
/// [`MAX_BATCH_BYTES`].
pub fn encode_page_batches(rows: &[Vec<Vec<u8>>], mono: bool) -> Vec<RasterBatch> {
    let mut batches = Vec::new();
    let plane_len = rows.first().map(|planes| planes[0].len()).unwrap_or(0);
    let num_planes = if mono { 1 } else { 4 };
    let mut batch_start = 0usize;
    let mut batch_data = Vec::new();
    let mut last_planes = vec![vec![0u8; plane_len]; num_planes];
    for (row_idx, planes) in rows.iter().enumerate() {
        // The first row of every band is absolute; the rest delta against the
        // previous row (the printer resets its differencing state per band).
        let mut row_enc = encode_row(planes, &last_planes, !batch_data.is_empty(), mono);
        // Flush before this row would cross *either* printer limit: the
        // compressed G block must stay strictly below MAX_BATCH_BYTES, and
        // the band must stay within MAX_BAND_ROWS scanlines (compressible
        // mono pages hit the row cap long before the byte cap).
        let rows_in_band = row_idx - batch_start;
        let over_compressed = batch_data.len() + row_enc.len() >= MAX_BATCH_BYTES;
        let over_rows = rows_in_band + 1 > MAX_BAND_ROWS;
        if !batch_data.is_empty() && (over_compressed || over_rows) {
            batches.push(RasterBatch {
                top: batch_start as u16,
                bottom: (row_idx - 1) as u16,
                data: std::mem::take(&mut batch_data),
            });
            batch_start = row_idx;
            // This row now starts a new band, so re-encode it absolute.
            row_enc = encode_row(planes, &last_planes, false, mono);
        }
        batch_data.extend_from_slice(&row_enc);
        last_planes = planes.clone();
        if row_idx + 1 == rows.len() {
            batches.push(RasterBatch {
                top: batch_start as u16,
                bottom: row_idx as u16,
                data: batch_data,
            });
            break;
        }
    }
    batches
}

pub struct StyleWriterEncoder;

// StyleWriter Encoding Protocol Constants
pub const MAX_RUN: u8 = 0x3E;
pub const MAX_BLOCK: u8 = 0x3E;
pub const RUN_THRESH: u8 = 0x01;
pub const DATA_WHITE: u8 = 0x00;
pub const DATA_BLACK: u8 = 0xFF;
pub const MASK_RUNWHT: u8 = 0x80;
pub const MASK_RUNBLK: u8 = 0xC0;

impl StyleWriterEncoder {
    /// Create the bounding-box header (`R` for monochrome, `c` for color)
    /// that precedes each `G` raster block: tag byte, then little-endian
    /// left, top, right, bottom. Both `'R'` and `'c'` rects are 9 bytes, with
    /// the `G` block immediately after (verified against real Mac driver
    /// captures).
    pub fn encode_rect(top: u16, left: u16, bottom: u16, right: u16, is_color: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        if is_color {
            buf.push(b'c');
        } else {
            buf.push(b'R');
        }
        buf.extend_from_slice(&left.to_le_bytes());
        buf.extend_from_slice(&top.to_le_bytes());
        buf.extend_from_slice(&right.to_le_bytes());
        buf.extend_from_slice(&bottom.to_le_bytes());
        buf
    }

    /// Prepend the Apple `'G'` 2-byte chunk sizes to an encoded RLE block.
    /// The size field is u16, and anything at or above `MAX_BATCH_BYTES`
    /// stalls the printer anyway (`write_batch` enforces the latter).
    pub fn wrap_raster_chunk(encoded_data: &[u8]) -> Vec<u8> {
        debug_assert!(
            encoded_data.len() <= u16::MAX as usize,
            "G block length {} overflows the u16 size field",
            encoded_data.len()
        );
        let size = encoded_data.len() as u16;
        let mut buf = Vec::with_capacity(4 + size as usize);
        buf.push(b'G');
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(encoded_data);
        buf.push(0x00); // Null terminator required for G blocks
        buf
    }

    /// Encode a single raw bitmap scanline into the proprietary Apple RLE format
    /// Ported directly from lpstyl.c `encodescanline()`.
    ///
    /// `allow_blank_shortcut` controls the single-byte "entire plane is blank"
    /// special case: real color captures never use it for the K plane, even
    /// when blank, only for C/M/Y. Pass `false` for K/monochrome, `true` for
    /// C/M/Y.
    pub fn encode_scanline(src: &[u8], print_width_bytes: usize, allow_blank_shortcut: bool) -> Vec<u8> {
        let mut dst = Vec::with_capacity(src.len());

        // SPECIAL CASE: Check for a completely blank line
        if allow_blank_shortcut && src.iter().all(|&b| b == DATA_WHITE) {
            dst.push(MASK_RUNWHT);
            return dst;
        }

        let mut s = 0;
        let src_len = src.len();

        while s < src_len {
            let mut run_start = 0;
            let mut run_len = 0;
            let mut run_char = 0x0A; // DATA_OTHER (just not black or white)

            // Find the first run
            let mut found_break = false;
            let mut i = s;
            while i < src_len {
                if run_char == DATA_WHITE || run_char == DATA_BLACK {
                    if src[i] != run_char {
                        // This run is over
                        if (i - run_start) >= RUN_THRESH as usize {
                            // Run was long enough to count. Break out.
                            found_break = true;
                            break;
                        } else {
                            run_char = 0x0A; // Too short to count.
                        }
                    } else if (i - run_start) >= MAX_RUN as usize {
                        // Enough of a run to encode
                        found_break = true;
                        break;
                    }
                } else {
                    // run_char == DATA_OTHER
                    if src[i] == DATA_WHITE || src[i] == DATA_BLACK {
                        // Start a run
                        run_char = src[i];
                        run_start = i;
                    } else if (i - s) >= MAX_BLOCK as usize {
                        // Block is maximum length
                        found_break = true;
                        break;
                    }
                }
                i += 1;
            }

            if found_break || run_char != 0x0A {
                if run_char != 0x0A {
                    run_len = i - run_start;
                } else {
                    run_start = i;
                }
            } else {
                run_start = i;
            }

            if run_start != s {
                // Encode a run of random data
                dst.push((run_start - s) as u8);
                while s < run_start {
                    dst.push(src[s]);
                    s += 1;
                }
            }

            if run_len > 0 {
                // Encode a run of black or white
                if run_char == DATA_BLACK {
                    dst.push(MASK_RUNBLK + run_len as u8);
                } else if (s + run_len) < src_len {
                    dst.push(MASK_RUNWHT + run_len as u8);
                } else {
                    break; // Let padding handle it
                }
                s += run_len;
            }
        }

        // Pad out to the width of the page with white
        while s < print_width_bytes {
            let mut run_len = print_width_bytes - s;
            if run_len > MAX_RUN as usize {
                run_len = MAX_RUN as usize;
            }
            dst.push(MASK_RUNWHT + run_len as u8);
            s += run_len;
        }

        dst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_rect() {
        // R (0x52) or c (0x63), then little-endian left, top, right, bottom.
        // Both tags produce a 9-byte rect (verified against real Mac driver
        // captures).
        let bw = StyleWriterEncoder::encode_rect(10, 20, 30, 40, false);
        assert_eq!(bw, vec![b'R', 20, 0, 10, 0, 40, 0, 30, 0]);

        let color = StyleWriterEncoder::encode_rect(10, 20, 30, 40, true);
        assert_eq!(color, vec![b'c', 20, 0, 10, 0, 40, 0, 30, 0]);
    }

    #[test]
    fn test_wrap_raster_chunk() {
        let chunk = vec![0xAB, 0xCD, 0xEF];
        let wrapped = StyleWriterEncoder::wrap_raster_chunk(&chunk);

        assert_eq!(wrapped.len(), 7);
        assert_eq!(wrapped[0], b'G');
        assert_eq!(wrapped[1], 0x03); // Length LSB (3 bytes)
        assert_eq!(wrapped[2], 0x00); // Length MSB
        assert_eq!(&wrapped[3..6], &[0xAB, 0xCD, 0xEF]);
        assert_eq!(wrapped.last(), Some(&0x00)); // Null terminator
    }

    #[test]
    fn test_encode_scanline() {
        // Test a pure white line (all 0s)
        let white_line = vec![DATA_WHITE; 100];
        let encoded = StyleWriterEncoder::encode_scanline(&white_line, 100, true);
        assert_eq!(encoded, vec![MASK_RUNWHT]);

        // Test a line padded with white at the end
        let src = vec![DATA_BLACK, DATA_BLACK, DATA_BLACK]; // 3 black pixels
        let encoded = StyleWriterEncoder::encode_scanline(&src, 10, true);
        // Expect: MASK_RUNBLK + 3, MASK_RUNWHT + 7
        assert_eq!(encoded, vec![MASK_RUNBLK + 3, MASK_RUNWHT + 7]);

        // Test random data
        let src = vec![0x11, 0x22, 0x33, DATA_WHITE, DATA_WHITE];
        let encoded = StyleWriterEncoder::encode_scanline(&src, 5, true);
        // Expect: random length 3 | 0x11 | 0x22 | 0x33 | then white pad/run
        assert_eq!(encoded[0], 3); // 3 bytes of raw data
        assert_eq!(&encoded[1..4], &[0x11, 0x22, 0x33]);
        assert_eq!(encoded[4], MASK_RUNWHT + 2); // 2 bytes of white
    }

    #[test]
    fn test_encode_page_batches_bands() {
        // Rows of incompressible data force multiple bands; every band must
        // stay strictly below MAX_BATCH_BYTES and the bands must tile the
        // page contiguously.
        let plane_len = SW2200_PRINT_ROWBYTES;
        let rows: Vec<Vec<Vec<u8>>> = (0..400)
            .map(|r| {
                (0..4)
                    .map(|p| (0..plane_len).map(|i| ((r * 31 + p * 7 + i * 13) % 251) as u8 + 1).collect())
                    .collect()
            })
            .collect();
        let batches = encode_page_batches(&rows, false);
        assert!(batches.len() > 1, "expected multiple bands, got {}", batches.len());
        assert_eq!(batches[0].top, 0);
        assert_eq!(batches.last().unwrap().bottom as usize, rows.len() - 1);
        for pair in batches.windows(2) {
            assert_eq!(pair[1].top, pair[0].bottom + 1, "bands must be contiguous");
        }
        for b in &batches {
            assert!(b.data.len() < MAX_BATCH_BYTES);
            assert!(b.top <= b.bottom);
        }
    }

    #[test]
    fn test_encode_page_batches_row_cap() {
        // A tall, highly-compressible mono page (all white) compresses to a
        // few bytes per row, so the 32 KB *compressed* cap alone would let one
        // band span hundreds of rows — taller than the printer's paper feed
        // tracks, which shears the page (the vertical-streak bug). Every band
        // must stay within MAX_BAND_ROWS scanlines.
        let rows: Vec<Vec<Vec<u8>>> =
            (0..MAX_BAND_ROWS * 3 + 17).map(|_| vec![vec![0u8; SW2200_PRINT_ROWBYTES]]).collect();
        let batches = encode_page_batches(&rows, true);
        assert!(batches.len() >= 4, "row cap must split the page into several bands");
        for b in &batches {
            let band_rows = (b.bottom - b.top + 1) as usize;
            assert!(band_rows <= MAX_BAND_ROWS, "band of {band_rows} rows exceeds MAX_BAND_ROWS");
        }
        // Bands must still tile the page contiguously with no gaps.
        assert_eq!(batches[0].top, 0);
        assert_eq!(batches.last().unwrap().bottom as usize, rows.len() - 1);
        for pair in batches.windows(2) {
            assert_eq!(pair[1].top, pair[0].bottom + 1, "bands must be contiguous");
        }
    }

    #[test]
    fn test_encode_page_batches_mono_single_band() {
        // A small all-white mono page fits in a single band.
        let rows: Vec<Vec<Vec<u8>>> = (0..10).map(|_| vec![vec![0u8; 100]]).collect();
        let batches = encode_page_batches(&rows, true);
        assert_eq!(batches.len(), 1);
        assert_eq!((batches[0].top, batches[0].bottom), (0, 9));
    }

    #[test]
    fn test_encode_scanline_blank_shortcut_disabled() {
        // With the shortcut disabled, an all-white line must be encoded as
        // explicit white runs, not the single MASK_RUNWHT byte — matching
        // how a real color print capture always encodes the K plane.
        let white_line = vec![DATA_WHITE; 100];
        let encoded = StyleWriterEncoder::encode_scanline(&white_line, 100, false);
        assert_ne!(encoded, vec![MASK_RUNWHT]);
        assert_eq!(encoded, vec![MASK_RUNWHT + 62, MASK_RUNWHT + 38]);
    }
}
