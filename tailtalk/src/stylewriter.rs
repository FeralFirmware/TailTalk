use crate::{
    TalkStack,
    adsp::{AdspAddress, AdspStream},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Native printable width / row-byte-count for the Color StyleWriter 2200
/// (lpstyl `printerSetup()` for KIND_SW2200).
pub const SW2200_PRINT_WIDTH: usize = 2919;
pub const SW2200_PRINT_ROWBYTES: usize = SW2200_PRINT_WIDTH.div_ceil(8); // 365

/// The printer's internal raster buffer size (lpstyl `MAX_BUFFER` for the
/// CS family). It holds one whole rect+G block before printing the band, so
/// a block must stay *strictly smaller* than this or the printer stalls with
/// 'B' = 0x00 (buffer full) and ejects blank — confirmed with a 32863-byte
/// block. Callers must flush before a row would cross this limit, carrying
/// it over to the next block (lpstyl does the same).
///
/// A rect+G block must also span many rows, not one block per row — the
/// latter never printed anything despite being byte-correct.
pub const MAX_BATCH_BYTES: usize = 0x8000;

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
/// - Color ('c'/"m2sAH") scanlines must be XOR-delta encoded against the
///   previous row, restarting absolute at each rect+G block; the printer
///   XOR-reconstructs rows, so absolute color rows print as cumulative-XOR
///   noise. Monochrome ('R'/"m2nZAB") scanlines are absolute. See
///   `encode_row` in the adsp-stylewriter example.
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
        stack: &TalkStack,
        printer_addr: AdspAddress,
        username: &str,
    ) -> anyhow::Result<Self> {
        let (data_socket_num, mut data_listener) = stack.listen_adsp(None).await?;

        let mut ctrl = stack.connect_adsp(printer_addr).await?;
        let req_payload = build_print_request(data_socket_num, username);
        ctrl.send_attention(0x000b, &req_payload).await?;

        let mut result_buf = [0u8; 2];
        ctrl.read_exact(&mut result_buf).await?;
        let result = u16::from_be_bytes(result_buf);
        match result {
            0 => ctrl.close().await?,
            0xFFFF => anyhow::bail!("Printer rejected the print request (0xFFFF)"),
            _ => anyhow::bail!("Printer busy (result 0x{:04X}); retry later", result),
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
        // in-band bytes (0xFFFF in a real Mac driver capture); real Mac
        // drivers send the same pairs before each band. A missing reply is
        // non-fatal — and if a reply arrives late, drain_stale_input
        // discards it before the next status poll, so this can no longer
        // desync the query/reply pairing (the likely reason earlier attempts
        // to send this query seemed to get no answer).
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
    /// `color` selects the quality string: monochrome uses `"m2nZAB"`, color
    /// uses `"m2sAH"` (from real driver captures) — the string must match
    /// the raster tag ('R'/'c') or the printer's configured mode disagrees
    /// with the data it's told to expect.
    pub async fn setup(&mut self, color: bool) -> anyhow::Result<()> {
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

        let quality = if color { b"m2sAH".as_slice() } else { b"m2nZAB".as_slice() };
        write_flush(&mut self.data, quality).await?;
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
    /// Waits for a fully-idle 'B' status before sending, since the previous
    /// band must be completely drained first (see `SW2200_IDLE_MASK`).
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
        self.wait_ready()
            .await
            .map_err(|e| e.context("waiting for printer to drain before raster block"))?;
        let rect = StyleWriterEncoder::encode_rect(top, 0, bottom, SW2200_PRINT_WIDTH as u16, color);
        let g_block = StyleWriterEncoder::wrap_raster_chunk(encoded_planes);
        self.data.write_all(&rect).await?;
        self.data.write_all(&g_block).await?;
        self.data.flush().await?;
        Ok(())
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
    /// Create the bounding box header (`R` for monochrome, `c` for color)
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
        // R (0x52) or c (0x63), then little-endian left, top, right, bottom
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
