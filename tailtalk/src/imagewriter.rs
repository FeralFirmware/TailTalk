//! Printing and status queries for the Apple ImageWriter II/LQ LocalTalk
//! Option Card.
//!
//! [`ImageWriter`] is the whole interface: find a printer by NBP name, open a
//! PAP connection to it, read its status, and stream a job.
//!
//! ```no_run
//! # use tailtalk::{TalkStack, imagewriter::ImageWriter};
//! # async fn example(stack: &TalkStack, raster: Vec<u8>) -> anyhow::Result<()> {
//! let mut printer = ImageWriter::connect_named(&stack.ddp, &stack.nbp, "=").await?;
//! if printer.status().await?.out_of_paper() {
//!     anyhow::bail!("load some paper first");
//! }
//! printer.print_bytes(&raster).await?;
//! printer.close().await?;
//! # Ok(())
//! # }
//! ```
//!
//! The card has no PostScript interpreter, so a job is raw ImageWriter command
//! bytes (Ghostscript's `iwhi`/`iwhic` devices produce them), not PostScript.
//!
//! It has no query language of its own either, so everything it will tell us
//! arrives in the reply to a single PAP `SendStatus` call. Where a LaserWriter
//! puts a PostScript status comment, the option card puts a three-byte status
//! buffer: a length byte (always 2) followed by the two `statusBits` bytes.
//! Reading it therefore goes through [`PapClient::get_status_bytes`] rather than
//! the text-oriented `get_status`.
//!
//! Bit assignments. The starting point was the "PAP Status Buffer from an
//! ImageWriter II/LQ LocalTalk Option Card" figure in Apple's PAP
//! documentation, but the hardware does not agree with it, so treat the figure
//! as a hint rather than a specification:
//!
//! ```text
//!  15  14 13 12 11 10 9 8   7    6    5    4     3    2    1    0
//! busy |<--- unused --->| ribbon feed  ?  cover paper jam fault active
//! ```
//!
//! Confirmed against a real ImageWriter II:
//!
//!   * Bit 3 is **paper present**, not the figure's "off line", and it is
//!     asserted when paper is loaded. An empty printer read `0x0080`; loading
//!     paper changed it to `0x0088` and nothing else moved. It therefore reads
//!     the opposite way round to the error bits around it.
//!   * Bit 7 is the colour ribbon, set in both of those readings on a printer
//!     with a colour ribbon fitted.
//!   * Bit 5, which the figure labels paper-out, stayed clear while the printer
//!     was genuinely out of paper. Whatever it is, it is not that.
//!
//! Everything else below is still only the figure's word. Bits 6, 4, 2, 1 and 0
//! were clear in both confirmed readings, consistent with active-high
//! conditions that never fired, but none has been deliberately triggered and
//! checked. [`error_text`](ImageWriterStatus::error_text) reports the
//! unconfirmed ones, so a surprising error there is as likely to be a wrong bit
//! as a real fault.
//!
//! The card sends the low byte first, so the word is assembled little-endian
//! even though AppleTalk is otherwise big-endian. Both confirmed readings put
//! the meaningful bits in the byte that arrives first, which is also why the
//! card's documented glitch reply is "all ones in the low byte".
//!
//! That glitch is occasional and not sticky: the card sometimes answers with
//! every bit of the low byte set, and the call simply has to be repeated.
//! [`StatusHandle::read`] does that; [`ImageWriterStatus::parse`] rejects it.

use crate::atp::{Atp, AtpAddress};
use crate::ddp::DdpHandle;
use crate::nbp::NbpHandle;
use crate::pap::{IMAGEWRITER_CHUNK_SIZE, PapClient, PapStatusHandle};
use anyhow::{Result, anyhow};
use encoding_rs::MACINTOSH;
use tailtalk_packets::nbp::{EntityName, NbpTuple};
use tokio::io::AsyncRead;

/// The NBP type the LocalTalk Option Card registers itself under.
pub const NBP_TYPE: &str = "ImageWriter";

/// `ESC b`, the option card's rename command. See [`rename_command`].
const RENAME_COMMAND: [u8; 2] = [0x1B, 0x62];

/// Longest name the card is given. An NBP object name is at most 32 bytes, and
/// the StyleWriter's rename caps at 31, so this matches that until hardware
/// says otherwise.
pub const MAX_NAME_LEN: usize = 31;

const BUSY: u16 = 1 << 15;
const COLOR_RIBBON: u16 = 1 << 7;
const SHEET_FEEDER: u16 = 1 << 6;
const COVER_OPEN: u16 = 1 << 4;
/// Set while paper is loaded, so this reads the opposite way round to the
/// error bits. See the module note on which bits are confirmed.
const PAPER_PRESENT: u16 = 1 << 3;
const PAPER_JAM: u16 = 1 << 2;
const FAULT: u16 = 1 << 1;
const ACTIVE: u16 = 1 << 0;

const LOW_BYTE: u16 = 0x00FF;

/// How many PAP status calls [`StatusHandle::read`] makes before giving up on
/// the card returning a valid word.
pub const DEFAULT_STATUS_ATTEMPTS: usize = 3;

/// A decoded `statusBits` word from an ImageWriter II/LQ LocalTalk Option Card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageWriterStatus {
    /// The raw word, kept verbatim so callers can inspect the undocumented
    /// bits 8 to 14.
    pub raw: u16,
}

impl ImageWriterStatus {
    /// Decode the status buffer returned by [`PapClient::get_status_bytes`],
    /// i.e. the two `statusBits` bytes with the leading length byte already
    /// stripped. The low byte comes first.
    ///
    /// Fails when the buffer is too short, or when the card returned the
    /// all-ones low byte that marks an invalid reply. Prefer
    /// [`StatusHandle::read`], which retries that case for you.
    pub fn parse(status_buffer: &[u8]) -> Result<Self> {
        let bytes = status_buffer.get(..2).ok_or_else(|| {
            anyhow!(
                "ImageWriter status buffer is {} byte(s), expected 2",
                status_buffer.len()
            )
        })?;
        let raw = u16::from_le_bytes([bytes[0], bytes[1]]);
        if !Self::is_valid(raw) {
            return Err(anyhow!(
                "ImageWriter returned an invalid status word (0x{raw:04X}): \
                 all ones in the low byte means the reply must be repeated"
            ));
        }
        Ok(Self { raw })
    }

    /// False for the card's glitch reply, an all-ones low byte, which makes the
    /// whole word meaningless.
    pub fn is_valid(raw: u16) -> bool {
        raw & LOW_BYTE != LOW_BYTE
    }

    /// The two bytes as they arrived on the wire, low byte first, for showing
    /// an unaltered reading next to the decode.
    pub fn wire_bytes(&self) -> [u8; 2] {
        self.raw.to_le_bytes()
    }

    /// The printer is busy (bit 15), i.e. it already has a PAP connection open.
    pub fn busy(&self) -> bool {
        self.raw & BUSY != 0
    }

    /// A colour ribbon is installed (bit 7). The only capability bit the card
    /// exposes.
    pub fn color_ribbon(&self) -> bool {
        self.raw & COLOR_RIBBON != 0
    }

    /// A cut-sheet feeder is installed (bit 6). Unconfirmed, see the module
    /// note; it only changes the wording of the jam text.
    pub fn sheet_feeder(&self) -> bool {
        self.raw & SHEET_FEEDER != 0
    }

    /// Paper is loaded (bit 3). Confirmed on real hardware: loading paper is
    /// what sets this bit. Note the sense, it is asserted when all is well.
    pub fn paper_present(&self) -> bool {
        self.raw & PAPER_PRESENT != 0
    }

    /// Raw paper-jam bit (bit 2). Unconfirmed, see the module note.
    pub fn paper_jam_bit(&self) -> bool {
        self.raw & PAPER_JAM != 0
    }

    /// The cover is open (bit 4). Unconfirmed, see the module note.
    pub fn cover_open(&self) -> bool {
        self.raw & COVER_OPEN != 0
    }

    /// A general printer fault is asserted (bit 1). Unconfirmed, see the module
    /// note.
    pub fn fault(&self) -> bool {
        self.raw & FAULT != 0
    }

    /// The printer is actively printing, i.e. the head is moving (bit 0).
    pub fn active(&self) -> bool {
        self.raw & ACTIVE != 0
    }

    /// Whether the printer is out of paper, i.e. [`paper_present`] is clear.
    ///
    /// [`paper_present`]: Self::paper_present
    pub fn out_of_paper(&self) -> bool {
        !self.paper_present()
    }

    /// Every error condition the card is reporting, or `None` when it reports
    /// none. Ready-but-busy is not an error and does not appear here.
    pub fn error_text(&self) -> Option<String> {
        let mut errors: Vec<&str> = Vec::new();
        if self.out_of_paper() {
            errors.push("Out of paper");
        }
        if self.paper_jam_bit() {
            errors.push(if self.sheet_feeder() {
                "Paper jam or sheet feeder empty"
            } else {
                "Paper jam"
            });
        }
        if self.cover_open() {
            errors.push("Cover open");
        }
        if self.fault() {
            errors.push("Printer fault");
        }
        (!errors.is_empty()).then(|| errors.join(", "))
    }

    /// Which ribbon is installed, in the same shape as the StyleWriter's
    /// cartridge readout so both printer tools can present it alike.
    pub fn ribbon_text(&self) -> &'static str {
        if self.color_ribbon() {
            "Color"
        } else {
            "Black only"
        }
    }
}

/// A connection to an ImageWriter II/LQ LocalTalk Option Card.
///
/// The card speaks PAP, so this wraps a [`PapClient`] with the pieces specific
/// to the ImageWriter: the chunk size it needs, its packed status word, and the
/// fact that a job is raw command bytes with no interpreter behind it and so no
/// job output to read back.
///
/// Holding one of these holds the printer's single PAP connection open, which
/// every other host sees as the busy bit, so [`close`](Self::close) as soon as
/// the job is done. Status can be read without a connection at all, via
/// [`ImageWriter::status_of`].
///
/// Two ATP sockets are allocated: one carrying the PAP connection, and one for
/// status queries, which keeps polling entirely clear of the job's transactions.
/// See [`StatusHandle`].
pub struct ImageWriter {
    pap: PapClient,
    status: StatusHandle,
    address: AtpAddress,
}

impl ImageWriter {
    /// Find ImageWriters on the network. `object` is an NBP object name, `=`
    /// for any, and the type is always [`NBP_TYPE`].
    pub async fn lookup(nbp: &NbpHandle, object: &str) -> Result<Vec<NbpTuple>> {
        let entity = EntityName {
            object: object.to_string(),
            entity_type: NBP_TYPE.to_string(),
            zone: "*".to_string(),
        };
        Ok(nbp.lookup(entity).await?)
    }

    /// Open a PAP connection to the printer at `address`.
    pub async fn connect(ddp: &DdpHandle, address: AtpAddress) -> Result<Self> {
        let (_, req, resp) = Atp::spawn(ddp, None).await;
        let mut pap = PapClient::new(req, resp);
        pap.connect(address).await?;
        pap.chunk_size = Some(IMAGEWRITER_CHUNK_SIZE);
        let status = StatusHandle::new(ddp, address).await;
        Ok(Self {
            pap,
            status,
            address,
        })
    }

    /// Look an ImageWriter up by NBP object name and connect to the first one
    /// that answers. Pass `=` to take whichever ImageWriter is on the network.
    pub async fn connect_named(ddp: &DdpHandle, nbp: &NbpHandle, object: &str) -> Result<Self> {
        let tuples = Self::lookup(nbp, object).await?;
        let printer = tuples.first().ok_or_else(|| {
            anyhow!("no ImageWriter named '{object}:{NBP_TYPE}@*' on the network")
        })?;
        tracing::info!(
            "ImageWriter: found {} at {}.{} socket {}",
            printer.entity_name,
            printer.network_number,
            printer.node_id,
            printer.socket_number
        );
        Self::connect(ddp, printer.service_address().into()).await
    }

    /// Read the printer's status word without opening a connection, so this
    /// works against a printer that is busy or mid-job. For repeated reads,
    /// keep a [`StatusHandle`] instead: this allocates a socket per call.
    pub async fn status_of(ddp: &DdpHandle, address: AtpAddress) -> Result<ImageWriterStatus> {
        StatusHandle::new(ddp, address).await.read().await
    }

    /// Read the printer's status word over this session's status socket.
    pub async fn status(&self) -> Result<ImageWriterStatus> {
        self.status.read().await
    }

    /// A status reader that borrows nothing from the session, so it can run
    /// while [`print`](Self::print) holds `&mut self`. See [`StatusHandle`].
    pub fn status_handle(&self) -> StatusHandle {
        self.status.clone()
    }

    /// Stream a job to the printer: raw ImageWriter command bytes, as produced
    /// by Ghostscript's `iwhi` (mono) or `iwhic` (colour ribbon) device.
    pub async fn print<R: AsyncRead + Unpin>(&mut self, source: R) -> Result<()> {
        self.pap.print_stream(source).await
    }

    /// [`print`](Self::print) for a job already in memory.
    pub async fn print_bytes(&mut self, data: &[u8]) -> Result<()> {
        self.print(std::io::Cursor::new(data)).await
    }

    /// Rename the printer, which is the one setting the option card holds.
    ///
    /// The new name is what the card registers with NBP, so it is what the
    /// Chooser and [`lookup`](Self::lookup) will show. It survives a power
    /// cycle, and the card re-registers itself, so a lookup shortly afterwards
    /// should find the printer under the new name.
    ///
    /// See [`rename_command`] for the wire format and the caveats on it.
    pub async fn set_name(&mut self, name: &str) -> Result<()> {
        self.print_bytes(&rename_command(name)?).await
    }

    /// The address this connection was opened to.
    pub fn address(&self) -> AtpAddress {
        self.address
    }

    /// Close the PAP connection, releasing the printer for other hosts.
    pub async fn close(mut self) -> Result<()> {
        self.pap.close().await
    }
}

/// Build the option card's rename command: `ESC b` followed by the new name as
/// a MacRoman Pascal string (one length byte, then the bytes).
///
/// `ESC b` is unassigned in the ImageWriter II's own command set (it appears
/// nowhere in the Technical Reference Manual's command summary), which is what
/// leaves it free for the card to claim. The card intercepts it rather than
/// passing it through to the printer, so the command is sent the same way a
/// job is, as PAP data.
///
/// Names are capped at [`MAX_NAME_LEN`] and may not contain the NBP delimiters
/// `:`, `@` or `*`. Characters MacRoman cannot represent are rejected rather
/// than substituted, since a mangled name is one the Chooser will show and we
/// would then have to look up.
pub fn rename_command(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() {
        return Err(anyhow!("printer name cannot be empty"));
    }
    if name.contains([':', '@', '*']) {
        return Err(anyhow!("printer name cannot contain ':', '@', or '*'"));
    }

    let (bytes, _, unmappable) = MACINTOSH.encode(name);
    if unmappable {
        return Err(anyhow!(
            "printer name contains characters MacRoman cannot represent"
        ));
    }
    if bytes.len() > MAX_NAME_LEN {
        return Err(anyhow!(
            "printer name is {} bytes, the maximum is {MAX_NAME_LEN}",
            bytes.len()
        ));
    }

    let mut cmd = Vec::with_capacity(3 + bytes.len());
    cmd.extend_from_slice(&RENAME_COMMAND);
    cmd.push(bytes.len() as u8);
    cmd.extend_from_slice(&bytes);
    Ok(cmd)
}

/// Reads an ImageWriter's status independently of the [`ImageWriter`] session
/// it came from, so a job can be watched while it prints.
///
/// This is [`PapStatusHandle`] (its own ATP socket, no PAP connection, safe to
/// call mid-job) plus the ImageWriter's decode: the packed status word, and the
/// retry that rides out the card's glitch reply.
///
/// Poll gently. Each read is a round trip on a bus the job is already saturating
/// (a few seconds between reads is plenty), and expect
/// [`busy`](ImageWriterStatus::busy) to be set throughout: that is our own
/// connection. The bits worth watching during a job are
/// [`active`](ImageWriterStatus::active) and the error bits.
///
/// ```no_run
/// # use std::time::Duration;
/// # use tailtalk::imagewriter::ImageWriter;
/// # async fn example(printer: &mut ImageWriter, raster: Vec<u8>) -> anyhow::Result<()> {
/// let status = printer.status_handle();
/// let mut ticker = tokio::time::interval(Duration::from_secs(5));
/// ticker.tick().await; // the first tick is immediate
///
/// tokio::select! {
///     result = printer.print_bytes(&raster) => result?,
///     // Never finishes, so the job is always what ends the select.
///     _ = async {
///         loop {
///             ticker.tick().await;
///             match status.read().await {
///                 Ok(s) => println!("printing={} {}", s.active(), s.error_text().unwrap_or_default()),
///                 Err(e) => tracing::warn!("status poll failed: {e}"),
///             }
///         }
///     } => {}
/// }
/// # Ok(())
/// # }
/// ```
///
/// The handle keeps its ATP socket alive for as long as it (or any clone of it)
/// exists, so drop it once you are done watching.
#[derive(Clone)]
pub struct StatusHandle {
    pap: PapStatusHandle,
}

impl From<PapStatusHandle> for StatusHandle {
    /// Add the ImageWriter decode to a status socket that already exists, for
    /// callers polling a printer whose family isn't known until runtime.
    fn from(pap: PapStatusHandle) -> Self {
        Self { pap }
    }
}

impl StatusHandle {
    /// Allocate a status socket for the printer at `address`. No PAP connection
    /// is opened, so this works against a busy printer, and works with no
    /// [`ImageWriter`] session at all.
    pub async fn new(ddp: &DdpHandle, address: AtpAddress) -> Self {
        Self {
            pap: PapStatusHandle::new(ddp, address).await,
        }
    }

    /// Read the status word, retrying the card's glitch reply
    /// [`DEFAULT_STATUS_ATTEMPTS`] times.
    pub async fn read(&self) -> Result<ImageWriterStatus> {
        self.read_with_attempts(DEFAULT_STATUS_ATTEMPTS).await
    }

    /// [`read`](Self::read) with an explicit retry count.
    pub async fn read_with_attempts(&self, attempts: usize) -> Result<ImageWriterStatus> {
        let attempts = attempts.max(1);
        let mut last_err = None;
        for attempt in 1..=attempts {
            let buf = self.pap.read_bytes().await?;
            // Log the unaltered buffer: a raw reading is what any "this status
            // looks wrong" report will need.
            tracing::debug!(
                "ImageWriter status buffer (attempt {attempt}/{attempts}): {}",
                buf.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            match ImageWriterStatus::parse(&buf) {
                Ok(status) => return Ok(status),
                Err(e) => {
                    tracing::debug!(
                        "ImageWriter status attempt {attempt}/{attempts} rejected: {e}"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("ImageWriter status query made no attempts")))
    }

    /// The printer this handle reads from.
    pub fn address(&self) -> AtpAddress {
        self.pap.address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a status buffer the way the card sends it: low byte first.
    fn wire(low: u8, high: u8) -> [u8; 2] {
        [low, high]
    }

    #[test]
    fn rename_command_is_esc_b_then_a_pascal_string() {
        assert_eq!(
            rename_command("Lobby").unwrap(),
            b"\x1Bb\x05Lobby",
            "ESC b, one length byte, then the name"
        );
        // The length byte counts encoded bytes, and MacRoman is single byte, so
        // an accented name stays one byte per character rather than UTF-8's two.
        let cmd = rename_command("Café").unwrap();
        assert_eq!(cmd[..3], [0x1B, 0x62, 4]);
        assert_eq!(cmd.len(), 7);
    }

    /// A name the Chooser will display and NBP has to carry, so reject anything
    /// that would arrive mangled rather than silently substituting.
    #[test]
    fn rename_command_rejects_unusable_names() {
        assert!(rename_command("").is_err());
        // NBP entity-name delimiters.
        assert!(rename_command("Front:Desk").is_err());
        assert!(rename_command("Front@Desk").is_err());
        assert!(rename_command("Front*Desk").is_err());
        // Not representable in MacRoman.
        assert!(rename_command("Printer \u{4E2D}").is_err());
        // One over the cap, counted in encoded bytes.
        assert!(rename_command(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert!(rename_command(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    /// Pins each bit position we decode. Bit 5 is deliberately absent: the
    /// figure calls it paper-out, but the hardware left it clear with the
    /// printer empty, so nothing is decoded from it.
    #[test]
    fn decodes_each_documented_bit() {
        let s = ImageWriterStatus::parse(&wire(0x00, 0x80)).unwrap();
        assert!(s.busy() && !s.color_ribbon() && !s.active());

        let s = ImageWriterStatus::parse(&wire(0x80, 0x00)).unwrap();
        assert!(s.color_ribbon() && !s.sheet_feeder());

        let s = ImageWriterStatus::parse(&wire(0x40, 0x00)).unwrap();
        assert!(s.sheet_feeder() && !s.color_ribbon());

        let s = ImageWriterStatus::parse(&wire(0x20, 0x00)).unwrap();
        assert!(
            s.out_of_paper(),
            "bit 5 is not decoded, bit 3 is still clear"
        );

        let s = ImageWriterStatus::parse(&wire(0x10, 0x00)).unwrap();
        assert!(s.cover_open());

        let s = ImageWriterStatus::parse(&wire(0x08, 0x00)).unwrap();
        assert!(s.paper_present() && !s.out_of_paper());

        let s = ImageWriterStatus::parse(&wire(0x04, 0x00)).unwrap();
        assert!(s.paper_jam_bit());

        let s = ImageWriterStatus::parse(&wire(0x02, 0x00)).unwrap();
        assert!(s.fault());

        let s = ImageWriterStatus::parse(&wire(0x01, 0x00)).unwrap();
        assert!(s.active());
    }

    /// The pair of readings that pin bit 3, taken from a real ImageWriter II
    /// with a colour ribbon and no sheet feeder. Only one thing changed between
    /// them: paper was loaded. Only one bit moved with it.
    #[test]
    fn matches_observed_hardware_readings() {
        // Empty printer.
        let empty = ImageWriterStatus::parse(&[0x80, 0x00]).unwrap();
        assert_eq!(empty.raw, 0x0080);
        assert!(empty.out_of_paper(), "printer had no paper in it");
        assert_eq!(empty.error_text().as_deref(), Some("Out of paper"));

        // Same printer, paper loaded.
        let loaded = ImageWriterStatus::parse(&[0x88, 0x00]).unwrap();
        assert_eq!(loaded.raw, 0x0088);
        assert!(loaded.paper_present(), "printer had paper in it");
        assert_eq!(loaded.error_text(), None, "a ready printer has no errors");

        // Loading paper moved bit 3 and nothing else.
        assert_eq!(empty.raw ^ loaded.raw, PAPER_PRESENT);

        // Both readings agree on the rest of the printer's state.
        for s in [empty, loaded] {
            assert!(s.color_ribbon(), "printer had a colour ribbon fitted");
            assert!(!s.sheet_feeder(), "printer had no sheet feeder");
            assert!(!s.busy(), "printer was idle");
            // Nothing lands in the unused 8..=14 range.
            assert_eq!(s.raw & 0x7F00, 0);
        }
    }

    /// Capability bits come out of the first byte, the busy bit out of the second.
    #[test]
    fn word_is_little_endian_on_the_wire() {
        let s = ImageWriterStatus::parse(&[0x80, 0x80]).unwrap();
        assert_eq!(s.raw, 0x8080);
        assert!(s.busy() && s.color_ribbon());
        // Round-trips back to the bytes the card sent.
        assert_eq!(s.wire_bytes(), [0x80, 0x80]);

        let s = ImageWriterStatus::parse(&[0x01, 0x80]).unwrap();
        assert_eq!(s.wire_bytes(), [0x01, 0x80]);
        assert!(s.busy() && s.active());
    }

    /// A black ribbon must not be mistaken for a colour one: that bit decides
    /// the IPP colour advertisement and the Ghostscript device.
    #[test]
    fn black_ribbon_is_not_color() {
        // Idle, black ribbon, nothing else asserted.
        assert!(
            !ImageWriterStatus::parse(&wire(0x00, 0x00))
                .unwrap()
                .color_ribbon()
        );
        // Busy with a black ribbon: the busy bit must not leak into the ribbon read.
        assert!(
            !ImageWriterStatus::parse(&wire(0x00, 0x80))
                .unwrap()
                .color_ribbon()
        );
    }

    /// The jam bit's wording depends on whether a feeder is fitted, since with
    /// one an empty tray is said to raise it too. Both the bit and that
    /// distinction come from the figure and neither is confirmed; paper is
    /// present in each case here so the confirmed bit stays out of the way.
    #[test]
    fn sheet_feeder_changes_the_jam_wording() {
        let paper = PAPER_PRESENT as u8;

        let feeder =
            ImageWriterStatus::parse(&wire(paper | SHEET_FEEDER as u8 | PAPER_JAM as u8, 0x00))
                .unwrap();
        assert_eq!(
            feeder.error_text().as_deref(),
            Some("Paper jam or sheet feeder empty")
        );

        let no_feeder = ImageWriterStatus::parse(&wire(paper | PAPER_JAM as u8, 0x00)).unwrap();
        assert_eq!(no_feeder.error_text().as_deref(), Some("Paper jam"));
    }

    /// The glitch reply must be rejected rather than decoded as "every error at
    /// once".
    #[test]
    fn rejects_all_ones_low_byte() {
        assert!(ImageWriterStatus::parse(&[0xFF, 0x00]).is_err());
        assert!(ImageWriterStatus::parse(&[0xFF, 0x80]).is_err());
        assert!(!ImageWriterStatus::is_valid(0x00FF));
        // A high byte of ones is not the documented glitch, so it stays valid.
        assert!(ImageWriterStatus::is_valid(0xFF00));
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(ImageWriterStatus::parse(&[]).is_err());
        assert!(ImageWriterStatus::parse(&[0x00]).is_err());
    }

    /// Extra trailing bytes are ignored rather than rejected: only the first
    /// two are the status word.
    #[test]
    fn ignores_trailing_bytes() {
        let s = ImageWriterStatus::parse(&[0x80, 0x00, 0xAA]).unwrap();
        assert_eq!(s.raw, 0x0080);
    }

    /// A ready printer has paper, so bit 3 is part of every no-error reading.
    #[test]
    fn idle_printer_reports_no_error() {
        let paper = PAPER_PRESENT as u8;

        let s = ImageWriterStatus::parse(&wire(paper | 0x80, 0x00)).unwrap();
        assert_eq!(s.error_text(), None);
        assert_eq!(s.ribbon_text(), "Color");

        // Busy and actively printing is a state, not an error.
        let s = ImageWriterStatus::parse(&wire(paper | 0x01, 0x80)).unwrap();
        assert_eq!(s.error_text(), None);
        assert!(s.busy() && s.active());
        assert_eq!(s.ribbon_text(), "Black only");
    }
}
