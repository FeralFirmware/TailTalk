//! ImageWriter II/LQ LocalTalk Option Card role.
//!
//! Registers as `<name>:ImageWriter@*` and emulates the option card's PAP
//! behaviour: job data is raw ImageWriter command bytes piped verbatim to
//! the UART, and SendStatus answers with the card's three-byte status
//! buffer - a length byte of 2 followed by the two `statusBits` bytes, low
//! byte first (the card is little-endian here even though AppleTalk is
//! otherwise big-endian).
//!
//! ```text
//!  15  14 13 12 11 10 9 8   7    6     5     4     3    2    1    0
//! busy |<--- unused --->| ribbon feed paper cover  off  jam fault active
//!                                      out         line
//! ```
//!
//! Every bit confirmed on a real ImageWriter II is active-high. Three
//! readings, all with a colour ribbon fitted: paper loaded and selected
//! reads 0x0080, deselected 0x0088, and out of paper while deselected
//! 0x00AA - so bit 3 is off line, and bits 5 and 1 (paper out and the
//! general fault) move together. Bits 6, 4, 2 and 0 are the published
//! figure alone, never deliberately triggered.
//!
//! Ribbon detection. Bit 7 of that word says a colour ribbon is fitted, and
//! a serial ImageWriter will tell us: `ESC ?`, the self ID command
//! (*ImageWriter II Technical Reference*, Table 6-7), is answered with an
//! unterminated ASCII string `IW<width>[C][F]` - `IW` for an ImageWriter,
//! the carriage width in inches, then `C` only when a colour ribbon is in
//! place and `F` only when the SheetFeeder is installed. The role asks once
//! while idle and again after each job, since a ribbon can be swapped
//! between them.
//!
//! Two constraints from the manual shape how that query is issued. The
//! printer does not read a command until it reaches the line being printed,
//! so with a queue in front of it the answer can be "several minutes" away
//! (manual p89) - hence only ever asking when no job is open. And the reply
//! carries no terminator, so it is collected until it stops arriving rather
//! than parsed for an end marker.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Micros;
use crate::pap::{PapEvent, PapServer};

/// Self ID query (manual Table 6-7). Answered with `IW<width>[C][F]`.
pub const SELF_ID: &[u8] = &[0x1B, b'?'];

/// The card's rename command, followed by the new name as a Pascal string.
pub const RENAME: &[u8] = &[0x1B, b'b'];

/// Colour ribbon fitted (status word bit 7). Verified active-high on a
/// real ImageWriter II; see the module docs for the readings.
pub const STATUS_COLOUR_RIBBON: u16 = 0x0080;
/// If the printer is currently reported as busy (i.e processing a job by us/others)
pub const STATUS_BUSY: u16 = 0x8000;
/// Set when a status feeder is installed on this printer
pub const STATUS_SHEET_FEEDER: u16 = 0x0040;

/// Status word for a ready printer 
pub const READY_STATUS: u16 = STATUS_COLOUR_RIBBON;

/// Longest self ID reply worth waiting for: `IW` + two width digits + `C` +
/// `F`. A 15-inch LQ answers the same length.
const SELF_ID_MAX: usize = 8;

/// Quiet time after the last byte that marks the end of the reply. It has
/// no terminator, and the shortest valid one (`IW10`) is four bytes, so the
/// only way to know it finished is that nothing more came. At 300 baud, the
/// slowest rate the printer supports, one character takes 33 ms, so this
/// cannot fall inside a reply that is still arriving.
const SELF_ID_GAP: Micros = 150_000;

/// How long to wait for a reply that never starts before keeping the
/// default. Only ever spent while idle.
const SELF_ID_TIMEOUT: Micros = 2_000_000;

/// Where the role is in identifying the ribbon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ident {
    /// Nothing asked yet, or a job just ended and the ribbon may have moved.
    Due,
    /// Query sent at `since`, and no reply read yet. Gives up at
    /// [`SELF_ID_TIMEOUT`].
    Waiting { since: Micros },
    /// Answered, or given up on. No further query until the next job ends,
    /// though a reply that turns up anyway is still read.
    Settled,
}

pub enum ImageWriterError {
    /// Returned when we cant correctly parse the ident string from the printer
    UnknownModel,
}

/// What the embedder sees. The PAP server's own events pass through; the
/// rename is the role's, because `ESC b` is a printer-stream command and PAP
/// has no business knowing about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageWriterEvent {
    ConnectionOpened {
        client: ServiceAddress,
    },
    /// Job bytes for the printer UART.
    ToPrinter(Vec<u8>),
    JobEof,
    ConnectionClosed,
    /// The client renamed the card, as raw MacRoman bytes. The embedder owns
    /// what happens next: re-register under it, and persist it. A real card
    /// keeps the name across a power cycle and re-registers itself.
    Rename(Vec<u8>),
    /// The printer we are connected to has changed (either newly identified, or
    /// a new type has been plugged in to us).
    NbpTypeChanged(&'static str),
}

pub enum SheetFeeder {
    II,
    LQ {
        /// How many paper bins the sheet feeder has available to pull from
        bins: u8,
        /// Whether the envelope attachment is installed
        envelope: bool,
    }
}

#[derive(Default)]
pub struct ImageWriterII {
    /// Whether or not a sheet feeder is installed. No options unlike the LQ
    sheet_feeder: Option<SheetFeeder>,
    /// Whether a colour ribbon is installed
    colour_ribbon: bool,
}

#[derive(Default)]
pub struct ImageWriterLQ {
    /// Whether or not a sheet feeder is installed, and if so what options it has
    sheet_feeder: Option<SheetFeeder>,
    /// Whether a colour ribbon is installed
    colour_ribbon: bool,
    /// Whether it is currently set to pull tractor paper or not
    pull_tractor: bool,
}

pub enum ImageWriterModel {
    ImageWriter,
    ImageWriterII(ImageWriterII),
    ImageWriterLQ(ImageWriterLQ),
}

impl TryFrom<&[u8]> for ImageWriterModel {
    type Error = ImageWriterError;

    fn try_from(ident: &[u8]) -> Result<Self, Self::Error> {
        // ImageWriter II
        if ident.starts_with(b"IW10") {
            let mut model = ImageWriterII::default();

            for byte in &ident[4..] {
                match byte {
                    b'C' => model.colour_ribbon = true,
                    b'F' => model.sheet_feeder = Some(SheetFeeder::II),
                    _ => {}
                }
            }

            Ok(ImageWriterModel::ImageWriterII(model))
        // ImageWriter LQ
        } else if ident.starts_with(b"LQ1") {
            let mut model = ImageWriterLQ::default();
            let mut feeder = false;
            let mut envelope = false;
            let mut bins = 1;

            for byte in &ident[3..] {
                match byte {
                    b'C' => model.colour_ribbon = true,
                    b'F' => feeder = true,
                    b'E' => (feeder, envelope) = (true, true),
                    b'1'..=b'9' => bins = byte - b'0',
                    b'P' => model.pull_tractor = true,
                    b'\r' => break, // Signifies end of reply
                    _ => {}
                }
            }

            model.sheet_feeder = feeder.then_some(SheetFeeder::LQ { bins, envelope });

            Ok(ImageWriterModel::ImageWriterLQ(model))
        } else {
            Err(ImageWriterError::UnknownModel)
        }
    }
}

impl ImageWriterModel {
    /// Returns true if a colour ribbon is currently installed
    pub fn colour_ribbon(&self) -> bool {
        match self {
            ImageWriterModel::ImageWriter => false,
            ImageWriterModel::ImageWriterII(iw) => iw.colour_ribbon,
            ImageWriterModel::ImageWriterLQ(lq) => lq.colour_ribbon,
        }
    }

    /// Returns true if a sheet feeder is currently installed
    pub fn sheet_feeder(&self) -> bool {
        match self {
            ImageWriterModel::ImageWriter => false,
            ImageWriterModel::ImageWriterII(iw) => iw.sheet_feeder.is_some(),
            ImageWriterModel::ImageWriterLQ(lq) => lq.sheet_feeder.is_some(),
        }
    }

    /// The NBP type string for registering this printer model
    pub const fn nbp_type(&self) -> &'static str {
        match self {
            ImageWriterModel::ImageWriter => "ImageWriter",
            ImageWriterModel::ImageWriterII(_) => "ImageWriter",
            ImageWriterModel::ImageWriterLQ(_) => "LQ",
        }
    }
}

pub struct ImageWriterRole {
    server: PapServer,
    ident: Ident,
    ident_reply: Vec<u8>,
    /// When the last byte of a reply still being collected arrived. An II's
    /// reply has no terminator, so it ends once this is [`SELF_ID_GAP`] old.
    reply_last: Option<Micros>,
    /// What model we have identified from ident_reply, if any.
    model: Option<ImageWriterModel>,
    /// Events the role raises itself, ahead of the PAP server's.
    events: VecDeque<ImageWriterEvent>,
    /// Set while the next job bytes are still the first of a job.
    job_start: bool,
}

impl ImageWriterRole {
    /// FIXME: Because of bad choices I made we have to have an NBP name at bind
    /// time. This is just the placeholder for now.
    pub const fn default_nbp() -> &'static str {
        ImageWriterModel::ImageWriter.nbp_type()
    }

    pub fn new(listener_socket: u8, conn_socket: u8) -> Self {
        let mut role = Self {
            server: PapServer::new(listener_socket, conn_socket),
            ident: Ident::Due,
            ident_reply: Vec::new(),
            reply_last: None,
            model: None,
            events: VecDeque::new(),
            job_start: true,
        };
        role.apply_status();
        role
    }

    /// The u16 bitmap value that is reported via PAP because Apple decided to be weird and not
    /// use human text for some reason.
    fn status_word(&self) -> u16 {
        let mut word = match &self.model {
            Some(model) => {
                let mut w = 0;
                if model.colour_ribbon() {
                    w |= STATUS_COLOUR_RIBBON;
                }
                if model.sheet_feeder() {
                    w |= STATUS_SHEET_FEEDER;
                }
                w
            }
            // The printer hasn't answered.
            None => STATUS_COLOUR_RIBBON,
        };
        if self.server.busy() {
            word |= STATUS_BUSY;
        }
        word
    }

    fn apply_status(&mut self) {
        // Low byte first; the length byte is added by the PAP framing.
        self.server.set_status(&self.status_word().to_le_bytes());
    }

    pub fn colour_ribbon(&self) -> bool {
        self.status_word() & STATUS_COLOUR_RIBBON != 0
    }

    pub fn listener_socket(&self) -> u8 {
        self.server.listener_socket()
    }

    pub fn conn_socket(&self) -> u8 {
        self.server.conn_socket()
    }

    /// Free space in the UART TX ring; pulls stop when it runs low.
    pub fn set_sink_credit(&mut self, bytes: usize, now: Micros) {
        self.server.set_sink_credit(bytes, now);
    }

    /// Bytes the printer sent. Only the self ID reply is of interest; the
    /// option card has no reverse data path, so anything else is dropped.
    ///
    /// Read whenever it arrives, not only while a query is outstanding: the
    /// reply to a query sent after a job comes once the printer has printed
    /// what it had buffered, and one sent while the printer was off comes
    /// when it is switched on.
    pub fn printer_input(&mut self, data: &[u8], now: Micros) {
        for &b in data {
            // A reply starts with `IW` or `LQ`. Anything ahead of it, such as
            // the XON a printer in XON/XOFF mode sends when it comes ready,
            // is not part of one.
            if self.ident_reply.is_empty() && b != b'I' && b != b'L' {
                continue;
            }
            self.ident_reply.push(b);
            // The LQ ends its reply with a CR. The II's has no terminator and
            // ends when the line goes quiet, which `poll` watches for.
            if b == b'\r' || self.ident_reply.len() >= SELF_ID_MAX {
                self.settle_ident();
            }
        }
        self.reply_last = (!self.ident_reply.is_empty()).then_some(now);
    }

    /// Attempts to parse the identify string response from the printer, and if valid update
    /// our internal options.
    fn settle_ident(&mut self) {
        if let Ok(model) = ImageWriterModel::try_from(self.ident_reply.as_slice()) {
            let nbp_type = model.nbp_type();
            let changed = nbp_type != self.nbp_type();
            self.model = Some(model);
            self.apply_status();

            // Answered. Anything that is not a reply leaves the query
            // waiting for the real one.
            if matches!(self.ident, Ident::Waiting { .. }) {
                self.ident = Ident::Settled;
            }

            if changed {
                self.events
                    .push_back(ImageWriterEvent::NbpTypeChanged(nbp_type));
            }
        }

        self.ident_reply.clear();
        self.reply_last = None;
    }

    pub fn nbp_type(&self) -> &'static str {
        self.model
            .as_ref()
            .map_or_else(Self::default_nbp, ImageWriterModel::nbp_type)
    }

    pub fn handle_datagram(
        &mut self,
        local_socket: u8,
        src: ServiceAddress,
        payload: &[u8],
        now: Micros,
    ) {
        self.server.handle_datagram(local_socket, src, payload, now);
    }

    pub fn poll(&mut self, now: Micros) {
        self.server.poll(now);
        if self
            .reply_last
            .is_some_and(|t| now.saturating_sub(t) >= SELF_ID_GAP)
        {
            self.settle_ident();
        }
        self.poll_ident(now);
    }

    /// Issue or time out the self ID query. Never while a job is open: the
    /// printer would not read the command until it reached that point in the
    /// stream, and the query bytes would sit in the middle of the job.
    fn poll_ident(&mut self, now: Micros) {
        match self.ident {
            Ident::Due if !self.server.busy() => {
                self.events
                    .push_back(ImageWriterEvent::ToPrinter(SELF_ID.to_vec()));
                self.ident = Ident::Waiting { since: now };
            }
            // Giving up only stops the waiting. A reply still arriving is
            // left for `poll` to finish.
            Ident::Waiting { since } if now.saturating_sub(since) >= SELF_ID_TIMEOUT => {
                self.ident = Ident::Settled;
            }
            _ => {}
        }
    }

    pub fn next_deadline(&self) -> Option<Micros> {
        let ident = match self.ident {
            Ident::Waiting { since } => Some(since + SELF_ID_TIMEOUT),
            // A query that is due needs a wake-up to go out at all - but
            // only once the printer is idle. While a job is open it is the
            // CloseConn that re-arms it, not the clock, and asking for an
            // immediate wake-up here would spin the caller's event loop for
            // the whole length of the job.
            Ident::Due if !self.server.busy() => Some(0),
            Ident::Due => None,
            Ident::Settled => None,
        };
        // A reply in progress needs waking once the line has been quiet long
        // enough to end it.
        let reply = self.reply_last.map(|t| t + SELF_ID_GAP);
        [self.server.next_deadline(), ident, reply]
            .into_iter()
            .flatten()
            .min()
    }

    pub fn poll_transmit(&mut self) -> Option<(u8, ServiceAddress, Vec<u8>)> {
        self.server.poll_transmit()
    }

    pub fn poll_event(&mut self) -> Option<ImageWriterEvent> {
        if let Some(event) = self.events.pop_front() {
            return Some(event);
        }
        match self.server.poll_event()? {
            PapEvent::ConnectionOpened { client } => {
                self.job_start = true;
                self.apply_status();
                Some(ImageWriterEvent::ConnectionOpened { client })
            }
            PapEvent::JobEof => {
                self.job_start = true;
                Some(ImageWriterEvent::JobEof)
            }
            PapEvent::ConnectionClosed => {
                // The ribbon can be changed between jobs, so ask again once
                // the printer is idle.
                self.ident = Ident::Due;
                self.job_start = true;
                self.apply_status();
                Some(ImageWriterEvent::ConnectionClosed)
            }
            PapEvent::ToPrinter(bytes) => {
                // A rename is sent the way a job is, so it has to be pulled
                // out of the stream before the bytes reach the UART - the
                // printer has no `ESC b` and would print the name. Only
                // honoured at the head of a job, which is how a client sends
                // it: a bitmap run is arbitrary binary and a packet of it may
                // well begin with 1B 62.
                let at_start = self.job_start;
                self.job_start = false;
                match parse_rename(&bytes) {
                    Some(name) if at_start => Some(ImageWriterEvent::Rename(name)),
                    _ => Some(ImageWriterEvent::ToPrinter(bytes)),
                }
            }
        }
    }
}

/// Pull a rename out of a job's opening bytes: `ESC b` then a Pascal string,
/// and nothing else. `ESC b` is unassigned in the ImageWriter's own command
/// set, which is what left it free for the card to claim.
fn parse_rename(bytes: &[u8]) -> Option<Vec<u8>> {
    let rest = bytes.strip_prefix(RENAME)?;
    let (&len, name) = rest.split_first()?;
    if len == 0 || name.len() != len as usize {
        return None;
    }
    Some(name.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pap::test_support::{MiniClient, PapPeer, addr, shuttle};

    impl PapPeer for ImageWriterRole {
        fn handle_datagram(
            &mut self,
            local_socket: u8,
            src: ServiceAddress,
            payload: &[u8],
            now: Micros,
        ) {
            ImageWriterRole::handle_datagram(self, local_socket, src, payload, now);
        }
        fn poll_transmit(&mut self) -> Option<(u8, ServiceAddress, Vec<u8>)> {
            ImageWriterRole::poll_transmit(self)
        }
    }

    /// Drain the role's events, returning the first thing sent to the
    /// printer.
    fn next_to_printer(role: &mut ImageWriterRole) -> Option<Vec<u8>> {
        core::iter::from_fn(|| role.poll_event()).find_map(|e| match e {
            ImageWriterEvent::ToPrinter(bytes) => Some(bytes),
            _ => None,
        })
    }

    /// A role whose idle self ID query has just gone out, at time 0.
    fn asked() -> ImageWriterRole {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        assert_eq!(next_to_printer(&mut role).as_deref(), Some(SELF_ID));
        role
    }

    /// The status word as a Mac reads it: the role's answer to a SendStatus,
    /// taken off the wire rather than recomputed, so a change the role never
    /// applied shows up as a stale word.
    fn wire_status(role: &mut ImageWriterRole, mac: &mut MiniClient, now: Micros) -> u16 {
        use crate::atp::AtpEvent;
        use tailtalk_packets::pap::{PapFunction, PapPacket};

        let request = PapPacket {
            connection_id: 0,
            function: PapFunction::SendStatus,
            sequence_num: 0,
            eof: false,
            data: &[],
        };
        let (ub, d) = request.to_atp_parts();
        mac.ep
            .request(addr(130, role.listener_socket()), ub, d, 0x01, now);
        shuttle(role, 130, mac, now);
        loop {
            match mac.ep.poll_event() {
                Some(AtpEvent::Response {
                    user_bytes, data, ..
                }) => {
                    let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                    if pap.function != PapFunction::Status {
                        continue;
                    }
                    // Four reserved bytes, then the card's buffer: a length
                    // of 2 and the word, low byte first.
                    assert_eq!(pap.data[4], 2, "the card's status buffer is two bytes");
                    return u16::from_le_bytes([pap.data[5], pap.data[6]]);
                }
                Some(_) => continue,
                None => panic!("the role never answered SendStatus"),
            }
        }
    }

    /// Every reply the manuals allow. The II (p88): `IW10`, then `C` for a
    /// colour ribbon and `F` for the SheetFeeder. The LQ (Table 8-8): `LQ1`,
    /// then `C`, `F` or `E` (with the envelope attachment) and a bin count
    /// for the Cut Sheet Feeder, `P` for the pull tractor, and a CR. The first
    /// two LQ rows are the manual's own examples. A feeder with no count has
    /// one bin, and the parser takes a reply with or without its CR.
    ///
    /// Anything without a known prefix is no reply at all. Bytes ahead of a
    /// real reply are the role's to strip, not the parser's.
    #[test]
    fn parses_every_self_id_reply() {
        let ii: &[(&[u8], bool, bool)] = &[
            (b"IW10", false, false),
            (b"IW10C", true, false),
            (b"IW10F", false, true),
            (b"IW10CF", true, true),
        ];
        for &(reply, colour, feeder) in ii {
            let Ok(ImageWriterModel::ImageWriterII(m)) = ImageWriterModel::try_from(reply) else {
                panic!("{} is an ImageWriter II", reply.escape_ascii());
            };
            assert_eq!(
                (m.colour_ribbon, m.sheet_feeder.is_some()),
                (colour, feeder),
                "{}",
                reply.escape_ascii()
            );
        }

        /// Reply, colour ribbon, feeder as (bins, envelope), pull tractor.
        type LqCase = (&'static [u8], bool, Option<(u8, bool)>, bool);
        let lq: &[LqCase] = &[
            (b"LQ1P\r", false, None, true),
            (b"LQ1CE3\r", true, Some((3, true)), false),
            (b"LQ1\r", false, None, false),
            (b"LQ1C\r", true, None, false),
            (b"LQ1F\r", false, Some((1, false)), false),
            (b"LQ1F2\r", false, Some((2, false)), false),
            (b"LQ1CF3\r", true, Some((3, false)), false),
            (b"LQ1CE3P\r", true, Some((3, true)), true),
            (b"LQ1CE3", true, Some((3, true)), false),
        ];
        for &(reply, colour, feeder, pull) in lq {
            let Ok(ImageWriterModel::ImageWriterLQ(m)) = ImageWriterModel::try_from(reply) else {
                panic!("{} is an ImageWriter LQ", reply.escape_ascii());
            };
            let got_feeder = match m.sheet_feeder {
                None => None,
                Some(SheetFeeder::LQ { bins, envelope }) => Some((bins, envelope)),
                Some(SheetFeeder::II) => panic!("{} gave a II feeder", reply.escape_ascii()),
            };
            assert_eq!(
                (m.colour_ribbon, got_feeder, m.pull_tractor),
                (colour, feeder, pull),
                "{}",
                reply.escape_ascii()
            );
        }

        for reply in [
            &b""[..],
            b"IW",
            b"IW1",
            b"LQ",
            b"\x11IW10C",
            b"LXC",
            b"\xFFC",
        ] {
            assert!(
                ImageWriterModel::try_from(reply).is_err(),
                "{}",
                reply.escape_ascii()
            );
        }
    }

    /// The reply decides bits 7 (colour ribbon) and 6 (sheet feeder) of the
    /// word a Mac reads. Black is the *absence* of `C`, so it can only come
    /// from a reply that arrived. An II's reply has no terminator and ends
    /// when the line goes quiet. An LQ's ends at its CR with no wait, so those
    /// rows are never polled. The longest LQ reply arrives whole.
    #[test]
    fn the_reply_decides_the_status_word() {
        let cases: &[(&[u8], u16)] = &[
            (b"IW10CF", STATUS_COLOUR_RIBBON | STATUS_SHEET_FEEDER),
            (b"IW10F", STATUS_SHEET_FEEDER),
            (b"IW10", 0),
            (b"LQ1CE3\r", STATUS_COLOUR_RIBBON | STATUS_SHEET_FEEDER),
            (b"LQ1P\r", 0),
        ];
        for &(reply, word) in cases {
            let mut role = asked();
            let mut mac = MiniClient::new(10, 70);
            role.printer_input(reply, 100);
            if !reply.ends_with(b"\r") {
                role.poll(100 + SELF_ID_GAP);
            }
            assert_eq!(
                wire_status(&mut role, &mut mac, 100 + SELF_ID_GAP),
                word,
                "{}",
                reply.escape_ascii()
            );
        }

        let mut role = asked();
        role.printer_input(b"LQ1CE3P\r", 100);
        assert!(
            matches!(&role.model, Some(ImageWriterModel::ImageWriterLQ(lq)) if lq.pull_tractor),
            "the `P` at the end of the longest reply must survive the length cap"
        );
    }

    /// UART reads cut a reply wherever they like, and a printer in XON/XOFF
    /// mode sends an XON as it comes ready, just ahead of the reply. The reply
    /// starts at its `I` or `L`. An II's ends once the line has been quiet for
    /// the gap counted from its last byte, so a shorter pause between pieces
    /// does not end it early. An LQ's CR ends it whichever read it lands in.
    /// Both replies are black-ribbon ones, so the colour default only changes
    /// if the reply was read.
    #[test]
    fn a_reply_split_across_reads_is_put_back_together() {
        let mut role = asked();
        role.printer_input(b"\x11IW1", 100);
        let second = 100 + SELF_ID_GAP / 2;
        role.printer_input(b"0", second);
        // A full gap after the first piece, but not after the second.
        role.poll(100 + SELF_ID_GAP);
        assert!(role.model.is_none(), "the reply is still arriving");
        role.poll(second + SELF_ID_GAP);
        assert!(!role.colour_ribbon());

        let mut role = asked();
        role.printer_input(b"LQ1", 100);
        role.printer_input(b"P\r", 200);
        assert!(!role.colour_ribbon());
    }

    /// A printer that says nothing - powered off, option card holding the
    /// serial port, wrong baud rate - leaves the default standing rather than
    /// reading as a black ribbon, and is not asked again while the query is
    /// outstanding. A reply that turns up after the role has given up is
    /// still the printer's answer: the one to a query sent after a job comes
    /// once the printer has printed what it had buffered, and one sent while
    /// it was off comes when it is switched on.
    #[test]
    fn silence_keeps_the_default_until_a_late_reply() {
        let mut role = asked();
        let mut mac = MiniClient::new(10, 70);
        role.poll(1_000);
        assert_eq!(
            next_to_printer(&mut role),
            None,
            "the query is not repeated"
        );

        role.poll(SELF_ID_TIMEOUT);
        assert_eq!(
            wire_status(&mut role, &mut mac, SELF_ID_TIMEOUT),
            STATUS_COLOUR_RIBBON
        );
        // The caller sleeps on this deadline, so one already past would spin
        // its event loop.
        assert!(
            role.next_deadline().is_none_or(|t| t > SELF_ID_TIMEOUT),
            "a role that has given up must not keep asking to be woken"
        );

        let late = SELF_ID_TIMEOUT * 5;
        role.printer_input(b"IW10", late);
        assert!(
            role.next_deadline()
                .is_some_and(|t| t <= late + SELF_ID_GAP),
            "a reply in progress must ask to be woken when the line goes quiet"
        );
        role.poll(late + SELF_ID_GAP);
        assert_eq!(wire_status(&mut role, &mut mac, late + SELF_ID_GAP), 0);
    }

    /// The busy bit tells every Mac that a job is open, so it is set for as
    /// long as a session is and cleared when the session closes.
    #[test]
    fn the_busy_bit_follows_the_session() {
        use tailtalk_packets::pap::{PapFunction, PapPacket};

        let mut role = ImageWriterRole::new(190, 191);
        let mut mac = MiniClient::new(10, 70);
        assert_eq!(wire_status(&mut role, &mut mac, 0) & STATUS_BUSY, 0, "idle");

        mac.open_conn(addr(130, role.listener_socket()), 10);
        shuttle(&mut role, 130, &mut mac, 10);
        // The embedder drains the role's events as they come, and the status
        // follows from those.
        while role.poll_event().is_some() {}
        assert_ne!(
            wire_status(&mut role, &mut mac, 20) & STATUS_BUSY,
            0,
            "a job is open"
        );

        let close = PapPacket {
            connection_id: 70,
            function: PapFunction::CloseConn,
            sequence_num: 0,
            eof: false,
            data: &[],
        };
        let (ub, d) = close.to_atp_parts();
        mac.ep
            .request(addr(130, role.conn_socket()), ub, d, 0x01, 30);
        shuttle(&mut role, 130, &mut mac, 30);
        while role.poll_event().is_some() {}
        assert_eq!(
            wire_status(&mut role, &mut mac, 40) & STATUS_BUSY,
            0,
            "the job is over"
        );
    }

    /// Open a session and answer the server's pulls with `chunks`, one PAP
    /// data packet each, the last carrying eof. Returns every event raised.
    ///
    /// Chunking matters here: the role sees one `ToPrinter` per packet, so a
    /// raster split such that a packet begins with `1B 62` is exactly the
    /// case the start-of-job rule has to reject.
    fn run_job(chunks: &[&[u8]]) -> Vec<ImageWriterEvent> {
        use crate::atp::AtpEvent;
        use tailtalk_packets::pap::{PapFunction, PapPacket};

        let mut role = ImageWriterRole::new(190, 191);
        role.set_sink_credit(64 * 1024, 0);
        let mut client = MiniClient::new(10, 70);
        client.open_conn(addr(130, role.listener_socket()), 0);
        shuttle(&mut role, 130, &mut client, 0);

        let mut events: Vec<ImageWriterEvent> = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let now = 20 + i as Micros * 10;
            // The server pulls as soon as it has credit, so a SendData is
            // already among the events the last exchange produced.
            let (source, tid) = loop {
                match client.ep.poll_event() {
                    Some(AtpEvent::Request {
                        source,
                        tid,
                        user_bytes,
                        data,
                        ..
                    }) => {
                        let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                        if pap.function == PapFunction::SendData {
                            break (source, tid);
                        }
                    }
                    Some(_) => continue,
                    None => panic!("the server never pulled for chunk {i}"),
                }
            };
            let job = PapPacket {
                connection_id: 70,
                function: PapFunction::Data,
                sequence_num: 0,
                eof: i + 1 == chunks.len(),
                data: chunk,
            };
            let (ub, d) = job.to_atp_parts();
            client
                .ep
                .respond(source, tid, ub, d, crate::pap::PAP_MAX_DATA_PER_PACKET, now);
            shuttle(&mut role, 130, &mut client, now);
            events.extend(core::iter::from_fn(|| role.poll_event()));
        }
        events
    }

    /// A rename must never reach the UART: the printer has no `ESC b` and
    /// would print the name across the page.
    #[test]
    fn a_rename_job_is_swallowed_rather_than_printed() {
        let events = run_job(&[b"\x1bb\x04Inky"]);
        assert!(
            events.contains(&ImageWriterEvent::Rename(b"Inky".to_vec())),
            "the rename must be raised: {events:02X?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ImageWriterEvent::ToPrinter(b) if b.starts_with(RENAME))),
            "and must not also go to the printer: {events:02X?}"
        );
    }

    /// A later packet that begins with the rename bytes is still pixels: a
    /// bitmap run is arbitrary binary and may be split anywhere.
    #[test]
    fn esc_b_later_in_a_job_stays_printer_data() {
        let events = run_job(&[b"\x1bG0008", b"\x1bb\x04Inky"]);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ImageWriterEvent::Rename(_))),
            "1B 62 in a bitmap run is data, not a rename: {events:02X?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ImageWriterEvent::ToPrinter(b) if b.ends_with(b"Inky"))),
            "the bytes must reach the printer: {events:02X?}"
        );
    }

    /// The wire format: `ESC b`, a length byte, then the name.
    #[test]
    fn a_rename_is_pulled_out_of_the_job_stream() {
        assert_eq!(parse_rename(b"\x1bb\x04Inky"), Some(b"Inky".to_vec()));
    }

    /// Strict on its own, not only through the start-of-job rule: 1B 62
    /// occurs in bitmap runs as pixel data, so anything but exactly `ESC b`,
    /// a length byte and that many name bytes stays printer data.
    #[test]
    fn only_a_bare_well_formed_rename_is_taken() {
        // Trailing bytes: a raster that merely opens with the same two bytes.
        assert_eq!(parse_rename(b"\x1bb\x04Inky\x1bG0008"), None);
        // Length byte disagreeing with what follows.
        assert_eq!(parse_rename(b"\x1bb\x09Inky"), None);
        // Empty name.
        assert_eq!(parse_rename(b"\x1bb\x00"), None);
        // Truncated.
        assert_eq!(parse_rename(b"\x1bb"), None);
        // An ordinary bitmap run.
        assert_eq!(parse_rename(b"\x1bG0004\x1bb\x04Inky"), None);
    }

    /// The manual's constraint (p89): the printer does not read a command
    /// until the paper reaches that point in the job, so a query issued
    /// mid-stream would land in the middle of a bitmap and be answered
    /// minutes later. A session that opens before the idle query has gone
    /// out must therefore hold it back until the job is done.
    #[test]
    fn the_query_is_held_back_while_a_job_is_open() {
        let mut role = ImageWriterRole::new(190, 191);
        role.set_sink_credit(64 * 1024, 0);

        let mut client = MiniClient::new(10, 70);
        client.open_conn(addr(130, role.listener_socket()), 0);
        shuttle(&mut role, 130, &mut client, 0);
        assert!(
            core::iter::from_fn(|| role.poll_event())
                .any(|e| matches!(e, ImageWriterEvent::ConnectionOpened { .. })),
            "the session must be open for this test to mean anything"
        );

        // Well past the point an idle role would have asked and given up.
        for tick in 1..=20u64 {
            role.poll(tick * SELF_ID_TIMEOUT / 4);
        }
        assert_eq!(
            next_to_printer(&mut role),
            None,
            "no self ID query may be mixed into an open job"
        );
        // And it must not ask to be woken for it either: the caller sleeps
        // on this deadline, so a query held back for the length of a job
        // would spin the event loop for that whole time.
        assert_ne!(
            role.next_deadline(),
            Some(0),
            "a held-back query must wait for the CloseConn, not the clock"
        );
    }

    /// Nor must line noise. At the wrong baud rate the bytes that arrive are
    /// arbitrary, and one of them being `C` cannot be allowed to decide, not
    /// even after a stray `L` that looks like the start of a reply.
    #[test]
    fn a_reply_that_is_not_an_imagewriter_id_is_ignored() {
        let mut role = asked();
        role.printer_input(b"IW10", 100);
        role.poll(100 + SELF_ID_GAP);
        assert!(!role.colour_ribbon(), "a black ribbon to start from");

        role.printer_input(&[0xFF, b'C', 0x00, 0xAA, 0x55, 0x13], 1_000_000);
        role.printer_input(b"LXC", 1_000_100);
        role.poll(1_000_100 + SELF_ID_GAP);
        assert!(
            !role.colour_ribbon(),
            "only a reply starting `IW` or `LQ` may change the ribbon"
        );
    }
}
