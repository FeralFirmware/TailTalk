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
//!
//! Nothing else the printer sends is forwarded: the option card being
//! emulated has no reverse data path to the Mac, so job-time chatter is
//! dropped as it would be on real hardware.
//!
//! Everything below bit 7 is a live condition - paper out, off line, cover,
//! jam - and reading those needs the printer's DTR line, which the current
//! InkTalk board does not bring to the MCU. Until it does, the role reports
//! a ready printer and only the ribbon bit is answered from hardware.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Micros;
use crate::pap::{PapEvent, PapServer};

/// The NBP type the option card registers itself under.
pub const NBP_TYPE: &str = "ImageWriter";

/// Self ID query (manual Table 6-7). Answered with `IW<width>[C][F]`.
pub const SELF_ID: &[u8] = &[0x1B, b'?'];

/// The card's rename command, followed by the new name as a Pascal string.
pub const RENAME: &[u8] = &[0x1B, b'b'];

/// Colour ribbon fitted (status word bit 7). Verified active-high on a
/// real ImageWriter II; see the module docs for the readings.
pub const STATUS_COLOUR_RIBBON: u16 = 0x0080;

/// Status word for a ready printer, with the ribbon bit supplied by
/// [`ImageWriterRole::set_colour_ribbon`] or by the self ID reply.
pub const READY_STATUS: u16 = STATUS_COLOUR_RIBBON;

/// Longest self ID reply worth waiting for: `IW` + two width digits + `C` +
/// `F`. A 15-inch LQ answers the same length.
const SELF_ID_MAX: usize = 6;

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
    /// Query sent; collecting an unterminated reply. `last` is when a byte
    /// most recently arrived, which is what says the reply has finished.
    Waiting { since: Micros, last: Option<Micros> },
    /// Answered, or given up on. Nothing further until the next job ends.
    Settled,
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
}

pub struct ImageWriterRole {
    server: PapServer,
    ident: Ident,
    ident_reply: Vec<u8>,
    /// Events the role raises itself, ahead of the PAP server's.
    events: VecDeque<ImageWriterEvent>,
    colour_ribbon: bool,
    /// Set while the next job bytes are still the first of a job.
    job_start: bool,
}

impl ImageWriterRole {
    pub fn new(listener_socket: u8, conn_socket: u8) -> Self {
        let mut role = Self {
            server: PapServer::new(listener_socket, conn_socket),
            ident: Ident::Due,
            ident_reply: Vec::new(),
            events: VecDeque::new(),
            colour_ribbon: true,
            job_start: true,
        };
        role.apply_status();
        role
    }

    fn apply_status(&mut self) {
        let word = if self.colour_ribbon {
            STATUS_COLOUR_RIBBON
        } else {
            0
        };
        // Low byte first; the length byte is added by the PAP framing.
        self.server
            .set_status(&[(word & 0xFF) as u8, (word >> 8) as u8]);
    }

    /// Whether a colour ribbon is currently reported. Optimistic until the
    /// printer answers: claiming colour on a black ribbon costs nothing,
    /// because the ImageWriter ignores the colour commands unless a colour
    /// ribbon is installed (manual, chapter 8).
    pub fn colour_ribbon(&self) -> bool {
        self.colour_ribbon
    }

    /// Override the ribbon reading, for a printer that will not answer the
    /// self ID query.
    pub fn set_colour_ribbon(&mut self, colour: bool) {
        self.colour_ribbon = colour;
        self.apply_status();
    }

    /// Report a whole status word, should a path to the live condition bits
    /// appear. Overwrites the ribbon bit along with everything else.
    pub fn set_status_word(&mut self, word: u16) {
        self.colour_ribbon = word & STATUS_COLOUR_RIBBON != 0;
        self.server
            .set_status(&[(word & 0xFF) as u8, (word >> 8) as u8]);
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
    pub fn printer_input(&mut self, data: &[u8], now: Micros) {
        let Ident::Waiting { since, .. } = self.ident else {
            return;
        };
        for &b in data {
            if self.ident_reply.len() < SELF_ID_MAX {
                self.ident_reply.push(b);
            }
        }
        if self.ident_reply.len() >= SELF_ID_MAX {
            self.settle_ident();
        } else {
            self.ident = Ident::Waiting {
                since,
                last: Some(now),
            };
        }
    }

    /// Read the ribbon out of whatever arrived, then stop waiting.
    ///
    /// Only a reply that starts `IW` is believed: at the wrong baud rate, or
    /// from a printer whose option card has taken the serial port, the
    /// buffer holds noise or nothing, and the default must stand rather than
    /// a stray byte deciding the ribbon.
    fn settle_ident(&mut self) {
        if self.ident_reply.starts_with(b"IW") {
            // `C` appears in the reply only as the colour flag: the other
            // letters it can carry are `I`, `W` and `F`.
            self.colour_ribbon = self.ident_reply.contains(&b'C');
            self.apply_status();
        }
        self.ident_reply.clear();
        self.ident = Ident::Settled;
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
        self.poll_ident(now);
    }

    /// Issue or time out the self ID query. Never while a job is open: the
    /// printer would not read the command until it reached that point in the
    /// stream, and the query bytes would sit in the middle of the job.
    fn poll_ident(&mut self, now: Micros) {
        match self.ident {
            Ident::Due if !self.server.busy() => {
                self.ident_reply.clear();
                self.events
                    .push_back(ImageWriterEvent::ToPrinter(SELF_ID.to_vec()));
                self.ident = Ident::Waiting {
                    since: now,
                    last: None,
                };
            }
            Ident::Waiting { since, last } => {
                let finished = last.is_some_and(|t| now.saturating_sub(t) >= SELF_ID_GAP);
                if finished || now.saturating_sub(since) >= SELF_ID_TIMEOUT {
                    self.settle_ident();
                }
            }
            _ => {}
        }
    }

    pub fn next_deadline(&self) -> Option<Micros> {
        let ident = match self.ident {
            Ident::Waiting { since, last } => Some(match last {
                Some(t) => (t + SELF_ID_GAP).min(since + SELF_ID_TIMEOUT),
                None => since + SELF_ID_TIMEOUT,
            }),
            // A query that is due needs a wake-up to go out at all - but
            // only once the printer is idle. While a job is open it is the
            // CloseConn that re-arms it, not the clock, and asking for an
            // immediate wake-up here would spin the caller's event loop for
            // the whole length of the job.
            Ident::Due if !self.server.busy() => Some(0),
            Ident::Due => None,
            Ident::Settled => None,
        };
        match (self.server.next_deadline(), ident) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
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

    fn status_word(role: &ImageWriterRole) -> u16 {
        if role.colour_ribbon() {
            STATUS_COLOUR_RIBBON
        } else {
            0
        }
    }

    #[test]
    fn the_self_id_query_goes_out_once_the_role_is_polled() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        assert_eq!(next_to_printer(&mut role).as_deref(), Some(SELF_ID));

        // And is not repeated while the answer is still outstanding.
        role.poll(1_000);
        assert_eq!(next_to_printer(&mut role), None);
    }

    #[test]
    fn a_colour_ribbon_is_read_out_of_the_reply() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        role.printer_input(b"IW10CF", 100);
        assert!(role.colour_ribbon());
        assert_eq!(status_word(&role), STATUS_COLOUR_RIBBON);
    }

    /// The interesting direction: a black ribbon is the *absence* of `C`, so
    /// it can only be detected by believing a reply that arrived, which is
    /// why a reply that never came must not be read as "no colour".
    #[test]
    fn a_black_ribbon_clears_the_ribbon_bit() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        // No `C`, and no sheet feeder either: the shortest valid reply.
        role.printer_input(b"IW10", 100);
        // Four bytes is under the cap, so it settles once the line goes
        // quiet - well before the give-up timeout.
        role.poll(100 + SELF_ID_GAP);
        assert!(!role.colour_ribbon());
        assert_eq!(status_word(&role), 0);
    }

    #[test]
    fn a_sheet_feeder_alone_is_not_mistaken_for_colour() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        role.printer_input(b"IW10F", 100);
        role.poll(100 + SELF_ID_GAP);
        assert!(!role.colour_ribbon(), "`F` is the feeder, not the ribbon");
    }

    /// The printer answers in its own time - it has a print buffer in front
    /// of the command - so the role must still be listening when the reply
    /// arrives rather than having given up on the first quiet poll.
    #[test]
    fn a_reply_that_takes_a_moment_is_still_read() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        // Polls go by with the line quiet, well short of the give-up point.
        for tick in 1..=5u64 {
            role.poll(tick * SELF_ID_TIMEOUT / 10);
        }
        let arrived = SELF_ID_TIMEOUT / 2;
        role.printer_input(b"IW10", arrived);
        role.poll(arrived + SELF_ID_GAP);
        assert!(!role.colour_ribbon(), "a late answer must still be read");
    }

    /// A printer that says nothing - powered off, option card holding the
    /// serial port, wrong baud rate - must leave the default standing rather
    /// than be read as a black ribbon.
    #[test]
    fn silence_keeps_the_default() {
        let mut role = ImageWriterRole::new(190, 191);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        role.poll(SELF_ID_TIMEOUT);
        assert!(role.colour_ribbon(), "no answer must not clear the bit");
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
    /// arbitrary, and one of them being `C` cannot be allowed to decide.
    #[test]
    fn a_reply_that_is_not_an_imagewriter_id_is_ignored() {
        let mut role = ImageWriterRole::new(190, 191);
        role.set_colour_ribbon(false);
        role.poll(0);
        let _ = next_to_printer(&mut role);

        role.printer_input(&[0xFF, b'C', 0x00, 0xAA, 0x55, 0x13], 100);
        assert!(
            !role.colour_ribbon(),
            "only a reply starting `IW` may change the ribbon"
        );
    }
}
