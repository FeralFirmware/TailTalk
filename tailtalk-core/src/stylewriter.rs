//! The printer side of a StyleWriter's AppleTalk adapter: the role that takes
//! print jobs over ADSP and hands their bytes to a serial StyleWriter.
//! 
//! Most of the knowledge here is from a mixture of lpstyl, my own hacking, and
//! decompiling Apples 1500 and 2500 drivers to see how exactly it did everything
//! and what it all meant.
//! 
//! The adapter can be thought of as a pipe to the printer's serial port reachable
//! as an ADSP socket, with some queuing and commands built around it. Regular data
//! received is interpreted as "send this directly to the printer", and messages meant
//! for the adapter itself (Like what is your name, who is printing, and so on) are
//! handled via ADSP attention codes.
//! 
//! By default the adapter and printer boot up using 57600 baud, but most models support
//! a way to have the adapter be clocked via the HSKi pin which allows it to better saturate
//! the LocalTalk link.

use alloc::vec::Vec;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Micros;
use crate::adsp::{AdspEndpoint, AdspEvent};

/// The NBP type the EtherTalk/LocalTalk adapter will use if it is connected to
/// a 2200, 2400 or 2500 Colour StyleWriter.
pub const NBP_TYPE: &str = "ColorStyleWriter2400AT";

/// The NBP type the other StyleWriters use - this includes the original, II, 1200
/// and 1500.
pub const NBP_TYPE_1200: &str = "StyleWriter1200AT";

// The following are ADSP attention codes that are handled directly by the LocalTalk/
// EtherTalk adapter rather than getting fed to the printer.

/// Send a BREAK to the printer (`SerSetBrk` then `SerClrBrk`). I dont think the original
/// driver sends this, but its a holdover from the QuickDraw LaserWriters which do use it.
pub const ATTN_SEND_BREAK: u16 = 0x0001;
/// Same as above - signifies back towards the Mac that a break was received.
pub const ATTN_BREAK_RECEIVED: u16 = 0x0002;
/// Instructs the adapter to use this serial config when talking to the printer.
pub const ATTN_SERIAL_CONFIG: u16 = 0x0003;
/// The [`ATTN_SERIAL_CONFIG`] word for 57600 baud, 8N1. 
pub const SERIAL_CONFIG_57600: u16 = 0x4C00;
/// Sent by a Mac after it has switched a Color StyleWriter to fast mode with
/// `x`. A payload of 0x40 tells the adapter to clock the port from the
/// printer's HSKi from now on, and 0x00 switches it back to its own clock. The
/// Mac only sends this once its earlier data has been acknowledged, and only if
/// [`ATTN_FAST_CLOCK_QUERY`] said yes. Always answered with 0x0000.
pub const ATTN_SERIAL_OPTIONS: u16 = 0x0004;
/// Asks whether the adapter can follow a Color StyleWriter's fast clock. A low
/// byte of 0 means yes. On anything else the Mac never sends `x` or
/// [`ATTN_SERIAL_OPTIONS`].
pub const ATTN_FAST_CLOCK_QUERY: u16 = 0x0005;
/// Asks whether every byte the Mac has sent has actually been written to the
/// printer. A non-zero low byte means yes. The Mac polls this before every
/// raster band for up to 10 seconds, and treats a printer that stays busy that
/// long as a communication error.
pub const ATTN_OUTPUT_DRAINED: u16 = 0x0006;
/// StyleWriter II and 1200's fast mode enable command, which sets the printer
/// to run at 230,400 baud (without using HSKi like the later models).
/// The Mac first sends 0x0000 to ask whether the adapter supports this mode.
/// If the answer from us is 0x0000, it sends `h` to the
/// printer and then 0x0001, which moves the port to 230,400 baud. On any other
/// answer the printer stays at 57600, and the Mac sets the port back to that
/// speed with [`ATTN_SERIAL_CONFIG`].
pub const ATTN_SERIAL_CONTROL_JF: u16 = 0x0007;
/// Sent with 0x0101 between the two [`ATTN_SERIAL_CONTROL_JF`]s. There is
/// nothing for the adapter's port to do, and it is answered with 0x0000.
pub const ATTN_SERIAL_CONTROL_LOWER_JF: u16 = 0x0008;

/// Asks the adapter to change its name broadcasted via NBP. Name is passed as a Pascal string.
pub const ATTN_SET_NAME: u16 = 0x0009;
/// Asks the adapter to set the status message that other Macs can query to see 
/// what it is currently up to. It starts with a u16 which is the STR# resource num,
/// then a human readable message padded to 257 bytes.
pub const ATTN_SET_STATUS: u16 = 0x000A;
/// Request by a Mac to start a new print job. This takes the following args:
/// 
/// Bytes:
/// 0 - 3: socket number
/// 4 - 36: The user's name as a 32 character Pascal string.
/// 37 - 69: Padding? I honestly dont know why its padded out this much.
/// 
/// Note that only the socket number is explicitly required. The rest can be whatever, its
/// really just for Macs. The only note is that a job withdrawal must repeat the same data.
pub const ATTN_PRINT_REQUEST: u16 = 0x000B;
/// Asks the adapter to drop a queued print request. This is matched by the request blob 
/// sent in [`ATTN_PRINT_REQUEST`].
pub const ATTN_WITHDRAW: u16 = 0x000C;
/// Where the client is in the queue, returned as a u16 value where 1 is "You are next".
pub const ATTN_QUEUE_POSITION: u16 = 0x000D;
/// Who we are currently processing a job for. Returns the blob sent in [`ATTN_PRINT_REQUEST`]
/// if we are processing for anyone.
pub const ATTN_JOB_USER: u16 = 0x000E;
/// Returns the status (if any) previously set by [`ATTN_SET_STATUS`].
pub const ATTN_JOB_STATUS: u16 = 0x0010;
/// The number of pending jobs in our queue as a u16. If a Mac is waiting for its job to be
/// printed and this query returns 0 it will consider that the job was dropped.
pub const ATTN_JOB_COUNT: u16 = 0x0011;
/// Ends the current session.
pub const ATTN_END_SESSION: u16 = 0x0012;

/// Mac sized value for [`ATTN_PRINT_REQUEST`]. We could probably make this bigger but Macs
/// seem to get upsetti spaghetti if we deviate from it.
pub const PRINT_REQUEST_LEN: usize = 70;
/// The max name length as part of the print request above.
pub const USER_NAME_MAX: usize = 32;

/// The length of a status set request [`ATTN_SET_STATUS`] payload or a
/// [`ATTN_JOB_STATUS`] reply.
pub const JOB_STATUS_TEXT_LEN: usize = 255;

const RESULT_ACCEPTED: [u8; 2] = [0x00, 0x00];
const RESULT_BUSY: [u8; 2] = [0x00, 0x01];
/// The answer to a print request that cannot be called back, such as one too
/// short to name a socket. Any result but 0x0000 turns the Mac away.
const RESULT_REJECTED: [u8; 2] = [0xFF, 0xFF];

const OUTPUT_DRAINED: [u8; 2] = [0xFF, 0xFF];
const OUTPUT_PENDING: [u8; 2] = [0x00, 0x00];

/// If an adapter is unable to be externally clocked this is what it should
/// return so a Mac does not try and enable it.
const FAST_CLOCK_UNAVAILABLE: [u8; 2] = [0x00, 0xEF];

/// The answer to [`ATTN_SERIAL_CONTROL_JF`] from a port that cannot run at
/// 230,400 baud, so the Mac keeps a StyleWriter II or 1200 at 57600.
const SERIAL_CONTROL_REFUSED: [u8; 2] = (-17i16).to_be_bytes();

/// Puts the printer back in to a known state, including ejecting paper if 
/// still present in its feed. This can also pull the printer out of fast mode
/// if enabled and we are not aware (i.e power cycled).
pub const PRINTER_RESET: &[u8] = &[0x00, 0xFF, 0xFF, 0xFF, QUERY_RESET];

/// Puts a Colour StyleWriter into its fast mode, where it clocks the link on
/// HSKi.
pub const FAST_CLOCK: u8 = b'x';

/// Puts a StyleWriter II or 1200 into its fast mode, 230,400 baud.
pub const FAST_CLOCK_SW: u8 = b'h';

/// [`ATTN_SERIAL_OPTIONS`] bit: clock the port from the printer's HSKi.
pub const SERIAL_EXTERNAL_CLOCK: u8 = 0x40;

/// Allows an adapter implementation to decide if it does or does not support
/// the printers' fast modes, which are following a Colour StyleWriter's clock on
/// HSKi and running a StyleWriter II or 1200 at 230,400 baud. If [`FastClock::Supported`]
/// is chosen, [`StyleWriterEvent::PortClock`] will be passed on the event handler
/// to instruct the adapter when it should reconfigure its UART.
///
/// If [`FastClock::Unsupported`] is chosen these events will not occur and we
/// will report back to the Mac to not attempt either fast mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastClock {
    Supported,
    Unsupported,
}

/// What clocks the adapter's printer port. Every printer starts at
/// [`PortClock::Normal`], and a job can move it into the printer's fast mode
/// and back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortClock {
    /// The printer's usual 57600 baud, 8N1, on the port's own clock.
    Normal,
    /// A Colour StyleWriter's fast mode, where the printer drives a bit clock on
    /// HSKi, one clock per bit, and both directions keep to 8N1 framing on it.
    PrinterHski,
    /// A StyleWriter II or 1200's fast mode, which is 230,400 baud, 8N1, on the
    /// port's own clock.
    Baud230400,
}

/// The identify command. The printer answers with its model string,
/// terminated by a carriage return.
pub const IDENTIFY: u8 = b'?';

/// Status queries, sent as `FF FF FF <q>` and each answered with one byte.
/// See [`status1`] and [`status2`] for what the bits mean.
pub const QUERY_STATUS: u8 = b'1';
/// Error status. See [`status2`] for what the bits mean.
pub const QUERY_ERROR: u8 = b'2';
/// Free space in the printer's buffer, counted in 256-byte units (64-byte
/// units on an original StyleWriter) less 2 KB, so it reads highest when
/// empty.
pub const QUERY_BUFFER: u8 = b'B';
/// Asks the printer what cartridge it has installed. 0x01 is a black cartridge,
/// 0x80 is a colour cartridge, and 0x81 is both.
pub const QUERY_CARTRIDGE: u8 = b'H';
/// Status query only used on a 2200, 2400 or 2500 with the black cartridge in. When
/// printing a black and white page at Best quality on plain paper or transparencies, a Mac
/// asks for this and sends `N` if it is below [`QUERY_R_FINE_LIMIT`], or `s` otherwise.
/// Grayscale pages always get `s`. A reply of 0 means the printer has no reading.
pub const QUERY_R: u8 = b'R';
/// See [`QUERY_R`].
pub const QUERY_R_FINE_LIMIT: u8 = 0x7E;
/// Asks the printer to reset itself. There is no reply.
pub const QUERY_RESET: u8 = b'I';
/// Asks the printer to resume a job after it hit an error, like a paper jam or
/// an out of paper error. There is no reply.
pub const QUERY_RESUME: u8 = b'S';

/// Bits in the reply to [`QUERY_STATUS`].
pub mod status1 {
    /// The printer is busy, such as just after a reset or while it cleans.
    pub const BUSY: u8 = 0x01;
    /// Something is wrong with the printer. The original, II, 1200 and 1500
    /// don't say what, and clear it on their own.
    pub const PRINTER_ERROR: u8 = 0x02;
    /// Hardware error - usually something blocking the cartridge carriage.
    pub const HARDWARE_ERROR: u8 = 0x04;
    /// Everything sent so far has been printed.
    pub const PRINTED: u8 = 0x08;
    pub const DOOR_OPEN: u8 = 0x40;
    pub const WASTE_INK_FULL: u8 = 0x80;
}

/// Bits in the reply to [`QUERY_ERROR`]. Sending [`QUERY_RESUME`] clears all of
/// them apart from out of paper.
pub mod status2 {
    pub const CARTRIDGE_JAMMED: u8 = 0x01;
    /// An ink tank or the cartridge needs replacing. Only the 2200, 2400 and 2500
    /// mean this - the original, II, 1200 and 1500 set it without saying why.
    pub const INK_OUT: u8 = 0x02;
    /// Out of paper. The original StyleWriter also needs its Ready button pressed
    /// once paper is loaded.
    pub const OUT_OF_PAPER: u8 = 0x04;
    pub const PAPER_JAM: u8 = 0x08;
    /// Something is wrong with the printer, often a loose connection.
    pub const PRINTER_ERROR: u8 = 0x10;
    /// The cartridge is missing or not seated properly.
    pub const CARTRIDGE_MISSING: u8 = 0x20;
    /// The paper is smaller than the page being printed.
    pub const PAPER_TOO_SMALL: u8 = 0x40;
    /// Another printer error bit, handled the same as [`PRINTER_ERROR`]. 2400s and
    /// 2500s have been seen setting this with nothing wrong.
    pub const PRINTER_ERROR_HIGH: u8 = 0x80;
}

/// Color StyleWriter submodel. Only ask a printer that identified as
/// [`COLOR_FAMILY`]: a StyleWriter given a code it does not know ejects the
/// page and resets.
pub const QUERY_SUBMODEL: u8 = b'p';

/// The identify string every Color StyleWriter (1500, 2200, 2400, 2500)
/// shares; [`QUERY_SUBMODEL`] tells them apart.
pub const COLOR_FAMILY: &[u8] = b"CS";

/// The bytes of status query `q`.
pub const fn status_query(q: u8) -> [u8; 4] {
    [0xFF, 0xFF, 0xFF, q]
}

/// Which Colour StyleWriter a "CS" printer is, going by its [`QUERY_SUBMODEL`] reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorModel {
    Cs1500,
    Cs2200,
    Cs2400,
    Cs2500,
    /// No reply to [`QUERY_SUBMODEL`], or a value we don't recognise.
    Unknown,
}

impl ColorModel {
    pub fn from_submodel(submodel: Option<u8>) -> Self {
        match submodel {
            Some(0x01) => ColorModel::Cs2400,
            Some(0x02) => ColorModel::Cs2200,
            Some(0x04) => ColorModel::Cs1500,
            Some(0x05) => ColorModel::Cs2500,
            _ => ColorModel::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ColorModel::Cs1500 => "Apple Color StyleWriter 1500",
            ColorModel::Cs2200 => "Apple Color StyleWriter 2200",
            ColorModel::Cs2400 => "Apple Color StyleWriter 2400",
            ColorModel::Cs2500 => "Apple Color StyleWriter 2500",
            ColorModel::Unknown => "Apple Color StyleWriter",
        }
    }
}

/// The model name for an identify string, using the [`QUERY_SUBMODEL`] reply for
/// Colour StyleWriters. Returns `None` if we don't recognise the string.
pub fn model_name(identity: &[u8], submodel: Option<u8>) -> Option<&'static str> {
    Some(match identity {
        b"IJ10" => "Apple StyleWriter",
        b"SW" => "Apple StyleWriter II",
        b"SW3" => "Apple StyleWriter 1200",
        COLOR_FAMILY => ColorModel::from_submodel(submodel).name(),
        _ => return None,
    })
}

/// The NBP type the adapter should register under for the printer it found. The
/// original, II, 1200 and 1500 get [`NBP_TYPE_1200`], and everything else gets
/// [`NBP_TYPE`], including a printer that never answered.
pub fn nbp_type_for(identity: &[u8], submodel: Option<u8>) -> &'static str {
    match identity {
        b"IJ10" | b"SW" | b"SW3" => NBP_TYPE_1200,
        COLOR_FAMILY if ColorModel::from_submodel(submodel) == ColorModel::Cs1500 => NBP_TYPE_1200,
        _ => NBP_TYPE,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StyleWriterEvent {
    /// A job was accepted; the user name is the raw Pascal-string bytes from
    /// the print request (MacRoman, informational only).
    JobStarted { user: Vec<u8> },
    /// Bytes for the printer UART.
    ToPrinter(Vec<u8>),
    /// The job ended. `clean` is true if the Mac ended it properly, and false if
    /// the client vanished - in that case a reset has already been queued as a
    /// `ToPrinter` event.
    JobEnded { clean: bool },
    /// The client committed a new NBP name, as raw MacRoman bytes. The
    /// embedder owns what happens next: re-register under it, and persist it
    /// if the hardware has somewhere to put it. A real adapter keeps the name
    /// across a power cycle and re-registers itself, so a client looking the
    /// printer up shortly afterwards expects to find the new name.
    Rename(Vec<u8>),
    /// From here on, run the printer port on this clock. A fast mode comes after
    /// the bytes that switched the printer into it. [`PortClock::Normal`] comes
    /// when the client switches the fast mode off or the job ends, after any
    /// bytes the printer still has to hear at its fast speed, such as the reset
    /// for a client that vanished. Only with [`FastClock::Supported`].
    PortClock(PortClock),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    /// Accepted a print request on this control connection, and waiting for the
    /// Mac to close it before calling back.
    AwaitingCtrlClose {
        ctrl: u16,
        mac_node: ServiceAddress,
        data_socket: u8,
    },
    /// Reverse connection in flight.
    Connecting {
        conn: u16,
    },
    /// Byte pipe active on this data connection.
    Piping {
        conn: u16,
        kill_seen: bool,
    },
}

/// How long a half-finished handshake may sit before the role gives up and
/// makes itself available again.
///
/// A healthy client reads the two-byte accept and closes the control
/// connection straight away, and the role calls back at once. A client that
/// dies in between, or whose close never reaches us, would otherwise pin
/// the role in a non-idle state forever, and every later print request gets
/// answered "busy" by a printer that is doing nothing at all. Generous
/// enough to cover the ADSP open retry budget on the reverse connection.
const HANDSHAKE_TIMEOUT_US: Micros = 15_000_000;

pub struct StyleWriterRole {
    endpoint: AdspEndpoint,
    state: State,
    /// When the current state was entered, for [`HANDSHAKE_TIMEOUT_US`].
    /// Only consulted in the handshake states; a live byte pipe has no
    /// deadline of its own and ends when the connection does.
    state_since: Micros,
    events: alloc::collections::VecDeque<StyleWriterEvent>,
    /// Name staged by [`ATTN_SET_NAME`] and the connection it came on. Only
    /// that connection's [`ATTN_END_SESSION`] publishes it, and it is
    /// dropped if that connection closes first.
    pending_name: Option<(u16, Vec<u8>)>,
    /// The accepted print request as the Mac sent it, zero padded, for
    /// [`ATTN_JOB_USER`] and to recognise its [`ATTN_WITHDRAW`]. Only
    /// meaningful while [`Self::busy`].
    job_request: [u8; PRINT_REQUEST_LEN],
    /// The message ID and text from the job's last [`ATTN_SET_STATUS`], for
    /// [`ATTN_JOB_STATUS`].
    job_status_id: u16,
    job_status: Vec<u8>,
    /// Whether every byte of the job so far has gone out to the printer, for
    /// [`ATTN_OUTPUT_DRAINED`]. The embedder keeps it current with
    /// [`Self::set_printer_drained`].
    printer_drained: bool,
    /// Whether the next data packet starts an ADSP message, i.e. the last
    /// one ended with EOM. The fast mode switches only count as whole
    /// messages, never as bytes inside raster data.
    data_msg_start: bool,
    fast_clock: FastClock,
    /// The clock the port has been told to run on.
    port_clock: PortClock,
}

impl StyleWriterRole {
    pub fn new(control_socket: u8, seed: u32, fast_clock: FastClock) -> Self {
        let mut endpoint = AdspEndpoint::new(control_socket, seed);
        endpoint.set_listening(true);
        Self {
            endpoint,
            state: State::Idle,
            state_since: 0,
            events: alloc::collections::VecDeque::new(),
            pending_name: None,
            job_request: [0; PRINT_REQUEST_LEN],
            job_status_id: 0,
            job_status: Vec::new(),
            printer_drained: true,
            data_msg_start: true,
            fast_clock,
            port_clock: PortClock::Normal,
        }
    }

    /// Tell the embedder to switch the port's clock, if that changes it.
    fn set_port_clock(&mut self, clock: PortClock) {
        if clock != self.port_clock {
            self.port_clock = clock;
            self.events.push_back(StyleWriterEvent::PortClock(clock));
        }
    }

    /// Switch the port's clock for a request on `conn`. The port belongs to
    /// the job in hand, so only its data connection can move it. The same
    /// request from any other connection is answered as usual and changes
    /// nothing.
    fn set_port_clock_for(&mut self, conn: u16, clock: PortClock) {
        if matches!(self.state, State::Piping { conn: dc, .. } if dc == conn) {
            self.set_port_clock(clock);
        }
    }

    /// The [`ATTN_JOB_USER`] reply. This is the current job's 70-byte print
    /// request followed by a 0x0000 result, with the request all zero when no
    /// job is active.
    fn job_user_reply(&self) -> Vec<u8> {
        let mut reply = if self.busy() {
            self.job_request.to_vec()
        } else {
            alloc::vec![0; PRINT_REQUEST_LEN]
        };
        reply.extend_from_slice(&RESULT_ACCEPTED);
        reply
    }

    /// The [`ATTN_JOB_STATUS`] reply. This is the status message ID, the text
    /// as a Pascal string zero padded to 255 bytes, then a 0x0000 result. The
    /// ID and text are empty when no job is active or the Mac has not set one.
    fn job_status_reply(&self) -> Vec<u8> {
        let (id, text): (u16, &[u8]) = if self.busy() {
            (self.job_status_id, &self.job_status)
        } else {
            (0, &[])
        };
        let mut reply = id.to_be_bytes().to_vec();
        reply.push(text.len() as u8);
        reply.extend_from_slice(text);
        reply.resize(2 + JOB_STATUS_TEXT_LEN, 0);
        reply.extend_from_slice(&RESULT_ACCEPTED);
        reply
    }

    /// Enter `state`, restarting the handshake timeout.
    fn enter(&mut self, state: State, now: Micros) {
        self.state = state;
        self.state_since = now;
    }

    pub fn control_socket(&self) -> u8 {
        self.endpoint.local_socket()
    }

    /// Whether a job is active (used to answer competing print requests
    /// with "busy").
    pub fn busy(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// Advertise how many bytes the printer sink (UART TX ring) can absorb.
    /// This becomes the ADSP receive window: it shrinks toward zero instead
    /// of data being dropped, which is InkTalk's only flow control.
    pub fn set_printer_credit(&mut self, bytes: usize) {
        self.endpoint
            .set_recv_window(bytes.min(u16::MAX as usize) as u16);
    }

    /// Tells the role whether every byte of the job so far has actually been
    /// written to the printer. This is what we answer [`ATTN_OUTPUT_DRAINED`]
    /// with. Defaults to true.
    pub fn set_printer_drained(&mut self, drained: bool) {
        self.printer_drained = drained;
    }

    /// Bytes the printer produced (UART RX): forward down the data pipe.
    /// Silently dropped when no job is active, like a real printer's chatter
    /// after its host vanished.
    pub fn printer_input(&mut self, data: &[u8]) {
        if let State::Piping { conn, .. } = self.state {
            let _ = self.endpoint.send(conn, data, false);
        }
    }

    /// Backlog of bytes queued toward the Mac; callers pacing printer reads
    /// can consult this.
    pub fn tx_backlog(&self) -> usize {
        match self.state {
            State::Piping { conn, .. } => self.endpoint.tx_backlog(conn),
            _ => 0,
        }
    }

    pub fn handle_datagram(&mut self, src: ServiceAddress, payload: &[u8], now: Micros) {
        self.endpoint.handle_datagram(src, payload, now);
        self.drain_endpoint(now);
    }

    pub fn poll(&mut self, now: Micros) {
        self.endpoint.poll(now);
        self.drain_endpoint(now);
        self.expire_stalled_handshake(now);
    }

    /// Release the role if a handshake stalled part-way through. Without
    /// this the printer answers every later request "busy" while idle.
    fn expire_stalled_handshake(&mut self, now: Micros) {
        let stalled = matches!(
            self.state,
            State::AwaitingCtrlClose { .. } | State::Connecting { .. }
        ) && now.saturating_sub(self.state_since) > HANDSHAKE_TIMEOUT_US;
        if stalled {
            self.events
                .push_back(StyleWriterEvent::JobEnded { clean: false });
            self.enter(State::Idle, now);
        }
    }

    pub fn next_deadline(&self) -> Option<Micros> {
        let handshake = matches!(
            self.state,
            State::AwaitingCtrlClose { .. } | State::Connecting { .. }
        )
        .then(|| self.state_since + HANDSHAKE_TIMEOUT_US);
        match (self.endpoint.next_deadline(), handshake) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Outgoing DDP payloads `(dest, adsp bytes)`, to send from the control
    /// socket with DDP type ADSP.
    pub fn poll_transmit(&mut self) -> Option<(ServiceAddress, Vec<u8>)> {
        self.endpoint.poll_transmit()
    }

    pub fn poll_event(&mut self) -> Option<StyleWriterEvent> {
        self.events.pop_front()
    }

    fn drain_endpoint(&mut self, now: Micros) {
        while let Some(ev) = self.endpoint.poll_event() {
            self.handle_adsp_event(ev, now);
        }
    }

    fn handle_adsp_event(&mut self, ev: AdspEvent, now: Micros) {
        match ev {
            AdspEvent::Opened { conn, inbound, .. } => {
                // A printer role has at most one outbound connect in flight, so
                // any completing outbound connection is the data pipe it called
                // back on. Inbound ones are control connections, and there is
                // nothing to do until their print-request attention arrives.
                //
                // Piping is accepted here as well as Connecting. The endpoint
                // re-announces the pipe if the peer answered a retransmitted
                // open with a second connection and moved to it, and latching
                // onto the new key is the whole point of that notification.
                if !inbound && matches!(self.state, State::Connecting { .. } | State::Piping { .. })
                {
                    self.data_msg_start = true;
                    self.enter(
                        State::Piping {
                            conn,
                            kill_seen: false,
                        },
                        now,
                    );
                }
            }
            AdspEvent::Attention { conn, code, data } => {
                self.handle_attention(conn, code, &data, now);
            }
            AdspEvent::Data { conn, data, eom } => {
                if let State::Piping { conn: dc, .. } = self.state
                    && conn == dc
                    && !data.is_empty()
                {
                    let whole_message = self.data_msg_start && eom;
                    self.data_msg_start = eom;
                    let fast_mode_switch = data == [FAST_CLOCK] || data == [FAST_CLOCK_SW];
                    if whole_message && fast_mode_switch && self.fast_clock == FastClock::Unsupported {
                        return;
                    }
                    self.events.push_back(StyleWriterEvent::ToPrinter(data));
                }
            }
            AdspEvent::Closed { conn } => {
                if self.pending_name.as_ref().is_some_and(|(c, _)| *c == conn) {
                    self.pending_name = None;
                }
                match self.state {
                    State::AwaitingCtrlClose {
                        ctrl,
                        mac_node,
                        data_socket,
                    } if conn == ctrl => {
                        let dest = ServiceAddress {
                            network_number: mac_node.network_number,
                            node_number: mac_node.node_number,
                            socket_number: data_socket,
                        };
                        let pending = self.endpoint.connect(dest, now);
                        self.enter(State::Connecting { conn: pending }, now);
                    }
                    State::Piping {
                        conn: dc,
                        kill_seen,
                    } if conn == dc => {
                        if !kill_seen {
                            // Client vanished mid-job: eject and reset so paper
                            // is not left in the feed path.
                            self.events
                                .push_back(StyleWriterEvent::ToPrinter(PRINTER_RESET.to_vec()));
                        }
                        self.set_port_clock(PortClock::Normal);
                        self.events
                            .push_back(StyleWriterEvent::JobEnded { clean: kill_seen });
                        self.enter(State::Idle, now);
                    }
                    _ => {}
                }
            }
            AdspEvent::AttentionAcked { .. } | AdspEvent::AttentionFailed { .. } => {
                // The printer role only ever answers attentions, in band;
                // it sends none of its own, so neither outcome concerns it.
            }
            AdspEvent::OpenFailed { conn } => {
                if matches!(self.state, State::Connecting { conn: c } if c == conn) {
                    // Could not dial back; the job never started.
                    self.enter(State::Idle, now);
                }
            }
        }
    }

    fn handle_attention(&mut self, conn: u16, code: u16, data: &[u8], now: Micros) {
        match code {
            ATTN_PRINT_REQUEST => {
                // Two zero bytes, a zero byte and the data socket, then the
                // user name as a Pascal string, zero padded to 70 bytes.
                if data.len() < 5 {
                    let _ = self.endpoint.send(conn, &RESULT_REJECTED, false);
                    return;
                }
                if self.busy() {
                    let _ = self.endpoint.send(conn, &RESULT_BUSY, false);
                    return;
                }
                let data_socket = data[3];
                let name_len = (data[4] as usize).min(USER_NAME_MAX).min(data.len() - 5);
                let user = data[5..5 + name_len].to_vec();

                // We do not know the Mac's address from the attention alone;
                // AdspEvent::Opened carried it. Look it up from the
                // connection the attention arrived on.
                let Some(remote) = self.endpoint.remote_of(conn) else {
                    let _ = self.endpoint.send(conn, &RESULT_REJECTED, false);
                    return;
                };

                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                self.job_request = print_request_block(data);
                self.job_status_id = 0;
                self.job_status.clear();
                self.enter(
                    State::AwaitingCtrlClose {
                        ctrl: conn,
                        mac_node: remote,
                        data_socket,
                    },
                    now,
                );
                self.events.push_back(StyleWriterEvent::JobStarted { user });
            }
            ATTN_WITHDRAW => {
                // Only a job still waiting to be called back can be withdrawn,
                // as it has not reached the printer yet.
                let waiting = match self.state {
                    State::AwaitingCtrlClose { .. } => None,
                    State::Connecting { conn: pending } => Some(pending),
                    State::Idle | State::Piping { .. } => {
                        let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                        return;
                    }
                };
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                if print_request_block(data) == self.job_request {
                    if let Some(pending) = waiting {
                        self.endpoint.abandon_open(pending);
                    }
                    self.events
                        .push_back(StyleWriterEvent::JobEnded { clean: true });
                    self.enter(State::Idle, now);
                }
            }
            ATTN_OUTPUT_DRAINED => {
                let reply = if self.printer_drained {
                    OUTPUT_DRAINED
                } else {
                    OUTPUT_PENDING
                };
                let _ = self.endpoint.send(conn, &reply, false);
            }
            ATTN_END_SESSION => {
                // On the data connection this ends the job. On any other
                // connection it ends whatever exchange was made there.
                if let State::Piping { conn: dc, .. } = self.state
                    && conn == dc
                {
                    // The Mac discards the two reply bytes. Then expect it to
                    // close.
                    let _ = self.endpoint.send(conn, &[0xFF, 0xFF], false);
                    self.enter(
                        State::Piping {
                            conn: dc,
                            kill_seen: true,
                        },
                        now,
                    );
                } else {
                    // Publish whatever SET_NAME staged on this connection.
                    // A session with nothing staged is still answered,
                    // because the client waits on the reply either way.
                    if self.pending_name.as_ref().is_some_and(|(c, _)| *c == conn)
                        && let Some((_, name)) = self.pending_name.take()
                    {
                        self.events.push_back(StyleWriterEvent::Rename(name));
                    }
                    let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                }
            }
            ATTN_JOB_COUNT => {
                let count = u16::from(self.busy());
                let _ = self.endpoint.send(conn, &count.to_be_bytes(), false);
            }
            ATTN_QUEUE_POSITION => {
                // There is no queue behind the job in hand, so a Mac waiting
                // on it is next.
                let position = u16::from(self.busy());
                let _ = self.endpoint.send(conn, &position.to_be_bytes(), false);
            }
            ATTN_FAST_CLOCK_QUERY => {
                let reply = match self.fast_clock {
                    FastClock::Supported => RESULT_ACCEPTED,
                    FastClock::Unsupported => FAST_CLOCK_UNAVAILABLE,
                };
                let _ = self.endpoint.send(conn, &reply, false);
            }
            ATTN_SERIAL_OPTIONS => {
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                if self.fast_clock == FastClock::Supported {
                    let external = data.first().is_some_and(|o| o & SERIAL_EXTERNAL_CLOCK != 0);
                    self.set_port_clock_for(conn, if external { PortClock::PrinterHski } else { PortClock::Normal });
                }
            }
            ATTN_SET_STATUS => {
                // A u16 message ID, then the text as a Pascal string, kept to
                // what fits the 255-byte field of the ATTN_JOB_STATUS reply.
                if let Some(&len) = data.get(2) {
                    self.job_status_id = u16::from_be_bytes([data[0], data[1]]);
                    let text = &data[3..];
                    let len = (len as usize).min(text.len()).min(JOB_STATUS_TEXT_LEN - 1);
                    self.job_status = text[..len].to_vec();
                }
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
            ATTN_JOB_USER => {
                let reply = self.job_user_reply();
                let _ = self.endpoint.send(conn, &reply, false);
            }
            ATTN_JOB_STATUS => {
                let reply = self.job_status_reply();
                let _ = self.endpoint.send(conn, &reply, false);
            }
            ATTN_SET_NAME => {
                // A Pascal string of one length byte, then MacRoman bytes. It
                // is staged rather than published, because the client only
                // treats the rename as done once its session ends.
                if let Some(&len) = data.first()
                    && len > 0
                    && data.len() > len as usize
                {
                    self.pending_name = Some((conn, data[1..1 + len as usize].to_vec()));
                }
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
            ATTN_SERIAL_CONTROL_JF => match self.fast_clock {
                FastClock::Supported => {
                    let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                    let fast = data.get(..2).is_some_and(|arg| arg != [0, 0]);
                    self.set_port_clock_for(conn, if fast { PortClock::Baud230400 } else { PortClock::Normal });
                }
                FastClock::Unsupported => {
                    let _ = self.endpoint.send(conn, &SERIAL_CONTROL_REFUSED, false);
                }
            },
            ATTN_SERIAL_CONFIG => {
                // Only ever the printer's usual 57600 baud, which the port
                // runs at whenever the printer is out of its fast mode.
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                self.set_port_clock_for(conn, PortClock::Normal);
            }
            ATTN_SEND_BREAK | ATTN_BREAK_RECEIVED | ATTN_SERIAL_CONTROL_LOWER_JF => {
                // Nothing for the port to do. For ATTN_BREAK_RECEIVED, 0x0000
                // means no break has arrived.
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
            _ => {
                // Every attention is followed by a read of an in-band reply,
                // and the Mac hangs for good if none comes. A guessed 0x0000
                // fails visibly instead, and the code is in the RX log.
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
        }
    }
}

/// A print request as kept for [`ATTN_JOB_USER`], which is its first 70 bytes,
/// zero padded.
fn print_request_block(data: &[u8]) -> [u8; PRINT_REQUEST_LEN] {
    let mut block = [0; PRINT_REQUEST_LEN];
    let n = data.len().min(PRINT_REQUEST_LEN);
    block[..n].copy_from_slice(&data[..n]);
    block
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adsp::AdspEndpoint;
    use tailtalk_packets::nbp::ServiceAddress;

    fn addr(node: u8, socket: u8) -> ServiceAddress {
        ServiceAddress {
            network_number: 0,
            node_number: node,
            socket_number: socket,
        }
    }

    /// Move traffic between the role (printer, node 130 socket 129) and a
    /// raw client endpoint (Mac, node 10) until quiescent.
    fn shuttle(
        role: &mut StyleWriterRole,
        mac: &mut AdspEndpoint,
        mac_ctrl: ServiceAddress,
        now: Micros,
    ) {
        let printer = addr(130, role.control_socket());
        loop {
            let mut progressed = false;
            while let Some((dest, payload)) = role.poll_transmit() {
                assert_eq!(dest.node_number, 10);
                // The Mac endpoint owns every socket on node 10 in this
                // harness, both the control client and the data listener.
                let _ = dest;
                mac.handle_datagram(printer, &payload, now);
                progressed = true;
            }
            while let Some((dest, payload)) = mac.poll_transmit() {
                assert_eq!(dest.node_number, 130);
                role.handle_datagram(mac_ctrl, &payload, now);
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
    }

    fn print_request(data_socket: u8, user: &[u8]) -> Vec<u8> {
        let mut p = Vec::with_capacity(70);
        p.extend_from_slice(&(data_socket as u32).to_be_bytes());
        p.push(user.len() as u8);
        p.extend_from_slice(user);
        p.resize(70, 0);
        p
    }

    /// Open a control connection from the Mac side, returning its handle.
    fn open_control(
        role: &mut StyleWriterRole,
        mac: &mut AdspEndpoint,
        mac_addr: ServiceAddress,
    ) -> u16 {
        let _ = mac.connect(addr(130, 129), 0);
        shuttle(role, mac, mac_addr, 0);
        match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("expected ctrl Opened, got {other:?}"),
        }
    }

    /// The next in-band data the Mac sees on `want`.
    fn in_band(mac: &mut AdspEndpoint, want: u16) -> Vec<u8> {
        loop {
            match mac.poll_event() {
                Some(AdspEvent::Data { conn, data, .. }) if conn == want => break data,
                Some(_) => continue,
                None => panic!("no in-band reply"),
            }
        }
    }

    fn pascal(name: &[u8]) -> Vec<u8> {
        let mut v = alloc::vec![name.len() as u8];
        v.extend_from_slice(name);
        v
    }

    fn role_events(role: &mut StyleWriterRole) -> Vec<StyleWriterEvent> {
        core::iter::from_fn(|| role.poll_event()).collect()
    }

    #[test]
    fn identify_strings_name_the_model_and_its_nbp_type() {
        for (identity, submodel, name, nbp_type) in [
            (&b"IJ10"[..], None, Some("Apple StyleWriter"), NBP_TYPE_1200),
            (b"SW", None, Some("Apple StyleWriter II"), NBP_TYPE_1200),
            (b"SW3", None, Some("Apple StyleWriter 1200"), NBP_TYPE_1200),
            (b"CS", Some(0x04), Some("Apple Color StyleWriter 1500"), NBP_TYPE_1200),
            (b"CS", Some(0x02), Some("Apple Color StyleWriter 2200"), NBP_TYPE),
            (b"CS", Some(0x01), Some("Apple Color StyleWriter 2400"), NBP_TYPE),
            (b"CS", Some(0x05), Some("Apple Color StyleWriter 2500"), NBP_TYPE),
            (b"CS", None, Some("Apple Color StyleWriter"), NBP_TYPE),
            (b"XY", None, None, NBP_TYPE),
        ] {
            assert_eq!(model_name(identity, submodel), name, "{identity:?} {submodel:?}");
            assert_eq!(nbp_type_for(identity, submodel), nbp_type, "{identity:?} {submodel:?}");
        }
    }

    /// A rename takes three attentions, which are the job count, the new name
    /// and then the end of the session, each answered in band. The name is only
    /// published by the end of the session on the connection that sent it, so
    /// one left behind by a client that went away is never published.
    #[test]
    fn a_rename_is_published_only_by_its_own_session_end() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);
        let ctrl = open_control(&mut role, &mut mac, mac_addr);

        let mut now = 100;
        for (code, payload) in [
            (ATTN_JOB_COUNT, alloc::vec![0x00]),
            (ATTN_SET_NAME, pascal(b"Inky")),
            (ATTN_END_SESSION, alloc::vec![0x00]),
        ] {
            mac.send_attention(ctrl, code, &payload, now).unwrap();
            shuttle(&mut role, &mut mac, mac_addr, now);
            assert_eq!(
                in_band(&mut mac, ctrl),
                alloc::vec![0x00, 0x00],
                "{code:#06x} must be answered"
            );
            now += 100;
        }
        assert_eq!(
            role_events(&mut role),
            alloc::vec![StyleWriterEvent::Rename(b"Inky".to_vec())]
        );

        let staged = open_control(&mut role, &mut mac, mac_addr);
        mac.send_attention(staged, ATTN_SET_NAME, &pascal(b"Never"), 400)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 400);
        assert_eq!(in_band(&mut mac, staged), [0x00, 0x00]);
        mac.close(staged);
        shuttle(&mut role, &mut mac, mac_addr, 500);

        let next = open_control(&mut role, &mut mac, mac_addr);
        mac.send_attention(next, ATTN_END_SESSION, &[0x00], 600)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 600);
        assert_eq!(in_band(&mut mac, next), [0x00, 0x00]);
        assert!(role_events(&mut role).is_empty(), "an abandoned name is never published");
    }

    /// A print request too short to name a socket is refused, as the Mac waits
    /// for a reply to every attention. In a full one the user name field holds
    /// 32 characters, and anything past that belongs to the second string.
    #[test]
    fn print_requests_are_read_within_their_fields() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);
        let ctrl = open_control(&mut role, &mut mac, mac_addr);

        mac.send_attention(ctrl, ATTN_PRINT_REQUEST, &[0x00, 0x00, 0x00, 70], 100)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);
        assert_eq!(in_band(&mut mac, ctrl), [0xFF, 0xFF]);
        assert!(!role.busy());

        let mut request = alloc::vec![0, 0, 0, 70, 40];
        request.extend_from_slice(&[b'u'; 40]);
        request.resize(70, 0);
        mac.send_attention(ctrl, ATTN_PRINT_REQUEST, &request, 200)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 200);
        assert_eq!(in_band(&mut mac, ctrl), [0x00, 0x00]);
        assert_eq!(
            role.poll_event(),
            Some(StyleWriterEvent::JobStarted { user: alloc::vec![b'u'; USER_NAME_MAX] })
        );
    }

    #[test]
    fn full_handshake_and_byte_pipe() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42, FastClock::Unsupported);
        // One endpoint on the Mac side plays both the control client and
        // the data listener (both live on node 10).
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);

        let printer = addr(130, 129);
        let ctrl = mac.connect(printer, 0);
        shuttle(&mut role, &mut mac, mac_addr, 0);
        let ctrl_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("expected ctrl Opened, got {other:?}"),
        };
        let _ = ctrl;

        // Its print request names data socket 70, on the same endpoint here.
        mac.send_attention(
            ctrl_conn,
            ATTN_PRINT_REQUEST,
            &print_request(70, b"Bob"),
            100,
        )
        .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);

        assert_eq!(
            role.poll_event(),
            Some(StyleWriterEvent::JobStarted {
                user: b"Bob".to_vec()
            })
        );

        // The two-byte accept arrives in band on the control connection.
        let accept = loop {
            match mac.poll_event() {
                Some(AdspEvent::Data { conn, data, .. }) if conn == ctrl_conn => break data,
                Some(_) => continue,
                None => panic!("no accept bytes"),
            }
        };
        assert_eq!(accept, [0x00, 0x00]);

        // The Mac closes the control connection, and the role calls back on
        // the data socket.
        mac.close(ctrl_conn);
        shuttle(&mut role, &mut mac, mac_addr, 200);
        let data_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, remote, .. }) => {
                assert_eq!(remote.node_number, 130);
                conn
            }
            other => panic!("expected reverse Opened, got {other:?}"),
        };

        // The Mac mirrors its status message on the data connection, as the
        // message ID followed by the text.
        let mut status = alloc::vec![0x06, 0x47, 8];
        status.extend_from_slice(b"Printing");
        status.resize(257, 0);
        mac.send_attention(data_conn, ATTN_SET_STATUS, &status, 240)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 240);
        assert_eq!(in_band(&mut mac, data_conn), [0x00, 0x00]);

        // A Mac waiting in the queue polls it on a fresh control
        // connection, stalling on any attention left unanswered.
        let ctrl2 = open_control(&mut role, &mut mac, mac_addr);
        let mut now = 250;
        let mut ask = |role: &mut StyleWriterRole, mac: &mut AdspEndpoint, code, payload: &[u8]| {
            mac.send_attention(ctrl2, code, payload, now).unwrap();
            shuttle(role, mac, mac_addr, now);
            now += 10;
            in_band(mac, ctrl2)
        };
        // Next in line ("You will be next"), behind the one job there is.
        assert_eq!(
            ask(&mut role, &mut mac, ATTN_QUEUE_POSITION, &print_request(70, b"Bob")),
            [0x00, 0x01]
        );
        // There is one job, the Mac's own. A count of 0 would make the Mac
        // report it deleted.
        assert_eq!(ask(&mut role, &mut mac, ATTN_JOB_COUNT, &[0x00]), [0x00, 0x01]);

        // The request as it came, then the result. The Mac reads the user name
        // at offset 4.
        let user = ask(&mut role, &mut mac, ATTN_JOB_USER, &[0x00, 0x00]);
        assert_eq!(user.len(), 72);
        assert_eq!(user[..70], print_request(70, b"Bob")[..]);
        assert_eq!(user[4..8], *b"\x03Bob");
        assert_eq!(user[70..], [0x00, 0x00]);

        // The message ID and text the Mac set, then the result.
        let job_status = ask(&mut role, &mut mac, ATTN_JOB_STATUS, &[0x00]);
        assert_eq!(job_status.len(), 259);
        assert_eq!(job_status[..3], [0x06, 0x47, 8]);
        assert_eq!(job_status[3..11], *b"Printing");
        assert!(job_status[11..].iter().all(|&b| b == 0));

        mac.close(ctrl2);
        shuttle(&mut role, &mut mac, mac_addr, 300);
        assert!(role.busy(), "closing the second control conn keeps the job");

        // Bytes flow both ways verbatim.
        // Every command is a message of its own, EOM set, as the Mac sends it.
        mac.send(data_conn, b"?", true).unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 300);
        assert_eq!(
            role.poll_event(),
            Some(StyleWriterEvent::ToPrinter(b"?".to_vec()))
        );

        role.printer_input(b"CS\r");
        shuttle(&mut role, &mut mac, mac_addr, 400);
        let reply = loop {
            match mac.poll_event() {
                Some(AdspEvent::Data { conn, data, .. }) if conn == data_conn => break data,
                Some(_) => continue,
                None => panic!("no printer reply"),
            }
        };
        assert_eq!(reply, b"CS\r");

        // Attention 0x0006 says whether the printer has had every byte. It
        // answers 0xFFFF when it has, and 0x0000 while the embedder still holds
        // some.
        for (at, drained, expect) in [(500, true, [0xFF, 0xFF]), (505, false, [0x00, 0x00])] {
            role.set_printer_drained(drained);
            mac.send_attention(data_conn, ATTN_OUTPUT_DRAINED, &[0x00], at)
                .unwrap();
            shuttle(&mut role, &mut mac, mac_addr, at);
            assert_eq!(in_band(&mut mac, data_conn), expect, "drained {drained}");
        }

        // The port cannot follow the fast clock, which the Mac reads in the
        // low byte. An unknown code still gets a reply, so the Mac does not
        // hang.
        for (at, code, expect) in [(510, ATTN_FAST_CLOCK_QUERY, [0x00, 0xEF]), (520, 0x0042, [0x00, 0x00])] {
            mac.send_attention(data_conn, code, &[0x00], at).unwrap();
            shuttle(&mut role, &mut mac, mac_addr, at);
            assert_eq!(in_band(&mut mac, data_conn), expect, "{code:#06x}");
        }

        // Without fast clock support, the switch to fast mode never reaches
        // the printer, and the port options after it are answered and
        // nothing more.
        mac.send(data_conn, &[FAST_CLOCK], true).unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 530);
        mac.send_attention(data_conn, ATTN_SERIAL_OPTIONS, &[0x40], 540)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 540);
        assert_eq!(in_band(&mut mac, data_conn), [0x00, 0x00]);
        assert_eq!(role.poll_event(), None, "nothing for the embedder");

        // An 'x' that is data rather than a command still goes through:
        // inside a longer message, or ending one an earlier packet started.
        for (at, bytes, eom) in [
            (550, &b"xx"[..], true),
            (560, &b"ab"[..], false),
            (570, &b"x"[..], true),
        ] {
            mac.send(data_conn, bytes, eom).unwrap();
            shuttle(&mut role, &mut mac, mac_addr, at);
            assert_eq!(
                role.poll_event(),
                Some(StyleWriterEvent::ToPrinter(bytes.to_vec()))
            );
        }

        // Ending the session, then closing, is a clean end with no reset.
        mac.send_attention(data_conn, ATTN_END_SESSION, &[0x00], 600)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 600);
        mac.close(data_conn);
        shuttle(&mut role, &mut mac, mac_addr, 700);

        // Drain role events: kill reply already went in-band; the end event
        // must be clean with no ToPrinter reset.
        let mut saw_end = false;
        while let Some(ev) = role.poll_event() {
            match ev {
                StyleWriterEvent::JobEnded { clean } => {
                    assert!(clean);
                    saw_end = true;
                }
                StyleWriterEvent::ToPrinter(data) => {
                    assert_ne!(data, PRINTER_RESET, "reset must not fire on clean close");
                }
                other => panic!("unexpected event {other:?}"),
            }
        }
        assert!(saw_end);
        assert!(!role.busy());
    }

    #[test]
    fn vanished_client_resets_the_printer() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 1, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 2);
        mac.set_listening(true);

        let printer = addr(130, 129);
        let ctrl = mac.connect(printer, 0);
        shuttle(&mut role, &mut mac, mac_addr, 0);
        let ctrl_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        let _ = ctrl;
        mac.send_attention(
            ctrl_conn,
            ATTN_PRINT_REQUEST,
            &print_request(70, b"Eve"),
            100,
        )
        .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);
        mac.close(ctrl_conn);
        shuttle(&mut role, &mut mac, mac_addr, 200);

        // Data conn is up; now the client silently dies mid-job. Give the
        // role unackable data so its retransmit timer eventually gives up.
        role.printer_input(b"status byte");
        while role.poll_transmit().is_some() {}
        let mut now;
        for _ in 0..64 {
            match role.next_deadline() {
                Some(d) => now = d,
                None => break,
            }
            role.poll(now);
            while role.poll_transmit().is_some() {}
        }

        let mut saw_reset = false;
        let mut saw_unclean_end = false;
        while let Some(ev) = role.poll_event() {
            match ev {
                StyleWriterEvent::ToPrinter(d) if d == PRINTER_RESET => saw_reset = true,
                StyleWriterEvent::JobEnded { clean: false } => saw_unclean_end = true,
                StyleWriterEvent::JobStarted { .. } | StyleWriterEvent::ToPrinter(_) => {}
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(saw_reset, "printer reset must be injected");
        assert!(saw_unclean_end);
        assert!(!role.busy());
    }

    /// With fast clock support the switch reaches the printer, and the port
    /// follows the printer's clock until the client switches it back or the
    /// job ends, after any reset the printer still has to hear at its speed.
    #[test]
    fn supported_fast_clock_follows_the_client_and_the_job() {
        use StyleWriterEvent::{JobEnded, ToPrinter};
        let hski = StyleWriterEvent::PortClock(PortClock::PrinterHski);
        let normal = StyleWriterEvent::PortClock(PortClock::Normal);
        let mac_addr = addr(10, 70);
        let (mut role, mut mac, data_conn) = job_in_progress(FastClock::Supported);

        // The Mac asks first, and only switches on a yes.
        mac.send_attention(data_conn, ATTN_FAST_CLOCK_QUERY, &[0x00], 250)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 250);
        assert_eq!(in_band(&mut mac, data_conn), [0x00, 0x00]);

        mac.send(data_conn, &[FAST_CLOCK], true).unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 300);
        let mut expected = alloc::vec![ToPrinter(alloc::vec![FAST_CLOCK])];
        for (at, options, event) in [
            (310, 0x40, Some(hski.clone())),
            (320, 0x40, None),
            (330, 0x00, Some(normal.clone())),
            (340, 0x40, Some(hski.clone())),
        ] {
            mac.send_attention(data_conn, ATTN_SERIAL_OPTIONS, &[options], at)
                .unwrap();
            shuttle(&mut role, &mut mac, mac_addr, at);
            assert_eq!(in_band(&mut mac, data_conn), [0x00, 0x00]);
            expected.extend(event);
            assert_eq!(role_events(&mut role), expected, "options {options:#04x}");
            expected.clear();
        }

        // A second connection, such as another Mac asking after the printer,
        // cannot move the port out from under the job.
        let other = open_control(&mut role, &mut mac, mac_addr);
        assert_eq!(ask(&mut role, &mut mac, other, ATTN_SERIAL_CONFIG, &[0x4C, 0x00], 350), [0, 0]);
        assert_eq!(role_events(&mut role), []);

        // The client vanishes mid-job, as in vanished_client_resets_the_printer.
        role.printer_input(b"status byte");
        while role.poll_transmit().is_some() {}
        while let Some(now) = role.next_deadline() {
            role.poll(now);
            while role.poll_transmit().is_some() {}
            if !role.busy() {
                break;
            }
        }
        assert_eq!(
            role_events(&mut role),
            [
                ToPrinter(PRINTER_RESET.to_vec()),
                normal,
                JobEnded { clean: false },
            ]
        );
    }

    /// A role with a job in progress, and the Mac's end of its data
    /// connection, with the job's start already read off the role.
    fn job_in_progress(fast_clock: FastClock) -> (StyleWriterRole, AdspEndpoint, u16) {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 5, fast_clock);
        let mut mac = AdspEndpoint::new(70, 6);
        mac.set_listening(true);
        let ctrl = open_control(&mut role, &mut mac, mac_addr);
        mac.send_attention(ctrl, ATTN_PRINT_REQUEST, &print_request(70, b"Ann"), 100)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);
        mac.close(ctrl);
        shuttle(&mut role, &mut mac, mac_addr, 200);
        let data_conn = loop {
            match mac.poll_event() {
                Some(AdspEvent::Opened { conn, .. }) => break conn,
                Some(_) => continue,
                None => panic!("no data connection"),
            }
        };
        assert!(matches!(role.poll_event(), Some(StyleWriterEvent::JobStarted { .. })));
        (role, mac, data_conn)
    }

    /// Send attention `code` with `arg` and return its in-band answer.
    fn ask(role: &mut StyleWriterRole, mac: &mut AdspEndpoint, conn: u16, code: u16, arg: &[u8], now: Micros) -> Vec<u8> {
        mac.send_attention(conn, code, arg, now).unwrap();
        shuttle(role, mac, addr(10, 70), now);
        in_band(mac, conn)
    }

    /// A StyleWriter II goes fast only where the port can run at 230,400 baud.
    /// A port that cannot refuses the Mac's call, so the printer stays at 57600
    /// baud, and a stray `h` is kept from the printer. One that can passes the
    /// switch on, moves to 230,400 baud once the Mac says so, and goes back when
    /// the Mac puts it at 57600 baud again.
    #[test]
    fn a_stylewriter_ii_goes_fast_only_where_the_port_can_run_at_230400() {
        use StyleWriterEvent::ToPrinter;
        let (mut role, mut mac, data) = job_in_progress(FastClock::Unsupported);
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONTROL_JF, &[0, 0], 250), [0xFF, 0xEF]);
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONFIG, &[0x4C, 0x00], 260), [0, 0]);
        // Only a lone `h` is the switch. Inside data it is just a byte.
        mac.send(data, &[FAST_CLOCK_SW], true).unwrap();
        shuttle(&mut role, &mut mac, addr(10, 70), 270);
        assert_eq!(role.poll_event(), None);
        mac.send(data, b"hh", true).unwrap();
        shuttle(&mut role, &mut mac, addr(10, 70), 280);
        assert_eq!(role.poll_event(), Some(ToPrinter(b"hh".to_vec())));

        let (mut role, mut mac, data) = job_in_progress(FastClock::Supported);
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONTROL_JF, &[0, 0], 250), [0, 0]);
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONTROL_LOWER_JF, &[0x01, 0x01], 260), [0, 0]);
        assert_eq!(role_events(&mut role), []);
        mac.send(data, &[FAST_CLOCK_SW], true).unwrap();
        shuttle(&mut role, &mut mac, addr(10, 70), 270);
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONTROL_JF, &[0, 1], 280), [0, 0]);
        assert_eq!(
            role_events(&mut role),
            [ToPrinter(vec![FAST_CLOCK_SW]), StyleWriterEvent::PortClock(PortClock::Baud230400)]
        );
        assert_eq!(ask(&mut role, &mut mac, data, ATTN_SERIAL_CONFIG, &[0x4C, 0x00], 290), [0, 0]);
        assert_eq!(role_events(&mut role), [StyleWriterEvent::PortClock(PortClock::Normal)]);
    }

    /// A client that vanishes between the accept and the control close
    /// must not pin the role busy forever. Before the handshake timeout
    /// existed, one abandoned attempt made the printer answer "busy" to
    /// every later request while sitting completely idle - which is exactly
    /// what a Chooser query looks like when it reports result 0x0001.
    #[test]
    fn abandoned_handshake_releases_the_role() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 5, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 6);
        mac.set_listening(true);

        let printer = addr(130, 129);
        let _c = mac.connect(printer, 0);
        shuttle(&mut role, &mut mac, mac_addr, 0);
        let ctrl_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        mac.send_attention(
            ctrl_conn,
            ATTN_PRINT_REQUEST,
            &print_request(70, b"Gone"),
            100,
        )
        .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);
        assert!(role.busy(), "accepted request should hold the role");

        // The client now disappears: it never closes the control
        // connection, so nothing else moves the state machine.
        role.poll(200);
        assert!(
            role.busy(),
            "must not release while the wait is still fresh"
        );

        role.poll(200 + HANDSHAKE_TIMEOUT_US + 1);
        assert!(!role.busy(), "stalled handshake must release the role");

        // And the release is reported rather than happening silently.
        let ended = core::iter::from_fn(|| role.poll_event())
            .any(|e| matches!(e, StyleWriterEvent::JobEnded { clean: false }));
        assert!(ended, "an abandoned job should report an unclean end");
    }

    #[test]
    fn second_request_while_busy_gets_busy_result() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 9, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 8);
        mac.set_listening(true);

        let printer = addr(130, 129);
        let _c = mac.connect(printer, 0);
        shuttle(&mut role, &mut mac, mac_addr, 0);
        let ctrl_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        mac.send_attention(ctrl_conn, ATTN_PRINT_REQUEST, &print_request(70, b"A"), 100)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);
        while mac.poll_event().is_some() {}
        while role.poll_event().is_some() {}
        assert!(role.busy());

        // A second Mac tries: its request must get a non-zero, non-0xFFFF
        // result.
        let mac2_addr = addr(11, 70);
        let mut mac2 = AdspEndpoint::new(70, 33);
        let _c2 = mac2.connect(printer, 0);
        loop {
            let mut progressed = false;
            while let Some((_, p)) = mac2.poll_transmit() {
                role.handle_datagram(mac2_addr, &p, 200);
                progressed = true;
            }
            while let Some((dest, p)) = role.poll_transmit() {
                if dest.node_number == 11 {
                    mac2.handle_datagram(printer, &p, 200);
                }
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        let ctrl2 = match mac2.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        mac2.send_attention(ctrl2, ATTN_PRINT_REQUEST, &print_request(70, b"B"), 300)
            .unwrap();
        loop {
            let mut progressed = false;
            while let Some((_, p)) = mac2.poll_transmit() {
                role.handle_datagram(mac2_addr, &p, 300);
                progressed = true;
            }
            while let Some((dest, p)) = role.poll_transmit() {
                if dest.node_number == 11 {
                    mac2.handle_datagram(printer, &p, 300);
                }
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        let result = loop {
            match mac2.poll_event() {
                Some(AdspEvent::Data { data, .. }) => break data,
                Some(_) => continue,
                None => panic!("no busy result"),
            }
        };
        assert_ne!(result, [0x00, 0x00]);
        assert_ne!(result, [0xFF, 0xFF]);
    }

    /// Move traffic between the role and `ep` (node `node`) until quiescent,
    /// dropping whatever the role sends to any other node.
    fn exchange_only(role: &mut StyleWriterRole, ep: &mut AdspEndpoint, node: u8, now: Micros) {
        let printer = addr(130, role.control_socket());
        loop {
            let mut progressed = false;
            while let Some((_, p)) = ep.poll_transmit() {
                role.handle_datagram(addr(node, 70), &p, now);
                progressed = true;
            }
            while let Some((dest, p)) = role.poll_transmit() {
                if dest.node_number == node {
                    ep.handle_datagram(printer, &p, now);
                }
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
    }

    /// A role that has accepted `request` from node 10 and is still dialing
    /// back, with an open that never gets an answer.
    fn role_calling_back(request: &[u8]) -> StyleWriterRole {
        let mut role = StyleWriterRole::new(129, 21, FastClock::Unsupported);
        let mut mac = AdspEndpoint::new(70, 22);
        let _c = mac.connect(addr(130, 129), 0);
        exchange_only(&mut role, &mut mac, 10, 0);
        let ctrl = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        mac.send_attention(ctrl, ATTN_PRINT_REQUEST, request, 100)
            .unwrap();
        exchange_only(&mut role, &mut mac, 10, 100);
        mac.close(ctrl);
        // The close reaches the role, which dials back, but nothing answers.
        exchange_only(&mut role, &mut mac, 99, 200);
        while role.poll_event().is_some() {}
        assert!(role.busy());
        role
    }

    /// Withdraw `request` over a control connection from node 11, an endpoint
    /// seeded with `seed`, returning the in-band reply.
    fn withdraw(role: &mut StyleWriterRole, request: &[u8], seed: u32) -> Vec<u8> {
        let mut mac = AdspEndpoint::new(70, seed);
        let _c = mac.connect(addr(130, 129), 300);
        exchange_only(role, &mut mac, 11, 300);
        let ctrl = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("{other:?}"),
        };
        mac.send_attention(ctrl, ATTN_WITHDRAW, request, 400).unwrap();
        exchange_only(role, &mut mac, 11, 400);
        in_band(&mut mac, ctrl)
    }

    /// A job still waiting to be called back can be withdrawn, but only with
    /// its own request. Nothing has reached the printer, so it ends cleanly,
    /// with no reset, and the role stops dialing.
    #[test]
    fn a_withdrawn_request_releases_the_role() {
        let request = print_request(70, b"Hal");
        let mut role = role_calling_back(&request);
        assert_eq!(withdraw(&mut role, &print_request(71, b"Ivy"), 23), [0x00, 0x00]);
        assert!(role.busy(), "another Mac's request keeps the job");
        assert!(role_events(&mut role).is_empty());

        assert_eq!(withdraw(&mut role, &request, 24), [0x00, 0x00]);
        assert_eq!(
            role_events(&mut role),
            alloc::vec![StyleWriterEvent::JobEnded { clean: true }]
        );
        assert!(!role.busy());

        // The abandoned open is not retried.
        for _ in 0..20 {
            match role.next_deadline() {
                Some(d) => role.poll(d),
                None => break,
            }
        }
        assert!(
            core::iter::from_fn(|| role.poll_transmit()).all(|(dest, _)| dest.node_number != 10),
            "no more opens toward the Mac"
        );
    }

}
