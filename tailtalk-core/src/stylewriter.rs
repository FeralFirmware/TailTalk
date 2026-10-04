//! StyleWriter printer role: the printer side of the two-connection ADSP
//! handshake.
//!
//! No published spec covers this exchange. The sequence below comes from
//! the client half in `tailtalk/src/stylewriter.rs`, which is verified
//! against real hardware, and from lpstyl's `at_printer_open`.
//!
//! Sequence, as the printer:
//!
//! 1. The role's [`AdspEndpoint`] listens on the control socket, registered
//!    in NBP as `<name>:ColorStyleWriter2400AT@*` (registration is the
//!    embedder's job; the role only owns the endpoint).
//! 2. The Mac opens an ADSP connection to the control socket.
//! 3. It sends attention 0x000B with a 70-byte payload: u32 BE data socket
//!    number, then a Pascal string (up to 64 bytes) of user name, zero
//!    padded to 70.
//! 4. We reply IN BAND on the control connection with two bytes: 0x0000
//!    accepted, 0xFFFF rejected, anything else "busy, retry later".
//! 5. The Mac closes the control connection.
//! 6. We open a REVERSE ADSP connection to the Mac's node, at the data
//!    socket from step 3.
//! 7. The data connection is then a bidirectional byte pipe to the printer
//!    UART, carried verbatim: `?` identify, `\xFF\xFF\xFF<q>` status
//!    queries, mode strings, rect+G raster - none of it is interpreted
//!    here. lpstyl drives a serial StyleWriter with the same command
//!    language, so the bytes can be piped to a UART unchanged.
//! 8. Teardown: the driver sends in-band 0x00 + `\xFF\xFF\xFF I`, then
//!    attention 0x0012 and reads a 2-byte reply, then closes. Getting this
//!    wrong makes the printer try to reopen a connection to the original
//!    control socket.
//!
//! Attention replies: a native Mac driver capture shows attention 0x0006
//! ("buffer ready?") answered with two IN-BAND bytes 0xFF 0xFF. The reply to
//! the 0x0012 kill attention is also two in-band bytes; the client discards
//! the value, and no capture of a real printer's value exists yet, so we
//! send 0xFF 0xFF there too. If hardware disagrees, the hardware is right -
//! update this and the comment.

use alloc::vec::Vec;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Micros;
use crate::adsp::{AdspEndpoint, AdspEvent};

/// NBP type the Mac's Color StyleWriter 2400 driver looks up.
pub const NBP_TYPE: &str = "ColorStyleWriter2400AT";

/// The print-request attention (lpstyl `at_printer_open`).
pub const ATTN_PRINT_REQUEST: u16 = 0x000B;
/// Buffer-ready query, answered with in-band 0xFFFF.
pub const ATTN_BUFFER_READY: u16 = 0x0006;
/// Kill/teardown attention (lpstyl `at_printer_kill`). The rename sequence
/// reuses this code as its commit step, so the two are told apart by which
/// connection the attention arrives on: a job's kill comes in on the data
/// connection, a commit on a control connection.
pub const ATTN_KILL: u16 = 0x0012;
/// The number of jobs on the printer, as an in-band u16 (lpstyl reads it
/// as the queue length on a busy printer). The Mac driver asks while
/// printing, and takes 0 to mean its job was deleted. The rename sequence
/// also opens with it, on an idle printer, and checks for exactly 0x0000.
pub const ATTN_JOB_COUNT: u16 = 0x0011;
/// Carries the new name as a Pascal string. Answered with in-band 0x0000.
pub const ATTN_SET_NAME: u16 = 0x0009;
/// Status text for the printer to show (lpstyl `at_printer_setstatus`),
/// sent on the data connection. lpstyl reads a two-byte reply and ignores
/// it; we send 0x0000.
pub const ATTN_SET_STATUS: u16 = 0x000A;
/// Sent by the Mac's own driver, not lpstyl, on a second control connection
/// once the reverse data connection is up. The payload repeats the print
/// request's (data socket, user name). The driver waits on a two-byte
/// in-band reply and stalls without one; the value is unverified, and
/// 0x0000 is what this protocol answers success with everywhere else.
pub const ATTN_JOB_CONFIRM: u16 = 0x000D;
/// Who the current job belongs to. lpstyl asks when a printer is busy, and
/// the Mac driver asks after [`ATTN_JOB_CONFIRM`]. Answered with 72 in-band
/// bytes: lpstyl reads a Pascal user name at offset 6, which fits a 2-byte
/// result ahead of the 70-byte print request (u32 port, Pascal user).
pub const ATTN_JOB_USER: u16 = 0x000E;
/// The printer's status text. lpstyl reads 259 in-band bytes with a Pascal
/// string at offset 2, and like [`ATTN_JOB_USER`] it is asked for on a busy
/// printer.
pub const ATTN_JOB_STATUS: u16 = 0x0010;

const JOB_USER_REPLY_LEN: usize = 72;
const JOB_STATUS_REPLY_LEN: usize = 259;

/// In-band print-request results (step 4).
const RESULT_ACCEPTED: [u8; 2] = [0x00, 0x00];
const RESULT_BUSY: [u8; 2] = [0x00, 0x01];

/// Sent to the serial printer when a client disappears mid-job: lpstyl's
/// eject-and-reset bytes (null then `FF FF FF 'I'`), so paper does not sit
/// in the feed path until the next job. Silent: the printer does not reply.
pub const PRINTER_RESET: &[u8] = &[0x00, 0xFF, 0xFF, 0xFF, b'I'];

/// The identify command. The printer answers with its model string,
/// terminated by a carriage return. lpstyl only sends it after a reset and a
/// ready status, and that order matters: an original StyleWriter left idle
/// ignores it until it has been reset (confirmed on hardware).
pub const IDENTIFY: u8 = b'?';

/// Status queries, sent as `FF FF FF <q>` and each answered with one byte.
/// The meanings are lpstyl's README.protocol.
pub const QUERY_STATUS: u8 = b'1';
/// Error status: 0x00 and 0x80 mean nothing wrong, 0x04 out of paper.
pub const QUERY_ERROR: u8 = b'2';
/// Buffer gauge, scaled differently on every model.
pub const QUERY_BUFFER: u8 = b'B';
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

/// Whether a printer that was just reset is ready to be identified, given
/// its replies to [`QUERY_STATUS`], [`QUERY_ERROR`] and [`QUERY_BUFFER`]
/// (`None` where it did not answer).
///
/// This is lpstyl's post-reset loop (`printerSetup()`), which waits while
/// status `1` is 0x01 or unanswered, except that an original StyleWriter
/// shows readiness as `1` = 0x01, `2` = 0x00 and `B` = 0xA0. That reading is
/// confirmed on hardware.
pub fn ready_after_reset(status: Option<u8>, error: Option<u8>, buffer: Option<u8>) -> bool {
    match status {
        None => false,
        Some(0x01) => error == Some(0x00) && buffer == Some(0xA0),
        Some(_) => true,
    }
}

/// The model an identify string names, using lpstyl's tables, with the
/// [`QUERY_SUBMODEL`] reply for a Color StyleWriter. `None` for a string
/// lpstyl does not know.
pub fn model_name(identity: &[u8], submodel: Option<u8>) -> Option<&'static str> {
    Some(match identity {
        b"IJ10" => "Apple StyleWriter",
        b"SW" => "Apple StyleWriter II",
        b"SW3" => "Apple StyleWriter 1200",
        COLOR_FAMILY => match submodel {
            Some(0x01) => "Apple Color StyleWriter 2400",
            Some(0x02) => "Apple Color StyleWriter 2200",
            Some(0x04) => "Apple Color StyleWriter 1500",
            Some(0x05) => "Apple Color StyleWriter 2500",
            _ => "Apple Color StyleWriter",
        },
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StyleWriterEvent {
    /// A job was accepted; the user name is the raw Pascal-string bytes from
    /// the print request (MacRoman, informational only).
    JobStarted { user: Vec<u8> },
    /// Bytes for the printer UART.
    ToPrinter(Vec<u8>),
    /// The job ended. `clean` distinguishes the driver's kill sequence from
    /// a vanished client; on an unclean end a reset was already queued as a
    /// `ToPrinter` event.
    JobEnded { clean: bool },
    /// The client committed a new NBP name, as raw MacRoman bytes. The
    /// embedder owns what happens next: re-register under it, and persist it
    /// if the hardware has somewhere to put it. A real adapter keeps the name
    /// across a power cycle and re-registers itself, so a client looking the
    /// printer up shortly afterwards expects to find the new name.
    Rename(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    /// Accepted a print request on this control connection; waiting for the
    /// Mac to close it (step 5) before dialing back.
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
/// Steps 4 to 6 are back-to-back on a healthy client: it reads our two-byte
/// accept, closes the control connection, and we dial back. A client that
/// dies in between - or whose close never reaches us - would otherwise pin
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
    /// Name staged by [`ATTN_SET_NAME`], published when the commit arrives.
    pending_name: Option<Vec<u8>>,
    /// The accepted print request's data socket and user name, for
    /// [`ATTN_JOB_USER`]. Only meaningful while [`Self::busy`].
    job_port: u8,
    job_user: Vec<u8>,
    /// The text from the job's last [`ATTN_SET_STATUS`], for
    /// [`ATTN_JOB_STATUS`].
    job_status: Vec<u8>,
}

impl StyleWriterRole {
    pub fn new(control_socket: u8, seed: u32) -> Self {
        let mut endpoint = AdspEndpoint::new(control_socket, seed);
        endpoint.set_listening(true);
        Self {
            endpoint,
            state: State::Idle,
            state_since: 0,
            events: alloc::collections::VecDeque::new(),
            pending_name: None,
            job_port: 0,
            job_user: Vec::new(),
            job_status: Vec::new(),
        }
    }

    /// The [`ATTN_JOB_USER`] reply: a 0x0000 result, then the current job's
    /// print request (u32 port, Pascal user), zero padded. All zero when no
    /// job is active.
    fn job_user_reply(&self) -> Vec<u8> {
        let mut reply = RESULT_ACCEPTED.to_vec();
        if self.busy() {
            reply.extend_from_slice(&(self.job_port as u32).to_be_bytes());
            reply.push(self.job_user.len() as u8);
            reply.extend_from_slice(&self.job_user);
        }
        reply.resize(JOB_USER_REPLY_LEN, 0);
        reply
    }

    /// The [`ATTN_JOB_STATUS`] reply: a 0x0000 result, then the status as a
    /// Pascal string, zero padded. Empty when no job is active or the Mac has
    /// not set one.
    fn job_status_reply(&self) -> Vec<u8> {
        let mut reply = RESULT_ACCEPTED.to_vec();
        let text: &[u8] = if self.busy() { &self.job_status } else { &[] };
        reply.push(text.len() as u8);
        reply.extend_from_slice(text);
        reply.resize(JOB_STATUS_REPLY_LEN, 0);
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
                // A printer role has at most one outbound connect in flight,
                // so any completing outbound connection is the reverse data
                // pipe (step 6 done). Inbound ones are control connections;
                // nothing to do until their print-request attention arrives.
                //
                // Piping is accepted here as well as Connecting: the
                // endpoint re-announces the pipe if the peer answered a
                // retransmitted open with a second connection and moved to
                // it, and latching onto the new key is the whole point of
                // that notification.
                if !inbound && matches!(self.state, State::Connecting { .. } | State::Piping { .. })
                {
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
            AdspEvent::Data { conn, data, .. } => {
                if let State::Piping { conn: dc, .. } = self.state
                    && conn == dc
                    && !data.is_empty()
                {
                    self.events.push_back(StyleWriterEvent::ToPrinter(data));
                }
            }
            AdspEvent::Closed { conn } => match self.state {
                State::AwaitingCtrlClose {
                    ctrl,
                    mac_node,
                    data_socket,
                } if conn == ctrl => {
                    // Step 6: dial the Mac's data socket.
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
                    self.events
                        .push_back(StyleWriterEvent::JobEnded { clean: kill_seen });
                    self.enter(State::Idle, now);
                }
                _ => {}
            },
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
                // printRequest { u32 be port; pascal string user; } zero
                // padded to 70, as lpstyl builds it.
                if data.len() < 5 {
                    return;
                }
                if self.busy() {
                    let _ = self.endpoint.send(conn, &RESULT_BUSY, false);
                    return;
                }
                let data_socket = data[3]; // u32 be, but a socket is one byte
                let name_len = (data[4] as usize).min(64).min(data.len() - 5);
                let user = data[5..5 + name_len].to_vec();

                // We do not know the Mac's address from the attention alone;
                // AdspEvent::Opened carried it. Look it up from the
                // connection the attention arrived on.
                let Some(remote) = self.endpoint.remote_of(conn) else {
                    return;
                };

                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                self.job_port = data_socket;
                self.job_user = user.clone();
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
            ATTN_BUFFER_READY => {
                // Two in-band 0xFF bytes, per a native Mac driver capture.
                let _ = self.endpoint.send(conn, &[0xFF, 0xFF], false);
            }
            ATTN_KILL => {
                // Kill on the data connection, rename commit anywhere else;
                // see ATTN_KILL.
                if let State::Piping { conn: dc, .. } = self.state
                    && conn == dc
                {
                    // Two in-band reply bytes; value unverified on hardware,
                    // see the module docs. Then expect the peer to close.
                    let _ = self.endpoint.send(conn, &[0xFF, 0xFF], false);
                    self.enter(
                        State::Piping {
                            conn: dc,
                            kill_seen: true,
                        },
                        now,
                    );
                } else {
                    // Commit: publish whatever SET_NAME staged. A commit with
                    // nothing staged is still answered, because the client
                    // waits on the reply either way.
                    if let Some(name) = self.pending_name.take() {
                        self.events.push_back(StyleWriterEvent::Rename(name));
                    }
                    let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
                }
            }
            ATTN_JOB_COUNT => {
                let count = u16::from(self.busy());
                let _ = self.endpoint.send(conn, &count.to_be_bytes(), false);
            }
            ATTN_JOB_CONFIRM => {
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
            ATTN_SET_STATUS => {
                // lpstyl's record: 0x06 0x47, then the text as a Pascal
                // string, zero padded to 257.
                if let Some(&len) = data.get(2) {
                    let text = &data[3..];
                    self.job_status = text[..(len as usize).min(text.len())].to_vec();
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
                // Pascal string: one length byte, then MacRoman bytes. Staged
                // rather than published, because the client only treats the
                // rename as done once its commit is answered.
                if let Some(&len) = data.first()
                    && len > 0
                    && data.len() > len as usize
                {
                    self.pending_name = Some(data[1..1 + len as usize].to_vec());
                }
                let _ = self.endpoint.send(conn, &RESULT_ACCEPTED, false);
            }
            _ => {}
        }
    }
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

    /// An original StyleWriter after a reset answered 01 / 00 / A0 on
    /// hardware, and only then answered `?`.
    #[test]
    fn an_original_stylewriter_is_ready_on_its_own_status_pattern() {
        assert!(ready_after_reset(Some(0x01), Some(0x00), Some(0xA0)));
        // 0x01 on its own is lpstyl's "still busy" for everyone else.
        assert!(!ready_after_reset(Some(0x01), Some(0x00), Some(0xF8)));
        assert!(!ready_after_reset(Some(0x01), None, None));
        // Any other answer is ready, and silence never is.
        assert!(ready_after_reset(Some(0x80), None, None));
        assert!(!ready_after_reset(None, Some(0x00), Some(0xA0)));
    }

    /// The three-attention rename: query, set, commit.
    ///
    /// Each step is answered with in-band 0x0000, and the client blocks on
    /// that reply before sending the next - so an unanswered step stalls the
    /// rename rather than failing it.
    #[test]
    fn a_rename_is_answered_at_each_step_and_published_on_commit() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42);
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);
        let ctrl = open_control(&mut role, &mut mac, mac_addr);

        let mut now = 100;
        for (code, payload) in [
            (ATTN_JOB_COUNT, alloc::vec![0x00]),
            (ATTN_SET_NAME, pascal(b"Inky")),
            (ATTN_KILL, alloc::vec![0x00]),
        ] {
            mac.send_attention(ctrl, code, &payload, now).unwrap();
            shuttle(&mut role, &mut mac, mac_addr, now);
            assert_eq!(
                in_band(&mut mac, ctrl),
                alloc::vec![0x00, 0x00],
                "step {code:#06x} must be answered"
            );
            now += 100;
        }

        assert_eq!(
            role_events(&mut role),
            alloc::vec![StyleWriterEvent::Rename(b"Inky".to_vec())]
        );
    }

    /// A name arriving with no commit behind it is never published: the
    /// client has not been told the rename took.
    #[test]
    fn a_staged_name_without_a_commit_is_not_published() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42);
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);
        let ctrl = open_control(&mut role, &mut mac, mac_addr);

        mac.send_attention(ctrl, ATTN_SET_NAME, &pascal(b"Never"), 100)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 100);

        assert!(
            !role_events(&mut role)
                .iter()
                .any(|e| matches!(e, StyleWriterEvent::Rename(_))),
            "nothing is published until the commit"
        );
    }

    #[test]
    fn full_handshake_and_byte_pipe() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 42);
        // One endpoint on the Mac side plays both the control client and
        // the data listener (both live on node 10).
        let mut mac = AdspEndpoint::new(70, 77);
        mac.set_listening(true);

        // Step 2: Mac opens the control connection.
        let printer = addr(130, 129);
        let ctrl = mac.connect(printer, 0);
        shuttle(&mut role, &mut mac, mac_addr, 0);
        let ctrl_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, .. }) => conn,
            other => panic!("expected ctrl Opened, got {other:?}"),
        };
        let _ = ctrl;

        // Step 3: print request naming data socket 70 (same endpoint here).
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

        // Step 4: two-byte accept arrives in band on the control conn.
        let accept = loop {
            match mac.poll_event() {
                Some(AdspEvent::Data { conn, data, .. }) if conn == ctrl_conn => break data,
                Some(_) => continue,
                None => panic!("no accept bytes"),
            }
        };
        assert_eq!(accept, [0x00, 0x00]);

        // Step 5: Mac closes the control connection; step 6: the role dials
        // back to the data socket.
        mac.close(ctrl_conn);
        shuttle(&mut role, &mut mac, mac_addr, 200);
        let data_conn = match mac.poll_event() {
            Some(AdspEvent::Opened { conn, remote, .. }) => {
                assert_eq!(remote.node_number, 130);
                conn
            }
            other => panic!("expected reverse Opened, got {other:?}"),
        };

        // The Mac driver then opens a second control connection and repeats
        // the request as 0x000D, and stalls until it is answered.
        // lpstyl sets a status string on the data connection and reads a
        // two-byte reply.
        let mut status = alloc::vec![0x06, 0x47, 8];
        status.extend_from_slice(b"Printing");
        status.resize(257, 0);
        mac.send_attention(data_conn, ATTN_SET_STATUS, &status, 240)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 240);
        assert_eq!(in_band(&mut mac, data_conn), [0x00, 0x00]);

        // The Mac driver then opens a second control connection, repeats
        // the request as 0x000D, and asks about the job, stalling on any
        // attention left unanswered.
        let ctrl2 = open_control(&mut role, &mut mac, mac_addr);
        let mut now = 250;
        let mut ask = |role: &mut StyleWriterRole, mac: &mut AdspEndpoint, code, payload: &[u8]| {
            mac.send_attention(ctrl2, code, payload, now).unwrap();
            shuttle(role, mac, mac_addr, now);
            now += 10;
            in_band(mac, ctrl2)
        };
        assert_eq!(
            ask(&mut role, &mut mac, ATTN_JOB_CONFIRM, &print_request(70, b"Bob")),
            [0x00, 0x00]
        );
        // One job, the Mac's own: 0 here makes the driver report the job deleted.
        assert_eq!(ask(&mut role, &mut mac, ATTN_JOB_COUNT, &[0x00]), [0x00, 0x01]);

        let user = ask(&mut role, &mut mac, ATTN_JOB_USER, &[0x00, 0x00]);
        assert_eq!(user.len(), 72);
        assert_eq!(user[..6], [0x00, 0x00, 0x00, 0x00, 0x00, 70]);
        assert_eq!(user[6..10], *b"\x03Bob");
        assert!(user[10..].iter().all(|&b| b == 0));

        let job_status = ask(&mut role, &mut mac, ATTN_JOB_STATUS, &[0x00]);
        assert_eq!(job_status.len(), 259);
        assert_eq!(job_status[..3], [0x00, 0x00, 8]);
        assert_eq!(job_status[3..11], *b"Printing");

        mac.close(ctrl2);
        shuttle(&mut role, &mut mac, mac_addr, 300);
        assert!(role.busy(), "closing the second control conn keeps the job");

        // Step 7: bytes flow both ways verbatim.
        mac.send(data_conn, b"?", false).unwrap();
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

        // Attention 0x0006 is answered with in-band 0xFFFF.
        mac.send_attention(data_conn, ATTN_BUFFER_READY, &[0x00], 500)
            .unwrap();
        shuttle(&mut role, &mut mac, mac_addr, 500);
        let br = loop {
            match mac.poll_event() {
                Some(AdspEvent::Data { conn, data, .. }) if conn == data_conn => break data,
                Some(_) => continue,
                None => panic!("no buffer-ready reply"),
            }
        };
        assert_eq!(br, [0xFF, 0xFF]);

        // Step 8: kill attention then close = clean end, no reset injected.
        mac.send_attention(data_conn, ATTN_KILL, &[0x00], 600)
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
        let mut role = StyleWriterRole::new(129, 1);
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

    /// A client that vanishes between the accept and the control close
    /// must not pin the role busy forever. Before the handshake timeout
    /// existed, one abandoned attempt made the printer answer "busy" to
    /// every later request while sitting completely idle - which is exactly
    /// what a Chooser query looks like when it reports result 0x0001.
    #[test]
    fn abandoned_handshake_releases_the_role() {
        let mac_addr = addr(10, 70);
        let mut role = StyleWriterRole::new(129, 5);
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
        let mut role = StyleWriterRole::new(129, 9);
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
}
