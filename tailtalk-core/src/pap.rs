//! PAP printer server.
//!
//! Serves one print job at a time, handing the job out in packet-sized
//! pieces as they arrive. The next SendData pull is issued only once the
//! caller reports enough sink credit - free space wherever the bytes are
//! going - to absorb a full reply, so a printer that cannot keep up slows
//! the pull schedule and the back pressure reaches the Mac. A job is never
//! held whole, so its size is bounded by the wire rather than by RAM.
//!
//! Two ATP sockets are involved. The listener socket, advertised in NBP,
//! answers SendStatus and OpenConn for the life of the server. A separate
//! connection socket carries the session itself: client reads, CloseConn,
//! and the server's own SendData pulls. That one connection socket serves
//! every session in turn, which is safe because only one session is open at
//! a time and the PAP connection ID tells stale traffic from live.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use tailtalk_packets::nbp::ServiceAddress;
use tailtalk_packets::pap::{PapFunction, PapPacket};

use crate::Micros;
use crate::atp::{AtpEndpoint, AtpEvent};

/// Per-ATP-packet cap for PAP data. Observed on hardware: a real
/// LaserWriter gets very upset over LocalTalk with packets above 512 bytes,
/// and 512 also lets a SendData be answered with a full quantum of eight.
pub const PAP_MAX_DATA_PER_PACKET: usize = 512;

/// Response packets one SendData pull may bring back. Eight is the usual
/// PAP flow quantum.
pub const FLOW_QUANTUM: u8 = 8;

/// Bytes one of our SendData pulls can bring in; the sink must have at least
/// this much room before a pull is issued.
pub const PULL_CAPACITY: usize = FLOW_QUANTUM as usize * PAP_MAX_DATA_PER_PACKET;

/// A read left waiting while the client has also gone quiet is answered
/// empty after this long, so the client's own read does not time out.
const READ_IDLE_ANSWER: Micros = 2_000_000;

/// Tickle interval and session inactivity timeout.
const TICKLE_INTERVAL: Micros = 30_000_000;
const INACTIVITY_TIMEOUT: Micros = 120_000_000;

/// Replies to client reads kept for PAP-level retransmits (a retransmit with
/// a fresh ATP TID but the same PAP sequence number). ATP-level retransmits
/// are already replayed by the ATP endpoint's own cache.
const READ_REPLY_CACHE_LEN: usize = 8;

/// Advance a PAP sequence number: 1-65535, wrapping to 1 (0 = unsequenced).
fn next_pap_seq(seq: u16) -> u16 {
    if seq == u16::MAX { 1 } else { seq + 1 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PapEvent {
    ConnectionOpened {
        client: ServiceAddress,
    },
    /// Job bytes for the printer UART.
    ToPrinter(Vec<u8>),
    /// The client marked end of job (PAP eof).
    JobEof,
    /// The session ended (client CloseConn, or inactivity timeout).
    ConnectionClosed,
}

struct Session {
    conn_id: u8,
    client: ServiceAddress,
    /// Our SendData pull sequence and the ATP handle of the pull in flight.
    pull_seq: u16,
    outstanding_pull: Option<u16>,
    /// Bytes received since the last JobEof, to suppress the empty job a
    /// client's post-EOF drain produces when it answers in-flight pulls.
    job_bytes: usize,
    /// Client read bookkeeping.
    read_seq: u16,
    read_cache: VecDeque<(u16, [u8; 4], Vec<u8>)>,
    pending_read: Option<(ServiceAddress, u16, u8, u16)>,
    /// Reverse stream (printer output) toward the client.
    stdout: VecDeque<u8>,
    eof_queued: bool,
    last_client_write: Micros,
    last_activity: Micros,
    next_tickle: Micros,
}

pub struct PapServer {
    listener: AtpEndpoint,
    conn_ep: AtpEndpoint,
    /// Raw status string bytes ("%%[ status: idle ]%%" or an option card's
    /// two status bytes); framed as a Pascal string on the wire.
    status: Vec<u8>,
    session: Option<Session>,
    sink_credit: usize,
    events: VecDeque<PapEvent>,
}

impl PapServer {
    pub fn new(listener_socket: u8, conn_socket: u8) -> Self {
        Self {
            listener: AtpEndpoint::new(listener_socket),
            conn_ep: AtpEndpoint::new(conn_socket),
            status: Vec::new(),
            session: None,
            sink_credit: 0,
            events: VecDeque::new(),
        }
    }

    pub fn listener_socket(&self) -> u8 {
        self.listener.local_socket()
    }

    pub fn conn_socket(&self) -> u8 {
        self.conn_ep.local_socket()
    }

    pub fn busy(&self) -> bool {
        self.session.is_some()
    }

    /// Set the status answered to SendStatus (and embedded in OpenConnReply).
    pub fn set_status(&mut self, status: &[u8]) {
        self.status = status.to_vec();
        self.status.truncate(255);
    }

    /// Report free space in the printer sink. Pulls are issued only while at
    /// least [`PULL_CAPACITY`] is free.
    pub fn set_sink_credit(&mut self, bytes: usize, now: Micros) {
        self.sink_credit = bytes;
        self.maybe_pull(now);
    }

    /// Queue printer output for the client's reads (the PAP reverse stream).
    pub fn queue_output(&mut self, data: &[u8], now: Micros) {
        if let Some(s) = &mut self.session {
            s.stdout.extend(data.iter().copied());
        }
        self.answer_read(now);
    }

    /// Mark the reverse stream's end: the read that drains the queue gets
    /// the PAP eof flag, telling the driver the job's output is complete.
    pub fn end_output(&mut self, now: Micros) {
        if let Some(s) = &mut self.session {
            s.eof_queued = true;
        }
        self.answer_read(now);
    }

    pub fn handle_datagram(
        &mut self,
        local_socket: u8,
        src: ServiceAddress,
        payload: &[u8],
        now: Micros,
    ) {
        if local_socket == self.listener.local_socket() {
            self.listener.handle_datagram(src, payload, now);
        } else if local_socket == self.conn_ep.local_socket() {
            self.conn_ep.handle_datagram(src, payload, now);
        }
        self.drain(now);
    }

    pub fn poll(&mut self, now: Micros) {
        self.listener.poll(now);
        self.conn_ep.poll(now);
        self.drain(now);

        let mut closed = false;
        if let Some(s) = &mut self.session {
            if now.saturating_sub(s.last_activity) > INACTIVITY_TIMEOUT {
                closed = true;
            } else if now >= s.next_tickle {
                s.next_tickle = now + TICKLE_INTERVAL;
                let tickle = PapPacket {
                    connection_id: s.conn_id,
                    function: PapFunction::Tickle,
                    sequence_num: 0,
                    eof: false,
                    data: &[],
                };
                let (ub, _) = tickle.to_atp_parts();
                let client = s.client;
                self.conn_ep.send_alo(client, ub);
            }
        }
        if closed {
            self.session = None;
            self.events.push_back(PapEvent::ConnectionClosed);
        }
        self.answer_read(now);
        self.maybe_pull(now);
    }

    pub fn next_deadline(&self) -> Option<Micros> {
        let mut deadline = self.listener.next_deadline();
        let mut fold = |d: Option<Micros>| {
            deadline = match (deadline, d) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
        };
        fold(self.conn_ep.next_deadline());
        if let Some(s) = &self.session {
            fold(Some(s.next_tickle));
            fold(Some(s.last_activity + INACTIVITY_TIMEOUT));
            if s.pending_read.is_some() {
                fold(Some(s.last_client_write + READ_IDLE_ANSWER));
            }
        }
        deadline
    }

    /// Next outgoing DDP payload: `(source socket, destination, atp bytes)`,
    /// DDP type ATP.
    pub fn poll_transmit(&mut self) -> Option<(u8, ServiceAddress, Vec<u8>)> {
        if let Some((dest, payload)) = self.listener.poll_transmit() {
            return Some((self.listener.local_socket(), dest, payload));
        }
        if let Some((dest, payload)) = self.conn_ep.poll_transmit() {
            return Some((self.conn_ep.local_socket(), dest, payload));
        }
        None
    }

    pub fn poll_event(&mut self) -> Option<PapEvent> {
        self.events.pop_front()
    }

    fn status_pascal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.status.len());
        out.push(self.status.len() as u8);
        out.extend_from_slice(&self.status);
        out
    }

    fn drain(&mut self, now: Micros) {
        while let Some(ev) = self.listener.poll_event() {
            self.handle_listener_event(ev, now);
        }
        while let Some(ev) = self.conn_ep.poll_event() {
            self.handle_conn_event(ev, now);
        }
        self.answer_read(now);
        self.maybe_pull(now);
    }

    fn handle_listener_event(&mut self, ev: AtpEvent, now: Micros) {
        let AtpEvent::Request {
            source,
            tid,
            user_bytes,
            data,
            ..
        } = ev
        else {
            return;
        };
        let Ok(pap) = PapPacket::parse_from_atp(user_bytes, &data) else {
            return;
        };
        match pap.function {
            PapFunction::SendStatus => {
                // Status payload: four unused bytes, then the Pascal string.
                let mut status = alloc::vec![0u8, 0, 0, 0];
                status.extend_from_slice(&self.status_pascal());
                let reply = PapPacket {
                    connection_id: 0,
                    function: PapFunction::Status,
                    sequence_num: 0,
                    eof: false,
                    data: &status,
                };
                self.respond_pap(true, source, tid, &reply, now);
            }
            PapFunction::OpenConn => {
                if pap.data.len() < 2 {
                    return;
                }
                if self.session.is_some() {
                    // Busy: result 0xFFFF; the driver retries every 2 s.
                    let mut d = alloc::vec![0u8, FLOW_QUANTUM, 0xFF, 0xFF];
                    d.extend_from_slice(&self.status_pascal());
                    let reply = PapPacket {
                        connection_id: pap.connection_id,
                        function: PapFunction::OpenConnReply,
                        sequence_num: 0,
                        eof: false,
                        data: &d,
                    };
                    self.respond_pap(true, source, tid, &reply, now);
                    return;
                }

                let client_socket = pap.data[0];
                let client = ServiceAddress {
                    network_number: source.network_number,
                    node_number: source.node_number,
                    socket_number: client_socket,
                };
                let mut d = alloc::vec![self.conn_ep.local_socket(), FLOW_QUANTUM, 0, 0];
                d.extend_from_slice(&self.status_pascal());
                let reply = PapPacket {
                    connection_id: pap.connection_id,
                    function: PapFunction::OpenConnReply,
                    sequence_num: 0,
                    eof: false,
                    data: &d,
                };
                self.respond_pap(true, source, tid, &reply, now);
                self.session = Some(Session {
                    conn_id: pap.connection_id,
                    client,
                    pull_seq: 1,
                    outstanding_pull: None,
                    job_bytes: 0,
                    read_seq: 1,
                    read_cache: VecDeque::new(),
                    pending_read: None,
                    stdout: VecDeque::new(),
                    eof_queued: false,
                    last_client_write: now,
                    last_activity: now,
                    next_tickle: now + TICKLE_INTERVAL,
                });
                self.events.push_back(PapEvent::ConnectionOpened { client });
            }
            _ => {}
        }
    }

    fn handle_conn_event(&mut self, ev: AtpEvent, now: Micros) {
        match ev {
            AtpEvent::Request {
                source,
                tid,
                user_bytes,
                data,
                bitmap,
                ..
            } => {
                let Ok(pap) = PapPacket::parse_from_atp(user_bytes, &data) else {
                    return;
                };
                let Some(s) = &mut self.session else {
                    return;
                };
                if pap.connection_id != s.conn_id {
                    return;
                }
                s.last_activity = now;
                match pap.function {
                    PapFunction::SendData => {
                        // A retransmit of an answered read gets the identical
                        // reply; anything else out of order is stale.
                        if pap.sequence_num != 0 && pap.sequence_num != s.read_seq {
                            if let Some((_, ub, d)) =
                                s.read_cache.iter().find(|(q, _, _)| *q == pap.sequence_num)
                            {
                                let (ub, d) = (*ub, d.clone());
                                self.conn_ep.respond(
                                    source,
                                    tid,
                                    ub,
                                    &d,
                                    PAP_MAX_DATA_PER_PACKET,
                                    now,
                                );
                            }
                        } else {
                            s.pending_read = Some((source, tid, bitmap, pap.sequence_num));
                        }
                    }
                    PapFunction::Tickle => {}
                    PapFunction::CloseConn => {
                        let reply = PapPacket {
                            connection_id: pap.connection_id,
                            function: PapFunction::CloseConnReply,
                            sequence_num: 0,
                            eof: false,
                            data: &[],
                        };
                        self.respond_pap(false, source, tid, &reply, now);
                        self.session = None;
                        self.events.push_back(PapEvent::ConnectionClosed);
                    }
                    _ => {}
                }
            }
            AtpEvent::Response {
                handle,
                user_bytes,
                data,
            } => {
                let Some(s) = &mut self.session else {
                    return;
                };
                if s.outstanding_pull != Some(handle) {
                    return;
                }
                s.outstanding_pull = None;
                let Ok(pap) = PapPacket::parse_from_atp(user_bytes, &data) else {
                    return;
                };
                if pap.function != PapFunction::Data {
                    return;
                }
                s.last_activity = now;
                s.last_client_write = now;
                s.pull_seq = next_pap_seq(s.pull_seq);
                let had_bytes = !pap.data.is_empty();
                if had_bytes {
                    s.job_bytes += pap.data.len();
                    self.events
                        .push_back(PapEvent::ToPrinter(pap.data.to_vec()));
                }
                if pap.eof {
                    // A client's post-EOF drain answers in-flight pulls
                    // with empty EOFs; only a job that carried bytes ends
                    // one.
                    if self.session.as_ref().is_some_and(|s| s.job_bytes > 0) {
                        if let Some(s) = &mut self.session {
                            s.job_bytes = 0;
                        }
                        self.events.push_back(PapEvent::JobEof);
                    }
                }
            }
            AtpEvent::RequestFailed { handle } => {
                // The pull's ATP retries ran out: the client is idle or gone.
                // Re-issue (papd's infinite-retry PAP_READ); the inactivity
                // timeout is what finally ends an abandoned session.
                if let Some(s) = &mut self.session
                    && s.outstanding_pull == Some(handle)
                {
                    s.outstanding_pull = None;
                }
            }
        }
    }

    /// Issue the next SendData pull if the session is open, none is in
    /// flight, and the sink can absorb a full reply.
    fn maybe_pull(&mut self, now: Micros) {
        let Some(s) = &mut self.session else {
            return;
        };
        if s.outstanding_pull.is_some() || self.sink_credit < PULL_CAPACITY {
            return;
        }
        let pull = PapPacket {
            connection_id: s.conn_id,
            function: PapFunction::SendData,
            sequence_num: s.pull_seq,
            eof: false,
            data: &[],
        };
        let (ub, d) = pull.to_atp_parts();
        let client = s.client;
        let handle = self.conn_ep.request(client, ub, d, 0xFF, now);
        self.session.as_mut().unwrap().outstanding_pull = Some(handle);
    }

    /// Serve a waiting client read: printer output when there is any, eof
    /// when the reverse stream ended, or an empty keep-alive once the client
    /// has been idle.
    fn answer_read(&mut self, now: Micros) {
        let Some(s) = &mut self.session else {
            return;
        };
        let Some((source, tid, bitmap, seq)) = s.pending_read else {
            return;
        };
        let have_output = !s.stdout.is_empty() || s.eof_queued;
        let idle = now >= s.last_client_write + READ_IDLE_ANSWER;
        if !have_output && !idle {
            return;
        }
        s.pending_read = None;

        let max_packets = bitmap.count_ones().clamp(1, 8) as usize;
        let capacity = max_packets * PAP_MAX_DATA_PER_PACKET;
        let take = s.stdout.len().min(capacity);
        let chunk: Vec<u8> = s.stdout.drain(..take).collect();
        let eof = s.eof_queued && s.stdout.is_empty();
        if eof {
            s.eof_queued = false;
        }

        let reply = PapPacket {
            connection_id: s.conn_id,
            function: PapFunction::Data,
            sequence_num: 0,
            eof,
            data: &chunk,
        };
        let (ub, d) = reply.to_atp_parts();
        let d = d.to_vec();
        if seq != 0 {
            s.read_seq = next_pap_seq(s.read_seq);
            if s.read_cache.len() == READ_REPLY_CACHE_LEN {
                s.read_cache.pop_front();
            }
            s.read_cache.push_back((seq, ub, d.clone()));
        }
        self.conn_ep
            .respond(source, tid, ub, &d, PAP_MAX_DATA_PER_PACKET, now);
    }

    fn respond_pap(
        &mut self,
        on_listener: bool,
        source: ServiceAddress,
        tid: u16,
        pap: &PapPacket,
        now: Micros,
    ) {
        let (ub, d) = pap.to_atp_parts();
        let ep = if on_listener {
            &mut self.listener
        } else {
            &mut self.conn_ep
        };
        ep.respond(source, tid, ub, d, PAP_MAX_DATA_PER_PACKET, now);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! A packet-level stand-in for the Mac side, shared by the PAP
    //! server's own tests and by the printer roles built on it.
    use super::*;

    pub(crate) fn addr(node: u8, socket: u8) -> ServiceAddress {
        ServiceAddress {
            network_number: 0,
            node_number: node,
            socket_number: socket,
        }
    }

    /// A hand-rolled PAP client speaking through raw AtpEndpoints, standing
    /// in for the Mac side at the packet level.
    pub(crate) struct MiniClient {
        pub(crate) ep: AtpEndpoint,
        pub(crate) addr: ServiceAddress,
    }

    impl MiniClient {
        pub(crate) fn new(node: u8, socket: u8) -> Self {
            Self {
                ep: AtpEndpoint::new(socket),
                addr: addr(node, socket),
            }
        }

        /// OpenConn, naming this client's own socket as the responding one.
        pub(crate) fn open_conn(&mut self, listener: ServiceAddress, now: Micros) {
            let socket = self.addr.socket_number;
            let open = PapPacket {
                connection_id: socket,
                function: PapFunction::OpenConn,
                sequence_num: 0,
                eof: false,
                data: &[socket, FLOW_QUANTUM, 0, 0],
            };
            let (ub, d) = open.to_atp_parts();
            self.ep.request(listener, ub, d, 0x01, now);
        }
    }

    /// What [`shuttle`] needs of the server side: a bare [`PapServer`], or a
    /// printer role that wraps one.
    pub(crate) trait PapPeer {
        fn handle_datagram(
            &mut self,
            local_socket: u8,
            src: ServiceAddress,
            payload: &[u8],
            now: Micros,
        );
        fn poll_transmit(&mut self) -> Option<(u8, ServiceAddress, Vec<u8>)>;
    }

    impl PapPeer for PapServer {
        fn handle_datagram(
            &mut self,
            local_socket: u8,
            src: ServiceAddress,
            payload: &[u8],
            now: Micros,
        ) {
            PapServer::handle_datagram(self, local_socket, src, payload, now);
        }

        fn poll_transmit(&mut self) -> Option<(u8, ServiceAddress, Vec<u8>)> {
            PapServer::poll_transmit(self)
        }
    }

    /// Carry datagrams both ways until neither side has more to say.
    pub(crate) fn shuttle(
        server: &mut impl PapPeer,
        server_node: u8,
        client: &mut MiniClient,
        now: Micros,
    ) {
        loop {
            let mut progressed = false;
            while let Some((sock, dest, payload)) = server.poll_transmit() {
                assert_eq!(dest.node_number, client.addr.node_number);
                let src = ServiceAddress {
                    network_number: 0,
                    node_number: server_node,
                    socket_number: sock,
                };
                client.ep.handle_datagram(src, &payload, now);
                progressed = true;
            }
            while let Some((dest, payload)) = client.ep.poll_transmit() {
                server.handle_datagram(dest.socket_number, client.addr, &payload, now);
                progressed = true;
            }
            if !progressed {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{MiniClient, addr, shuttle};
    use super::*;

    #[test]
    fn status_open_stream_and_close() {
        let mut server = PapServer::new(190, 191);
        server.set_status(b"ready");
        server.set_sink_credit(64 * 1024, 0);
        let mut client = MiniClient {
            ep: AtpEndpoint::new(70),
            addr: addr(10, 70),
        };
        let listener = addr(130, 190);

        // SendStatus before connecting.
        let st = PapPacket {
            connection_id: 0,
            function: PapFunction::SendStatus,
            sequence_num: 0,
            eof: false,
            data: &[],
        };
        let (ub, d) = st.to_atp_parts();
        client.ep.request(listener, ub, d, 0x01, 0);
        shuttle(&mut server, 130, &mut client, 0);
        match client.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::Status);
                assert_eq!(&pap.data[4..], b"\x05ready");
            }
            other => panic!("{other:?}"),
        }

        // OpenConn: client responding socket is 70 (same endpoint).
        let open = PapPacket {
            connection_id: 70,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: &[70, 8, 0, 0],
        };
        let (ub, d) = open.to_atp_parts();
        client.ep.request(listener, ub, d, 0x01, 10);
        shuttle(&mut server, 130, &mut client, 10);

        let conn_socket = match client.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::OpenConnReply);
                assert_eq!(pap.connection_id, 70);
                assert_eq!(pap.data[1], FLOW_QUANTUM);
                assert_eq!(&pap.data[2..4], &[0, 0], "result must be accepted");
                pap.data[0]
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(conn_socket, 191);
        assert!(matches!(
            server.poll_event(),
            Some(PapEvent::ConnectionOpened { client }) if client.socket_number == 70
        ));

        // The server has already pulled: answer its SendData with job data.
        let (source, tid, pull_seq) = match client.ep.poll_event() {
            Some(AtpEvent::Request {
                source,
                tid,
                user_bytes,
                data,
                ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::SendData);
                assert_eq!(pap.sequence_num, 1);
                (source, tid, pap.sequence_num)
            }
            other => panic!("expected pull, got {other:?}"),
        };
        let _ = pull_seq;
        let job = PapPacket {
            connection_id: 70,
            function: PapFunction::Data,
            sequence_num: 0,
            eof: true,
            data: b"ESC codes",
        };
        let (ub, d) = job.to_atp_parts();
        client
            .ep
            .respond(source, tid, ub, d, PAP_MAX_DATA_PER_PACKET, 20);
        shuttle(&mut server, 130, &mut client, 20);

        assert_eq!(
            server.poll_event(),
            Some(PapEvent::ToPrinter(b"ESC codes".to_vec()))
        );
        assert_eq!(server.poll_event(), Some(PapEvent::JobEof));

        // CloseConn on the connection socket.
        let close = PapPacket {
            connection_id: 70,
            function: PapFunction::CloseConn,
            sequence_num: 0,
            eof: false,
            data: &[],
        };
        let (ub, d) = close.to_atp_parts();
        client.ep.request(addr(130, conn_socket), ub, d, 0x01, 30);
        shuttle(&mut server, 130, &mut client, 30);
        match client.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::CloseConnReply);
            }
            // The server's next pull may arrive first; either order is fine.
            Some(AtpEvent::Request { .. }) => match client.ep.poll_event() {
                Some(AtpEvent::Response {
                    user_bytes, data, ..
                }) => {
                    let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                    assert_eq!(pap.function, PapFunction::CloseConnReply);
                }
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
        let mut saw_closed = false;
        while let Some(ev) = server.poll_event() {
            if ev == PapEvent::ConnectionClosed {
                saw_closed = true;
            }
        }
        assert!(saw_closed);
        assert!(!server.busy());
    }

    #[test]
    fn no_pull_without_sink_credit() {
        let mut server = PapServer::new(190, 191);
        server.set_status(b"ok");
        // No credit reported yet.
        let mut client = MiniClient {
            ep: AtpEndpoint::new(70),
            addr: addr(10, 70),
        };
        let listener = addr(130, 190);
        let open = PapPacket {
            connection_id: 70,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: &[70, 8, 0, 0],
        };
        let (ub, d) = open.to_atp_parts();
        client.ep.request(listener, ub, d, 0x01, 0);
        shuttle(&mut server, 130, &mut client, 0);
        while client.ep.poll_event().is_some() {}

        // Starved sink: no SendData may be issued.
        server.poll(1_000_000);
        assert!(
            server.poll_transmit().is_none(),
            "pull issued with no credit"
        );

        // Credit appears: the pull follows.
        server.set_sink_credit(PULL_CAPACITY, 2_000_000);
        shuttle(&mut server, 130, &mut client, 2_000_000);
        match client.ep.poll_event() {
            Some(AtpEvent::Request {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::SendData);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn second_open_gets_busy_result() {
        let mut server = PapServer::new(190, 191);
        server.set_status(b"s");
        server.set_sink_credit(PULL_CAPACITY, 0);
        let mut client = MiniClient {
            ep: AtpEndpoint::new(70),
            addr: addr(10, 70),
        };
        let listener = addr(130, 190);
        let open = PapPacket {
            connection_id: 70,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: &[70, 8, 0, 0],
        };
        let (ub, d) = open.to_atp_parts();
        client.ep.request(listener, ub, d, 0x01, 0);
        shuttle(&mut server, 130, &mut client, 0);
        while client.ep.poll_event().is_some() {}

        let mut client2 = MiniClient {
            ep: AtpEndpoint::new(71),
            addr: addr(11, 71),
        };
        let open2 = PapPacket {
            connection_id: 71,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: &[71, 8, 0, 0],
        };
        let (ub, d) = open2.to_atp_parts();
        client2.ep.request(listener, ub, d, 0x01, 100);
        // Move only listener traffic for client2.
        loop {
            let mut progressed = false;
            while let Some((_, p)) = client2.ep.poll_transmit() {
                server.handle_datagram(190, client2.addr, &p, 100);
                progressed = true;
            }
            while let Some((sock, dest, p)) = server.poll_transmit() {
                if dest.node_number == 11 {
                    client2.ep.handle_datagram(addr(130, sock), &p, 100);
                } // traffic to client 1 (pulls) is dropped here
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
        match client2.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::OpenConnReply);
                assert_eq!(&pap.data[2..4], &[0xFF, 0xFF]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn client_read_gets_output_then_eof() {
        let mut server = PapServer::new(190, 191);
        server.set_status(b"s");
        server.set_sink_credit(PULL_CAPACITY, 0);
        let mut client = MiniClient {
            ep: AtpEndpoint::new(70),
            addr: addr(10, 70),
        };
        let listener = addr(130, 190);
        let open = PapPacket {
            connection_id: 70,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: &[70, 8, 0, 0],
        };
        let (ub, d) = open.to_atp_parts();
        client.ep.request(listener, ub, d, 0x01, 0);
        shuttle(&mut server, 130, &mut client, 0);
        while client.ep.poll_event().is_some() {}

        // Client read (SendData seq 1) with nothing queued: held.
        let read = PapPacket {
            connection_id: 70,
            function: PapFunction::SendData,
            sequence_num: 1,
            eof: false,
            data: &[],
        };
        let (ub, d) = read.to_atp_parts();
        client.ep.request(addr(130, 191), ub, d, 0xFF, 10);
        shuttle(&mut server, 130, &mut client, 10);
        assert!(client.ep.poll_event().is_none(), "read must be held");

        // Printer output arrives: the held read is answered with it at once
        // (the end marker is not known yet, so no eof).
        server.queue_output(b"%%[ status: idle ]%%", 20);
        shuttle(&mut server, 130, &mut client, 20);
        match client.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::Data);
                assert!(!pap.eof);
                assert_eq!(pap.data, b"%%[ status: idle ]%%");
            }
            other => panic!("{other:?}"),
        }

        // The stream ends; the next read drains empty with the eof flag.
        server.end_output(30);
        let read2 = PapPacket {
            connection_id: 70,
            function: PapFunction::SendData,
            sequence_num: 2,
            eof: false,
            data: &[],
        };
        let (ub, d) = read2.to_atp_parts();
        client.ep.request(addr(130, 191), ub, d, 0xFF, 30);
        shuttle(&mut server, 130, &mut client, 30);
        match client.ep.poll_event() {
            Some(AtpEvent::Response {
                user_bytes, data, ..
            }) => {
                let pap = PapPacket::parse_from_atp(user_bytes, &data).unwrap();
                assert_eq!(pap.function, PapFunction::Data);
                assert!(pap.eof);
                assert!(pap.data.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
}
