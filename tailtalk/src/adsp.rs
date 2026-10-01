use crate::ddp::{DdpAddress, DdpHandle, DdpSocket};
use bytes::BytesMut;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tailtalk_packets::{
    ddp::DdpProtocolType,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tailtalk_core::Micros;
use tailtalk_core::adsp::{AdspEndpoint, AdspEvent};

/// Advertised receive window. `tailtalk-core`'s default is deliberately
/// small; a desktop has memory to spare and asks for more.
const ADSP_RECV_WINDOW: u16 = 4096;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;



/// ADSP network address
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AdspAddress {
    pub network_number: u16,
    pub node_number: u8,
    pub socket_number: u8,
}

impl From<tailtalk_packets::nbp::ServiceAddress> for AdspAddress {
    fn from(a: tailtalk_packets::nbp::ServiceAddress) -> Self {
        AdspAddress {
            network_number: a.network_number,
            node_number: a.node_number,
            socket_number: a.socket_number,
        }
    }
}

fn service_addr(addr: AdspAddress) -> tailtalk_packets::nbp::ServiceAddress {
    tailtalk_packets::nbp::ServiceAddress {
        network_number: addr.network_number,
        node_number: addr.node_number,
        socket_number: addr.socket_number,
    }
}

fn ddp_dest(addr: AdspAddress) -> DdpAddress {
    DdpAddress::new(
        tailtalk_packets::aarp::AppleTalkAddress {
            network_number: addr.network_number,
            node_number: addr.node_number,
        },
        addr.socket_number,
    )
}

/// The host-side half of one connection: the channels feeding its
/// [`AdspStream`], and the callers waiting on operations the state machine
/// has not finished yet.
///
/// Everything protocol-shaped - sequence numbers, windows, flight buffers,
/// retransmission - lives in [`AdspEndpoint`] and is shared with the
/// embedded firmware. What is left here is strictly the tokio adaptation.
struct StreamPlumbing {
    /// Received data, and whether the peer ended a message with it.
    data_tx: mpsc::Sender<(Vec<u8>, bool)>,
    attn_tx: mpsc::Sender<(u16, Vec<u8>)>,
    /// Writes handed to the endpoint, oldest first. Each caller's flush
    /// completes when the endpoint reports that write fully cut into
    /// packets, which is when the peer's window has admitted every byte.
    writes: std::collections::VecDeque<(u64, oneshot::Sender<io::Result<()>>)>,
    /// ADSP permits one attention in flight per connection (spec 12), and
    /// the endpoint enforces that. This crate's API queues rather than
    /// rejects, so the queue lives here.
    attn_inflight: Option<oneshot::Sender<io::Result<()>>>,
    attn_queue: std::collections::VecDeque<(u16, Vec<u8>, oneshot::Sender<io::Result<()>>)>,
}

impl StreamPlumbing {
    /// Fail every caller still waiting on this connection. Dropping the
    /// senders afterwards is what gives a blocked reader its EOF.
    fn fail_all(&mut self, why: &'static str) {
        for (_, reply) in self.writes.drain(..) {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::ConnectionAborted, why)));
        }
        if let Some(reply) = self.attn_inflight.take() {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::NotConnected, why)));
        }
        for (_, _, reply) in self.attn_queue.drain(..) {
            let _ = reply.send(Err(io::Error::new(io::ErrorKind::NotConnected, why)));
        }
    }
}

// ── Actor command channel ─────────────────────────────────────────────────────
//
// All AdspStream instances share a clone of the same mpsc::Sender<ActorCmd>.
// This replaces the old per-connection command_rx on each connection, which
// required busy-polling every connection's channel before each select! tick.

enum ActorCmd {
    SendData {
        conn_id: u16,
        data: Vec<u8>,
        eom: bool,
        reply: oneshot::Sender<io::Result<()>>,
    },
    SendAttention {
        conn_id: u16,
        code: u16,
        data: Vec<u8>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    Close {
        conn_id: u16,
        reply: oneshot::Sender<io::Result<()>>,
    },
}

// ── Adsp actor ────────────────────────────────────────────────────────────────

pub struct Adsp {
    sock: DdpSocket,
    /// The protocol state machine, shared with the embedded firmware.
    endpoint: AdspEndpoint,
    /// Per-connection host plumbing, keyed the same way the endpoint keys
    /// connections (by the peer's ConnID).
    streams: HashMap<u16, StreamPlumbing>,
    accept_tx: Option<mpsc::Sender<AdspStream>>,
    /// Outbound connects awaiting their `Opened`, keyed by the handle
    /// [`AdspEndpoint::connect`] returned.
    pending_opens: HashMap<u16, oneshot::Sender<io::Result<AdspStream>>>,
    /// Outbound connect handle -> the key its connection currently has. The
    /// endpoint re-keys a connection if a peer answers a retransmitted open
    /// with a second ConnID and then uses it; this is how the plumbing
    /// follows it.
    outbound_key: HashMap<u16, u16>,
    cmd_rx: mpsc::Receiver<ActorCmd>,
    /// Cloned into each AdspStream so they can send commands back.
    cmd_tx: mpsc::Sender<ActorCmd>,
    /// The endpoint takes monotonic microseconds; this is their zero point.
    epoch: std::time::Instant,
}

impl Adsp {
    pub async fn bind(ddp: &DdpHandle, socket_number: Option<u8>) -> io::Result<(u8, AdspListener)> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, socket_number)
            .await
            .map_err(io::Error::other)?;
        let actual_socket = sock.socket_num();
        let (accept_tx, accept_rx) = mpsc::channel(10);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        let mut endpoint = AdspEndpoint::new(actual_socket, rand::random());
        endpoint.set_recv_window(ADSP_RECV_WINDOW);
        endpoint.set_listening(true);

        let adsp = Adsp {
            sock,
            endpoint,
            streams: HashMap::new(),
            accept_tx: Some(accept_tx),
            pending_opens: HashMap::new(),
            outbound_key: HashMap::new(),
            cmd_rx,
            cmd_tx,
            epoch: std::time::Instant::now(),
        };

        tokio::spawn(async move { adsp.run().await });

        Ok((actual_socket, AdspListener { local_socket: actual_socket, accept_rx }))
    }

    pub async fn connect(ddp: &DdpHandle, remote_addr: AdspAddress) -> io::Result<AdspStream> {
        let sock = ddp
            .new_sock(DdpProtocolType::Adsp, None)
            .await
            .map_err(io::Error::other)?;
        let local_socket = sock.socket_num();
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();

        let mut endpoint = AdspEndpoint::new(local_socket, rand::random());
        endpoint.set_recv_window(ADSP_RECV_WINDOW);

        let mut adsp = Adsp {
            sock,
            endpoint,
            streams: HashMap::new(),
            accept_tx: None,
            pending_opens: HashMap::new(),
            outbound_key: HashMap::new(),
            cmd_rx,
            cmd_tx,
            epoch: std::time::Instant::now(),
        };

        let now = adsp.now();
        let handle = adsp.endpoint.connect(service_addr(remote_addr), now);
        adsp.pending_opens.insert(handle, ready_tx);
        tokio::spawn(async move { adsp.run().await });

        ready_rx.await.map_err(io::Error::other)?
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn now(&self) -> Micros {
        self.epoch.elapsed().as_micros() as Micros
    }

    fn make_stream(
        &self,
        conn_id: u16,
        remote_addr: AdspAddress,
        data_rx: mpsc::Receiver<(Vec<u8>, bool)>,
        attn_rx: mpsc::Receiver<(u16, Vec<u8>)>,
    ) -> AdspStream {
        AdspStream {
            conn_id,
            remote_addr,
            cmd_tx: self.cmd_tx.clone(),
            read: std::sync::Mutex::new(ReadState::new(data_rx)),
            attn_rx: std::sync::Mutex::new(attn_rx),
            write_buf: BytesMut::new(),
            flush_tx: PollSender::new(self.cmd_tx.clone()),
            flush_reply: None,
        }
    }

    /// Build the host plumbing for a newly opened connection and hand back
    /// the stream its owner will hold.
    fn attach_stream(&mut self, conn: u16, remote: AdspAddress) -> AdspStream {
        let (data_tx, data_rx) = mpsc::channel(32);
        let (attn_tx, attn_rx) = mpsc::channel(8);
        self.streams.insert(conn, StreamPlumbing {
            data_tx,
            attn_tx,
            writes: std::collections::VecDeque::new(),
            attn_inflight: None,
            attn_queue: std::collections::VecDeque::new(),
        });
        self.make_stream(conn, remote, data_rx, attn_rx)
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    async fn run(mut self) {
        // Flush anything queued before the loop started - `connect` puts an
        // open request in the endpoint's outbox.
        self.pump().await;

        loop {
            let wait = self.endpoint.next_deadline().map(|deadline| {
                std::time::Duration::from_micros(deadline.saturating_sub(self.now()))
            });

            tokio::select! {
                pkt = self.sock.recv() => {
                    match pkt {
                        Ok(p) => {
                            let src = tailtalk_packets::nbp::ServiceAddress {
                                network_number: p.headers.src_network_num,
                                node_number: p.headers.src_node_id,
                                socket_number: p.headers.src_sock_num,
                            };
                            let now = self.now();
                            self.endpoint.handle_datagram(src, &p.payload, now);
                        }
                        Err(e) => {
                            tracing::error!("ADSP socket error: {e}");
                            break;
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_cmd(c),
                        None => break,
                    }
                }
                _ = async {
                    match wait {
                        Some(d) => tokio::time::sleep(d).await,
                        // No deadline: park until one of the other branches
                        // wakes us and recomputes it.
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let now = self.now();
                    self.endpoint.poll(now);
                }
            }

            self.pump().await;
        }
    }

    fn handle_cmd(&mut self, cmd: ActorCmd) {
        match cmd {
            ActorCmd::SendData { conn_id, data, eom, reply } => {
                match self.endpoint.send(conn_id, &data, eom) {
                    Ok(write_id) => {
                        if let Some(plumbing) = self.streams.get_mut(&conn_id) {
                            plumbing.writes.push_back((write_id, reply));
                        }
                    }
                    Err(_) => {
                        let _ = reply.send(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "connection is gone",
                        )));
                    }
                }
            }
            ActorCmd::SendAttention { conn_id, code, data, reply } => {
                let Some(plumbing) = self.streams.get_mut(&conn_id) else {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection is gone",
                    )));
                    return;
                };
                // One at a time on the wire; the rest wait their turn.
                if plumbing.attn_inflight.is_some() {
                    plumbing.attn_queue.push_back((code, data, reply));
                    return;
                }
                let now = self.now();
                match self.endpoint.send_attention(conn_id, code, &data, now) {
                    Ok(()) => {
                        self.streams.get_mut(&conn_id).unwrap().attn_inflight = Some(reply);
                    }
                    Err(e) => {
                        let _ = reply.send(Err(io::Error::other(format!(
                            "attention rejected: {e:?}"
                        ))));
                    }
                }
            }
            ActorCmd::Close { conn_id, reply } => {
                self.endpoint.close(conn_id);
                if let Some(mut plumbing) = self.streams.remove(&conn_id) {
                    plumbing.fail_all("connection closed");
                }
                self.outbound_key.retain(|_, key| *key != conn_id);
                let _ = reply.send(Ok(()));
            }
        }
    }

    /// Drain the endpoint until it is quiescent: put its packets on the
    /// wire, deliver its events, and settle any callers whose work the last
    /// round completed. Events can queue further packets, so this loops.
    async fn pump(&mut self) {
        loop {
            let mut progressed = false;

            while let Some((dest, payload)) = self.endpoint.poll_transmit() {
                progressed = true;
                if let Err(e) = self.sock.send_to(&payload, ddp_dest(dest.into())).await {
                    tracing::warn!("ADSP send failed: {e}");
                }
            }

            while let Some(event) = self.endpoint.poll_event() {
                progressed = true;
                self.handle_event(event).await;
            }

            self.settle_writes();

            if !progressed {
                break;
            }
        }
    }

    async fn handle_event(&mut self, event: AdspEvent) {
        match event {
            AdspEvent::Opened { conn, remote, inbound, pending } => {
                let remote = remote.into();
                if inbound {
                    tracing::info!("ADSP accepting conn {} from {:?}", conn, remote);
                    let stream = self.attach_stream(conn, remote);
                    if let Some(tx) = &self.accept_tx {
                        let _ = tx.send(stream).await;
                    }
                    return;
                }

                let handle = pending.unwrap_or(conn);
                if let Some(ready) = self.pending_opens.remove(&handle) {
                    tracing::info!("ADSP conn established: conn={} remote={:?}", conn, remote);
                    let stream = self.attach_stream(conn, remote);
                    self.outbound_key.insert(handle, conn);
                    let _ = ready.send(Ok(stream));
                } else if let Some(old) = self.outbound_key.insert(handle, conn) {
                    // Re-key: the peer answered a retransmitted open with a
                    // second ConnID and moved to it. Carry the plumbing over
                    // rather than stranding the stream its owner holds.
                    if old != conn && let Some(plumbing) = self.streams.remove(&old) {
                        tracing::debug!("ADSP conn {} re-keyed to {}", old, conn);
                        self.streams.insert(conn, plumbing);
                    }
                }
            }
            AdspEvent::OpenFailed { conn } => {
                if let Some(ready) = self.pending_opens.remove(&conn) {
                    let _ = ready.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "peer never completed the ADSP open",
                    )));
                }
            }
            // An empty chunk still counts: if a peer marks the end of a
            // message after its data has already gone out, the flag arrives
            // in an empty packet.
            AdspEvent::Data { conn, data, eom } => {
                if let Some(plumbing) = self.streams.get(&conn)
                    && plumbing.data_tx.send((data, eom)).await.is_err()
                {
                    // Reader dropped; the connection is no longer useful.
                    tracing::debug!("ADSP conn {} reader gone", conn);
                }
            }
            AdspEvent::Attention { conn, code, data } => {
                if let Some(plumbing) = self.streams.get(&conn) {
                    let _ = plumbing.attn_tx.send((code, data)).await;
                }
            }
            AdspEvent::AttentionAcked { conn } => {
                self.finish_attention(conn, Ok(()));
            }
            AdspEvent::AttentionFailed { conn } => {
                self.finish_attention(
                    conn,
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "attention message was never acknowledged",
                    )),
                );
            }
            AdspEvent::Closed { conn } => {
                tracing::info!("ADSP conn {} closed", conn);
                if let Some(mut plumbing) = self.streams.remove(&conn) {
                    plumbing.fail_all("connection closed");
                }
                self.outbound_key.retain(|_, key| *key != conn);
            }
        }
    }

    /// Settle the caller waiting on this connection's in-flight attention,
    /// then start whatever queued behind it.
    fn finish_attention(&mut self, conn: u16, result: io::Result<()>) {
        let Some(plumbing) = self.streams.get_mut(&conn) else { return };
        if let Some(reply) = plumbing.attn_inflight.take() {
            let _ = reply.send(result);
        }
        let Some((code, data, reply)) = plumbing.attn_queue.pop_front() else { return };
        let now = self.now();
        match self.endpoint.send_attention(conn, code, &data, now) {
            Ok(()) => {
                self.streams.get_mut(&conn).unwrap().attn_inflight = Some(reply);
            }
            Err(e) => {
                let _ = reply.send(Err(io::Error::other(format!(
                    "attention rejected: {e:?}"
                ))));
            }
        }
    }

    /// Complete every write the endpoint has finished cutting into packets.
    fn settle_writes(&mut self) {
        for (conn, plumbing) in self.streams.iter_mut() {
            let Some(completed) = self.endpoint.writes_completed(*conn) else { continue };
            while plumbing.writes.front().is_some_and(|(id, _)| *id <= completed) {
                let (_, reply) = plumbing.writes.pop_front().expect("just checked");
                let _ = reply.send(Ok(()));
            }
        }
    }
}

// ── AdspStream ────────────────────────────────────────────────────────────────
//
// AdspStream: Unpin — all fields are Unpin (Box<T>: Unpin unconditionally, so
// Pin<Box<dyn Future>>: Unpin), which lets us use Pin::get_mut() freely in the
// poll_* impls and store a boxed future across poll_flush invocations.

/// The receive half of an [`AdspStream`]: the channel carrying chunks from the
/// actor, plus whatever a short read left over from the last chunk.
///
/// These two are one lock rather than two because every read touches both, and
/// splitting them would mean a lock ordering that a later edit could get
/// wrong. One mutex makes that class of bug unrepresentable.
///
/// The lock is only ever held across a `poll_recv` and a buffer copy, never
/// across an `.await`, so it is uncontended in practice and cannot stall the
/// runtime.
struct ReadState {
    rx: mpsc::Receiver<(Vec<u8>, bool)>,
    /// Bytes the actor has delivered that nobody has read yet.
    held: BytesMut,
    /// Where messages end in `held`, as offsets from its front.
    eoms: std::collections::VecDeque<usize>,
}

impl ReadState {
    fn new(rx: mpsc::Receiver<(Vec<u8>, bool)>) -> Self {
        Self { rx, held: BytesMut::new(), eoms: Default::default() }
    }

    /// Move the next chunk from the actor into `held`. `false` once the
    /// actor has hung up, which is the end of the stream.
    fn poll_chunk(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some((data, eom))) => {
                self.held.extend_from_slice(&data);
                if eom {
                    self.eoms.push_back(self.held.len());
                }
                Poll::Ready(true)
            }
            Poll::Ready(None) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Ready once there is something to read, if only the end of an empty
    /// message, or the stream has ended.
    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        while self.held.is_empty() && self.eoms.is_empty() {
            if !std::task::ready!(self.poll_chunk(cx)) {
                break;
            }
        }
        Poll::Ready(())
    }

    /// Up to `max` held bytes, stopping at the end of a message, and whether
    /// they reached it.
    fn take(&mut self, max: usize) -> (BytesMut, bool) {
        let to_end = self.eoms.front().copied().unwrap_or(self.held.len());
        let n = to_end.min(max);
        self.eoms.iter_mut().for_each(|e| *e -= n);
        let eom = self.eoms.front() == Some(&0);
        if eom {
            self.eoms.pop_front();
        }
        (self.held.split_to(n), eom)
    }

    /// [`ReadState::take`] for a byte stream reader, ready once there is at
    /// least one byte or the stream has ended. Empty messages are skipped,
    /// since an empty read means the end of the stream.
    fn poll_take(&mut self, cx: &mut Context<'_>, max: usize) -> Poll<BytesMut> {
        loop {
            std::task::ready!(self.poll_readable(cx));
            match self.take(max) {
                (bytes, true) if bytes.is_empty() && max > 0 => continue,
                (bytes, _) => return Poll::Ready(bytes),
            }
        }
    }

    /// The next whole message, waiting for its end to arrive.
    fn poll_message(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            if let Some(end) = self.eoms.pop_front() {
                self.eoms.iter_mut().for_each(|e| *e -= end);
                return Poll::Ready(Ok(Some(self.held.split_to(end).to_vec())));
            }
            if !std::task::ready!(self.poll_chunk(cx)) {
                return Poll::Ready(if self.held.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "ADSP connection closed in the middle of a message",
                    ))
                });
            }
        }
    }
}

/// An open ADSP connection: a byte stream plus an out-of-band attention queue.
///
/// Read the byte stream with [`read_data`](Self::read_data) or the
/// [`AsyncRead`] impl, write with the [`AsyncWrite`] impl, and take
/// out-of-band messages with [`attention`](Self::attention). A peer that
/// frames its data in ADSP messages is read with
/// [`read_message`](Self::read_message) and written with
/// [`write_eom`](Self::write_eom) after each message.
///
/// # Cancel safety
///
/// [`read_data`](Self::read_data) and [`attention`](Self::attention) both take
/// `&self` and are cancel-safe, so a `select!` can await both at once and drop
/// the loser each iteration without losing data:
///
/// ```no_run
/// # async fn f(stream: &tailtalk::adsp::AdspStream) -> std::io::Result<()> {
/// let mut buf = [0u8; 512];
/// loop {
///     tokio::select! {
///         n = stream.read_data(&mut buf) => { let n = n?; }
///         Some((code, body)) = stream.attention() => {}
///     }
/// }
/// # }
/// ```
pub struct AdspStream {
    conn_id: u16,
    remote_addr: AdspAddress,
    cmd_tx: mpsc::Sender<ActorCmd>,
    /// The receive queue and its leftover buffer under one lock, so the two
    /// can never be acquired in conflicting orders. See [`ReadState`].
    read: std::sync::Mutex<ReadState>,
    /// Behind a mutex so [`AdspStream::attention`] can take `&self` and
    /// therefore share a `tokio::select!` with [`AdspStream::read_data`].
    /// Uncontended in practice: the lock is held only for the duration of a
    /// single non-blocking poll.
    attn_rx: std::sync::Mutex<mpsc::Receiver<(u16, Vec<u8>)>>,
    write_buf: BytesMut,
    /// `cmd_tx` again, in a form [`AsyncWrite::poll_flush`] can send on.
    flush_tx: PollSender<ActorCmd>,
    /// The actor's answer to the send a flush is waiting on.
    flush_reply: Option<oneshot::Receiver<io::Result<()>>>,
}

// A task can only hold a `&self` read across an await if the stream is `Sync`.
const _: fn() = || {
    fn sync<T: Sync>() {}
    sync::<AdspStream>();
};

impl AdspStream {
    pub fn remote_addr(&self) -> AdspAddress {
        self.remote_addr
    }

    /// Send an ADSP attention message with the given 16-bit code and payload.
    ///
    /// Attention messages are out-of-band from the normal data stream; they
    /// are delivered to the peer using a separate sequence number space and
    /// a dedicated descriptor (Control=0, AckReq=1, Attn=1).
    pub async fn send_attention(&mut self, code: u16, data: &[u8]) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ActorCmd::SendAttention {
                conn_id: self.conn_id,
                code,
                data: data.to_vec(),
                reply: tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?
    }

    /// The body of [`AsyncRead::poll_read`], written against `&self` so both
    /// the trait impl and [`read`](Self::read) can share it.
    fn poll_read_shared(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut read = self.read.lock().expect("read state poisoned");
        let bytes = std::task::ready!(read.poll_take(cx, buf.remaining()));
        buf.put_slice(&bytes);
        Poll::Ready(Ok(()))
    }

    /// Read stream bytes into `buf`, returning the number read (`0` at EOF).
    /// A read stops at the end of a message, as the Mac's `dspRead` does, so
    /// it can come up short.
    ///
    /// Equivalent to [`AsyncReadExt::read`](tokio::io::AsyncReadExt::read) but
    /// takes `&self`, so it can share a `tokio::select!` with
    /// [`attention`](Self::attention).
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: a future dropped before it resolves leaves the stream
    /// exactly as it found it, so a read that loses a `select!` race costs no
    /// data and a later read returns the same bytes. Data arriving while no
    /// read is outstanding stays queued.
    ///
    /// A read whose buffer is smaller than the available data keeps the
    /// remainder for the next call rather than discarding it, so a small
    /// buffer costs extra calls, never bytes.
    ///
    /// As with any async fn, a future dropped *after* it resolves has already
    /// done its work — the bytes it returned are consumed even if the caller
    /// discards them. `select!` cannot do this (it always runs the handler of
    /// a branch that resolves); only a hand-written poll loop can.
    ///
    /// Named distinctly rather than `read` so it does not shadow the
    /// `AsyncReadExt` method for existing callers, which would silently change
    /// which function a bare `.read(..)` resolves to.
    pub async fn read_data(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Nothing is taken until the poll that returns it, so a dropped
        // future cannot strand bytes.
        let bytes = std::future::poll_fn(|cx| {
            self.read.lock().expect("read state poisoned").poll_take(cx, buf.len())
        })
        .await;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    /// Read stream bytes as the Mac's `dspRead` does: up to `buf.len()`, but
    /// never past the end of a message. Returns how many, and whether they
    /// reached the end of a message. A message longer than `buf` comes in
    /// several reads, the last with the flag set, and an empty one as
    /// `(0, true)`. `(0, false)` at EOF.
    ///
    /// Takes `&self` and is cancel-safe, like [`read_data`](Self::read_data).
    pub async fn read_with_eom(&self, buf: &mut [u8]) -> io::Result<(usize, bool)> {
        let (bytes, eom) = std::future::poll_fn(|cx| {
            let mut read = self.read.lock().expect("read state poisoned");
            std::task::ready!(read.poll_readable(cx));
            Poll::Ready(read.take(buf.len()))
        })
        .await;
        buf[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), eom))
    }

    /// Read one whole message: everything up to the peer's next
    /// end-of-message. `None` once the connection has closed between
    /// messages; a close in the middle of one is an
    /// [`UnexpectedEof`](io::ErrorKind::UnexpectedEof) error.
    ///
    /// Takes `&self` and is cancel-safe, like [`read_data`](Self::read_data):
    /// a message leaves the stream only in the poll that returns it.
    pub async fn read_message(&self) -> io::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| self.read.lock().expect("read state poisoned").poll_message(cx)).await
    }

    /// Receive the next ADSP attention message from the peer, as
    /// `(code, body)`.
    ///
    /// Attention messages are out-of-band: they arrive on their own sequence
    /// space and are queued separately from the byte stream, so this never
    /// consumes or reorders data that [`AsyncRead`] would return. Waits until
    /// one arrives, yielding `None` once the connection is gone and no queued
    /// messages remain.
    ///
    /// Takes `&self`, as does [`read_data`](Self::read_data), so the two compose
    /// directly in a single `tokio::select!` with no splitting — the shape a
    /// server needs when it must react to out-of-band messages while a
    /// transfer is in progress (the StyleWriter adapter protocol interleaves
    /// both on one connection):
    ///
    /// ```no_run
    /// # async fn f(stream: &tailtalk::adsp::AdspStream) -> std::io::Result<()> {
    /// let mut buf = [0u8; 512];
    /// loop {
    ///     tokio::select! {
    ///         n = stream.read_data(&mut buf) => { let n = n?; /* raster bytes */ }
    ///         Some((code, body)) = stream.attention() => { /* 0x000b, 0x0006, ... */ }
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// # Cancel safety
    ///
    /// Cancel-safe: a message leaves the queue only on a poll that resolves,
    /// so a future dropped before then — the losing branch of a `select!` —
    /// costs nothing, and the message is still waiting for the next call.
    ///
    /// As with [`read_data`](Self::read_data), a future dropped after it
    /// resolves has already taken its message. `select!` never does this; only
    /// a hand-written poll loop can.
    pub async fn attention(&self) -> Option<(u16, Vec<u8>)> {
        std::future::poll_fn(|cx| {
            let mut rx = self.attn_rx.lock().expect("attention queue poisoned");
            rx.poll_recv(cx)
        })
        .await
    }

    /// Receive the next attention message if one is already queued, without
    /// waiting.
    ///
    /// `None` covers both "nothing pending" and "connection gone"; use
    /// [`attention`](Self::attention) when that distinction matters.
    ///
    /// Synchronous, so cancellation does not apply.
    pub fn try_attention(&self) -> Option<(u16, Vec<u8>)> {
        self.attn_rx
            .lock()
            .expect("attention queue poisoned")
            .try_recv()
            .ok()
    }

    /// Flush the write buffer and mark the message boundary with the EOM flag.
    /// This is the ADSP-specific alternative to a bare flush — use it when the
    /// peer expects record-oriented framing (e.g. PAP / StyleWriter).
    pub async fn write_eom(&mut self) -> io::Result<()> {
        let data = self.write_buf.split().to_vec();
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ActorCmd::SendData {
                conn_id: self.conn_id,
                data,
                eom: true,
                reply: tx,
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead"))?
    }

    /// Send a CloseAdvice and shut down the connection.
    pub async fn close(self) -> io::Result<()> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ActorCmd::Close { conn_id: self.conn_id, reply: tx })
            .await;
        rx.await.unwrap_or(Ok(()))
    }
}

impl AsyncRead for AdspStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_shared(cx, buf)
    }
}

impl AsyncWrite for AdspStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let actor_dead = || io::Error::new(io::ErrorKind::BrokenPipe, "adsp actor dead");

        if this.flush_reply.is_none() {
            if this.write_buf.is_empty() {
                return Poll::Ready(Ok(()));
            }
            // Ship the write buffer to the actor once there's room for it.
            std::task::ready!(this.flush_tx.poll_reserve(cx)).map_err(|_| actor_dead())?;
            let (reply, flush_reply) = oneshot::channel();
            let data = this.write_buf.split().to_vec();
            this.flush_tx
                .send_item(ActorCmd::SendData { conn_id: this.conn_id, data, eom: false, reply })
                .map_err(|_| actor_dead())?;
            this.flush_reply = Some(flush_reply);
        }

        // The actor answers once the peer's window has taken every byte.
        let reply = this.flush_reply.as_mut().expect("a send in flight");
        let result = std::task::ready!(Pin::new(reply).poll(cx));
        this.flush_reply = None;
        Poll::Ready(result.unwrap_or_else(|_| Err(actor_dead())))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any buffered data, then the actor will handle the close.
        self.poll_flush(cx)
    }
}

// ── AdspListener ──────────────────────────────────────────────────────────────

pub struct AdspListener {
    local_socket: u8,
    accept_rx: mpsc::Receiver<AdspStream>,
}

impl AdspListener {
    pub async fn accept(&mut self) -> io::Result<AdspStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "listener closed"))
    }

    pub fn local_addr(&self) -> u8 {
        self.local_socket
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a stream fed by the returned sender, with no actor or socket
    /// behind it, so a test drives the receive queue directly.
    fn test_stream() -> (AdspStream, mpsc::Sender<(Vec<u8>, bool)>) {
        let (data_tx, data_rx) = mpsc::channel(8);
        let (_attn_tx, attn_rx) = mpsc::channel(8);
        let (cmd_tx, _cmd_rx) = mpsc::channel(8);
        let stream = AdspStream {
            conn_id: 1,
            remote_addr: AdspAddress { network_number: 1, node_number: 2, socket_number: 3 },
            cmd_tx: cmd_tx.clone(),
            read: std::sync::Mutex::new(ReadState::new(data_rx)),
            attn_rx: std::sync::Mutex::new(attn_rx),
            write_buf: BytesMut::new(),
            flush_tx: PollSender::new(cmd_tx),
            flush_reply: None,
        };
        (stream, data_tx)
    }

    /// A read whose buffer is smaller than the arriving chunk must keep the
    /// remainder reachable.
    ///
    /// This also covers the cancellation contract: `read_data` waits without
    /// consuming and only takes bytes after it resolves, so the remainder has
    /// to survive in `ReadState::held` between calls. A `select!`-based
    /// test cannot add to this — the macro always runs the handler of a branch
    /// that resolves, so a dropped losing branch has taken nothing to lose.
    #[tokio::test]
    async fn read_data_preserves_partial_chunk_remainder() {
        let (stream, data_tx) = test_stream();
        data_tx.send((b"ABCDEFGH".to_vec(), false)).await.expect("send failed");

        let mut first = [0u8; 4];
        let n = stream.read_data(&mut first).await.expect("read failed");
        assert_eq!(&first[..n], b"ABCD");

        let mut second = [0u8; 8];
        let n2 = stream.read_data(&mut second).await.expect("read failed");
        assert_eq!(&second[..n2], b"EFGH", "the chunk remainder was stranded");
    }

    /// A message is everything up to its end, however the peer's packets
    /// cut it, and a bare end-of-message closes one too.
    #[tokio::test]
    async fn read_message_follows_the_peers_boundaries() {
        let (stream, data_tx) = test_stream();
        for (data, eom) in [("he", false), ("llo", true), ("x", false), ("", true), ("y", false)] {
            data_tx.send((data.into(), eom)).await.expect("send failed");
        }
        drop(data_tx);

        assert_eq!(stream.read_message().await.unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(stream.read_message().await.unwrap().as_deref(), Some(&b"x"[..]));
        let cut_off = stream.read_message().await.unwrap_err();
        assert_eq!(cut_off.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Reads stop at each message's end and say when they reach it, a long
    /// message comes in parts, and an empty one reads as `(0, true)`. A byte
    /// stream read stops at a message's end too.
    #[tokio::test]
    async fn reads_stop_at_the_end_of_each_message() {
        let (stream, data_tx) = test_stream();
        for (data, eom) in [("abc", false), ("de", true), ("", true), ("f", true), ("g", true), ("h", true)] {
            data_tx.send((data.into(), eom)).await.expect("send failed");
        }

        // However the parts fall, they add up to the message and only the
        // last carries the flag.
        let mut buf = [0u8; 2];
        let mut message = Vec::new();
        loop {
            let (n, eom) = stream.read_with_eom(&mut buf).await.unwrap();
            message.extend_from_slice(&buf[..n]);
            if eom {
                break;
            }
        }
        assert_eq!(message, b"abcde");
        assert_eq!(stream.read_with_eom(&mut buf).await.unwrap(), (0, true));
        assert_eq!(stream.read_with_eom(&mut buf).await.unwrap(), (1, true));
        assert_eq!(buf[0], b'f');

        let mut buf = [0u8; 8];
        assert_eq!(stream.read_data(&mut buf).await.unwrap(), 1);
        assert_eq!(buf[0], b'g');
    }
}
