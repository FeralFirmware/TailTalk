//! ADSP: Apple's funny TCP equivalent. This module is a no_std embeddable version
//! of ADSP for use in both TailTalk desktop and InkTalk. It can be thought of as
//! similar to TCP, with the main differences being ADSP does not
//! support out of order packets (they're simply thrown away), not all packets need
//! to be acked, and it has a built in side channel called "Attention" packets.
//!
//! The only real use I have found for ADSP is StyleWriter printing over AppleTalk. The
//! official adapters all use ADSP and this is the same use case we use for this.
//!
//! [`AdspListener::accept`] and [`AdspStream::connect`] hand out streams,
//! which implement `embedded_io_async` on both `stream` and `&stream`. Every
//! method takes `&self`, so one task can wait on data and attentions at once:
//!
//! ```ignore
//! loop {
//!     match select(stream.read_data(&mut buf), stream.attention()).await {
//!         Either::First(n) => { /* n bytes; 0 at end of stream */ }
//!         Either::Second(Some((code, body))) => { /* out of band */ }
//!         Either::Second(None) => break, // closed
//!     }
//! }
//! ```

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use embedded_io_async::{ErrorKind, ErrorType, Read, Write};
use tailtalk_core::Micros;
use tailtalk_core::adsp::{ADSP_MAX_DATA, AdspEndpoint, AdspError as CoreError, AdspEvent};
use tailtalk_core::ddp::Datagram;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Platform;
use crate::net::{BindError, Hosted, Net, Transmit};

/// Received bytes a connection holds for a reader before its window
/// closes.
pub const RX_WINDOW: usize = 4096;

/// Bytes a connection holds toward its peer before a write waits.
pub const TX_BUFFER: usize = 4096;

/// Inbound connections held for a listener that has not accepted them.
/// Past this, new ones are closed as they open.
const ACCEPT_QUEUE_LEN: usize = 4;

/// Attention messages held for a reader. Past this, new ones are dropped;
/// they were acknowledged on arrival, so the peer will not resend them.
const ATTN_QUEUE_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdspError {
    /// No socket was free to connect from.
    NoSocket,
    /// The peer refused the connection or never answered.
    OpenFailed,
    /// The connection closed: the peer closed it, or it stopped answering
    /// retransmissions.
    Closed,
    /// An attention message went unacknowledged through every retry.
    AttentionUnacknowledged,
}

impl embedded_io_async::Error for AdspError {
    fn kind(&self) -> ErrorKind {
        match self {
            AdspError::NoSocket => ErrorKind::AddrNotAvailable,
            AdspError::OpenFailed => ErrorKind::ConnectionRefused,
            AdspError::Closed => ErrorKind::NotConnected,
            AdspError::AttentionUnacknowledged => ErrorKind::TimedOut,
        }
    }
}

/// Where a connection's one permitted outgoing attention stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attn {
    Idle,
    /// Sent. `abandoned` when its sender gave up waiting; the outcome is
    /// then discarded instead of held for nobody.
    InFlight { abandoned: bool },
    Done(Result<(), AdspError>),
}

struct Conn {
    /// The endpoint's key for this connection. It can change after the
    /// open, when a peer answers a retransmitted open with a second ConnID.
    key: u16,
    remote: ServiceAddress,
    rx: VecDeque<u8>,
    attn_rx: VecDeque<(u16, Vec<u8>)>,
    attn: Attn,
    closed: bool,
}

struct AdspState {
    ep: AdspEndpoint,
    /// Open connections, by stream id. Ids are this crate's own, stable
    /// across the re-keying above.
    conns: BTreeMap<u32, Conn>,
    next_id: u32,
    accept: VecDeque<u32>,
    listener_alive: bool,
    /// Outbound opens with a caller waiting, by endpoint handle.
    connects: BTreeMap<u16, Option<Result<u32, AdspError>>>,
    /// Outbound open handle to the stream it became, to follow a re-key.
    outbound: BTreeMap<u16, u32>,
}

impl AdspState {
    fn new(ep: AdspEndpoint, listening: bool) -> Self {
        Self {
            ep,
            conns: BTreeMap::new(),
            next_id: 0,
            accept: VecDeque::new(),
            listener_alive: listening,
            connects: BTreeMap::new(),
            outbound: BTreeMap::new(),
        }
    }

    fn add(&mut self, key: u16, remote: ServiceAddress) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.conns.insert(
            id,
            Conn {
                key,
                remote,
                rx: VecDeque::new(),
                attn_rx: VecDeque::new(),
                attn: Attn::Idle,
                closed: false,
            },
        );
        id
    }

    fn by_key(&mut self, key: u16) -> Option<&mut Conn> {
        self.conns.values_mut().find(|c| c.key == key && !c.closed)
    }

    fn settle_attention(&mut self, key: u16, outcome: Result<(), AdspError>) {
        if let Some(c) = self.by_key(key) {
            c.attn = match c.attn {
                Attn::InFlight { abandoned: false } => Attn::Done(outcome),
                _ => Attn::Idle,
            };
        }
    }

    fn sort_events(&mut self) {
        while let Some(ev) = self.ep.poll_event() {
            match ev {
                AdspEvent::Opened {
                    conn,
                    remote,
                    inbound: true,
                    ..
                } => {
                    if self.listener_alive && self.accept.len() < ACCEPT_QUEUE_LEN {
                        let id = self.add(conn, remote);
                        self.accept.push_back(id);
                    } else {
                        self.ep.close(conn);
                    }
                }
                AdspEvent::Opened {
                    conn,
                    remote,
                    inbound: false,
                    pending,
                } => {
                    let handle = pending.unwrap_or(conn);
                    if matches!(self.connects.get(&handle), Some(None)) {
                        let id = self.add(conn, remote);
                        self.connects.insert(handle, Some(Ok(id)));
                        self.outbound.insert(handle, id);
                    } else if let Some(&id) = self.outbound.get(&handle) {
                        // Re-keyed; the stream follows it.
                        if let Some(c) = self.conns.get_mut(&id) {
                            c.key = conn;
                        }
                    } else {
                        // Whoever asked for it gave up waiting.
                        self.ep.close(conn);
                    }
                }
                AdspEvent::OpenFailed { conn } => {
                    if let Some(slot) = self.connects.get_mut(&conn) {
                        *slot = Some(Err(AdspError::OpenFailed));
                    }
                }
                AdspEvent::Data { conn, data, .. } => {
                    if let Some(c) = self.by_key(conn) {
                        c.rx.extend(data);
                    }
                }
                AdspEvent::Attention { conn, code, data } => {
                    if let Some(c) = self.by_key(conn)
                        && c.attn_rx.len() < ATTN_QUEUE_LEN
                    {
                        c.attn_rx.push_back((code, data));
                    }
                }
                AdspEvent::AttentionAcked { conn } => self.settle_attention(conn, Ok(())),
                AdspEvent::AttentionFailed { conn } => {
                    self.settle_attention(conn, Err(AdspError::AttentionUnacknowledged))
                }
                AdspEvent::Closed { conn } => {
                    if let Some(c) = self.by_key(conn) {
                        c.closed = true;
                        if let Attn::InFlight { abandoned } = c.attn {
                            c.attn = if abandoned {
                                Attn::Idle
                            } else {
                                Attn::Done(Err(AdspError::Closed))
                            };
                        }
                    }
                }
            }
        }
        self.update_window();
    }

    /// Advertise the room left in the fullest receive queue. The endpoint
    /// has one window for all its connections, so the slowest reader sets
    /// it. Less than a packet's worth is advertised as none, so a peer is
    /// not coaxed into a trickle of tiny packets while a reader catches up.
    fn update_window(&mut self) {
        let held = self.conns.values().map(|c| c.rx.len()).max().unwrap_or(0);
        let room = RX_WINDOW.saturating_sub(held);
        let window = if room < ADSP_MAX_DATA { 0 } else { room };
        self.ep.set_recv_window(window.min(u16::MAX as usize) as u16);
    }
}

impl Hosted for AdspState {
    fn handle_datagram(&mut self, dg: Datagram, now: Micros) {
        let src = ServiceAddress {
            network_number: dg.src.network_number,
            node_number: dg.src.node_number,
            socket_number: dg.src_socket,
        };
        self.ep.handle_datagram(src, &dg.payload, now);
        self.sort_events();
    }

    fn poll(&mut self, now: Micros) {
        self.ep.poll(now);
        self.sort_events();
    }

    fn next_deadline(&self) -> Option<Micros> {
        self.ep.next_deadline()
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let (dest, payload) = self.ep.poll_transmit()?;
        Some(Transmit {
            src_socket: self.ep.local_socket(),
            dest,
            proto: DdpProtocolType::Adsp,
            payload,
        })
    }

    fn finished(&self) -> bool {
        !self.listener_alive && self.conns.is_empty() && self.connects.is_empty()
    }
}

/// Accepts ADSP connections on one socket. Dropping it stops accepting and
/// closes connections not yet accepted; accepted streams live on.
pub struct AdspListener<'a, P: Platform> {
    net: Net<'a, P>,
    slot: usize,
    socket: u8,
}

impl<'a, P: Platform> AdspListener<'a, P> {
    /// Listen on `socket`, or a free dynamic socket for `None`.
    pub fn bind(net: Net<'a, P>, socket: Option<u8>) -> Result<Self, BindError> {
        net.with(|inner| {
            let socket = inner.stack.open_socket(socket)?;
            let mut ep = AdspEndpoint::new(socket, inner.stack.next_random());
            ep.set_listening(true);
            ep.set_recv_window(RX_WINDOW as u16);
            let slot = inner.insert(Box::new(AdspState::new(ep, true)), vec![socket]);
            Ok(Self { net, slot, socket })
        })
    }

    pub fn socket(&self) -> u8 {
        self.socket
    }

    /// The next inbound connection.
    pub async fn accept(&self) -> AdspStream<'a, P> {
        let (id, remote) = self
            .net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let id = s.accept.pop_front()?;
                Some((id, s.conns[&id].remote))
            })
            .await;
        AdspStream {
            net: self.net,
            slot: self.slot,
            id,
            remote,
            local_socket: self.socket,
        }
    }
}

impl<P: Platform> Drop for AdspListener<'_, P> {
    fn drop(&mut self) {
        self.net.with(|inner| {
            let s = inner.get::<AdspState>(self.slot);
            s.listener_alive = false;
            s.ep.set_listening(false);
            while let Some(id) = s.accept.pop_front() {
                if let Some(c) = s.conns.remove(&id)
                    && !c.closed
                {
                    s.ep.close(c.key);
                }
            }
            inner.kick();
        });
    }
}

/// One ADSP connection. Closed when dropped; [`AdspStream::close`] waits
/// for written bytes to be acknowledged first.
pub struct AdspStream<'a, P: Platform> {
    net: Net<'a, P>,
    slot: usize,
    id: u32,
    remote: ServiceAddress,
    local_socket: u8,
}

impl<'a, P: Platform> AdspStream<'a, P> {
    /// Open a connection to `remote` from a fresh dynamic socket, which is
    /// released again when the stream is dropped.
    pub async fn connect(net: Net<'a, P>, remote: ServiceAddress) -> Result<Self, AdspError> {
        let (slot, handle, local_socket) = net.with(|inner| {
            let socket = inner.stack.open_socket(None).map_err(|_| AdspError::NoSocket)?;
            let mut ep = AdspEndpoint::new(socket, inner.stack.next_random());
            ep.set_recv_window(RX_WINDOW as u16);
            let handle = ep.connect(remote, P::now());
            let mut state = AdspState::new(ep, false);
            state.connects.insert(handle, None);
            let slot = inner.insert(Box::new(state), vec![socket]);
            inner.kick();
            Ok((slot, handle, socket))
        })?;

        // Withdraw the request if this future is dropped early; the slot is
        // then finished, and the runner reclaims it.
        let guard = ConnectGuard { net, slot, handle };
        let outcome = net
            .wait_on::<AdspState, _>(slot, |s| match s.connects.get(&handle) {
                Some(Some(_)) => s.connects.remove(&handle).flatten(),
                _ => None,
            })
            .await;
        core::mem::forget(guard);

        match outcome {
            Ok(id) => {
                let remote = net.with(|inner| inner.get::<AdspState>(slot).conns[&id].remote);
                Ok(Self {
                    net,
                    slot,
                    id,
                    remote,
                    local_socket,
                })
            }
            Err(e) => {
                net.with(|inner| inner.kick());
                Err(e)
            }
        }
    }

    pub fn remote(&self) -> ServiceAddress {
        self.remote
    }

    /// The socket this end of the connection is on.
    pub fn local_socket(&self) -> u8 {
        self.local_socket
    }

    /// Read stream bytes, returning how many; 0 once the connection has
    /// closed and everything before the close has been read.
    ///
    /// Cancel safe: bytes leave the stream only in the poll that returns
    /// them.
    pub async fn read_data(&self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        let id = self.id;
        let n = self
            .net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let c = s.conns.get_mut(&id)?;
                if c.rx.is_empty() {
                    return c.closed.then_some(0);
                }
                let n = buf.len().min(c.rx.len());
                for (dst, b) in buf.iter_mut().zip(c.rx.drain(..n)) {
                    *dst = b;
                }
                Some(n)
            })
            .await;
        // Room was made; the window may have reopened.
        self.net.with(|inner| {
            inner.get::<AdspState>(self.slot).update_window();
            inner.kick();
        });
        n
    }

    /// Queue as much of `data` as fits, waiting while the queue toward the
    /// peer is full. Returns how many bytes were taken.
    pub async fn write_data(&self, data: &[u8]) -> Result<usize, AdspError> {
        if data.is_empty() {
            return Ok(0);
        }
        let id = self.id;
        let n = self
            .net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let Some(c) = s.conns.get(&id) else {
                    return Some(Err(AdspError::Closed));
                };
                if c.closed {
                    return Some(Err(AdspError::Closed));
                }
                let key = c.key;
                let room = TX_BUFFER.saturating_sub(s.ep.tx_backlog(key));
                if room == 0 {
                    return None;
                }
                let n = room.min(data.len());
                Some(match s.ep.send(key, &data[..n], false) {
                    Ok(_) => Ok(n),
                    Err(_) => Err(AdspError::Closed),
                })
            })
            .await?;
        self.net.with(|inner| inner.kick());
        Ok(n)
    }

    /// Mark a message boundary after everything written so far.
    pub fn write_eom(&self) -> Result<(), AdspError> {
        self.net.with(|inner| {
            let s = inner.get::<AdspState>(self.slot);
            let key = match s.conns.get(&self.id) {
                Some(c) if !c.closed => c.key,
                _ => return Err(AdspError::Closed),
            };
            s.ep.send(key, &[], true).map_err(|_| AdspError::Closed)?;
            inner.kick();
            Ok(())
        })
    }

    /// Wait until the peer has acknowledged every byte written.
    pub async fn flush_data(&self) -> Result<(), AdspError> {
        let id = self.id;
        self.net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let Some(c) = s.conns.get(&id) else {
                    return Some(Err(AdspError::Closed));
                };
                if s.ep.tx_backlog(c.key) == 0 {
                    Some(Ok(()))
                } else if c.closed {
                    Some(Err(AdspError::Closed))
                } else {
                    None
                }
            })
            .await
    }

    /// Send an attention message and wait for the peer to acknowledge it.
    /// ADSP allows one in flight per connection; concurrent callers take
    /// turns.
    pub async fn send_attention(&self, code: u16, data: &[u8]) -> Result<(), AdspError> {
        let id = self.id;
        self.net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let (key, attn, closed) = match s.conns.get(&id) {
                    Some(c) => (c.key, c.attn, c.closed),
                    None => return Some(Err(AdspError::Closed)),
                };
                if closed {
                    return Some(Err(AdspError::Closed));
                }
                if attn != Attn::Idle {
                    return None;
                }
                match s.ep.send_attention(key, code, data, P::now()) {
                    Ok(()) => {
                        s.conns.get_mut(&id).unwrap().attn = Attn::InFlight { abandoned: false };
                        Some(Ok(()))
                    }
                    Err(CoreError::NoSuchConnection) => Some(Err(AdspError::Closed)),
                    // Still in flight from a sender that gave up; its outcome
                    // is on its way and will wake this one.
                    Err(CoreError::AttentionInFlight) => None,
                }
            })
            .await?;
        self.net.with(|inner| inner.kick());

        let guard = AttnGuard { stream: self };
        let outcome = self
            .net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let c = s.conns.get_mut(&id)?;
                match c.attn {
                    Attn::Done(outcome) => {
                        c.attn = Attn::Idle;
                        Some(outcome)
                    }
                    _ => None,
                }
            })
            .await;
        core::mem::forget(guard);
        outcome
    }

    /// The next attention message from the peer, as `(code, body)`; `None`
    /// once the connection has closed and none are left.
    ///
    /// Cancel safe, and takes `&self`, so it can race
    /// [`AdspStream::read_data`] in one `select`.
    pub async fn attention(&self) -> Option<(u16, Vec<u8>)> {
        let id = self.id;
        self.net
            .wait_on::<AdspState, _>(self.slot, |s| {
                let Some(c) = s.conns.get_mut(&id) else {
                    return Some(None);
                };
                match c.attn_rx.pop_front() {
                    Some(m) => Some(Some(m)),
                    None if c.closed => Some(None),
                    None => None,
                }
            })
            .await
    }

    /// An attention message if one is already waiting.
    pub fn try_attention(&self) -> Option<(u16, Vec<u8>)> {
        self.net.with(|inner| {
            inner
                .get::<AdspState>(self.slot)
                .conns
                .get_mut(&self.id)?
                .attn_rx
                .pop_front()
        })
    }

    /// Wait for written bytes to be acknowledged, then close.
    pub async fn close(self) -> Result<(), AdspError> {
        let flushed = self.flush_data().await;
        drop(self);
        flushed
    }
}

impl<P: Platform> Drop for AdspStream<'_, P> {
    fn drop(&mut self) {
        self.net.with(|inner| {
            let s = inner.get::<AdspState>(self.slot);
            if let Some(c) = s.conns.remove(&self.id)
                && !c.closed
            {
                s.ep.close(c.key);
            }
            let id = self.id;
            s.outbound.retain(|_, v| *v != id);
            s.update_window();
            // The runner sends the CloseAdvice, then reclaims the socket if
            // this was the last thing on it.
            inner.kick();
        });
    }
}

impl<P: Platform> ErrorType for AdspStream<'_, P> {
    type Error = AdspError;
}

impl<P: Platform> ErrorType for &AdspStream<'_, P> {
    type Error = AdspError;
}

impl<P: Platform> Read for AdspStream<'_, P> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, AdspError> {
        Ok(self.read_data(buf).await)
    }
}

impl<P: Platform> Read for &AdspStream<'_, P> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, AdspError> {
        Ok(self.read_data(buf).await)
    }
}

impl<P: Platform> Write for AdspStream<'_, P> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, AdspError> {
        self.write_data(buf).await
    }

    async fn flush(&mut self) -> Result<(), AdspError> {
        self.flush_data().await
    }
}

impl<P: Platform> Write for &AdspStream<'_, P> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, AdspError> {
        self.write_data(buf).await
    }

    async fn flush(&mut self) -> Result<(), AdspError> {
        self.flush_data().await
    }
}

struct ConnectGuard<'a, P: Platform> {
    net: Net<'a, P>,
    slot: usize,
    handle: u16,
}

impl<P: Platform> Drop for ConnectGuard<'_, P> {
    fn drop(&mut self) {
        let (slot, handle) = (self.slot, self.handle);
        self.net.with(|inner| {
            let s = inner.get::<AdspState>(slot);
            // If it opened in the meantime, nobody will hold the stream.
            if let Some(Some(Ok(id))) = s.connects.remove(&handle)
                && let Some(c) = s.conns.remove(&id)
            {
                s.ep.close(c.key);
            }
            inner.kick();
        });
    }
}

struct AttnGuard<'s, 'a, P: Platform> {
    stream: &'s AdspStream<'a, P>,
}

impl<P: Platform> Drop for AttnGuard<'_, '_, P> {
    fn drop(&mut self) {
        let (slot, id) = (self.stream.slot, self.stream.id);
        self.stream.net.with(|inner| {
            if let Some(c) = inner.get::<AdspState>(slot).conns.get_mut(&id) {
                c.attn = match c.attn {
                    Attn::InFlight { .. } => Attn::InFlight { abandoned: true },
                    _ => Attn::Idle,
                };
            }
        });
    }
}
