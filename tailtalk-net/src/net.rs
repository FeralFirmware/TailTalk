//! The shared state, the [`Net`] handle over it, and the [`Runner`] that
//! drives it.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::any::Any;
use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll, Waker};

use embassy_futures::select::select3;
use embassy_sync::blocking_mutex::Mutex;
use tailtalk_core::Micros;
use tailtalk_core::ddp::Datagram;
use tailtalk_core::stack::{SocketError, Stack, StackConfig, StackEvent};
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::nbp::{EntityName, ServiceAddress};

use crate::{Link, MAX_FRAME_LEN, Platform};

/// Why a socket could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// The requested socket number is taken or reserved.
    SocketInUse,
    /// No dynamic socket number is free.
    SocketsExhausted,
    /// The NBP name is malformed or a component is too long.
    BadName,
    /// The NBP registry has no room for another name.
    NameTableFull,
}

impl From<SocketError> for BindError {
    fn from(e: SocketError) -> Self {
        match e {
            SocketError::InUse => BindError::SocketInUse,
            SocketError::Exhausted => BindError::SocketsExhausted,
        }
    }
}

/// A datagram a hosted state machine wants sent.
pub(crate) struct Transmit {
    pub src_socket: u8,
    pub dest: ServiceAddress,
    pub proto: DdpProtocolType,
    pub payload: Vec<u8>,
}

/// A state machine living in the shared state, driven by the runner. Each
/// socket type wraps its core state machine in one of these, together with
/// whatever its handle needs sorted out of the event stream.
pub(crate) trait Hosted: Any + Send {
    fn handle_datagram(&mut self, dg: Datagram, now: Micros);
    fn poll(&mut self, now: Micros);
    fn next_deadline(&self) -> Option<Micros>;
    fn poll_transmit(&mut self) -> Option<Transmit>;

    /// Whether the slot can go: every handle is gone and nothing is left to
    /// send. Checked only once the slot's transmits are drained, so a
    /// closing handle's last packets (an ADSP CloseAdvice) still go out.
    fn finished(&self) -> bool {
        false
    }
}

/// Every waker waiting on one thing. Socket methods take `&self`, so one
/// slot can have several futures waiting at once (a read racing an
/// attention, two ATP requests); waking them all is fine because each
/// re-checks its own condition.
#[derive(Default)]
struct WakerSet(Vec<Waker>);

impl WakerSet {
    fn register(&mut self, waker: &Waker) {
        if !self.0.iter().any(|w| w.will_wake(waker)) {
            self.0.push(waker.clone());
        }
    }

    fn wake(&mut self) {
        for w in self.0.drain(..) {
            w.wake();
        }
    }
}

struct Slot {
    hosted: Box<dyn Hosted>,
    sockets: Vec<u8>,
    wakers: WakerSet,
}

/// Something the runner has to do outside the lock.
enum Action {
    Transmit(Vec<u8>),
    NodeAcquired(u8),
}

pub(crate) struct Inner {
    pub(crate) stack: Stack,
    slots: Vec<Option<Slot>>,
    by_socket: BTreeMap<u8, usize>,
    runner: Option<Waker>,
    /// Set by a handle that queued work, so the runner flushes it without
    /// waiting for a frame or a timer.
    kicked: bool,
    address_waiters: WakerSet,
}

impl Inner {
    /// Host `hosted` on already opened `sockets`. Returns its slot id.
    pub(crate) fn insert(&mut self, hosted: Box<dyn Hosted>, sockets: Vec<u8>) -> usize {
        let id = match self.slots.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        for &s in &sockets {
            self.by_socket.insert(s, id);
        }
        self.slots[id] = Some(Slot {
            hosted,
            sockets,
            wakers: WakerSet::default(),
        });
        id
    }

    /// Drop a slot and release its sockets.
    pub(crate) fn remove(&mut self, id: usize) {
        let Some(slot) = self.slots.get_mut(id).and_then(Option::take) else {
            return;
        };
        for s in slot.sockets {
            self.by_socket.remove(&s);
            self.stack.close_socket(s);
        }
    }

    /// The state machine in slot `id`. Handles only ever ask for the type
    /// they put there, so a mismatch is a bug in this crate.
    pub(crate) fn get<T: Hosted>(&mut self, id: usize) -> &mut T {
        let slot = self.slots[id].as_mut().expect("handle outlived its slot");
        let any: &mut dyn Any = &mut *slot.hosted;
        any.downcast_mut().expect("slot holds another socket type")
    }

    fn register(&mut self, id: usize, waker: &Waker) {
        if let Some(slot) = self.slots[id].as_mut() {
            slot.wakers.register(waker);
        }
    }

    /// Ask the runner to go round again: a handle queued something.
    pub(crate) fn kick(&mut self) {
        self.kicked = true;
        if let Some(w) = self.runner.take() {
            w.wake();
        }
    }

    fn deliver(&mut self, dg: Datagram, now: Micros) {
        let Some(&id) = self.by_socket.get(&dg.dst_socket) else {
            return;
        };
        if let Some(slot) = self.slots[id].as_mut() {
            slot.hosted.handle_datagram(dg, now);
            slot.wakers.wake();
        }
    }

    /// Drop every slot whose handles have all gone and whose last packets
    /// have been sent.
    fn sweep(&mut self) {
        let done: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.as_ref().is_some_and(|s| s.hosted.finished()))
            .map(|(id, _)| id)
            .collect();
        for id in done {
            self.remove(id);
        }
    }

    /// Run every timer that is due. Cheap enough to call on every pass,
    /// which is what keeps a flood of frames from starving the timers.
    fn poll_timers(&mut self, now: Micros) {
        self.stack.poll(now);
        for slot in self.slots.iter_mut().flatten() {
            if slot.hosted.next_deadline().is_some_and(|d| d <= now) {
                slot.hosted.poll(now);
                slot.wakers.wake();
            }
        }
    }

    fn next_deadline(&self) -> Option<Micros> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|s| s.hosted.next_deadline())
            .chain(self.stack.next_deadline())
            .min()
    }

    /// Settle everything that can be settled under the lock, and return the
    /// next thing that cannot: a frame to transmit, or the link to arm.
    fn next_action(&mut self, now: Micros) -> Option<Action> {
        loop {
            if let Some(ev) = self.stack.poll_event() {
                match ev {
                    StackEvent::AddressAcquired(addr) => {
                        self.address_waiters.wake();
                        return Some(Action::NodeAcquired(addr.node_number));
                    }
                    StackEvent::NetworkNumberChanged(_) => {}
                    StackEvent::Datagram(dg) => self.deliver(dg, now),
                }
                continue;
            }
            if let Some(frame) = self.stack.poll_transmit() {
                return Some(Action::Transmit(frame.to_bytes()));
            }
            // Move one datagram from a socket down into the stack, then go
            // round again to frame it. A datagram to ourselves comes back
            // up as an event instead, which the loop also handles.
            let mut moved = false;
            for slot in self.slots.iter_mut().flatten() {
                if let Some(t) = slot.hosted.poll_transmit() {
                    let dest = AppleTalkAddress {
                        network_number: t.dest.network_number,
                        node_number: t.dest.node_number,
                    };
                    // Before the probe settles there is no address to send
                    // from. Nothing is lost that matters: every protocol
                    // here retransmits, and a peer cannot have reached us
                    // yet to be owed a reply.
                    let _ = self.stack.send_ddp(
                        dest,
                        t.dest.socket_number,
                        t.src_socket,
                        t.proto,
                        &t.payload,
                    );
                    moved = true;
                    break;
                }
            }
            if !moved {
                self.sweep();
                return None;
            }
        }
    }
}

/// Storage for one AppleTalk node: the LocalTalk stack, and every socket
/// state machine opened on it. Put it somewhere that outlives the handles -
/// a `StaticCell` on the firmware - and hand it to [`new`].
pub struct NetState<P: Platform> {
    inner: Mutex<P::Mutex, RefCell<Inner>>,
}

impl<P: Platform> NetState<P> {
    pub fn new(config: StackConfig) -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Inner {
                stack: Stack::new(config, P::now()),
                slots: Vec::new(),
                by_socket: BTreeMap::new(),
                runner: None,
                kicked: false,
                address_waiters: WakerSet::default(),
            })),
        }
    }
}

/// Start a node on `link`. Spawn the runner and keep it running for as long
/// as any socket is in use; the handle goes wherever sockets are opened.
pub fn new<'a, P: Platform, L: Link>(state: &'a NetState<P>, link: L) -> (Net<'a, P>, Runner<'a, P, L>) {
    let net = Net { state };
    (net, Runner { net, link })
}

/// A handle to one node. `Copy`, so pass it to every task that opens
/// sockets.
pub struct Net<'a, P: Platform> {
    state: &'a NetState<P>,
}

impl<P: Platform> Clone for Net<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Platform> Copy for Net<'_, P> {}

impl<'a, P: Platform> Net<'a, P> {
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        self.state.inner.lock(|cell| f(&mut cell.borrow_mut()))
    }

    /// Wait on slot `id` until `f` produces a value.
    ///
    /// `f` runs under the lock and whatever it takes is taken in the poll
    /// that returns it, so a future dropped while waiting has taken nothing.
    /// This is what makes the socket methods built on it cancel safe.
    pub(crate) async fn wait_on<T: Hosted, R>(&self, id: usize, mut f: impl FnMut(&mut T) -> Option<R>) -> R {
        poll_fn(|cx: &mut Context<'_>| {
            self.with(|inner| match f(inner.get::<T>(id)) {
                Some(r) => Poll::Ready(r),
                None => {
                    inner.register(id, cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }

    /// Our address, once the node probe has settled. The network number is
    /// 0 until a router's RTMP broadcast supplies the real one.
    pub fn address(&self) -> Option<AppleTalkAddress> {
        self.with(|inner| inner.stack.our_address())
    }

    /// Wait for the node probe to settle.
    pub async fn wait_address(&self) -> AppleTalkAddress {
        poll_fn(|cx| {
            self.with(|inner| match inner.stack.our_address() {
                Some(addr) => Poll::Ready(addr),
                None => {
                    inner.address_waiters.register(cx.waker());
                    Poll::Pending
                }
            })
        })
        .await
    }

    /// Answer NBP lookups for `name` with `socket` on this node.
    pub fn nbp_register(&self, name: EntityName, socket: u8) -> Result<(), BindError> {
        self.with(|inner| inner.stack.nbp_register(name, socket))
            .map_err(|_| BindError::NameTableFull)
    }

    /// Stop answering for `name`. Returns whether it was registered.
    pub fn nbp_unregister(&self, name: &EntityName, socket: u8) -> bool {
        self.with(|inner| inner.stack.nbp_unregister(name, socket))
    }

    /// Whether a router has been heard on the cable.
    pub fn router_seen(&self) -> bool {
        self.with(|inner| inner.stack.router_seen())
    }
}

/// Drives the node: moves frames between the link and the state machines,
/// runs their timers, and wakes the sockets they concern. Spawn
/// [`Runner::run`] once, before anything waits on a socket.
pub struct Runner<'a, P: Platform, L: Link> {
    net: Net<'a, P>,
    link: L,
}

impl<P: Platform, L: Link> Runner<'_, P, L> {
    pub async fn run(&mut self) -> ! {
        let net = self.net;
        let mut buf = [0u8; MAX_FRAME_LEN];
        loop {
            while let Some(action) = net.with(|inner| inner.next_action(P::now())) {
                match action {
                    Action::Transmit(frame) => self.link.transmit(&frame).await,
                    Action::NodeAcquired(node) => self.link.node_acquired(node),
                }
            }

            let deadline = net.with(|inner| inner.next_deadline());
            let sleep = async {
                match deadline {
                    Some(d) => P::sleep_until(d).await,
                    None => core::future::pending().await,
                }
            };
            let kicked = poll_fn(|cx| {
                net.with(|inner| {
                    if inner.kicked {
                        inner.kicked = false;
                        Poll::Ready(())
                    } else {
                        inner.runner = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
            });

            let received = match select3(self.link.receive(&mut buf), sleep, kicked).await {
                embassy_futures::select::Either3::First(n) => Some(n),
                _ => None,
            };
            net.with(|inner| {
                let now = P::now();
                if let Some(n) = received {
                    inner.stack.handle_frame(&buf[..n.min(buf.len())], now);
                }
                inner.poll_timers(now);
            });
        }
    }
}
