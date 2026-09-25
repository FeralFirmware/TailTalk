//! Async AppleTalk sockets over `tailtalk-core`'s sans-io state machines.
//!
//! `tailtalk-core` implements the protocols and never touches I/O, a clock
//! or an executor. This crate is the other half: it owns the state machines
//! behind a shared handle, drives them from one [`Runner`] future, and hands
//! out socket objects whose methods are ordinary `async fn`s. Nothing here
//! names a runtime, so the same code runs under Embassy on the InkTalk
//! firmware and under tokio on a host.
//!
//! ```ignore
//! static STATE: StaticCell<NetState<MyPlatform>> = StaticCell::new();
//! let state = STATE.init(NetState::new(StackConfig { seed, ..Default::default() }));
//! let (net, mut runner) = tailtalk_net::new(state, my_link);
//! spawn(async move { runner.run().await });
//!
//! let mut printer = Printer::imagewriter(net, "Inky")?;
//! loop {
//!     match printer.run(&mut uart_tx, &mut uart_rx).await? {
//!         PrinterEvent::Renamed(name) => save(name).await,
//!         _ => {}
//!     }
//! }
//! ```
//!
//! The shape follows embassy-net: [`NetState`] holds every state machine
//! behind one blocking mutex, [`Net`] is a `Copy` handle to it, and sockets
//! register wakers there. That shape is forced by Embassy, which cannot
//! spawn a task per socket the way a tokio actor would, so one runner drives
//! them all.
//!
//! Only the runner ever sleeps. Every protocol timeout already lives in
//! core as a `next_deadline`, so sockets simply wait to be woken, and the
//! runtime abstraction shrinks to [`Platform`]: a clock, a sleep, and the
//! mutex flavour.
#![no_std]

extern crate alloc;

pub mod adsp;
pub mod atp;
pub mod ddp;
mod net;
pub mod printer;

use core::future::Future;

use embassy_sync::blocking_mutex::raw::RawMutex;

pub use net::{BindError, Net, NetState, Runner, new};
pub use tailtalk_core::Micros;
pub use tailtalk_core::addressing::NodeClass;
pub use tailtalk_core::ddp::Datagram;
pub use tailtalk_core::stack::{SendError, StackConfig};
pub use tailtalk_packets::aarp::AppleTalkAddress;
pub use tailtalk_packets::ddp::DdpProtocolType;
pub use tailtalk_packets::nbp::{EntityName, ServiceAddress};

/// Longest LLAP frame a [`Link`] hands up: 3-byte LLAP header, 13-byte long
/// DDP header, 586 bytes of payload, and the FCS if the link leaves it on.
pub const MAX_FRAME_LEN: usize = 3 + 13 + 586 + 2;

/// What the runtime provides: a monotonic clock, a way to sleep until a
/// point on it, and the mutex that guards the shared state.
///
/// Associated functions rather than methods: clocks are global on every
/// target this serves, and a type parameter reaches every handle for free
/// where an instance would have to be stored in each.
pub trait Platform: 'static {
    /// `ThreadModeRawMutex` on a single-core executor, a critical-section
    /// mutex where handles cross threads, `NoopRawMutex` in a test that
    /// never leaves one task.
    type Mutex: RawMutex + 'static;

    /// Monotonic microseconds. The zero point is arbitrary.
    fn now() -> Micros;

    /// Resolve once [`Platform::now`] reaches `deadline`; immediately if it
    /// already has.
    fn sleep_until(deadline: Micros) -> impl Future<Output = ()>;
}

/// The LocalTalk link: whatever puts LLAP frames on the cable and takes
/// them off it.
///
/// Frames are raw LLAP (destination, source, type, payload). A received
/// frame may still carry its two FCS bytes, since the DDP length field
/// bounds what the parser reads; a transmitted one never does, and the link
/// appends the FCS itself if the hardware needs it.
// The futures are not declared Send. Embassy does not need them to be; a
// multi-threaded tokio runtime would, and that is a change to this trait
// when the desktop moves onto this crate.
#[allow(async_fn_in_trait)]
pub trait Link {
    /// Wait for the next frame, copy it into `buf`, and return its length.
    ///
    /// Must be cancel safe: the runner races this against its timers and
    /// drops it when they win, so a frame must never be lost half-read.
    async fn receive(&mut self, buf: &mut [u8]) -> usize;

    /// Put one frame on the wire.
    async fn transmit(&mut self, frame: &[u8]);

    /// The node probe finished and `node` is ours. A link that answers ENQs
    /// in hardware programs its address filter here, and only here: armed
    /// any earlier it would answer our own probes and every candidate would
    /// look taken.
    fn node_acquired(&mut self, _node: u8) {}
}
