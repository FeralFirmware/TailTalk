//! The on-board AppleTalk node: `tailtalk-net` wired to the firmware's wire,
//! UART, and LED plumbing.
//!
//! Three tasks. The runner moves LocalTalk frames between core 1 and the
//! protocol state machines and keeps their timers; the printer task serves
//! the configured printer on the UART and deals with what it reports; and
//! the control task (control.rs) looks after configuration clients. All
//! the protocol work lives in `tailtalk-net` and `tailtalk-core`, so what is
//! left here is the hardware: the link, the clock, the port, and where a
//! rename is saved.
//!
//! Core 1 answers ENQs for our node, but only once the probe has settled.
//! Before that it would ACK our own probes and every node would look taken.

use core::sync::atomic::Ordering;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::once_lock::OnceLock;
use embassy_time::{Instant, Timer};
use static_cell::StaticCell;

use localtalk::MAX_FRAME_LEN;
use localtalk::crc::lt_crc;
use tailtalk_net::printer::{FastClock, Printer, PrinterEvent};
use tailtalk_net::{AppleTalkAddress, Link, Micros, Net, NetState, NodeClass, Platform, Runner, StackConfig};

use crate::config::Role;
use crate::control::{self, JOB_ACTIVE, NAME_CHANGED, PRINTER_NAME};
use crate::core1::SharedState;
use crate::{identify, led, printer, tt_log};

/// The runtime `tailtalk-net` runs on here: Embassy's clock, and a
/// thread-mode mutex since everything touching the node runs on core 0's
/// executor.
pub struct InkTalk;

impl Platform for InkTalk {
    type Mutex = ThreadModeRawMutex;

    fn now() -> Micros {
        Instant::now().as_micros()
    }

    fn sleep_until(deadline: Micros) -> impl core::future::Future<Output = ()> {
        Timer::at(Instant::from_micros(deadline))
    }
}

/// A frame for the stack, straight off the wire (FCS still attached; the
/// DDP length field bounds what the parsers read).
pub struct StackFrame {
    pub buf: [u8; MAX_FRAME_LEN],
    pub len: u16,
}

pub static STACK_RX: Channel<ThreadModeRawMutex, StackFrame, 4> = Channel::new();

pub fn try_forward_to_stack(frame: &[u8]) {
    let n = frame.len().min(MAX_FRAME_LEN);
    let mut f = StackFrame {
        buf: [0u8; MAX_FRAME_LEN],
        len: n as u16,
    };
    f.buf[..n].copy_from_slice(&frame[..n]);
    let _ = STACK_RX.try_send(f);
}

/// Core 1's queues, as a `tailtalk-net` link.
pub struct InkLink {
    shared: &'static SharedState,
}

impl Link for InkLink {
    async fn receive(&mut self, buf: &mut [u8]) -> usize {
        // Channel::receive is cancel safe, which the runner relies on.
        let frame = STACK_RX.receive().await;
        led::pulse_localtalk_rx();
        let n = (frame.len as usize).min(buf.len());
        buf[..n].copy_from_slice(&frame.buf[..n]);
        n
    }

    async fn transmit(&mut self, frame: &[u8]) {
        let mut out = [0u8; MAX_FRAME_LEN];
        let n = frame.len();
        if n + 2 > out.len() {
            tt_log!("STACK: frame too long to send ({} bytes)", n);
            return;
        }
        out[..n].copy_from_slice(frame);
        let crc = lt_crc(frame);
        out[n..n + 2].copy_from_slice(&crc);
        // The only place to see a frame the stack built, whether or not it
        // makes it onto the wire.
        tt_log!(
            "STACK TX dst={:02X} src={:02X} type={:02X} len={}",
            out[0],
            out[1],
            out[2],
            n + 2
        );
        crate::wire::submit_tx(self.shared, &out[..n + 2]).await;
    }

    fn node_acquired(&mut self, node: u8) {
        tt_log!("STACK: node {} acquired", node);
        crate::wire::set_node(self.shared, node);
        led::set_have_address(true);
    }
}

static STATE: StaticCell<NetState<InkTalk>> = StaticCell::new();
static NET: OnceLock<Net<'static, InkTalk>> = OnceLock::new();

/// Our address, once the node probe has settled. For the debug shell.
pub fn our_address() -> Option<AppleTalkAddress> {
    NET.try_get().and_then(|net| net.address())
}

/// The node this board answers for, or 0 if it has not claimed one yet.
pub fn our_node() -> u8 {
    our_address().map_or(0, |a| a.node_number)
}

/// Gather 32 bits of ROSC entropy for the protocol PRNGs.
fn rosc_seed() -> u32 {
    let mut seed = 0u32;
    for _ in 0..32 {
        seed = (seed << 1) | (embassy_rp::pac::ROSC.randombit().read().randombit() as u32);
        cortex_m::asm::delay(50);
    }
    if seed == 0 { 0xDEAD_BEEF } else { seed }
}

/// Bring the node up and start serving `role` as `name`. `baud` is what the
/// printer port was set to at boot.
pub fn start(spawner: &Spawner, shared: &'static SharedState, role: Role, name: heapless::String<31>, baud: u32) {
    let state = STATE.init(NetState::new(StackConfig {
        node_class: NodeClass::Server,
        seed: rosc_seed(),
        // Core 1's auto-reply engine ACKs ENQs once our node is in the
        // bitmap; no software ACK needed.
        auto_ack_enq: false,
    }));
    let (net, runner) = tailtalk_net::new(state, InkLink { shared });
    let _ = NET.init(net);
    defmt::unwrap!(spawner.spawn(run_node(runner)));
    defmt::unwrap!(spawner.spawn(serve_printer(shared, net, role, name)));
    defmt::unwrap!(spawner.spawn(control::run(shared, net, control::Running { role, baud })));
}

#[embassy_executor::task]
async fn run_node(mut runner: Runner<'static, InkTalk, InkLink>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn serve_printer(
    shared: &'static SharedState,
    net: Net<'static, InkTalk>,
    role: Role,
    name: heapless::String<31>,
) -> ! {
    let bind = |name: &str| match role {
        // Fast mode needs the UART clocked from HSKi, which we don't do yet.
        Role::StyleWriter => Printer::stylewriter(net, name, FastClock::Unsupported),
        Role::ImageWriter => Printer::imagewriter(net, name),
    };
    // A name that cannot be registered would leave the printer invisible
    // until someone set another from the debug shell, so fall back instead.
    let mut served = match bind(name.as_str()) {
        Ok(p) => p,
        Err(e) => {
            tt_log!("STACK: cannot register {}: {:?}, using InkTalk", name.as_str(), e);
            defmt::unwrap!(bind("InkTalk").ok())
        }
    };
    tt_log!("STACK: role={} name={}", role.name(), served.name());
    let _ = PRINTER_NAME.init(served.name_handle());

    let mut tx = printer::PortTx;
    let mut rx = printer::PortRx::default();
    let identifies = role == Role::StyleWriter;
    if identifies {
        identify::set_enabled();
        // The printer is already registered, so a client that turns up now
        // is accepted and its bytes wait in the window until this is done.
        identify::run(&mut tx, &mut rx).await;
    }
    loop {
        // A re-identify may only interrupt `run` between jobs: a write it
        // abandons is lost, and mid-job that would be a client's raster.
        let result = if identifies && !JOB_ACTIVE.load(Ordering::Relaxed) {
            match select(served.run(&mut tx, &mut rx), identify::REPROBE.wait()).await {
                Either::First(r) => r,
                Either::Second(()) => {
                    identify::run(&mut tx, &mut rx).await;
                    continue;
                }
            }
        } else {
            served.run(&mut tx, &mut rx).await
        };
        match result {
            Ok(PrinterEvent::JobStarted) => {
                JOB_ACTIVE.store(true, Ordering::Relaxed);
                match served.colour_ribbon() {
                    Some(colour) => tt_log!(
                        "PRINTER: job started, ribbon={}",
                        if colour { "colour" } else { "black" }
                    ),
                    None => tt_log!("PRINTER: job started"),
                }
            }
            Ok(PrinterEvent::JobEof) => tt_log!("PRINTER: job eof"),
            Ok(PrinterEvent::JobEnded { clean }) => {
                JOB_ACTIVE.store(false, Ordering::Relaxed);
                tt_log!("PRINTER: job ended clean={}", clean);
            }
            Ok(PrinterEvent::Renamed(new_name)) => {
                tt_log!("STACK: renamed to {}", new_name.as_str());
                signal_name(&new_name);
                save_name(shared, &new_name).await;
            }
            Ok(PrinterEvent::RenameRejected) => tt_log!("STACK: rename ignored, name not usable"),
            // Never sent: the StyleWriter is bound without fast clock support.
            Ok(PrinterEvent::FastClockEnable | PrinterEvent::FastClockDisable) => {}
            // Our port can't fail or reach end of stream. This keeps a future
            // one that can from spinning.
            Err(e) => {
                tt_log!("PRINTER: port error {:?}", e);
                Timer::after_millis(100).await;
            }
        }
    }
}

/// Let the control task know a client renamed the printer.
fn signal_name(name: &str) {
    if let Ok(name) = heapless::String::try_from(name) {
        NAME_CHANGED.signal(name);
    }
}

/// Keep a client's rename across a power cycle, as the adapter being
/// emulated does. The live registration already stands; this is only what
/// the Chooser sees after a reboot.
async fn save_name(shared: &'static SharedState, name: &str) {
    let Ok(name) = heapless::String::<31>::try_from(name) else {
        tt_log!("STACK: rename not saved, longer than 31 bytes");
        return;
    };
    {
        let mut guard = crate::config::ACTIVE.lock().await;
        match guard.as_mut() {
            // The control task made this rename and has already saved it.
            Some(cfg) if cfg.name == name => return,
            Some(cfg) => cfg.name = name,
            None => {}
        }
    }
    // Saving parks core 1 while a flash sector is erased, so the wire goes
    // quiet. The client's reply is already queued and at worst goes out
    // just after, well inside its timeout.
    let cfg = crate::config::ACTIVE.lock().await.clone();
    if let Some(cfg) = cfg
        && let Err(e) = crate::config::save(shared, &cfg).await
    {
        tt_log!("STACK: rename not saved: {}", e);
    }
}
