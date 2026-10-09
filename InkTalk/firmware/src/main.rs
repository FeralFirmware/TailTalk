//! InkTalk firmware entry point.
//!
//! InkTalk makes a serial Mac printer appear on a LocalTalk network as a
//! native AppleTalk printer. It runs the AppleTalk stack itself (node
//! acquisition, NBP, and a printer role over ADSP or ATP/PAP) and converts
//! the payload into the byte stream the attached printer expects. That is
//! all it does: the USB-C port carries power and a debug/analyzer/config
//! shell on one CDC, and nothing else.
//!
//! Dual-core architecture:
//! - **Core 0** (Embassy async): USB, debug shell, the AppleTalk stack and
//!   printer role, printer UART, LEDs, watchdog.
//! - **Core 1** (bare-metal loop): PIO, DMA, all LocalTalk wire interaction.
//!
//! ## Pin assignments
//!
//! | GPIO | Net | Function |
//! |---|---|---|
//! | GP2  | `LocalTalk_TX`         | PIO0 SM0 OUT -> U4 D |
//! | GP3  | `LocalTalk_DE`         | software GPIO -> U4 DE |
//! | GP4  | `LocalTalk_RX`         | PIO1 SM0 JMP PIN <- U4 R |
//! | GP6/7| (unconnected)          | DBG0/DBG1 scope outputs |
//! | GP17 | `Net-(TX1-K)`          | TX1 blue LED, active low |
//! | GP18 | `PRINT_HSKI_CLAMPED`   | UART0 CTS <- printer HSKi, inverted in the pad |
//! | GP19 | `Net-(RX1-K)`          | RX1 green LED, active low |
//! | GP26 | `PRINT_DE`             | U5 DE, driven high |
//! | GP27 | `PRINT_RE`             | U5 /RE, driven low |
//! | GP28 | `PRINT_D`              | UART0 TX -> U5 D |
//! | GP29 | `PRINT_R`              | UART0 RX <- U5 R |
//!
//! U4 /RE is strapped to ground, so the LocalTalk receiver is always on. It
//! hears our own frames only if the connector box joins the TX and RX
//! pairs; core 1 drops any that come back.
//! The printer port and its handshake lines are described in `printer.rs`.
//!
//! ## RAM budget (264 KB total)
//!
//! ```text
//! core 1 stack                  16 KB  (deepest path is the RTS/CTS dialog)
//! TX slots (2 x ~2 KB DMA buf)   4 KB
//! RX slot ring (4 x 608 B)     2.4 KB
//! PIO RX DMA ring               16 KB  (4096 words, 16 KB aligned)
//! static TX encode buffers      24 KB  (must not live on the stack)
//! USB buffers + Embassy arena  ~72 KB  (task-arena-size-65536)
//! printer UART rings             6 KB  (4 KB pipe out, 2 KB buffered uart)
//! embedded-alloc heap           24 KB  (high-water in the `s` command)
//! ```
//!
//! Everything above is in `.bss`. Core 0's stack gets what is left, up to
//! the top of RAM, and needs a fair amount: an `NbpPacket` alone carries 15
//! tuples of ~104 bytes. `.uninit` sits just below it, so an overflow would
//! quietly overwrite PANIC_BUF; [`stack_canary_free_words`] watches for that
//! and `s` reports it.

#![no_std]
#![no_main]
#![allow(static_mut_refs)] // embassy multicore API requires &mut Stack

extern crate alloc;

use core::sync::atomic::Ordering;

use defmt::info;
use defmt_rtt as _;
use embassy_executor::Executor;
use embassy_rp::bind_interrupts;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::gpio::{Level, Output};
use embassy_rp::multicore::Stack;
use embassy_rp::peripherals::{UART0, USB};
use embassy_rp::uart::{BufferedInterruptHandler, BufferedUart};
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_time::Timer;
use embedded_alloc::LlffHeap;
use static_cell::StaticCell;


mod config;
mod control;
mod core1;
mod debug;
mod identify;
mod wire;
mod led;
mod localtalk;
mod printer;
mod stack_task;
#[macro_use]
mod tt_log;
mod usb_dev;

// ── Heap ────────────────────────────────────────────────────────────
#[global_allocator]
pub static HEAP: LlffHeap = LlffHeap::empty();
const HEAP_SIZE: usize = 24 * 1024;
static mut HEAP_MEM: [core::mem::MaybeUninit<u8>; HEAP_SIZE] =
    [core::mem::MaybeUninit::uninit(); HEAP_SIZE];

// ── Panic handler (reboots to BOOTSEL, message in no-init RAM) ─────
#[unsafe(link_section = ".uninit.PANIC_BUF")]
static mut PANIC_BUF: core::mem::MaybeUninit<[u8; 512]> =
    core::mem::MaybeUninit::uninit();

const PANIC_MARKER: &[u8] = b"\xDEPANIC_BUF\xDE ";

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(PANIC_BUF).cast::<[u8; 512]>() };
    for b in buf.iter_mut() { *b = 0; }
    buf[..PANIC_MARKER.len()].copy_from_slice(PANIC_MARKER);
    let mut w = SliceWriter { buf, pos: PANIC_MARKER.len() };
    if let Some(loc) = info.location() {
        let _ = write!(&mut w, "{}:{}:{} ", loc.file(), loc.line(), loc.column());
    } else {
        let _ = write!(&mut w, "<no location> ");
    }
    let _ = write!(&mut w, "msg=");
    let _ = write!(&mut w, "{}", info);
    embassy_rp::rom_data::reset_to_usb_boot(0, 0);
    loop { cortex_m::asm::nop(); }
}

// ── Stack canary ────────────────────────────────────────────────────
//
// Core 0's stack grows down from the top of RAM toward the end of
// `.uninit`, with nothing in between and no MPU guard, so an overflow just
// starts overwriting `.uninit` (PANIC_BUF) and then `.bss` - silently, and
// taking the panic message with it. Painting the bottom of the stack lets
// us see how close it has come.

unsafe extern "C" {
    /// End of `.uninit`, i.e. the lowest address core 0's stack can reach
    /// before it starts destroying static data. cortex-m-rt PROVIDEs this.
    static mut __sheap: u32;
}

/// Words of canary painted at the bottom of the stack (4 KB).
const CANARY_WORDS: usize = 1024;
const CANARY: u32 = 0xC0DE_FACE;

/// Paint the canary. Must run before the executor starts, while the stack
/// is still shallow enough not to be sitting in the painted region.
fn paint_stack_canary() {
    let base = &raw mut __sheap;
    for i in 0..CANARY_WORDS {
        // SAFETY: [__sheap, __sheap + 4 KB) is stack space the linker gave
        // us, and this runs before anything has recursed into it.
        unsafe { base.add(i).write_volatile(CANARY) };
    }
}

/// How many canary words are still untouched, counting up from the stack's
/// floor. `CANARY_WORDS` means the stack never came within 4 KB of the
/// bottom; 0 means it overflowed the painted region entirely and static
/// data is already corrupt.
pub fn stack_canary_free_words() -> usize {
    let base = &raw const __sheap;
    let mut intact = 0;
    while intact < CANARY_WORDS {
        // SAFETY: same region painted above, read only.
        if unsafe { base.add(intact).read_volatile() } != CANARY {
            break;
        }
        intact += 1;
    }
    intact
}

/// The message from the panic that rebooted us, if the last reset was a
/// panic. `PANIC_BUF` lives in `.uninit`, so it is not cleared at startup
/// and survives the reboot-to-BOOTSEL the panic handler performs; the
/// marker tells us whether the contents are ours or power-on garbage.
///
/// Returns the message without the marker. Call [`clear_panic_message`] to
/// stop it being reported.
pub fn panic_message() -> Option<&'static str> {
    // SAFETY: read-only, single caller (the debug task), and the marker
    // check rejects uninitialised RAM.
    let buf = unsafe { &*core::ptr::addr_of!(PANIC_BUF).cast::<[u8; 512]>() };
    if !buf.starts_with(PANIC_MARKER) {
        return None;
    }
    let body = &buf[PANIC_MARKER.len()..];
    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
    core::str::from_utf8(&body[..end]).ok()
}

/// Forget the stored panic message so it stops appearing in the banner.
pub fn clear_panic_message() {
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(PANIC_BUF).cast::<[u8; 512]>() };
    buf[..PANIC_MARKER.len()].fill(0);
}

struct SliceWriter<'a> { buf: &'a mut [u8], pos: usize }

impl core::fmt::Write for SliceWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.bytes() {
            if self.pos < self.buf.len() - 1 {
                self.buf[self.pos] = b;
                self.pos += 1;
            }
        }
        Ok(())
    }
}

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
    UART0_IRQ => BufferedInterruptHandler<UART0>;
});

// ── Core 1 stack ────────────────────────────────────────────────────
// Core 1's deepest path is the RTS/CTS dialog: a FrameAssembler (~600 B),
// a BitUnstuffer and a 256-byte bit buffer. 16 KB is plenty.
static mut CORE1_STACK: Stack<16384> = Stack::new();

// ── Shared state (inter-core) ───────────────────────────────────────
static SHARED: core1::SharedState = core1::SharedState::new();

// ── Executor ────────────────────────────────────────────────────────
static EXECUTOR0: StaticCell<Executor> = StaticCell::new();

#[cortex_m_rt::entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    info!("inktalk booting (dual-core)");

    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
    paint_stack_canary();

    // ── Flash: unique ID for USB serial, then the config store ──────
    let mut flash =
        Flash::<_, Blocking, { config::FLASH_SIZE }>::new_blocking(p.FLASH);
    let mut uid = [0u8; 8];
    let _ = flash.blocking_unique_id(&mut uid);
    let cfg = config::load(&mut flash);
    info!("config: role={} baud={}", cfg.role as u8, cfg.baud);

    // ── LocalTalk PHY (configures PIO + pins, drops handles) ────────
    localtalk::phy::init_phy(
        p.PIO0,
        localtalk::phy::Pio0Irqs {},
        p.PIO1,
        localtalk::phy::Pio1Irqs {},
        p.PIN_2,
        p.PIN_3,
        p.PIN_4,
    );
    info!("PHY: init done");

    // ── Printer port: transceiver enables + buffered UART0 ─────────
    // Full duplex: DE high and /RE low, for good.
    let printer_de = Output::new(p.PIN_26, Level::High);
    let printer_re = Output::new(p.PIN_27, Level::Low);
    core::mem::forget(printer_de);
    core::mem::forget(printer_re);

    static UART_TX_BUF: StaticCell<[u8; 512]> = StaticCell::new();
    static UART_RX_BUF: StaticCell<[u8; 2048]> = StaticCell::new();
    let mut uart_config = embassy_rp::uart::Config::default();
    uart_config.baudrate = cfg.baud;
    let uart = BufferedUart::new(
        p.UART0,
        Irqs,
        p.PIN_28,
        p.PIN_29,
        UART_TX_BUF.init([0u8; 512]),
        UART_RX_BUF.init([0u8; 2048]),
        uart_config,
    );
    let (uart_tx, uart_rx) = uart.split();
    // HSKi on GP18 as UART0's CTS. After the UART, since building it writes
    // uartcr, which would clear ctsen.
    printer::init_handshake();

    // ── LEDs (active low, so high starts them dark) ─────────────────
    let led_tx_blue = Output::new(p.PIN_17, Level::High);
    let led_rx_green = Output::new(p.PIN_19, Level::High);

    // ── Spawn core 1 (before starting executor) ─────────────────────
    embassy_rp::multicore::spawn_core1(
        p.CORE1,
        unsafe { &mut CORE1_STACK },
        move || core1::core1_main(&SHARED),
    );
    info!("Core 1 spawned");

    // ── Watchdog ────────────────────────────────────────────────────
    //
    // Clear the bootrom's "reboot into USB boot" magic before arming the
    // watchdog. `reset_to_usb_boot` leaves 0xB007C0D3 in watchdog scratch 4,
    // the bootrom checks it on every watchdog reset, and only a power cycle
    // clears it. Without this, a watchdog reset after any trip through
    // BOOTSEL (the button, `b`, a panic) lands back in the bootloader.
    let mut watchdog = embassy_rp::watchdog::Watchdog::new(p.WATCHDOG);
    watchdog.set_scratch(4, 0);

    // ── USB ─────────────────────────────────────────────────────────
    let driver = Driver::new(p.USB, Irqs);
    let (usb_run, debug_cdc) = usb_dev::build(driver, uid);

    // ── Start Embassy executor on core 0 ────────────────────────────
    let role = cfg.role;
    let name = cfg.name.clone();
    let baud = cfg.baud;
    let executor0 = EXECUTOR0.init(Executor::new());
    executor0.run(|spawner| {
        defmt::unwrap!(spawner.spawn(init_config_task(flash, cfg)));
        defmt::unwrap!(spawner.spawn(usb_run_task(usb_run)));
        defmt::unwrap!(spawner.spawn(debug::run(debug_cdc, &SHARED)));
        defmt::unwrap!(spawner.spawn(rx_dispatch_task(&SHARED)));
        stack_task::start(&spawner, &SHARED, role, name, baud);
        defmt::unwrap!(spawner.spawn(printer::tx_run(uart_tx)));
        defmt::unwrap!(spawner.spawn(printer::rx_run(uart_rx)));
        defmt::unwrap!(spawner.spawn(printer::handshake_run()));
        defmt::unwrap!(spawner.spawn(led::run(led_tx_blue, led_rx_green)));
        defmt::unwrap!(spawner.spawn(watchdog_task(watchdog)));
    });
}

/// Stash the flash handle and active config where the debug shell can
/// reach them. A task because the statics use async mutexes.
#[embassy_executor::task]
async fn init_config_task(flash: config::ConfigFlash, cfg: config::Config) {
    *config::FLASH_HANDLE.lock().await = Some(flash);
    *config::ACTIVE.lock().await = Some(cfg);
}

#[embassy_executor::task]
async fn usb_run_task(mut usb: usb_dev::UsbDevice) {
    usb.run().await;
}

/// How long core 1 may go without stamping its heartbeat before we treat it
/// as hung and stop feeding the watchdog. Core 1 stamps it even inside a
/// CSMA backoff and RTS/CTS dialog, so anything near a second means stuck.
const CORE1_STALL_US: u32 = 2_000_000;

/// Watchdog, fed while core 0 runs this task AND core 1 is still stamping
/// its heartbeat.
#[embassy_executor::task]
async fn watchdog_task(mut watchdog: embassy_rp::watchdog::Watchdog) -> ! {
    // Let USB enumerate and both cores settle first, so a slow start can't
    // reset us before the debug port is up to show why.
    Timer::after_secs(5).await;
    // The RP2040 watchdog tops out around 8.3 s; stay well inside it.
    watchdog.start(embassy_time::Duration::from_millis(5000));

    loop {
        Timer::after_millis(500).await;
        let parked = SHARED.flags.load(Ordering::Relaxed) & core1::PARKED != 0;
        // Wrapping subtraction on the low 32 bits of the microsecond timer:
        // correct across the ~71 minute wrap, which a plain compare is not.
        let since = (core1::timer_us() as u32).wrapping_sub(core1::heartbeat_us());
        if parked || since < CORE1_STALL_US {
            watchdog.feed();
        }
        // Otherwise core 1 is hung: stop feeding and let the watchdog reset us.
    }
}

/// Bridge: drains core 1's RX slot ring and fans each frame out to the
/// debug log and the stack.
#[embassy_executor::task]
async fn rx_dispatch_task(shared: &'static core1::SharedState) -> ! {
    loop {
        let got = shared.with_rx(|slot| {
            let len = slot.len as usize;
            let crc_ok = slot.status != 1;
            debug::log_rx_frame(&slot.buf[..len], crc_ok);
            if crc_ok {
                stack_task::try_forward_to_stack(&slot.buf[..len]);
            }
        });
        if got.is_none() {
            Timer::after_micros(50).await;
        }
    }
}
