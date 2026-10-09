//! LED task.
//!
//! Both LEDs have their cathode on the GPIO, so they light when the pin is
//! driven low. They show which way data is moving, for both ports at once:
//!
//! * **RX1 green (GP19)**: LocalTalk frames received, and bytes from the
//!   printer. Blinks slowly while we are still probing for a node address.
//! * **TX1 blue (GP17)**: LocalTalk frames sent, and bytes to the printer.
//! * **Fault**: the two alternate rapidly.
//!
//! Each pulse lights its LED for [`PULSE_TICKS`] ticks, so a single frame
//! is visible and steady traffic flickers.

use embassy_rp::gpio::{Level, Output};
use embassy_time::{Duration, Ticker};
use portable_atomic::{AtomicBool, AtomicU32, Ordering};

/// LED task period. Also the resolution of the activity stretch below.
const TICK_MS: u64 = 25;

/// How many ticks one activity pulse stays lit (~75 ms).
const PULSE_TICKS: u8 = 3;

/// Ticks per half period of the "no address yet" blink (~500 ms).
const SEARCH_BLINK_TICKS: u32 = 20;

/// Ticks per half period of the fault blink (~100 ms).
const FAULT_BLINK_TICKS: u32 = 4;

static RX_PULSES: AtomicU32 = AtomicU32::new(0);
static TX_PULSES: AtomicU32 = AtomicU32::new(0);
static HAVE_ADDRESS: AtomicBool = AtomicBool::new(false);
static FAULT: AtomicBool = AtomicBool::new(false);

/// A LocalTalk frame arrived off the wire.
pub fn pulse_localtalk_rx() {
    RX_PULSES.fetch_add(1, Ordering::Relaxed);
}

/// A LocalTalk frame was queued for transmission.
pub fn pulse_localtalk_tx() {
    TX_PULSES.fetch_add(1, Ordering::Relaxed);
}

/// Bytes were handed to the printer UART.
pub fn pulse_printer_tx() {
    TX_PULSES.fetch_add(1, Ordering::Relaxed);
}

/// Bytes arrived from the printer UART.
pub fn pulse_printer_rx() {
    RX_PULSES.fetch_add(1, Ordering::Relaxed);
}

/// Whether the stack has claimed a LocalTalk node address yet.
pub fn set_have_address(on: bool) {
    HAVE_ADDRESS.store(on, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn set_fault(on: bool) {
    FAULT.store(on, Ordering::Relaxed);
}

/// Heap high-water mark in bytes, sampled every tick for the `s` debug
/// command.
pub static HEAP_HIGH_WATER: AtomicU32 = AtomicU32::new(0);

/// Stretches a monotonically increasing pulse counter into a "lit for the
/// next few ticks" flag, so one frame is visible and a burst flickers.
struct Activity {
    last_seen: u32,
    remaining: u8,
}

impl Activity {
    fn new() -> Self {
        Self {
            last_seen: 0,
            remaining: 0,
        }
    }

    fn lit(&mut self, counter: &AtomicU32) -> bool {
        let now = counter.load(Ordering::Relaxed);
        if now != self.last_seen {
            self.last_seen = now;
            self.remaining = PULSE_TICKS;
        } else if self.remaining > 0 {
            self.remaining -= 1;
        }
        self.remaining > 0
    }
}

/// Active low: `true` lights the LED.
fn level(on: bool) -> Level {
    if on { Level::Low } else { Level::High }
}

#[embassy_executor::task]
pub async fn run(mut tx_blue: Output<'static>, mut rx_green: Output<'static>) -> ! {
    // Start dark.
    tx_blue.set_high();
    rx_green.set_high();

    let mut ticker = Ticker::every(Duration::from_millis(TICK_MS));
    let mut rx_activity = Activity::new();
    let mut tx_activity = Activity::new();
    let mut phase: u32 = 0;

    loop {
        ticker.next().await;
        phase = phase.wrapping_add(1);

        HEAP_HIGH_WATER.fetch_max(crate::HEAP.used() as u32, Ordering::Relaxed);

        // Sample both counters every tick, fault or not, so the stretch
        // state stays in step with real traffic.
        let rx_busy = rx_activity.lit(&RX_PULSES);
        let tx_busy = tx_activity.lit(&TX_PULSES);

        if FAULT.load(Ordering::Relaxed) {
            let on = (phase / FAULT_BLINK_TICKS).is_multiple_of(2);
            tx_blue.set_level(level(on));
            rx_green.set_level(level(!on));
            continue;
        }

        if HAVE_ADDRESS.load(Ordering::Relaxed) {
            rx_green.set_level(level(rx_busy));
        } else {
            // Still probing for a node address: slow blink, and let real
            // receive activity light it too so the wire is visibly alive.
            let searching = (phase / SEARCH_BLINK_TICKS).is_multiple_of(2);
            rx_green.set_level(level(searching || rx_busy));
        }
        tx_blue.set_level(level(tx_busy));
    }
}
