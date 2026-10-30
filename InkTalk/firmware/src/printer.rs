//! Printer serial port: UART0 on GP28 (`PRINT_D`, TX) and GP29 (`PRINT_R`,
//! RX) through the second SN65HVD1473 (U5).
//!
//! DE (GP26, active high) and RE (GP27, active low) are set once at boot for
//! full duplex. They are plain GPIOs so the port could run LocalTalk too. An
//! RE left floating reads as disabled, which is why `s` reads both back from
//! the pads.
//!
//! Flow control toward the Mac comes from the protocol layer: `tailtalk-net`
//! only opens the ADSP window or issues a PAP pull as fast as [`PortTx`]
//! writes complete, so a full [`TX_PIPE`] holds the Mac back. Toward the
//! printer, a StyleWriter is paced by its driver polling the 'B' buffer
//! gauge, which passes through untouched. An ImageWriter is paced by its
//! ready line.
//!
//! The handshake lines:
//!
//! - HSKo (J3 pin 1) is held high by R22, so the printer always sees us as
//!   ready. A StyleWriter won't send anything back otherwise. An ImageWriter
//!   has it on DSR, which it ignores.
//! - HSKi (J3 pin 2) is the printer's ready line, DTR on an ImageWriter. It
//!   swings about +4.5 V for ready and negative for busy; D5, R21 and R23
//!   turn that into high and 0 V on GP18, which is UART0's CTS input.
//!
//! It has to be CTS. An ImageWriter drops ready with 30 bytes of buffer left
//! and loses anything past the next 27 (technical reference p192). With CTS
//! the PL011 stops after the character it is shifting out; a software check
//! would be at least the driver's 512-byte buffer behind.
//!
//! nUARTCTS lets the UART transmit while it is low, so the pad input is
//! inverted. Gating is on from boot. `h` in the debug shell turns it off,
//! for when the printer is off or unplugged: both read as busy, and the
//! port just stops.
//!
//! A Colour StyleWriter in its fast mode uses HSKi for its bit clock instead,
//! and the port follows it through PIO (`fast_clock.rs`). A StyleWriter II or
//! 1200 in its fast mode runs at 230,400 baud, which the UART does on its own
//! clock. [`set_port_clock`] moves the port between these.

use core::cell::Cell;
use core::convert::Infallible;

use portable_atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::tt_log;

use embassy_futures::select::{Either, select};
use embassy_rp::peripherals::UART0;
use embassy_rp::uart::{BufferedUartRx, BufferedUartTx};
use embassy_sync::blocking_mutex;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::pipe::Pipe;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Timer};
use embedded_io_async::{ErrorType, Read, Write};
use tailtalk_net::printer::PortClock;

use crate::fast_clock::{FastRx, FastTx};

/// How long the UART can sit on bytes it can't send before we log it.
/// `handshake_run` counts this in its 1 ms ticks.
const STALL_WARN_MS: u32 = 5_000;

/// Bytes toward the printer, drained by `tx_run`. A write into a full pipe
/// waits, and that wait is what closes the protocol layer's window.
pub const TX_RING_BYTES: usize = 4096;
static TX_PIPE: Pipe<ThreadModeRawMutex, TX_RING_BYTES> = Pipe::new();

/// Bytes queued toward the printer but not yet handed to the UART driver.
/// Tracked separately because the protocol layer needs the free count and
/// the Pipe does not expose it.
static TX_PENDING: AtomicUsize = AtomicUsize::new(0);

/// Asks `tx_run` to move the port to a clock. It acts once the pipe is
/// empty, between chunks.
static CLOCK_REQUEST: Signal<ThreadModeRawMutex, PortClock> = Signal::new();
/// `tx_run` has acted on a [`CLOCK_REQUEST`].
static CLOCK_SWITCHED: Signal<ThreadModeRawMutex, ()> = Signal::new();
/// One [`set_port_clock`] at a time, since the signals each have one
/// waiter.
static CLOCK_SWITCH: Mutex<ThreadModeRawMutex, ()> = Mutex::new(());

/// The clock the port is on. Only `tx_run` changes it.
static PORT_CLOCK: blocking_mutex::Mutex<ThreadModeRawMutex, Cell<PortClock>> =
    blocking_mutex::Mutex::new(Cell::new(PortClock::Normal));

/// How long a printer told to switch to its fast mode gets, once the
/// command is out of the UART, before the port changes to the fast mode's
/// clock. As long as a Mac gives it.
const CLOCK_SETTLE: Duration = Duration::from_millis(33);

/// A StyleWriter II or 1200's fast mode.
const FAST_BAUD: u32 = 230_400;

/// Byte and error counters for the printer port, for the `s` debug command.
/// From the AppleTalk side a printer that never answers looks the same as
/// one that isn't plugged in; these tell the two apart.
static TX_BYTES: AtomicU32 = AtomicU32::new(0);
static RX_BYTES: AtomicU32 = AtomicU32::new(0);
static RX_ERRORS: AtomicU32 = AtomicU32::new(0);

/// Whether to log printer traffic as `P>` / `P<` lines. On by default, since
/// the printer's replies are short. A raster job is megabytes, so `k` in the
/// debug shell turns it off for real printing.
static TRACE: AtomicBool = AtomicBool::new(true);

pub fn trace() -> bool {
    TRACE.load(Ordering::Relaxed)
}

pub fn set_trace(on: bool) {
    TRACE.store(on, Ordering::Relaxed);
}

/// Bytes sent to / received from the printer, and UART read errors since
/// boot or the last counter clear. A non-zero error count with no received
/// bytes means the line is being driven at the wrong baud rate; zero of
/// both means nothing is arriving at all.
pub fn counters() -> (u32, u32, u32) {
    (
        TX_BYTES.load(Ordering::Relaxed),
        RX_BYTES.load(Ordering::Relaxed),
        RX_ERRORS.load(Ordering::Relaxed),
    )
}

pub fn clear_counters() {
    TX_BYTES.store(0, Ordering::Relaxed);
    RX_BYTES.store(0, Ordering::Relaxed);
    RX_ERRORS.store(0, Ordering::Relaxed);
}

/// A chunk of bytes the printer sent us.
pub type PrinterChunk = heapless::Vec<u8, 64>;
pub static RX_CHUNKS: Channel<ThreadModeRawMutex, PrinterChunk, 16> = Channel::new();

/// Free space in the printer TX path, for the `s` debug command.
pub fn tx_free() -> usize {
    TX_RING_BYTES.saturating_sub(TX_PENDING.load(Ordering::Relaxed))
}

/// Move the port to `clock`. Every byte queued before the call goes out at
/// the clock it was queued for, and the call returns once the port has
/// switched.
///
/// A printer that stops clocking while the port is on its HSKi clock drops
/// the port back to its own (see `tx_run`).
pub async fn set_port_clock(clock: PortClock) {
    let _one_at_a_time = CLOCK_SWITCH.lock().await;
    CLOCK_REQUEST.signal(clock);
    CLOCK_SWITCHED.wait().await;
}

/// The clock the port is on.
pub fn port_clock() -> PortClock {
    PORT_CLOCK.lock(Cell::get)
}

/// The printer's ready line, as last sampled by `handshake_run`.
static HANDSHAKE_HIGH: AtomicBool = AtomicBool::new(true);
/// Whether the ready line can hold off transmission. See the module docs.
static HANDSHAKE_GATING: AtomicBool = AtomicBool::new(true);

/// Whether the printer is asking for data, as last sampled. Reported by
/// the `s` debug command.
pub fn handshake_high() -> bool {
    HANDSHAKE_HIGH.load(Ordering::Relaxed)
}

/// Whether the UART still has bytes to send, in its FIFO or shift register.
/// Stays true while the printer holds us off, so it's the thing to check
/// when a job seems to hang.
pub fn tx_in_flight() -> bool {
    embassy_rp::pac::UART0.uartfr().read().busy()
}

/// The GP18 bit as SIO sees it, for the `s` debug command. The pad's input
/// inversion applies here too. It is on while the UART has the port, so this
/// reads 1 for a pin at 0 V. On the printer's HSKi clock it is off, and this
/// reads the pin as it is.
pub fn handshake_pad() -> bool {
    (embassy_rp::pac::SIO.gpio_in(0).read() >> CTS_GPIO) & 1 == 1
}

/// Whether the handshake line is being used to gate transmission.
pub fn handshake_gating() -> bool {
    HANDSHAKE_GATING.load(Ordering::Relaxed)
}

/// GPIO carrying the printer's ready line: UART0's CTS input.
const CTS_GPIO: usize = 18;
/// `Gpio18ctrlFuncsel::UART0_CTS`, as a raw funcsel value.
const FUNCSEL_UART0_CTS: u8 = 0x02;

/// Hand GP18 to UART0's CTS input, with the pad input inverted. Call once,
/// after the UART is built: building it writes `uartcr`, which would undo
/// the `ctsen` below.
pub fn init_handshake() {
    use embassy_rp::pac;
    // The UART can only see the line if the pad's input buffer is on.
    pac::PADS_BANK0.gpio(CTS_GPIO).modify(|w| {
        w.set_ie(true);
        w.set_od(false);
    });
    pac::IO_BANK0.gpio(CTS_GPIO).ctrl().write(|w| {
        w.set_funcsel(FUNCSEL_UART0_CTS);
        w.set_inover(pac::io::vals::Inover::INVERT);
    });
    set_handshake_gating(HANDSHAKE_GATING.load(Ordering::Relaxed));
}

/// Arm or disarm the PL011's CTS handshake. A printer that is off reads as
/// busy through R23, so with gating armed the port would wait forever.
pub fn set_handshake_gating(on: bool) {
    HANDSHAKE_GATING.store(on, Ordering::Relaxed);
    embassy_rp::pac::UART0.uartcr().modify(|w| w.set_ctsen(on));
}

/// Queue bytes for the printer, waiting while the pipe is full.
pub async fn send(data: &[u8]) {
    // Logged here rather than at the call sites so that everything reaching
    // the printer is visible - the protocol roles' output as well as the
    // debug shell's.
    log_chunk("P>", data);
    TX_BYTES.fetch_add(data.len() as u32, Ordering::Relaxed);
    TX_PENDING.fetch_add(data.len(), Ordering::Relaxed);
    let mut rest = data;
    while !rest.is_empty() {
        let n = TX_PIPE.write(rest).await;
        rest = &rest[n..];
    }
    crate::led::pulse_printer_tx();
}

/// The printer port's transmit half, as `tailtalk-net` writes to it.
pub struct PortTx;

impl ErrorType for PortTx {
    type Error = Infallible;
}

impl Write for PortTx {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
        send(buf).await;
        Ok(buf.len())
    }
}

/// The printer port's receive half, as `tailtalk-net` reads from it.
#[derive(Default)]
pub struct PortRx {
    chunk: PrinterChunk,
    pos: usize,
}

impl ErrorType for PortRx {
    type Error = Infallible;
}

impl Read for PortRx {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        if self.pos == self.chunk.len() {
            // Cancel safe: nothing is taken off the channel until the
            // receive completes, and then it is stored before any await.
            self.chunk = RX_CHUNKS.receive().await;
            self.pos = 0;
        }
        let n = buf.len().min(self.chunk.len() - self.pos);
        buf[..n].copy_from_slice(&self.chunk[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Feed the printer from [`TX_PIPE`], at whichever clock the port is on.
/// `base_baud` is what the UART runs at outside a fast mode.
#[embassy_executor::task]
pub async fn tx_run(mut tx: BufferedUartTx<'static, UART0>, mut fast: FastTx, base_baud: u32) -> ! {
    let mut buf = [0u8; 64];
    loop {
        // The pipe is polled first, so a clock switch waits for every byte
        // queued ahead of it.
        let n = match select(TX_PIPE.read(&mut buf), CLOCK_REQUEST.wait()).await {
            Either::First(n) => n,
            Either::Second(clock) => {
                switch_clock(&mut tx, &mut fast, base_baud, clock).await;
                CLOCK_SWITCHED.signal(());
                continue;
            }
        };
        if port_clock() == PortClock::PrinterHski {
            if fast.write(&buf[..n]).await.is_err() {
                // The printer has been reset or switched off, so it is back
                // at its own baud rate, and so is the port. What it missed is
                // dropped.
                fast.leave();
                PORT_CLOCK.lock(|c| c.set(PortClock::Normal));
                tt_log!("printer stopped clocking; port back on its own clock");
            }
        } else {
            let mut sent = 0;
            while sent < n {
                // There's no hold-off here, because CTS stops the PL011 by
                // itself. This only fills the driver's buffer, so it says
                // nothing about whether the printer is taking the bytes.
                // handshake_run watches for that.
                match tx.write(&buf[sent..n]).await {
                    Ok(written) => sent += written,
                    Err(_) => break,
                }
            }
        }
        TX_PENDING.fetch_sub(n, Ordering::Relaxed);
    }
}

/// Move the port to `to`, once what is already on its way has gone out at
/// the old clock.
async fn switch_clock(tx: &mut BufferedUartTx<'static, UART0>, fast: &mut FastTx, base_baud: u32, to: PortClock) {
    let from = port_clock();
    if to == from {
        return;
    }
    if from == PortClock::PrinterHski {
        if fast.flush().await.is_err() {
            tt_log!("printer stopped clocking with bytes still to send; dropped");
        }
        fast.leave();
    } else {
        let _ = tx.flush().await;
        while tx.busy() {
            Timer::after_micros(100).await;
        }
    }
    if to != PortClock::Normal {
        // The printer changes speed as soon as it has the command, so the
        // UART stops listening at the old one while the printer settles.
        set_uart_rx(false);
        Timer::after(CLOCK_SETTLE).await;
    }
    let uart_baud = |clock| if clock == PortClock::Baud230400 { FAST_BAUD } else { base_baud };
    if uart_baud(to) != uart_baud(from) {
        set_uart_baud(uart_baud(from), uart_baud(to)).await;
    }
    if to == PortClock::PrinterHski {
        fast.enter();
    } else {
        set_uart_rx(true);
    }
    PORT_CLOCK.lock(|c| c.set(to));
}

/// Turn UART0's receiver on or off.
fn set_uart_rx(on: bool) {
    embassy_rp::pac::UART0.uartcr().modify(|w| w.set_rxe(on));
}

/// Change UART0 from `from` baud to `to`, with nothing left in its
/// transmitter. The PL011 only takes new divisors with the `UARTLCR_H` write
/// that follows them, and wants to be disabled while they change. Disabled,
/// it still finishes a character it is part way through receiving, so that
/// gets 15 bit times at the old rate, half again a whole 8N1 frame.
async fn set_uart_baud(from: u32, to: u32) {
    let uart = embassy_rp::pac::UART0;
    let cr = uart.uartcr().read();
    uart.uartcr().modify(|w| w.set_uarten(false));
    Timer::after_micros(15_000_000 / u64::from(from)).await;
    // A bit is 16 divided clocks. The divisor goes in as an integer part and
    // a 6-bit fraction, so work in 64ths of it, rounded to nearest.
    let div64 = (8 * embassy_rp::clocks::clk_peri_freq() / to).div_ceil(2);
    uart.uartibrd().write(|w| w.set_baud_divint((div64 >> 6) as u16));
    uart.uartfbrd().write(|w| w.set_baud_divfrac((div64 & 0x3F) as u8));
    uart.uartlcr_h().modify(|_| {});
    uart.uartcr().write_value(cr);
}

/// Sample the ready line for `s`, and log when the printer has stopped
/// taking data.
///
/// The line is read from `UARTFR.CTS`, which is what the transmitter acts
/// on, and is valid whether or not gating is armed. 1 means the printer is
/// ready.
#[embassy_executor::task]
pub async fn handshake_run() -> ! {
    // Ticks the UART has held bytes it couldn't send. At any baud rate we
    // use, a full FIFO drains well inside STALL_WARN_MS, so this only grows
    // while the printer holds us off.
    let mut blocked: u32 = 0;
    let mut warned = false;
    loop {
        let fr = embassy_rp::pac::UART0.uartfr().read();
        // On the printer's clock the line is the clock, and a printer that
        // is clocking is ready.
        HANDSHAKE_HIGH.store(fr.cts() || port_clock() == PortClock::PrinterHski, Ordering::Relaxed);

        if fr.busy() {
            blocked = blocked.saturating_add(1);
        } else {
            blocked = 0;
            warned = false;
        }
        if blocked >= STALL_WARN_MS && !warned {
            warned = true;
            tt_log!(
                "printer not taking data for {}s: printer={} gate={}",
                STALL_WARN_MS / 1000,
                if fr.cts() { "READY" } else { "BUSY" },
                if handshake_gating() { "on" } else { "off" }
            );
        }
        embassy_time::Timer::after_millis(1).await;
    }
}

#[embassy_executor::task]
pub async fn rx_run(mut rx: BufferedUartRx<'static, UART0>, mut fast: FastRx) -> ! {
    let mut buf = [0u8; 64];
    let mut fast_buf = [0u8; 64];
    loop {
        // Only one of the two ever has anything. The UART receiver is off
        // while the port is on the printer's clock, and the state machine is
        // stopped the rest of the time.
        let (n, errors) = match select(rx.read(&mut buf), fast.read(&mut fast_buf)).await {
            Either::First(Ok(n)) => (n, 0),
            // Framing / parity / break.
            Either::First(Err(_)) => (0, 1),
            Either::Second(got) => {
                buf[..got.bytes].copy_from_slice(&fast_buf[..got.bytes]);
                (got.bytes, got.lost)
            }
        };
        if n > 0 {
            RX_BYTES.fetch_add(n as u32, Ordering::Relaxed);
            log_chunk("P<", &buf[..n]);
            crate::led::pulse_printer_rx();
            let mut chunk = PrinterChunk::new();
            let _ = chunk.extend_from_slice(&buf[..n]);
            // Blocks when the stack task falls behind, which is the
            // correct backpressure for the reverse direction too.
            RX_CHUNKS.send(chunk).await;
        }
        if errors > 0 {
            // Counted rather than logged per occurrence because a wrong
            // baud rate produces one of these per character. The count in
            // `s` is the signal.
            RX_ERRORS.fetch_add(errors, Ordering::Relaxed);
            // A pause keeps a wrong baud rate from spinning this task, and the
            // UART's ring holds what arrives meanwhile. On the printer's clock
            // there are only the state machine's eight frames behind it, under
            // 100 us at the printer's speed, so it reads on at once.
            if n == 0 && port_clock() != PortClock::PrinterHski {
                embassy_time::Timer::after_millis(10).await;
            }
        }
    }
}

/// Log a short hex and ASCII preview of printer traffic, while tracing is on.
pub fn log_chunk(tag: &str, data: &[u8]) {
    use core::fmt::Write;
    if !TRACE.load(Ordering::Relaxed) {
        return;
    }
    const PREVIEW: usize = 24;
    let mut hex: heapless::String<64> = heapless::String::new();
    let mut txt: heapless::String<32> = heapless::String::new();
    for &b in data.iter().take(PREVIEW) {
        let _ = write!(hex, "{:02X}", b);
        let _ = txt.push(if (0x20..0x7F).contains(&b) { b as char } else { '.' });
    }
    let ellipsis = if data.len() > PREVIEW { ".." } else { "" };
    crate::tt_log!(
        "{} {} bytes: {}{} |{}|",
        tag,
        data.len(),
        hex.as_str(),
        ellipsis,
        txt.as_str()
    );
}
