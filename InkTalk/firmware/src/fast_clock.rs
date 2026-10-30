//! The printer port on the printer's own clock.
//!
//! In its fast mode a Colour StyleWriter drives a bit clock on HSKi, one
//! clock per bit, and both directions keep to 8N1 framing on it. A 2200
//! runs it at about 885 kHz, with its data steady across each rising edge.
//! (A StyleWriter II or 1200's fast mode is plain 230,400 baud, which the
//! UART does itself, in `printer.rs`.) The PL011 has no external clock
//! input, so two PIO0 state machines take the data pins over while the
//! printer is clocking.
//!
//! - SM1 transmits on GP28 (`PRINT_D`). It moves the line just after each
//!   falling edge of HSKi, which leaves the printer half a clock either
//!   side of the rising edge to sample it.
//! - SM2 receives on GP29 (`PRINT_R`), sampling on each rising edge.
//!
//! Both run at the full system clock, so an edge is acted on within a few
//! 8 ns cycles of reaching the pad. HSKi reaches GP18 the right way up
//! (see `printer.rs`), so the state machines see it with the pad's input
//! inversion off.
//!
//! Outside fast mode both machines are stopped and the UART has the pins.
//! GP29 needs no switching, because every peripheral sees every GPIO
//! input. The UART receiver is turned off instead, so fast traffic doesn't
//! land in its error count. GP28's FUNCSEL moves between UART0 and PIO0,
//! with SM1 already holding the line at mark so the switch is clean. GP18
//! keeps the input inversion CTS wants whenever the UART has the port.
//!
//! The programs name GP18 directly in their `wait` instructions.

use embassy_rp::gpio::Level;
use embassy_rp::pac;
use embassy_rp::pac::io::vals::Inover;
use embassy_rp::peripherals::PIO0;
use embassy_rp::pio::{Config, Direction, FifoJoin, PioPin, ShiftConfig, ShiftDirection, StateMachine};
use embassy_rp::Peripheral;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use pio::{InstructionOperands, JmpCondition, SetDestination};

use crate::localtalk::phy::{Pio0Spare, pio0_ctrl_clear, pio0_ctrl_set};

const TX_SM: usize = 1;
const RX_SM: usize = 2;
const HSKI_GPIO: usize = 18;
const FUNCSEL_UART0: u8 = 0x02;
const FUNCSEL_PIO0: u8 = 0x06;

/// How long the printer can go without taking a byte before its clock is
/// taken to have stopped, most likely because it was reset or switched
/// off. A clocking printer takes a byte about every 11 us.
const CLOCK_LOST: Duration = Duration::from_secs(2);

/// Long enough for the printer to clock in the last stop bit, at any clock
/// down to 100 kHz.
const STOP_BIT: Duration = Duration::from_micros(10);

/// The printer stopped clocking with bytes still to send.
#[derive(Debug)]
pub struct ClockLost;

/// Turn GP18's input inversion on for the UART's CTS, or off for the state
/// machines.
fn set_hski_inversion(invert: bool) {
    let over = if invert { Inover::INVERT } else { Inover::NORMAL };
    pac::IO_BANK0.gpio(HSKI_GPIO).ctrl().modify(|w| w.set_inover(over));
}

/// The transmitting state machine, and everything switching the port
/// needs. The printer TX task owns it and switches between chunks.
pub struct FastTx {
    sm: StateMachine<'static, PIO0, TX_SM>,
    /// The data pin, whose FUNCSEL moves between UART0 and PIO0.
    tx_gpio: usize,
    tx_origin: u8,
    rx_origin: u8,
}

/// The receiving state machine. The printer RX task owns it.
pub struct FastRx {
    sm: StateMachine<'static, PIO0, RX_SM>,
}

/// What one [`FastRx::read`] got.
#[derive(Default)]
pub struct Received {
    /// Bytes copied into the buffer.
    pub bytes: usize,
    /// Frames lost, either ended by a 0 where the stop bit belongs (a
    /// framing error or a BREAK) or dropped because the FIFO was full.
    pub lost: u32,
}

/// Load both programs and configure both machines, stopped. Call before
/// the UART is built. GP28 and GP29 go to PIO0 here, and building the UART
/// takes them back.
pub fn init(
    spare: Pio0Spare,
    tx_pin: impl Peripheral<P = impl PioPin> + 'static,
    rx_pin: impl Peripheral<P = impl PioPin> + 'static,
) -> (FastTx, FastRx) {
    let Pio0Spare {
        mut common,
        sm1: mut tx_sm,
        sm2: mut rx_sm,
    } = spare;

    // One frame per byte pulled. The line stays at the last stop bit while
    // there is nothing to send.
    let tx_prog = pio_proc::pio_asm!(
        ".wrap_target",
        "    pull block",
        "    set x, 7",
        "    wait 1 gpio 18",
        "    wait 0 gpio 18",
        "    set pins, 0",        // start bit
        "data_bit:",
        "    wait 1 gpio 18",
        "    wait 0 gpio 18",
        "    out pins, 1",        // data, LSB first
        "    jmp x--, data_bit",
        "    wait 1 gpio 18",
        "    wait 0 gpio 18",
        "    set pins, 1",        // stop bit, held until the next start bit
        ".wrap",
    );
    let tx_loaded = common.load_program(&tx_prog.program);
    let tx_pin = common.make_pio_pin(tx_pin);
    let mut tx_cfg = Config::default();
    tx_cfg.use_program(&tx_loaded, &[]);
    tx_cfg.set_out_pins(&[&tx_pin]);
    tx_cfg.set_set_pins(&[&tx_pin]);
    tx_cfg.shift_out = ShiftConfig {
        threshold: 32,
        direction: ShiftDirection::Right,
        auto_fill: false,
    };
    tx_cfg.fifo_join = FifoJoin::TxOnly;
    tx_sm.set_config(&tx_cfg);
    tx_sm.set_pins(Level::High, &[&tx_pin]);
    tx_sm.set_pin_dirs(Direction::Out, &[&tx_pin]);

    // Each frame is pushed as the nine bits after its start bit, shifted in
    // from the top, so the stop bit lands in bit 31 and the data in 30..23.
    // `push noblock` drops a frame when the FIFO is full, and flags it in
    // FDEBUG.RXSTALL.
    let rx_prog = pio_proc::pio_asm!(
        ".wrap_target",
        "idle:",
        "    wait 0 gpio 18",
        "    wait 1 gpio 18",
        "    jmp pin, idle",      // still at mark
        "    set x, 8",           // a start bit, so eight data bits and the stop bit follow
        "frame_bit:",
        "    wait 0 gpio 18",
        "    wait 1 gpio 18",
        "    in pins, 1",
        "    jmp x--, frame_bit",
        "    push noblock",
        ".wrap",
    );
    let rx_loaded = common.load_program(&rx_prog.program);
    let rx_pin = common.make_pio_pin(rx_pin);
    let mut rx_cfg = Config::default();
    rx_cfg.use_program(&rx_loaded, &[]);
    rx_cfg.set_in_pins(&[&rx_pin]);
    rx_cfg.set_jmp_pin(&rx_pin);
    rx_cfg.shift_in = ShiftConfig {
        threshold: 32,
        direction: ShiftDirection::Right,
        auto_fill: false,
    };
    rx_cfg.fifo_join = FifoJoin::RxOnly;
    rx_sm.set_config(&rx_cfg);
    rx_sm.set_pin_dirs(Direction::In, &[&rx_pin]);

    // Kept for good, like PIO0's other handles. See Pio0Spare.
    core::mem::forget(common);

    (
        FastTx {
            sm: tx_sm,
            tx_gpio: usize::from(tx_pin.pin()),
            tx_origin: tx_loaded.origin,
            rx_origin: rx_loaded.origin,
        },
        FastRx { sm: rx_sm },
    )
}

/// Run `instr` on SM2, which [`FastRx`] holds. Switching the port restarts
/// it from here, while the RX task only ever waits on its FIFO.
///
/// # Safety
///
/// SM2 must be stopped, so `instr` can't land in the middle of its program.
unsafe fn exec_rx(instr: u16) {
    pac::PIO0.sm(RX_SM).instr().write(|w| w.set_instr(instr));
}

/// `jmp addr`.
const fn jmp(address: u8) -> u16 {
    InstructionOperands::JMP { condition: JmpCondition::Always, address }.encode()
}

/// `set pins, 1`.
const SET_PINS_HIGH: u16 = InstructionOperands::SET { destination: SetDestination::PINS, data: 1 }.encode();

impl FastTx {
    /// Hand the data pins to the state machines. Everything sent at the
    /// UART's clock must already be out of it.
    pub fn enter(&mut self) {
        pac::UART0.uartcr().modify(|w| w.set_rxe(false));
        set_hski_inversion(false);

        let both = (1 << TX_SM) | (1 << RX_SM);
        pio0_ctrl_set(|w| w.set_sm_restart(both));
        // SAFETY: both machines stay stopped until the enable below.
        unsafe {
            // A lost clock can leave GP28 low partway through a byte.
            self.sm.exec_instr(SET_PINS_HIGH);
            self.sm.exec_instr(jmp(self.tx_origin));
        }
        clear_fifo(RX_SM);
        // An overrun left over from the last time would count against this one.
        pac::PIO0.fdebug().write(|w| w.set_rxstall(1 << RX_SM));
        // SAFETY: as above.
        unsafe { exec_rx(jmp(self.rx_origin)) };
        pio0_ctrl_set(|w| w.set_sm_enable(both));

        pac::IO_BANK0.gpio(self.tx_gpio).ctrl().modify(|w| w.set_funcsel(FUNCSEL_PIO0));
    }

    /// Give the data pins back to the UART. Anything SM1 has not sent by
    /// now is dropped.
    pub fn leave(&mut self) {
        pac::IO_BANK0.gpio(self.tx_gpio).ctrl().modify(|w| w.set_funcsel(FUNCSEL_UART0));
        pio0_ctrl_clear(|w| w.set_sm_enable((1 << TX_SM) | (1 << RX_SM)));
        clear_fifo(TX_SM);

        set_hski_inversion(true);
        pac::UART0.uartcr().modify(|w| w.set_rxe(true));
    }

    /// Send bytes at the printer's clock, waiting while the FIFO is full.
    pub async fn write(&mut self, data: &[u8]) -> Result<(), ClockLost> {
        for &b in data {
            with_timeout(CLOCK_LOST, self.sm.tx().wait_push(u32::from(b)))
                .await
                .map_err(|_| ClockLost)?;
        }
        Ok(())
    }

    /// Wait until the last byte has gone out, stop bit and all.
    pub async fn flush(&mut self) -> Result<(), ClockLost> {
        let deadline = Instant::now() + CLOCK_LOST;
        // Idle is stalled on the opening `pull` with the FIFO empty. Anywhere
        // else the machine is partway through a byte.
        while !(self.sm.tx().empty() && pac::PIO0.sm(TX_SM).addr().read().addr() == self.tx_origin) {
            if Instant::now() >= deadline {
                return Err(ClockLost);
            }
            Timer::after_micros(20).await;
        }
        Timer::after(STOP_BIT).await;
        Ok(())
    }
}

/// Empty a stopped machine's FIFO. Changing its join discards what is in
/// it.
fn clear_fifo(sm: usize) {
    let shiftctrl = pac::PIO0.sm(sm).shiftctrl();
    let joined = shiftctrl.read();
    shiftctrl.modify(|w| {
        w.set_fjoin_rx(false);
        w.set_fjoin_tx(false);
    });
    shiftctrl.write_value(joined);
}

impl FastRx {
    /// Wait for frames from the printer and copy out every byte that has
    /// arrived, as many as fit in `buf`. An empty `buf` returns at once.
    ///
    /// It is cancel safe, since nothing is taken from the FIFO until the wait
    /// is over.
    pub async fn read(&mut self, buf: &mut [u8]) -> Received {
        let mut got = Received::default();
        if buf.is_empty() {
            return got;
        }
        let mut frame = Some(self.sm.rx().wait_pull().await);
        while let Some(word) = frame {
            let bits = word >> 23;
            if bits & 0x100 != 0 {
                buf[got.bytes] = bits as u8;
                got.bytes += 1;
            } else {
                got.lost += 1;
            }
            frame = if got.bytes < buf.len() { self.sm.rx().try_pull() } else { None };
        }
        if self.sm.rx().stalled() {
            got.lost += 1;
        }
        got
    }
}
