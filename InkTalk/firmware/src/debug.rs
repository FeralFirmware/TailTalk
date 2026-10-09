//! The debug shell on the USB CDC port: single-letter commands for the
//! LocalTalk wire, the printer port and the config (`?` lists them), with
//! the log interleaved.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::core1::SharedState;
use crate::tt_log::{LogLine, CHANNEL as LOG_CHANNEL};
use crate::usb_dev::Cdc;
use defmt::{info, warn};
use embassy_futures::select::{select, Either};
use embassy_usb::driver::EndpointError;
use localtalk::crc::lt_crc;

// ── RX monitor and frame log ──────────────────────────────────────

pub static MONITOR_ENABLED: AtomicBool = AtomicBool::new(false);
pub static ANALYZER_MODE: AtomicBool = AtomicBool::new(false);

const RX_LOG_SLOTS: usize = 16;
const RX_LOG_BYTES: usize = 64;
static mut RX_LOG: [[u8; RX_LOG_BYTES]; RX_LOG_SLOTS] = [[0u8; RX_LOG_BYTES]; RX_LOG_SLOTS];
static mut RX_LOG_LENS: [u16; RX_LOG_SLOTS] = [0u16; RX_LOG_SLOTS];
static mut RX_LOG_WRITE: usize = 0;
static mut RX_LOG_COUNT: usize = 0;

pub fn log_rx_frame(frame: &[u8], crc_ok: bool) {
    let n = frame.len().min(RX_LOG_BYTES);
    unsafe {
        let idx = RX_LOG_WRITE;
        RX_LOG[idx][..n].copy_from_slice(&frame[..n]);
        RX_LOG_LENS[idx] = frame.len() as u16;
        RX_LOG_WRITE = (idx + 1) % RX_LOG_SLOTS;
        if RX_LOG_COUNT < RX_LOG_SLOTS {
            RX_LOG_COUNT += 1;
        }
    }

    if MONITOR_ENABLED.load(Ordering::Relaxed) || ANALYZER_MODE.load(Ordering::Relaxed) {
        let mut s: LogLine = heapless::String::new();
        let ms = embassy_time::Instant::now().as_millis();
        let tag = if crc_ok { "RX" } else { "RX!" };
        let _ = core::fmt::Write::write_fmt(
            &mut s, core::format_args!("[{:06}] {}:", ms, tag));
        for &b in &frame[..frame.len().min(30)] {
            let _ = core::fmt::Write::write_fmt(
                &mut s, core::format_args!("{:02X}", b));
        }
        if frame.len() > 30 {
            let _ = core::fmt::Write::write_str(&mut s, "..");
        }
        let _ = crate::tt_log::CHANNEL.try_send(s);
    }
}

// ── Command state machine ─────────────────────────────────────────

const CMD_BUF_SIZE: usize = 1280;

enum CmdState {
    Idle,
    Accumulating { cmd: u8, pos: usize },
}

static mut CMD_BUF: [u8; CMD_BUF_SIZE] = [0u8; CMD_BUF_SIZE];
static mut CMD_STATE: CmdState = CmdState::Idle;


const BUILD_ID: &str = env!("BUILD_ID");

const HELP: &[u8] = b"\r\n\
commands:\r\n\
  t AABB..  TX raw hex frame (incl CRC) via CSMA\r\n\
  d XX HEX  directed TX to node XX with payload\r\n\
  m         toggle RX monitor (prints RX:hex lines)\r\n\
  a         toggle analyzer mode (all frames incl bad CRC)\r\n\
  c         clear all counters\r\n\
  f         dump buffered RX frames\r\n\
  i         print USB serial number\r\n\
  s         show status/counters\r\n\
  p         TX known test frame via CSMA\r\n\
  g         show config\r\n\
  r X       set role (0=stylewriter 1=imagewriter)\r\n\
  e NAME    set printer name\r\n\
  u BAUD    set printer UART baud\r\n\
  v         save config to flash (role/baud apply on reboot)\r\n\
  h         toggle printer CTS handshake on GP18 (on by default)\r\n\
  w HEX     send raw bytes to the printer UART (FFFFFF31=status)\r\n\
  l         printer UART internal loopback self-test\r\n\
  q         reset and identify the StyleWriter again\r\n\
  k         toggle printer traffic trace (P> / P< lines)\r\n\
  b         reboot to BOOTSEL\r\n\
  ?         this help\r\n\
\r\n";

fn format_banner() -> heapless::String<256> {
    use core::fmt::Write;
    let mut s = heapless::String::<256>::new();
    let serial = crate::usb_dev::serial();
    let ms = embassy_time::Instant::now().as_millis();
    let _ = write!(s, "\r\nINKTALK {} serial={} uptime={}ms\r\n", BUILD_ID, serial, ms);
    let _ = write!(s, "commands: t d m a c f i s p g r e u v h w l q k b ?\r\n");
    s
}

// ── Task entry ────────────────────────────────────────────────────

#[embassy_executor::task]
pub async fn run(
    mut cdc: Cdc,
    shared: &'static SharedState,
) -> ! {
    while shared.flags.load(Ordering::Relaxed) & crate::core1::CORE1_ALIVE == 0 {
        embassy_time::Timer::after_millis(1).await;
    }

    let mut buf = [0u8; 64];
    loop {
        cdc.wait_connection().await;
        info!("TT_DEBUG: host connected");
        unsafe { CMD_STATE = CmdState::Idle; }

        let banner = format_banner();
        let _ = write_chunked(&mut cdc, banner.as_bytes()).await;
        // A stored panic means the last run died rather than being reset,
        // and it is the single most useful thing to say on connect.
        if let Some(msg) = crate::panic_message() {
            let _ = write_chunked(&mut cdc, b"\r\n*** PANIC ON PREVIOUS RUN ***\r\n").await;
            let _ = write_chunked(&mut cdc, msg.as_bytes()).await;
            let _ = write_chunked(&mut cdc, b"\r\n(clear with 'c')\r\n").await;
        }
        let _ = write_chunked(&mut cdc, b"READY\r\n").await;

        loop {
            match select(cdc.read_packet(&mut buf), LOG_CHANNEL.receive()).await {
                Either::First(Ok(n)) => {
                    if let Err(e) = handle_input(&mut cdc, &buf[..n], shared).await {
                        warn!("TT_DEBUG write failed: {}", classify(e));
                        break;
                    }
                }
                Either::First(Err(e)) => {
                    warn!("TT_DEBUG read failed: {}", classify(e));
                    break;
                }
                Either::Second(line) => {
                    if let Err(e) = write_log_line(&mut cdc, &line).await {
                        warn!("TT_DEBUG log write failed: {}", classify(e));
                        break;
                    }
                }
            }
        }
        info!("TT_DEBUG: host disconnected");
    }
}

// ── Input handling ────────────────────────────────────────────────

async fn handle_input(
    cdc: &mut Cdc,
    data: &[u8],
    shared: &'static SharedState,
) -> Result<(), EndpointError> {
    for &b in data {
        let state = unsafe { &mut CMD_STATE };
        match state {
            CmdState::Idle => {
                match b {
                    b't' | b'T' | b'd' | b'r' | b'e' | b'u' | b'w' | b'W' => {
                        unsafe {
                            CMD_STATE = CmdState::Accumulating { cmd: b, pos: 0 };
                        }
                        write_chunked(cdc, core::slice::from_ref(&b)).await?;
                    }
                    b'p' | b'P' => {
                        write_chunked(cdc, b"\r\nOK TX\r\n").await?;
                        let frame = debug_test_frame();
                        crate::wire::submit_tx_from_debug(shared, &frame).await;
                        write_chunked(cdc, b"OK\r\n").await?;
                    }
                    b's' | b'S' => {
                        write_chunked(cdc, b"\r\n").await?;
                        let status = pio_status(shared);
                        write_chunked(cdc, status.as_bytes()).await?;
                        write_chunked(cdc, b"---\r\n").await?;
                    }
                    b'c' | b'C' => {
                        crate::core1::clear_counters();
                        crate::printer::clear_counters();
                        crate::clear_panic_message();
                        write_chunked(cdc, b"\r\nCOUNTERS CLEARED\r\n").await?;
                    }
                    b'm' | b'M' => {
                        let prev = MONITOR_ENABLED.load(Ordering::Relaxed);
                        MONITOR_ENABLED.store(!prev, Ordering::Relaxed);
                        write_chunked(cdc, if prev { b"\r\nMONITOR OFF\r\n".as_slice() } else { b"\r\nMONITOR ON\r\n".as_slice() }).await?;
                    }
                    b'a' | b'A' => {
                        let prev = ANALYZER_MODE.load(Ordering::Relaxed);
                        ANALYZER_MODE.store(!prev, Ordering::Relaxed);
                        write_chunked(cdc, if prev { b"\r\nANALYZER OFF\r\n".as_slice() } else { b"\r\nANALYZER ON\r\n".as_slice() }).await?;
                    }
                    b'f' | b'F' => {
                        write_chunked(cdc, b"\r\n").await?;
                        cmd_dump_rx(cdc).await?;
                    }
                    b'i' | b'I' => {
                        let serial = crate::usb_dev::serial();
                        write_chunked(cdc, b"\r\nID:").await?;
                        write_chunked(cdc, serial.as_bytes()).await?;
                        write_chunked(cdc, b"\r\n").await?;
                    }
                    b'g' | b'G' => {
                        write_chunked(cdc, b"\r\n").await?;
                        let cfg = format_config().await;
                        write_chunked(cdc, cfg.as_bytes()).await?;
                    }
                    b'v' | b'V' => {
                        write_chunked(cdc, b"\r\n").await?;
                        cmd_save(cdc, shared).await?;
                    }
                    b'k' | b'K' => {
                        let on = !crate::printer::trace();
                        crate::printer::set_trace(on);
                        write_chunked(
                            cdc,
                            if on {
                                b"\r\nPRINTER TRACE ON\r\n".as_slice()
                            } else {
                                b"\r\nPRINTER TRACE OFF\r\n".as_slice()
                            },
                        )
                        .await?;
                    }
                    b'l' | b'L' => {
                        write_chunked(cdc, b"\r\n").await?;
                        cmd_printer_loopback(cdc).await?;
                    }
                    b'q' | b'Q' => {
                        // The printer task does the asking, since it owns
                        // the replies; the result arrives as PRINTER: log
                        // lines and in `s`.
                        let reply: &[u8] = if !crate::identify::enabled() {
                            b"\r\nERR:only the stylewriter role identifies\r\n"
                        } else if crate::control::JOB_ACTIVE.load(Ordering::Relaxed) {
                            b"\r\nERR:job in progress\r\n"
                        } else {
                            crate::identify::REPROBE.signal(());
                            b"\r\nIDENTIFY REQUESTED (resets the printer)\r\n"
                        };
                        write_chunked(cdc, reply).await?;
                    }
                    b'h' | b'H' => {
                        // CTS gating on the printer's ready line, see
                        // printer.rs. `s` shows the line.
                        let on = !crate::printer::handshake_gating();
                        crate::printer::set_handshake_gating(on);
                        write_chunked(
                            cdc,
                            if on {
                                b"\r\nHANDSHAKE GATING ON\r\n".as_slice()
                            } else {
                                b"\r\nHANDSHAKE GATING OFF\r\n".as_slice()
                            },
                        )
                        .await?;
                    }
                    b'b' | b'B' => {
                        write_chunked(cdc, b"\r\nBOOTSEL\r\n").await?;
                        embassy_time::Timer::after_millis(50).await;
                        embassy_rp::rom_data::reset_to_usb_boot(0, 0);
                    }
                    b'?' => {
                        write_chunked(cdc, HELP).await?;
                    }
                    b'\r' | b'\n' => {
                        write_chunked(cdc, b"\r\n").await?;
                    }
                    _ => {
                        write_chunked(cdc, core::slice::from_ref(&b)).await?;
                    }
                }
            }
            CmdState::Accumulating { cmd, pos } => {
                if b == b'\r' || b == b'\n' {
                    write_chunked(cdc, b"\r\n").await?;
                    let cmd_byte = *cmd;
                    let len = *pos;
                    unsafe { CMD_STATE = CmdState::Idle; }
                    let line = unsafe { &CMD_BUF[..len] };
                    dispatch_cmd(cdc, shared, cmd_byte, line).await?;
                } else if *pos < CMD_BUF_SIZE {
                    unsafe { CMD_BUF[*pos] = b; }
                    *pos += 1;
                    write_chunked(cdc, core::slice::from_ref(&b)).await?;
                }
            }
        }
    }
    Ok(())
}

async fn dispatch_cmd(
    cdc: &mut Cdc,
    shared: &'static SharedState,
    cmd: u8,
    args: &[u8],
) -> Result<(), EndpointError> {
    let args = strip_leading(args, b' ');

    match cmd {
        b't' | b'T' => cmd_tx_raw(cdc, shared, args).await,
        b'd' => cmd_directed(cdc, shared, args).await,
        b'r' => cmd_set_role(cdc, args).await,
        b'e' => cmd_set_name(cdc, args).await,
        b'u' => cmd_set_baud(cdc, args).await,
        b'w' | b'W' => cmd_printer_write(cdc, args).await,
        _ => {
            write_chunked(cdc, b"ERR:unknown\r\n").await
        }
    }
}

// ── Config commands ───────────────────────────────────────────────

async fn format_config() -> heapless::String<192> {
    use core::fmt::Write;
    let mut s = heapless::String::<192>::new();
    let guard = crate::config::ACTIVE.lock().await;
    match guard.as_ref() {
        Some(cfg) => {
            let _ = write!(
                s,
                "role={} name={} baud={}\r\n(unsaved changes apply after 'v' + reboot)\r\n",
                cfg.role.name(),
                cfg.name.as_str(),
                cfg.baud
            );
        }
        None => {
            let _ = write!(s, "config not loaded\r\n");
        }
    }
    s
}

async fn cmd_set_role(cdc: &mut Cdc, args: &[u8]) -> Result<(), EndpointError> {
    let Some(v) = args.first().and_then(|c| (*c as char).to_digit(10)) else {
        return write_chunked(cdc, b"ERR:role 0-1\r\n").await;
    };
    let Some(role) = crate::config::Role::from_u8(v as u8) else {
        return write_chunked(cdc, b"ERR:role 0-1\r\n").await;
    };
    let baud = {
        let mut guard = crate::config::ACTIVE.lock().await;
        match guard.as_mut() {
            Some(cfg) => {
                cfg.role = role;
                cfg.baud
            }
            None => return write_chunked(cdc, b"ERR:no config\r\n").await,
        }
    };
    // The baud rate does not follow the role, and the roles do not agree on
    // one: lpstyl drives a StyleWriter at 57600, while an ImageWriter's
    // serial rate is whatever its DIP switches say. Saying the rate here
    // puts the mismatch in front of whoever just changed the role, which is
    // the moment it is created.
    let mut out: heapless::String<96> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(
        &mut out,
        core::format_args!(
            "ROLE SET, baud still {} (change with u)\r\nsave with v, applies on reboot\r\n",
            baud
        ),
    );
    write_chunked(cdc, out.as_bytes()).await
}

async fn cmd_set_name(cdc: &mut Cdc, args: &[u8]) -> Result<(), EndpointError> {
    let Ok(name_str) = core::str::from_utf8(args) else {
        return write_chunked(cdc, b"ERR:bad name\r\n").await;
    };
    let Some(name) = crate::config::parse_name(name_str.trim()) else {
        return write_chunked(cdc, b"ERR:1-31 chars, no :@=*\r\n").await;
    };
    let mut guard = crate::config::ACTIVE.lock().await;
    if let Some(cfg) = guard.as_mut() {
        cfg.name = name;
    }
    write_chunked(cdc, b"NAME SET (save with v, applies on reboot)\r\n").await
}

async fn cmd_set_baud(cdc: &mut Cdc, args: &[u8]) -> Result<(), EndpointError> {
    let mut baud = 0u32;
    let mut any = false;
    for &c in args {
        match c {
            b'0'..=b'9' => {
                any = true;
                baud = baud.saturating_mul(10).saturating_add((c - b'0') as u32);
            }
            b' ' => {}
            _ => return write_chunked(cdc, b"ERR:bad baud\r\n").await,
        }
    }
    if !any || !crate::config::BAUD_RANGE.contains(&baud) {
        return write_chunked(cdc, b"ERR:baud 300-1000000\r\n").await;
    }
    let mut guard = crate::config::ACTIVE.lock().await;
    if let Some(cfg) = guard.as_mut() {
        cfg.baud = baud;
    }
    write_chunked(cdc, b"BAUD SET (save with v, applies on reboot)\r\n").await
}

async fn cmd_save(cdc: &mut Cdc, shared: &'static SharedState) -> Result<(), EndpointError> {
    let cfg = {
        let guard = crate::config::ACTIVE.lock().await;
        guard.clone()
    };
    let Some(cfg) = cfg else {
        return write_chunked(cdc, b"ERR:no config\r\n").await;
    };
    match crate::config::save(shared, &cfg).await {
        Ok(()) => write_chunked(cdc, b"SAVED\r\n").await,
        Err(e) => {
            write_chunked(cdc, b"ERR:").await?;
            write_chunked(cdc, e.as_bytes()).await?;
            write_chunked(cdc, b"\r\n").await
        }
    }
}

// ── Command implementations ───────────────────────────────────────

async fn cmd_tx_raw(
    cdc: &mut Cdc,
    shared: &'static SharedState,
    hex: &[u8],
) -> Result<(), EndpointError> {
    let Some(()) = parse_hex_to_buf(hex) else {
        return write_chunked(cdc, b"ERR:bad hex\r\n").await;
    };
    let len = frame_len();
    if !(5..=605).contains(&len) {
        return write_chunked(cdc, b"ERR:bad len\r\n").await;
    }
    let frame_slice = frame_slice_ref();
    crate::wire::submit_tx_from_debug(shared, frame_slice).await;
    write_chunked(cdc, b"OK\r\n").await
}

/// Write raw bytes straight to the printer UART, bypassing AppleTalk, to
/// tell a printer that never answers from a bridge that can't hear it.
/// Replies show up as `P<` lines.
///
/// Useful StyleWriter bytes: `FFFFFF31`, `FFFFFF32` and `FFFFFF42` are the
/// `1`, `2` and `B` status queries, one byte back each. `FFFFFF49` (eject
/// and reset) and `FFFFFF53` (resume) get no reply. `3F` (`?`) returns the
/// model string, but only after a reset. A busy printer may ignore a
/// query, so ask again with it idle.
async fn cmd_printer_write(cdc: &mut Cdc, hex: &[u8]) -> Result<(), EndpointError> {
    let Some(()) = parse_hex_to_buf(hex) else {
        return write_chunked(cdc, b"ERR:bad hex\r\n").await;
    };
    let len = frame_len();
    if len == 0 || len > 64 {
        return write_chunked(cdc, b"ERR:1-64 bytes\r\n").await;
    }
    // printer::send does the P> logging for every path, this one included.
    let bytes = frame_slice_ref();
    crate::printer::send(bytes).await;
    write_chunked(cdc, b"OK\r\n").await
}

/// Loop the printer UART back on itself inside the RP2040 (PL011 `LBE`)
/// and check a test pattern survives the round trip. When `s` shows
/// `rx=0 rx_err=0`, a pass puts the fault outside the chip (wire,
/// transceiver or printer) and a fail puts it in our receive path. The
/// pattern may reach the printer too; it's harmless.
async fn cmd_printer_loopback(cdc: &mut Cdc) -> Result<(), EndpointError> {
    use core::fmt::Write;
    use embassy_rp::pac;

    const PATTERN: &[u8] = &[0x55, 0xAA, 0x5A, 0xA5];
    let (_, rx_before, err_before) = crate::printer::counters();

    pac::UART0.uartcr().modify(|w| w.set_lbe(true));
    crate::printer::send(PATTERN).await;
    // 4 bytes at any supported rate clear the shift register in well under
    // this; the slack is for the RX task to be scheduled and drain them.
    embassy_time::Timer::after_millis(200).await;
    pac::UART0.uartcr().modify(|w| w.set_lbe(false));

    let (_, rx_after, err_after) = crate::printer::counters();
    let got = rx_after.wrapping_sub(rx_before);
    let errs = err_after.wrapping_sub(err_before);

    let mut out: heapless::String<160> = heapless::String::new();
    let _ = write!(
        out,
        "LOOPBACK: sent {} got {} errs {} -> {}\r\n",
        PATTERN.len(),
        got,
        errs,
        if got as usize == PATTERN.len() && errs == 0 {
            "PASS (receive path works; silence is on the wire)"
        } else {
            "FAIL (receive path is broken on this side)"
        },
    );
    write_chunked(cdc, out.as_bytes()).await
}


async fn cmd_directed(
    cdc: &mut Cdc,
    shared: &'static SharedState,
    args: &[u8],
) -> Result<(), EndpointError> {
    if args.len() < 3 {
        return write_chunked(cdc, b"ERR:need dest+payload\r\n").await;
    }
    let Some(dest) = parse_hex_byte(&args[..2]) else {
        return write_chunked(cdc, b"ERR:bad dest hex\r\n").await;
    };
    let payload_hex = strip_leading(&args[2..], b' ');
    let Some(_) = parse_hex_to_buf(payload_hex) else {
        return write_chunked(cdc, b"ERR:bad payload hex\r\n").await;
    };
    let payload_len = frame_len();

    // Source is whatever node the stack claimed; 1 keeps the frame legal
    // if this is sent before acquisition finishes.
    let src = match crate::stack_task::our_node() {
        0 => 1,
        n => n,
    };

    let mut frame_buf = [0u8; 610];
    frame_buf[0] = dest;
    frame_buf[1] = src;
    frame_buf[2] = 0x01; // DDP short
    let payload_slice = frame_slice_ref();
    let total_data = 3 + payload_len;
    frame_buf[3..3 + payload_len].copy_from_slice(&payload_slice[..payload_len]);
    let crc = lt_crc(&frame_buf[..total_data]);
    frame_buf[total_data] = crc[0];
    frame_buf[total_data + 1] = crc[1];
    let total = total_data + 2;

    let fails_before = unsafe { crate::core1::TX_FAIL_COUNT };
    crate::wire::submit_tx_from_debug(shared, &frame_buf[..total]).await;
    let fails_after = unsafe { crate::core1::TX_FAIL_COUNT };

    if fails_after != fails_before {
        write_chunked(cdc, b"DIR TIMEOUT\r\n").await
    } else {
        write_chunked(cdc, b"DIR OK\r\n").await
    }
}

async fn cmd_dump_rx(cdc: &mut Cdc) -> Result<(), EndpointError> {
    let count = unsafe { RX_LOG_COUNT };
    let write_idx = unsafe { RX_LOG_WRITE };

    if count == 0 {
        return write_chunked(cdc, b"END\r\n").await;
    }

    let start = if count < RX_LOG_SLOTS {
        0
    } else {
        write_idx
    };

    let mut hex_buf = [0u8; 132];
    for i in 0..count {
        let idx = (start + i) % RX_LOG_SLOTS;
        let len = unsafe { RX_LOG_LENS[idx] } as usize;
        let stored = len.min(RX_LOG_BYTES);
        let frame = unsafe { &RX_LOG[idx][..stored] };

        let mut pos = 0;
        hex_buf[pos] = b'R'; pos += 1;
        hex_buf[pos] = b'X'; pos += 1;
        hex_buf[pos] = b':'; pos += 1;
        for &b in frame {
            hex_buf[pos] = hex_char(b >> 4); pos += 1;
            hex_buf[pos] = hex_char(b & 0xF); pos += 1;
        }
        hex_buf[pos] = b'\r'; pos += 1;
        hex_buf[pos] = b'\n'; pos += 1;
        write_chunked(cdc, &hex_buf[..pos]).await?;
    }

    unsafe {
        RX_LOG_COUNT = 0;
        RX_LOG_WRITE = 0;
    }

    write_chunked(cdc, b"END\r\n").await
}

// ── Helpers ───────────────────────────────────────────────────────

fn debug_test_frame() -> [u8; 10] {
    let mut f = [0u8; 10];
    f[0] = 0x42; f[1] = 0x01; f[2] = 0x01;
    f[3] = 0x00; f[4] = 0x05; f[5] = 0xDE;
    f[6] = 0x00; f[7] = 0xAD;
    let crc = lt_crc(&f[..8]);
    f[8] = crc[0]; f[9] = crc[1];
    f
}

fn hex_char(nibble: u8) -> u8 {
    if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

static mut FRAME_BUF: [u8; 610] = [0u8; 610];
static mut FRAME_BUF_LEN: usize = 0;

fn parse_hex_to_buf(hex: &[u8]) -> Option<()> {
    let hex = strip_leading(hex, b' ');
    if !hex.len().is_multiple_of(2) { return None; }
    let byte_count = hex.len() / 2;
    if byte_count > 610 { return None; }
    unsafe {
        FRAME_BUF_LEN = 0;
        for i in 0..byte_count {
            let hi = hex_val(hex[i * 2])?;
            let lo = hex_val(hex[i * 2 + 1])?;
            FRAME_BUF[i] = (hi << 4) | lo;
        }
        FRAME_BUF_LEN = byte_count;
    }
    Some(())
}

fn frame_len() -> usize {
    unsafe { FRAME_BUF_LEN }
}

fn frame_slice_ref() -> &'static [u8] {
    unsafe { &FRAME_BUF[..FRAME_BUF_LEN] }
}

fn parse_hex_byte(hex: &[u8]) -> Option<u8> {
    let hex = strip_leading(hex, b' ');
    if hex.len() < 2 { return None; }
    let hi = hex_val(hex[0])?;
    let lo = hex_val(hex[1])?;
    Some((hi << 4) | lo)
}

fn strip_leading(data: &[u8], ch: u8) -> &[u8] {
    let mut i = 0;
    while i < data.len() && data[i] == ch { i += 1; }
    &data[i..]
}

async fn write_chunked(cdc: &mut Cdc, data: &[u8]) -> Result<(), EndpointError> {
    for chunk in data.chunks(64) {
        match embassy_futures::select::select(
            cdc.write_packet(chunk),
            embassy_time::Timer::after_millis(100),
        )
        .await
        {
            embassy_futures::select::Either::First(r) => r?,
            embassy_futures::select::Either::Second(()) => {
                return Err(EndpointError::Disabled);
            }
        }
    }
    Ok(())
}

async fn write_log_line(cdc: &mut Cdc, line: &LogLine) -> Result<(), EndpointError> {
    write_chunked(cdc, line.as_bytes()).await?;
    write_chunked(cdc, b"\r\n").await?;
    Ok(())
}

fn pio_status(shared: &SharedState) -> heapless::String<1024> {
    use core::fmt::Write;
    use embassy_rp::pac;

    let mut s = heapless::String::<1024>::new();
    let ms = embassy_time::Instant::now().as_millis();
    let _ = write!(s, "[{:06}] status\r\n", ms);

    let pio1_ctrl = pac::PIO1.ctrl().read();
    let gpio_in = pac::SIO.gpio_in(0).read();
    let flags = shared.flags.load(Ordering::Relaxed);
    let (_, waddr, ridx, en, remain) = crate::core1::rx_dma_diag();
    let base = unsafe { crate::core1::RX_RING.0.as_ptr() } as u32;
    let widx = (waddr.wrapping_sub(base)) / 4;

    let sm0_pc = pac::PIO1.sm(0).addr().read().addr();
    let _ = write!(s, "PIO1: sm_en={:04b} sm0_pc={} GP4(RX)={}\r\n",
        pio1_ctrl.sm_enable(), sm0_pc, (gpio_in >> 4) & 1);
    let _ = write!(s, "Flags: 0x{:02x} alive={}\r\n",
        flags, (flags >> 5) & 1);
    let loop_count = unsafe { crate::core1::LOOP_COUNT };
    let _ = write!(s, "DMA: en={} widx={} ridx={} remain={}\r\n", en, widx, ridx, remain);
    let _ = write!(s, "Core1: loops={}\r\n", loop_count);

    let good = unsafe { crate::core1::GOOD_CRC_COUNT };
    let bad = unsafe { crate::core1::BAD_CRC_COUNT };
    let ar = unsafe { crate::core1::AUTOREPLY_COUNT };
    let ar_late = unsafe { crate::core1::AUTOREPLY_LATE };
    let ar_wait = unsafe { crate::core1::AUTOREPLY_WAIT_MAX_US };
    let overruns = unsafe { crate::core1::RING_OVERRUN_COUNT };
    let dir_att = unsafe { crate::core1::DIRECTED_TX_ATTEMPTS };
    let dir_cts = unsafe { crate::core1::DIRECTED_TX_CTS_OK };
    let dir_tmo = unsafe { crate::core1::DIRECTED_TX_TIMEOUT };
    let dir_rx = unsafe { crate::core1::DIRECTED_RX_COUNT };
    let echo_skip = unsafe { crate::core1::ECHO_SKIP_COUNT };
    let bad_real = unsafe { crate::core1::BAD_REAL_COUNT };
    let rx_drop = unsafe { crate::core1::RX_DROP_COUNT };
    let tx_fail = unsafe { crate::core1::TX_FAIL_COUNT };

    let _ = write!(s, "Recv: good={} bad={} bad_real={} ar={} echo={} overrun={} drop={}\r\n",
        good, bad, bad_real, ar, echo_skip, overruns, rx_drop);
    // Auto-replies wait for the sender's abort sequence to finish first.
    // `late` counts the ones where the line didn't go quiet within 200 us.
    let _ = write!(s, "Reply: late={} wait_max={}us\r\n", ar_late, ar_wait);
    let _ = write!(s, "Send: dir_att={} cts_ok={} tmo={} dir_rx={} fail={}\r\n",
        dir_att, dir_cts, dir_tmo, dir_rx, tx_fail);
    let bus_tmo = unsafe { crate::core1::BUS_IDLE_TIMEOUTS };
    let stall_us = (crate::core1::timer_us() as u32)
        .wrapping_sub(crate::core1::heartbeat_us());
    let _ = write!(s, "Core1: heartbeat {}us ago, bus_idle_tmo={}\r\n", stall_us, bus_tmo);

    // InkTalk stack status: address, heap.
    let addr = crate::stack_task::our_address();
    match addr {
        Some(a) => {
            let _ = write!(s, "Stack: node {}.{}\r\n", a.network_number, a.node_number);
        }
        None => {
            let _ = write!(s, "Stack: acquiring address\r\n");
        }
    }
    let heap_used = crate::HEAP.used();
    let heap_free = crate::HEAP.free();
    let heap_hw = crate::led::HEAP_HIGH_WATER.load(Ordering::Relaxed);
    let _ = write!(s, "Heap: used={} free={} high_water={}\r\n", heap_used, heap_free, heap_hw);
    // Canary words still intact at the bottom of core 0's stack. Anything
    // below the full count means the stack came within that many bytes of
    // overwriting .uninit and .bss.
    let canary = crate::stack_canary_free_words();
    let _ = write!(
        s,
        "Stack: canary {}/1024 words clear{}\r\n",
        canary,
        if canary == 1024 { "" } else { "  *** STACK CAME CLOSE ***" },
    );
    let (ptx, prx, perr) = crate::printer::counters();
    let _ = write!(
        s,
        "Printer: tx_free={} printer={} gate={} gp18={}\r\n",
        crate::printer::tx_free(),
        // From UARTFR.CTS, which is what the transmitter acts on.
        if crate::printer::handshake_high() { "READY" } else { "BUSY" },
        if crate::printer::handshake_gating() { "on" } else { "off" },
        // The raw SIO bit, which INOVER inverts: expect the opposite of the
        // voltage you measure on the pin.
        crate::printer::handshake_pad() as u8,
    );
    // Bytes the UART has accepted but not got rid of. With gate=on and
    // printer=BUSY this is what proves the hold-off is real: tx_free goes
    // back to 4096 either way, because that only tracks the driver ring.
    let _ = write!(
        s,
        "Printer: uart_tx={}\r\n",
        if crate::printer::tx_in_flight() { "HOLDING" } else { "drained" },
    );
    // GP29 is the UART RX pin. Idle mark is high; a stuck-low line means
    // the transceiver or the wire is holding a break, not that the printer
    // is quiet.
    let rx_line = (gpio_in >> 29) & 1;
    // DE (GP26) and /RE (GP27) read back from the pads, not from what we
    // believe we wrote: the receiver is only enabled while /RE is low, and
    // a pad that never took the drive would look exactly like a silent
    // printer. U4 hard-grounds the same pin on the LocalTalk side.
    let de = (gpio_in >> 26) & 1;
    let re = (gpio_in >> 27) & 1;
    let _ = write!(
        s,
        "Printer: tx={}B rx={}B rx_err={} rx_line={} trace={}\r\n",
        ptx,
        prx,
        perr,
        if rx_line == 1 { "HIGH(idle)" } else { "LOW(break?)" },
        if crate::printer::trace() { "on" } else { "off" },
    );
    let _ = write!(
        s,
        "Printer: DE={} /RE={} ({})\r\n",
        de,
        re,
        match (de, re) {
            (1, 0) => "driver+receiver enabled",
            (1, _) => "RECEIVER DISABLED",
            (_, 0) => "DRIVER DISABLED",
            _ => "BOTH DISABLED",
        },
    );
    if crate::identify::enabled() {
        let found = crate::identify::found();
        let _ = match &found {
            crate::identify::Found::Pending => write!(s, "Printer: model=identifying\r\n"),
            crate::identify::Found::Silent => write!(s, "Printer: model=no answer ('q' retries)\r\n"),
            crate::identify::Found::Printer { .. } => write!(s, "Printer: model={}\r\n", found.model()),
        };
    }

    s
}

fn classify(e: EndpointError) -> defmt::Str {
    match e {
        EndpointError::BufferOverflow => defmt::intern!("buffer overflow"),
        EndpointError::Disabled => defmt::intern!("endpoint disabled"),
    }
}
