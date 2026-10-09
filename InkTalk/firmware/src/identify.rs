//! Asking the attached StyleWriter which model it is.
//!
//! The sequence is lpstyl's `printerSetup()`, and close to what Apple's
//! EtherTalk adapter does at power-up: reset, wait for a ready status, send
//! `?`, and ask a Color StyleWriter for its submodel with `p`. The reset is not optional: an original StyleWriter left idle ignores
//! `?` until it has been reset.
//!
//! The answer is for people, not for the protocol: it is logged, shown by
//! `s`, and reported in the control protocol's INFO reply. The printer stays
//! registered as a Color StyleWriter 2400 whatever it turns out to be.
//!
//! The printer task runs this once at boot, before it starts serving, and
//! again whenever [`REPROBE`] is signalled with no job in progress. It owns
//! the printer port's receive half, so it is the only task that can read
//! the replies.

use core::cell::RefCell;

use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::{Read, Write};
use portable_atomic::{AtomicBool, Ordering};
use tailtalk_core::stylewriter as sw;

use crate::printer::{self, PortRx, PortTx};
use crate::tt_log;

/// lpstyl sleeps this long after the reset before it asks anything.
const RESET_SETTLE: Duration = Duration::from_secs(2);

/// How long to keep polling for a ready status after the reset, and how
/// long to wait for the handshake line before sending anything at all.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a status query or a byte of the identify string may take. Every
/// reply seen on hardware so far arrived within a few milliseconds.
const REPLY_TIMEOUT: Duration = Duration::from_millis(250);

/// Between rounds of status queries while the printer is still busy.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Longest identify string kept. The known ones are at most four bytes.
pub type IdString = heapless::Vec<u8, 15>;

#[derive(Clone, Debug)]
pub enum Found {
    /// Not asked yet, or being asked right now.
    Pending,
    /// The printer never answered `?`.
    Silent,
    /// What the printer said to `?`, and to `p` if it is a Color StyleWriter
    /// and answered.
    Printer { id: IdString, submodel: Option<u8> },
}

impl Found {
    /// The model name, or for an identify string lpstyl does not know, the
    /// string itself. Empty unless a printer answered.
    pub fn model(&self) -> heapless::String<31> {
        let mut s = heapless::String::new();
        if let Found::Printer { id, submodel } = self {
            let _ = match sw::model_name(id, *submodel) {
                Some(name) => s.push_str(name),
                None => s.push_str(model_id(id).as_str()),
            };
        }
        s
    }
}

static FOUND: Mutex<ThreadModeRawMutex, RefCell<Found>> = Mutex::new(RefCell::new(Found::Pending));

/// Set by the printer task when it serves a StyleWriter, the only role this
/// applies to.
static ENABLED: AtomicBool = AtomicBool::new(false);

/// Ask the printer task to identify the printer again. It only acts on this
/// between jobs; one signalled mid-job runs when the job ends.
pub static REPROBE: Signal<ThreadModeRawMutex, ()> = Signal::new();

/// The latest answer.
pub fn found() -> Found {
    FOUND.lock(|f| f.borrow().clone())
}

/// Whether this board identifies its printer at all.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Identify the printer and record the answer. Resets the printer, so call
/// it only between jobs.
pub async fn run(tx: &mut PortTx, rx: &mut PortRx) {
    FOUND.lock(|f| *f.borrow_mut() = Found::Pending);
    tt_log!("PRINTER: identifying");
    let found = probe(tx, rx).await;
    match &found {
        Found::Printer { id, submodel } => {
            let model = found.model();
            match submodel {
                Some(p) => tt_log!("PRINTER: identified {} (id {} p={:02X})", model.as_str(), model_id(id).as_str(), p),
                None => tt_log!("PRINTER: identified {} (id {})", model.as_str(), model_id(id).as_str()),
            }
        }
        Found::Silent => tt_log!("PRINTER: no answer to identify ('q' retries)"),
        Found::Pending => {}
    }
    FOUND.lock(|f| *f.borrow_mut() = found);
}

async fn probe(tx: &mut PortTx, rx: &mut PortRx) -> Found {
    // With the handshake armed, a printer that is off holds the line busy
    // and everything sent would sit in the UART until it came on, then
    // arrive as a burst of stale queries. Do not start what cannot finish.
    let deadline = Instant::now() + READY_TIMEOUT;
    while printer::handshake_gating() && !printer::handshake_high() {
        if Instant::now() >= deadline {
            tt_log!("PRINTER: handshake BUSY, not identifying (is the printer on?)");
            return Found::Silent;
        }
        Timer::after(POLL_INTERVAL).await;
    }

    let _ = tx.write_all(sw::PRINTER_RESET).await;
    Timer::after(RESET_SETTLE).await;

    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        let status = query(tx, rx, sw::QUERY_STATUS).await;
        let error = query(tx, rx, sw::QUERY_ERROR).await;
        let buffer = query(tx, rx, sw::QUERY_BUFFER).await;
        if sw::ready_after_reset(status, error, buffer) {
            break;
        }
        if Instant::now() >= deadline {
            // lpstyl would wait forever here. Asking anyway costs a
            // quarter of a second and might still get an answer.
            tt_log!("PRINTER: no ready status after reset, asking anyway");
            break;
        }
        Timer::after(POLL_INTERVAL).await;
    }

    drain(rx).await;
    let _ = tx.write_all(&[sw::IDENTIFY]).await;
    let mut id = IdString::new();
    // lpstyl stops at the carriage return or at a read that times out, and
    // uses whatever it has; so do we.
    while let Some(b) = read_byte(rx).await {
        if b == 0x0D || id.push(b).is_err() {
            break;
        }
    }
    if id.is_empty() {
        return Found::Silent;
    }

    let submodel = if id.as_slice() == sw::COLOR_FAMILY {
        query(tx, rx, sw::QUERY_SUBMODEL).await
    } else {
        None
    };
    Found::Printer { id, submodel }
}

/// Send status query `q` and return its one-byte reply.
async fn query(tx: &mut PortTx, rx: &mut PortRx, q: u8) -> Option<u8> {
    drain(rx).await;
    let _ = tx.write_all(&sw::status_query(q)).await;
    read_byte(rx).await
}

async fn read_byte(rx: &mut PortRx) -> Option<u8> {
    let mut b = [0u8; 1];
    match with_timeout(REPLY_TIMEOUT, rx.read(&mut b)).await {
        Ok(Ok(1)) => Some(b[0]),
        _ => None,
    }
}

/// Throw away anything already received, so a late reply to one query is
/// not read as the answer to the next. `PortRx` is cancel safe, so the
/// timeout cannot lose a byte that matters.
async fn drain(rx: &mut PortRx) {
    let mut buf = [0u8; 16];
    while let Ok(Ok(n)) = with_timeout(Duration::from_millis(20), rx.read(&mut buf)).await {
        if n == 0 {
            break;
        }
    }
}

/// The identify string as text for the log.
fn model_id(id: &[u8]) -> heapless::String<15> {
    let mut s = heapless::String::new();
    for &b in id {
        let _ = s.push(if (0x20..0x7F).contains(&b) { b as char } else { '?' });
    }
    s
}
