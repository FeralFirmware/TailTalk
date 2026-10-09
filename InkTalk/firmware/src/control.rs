//! The control channel. This is an ADSP listener registered as
//! `<name>:InkTalk@*` that speaks the protocol from the `inkproto` crate, so
//! a Mac on the network can check our status and change our settings.
//!
//! We only serve one client at a time. The listener will hold a few more
//! connections open until the current one finishes and closes anything past
//! that. A client that goes quiet for [`IDLE_TIMEOUT`] gets dropped, so a Mac
//! that crashes mid-session can't tie the device up.
//!
//! Each frame is one ADSP message, and each reply goes back as one.
//!
//! Changes are applied and saved as soon as they arrive. A new name gets
//! registered from here using the printer's [`PrinterName`] handle, without
//! needing the printer task at all. A new role or baud rate needs a restart,
//! which we do by ourselves after sending the reply.
//!
//! The control name always follows the printer's name. Renames made here
//! update both at once, and if a printing client renames the printer (like
//! the Chooser does) the printer task tells us through [`NAME_CHANGED`].

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_futures::select::{Either, Either3, select, select3};
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use inkproto::{FrameWriter, Header, Items, Overflow, cmd, err, tag};
use tailtalk_net::adsp::{AdspListener, AdspStream, MessageError};
use tailtalk_net::printer::PrinterName;
use tailtalk_net::{EntityName, Net};

use crate::config::{self, Config, Role};
use crate::core1::SharedState;
use crate::stack_task::InkTalk;
use crate::{identify, printer, stack_task, tt_log};

/// The printer's name, set by the printer task once it has registered.
pub static PRINTER_NAME: OnceLock<PrinterName<'static, InkTalk>> = OnceLock::new();

/// A new name a printing client gave the printer. It's already registered
/// by the time we hear about it.
pub static NAME_CHANGED: Signal<ThreadModeRawMutex, heapless::String<31>> = Signal::new();

/// Set by the printer task between a job's start and its end.
pub static JOB_ACTIVE: AtomicBool = AtomicBool::new(false);

const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long a reboot waits for the client to acknowledge its reply.
const REBOOT_FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

const BUILD_ID: &str = env!("BUILD_ID");

// The wire's role numbers are the config's.
const _: () = assert!(Role::StyleWriter as u16 == inkproto::role::STYLEWRITER);
const _: () = assert!(Role::ImageWriter as u16 == inkproto::role::IMAGEWRITER);

/// What was loaded at boot, to tell whether a change needs a restart.
pub struct Running {
    pub role: Role,
    pub baud: u32,
}

/// Request and reply buffers. These are static so the task doesn't carry
/// an extra 2 KB around.
static mut RX: [u8; inkproto::MAX_FRAME_LEN] = [0; inkproto::MAX_FRAME_LEN];
static mut OUT: [u8; inkproto::MAX_FRAME_LEN] = [0; inkproto::MAX_FRAME_LEN];

#[embassy_executor::task]
pub async fn run(shared: &'static SharedState, net: Net<'static, InkTalk>, running: Running) -> ! {
    // SAFETY: this task is the only user of the buffers, and it is spawned
    // once.
    let (rx, out) = unsafe { (&mut *core::ptr::addr_of_mut!(RX), &mut *core::ptr::addr_of_mut!(OUT)) };

    let listener = defmt::unwrap!(AdspListener::bind(net, None).ok());
    let printer_name = *PRINTER_NAME.get().await;
    let mut ctx = Ctx {
        shared,
        running,
        printer_name,
        reg: Registration {
            net,
            socket: listener.socket(),
            entity: None,
            name: heapless::String::new(),
        },
    };
    ctx.reg.follow(&printer_name.get().unwrap_or_default());

    loop {
        match select(listener.accept(), NAME_CHANGED.wait()).await {
            Either::First(stream) => {
                let r = stream.remote();
                tt_log!("CONTROL: open from {}.{}:{}", r.network_number, r.node_number, r.socket_number);
                serve(&stream, &mut ctx, rx, out).await;
                tt_log!("CONTROL: closed");
            }
            Either::Second(name) => ctx.reg.follow(&name),
        }
    }
}

/// Everything a command might need.
struct Ctx {
    shared: &'static SharedState,
    running: Running,
    printer_name: PrinterName<'static, InkTalk>,
    reg: Registration,
}

/// Answer one client until it closes the connection, goes idle or sends us
/// a frame too long to read.
async fn serve(stream: &AdspStream<'static, InkTalk>, ctx: &mut Ctx, rx: &mut [u8], out: &mut [u8]) {
    loop {
        // All three of these are cancel safe, so it doesn't matter which one
        // loses the race.
        let len = match select3(
            stream.read_message(rx),
            Timer::after(IDLE_TIMEOUT),
            NAME_CHANGED.wait(),
        )
        .await
        {
            Either3::First(Ok(len)) => len,
            Either3::First(Err(MessageError::Closed)) => return,
            // It was skipped whole, but we can't answer it without its seq.
            Either3::First(Err(MessageError::TooLong)) => {
                tt_log!("CONTROL: frame over {} bytes, closing", rx.len());
                return;
            }
            Either3::Second(()) => {
                tt_log!("CONTROL: idle, closing");
                return;
            }
            Either3::Third(name) => {
                ctx.reg.follow(&name);
                continue;
            }
        };
        let (len, reboot) = handle(&rx[..len], out, ctx).await;
        // Sent as one message so the end-of-message flag goes out on the
        // reply's last packet, instead of in an extra empty packet.
        if stream.write_message(&out[..len]).await.is_err() {
            return;
        }
        if reboot {
            reboot_after_flush(stream).await;
        }
    }
}

/// Build the reply to `frame` in `out`. Returns the reply length, and whether
/// we should reboot once it has been sent.
async fn handle(frame: &[u8], out: &mut [u8], ctx: &mut Ctx) -> (usize, bool) {
    // A frame too short for a header still gets an answer: BAD_FRAME, from
    // the items check below, with nothing to echo.
    let header = Header::parse(frame).unwrap_or(Header {
        seq: 0,
        command: 0,
        result: 0,
    });
    let Ok(mut w) = FrameWriter::new(out, header.seq, header.command) else {
        return (0, false);
    };
    let mut reboot = false;
    let result = match Items::of_frame(frame) {
        Err(_) => Ok(err::BAD_FRAME),
        Ok(items) => match header.command {
            cmd::HELLO => hello(&mut w).map(|()| err::NO_ERR),
            cmd::INFO => info(&mut w, ctx).await.map(|()| err::NO_ERR),
            cmd::SET_CONFIG => set_config(&mut w, items, ctx, &mut reboot).await,
            cmd::REBOOT if JOB_ACTIVE.load(Ordering::Relaxed) => Ok(err::BUSY),
            cmd::REBOOT => {
                reboot = true;
                w.boolean(tag::REBOOTING, true).map(|()| err::NO_ERR)
            }
            _ => Ok(err::UNIMPLEMENTED),
        },
    };
    let result = result.unwrap_or_else(|Overflow| {
        tt_log!("CONTROL: reply to {:08X} overflowed", header.command);
        err::INTERNAL
    });
    (w.finish(result).len(), reboot)
}

fn hello(w: &mut FrameWriter<'_>) -> Result<(), Overflow> {
    w.u16(tag::PROTOCOL, inkproto::PROTOCOL_VERSION)?;
    let id = BUILD_ID.as_bytes();
    w.pstr(tag::FIRMWARE, &id[..id.len().min(31)])?;
    w.u16(tag::MAX_FRAME, inkproto::MAX_FRAME_LEN as u16)
}

async fn info(w: &mut FrameWriter<'_>, ctx: &Ctx) -> Result<(), Overflow> {
    let live = ctx.printer_name.get().unwrap_or_default();
    let cfg = config::ACTIVE.lock().await.clone();
    if let Some(cfg) = cfg {
        w.pstr(tag::NAME, cfg.name.as_bytes())?;
        w.u16(tag::ROLE, cfg.role as u16)?;
        w.u32(tag::BAUD, cfg.baud)?;
        let pending = needs_restart(&cfg, &ctx.running) || cfg.name.as_str() != live;
        w.boolean(tag::REBOOT_NEEDED, pending)?;
    }
    w.pstr(tag::LIVE_NAME, live.as_bytes())?;
    w.boolean(tag::JOB_ACTIVE, JOB_ACTIVE.load(Ordering::Relaxed))?;
    w.boolean(tag::PRINTER_READY, printer::handshake_high())?;
    w.u32(tag::UPTIME, Instant::now().as_secs() as u32)?;
    if let Some(a) = stack_task::our_address() {
        let [hi, lo] = a.network_number.to_be_bytes();
        w.item(tag::ADDRESS, &[hi, lo, a.node_number, 0])?;
    }
    let (tx, rx, _) = printer::counters();
    w.u32(tag::PRINTER_TX, tx)?;
    w.u32(tag::PRINTER_RX, rx)?;
    if identify::enabled() {
        let found = identify::found();
        if !matches!(found, identify::Found::Pending) {
            w.pstr(tag::PRINTER_MODEL, found.model().as_bytes())?;
        }
    }
    Ok(())
}

/// Apply every item or none of them, then save. If an item can't be used we
/// name it in the reply and leave everything as it was.
async fn set_config(w: &mut FrameWriter<'_>, items: Items<'_>, ctx: &mut Ctx, reboot: &mut bool) -> Result<i16, Overflow> {
    // This is only empty for a moment after boot, before the config task has
    // run.
    let Some(mut cfg) = config::ACTIVE.lock().await.clone() else {
        return Ok(err::BUSY);
    };
    let mut new_name = None;
    for item in items.iter() {
        let usable = match item.tag {
            tag::NAME => {
                new_name = item.pstr().and_then(name_from_wire);
                new_name.is_some()
            }
            tag::ROLE => match item.u16().and_then(|r| Role::from_u8(u8::try_from(r).ok()?)) {
                Some(role) => {
                    cfg.role = role;
                    true
                }
                None => false,
            },
            tag::BAUD => match item.u32().filter(|b| config::BAUD_RANGE.contains(b)) {
                Some(baud) => {
                    cfg.baud = baud;
                    true
                }
                None => false,
            },
            other => return refuse(w, err::UNKNOWN_TAG, other),
        };
        if !usable {
            return refuse(w, err::PARAM, item.tag);
        }
    }

    // Restarting in the middle of a job would cut the page off.
    let restart = needs_restart(&cfg, &ctx.running);
    if restart && JOB_ACTIVE.load(Ordering::Relaxed) {
        return Ok(err::BUSY);
    }

    if let Some(name) = new_name {
        if ctx.printer_name.get().as_deref() != Some(name.as_str()) {
            if let Err(e) = ctx.printer_name.set(&name) {
                tt_log!("CONTROL: cannot register {}: {:?}", name.as_str(), e);
                return refuse(w, err::PARAM, tag::NAME);
            }
            ctx.reg.follow(&name);
        }
        cfg.name = name;
    }

    *config::ACTIVE.lock().await = Some(cfg.clone());
    if let Err(e) = config::save(ctx.shared, &cfg).await {
        tt_log!("CONTROL: save failed: {}", e);
        return Ok(err::FLASH);
    }
    tt_log!(
        "CONTROL: config saved, role={} name={} baud={}",
        cfg.role.name(),
        cfg.name.as_str(),
        cfg.baud
    );
    *reboot = restart;
    w.boolean(tag::REBOOTING, restart)?;
    Ok(err::NO_ERR)
}

/// An error reply that names the item we refused.
fn refuse(w: &mut FrameWriter<'_>, code: i16, item: inkproto::OSType) -> Result<i16, Overflow> {
    w.u32(tag::ERROR_TAG, item)?;
    Ok(code)
}

/// Reset once the client has our reply, or has had long enough to get it.
async fn reboot_after_flush(stream: &AdspStream<'static, InkTalk>) -> ! {
    tt_log!("CONTROL: rebooting at the client's request");
    let _ = with_timeout(REBOOT_FLUSH_TIMEOUT, stream.flush_data()).await;
    // Give the log line time to make it out the debug port.
    Timer::after_millis(50).await;
    cortex_m::peripheral::SCB::sys_reset();
}

/// Whether `cfg` changes anything from what was loaded at boot that needs a
/// restart to take effect.
fn needs_restart(cfg: &Config, running: &Running) -> bool {
    cfg.role != running.role || cfg.baud != running.baud
}

/// A name from the wire. Names on the wire are MacRoman, but until we have a
/// MacRoman table we only accept the ASCII half of it, the same as we do for
/// a printing client's rename.
fn name_from_wire(chars: &[u8]) -> Option<heapless::String<31>> {
    if !chars.iter().all(|c| (0x20..0x7F).contains(c)) {
        return None;
    }
    config::parse_name(core::str::from_utf8(chars).ok()?)
}

/// Our control entity, which we keep in step with the printer's name.
struct Registration {
    net: Net<'static, InkTalk>,
    socket: u8,
    entity: Option<EntityName>,
    name: heapless::String<31>,
}

impl Registration {
    fn follow(&mut self, name: &str) {
        if self.entity.is_some() && self.name.as_str() == name {
            return;
        }
        let Some(new) = entity_name(name) else {
            tt_log!("CONTROL: cannot register {}", name);
            return;
        };
        if let Some(old) = &self.entity {
            self.net.nbp_unregister(old, self.socket);
        }
        if self.net.nbp_register(new.clone(), self.socket).is_ok() {
            tt_log!("CONTROL: registered {}:{}", name, inkproto::NBP_TYPE);
            self.entity = Some(new);
            if let Ok(name) = heapless::String::try_from(name) {
                self.name = name;
            }
        } else if let Some(old) = &self.entity {
            // Better to keep answering under the old name than to vanish.
            let _ = self.net.nbp_register(old.clone(), self.socket);
            tt_log!("CONTROL: cannot register {}, keeping the old name", name);
        }
    }
}

fn entity_name(name: &str) -> Option<EntityName> {
    let mut s = heapless::String::<64>::new();
    core::fmt::Write::write_fmt(&mut s, format_args!("{}:{}@*", name, inkproto::NBP_TYPE)).ok()?;
    EntityName::try_from(s.as_str()).ok()
}
