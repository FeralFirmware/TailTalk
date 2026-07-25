//! The "Printer Tool" window: a master/detail view over the printers TailTalk
//! already knows how to talk to. The sidebar lists what NBP finds; selecting a
//! printer queries it and shows the result, plus whatever settings that family
//! lets us change:
//!
//!   * StyleWriter — rename, over the ADSP management socket (`sw-rename`).
//!   * LaserWriter — rename, default paper size and power-on startup page, as
//!     PostScript over PAP (`pap-print`).
//!
//! The server has to be running: we borrow its live `NbpHandle`/`DdpHandle`
//! rather than building a second stack, which couldn't reopen an in-use
//! TashTalk serial port.

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, Model, VecModel, Weak};
use tailtalk::{
    adsp::{Adsp, AdspAddress, AdspStream},
    atp::{Atp, AtpAddress},
    ddp::DdpHandle,
    pap::PapClient,
    stylewriter::StyleWriterSession,
};
use tailtalk_packets::nbp::EntityName;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

use crate::{InfoRow, PrinterHandles, PrinterRow, PrinterToolWindow};

/// One line of the information panel. The query tasks build these and hand them
/// to the event loop, which turns them into Slint [`InfoRow`]s — `SharedString`
/// isn't `Send`, so it can't cross that boundary.
struct Line {
    label: String,
    value: String,
    section: bool,
}

impl Line {
    /// A heading row; `value` is unused.
    fn section(label: &str) -> Line {
        Line { label: label.to_string(), value: String::new(), section: true }
    }

    fn field(label: &str, value: impl Into<String>) -> Line {
        Line { label: label.to_string(), value: value.into(), section: false }
    }
}

fn to_model(lines: Vec<Line>) -> slint::ModelRc<InfoRow> {
    let rows: Vec<InfoRow> = lines
        .into_iter()
        .map(|l| InfoRow {
            label: l.label.into(),
            value: l.value.into(),
            is_section: l.section,
        })
        .collect();
    Rc::new(VecModel::from(rows)).into()
}

/// The AppleTalk printer families the tool understands.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names, reason = "these are Apple's product names")]
enum PrinterKind {
    /// PostScript printer driven over PAP (NBP type "LaserWriter").
    LaserWriter,
    /// Color StyleWriter behind an EtherTalk adapter, driven over ADSP
    /// (NBP type "ColorStyleWriter2400AT").
    StyleWriter,
}

/// ADSP management socket — fixed at 129 on StyleWriter adapters (see `sw-rename`).
const SW_MGMT_SOCKET: u8 = 129;

/// Attention codes used by the StyleWriter name-change protocol.
const ATTN_GET_NAME: u16 = 0x0011;
const ATTN_SET_NAME: u16 = 0x0009;
const ATTN_COMMIT: u16 = 0x0012;

/// A printer found by [`discover`]; carries the real AppleTalk address that the
/// Slint model rows (indexed 1:1) can't hold.
#[derive(Clone)]
struct Discovered {
    name: String,
    kind: PrinterKind,
    net: u16,
    node: u8,
    socket: u8,
}

impl Discovered {
    /// The advertised print endpoint, as an ADSP address (StyleWriter).
    fn adsp_print_addr(&self) -> AdspAddress {
        AdspAddress {
            network_number: self.net,
            node_number: self.node,
            socket_number: self.socket,
        }
    }

    /// The fixed management endpoint used for renaming (StyleWriter).
    fn adsp_mgmt_addr(&self) -> AdspAddress {
        AdspAddress {
            network_number: self.net,
            node_number: self.node,
            socket_number: SW_MGMT_SOCKET,
        }
    }

    /// The advertised print endpoint, as an ATP address (LaserWriter).
    fn atp_addr(&self) -> AtpAddress {
        AtpAddress {
            network_number: self.net,
            node_number: self.node,
            socket_number: self.socket,
        }
    }

    fn row(&self) -> PrinterRow {
        PrinterRow {
            name: self.name.as_str().into(),
            kind: match self.kind {
                PrinterKind::LaserWriter => "LaserWriter (PostScript)".into(),
                PrinterKind::StyleWriter => "Color StyleWriter".into(),
            },
            address: format!("{}.{} socket {}", self.net, self.node, self.socket).into(),
            is_stylewriter: self.kind == PrinterKind::StyleWriter,
        }
    }
}

/// Paper sizes the tool can set on a LaserWriter (mirrors `pap-print`).
#[derive(Clone, Copy)]
enum PaperSize {
    Letter,
    A4,
    Legal,
    Executive,
    B5,
}

impl PaperSize {
    /// Index order must match the ComboBox model in `printer_tool.slint`.
    fn from_index(i: i32) -> PaperSize {
        match i {
            1 => PaperSize::A4,
            2 => PaperSize::Legal,
            3 => PaperSize::Executive,
            4 => PaperSize::B5,
            _ => PaperSize::Letter,
        }
    }

    fn points(self) -> (u32, u32) {
        match self {
            PaperSize::Letter => (612, 792),
            PaperSize::A4 => (595, 842),
            PaperSize::Legal => (612, 1008),
            PaperSize::Executive => (522, 756),
            PaperSize::B5 => (516, 729),
        }
    }

    fn label(self) -> &'static str {
        match self {
            PaperSize::Letter => "Letter",
            PaperSize::A4 => "A4",
            PaperSize::Legal => "Legal",
            PaperSize::Executive => "Executive",
            PaperSize::B5 => "B5",
        }
    }
}

/// Map a PostScript "w h" page-size string to the closest ComboBox index;
/// unknown sizes fall back to Letter (0).
fn pts_to_paper_index(pts: &str) -> i32 {
    let mut nums = pts.split_whitespace().filter_map(|s| s.parse::<f32>().ok());
    let (Some(w), Some(h)) = (nums.next(), nums.next()) else {
        return 0;
    };
    let known: &[(f32, f32, i32)] = &[
        (612.0, 792.0, 0),  // Letter
        (595.0, 842.0, 1),  // A4
        (612.0, 1008.0, 2), // Legal
        (522.0, 756.0, 3),  // Executive
        (516.0, 729.0, 4),  // B5
    ];
    for &(pw, ph, idx) in known {
        if (w - pw).abs() < 5.0 && (h - ph).abs() < 5.0 {
            return idx;
        }
    }
    0
}

/// What a query produced.
struct Queried {
    lines: Vec<Line>,
    /// LaserWriter only: current values for the editable controls.
    settings: Option<LaserSettings>,
}

struct LaserSettings {
    paper_index: i32,
    startup_enabled: bool,
    printer_name: String,
}

/// Reject names AppleTalk can't carry: `:`, `@` and `*` are NBP entity-name
/// delimiters. `max` is the family's own length limit — 31 for the StyleWriter's
/// Pascal-string rename, 32 for the LaserWriter's `PrinterName`.
fn validate_name(name: &str, max: usize) -> anyhow::Result<()> {
    if name.is_empty() || name.len() > max {
        anyhow::bail!("name must be 1–{max} characters (got {})", name.len());
    }
    if name.contains([':', '@', '*']) {
        anyhow::bail!("name cannot contain ':', '@', or '*'");
    }
    Ok(())
}

/// Escape a string for use inside a PostScript `(...)` literal.
fn ps_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '(' | ')') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ── Async operations (reuse the existing protocol code) ───────────────────────

/// Discover LaserWriters and Color StyleWriters — the same batched NBP lookup
/// the IPP bridge performs.
async fn discover(handles: &PrinterHandles) -> anyhow::Result<Vec<Discovered>> {
    const PATTERNS: [(PrinterKind, &str); 2] = [
        (PrinterKind::LaserWriter, "=:LaserWriter@*"),
        (PrinterKind::StyleWriter, "=:ColorStyleWriter2400AT@*"),
    ];

    // Our own address on each transport, so registrations belonging to this
    // stack (chiefly the built-in LaserWriter emulator) can be dropped below.
    let local: Vec<(u16, u8)> = handles
        .local_addrs
        .iter()
        .filter_map(|w| w.borrow().map(|a| (a.network_number, a.node_number)))
        .collect();

    let names = PATTERNS
        .iter()
        .map(|(_, pattern)| {
            EntityName::try_from(*pattern)
                .map_err(|e| anyhow::anyhow!("bad entity name '{pattern}': {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut found = Vec::new();
    for ((kind, _), tuples) in PATTERNS.iter().zip(handles.nbp.lookup_many(names).await?) {
        for t in tuples {
            if t.entity_name.object.is_empty() {
                continue;
            }
            if local.contains(&(t.network_number, t.node_id)) {
                tracing::debug!(
                    "Printer Tool: skipping own registration \"{}\" at {}.{}",
                    t.entity_name.object,
                    t.network_number,
                    t.node_id
                );
                continue;
            }
            found.push(Discovered {
                name: t.entity_name.object,
                kind: *kind,
                net: t.network_number,
                node: t.node_id,
                socket: t.socket_number,
            });
        }
    }
    Ok(found)
}

/// Query a StyleWriter's identity over a short-lived ADSP session (no page fed).
async fn query_stylewriter(ddp: &DdpHandle, addr: AdspAddress) -> anyhow::Result<Queried> {
    let mut session = StyleWriterSession::connect(ddp, addr, "TailTalk").await?;
    let info = session.query_info().await;
    let _ = session.abort().await;
    let info = info?;

    /// Render a raw status byte as hex, or a placeholder when unanswered.
    fn raw(b: Option<u8>) -> String {
        b.map_or_else(|| "no response".to_string(), |v| format!("0x{v:02X}"))
    }

    Ok(Queried {
        lines: vec![
            Line::section("Status"),
            Line::field("Condition", info.error_text()),
            Line::field(
                "Buffer",
                match info.buffer_idle() {
                    Some(true) => format!("Idle ({})", raw(info.status_buffer)),
                    Some(false) => format!("Busy — data draining ({})", raw(info.status_buffer)),
                    None => raw(info.status_buffer),
                },
            ),
            Line::section("Hardware"),
            Line::field("Model", info.model_name()),
            Line::field("Cartridge", info.cartridge_text()),
            Line::field(
                "Colour printing",
                if info.color_capable() {
                    "Yes"
                } else if info.identity == "CS" {
                    "No — black cartridge installed"
                } else {
                    "No — this model is mono only"
                },
            ),
            // The printer's error vocabulary was never fully reverse-engineered
            // (lpstyl documents three codes for '2' and nothing at all for '1'),
            // so show the raw bytes rather than decode them into a guess.
            Line::section("Raw protocol replies"),
            Line::field(
                "Identity  '?'",
                if info.identity.is_empty() { "(empty)" } else { &info.identity },
            ),
            Line::field("Submodel  'p'", raw(info.submodel)),
            Line::field("Config    'H'", raw(info.config_raw)),
            Line::field("Status    '1'", raw(info.status_general)),
            Line::field("Status    '2'", raw(info.status_error)),
            Line::field("Buffer    'B'", raw(info.status_buffer)),
        ],
        settings: None,
    })
}

/// Send one attention command and check the printer's two-byte acknowledgement.
async fn attention(stream: &mut AdspStream, code: u16, payload: &[u8]) -> anyhow::Result<()> {
    stream.send_attention(code, payload).await?;
    let mut resp = [0u8; 2];
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for reply to 0x{code:04X}"))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected reply to 0x{code:04X}: {resp:02X?}");
    }
    Ok(())
}

/// Rename a StyleWriter via its ADSP management socket (the `sw-rename` flow).
async fn rename_stylewriter(
    ddp: &DdpHandle,
    mgmt_addr: AdspAddress,
    new_name: &str,
) -> anyhow::Result<String> {
    validate_name(new_name, 31)?;

    let mut stream = timeout(Duration::from_secs(10), Adsp::connect(ddp, mgmt_addr))
        .await
        .map_err(|_| anyhow::anyhow!("ADSP connect timed out — is socket {SW_MGMT_SOCKET} open?"))??;

    // Pascal string: length byte followed by the name bytes.
    let mut pascal = Vec::with_capacity(1 + new_name.len());
    pascal.push(new_name.len() as u8);
    pascal.extend_from_slice(new_name.as_bytes());

    attention(&mut stream, ATTN_GET_NAME, &[0x00]).await?;
    attention(&mut stream, ATTN_SET_NAME, &pascal).await?;
    attention(&mut stream, ATTN_COMMIT, &[0x00]).await?;
    stream.close().await?;

    Ok(format!(
        "Renamed to \"{new_name}\". Click Refresh in a moment to confirm re-registration."
    ))
}

/// Run a PostScript job over PAP and return the printer's response lines, with
/// PS status messages (`%%[ … ]%%`) filtered out.
async fn run_ps_job(ddp: &DdpHandle, addr: AtpAddress, job: &str) -> anyhow::Result<Vec<String>> {
    let (_, req, resp) = Atp::spawn(ddp, None).await;
    let mut client = PapClient::new(req, resp);
    client.connect(addr).await?;
    client.print_stream(Cursor::new(job.as_bytes())).await?;

    // A job that only sets things up may say nothing back; that isn't an error.
    let bytes = match timeout(Duration::from_secs(15), client.read_response()).await {
        Ok(r) => r?,
        Err(_) => Vec::new(),
    };
    client.close().await?;

    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|l| !l.trim_start().starts_with("%%["))
        .map(str::to_string)
        .collect())
}

/// The properties [`query_laserwriter`] reports, in the order the printer prints
/// them: panel label, and the PostScript that emits the value.
const LASER_QUERIES: &[(&str, &str)] = &[
    ("Product", "statusdict /product get printval"),
    ("PS Version", "version printval"),
    ("Firmware Rev", "statusdict /revision get printval"),
    (
        "Resolution",
        "{ statusdict /resolution get } stopped \
         { currentpagedevice /HWResolution get 0 get } if printval",
    ),
    ("RAM", "statusdict begin ramsize end printval"),
    ("Page count", "statusdict begin pagecount end printval"),
    ("Page size (pts)", "currentpagedevice /PageSize get printval"),
    ("AppleTalk type", "statusdict /appletalktype get printval"),
    ("Input trays", "currentpagedevice /InputAttributes get length ="),
    (
        "Tray 0 paper (pts)",
        "currentpagedevice /InputAttributes get 0 get /PageSize get printval",
    ),
    ("Has manual feed", "currentpagedevice /ManualFeed known ="),
    ("Startup page", "statusdict begin dostartpage end printval"),
    ("Printer name", "40 string statusdict begin printername end printval"),
];

/// Assemble the query job. `printval` prints arrays space-separated on one line
/// and everything else via `=`, so each property answers with exactly one line;
/// every property is guarded so a printer missing one still answers the rest.
fn laser_query_job() -> String {
    let mut job = String::from(
        "%!PS-Adobe-3.0\n\
         %%EndComments\n\
         errordict /handleerror {} put\n\
         /printval {\n\
           dup type /arraytype eq {\n\
             { dup type /stringtype eq { print } { 20 string cvs print } ifelse ( ) print } forall\n\
             (\\n) print\n\
           } { = } ifelse\n\
         } def\n",
    );
    for (_, expr) in LASER_QUERIES {
        job.push_str(&format!("{{ {expr} }} stopped {{ (error) = }} if\n"));
    }
    job.push_str("flush\n%%EOF\n");
    job
}

/// Pretty-print `ramsize`'s byte count.
fn format_ram(value: &str) -> String {
    let Ok(bytes) = value.parse::<u64>() else {
        return value.to_string();
    };
    let mib = bytes as f64 / (1024.0 * 1024.0);
    if mib.fract() == 0.0 {
        format!("{} MiB", mib as u64)
    } else {
        format!("{mib:.1} MiB")
    }
}

/// Query a LaserWriter over PAP: its PAP status string plus the PostScript
/// Query Protocol capability dump.
async fn query_laserwriter(ddp: &DdpHandle, addr: AtpAddress) -> anyhow::Result<Queried> {
    let mut lines = vec![Line::section("Status")];

    // PAP status string first (short, cheap).
    let (_, req, _) = Atp::spawn(ddp, None).await;
    match PapClient::get_status(req, addr).await {
        Ok(status) => lines.push(Line::field("Condition", status)),
        Err(e) => lines.push(Line::field("Condition", format!("Unavailable: {e}"))),
    }
    lines.push(Line::section("Printer"));

    let replies = run_ps_job(ddp, addr, &laser_query_job()).await?;
    let reply = |i: usize| replies.get(i).map(|s| s.trim()).unwrap_or_default();

    for (i, (label, _)) in LASER_QUERIES.iter().enumerate() {
        let value = reply(i);
        let display = if value.is_empty() {
            "no response".to_string()
        } else if *label == "RAM" {
            format_ram(value)
        } else {
            value.to_string()
        };
        lines.push(Line::field(label, display));
    }

    let by_label = |name: &str| {
        LASER_QUERIES.iter().position(|(l, _)| *l == name).map(reply).unwrap_or_default()
    };

    Ok(Queried {
        lines,
        settings: Some(LaserSettings {
            paper_index: pts_to_paper_index(by_label("Tray 0 paper (pts)")),
            startup_enabled: by_label("Startup page") == "true",
            printer_name: by_label("Printer name").to_string(),
        }),
    })
}

/// Apply a LaserWriter's editable settings in one NVRAM-writing job: its
/// AppleTalk name, the default cassette paper size and the power-on startup
/// (test) page flag. `exitserver` (password 0) makes all three persist across
/// power cycles.
async fn save_laserwriter(
    ddp: &DdpHandle,
    addr: AtpAddress,
    size: PaperSize,
    startup: bool,
    name: &str,
) -> anyhow::Result<String> {
    validate_name(name, 32)?;
    let (w, h) = size.points();
    let escaped_name = ps_escape(name);
    let job = format!(
        "%!PS-Adobe-3.0\n\
         %%EndComments\n\
         serverdict begin 0 exitserver\n\
         << /PageSize [{w} {h}] /InputAttributes << 0 << /PageSize [{w} {h}] >> >> >> setpagedevice\n\
         statusdict begin {startup} setdostartpage end\n\
         statusdict begin ({escaped_name}) setprintername end\n\
         flush\n\
         %%EOF\n"
    );

    let output = run_ps_job(ddp, addr, &job).await?;
    let output: Vec<String> = output.into_iter().filter(|l| !l.trim().is_empty()).collect();

    let mut msg = format!(
        "Saved: name \"{name}\", default paper {} ({w}×{h} pts), startup page {}. \
         Click Refresh in a moment to confirm re-registration.",
        size.label(),
        if startup { "on" } else { "off" }
    );
    if !output.is_empty() {
        msg.push_str(&format!("\nPrinter responded:\n{}", output.join("\n")));
    }
    Ok(msg)
}

// ── Window wiring ─────────────────────────────────────────────────────────────

/// Open (or re-focus) the Printer Tool window. `handles` is the running stack's
/// shared handle store; `slot` keeps the window alive past the callback that
/// created it.
pub fn open(
    rt: &tokio::runtime::Handle,
    handles: Arc<Mutex<Option<PrinterHandles>>>,
    slot: Rc<RefCell<Option<PrinterToolWindow>>>,
) {
    if let Some(existing) = slot.borrow().as_ref() {
        let _ = existing.show();
        return;
    }

    let window = match PrinterToolWindow::new() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Printer Tool: failed to create window: {e}");
            return;
        }
    };

    // Discovered printers, kept 1:1 with the Slint model rows so a row index
    // maps back to a real AppleTalk address.
    let discovered: Arc<Mutex<Vec<Discovered>>> = Arc::new(Mutex::new(Vec::new()));

    // Bumped whenever the selection changes or the list is refreshed. Background
    // tasks capture the value they started with and drop their results if it no
    // longer matches, so a slow query can't overwrite a newer selection's panel.
    let generation: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // ── Refresh ──────────────────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let generation = generation.clone();
        window.on_refresh(move || {
            generation.fetch_add(1, Ordering::SeqCst);
            let Some(handles) = handles.lock().unwrap().clone() else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };
            begin_busy(&weak, "Discovering printers…");
            if let Some(w) = weak.upgrade() {
                w.set_selected(-1);
                w.set_detail_loaded(false);
            }
            let weak = weak.clone();
            let discovered = discovered.clone();
            rt.spawn(async move {
                let result = discover(&handles).await;
                slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    match result {
                        Ok(found) => {
                            let rows: Vec<PrinterRow> = found.iter().map(Discovered::row).collect();
                            let n = rows.len();
                            *discovered.lock().unwrap() = found;
                            w.set_printers(Rc::new(VecModel::from(rows)).into());
                            w.set_selected(-1);
                            w.set_status_text(if n == 0 {
                                "No printers found. Is one powered on and on the same network?"
                                    .into()
                            } else {
                                format!("Found {n} printer(s).").into()
                            });
                        }
                        Err(e) => w.set_status_text(format!("Discovery failed: {e}").into()),
                    }
                    w.set_busy(false);
                })
                .ok();
            });
        });
    }

    // ── Query (auto-fired when a printer is selected) ────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let generation = generation.clone();
        window.on_query(move |index| {
            let my_gen = generation.fetch_add(1, Ordering::SeqCst) + 1;
            let Some(printer) = discovered.lock().unwrap().get(index as usize).cloned() else {
                return;
            };
            let Some(ddp) = handles.lock().unwrap().as_ref().map(|h| h.ddp.clone()) else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };

            // Reset the detail pane and seed the name field from the NBP name;
            // a LaserWriter query refines it with the printer's own PrinterName.
            if let Some(w) = weak.upgrade() {
                w.set_detail_loaded(false);
                w.set_info_rows(to_model(Vec::new()));
                w.set_error_text("".into());
                w.set_edit_name(printer.name.as_str().into());
            }
            begin_busy(&weak, "Querying printer…");

            if printer.kind == PrinterKind::LaserWriter {
                poll_status(&rt, weak.clone(), ddp.clone(), printer.atp_addr(), &generation, my_gen);
            }

            let weak = weak.clone();
            let discovered = discovered.clone();
            let generation = generation.clone();
            rt.spawn(async move {
                let result = match printer.kind {
                    PrinterKind::StyleWriter => {
                        query_stylewriter(&ddp, printer.adsp_print_addr()).await
                    }
                    PrinterKind::LaserWriter => query_laserwriter(&ddp, printer.atp_addr()).await,
                };
                slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    if generation.load(Ordering::SeqCst) != my_gen {
                        return; // the selection moved on while we were querying
                    }
                    match result {
                        Ok(q) => {
                            w.set_info_rows(to_model(q.lines));
                            if let Some(s) = q.settings {
                                w.set_paper_index(s.paper_index);
                                w.set_startup_enabled(s.startup_enabled);
                                if !s.printer_name.is_empty() {
                                    w.set_edit_name(s.printer_name.as_str().into());
                                    rename_row(&w, &discovered, index as usize, &s.printer_name);
                                }
                            }
                            w.set_detail_loaded(true);
                            w.set_status_text("Ready.".into());
                        }
                        Err(e) => {
                            w.set_error_text(e.to_string().into());
                            w.set_status_text("Query failed.".into());
                        }
                    }
                    w.set_busy(false);
                })
                .ok();
            });
        });
    }

    // ── Save (kind-dependent) ────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        window.on_save(move |index| {
            let Some(w) = weak.upgrade() else { return };
            let Some(printer) = discovered.lock().unwrap().get(index as usize).cloned() else {
                return;
            };
            let Some(ddp) = handles.lock().unwrap().as_ref().map(|h| h.ddp.clone()) else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };
            begin_busy(&weak, "Saving…");
            let weak = weak.clone();
            let name = w.get_edit_name().to_string();
            match printer.kind {
                PrinterKind::StyleWriter => {
                    rt.spawn(async move {
                        let result =
                            rename_stylewriter(&ddp, printer.adsp_mgmt_addr(), &name).await;
                        finish_save(weak, result, None);
                    });
                }
                PrinterKind::LaserWriter => {
                    let size = PaperSize::from_index(w.get_paper_index());
                    let startup = w.get_startup_enabled();
                    rt.spawn(async move {
                        let addr = printer.atp_addr();
                        let result = save_laserwriter(&ddp, addr, size, startup, &name).await;
                        // Re-query on success so the panel reflects what stuck.
                        finish_save(weak, result, Some(index));
                    });
                }
            }
        });
    }

    if let Err(e) = window.show() {
        tracing::error!("Printer Tool: failed to show window: {e}");
        return;
    }

    window.invoke_refresh();
    *slot.borrow_mut() = Some(window);
}

/// Re-check a LaserWriter's PAP status every few seconds for as long as it stays
/// selected, so the Condition line doesn't sit stale between the much slower
/// PostScript queries.
fn poll_status(
    rt: &tokio::runtime::Handle,
    weak: Weak<PrinterToolWindow>,
    ddp: DdpHandle,
    addr: AtpAddress,
    generation: &Arc<AtomicU64>,
    my_gen: u64,
) {
    let generation = generation.clone();
    rt.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.tick().await; // the initial query already left a fresh status
        loop {
            ticker.tick().await;
            if generation.load(Ordering::SeqCst) != my_gen {
                return;
            }
            let (_, req, _) = Atp::spawn(&ddp, None).await;
            let status = PapClient::get_status(req, addr).await;

            let weak = weak.clone();
            let generation = generation.clone();
            let posted = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                if generation.load(Ordering::SeqCst) != my_gen {
                    return;
                }
                set_condition(&w, match status {
                    Ok(s) if !s.is_empty() => s,
                    Ok(_) => "No status string returned".to_string(),
                    Err(e) => format!("Unavailable: {e}"),
                });
            });
            if posted.is_err() {
                return; // the Slint event loop is gone — the app is shutting down
            }
        }
    });
}

/// Overwrite the info panel's Condition row in place.
fn set_condition(w: &PrinterToolWindow, text: String) {
    let model = w.get_info_rows();
    for i in 0..model.row_count() {
        let Some(mut row) = model.row_data(i) else { continue };
        if !row.is_section && row.label.as_str() == "Condition" {
            row.value = text.into();
            model.set_row_data(i, row);
            return;
        }
    }
}

/// Show the printer's real name in the sidebar row and our cached entry, so a
/// rename appears without waiting for the next NBP refresh.
fn rename_row(w: &PrinterToolWindow, discovered: &Mutex<Vec<Discovered>>, index: usize, name: &str) {
    if let Some(d) = discovered.lock().unwrap().get_mut(index) {
        d.name = name.to_string();
    }
    let model = w.get_printers();
    if let Some(mut row) = model.row_data(index)
        && row.name.as_str() != name
    {
        row.name = name.into();
        model.set_row_data(index, row);
    }
}

/// Flip the window into the busy state with a status message. Runs on the UI thread.
fn begin_busy(weak: &Weak<PrinterToolWindow>, status: &str) {
    if let Some(w) = weak.upgrade() {
        w.set_busy(true);
        w.set_status_text(status.into());
    }
}

/// Set only the status line (no busy toggle). Runs on the UI thread.
fn set_status(weak: &Weak<PrinterToolWindow>, status: &str) {
    if let Some(w) = weak.upgrade() {
        w.set_status_text(status.into());
    }
}

/// Marshal a Save result back to the window. On success, `requery` (if given)
/// re-runs the query for that row so the panel shows the persisted values —
/// unless the user has moved on to another printer in the meantime.
fn finish_save(weak: Weak<PrinterToolWindow>, result: anyhow::Result<String>, requery: Option<i32>) {
    slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_busy(false);
        match result {
            Ok(msg) => {
                w.set_status_text(msg.into());
                if requery == Some(w.get_selected()) {
                    w.invoke_query(w.get_selected());
                }
            }
            Err(e) => w.set_status_text(format!("Save failed: {e}").into()),
        }
    })
    .ok();
}
