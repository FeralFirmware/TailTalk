//! The "Printer Tool" window: an interactive master/detail shell over
//! TailTalk's existing printer machinery. The sidebar lists printers discovered
//! over NBP (the same lookups the IPP bridge uses); selecting one queries its
//! info and shows it on the right, along with editable settings and a Save
//! button that applies them:
//!   * StyleWriter → rename (the `sw-rename` ADSP management flow).
//!   * LaserWriter → default paper size + power-on startup page (PostScript
//!     over PAP, as `pap-print` does).
//!
//! It requires the AFP server to be running and reuses that stack's live
//! `NbpHandle` + `DdpHandle` rather than building a second stack (which would
//! fail to reopen an in-use TashTalk serial port).

use std::cell::RefCell;
use std::io::Cursor;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, SharedString, VecModel, Weak};
use tailtalk::{
    adsp::{Adsp, AdspAddress},
    atp::{Atp, AtpAddress},
    ddp::DdpHandle,
    pap::PapClient,
    stylewriter::StyleWriterSession,
};
use tailtalk_packets::nbp::EntityName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

use crate::{InfoRow, PrinterHandles, PrinterRow, PrinterToolWindow};

/// One line of the information panel, in plain Rust types.
///
/// The async query tasks build these and hand them to the event loop, which
/// converts them to the Slint [`InfoRow`]; Slint's `SharedString` isn't
/// something we want to move across the spawn boundary.
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
    /// A label/value row.
    fn field(label: &str, value: impl Into<String>) -> Line {
        Line { label: label.to_string(), value: value.into(), section: false }
    }
}

/// Convert query output into a model the window can display.
fn to_model(lines: Vec<Line>) -> slint::ModelRc<InfoRow> {
    let rows: Vec<InfoRow> = lines
        .into_iter()
        .map(|l| InfoRow {
            label: l.label.as_str().into(),
            value: l.value.as_str().into(),
            is_section: l.section,
        })
        .collect();
    Rc::new(VecModel::from(rows)).into()
}

/// The AppleTalk printer families the tool understands.
#[derive(Clone, Copy, PartialEq)]
enum PrinterKind {
    /// PostScript printer driven over PAP (NBP type "LaserWriter").
    LaserWriter,
    /// Color StyleWriter behind an EtherTalk adapter, driven over ADSP
    /// (NBP type "ColorStyleWriter2400AT").
    StyleWriter,
    /// Apple ImageWriter II driven over PAP (NBP type "ImageWriter"). No
    /// PostScript interpreter, so only a test page is offered — no query/save.
    ImageWriter,
}

/// ADSP management socket — fixed at 129 on StyleWriter adapters (see `sw-rename`).
const SW_MGMT_SOCKET: u8 = 129;

/// Attention command codes used by the StyleWriter name-change protocol.
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
    /// The advertised print endpoint viewed as an ADSP address (StyleWriter query).
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

    /// The advertised print endpoint viewed as an ATP address (LaserWriter).
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
                PrinterKind::ImageWriter => "ImageWriter (dot matrix)".into(),
            },
            address: format!("{}.{} socket {}", self.net, self.node, self.socket).into(),
            is_stylewriter: self.kind == PrinterKind::StyleWriter,
            is_imagewriter: self.kind == PrinterKind::ImageWriter,
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

/// Structured result of a LaserWriter query: the info panel's rows plus the
/// current values needed to seed the editable controls.
struct LaserInfo {
    lines: Vec<Line>,
    paper_index: i32,
    startup_enabled: bool,
}

// ── Async operations (reuse the existing protocol code) ───────────────────────

/// Discover LaserWriters, Color StyleWriters, and ImageWriters — the same
/// batched NBP lookup the IPP bridge performs.
async fn discover(handles: &PrinterHandles) -> anyhow::Result<Vec<Discovered>> {
    // Snapshot our own address on each transport, so registrations belonging to
    // this stack (the built-in LaserWriter emulator) can be dropped below.
    let local: Vec<(u16, u8)> = handles
        .local_addrs
        .iter()
        .filter_map(|w| w.borrow().map(|a| (a.network_number, a.node_number)))
        .collect();

    let patterns: [(PrinterKind, &str); 3] = [
        (PrinterKind::LaserWriter, "=:LaserWriter@*"),
        (PrinterKind::StyleWriter, "=:ColorStyleWriter2400AT@*"),
        (PrinterKind::ImageWriter, "=:ImageWriter@*"),
    ];

    let mut kinds = Vec::new();
    let mut names: Vec<EntityName> = Vec::new();
    for (kind, pattern) in patterns {
        let entity: EntityName = pattern
            .try_into()
            .map_err(|e| anyhow::anyhow!("bad entity name '{pattern}': {e}"))?;
        kinds.push(kind);
        names.push(entity);
    }

    let results = handles.nbp.lookup_many(names).await?;

    let mut found = Vec::new();
    for (kind, tuples) in kinds.into_iter().zip(results) {
        for t in tuples {
            if t.entity_name.object.is_empty() {
                continue;
            }
            // Us — the LaserWriter emulator answering our own lookup.
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
                name: t.entity_name.object.clone(),
                kind,
                net: t.network_number,
                node: t.node_id,
                socket: t.socket_number,
            });
        }
    }
    Ok(found)
}

/// Query an ImageWriter's PAP status string. There's no PostScript interpreter
/// to interrogate further, so this is the extent of what's queryable.
async fn query_imagewriter(ddp: &DdpHandle, addr: AtpAddress) -> anyhow::Result<Vec<Line>> {
    let (_, status_req, _) = Atp::spawn(ddp, None).await;
    let status = match PapClient::get_status(status_req, addr).await {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => "No status string returned".to_string(),
        Err(e) => format!("Unavailable: {e}"),
    };

    Ok(vec![
        Line::section("Status"),
        Line::field("Condition", status),
        Line::section("Printer"),
        Line::field("Protocol", "PAP (Printer Access Protocol)"),
        Line::field("Assumed model", "ImageWriter II"),
    ])
}

/// Render "Hello from TailTalk!" centered on a US Letter page with
/// Ghostscript's `iwhi` device (ImageWriter II, 160x144 dpi) and print it over
/// PAP. Mirrors `examples/iw-print`.
async fn print_test_page_imagewriter(ddp: &DdpHandle, addr: AtpAddress) -> anyhow::Result<String> {
    const JOB: &str = "%!PS-Adobe-2.0\n\
        %%Title: TailTalk ImageWriter Test Page\n\
        %%Creator: TailTalk Printer Tool\n\
        %%EndComments\n\
        /Courier findfont 24 scalefont setfont\n\
        /msg (Hello from TailTalk!) def\n\
        msg stringwidth pop 612 exch sub 2 div 396 moveto\n\
        msg show\n\
        showpage\n\
        %%EOF\n";

    let mut child = tokio::process::Command::new(crate::ipp_bridge::gs_command())
        .args([
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            "-sDEVICE=iwhi",
            "-sOutputFile=-",
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch Ghostscript: {e}"))?;

    let mut stdin = child.stdin.take().expect("stdin was piped");
    stdin.write_all(JOB.as_bytes()).await?;
    drop(stdin); // EOF tells Ghostscript the job is complete

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "Ghostscript exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if output.stdout.is_empty() {
        anyhow::bail!("Ghostscript produced no output");
    }

    let (_, req, resp) = Atp::spawn(ddp, None).await;
    let mut client = PapClient::new(req, resp);
    client.connect(addr).await?;
    client.chunk_size = Some(512);
    client.print_stream(Cursor::new(output.stdout)).await?;
    client.close().await?;

    Ok("Test page sent — the printer should eject a page shortly.".to_string())
}

/// Query a StyleWriter's identity over a short-lived ADSP session (no page fed).
async fn query_stylewriter(ddp: &DdpHandle, addr: AdspAddress) -> anyhow::Result<Vec<Line>> {
    let mut session = StyleWriterSession::connect(ddp, addr, "TailTalk").await?;
    let info = session.query_info().await;
    let _ = session.abort().await;
    let info = info?;

    /// Render a raw status byte as hex, or a placeholder when unanswered.
    fn raw(b: Option<u8>) -> String {
        b.map_or_else(|| "no response".to_string(), |v| format!("0x{v:02X}"))
    }

    Ok(vec![
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
        // so the raw bytes are shown rather than decoded into a guess.
        Line::section("Raw protocol replies"),
        Line::field("Identity  '?'", if info.identity.is_empty() { "(empty)".to_string() } else { info.identity.clone() }),
        Line::field("Submodel  'p'", raw(info.submodel)),
        Line::field("Config    'H'", raw(info.config_raw)),
        Line::field("Status    '1'", raw(info.status_general)),
        Line::field("Status    '2'", raw(info.status_error)),
        Line::field("Buffer    'B'", raw(info.status_buffer)),
    ])
}

/// Rename a StyleWriter via its ADSP management socket (the `sw-rename` flow).
async fn rename_stylewriter(
    ddp: &DdpHandle,
    mgmt_addr: AdspAddress,
    new_name: &str,
) -> anyhow::Result<String> {
    if new_name.is_empty() || new_name.len() > 31 {
        anyhow::bail!("name must be 1–31 characters (got {})", new_name.len());
    }

    let mut stream = timeout(Duration::from_secs(10), Adsp::connect(ddp, mgmt_addr))
        .await
        .map_err(|_| anyhow::anyhow!("ADSP connect timed out — is socket {SW_MGMT_SOCKET} open?"))??;

    let mut resp = [0u8; 2];

    // Init query.
    stream.send_attention(ATTN_GET_NAME, &[0x00]).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{ATTN_GET_NAME:04X}"))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{ATTN_GET_NAME:04X}: {resp:02X?}");
    }

    // Pascal string: length byte followed by the name bytes.
    let name_bytes = new_name.as_bytes();
    let mut pascal = Vec::with_capacity(1 + name_bytes.len());
    pascal.push(name_bytes.len() as u8);
    pascal.extend_from_slice(name_bytes);

    stream.send_attention(ATTN_SET_NAME, &pascal).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{ATTN_SET_NAME:04X}"))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{ATTN_SET_NAME:04X}: {resp:02X?}");
    }

    stream.send_attention(ATTN_COMMIT, &[0x00]).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{ATTN_COMMIT:04X}"))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{ATTN_COMMIT:04X}: {resp:02X?}");
    }

    stream.close().await?;
    Ok(format!(
        "Renamed to \"{new_name}\". Click Refresh in a moment to confirm re-registration."
    ))
}

/// Run a PostScript job over PAP and return the printer's response lines with
/// PS status messages (`%%[ … ]%%`) filtered out.
async fn run_ps_job(ddp: &DdpHandle, addr: AtpAddress, job: &str) -> anyhow::Result<Vec<String>> {
    let (_, req, resp) = Atp::spawn(ddp, None).await;
    let mut client = PapClient::new(req, resp);
    client.connect(addr).await?;
    client.print_stream(Cursor::new(job.as_bytes())).await?;

    let response_bytes = timeout(Duration::from_secs(15), client.read_response())
        .await
        .unwrap_or_else(|_| Ok(vec![]))?;
    client.close().await?;

    let response = String::from_utf8_lossy(&response_bytes);
    Ok(response
        .lines()
        .filter(|l| !l.trim_start().starts_with("%%["))
        .map(|l| l.to_string())
        .collect())
}

/// Query a LaserWriter over PAP: its PAP status string plus the PostScript
/// Query Protocol capability dump (extends `pap-print query` with the power-on
/// startup-page flag).
async fn query_laserwriter(ddp: &DdpHandle, addr: AtpAddress) -> anyhow::Result<LaserInfo> {
    let mut lines = vec![Line::section("Status")];

    // PAP status string first (short, cheap).
    let (_, status_req, _) = Atp::spawn(ddp, None).await;
    match PapClient::get_status(status_req, addr).await {
        Ok(status) => lines.push(Line::field("Condition", status)),
        Err(e) => lines.push(Line::field("Condition", format!("Unavailable: {e}"))),
    }
    lines.push(Line::section("Printer"));

    let labels = &[
        "Product", "PS Version", "Firmware Rev", "Resolution",
        "RAM (bytes)", "Page count", "Page size (pts)", "AppleTalk type",
        "Input trays", "Tray 0 paper (pts)", "Has manual feed", "Startup page",
    ];

    let job =
        "%!PS-Adobe-3.0\n\
         %%EndComments\n\
         errordict /handleerror {} put\n\
         /printval {\n\
           dup type /arraytype eq {\n\
             { dup type /stringtype eq { print } { 20 string cvs print } ifelse ( ) print } forall\n\
             (\\n) print\n\
           } { = } ifelse\n\
         } def\n\
         { statusdict /product get printval } stopped { (error) = } if\n\
         { version printval } stopped { (error) = } if\n\
         { statusdict /revision get printval } stopped { (error) = } if\n\
         { statusdict /resolution get printval } stopped { currentpagedevice /HWResolution get 0 get printval } if\n\
         { statusdict begin ramsize end printval } stopped { (error) = } if\n\
         { statusdict begin pagecount end printval } stopped { (error) = } if\n\
         { currentpagedevice /PageSize get printval } stopped { (error) = } if\n\
         { statusdict /appletalktype get printval } stopped { (error) = } if\n\
         { currentpagedevice /InputAttributes get length = } stopped { (error) = } if\n\
         { currentpagedevice /InputAttributes get 0 get /PageSize get printval } stopped { (error) = } if\n\
         { currentpagedevice /ManualFeed known = } stopped { (error) = } if\n\
         { statusdict /dostartpage get printval } stopped { (error) = } if\n\
         flush\n\
         %%EOF\n";

    let vals = run_ps_job(ddp, addr, job).await?;
    let mut vals = vals.into_iter();
    let mut collected: Vec<String> = Vec::new();
    for label in labels {
        let value = vals.next().unwrap_or_default();
        let value = value.trim();
        lines.push(Line::field(
            label,
            if value.is_empty() { "no response" } else { value },
        ));
        collected.push(value.to_string());
    }

    // Index 9 = Tray 0 paper size; index 11 = startup-page flag.
    let paper_index = collected.get(9).map(|s| pts_to_paper_index(s)).unwrap_or(0);
    let startup_enabled = collected.get(11).map(|s| s == "true").unwrap_or(false);

    Ok(LaserInfo { lines, paper_index, startup_enabled })
}

/// Apply a LaserWriter's editable settings in one NVRAM-writing job: the
/// default cassette paper size and the power-on startup (test) page flag.
/// `exitserver` (password 0) makes both persist across power cycles.
async fn save_laserwriter(
    ddp: &DdpHandle,
    addr: AtpAddress,
    size: PaperSize,
    startup: bool,
) -> anyhow::Result<String> {
    let (w, h) = size.points();
    let job = format!(
        "%!PS-Adobe-3.0\n\
         %%EndComments\n\
         serverdict begin 0 exitserver\n\
         << /PageSize [{w} {h}] /InputAttributes << 0 << /PageSize [{w} {h}] >> >> >> setpagedevice\n\
         statusdict begin {startup} setdostartpage end\n\
         flush\n\
         %%EOF\n"
    );

    let output = run_ps_job(ddp, addr, &job).await?;
    let output: Vec<String> = output.into_iter().filter(|l| !l.trim().is_empty()).collect();

    let base = format!(
        "Saved: default paper {} ({}×{} pts), startup page {}.",
        size.label(),
        w,
        h,
        if startup { "on" } else { "off" }
    );
    if output.is_empty() {
        Ok(base)
    } else {
        Ok(format!("{base}\nPrinter responded:\n{}", output.join("\n")))
    }
}

// ── Window wiring ─────────────────────────────────────────────────────────────

/// Open (or re-focus) the Printer Tool window. `handles` is the running stack's
/// shared handle store; `slot` keeps the window alive across the callback that
/// created it. Both are cheap to clone and shared with the spawned tasks.
pub fn open(
    rt: &tokio::runtime::Handle,
    handles: Arc<Mutex<Option<PrinterHandles>>>,
    slot: Rc<RefCell<Option<PrinterToolWindow>>>,
) {
    // Already open — just bring it forward.
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

    // Shared list of discovered printers, kept 1:1 with the Slint model rows so
    // a row index maps back to a real AppleTalk address. `Arc<Mutex<>>` (not Rc)
    // so it can cross the spawn/event-loop Send boundary in the refresh task.
    let discovered: Arc<Mutex<Vec<Discovered>>> = Arc::new(Mutex::new(Vec::new()));

    // ── Refresh ──────────────────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        window.on_refresh(move || {
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
                            let new_rows: Vec<PrinterRow> = found.iter().map(|d| d.row()).collect();
                            let n = new_rows.len();
                            *discovered.lock().unwrap() = found;
                            w.set_printers(Rc::new(VecModel::from(new_rows)).into());
                            w.set_selected(-1);
                            w.set_status_text(
                                if n == 0 {
                                    "No printers found. Is one powered on and on the same network?".into()
                                } else {
                                    format!("Found {n} printer(s).").into()
                                },
                            );
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
        window.on_query(move |index| {
            let Some(printer) = discovered.lock().unwrap().get(index as usize).cloned() else {
                return;
            };
            let Some(ddp) = handles.lock().unwrap().as_ref().map(|h| h.ddp.clone()) else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };
            // Reset the detail pane and seed the StyleWriter name field.
            if let Some(w) = weak.upgrade() {
                w.set_detail_loaded(false);
                w.set_info_rows(to_model(Vec::new()));
                w.set_error_text("".into());
                if printer.kind == PrinterKind::StyleWriter {
                    w.set_edit_name(printer.name.as_str().into());
                }
            }
            begin_busy(&weak, "Querying printer…");
            let weak = weak.clone();
            rt.spawn(async move {
                match printer.kind {
                    PrinterKind::StyleWriter => {
                        let result = query_stylewriter(&ddp, printer.adsp_print_addr()).await;
                        slint::invoke_from_event_loop(move || {
                            let Some(w) = weak.upgrade() else { return };
                            match result {
                                Ok(lines) => {
                                    w.set_info_rows(to_model(lines));
                                    w.set_detail_loaded(true);
                                    w.set_status_text("Ready.".into());
                                }
                                Err(e) => {
                                    w.set_error_text(SharedString::from(format!("{e}")));
                                    w.set_status_text("Query failed.".into());
                                }
                            }
                            w.set_busy(false);
                        })
                        .ok();
                    }
                    PrinterKind::LaserWriter => {
                        let result = query_laserwriter(&ddp, printer.atp_addr()).await;
                        slint::invoke_from_event_loop(move || {
                            let Some(w) = weak.upgrade() else { return };
                            match result {
                                Ok(info) => {
                                    w.set_info_rows(to_model(info.lines));
                                    w.set_paper_index(info.paper_index);
                                    w.set_startup_enabled(info.startup_enabled);
                                    w.set_detail_loaded(true);
                                    w.set_status_text("Ready.".into());
                                }
                                Err(e) => {
                                    w.set_error_text(SharedString::from(format!("{e}")));
                                    w.set_status_text("Query failed.".into());
                                }
                            }
                            w.set_busy(false);
                        })
                        .ok();
                    }
                    PrinterKind::ImageWriter => {
                        let result = query_imagewriter(&ddp, printer.atp_addr()).await;
                        slint::invoke_from_event_loop(move || {
                            let Some(w) = weak.upgrade() else { return };
                            match result {
                                Ok(lines) => {
                                    w.set_info_rows(to_model(lines));
                                    w.set_detail_loaded(true);
                                    w.set_status_text("Ready.".into());
                                }
                                Err(e) => {
                                    w.set_error_text(SharedString::from(format!("{e}")));
                                    w.set_status_text("Query failed.".into());
                                }
                            }
                            w.set_busy(false);
                        })
                        .ok();
                    }
                }
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
            match printer.kind {
                PrinterKind::StyleWriter => {
                    let new_name = w.get_edit_name().to_string();
                    rt.spawn(async move {
                        let result = rename_stylewriter(&ddp, printer.adsp_mgmt_addr(), &new_name).await;
                        finish_save(weak, result, None);
                    });
                }
                PrinterKind::LaserWriter => {
                    let size = PaperSize::from_index(w.get_paper_index());
                    let startup = w.get_startup_enabled();
                    rt.spawn(async move {
                        let result = save_laserwriter(&ddp, printer.atp_addr(), size, startup).await;
                        // Re-query on success so the panel reflects what stuck.
                        finish_save(weak, result, Some(index));
                    });
                }
                PrinterKind::ImageWriter => {
                    rt.spawn(async move {
                        let result = print_test_page_imagewriter(&ddp, printer.atp_addr()).await;
                        finish_save(weak, result, None);
                    });
                }
            }
        });
    }

    if let Err(e) = window.show() {
        tracing::error!("Printer Tool: failed to show window: {e}");
        return;
    }

    // Kick off an initial discovery so the list is populated on open.
    window.invoke_refresh();

    *slot.borrow_mut() = Some(window);
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
/// re-runs the query for that row so the panel shows the persisted values.
fn finish_save(weak: Weak<PrinterToolWindow>, result: anyhow::Result<String>, requery: Option<i32>) {
    slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_busy(false);
        match result {
            Ok(msg) => {
                w.set_status_text(SharedString::from(msg));
                if let Some(index) = requery {
                    w.invoke_query(index);
                }
            }
            Err(e) => w.set_status_text(SharedString::from(format!("Save failed: {e}"))),
        }
    })
    .ok();
}
