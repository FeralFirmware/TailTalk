//! The "Network Explorer" window: a master/detail view over everything NBP can
//! see on the AppleTalk network. The sidebar lists every registered entity
//! (file servers, workstations, routers and printers alike) with the round-trip
//! time to its node measured by AEP echo. Selecting one shows what we can learn
//! about it, plus a ping test that works against any node.
//!
//! Printers are the one family the explorer can also configure, and each has its
//! own way in:
//!
//!   * StyleWriter — rename, over the ADSP management socket (`sw-rename`).
//!   * LaserWriter — rename, default paper size and power-on startup page, as
//!     PostScript over PAP (`pap-print`).
//!   * ImageWriter — rename, as the option card's `ESC b` command over PAP.
//!     Status comes back from the same card as a packed status word.
//!
//! Everything else is listed, described from its NBP registration and pinged,
//! but has no protocol we can query or configure it with.
//!
//! The server has to be running: we borrow its live `NbpHandle`/`DdpHandle`/
//! `EchoHandle` rather than building a second stack, which couldn't reopen an
//! in-use TashTalk serial port.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use slint::{ComponentHandle, Model, VecModel, Weak};
use tailtalk::{
    adsp::{Adsp, AdspAddress, AdspStream},
    atp::{Atp, AtpAddress},
    ddp::DdpHandle,
    echo::{EchoHandle, MAX_ECHO_DATA},
    imagewriter::{self, ImageWriter, ImageWriterStatus},
    pap::{PapClient, PapStatusHandle},
    stylewriter::StyleWriterSession,
};
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::nbp::EntityName;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

use crate::{DeviceRow, ExplorerHandles, InfoRow, NetworkExplorerWindow};

/// One line of the information panel. The query tasks build these and hand them
/// to the event loop, which turns them into Slint [`InfoRow`]s — `SharedString`
/// isn't `Send`, so it can't cross that boundary.
#[derive(Clone)]
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

/// The device families the explorer understands. Only the three printer
/// families can be queried or configured; everything else is listed from its
/// NBP registration and reachable only over AEP.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeviceKind {
    /// PostScript printer driven over PAP (NBP type "LaserWriter").
    LaserWriter,
    /// Color StyleWriter behind an EtherTalk adapter, driven over ADSP
    /// (NBP type "ColorStyleWriter2400AT").
    StyleWriter,
    /// Apple ImageWriter II/LQ behind a LocalTalk Option Card, queried over PAP
    /// (NBP type "ImageWriter").
    ImageWriter,
    /// Anything else NBP advertises: file servers, workstations, routers,
    /// third-party printers.
    Generic,
}

/// ADSP management socket — fixed at 129 on StyleWriter adapters (see `sw-rename`).
const SW_MGMT_SOCKET: u8 = 129;

/// Longest name each family accepts: the StyleWriter's Pascal-string rename
/// takes 31, the LaserWriter's `PrinterName` 32. Drives both validation and the
/// hint under the name field, so the two cannot disagree.
const SW_MAX_NAME_LEN: usize = 31;
const LW_MAX_NAME_LEN: usize = 32;

impl DeviceKind {
    /// The NBP type each configurable family registers under.
    fn nbp_type(self) -> Option<&'static str> {
        match self {
            DeviceKind::LaserWriter => Some("LaserWriter"),
            DeviceKind::StyleWriter => Some("ColorStyleWriter2400AT"),
            DeviceKind::ImageWriter => Some("ImageWriter"),
            DeviceKind::Generic => None,
        }
    }

    /// Classify a registration by its NBP type. Case-insensitive, because NBP
    /// itself is (see `EntityName::matches`) and [`describe_type`] already is:
    /// a printer registered as "LASERWRITER" would otherwise be labelled a
    /// LaserWriter in the sidebar and still treated as an unknown device, with
    /// no query and no settings.
    fn from_nbp_type(nbp_type: &str) -> DeviceKind {
        for kind in [DeviceKind::LaserWriter, DeviceKind::StyleWriter, DeviceKind::ImageWriter] {
            if kind.nbp_type().is_some_and(|t| t.eq_ignore_ascii_case(nbp_type)) {
                return kind;
            }
        }
        DeviceKind::Generic
    }

    /// Whether the detail pane offers anything editable for this family.
    fn has_settings(self) -> bool {
        self != DeviceKind::Generic
    }

    fn max_name_len(self) -> usize {
        match self {
            DeviceKind::StyleWriter => SW_MAX_NAME_LEN,
            DeviceKind::LaserWriter => LW_MAX_NAME_LEN,
            DeviceKind::ImageWriter => imagewriter::MAX_NAME_LEN,
            // Nothing to rename, but the field's limit still has to be a number.
            DeviceKind::Generic => SW_MAX_NAME_LEN,
        }
    }
}

/// Icon and human-readable family for the NBP types worth naming. Anything not
/// listed falls back to [`describe_type`]'s heuristics and the raw type string,
/// so an unfamiliar device still lists under whatever it calls itself.
const KNOWN_TYPES: &[(&str, &str, &str)] = &[
    ("LaserWriter", "🖨", "LaserWriter (PostScript)"),
    ("ColorStyleWriter2400AT", "🖨", "Color StyleWriter"),
    ("ImageWriter", "🖨", "ImageWriter"),
    ("ImageWriter LQ", "🖨", "ImageWriter LQ"),
    ("DeskWriter", "🖨", "HP DeskWriter"),
    ("AFPServer", "🗄", "File Server"),
    ("Workstation", "💻", "Workstation"),
    ("netatalk", "💻", "Netatalk Host"),
    ("Macintosh", "💻", "Macintosh"),
    ("AppleRouter", "🌐", "Router"),
    ("IPGATEWAY", "🌐", "IP Gateway"),
    ("SNMP Agent", "📊", "SNMP Agent"),
];

/// Pick an icon and a display name for an NBP type. Unknown types are guessed
/// at from the words in the type itself, which is how most of the third-party
/// AppleTalk world names things ("HP LaserJet 4MV", "ARA Server"), and are shown
/// with their own type as the label rather than a made-up one.
fn describe_type(nbp_type: &str) -> (&'static str, String) {
    if let Some((_, icon, label)) =
        KNOWN_TYPES.iter().find(|(t, _, _)| t.eq_ignore_ascii_case(nbp_type))
    {
        return (icon, (*label).to_string());
    }

    let lower = nbp_type.to_ascii_lowercase();
    let icon = if lower.contains("writer")
        || lower.contains("printer")
        || lower.contains("laserjet")
        || lower.contains("jetdirect")
    {
        "🖨"
    } else if lower.contains("server") || lower.contains("share") {
        "🗄"
    } else if lower.contains("router") || lower.contains("gateway") || lower.contains("bridge") {
        "🌐"
    } else if lower.contains("station") || lower.contains("mac") {
        "💻"
    } else {
        "📦"
    };

    let label = if nbp_type.is_empty() { "Unknown type".to_string() } else { nbp_type.to_string() };
    (icon, label)
}

/// A device found by [`discover`]; carries the real AppleTalk address that the
/// Slint model rows (indexed 1:1) can't hold.
#[derive(Clone)]
struct Device {
    name: String,
    nbp_type: String,
    zone: String,
    kind: DeviceKind,
    net: u16,
    node: u8,
    socket: u8,
}

impl Device {
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

    /// The advertised print endpoint, as an ATP address (LaserWriter, ImageWriter).
    fn atp_addr(&self) -> AtpAddress {
        AtpAddress {
            network_number: self.net,
            node_number: self.node,
            socket_number: self.socket,
        }
    }

    /// The node itself. AEP answers on socket 4 of every node, so latency is a
    /// property of the node rather than of the advertised service.
    fn node_addr(&self) -> AppleTalkAddress {
        AppleTalkAddress { network_number: self.net, node_number: self.node }
    }

    fn address_text(&self) -> String {
        format!("{}.{} socket {}", self.net, self.node, self.socket)
    }

    fn row(&self) -> DeviceRow {
        let (icon, kind) = describe_type(&self.nbp_type);
        DeviceRow {
            name: self.name.as_str().into(),
            kind: kind.into(),
            address: self.address_text().into(),
            icon: icon.into(),
            latency: "…".into(),
            latency_ok: false,
            has_settings: self.kind.has_settings(),
            is_stylewriter: self.kind == DeviceKind::StyleWriter,
            is_imagewriter: self.kind == DeviceKind::ImageWriter,
            is_laserwriter: self.kind == DeviceKind::LaserWriter,
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
    /// Index order must match the ComboBox model in `network_explorer.slint`.
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

/// What a query produced. Kept in the [`Cache`] once fetched, so re-selecting a
/// device costs nothing on the wire.
#[derive(Clone)]
struct Queried {
    lines: Vec<Line>,
    /// LaserWriter only: current values for the editable controls.
    settings: Option<LaserSettings>,
}

#[derive(Clone)]
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

// ── AEP echo (latency readings and the ping test) ─────────────────────────────

/// Probes fired when a device is listed or selected, to fill in the sidebar's
/// round-trip reading. Short and few: this runs for every node found, so it has
/// to stay well clear of the pace a LocalTalk cable can sustain.
const QUICK_PING_COUNT: u32 = 3;
const QUICK_PING_TIMEOUT: Duration = Duration::from_millis(1500);
const QUICK_PING_BYTES: usize = 16;

/// Per-packet deadline and inter-packet gap for the configurable test. The gap
/// keeps a long run from monopolising a 230 kbit LocalTalk segment; the deadline
/// is generous enough for a busy printer that answers AEP between pages.
const PING_TIMEOUT: Duration = Duration::from_secs(2);
const PING_INTERVAL: Duration = Duration::from_millis(100);

/// How often the latency column is re-measured. Selecting a device does not
/// probe it: a click should cost nothing on the wire, and a reading that only
/// updated when clicked would be a reading of when it was clicked. One timer
/// sweeps every node instead.
const LATENCY_REFRESH: Duration = Duration::from_secs(30);

/// Ping-test bounds. These are handed to the .slint at startup rather than
/// written down twice, so the field's limits are these limits. The floor on
/// size is four bytes because [`ping_payload`] puts the sequence number there,
/// which is what lets the echo actor tell concurrent replies apart.
const MIN_PING_BYTES: usize = 4;
const MAX_PING_COUNT: u32 = 500;

/// What a run of probes measured.
#[derive(Clone, Copy, Default)]
struct PingStats {
    sent: u32,
    received: u32,
    fastest: Option<Duration>,
    slowest: Option<Duration>,
    /// Summed round-trip times of the replies, for the average.
    total: Duration,
}

impl PingStats {
    fn record(&mut self, rtt: Option<Duration>) {
        self.sent += 1;
        let Some(rtt) = rtt else { return };
        self.received += 1;
        self.total += rtt;
        self.fastest = Some(self.fastest.map_or(rtt, |f| f.min(rtt)));
        self.slowest = Some(self.slowest.map_or(rtt, |s| s.max(rtt)));
    }

    fn average(&self) -> Option<Duration> {
        (self.received > 0).then(|| self.total / self.received)
    }

    /// Fraction of probes that went unanswered, as a percentage.
    fn loss_percent(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        (self.sent - self.received) as f64 * 100.0 / self.sent as f64
    }
}

/// Round-trip times as a person reads them: sub-10 ms wants a decimal (an
/// EtherTalk hop lands there), anything slower does not.
fn format_ms(d: Duration) -> String {
    let ms = d.as_secs_f64() * 1000.0;
    if ms < 10.0 { format!("{ms:.1} ms") } else { format!("{ms:.0} ms") }
}

fn format_opt_ms(d: Option<Duration>) -> String {
    d.map_or_else(|| "—".to_string(), format_ms)
}

/// A probe tag unique for the life of the process.
///
/// Numbering per run would not be enough: the latency sweep and a ping test can
/// be in flight against the same node at the same time, and with the same size
/// they would emit byte-identical data whose replies could be cross-credited.
fn next_probe_tag() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Echo data of `len` bytes carrying `tag` in the first four. AEP returns the
/// data untouched, so the tag is what matches a reply to the probe that caused
/// it. Without it a late reply would be credited to the next probe and report
/// an impossibly short round trip.
fn ping_payload(tag: u32, len: usize) -> Vec<u8> {
    let tag = tag.to_be_bytes();
    (0..len).map(|i| if i < tag.len() { tag[i] } else { (i % 251) as u8 }).collect()
}

/// Fire `count` probes back to back, reporting each result as it lands. `report`
/// returns false to abandon the run (the user pressed Stop, or moved on).
async fn ping_run(
    echo: &EchoHandle,
    addr: AppleTalkAddress,
    count: u32,
    bytes: usize,
    per_packet: Duration,
    gap: Duration,
    mut report: impl FnMut(PingStats) -> bool,
) -> PingStats {
    let mut stats = PingStats::default();
    for seq in 0..count {
        let payload = ping_payload(next_probe_tag(), bytes);
        let rtt = echo.send_timeout(addr, &payload, per_packet).await.ok();
        stats.record(rtt);
        if !report(stats) {
            break;
        }
        if seq + 1 < count && !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }
    stats
}

/// The three-probe reading behind the sidebar's latency line. Sent back to back
/// with no gap so selecting a device feels immediate.
async fn quick_ping(echo: &EchoHandle, addr: AppleTalkAddress) -> PingStats {
    ping_run(
        echo,
        addr,
        QUICK_PING_COUNT,
        QUICK_PING_BYTES,
        QUICK_PING_TIMEOUT,
        Duration::ZERO,
        |_| true,
    )
    .await
}

/// The sidebar's one-line reading: the average when anything answered, and a
/// word rather than a time when nothing did.
fn latency_text(stats: &PingStats) -> (String, bool) {
    match stats.average() {
        Some(avg) => (format_ms(avg), true),
        None => ("lost".to_string(), false),
    }
}

// ── Async operations (reuse the existing protocol code) ───────────────────────

/// Discover everything registered with NBP.
///
/// The wildcard `=:=@*` alone would be enough for a well-behaved network, but
/// the three printer families are asked for by name as well: they are the ones
/// the explorer can actually configure, and asking for a type directly is the
/// lookup those printers have always been tested against. The results are merged,
/// so a device answering both is listed once.
async fn discover(handles: &ExplorerHandles) -> anyhow::Result<Vec<Device>> {
    let patterns: Vec<String> = std::iter::once("=:=@*".to_string())
        .chain(
            [DeviceKind::LaserWriter, DeviceKind::StyleWriter, DeviceKind::ImageWriter]
                .iter()
                .filter_map(|k| k.nbp_type())
                .map(|t| format!("=:{t}@*")),
        )
        .collect();

    // Our own address on each transport, so registrations belonging to this
    // stack (our AFP server, the built-in LaserWriter emulator) can be dropped
    // below.
    let local: Vec<(u16, u8)> = handles
        .local_addrs
        .iter()
        .filter_map(|w| w.borrow().map(|a| (a.network_number, a.node_number)))
        .collect();

    let names = patterns
        .iter()
        .map(|pattern| {
            EntityName::try_from(pattern.as_str())
                .map_err(|e| anyhow::anyhow!("bad entity name '{pattern}': {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut found = Vec::new();
    let mut seen: HashSet<(String, String, u16, u8, u8)> = HashSet::new();
    for tuples in handles.nbp.lookup_many(names).await? {
        for t in tuples {
            if t.entity_name.object.is_empty() {
                continue;
            }
            if local.contains(&(t.network_number, t.node_id)) {
                tracing::debug!(
                    "Network Explorer: skipping own registration \"{}\" at {}.{}",
                    t.entity_name.object,
                    t.network_number,
                    t.node_id
                );
                continue;
            }
            let object = t.entity_name.object.to_utf8_string();
            let entity_type = t.entity_name.entity_type.to_utf8_string();
            let key = (
                object.clone(),
                entity_type.clone(),
                t.network_number,
                t.node_id,
                t.socket_number,
            );
            if !seen.insert(key) {
                continue; // already listed from another pattern
            }
            found.push(Device {
                kind: DeviceKind::from_nbp_type(&entity_type),
                name: object,
                nbp_type: entity_type,
                zone: t.entity_name.zone.to_utf8_string(),
                net: t.network_number,
                node: t.node_id,
                socket: t.socket_number,
            });
        }
    }

    // Configurable devices first, since they are what the window can act on,
    // then everything else alphabetically so a refresh doesn't reshuffle.
    found.sort_by(|a, b| {
        b.kind
            .has_settings()
            .cmp(&a.kind.has_settings())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            .then_with(|| a.nbp_type.cmp(&b.nbp_type))
    });
    Ok(found)
}

/// The rows every device has, whatever it is: what it told NBP about itself.
fn directory_lines(device: &Device) -> Vec<Line> {
    vec![
        Line::section("Directory"),
        Line::field("Name", device.name.clone()),
        Line::field("NBP type", device.nbp_type.clone()),
        Line::field(
            "Zone",
            if device.zone.is_empty() || device.zone == "*" {
                "(no zone)".to_string()
            } else {
                device.zone.clone()
            },
        ),
        Line::field("Address", device.address_text()),
    ]
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

/// Query an ImageWriter's LocalTalk Option Card over PAP. No connection is
/// opened, so this works even while the printer is mid-job. Everything the card
/// reports is in one 16-bit word, so there is nothing further to ask it.
async fn query_imagewriter(ddp: &DdpHandle, addr: AtpAddress) -> anyhow::Result<Queried> {
    let s = ImageWriter::status_of(ddp, addr).await?;
    Ok(Queried {
        lines: imagewriter_lines(&s),
        settings: None,
    })
}

/// The printer half of the info panel for one status word. Every row here bar
/// the model comes out of that word, so the poller re-renders all of them
/// together rather than refreshing the Condition line over a frozen copy of
/// everything else.
fn imagewriter_lines(s: &ImageWriterStatus) -> Vec<Line> {
    let yes_no = |b: bool| if b { "Yes" } else { "No" };

    vec![
        Line::section("Status"),
        Line::field("Condition", imagewriter_condition(s)),
        Line::field("Paper", if s.paper_present() { "Loaded" } else { "Out of paper" }),
        Line::field("Select", if s.off_line() { "Off line" } else { "On line" }),
        Line::field("Busy", yes_no(s.busy())),
        Line::field("Printing", yes_no(s.active())),
        Line::section("Hardware"),
        Line::field("Model", "Apple ImageWriter II/LQ"),
        Line::field("Ribbon", s.ribbon_text()),
        Line::field(
            "Colour printing",
            if s.color_ribbon() { "Yes" } else { "No, black ribbon installed" },
        ),
        Line::field("Sheet feeder", yes_no(s.sheet_feeder())),
        // The unaltered reply alongside the decode: a raw reading is what
        // any "this status looks wrong" report needs.
        Line::section("Raw protocol reply"),
        Line::field("Status word", format!("0x{:04X}", s.raw)),
        Line::field(
            "Wire bytes",
            s.wire_bytes().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" "),
        ),
    ]
}

/// One-line summary for the Condition row, matching how the other two families
/// phrase it: errors first, then whatever the printer is doing.
fn imagewriter_condition(s: &ImageWriterStatus) -> String {
    if let Some(e) = s.error_text() {
        e
    } else if s.active() {
        "Printing".to_string()
    } else if s.busy() {
        "Busy: connection open or printer not ready".to_string()
    } else {
        "Ready".to_string()
    }
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

/// Attention codes used by the StyleWriter name-change protocol.
const ATTN_GET_NAME: u16 = 0x0011;
const ATTN_SET_NAME: u16 = 0x0009;
const ATTN_COMMIT: u16 = 0x0012;

/// Rename a StyleWriter via its ADSP management socket (the `sw-rename` flow).
async fn rename_stylewriter(
    ddp: &DdpHandle,
    mgmt_addr: AdspAddress,
    new_name: &str,
) -> anyhow::Result<String> {
    validate_name(new_name, DeviceKind::StyleWriter.max_name_len())?;

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

/// Rename an ImageWriter by sending the option card's `ESC b` command over PAP.
/// The card takes the name out of the data stream instead of passing it to the
/// printer, so this goes over an ordinary print connection.
async fn rename_imagewriter(
    ddp: &DdpHandle,
    addr: AtpAddress,
    new_name: &str,
) -> anyhow::Result<String> {
    validate_name(new_name, DeviceKind::ImageWriter.max_name_len())?;

    let mut printer = ImageWriter::connect(ddp, addr).await?;
    let result = printer.set_name(new_name).await;
    // Close either way: leaving the connection open holds the printer busy.
    let closed = printer.close().await;
    result.and(closed)?;

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
    validate_name(name, DeviceKind::LaserWriter.max_name_len())?;
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

/// What the window remembers between clicks. Selecting a device is a free
/// action: everything the detail pane needs is either already here or is being
/// fetched for the first time.
#[derive(Default)]
struct Cache {
    /// Round-trip time per node, refreshed by the latency sweep on its own
    /// timer. Keyed by node rather than by row, since one node can advertise
    /// several services and they all share the one measurement.
    latency: HashMap<(u16, u8), PingStats>,
    /// The last full query per sidebar row. Discovery clears this (the rows it
    /// is keyed against are rebuilt); so does a successful save, which changes
    /// what a fresh query would return.
    queries: HashMap<usize, Queried>,
}

/// Open (or re-focus) the Network Explorer window. `handles` is the running
/// stack's shared handle store; `slot` keeps the window alive past the callback
/// that created it.
pub fn open(
    rt: &tokio::runtime::Handle,
    handles: Arc<Mutex<Option<ExplorerHandles>>>,
    slot: Rc<RefCell<Option<NetworkExplorerWindow>>>,
) {
    if let Some(existing) = slot.borrow().as_ref() {
        let _ = existing.show();
        // The latency sweep stops when the window is closed, so re-opening has
        // to start a new one. Discovery is the thing that starts it.
        existing.invoke_refresh();
        return;
    }

    let window = match NetworkExplorerWindow::new() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Network Explorer: failed to create window: {e}");
            return;
        }
    };
    // The .slint declares no bounds of its own; these are the protocol's.
    window.set_ping_size_min(MIN_PING_BYTES as i32);
    window.set_ping_size_max(MAX_ECHO_DATA as i32);
    window.set_ping_count_max(MAX_PING_COUNT as i32);

    // Discovered devices, kept 1:1 with the Slint model rows so a row index
    // maps back to a real AppleTalk address.
    let discovered: Arc<Mutex<Vec<Device>>> = Arc::new(Mutex::new(Vec::new()));

    // Everything already measured or fetched. The information panel is rendered
    // from this, never from what happens to be on screen.
    let cache: Arc<Mutex<Cache>> = Arc::new(Mutex::new(Cache::default()));

    // Bumped whenever the selection changes or the list is refreshed. Background
    // tasks capture the value they started with and drop their results if it no
    // longer matches, so a slow query can't overwrite a newer selection's panel.
    let generation: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // Bumped only by Refresh. The latency sweep runs for as long as the window
    // is open and must outlive selection changes, which move `generation` on
    // every click.
    let sweep_gen: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

    // Set to stop an in-progress ping test: by the Stop button, by selecting a
    // different device, or by a refresh.
    let ping_cancel: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));

    // ── Refresh ──────────────────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let cache = cache.clone();
        let generation = generation.clone();
        let sweep_gen = sweep_gen.clone();
        let ping_cancel = ping_cancel.clone();
        window.on_refresh(move || {
            generation.fetch_add(1, Ordering::SeqCst);
            let my_sweep = sweep_gen.fetch_add(1, Ordering::SeqCst) + 1;
            ping_cancel.store(true, Ordering::SeqCst);
            let Some(handles) = handles.lock().unwrap().clone() else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };
            // Queried detail is keyed by row index, and discovery rebuilds the
            // rows. Latency is keyed by node, so it survives and seeds the new
            // list rather than blanking every reading back to a placeholder.
            cache.lock().unwrap().queries.clear();

            begin_busy(&weak, "Discovering devices…");
            if let Some(w) = weak.upgrade() {
                w.set_selected(-1);
                w.set_detail_loaded(false);
                clear_ping_results(&w);
            }
            let weak = weak.clone();
            let discovered = discovered.clone();
            let cache = cache.clone();
            let sweep_gen = sweep_gen.clone();
            rt.spawn(async move {
                let result = discover(&handles).await;
                let nodes: Vec<AppleTalkAddress> = match &result {
                    Ok(found) => unique_nodes(found),
                    Err(_) => Vec::new(),
                };

                let posted = {
                    let weak = weak.clone();
                    let discovered = discovered.clone();
                    let cache = cache.clone();
                    slint::invoke_from_event_loop(move || {
                        let Some(w) = weak.upgrade() else { return };
                        match result {
                            Ok(found) => {
                                let rows: Vec<DeviceRow> = found.iter().map(Device::row).collect();
                                let n = rows.len();
                                *discovered.lock().unwrap() = found;
                                w.set_devices(Rc::new(VecModel::from(rows)).into());
                                w.set_selected(-1);
                                apply_cached_latency(&w, &discovered, &cache);
                                w.set_status_text(if n == 0 {
                                    "No devices found. Is anything powered on and on the same network?"
                                        .into()
                                } else {
                                    format!("Found {n} device(s). Measuring latency…").into()
                                });
                            }
                            Err(e) => w.set_status_text(format!("Discovery failed: {e}").into()),
                        }
                        w.set_busy(false);
                    })
                };
                if posted.is_err() {
                    return;
                }

                latency_sweep(weak, discovered, cache, handles.echo, nodes, sweep_gen, my_sweep)
                    .await;
            });
        });
    }

    // ── Query (auto-fired when a device is selected) ─────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let cache = cache.clone();
        let generation = generation.clone();
        let ping_cancel = ping_cancel.clone();
        window.on_query(move |index| {
            let my_gen = generation.fetch_add(1, Ordering::SeqCst) + 1;
            ping_cancel.store(true, Ordering::SeqCst);
            let idx = index as usize;
            let Some(device) = discovered.lock().unwrap().get(idx).cloned() else {
                return;
            };
            let Some(w) = weak.upgrade() else { return };
            let Some(handles) = handles.lock().unwrap().clone() else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };

            // Down until this selection has values of its own. Leaving it set
            // would keep Save enabled over the *previous* device's paper size
            // and startup flag if this query fails, and write those to this
            // printer's NVRAM.
            w.set_detail_loaded(false);
            w.set_error_text("".into());
            w.set_edit_name(device.name.as_str().into());
            w.set_name_max(device.kind.max_name_len() as i32);
            clear_ping_results(&w);

            // A device is queried once. Its status keeps ticking over through
            // the poller below, but the slow part - a PostScript capability
            // dump, or an ADSP session - is not repeated on every click.
            // `Some(None)` is a device that was queried and reported no
            // settings, which is not the same as one never queried at all.
            let cached = cache.lock().unwrap().queries.get(&idx).map(|q| q.settings.clone());
            if let Some(settings) = cached {
                // Settings first: a LaserWriter's own name can differ from the
                // one it registered, and renaming the row feeds the panel.
                apply_settings(&w, &discovered, idx, settings.as_ref());
                render_panel(&w, &discovered, &cache, idx);
                w.set_detail_loaded(true);
                w.set_busy(false);
                w.set_status_text("Ready. Showing the earlier query; Refresh to query again.".into());
                start_status_poller(&rt, &weak, &discovered, &cache, idx, &device, &handles.ddp,
                    &generation, my_gen);
                return;
            }

            // Nothing cached yet, so put up what costs nothing - the
            // registration, and whatever the sweep last measured - and query
            // behind it rather than leaving the panel blank.
            render_panel(&w, &discovered, &cache, idx);
            begin_busy(&weak, "Querying device…");

            let rt_poll = rt.clone();
            let weak = weak.clone();
            let discovered = discovered.clone();
            let cache = cache.clone();
            let generation = generation.clone();
            rt.spawn(async move {
                let ddp = handles.ddp.clone();
                let result = match device.kind {
                    DeviceKind::StyleWriter => {
                        query_stylewriter(&ddp, device.adsp_print_addr()).await
                    }
                    DeviceKind::LaserWriter => query_laserwriter(&ddp, device.atp_addr()).await,
                    DeviceKind::ImageWriter => query_imagewriter(&ddp, device.atp_addr()).await,
                    // Nothing beyond the registration and the latency reading.
                    DeviceKind::Generic => Ok(Queried { lines: Vec::new(), settings: None }),
                };

                slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    if generation.load(Ordering::SeqCst) != my_gen {
                        return; // the selection moved on while we were querying
                    }
                    match result {
                        Ok(q) => {
                            let settings = q.settings.clone();
                            cache.lock().unwrap().queries.insert(idx, q);
                            apply_settings(&w, &discovered, idx, settings.as_ref());
                            render_panel(&w, &discovered, &cache, idx);
                            w.set_detail_loaded(true);
                            w.set_status_text("Ready.".into());
                            // Both PAP families re-poll cheaply, so keep the
                            // status rows fresh while the device stays selected.
                            // The StyleWriter's ADSP query needs a whole session,
                            // so it is left to the manual refresh.
                            start_status_poller(&rt_poll, &w.as_weak(), &discovered, &cache, idx,
                                &device, &ddp, &generation, my_gen);
                        }
                        Err(e) => {
                            // The registration and the latency reading still
                            // stand, so keep them and put the failure beside
                            // them rather than in their place. Nothing is
                            // cached, so re-selecting will try the query again.
                            render_panel(&w, &discovered, &cache, idx);
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

    // ── Ping test ────────────────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let cache = cache.clone();
        let generation = generation.clone();
        let ping_cancel = ping_cancel.clone();
        window.on_run_ping_test(move |index| {
            let Some(w) = weak.upgrade() else { return };
            let Some(device) = discovered.lock().unwrap().get(index as usize).cloned() else {
                return;
            };
            let Some(echo) = handles.lock().unwrap().as_ref().map(|h| h.echo.clone()) else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };

            // The fields clamp themselves, so this is belt and braces: nothing
            // reaching the wire should depend on a UI widget having behaved.
            let count = w.get_ping_count().clamp(1, MAX_PING_COUNT as i32) as u32;
            let bytes = (w.get_ping_size() as usize).clamp(MIN_PING_BYTES, MAX_ECHO_DATA);
            let addr = device.node_addr();

            clear_ping_results(&w);
            w.set_ping_busy(true);
            w.set_ping_status(format!("Pinging {}.{}…", addr.network_number, addr.node_number).into());

            let cancel = ping_cancel.clone();
            cancel.store(false, Ordering::SeqCst);
            let my_gen = generation.load(Ordering::SeqCst);
            let generation = generation.clone();
            let weak = weak.clone();
            let discovered = discovered.clone();
            let cache = cache.clone();
            rt.spawn(async move {
                let report_gen = generation.clone();
                let report_weak = weak.clone();
                let report_cancel = cancel.clone();
                let stats = ping_run(
                    &echo,
                    addr,
                    count,
                    bytes,
                    PING_TIMEOUT,
                    PING_INTERVAL,
                    move |stats| {
                        if report_cancel.load(Ordering::SeqCst)
                            || report_gen.load(Ordering::SeqCst) != my_gen
                        {
                            return false;
                        }
                        // Let the figures build as the run goes, so a long test
                        // shows its shape instead of a spinner.
                        let weak = report_weak.clone();
                        slint::invoke_from_event_loop(move || {
                            if let Some(w) = weak.upgrade() {
                                show_ping_stats(&w, &stats);
                                w.set_ping_status(
                                    format!("Sent {} of {count}…", stats.sent).into(),
                                );
                            }
                        })
                        .is_ok()
                    },
                )
                .await;

                let stopped = cancel.load(Ordering::SeqCst);
                slint::invoke_from_event_loop(move || {
                    let Some(w) = weak.upgrade() else { return };
                    w.set_ping_busy(false);
                    if generation.load(Ordering::SeqCst) != my_gen {
                        return; // another device is selected now
                    }
                    // A deliberate run is a better measurement than the sweep's
                    // three probes, so it stands in for the latest reading.
                    set_node_latency(&w, &discovered, &cache, addr, &stats);
                    show_ping_stats(&w, &stats);
                    w.set_ping_status(
                        format!(
                            "{} {} of {} probe(s) at {bytes} bytes to {}.{} — {} answered.",
                            if stopped { "Stopped after" } else { "Sent" },
                            stats.sent,
                            count,
                            addr.network_number,
                            addr.node_number,
                            stats.received,
                        )
                        .into(),
                    );
                })
                .ok();
            });
        });
    }

    {
        let ping_cancel = ping_cancel.clone();
        window.on_stop_ping_test(move || {
            ping_cancel.store(true, Ordering::SeqCst);
        });
    }

    // ── Save (kind-dependent) ────────────────────────────────────────────────
    {
        let rt = rt.clone();
        let handles = handles.clone();
        let weak = window.as_weak();
        let discovered = discovered.clone();
        let cache = cache.clone();
        window.on_save(move |index| {
            let Some(w) = weak.upgrade() else { return };
            let Some(device) = discovered.lock().unwrap().get(index as usize).cloned() else {
                return;
            };
            let Some(ddp) = handles.lock().unwrap().as_ref().map(|h| h.ddp.clone()) else {
                set_status(&weak, "The AFP server is no longer running.");
                return;
            };
            begin_busy(&weak, "Saving…");
            let weak = weak.clone();
            let cache = cache.clone();
            let name = w.get_edit_name().to_string();
            match device.kind {
                DeviceKind::StyleWriter => {
                    rt.spawn(async move {
                        let result = rename_stylewriter(&ddp, device.adsp_mgmt_addr(), &name).await;
                        finish_save(weak, cache, index, result, false);
                    });
                }
                DeviceKind::LaserWriter => {
                    let size = PaperSize::from_index(w.get_paper_index());
                    let startup = w.get_startup_enabled();
                    rt.spawn(async move {
                        let addr = device.atp_addr();
                        let result = save_laserwriter(&ddp, addr, size, startup, &name).await;
                        // Re-query on success so the panel reflects what stuck.
                        finish_save(weak, cache, index, result, true);
                    });
                }
                DeviceKind::ImageWriter => {
                    rt.spawn(async move {
                        let result = rename_imagewriter(&ddp, device.atp_addr(), &name).await;
                        finish_save(weak, cache, index, result, false);
                    });
                }
                // The Save button is hidden for these, so this is unreachable
                // from the UI; refusing beats silently doing nothing.
                DeviceKind::Generic => {
                    set_status(&weak, "This device has no settings the explorer can change.");
                    if let Some(w) = weak.upgrade() {
                        w.set_busy(false);
                    }
                }
            }
        });
    }

    if let Err(e) = window.show() {
        tracing::error!("Network Explorer: failed to show window: {e}");
        return;
    }

    window.invoke_refresh();
    *slot.borrow_mut() = Some(window);
}

/// Every distinct node among the discovered devices, in list order. One node can
/// register several services (a Mac advertising both `Workstation` and
/// `AFPServer`), and they all share one round-trip time.
fn unique_nodes(devices: &[Device]) -> Vec<AppleTalkAddress> {
    let mut seen = HashSet::new();
    devices
        .iter()
        .map(Device::node_addr)
        .filter(|a| seen.insert((a.network_number, a.node_number)))
        .collect()
}

/// Measure every node, then keep re-measuring on [`LATENCY_REFRESH`] for as long
/// as this discovery is the current one and the window is open.
///
/// Nodes are probed one at a time: the probes are tiny, but a LocalTalk segment
/// carrying a dozen devices is not, and nothing here is urgent enough to justify
/// putting them all on the wire at once.
async fn latency_sweep(
    weak: Weak<NetworkExplorerWindow>,
    discovered: Arc<Mutex<Vec<Device>>>,
    cache: Arc<Mutex<Cache>>,
    echo: EchoHandle,
    nodes: Vec<AppleTalkAddress>,
    sweep_gen: Arc<AtomicU64>,
    my_sweep: u64,
) {
    if nodes.is_empty() {
        return;
    }
    // Set from the UI thread on each pass. A closed window still upgrades (the
    // caller holds it open for re-showing), so this is what tells us to stop.
    let open = Arc::new(AtomicBool::new(true));

    loop {
        for &addr in &nodes {
            if sweep_gen.load(Ordering::SeqCst) != my_sweep || !open.load(Ordering::SeqCst) {
                return;
            }
            let stats = quick_ping(&echo, addr).await;

            let weak = weak.clone();
            let discovered = discovered.clone();
            let cache = cache.clone();
            let sweep_gen = sweep_gen.clone();
            let open = open.clone();
            let posted = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                open.store(w.window().is_visible(), Ordering::SeqCst);
                if sweep_gen.load(Ordering::SeqCst) != my_sweep {
                    return;
                }
                set_node_latency(&w, &discovered, &cache, addr, &stats);
            });
            if posted.is_err() {
                return; // the Slint event loop is gone, so the app is closing
            }
        }

        {
            let weak = weak.clone();
            let sweep_gen = sweep_gen.clone();
            slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade()
                    && sweep_gen.load(Ordering::SeqCst) == my_sweep
                    && !w.get_busy()
                    && w.get_status_text().ends_with("Measuring latency…")
                {
                    w.set_status_text("Ready.".into());
                }
            })
            .ok();
        }

        tokio::time::sleep(LATENCY_REFRESH).await;
    }
}

/// What one poll produced: either a whole new set of family rows, or just a new
/// Condition line for families whose other rows this poll can't refresh.
enum PollUpdate {
    Rows(Vec<Line>),
    Condition(String),
}

/// Start the PAP status poller for `device`, if its family has one.
///
/// A LaserWriter and an ImageWriter both answer a status request without a PAP
/// connection being opened, so this is cheap enough to run while the device is
/// selected. It is what keeps a once-queried printer's status current, and is
/// started on every selection - including one served entirely from the cache.
#[allow(clippy::too_many_arguments, reason = "one call site per selection path")]
fn start_status_poller(
    rt: &tokio::runtime::Handle,
    weak: &Weak<NetworkExplorerWindow>,
    discovered: &Arc<Mutex<Vec<Device>>>,
    cache: &Arc<Mutex<Cache>>,
    index: usize,
    device: &Device,
    ddp: &DdpHandle,
    generation: &Arc<AtomicU64>,
    my_gen: u64,
) {
    if !matches!(device.kind, DeviceKind::LaserWriter | DeviceKind::ImageWriter) {
        return;
    }
    let weak = weak.clone();
    let discovered = discovered.clone();
    let cache = cache.clone();
    let generation = generation.clone();
    let ddp = ddp.clone();
    let addr = device.atp_addr();
    let kind = device.kind;

    // Set from the UI thread on each tick. A closed window still upgrades (the
    // caller holds it open for re-showing), so without this the poller would
    // keep questioning the printer every five seconds for the life of the app.
    let open = Arc::new(AtomicBool::new(true));

    rt.spawn(async move {
        let status_socket = PapStatusHandle::new(&ddp, addr).await;
        let imagewriter = imagewriter::StatusHandle::from(status_socket.clone());
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.tick().await; // the initial query already left a fresh status
        loop {
            ticker.tick().await;
            if generation.load(Ordering::SeqCst) != my_gen || !open.load(Ordering::SeqCst) {
                return;
            }
            let update = match kind {
                // Every ImageWriter row comes from the status word, so replace
                // them all rather than leaving the raw reply showing an older
                // reading than the Condition line above it.
                DeviceKind::ImageWriter => {
                    imagewriter.read().await.map(|s| PollUpdate::Rows(imagewriter_lines(&s)))
                }
                // A LaserWriter's other rows come from PostScript queries this
                // poll doesn't run, so only the condition is refreshed.
                _ => status_socket.read_text().await.map(|s| {
                    PollUpdate::Condition(if s.is_empty() {
                        "No status string returned".to_string()
                    } else {
                        s
                    })
                }),
            };

            let weak = weak.clone();
            let discovered = discovered.clone();
            let cache = cache.clone();
            let generation = generation.clone();
            let open = open.clone();
            let posted = slint::invoke_from_event_loop(move || {
                let Some(w) = weak.upgrade() else { return };
                open.store(w.window().is_visible(), Ordering::SeqCst);
                if generation.load(Ordering::SeqCst) != my_gen {
                    return;
                }
                // The poll updates what is cached, not what is on screen, so a
                // later re-render (a latency sweep, a re-selection) carries the
                // fresh status rather than reverting to the query-time one.
                {
                    let mut cache = cache.lock().unwrap();
                    let Some(q) = cache.queries.get_mut(&index) else { return };
                    match update {
                        Ok(PollUpdate::Rows(lines)) => q.lines = lines,
                        Ok(PollUpdate::Condition(s)) => set_condition(&mut q.lines, s),
                        Err(e) => set_condition(&mut q.lines, format!("Unavailable: {e}")),
                    }
                }
                render_panel(&w, &discovered, &cache, index);
            });
            if posted.is_err() {
                return; // the Slint event loop is gone, so the app is closing
            }
        }
    });
}

/// Overwrite a cached query's Condition row.
fn set_condition(lines: &mut [Line], text: String) {
    if let Some(line) = lines.iter_mut().find(|l| !l.section && l.label == "Condition") {
        line.value = text;
    }
}

/// Rebuild the whole information panel for one row out of the cache: what NBP
/// said, then whatever the family query returned. Latency is deliberately not
/// here - the sidebar already carries it, and the panel would only repeat it.
///
/// Every path that changes either half re-renders through here, so the panel
/// can never show a mix of one refresh and another.
fn render_panel(
    w: &NetworkExplorerWindow,
    discovered: &Mutex<Vec<Device>>,
    cache: &Mutex<Cache>,
    index: usize,
) {
    let Some(device) = discovered.lock().unwrap().get(index).cloned() else {
        return;
    };
    let family = cache.lock().unwrap().queries.get(&index).map(|q| q.lines.clone());

    let mut lines = directory_lines(&device);
    lines.extend(family.unwrap_or_default());
    w.set_info_rows(to_model(lines));
}

/// Push a LaserWriter's queried settings into the editable controls. The other
/// families report none, and leave the name field on the NBP name.
fn apply_settings(
    w: &NetworkExplorerWindow,
    discovered: &Mutex<Vec<Device>>,
    index: usize,
    settings: Option<&LaserSettings>,
) {
    let Some(s) = settings else { return };
    w.set_paper_index(s.paper_index);
    w.set_startup_enabled(s.startup_enabled);
    if !s.printer_name.is_empty() {
        w.set_edit_name(s.printer_name.as_str().into());
        rename_row(w, discovered, index, &s.printer_name);
    }
}

/// Record a fresh round-trip reading and write it into every sidebar row sitting
/// on `addr`. A node advertising several services has one row each, and they all
/// share the one measurement.
fn set_node_latency(
    w: &NetworkExplorerWindow,
    discovered: &Mutex<Vec<Device>>,
    cache: &Mutex<Cache>,
    addr: AppleTalkAddress,
    stats: &PingStats,
) {
    cache
        .lock()
        .unwrap()
        .latency
        .insert((addr.network_number, addr.node_number), *stats);

    let (text, ok) = latency_text(stats);
    let devices = discovered.lock().unwrap();
    let model = w.get_devices();
    for (i, device) in devices.iter().enumerate() {
        if device.net != addr.network_number || device.node != addr.node_number {
            continue;
        }
        let Some(mut row) = model.row_data(i) else { continue };
        row.latency = text.as_str().into();
        row.latency_ok = ok;
        model.set_row_data(i, row);
    }
}

/// Seed a freshly discovered list from readings the sweep already took, so a
/// refresh doesn't blank every latency back to a placeholder while it re-probes.
fn apply_cached_latency(
    w: &NetworkExplorerWindow,
    discovered: &Mutex<Vec<Device>>,
    cache: &Mutex<Cache>,
) {
    let devices = discovered.lock().unwrap();
    let cache = cache.lock().unwrap();
    let model = w.get_devices();
    for (i, device) in devices.iter().enumerate() {
        let Some(stats) = cache.latency.get(&(device.net, device.node)) else {
            continue;
        };
        let Some(mut row) = model.row_data(i) else { continue };
        let (text, ok) = latency_text(stats);
        row.latency = text.as_str().into();
        row.latency_ok = ok;
        model.set_row_data(i, row);
    }
}

/// Push a run's figures into the four stat tiles.
fn show_ping_stats(w: &NetworkExplorerWindow, stats: &PingStats) {
    w.set_ping_average(format_opt_ms(stats.average()).into());
    w.set_ping_fastest(format_opt_ms(stats.fastest).into());
    w.set_ping_slowest(format_opt_ms(stats.slowest).into());
    w.set_ping_loss(format!("{:.0}%", stats.loss_percent()).into());
}

/// Reset the ping figures to their placeholders, so a run's numbers never linger
/// over another device. The tiles stay on screen either way.
fn clear_ping_results(w: &NetworkExplorerWindow) {
    w.set_ping_average("—".into());
    w.set_ping_fastest("—".into());
    w.set_ping_slowest("—".into());
    w.set_ping_loss("—".into());
    w.set_ping_status("".into());
}

/// Show the device's real name in the sidebar row and our cached entry, so a
/// rename appears without waiting for the next NBP refresh.
fn rename_row(
    w: &NetworkExplorerWindow,
    discovered: &Mutex<Vec<Device>>,
    index: usize,
    name: &str,
) {
    if let Some(d) = discovered.lock().unwrap().get_mut(index) {
        d.name = name.to_string();
    }
    let model = w.get_devices();
    if let Some(mut row) = model.row_data(index)
        && row.name.as_str() != name
    {
        row.name = name.into();
        model.set_row_data(index, row);
    }
}

/// Flip the window into the busy state with a status message. Runs on the UI thread.
fn begin_busy(weak: &Weak<NetworkExplorerWindow>, status: &str) {
    if let Some(w) = weak.upgrade() {
        w.set_busy(true);
        w.set_status_text(status.into());
    }
}

/// Set only the status line (no busy toggle). Runs on the UI thread.
fn set_status(weak: &Weak<NetworkExplorerWindow>, status: &str) {
    if let Some(w) = weak.upgrade() {
        w.set_status_text(status.into());
    }
}

/// Marshal a Save result back to the window.
///
/// A save changes what a query would return, so the cached one for that row is
/// dropped either way. When `requery` is set the query is also re-run at once,
/// so the panel shows the values that actually persisted - unless the user has
/// moved on to another device in the meantime.
fn finish_save(
    weak: Weak<NetworkExplorerWindow>,
    cache: Arc<Mutex<Cache>>,
    index: i32,
    result: anyhow::Result<String>,
    requery: bool,
) {
    slint::invoke_from_event_loop(move || {
        let Some(w) = weak.upgrade() else { return };
        w.set_busy(false);
        match result {
            Ok(msg) => {
                cache.lock().unwrap().queries.remove(&(index as usize));
                w.set_status_text(msg.into());
                if requery && index == w.get_selected() {
                    w.invoke_query(index);
                }
            }
            Err(e) => w.set_status_text(format!("Save failed: {e}").into()),
        }
    })
    .ok();
}
