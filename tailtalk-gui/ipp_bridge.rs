/// A super hacky IPP bridge that exposes LaserWriter printers on the local network via
/// mDNS/Bonjour and accepts IPP print jobs from macOS/iOS. I built this around making my
/// LaserWriter 4/600 PS accessible via my Mac, and iOS devices for printing. Pretty sure
/// it should work on other systems as it exposes a standard IPP interface and uses PostScript
/// queries to figure out printer capabilities, but I haven't tested beyond the single one I have.
///
/// The other part of this I found is that modern prints tend to generate _enormous_ PostScript files,
/// and these are both slow to send to the printer and take significant time ot process (on the order of 5-10 minutes).
/// With this we now pre-rasterize the PostScript to a smaller PostScript file (with rasterized pages) before sending
/// to the printer, which is much faster - it typically starts printing as soon as the job is fully sent.
/// The rasterization is done via Ghostscript, which must be installed on the system for this to work.
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read as _, Write as _},
    net::IpAddr,
    sync::{Arc, atomic::{AtomicU32, Ordering}},
    time::{Duration, Instant},
};

use axum::{Router, body::Bytes, extract::{Path, State}, routing::post};
use ipp::{parser::IppParser, prelude::*, reader::IppReader};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tailtalk::{
    CancellationToken,
    adsp::AdspAddress,
    atp::{Atp, AtpAddress},
    ddp::DdpHandle,
    nbp::NbpHandle,
    pap::PapClient,
    stylewriter::{
        PrintQuality, PrinterBusy, SW2200_PRINT_ROWBYTES, SW2200_PRINT_WIDTH,
        StyleWriterSession, encode_page_batches,
    },
};
use tailtalk_packets::nbp::{EntityName, ServiceAddress};
use tokio::sync::{Mutex, RwLock};

// Standard media sizes supported by all LaserWriters.
const STANDARD_MEDIA: &[&str] = &[
    "na_letter_8.5x11in",
    "na_legal_8.5x14in",
    "iso_a4_210x297mm",
    "iso_b5_176x250mm",
    "na_executive_7.25x10.5in",
    "na_number-10_4.125x9.5in",
    "na_monarch_3.875x7.5in",
    "iso_c5_162x229mm",
    "iso_dl_110x220mm",
];

// Extra sizes the StyleWriter's sheet feeder handles beyond STANDARD_MEDIA.
// "invoice" is the PWG self-describing name for half letter / statement.
const STYLEWRITER_EXTRA_MEDIA: &[&str] = &[
    "na_invoice_5.5x8.5in",
];

#[derive(Clone, Debug, PartialEq)]
enum JobState {
    Processing,
    Completed,
    Aborted,
}

impl JobState {
    fn ipp_enum(&self) -> i32 {
        match self { Self::Processing => 5, Self::Completed => 9, Self::Aborted => 8 }
    }
    fn ipp_reason(&self) -> &'static str {
        match self { Self::Processing => "job-printing", Self::Completed => "none", Self::Aborted => "aborted-by-system" }
    }
}

#[derive(Clone, Debug)]
struct JobRecord {
    id: u32,
    printer_key: String,
    uri: String,
    state: JobState,
    state_message: String,
    impressions_completed: i32,
    created_at: u32,
}

/// Which AppleTalk print path a discovered printer uses.
#[derive(Clone, Copy, Debug, PartialEq)]
enum PrinterKind {
    /// PostScript printer driven over PAP (NBP type "LaserWriter").
    LaserWriter,
    /// Color StyleWriter behind an EtherTalk adapter, driven over ADSP
    /// (NBP type "ColorStyleWriter2400AT").
    StyleWriter,
}

/// StyleWriters print at a fixed 360 dpi.
const SW_DPI: u32 = 360;
/// Printable-area margins at 360 dpi (lpstyl `printerSetup()` for the CS
/// family): 72 px (9 bytes) left, 90 px top and bottom.
const SW_LEFT_MARGIN_PX: usize = 72;
const SW_TOP_MARGIN_ROWS: usize = 90;
const SW_BOTTOM_MARGIN_ROWS: usize = 90;

#[derive(Clone)]
struct PrinterCaps {
    dpi: u32,
    color: bool,
    model: String,
    /// IPP PWG media name for the paper currently loaded.
    media_default: String,
    /// IPP `media-source` keywords for each input tray.
    tray_sources: Vec<String>,
}

impl Default for PrinterCaps {
    fn default() -> Self {
        PrinterCaps {
            dpi: 600,
            color: false,
            model: "Apple LaserWriter 4/600 PS".to_string(),
            media_default: "na_letter_8.5x11in".to_string(),
            tray_sources: vec!["main".into(), "manual".into()],
        }
    }
}

#[derive(Clone)]
struct Printer {
    name: String,
    kind: PrinterKind,
    addr: ServiceAddress,
    key: String,
    mdns_fullname: String,
    caps: PrinterCaps,
}

impl Printer {
    /// The DDP endpoint viewed as an ADSP address (StyleWriter path).
    fn adsp_addr(&self) -> AdspAddress {
        self.addr.into()
    }
}

struct BridgeState {
    printers: Arc<RwLock<Vec<Printer>>>,
    ddp: DdpHandle,
    jobs: RwLock<HashMap<u32, Arc<Mutex<JobRecord>>>>,
    next_job_id: AtomicU32,
    start_time: Instant,
    /// Per-printer locks (keyed by printer key) serialising print sessions:
    /// LaserWriters accept one PAP connection at a time (and connect() gives
    /// up after 60s of busy-retries); StyleWriters likewise hold a single
    /// ADSP print connection. Concurrent jobs must queue here.
    job_locks: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

pub async fn run(nbp: NbpHandle, ddp: DdpHandle, token: CancellationToken) {
    let printers: Arc<RwLock<Vec<Printer>>> = Arc::new(RwLock::new(Vec::new()));

    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("IPP bridge: failed to create mDNS daemon: {e}");
            return;
        }
    };

    let ddp2 = ddp.clone();
    let nbp2 = nbp.clone();
    let printers2 = printers.clone();
    let mdns2 = mdns.clone();
    let token2 = token.clone();

    discover(&nbp, &ddp, &printers, &mdns).await;

    let state = Arc::new(BridgeState {
        printers: printers.clone(),
        ddp,
        jobs: RwLock::new(HashMap::new()),
        next_job_id: AtomicU32::new(1),
        start_time: Instant::now(),
        job_locks: std::sync::Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/ipp/{key}", post(handle_ipp))
        .fallback(|uri: axum::http::Uri, method: axum::http::Method, body: Bytes| async move {
            tracing::warn!("IPP: unmatched request {method} {uri} ({} bytes)", body.len());
            axum::response::Response::builder().status(404).body(axum::body::Body::empty()).unwrap()
        })
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:8631").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("IPP bridge: failed to bind port 8631: {e}");
            return;
        }
    };

    tracing::info!("IPP bridge: listening on port 8631");

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = token2.cancelled() => break,
                _ = interval.tick() => discover(&nbp2, &ddp2, &printers2, &mdns2).await,
            }
        }
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { token.cancelled().await })
        .await
        .ok();

    let lock = printers.read().await;
    for p in lock.iter() {
        if let Ok(rx) = mdns.unregister(&p.mdns_fullname) {
            drop(rx);
        }
    }
    drop(lock);
    // Stop the mdns-sd background thread; dropping the handle alone leaks it,
    // and the bridge is respawned with a fresh daemon on every server start.
    let _ = mdns.shutdown();
}

/// Non-loopback IPv4 addresses; avoids 127.0.0.1 appearing in mDNS advertisements.
fn local_ipv4_addrs() -> Vec<IpAddr> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .filter_map(|iface| {
            if let if_addrs::IfAddr::V4(ref v4) = iface.addr {
                Some(IpAddr::V4(v4.ip))
            } else {
                None
            }
        })
        .collect()
}

fn make_key(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[allow(dead_code)]
fn urf_string(caps: &PrinterCaps) -> String {
    // CP1 = sRGB profile 1 (required by AirPrint spec; CP255 is not valid).
    // We always advertise SRGB24 so iOS sends colour jobs; ghostscript converts to mono.
    format!("W8,SRGB24,CP1,RS{}", caps.dpi)
}

/// IPP endpoint key for a discovered printer: name slug + AppleTalk address,
/// plus a "-sw" tag for StyleWriters. The address keeps two identically-named
/// devices on different nodes from colliding on one /ipp/{key} route; the tag
/// keeps a LaserWriter and StyleWriter that share a name apart.
fn printer_key(kind: PrinterKind, name: &str, addr: ServiceAddress) -> String {
    let key = make_key(name);
    let a = format!("{}-{}-{}", addr.network_number, addr.node_number, addr.socket_number);
    match kind {
        PrinterKind::LaserWriter => format!("{key}-{a}"),
        PrinterKind::StyleWriter => format!("{key}-{a}-sw"),
    }
}

async fn discover(
    nbp: &NbpHandle,
    ddp: &DdpHandle,
    printers: &Arc<RwLock<Vec<Printer>>>,
    mdns: &ServiceDaemon,
) {
    // (kind, NBP type pattern) for each supported printer family.
    let lookups: [(PrinterKind, &str); 2] = [
        (PrinterKind::LaserWriter, "=:LaserWriter@*"),
        (PrinterKind::StyleWriter, "=:ColorStyleWriter2400AT@*"),
    ];

    let entities: Vec<(PrinterKind, EntityName)> = lookups
        .iter()
        .filter_map(|(kind, pattern)| match (*pattern).try_into() {
            Ok(e) => Some((*kind, e)),
            Err(e) => { tracing::error!("IPP bridge: bad entity name '{pattern}': {e}"); None }
        })
        .collect();

    let mut tuples: Vec<(PrinterKind, tailtalk_packets::nbp::NbpTuple)> = Vec::new();
    // If the lookup errors, keep the existing registrations rather than
    // pruning them on a transient failure.
    let mut lookup_ok: Vec<PrinterKind> = Vec::new();
    // Both name patterns go out as one concurrent batch, sharing a single
    // NBP reply-collection window.
    let names: Vec<EntityName> = entities.iter().map(|(_, e)| e.clone()).collect();
    match nbp.lookup_many(names).await {
        Ok(results) => {
            for ((kind, _), found) in entities.iter().zip(results) {
                tracing::info!("IPP bridge: found {} {kind:?}(s)", found.len());
                lookup_ok.push(*kind);
                tuples.extend(found.into_iter().map(|t| (*kind, t)));
            }
        }
        Err(e) => tracing::warn!("IPP bridge: NBP lookup failed: {e}"),
    }

    let new_keys: HashSet<String> = tuples.iter()
        .filter(|(_, t)| !make_key(&t.entity_name.object).is_empty())
        .map(|(kind, t)| printer_key(*kind, &t.entity_name.object, t.service_address()))
        .collect();

    // Prune vanished printers under a short-lived write lock, then release it:
    // query_printer_caps can block for over a minute on a busy/unreachable
    // printer, and every IPP handler takes printers.read() first.
    let mut current_keys: HashSet<String> = {
        let mut current = printers.write().await;
        current.retain(|p| {
            if new_keys.contains(&p.key) || !lookup_ok.contains(&p.kind) {
                true
            } else {
                if let Ok(rx) = mdns.unregister(&p.mdns_fullname) { drop(rx); }
                false
            }
        });
        current.iter().map(|p| p.key.clone()).collect()
    };

    // Names that appear on more than one device this cycle. The mDNS instance
    // name must be unique, so those get disambiguated by address below.
    let mut name_counts: HashMap<&str, usize> = HashMap::new();
    for (_, t) in &tuples {
        *name_counts.entry(t.entity_name.object.as_str()).or_default() += 1;
    }

    for (kind, tuple) in &tuples {
        let kind = *kind;
        let name = tuple.entity_name.object.clone();
        let addr = tuple.service_address();
        let key = printer_key(kind, &name, addr);
        if make_key(&name).is_empty() || current_keys.contains(&key) {
            continue;
        }

        let caps = match kind {
            PrinterKind::LaserWriter => query_printer_caps(ddp, addr.into()).await,
            PrinterKind::StyleWriter => {
                match query_stylewriter_caps(ddp, addr.into()).await {
                    Ok(caps) => caps,
                    Err(e) if e.downcast_ref::<PrinterBusy>().is_some() => {
                        // Someone is printing; retry on the next discovery
                        // cycle rather than registering with guessed caps.
                        tracing::info!("IPP bridge: StyleWriter '{name}' is busy, deferring registration");
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("IPP bridge: StyleWriter caps query for '{name}' failed ({e}), using defaults");
                        default_stylewriter_caps()
                    }
                }
            }
        };

        // When two devices share a name, the mDNS instance name (which must be
        // unique) gets an address tag so both show up; unique names stay clean.
        let instance_name = if name_counts.get(name.as_str()).copied().unwrap_or(0) > 1 {
            format!("{name} ({}-{})", addr.network_number, addr.node_number)
        } else {
            name.clone()
        };

        let hostname = format!("tailtalk-{key}.local.");
        let rp = format!("ipp/{key}");
        let product = format!("({})", caps.model);

        #[cfg(not(target_os = "windows"))]
        let urf = urf_string(&caps);

        let mut props: Vec<(&str, &str)> = vec![
            ("rp", rp.as_str()),
            ("ty", name.as_str()),
            ("product", product.as_str()),
            ("Color", if caps.color { "T" } else { "F" }),
            ("qtotal", "1"),
            ("txtvers", "1"),
        ];
        #[cfg(not(target_os = "windows"))]
        {
            props.push(("pdl", "image/urf,application/pdf,application/postscript"));
            props.push(("URF", urf.as_str()));
        }
        #[cfg(target_os = "windows")]
        props.push(("pdl", "application/pdf,application/postscript"));

        let addrs = local_ipv4_addrs();
        let service_info = match ServiceInfo::new("_universal._sub._ipp._tcp.local.", &instance_name, &hostname, addrs.as_slice(), 8631u16, &props[..]) {
            Ok(si) => si,
            Err(e) => { tracing::warn!("IPP bridge: ServiceInfo error for '{name}': {e}"); continue; }
        };

        let mdns_fullname = service_info.get_fullname().to_string();

        if let Err(e) = mdns.register(service_info) {
            tracing::warn!("IPP bridge: mDNS register failed for '{name}': {e}");
            continue;
        }

        tracing::info!(
            "IPP bridge: registered '{name}' → /ipp/{key} ({}dpi, color={}, default={})",
            caps.dpi, caps.color, caps.media_default,
        );
        current_keys.insert(key.clone());
        printers.write().await.push(Printer { name, kind, addr, key, mdns_fullname, caps });
    }

}

/// Fallback caps when a StyleWriter is discovered but its info query fails.
/// Assume color: a color job on a black cartridge is refused cleanly at
/// setup time ('H' check), whereas advertising mono-only would permanently
/// hide a working color printer.
fn default_stylewriter_caps() -> PrinterCaps {
    PrinterCaps {
        dpi: SW_DPI,
        color: true,
        model: "Apple Color StyleWriter".to_string(),
        media_default: "na_letter_8.5x11in".to_string(),
        tray_sources: vec!["main".into()],
    }
}

/// Query a StyleWriter's model and installed cartridge over a short-lived
/// ADSP session (no page is fed). Propagates [`PrinterBusy`] so the caller
/// can defer registration instead of guessing.
async fn query_stylewriter_caps(ddp: &DdpHandle, addr: AdspAddress) -> anyhow::Result<PrinterCaps> {
    let mut session = StyleWriterSession::connect(ddp, addr, "TailTalk").await?;
    let info = session.query_info().await;
    let _ = session.abort().await;
    let info = info?;

    tracing::info!(
        "IPP bridge: StyleWriter identity '{}' submodel {:?} cartridge={}",
        info.identity,
        info.submodel,
        if info.color_cartridge { "color" } else { "black" },
    );

    Ok(PrinterCaps {
        dpi: SW_DPI,
        color: info.color_capable(),
        model: info.model_name().to_string(),
        ..default_stylewriter_caps()
    })
}

/// Query printer capabilities via the PostScript Query Protocol.
async fn query_printer_caps(ddp: &DdpHandle, addr: AtpAddress) -> PrinterCaps {
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
         { currentpagedevice /ColorDevice get = } stopped { false = } if\n\
         { currentpagedevice /InputAttributes get length = } stopped { 1 = } if\n\
         { currentpagedevice /ManualFeed known = } stopped { false = } if\n\
         flush\n\
         %%EOF\n";

    let result: anyhow::Result<PrinterCaps> = async {
        let (_, req, resp) = Atp::spawn(ddp, None).await;
        let mut client = PapClient::new(req, resp);
        client.connect(addr).await?;
        client.print_stream(Cursor::new(job.as_bytes())).await?;
        let response_bytes = tokio::time::timeout(
            Duration::from_secs(15),
            client.read_response(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("PAP query timed out"))??;
        client.close().await?;

        let response = String::from_utf8_lossy(&response_bytes);
        let mut lines = response.lines().filter(|l| !l.trim_start().starts_with("%%["));

        // Line 0: product name
        let raw_model = lines.next().unwrap_or("").trim().to_string();
        let model = raw_model.trim_matches(|c| c == '(' || c == ')').to_string();

        let _ = lines.next(); // Line 1: PS version
        let _ = lines.next(); // Line 2: firmware revision

        // Line 3: resolution (integer, or "w h" array)
        let resolution_line = lines.next().unwrap_or("300").trim().to_string();
        let dpi = resolution_line.split_whitespace()
            .next()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(300);

        let _ = lines.next(); // Line 4: RAM
        let _ = lines.next(); // Line 5: page count

        // Line 6: page size in points
        let page_size_line = lines.next().unwrap_or("").trim().to_string();
        let media_default = parse_pts_to_media(&page_size_line)
            .to_string();

        let _ = lines.next(); // Line 7: AppleTalk type

        // Line 8: ColorDevice
        let color = lines.next().unwrap_or("false").trim() == "true";

        // Line 9: InputAttributes length (cassette count)
        let cassette_count = lines.next().unwrap_or("1").trim()
            .parse::<u32>().unwrap_or(1);

        // Line 10: ManualFeed supported
        let has_manual = lines.next().unwrap_or("false").trim() == "true";

        let mut tray_sources: Vec<String> = Vec::new();
        if cassette_count >= 1 { tray_sources.push("main".into()); }
        if cassette_count >= 2 { tray_sources.push("alternate".into()); }
        if has_manual           { tray_sources.push("manual".into()); }
        if tray_sources.is_empty() { tray_sources.push("main".into()); }

        Ok(PrinterCaps {
            dpi,
            color,
            model: if model.is_empty() || model == "error" {
                "LaserWriter".to_string()
            } else {
                model
            },
            media_default,
            tray_sources,
        })
    }
    .await;

    result.unwrap_or_else(|e| {
        tracing::warn!("IPP bridge: caps query failed ({e}), using defaults");
        PrinterCaps::default()
    })
}

/// Map a PostScript page-size string ("w h ") to the closest IPP PWG media name.
fn parse_pts_to_media(pts: &str) -> &'static str {
    let mut nums = pts.split_whitespace().filter_map(|s| s.parse::<f32>().ok());
    let (Some(w), Some(h)) = (nums.next(), nums.next()) else {
        return "na_letter_8.5x11in";
    };
    // Tolerance of 5 points covers rounding in printer firmware.
    let known: &[(f32, f32, &str)] = &[
        (612.0, 792.0,  "na_letter_8.5x11in"),
        (612.0, 1008.0, "na_legal_8.5x14in"),
        (595.0, 842.0,  "iso_a4_210x297mm"),
        (516.0, 729.0,  "iso_b5_176x250mm"),
        (522.0, 756.0,  "na_executive_7.25x10.5in"),
        (297.0, 684.0,  "na_number-10_4.125x9.5in"),
        (279.0, 540.0,  "na_monarch_3.875x7.5in"),
        (459.0, 649.0,  "iso_c5_162x229mm"),
        (312.0, 624.0,  "iso_dl_110x220mm"),
    ];
    for &(pw, ph, name) in known {
        if (w - pw).abs() < 5.0 && (h - ph).abs() < 5.0 {
            return name;
        }
    }
    "na_letter_8.5x11in"
}

fn ipp_bytes(resp: IppRequestResponse) -> axum::response::Response {
    let bytes = resp.to_bytes();
    axum::response::Response::builder()
        .header("content-type", "application/ipp")
        .body(axum::body::Body::from(bytes))
        .unwrap()
}

fn ipp_status(req_id: u32, status: StatusCode) -> axum::response::Response {
    match IppRequestResponse::new_response(IppVersion::v1_1(), status, req_id) {
        Ok(r) => ipp_bytes(r),
        Err(_) => axum::response::Response::new(axum::body::Body::empty()),
    }
}

fn ipp_ok(req_id: u32) -> axum::response::Response {
    ipp_status(req_id, StatusCode::SuccessfulOk)
}

fn job_created_response(job_id: u32, job_uri: &str, req_id: u32) -> axum::response::Response {
    let mut resp = match IppRequestResponse::new_response(IppVersion::v1_1(), StatusCode::SuccessfulOk, req_id) {
        Ok(r) => r,
        Err(_) => return axum::response::Response::new(axum::body::Body::empty()),
    };
    let mut add = |name: &str, val: IppValue| {
        if let Ok(a) = IppAttribute::with_name(name, val) {
            resp.attributes_mut().add(DelimiterTag::JobAttributes, a);
        }
    };
    add("job-id", IppValue::Integer(job_id as i32));
    if let Ok(u) = job_uri.try_into() { add("job-uri", IppValue::Uri(u)); }
    add("job-state", IppValue::Enum(JobState::Processing.ipp_enum()));
    if let Ok(k) = JobState::Processing.ipp_reason().try_into() {
        add("job-state-reasons", IppValue::Keyword(k));
    }
    ipp_bytes(resp)
}

fn job_attributes_response(job: &JobRecord, req_id: u32) -> axum::response::Response {
    let mut resp = match IppRequestResponse::new_response(IppVersion::v1_1(), StatusCode::SuccessfulOk, req_id) {
        Ok(r) => r,
        Err(_) => return axum::response::Response::new(axum::body::Body::empty()),
    };
    let mut add = |name: &str, val: IppValue| {
        if let Ok(a) = IppAttribute::with_name(name, val) {
            resp.attributes_mut().add(DelimiterTag::JobAttributes, a);
        }
    };
    add("job-id", IppValue::Integer(job.id as i32));
    if let Ok(u) = job.uri.as_str().try_into() { add("job-uri", IppValue::Uri(u)); }
    add("job-state", IppValue::Enum(job.state.ipp_enum()));
    if let Ok(k) = job.state.ipp_reason().try_into() {
        add("job-state-reasons", IppValue::Keyword(k));
    }
    if let Ok(t) = job.state_message.as_str().try_into() {
        add("job-state-message", IppValue::TextWithoutLanguage(t));
    }
    add("job-impressions-completed", IppValue::Integer(job.impressions_completed));
    add("time-at-creation", IppValue::Integer(job.created_at as i32));
    ipp_bytes(resp)
}

fn get_jobs_response(jobs: &[JobRecord], req_id: u32) -> axum::response::Response {
    let mut resp = match IppRequestResponse::new_response(IppVersion::v1_1(), StatusCode::SuccessfulOk, req_id) {
        Ok(r) => r,
        Err(_) => return axum::response::Response::new(axum::body::Body::empty()),
    };
    for job in jobs {
        let mut add = |name: &str, val: IppValue| {
            if let Ok(a) = IppAttribute::with_name(name, val) {
                resp.attributes_mut().add(DelimiterTag::JobAttributes, a);
            }
        };
        add("job-id", IppValue::Integer(job.id as i32));
        if let Ok(u) = job.uri.as_str().try_into() { add("job-uri", IppValue::Uri(u)); }
        add("job-state", IppValue::Enum(job.state.ipp_enum()));
        if let Ok(k) = job.state.ipp_reason().try_into() {
            add("job-state-reasons", IppValue::Keyword(k));
        }
    }
    ipp_bytes(resp)
}

/// Extract job-id from operation attributes, trying `job-id` (integer) then
/// the trailing path component of `job-uri`.
fn extract_job_id(parsed: &IppRequestResponse) -> Option<u32> {
    parsed.attributes()
        .groups_of(DelimiterTag::OperationAttributes)
        .next()
        .and_then(|g| {
            if let Some(a) = g.attributes().get("job-id")
                && let IppValue::Integer(id) = a.value() {
                    return Some(*id as u32);
                }
            if let Some(a) = g.attributes().get("job-uri")
                && let IppValue::Uri(u) = a.value() {
                    return u.as_str().rsplit('/').next()?.parse::<u32>().ok();
                }
            None
        })
}

async fn handle_ipp(
    State(state): State<Arc<BridgeState>>,
    Path(key): Path<String>,
    body: Bytes,
) -> axum::response::Response {
    let reader = IppReader::new(Cursor::new(body.to_vec()));
    let mut parsed = match IppParser::new(reader).parse() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("IPP: parse error: {e}");
            return axum::response::Response::builder()
                .status(400)
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    let op = parsed.header().operation_or_status;
    let req_id = parsed.header().request_id;
    tracing::debug!("IPP: op=0x{op:04x} req_id={req_id} key={key}");

    let printer = {
        let lock = state.printers.read().await;
        lock.iter().find(|p| p.key == key).cloned()
    };

    let printer = match printer {
        Some(p) => p,
        None => return ipp_status(req_id, StatusCode::ClientErrorNotFound),
    };

    match op {
        op if op == Operation::GetPrinterAttributes as u16 => {
            printer_attributes(&printer, req_id)
        }
        op if op == Operation::PrintJob as u16 => {
            let job_id = state.next_job_id.fetch_add(1, Ordering::Relaxed);
            let job_uri = format!("ipp://localhost:8631/ipp/{}/{job_id}", printer.key);
            let created_at = state.start_time.elapsed().as_secs() as u32;
            let job = Arc::new(Mutex::new(JobRecord {
                id: job_id,
                printer_key: printer.key.clone(),
                uri: job_uri.clone(),
                state: JobState::Processing,
                state_message: "Received".to_string(),
                impressions_completed: 0,
                created_at,
            }));
            {
                let mut jobs = state.jobs.write().await;
                let uptime = state.start_time.elapsed().as_secs();
                jobs.retain(|_, arc| {
                    if let Ok(j) = arc.try_lock() {
                        j.state == JobState::Processing
                            || uptime.saturating_sub(j.created_at as u64) < 3600
                    } else {
                        true
                    }
                });
                jobs.insert(job_id, job.clone());
            }

            let fmt = doc_format(&parsed);
            let tray = job_media_source(&parsed);
            let mut doc = Vec::new();
            parsed.payload_mut().read_to_end(&mut doc).ok();
            tracing::info!("IPP: PrintJob id={job_id} fmt={fmt:?} doc_bytes={} tray={tray:?}", doc.len());

            let ddp = state.ddp.clone();
            let job_lock = {
                let mut locks = state.job_locks.lock().unwrap();
                locks.entry(printer.key.clone()).or_default().clone()
            };
            match printer.kind {
                PrinterKind::LaserWriter => {
                    let addr: AtpAddress = printer.addr.into();
                    let dpi = printer.caps.dpi;
                    tokio::spawn(async move {
                        job.lock().await.state_message = "Rasterizing".to_string();
                        let (ps, page_count) = match rasterize_to_ps(doc, &fmt, &tray, dpi, job_id).await {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::error!("IPP: rasterize failed: {e}");
                                let mut j = job.lock().await;
                                j.state = JobState::Aborted;
                                j.state_message = format!("Rasterize failed: {e}");
                                return;
                            }
                        };
                        tracing::info!("IPP: rasterized {page_count} page(s) to {} bytes PS", ps.len());
                        job.lock().await.state_message = "Waiting for printer".to_string();
                        let _pap_guard = job_lock.lock().await;
                        job.lock().await.state_message = "Printing".to_string();
                        match print_to_pap(ddp, addr, ps).await {
                            Ok(printer_output) => {
                                let mut j = job.lock().await;
                                j.impressions_completed = page_count as i32;
                                if let Some(err) = parse_printer_error(&printer_output) {
                                    tracing::warn!("IPP: job {job_id} printer error: {err}");
                                    j.state = JobState::Aborted;
                                    j.state_message = err;
                                } else {
                                    j.state = JobState::Completed;
                                    j.state_message = "Completed".to_string();
                                }
                            }
                            Err(e) => {
                                tracing::error!("IPP: job {job_id} PAP error: {e}");
                                let mut j = job.lock().await;
                                j.state = JobState::Aborted;
                                j.state_message = format!("PAP error: {e}");
                            }
                        }
                    });
                }
                PrinterKind::StyleWriter => {
                    // Mono jobs take the K-only path even on a color cartridge:
                    // true black beats CMY-composite gray and saves the color inks.
                    let color = printer.caps.color
                        && job_color_mode(&parsed).as_deref() != Some("monochrome");
                    let quality = match job_print_quality(&parsed) {
                        Some(5) => PrintQuality::Best,
                        _ => PrintQuality::Normal,
                    };
                    let username = job_user_name(&parsed)
                        .unwrap_or_else(|| "TailTalk".to_string());
                    let addr = printer.adsp_addr();
                    tracing::info!(
                        "IPP: StyleWriter job {job_id}: color={color} quality={quality:?} user={username}"
                    );
                    tokio::spawn(run_stylewriter_job(
                        job, ddp, addr, doc, fmt, color, quality, username, job_lock, job_id,
                    ));
                }
            }
            job_created_response(job_id, &job_uri, req_id)
        }
        op if op == Operation::ValidateJob as u16 => ipp_ok(req_id),
        op if op == Operation::CancelJob as u16 => ipp_ok(req_id),
        op if op == Operation::GetJobAttributes as u16 => {
            let job_id = extract_job_id(&parsed);
            match job_id {
                None => ipp_status(req_id, StatusCode::ClientErrorBadRequest),
                Some(id) => {
                    let arc = state.jobs.read().await.get(&id).cloned();
                    match arc {
                        None => ipp_status(req_id, StatusCode::ClientErrorNotFound),
                        Some(arc) => {
                            let j = arc.lock().await;
                            job_attributes_response(&j, req_id)
                        }
                    }
                }
            }
        }
        op if op == Operation::GetJobs as u16 => {
            let key = printer.key.clone();
            let arcs: Vec<Arc<Mutex<JobRecord>>> =
                state.jobs.read().await.values().cloned().collect();
            let mut snapshots = Vec::new();
            for arc in arcs {
                let j = arc.lock().await;
                if j.printer_key == key { snapshots.push(j.clone()); }
            }
            get_jobs_response(&snapshots, req_id)
        }
        _ => {
            tracing::debug!("IPP: unsupported operation 0x{op:04x}");
            ipp_status(req_id, StatusCode::ServerErrorOperationNotSupported)
        }
    }
}

/// Deterministic UUID URN derived from the printer key.
/// Stable across restarts so PrintKit can identify the same printer session.
fn printer_uuid(key: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h1 = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut h1);
    "tailtalk-ipp".hash(&mut h1);
    let lo = h1.finish();
    let mut h2 = std::collections::hash_map::DefaultHasher::new();
    "tailtalk-ipp".hash(&mut h2);
    key.len().hash(&mut h2);
    let hi = h2.finish();
    let b = ((hi as u128) << 64) | lo as u128;
    let bytes = b.to_be_bytes();
    format!(
        "urn:uuid:{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0FFF,
        (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3FFF) | 0x8000,
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]),
    )
}

fn printer_attributes(printer: &Printer, req_id: u32) -> axum::response::Response {
    let mut resp = match IppRequestResponse::new_response(
        IppVersion::v1_1(),
        StatusCode::SuccessfulOk,
        req_id,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("IPP: response build error: {e}");
            return axum::response::Response::new(axum::body::Body::empty());
        }
    };

    let uri = format!("ipp://localhost:8631/ipp/{}", printer.key);
    let caps = &printer.caps;

    // A StyleWriter with a black cartridge really is monochrome-only; the
    // LaserWriter path always accepts color input (ghostscript converts).
    let color_modes: &[&str] = match printer.kind {
        PrinterKind::StyleWriter if !caps.color => &["monochrome"],
        _ => &["auto", "color", "monochrome"],
    };
    let color_mode_default = if printer.kind == PrinterKind::StyleWriter && caps.color {
        "auto"
    } else {
        "monochrome"
    };
    // StyleWriter quality maps to the printer's own mode string (normal/best);
    // draft has no known string, so it isn't offered there.
    let qualities: &[i32] = match printer.kind {
        PrinterKind::LaserWriter => &[3, 4, 5],
        PrinterKind::StyleWriter => &[4, 5],
    };

    let mut add = |name: &str, val: IppValue| {
        if let Ok(a) = IppAttribute::with_name(name, val) {
            resp.attributes_mut().add(DelimiterTag::PrinterAttributes, a);
        }
    };

    if let Ok(u) = uri.as_str().try_into() {
        add("printer-uri-supported", IppValue::Uri(u));
    }
    if let Ok(k) = "none".try_into() { add("uri-security-supported", IppValue::Keyword(k)); }
    if let Ok(k) = "none".try_into() { add("uri-authentication-supported", IppValue::Keyword(k)); }
    if let Ok(n) = printer.name.as_str().try_into() {
        add("printer-name", IppValue::NameWithoutLanguage(n));
    }
    if let Ok(n) = caps.model.as_str().try_into() {
        add("printer-make-and-model", IppValue::NameWithoutLanguage(n));
    }

    // printer-kind: required by PrintKit; include "photo" so Photos.app accepts the printer.
    {
        let kinds: Vec<IppValue> = ["document", "photo"].iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("printer-kind", IppValue::Array(kinds));
    }
    // printer-uuid: stable identifier; PrintKit loops on GetPrinterAttributes without it.
    let uuid_urn = printer_uuid(&printer.key);
    if let Ok(u) = uuid_urn.as_str().try_into() {
        add("printer-uuid", IppValue::Uri(u));
    }
    if let Ok(n) = printer.name.as_str().try_into() {
        add("printer-dns-sd-name", IppValue::NameWithoutLanguage(n));
    }
    if let Ok(t) = "".try_into() { add("printer-location", IppValue::TextWithoutLanguage(t)); }
    // output-mode-supported: older Apple attribute; synonym for print-color-mode-supported.
    {
        let modes: Vec<IppValue> = color_modes.iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("output-mode-supported", IppValue::Array(modes));
    }
    add("pages-per-minute", IppValue::Integer(
        match printer.kind { PrinterKind::LaserWriter => 8, PrinterKind::StyleWriter => 1 },
    ));
    add("pdf-k-octets-supported", IppValue::RangeOfInteger { min: 1, max: 65535 });
    add("jpeg-k-octets-supported", IppValue::RangeOfInteger { min: 1, max: 65535 });
    add("printer-state", IppValue::Enum(3)); // idle
    if let Ok(k) = "none".try_into() { add("printer-state-reasons", IppValue::Keyword(k)); }
    if let Ok(k) = "1.1".try_into() { add("ipp-versions-supported", IppValue::Keyword(k)); }
    add("operations-supported", IppValue::Array(vec![
        IppValue::Enum(Operation::PrintJob as i32),
        IppValue::Enum(Operation::ValidateJob as i32),
        IppValue::Enum(Operation::CancelJob as i32),
        IppValue::Enum(Operation::GetJobAttributes as i32),
        IppValue::Enum(Operation::GetJobs as i32),
        IppValue::Enum(Operation::GetPrinterAttributes as i32),
    ]));
    if let Ok(c) = "utf-8".try_into() { add("charset-configured", IppValue::Charset(c)); }
    if let Ok(c) = "utf-8".try_into() { add("charset-supported", IppValue::Charset(c)); }
    if let Ok(l) = "en".try_into() { add("natural-language-configured", IppValue::NaturalLanguage(l)); }
    if let Ok(l) = "en".try_into() { add("generated-natural-language-supported", IppValue::NaturalLanguage(l)); }
    if let Ok(m) = "application/pdf".try_into() {
        add("document-format-default", IppValue::MimeMediaType(m));
    }
    {
        #[cfg(not(target_os = "windows"))]
        let fmts = ["application/pdf", "application/postscript", "image/urf", "application/octet-stream"];
        #[cfg(target_os = "windows")]
        let fmts = ["application/pdf", "application/postscript", "application/octet-stream"];
        let vals: Vec<IppValue> = fmts.iter().copied()
            .filter_map(|f| f.try_into().ok())
            .map(IppValue::MimeMediaType)
            .collect();
        add("document-format-supported", IppValue::Array(vals));
    }
    #[cfg(not(target_os = "windows"))]
    {
        let urf_str = urf_string(caps);
        let urf_caps: Vec<&str> = urf_str.split(',').collect();
        let vals: Vec<IppValue> = urf_caps.iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("urf-supported", IppValue::Array(vals));
    }

    add("printer-resolution-default", IppValue::Resolution {
        cross_feed: caps.dpi as i32,
        feed: caps.dpi as i32,
        units: 3, // dots per inch
    });
    add("printer-resolution-supported", IppValue::Resolution {
        cross_feed: caps.dpi as i32,
        feed: caps.dpi as i32,
        units: 3,
    });

    {
        let mut media: Vec<&str> = STANDARD_MEDIA.to_vec();
        if printer.kind == PrinterKind::StyleWriter {
            media.extend_from_slice(STYLEWRITER_EXTRA_MEDIA);
        }
        let vals: Vec<IppValue> = media.into_iter()
            .filter_map(|m| m.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("media-supported", IppValue::Array(vals));
    }
    if let Ok(k) = caps.media_default.as_str().try_into() {
        add("media-default", IppValue::Keyword(k));
    }

    if !caps.tray_sources.is_empty() {
        let vals: Vec<IppValue> = caps.tray_sources.iter()
            .filter_map(|s| s.as_str().try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("media-source-supported", IppValue::Array(vals));
    }
    if let Ok(k) = "main".try_into() {
        add("media-source-default", IppValue::Keyword(k));
    }

    // Colour capability: the bridge converts via ghostscript so we always accept
    // colour input, but report whether the physical device produces colour output.
    add("color-supported", IppValue::Boolean(caps.color));

    // RFC 8011 required job-template attributes.
    add("copies-default", IppValue::Integer(1));
    add("copies-supported", IppValue::RangeOfInteger { min: 1, max: 99 });
    add("finishings-default", IppValue::Enum(3)); // 3 = none
    add("finishings-supported", IppValue::Enum(3));
    add("page-ranges-supported", IppValue::Boolean(false));
    add("sides-default", IppValue::Keyword("one-sided".try_into().unwrap()));
    add("sides-supported", IppValue::Keyword("one-sided".try_into().unwrap()));
    add("print-quality-default", IppValue::Enum(4)); // 4 = normal
    {
        let vals: Vec<IppValue> = qualities.iter().map(|&q| IppValue::Enum(q)).collect();
        add("print-quality-supported", IppValue::Array(vals));
    }
    // macOS Photos checks print-color-mode-supported before queuing photo jobs.
    {
        let modes: Vec<IppValue> = color_modes.iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("print-color-mode-supported", IppValue::Array(modes));
    }
    if let Ok(k) = color_mode_default.try_into() {
        add("print-color-mode-default", IppValue::Keyword(k));
    }

    add("printer-is-accepting-jobs", IppValue::Boolean(true));
    add("queued-job-count", IppValue::Integer(0));
    if let Ok(k) = "not-attempted".try_into() {
        add("pdl-override-supported", IppValue::Keyword(k));
    }
    add("printer-up-time", IppValue::Integer(1));
    if let Ok(k) = "none".try_into() { add("compression-supported", IppValue::Keyword(k)); }

    ipp_bytes(resp)
}

fn doc_format(parsed: &IppRequestResponse) -> String {
    parsed.attributes()
        .groups_of(DelimiterTag::OperationAttributes)
        .next()
        .and_then(|g| g.attributes().get("document-format"))
        .and_then(|a| {
            if let IppValue::MimeMediaType(m) = a.value() {
                Some(m.as_str().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

/// Extract the `media-source` job attribute, defaulting to `"main"`.
fn job_media_source(parsed: &IppRequestResponse) -> String {
    parsed.attributes()
        .groups_of(DelimiterTag::JobAttributes)
        .next()
        .and_then(|g| g.attributes().get("media-source"))
        .and_then(|a| {
            if let IppValue::Keyword(k) = a.value() {
                Some(k.as_str().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "main".to_string())
}

/// Extract the requested color mode: `print-color-mode`, falling back to the
/// older Apple `output-mode` synonym.
fn job_color_mode(parsed: &IppRequestResponse) -> Option<String> {
    let group = parsed.attributes()
        .groups_of(DelimiterTag::JobAttributes)
        .next()?;
    for name in ["print-color-mode", "output-mode"] {
        if let Some(a) = group.attributes().get(name)
            && let IppValue::Keyword(k) = a.value() {
                return Some(k.as_str().to_string());
            }
    }
    None
}

/// Extract the `print-quality` job attribute (3=draft, 4=normal, 5=high).
fn job_print_quality(parsed: &IppRequestResponse) -> Option<i32> {
    parsed.attributes()
        .groups_of(DelimiterTag::JobAttributes)
        .next()
        .and_then(|g| g.attributes().get("print-quality"))
        .and_then(|a| match a.value() {
            IppValue::Enum(v) | IppValue::Integer(v) => Some(*v),
            _ => None,
        })
}

/// Extract `requesting-user-name` (sent to the StyleWriter in its
/// print-request handshake, where the real Mac driver sends the chooser name).
fn job_user_name(parsed: &IppRequestResponse) -> Option<String> {
    parsed.attributes()
        .groups_of(DelimiterTag::OperationAttributes)
        .next()
        .and_then(|g| g.attributes().get("requesting-user-name"))
        .and_then(|a| match a.value() {
            IppValue::NameWithoutLanguage(n) => Some(n.as_str().to_string()),
            IppValue::TextWithoutLanguage(t) => Some(t.to_string()),
            _ => None,
        })
}

/// Convert `image/urf` to a format gs can rasterize.
/// On macOS uses `sips` to produce PDF; on Linux uses `ippeveps` to produce PostScript.
/// Both outputs are accepted by the gs pbmraw call downstream.
async fn urf_to_rasterizable(data: Vec<u8>, job_token: u32) -> anyhow::Result<Vec<u8>> {
    let tmp = std::env::temp_dir();
    let urf_path = tmp.join(format!("tailtalk-{job_token}.urf"));
    tokio::fs::write(&urf_path, &data).await?;

    #[cfg(target_os = "macos")]
    return {
        let pdf_path = tmp.join(format!("tailtalk-{job_token}.pdf"));
        let status = tokio::process::Command::new("sips")
            .args(["--setProperty", "format", "pdf"])
            .arg(&urf_path)
            .arg("--out")
            .arg(&pdf_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await?;
        let _ = tokio::fs::remove_file(&urf_path).await;
        anyhow::ensure!(status.success(), "sips URF→PDF failed: {}", status);
        let pdf = tokio::fs::read(&pdf_path).await?;
        let _ = tokio::fs::remove_file(&pdf_path).await;
        Ok(pdf)
    };

    #[cfg(target_os = "linux")]
    return {
        // ippeveps converts URF → PostScript; gs accepts PS from a file just as well as PDF.
        let output = tokio::process::Command::new("ippeveps")
            .arg(&urf_path)
            .env("CONTENT_TYPE", "image/urf")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await?;
        let _ = tokio::fs::remove_file(&urf_path).await;
        anyhow::ensure!(output.status.success(), "ippeveps URF→PS failed: {}", output.status);
        Ok(output.stdout)
    };

    // URF conversion is not supported on Windows; the magic-byte sniff in rasterize_to_ps
    // should never reach here because URF is not advertised in the mDNS record on Windows,
    // but guard against it explicitly.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = tokio::fs::remove_file(&urf_path).await;
        anyhow::bail!("URF format is not supported on this platform");
    }
}

/// Return the name of the Ghostscript executable on this platform.
/// On Windows, Ghostscript may be installed as `gswin64c` or `gswin32c`
/// rather than `gs`; try each in order and return the first one found.
fn gs_command() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        for candidate in &["gswin64c", "gswin32c", "gs"] {
            if std::process::Command::new(candidate)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return candidate;
            }
        }
        "gswin64c" // fall through to a named binary so the error message is useful
    }
    #[cfg(not(target_os = "windows"))]
    "gs"
}

/// Returns true if a usable Ghostscript executable is found on this platform.
pub fn gs_probe() -> bool {
    #[cfg(target_os = "windows")]
    {
        // gs_command() already probes all candidates; if it falls through to the
        // default name without finding anything, a --version call will fail.
        for candidate in &["gswin64c", "gswin32c", "gs"] {
            if std::process::Command::new(candidate)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::process::Command::new("gs")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Rasterize a PDF/PS/URF document with Ghostscript to a raw raster device
/// (`pbmraw`, `ppmraw`, …) at `dpi`, returning the concatenated raw pages.
async fn gs_raster(mut data: Vec<u8>, fmt: &str, device: &str, dpi: u32, job_token: u32) -> anyhow::Result<Vec<u8>> {
    // Track whether urf_to_rasterizable ran — on Linux it returns PostScript, not PDF.
    let is_urf = fmt == "image/urf" || data.starts_with(b"UNIRAST");
    if is_urf {
        data = urf_to_rasterizable(data, job_token).await?;
    }

    // Raw raster devices cannot write to stdout, so use a temp file.
    let tmp = std::env::temp_dir();
    let out_path = tmp.join(format!("tailtalk-rip-{job_token}.{device}"));
    let res_arg = format!("-r{dpi}");
    let dev_arg = format!("-sDEVICE={device}");

    // Use .ps extension when we know the content is PostScript (Linux ippeveps output),
    // .pdf otherwise. gs content-sniffs regardless, but the correct extension avoids
    // confusion when the input file is retained for post-mortem debugging.
    #[cfg(target_os = "linux")]
    let input_ext = if is_urf { "ps" } else { "pdf" };
    #[cfg(not(target_os = "linux"))]
    let input_ext = "pdf";
    let input_path = tmp.join(format!("tailtalk-in-{job_token}.{input_ext}"));
    tokio::fs::write(&input_path, &data).await?;

    let output = tokio::process::Command::new(gs_command())
        // Pass -sOutputFile as a separate -o arg so the OS handles path quoting,
        // avoiding issues with spaces in the temp directory path on Windows.
        .args(["-dNOPAUSE", "-dBATCH", "-dSAFER", &dev_arg, &res_arg, "-o"])
        .arg(&out_path)
        .arg(&input_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Keep the input file around for post-mortem; clean up the (possibly partial) raster.
        let _ = tokio::fs::remove_file(&out_path).await;
        anyhow::bail!(
            "gs {device} exited with {} (input kept at {})\nstderr: {}\nstdout: {}",
            output.status,
            input_path.display(),
            stderr.trim(),
            stdout.trim(),
        );
    }
    let _ = tokio::fs::remove_file(&input_path).await;

    let raster = tokio::fs::read(&out_path).await;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(raster?)
}

// gs pbmraw → per-page PS Level-2 image; most reliable path for classic LaserWriter firmware.
async fn rasterize_to_ps(data: Vec<u8>, fmt: &str, tray_source: &str, dpi: u32, job_token: u32) -> anyhow::Result<(Vec<u8>, usize)> {
    if fmt == "application/postscript" || fmt == "application/vnd.cups-postscript" {
        let page_count = data.windows(7).filter(|w| *w == b"%%Page:").count().max(1);
        return Ok((data, page_count));
    }

    let pbm = gs_raster(data, fmt, "pbmraw", dpi, job_token).await?;
    let pages = parse_pbm_pages(&pbm)?;
    anyhow::ensure!(!pages.is_empty(), "gs produced no pages");

    let page_count = pages.len();
    Ok((build_ps_raster(&pages, dpi, tray_source), page_count))
}

/// One page of raw planar StyleWriter scanlines: rows → planes (1 for mono,
/// C/M/Y/K for color) → plane bytes (1 bit per pixel, MSB first, 1 = ink).
type PlanarPage = Vec<Vec<Vec<u8>>>;

/// Rasterize a document for the StyleWriter at 360 dpi and crop each page
/// to the printable window (lpstyl's margins for the CS family).
async fn rasterize_for_stylewriter(data: Vec<u8>, fmt: &str, color: bool, job_token: u32) -> anyhow::Result<Vec<PlanarPage>> {
    let device = if color { "ppmraw" } else { "pbmraw" };
    let raster = gs_raster(data, fmt, device, SW_DPI, job_token).await?;
    let pages: Vec<PlanarPage> = if color {
        parse_ppm_pages(&raster)?
            .into_iter()
            .map(|(w, h, rgb)| ppm_page_to_planar(w, h, &rgb))
            .collect()
    } else {
        parse_pbm_pages(&raster)?
            .into_iter()
            .map(|(w, h, bits)| pbm_page_to_planar(w, h, &bits))
            .collect()
    };
    anyhow::ensure!(!pages.is_empty(), "gs produced no pages");
    Ok(pages)
}

/// Number of printable rows for a page of `h` rows: skip the top margin and
/// stop above the bottom margin (lpstyl: PRINT_HEIGHT = height - (TOP +
/// BOTTOM + 1)). Returns the top offset and one-past-the-end row.
fn sw_printable_rows(h: usize) -> (usize, usize) {
    let top = SW_TOP_MARGIN_ROWS.min(h);
    let bottom = h.saturating_sub(SW_BOTTOM_MARGIN_ROWS + 1).max(top);
    (top, bottom)
}

/// Crop a full-page 360 dpi PBM raster to the printable window, returning
/// per-row single-plane scanlines. PBM bit 1 = black = deposit ink, which is
/// exactly the K-plane sense — no inversion needed.
fn pbm_page_to_planar(w: u32, h: u32, bits: &[u8]) -> PlanarPage {
    let row_bytes = (w as usize).div_ceil(8);
    let left_bytes = SW_LEFT_MARGIN_PX / 8; // 72 px: exactly byte-aligned
    let take = SW2200_PRINT_ROWBYTES.min(row_bytes.saturating_sub(left_bytes));
    let (top, bottom) = sw_printable_rows(h as usize);
    let mut rows = Vec::with_capacity(bottom - top);
    for y in top..bottom {
        let start = y * row_bytes + left_bytes;
        rows.push(vec![bits[start..start + take].to_vec()]);
    }
    rows
}

/// Crop a full-page 360 dpi RGB raster to the printable window and
/// Floyd–Steinberg dither it into C/M/Y 1-bit planes.
///
/// The K plane stays empty: with a color cartridge the printer deposits no
/// ink for the K plane at all, so black must be composited from C+M+Y
/// (undercolor removal 0 — see to_bitcmyk.py, verified on a real SW2200
/// where UCR-moved black simply vanished from the page).
fn ppm_page_to_planar(w: u32, h: u32, rgb: &[u8]) -> PlanarPage {
    let (w, h) = (w as usize, h as usize);
    let left = SW_LEFT_MARGIN_PX.min(w);
    let print_w = (w - left).min(SW2200_PRINT_WIDTH);
    let (top, bottom) = sw_printable_rows(h);
    let plane_bytes = print_w.div_ceil(8).max(1);

    // Floyd–Steinberg error buffers for the C/M/Y channels, padded one
    // pixel each side so diffusion needs no bounds checks.
    let mut err_cur = vec![[0.0f32; 3]; print_w + 2];
    let mut err_next = vec![[0.0f32; 3]; print_w + 2];

    let mut rows = Vec::with_capacity(bottom - top);
    for y in top..bottom {
        let mut planes = vec![vec![0u8; plane_bytes]; 4];
        for x in 0..print_w {
            let px = (y * w + left + x) * 3;
            for ch in 0..3 {
                // RGB → CMY: ink = 255 - value (R→C, G→M, B→Y).
                let want = (255 - rgb[px + ch]) as f32 + err_cur[x + 1][ch];
                let on = want >= 127.5;
                if on {
                    planes[ch][x / 8] |= 0x80 >> (x % 8);
                }
                let e = want - if on { 255.0 } else { 0.0 };
                err_cur[x + 2][ch] += e * (7.0 / 16.0);
                err_next[x][ch] += e * (3.0 / 16.0);
                err_next[x + 1][ch] += e * (5.0 / 16.0);
                err_next[x + 2][ch] += e * (1.0 / 16.0);
            }
        }
        rows.push(planes);
        std::mem::swap(&mut err_cur, &mut err_next);
        for e in err_next.iter_mut() {
            *e = [0.0; 3];
        }
    }
    rows
}

/// Connect to a StyleWriter, retrying while it reports busy — another host
/// may hold the print connection, or it may still be ejecting the previous
/// page of this very job.
async fn connect_stylewriter(ddp: &DdpHandle, addr: AdspAddress, username: &str) -> anyhow::Result<StyleWriterSession> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    loop {
        match StyleWriterSession::connect(ddp, addr, username).await {
            Err(e) if e.downcast_ref::<PrinterBusy>().is_some()
                && tokio::time::Instant::now() < deadline =>
            {
                tracing::debug!("IPP: StyleWriter busy, retrying in 5s");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            other => return other,
        }
    }
}

/// Print one page over a fresh ADSP session (connect → setup → bands →
/// finish); on failure the abort path ejects any loaded page and resets the
/// printer so the paper path isn't left wedged.
async fn print_stylewriter_page(
    ddp: &DdpHandle,
    addr: AdspAddress,
    rows: &PlanarPage,
    color: bool,
    quality: PrintQuality,
    username: &str,
) -> anyhow::Result<()> {
    let batches = encode_page_batches(rows, !color);
    let mut session = connect_stylewriter(ddp, addr, username).await?;
    let result: anyhow::Result<()> = async {
        session.setup(color, quality).await?;
        for batch in &batches {
            session.write_batch(batch.top, batch.bottom, &batch.data, color).await?;
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => session.finish().await,
        Err(e) => {
            let _ = session.abort().await;
            Err(e)
        }
    }
}

/// Full StyleWriter job pipeline: rasterize + dither, queue behind any job
/// already printing (per-printer lock), then print page by page.
#[allow(clippy::too_many_arguments)]
async fn run_stylewriter_job(
    job: Arc<Mutex<JobRecord>>,
    ddp: DdpHandle,
    addr: AdspAddress,
    doc: Vec<u8>,
    fmt: String,
    color: bool,
    quality: PrintQuality,
    username: String,
    job_lock: Arc<Mutex<()>>,
    job_id: u32,
) {
    job.lock().await.state_message = "Rasterizing".to_string();
    let pages = match rasterize_for_stylewriter(doc, &fmt, color, job_id).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("IPP: StyleWriter job {job_id} rasterize failed: {e}");
            let mut j = job.lock().await;
            j.state = JobState::Aborted;
            j.state_message = format!("Rasterize failed: {e}");
            return;
        }
    };
    tracing::info!("IPP: StyleWriter job {job_id}: {} page(s) rasterized", pages.len());

    job.lock().await.state_message = "Waiting for printer".to_string();
    let _guard = job_lock.lock().await;
    for (i, rows) in pages.iter().enumerate() {
        job.lock().await.state_message = format!("Printing page {} of {}", i + 1, pages.len());
        if let Err(e) = print_stylewriter_page(&ddp, addr, rows, color, quality, &username).await {
            tracing::error!("IPP: StyleWriter job {job_id} failed on page {}: {e:#}", i + 1);
            let mut j = job.lock().await;
            j.state = JobState::Aborted;
            j.state_message = format!("Print failed on page {}: {e:#}", i + 1);
            return;
        }
        job.lock().await.impressions_completed = (i + 1) as i32;
    }
    let mut j = job.lock().await;
    j.state = JobState::Completed;
    j.state_message = "Completed".to_string();
}

/// Parse one or more concatenated P4 (binary PBM) images from `data`.
fn parse_pbm_pages(data: &[u8]) -> anyhow::Result<Vec<(u32, u32, Vec<u8>)>> {
    let mut pages = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Some((w, h, header_len)) = parse_pbm_header(&data[pos..]) else { break };
        let row_bytes = (w as usize).div_ceil(8);
        let page_bytes = row_bytes * h as usize;
        let data_start = pos + header_len;
        let data_end = data_start + page_bytes;
        if data_end > data.len() { break; }
        pages.push((w, h, data[data_start..data_end].to_vec()));
        pos = data_end;
    }
    Ok(pages)
}

/// Parse one or more concatenated P6 (binary PPM, maxval 255) images from `data`.
fn parse_ppm_pages(data: &[u8]) -> anyhow::Result<Vec<(u32, u32, Vec<u8>)>> {
    let mut pages = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let Some((w, h, header_len)) = parse_ppm_header(&data[pos..]) else { break };
        let page_bytes = w as usize * h as usize * 3;
        let data_start = pos + header_len;
        let data_end = data_start + page_bytes;
        if data_end > data.len() { break; }
        pages.push((w, h, data[data_start..data_end].to_vec()));
        pos = data_end;
    }
    Ok(pages)
}

/// Parse a P4 (binary PBM) header starting at `data[0]`.
fn parse_pbm_header(data: &[u8]) -> Option<(u32, u32, usize)> {
    parse_pnm_header(data, b'4', false)
}

/// Parse a P6 (binary PPM) header starting at `data[0]`; only maxval 255 is accepted.
fn parse_ppm_header(data: &[u8]) -> Option<(u32, u32, usize)> {
    parse_pnm_header(data, b'6', true)
}

/// Parse a binary PNM header (`P<magic>`, width, height, optional maxval)
/// starting at `data[0]`, returning (width, height, header length).
fn parse_pnm_header(data: &[u8], magic: u8, has_maxval: bool) -> Option<(u32, u32, usize)> {
    if data.first() != Some(&b'P') || data.get(1) != Some(&magic) { return None; }
    let mut pos = 2;

    let skip = |data: &[u8], pos: &mut usize| {
        loop {
            while *pos < data.len() && matches!(data[*pos], b' ' | b'\t' | b'\r' | b'\n') {
                *pos += 1;
            }
            if *pos < data.len() && data[*pos] == b'#' {
                while *pos < data.len() && data[*pos] != b'\n' { *pos += 1; }
            } else {
                break;
            }
        }
    };

    let read_u32 = |data: &[u8], pos: &mut usize| -> Option<u32> {
        skip(data, pos);
        let start = *pos;
        while *pos < data.len() && data[*pos].is_ascii_digit() { *pos += 1; }
        if *pos == start { return None; }
        std::str::from_utf8(&data[start..*pos]).ok()?.parse().ok()
    };

    let w = read_u32(data, &mut pos)?;
    let h = read_u32(data, &mut pos)?;
    if has_maxval && read_u32(data, &mut pos)? != 255 { return None; }
    if pos >= data.len() { return None; }
    pos += 1; // mandatory single whitespace after the last header field
    Some((w, h, pos))
}

/// PackBits (PostScript RunLengthDecode) encoder.
fn encode_runlength(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let mut run = 1;
        while i + run < data.len() && data[i + run] == b && run < 128 { run += 1; }
        if run >= 2 {
            out.push((257 - run) as u8);
            out.push(b);
            i += run;
        } else {
            let lit_start = i;
            i += 1;
            while i < data.len() && (i - lit_start) < 128 {
                let mut ahead = 1;
                while i + ahead < data.len() && data[i + ahead] == data[i] && ahead < 128 { ahead += 1; }
                if ahead >= 3 { break; }
                i += 1;
            }
            let lit_len = i - lit_start;
            out.push((lit_len - 1) as u8);
            out.extend_from_slice(&data[lit_start..i]);
        }
    }
    out.push(0x80); // EOD
    out
}

// LaserWriter 4/600 fw 2014.107 crashes on multi-level filter chains (e.g. CCITTFax) — ASCIIHex only.
fn encode_asciihex(data: &[u8]) -> Vec<u8> {
    const BYTES_PER_LINE: usize = 38;
    let mut out = Vec::with_capacity(data.len() * 2 + data.len() / BYTES_PER_LINE + 2);
    for chunk in data.chunks(BYTES_PER_LINE) {
        for byte in chunk {
            let hi = byte >> 4;
            let lo = byte & 0xF;
            out.push(if hi < 10 { b'0' + hi } else { b'A' + hi - 10 });
            out.push(if lo < 10 { b'0' + lo } else { b'A' + lo - 10 });
        }
        out.push(b'\n');
    }
    out.push(b'>');
    out.push(b'\n');
    out
}

/// Assemble a multi-page PS document from rasterized PBM pages.
fn build_ps_raster(pages: &[(u32, u32, Vec<u8>)], dpi: u32, tray_source: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = writeln!(out, "%!PS-Adobe-3.0");
    let _ = writeln!(out, "%%LanguageLevel: 2");
    let _ = writeln!(out, "%%Pages: {}", pages.len());
    let _ = writeln!(out, "%%EndComments");
    match tray_source {
        "manual" => {
            let _ = writeln!(out, "%%BeginSetup");
            let _ = writeln!(out, "<< /ManualFeed true >> setpagedevice");
            let _ = writeln!(out, "%%EndSetup");
        }
        "alternate" => {
            let _ = writeln!(out, "%%BeginSetup");
            let _ = writeln!(out, "<< /MediaPosition 1 >> setpagedevice");
            let _ = writeln!(out, "%%EndSetup");
        }
        _ => {}
    }
    for (i, (width, height, bitmap)) in pages.iter().enumerate() {
        let (width, height) = (*width, *height);
        let pts_w = width as f64 * 72.0 / dpi as f64;
        let pts_h = height as f64 * 72.0 / dpi as f64;
        let _ = writeln!(out, "%%Page: {} {}", i + 1, i + 1);
        let _ = writeln!(out, "gsave");
        let _ = writeln!(out, "{pts_w:.4} {pts_h:.4} scale");
        let _ = writeln!(out, "{width} {height} 1");
        // Matrix: map [0..1 × 0..1] to pixel coords, flip Y so row 0 → top of page.
        let _ = writeln!(out, "[ {width} 0 0 -{height} 0 {height} ]");
        let _ = writeln!(out, "currentfile /ASCIIHexDecode filter /RunLengthDecode filter");
        let _ = writeln!(out, "image");
        // PBM: 1 = black; PostScript image: 1 = white — invert.
        let inverted: Vec<u8> = bitmap.iter().map(|b| !b).collect();
        let compressed = encode_runlength(&inverted);
        out.extend_from_slice(&encode_asciihex(&compressed));
        let _ = writeln!(out, "grestore");
        let _ = writeln!(out, "showpage");
    }
    let _ = writeln!(out, "%%EOF");
    out
}

async fn print_to_pap(ddp: DdpHandle, addr: AtpAddress, doc: Vec<u8>) -> anyhow::Result<String> {
    if doc.is_empty() {
        tracing::warn!("IPP: empty document, skipping print");
        return Ok(String::new());
    }
    let (_, req, resp) = Atp::spawn(&ddp, None).await;
    let mut pap = PapClient::new(req, resp);
    pap.connect(addr).await?;
    pap.print_stream(Cursor::new(doc)).await?;
    let output_bytes = tokio::time::timeout(Duration::from_secs(15), pap.read_response())
        .await
        .unwrap_or_else(|_| Ok(vec![]))?;
    pap.close().await?;
    let output = String::from_utf8_lossy(&output_bytes).into_owned();
    if !output.trim().is_empty() {
        tracing::info!("IPP: printer output: {output}");
    }
    Ok(output)
}

/// Returns the PS error string from `%%[ Error: ]%%` lines; ignores `PrinterError`/`LastError`.
fn parse_printer_error(output: &str) -> Option<String> {
    output.lines()
        .map(|l| l.trim())
        .find(|l| l.starts_with("%%[ Error:"))
        .map(|l| l.trim_start_matches("%%[").trim_end_matches("]%%").trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ppm_pages_concatenated() {
        // Header shape matches real gs ppmraw output, including the comment
        // line between the magic and the dimensions.
        let mut data = Vec::new();
        for fill in [0u8, 255u8] {
            data.extend_from_slice(b"P6\n# Image generated by GPL Ghostscript (device=ppmraw)\n4 2\n255\n");
            data.extend_from_slice(&[fill; 4 * 2 * 3]);
        }
        let pages = parse_ppm_pages(&data).unwrap();
        assert_eq!(pages.len(), 2);
        assert_eq!((pages[0].0, pages[0].1), (4, 2));
        assert!(pages[0].2.iter().all(|&b| b == 0));
        assert!(pages[1].2.iter().all(|&b| b == 255));
    }

    #[test]
    fn test_sw_printable_rows() {
        // Letter at 360 dpi: 3960 rows → lpstyl's PRINT_HEIGHT = 3960 - 181.
        let (top, bottom) = sw_printable_rows(3960);
        assert_eq!(top, SW_TOP_MARGIN_ROWS);
        assert_eq!(bottom - top, 3960 - 181);
        // Degenerate tiny page must not underflow.
        let (top, bottom) = sw_printable_rows(50);
        assert!(bottom >= top);
    }

    #[test]
    fn test_pbm_page_to_planar_crop() {
        // 2 printable rows on a page just tall enough to have them; row bytes
        // beyond the left margin land at byte offset 9.
        let w = 3060u32; // letter width at 360 dpi
        let h = (SW_TOP_MARGIN_ROWS + SW_BOTTOM_MARGIN_ROWS + 3) as u32;
        let row_bytes = (w as usize).div_ceil(8);
        let mut bits = vec![0u8; row_bytes * h as usize];
        let printable_row = SW_TOP_MARGIN_ROWS;
        bits[printable_row * row_bytes + SW_LEFT_MARGIN_PX / 8] = 0xAB;
        let rows = pbm_page_to_planar(w, h, &bits);
        assert_eq!(rows.len(), 2); // h - (top + bottom + 1)
        assert_eq!(rows[0].len(), 1); // single K plane
        assert_eq!(rows[0][0].len(), SW2200_PRINT_ROWBYTES.min(row_bytes - 9));
        assert_eq!(rows[0][0][0], 0xAB);
        assert!(rows[1][0].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_ppm_page_to_planar_dither_extremes() {
        let w = 200u32;
        let h = (SW_TOP_MARGIN_ROWS + SW_BOTTOM_MARGIN_ROWS + 5) as u32;
        // Pure black page: every C/M/Y bit inside the printable window must
        // be set (composite black), and the K plane must stay empty.
        let black = vec![0u8; (w * h * 3) as usize];
        let rows = pbm_like_bits(&ppm_page_to_planar(w, h, &black), w as usize);
        for (c, m, y, k) in rows {
            assert!(c && m && y, "black page must dither to solid CMY");
            assert!(!k, "K plane must stay empty in color mode");
        }
        // Pure white page: no ink anywhere.
        let white = vec![255u8; (w * h * 3) as usize];
        for planes in ppm_page_to_planar(w, h, &white) {
            for plane in planes {
                assert!(plane.iter().all(|&b| b == 0));
            }
        }
    }

    /// Collapse a dithered page to per-plane "any ink missing / any ink present"
    /// flags over the printable pixel span (ignores byte padding bits).
    fn pbm_like_bits(page: &PlanarPage, w: usize) -> Vec<(bool, bool, bool, bool)> {
        let print_w = (w - SW_LEFT_MARGIN_PX).min(SW2200_PRINT_WIDTH);
        page.iter()
            .map(|planes| {
                let all_set = |p: &Vec<u8>| (0..print_w).all(|x| p[x / 8] & (0x80 >> (x % 8)) != 0);
                let any_set = |p: &Vec<u8>| (0..print_w).any(|x| p[x / 8] & (0x80 >> (x % 8)) != 0);
                (all_set(&planes[0]), all_set(&planes[1]), all_set(&planes[2]), any_set(&planes[3]))
            })
            .collect()
    }
}
