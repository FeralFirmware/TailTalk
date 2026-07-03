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
use tailtalk::{atp::{Atp, AtpAddress}, ddp::DdpHandle, nbp::NbpHandle, pap::PapClient, CancellationToken};
use tailtalk_packets::nbp::EntityName;
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
    addr: AtpAddress,
    key: String,
    mdns_fullname: String,
    caps: PrinterCaps,
}

struct BridgeState {
    printers: Arc<RwLock<Vec<Printer>>>,
    ddp: DdpHandle,
    jobs: RwLock<HashMap<u32, Arc<Mutex<JobRecord>>>>,
    next_job_id: AtomicU32,
    start_time: Instant,
    /// Per-printer locks (keyed by printer key) serialising PAP sessions:
    /// LaserWriters accept one PAP connection at a time and connect() gives
    /// up after 60s of busy-retries, so concurrent jobs must queue here.
    pap_locks: std::sync::Mutex<HashMap<String, Arc<Mutex<()>>>>,
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
        pap_locks: std::sync::Mutex::new(HashMap::new()),
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

fn urf_string(caps: &PrinterCaps) -> String {
    // CP1 = sRGB profile 1 (required by AirPrint spec; CP255 is not valid).
    // We always advertise SRGB24 so iOS sends colour jobs; ghostscript converts to mono.
    format!("W8,SRGB24,CP1,RS{}", caps.dpi)
}

async fn discover(
    nbp: &NbpHandle,
    ddp: &DdpHandle,
    printers: &Arc<RwLock<Vec<Printer>>>,
    mdns: &ServiceDaemon,
) {
    let entity: EntityName = match "=:LaserWriter@*".try_into() {
        Ok(e) => e,
        Err(e) => { tracing::error!("IPP bridge: bad entity name: {e}"); return; }
    };

    let tuples = match nbp.lookup(entity).await {
        Ok(t) => t,
        Err(e) => { tracing::warn!("IPP bridge: NBP lookup failed: {e}"); return; }
    };

    tracing::info!("IPP bridge: found {} LaserWriter(s)", tuples.len());

    let new_keys: HashSet<String> = tuples.iter()
        .map(|t| make_key(&t.entity_name.object))
        .filter(|k| !k.is_empty())
        .collect();

    // Prune vanished printers under a short-lived write lock, then release it:
    // query_printer_caps can block for over a minute on a busy/unreachable
    // printer, and every IPP handler takes printers.read() first.
    let mut current_keys: HashSet<String> = {
        let mut current = printers.write().await;
        current.retain(|p| {
            if new_keys.contains(&p.key) {
                true
            } else {
                if let Ok(rx) = mdns.unregister(&p.mdns_fullname) { drop(rx); }
                false
            }
        });
        current.iter().map(|p| p.key.clone()).collect()
    };

    for tuple in &tuples {
        let name = tuple.entity_name.object.clone();
        let key = make_key(&name);
        if key.is_empty() || current_keys.contains(&key) {
            continue;
        }

        let addr = AtpAddress {
            network_number: tuple.network_number,
            node_number: tuple.node_id,
            socket_number: tuple.socket_number,
        };

        let caps = query_printer_caps(ddp, addr).await;

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
        let service_info = match ServiceInfo::new("_universal._sub._ipp._tcp.local.", &name, &hostname, addrs.as_slice(), 8631u16, &props[..]) {
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
        printers.write().await.push(Printer { name, addr, key, mdns_fullname, caps });
    }

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
            let addr = printer.addr;
            let dpi = printer.caps.dpi;
            let pap_lock = {
                let mut locks = state.pap_locks.lock().unwrap();
                locks.entry(printer.key.clone()).or_default().clone()
            };
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
                let _pap_guard = pap_lock.lock().await;
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
        let modes: Vec<IppValue> = ["auto", "color", "monochrome"].iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("output-mode-supported", IppValue::Array(modes));
    }
    add("pages-per-minute", IppValue::Integer(8));
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
        let vals: Vec<IppValue> = STANDARD_MEDIA.iter().copied()
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
        let vals = vec![IppValue::Enum(3), IppValue::Enum(4), IppValue::Enum(5)]; // draft/normal/high
        add("print-quality-supported", IppValue::Array(vals));
    }
    // macOS Photos checks print-color-mode-supported before queuing photo jobs.
    // Advertise all modes; ghostscript converts colour → mono for this printer.
    {
        let modes: Vec<IppValue> = ["auto", "color", "monochrome"].iter().copied()
            .filter_map(|k| k.try_into().ok())
            .map(IppValue::Keyword)
            .collect();
        add("print-color-mode-supported", IppValue::Array(modes));
    }
    if let Ok(k) = "monochrome".try_into() {
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

/// Convert `image/urf` to a format gs can rasterize.
/// On macOS uses `sips` to produce PDF; on Linux uses `ippeveps` to produce PostScript.
/// Both outputs are accepted by the gs pbmraw call downstream.
async fn urf_to_rasterizable(data: Vec<u8>, job_token: u32) -> anyhow::Result<Vec<u8>> {
    let tmp = std::env::temp_dir();
    let urf_path = tmp.join(format!("tailtalk-{job_token}.urf"));
    tokio::fs::write(&urf_path, &data).await?;

    #[cfg(target_os = "macos")]
    let result: anyhow::Result<Vec<u8>> = {
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
    let result: anyhow::Result<Vec<u8>> = {
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
    let result: anyhow::Result<Vec<u8>> = {
        let _ = tokio::fs::remove_file(&urf_path).await;
        anyhow::bail!("URF format is not supported on this platform");
    };

    result
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

// gs pbmraw → per-page PS Level-2 image; most reliable path for classic LaserWriter firmware.
async fn rasterize_to_ps(mut data: Vec<u8>, fmt: &str, tray_source: &str, dpi: u32, job_token: u32) -> anyhow::Result<(Vec<u8>, usize)> {
    if fmt == "application/postscript" || fmt == "application/vnd.cups-postscript" {
        let page_count = data.windows(7).filter(|w| *w == b"%%Page:").count().max(1);
        return Ok((data, page_count));
    }
    // Track whether urf_to_rasterizable ran — on Linux it returns PostScript, not PDF.
    let is_urf = fmt == "image/urf" || data.starts_with(b"UNIRAST");
    if is_urf {
        data = urf_to_rasterizable(data, job_token).await?;
    }

    // pbmraw cannot write to stdout, so use a temp file.
    let tmp = std::env::temp_dir();
    let pbm_path = tmp.join(format!("tailtalk-rip-{job_token}.pbm"));
    let res_arg = format!("-r{dpi}");

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
        .args(["-dNOPAUSE", "-dBATCH", "-dSAFER", "-sDEVICE=pbmraw", &res_arg, "-o"])
        .arg(&pbm_path)
        .arg(&input_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Keep the input file around for post-mortem; clean up the (possibly partial) pbm.
        let _ = tokio::fs::remove_file(&pbm_path).await;
        anyhow::bail!(
            "gs pbmraw exited with {} (input kept at {})\nstderr: {}\nstdout: {}",
            output.status,
            input_path.display(),
            stderr.trim(),
            stdout.trim(),
        );
    }
    let _ = tokio::fs::remove_file(&input_path).await;

    let pbm = tokio::fs::read(&pbm_path).await;
    let _ = tokio::fs::remove_file(&pbm_path).await;
    let pbm = pbm?;

    let pages = parse_pbm_pages(&pbm)?;
    anyhow::ensure!(!pages.is_empty(), "gs produced no pages");

    let page_count = pages.len();
    Ok((build_ps_raster(&pages, dpi, tray_source), page_count))
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

/// Parse a P4 (binary PBM) header starting at `data[0]`.
fn parse_pbm_header(data: &[u8]) -> Option<(u32, u32, usize)> {
    if data.get(0..2) != Some(b"P4") { return None; }
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
    if pos >= data.len() { return None; }
    pos += 1; // mandatory single whitespace after height
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
