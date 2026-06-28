/// The reverse of ipp_bridge: discovers modern IPP printers via mDNS/Bonjour and
/// exposes each one on AppleTalk as an emulated LaserWriter, so old Macs can print
/// to them from the Chooser. The real printer's name, make/model, colour capability,
/// resolution and paper sizes are passed through to the Chooser name and the PAP
/// emulator's PostScript query answers (`*Product`, `*ColorDevice`, `*?Resolution`, …).
///
/// Jobs arrive as PostScript from the LaserWriter driver and are submitted with IPP
/// Print-Job: passed through untouched if the printer accepts PostScript, otherwise
/// converted with Ghostscript (PDF, or URF/PWG raster for driverless-only printers).
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::Cursor,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

pub(crate) static GS_COUNTER: AtomicU64 = AtomicU64::new(1);

use ipp::prelude::*;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use tailtalk::{
    CancellationToken,
    atp::Atp,
    ddp::DdpHandle,
    nbp::{NbpHandle, RegisteredName},
    pap::{PapServer, PaperSize, PrintJob, PrintSink, PrinterAttributes},
};
use tailtalk_packets::nbp::EntityName;
use tokio::sync::Mutex;

/// Names this bridge has registered on NBP. Shared with ipp_bridge so it can skip
/// them during its own discovery — otherwise a bridged printer would be re-exported
/// over mDNS as a duplicate of the real device.
pub type BridgedNames = Arc<StdMutex<HashSet<(String, u8)>>>;

/// Document format jobs are forwarded in, in order of preference. PostScript is a
/// pass-through; everything else is converted with Ghostscript.
#[derive(Clone, Copy, Debug)]
enum ForwardFormat {
    Postscript,
    Pdf,
    Urf,
    PwgRaster,
}

impl ForwardFormat {
    fn mime(self) -> &'static str {
        match self {
            Self::Postscript => "application/postscript",
            Self::Pdf => "application/pdf",
            Self::Urf => "image/urf",
            Self::PwgRaster => "image/pwg-raster",
        }
    }
}

/// Capabilities pulled from the real printer via Get-Printer-Attributes.
#[derive(Debug)]
struct IppCaps {
    make_and_model: String,
    color: bool,
    dpi: u32,
    paper_sizes: Vec<PaperSize>,
    format: ForwardFormat,
}

impl Default for IppCaps {
    /// Fallback when the attribute query fails: nearly every IPP printer accepts
    /// PDF, and assuming colour avoids degrading colour jobs (a mono printer
    /// grayscales them itself).
    fn default() -> Self {
        Self {
            make_and_model: String::new(),
            color: true,
            dpi: 300,
            paper_sizes: vec![PaperSize::Letter, PaperSize::A4],
            format: ForwardFormat::Pdf,
        }
    }
}

struct BridgedPrinter {
    uri: String,
    nbp_name: String,
    registration: RegisteredName,
    task: tokio::task::JoinHandle<()>,
}

struct ResolvedPrinter {
    fullname: String,
    printer: BridgedPrinter,
}

pub async fn run(
    nbp: NbpHandle,
    ddp: DdpHandle,
    token: CancellationToken,
    bridged_names: BridgedNames,
) {
    let mdns = ServiceDaemon::new().expect("LW bridge: failed to create mDNS daemon");
    let receiver = match mdns.browse("_ipp._tcp.local.") {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("LW bridge: mDNS browse failed: {e}");
            let _ = mdns.shutdown();
            return;
        }
    };

    tracing::info!("LW bridge: browsing for IPP printers");

    let mut printers: HashMap<String, BridgedPrinter> = HashMap::new();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ResolvedPrinter>();

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            Some(res) = rx.recv() => {
                printers.insert(res.fullname, res.printer);
            }
            ev = receiver.recv_async() => {
                let Ok(ev) = ev else { break };
                match ev {
                    ServiceEvent::ServiceResolved(info) => {
                        let fullname = info.get_fullname().to_string();
                        let instance = fullname
                            .strip_suffix("._ipp._tcp.local.")
                            .unwrap_or(&fullname)
                            .to_string();

                        if info.get_hostname().starts_with("tailtalk-") || info.get_port() == 8631 {
                            tracing::debug!("LW bridge: ignoring TailTalk-published service '{instance}'");
                            continue;
                        }

                        let Some(ip) = info.get_addresses_v4().into_iter().min() else {
                            tracing::debug!("LW bridge: no IPv4 address for '{instance}', skipping");
                            continue;
                        };
                        let rp = info.get_property_val_str("rp").unwrap_or("");
                        let uri_str = format!("ipp://{ip}:{}/{rp}", info.get_port());

                        match printers.get(&fullname) {
                            Some(existing) if existing.uri == uri_str => continue,
                            Some(_) => remove_printer(&nbp, &mut printers, &bridged_names, &fullname).await,
                            None => {}
                        }

                        let taken: HashSet<String> = printers.values().map(|p| p.nbp_name.clone()).collect();
                        let nbp = nbp.clone();
                        let ddp = ddp.clone();
                        let bridged_names = bridged_names.clone();
                        let tx = tx.clone();
                        let _info = info.clone();

                        tokio::spawn(async move {
                            let uri: Uri = match uri_str.parse() {
                                Ok(u) => u,
                                Err(e) => {
                                    tracing::warn!("LW bridge: bad URI '{uri_str}': {e}");
                                    return;
                                }
                            };

                            let caps = match query_ipp_caps(&uri).await {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(
                                        "LW bridge: attribute query for '{instance}' failed ({e}), using defaults"
                                    );
                                    IppCaps {
                                        make_and_model: instance.clone(),
                                        ..IppCaps::default()
                                    }
                                }
                            };

                            let mut nbp_name = unique_nbp_name(&instance, &taken.iter().map(|s| s.as_str()).collect());
                            if nbp_name.is_empty() {
                                tracing::warn!("LW bridge: '{instance}' has no NBP-representable name, skipping");
                                return;
                            }

                            let mut suffix = 2;
                            loop {
                                let entity: EntityName = match format!("{nbp_name}:LaserWriter@*").as_str().try_into() {
                                    Ok(e) => e,
                                    Err(_) => return,
                                };
                                if let Ok(res) = nbp.lookup(entity).await {
                                    if res.is_empty() { break; }
                                } else {
                                    break;
                                }

                                let base = nbp_safe_name(&instance);
                                let s = format!(" {suffix}");
                                nbp_name = base.chars().take(32 - s.len()).collect::<String>().trim_end().to_string() + &s;
                                suffix += 1;
                                if suffix > 100 { return; }
                            }

                            let attrs = PrinterAttributes {
                                product_name: if caps.make_and_model.is_empty() {
                                    nbp_name.clone()
                                } else {
                                    caps.make_and_model.clone()
                                },
                                color: caps.color,
                                resolutions_dpi: vec![caps.dpi],
                                paper_sizes: caps.paper_sizes.clone(),
                                ..PrinterAttributes::default()
                            };

                            let sink = IppForwardSink {
                                uri,
                                format: caps.format,
                                dpi: caps.dpi,
                                color: caps.color,
                                printer: nbp_name.clone(),
                                serial: Arc::new(tokio::sync::Mutex::new(())),
                                counter: std::sync::atomic::AtomicU32::new(0),
                            };

                            let (socket_num, _requestor, responder) = Atp::spawn(&ddp, None).await;
                            let mut server = PapServer::new(
                                responder,
                                ddp,
                                socket_num,
                                attrs,
                                Box::new(sink),
                            );

                            let entity: EntityName = match format!("{nbp_name}:LaserWriter@*").as_str().try_into() {
                                Ok(e) => e,
                                Err(e) => {
                                    tracing::warn!("LW bridge: invalid NBP name '{nbp_name}': {e}");
                                    return;
                                }
                            };
                            let registration = RegisteredName {
                                name: entity,
                                sock_num: socket_num,
                            };
                            
                            bridged_names.lock().unwrap().insert((nbp_name.clone(), socket_num));
                            if let Err(e) = nbp.register(registration.clone()).await {
                                tracing::warn!("LW bridge: NBP registration for '{nbp_name}' failed: {e}");
                                bridged_names.lock().unwrap().remove(&(nbp_name, socket_num));
                                return;
                            }

                            let task_name = nbp_name.clone();
                            let task = tokio::spawn(async move {
                                if let Err(e) = server.run().await {
                                    tracing::warn!("LW bridge: PAP server for '{task_name}' stopped: {e}");
                                }
                            });

                            tracing::info!(
                                "LW bridge: bridged '{instance}' → \"{nbp_name}:LaserWriter\" \
                                 ({}, {}dpi, color={}, sending {})",
                                if caps.make_and_model.is_empty() { "unknown model" } else { &caps.make_and_model },
                                caps.dpi,
                                caps.color,
                                caps.format.mime(),
                            );

                            let printer = BridgedPrinter {
                                uri: uri_str,
                                nbp_name,
                                registration,
                                task,
                            };
                            let _ = tx.send(ResolvedPrinter { fullname, printer });
                        });
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        remove_printer(&nbp, &mut printers, &bridged_names, &fullname).await;
                    }
                    _ => {}
                }
            }
        }
    }

    for (_, p) in printers.drain() {
        p.task.abort();
        let _ = nbp.unregister(p.registration.clone()).await;
        bridged_names.lock().unwrap().remove(&(p.nbp_name.clone(), p.registration.sock_num));
    }
    let _ = mdns.shutdown();
}

async fn remove_printer(
    nbp: &NbpHandle,
    printers: &mut HashMap<String, BridgedPrinter>,
    bridged_names: &BridgedNames,
    fullname: &str,
) {
    let Some(p) = printers.remove(fullname) else { return };
    tracing::info!("LW bridge: '{}' vanished, unregistering", p.nbp_name);
    p.task.abort();
    if let Err(e) = nbp.unregister(p.registration.clone()).await {
        tracing::warn!("LW bridge: NBP unregister for '{}' failed: {e}", p.nbp_name);
    }
    bridged_names.lock().unwrap().remove(&(p.nbp_name.clone(), p.registration.sock_num));
}

/// Make a printer's mDNS instance name safe for NBP: ASCII only (NBP names are
/// MacRoman on the wire; non-ASCII would mojibake in the Chooser), no NBP
/// metacharacters, at most 32 characters.
fn nbp_safe_name(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| match c {
            ':' | '@' | '=' | '*' => ' ',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => ' ',
        })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    cleaned.chars().take(32).collect::<String>().trim_end().to_string()
}

/// NBP-safe name, disambiguated with a numeric suffix if another bridged
/// printer already claimed it.
fn unique_nbp_name(instance: &str, taken: &HashSet<&str>) -> String {
    let base = nbp_safe_name(instance);
    if base.is_empty() || !taken.contains(base.as_str()) {
        return base;
    }
    for n in 2..100 {
        let suffix = format!(" {n}");
        let candidate: String = base
            .chars()
            .take(32 - suffix.len())
            .collect::<String>()
            .trim_end()
            .to_string()
            + &suffix;
        if !taken.contains(candidate.as_str()) {
            return candidate;
        }
    }
    String::new()
}

// ── IPP attribute query ───────────────────────────────────────────────────────

fn attr_string(v: &IppValue) -> Option<String> {
    match v {
        IppValue::NameWithoutLanguage(s) | IppValue::Keyword(s) => Some(s.to_string()),
        IppValue::TextWithoutLanguage(s) => Some(s.to_string()),
        _ => None,
    }
}

/// Iterate an attribute's values whether it's a single value or a 1setOf array.
fn attr_values(v: &IppValue) -> Vec<&IppValue> {
    match v {
        IppValue::Array(vals) => vals.iter().collect(),
        other => vec![other],
    }
}

async fn query_ipp_caps(uri: &Uri) -> anyhow::Result<IppCaps> {
    let client = AsyncIppClient::new(uri.clone());
    let op = IppOperationBuilder::get_printer_attributes(uri.clone())
        .attributes([
            "printer-make-and-model",
            "color-supported",
            "printer-resolution-default",
            "media-supported",
            "document-format-supported",
        ])
        .build()?;
    let resp = tokio::time::timeout(Duration::from_secs(15), client.send(op))
        .await
        .map_err(|_| anyhow::anyhow!("Get-Printer-Attributes timed out"))??;

    let status = resp.header().operation_or_status;
    anyhow::ensure!(status < 0x100, "Get-Printer-Attributes failed: 0x{status:04x}");

    let group = resp
        .attributes()
        .groups_of(DelimiterTag::PrinterAttributes)
        .next()
        .ok_or_else(|| anyhow::anyhow!("response has no printer attributes"))?;
    let attrs = group.attributes();

    let make_and_model = attrs
        .get("printer-make-and-model")
        .and_then(|a| attr_string(a.value()))
        .unwrap_or_default();

    let color = attrs
        .get("color-supported")
        .and_then(|a| match a.value() {
            IppValue::Boolean(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(false);

    let dpi = attrs
        .get("printer-resolution-default")
        .and_then(|a| match a.value() {
            IppValue::Resolution { cross_feed, units, .. } if *cross_feed > 0 => {
                if *units == 4 {
                    Some((*cross_feed as f64 * 2.54).round() as u32)
                } else {
                    Some(*cross_feed as u32)
                }
            }
            _ => None,
        })
        .unwrap_or(300);

    let mut paper_sizes: Vec<PaperSize> = Vec::new();
    if let Some(a) = attrs.get("media-supported") {
        for v in attr_values(a.value()) {
            let Some(media) = attr_string(v) else { continue };
            let size = if media.starts_with("na_letter") {
                Some(PaperSize::Letter)
            } else if media.starts_with("na_legal") {
                Some(PaperSize::Legal)
            } else if media.starts_with("iso_a4") {
                Some(PaperSize::A4)
            } else if media.starts_with("iso_a3") {
                Some(PaperSize::A3)
            } else if media.starts_with("iso_b5") || media.starts_with("jis_b5") {
                Some(PaperSize::B5)
            } else if media.starts_with("na_executive") {
                Some(PaperSize::Executive)
            } else {
                None
            };
            if let Some(s) = size
                && !paper_sizes.contains(&s)
            {
                paper_sizes.push(s);
            }
        }
    }
    if paper_sizes.is_empty() {
        paper_sizes = vec![PaperSize::Letter, PaperSize::A4];
    }

    let mut formats: HashSet<String> = HashSet::new();
    if let Some(a) = attrs.get("document-format-supported") {
        for v in attr_values(a.value()) {
            if let IppValue::MimeMediaType(m) = v {
                formats.insert(m.to_string());
            }
        }
    }
    let format = if formats.contains("application/postscript") {
        ForwardFormat::Postscript
    } else if formats.contains("application/pdf") {
        ForwardFormat::Pdf
    } else if formats.contains("image/urf") {
        ForwardFormat::Urf
    } else if formats.contains("image/pwg-raster") {
        ForwardFormat::PwgRaster
    } else {
        // Nothing recognised (or the attribute was withheld); PDF is the safest bet.
        ForwardFormat::Pdf
    };

    Ok(IppCaps {
        make_and_model,
        color,
        dpi,
        paper_sizes,
        format,
    })
}

// ── Print sink: PostScript → IPP Print-Job ────────────────────────────────────

struct IppForwardSink {
    uri: Uri,
    format: ForwardFormat,
    dpi: u32,
    color: bool,
    printer: String,
    /// Serialises forwarded jobs so two quick prints can't arrive out of order.
    serial: Arc<Mutex<()>>,
    counter: AtomicU32,
}

impl PrintSink for IppForwardSink {
    fn receive_job(
        &self,
        job: PrintJob,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + '_>> {
        let uri = self.uri.clone();
        let format = self.format;
        let dpi = self.dpi;
        let color = self.color;
        let printer = self.printer.clone();
        let serial = self.serial.clone();
        let n = self.counter.fetch_add(1, Ordering::Relaxed) + 1;
        Box::pin(async move {
            // Forward in the background so the PAP session keeps answering the Mac's
            // status polls; the Mac considers the job delivered at PAP EOF, so a
            // failure here can only be logged.
            tokio::spawn(async move {
                let _guard = serial.lock().await;
                match forward_job(&uri, format, dpi, color, job.data, n).await {
                    Ok(job_id) => tracing::info!(
                        "LW bridge: job {n} for '{printer}' submitted (IPP job {job_id})"
                    ),
                    Err(e) => tracing::error!("LW bridge: job {n} for '{printer}' failed: {e}"),
                }
            });
            Ok(())
        })
    }
}

/// Extract the `%%Title:` DSC comment from a PostScript job for the IPP job name.
fn ps_title(data: &[u8]) -> Option<String> {
    let head = &data[..data.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    for line in text.split(['\r', '\n']) {
        if let Some(title) = line.strip_prefix("%%Title:") {
            let title = title.trim().trim_matches(|c| c == '(' || c == ')').trim();
            if !title.is_empty() {
                return Some(title.chars().take(255).collect());
            }
        }
    }
    None
}

async fn forward_job(
    uri: &Uri,
    format: ForwardFormat,
    dpi: u32,
    color: bool,
    ps: Vec<u8>,
    n: u32,
) -> anyhow::Result<i32> {
    let title = ps_title(&ps).unwrap_or_else(|| format!("TailTalk job {n}"));

    let doc = match format {
        ForwardFormat::Postscript => ps,
        ForwardFormat::Pdf => gs_convert(&ps, "pdfwrite", &[]).await?,
        ForwardFormat::Urf => {
            let device = if color { "urfrgb" } else { "urfgray" };
            gs_convert(&ps, device, &[format!("-r{dpi}")]).await?
        }
        ForwardFormat::PwgRaster => {
            gs_convert(&ps, "pwgraster", &[format!("-r{dpi}")]).await?
        }
    };

    let payload = IppPayload::new(Cursor::new(doc));
    let op = IppOperationBuilder::print_job(uri.clone(), payload)
        .user_name("TailTalk")
        .job_title(&title)
        .document_format(format.mime())
        .build()?;

    let client = AsyncIppClient::new(uri.clone());
    let resp = tokio::time::timeout(Duration::from_secs(300), client.send(op))
        .await
        .map_err(|_| anyhow::anyhow!("Print-Job timed out"))??;

    let status = resp.header().operation_or_status;
    anyhow::ensure!(status < 0x100, "Print-Job failed: 0x{status:04x}");

    let job_id = resp
        .attributes()
        .groups_of(DelimiterTag::JobAttributes)
        .next()
        .and_then(|g| g.attributes().get("job-id"))
        .and_then(|a| match a.value() {
            IppValue::Integer(id) => Some(*id),
            _ => None,
        })
        .unwrap_or(0);
    Ok(job_id)
}

/// Run Ghostscript over a PostScript job with the given output device.
pub(crate) async fn gs_convert(
    ps: &[u8],
    device: &str,
    extra_args: &[String],
) -> anyhow::Result<Vec<u8>> {
    let id = GS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir();
    let in_path = tmp.join(format!("tailtalk-gs-{id}.ps"));
    let out_path = tmp.join(format!("tailtalk-gs-{id}.out"));
    tokio::fs::write(&in_path, ps).await?;

    let output = tokio::process::Command::new(crate::ipp_bridge::gs_command())
        .args(["-dNOPAUSE", "-dBATCH", "-dSAFER"])
        .arg(format!("-sDEVICE={device}"))
        .args(extra_args)
        .arg("-o")
        .arg(&out_path)
        .arg(&in_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await?;

    let _ = tokio::fs::remove_file(&in_path).await;

    if !output.status.success() {
        let _ = tokio::fs::remove_file(&out_path).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gs {device} exited with {}: {}", output.status, stderr.trim());
    }

    let out = tokio::fs::read(&out_path).await?;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nbp_names_sanitized() {
        assert_eq!(nbp_safe_name("HP LaserJet Pro"), "HP LaserJet Pro");
        assert_eq!(nbp_safe_name("Foo: Bar @ Home"), "Foo Bar Home");
        assert_eq!(
            nbp_safe_name("A very long printer name that exceeds limits"),
            "A very long printer name that ex"
        );
        assert_eq!(nbp_safe_name("Caf\u{e9} Printer"), "Caf Printer");
    }

    #[test]
    fn nbp_names_disambiguated() {
        let mut taken = HashSet::new();
        assert_eq!(unique_nbp_name("Printer", &taken), "Printer");
        taken.insert("Printer");
        assert_eq!(unique_nbp_name("Printer", &taken), "Printer 2");
    }

    /// Live query against a real printer, e.g.:
    ///   TAILTALK_TEST_IPP_URI=ipp://printer.local:631/ipp/print \
    ///     cargo test -p tailtalk-gui live_ipp_caps -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn live_ipp_caps() {
        let uri = std::env::var("TAILTALK_TEST_IPP_URI")
            .expect("set TAILTALK_TEST_IPP_URI to run this test");
        let caps = query_ipp_caps(&uri.parse().unwrap()).await.unwrap();
        println!("caps: {caps:?}");
    }

    #[test]
    fn ps_title_extracted() {
        let ps = b"%!PS-Adobe-3.0\r%%Title: (My Document)\r%%EndComments\r";
        assert_eq!(ps_title(ps).as_deref(), Some("My Document"));
        assert_eq!(ps_title(b"%!PS-Adobe-3.0\n"), None);
    }
}
