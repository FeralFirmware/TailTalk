use std::path::{Path, PathBuf};

#[cfg(any(feature = "ethertalk", feature = "tashtalk"))]
use std::rc::Rc;
#[cfg(feature = "tashtalk")]
use std::cell::RefCell;

use slint::SharedString;
#[cfg(feature = "tashtalk")]
use slint::Model as _;
use serde::{Deserialize, Serialize};
use tailtalk::ShutdownHandle;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, prelude::*};

slint::include_modules!();

// ── Persisted user configuration ──────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct AppConfig {
    server_name: Option<String>,
    volume_name: Option<String>,
    volume_path: Option<String>,
    // Stored as the port path string so it survives device re-enumeration.
    tashtalk_port: Option<String>,
    ethernet_interface: Option<String>,
    pcap_enabled: bool,
    pcap_path: Option<String>,
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("TailTalk").join("config.toml"))
}

fn load_config() -> AppConfig {
    config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_config(config: &AppConfig) {
    let Some(path) = config_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = toml::to_string(config) {
        let _ = std::fs::write(path, s);
    }
}

// ── Commands sent from the UI thread to the tokio server task ─────────────────

enum ServerCommand {
    Start {
        server_name: String,
        volume_name: String,
        #[cfg(feature = "ethertalk")]
        ethernet: Option<String>,
        #[cfg(feature = "tashtalk")]
        tashtalk: Option<String>,
        volume: PathBuf,
        pcap_path: Option<PathBuf>,
    },
    Stop,
}

// ── Interface enumeration ─────────────────────────────────────────────────────

#[cfg(feature = "ethertalk")]
fn enumerate_ethernet() -> Vec<String> {
    let mut names = vec!["None".to_string()];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        let mut seen = std::collections::HashSet::new();
        for iface in ifaces {
            if !iface.is_loopback() && seen.insert(iface.name.clone()) {
                names.push(iface.name);
            }
        }
    }
    names
}

#[cfg(feature = "tashtalk")]
const TASHTALK_USB_VID: u16 = 0x10c4;
#[cfg(feature = "tashtalk")]
const TASHTALK_USB_PID: u16 = 0xea60;

#[cfg(feature = "tashtalk")]
struct SerialDevice {
    label: String,
    path: String,
}

#[cfg(feature = "tashtalk")]
fn enumerate_serial() -> Vec<SerialDevice> {
    let mut devices = Vec::new();
    if let Ok(available) = serialport::available_ports() {
        for p in available {
            #[cfg(target_os = "macos")]
            if p.port_name.starts_with("/dev/tty.") {
                continue;
            }
            if let serialport::SerialPortType::UsbPort(ref info) = p.port_type
                && info.vid == TASHTALK_USB_VID
                && info.pid == TASHTALK_USB_PID
            {
                let product = info.product.as_deref().unwrap_or("TashTalk USB");
                devices.push(SerialDevice {
                    label: format!("{} - {}", product, p.port_name),
                    path: p.port_name,
                });
            }
        }
    }
    devices
}

// ── Logging ───────────────────────────────────────────────────────────────────

/// Set up tracing to write to both stdout and a rolling daily log file.
/// Returns a guard that must be kept alive for the duration of the process;
/// dropping it flushes and closes the file writer.
fn init_logging() -> Option<WorkerGuard> {
    #[cfg(target_os = "macos")]
    {
        let log_dir = dirs::home_dir()
            .map(|h| h.join("Library/Logs/TailTalk"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/TailTalk"));
        let _ = std::fs::create_dir_all(&log_dir);

        let file_appender = tracing_appender::rolling::daily(&log_dir, "tailtalk.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer()) // stdout
            .with(tracing_subscriber::fmt::layer().with_writer(non_blocking)) // file
            .init();

        return Some(guard);
    }

    #[allow(unreachable_code)]
    {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info"));

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
        None
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ServerCommand>(4);

    let _log_guard = init_logging();

    let rt = tokio::runtime::Runtime::new()?;
    let rt_handle = rt.handle().clone();

    let ui = AppWindow::new()?;

    // Inform the UI which transport sections to show
    ui.set_feature_ethertalk(cfg!(feature = "ethertalk"));
    ui.set_feature_tashtalk(cfg!(feature = "tashtalk"));

    #[cfg(feature = "ethertalk")]
    let ethernet_names = enumerate_ethernet();
    #[cfg(feature = "tashtalk")]
    let tashtalk_devices = Rc::new(RefCell::new(enumerate_serial()));

    #[cfg(feature = "ethertalk")]
    {
        let eth_model: slint::ModelRc<SharedString> = Rc::new(slint::VecModel::from(
            ethernet_names
                .iter()
                .map(|s| SharedString::from(s.as_str()))
                .collect::<Vec<_>>(),
        ))
        .into();
        ui.set_ethernet_interfaces(eth_model);
    }

    #[cfg(feature = "tashtalk")]
    let tash_model = {
        let entries: Vec<SharedString> = std::iter::once(SharedString::from("None"))
            .chain(
                tashtalk_devices
                    .borrow()
                    .iter()
                    .map(|d| SharedString::from(d.label.as_str())),
            )
            .collect();
        let model = Rc::new(slint::VecModel::from(entries));
        ui.set_tashtalk_ports(model.clone().into());
        model
    };

    // Restore previously saved settings
    {
        let config = load_config();
        if let Some(ref v) = config.server_name {
            ui.set_server_name(v.as_str().into());
        }
        if let Some(ref v) = config.volume_name {
            ui.set_volume_name(v.as_str().into());
        }
        if let Some(ref v) = config.volume_path {
            ui.set_volume_path(v.as_str().into());
        }
        #[cfg(feature = "ethertalk")]
        if let Some(ref iface) = config.ethernet_interface {
            if let Some(idx) = ethernet_names.iter().position(|n| n == iface) {
                ui.set_selected_ethernet(idx as i32);
            }
        }
        #[cfg(feature = "tashtalk")]
        if let Some(ref port) = config.tashtalk_port {
            // index 0 is "None"; device entries start at 1
            if let Some(idx) = tashtalk_devices.borrow().iter().position(|d| &d.path == port) {
                ui.set_selected_tashtalk((idx + 1) as i32);
            }
        }
        ui.set_pcap_enabled(config.pcap_enabled);
        if let Some(ref path) = config.pcap_path {
            ui.set_pcap_path(path.as_str().into());
        }
    }

    let ui_handle = ui.as_weak();
    rt_handle.spawn(server_loop(cmd_rx, ui_handle));

    let ui_weak = ui.as_weak();
    #[cfg(feature = "ethertalk")]
    let eth_names = ethernet_names.clone();
    #[cfg(feature = "tashtalk")]
    let tash_devices = tashtalk_devices.clone();

    ui.on_start_stop(move || {
        let Some(ui) = ui_weak.upgrade() else { return };

        if ui.get_running() {
            let _ = cmd_tx.try_send(ServerCommand::Stop);
        } else {
            #[cfg(feature = "ethertalk")]
            let ethernet = {
                let eth_idx = ui.get_selected_ethernet() as usize;
                eth_names
                    .get(eth_idx)
                    .filter(|s| s.as_str() != "None")
                    .cloned()
            };

            #[cfg(feature = "tashtalk")]
            let tashtalk = {
                let tash_idx = ui.get_selected_tashtalk() as usize;
                // index 0 is "None"; devices start at 1
                tash_idx
                    .checked_sub(1)
                    .and_then(|i| tash_devices.borrow().get(i).map(|d| d.path.clone()))
            };

            #[allow(unused_mut)]
            let mut any_transport = false;
            #[cfg(feature = "ethertalk")]
            if ethernet.is_some() {
                any_transport = true;
            }
            #[cfg(feature = "tashtalk")]
            if tashtalk.is_some() {
                any_transport = true;
            }
            if !any_transport {
                tracing::error!("At least one transport must be selected");
                return;
            }

            let volume = PathBuf::from(ui.get_volume_path().as_str());
            if volume.as_os_str().is_empty() {
                tracing::error!("No volume path selected");
                return;
            }

            save_config(&AppConfig {
                server_name: Some(ui.get_server_name().to_string()),
                volume_name: Some(ui.get_volume_name().to_string()),
                volume_path: Some(ui.get_volume_path().to_string()),
                tashtalk_port: {
                    #[cfg(feature = "tashtalk")]
                    { tashtalk.clone() }
                    #[cfg(not(feature = "tashtalk"))]
                    { None }
                },
                ethernet_interface: {
                    #[cfg(feature = "ethertalk")]
                    { ethernet.clone() }
                    #[cfg(not(feature = "ethertalk"))]
                    { None }
                },
                pcap_enabled: ui.get_pcap_enabled(),
                pcap_path: {
                    let s = ui.get_pcap_path().to_string();
                    if s.is_empty() { None } else { Some(s) }
                },
            });

            let pcap_path: Option<PathBuf> = if ui.get_pcap_enabled() {
                let s = ui.get_pcap_path().to_string();
                if s.is_empty() { None } else { Some(PathBuf::from(s)) }
            } else {
                None
            };

            let _ = cmd_tx.try_send(ServerCommand::Start {
                server_name: ui.get_server_name().to_string(),
                volume_name: ui.get_volume_name().to_string(),
                #[cfg(feature = "ethertalk")]
                ethernet,
                #[cfg(feature = "tashtalk")]
                tashtalk,
                volume,
                pcap_path,
            });
        }
    });

    let ui_weak = ui.as_weak();
    let rt_handle_bv = rt_handle.clone();
    ui.on_browse_volume(move || {
        let ui_weak = ui_weak.clone();
        rt_handle_bv.spawn(async move {
            if let Some(handle) = rfd::AsyncFileDialog::new().pick_folder().await {
                let path_str: slint::SharedString =
                    handle.path().to_string_lossy().into_owned().into();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_volume_path(path_str);
                    }
                })
                .ok();
            }
        });
    });

    let ui_weak = ui.as_weak();
    let rt_handle_bp = rt_handle.clone();
    ui.on_browse_pcap(move || {
        let ui_weak = ui_weak.clone();
        rt_handle_bp.spawn(async move {
            if let Some(handle) = rfd::AsyncFileDialog::new()
                .add_filter("pcap capture", &["pcap"])
                .set_file_name("tailtalk_capture.pcap")
                .save_file()
                .await
            {
                let path_str: slint::SharedString =
                    handle.path().to_string_lossy().into_owned().into();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_pcap_path(path_str);
                    }
                })
                .ok();
            }
        });
    });

    ui.on_clamp_to_one(|s| s.chars().next().map_or(String::new(), |c| c.to_string()).into());

    let ui_weak = ui.as_weak();
    let rt_handle_fi = rt_handle.clone();
    ui.on_inspect_finder_info(move || {
        let ui_weak = ui_weak.clone();
        let volume_path = ui_weak
            .upgrade()
            .map(|ui| ui.get_volume_path().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        rt_handle_fi.spawn(async move {
            let mut dialog = rfd::AsyncFileDialog::new().set_title("Choose a file to inspect");
            if let Some(ref dir) = volume_path {
                dialog = dialog.set_directory(dir);
            }
            let path = dialog.pick_file().await.map(|h| h.path().to_path_buf());

            let Some(path) = path else { return };

            let info = match tailtalk::afp::read_finder_info(&path).await {
                Ok(v) => v,
                Err(e) => {
                    let msg = format!("Could not read Finder Info: {e}");
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_error_message(msg.into());
                        }
                    })
                    .ok();
                    return;
                }
            };

            let type_chars = ostype_to_chars(&info.file_type);
            let creator_chars = ostype_to_chars(&info.creator);
            let path_str: SharedString = path.to_string_lossy().into_owned().into();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_finder_info_type_0(type_chars[0].clone());
                    ui.set_finder_info_type_1(type_chars[1].clone());
                    ui.set_finder_info_type_2(type_chars[2].clone());
                    ui.set_finder_info_type_3(type_chars[3].clone());
                    ui.set_finder_info_creator_0(creator_chars[0].clone());
                    ui.set_finder_info_creator_1(creator_chars[1].clone());
                    ui.set_finder_info_creator_2(creator_chars[2].clone());
                    ui.set_finder_info_creator_3(creator_chars[3].clone());
                    ui.set_finder_info_path(path_str);
                    ui.set_finder_info_visible(true);
                }
            })
            .ok();
        });
    });

    let ui_weak = ui.as_weak();
    let rt_handle_sfi = rt_handle.clone();
    ui.on_save_finder_info(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let path = PathBuf::from(ui.get_finder_info_path().as_str());
        let type_str = format!(
            "{}{}{}{}",
            ui.get_finder_info_type_0(),
            ui.get_finder_info_type_1(),
            ui.get_finder_info_type_2(),
            ui.get_finder_info_type_3(),
        );
        let creator_str = format!(
            "{}{}{}{}",
            ui.get_finder_info_creator_0(),
            ui.get_finder_info_creator_1(),
            ui.get_finder_info_creator_2(),
            ui.get_finder_info_creator_3(),
        );
        let file_type = string_to_ostype(&type_str);
        let creator = string_to_ostype(&creator_str);
        let ui_weak = ui_weak.clone();

        rt_handle_sfi.spawn(async move {
            let mut info = tailtalk::afp::read_finder_info(&path).await.unwrap_or_default();
            info.file_type = file_type;
            info.creator = creator;
            let result = tailtalk::afp::write_finder_info(&path, &info).await;
            slint::invoke_from_event_loop(move || {
                let Some(ui) = ui_weak.upgrade() else { return };
                match result {
                    Ok(()) => ui.set_finder_info_visible(false),
                    Err(e) => ui.set_error_message(format!("Could not write Finder Info: {e}").into()),
                }
            })
            .ok();
        });
    });

    let ui_weak = ui.as_weak();
    let rt_handle_sit = rt_handle.clone();
    ui.on_import_stuffit(move || {
        let ui_weak = ui_weak.clone();
        let rt_handle_sit = rt_handle_sit.clone();

        let (volume_path, is_running) = {
            let Some(ui) = ui_weak.upgrade() else { return };
            (PathBuf::from(ui.get_volume_path().as_str()), ui.get_running())
        };

        if is_running {
            show_error(
                ui_weak,
                "Please stop the AFP server before importing an archive.\n\
                 Importing while the server is running may corrupt the desktop database."
                    .to_string(),
            );
            return;
        }

        if volume_path.as_os_str().is_empty() {
            show_error(ui_weak, "Please set a volume path before importing.".to_string());
            return;
        }

        rt_handle_sit.spawn(async move {
            let Some(handle) = rfd::AsyncFileDialog::new()
                .add_filter("StuffIt Archive", &["sit"])
                .set_title("Import StuffIt Archive")
                .pick_file()
                .await
            else {
                return;
            };
            let sit_path = handle.path().to_path_buf();

            match extract_sit(&sit_path, &volume_path).await {
                Ok(count) => show_info(
                    ui_weak,
                    format!("Extracted {count} file(s) from the archive successfully."),
                ),
                Err(e) => show_error(ui_weak, e),
            }
        });
    });

    let ui_weak = ui.as_weak();
    let rt_handle_hfs = rt_handle.clone();
    ui.on_import_hfs_image(move || {
        let ui_weak = ui_weak.clone();
        let rt_handle_hfs = rt_handle_hfs.clone();

        let (volume_path, is_running) = {
            let Some(ui) = ui_weak.upgrade() else { return };
            (PathBuf::from(ui.get_volume_path().as_str()), ui.get_running())
        };

        if is_running {
            show_error(
                ui_weak,
                "Please stop the AFP server before importing a disk image.\n\
                 Importing while the server is running may corrupt the desktop database."
                    .to_string(),
            );
            return;
        }

        if volume_path.as_os_str().is_empty() {
            show_error(ui_weak, "Please set a volume path before importing.".to_string());
            return;
        }

        rt_handle_hfs.spawn(async move {
            let Some(handle) = rfd::AsyncFileDialog::new()
                .add_filter("HFS Disk Image", &["dsk", "img", "hfs", "image"])
                .set_title("Import HFS Disk Image")
                .pick_file()
                .await
            else {
                return;
            };
            let img_path = handle.path().to_path_buf();

            match extract_hfs_image(&img_path, &volume_path).await {
                Ok(count) => show_info(
                    ui_weak,
                    format!("Imported {count} file(s) from the HFS image successfully."),
                ),
                Err(e) => show_error(ui_weak, e),
            }
        });
    });

    // Poll for serial device changes every 1.5 s so plug/unplug is reflected live.
    #[cfg(feature = "tashtalk")]
    let _serial_poll_timer = {
        let ui_weak = ui.as_weak();
        let poll_devices = tashtalk_devices.clone();
        let poll_model = tash_model.clone();
        let timer = slint::Timer::default();
        timer.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_millis(1500),
            move || {
                let new_devices = enumerate_serial();
                let mut current = poll_devices.borrow_mut();
                let changed = new_devices.len() != current.len()
                    || new_devices
                        .iter()
                        .zip(current.iter())
                        .any(|(a, b)| a.path != b.path);
                if !changed {
                    return;
                }
                // Remember which port was selected so we can re-select it.
                let selected_path = {
                    let Some(ui) = ui_weak.upgrade() else { return };
                    let idx = ui.get_selected_tashtalk() as usize;
                    idx.checked_sub(1)
                        .and_then(|i| current.get(i).map(|d| d.path.clone()))
                };
                *current = new_devices;
                // Rebuild model entries.
                while poll_model.row_count() > 1 {
                    poll_model.remove(poll_model.row_count() - 1);
                }
                for d in current.iter() {
                    poll_model.push(SharedString::from(d.label.as_str()));
                }
                // Restore selection by path, fall back to "None".
                let new_idx = selected_path
                    .and_then(|p| current.iter().position(|d| d.path == p))
                    .map(|i| (i + 1) as i32)
                    .unwrap_or(0);
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_selected_tashtalk(new_idx);
                }
            },
        );
        timer
    };

    ui.run()?;
    Ok(())
}

// ── Server loop (runs on the background tokio thread) ─────────────────────────

async fn server_loop(
    mut cmd_rx: tokio::sync::mpsc::Receiver<ServerCommand>,
    ui_weak: slint::Weak<AppWindow>,
) {
    let mut shutdown_handle: Option<ShutdownHandle> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            ServerCommand::Start {
                server_name,
                volume_name,
                #[cfg(feature = "ethertalk")]
                ethernet,
                #[cfg(feature = "tashtalk")]
                tashtalk,
                volume,
                pcap_path,
            } => {
                if let Some(h) = shutdown_handle.take() {
                    h.graceful_shutdown().await;
                }

                let ui_w = ui_weak.clone();
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<ShutdownHandle>();
                tokio::spawn(run_server(
                    server_name,
                    volume_name,
                    #[cfg(feature = "ethertalk")]
                    ethernet,
                    #[cfg(feature = "tashtalk")]
                    tashtalk,
                    volume,
                    pcap_path,
                    ready_tx,
                    ui_w.clone(),
                ));

                // Wait for the stack to finish initialising (AARP probe etc.)
                // before flipping the UI to "Running".
                if let Ok(handle) = ready_rx.await {
                    shutdown_handle = Some(handle);
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_w.upgrade() {
                            ui.set_running(true);
                        }
                    })
                    .ok();
                }
                // If ready_rx errors the stack failed to build; run_server
                // already logged the error and reset the UI.
            }

            ServerCommand::Stop => {
                if let Some(h) = shutdown_handle.take() {
                    h.graceful_shutdown().await;
                }
                let ui_w = ui_weak.clone();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_w.upgrade() {
                        ui.set_running(false);
                    }
                })
                .ok();
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn show_error(ui_weak: slint::Weak<AppWindow>, message: String) {
    slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_error_message(message.into());
        }
    })
    .ok();
}

fn show_info(ui_weak: slint::Weak<AppWindow>, message: String) {
    slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_info_message(message.into());
        }
    })
    .ok();
}

// ── OSType (4-byte Mac type/creator code) helpers ────────────────────────────

/// Split a 4-byte OSType into 4 individual SharedStrings for the per-character UI boxes.
fn ostype_to_chars(bytes: &[u8]) -> [SharedString; 4] {
    let s = ostype_to_string(bytes);
    let mut chars = s.chars();
    std::array::from_fn(|_| {
        chars.next().map_or(SharedString::default(), |c| c.to_string().into())
    })
}

/// Convert a 4-byte OSType to a displayable string, replacing non-graphic bytes with spaces.
fn ostype_to_string(bytes: &[u8]) -> String {
    if bytes.iter().all(|&b| b == 0) {
        return String::new();
    }
    bytes
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { ' ' })
        .collect()
}

/// Convert a user-supplied string to a 4-byte OSType, truncating or space-padding as needed.
fn string_to_ostype(s: &str) -> [u8; 4] {
    let mut out = [b' '; 4];
    for (dst, src) in out.iter_mut().zip(s.bytes()) {
        *dst = src;
    }
    out
}

// ── Mac resource fork parsing ─────────────────────────────────────────────────

/// Parse a Mac resource fork and return every (resource_type, data) pair found.
///
/// The resource fork binary layout (Inside Macintosh, Files chapter):
///   [0..4]   offset to resource-data section from fork start
///   [4..8]   offset to resource map from fork start
///   [8..12]  length of resource-data section
///   [12..16] length of resource map
///
/// Resource map at `map_off`:
///   [24..26] offset to type list, relative to start of map
///   [28..30] number of resource types - 1  (0xFFFF → 0 types)
///
/// Type-list layout (at map_off + type_list_off):
///   [0..2]   num_types - 1 (duplicate of map[28..30])
///   then for each type, 8 bytes:
///     [0..4]  resource type (OSType)
///     [4..6]  num_resources - 1
///     [6..8]  offset of this type's reference list, from type-list start
///
/// Reference-list entries (12 bytes each):
///   [0..2]  resource ID
///   [2..4]  name-list offset (0xFFFF = no name)
///   [4]     attributes
///   [5..8]  3-byte big-endian offset into resource-data section
///   [8..12] reserved
///
#[derive(Debug, Clone)]
struct Resource {
    res_type: [u8; 4],
    id: i16,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct BndlMapping {
    local_id: u16,
    res_id: u16,
}

#[derive(Debug, Clone)]
struct BndlTypeArray {
    res_type: [u8; 4],
    mappings: Vec<BndlMapping>,
}

#[derive(Debug, Clone)]
struct Bndl {
    creator: [u8; 4],
    type_arrays: Vec<BndlTypeArray>,
}

#[derive(Debug, Clone, Copy)]
struct Fref {
    file_type: [u8; 4],
    local_icon_id: u16,
}

/// Parse a Mac resource fork, returning every resource it contains.
fn parse_resource_fork(fork: &[u8]) -> Vec<Resource> {
    let Some(b) = fork.get(0..4) else { return vec![] };
    let data_section_off = u32::from_be_bytes(b.try_into().unwrap()) as usize;
    let Some(b) = fork.get(4..8) else { return vec![] };
    let map_off = u32::from_be_bytes(b.try_into().unwrap()) as usize;
    let Some(b) = fork.get(map_off + 24..map_off + 26) else { return vec![] };
    let type_list_off_in_map = u16::from_be_bytes(b.try_into().unwrap()) as usize;
    let Some(b) = fork.get(map_off + 28..map_off + 30) else { return vec![] };
    let num_types_raw = u16::from_be_bytes(b.try_into().unwrap());
    if num_types_raw == 0xFFFF {
        return vec![];
    }
    let num_types = num_types_raw as usize + 1;

    let type_list_abs = map_off + type_list_off_in_map;
    let type_entries_abs = type_list_abs + 2;
    let mut out = Vec::new();

    for i in 0..num_types {
        let te = type_entries_abs + i * 8;
        let Some(entry) = fork.get(te..te + 8) else { break };
        let res_type: [u8; 4] = entry[0..4].try_into().unwrap();
        let count_raw = u16::from_be_bytes([entry[4], entry[5]]);
        if count_raw == 0xFFFF {
            continue;
        }
        let count = count_raw as usize + 1;
        let ref_list_abs = type_list_abs + u16::from_be_bytes([entry[6], entry[7]]) as usize;

        for j in 0..count {
            let re = ref_list_abs + j * 12;
            let Some(ref_entry) = fork.get(re..re + 12) else { break };
            let id = i16::from_be_bytes([ref_entry[0], ref_entry[1]]);
            let data_off = ((ref_entry[5] as u32) << 16)
                | ((ref_entry[6] as u32) << 8)
                | (ref_entry[7] as u32);
            let abs = data_section_off + data_off as usize;
            let Some(len_bytes) = fork.get(abs..abs + 4) else { continue };
            let res_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
            let start = abs + 4;
            let Some(data) = fork.get(start..start + res_len) else { continue };
            out.push(Resource { res_type, id, data: data.to_vec() });
        }
    }
    out
}

/// Parse a `'BNDL'` resource.
fn parse_bndl(data: &[u8]) -> Option<Bndl> {
    let creator: [u8; 4] = data.get(0..4)?.try_into().ok()?;
    // data[4..6] is the bundle version, always 0 — skip.
    let num_type_arrays =
        u16::from_be_bytes(data.get(6..8)?.try_into().ok()?) as usize + 1;

    let mut pos = 8;
    let mut type_arrays = Vec::new();

    for _ in 0..num_type_arrays {
        let Some(header) = data.get(pos..pos + 6) else { break };
        let res_type: [u8; 4] = header[0..4].try_into().unwrap();
        let num_entries = u16::from_be_bytes([header[4], header[5]]) as usize + 1;
        pos += 6;

        let mut mappings = Vec::new();
        for _ in 0..num_entries {
            let Some(e) = data.get(pos..pos + 4) else { break };
            mappings.push(BndlMapping {
                local_id: u16::from_be_bytes([e[0], e[1]]),
                res_id: u16::from_be_bytes([e[2], e[3]]),
            });
            pos += 4;
        }

        type_arrays.push(BndlTypeArray { res_type, mappings });
    }

    Some(Bndl { creator, type_arrays })
}

impl TryFrom<&[u8]> for Fref {
    type Error = ();
    fn try_from(data: &[u8]) -> Result<Self, ()> {
        (|| Some(Self {
            file_type: data.get(0..4)?.try_into().ok()?,
            local_icon_id: u16::from_be_bytes(data.get(4..6)?.try_into().ok()?),
        }))().ok_or(())
    }
}

/// AFP icon type byte used in FPAddIcon/FPGetIcon, keyed by Mac resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AfpIconType {
    Icn32,  // ICN# — 32×32 1-bit icon + mask
    Ics16,  // ics# — 16×16 1-bit icon + mask
    Icl4,   // icl4 — 32×32 4-bit colour
    Ics4,   // ics4 — 16×16 4-bit colour
    Icl8,   // icl8 — 32×32 8-bit colour
    Ics8,   // ics8 — 16×16 8-bit colour
}

impl TryFrom<&[u8; 4]> for AfpIconType {
    type Error = ();
    fn try_from(res_type: &[u8; 4]) -> Result<Self, ()> {
        match res_type {
            b"ICN#" => Ok(Self::Icn32),
            b"ics#" => Ok(Self::Ics16),
            b"icl4" => Ok(Self::Icl4),
            b"ics4" => Ok(Self::Ics4),
            b"icl8" => Ok(Self::Icl8),
            b"ics8" => Ok(Self::Ics8),
            _ => Err(()),
        }
    }
}

impl From<AfpIconType> for u8 {
    fn from(t: AfpIconType) -> u8 {
        match t {
            AfpIconType::Icn32 => 1,
            AfpIconType::Ics16 => 2,
            AfpIconType::Icl4  => 3,
            AfpIconType::Ics4  => 4,
            AfpIconType::Icl8  => 5,
            AfpIconType::Ics8  => 6,
        }
    }
}

impl AfpIconType {
    fn res_type(self) -> [u8; 4] {
        match self {
            Self::Icn32 => *b"ICN#",
            Self::Ics16 => *b"ics#",
            Self::Icl4  => *b"icl4",
            Self::Ics4  => *b"ics4",
            Self::Icl8  => *b"icl8",
            Self::Ics8  => *b"ics8",
        }
    }
}

/// Extract just the creator code from a resource fork's `'BNDL'` resource,
/// without opening the database.  Returns `None` if no BNDL is present.
fn extract_bndl_creator(fork: &[u8]) -> Option<[u8; 4]> {
    parse_resource_fork(fork)
        .into_iter()
        .find(|r| &r.res_type == b"BNDL")
        .and_then(|r| parse_bndl(&r.data))
        .map(|b| b.creator)
}

/// Store the icon resources from an `"Icon\r"` resource fork in the desktop database.
///
/// `creator` should be the actual application creator code found via `'BNDL'`
/// in the same directory, so that `FPGetIcon` lookups match.
fn load_icon_rsrc_into_desktop_db(
    rsrc_fork: &[u8],
    creator: [u8; 4],
    volume_root: &Path,
) -> Result<(), String> {
    use tailtalk::afp::DesktopDatabase;

    let db = DesktopDatabase::new(volume_root, 0)
        .map_err(|e| format!("Failed to open desktop database: {e:?}"))?;

    let resources = parse_resource_fork(rsrc_fork);
    let mut stored = 0usize;

    for r in &resources {
        if let Ok(icon_type) = AfpIconType::try_from(&r.res_type) {
            db.add_icon(creator, *b"fold", icon_type.into(), &r.data)
                .map_err(|e| format!("Failed to store icon resource: {e:?}"))?;
            stored += 1;
        }
    }

    let creator_display: String = creator
        .iter()
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '·' })
        .collect();
    tracing::info!(
        "Loaded {stored} icon resource(s) from Icon\\r into desktop database \
         (creator={creator_display:?} ({:#010x}))",
        u32::from_be_bytes(creator),
    );
    Ok(())
}

/// If the resource fork contains a `'BNDL'` resource, register the application
/// and all of its file-type icons in the desktop database.
///
/// Does nothing (returns `Ok(())`) when no `'BNDL'` is present so the caller
/// can unconditionally call this for every extracted file.
fn register_appl_from_resource_fork(
    rsrc_fork: &[u8],
    rel_path: &Path,
    volume_root: &Path,
) -> Result<(), String> {
    use std::collections::HashMap;
    use tailtalk::afp::DesktopDatabase;

    let resources = parse_resource_fork(rsrc_fork);

    // Find the 'BNDL' resource (ID 128 is canonical, but accept any).
    let bndl_data = match resources.iter().find(|r| &r.res_type == b"BNDL") {
        Some(r) => r.data.clone(),
        None => return Ok(()),
    };

    let Bndl { creator, type_arrays } = match parse_bndl(&bndl_data) {
        Some(v) => v,
        None => return Ok(()),
    };

    let db = DesktopDatabase::new(volume_root, 0)
        .map_err(|e| format!("Failed to open desktop database: {e:?}"))?;

    // Register the application itself.
    // directory_id=2 is the AFP volume root; path uses ':' as AFP path separator.
    let afp_path = rel_path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":");
    db.add_appl(creator, 0, 2, &afp_path)
        .map_err(|e| format!("Failed to register APPL in desktop database: {e:?}"))?;

    // Build a flat resource lookup: (type, id) → &data
    let res_lookup: HashMap<([u8; 4], i16), &Vec<u8>> = resources
        .iter()
        .map(|r| ((r.res_type, r.id), &r.data))
        .collect();

    // Separate the BNDL arrays by role.
    // fref_entries: (local_id → FREF resource_id)
    // icon_entries: icon_res_type → (local_id → icon resource_id)
    let mut fref_entries: Vec<BndlMapping> = Vec::new();
    let mut icon_entries: HashMap<AfpIconType, HashMap<u16, u16>> = HashMap::new();

    for ta in &type_arrays {
        if &ta.res_type == b"FREF" {
            fref_entries = ta.mappings.clone();
        } else if let Ok(icon_type) = AfpIconType::try_from(&ta.res_type) {
            let by_local: HashMap<u16, u16> =
                ta.mappings.iter().map(|m| (m.local_id, m.res_id)).collect();
            icon_entries.insert(icon_type, by_local);
        }
    }

    // For each FREF entry: resolve the file type and its matching icon resources.
    let mut icons_stored = 0usize;
    for fref_mapping in &fref_entries {
        let Some(fref_data) = res_lookup.get(&(*b"FREF", fref_mapping.res_id as i16)) else {
            continue;
        };
        let Ok(Fref { file_type, local_icon_id }) = Fref::try_from(fref_data.as_slice()) else {
            continue;
        };

        for (icon_type, local_to_res) in &icon_entries {
            let Some(&icon_res_id) = local_to_res.get(&local_icon_id) else { continue };
            let Some(icon_data) = res_lookup.get(&(icon_type.res_type(), icon_res_id as i16))
            else {
                continue;
            };
            let _ = db.add_icon(creator, file_type, u8::from(*icon_type), icon_data);
            icons_stored += 1;
        }
    }

    let creator_display: String = creator
        .iter()
        .map(|&b| if b.is_ascii_graphic() { b as char } else { '·' })
        .collect();
    tracing::info!(
        "Registered APPL creator={creator_display:?} ({:#010x}) path={afp_path:?} \
         with {icons_stored} icon(s)",
        u32::from_be_bytes(creator),
    );
    Ok(())
}

// ── StuffIt extraction ────────────────────────────────────────────────────────

/// Extract a StuffIt archive into `volume_path`, placing resource fork sidecars
/// under `<volume_path>/.tailtalk/rsrc/<relative_path>` to match TailTalk's layout.
async fn extract_sit(sit_path: &Path, volume_path: &Path) -> Result<usize, String> {
    let bytes = tokio::fs::read(sit_path).await
        .map_err(|e| format!("Failed to read archive: {e}"))?;

    let archive = stuffit::SitArchive::parse(&bytes)
        .map_err(|e| format!("Failed to parse StuffIt archive: {e}"))?;

    // directory (relative) → creator code found via BNDL in that directory
    let mut dir_creators: std::collections::HashMap<PathBuf, [u8; 4]> =
        std::collections::HashMap::new();
    // Icon\r entries whose DB load is deferred until we have the creator map
    let mut deferred_icon_cr: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    let mut file_count = 0usize;

    for entry in &archive.entries {
        // Build a sanitized relative path: skip empty/`.`/`..` components.
        let rel: PathBuf = entry.name
            .split('/')
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
            .collect();

        if rel.as_os_str().is_empty() {
            continue;
        }

        if entry.is_folder {
            tokio::fs::create_dir_all(volume_path.join(&rel)).await
                .map_err(|e| format!("Failed to create '{}': {e}", rel.display()))?;
            continue;
        }

        // Ensure parent directory exists in the volume.
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(volume_path.join(parent)).await
                .map_err(|e| format!("Failed to create parent for '{}': {e}", rel.display()))?;
        }

        let (data_fork, rsrc_fork) = entry
            .decompressed_forks()
            .map_err(|e| format!("Failed to decompress '{}': {e}", entry.name))?;

        // Always create the data fork file, even when empty, so that AFP can
        // serve the resource fork sidecar for resource-only files (e.g. apps).
        let dest = volume_path.join(&rel);
        tokio::fs::write(&dest, &data_fork).await
            .map_err(|e| format!("Failed to write '{}': {e}", dest.display()))?;
        file_count += 1;

        // Preserve the Mac file type and creator from the archive so that AFP
        // reports correct FinderInfo (the Finder needs type=APPL to launch apps).
        let finder_info = tailtalk::afp::FinderInfo {
            file_type: entry.file_type,
            creator: entry.creator,
            ..Default::default()
        };
        if let Err(e) = tailtalk::afp::write_finder_info(&dest, &finder_info).await {
            tracing::warn!("Could not set FinderInfo for '{}': {e}", rel.display());
        }

        if !rsrc_fork.is_empty() {
            let rsrc_dest = volume_path.join(".tailtalk").join("rsrc").join(&rel);
            if let Some(parent) = rsrc_dest.parent() {
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| format!("Failed to create rsrc dir for '{}': {e}", rel.display()))?;
            }
            tokio::fs::write(&rsrc_dest, &rsrc_fork).await
                .map_err(|e| format!("Failed to write resource fork for '{}': {e}", rel.display()))?;

            let file_name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if file_name == "Icon\r" {
                // Defer: we may not have seen the BNDL for this directory yet.
                let parent_dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
                deferred_icon_cr.push((parent_dir, rsrc_fork));
            } else {
                // Register application + icons if a BNDL is present; also
                // record the creator so Icon\r entries in the same dir can use it.
                if let Some(creator) = extract_bndl_creator(&rsrc_fork) {
                    let parent_dir = rel.parent().unwrap_or(Path::new("")).to_path_buf();
                    dir_creators.entry(parent_dir).or_insert(creator);
                }
                if let Err(e) =
                    register_appl_from_resource_fork(&rsrc_fork, &rel, volume_path)
                {
                    tracing::warn!("Could not register APPL for '{}': {e}", rel.display());
                }
            }
        }
    }

    // Process deferred Icon\r entries now that we have the full creator map.
    for (parent_dir, rsrc_fork) in &deferred_icon_cr {
        // Use the real creator from a BNDL in the same directory if available.
        let creator = dir_creators.get(parent_dir).copied().unwrap_or_else(|| {
            // Fallback: derive from the folder name (space-padded to 4 bytes).
            let folder_name = parent_dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            let mut c = [b' '; 4];
            for (dst, src) in c.iter_mut().zip(folder_name.bytes()) {
                *dst = src;
            }
            c
        });
        if let Err(e) = load_icon_rsrc_into_desktop_db(rsrc_fork, creator, volume_path) {
            tracing::warn!("Could not load Icon\\r into desktop db: {e}");
        }
    }

    Ok(file_count)
}

// ── HFS disk image extraction ─────────────────────────────────────────────────

/// Extract an HFS (classic, not HFS+) disk image into `volume_path`.
///
/// Resource forks are stored as TailTalk sidecars under
/// `<volume_path>/.tailtalk/rsrc/<relative_path>`, matching the StuffIt layout.
/// FinderInfo (type + creator) is preserved via xattr.
///
/// Returns the number of files extracted on success.
async fn extract_hfs_image(img_path: &Path, volume_path: &Path) -> Result<usize, String> {
    let img = tokio::fs::read(img_path).await
        .map_err(|e| format!("Failed to read disk image: {e}"))?;

    let vol = hfs_reader::HfsVolume::parse(&img)
        .map_err(|e| format!("Failed to parse HFS image: {e}"))?;

    // Place all extracted files inside a subdirectory named after the HFS volume.
    // Fall back to the image filename stem when the volume has no name.
    let vol_subdir: PathBuf = if vol.volume_name.is_empty() {
        img_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "untitled".to_string())
            .into()
    } else {
        vol.volume_name.clone().into()
    };
    let dest_root = volume_path.join(&vol_subdir);
    tokio::fs::create_dir_all(&dest_root).await
        .map_err(|e| format!("Failed to create destination directory '{}': {e}", dest_root.display()))?;

    let mut dir_creators: std::collections::HashMap<u32, [u8; 4]> =
        std::collections::HashMap::new();
    let mut deferred_icon_cr: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut file_count = 0usize;

    // Walk every file record in the catalog B-tree.
    for file in &vol.files {
        let rel = &file.rel_path;
        // AFP looks up sidecars as volume_path/.tailtalk/rsrc/<full_rel_from_volume_root>.
        // Since dest_root is volume_path/<vol_subdir>, the full path relative to volume_path is
        // <vol_subdir>/<rel>.
        let full_rel = vol_subdir.join(rel);

        // Ensure parent directory exists.
        if let Some(parent) = rel.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(dest_root.join(parent)).await
                .map_err(|e| format!("Failed to create parent for '{}': {e}", rel.display()))?;
        }

        let data_fork = vol.read_data_fork(file)
            .map_err(|e| format!("Failed to read data fork for '{}': {e}", rel.display()))?;
        let rsrc_fork = vol.read_rsrc_fork(file)
            .map_err(|e| format!("Failed to read resource fork for '{}': {e}", rel.display()))?;

        let dest = dest_root.join(rel);
        tokio::fs::write(&dest, &data_fork).await
            .map_err(|e| format!("Failed to write '{}': {e}", dest.display()))?;
        file_count += 1;

        let finder_info = tailtalk::afp::FinderInfo {
            file_type: file.file_type,
            creator: file.creator,
            ..Default::default()
        };
        if let Err(e) = tailtalk::afp::write_finder_info(&dest, &finder_info).await {
            tracing::warn!("Could not set FinderInfo for '{}': {e}", rel.display());
        }

        if !rsrc_fork.is_empty() {
            // Sidecar must live under volume_path/.tailtalk/rsrc/<vol_subdir>/<rel>
            // so that the AFP server (which is rooted at volume_path) finds it.
            let rsrc_dest = volume_path.join(".tailtalk").join("rsrc").join(&full_rel);
            if let Some(parent) = rsrc_dest.parent() {
                tokio::fs::create_dir_all(parent).await
                    .map_err(|e| format!("Failed to create rsrc dir for '{}': {e}", rel.display()))?;
            }
            tokio::fs::write(&rsrc_dest, &rsrc_fork).await
                .map_err(|e| format!("Failed to write resource fork for '{}': {e}", rel.display()))?;

            let file_name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if file_name == "Icon\r" {
                let parent_dir = full_rel.parent().unwrap_or(Path::new("")).to_path_buf();
                deferred_icon_cr.push((parent_dir, rsrc_fork));
            } else {
                if let Some(creator) = extract_bndl_creator(&rsrc_fork) {
                    dir_creators.entry(file.parent_cnid).or_insert(creator);
                }
                if let Err(e) = register_appl_from_resource_fork(&rsrc_fork, &full_rel, volume_path) {
                    tracing::warn!("Could not register APPL for '{}': {e}", rel.display());
                }
            }
        }
    }

    // Also create any directories that existed in the image but had no files.
    for dir in &vol.dirs {
        let abs = dest_root.join(&dir.rel_path);
        tokio::fs::create_dir_all(&abs).await
            .map_err(|e| format!("Failed to create directory '{}': {e}", dir.rel_path.display()))?;
    }

    // Process deferred Icon\r entries now that we have the full creator map.
    for (parent_dir, rsrc_fork) in &deferred_icon_cr {
        let creator = dir_creators
            .values()
            .next()
            .copied()
            .unwrap_or_else(|| {
                let folder_name = parent_dir
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                let mut c = [b' '; 4];
                for (dst, src) in c.iter_mut().zip(folder_name.bytes()) {
                    *dst = src;
                }
                c
            });
        if let Err(e) = load_icon_rsrc_into_desktop_db(rsrc_fork, creator, volume_path) {
            tracing::warn!("Could not load Icon\\r into desktop db: {e}");
        }
    }

    Ok(file_count)
}

// ── AFP server task ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_server(
    server_name: String,
    volume_name: String,
    #[cfg(feature = "ethertalk")] ethernet: Option<String>,
    #[cfg(feature = "tashtalk")] tashtalk: Option<String>,
    volume: PathBuf,
    pcap_path: Option<PathBuf>,
    ready_tx: tokio::sync::oneshot::Sender<ShutdownHandle>,
    ui_weak: slint::Weak<AppWindow>,
) {
    use tailtalk::{
        TalkStack,
        afp::AfpServerConfig,
    };

    let set_stopped = |ui_weak: slint::Weak<AppWindow>| {
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_running(false);
            }
        })
        .ok();
    };

    #[allow(unused_mut)]
    let mut stack_builder = TalkStack::builder();

    #[cfg(feature = "ethertalk")]
    if let Some(ref intf) = ethernet {
        stack_builder = stack_builder.ethernet(intf);
    }

    if let Some(path) = pcap_path {
        stack_builder = stack_builder.pcap_capture(path);
    }

    #[cfg(feature = "tashtalk")]
    if let Some(ref tty) = tashtalk {
        let features = tailtalk::TashTalkFeatures::new()
            .with_crc_calculation()
            .with_crc_checking();
        stack_builder = stack_builder.localtalk(tty).tashtalk_features(features);
    }

    let stack = match stack_builder.build().await {
        Ok(s) => s,
        Err(e) => {
            let is_perm = e.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
                    .unwrap_or(false)
            });

            if is_perm {
                #[cfg(target_os = "linux")]
                {
                    if let Ok(exe) = std::env::current_exe() {
                        tracing::warn!(
                            "Permission denied — requesting CAP_NET_RAW via pkexec setcap..."
                        );
                        let result = tokio::process::Command::new("pkexec")
                            .args(["setcap", "cap_net_raw+eip"])
                            .arg(&exe)
                            .status()
                            .await;

                        match result {
                            Ok(s) if s.success() => {
                                tracing::info!("Capability granted — relaunching...");
                                std::process::Command::new(&exe).spawn().ok();
                                std::process::exit(0);
                            }
                            _ => {
                                let msg = format!(
                                    "Permission denied. Run manually:\nsudo setcap cap_net_raw+eip {}",
                                    exe.display()
                                );
                                tracing::error!("{msg}");
                                show_error(ui_weak.clone(), msg);
                            }
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let msg = format!("Permission denied: {e}");
                    tracing::error!("{msg}");
                    show_error(ui_weak.clone(), msg);
                }
            } else {
                let msg = format!("Failed to start AppleTalk stack:\n{e}");
                tracing::error!("{msg}");
                show_error(ui_weak.clone(), msg);
            }

            set_stopped(ui_weak);
            return;
        }
    };

    let afp_config = AfpServerConfig {
        volume_path: volume,
        volume_name,
        server_name,
        ..AfpServerConfig::default()
    };

    let _afp = match stack.spawn_afp(Some(254), afp_config).await {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("Failed to start AFP server:\n{e}");
            tracing::error!("{msg}");
            show_error(ui_weak.clone(), msg);
            set_stopped(ui_weak);
            return;
        }
    };

    #[cfg(any(feature = "ethertalk", feature = "tashtalk"))]
    {
        #[cfg(all(feature = "ethertalk", feature = "tashtalk"))]
        let transport_desc = match (&ethernet, &tashtalk) {
            (Some(eth), Some(tty)) => format!("{eth} + {tty}"),
            (Some(eth), None) => eth.clone(),
            (None, Some(tty)) => tty.clone(),
            (None, None) => unreachable!(),
        };
        #[cfg(all(feature = "ethertalk", not(feature = "tashtalk")))]
        let transport_desc = ethernet.as_deref().unwrap_or("(none)").to_string();
        #[cfg(all(not(feature = "ethertalk"), feature = "tashtalk"))]
        let transport_desc = tashtalk.as_deref().unwrap_or("(none)").to_string();
        tracing::info!("AFP server running on {transport_desc}");
    }

    // Signal the GUI that the stack is up; hand over the shutdown handle.
    let _ = ready_tx.send(stack.shutdown_handle());

    // Block until shutdown() is called (e.g. the user clicks Stop).
    stack.wait_for_shutdown().await;

    set_stopped(ui_weak);
}
