use std::path::PathBuf;
use std::rc::Rc;

use slint::SharedString;
use tracing_subscriber::{filter::LevelFilter, prelude::*};

slint::include_modules!();

// ── Commands sent from the UI thread to the tokio server task ─────────────────

enum ServerCommand {
    Start {
        server_name: String,
        ethernet: Option<String>,
        tashtalk: Option<String>,
        tashtalk_crc_generation: bool,
        tashtalk_crc_checking: bool,
        volume: PathBuf,
    },
    Stop,
}

// ── Interface enumeration ─────────────────────────────────────────────────────

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

fn enumerate_serial() -> Vec<String> {
    let mut ports = vec!["None".to_string()];
    if let Ok(available) = serialport::available_ports() {
        for p in available {
            ports.push(p.port_name);
        }
    }
    ports
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    // Commands flow from Slint callbacks → this channel → tokio server_loop
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<ServerCommand>(4);

    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let ui = AppWindow::new()?;

    // Enumerate once at startup
    let ethernet_names = enumerate_ethernet();
    let tashtalk_names = enumerate_serial();

    let eth_model: slint::ModelRc<SharedString> = Rc::new(slint::VecModel::from(
        ethernet_names
            .iter()
            .map(|s| SharedString::from(s.as_str()))
            .collect::<Vec<_>>(),
    ))
    .into();

    let tash_model: slint::ModelRc<SharedString> = Rc::new(slint::VecModel::from(
        tashtalk_names
            .iter()
            .map(|s| SharedString::from(s.as_str()))
            .collect::<Vec<_>>(),
    ))
    .into();

    ui.set_ethernet_interfaces(eth_model);
    ui.set_tashtalk_ports(tash_model);

    // Spawn tokio runtime on a background thread
    let ui_handle = ui.as_weak();
    std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(server_loop(cmd_rx, ui_handle));
    });

    // on_start_stop: read UI state, send Start or Stop command
    let ui_weak = ui.as_weak();
    let eth_names = ethernet_names.clone();
    let tash_names = tashtalk_names.clone();
    ui.on_start_stop(move || {
        let Some(ui) = ui_weak.upgrade() else { return };

        if ui.get_running() {
            let _ = cmd_tx.try_send(ServerCommand::Stop);
        } else {
            let eth_idx = ui.get_selected_ethernet() as usize;
            let tash_idx = ui.get_selected_tashtalk() as usize;

            let ethernet = eth_names
                .get(eth_idx)
                .filter(|s| s.as_str() != "None")
                .cloned();

            let tashtalk = tash_names
                .get(tash_idx)
                .filter(|s| s.as_str() != "None")
                .cloned();

            if ethernet.is_none() && tashtalk.is_none() {
                tracing::error!("At least one of Ethernet or TashTalk must be selected");
                return;
            }

            let volume = PathBuf::from(ui.get_volume_path().as_str());
            if volume.as_os_str().is_empty() {
                tracing::error!("No volume path selected");
                return;
            }

            let _ = cmd_tx.try_send(ServerCommand::Start {
                server_name: ui.get_server_name().to_string(),
                ethernet,
                tashtalk,
                tashtalk_crc_generation: ui.get_tashtalk_crc_generation(),
                tashtalk_crc_checking: ui.get_tashtalk_crc_checking(),
                volume,
            });
        }
    });

    // on_browse_volume: show native folder picker and update the path field
    let ui_weak = ui.as_weak();
    ui.on_browse_volume(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            ui.set_volume_path(path.to_string_lossy().into_owned().into());
        }
    });

    ui.run()?;
    Ok(())
}

// ── Server loop (runs on the background tokio thread) ─────────────────────────

async fn server_loop(
    mut cmd_rx: tokio::sync::mpsc::Receiver<ServerCommand>,
    ui_weak: slint::Weak<AppWindow>,
) {
    let mut abort_handle: Option<tokio::task::AbortHandle> = None;

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            ServerCommand::Start {
                server_name,
                ethernet,
                tashtalk,
                tashtalk_crc_generation,
                tashtalk_crc_checking,
                volume,
            } => {
                // Abort any running server first
                if let Some(h) = abort_handle.take() {
                    h.abort();
                }

                let ui_w = ui_weak.clone();
                let task = tokio::spawn(run_server(
                    server_name,
                    ethernet,
                    tashtalk,
                    tashtalk_crc_generation,
                    tashtalk_crc_checking,
                    volume,
                    ui_w,
                ));
                abort_handle = Some(task.abort_handle());

                let ui_w = ui_weak.clone();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_w.upgrade() {
                        ui.set_running(true);
                    }
                })
                .ok();
            }

            ServerCommand::Stop => {
                if let Some(h) = abort_handle.take() {
                    h.abort();
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

// ── AFP server task ───────────────────────────────────────────────────────────

async fn run_server(
    server_name: String,
    ethernet: Option<String>,
    tashtalk: Option<String>,
    tashtalk_crc_generation: bool,
    tashtalk_crc_checking: bool,
    volume: PathBuf,
    ui_weak: slint::Weak<AppWindow>,
) {
    use tailtalk::{
        TalkStack,
        afp::{AfpServer, AfpServerConfig},
    };

    let set_stopped = |ui_weak: slint::Weak<AppWindow>| {
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_running(false);
            }
        })
        .ok();
    };

    let mut stack_builder = TalkStack::builder();
    if let Some(ref intf) = ethernet {
        stack_builder = stack_builder.ethernet(intf);
    }
    if let Some(ref tty) = tashtalk {
        let mut features = tailtalk::TashTalkFeatures::new();
        if tashtalk_crc_generation {
            features = features.with_crc_calculation();
        }
        if tashtalk_crc_checking {
            features = features.with_crc_checking();
        }
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
                            _ => tracing::error!(
                                "pkexec setcap failed. Run manually: sudo setcap cap_net_raw+eip {}",
                                exe.display()
                            ),
                        }
                    }
                }
                #[cfg(not(target_os = "linux"))]
                tracing::error!("Permission denied opening raw socket: {e}");
            } else {
                tracing::error!("Failed to build AppleTalk stack: {e}");
            }

            set_stopped(ui_weak);
            return;
        }
    };

    let mut afp_config = AfpServerConfig::default();
    afp_config.volume_path = volume;
    afp_config.server_name = server_name;

    let _afp = match AfpServer::spawn(&stack.ddp, &stack.nbp, Some(254), afp_config).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to spawn AFP server: {e}");
            set_stopped(ui_weak);
            return;
        }
    };

    let transport_desc = match (&ethernet, &tashtalk) {
        (Some(eth), Some(tty)) => format!("{eth} + {tty}"),
        (Some(eth), None) => eth.clone(),
        (None, Some(tty)) => tty.clone(),
        (None, None) => unreachable!(),
    };
    tracing::info!("AFP server running on {transport_desc}");

    // Keep this task alive until it is aborted via Stop
    std::future::pending::<()>().await;
}
