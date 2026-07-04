use clap::Parser;
use std::path::PathBuf;
use tailtalk::{
    TalkStack,
    afp::AfpServerConfig,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long)]
    interface: Option<String>,

    /// Path to serve via AFP
    #[arg(short, long)]
    path: PathBuf,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long)]
    tashtalk: Option<String>,

    /// Unix socket path of a running tailtalkd to use instead of
    /// handling the interfaces in-process
    #[cfg(unix)]
    #[arg(short, long, conflicts_with_all = ["interface", "tashtalk", "daemon_udp"])]
    daemon: Option<PathBuf>,

    /// UDP address of a running tailtalkd (e.g. 127.0.0.1:1954)
    #[arg(long, conflicts_with_all = ["interface", "tashtalk", "daemon"])]
    daemon_udp: Option<std::net::SocketAddr>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    if args.interface.is_none()
        && args.tashtalk.is_none()
        && {
            #[cfg(unix)] { args.daemon.is_none() }
            #[cfg(not(unix))] { true }
        }
        && args.daemon_udp.is_none()
    {
        eprintln!("error: at least one of --interface, --tashtalk, --daemon or --daemon-udp is required");
        std::process::exit(1);
    }

    let mut builder = TalkStack::builder();
    if let Some(ref intf) = args.interface {
        builder = builder.ethernet(intf);
    }
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    #[cfg(unix)]
    if let Some(ref sock) = args.daemon {
        builder = builder.daemon_unix(sock);
    }
    if let Some(addr) = args.daemon_udp {
        builder = builder.daemon_udp(addr);
    }
    let stack = builder.build().await.expect("failed to build AppleTalk stack");

    let afp_config = AfpServerConfig {
        volume_path: args.path.clone(),
        ..AfpServerConfig::default()
    };

    stack.spawn_afp(Some(254), afp_config)
        .await
        .expect("failed to spawn AFP server");

    let mut transport = "LocalTalk".to_string();
    if let Some(intf) = &args.interface {
        transport = intf.clone();
    } else if let Some(addr) = &args.daemon_udp {
        transport = format!("daemon at {addr}");
    }
    #[cfg(unix)]
    if let Some(sock) = &args.daemon {
        transport = format!("daemon at {}", sock.display());
    }
    tracing::info!("AFP server serving {:?} on {}", args.path, transport);
    tracing::info!("Press Ctrl+C to exit");

    let shutdown = stack.shutdown_handle();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C received, shutting down");
        }
        _ = shutdown.transport_closed() => {
            tracing::info!("Transport closed, shutting down");
        }
    }
    shutdown.graceful_shutdown().await;
}
