use clap::Parser;
use std::path::PathBuf;
use tailtalk::{
    TalkStack,
    afp::{AfpServer, AfpServerConfig},
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

    if args.interface.is_none() && args.tashtalk.is_none() {
        eprintln!("error: at least one of --interface or --tashtalk is required");
        std::process::exit(1);
    }

    let mut builder = TalkStack::builder();
    if let Some(ref intf) = args.interface {
        builder = builder.ethernet(intf);
    }
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    let stack = builder.build().await.expect("failed to build AppleTalk stack");

    let afp_config = AfpServerConfig {
        volume_path: args.path.clone(),
        ..AfpServerConfig::default()
    };

    let _afp_server = AfpServer::spawn(&stack.ddp, &stack.nbp, Some(254), afp_config, stack.token(), stack.services_done_token())
        .await
        .expect("failed to spawn AFP server");

    let transport = args.interface.as_deref().unwrap_or("LocalTalk");
    tracing::info!("AFP server serving {:?} on {}", args.path, transport);
    tracing::info!("Press Ctrl+C to exit");

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");

    tracing::info!("Shutting down");
    stack.shutdown_handle().graceful_shutdown().await;
}
