use clap::Parser;
use std::path::PathBuf;
use tailtalk::{
    TalkStack,
    afp::{AfpServer, AfpServerConfig},
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
    interface: String,

    /// Path to serve via AFP
    #[arg(short, long)]
    path: PathBuf,

    /// Optional TashTalk serial port path
    #[arg(short, long)]
    tashtalk: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();

    let mut builder = TalkStack::builder().ethernet(&args.interface);
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    let stack = builder.build().await.expect("failed to build AppleTalk stack");

    let mut afp_config = AfpServerConfig::default();
    afp_config.volume_path = args.path.clone();

    let _afp_server = AfpServer::spawn(&stack.ddp, &stack.nbp, Some(254), afp_config)
        .await
        .expect("failed to spawn AFP server");

    tracing::info!("AFP server serving {:?} on {}", args.path, args.interface);
    tracing::info!("Press Ctrl+C to exit");

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");

    tracing::info!("Shutting down");
}
