use clap::Parser;
use std::path::PathBuf;
use tailtalk::{
    PacketProcessor,
    addressing::Addressing,
    afp::{AfpServer, AfpServerConfig},
    ddp::DdpProcessor,
    echo::Echo,
    nbp::Nbp,
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let (processor, handle) =
        PacketProcessor::spawn(&args.interface).expect("failed to spawn sockets");
    let addressing = Addressing::spawn(processor.get_mac(), handle.clone(), None);

    let processor_addressing = addressing.clone();

    let ddp = DdpProcessor::spawn(addressing.clone(), handle.clone());
    let _echo = Echo::spawn(&ddp).await;
    let nbp = Nbp::spawn(&ddp, addressing.clone()).await;

    // Start AFP server
    let mut afp_config = AfpServerConfig::default();
    afp_config.volume_path = args.path.clone();

    let _afp_server = AfpServer::spawn(&ddp, &nbp, Some(254), afp_config)
        .await
        .expect("failed to spawn AFP server");

    tokio::task::spawn_blocking(|| processor.run(processor_addressing, ddp));

    tracing::info!("AFP server serving {:?} on {}", args.path, args.interface);
    tracing::info!("Press Ctrl+C to exit");

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");

    tracing::info!("Shutting down");
}
