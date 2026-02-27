use clap::Parser;
use tailtalk::{PacketProcessor, addressing::Addressing, ddp::DdpProcessor, echo::Echo, nbp::Nbp};
use tailtalk_packets::aarp::AppleTalkAddress;

#[derive(Parser, Debug)]
#[command(about = "Send an AppleTalk AEP (Echo Protocol) request")]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
    interface: String,

    /// Destination AppleTalk network number
    #[arg(short, long)]
    network: u16,

    /// Destination AppleTalk node number
    #[arg(short = 'n', long)]
    node: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let (processor, handle) =
        PacketProcessor::spawn(&args.interface).expect("failed to spawn sockets");
    let addressing = Addressing::spawn(processor.get_mac(), handle.clone(), None);
    let ddp = DdpProcessor::spawn(addressing.clone(), handle.clone());
    let echo = Echo::spawn(&ddp).await;
    let _nbp = Nbp::spawn(&ddp, addressing.clone()).await;

    let proc_addressing = addressing.clone();
    tokio::task::spawn_blocking(|| processor.run(proc_addressing, ddp));

    // Give AARP a moment to acquire a node address
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let addr = AppleTalkAddress {
        network_number: args.network,
        node_number: args.node,
    };

    println!("Sending AEP echo to {}.{}...", args.network, args.node);
    match echo.send(addr, b"Hello, AppleTalk!").await {
        Ok(rtt) => println!("Echo reply received! RTT: {}ms", rtt.as_millis()),
        Err(e) => eprintln!("Echo failed: {}", e),
    }

    Ok(())
}
