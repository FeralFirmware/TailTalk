use clap::Parser;
use tailtalk::TalkStack;
use tailtalk_packets::aarp::AppleTalkAddress;

#[derive(Parser, Debug)]
#[command(about = "Send an AppleTalk AEP (Echo Protocol) request")]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long)]
    interface: Option<String>,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long)]
    tashtalk: Option<String>,

    /// Destination AppleTalk network number
    #[arg(short = 'N', long)]
    network: u16,

    /// Destination AppleTalk node number
    #[arg(short = 'n', long)]
    node: u8,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    if args.interface.is_none() && args.tashtalk.is_none() {
        anyhow::bail!("at least one of --interface or --tashtalk is required");
    }

    let mut builder = TalkStack::builder();
    if let Some(ref intf) = args.interface {
        builder = builder.ethernet(intf);
    }
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    let stack = builder.build().await.expect("failed to build AppleTalk stack");

    let addr = AppleTalkAddress {
        network_number: args.network,
        node_number: args.node,
    };

    println!("Sending AEP echo to {}.{}...", args.network, args.node);
    match stack.echo.send(addr, b"Hello, AppleTalk!").await {
        Ok(rtt) => println!("Echo reply received! RTT: {}ms", rtt.as_millis()),
        Err(e) => eprintln!("Echo failed: {}", e),
    }

    Ok(())
}
