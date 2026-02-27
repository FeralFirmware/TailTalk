use clap::Parser;
use tailtalk::{PacketProcessor, addressing::Addressing, ddp::DdpProcessor, echo::Echo, nbp::Nbp};
use tailtalk_packets::nbp::EntityName;

#[derive(Parser, Debug)]
#[command(about = "Perform an NBP lookup on the AppleTalk network")]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
    interface: String,

    /// Entity to look up in Object:Type@Zone format. Use = as wildcard.
    #[arg(default_value = "=:=@*")]
    entity: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let entity: EntityName = args
        .entity
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid entity name: {}", e))?;

    let (processor, handle) =
        PacketProcessor::spawn(&args.interface).expect("failed to spawn sockets");
    let addressing = Addressing::spawn(processor.get_mac(), handle.clone(), None);
    let ddp = DdpProcessor::spawn(addressing.clone(), handle.clone());
    let _echo = Echo::spawn(&ddp).await;
    let nbp = Nbp::spawn(&ddp, addressing.clone()).await;

    let proc_addressing = addressing.clone();
    tokio::task::spawn_blocking(|| processor.run(proc_addressing, ddp));

    // Give AARP a moment to acquire a node address before sending lookups
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    println!("Looking up '{}'...", entity);
    match nbp.lookup(entity).await {
        Ok(tuples) => {
            if tuples.is_empty() {
                println!("No results found.");
            } else {
                println!("Found {} result(s):", tuples.len());
                for t in &tuples {
                    println!(
                        "  {} — {}.{} socket {}",
                        t.entity_name, t.network_number, t.node_id, t.socket_number
                    );
                }
            }
        }
        Err(e) => eprintln!("Lookup failed: {}", e),
    }

    Ok(())
}
