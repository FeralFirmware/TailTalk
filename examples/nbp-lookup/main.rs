use clap::Parser;
use tailtalk::TalkStack;
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

    let stack = TalkStack::builder()
        .ethernet(&args.interface)
        .build()
        .await
        .expect("failed to build AppleTalk stack");

    // Give AARP a moment to acquire a node address before sending lookups
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    println!("Looking up '{}'...", entity);
    match stack.nbp.lookup(entity).await {
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
