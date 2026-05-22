use clap::Parser;
use tailtalk::TalkStack;
use tailtalk_packets::nbp::EntityName;

#[derive(Parser, Debug)]
#[command(about = "Perform an NBP lookup on the AppleTalk network")]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long)]
    interface: Option<String>,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long)]
    tashtalk: Option<String>,

    /// Entity to look up in Object:Type@Zone format. Use = as wildcard.
    #[arg(default_value = "=:=@*")]
    entity: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    if args.interface.is_none() && args.tashtalk.is_none() {
        anyhow::bail!("at least one of --interface or --tashtalk is required");
    }

    let entity: EntityName = args
        .entity
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid entity name: {}", e))?;

    let mut builder = TalkStack::builder();
    if let Some(ref intf) = args.interface {
        builder = builder.ethernet(intf);
    }
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    let stack = builder.build().await.expect("failed to build AppleTalk stack");

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
