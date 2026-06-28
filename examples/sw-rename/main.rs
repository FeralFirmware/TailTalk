use clap::Parser;
use tailtalk::{TalkStack, adsp::AdspAddress};
use tailtalk_packets::nbp::EntityName;
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

/// ADSP management socket — fixed at 129 on StyleWriter adapters.
const SW_MGMT_SOCKET: u8 = 129;

/// Attention command codes used by the StyleWriter name-change protocol.
const ATTN_GET_NAME: u16 = 0x0011;
const ATTN_SET_NAME: u16 = 0x0009;
const ATTN_COMMIT:   u16 = 0x0012;

#[derive(Parser, Debug)]
#[command(about = "Rename a Color StyleWriter adapter via ADSP")]
struct Args {
    /// EtherTalk network interface
    #[arg(short, long)]
    interface: String,

    /// NBP entity to search for (Object:Type@Zone)
    #[arg(short, long, default_value = "=:ColorStyleWriter2400AT@*")]
    target: String,

    /// New printer name (max 31 characters)
    #[arg(short, long)]
    name: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let args = Args::parse();

    if args.name.is_empty() || args.name.len() > 31 {
        anyhow::bail!("name must be 1–31 characters (got {})", args.name.len());
    }

    let entity: EntityName = args
        .target
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid target: {}", e))?;

    println!("Building AppleTalk stack on {}...", args.interface);
    let stack = TalkStack::builder()
        .ethernet(&args.interface)
        .build()
        .await?;

    println!("Looking up '{}'...", entity);
    let tuples = timeout(Duration::from_secs(10), stack.nbp.lookup(entity))
        .await
        .map_err(|_| anyhow::anyhow!("NBP lookup timed out after 10 s"))?
        .map_err(|e| anyhow::anyhow!("NBP lookup failed: {}", e))?;

    if tuples.is_empty() {
        anyhow::bail!("no printer found — is it powered on and on the same network?");
    }

    let printer = &tuples[0];
    println!(
        "Found: {} — {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );
    let old_name = printer.entity_name.object.clone();

    // The management ADSP port is fixed at socket 129, independent of the PAP
    // socket that NBP advertises.
    let mgmt_addr = AdspAddress {
        network_number: printer.network_number,
        node_number:    printer.node_id,
        socket_number:  SW_MGMT_SOCKET,
    };

    println!(
        "Connecting ADSP to {}.{} socket {}...",
        mgmt_addr.network_number, mgmt_addr.node_number, mgmt_addr.socket_number
    );
    let mut stream = timeout(Duration::from_secs(10), stack.connect_adsp(mgmt_addr))
        .await
        .map_err(|_| anyhow::anyhow!("ADSP connect timed out — is socket {} open?", SW_MGMT_SOCKET))?
        .map_err(|e| anyhow::anyhow!("ADSP connect failed: {}", e))?;
    println!("ADSP session established.");

    let mut resp = [0u8; 2];

    println!("Sending init query (0x{:04X})...", ATTN_GET_NAME);
    stream.send_attention(ATTN_GET_NAME, &[0x00]).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{:04X}", ATTN_GET_NAME))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{:04X}: {:02X?}", ATTN_GET_NAME, resp);
    }

    // Pascal string: length byte followed by the name bytes.
    let name_bytes = args.name.as_bytes();
    let mut pascal = Vec::with_capacity(1 + name_bytes.len());
    pascal.push(name_bytes.len() as u8);
    pascal.extend_from_slice(name_bytes);

    println!("Setting name to {:?} (0x{:04X})...", args.name, ATTN_SET_NAME);
    stream.send_attention(ATTN_SET_NAME, &pascal).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{:04X}", ATTN_SET_NAME))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{:04X}: {:02X?}", ATTN_SET_NAME, resp);
    }

    println!("Committing (0x{:04X})...", ATTN_COMMIT);
    stream.send_attention(ATTN_COMMIT, &[0x00]).await?;
    timeout(Duration::from_secs(30), stream.read_exact(&mut resp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for response to 0x{:04X}", ATTN_COMMIT))??;
    if resp != [0x00, 0x00] {
        anyhow::bail!("unexpected response to 0x{:04X}: {:02X?}", ATTN_COMMIT, resp);
    }

    stream.close().await?;
    println!("Connection closed.");

    println!("Waiting 3 s for the printer to re-register via NBP...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let verify_entity: EntityName = format!("{}:ColorStyleWriter2400AT@*", args.name)
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("could not build verification entity: {}", e))?;

    println!("Looking up '{}' to verify rename...", verify_entity);
    let verify_tuples = timeout(Duration::from_secs(10), stack.nbp.lookup(verify_entity))
        .await
        .map_err(|_| anyhow::anyhow!("NBP verification lookup timed out"))?
        .map_err(|e| anyhow::anyhow!("NBP verification lookup failed: {}", e))?;

    if verify_tuples.is_empty() {
        println!("WARNING: could not verify rename via NBP — printer may still be updating.");
        println!("  Old name: {}", old_name);
        println!("  New name: {} (requested)", args.name);
    } else {
        println!("Rename verified!");
        for t in &verify_tuples {
            println!("  {} — {}.{} socket {}", t.entity_name, t.network_number, t.node_id, t.socket_number);
        }
        println!("  {} → {}", old_name, args.name);
    }

    Ok(())
}
