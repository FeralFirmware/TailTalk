use clap::Parser;
use std::process::Stdio;
use tailtalk::{TalkStack, atp::AtpAddress};
use tailtalk_packets::nbp::EntityName;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const HELLO_WORLD_JOB: &str = "%!PS-Adobe-2.0\n\
    %%Title: TailTalk ImageWriter Test Page\n\
    %%Creator: TailTalk iw-print\n\
    %%EndComments\n\
    /Courier findfont 24 scalefont setfont\n\
    /msg (Hello from TailTalk!) def\n\
    msg stringwidth pop 612 exch sub 2 div 396 moveto\n\
    msg show\n\
    showpage\n\
    %%EOF\n";

#[derive(Parser, Debug)]
#[command(about = "Print a 'Hello world!' test page on an Apple ImageWriter II via PAP")]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long)]
    interface: Option<String>,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long)]
    tashtalk: Option<String>,

    /// Printer entity name to look up, e.g. "ImageWriter LQ:ImageWriter@*"
    #[arg(short, long, default_value = "=:ImageWriter@*")]
    printer: String,

    /// Path to the Ghostscript executable
    #[arg(long, default_value = "gs")]
    ghostscript: String,

    /// Write a LocalTalk pcap capture to this file
    #[arg(long)]
    pcap: Option<String>,
}

async fn render_hello_world(gs_path: &str) -> anyhow::Result<Vec<u8>> {
    let mut child = Command::new(gs_path)
        .args([
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            "-sDEVICE=iwhi",
            "-sOutputFile=-",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch Ghostscript ('{}'): {}", gs_path, e))?;

    let mut stdin = child.stdin.take().expect("stdin was piped");
    stdin.write_all(HELLO_WORLD_JOB.as_bytes()).await?;
    drop(stdin); // EOF tells Ghostscript the job is complete

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        anyhow::bail!(
            "Ghostscript exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if output.stdout.is_empty() {
        anyhow::bail!("Ghostscript produced no output");
    }
    Ok(output.stdout)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    if args.interface.is_none() && args.tashtalk.is_none() {
        anyhow::bail!("at least one of --interface or --tashtalk is required");
    }

    let entity: EntityName = args
        .printer
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid printer name: {}", e))?;

    let mut builder = TalkStack::builder();
    if let Some(ref intf) = args.interface {
        builder = builder.ethernet(intf);
    }
    if let Some(ref tty) = args.tashtalk {
        builder = builder.localtalk(tty);
    }
    if let Some(ref path) = args.pcap {
        builder = builder.pcap_capture(path);
    }
    let stack = builder
        .build()
        .await
        .expect("failed to build AppleTalk stack");

    let tuples = stack.nbp.lookup(entity).await?;
    let printer = tuples
        .first()
        .ok_or_else(|| anyhow::anyhow!("ImageWriter not found on network"))?;
    println!(
        "Found {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );

    let printer_addr = AtpAddress {
        network_number: printer.network_number,
        node_number: printer.node_id,
        socket_number: printer.socket_number,
    };

    let raster = render_hello_world(&args.ghostscript).await?;
    println!("Rendered {} bytes", raster.len());

    let mut client = stack.pap_client().await;
    client.connect(printer_addr).await?;
    client.chunk_size = Some(512);

    client.print_stream(std::io::Cursor::new(raster)).await?;
    client.close().await?;

    Ok(())
}
