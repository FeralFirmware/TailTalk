use clap::Parser;
use tailtalk::{
    TalkStack,
    atp::{Atp, AtpAddress},
    pap::PapClient,
};
use tailtalk_packets::nbp::EntityName;

#[derive(Parser, Debug)]
#[command(about = "Print a PostScript file to a PAP-capable AppleTalk printer")]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
    interface: String,

    /// Printer entity name to look up, e.g. "LaserWriter 4/600:LaserWriter@*"
    #[arg(short, long, default_value = "=:LaserWriter@*")]
    printer: String,

    /// PostScript file to print (omit for a built-in test page)
    #[arg(short, long)]
    file: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let entity: EntityName = args
        .printer
        .as_str()
        .try_into()
        .map_err(|e| anyhow::anyhow!("Invalid printer name: {}", e))?;

    let stack = TalkStack::builder()
        .ethernet(&args.interface)
        .build()
        .await
        .expect("failed to build AppleTalk stack");

    // Two ATP sockets: one for sending requests, one for receiving printer-initiated ones
    let (_req_sock, atp_requestor, _) = Atp::spawn(&stack.ddp, None).await;
    let (_resp_sock, _, atp_responder) = Atp::spawn(&stack.ddp, None).await;

    // Give AARP a moment to acquire a node address
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Locate the printer via NBP
    println!("Looking up printer '{}'...", entity);
    let tuples = stack.nbp.lookup(entity).await?;
    let printer = tuples
        .first()
        .ok_or_else(|| anyhow::anyhow!("Printer not found on network"))?;

    println!(
        "Found printer {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );

    let printer_addr = AtpAddress {
        network_number: printer.network_number,
        node_number: printer.node_id,
        socket_number: printer.socket_number,
    };

    // Query status
    println!("Querying printer status...");
    let status_requestor = atp_requestor.clone();
    match PapClient::get_status(status_requestor, printer_addr).await {
        Ok(status) => println!("Printer status: '{}'", status),
        Err(e) => println!("Could not get status: {}", e),
    }

    // Prepare data
    let data = if let Some(path) = &args.file {
        println!("Reading file '{}'...", path);
        std::fs::read(path)?
    } else {
        println!("Using built-in test page...");
        b"%!PS-Adobe-2.0
%%Title: TailTalk Test Page
%%Creator: TailTalk pap-print
%%EndComments
/Courier findfont 15 scalefont setfont
72 720 moveto
(TailTalk PAP Test) show
showpage
"
        .to_vec()
    };

    println!("Connecting to printer ({} bytes to send)...", data.len());
    let mut client = PapClient::new(atp_requestor, atp_responder);
    client.connect(printer_addr).await?;

    println!("Printing...");
    client.print(&data).await?;

    println!("Print job finished successfully!");

    Ok(())
}
