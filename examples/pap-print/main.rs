use clap::{Parser, Subcommand};
use tailtalk::{
    TalkStack,
    atp::AtpAddress,
};
use tailtalk_packets::nbp::EntityName;
use tokio::time::Duration;

#[derive(Parser, Debug)]
#[command(about = "Print and query PAP-capable AppleTalk printers")]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long, global = true)]
    interface: Option<String>,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long, global = true)]
    tashtalk: Option<String>,

    /// Printer entity name to look up, e.g. "LaserWriter 4/600:LaserWriter@*"
    #[arg(short, long, global = true, default_value = "=:LaserWriter@*")]
    printer: String,

    /// Write a LocalTalk pcap capture to this file
    #[arg(long, global = true)]
    pcap: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print a PostScript file (omit --file for a built-in test page)
    Print {
        /// PostScript file to send
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Query the printer's PAP status string
    Status,
    /// Query printer settings via the PostScript Query Protocol (PQP)
    Query,
    /// Dump the entire statusdict (all keys and values) for diagnostics
    DumpStatusdict,
    /// Connect to the printer and immediately close the connection (for diagnostics)
    TestClose,
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
        .ok_or_else(|| anyhow::anyhow!("Printer not found on network"))?;

    println!(
        "Found {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );

    let printer_addr = AtpAddress {
        network_number: printer.network_number,
        node_number: printer.node_id,
        socket_number: printer.socket_number,
    };

    match args.command {
        Command::Status => {
            let status = stack.pap_status(printer_addr).await?;
            println!("{}", status);
        }

        Command::Query => {
            let labels = &[
                "Product", "PS Version", "Firmware Rev", "Resolution",
                "RAM (bytes)", "Page count", "Page size (pts)", "AppleTalk type",
            ];

            // All queries in one job. `stopped` isolates failures per entry; `printval`
            // handles arrays (e.g. PageSize). Procedure entries need `begin/end` to call them.
            let job =
                "%!PS-Adobe-3.0\n\
                 %%EndComments\n\
                 errordict /handleerror {} put\n\
                 /printval {\n\
                   dup type /arraytype eq {\n\
                     { dup type /stringtype eq { print } { 20 string cvs print } ifelse ( ) print } forall\n\
                     (\\n) print\n\
                   } { = } ifelse\n\
                 } def\n\
                 { statusdict /product get printval } stopped { (error) = } if\n\
                 { version printval } stopped { (error) = } if\n\
                 { statusdict /revision get printval } stopped { (error) = } if\n\
                 { statusdict /resolution get printval } stopped { currentpagedevice /HWResolution get 0 get printval } if\n\
                 { statusdict begin ramsize end printval } stopped { (error) = } if\n\
                 { statusdict begin pagecount end printval } stopped { (error) = } if\n\
                 { currentpagedevice /PageSize get printval } stopped { (error) = } if\n\
                 { statusdict /appletalktype get printval } stopped { (error) = } if\n\
                 flush\n\
                 %%EOF\n";

            let mut client = stack.pap_client().await;
            client.connect(printer_addr).await?;
            client.print_stream(std::io::Cursor::new(job.as_bytes())).await?;

            let response_bytes = tokio::time::timeout(
                Duration::from_secs(15),
                client.read_response(),
            ).await.unwrap_or_else(|_| Ok(vec![]))?;

            client.close().await?;

            let response = String::from_utf8_lossy(&response_bytes);
            let mut lines = response.lines();
            for label in labels {
                let value = lines.next().unwrap_or("no response");
                println!("{label}: {}", if value.is_empty() { "no response" } else { value });
            }
        }

        Command::Print { file } => {
            println!("Querying status...");
            match stack.pap_status(printer_addr).await {
                Ok(status) => println!("Status: {}", status),
                Err(e) => println!("Could not get status: {}", e),
            }

            let mut client = stack.pap_client().await;
            client.connect(printer_addr).await?;

            if let Some(path) = file {
                println!("Sending '{}'...", path);
                let f = tokio::fs::File::open(&path).await?;
                client.print_stream(f).await?;
            } else {
                println!("Sending built-in test page...");
                let data: &[u8] = b"%!PS-Adobe-2.0
%%Title: TailTalk Test Page
%%Creator: TailTalk pap-print
%%EndComments
/Courier findfont 15 scalefont setfont
72 720 moveto
(TailTalk PAP Test) show
showpage
";
                client.print_stream(std::io::Cursor::new(data)).await?;
            }

            println!("Done.");
        }

        Command::DumpStatusdict => {
            let job =
                "%!PS-Adobe-3.0\n\
                 %%EndComments\n\
                 errordict /handleerror {} put\n\
                 statusdict { exch = = } forall\n\
                 flush\n\
                 %%EOF\n";

            let mut client = stack.pap_client().await;
            client.connect(printer_addr).await?;
            client.print_stream(std::io::Cursor::new(job.as_bytes())).await?;

            let response_bytes = tokio::time::timeout(
                Duration::from_secs(15),
                client.read_response(),
            ).await.unwrap_or_else(|_| Ok(vec![]))?;

            client.close().await?;

            print!("{}", String::from_utf8_lossy(&response_bytes));
        }

        Command::TestClose => {
            println!("Connecting...");
            let mut client = stack.pap_client().await;
            client.connect(printer_addr).await?;
            println!("Connected. Sending CloseConn...");
            client.close().await?;
            println!("CloseConn acknowledged.");
        }
    }

    Ok(())
}
