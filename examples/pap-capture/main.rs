use anyhow::Result;
use clap::Parser;
use tailtalk::{
    TalkStack,
    pap::{FileSink, PaperSize, PrinterAttributes},
};

#[derive(Parser, Debug)]
#[command(about = "Emulate a PAP LaserWriter and capture incoming PostScript jobs to disk")]
struct Args {
    /// Network interface to bind to (EtherTalk)
    #[arg(short, long)]
    interface: Option<String>,

    /// TashTalk serial port path (LocalTalk)
    #[arg(short, long)]
    tashtalk: Option<String>,

    /// Printer name to advertise in NBP, e.g. "Color LaserWriter 12/600"
    #[arg(short, long, default_value = "Color LaserWriter 12/600")]
    name: String,

    /// Directory to write captured PostScript files into
    #[arg(short, long, default_value = ".")]
    output: String,

    /// Write a pcap capture to this file
    #[arg(long)]
    pcap: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

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
    if let Some(ref path) = args.pcap {
        builder = builder.pcap_capture(path);
    }
    let stack = builder.build().await?;

    let attrs = PrinterAttributes {
        status: "%%[ status: idle; source: EtherTalk ]%%".to_string(),
        product_name: args.name.clone(),
        language_level: 2,
        color: true,
        resolutions_dpi: vec![600],
        paper_sizes: vec![PaperSize::Letter, PaperSize::A4],
    };

    let mut server = stack
        .add_printer(&args.name, attrs, FileSink::new(&args.output))
        .await?;

    println!(
        "Advertising \"{}\" on socket {} — saving jobs to: {}",
        args.name, server.socket_number, args.output
    );

    server.run().await
}
