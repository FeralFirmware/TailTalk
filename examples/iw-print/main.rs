use clap::Parser;
use std::process::Stdio;
use std::time::Duration;
use tailtalk::{TalkStack, atp::AtpAddress, imagewriter::ImageWriter};
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

/// Colour variant: one line per ribbon band, so a glance at the page shows
/// whether every band of the colour ribbon is actually being struck.
const COLOR_TEST_JOB: &str = "%!PS-Adobe-2.0\n\
    %%Title: TailTalk ImageWriter Colour Test Page\n\
    %%Creator: TailTalk iw-print\n\
    %%EndComments\n\
    /Courier findfont 24 scalefont setfont\n\
    /line { moveto show } bind def\n\
    1 0 0 setrgbcolor (Red    - Hello from TailTalk!) 108 500 line\n\
    0 1 0 setrgbcolor (Green  - Hello from TailTalk!) 108 460 line\n\
    0 0 1 setrgbcolor (Blue   - Hello from TailTalk!) 108 420 line\n\
    1 1 0 setrgbcolor (Yellow - Hello from TailTalk!) 108 380 line\n\
    0 0 0 setrgbcolor (Black  - Hello from TailTalk!) 108 340 line\n\
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

    /// NBP object name of the printer to look up, e.g. "ImageWriter LQ".
    /// The NBP type is always "ImageWriter"; "=" matches any.
    #[arg(short, long, default_value = "=")]
    printer: String,

    /// Path to the Ghostscript executable
    #[arg(long, default_value = "gs")]
    ghostscript: String,

    /// Write a LocalTalk pcap capture to this file
    #[arg(long)]
    pcap: Option<String>,

    /// Query the printer's status and exit without printing anything
    #[arg(long)]
    status_only: bool,

    /// Force the monochrome path even if a colour ribbon is installed
    #[arg(long)]
    mono: bool,

    /// Poll the printer's status this often (in seconds) while the job streams.
    /// 0 disables polling.
    #[arg(long, default_value_t = 0)]
    watch: u64,
}

async fn render_hello_world(gs_path: &str, color: bool) -> anyhow::Result<Vec<u8>> {
    // `iwhic` is the colour twin of `iwhi`.
    let device = if color {
        "-sDEVICE=iwhic"
    } else {
        "-sDEVICE=iwhi"
    };
    let job = if color {
        COLOR_TEST_JOB
    } else {
        HELLO_WORLD_JOB
    };

    let mut child = Command::new(gs_path)
        .args([
            "-q",
            "-dNOPAUSE",
            "-dBATCH",
            "-dSAFER",
            device,
            // Force Letter rather than inheriting the build's default paper
            // size: the device crashes on a page wider than 612pt or a height
            // that isn't a multiple of 24pt, and A4's 842pt is not (many
            // Ghostscript builds default to A4).
            "-dDEVICEWIDTHPOINTS=612",
            "-dDEVICEHEIGHTPOINTS=792",
            "-dFIXEDMEDIA",
            "-sOutputFile=-",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch Ghostscript ('{}'): {}", gs_path, e))?;

    let mut stdin = child.stdin.take().expect("stdin was piped");
    stdin.write_all(job.as_bytes()).await?;
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

    let tuples = ImageWriter::lookup(&stack.nbp, &args.printer).await?;
    let printer = tuples
        .first()
        .ok_or_else(|| anyhow::anyhow!("ImageWriter not found on network"))?;
    println!(
        "Found {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );
    let printer_addr: AtpAddress = printer.service_address().into();

    // Status needs no connection, so this works even if the printer is mid-job.
    let status = ImageWriter::status_of(&stack.ddp, printer_addr).await?;
    println!("Status word: 0x{:04X}", status.raw);
    println!("  Ribbon:       {}", status.ribbon_text());
    println!(
        "  Sheet feeder: {}",
        if status.sheet_feeder() {
            "installed"
        } else {
            "not installed"
        }
    );
    println!(
        "  Paper:        {}",
        if status.paper_present() {
            "loaded"
        } else {
            "out of paper"
        }
    );
    println!(
        "  Select:       {}",
        if status.off_line() { "off line" } else { "on line" }
    );
    println!("  Busy:         {}", status.busy());
    println!("  Printing:     {}", status.active());
    match status.error_text() {
        Some(e) => println!("  Errors:       {e}"),
        None => println!("  Errors:       none"),
    }

    if args.status_only {
        return Ok(());
    }
    if !status.ready_to_print() {
        anyhow::bail!(
            "printer is not ready ({}), refusing to print",
            status.error_text().unwrap_or_default()
        );
    }

    let color = status.color_ribbon() && !args.mono;
    println!(
        "Rendering the {} test page via Ghostscript",
        if color { "colour" } else { "monochrome" }
    );
    let raster = render_hello_world(&args.ghostscript, color).await?;
    println!("Rendered {} bytes", raster.len());

    let mut client = ImageWriter::connect(&stack.ddp, printer_addr).await?;
    if args.watch > 0 {
        print_watching(&mut client, &raster, Duration::from_secs(args.watch)).await?;
    } else {
        client.print_bytes(&raster).await?;
    }
    client.close().await?;

    Ok(())
}

/// Stream the job while polling the printer, to show what the option card
/// reports as a page goes through. The status socket is separate from the one
/// carrying the job, so the poll runs alongside the print rather than between
/// chunks of it.
async fn print_watching(
    client: &mut ImageWriter,
    raster: &[u8],
    every: Duration,
) -> anyhow::Result<()> {
    let status = client.status_handle();
    let mut ticker = tokio::time::interval(every);
    ticker.tick().await; // the first tick is immediate

    tokio::select! {
        result = client.print_bytes(raster) => result?,
        // Never returns, so the job is always what ends the select.
        _ = async {
            loop {
                ticker.tick().await;
                match status.read().await {
                    // Busy stays set for the whole job: that is our own connection.
                    Ok(s) => println!(
                        "  [status] 0x{:04X} printing={} {}",
                        s.raw,
                        s.active(),
                        s.error_text().unwrap_or_else(|| "no errors".to_string())
                    ),
                    Err(e) => eprintln!("  [status] poll failed: {e}"),
                }
            }
        } => {}
    }
    Ok(())
}
