use clap::Parser;
use std::io::Write;
use tailtalk::{
    TalkStack,
    adsp::AdspAddress,
    stylewriter::{
        MAX_BATCH_BYTES, PrintQuality, SW2200_PRINT_ROWBYTES, SW2200_PRINT_WIDTH,
        StyleWriterEncoder, StyleWriterSession, chunky_to_mono_plane, chunky_to_planes,
        encode_page_batches,
    },
};
use tailtalk_packets::nbp::EntityName;

#[derive(Parser, Debug)]
#[command(about = "Print a raw raster file to a Color StyleWriter via ADSP/EtherTalk")]
struct Args {
    /// Network interface to bind to (ignored when --dump is set)
    #[arg(short, long, default_value = "")]
    interface: String,

    /// Printer entity name to look up, e.g. "Color StyleWriter 2400:LaserWriter@*"
    #[arg(short, long, default_value = "=:LaserWriter@*")]
    printer: String,

    /// Raw Raster file to print
    #[arg(short, long)]
    file: String,

    /// Raster width in pixels (for raw headerless formats)
    #[arg(short = 'W', long, default_value_t = 2880)]
    width: usize,

    /// Dump encoded raster blocks to stdout instead of printing (for diffing against C reference)
    #[arg(long)]
    dump: bool,

    /// AppleTalk username to send in the print request handshake
    #[arg(short, long, default_value = "user")]
    username: String,

    /// Send only the K-nibble bit as a single monochrome plane ('R' tag)
    /// instead of full 4-plane CMYK ('c' tag). The StyleWriter I tested with
    /// allows using either the colour cartridge _or_ the black one. If Colour
    /// is chosen the printer will ignore the K-nibble and print the CMY planes instead.
    /// The native Mac OS driver does the same.
    #[arg(long)]
    mono: bool,

    /// Print quality: "normal" or "best" (see PrintQuality docs for which
    /// combinations are verified on real hardware)
    #[arg(short, long, default_value = "normal")]
    quality: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let quality = match args.quality.as_str() {
        "normal" => PrintQuality::Normal,
        "best" => PrintQuality::Best,
        other => anyhow::bail!("Unknown quality '{other}' (expected 'normal' or 'best')"),
    };

    let raw_data = std::fs::read(&args.file)?;
    let width_pixels = args.width;
    let chunky_scanline_len = width_pixels / 2;
    let planar_scanline_len = width_pixels / 8;
    let total_rows = raw_data.len() / chunky_scanline_len;

    eprintln!("Image: {} pixels wide, {} scanlines", width_pixels, total_rows);
    eprintln!("SW2200_PRINT_ROWBYTES = {}, padding {} px per plane with white",
        SW2200_PRINT_ROWBYTES, SW2200_PRINT_WIDTH - width_pixels);

    // Unpack every chunky scanline into raw planar rows, then encode the
    // whole page into rect+G bands (delta chains and band splitting live in
    // encode_page_batches).
    let rows: Vec<Vec<Vec<u8>>> = raw_data
        .chunks(chunky_scanline_len)
        .take(total_rows)
        .map(|chunky| {
            if args.mono {
                vec![chunky_to_mono_plane(chunky, planar_scanline_len)]
            } else {
                chunky_to_planes(chunky, planar_scanline_len).into()
            }
        })
        .collect();
    let batches = encode_page_batches(&rows, args.mono);

    // ── Dump mode: write raster blocks to stdout for comparison with C reference ─
    if args.dump {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for batch in &batches {
            // Rows are padded to the full printable width, so the rect
            // right edge is SW2200_PRINT_WIDTH (not the source width) —
            // keeps dump output byte-identical to what write_batch sends.
            let rect = StyleWriterEncoder::encode_rect(
                batch.top, 0, batch.bottom, SW2200_PRINT_WIDTH as u16, !args.mono,
            );
            let g_block = StyleWriterEncoder::wrap_raster_chunk(&batch.data);
            out.write_all(&rect)?;
            out.write_all(&g_block)?;
        }
        return Ok(());
    }

    // ── Network mode ─

    anyhow::ensure!(!args.interface.is_empty(), "--interface is required for printing");

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

    eprintln!("Looking up printer '{}'...", entity);
    let tuples = stack.nbp.lookup(entity).await?;
    let printer = tuples
        .first()
        .ok_or_else(|| anyhow::anyhow!("Printer not found on network"))?;

    eprintln!(
        "Found printer {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );

    let printer_addr = AdspAddress {
        network_number: printer.network_number,
        node_number: printer.node_id,
        socket_number: printer.socket_number,
    };

    eprintln!("Connecting to printer...");
    let mut session = StyleWriterSession::connect(&stack.ddp, printer_addr, &args.username).await?;
    eprintln!("Connected! Running setup...");

    // Run setup + raster transmission in a block so any failure can eject
    // the loaded page and reset the printer instead of leaving it stuck.
    let print_result: anyhow::Result<()> = async {
        session.setup(!args.mono, quality).await?;

        eprintln!("Transmitting {} rasters as {} delta-encoded band(s) ({} bytes/batch max)...",
            if args.mono { "monochrome" } else { "color" },
            batches.len(),
            MAX_BATCH_BYTES);
        for batch in &batches {
            session.write_batch(batch.top, batch.bottom, &batch.data, !args.mono).await?;
        }
        Ok(())
    }
    .await;

    if let Err(e) = print_result {
        eprintln!("Print failed ({e:#}); ejecting page and resetting printer...");
        let _ = session.abort().await;
        return Err(e);
    }

    eprintln!("Print data sent. Finishing page...");
    session.finish().await?;

    eprintln!("Done!");
    Ok(())
}
