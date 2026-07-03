use clap::Parser;
use std::io::Write;
use tailtalk::{
    TalkStack,
    adsp::AdspAddress,
    stylewriter::{StyleWriterEncoder, StyleWriterSession, MAX_BATCH_BYTES, SW2200_PRINT_ROWBYTES, SW2200_PRINT_WIDTH},
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

}

/// Unpack one chunky scanline into raw (pre-RLE) CMYK planar bytes.
fn chunky_to_planes(chunky: &[u8], planar_input_len: usize) -> [Vec<u8>; 4] {
    let mut planes = [
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
    ];

    for chunk_block in chunky.chunks(4) {
        let mut c = 0u8;
        let mut m = 0u8;
        let mut y = 0u8;
        let mut k = 0u8;
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            c = (c << 2) | ((b >> 6) & 2) | ((b >> 3) & 1);
            m = (m << 2) | ((b >> 5) & 2) | ((b >> 2) & 1);
            y = (y << 2) | ((b >> 4) & 2) | ((b >> 1) & 1);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        planes[0].push(c);
        planes[1].push(m);
        planes[2].push(y);
        planes[3].push(k);
    }
    planes
}

/// Unpack one chunky scanline's K-nibble bit only into a raw (pre-RLE) plane.
fn chunky_to_mono_plane(chunky: &[u8], planar_input_len: usize) -> Vec<u8> {
    let mut plane = Vec::with_capacity(planar_input_len);
    for chunk_block in chunky.chunks(4) {
        let mut k = 0u8;
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        plane.push(k);
    }
    plane
}

/// Encode one row's plane(s) into concatenated RLE bytes. `use_delta` XORs
/// each plane against the previous row's raw plane first (lpstyl's
/// `appendEncode()` differencing).
///
/// Delta is NOT optional for color: 'c'/"m2sAH" mode reconstructs each row
/// by XORing against the previous one, so absolute rows print as
/// cumulative-XOR garbage. Monochrome 'R'/"m2nZAB" bands are absolute.
///
/// `use_delta` must be false for the first row of every rect+G block, since
/// the printer's differencing state resets per block. Does not mutate
/// `last` — the caller updates it once per source row, so a row re-encoded
/// after a batch flush still deltas correctly.
fn encode_row(planes: &[Vec<u8>], last: &[Vec<u8>], use_delta: bool, mono: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, plane) in planes.iter().enumerate() {
        let delta;
        let src = if use_delta {
            delta = plane.iter().zip(last[i].iter()).map(|(c, l)| c ^ l).collect::<Vec<u8>>();
            &delta
        } else {
            plane
        };
        // K plane (mono, or index 3 of CMYK) never uses the blank-shortcut
        // (see encode_scanline docs); C/M/Y planes do.
        let allow_shortcut = !mono && i != 3;
        out.extend_from_slice(&StyleWriterEncoder::encode_scanline(src, SW2200_PRINT_ROWBYTES, allow_shortcut));
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let args = Args::parse();

    let raw_data = std::fs::read(&args.file)?;
    // Color rows must be XOR-delta encoded; mono rows must be absolute
    // (see encode_row) — this is the printer's wire format, not a choice.
    let use_delta = !args.mono;
    let width_pixels = args.width;
    let chunky_scanline_len = width_pixels / 2;
    let planar_scanline_len = width_pixels / 8;
    let total_rows = raw_data.len() / chunky_scanline_len;

    eprintln!("Image: {} pixels wide, {} scanlines", width_pixels, total_rows);
    eprintln!("SW2200_PRINT_ROWBYTES = {}, padding {} px per plane with white",
        SW2200_PRINT_ROWBYTES, SW2200_PRINT_WIDTH - width_pixels);

    // ── Dump mode: write raster blocks to stdout for comparison with C reference ─
    if args.dump {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let mut batch_start = 0usize;
        let mut batch_data = Vec::new();
        let mut last_planes = vec![vec![0u8; planar_scanline_len]; if args.mono { 1 } else { 4 }];
        for (row_idx, chunky) in raw_data.chunks(chunky_scanline_len).enumerate() {
            let planes: Vec<Vec<u8>> = if args.mono {
                vec![chunky_to_mono_plane(chunky, planar_scanline_len)]
            } else {
                chunky_to_planes(chunky, planar_scanline_len).into()
            };
            let mut row_enc = encode_row(&planes, &last_planes, use_delta && !batch_data.is_empty(), args.mono);
            // Flush before this row would cross the printer's buffer size:
            // one G block must stay strictly below MAX_BATCH_BYTES.
            if !batch_data.is_empty() && batch_data.len() + row_enc.len() >= MAX_BATCH_BYTES {
                let rect = StyleWriterEncoder::encode_rect(
                    batch_start as u16, 0, (row_idx - 1) as u16, SW2200_PRINT_WIDTH as u16, !args.mono,
                );
                let g_block = StyleWriterEncoder::wrap_raster_chunk(&batch_data);
                out.write_all(&rect)?;
                out.write_all(&g_block)?;
                batch_start = row_idx;
                batch_data.clear();
                if use_delta {
                    // This row now starts a new block: the delta chain resets.
                    row_enc = encode_row(&planes, &last_planes, false, args.mono);
                }
            }
            batch_data.extend_from_slice(&row_enc);
            last_planes = planes;
            if row_idx + 1 == total_rows {
                // Rows are padded to the full printable width, so the rect
                // right edge is SW2200_PRINT_WIDTH (not the source width) —
                // keeps dump output byte-identical to what write_batch sends.
                let rect = StyleWriterEncoder::encode_rect(
                    batch_start as u16, 0, row_idx as u16, SW2200_PRINT_WIDTH as u16, !args.mono,
                );
                let g_block = StyleWriterEncoder::wrap_raster_chunk(&batch_data);
                out.write_all(&rect)?;
                out.write_all(&g_block)?;
            }
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
    let mut session = StyleWriterSession::connect(&stack, printer_addr, &args.username).await?;
    eprintln!("Connected! Running setup...");

    // Run setup + raster transmission in a block so any failure can eject
    // the loaded page and reset the printer instead of leaving it stuck.
    let print_result: anyhow::Result<()> = async {
        session.setup(!args.mono).await?;

        eprintln!("Encoding and transmitting {} rasters ({}batched, {} bytes/batch max)...",
            if args.mono { "monochrome" } else { "color" },
            if use_delta { "delta-encoded, " } else { "" },
            MAX_BATCH_BYTES);
        let mut batch_start = 0usize;
        let mut batch_data = Vec::new();
        let mut last_planes = vec![vec![0u8; planar_scanline_len]; if args.mono { 1 } else { 4 }];
        for (row_idx, chunky) in raw_data.chunks(chunky_scanline_len).enumerate() {
            let planes: Vec<Vec<u8>> = if args.mono {
                vec![chunky_to_mono_plane(chunky, planar_scanline_len)]
            } else {
                chunky_to_planes(chunky, planar_scanline_len).into()
            };
            let mut row_enc = encode_row(&planes, &last_planes, use_delta && !batch_data.is_empty(), args.mono);
            // Flush before this row would cross the printer's buffer size:
            // one G block must stay strictly below MAX_BATCH_BYTES.
            if !batch_data.is_empty() && batch_data.len() + row_enc.len() >= MAX_BATCH_BYTES {
                session.write_batch(batch_start as u16, (row_idx - 1) as u16, &batch_data, !args.mono).await?;
                batch_start = row_idx;
                batch_data.clear();
                if use_delta {
                    // This row now starts a new block: the delta chain resets.
                    row_enc = encode_row(&planes, &last_planes, false, args.mono);
                }
            }
            batch_data.extend_from_slice(&row_enc);
            last_planes = planes;
            if row_idx + 1 == total_rows {
                session.write_batch(batch_start as u16, row_idx as u16, &batch_data, !args.mono).await?;
            }
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
