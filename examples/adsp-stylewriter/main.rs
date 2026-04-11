use clap::Parser;
use tailtalk::{
    PacketProcessor,
    addressing::Addressing,
    adsp::{Adsp, AdspAddress},
    ddp::DdpProcessor,
    nbp::Nbp,
    stylewriter::StyleWriterEncoder,
};
use tailtalk_packets::nbp::EntityName;
use tokio::io::AsyncWriteExt;

#[derive(Parser, Debug)]
#[command(about = "Print a raw raster file to a Color StyleWriter via ADSP/EtherTalk")]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
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

    let (processor, handle) = PacketProcessor::builder()
        .ethernet(&args.interface)
        .build()
        .expect("failed to build PacketProcessor");
    let addressing = Addressing::spawn(processor.get_mac().expect("ethernet transport required"), handle.clone(), None);
    let ddp = DdpProcessor::spawn(addressing.clone(), handle.clone());
    let nbp = Nbp::spawn(&ddp, addressing.clone()).await;

    let proc_addressing = addressing.clone();
    let proc_ddp = ddp.clone();
    tokio::task::spawn_blocking(|| processor.run(proc_addressing, proc_ddp));

    // Give AARP a moment to acquire a node address
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Locate the printer via NBP
    println!("Looking up printer '{}'...", entity);
    let tuples = nbp.lookup(entity).await?;
    let printer = tuples
        .first()
        .ok_or_else(|| anyhow::anyhow!("Printer not found on network"))?;

    println!(
        "Found printer {} at {}.{} socket {}",
        printer.entity_name, printer.network_number, printer.node_id, printer.socket_number
    );

    let printer_addr = AdspAddress {
        network_number: printer.network_number,
        node_number: printer.node_id,
        socket_number: printer.socket_number,
    };

    println!("Reading bitcmyk raster file '{}'...", args.file);
    let raw_data = std::fs::read(&args.file)?;

    // Ghostscript's bitcmyk format is chunky: 4 bits per pixel (CMYK). So 2 pixels per byte.
    let width_pixels = args.width;
    let chunky_scanline_len = width_pixels / 2;
    let planar_scanline_len = width_pixels / 8;

    println!("Connecting ADSP session to printer...");
    let mut adsp_stream = Adsp::connect(&ddp, printer_addr).await?;
    println!("ADSP session established!");

    // Send the initialization boundaries
    let mut init_block = Vec::new();
    // Color header c (top 0, left 0, bottom 1000, right width)
    init_block.extend_from_slice(&StyleWriterEncoder::encode_rect(
        0,
        0,
        1000,
        width_pixels as u16,
        true,
    ));
    adsp_stream.write_all(&init_block).await?;
    adsp_stream.write_eom().await?;

    // Now send the chunks
    println!("Encoding and transmitting color rasters...");
    for chunky_scanline in raw_data.chunks(chunky_scanline_len) {
        let mut planes = [
            Vec::with_capacity(planar_scanline_len), // C
            Vec::with_capacity(planar_scanline_len), // M
            Vec::with_capacity(planar_scanline_len), // Y
            Vec::with_capacity(planar_scanline_len), // K
        ];

        for chunk_block in chunky_scanline.chunks(4) {
            let mut c_byte = 0u8;
            let mut m_byte = 0u8;
            let mut y_byte = 0u8;
            let mut k_byte = 0u8;

            for i in 0..4 {
                let b = chunk_block.get(i).copied().unwrap_or(0);
                c_byte = (c_byte << 2) | ((b >> 6) & 2) | ((b >> 3) & 1);
                m_byte = (m_byte << 2) | ((b >> 5) & 2) | ((b >> 2) & 1);
                y_byte = (y_byte << 2) | ((b >> 4) & 2) | ((b >> 1) & 1);
                k_byte = (k_byte << 2) | ((b >> 3) & 2) | (b & 1);
            }

            planes[0].push(c_byte);
            planes[1].push(m_byte);
            planes[2].push(y_byte);
            planes[3].push(k_byte);
        }

        let mut raster_block = Vec::new();

        // Color StyleWriter expected order: C, M, Y, K
        for plane in &planes {
            let encoded_line = StyleWriterEncoder::encode_scanline(plane, planar_scanline_len);
            let g_wrapped = StyleWriterEncoder::wrap_raster_chunk(&encoded_line);
            raster_block.extend_from_slice(&g_wrapped);
        }

        adsp_stream.write_all(&raster_block).await?;
        adsp_stream.write_eom().await?;
    }

    println!("Print job finished! Closing connection...");
    adsp_stream.close().await?;

    Ok(())
}
