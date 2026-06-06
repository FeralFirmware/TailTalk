use anyhow::Error;
use mac_address::mac_address_by_name;
use rand::Rng;
use std::path::PathBuf;
use std::time::SystemTime;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::ethertalk::{EtherTalkPhase2Frame, EtherTalkPhase2Type};
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tashtalk::TashTalk;
use tokio::sync::mpsc;
use tokio_serial::SerialPortBuilderExt;
use futures::StreamExt;
pub use tokio_util::sync::CancellationToken;

pub use tashtalk::TashTalkFeatures;

pub mod addressing;
pub mod adsp;
pub mod afp;
pub mod asp;
pub mod atp;

pub mod ddp;
pub mod echo;
pub mod nbp;
pub mod pap;
pub mod stylewriter;

#[derive(Debug, PartialEq, Eq)]
pub enum DataLinkProtocol {
    Ddp,
    Aarp,
    LlapEnq,
    LlapAck,
}

#[derive(Debug)]
pub struct DataLinkPacket {
    pub dest_node: addressing::Node,
    pub protocol: DataLinkProtocol,
    pub payload: Box<[u8]>,
    /// Our own LocalTalk node ID, used to populate the LLAP `src_node` field.
    /// Zero for Ethernet destinations (LLAP is not used on EtherTalk).
    pub src_node_id: u8,
}

/// Trivial pcap codec that boxes the raw Ethernet frame bytes.
struct EtherTalkCodec;

impl pcap::PacketCodec for EtherTalkCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        packet.data.into()
    }
}

pub struct PacketProcessor {
    /// RX capture, consumed into an async stream in `run()`.
    pcap_rx: Option<pcap::Capture<pcap::Active>>,
    /// TX capture, used for packet injection in the outbound loop.
    pcap_tx: Option<pcap::Capture<pcap::Active>>,
    outbound_rx: mpsc::Receiver<DataLinkPacket>,
    our_mac: Option<[u8; 6]>,
    /// Opened TashTalk instance, stored here and handed to the async task in `run()`.
    tashtalk: Option<TashTalk<tokio_serial::SerialStream>>,
    /// CRC features to set on the TashTalk firmware at startup.
    tashtalk_features: tashtalk::TashTalkFeatures,
    /// Sender to the LocalTalk pcap writer thread, if capture is enabled.
    pcap_sender: Option<std::sync::mpsc::SyncSender<(SystemTime, Vec<u8>)>>,
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`PacketProcessor`].
///
/// At least one transport must be configured before calling [`build`](PacketProcessorBuilder::build).
///
/// # Example – EtherTalk only
/// ```no_run
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Example – LocalTalk only
/// ```no_run
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Example – both transports
/// ```no_run
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct PacketProcessorBuilder {
    ethernet_intf: Option<String>,
    localtalk_serial_path: Option<String>,
    tashtalk_features: tashtalk::TashTalkFeatures,
    pcap_path: Option<PathBuf>,
}

impl PacketProcessorBuilder {
    fn new() -> Self {
        Self {
            ethernet_intf: None,
            localtalk_serial_path: None,
            tashtalk_features: tashtalk::TashTalkFeatures::new(),
            pcap_path: None,
        }
    }

    /// Configure an EtherTalk transport on the given network interface.
    pub fn ethernet(mut self, intf: &str) -> Self {
        self.ethernet_intf = Some(intf.to_string());
        self
    }

    /// Configure which CRC features the TashTalk firmware should enable.
    ///
    /// By default no features are enabled.  Call this with a [`TashTalkFeatures`]
    /// value to turn on hardware CRC generation, checking, or both.
    pub fn tashtalk_features(mut self, features: tashtalk::TashTalkFeatures) -> Self {
        self.tashtalk_features = features;
        self
    }

    /// Configure a LocalTalk transport via a TashTalk serial adapter.
    ///
    /// The serial port is opened during [`build`](Self::build). The TashTalk
    /// async task (including node-ID registration) is started inside
    /// [`PacketProcessor::run`], which already receives the `addressing` and
    /// `ddp` handles needed for that setup.
    pub fn localtalk(mut self, serial_path: &str) -> Self {
        self.localtalk_serial_path = Some(serial_path.to_string());
        self
    }

    /// Enable LocalTalk pcap capture to the given file path.
    ///
    /// When set, every LocalTalk frame received from or sent to the TashTalk
    /// device is written to a pcap file (DLT 114 / LINKTYPE_LOCALTALK).
    /// Frames are written without the trailing CRC bytes.
    pub fn pcap_capture(mut self, path: impl Into<PathBuf>) -> Self {
        self.pcap_path = Some(path.into());
        self
    }

    /// Finalise the builder: open pcap captures and the serial port as configured.
    pub fn build(self) -> Result<(PacketProcessor, OutboundHandle), Error> {
        let mut pcap_rx: Option<pcap::Capture<pcap::Active>> = None;
        let mut pcap_tx: Option<pcap::Capture<pcap::Active>> = None;
        let mut our_mac: Option<[u8; 6]> = None;

        // ── EtherTalk setup ──────────────────────────────────────────────────
        if let Some(ref intf) = self.ethernet_intf {
            // Retrieve the interface MAC address cross-platform.
            let mac = mac_address_by_name(intf)?
                .ok_or_else(|| anyhow::anyhow!("no MAC address found for interface {}", intf))?;
            our_mac = Some(mac.bytes());

            // BPF filter: Phase 1 AppleTalk (0x809B), Phase 1 AARP (0x80F3),
            // and any IEEE 802.2 LLC/SNAP frame (length field ≤ 1500) for Phase 2.
            let filter = format!("(ether proto 0x809B or ether proto 0x80F3 or (ether[12:2] <= 1500)) and not ether src {mac}");

            tracing::info!("filter string: {filter}");
            // RX capture – promiscuous mode, filter applied.
            let mut rx = pcap::Capture::from_device(intf.as_str())?
                .promisc(true)
                .immediate_mode(true)
                .open()?;
            rx.filter(&filter, true)?;

            pcap_rx = Some(rx);

            // TX capture – separate handle used solely for packet injection.
            let tx = pcap::Capture::from_device(intf.as_str())?
                .promisc(true)
                .open()?;
            pcap_tx = Some(tx);

            tracing::info!("EtherTalk pcap captures opened on {}", intf);
        }

        // ── LocalTalk / TashTalk setup ───────────────────────────────────────
        // Open the serial port now so failures surface at build time.
        // The async task is deferred to run() where addressing/ddp handles are available.
        let tashtalk = if let Some(path) = self.localtalk_serial_path {
            let stream = tokio_serial::new(&path, 1_000_000)
                .flow_control(tokio_serial::FlowControl::Hardware)
                .open_native_async()
                .map_err(|e| anyhow::anyhow!("Failed to open TashTalk serial port '{}': {e}", path))?;
            Some(TashTalk::new(stream))
        } else {
            None
        };

        let (outbound_tx, outbound_rx) = mpsc::channel(100);

        let pcap_sender = self.pcap_path.and_then(spawn_pcap_writer);

        let processor = PacketProcessor {
            pcap_rx,
            pcap_tx,
            outbound_rx,
            our_mac,
            tashtalk,
            tashtalk_features: self.tashtalk_features,
            pcap_sender,
        };
        let handle = OutboundHandle { tx: outbound_tx };

        Ok((processor, handle))
    }
}

// ── LocalTalk pcap writer ─────────────────────────────────────────────────────

/// Spawn a background thread that writes LocalTalk frames to a pcap file.
///
/// Returns a `SyncSender` that the caller uses to submit `(timestamp, frame)`
/// pairs. The thread exits when the sender is dropped (channel closed).
/// Frames should not include the trailing 2-byte LocalTalk CRC.
fn spawn_pcap_writer(
    path: PathBuf,
) -> Option<std::sync::mpsc::SyncSender<(SystemTime, Vec<u8>)>> {
    use std::io::Write as _;

    let mut file = match std::fs::File::create(&path).map(std::io::BufWriter::new) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to create pcap file '{}': {e}", path.display());
            return None;
        }
    };

    // Classic pcap global header (little-endian, DLT 114 = LINKTYPE_LOCALTALK).
    let mut hdr = [0u8; 24];
    hdr[0..4].copy_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    hdr[4..6].copy_from_slice(&2u16.to_le_bytes());           // version major
    hdr[6..8].copy_from_slice(&4u16.to_le_bytes());           // version minor
    // thiszone and sigfigs remain 0
    hdr[16..20].copy_from_slice(&65535u32.to_le_bytes());     // snaplen
    hdr[20..24].copy_from_slice(&114u32.to_le_bytes());       // LINKTYPE_LOCALTALK

    if let Err(e) = file.write_all(&hdr) {
        tracing::error!("Failed to write pcap global header: {e}");
        return None;
    }

    let (tx, rx) = std::sync::mpsc::sync_channel::<(SystemTime, Vec<u8>)>(512);

    std::thread::spawn(move || {
        use std::io::Write as _;
        tracing::info!("LocalTalk pcap capture started: '{}'", path.display());
        for (ts, data) in rx {
            let d = ts.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let ts_sec = d.as_secs() as u32;
            let ts_usec = d.subsec_micros();
            let len = data.len() as u32;
            let mut rec = [0u8; 16];
            rec[0..4].copy_from_slice(&ts_sec.to_le_bytes());
            rec[4..8].copy_from_slice(&ts_usec.to_le_bytes());
            rec[8..12].copy_from_slice(&len.to_le_bytes());
            rec[12..16].copy_from_slice(&len.to_le_bytes());
            if file.write_all(&rec).is_err() || file.write_all(&data).is_err() {
                tracing::error!("pcap write error, stopping capture");
                break;
            }
            let _ = file.flush();
        }
        tracing::info!("LocalTalk pcap capture stopped: '{}'", path.display());
    });

    Some(tx)
}

// ── Ethernet framing helpers ──────────────────────────────────────────────────

/// Write a 14-byte EtherTalk Phase 1 Ethernet header into `buf` and return 14.
fn write_eth1_header(buf: &mut [u8], dst: [u8; 6], src: [u8; 6], ethertype: u16) -> usize {
    buf[0..6].copy_from_slice(&dst);
    buf[6..12].copy_from_slice(&src);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    14
}

/// Write a 22-byte EtherTalk Phase 2 LLC/SNAP header into `buf` and return 22.
///
/// `oui` is the 3-byte SNAP OUI: `[0x08, 0x00, 0x07]` for AppleTalk DDP,
/// `[0x00, 0x00, 0x00]` for AARP.
fn write_snap_header(
    buf: &mut [u8],
    dst: [u8; 6],
    src: [u8; 6],
    oui: [u8; 3],
    ethertype: u16,
    payload_len: usize,
) -> usize {
    buf[0..6].copy_from_slice(&dst);
    buf[6..12].copy_from_slice(&src);
    let frame_len = 8 + payload_len; // 3 LLC + 5 SNAP bytes
    buf[12..14].copy_from_slice(&(frame_len as u16).to_be_bytes());
    buf[14..17].copy_from_slice(&[0xAA, 0xAA, 0x03]); // LLC DSAP, SSAP, Control
    buf[17..20].copy_from_slice(&oui);
    buf[20..22].copy_from_slice(&ethertype.to_be_bytes());
    22
}

// ── PacketProcessor ───────────────────────────────────────────────────────────

impl PacketProcessor {
    pub fn builder() -> PacketProcessorBuilder {
        PacketProcessorBuilder::new()
    }

    /// Returns the Ethernet MAC address of the configured interface, or `None`
    /// if no EtherTalk transport was added.
    pub fn get_mac(&self) -> Option<[u8; 6]> {
        self.our_mac
    }

    pub async fn run(
        self,
        et_addressing: Option<addressing::AddressingHandle>,
        lt_addressing: Option<addressing::AddressingHandle>,
        ddp: ddp::DdpHandle,
        token: CancellationToken,
    ) {
        // Extract pcap senders before any other field moves.
        // pcap_rx_sender goes into the TashTalk receive task; pcap_tx_sender stays in the outbound loop.
        let pcap_rx_sender = self.pcap_sender.clone();
        let pcap_tx_sender = self.pcap_sender;

        // ── EtherTalk RX task ────────────────────────────────────────────────
        if let Some(rx_cap) = self.pcap_rx {
            let ddp_rx = ddp.clone();
            let addressing_rx = et_addressing.clone().expect("EtherTalk RX task requires ET addressing");
            let rx_token = token.clone();

            let rx_cap = match rx_cap.setnonblock() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to set pcap nonblocking: {e}");
                    return;
                }
            };
            let stream = match rx_cap.stream(EtherTalkCodec) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to create pcap stream: {e}");
                    return;
                }
            };

            tokio::spawn(async move {
                tracing::info!("EtherTalk RX task started");
                tokio::pin!(stream);
                loop {
                    let data: Box<[u8]> = tokio::select! {
                        _ = rx_token.cancelled() => break,
                        result = stream.next() => match result {
                            Some(Ok(d)) => d,
                            Some(Err(e)) => { tracing::error!("pcap rx error: {e}"); break; }
                            None => break,
                        },
                    };

                    let ethertype_or_len = u16::from_be_bytes([data[12], data[13]]);

                    if ethertype_or_len <= 1500 {
                        // EtherTalk Phase 2 – IEEE 802.2 LLC/SNAP encapsulation.
                        match EtherTalkPhase2Frame::parse(&data) {
                            Err(e) => tracing::debug!("Phase 2 parse failed: {:?}", e),
                            Ok(header) => {
                                let payload = &data[EtherTalkPhase2Frame::len()..];
                                match header.protocol {
                                    EtherTalkPhase2Type::Ddp => {
                                        ddp_rx.received_pkt(
                                            payload,
                                            aarp::AddressSource::EtherTalkPhase2,
                                            header.src_mac,
                                        );
                                    }
                                    EtherTalkPhase2Type::Aarp => {
                                        if let Err(e) = addressing_rx.received_pkt(
                                            payload,
                                            aarp::AddressSource::EtherTalkPhase2,
                                        ) {
                                            tracing::error!("failed to relay Phase 2 AARP: {e}");
                                        }
                                    }
                                }
                            }
                        }
                    } else if ethertype_or_len == 0x80F3 {
                        // EtherTalk Phase 1 AARP.
                        if data.len() > 14
                            && let Err(e) = addressing_rx.received_pkt(
                                &data[14..],
                                aarp::AddressSource::EtherTalkPhase1,
                            )
                        {
                            tracing::error!("failed to relay Phase 1 AARP: {e}");
                        }
                    } else if ethertype_or_len == 0x809B {
                        // EtherTalk Phase 1 – LLAP encapsulated in Ethernet.
                        if data.len() > 14 + LlapPacket::LEN
                            && let Ok(llap) = LlapPacket::parse(&data[14..])
                        {
                            match llap.type_ {
                                LlapType::DdpShort => {
                                    let payload = &data[(14 + LlapPacket::LEN)..];
                                    if payload.len() >= 5
                                        && let Ok(headers) = DdpPacket::parse_short(
                                            payload,
                                            llap.dst_node,
                                            llap.src_node,
                                        )
                                    {
                                        let ddp_payload = payload[5..headers.len.min(payload.len())].into();
                                        let source_mac: [u8; 6] =
                                            data[6..12].try_into().unwrap();
                                        ddp_rx.received_parsed_pkt(
                                            headers,
                                            ddp_payload,
                                            aarp::AddressSource::EtherTalkPhase1,
                                            source_mac,
                                        );
                                    }
                                }
                                LlapType::DdpLong => {
                                    let payload = &data[(14 + LlapPacket::LEN)..];
                                    if payload.len() >= DdpPacket::LEN
                                        && let Ok(headers) = DdpPacket::parse(payload)
                                    {
                                        let ddp_payload =
                                            payload[DdpPacket::LEN..headers.len.min(payload.len())].into();
                                        let source_mac: [u8; 6] =
                                            data[6..12].try_into().unwrap();
                                        ddp_rx.received_parsed_pkt(
                                            headers,
                                            ddp_payload,
                                            aarp::AddressSource::EtherTalkPhase1,
                                            source_mac,
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            });
        }

        // ── TashTalk async task ──────────────────────────────────────────────
        // Spawned here rather than in the builder because it needs the addressing
        // and ddp handles, which callers construct using the OutboundHandle that
        // build() returns.
        let tashtalk_features = self.tashtalk_features;
        let (tashtalk_ready_tx, mut tashtalk_ready_rx) = tokio::sync::watch::channel(false);
        let tashtalk_tx: Option<mpsc::Sender<Vec<u8>>> = if let Some(mut tashtalk_instance) = self.tashtalk {
            let (tx, mut tashtalk_rx) = mpsc::channel::<Vec<u8>>(100);

            let ddp_handle = ddp.clone();
            let addressing_handle = lt_addressing.clone().expect("TashTalk task requires LT addressing");
            let tash_token = token.clone();
            let ready = tashtalk_ready_tx; // moved into the spawned task

            tokio::spawn(async move {
                tracing::info!("Resetting TashTalk buffers...");
                if let Err(e) = tashtalk_instance.reset().await {
                    tracing::error!("Failed to reset TashTalk: {:?}", e);
                }

                tracing::info!("Setting TashTalk features: {:?}", tashtalk_features);
                if let Err(e) = tashtalk_instance
                    .set_features(tashtalk_features)
                    .await
                {
                    tracing::error!("Failed to set TashTalk features: {:?}", e);
                }

                match addressing_handle.addr().await {
                    Ok(addr) => {
                        let node_id = addr.node_number;
                        tracing::info!("Setting TashTalk node ID bits for node {}", node_id);
                        let mut node_bits = [0u8; 32];
                        let byte_idx = (node_id / 8) as usize;
                        let bit_idx = node_id % 8;
                        node_bits[byte_idx] |= 1 << bit_idx;
                        if let Err(e) = tashtalk_instance.set_node_ids(node_bits).await {
                            tracing::error!("Failed to set TashTalk node IDs: {:?}", e);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to get our AppleTalk address for TashTalk setup: {:?}",
                            e
                        );
                    }
                }

                tracing::info!("Starting TashTalk async loop");
                let _ = ready.send(true);
                loop {
                    tokio::select! {
                        _ = tash_token.cancelled() => break,
                        frame_opt = tashtalk_rx.recv() => {
                            if let Some(frame) = frame_opt {
                                if let Err(e) = tashtalk_instance.send_frame(&frame).await {
                                    tracing::error!("TashTalk send_frame error: {:?}", e);
                                }
                            } else {
                                break;
                            }
                        }
                        res = tashtalk_instance.receive_frame() => {
                            match res {
                                Ok(Some(data)) => {
                                    if let Some(ref tx) = pcap_rx_sender {
                                        let _ = tx.try_send((SystemTime::now(), data.clone()));
                                    }
                                    if data.len() < 3 { continue; }
                                    if let Ok(llap) = LlapPacket::parse(&data) {
                                        match llap.type_ {
                                            LlapType::DdpShort => {
                                                tracing::debug!("TashTalk: LocalTalk DDP Short");
                                                if let Ok(headers) = DdpPacket::parse_short(
                                                    &data[3..],
                                                    llap.dst_node,
                                                    llap.src_node,
                                                ) {
                                                    tracing::debug!(
                                                        "LLAP: {:?}, DDP Short: {:?}",
                                                        llap,
                                                        headers
                                                    );
                                                    let end = (3 + headers.len).min(data.len());
                                                    let payload = data[8..end].to_vec().into_boxed_slice();
                                                    ddp_handle.received_parsed_pkt(
                                                        headers,
                                                        payload,
                                                        aarp::AddressSource::LocalTalk,
                                                        [0; 6],
                                                    );
                                                }
                                            }
                                            LlapType::Enquiry => {
                                                addressing_handle.received_llap_enq(llap.dst_node);
                                            }
                                            LlapType::Acknowledge => {
                                                addressing_handle.received_llap_ack(llap.src_node);
                                            }
                                            LlapType::DdpLong => {
                                                tracing::info!("TashTalk: LocalTalk DDP Long");
                                                if let Ok(headers) = DdpPacket::parse(&data[3..]) {
                                                    let end = (3 + headers.len).min(data.len());
                                                    let payload =
                                                        data[(3 + DdpPacket::LEN)..end].to_vec().into_boxed_slice();
                                                    ddp_handle.received_parsed_pkt(
                                                        headers,
                                                        payload,
                                                        aarp::AddressSource::LocalTalk,
                                                        [0; 6],
                                                    );
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    tracing::error!("TashTalk I/O error: {:?}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            Some(tx)
        } else {
            // No TashTalk — signal ready immediately so the outbound
            // loop doesn't block waiting for a device that doesn't exist.
            let _ = tashtalk_ready_tx.send(true);
            None
        };

        // ── Outbound TX loop ─────────────────────────────────────────────────
        let our_mac = self.our_mac.unwrap_or([0; 6]);
        let mut rx = self.outbound_rx;
        let mut pcap_tx = self.pcap_tx;

        // Wait for TashTalk init (reset + set_features + set_node_ids) to
        // finish before processing outbound frames. Without this, frames
        // queued during init would be sent before the firmware is configured.
        let _ = tashtalk_ready_rx.wait_for(|ready| *ready).await;

        loop {
            let pkt = tokio::select! {
                _ = token.cancelled() => break,
                pkt = rx.recv() => match pkt { Some(p) => p, None => break },
            };
            let mut output_buf: [u8; 1500] = [0u8; 1500];

            let final_size = match pkt.protocol {
                DataLinkProtocol::Ddp => {
                    match pkt.dest_node {
                        addressing::Node::EtherTalkPhase1(mac) => {
                            let payload_len = pkt.payload.len();
                            let n = write_eth1_header(&mut output_buf, mac, our_mac, 0x809B);
                            // Phase 1 DDP: 3-byte LLAP header (dst, src, type=2) precedes the DDP packet.
                            // Node numbers are extracted from the DDP header bytes 8 and 9.
                            output_buf[n] = if payload_len > 8 { pkt.payload[8] } else { 0 };
                            output_buf[n + 1] = if payload_len > 9 { pkt.payload[9] } else { 0 };
                            output_buf[n + 2] = 2;
                            output_buf[n + 3..n + 3 + payload_len].copy_from_slice(&pkt.payload);
                            n + 3 + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            let payload_len = pkt.payload.len();
                            let n = write_snap_header(&mut output_buf, mac, our_mac, [0x08, 0x00, 0x07], 0x809B, payload_len);
                            output_buf[n..n + payload_len].copy_from_slice(&pkt.payload);
                            n + payload_len
                        }
                        addressing::Node::LocalTalk(node_id) => {
                            let llap_pkt = LlapPacket {
                                dst_node: node_id,
                                src_node: pkt.src_node_id,
                                type_: LlapType::DdpShort,
                            };
                            let header_len = llap_pkt
                                .to_bytes(&mut output_buf)
                                .expect("failed to frame LLAP");

                            let payload_len = pkt.payload.len();
                            output_buf[header_len..header_len + payload_len]
                                .copy_from_slice(&pkt.payload);

                            let frame_end = header_len + payload_len;
                            let crc = tashtalk::lt_crc(&output_buf[..frame_end]);
                            output_buf[frame_end] = crc[0];
                            output_buf[frame_end + 1] = crc[1];

                            frame_end + 2
                        }
                    }
                }
                DataLinkProtocol::LlapEnq | DataLinkProtocol::LlapAck => {
                    match pkt.dest_node {
                        addressing::Node::LocalTalk(node_id) => {
                            let type_ = if pkt.protocol == DataLinkProtocol::LlapEnq {
                                LlapType::Enquiry
                            } else {
                                LlapType::Acknowledge
                            };
                            let llap_pkt = LlapPacket {
                                dst_node: node_id,
                                src_node: pkt.src_node_id,
                                type_,
                            };
                            let header_len = llap_pkt
                                .to_bytes(&mut output_buf)
                                .expect("failed to frame LLAP control");
                            let crc = tashtalk::lt_crc(&output_buf[..header_len]);
                            output_buf[header_len] = crc[0];
                            output_buf[header_len + 1] = crc[1];
                            header_len + 2
                        }
                        _ => 0,
                    }
                }
                DataLinkProtocol::Aarp => {
                    let payload_len = pkt.payload.len();
                    match pkt.dest_node {
                        addressing::Node::EtherTalkPhase1(mac) => {
                            let n = write_eth1_header(&mut output_buf, mac, our_mac, 0x80F3);
                            output_buf[n..n + payload_len].copy_from_slice(&pkt.payload);
                            n + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            let n = write_snap_header(&mut output_buf, mac, our_mac, [0x00, 0x00, 0x00], 0x80F3, payload_len);
                            output_buf[n..n + payload_len].copy_from_slice(&pkt.payload);
                            n + payload_len
                        }
                        addressing::Node::LocalTalk(_) => 0,
                    }
                }
            };

            if final_size == 0 {
                continue;
            }

            match pkt.dest_node {
                addressing::Node::EtherTalkPhase1(_) | addressing::Node::EtherTalkPhase2(_) => {
                    if let Some(ref mut tx) = pcap_tx {
                        let padded_size = final_size.max(60);
                        if let Err(e) = tx.sendpacket(&output_buf[..padded_size]) {
                            tracing::error!("failed to send packet: {e}");
                        }
                    }
                }
                addressing::Node::LocalTalk(_) => {
                    if let Some(tx) = &tashtalk_tx {
                        tracing::debug!("Sending to Tashtalk tx: {:X?}", &output_buf[..final_size]);
                        if let Err(e) = tx.send(output_buf[..final_size].to_vec()).await {
                            tracing::error!("Failed to send to Tashtalk tx: {}", e);
                        }
                    }
                    // Capture outbound frame without the trailing 2 CRC bytes.
                    if let Some(ref tx) = pcap_tx_sender {
                        let frame_len = final_size.saturating_sub(2);
                        let _ = tx.try_send((SystemTime::now(), output_buf[..frame_len].to_vec()));
                    }
                }
            }
        }
    }
}

// ── OutboundHandle ────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct OutboundHandle {
    tx: mpsc::Sender<DataLinkPacket>,
}

impl OutboundHandle {
    pub fn new(tx: mpsc::Sender<DataLinkPacket>) -> Self {
        Self { tx }
    }

    pub async fn send(&self, packet: DataLinkPacket) -> Result<(), Error> {
        self.tx.send(packet).await?;
        Ok(())
    }
}

// ── TalkStack ─────────────────────────────────────────────────────────────────

/// A lightweight handle that can be used to shut down a running [`TalkStack`]
/// from another task without holding the full stack.
#[derive(Clone)]
pub struct ShutdownHandle {
    service_token: CancellationToken,
    transport_token: CancellationToken,
    services_done: CancellationToken,
}

impl ShutdownHandle {
    /// Force-stop everything immediately, with no graceful close.
    pub fn shutdown(&self) {
        self.service_token.cancel();
        self.transport_token.cancel();
    }

    /// Close sessions gracefully (e.g. send ASP CloseSess), then stop the
    /// transport once all services confirm they are done, or after 5 seconds.
    pub async fn graceful_shutdown(&self) {
        self.service_token.cancel();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.services_done.cancelled(),
        )
        .await;
        self.transport_token.cancel();
    }
}

/// Handles to all mandatory AppleTalk stack layers.
///
/// Obtain one via [`TalkStack::builder`]. Once built, spawn services on top:
///
/// ```no_run
/// # use tailtalk::{TalkStack, afp::AfpServerConfig};
/// # async fn example() -> anyhow::Result<()> {
/// let stack = TalkStack::builder()
///     .ethernet("eth0")
///     .build()
///     .await?;
///
/// let _afp = stack.spawn_afp(Some(254), AfpServerConfig::default()).await?;
/// # Ok(()) }
/// ```
pub struct TalkStack {
    /// EtherTalk addressing handle, present when an Ethernet interface is configured.
    pub et_addressing: Option<addressing::AddressingHandle>,
    /// LocalTalk addressing handle, present when a TashTalk serial interface is configured.
    pub lt_addressing: Option<addressing::AddressingHandle>,
    pub ddp: ddp::DdpHandle,
    pub nbp: nbp::NbpHandle,
    pub echo: echo::EchoHandle,
    /// Cancelled to signal top-of-stack services (AFP, ASP) to begin shutdown.
    service_token: CancellationToken,
    /// Cancelled to stop the transport (DDP, PacketProcessor). Only done after
    /// services have finished their cleanup.
    transport_token: CancellationToken,
    /// Cancelled by services once they have completed their shutdown sequence.
    services_done: CancellationToken,
}

impl TalkStack {
    /// Wait until the transport has been shut down.
    pub async fn wait_for_shutdown(&self) {
        self.transport_token.cancelled().await;
    }

    /// Return a [`ShutdownHandle`] that can be sent to another task to
    /// trigger shutdown remotely.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            service_token: self.service_token.clone(),
            transport_token: self.transport_token.clone(),
            services_done: self.services_done.clone(),
        }
    }

    /// Return the service-layer cancellation token, suitable for passing to
    /// sub-services such as [`AfpServer::spawn`](afp::AfpServer::spawn).
    pub fn token(&self) -> CancellationToken {
        self.service_token.clone()
    }

    /// Return the services-done token to pass to services so they can signal
    /// completion of their shutdown sequence.
    pub fn services_done_token(&self) -> CancellationToken {
        self.services_done.clone()
    }

    /// Start an AFP file server on this stack.
    pub async fn spawn_afp(&self, socket: Option<u8>, config: afp::AfpServerConfig) -> anyhow::Result<afp::AfpServer> {
        afp::AfpServer::spawn(&self.ddp, &self.nbp, socket, config, self.service_token.clone(), self.services_done.clone()).await
    }

    /// Bind an ASP listener on this stack.
    pub async fn listen_asp(
        &self,
        socket: Option<u8>,
        entity_name: tailtalk_packets::nbp::EntityName,
        status_data: Vec<u8>,
    ) -> anyhow::Result<asp::AspHandle> {
        asp::Asp::bind(&self.ddp, &self.nbp, socket, entity_name, status_data, self.service_token.clone(), self.services_done.clone()).await
    }

    /// Bind an ADSP listener.
    pub async fn listen_adsp(&self, socket: Option<u8>) -> std::io::Result<(u8, adsp::AdspListener)> {
        adsp::Adsp::bind(&self.ddp, socket).await
    }

    /// Open an outbound ADSP connection.
    pub async fn connect_adsp(&self, remote_addr: adsp::AdspAddress) -> std::io::Result<adsp::AdspStream> {
        adsp::Adsp::connect(&self.ddp, remote_addr).await
    }

    /// Create a PAP client backed by two fresh ATP sockets.
    pub async fn pap_client(&self) -> pap::PapClient {
        let (_, atp_requestor, _) = atp::Atp::spawn(&self.ddp, None).await;
        let (_, _, atp_responder) = atp::Atp::spawn(&self.ddp, None).await;
        pap::PapClient::new(atp_requestor, atp_responder)
    }

    /// Query the status string of a PAP printer without opening a full connection.
    pub async fn pap_status(&self, address: atp::AtpAddress) -> anyhow::Result<String> {
        let (_, atp_requestor, _) = atp::Atp::spawn(&self.ddp, None).await;
        pap::PapClient::get_status(atp_requestor, address).await
    }
}

/// Builder for [`TalkStack`].
pub struct TalkStackBuilder {
    ethernet_intf: Option<String>,
    localtalk_serial_path: Option<String>,
    tashtalk_features: tashtalk::TashTalkFeatures,
    fixed_addr: Option<tailtalk_packets::aarp::AppleTalkAddress>,
    pcap_path: Option<PathBuf>,
}

impl TalkStack {
    pub fn builder() -> TalkStackBuilder {
        TalkStackBuilder {
            ethernet_intf: None,
            localtalk_serial_path: None,
            tashtalk_features: tashtalk::TashTalkFeatures::new(),
            fixed_addr: None,
            pcap_path: None,
        }
    }
}

impl TalkStackBuilder {
    /// Configure an EtherTalk transport on the given network interface.
    pub fn ethernet(mut self, intf: &str) -> Self {
        self.ethernet_intf = Some(intf.to_string());
        self
    }

    /// Configure a LocalTalk transport via a TashTalk serial adapter.
    pub fn localtalk(mut self, serial_path: &str) -> Self {
        self.localtalk_serial_path = Some(serial_path.to_string());
        self
    }

    /// Configure which CRC features the TashTalk firmware should enable.
    pub fn tashtalk_features(mut self, features: tashtalk::TashTalkFeatures) -> Self {
        self.tashtalk_features = features;
        self
    }

    /// Enable LocalTalk pcap capture to the given file path.
    ///
    /// Forwarded to [`PacketProcessorBuilder::pcap_capture`].
    pub fn pcap_capture(mut self, path: impl Into<PathBuf>) -> Self {
        self.pcap_path = Some(path.into());
        self
    }

    /// Use a fixed AppleTalk address instead of probing via AARP.
    pub fn fixed_address(mut self, network: u16, node: u8) -> Self {
        self.fixed_addr = Some(tailtalk_packets::aarp::AppleTalkAddress {
            network_number: network,
            node_number: node,
        });
        self
    }

    /// Launch the full AppleTalk stack and return handles to each layer.
    ///
    /// Spawns actors for AARP/Addressing, DDP, AEP (Echo), and NBP in dependency
    /// order, then starts the [`PacketProcessor`] background task.
    pub async fn build(self) -> Result<TalkStack, Error> {
        let mut pp = PacketProcessor::builder().tashtalk_features(self.tashtalk_features);
        if let Some(ref intf) = self.ethernet_intf {
            pp = pp.ethernet(intf);
        }
        if let Some(ref path) = self.localtalk_serial_path {
            pp = pp.localtalk(path);
        }
        if let Some(path) = self.pcap_path {
            pp = pp.pcap_capture(path);
        }
        let (processor, outbound) = pp.build()?;

        // EtherTalk addressing: AARP probe (or fixed address if caller specified one).
        let et_addressing = if self.ethernet_intf.is_some() {
            Some(addressing::Addressing::spawn(
                processor.get_mac(),
                outbound.clone(),
                self.fixed_addr,
                aarp::AddressSource::EtherTalkPhase2,
            ))
        } else {
            None
        };

        // LocalTalk addressing: always a fixed random address on network 0.
        // LocalTalk short-DDP carries no network number (implying 0), so we
        // must stay on network 0 to keep addresses consistent end-to-end.
        let lt_addressing = if self.localtalk_serial_path.is_some() {
            let lt_fixed = Some(tailtalk_packets::aarp::AppleTalkAddress {
                network_number: 0,
                node_number: rand::rng().random_range(1..=253u8),
            });
            Some(addressing::Addressing::spawn(
                None,
                outbound.clone(),
                lt_fixed,
                aarp::AddressSource::LocalTalk,
            ))
        } else {
            None
        };

        let ddp = ddp::DdpProcessor::spawn(et_addressing.clone(), lt_addressing.clone(), outbound);
        let echo = echo::Echo::spawn(&ddp).await;
        let nbp = nbp::Nbp::spawn(&ddp, et_addressing.clone(), lt_addressing.clone()).await;

        let service_token = CancellationToken::new();
        let transport_token = CancellationToken::new();
        let services_done = CancellationToken::new();
        tokio::spawn(processor.run(et_addressing.clone(), lt_addressing.clone(), ddp.clone(), transport_token.clone()));

        // Wait until addressing has settled on all active interfaces.
        if let Some(et) = &et_addressing {
            et.addr().await?;
        }
        if let Some(lt) = &lt_addressing {
            lt.addr().await?;
        }

        Ok(TalkStack { et_addressing, lt_addressing, ddp, nbp, echo, service_token, transport_token, services_done })
    }
}

// ── AFP time helpers ──────────────────────────────────────────────────────────

/// Converts a SystemTime to a 32-bit AFP date for **AFP 2.x** (seconds since Jan 1, 2000).
///
/// AFP 2.0 and later use midnight, January 1, 2000 as the epoch. Times before the
/// epoch are clamped to 0.
pub fn time_to_afp(time: SystemTime) -> u32 {
    // Seconds from Unix epoch (Jan 1, 1970) to AFP 2.x epoch (Jan 1, 2000)
    const AFP2_EPOCH_OFFSET: u64 = 946_684_800;

    let unix_secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    unix_secs.saturating_sub(AFP2_EPOCH_OFFSET) as u32
}

/// Converts a SystemTime to a 32-bit AFP date for **AFP 1.x** (seconds since Jan 1, 1904).
///
/// AFP 1.x (and classic Mac OS) use midnight, January 1, 1904 as the epoch —
/// 2,082,844,800 seconds before the Unix epoch.
pub fn time_to_afp_v1(time: SystemTime) -> u32 {
    // Seconds from Jan 1, 1904 (Mac OS classic epoch) to Jan 1, 1970 (Unix epoch)
    const MAC_TO_UNIX_EPOCH_OFFSET: u64 = 2_082_844_800;

    let unix_secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    (unix_secs + MAC_TO_UNIX_EPOCH_OFFSET) as u32
}
