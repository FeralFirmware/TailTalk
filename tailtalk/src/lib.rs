use anyhow::Error;
use futures::StreamExt;
use mac_address::mac_address_by_name;
use std::time::SystemTime;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::ethertalk::{EtherTalkPhase2Frame, EtherTalkPhase2Type};
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tashtalk::TashTalk;
use tokio::sync::mpsc;
use tokio_serial::SerialPortBuilderExt;

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
}

// ── Builder ───────────────────────────────────────────────────────────────────

/// Builder for [`PacketProcessor`].
///
/// At least one transport must be configured before calling [`build`](PacketProcessorBuilder::build).
///
/// # Example – EtherTalk only
/// ```no_run
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .build()?;
/// ```
///
/// # Example – LocalTalk only
/// ```no_run
/// let (processor, handle) = PacketProcessor::builder()
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// ```
///
/// # Example – both transports
/// ```no_run
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// ```
pub struct PacketProcessorBuilder {
    ethernet_intf: Option<String>,
    localtalk_serial_path: Option<String>,
}

impl PacketProcessorBuilder {
    fn new() -> Self {
        Self {
            ethernet_intf: None,
            localtalk_serial_path: None,
        }
    }

    /// Configure an EtherTalk transport on the given network interface.
    pub fn ethernet(mut self, intf: &str) -> Self {
        self.ethernet_intf = Some(intf.to_string());
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
            let filter = "ether proto 0x809B or ether proto 0x80F3 or (ether[12:2] <= 1500)";

            // RX capture – promiscuous mode, filter applied.
            let mut rx = pcap::Capture::from_device(intf.as_str())?
                .promisc(true)
                .open()?;
            rx.filter(filter, true)?;
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
                .expect("Failed to open serial port for TashTalk");
            Some(TashTalk::new(stream))
        } else {
            None
        };

        let (outbound_tx, outbound_rx) = mpsc::channel(100);

        let processor = PacketProcessor {
            pcap_rx,
            pcap_tx,
            outbound_rx,
            our_mac,
            tashtalk,
        };
        let handle = OutboundHandle { tx: outbound_tx };

        Ok((processor, handle))
    }
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

    pub async fn run(self, addressing: addressing::AddressingHandle, ddp: ddp::DdpHandle) {
        // ── EtherTalk RX task ────────────────────────────────────────────────
        if let Some(rx_cap) = self.pcap_rx {
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

            let ddp_rx = ddp.clone();
            let addressing_rx = addressing.clone();

            tokio::spawn(async move {
                tracing::info!("EtherTalk RX task started");
                tokio::pin!(stream);
                while let Some(result) = stream.next().await {
                    let data: Box<[u8]> = match result {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::error!("pcap rx error: {e}");
                            break;
                        }
                    };

                    if data.len() < 14 {
                        continue;
                    }

                    let ethertype_or_len = u16::from_be_bytes([data[12], data[13]]);

                    if ethertype_or_len <= 1500 {
                        // EtherTalk Phase 2 – IEEE 802.2 LLC/SNAP encapsulation.
                        if let Ok(header) = EtherTalkPhase2Frame::parse(&data) {
                            let payload = &data[EtherTalkPhase2Frame::len()..];
                            match header.protocol {
                                EtherTalkPhase2Type::Ddp => ddp_rx.received_pkt(
                                    payload,
                                    aarp::AddressSource::EtherTalkPhase2,
                                    header.src_mac,
                                ),
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
                    } else if ethertype_or_len == 0x80F3 {
                        // EtherTalk Phase 1 AARP.
                        if data.len() > 14 {
                            if let Err(e) = addressing_rx.received_pkt(
                                &data[14..],
                                aarp::AddressSource::EtherTalkPhase1,
                            ) {
                                tracing::error!("failed to relay Phase 1 AARP: {e}");
                            }
                        }
                    } else if ethertype_or_len == 0x809B {
                        // EtherTalk Phase 1 – LLAP encapsulated in Ethernet.
                        if data.len() > 14 + LlapPacket::LEN {
                            if let Ok(llap) = LlapPacket::parse(&data[14..]) {
                                match llap.type_ {
                                    LlapType::DdpShort => {
                                        let payload = &data[(14 + LlapPacket::LEN)..];
                                        if payload.len() >= 5 {
                                            if let Ok(headers) = DdpPacket::parse_short(
                                                payload,
                                                llap.dst_node,
                                                llap.src_node,
                                            ) {
                                                let ddp_payload = payload[5..].into();
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
                                    }
                                    LlapType::DdpLong => {
                                        let payload = &data[(14 + LlapPacket::LEN)..];
                                        if payload.len() >= DdpPacket::LEN {
                                            if let Ok(headers) = DdpPacket::parse(payload) {
                                                let ddp_payload =
                                                    payload[DdpPacket::LEN..].into();
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
                                    }
                                    _ => {}
                                }
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
        let tashtalk_tx: Option<mpsc::Sender<Vec<u8>>> = if let Some(mut tashtalk_instance) = self.tashtalk {
            let (tx, mut tashtalk_rx) = mpsc::channel::<Vec<u8>>(100);

            let ddp_handle = ddp.clone();
            let addressing_handle = addressing.clone();

            tokio::spawn(async move {
                tracing::info!("Resetting TashTalk buffers...");
                if let Err(e) = tashtalk_instance.reset().await {
                    tracing::error!("Failed to reset TashTalk: {:?}", e);
                }

                tracing::info!("Enabling TashTalk CRC calculation...");
                if let Err(e) = tashtalk_instance
                    .set_features(tashtalk::TashTalkFeatures::new().with_crc_calculation())
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
                loop {
                    tokio::select! {
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
                                    if data.len() < 3 { continue; }
                                    if let Ok(llap) = LlapPacket::parse(&data) {
                                        match llap.type_ {
                                            LlapType::DdpShort => {
                                                tracing::info!("TashTalk: LocalTalk DDP Short");
                                                if let Ok(headers) = DdpPacket::parse_short(
                                                    &data[3..],
                                                    llap.dst_node,
                                                    llap.src_node,
                                                ) {
                                                    tracing::info!(
                                                        "LLAP: {:?}, DDP Short: {:?}",
                                                        llap,
                                                        headers
                                                    );
                                                    let payload = data[8..].to_vec().into_boxed_slice();
                                                    ddp_handle.received_parsed_pkt(
                                                        headers,
                                                        payload,
                                                        aarp::AddressSource::LocalTalk,
                                                        [0; 6],
                                                    );
                                                }
                                            }
                                            LlapType::DdpLong => {
                                                tracing::info!("TashTalk: LocalTalk DDP Long");
                                                if let Ok(headers) = DdpPacket::parse(&data[3..]) {
                                                    let payload =
                                                        data[(3 + DdpPacket::LEN)..].to_vec().into_boxed_slice();
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
                                    tracing::error!("TashTalk receive error: {:?}", e);
                                }
                            }
                        }
                    }
                }
            });

            Some(tx)
        } else {
            None
        };

        // ── Outbound TX loop ─────────────────────────────────────────────────
        let our_mac = self.our_mac.unwrap_or([0; 6]);
        let mut rx = self.outbound_rx;
        let mut pcap_tx = self.pcap_tx;

        while let Some(pkt) = rx.recv().await {
            let mut output_buf: [u8; 1500] = [0u8; 1500];

            let final_size = match pkt.protocol {
                DataLinkProtocol::Ddp => {
                    match pkt.dest_node {
                        addressing::Node::EtherTalkPhase1(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&our_mac);
                            output_buf[12] = 0x80;
                            output_buf[13] = 0x9B;
                            let dst_node = if pkt.payload.len() > 8 { pkt.payload[8] } else { 0 };
                            let src_node = if pkt.payload.len() > 9 { pkt.payload[9] } else { 0 };
                            output_buf[14] = dst_node;
                            output_buf[15] = src_node;
                            output_buf[16] = 2;
                            let payload_len = pkt.payload.len();
                            output_buf[17..17 + payload_len].copy_from_slice(&pkt.payload);
                            17 + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&our_mac);
                            let payload_len = pkt.payload.len();
                            let total_payload = 8 + payload_len;
                            output_buf[12] = (total_payload >> 8) as u8;
                            output_buf[13] = (total_payload & 0xFF) as u8;
                            output_buf[14] = 0xAA;
                            output_buf[15] = 0xAA;
                            output_buf[16] = 0x03;
                            output_buf[17] = 0x08;
                            output_buf[18] = 0x00;
                            output_buf[19] = 0x07;
                            output_buf[20] = 0x80;
                            output_buf[21] = 0x9B;
                            output_buf[22..22 + payload_len].copy_from_slice(&pkt.payload);
                            14 + total_payload
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

                            // TashTalk with CRC calculation (Bit 7) expects 2 dummy bytes
                            // at the end that it overwrites with the real CRC.
                            let final_size = header_len + payload_len + 2;
                            output_buf[final_size - 2] = 0;
                            output_buf[final_size - 1] = 0;

                            final_size
                        }
                    }
                }
                DataLinkProtocol::Aarp => {
                    let payload_len = pkt.payload.len();
                    match pkt.dest_node {
                        addressing::Node::EtherTalkPhase1(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&our_mac);
                            output_buf[12] = 0x80;
                            output_buf[13] = 0xF3;
                            output_buf[14..14 + payload_len].copy_from_slice(&pkt.payload);
                            14 + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&our_mac);
                            let total_payload = 8 + payload_len;
                            output_buf[12] = (total_payload >> 8) as u8;
                            output_buf[13] = (total_payload & 0xFF) as u8;
                            output_buf[14] = 0xAA;
                            output_buf[15] = 0xAA;
                            output_buf[16] = 0x03;
                            output_buf[17] = 0x00;
                            output_buf[18] = 0x00;
                            output_buf[19] = 0x00;
                            output_buf[20] = 0x80;
                            output_buf[21] = 0xF3;
                            output_buf[22..22 + payload_len].copy_from_slice(&pkt.payload);
                            14 + total_payload
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
                        if let Err(e) = tx.sendpacket(&output_buf[..final_size]) {
                            tracing::error!("failed to send packet: {e}");
                        }
                    }
                }
                addressing::Node::LocalTalk(_) => {
                    if let Some(tx) = &tashtalk_tx {
                        tracing::info!("Sending to Tashtalk tx: {:X?}", &output_buf[..final_size]);
                        if let Err(e) = tx.send(output_buf[..final_size].to_vec()).await {
                            tracing::error!("Failed to send to Tashtalk tx: {}", e);
                        }
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
