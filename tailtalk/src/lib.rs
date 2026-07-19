use anyhow::Error;
use std::path::PathBuf;
use std::time::SystemTime;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tashtalk::TashTalk;
use tokio::sync::mpsc;
use tokio_serial::SerialPortBuilderExt;
pub use tokio_util::sync::CancellationToken;

#[cfg(feature = "ethertalk")]
mod ethertalk;

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
pub mod remote;
pub mod route_table;
pub mod rtmp;
pub mod stylewriter;
pub mod zip;

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
    /// For `DataLinkProtocol::Ddp` on a LocalTalk destination, whether
    /// `payload` holds a long-form (13-byte) DDP header rather than the
    /// short-form (5-byte) one — selects the LLAP DDP-long vs. DDP-short
    /// frame type. Ignored for every other protocol/destination.
    pub ddp_long: bool,
}

pub struct PacketProcessor {
    #[cfg(feature = "ethertalk")]
    transport: Option<ethertalk::EtherTalkTransport>,
    outbound_rx: mpsc::Receiver<DataLinkPacket>,
    /// Serial port path for LocalTalk / TashTalk. The port is opened (and
    /// reopened on disconnect) inside the async task spawned by `run()`.
    localtalk_serial_path: Option<String>,
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
/// # Example – LocalTalk only
/// ```no_run
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Example – EtherTalk only (requires the `ethertalk` feature)
/// ```ignore
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Example – both transports (requires the `ethertalk` feature)
/// ```ignore
/// # use tailtalk::PacketProcessor;
/// let (processor, handle) = PacketProcessor::builder()
///     .ethernet("eth0")
///     .localtalk("/dev/ttyUSB0")
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct PacketProcessorBuilder {
    #[cfg(feature = "ethertalk")]
    ethernet_intf: Option<String>,
    localtalk_serial_path: Option<String>,
    tashtalk_features: tashtalk::TashTalkFeatures,
    pcap_path: Option<PathBuf>,
}

impl PacketProcessorBuilder {
    fn new() -> Self {
        Self {
            #[cfg(feature = "ethertalk")]
            ethernet_intf: None,
            localtalk_serial_path: None,
            tashtalk_features: tashtalk::TashTalkFeatures::new(),
            pcap_path: None,
        }
    }

    /// Configure an EtherTalk transport on the given network interface.
    #[cfg(feature = "ethertalk")]
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
    /// The serial port is opened lazily when the device becomes available.
    /// If the device is not present at startup, a warning is logged and
    /// the stack keeps running. When the device appears (or reappears
    /// after a disconnect), LocalTalk is brought up automatically.
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
        // ── EtherTalk setup ──────────────────────────────────────────────────
        #[cfg(feature = "ethertalk")]
        let transport = if let Some(ref intf) = self.ethernet_intf {
            Some(ethertalk::EtherTalkTransport::open(intf)?)
        } else {
            None
        };

        // ── LocalTalk / TashTalk setup ───────────────────────────────────────
        // Serial port is opened lazily inside the async task (hot-pluggable).
        // We just store the path here.

        let (outbound_tx, outbound_rx) = mpsc::channel(100);

        let pcap_sender = self.pcap_path.and_then(spawn_pcap_writer);

        let processor = PacketProcessor {
            #[cfg(feature = "ethertalk")]
            transport,
            outbound_rx,
            localtalk_serial_path: self.localtalk_serial_path,
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

// ── PacketProcessor ───────────────────────────────────────────────────────────

impl PacketProcessor {
    pub fn builder() -> PacketProcessorBuilder {
        PacketProcessorBuilder::new()
    }

    /// Returns the Ethernet MAC address of the configured interface, or `None`
    /// if no EtherTalk transport was added.
    pub fn get_mac(&self) -> Option<[u8; 6]> {
        #[cfg(feature = "ethertalk")]
        return self.transport.as_ref().map(|t| t.our_mac);
        #[cfg(not(feature = "ethertalk"))]
        None
    }

    pub async fn run(
        self,
        et_addressing: Option<addressing::AddressingHandle>,
        lt_addressing: Option<addressing::AddressingHandle>,
        ddp: ddp::DdpHandle,
        token: CancellationToken,
    ) {
        #[cfg(not(feature = "ethertalk"))]
        let _ = et_addressing;

        // Extract pcap senders before any other field moves.
        // pcap_rx_sender goes into the TashTalk receive task; pcap_tx_sender stays in the outbound loop.
        let pcap_rx_sender = self.pcap_sender.clone();
        let pcap_tx_sender = self.pcap_sender;

        // ── EtherTalk: spawn RX task, obtain TX handle ──────────────────────
        #[cfg(feature = "ethertalk")]
        let mut et_tx = if let Some(transport) = self.transport {
            let addressing = et_addressing.clone()
                .expect("EtherTalk transport requires ET addressing");
            match transport.spawn_rx_task(ddp.clone(), addressing, token.clone()) {
                None => return,
                Some(tx) => Some(tx),
            }
        } else {
            None
        };

        // ── TashTalk async task ──────────────────────────────────────────────
        // Spawned here rather than in the builder because it needs the addressing
        // and ddp handles. The task opens (and reopens) the serial port, so
        // the device can be hot-plugged.
        let tashtalk_features = self.tashtalk_features;
        let (tashtalk_ready_tx, mut tashtalk_ready_rx) = tokio::sync::watch::channel(false);
        // The TX sender is wrapped in a watch so the outbound loop can track
        // reconnections: None = device offline, Some(sender) = online.
        let (tashtalk_tx_watch_tx, tashtalk_tx_watch_rx) =
            tokio::sync::watch::channel::<Option<mpsc::Sender<Vec<u8>>>>(None);
        let has_localtalk = self.localtalk_serial_path.is_some();
        if let Some(serial_path) = self.localtalk_serial_path {
            let ddp_handle = ddp.clone();
            let addressing_handle = lt_addressing.clone().expect("TashTalk task requires LT addressing");
            let tash_token = token.clone();
            let ready = tashtalk_ready_tx;
            let tx_watch = tashtalk_tx_watch_tx;

            tokio::spawn(async move {
                // Watch for address changes (e.g. via a daemon SetAddress
                // request) so the TashTalk node ID bits can be reprogrammed.
                let mut addr_watch = addressing_handle
                    .addr_watch()
                    .expect("TashTalk requires locally-owned addressing");
                let mut addr_watch_alive = true;
                let mut first_connect = true;
                loop {
                    // ── Open serial port ────────────────────────────────
                    let stream = match tokio_serial::new(&serial_path, 1_000_000)
                        .flow_control(tokio_serial::FlowControl::Hardware)
                        .open_native_async()
                    {
                        Ok(s) => {
                            tracing::info!("TashTalk: opened {}", serial_path);
                            s
                        }
                        Err(e) => {
                            if first_connect {
                                tracing::warn!("TashTalk: {} not available ({e}), waiting for device", serial_path);
                                first_connect = false;
                            }
                            tokio::select! {
                                _ = tash_token.cancelled() => return,
                                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => continue,
                            }
                        }
                    };
                    first_connect = false;

                    let mut tashtalk_instance = TashTalk::new(stream);

                    // ── Init sequence ────────────────────────────────────
                    tracing::info!("TashTalk: resetting");
                    if let Err(e) = tashtalk_instance.reset().await {
                        tracing::error!("TashTalk reset failed: {:?}", e);
                        continue;
                    }

                    tracing::info!("TashTalk: setting features {:?}", tashtalk_features);
                    if let Err(e) = tashtalk_instance.set_features(tashtalk_features).await {
                        tracing::error!("TashTalk set_features failed: {:?}", e);
                        continue;
                    }

                    match addressing_handle.addr().await {
                        Ok(addr) => {
                            let node_id = addr.node_number;
                            tracing::info!("TashTalk: setting node ID bits for node {}", node_id);
                            let mut node_bits = [0u8; 32];
                            node_bits[(node_id / 8) as usize] |= 1 << (node_id % 8);
                            if let Err(e) = tashtalk_instance.set_node_ids(node_bits).await {
                                tracing::error!("TashTalk set_node_ids failed: {:?}", e);
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::error!("TashTalk: failed to get address: {:?}", e);
                            continue;
                        }
                    }
                    // The node bits above reflect the current address; don't
                    // replay an already-seen change notification.
                    let _ = addr_watch.borrow_and_update();

                    // ── Create TX channel for this connection ────────────
                    let (tx, mut tashtalk_rx) = mpsc::channel::<Vec<u8>>(100);
                    let _ = tx_watch.send(Some(tx));
                    let _ = ready.send(true);

                    // ── Main I/O loop ────────────────────────────────────
                    tracing::info!("TashTalk: online");
                    loop {
                        tokio::select! {
                            _ = tash_token.cancelled() => return,
                            changed = addr_watch.changed(), if addr_watch_alive => {
                                let new_addr = if changed.is_err() {
                                    addr_watch_alive = false;
                                    None
                                } else {
                                    *addr_watch.borrow_and_update()
                                };
                                if let Some(addr) = new_addr {
                                    let node_id = addr.node_number;
                                    tracing::info!("TashTalk: address changed, setting node ID bits for node {node_id}");
                                    let mut node_bits = [0u8; 32];
                                    node_bits[(node_id / 8) as usize] |= 1 << (node_id % 8);
                                    if let Err(e) = tashtalk_instance.set_node_ids(node_bits).await {
                                        tracing::error!("TashTalk set_node_ids failed: {:?}", e);
                                        break;
                                    }
                                }
                            }
                            frame_opt = tashtalk_rx.recv() => {
                                if let Some(frame) = frame_opt {
                                    if let Err(e) = tashtalk_instance.send_frame(&frame).await {
                                        tracing::error!("TashTalk send_frame error: {:?}", e);
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            res = tashtalk_instance.receive_frame() => {
                                match res {
                                    Ok(Some(tashtalk::TashTalkEvent::Frame(data))) => {
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
                                    Ok(Some(tashtalk::TashTalkEvent::Error(e))) => {
                                        // Bad frame already discarded; keep going.
                                        tracing::debug!("TashTalk: discarded bad frame: {}", e);
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
                    // Device disconnected — signal offline, then retry.
                    tracing::warn!("TashTalk: offline, will reconnect");
                    let _ = tx_watch.send(None);
                    let _ = ready.send(false);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
        } else {
            // No TashTalk — signal ready immediately so the outbound
            // loop doesn't block waiting for a device that doesn't exist.
            let _ = tashtalk_ready_tx.send(true);
        };

        // ── Outbound TX loop ─────────────────────────────────────────────────
        let mut rx = self.outbound_rx;

        // Wait for TashTalk init unless no LocalTalk is configured.
        // If the device isn't present yet, proceed — outbound frames to
        // LocalTalk will be silently dropped until the device comes online.
        if has_localtalk {
            // Non-blocking: if device isn't ready yet, just log and continue.
            if !*tashtalk_ready_rx.borrow() {
                tracing::info!("Waiting for TashTalk device...");
                let _ = tashtalk_ready_rx.wait_for(|ready| *ready).await;
            }
        }
        let mut tashtalk_tx_watch_rx = tashtalk_tx_watch_rx;

        loop {
            let pkt = tokio::select! {
                _ = token.cancelled() => break,
                pkt = rx.recv() => match pkt { Some(p) => p, None => break },
            };
            let mut output_buf: [u8; 1500] = [0u8; 1500];

            let final_size = match pkt.protocol {
                DataLinkProtocol::Ddp => {
                    match pkt.dest_node {
                        #[cfg(feature = "ethertalk")]
                        addressing::Node::EtherTalkPhase1(_) | addressing::Node::EtherTalkPhase2(_) => {
                            et_tx.as_ref().map_or(0, |t| t.build_ddp_frame(pkt.dest_node, &pkt.payload, &mut output_buf))
                        }
                        addressing::Node::LocalTalk(node_id) => {
                            let llap_pkt = LlapPacket {
                                dst_node: node_id,
                                src_node: pkt.src_node_id,
                                type_: if pkt.ddp_long { LlapType::DdpLong } else { LlapType::DdpShort },
                            };
                            let header_len = llap_pkt
                                .to_bytes(&mut output_buf)
                                .expect("failed to frame LLAP");

                            let payload_len = pkt.payload.len();
                            output_buf[header_len..header_len + payload_len]
                                .copy_from_slice(&pkt.payload);

                            // CRC is appended in send_frame.
                            header_len + payload_len
                        }
                        #[cfg(not(feature = "ethertalk"))]
                        _ => 0,
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
                            // CRC is appended in send_frame.
                            header_len
                        }
                        _ => 0,
                    }
                }
                DataLinkProtocol::Aarp => {
                    match pkt.dest_node {
                        #[cfg(feature = "ethertalk")]
                        addressing::Node::EtherTalkPhase1(_) | addressing::Node::EtherTalkPhase2(_) => {
                            et_tx.as_ref().map_or(0, |t| t.build_aarp_frame(pkt.dest_node, &pkt.payload, &mut output_buf))
                        }
                        addressing::Node::LocalTalk(_) => 0,
                        #[cfg(not(feature = "ethertalk"))]
                        _ => 0,
                    }
                }
            };

            if final_size == 0 {
                continue;
            }

            match pkt.dest_node {
                #[cfg(feature = "ethertalk")]
                addressing::Node::EtherTalkPhase1(_) | addressing::Node::EtherTalkPhase2(_) => {
                    if let Some(ref mut t) = et_tx {
                        t.sendpacket(&output_buf, final_size);
                    }
                }
                addressing::Node::LocalTalk(_) => {
                    let tashtalk_tx = tashtalk_tx_watch_rx.borrow_and_update().clone();
                    if let Some(tx) = tashtalk_tx {
                        tracing::debug!("Sending to Tashtalk tx: {:X?}", &output_buf[..final_size]);
                        if let Err(e) = tx.send(output_buf[..final_size].to_vec()).await {
                            tracing::error!("Failed to send to Tashtalk tx: {}", e);
                        }
                    }
                    // Outbound frame has no CRC bytes, so capture it as-is.
                    if let Some(ref tx) = pcap_tx_sender {
                        let _ = tx.try_send((SystemTime::now(), output_buf[..final_size].to_vec()));
                    }
                }
                #[cfg(not(feature = "ethertalk"))]
                _ => {}
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

    /// Wait until the transport layer shuts down (e.g. serial device
    /// disconnected). Useful for detecting when the stack is no longer viable.
    pub async fn transport_closed(&self) {
        self.transport_token.cancelled().await;
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
///     .localtalk("/dev/ttyUSB0")
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
    /// Handle to the resident ZIP client, for forcing a zone re-discovery.
    /// `None` with a remote daemon (which runs its own) or when router
    /// discovery is disabled.
    pub zip: Option<zip::ZipHandle>,
    /// Shared routing table. Call `insert_route` / `insert_zone` on this to
    /// program static routes before or after the stack is running.
    pub route_table: route_table::RouteTable,
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
    pub async fn spawn_afp(&self, socket: Option<u8>, config: afp::AfpServerConfig) -> anyhow::Result<()> {
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

    /// Create a PAP client backed by a single ATP socket.
    pub async fn pap_client(&self) -> pap::PapClient {
        let (_, atp_requestor, atp_responder) = atp::Atp::spawn(&self.ddp, None).await;
        pap::PapClient::new(atp_requestor, atp_responder)
    }

    /// Query the status string of a PAP printer without opening a full connection.
    pub async fn pap_status(&self, address: atp::AtpAddress) -> anyhow::Result<String> {
        let (_, atp_requestor, _) = atp::Atp::spawn(&self.ddp, None).await;
        pap::PapClient::get_status(atp_requestor, address).await
    }

    /// Create a PAP printer emulator.
    ///
    /// Allocates an ATP socket and returns a [`pap::PapServer`].  The socket
    /// number is available as `server.socket_number`; register it with NBP
    /// manually, or use [`add_printer`](TalkStack::add_printer) which does both
    /// in one call.
    pub async fn pap_server(
        &self,
        attributes: pap::PrinterAttributes,
        sink: impl pap::PrintSink + 'static,
    ) -> pap::PapServer {
        let (socket_num, _requestor, responder) = atp::Atp::spawn(&self.ddp, None).await;
        pap::PapServer::new(responder, self.ddp.clone(), socket_num, attributes, Box::new(sink))
    }

    /// Create a PAP printer emulator and register it with NBP as `{name}:LaserWriter@*`.
    ///
    /// This is the high-level convenience wrapper: it allocates an ATP socket,
    /// constructs the [`pap::PapServer`], and registers the NBP name so the Mac
    /// Chooser can discover the printer.  Call [`pap::PapServer::run`] (or loop
    /// on [`pap::PapServer::accept`]) to start serving connections.
    pub async fn add_printer(
        &self,
        name: &str,
        attributes: pap::PrinterAttributes,
        sink: impl pap::PrintSink + 'static,
    ) -> anyhow::Result<pap::PapServer> {
        let server = self.pap_server(attributes, sink).await;

        let entity_str = format!("{}:LaserWriter@*", name);
        let entity: tailtalk_packets::nbp::EntityName = entity_str
            .as_str()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid printer name: {}", e))?;

        self.nbp
            .register(nbp::RegisteredName {
                name: entity,
                sock_num: server.socket_number,
            })
            .await
            .map_err(|e| anyhow::anyhow!("NBP registration failed: {}", e))?;

        Ok(server)
    }
}

/// The lower half of the stack: interfaces, addressing (AARP/LLAP), DDP and
/// the routing table — without NBP/AEP services on top.
///
/// Produced by [`TalkStackBuilder::build_underlay`]. This is what the
/// TailTalk daemon (`tailtalkd`) runs to own the interfaces on behalf of
/// remote clients.
pub struct Underlay {
    pub et_addressing: Option<addressing::AddressingHandle>,
    pub lt_addressing: Option<addressing::AddressingHandle>,
    pub ddp: ddp::DdpHandle,
    pub route_table: route_table::RouteTable,
    /// Handle to the ZIP actor; `None` when router discovery is disabled.
    pub zip: Option<zip::ZipHandle>,
    /// Cancel to stop the transport (PacketProcessor).
    pub transport_token: CancellationToken,
}

/// Builder for [`TalkStack`].
///
/// The underlay (AARP/DDP + interfaces) either runs in-process — configure
/// [`ethernet`](Self::ethernet) and/or [`localtalk`](Self::localtalk) — or in
/// a separate TailTalk daemon reached via [`daemon_unix`](Self::daemon_unix)
/// or [`daemon_udp`](Self::daemon_udp). Everything above DDP behaves
/// identically in both modes.
pub struct TalkStackBuilder {
    #[cfg(feature = "ethertalk")]
    ethernet_intf: Option<String>,
    localtalk_serial_path: Option<String>,
    tashtalk_features: tashtalk::TashTalkFeatures,
    #[cfg(feature = "ethertalk")]
    fixed_addr: Option<tailtalk_packets::aarp::AppleTalkAddress>,
    lt_fixed_node: Option<u8>,
    pcap_path: Option<PathBuf>,
    daemon: Option<remote::DaemonEndpoint>,
    router_discovery: bool,
    zone_cache: Option<PathBuf>,
}

impl TalkStack {
    pub fn builder() -> TalkStackBuilder {
        TalkStackBuilder {
            #[cfg(feature = "ethertalk")]
            ethernet_intf: None,
            localtalk_serial_path: None,
            tashtalk_features: tashtalk::TashTalkFeatures::new(),
            #[cfg(feature = "ethertalk")]
            fixed_addr: None,
            lt_fixed_node: None,
            pcap_path: None,
            daemon: None,
            router_discovery: true,
            zone_cache: None,
        }
    }
}

impl TalkStackBuilder {
    /// Configure an EtherTalk transport on the given network interface.
    #[cfg(feature = "ethertalk")]
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

    /// Use a fixed AppleTalk node on LocalTalk instead of probing via LLAP ENQ.
    ///
    /// The network number starts as 0 on LocalTalk; a router's RTMP/ZIP
    /// advertisements may later supply the cable's real network number.
    pub fn localtalk_fixed_address(mut self, node: u8) -> Self {
        self.lt_fixed_node = Some(node);
        self
    }

    /// Disable the resident RTMP listener and ZIP client.
    ///
    /// These own DDP sockets 1 and 6 and adapt addressing/routing to router
    /// advertisements. Disable them when an external router engine (e.g.
    /// netatalk's `atalkd` driving a TailTalk daemon) needs those sockets and
    /// manages routes itself.
    pub fn disable_router_discovery(mut self) -> Self {
        self.router_discovery = false;
        self
    }

    /// Persist the learned zone name to this file (PRAM-style), so the next
    /// startup can ask the router to re-confirm it.
    pub fn zone_cache(mut self, path: impl Into<PathBuf>) -> Self {
        self.zone_cache = Some(path.into());
        self
    }

    /// Use a fixed AppleTalk address on EtherTalk instead of probing via AARP.
    #[cfg(feature = "ethertalk")]
    pub fn fixed_address(mut self, network: u16, node: u8) -> Self {
        self.fixed_addr = Some(tailtalk_packets::aarp::AppleTalkAddress {
            network_number: network,
            node_number: node,
        });
        self
    }

    /// Use a remote TailTalk daemon (reached over a Unix domain socket) as the
    /// AARP/DDP underlay instead of handling interfaces in this process.
    ///
    /// Mutually exclusive with [`ethernet`](Self::ethernet) /
    /// [`localtalk`](Self::localtalk): the daemon owns the interfaces.
    #[cfg(unix)]
    pub fn daemon_unix(mut self, path: impl Into<PathBuf>) -> Self {
        self.daemon = Some(remote::DaemonEndpoint::Unix(path.into()));
        self
    }

    /// Use a remote TailTalk daemon reached over UDP as the AARP/DDP underlay.
    ///
    /// See [`daemon_unix`](Self::daemon_unix).
    pub fn daemon_udp(mut self, addr: std::net::SocketAddr) -> Self {
        self.daemon = Some(remote::DaemonEndpoint::Udp(addr));
        self
    }

    fn has_local_transport(&self) -> bool {
        #[cfg(feature = "ethertalk")]
        if self.ethernet_intf.is_some() {
            return true;
        }
        self.localtalk_serial_path.is_some()
    }

    /// Launch only the lower half of the stack: interfaces, AARP/LLAP
    /// addressing, DDP and the routing table — no NBP or AEP services.
    ///
    /// This is what the TailTalk daemon runs; most applications want
    /// [`build`](Self::build) instead.
    pub async fn build_underlay(self) -> Result<Underlay, Error> {
        if self.daemon.is_some() {
            return Err(anyhow::anyhow!(
                "build_underlay creates a local underlay; use build() with a daemon endpoint"
            ));
        }

        let mut pp = PacketProcessor::builder().tashtalk_features(self.tashtalk_features);
        #[cfg(feature = "ethertalk")]
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
        #[cfg(feature = "ethertalk")]
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
        #[cfg(not(feature = "ethertalk"))]
        let et_addressing: Option<addressing::AddressingHandle> = None;

        let lt_addressing = if self.localtalk_serial_path.is_some() {
            let lt_fixed = self.lt_fixed_node.map(|node| tailtalk_packets::aarp::AppleTalkAddress {
                network_number: 0,
                node_number: node,
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

        let route_table = route_table::RouteTable::new(route_table::LearningMode::Dynamic);
        let ddp = ddp::DdpProcessor::spawn(et_addressing.clone(), lt_addressing.clone(), outbound, route_table.clone());

        let transport_token = CancellationToken::new();
        tokio::spawn(processor.run(et_addressing.clone(), lt_addressing.clone(), ddp.clone(), transport_token.clone()));

        // Wait until addressing has settled on all active interfaces.
        if let Some(et) = &et_addressing {
            et.addr().await?;
        }
        if let Some(lt) = &lt_addressing {
            lt.addr().await?;
        }

        // Router discovery starts only after addressing has settled: ZIP's
        // initial GetNetInfo broadcast needs a source address, and the RTMP
        // listener may adopt gleaned network numbers on top of it.
        let zip = if self.router_discovery {
            let zip = zip::Zip::spawn(
                &ddp,
                et_addressing.clone(),
                lt_addressing.clone(),
                route_table.clone(),
                self.zone_cache.clone(),
            )
            .await;
            rtmp::Rtmp::spawn(&ddp, route_table.clone(), lt_addressing.clone(), Some(zip.clone())).await;
            Some(zip)
        } else {
            None
        };

        Ok(Underlay { et_addressing, lt_addressing, ddp, route_table, zip, transport_token })
    }

    /// Launch the full AppleTalk stack and return handles to each layer.
    ///
    /// With local interfaces, spawns actors for AARP/Addressing, DDP, AEP
    /// (Echo), and NBP in dependency order, then starts the
    /// [`PacketProcessor`] background task. With a daemon endpoint, connects
    /// to the daemon and runs the same AEP/NBP services over its DDP layer.
    pub async fn build(self) -> Result<TalkStack, Error> {
        if let Some(endpoint) = self.daemon.clone() {
            return self.build_remote(endpoint).await;
        }

        let Underlay { et_addressing, lt_addressing, ddp, route_table, zip, transport_token } =
            self.build_underlay().await?;

        let echo = echo::Echo::spawn(&ddp).await;
        let nbp = nbp::Nbp::spawn(&ddp, et_addressing.clone(), lt_addressing.clone(), route_table.clone()).await;

        let service_token = CancellationToken::new();
        let services_done = CancellationToken::new();

        Ok(TalkStack { et_addressing, lt_addressing, ddp, nbp, echo, zip, route_table, service_token, transport_token, services_done })
    }

    /// Build the stack on top of a remote daemon's underlay.
    async fn build_remote(self, endpoint: remote::DaemonEndpoint) -> Result<TalkStack, Error> {
        if self.has_local_transport() {
            return Err(anyhow::anyhow!(
                "cannot combine local interfaces with a remote daemon; configure the interfaces on the daemon instead"
            ));
        }

        let client = remote::RemoteClient::connect(&endpoint).await?;

        // Map the daemon's interfaces onto addressing handles. If the daemon
        // has several interfaces of one type, the first is used — same as the
        // local builder, which supports one of each.
        let interfaces = client.list_interfaces().await?;
        let mut et_addressing: Option<addressing::AddressingHandle> = None;
        let mut lt_addressing: Option<addressing::AddressingHandle> = None;
        for iface in &interfaces {
            match tailtalk_proto::InterfaceType::try_from(iface.r#type) {
                Ok(tailtalk_proto::InterfaceType::Ethertalk) if et_addressing.is_none() => {
                    et_addressing = Some(addressing::AddressingHandle::remote(
                        client.clone(),
                        iface.name.clone(),
                        aarp::AddressSource::EtherTalkPhase2,
                    ));
                }
                Ok(tailtalk_proto::InterfaceType::Localtalk) if lt_addressing.is_none() => {
                    lt_addressing = Some(addressing::AddressingHandle::remote(
                        client.clone(),
                        iface.name.clone(),
                        aarp::AddressSource::LocalTalk,
                    ));
                }
                _ => {}
            }
        }

        let ddp = ddp::DdpHandle::remote(client.clone());

        // Routing is daemon-owned; local table is a cache for NBP zone dispatch.
        let route_table = route_table::RouteTable::new(route_table::LearningMode::Static);
        client.sync_routes_to(route_table.clone());
        let routes = client.list_routes().await?;
        route_table.replace_contents(remote::snapshot_from_proto(&routes));
        let (rt_tx, mut rt_rx) = tokio::sync::mpsc::unbounded_channel();
        route_table.set_publisher(rt_tx);
        {
            let client = client.clone();
            tokio::spawn(async move {
                while let Some(change) = rt_rx.recv().await {
                    if let Err(e) = client.apply_route_change(&change).await {
                        tracing::error!("failed to sync route change to daemon: {e}");
                    }
                }
            });
        }

        let echo = echo::Echo::spawn(&ddp).await;
        let nbp = nbp::Nbp::spawn(&ddp, et_addressing.clone(), lt_addressing.clone(), route_table.clone()).await;

        let service_token = CancellationToken::new();
        let transport_token = CancellationToken::new();
        let services_done = CancellationToken::new();

        // The daemon connection is our transport: shutting down the stack
        // closes the connection, and a dead connection shuts down the stack.
        {
            let client = client.clone();
            let transport_token = transport_token.clone();
            tokio::spawn(async move {
                let closed = client.closed_token();
                tokio::select! {
                    _ = transport_token.cancelled() => client.shutdown(),
                    _ = closed.cancelled() => transport_token.cancel(),
                }
            });
        }

        Ok(TalkStack { et_addressing, lt_addressing, ddp, nbp, echo, zip: None, route_table, service_token, transport_token, services_done })
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
