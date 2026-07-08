use futures::StreamExt;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::ethertalk::{EtherTalkPhase2Frame, EtherTalkPhase2Type};
use tailtalk_packets::llap::{LlapPacket, LlapType};

#[cfg(not(target_os = "windows"))]
use mac_address::mac_address_by_name;

#[cfg(target_os = "windows")]
use get_adapters_addresses::{AdaptersAddresses, Family, Flags};

use crate::{addressing, ddp, CancellationToken};

struct EtherTalkCodec;

impl pcap::PacketCodec for EtherTalkCodec {
    type Item = Box<[u8]>;
    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        packet.data.into()
    }
}

fn write_eth1_header(buf: &mut [u8], dst: [u8; 6], src: [u8; 6], ethertype: u16) -> usize {
    buf[0..6].copy_from_slice(&dst);
    buf[6..12].copy_from_slice(&src);
    buf[12..14].copy_from_slice(&ethertype.to_be_bytes());
    14
}

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

pub struct EtherTalkTransport {
    pcap_rx: Option<pcap::Capture<pcap::Active>>,
    pcap_tx: Option<pcap::Capture<pcap::Active>>,
    pub our_mac: [u8; 6],
}

pub struct EtherTalkTx {
    pcap_tx: Option<pcap::Capture<pcap::Active>>,
    our_mac: [u8; 6],
}

impl EtherTalkTransport {
    pub fn open(intf: &str) -> anyhow::Result<Self> {
        let mac: String;
        let device_description: Option<String>;
        let our_mac: [u8; 6];

        #[cfg(target_os = "windows")]
        {
            let intf_str = std::ffi::OsStr::new(intf);
            let adapter_addresses = AdaptersAddresses::try_new(Family::Unspec, *Flags::default().include_all_interfaces())?;
            let adt = adapter_addresses.iter().find( |a| a.friendly_name() == intf_str ).ok_or_else(|| anyhow::anyhow!("Failed to get interfaces '{}'", intf))?;

            //let intf_friendly_name = adt.friendly_name().to_str();
            device_description = match  adt.description().into_string() {
                Ok(s) => Some(s),
                Err(e) => panic!("Cannot get description of adapater {e:?}")
            };
            // Convert representation so that PCAP filter works
            mac = adt.physical_address().unwrap().to_string().replace("-",":");
            // Grab MAC Address for future use
            let t = adt.physical_address().expect("MAC Address missing").as_u64().to_le_bytes();
            our_mac = t[0..6].try_into().unwrap();


        }
        #[cfg(not(target_os = "windows"))]
        {
            // Retrieve the interface MAC address linux/mac
            let t = mac_address_by_name(intf)?
                .ok_or_else(|| anyhow::anyhow!("no MAC address found for interface {}", intf))?;
            our_mac = t.bytes();
            mac = t.to_string();
        }


        let filter = format!(
            "(ether proto 0x809B or ether proto 0x80F3 or (ether[12:2] <= 1500)) and not ether src {mac}"
        );
        tracing::info!("filter string: {filter}");

        #[cfg(target_os = "windows")]
        {

                let devices = pcap::Device::list()?;
                let device = devices.into_iter().find(|dev| dev.desc == device_description ) ;

                tracing::info!("device {:?}", device );

                let d1 = device.clone().unwrap();
                let d2 = device.unwrap();

                // RX capture – promiscuous mode, filter applied.
                let mut rx = pcap::Capture::from_device( d1 ) ?
                    .promisc(true)
                    .immediate_mode(true)
                    .open()?;
                rx.filter(&filter, true)?;

                // TX capture – separate handle used solely for packet injection.
                let tx = pcap::Capture::from_device( d2 )?
                    .promisc(true)
                    .open()?;
                tracing::info!("EtherTalk pcap captures opened on {}", intf);
                Ok(Self { pcap_rx: Some(rx), pcap_tx: Some(tx), our_mac })
            }
            #[cfg(not(target_os = "windows"))]
            {
                let mut rx = pcap::Capture::from_device(intf)?
                    .promisc(true)
                    .immediate_mode(true)
                    .open()?;
                rx.filter(&filter, true)?;

                let tx = pcap::Capture::from_device(intf)?
                    .promisc(true)
                    .open()?;

                tracing::info!("EtherTalk pcap captures opened on {}", intf);
                Ok(Self { pcap_rx: Some(rx), pcap_tx: Some(tx), our_mac })
            }

        

        
    }

    /// Returns `None` if pcap stream setup fails; the caller should abort the run loop.
    pub fn spawn_rx_task(
        self,
        ddp: ddp::DdpHandle,
        addressing: addressing::AddressingHandle,
        token: CancellationToken,
    ) -> Option<EtherTalkTx> {
        let EtherTalkTransport { pcap_rx, pcap_tx, our_mac } = self;

        if let Some(rx_cap) = pcap_rx {
            let rx_cap = match rx_cap.setnonblock() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to set pcap nonblocking: {e}");
                    return None;
                }
            };
            let stream = match rx_cap.stream(EtherTalkCodec) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to create pcap stream: {e}");
                    return None;
                }
            };

            tokio::spawn(async move {
                tracing::info!("EtherTalk RX task started");
                tokio::pin!(stream);
                loop {
                    let data: Box<[u8]> = tokio::select! {
                        _ = token.cancelled() => break,
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
                                        ddp.received_pkt(
                                            payload,
                                            aarp::AddressSource::EtherTalkPhase2,
                                            header.src_mac,
                                        );
                                    }
                                    EtherTalkPhase2Type::Aarp => {
                                        if let Err(e) = addressing.received_pkt(
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
                            && let Err(e) = addressing.received_pkt(
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
                                        let source_mac: [u8; 6] = data[6..12].try_into().unwrap();
                                        ddp.received_parsed_pkt(
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
                                        let source_mac: [u8; 6] = data[6..12].try_into().unwrap();
                                        ddp.received_parsed_pkt(
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

        Some(EtherTalkTx { pcap_tx, our_mac })
    }
}

impl EtherTalkTx {
    pub fn build_ddp_frame(
        &self,
        dest: addressing::Node,
        payload: &[u8],
        output_buf: &mut [u8],
    ) -> usize {
        let payload_len = payload.len();
        match dest {
            addressing::Node::EtherTalkPhase1(mac) => {
                let n = write_eth1_header(output_buf, mac, self.our_mac, 0x809B);
                // Phase 1 DDP: 3-byte LLAP header (dst, src, type=2) precedes the DDP packet.
                // Node numbers are extracted from the DDP header bytes 8 and 9.
                output_buf[n] = if payload_len > 8 { payload[8] } else { 0 };
                output_buf[n + 1] = if payload_len > 9 { payload[9] } else { 0 };
                output_buf[n + 2] = 2;
                output_buf[n + 3..n + 3 + payload_len].copy_from_slice(payload);
                n + 3 + payload_len
            }
            addressing::Node::EtherTalkPhase2(mac) => {
                let n = write_snap_header(output_buf, mac, self.our_mac, [0x08, 0x00, 0x07], 0x809B, payload_len);
                output_buf[n..n + payload_len].copy_from_slice(payload);
                n + payload_len
            }
            _ => 0,
        }
    }

    pub fn build_aarp_frame(
        &self,
        dest: addressing::Node,
        payload: &[u8],
        output_buf: &mut [u8],
    ) -> usize {
        let payload_len = payload.len();
        match dest {
            addressing::Node::EtherTalkPhase1(mac) => {
                let n = write_eth1_header(output_buf, mac, self.our_mac, 0x80F3);
                output_buf[n..n + payload_len].copy_from_slice(payload);
                n + payload_len
            }
            addressing::Node::EtherTalkPhase2(mac) => {
                let n = write_snap_header(output_buf, mac, self.our_mac, [0x00, 0x00, 0x00], 0x80F3, payload_len);
                output_buf[n..n + payload_len].copy_from_slice(payload);
                n + payload_len
            }
            _ => 0,
        }
    }

    pub fn sendpacket(&mut self, output_buf: &[u8], final_size: usize) {
        if let Some(ref mut tx) = self.pcap_tx {
            let padded_size = final_size.max(60); // Ethernet minimum frame size
            if let Err(e) = tx.sendpacket(&output_buf[..padded_size]) {
                tracing::error!("failed to send packet: {e}");
            }
        }
    }
}