use anyhow::{Error, bail};
use socket2::Socket;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::time::SystemTime;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::ethertalk::{EtherTalkPhase2Frame, EtherTalkPhase2Type};
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tashtalk::TashTalk;
use tokio::io::unix::AsyncFd;
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

struct BoundSocket {
    socket: Socket,
    protocol: u16,
}

pub struct PacketProcessor {
    sockets: Vec<BoundSocket>,
    outbound_rx: mpsc::Receiver<DataLinkPacket>,
    our_mac: [u8; 6],
    tashtalk_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl PacketProcessor {
    pub fn spawn(intf: &str) -> Result<(Self, OutboundHandle), Error> {
        let c_intf = CString::new(intf).expect("failed to parse intf name");
        let mut ifreq = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };

        // Open a temporary socket to get interface index and MAC
        let tmp_sock = Socket::new(
            libc::AF_PACKET.into(),
            libc::SOCK_RAW.into(),
            Some(libc::ETH_P_ALL.into()),
        )?;

        unsafe {
            c_intf.as_ptr().copy_to(
                ifreq.ifr_name.as_mut_ptr(),
                c_intf.as_bytes_with_nul().len(),
            );
            let res = libc::ioctl(
                tmp_sock.as_raw_fd(),
                libc::SIOCGIFHWADDR,
                &ifreq as *const _,
            );

            if res < 0 {
                panic!("res was -1!");
            }
        }

        let our_mac: [u8; 6] = unsafe {
            let mac_data = ifreq.ifr_ifru.ifru_hwaddr.sa_data;
            [
                mac_data[0] as u8,
                mac_data[1] as u8,
                mac_data[2] as u8,
                mac_data[3] as u8,
                mac_data[4] as u8,
                mac_data[5] as u8,
            ]
        };

        unsafe {
            let res = libc::ioctl(tmp_sock.as_raw_fd(), libc::SIOCGIFINDEX, &ifreq as *const _);

            if res < 0 {
                panic!("res was -1!");
            }
        }

        let if_index = unsafe { ifreq.ifr_ifru.ifru_ifindex };
        drop(tmp_sock);

        // ETH_P_ATALK and ETH_P_AARP for LLAP (Phase 1)
        // ETH_P_802_2 to capture 802.3 LLC/SNAP frames (EtherTalkPhase2 Phase 2)
        let protocols = [libc::ETH_P_ATALK, libc::ETH_P_AARP, libc::ETH_P_802_2];
        let mut sockets = Vec::new();

        for proto in protocols {
            tracing::info!("Creating socket for protocol: 0x{:04x}", proto);
            let sock = Socket::new(
                libc::AF_PACKET.into(),
                libc::SOCK_RAW.into(),
                Some(proto.into()),
            )?;

            // Enable promiscuous mode to receive broadcast packets (e.g., Apple's 09:00:07:FF:FF:FF)
            // TODO: Is this actually needed? Added during debugging but never got around to testing if the below multicast
            // does the trick.
            let mreq = libc::packet_mreq {
                mr_ifindex: if_index,
                mr_type: libc::PACKET_MR_PROMISC as u16,
                mr_alen: 0,
                mr_address: [0; 8],
            };

            if unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &mreq as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&mreq) as libc::socklen_t,
                )
            } < 0
            {
                bail!("failed to set promiscuous mode on sock");
            }

            // Also explicitly add Apple's multicast broadcast address
            let apple_mcast = libc::packet_mreq {
                mr_ifindex: if_index,
                mr_type: libc::PACKET_MR_MULTICAST as u16,
                mr_alen: 6,
                mr_address: [0x09, 0x00, 0x07, 0xff, 0xff, 0xff, 0, 0],
            };

            if unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &apple_mcast as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&apple_mcast) as libc::socklen_t,
                )
            } < 0
            {
                tracing::warn!("failed to add Apple multicast address - continuing anyway");
            }

            tracing::info!(
                "Successfully bound socket for protocol 0x{:04x} to interface index {}",
                proto,
                if_index
            );

            let addr = libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: u16::to_be(proto as u16),
                sll_ifindex: if_index,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0; 8], // Unused for now
            };

            // Bind the socket to the interface
            unsafe {
                let res = libc::bind(
                    sock.as_raw_fd(),
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as u32,
                );
                if res < 0 {
                    let err = std::io::Error::last_os_error().raw_os_error().unwrap();
                    panic!("err was: {err}");
                }
            }
            sockets.push(BoundSocket {
                socket: sock,
                protocol: proto as u16,
            });
        }

        let (tx, rx) = mpsc::channel(100);

        let processor = Self {
            sockets,
            outbound_rx: rx,
            our_mac,
            tashtalk_tx: None,
        };
        let handle = OutboundHandle { tx };

        Ok((processor, handle))
    }

    pub fn with_tashtalk(
        mut self,
        serial_path: &str,
        _addressing_handle: addressing::AddressingHandle,
        ddp_handle: ddp::DdpHandle,
    ) -> Self {
        let (tashtalk_tx, mut tashtalk_rx) = mpsc::channel(100);
        self.tashtalk_tx = Some(tashtalk_tx);

        let serial_stream = tokio_serial::new(serial_path, 1_000_000)
            .flow_control(tokio_serial::FlowControl::Hardware)
            .open_native_async()
            .expect("Failed to open serial port for TashTalk");
        let mut tashtalk_instance = TashTalk::new(serial_stream);

        tokio::spawn(async move {
            tracing::info!("Resetting TashTalk buffers...");
            if let Err(e) = tashtalk_instance.reset().await {
                tracing::error!("Failed to reset TashTalk: {:?}", e);
            }

            // Enable hardware CRC calculation
            tracing::info!("Enabling TashTalk CRC calculation...");
            if let Err(e) = tashtalk_instance
                .set_features(tashtalk::TashTalkFeatures::new().with_crc_calculation())
                .await
            {
                tracing::error!("Failed to set TashTalk features: {:?}", e);
            }

            // Register our node ID with TashTalk so it will ACK packets for us
            match _addressing_handle.addr().await {
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
                    tracing::error!("Failed to get our AppleTalk address for TashTalk setup: {:?}", e);
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
                                // Ensure LLAP packet is formed correctly
                                // TashTalk frames come packed without FCS bytes if crc_checking is not turned on
                                if let Ok(llap) = LlapPacket::parse(&data) {
                                    match llap.type_ {
                                        LlapType::DdpShort => {
                                            tracing::info!("TashTalk: LocalTalk DDP Short");
                                            if let Ok(headers) = DdpPacket::parse_short(
                                                &data[3..],
                                                llap.dst_node,
                                                llap.src_node,
                                            ) {
                                                tracing::info!("LLAP: {:?}, DDP Short: {:?}", llap, headers);
                                                let payload = data[8..].to_vec().into_boxed_slice();
                                                ddp_handle.received_parsed_pkt(
                                                    headers,
                                                    payload,
                                                    aarp::AddressSource::LocalTalk,
                                                    [0; 6], // Mac is unused for LocalTalk Node
                                                );
                                            }
                                        }
                                        LlapType::DdpLong => {
                                            tracing::info!("TashTalk: LocalTalk DDP Long");
                                            if let Ok(headers) = DdpPacket::parse(&data[3..]) {
                                                let payload = data[(3 + DdpPacket::LEN)..].to_vec().into_boxed_slice();
                                                ddp_handle.received_parsed_pkt(
                                                    headers,
                                                    payload,
                                                    aarp::AddressSource::LocalTalk,
                                                    [0; 6], // Mac is unused for LocalTalk Node
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

        self
    }

    pub fn get_mac(&self) -> [u8; 6] {
        self.our_mac
    }

    pub async fn run(self, addressing: addressing::AddressingHandle, ddp: ddp::DdpHandle) {
        // Spawn async receiver tasks for all ethernet sockets
        for bound_sock in &self.sockets {
            let sock_clone = bound_sock
                .socket
                .try_clone()
                .expect("failed to clone socket");
            sock_clone.set_nonblocking(true).unwrap();
            let protocol = bound_sock.protocol;
            let ddp = ddp.clone();
            let addressing = addressing.clone();

            let async_fd = AsyncFd::new(sock_clone).unwrap();
            tokio::spawn(async move {
                tracing::info!("Spawned rx task for interface 0x{:04x}", protocol);
                loop {
                    let mut guard = async_fd.readable().await.unwrap();
                    let mut ethertalk_buf = [0u8; 1500];
                    let raw_fd = async_fd.get_ref().as_raw_fd();
                    let read = unsafe {
                        libc::recv(
                            raw_fd,
                            ethertalk_buf.as_mut_ptr() as *mut libc::c_void,
                            ethertalk_buf.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };

                    if read > 0 {
                        let data = &ethertalk_buf[..read as usize];

                        // Check protocol type to determine parsing strategy
                        if protocol == libc::ETH_P_802_2 as u16 {
                            if data.len() >= 14 {
                                let ethertype_or_len = u16::from_be_bytes([data[12], data[13]]);
                                if ethertype_or_len <= 1500
                                    && let Ok(header) = EtherTalkPhase2Frame::parse(data) {
                                        let payload = &ethertalk_buf
                                            [EtherTalkPhase2Frame::len()..read as usize];
                                        match header.protocol {
                                            EtherTalkPhase2Type::Ddp => ddp.received_pkt(
                                                payload,
                                                aarp::AddressSource::EtherTalkPhase2,
                                                header.src_mac,
                                            ),
                                            EtherTalkPhase2Type::Aarp => addressing
                                                .received_pkt(
                                                    payload,
                                                    aarp::AddressSource::EtherTalkPhase2,
                                                )
                                                .expect("failed to relay aarp pkt"),
                                        }
                                    }
                            }
                        } else if let Ok(header) = EtherTalkPhase2Frame::parse(data) {
                            let payload =
                                &ethertalk_buf[EtherTalkPhase2Frame::len()..read as usize];
                            match header.protocol {
                                EtherTalkPhase2Type::Ddp => ddp.received_pkt(
                                    payload,
                                    aarp::AddressSource::EtherTalkPhase2,
                                    header.src_mac,
                                ),
                                EtherTalkPhase2Type::Aarp => addressing
                                    .received_pkt(payload, aarp::AddressSource::EtherTalkPhase2)
                                    .expect("failed to relay aarp pkt"),
                            }
                        } else if protocol == libc::ETH_P_AARP as u16 {
                            if data.len() > 14 {
                                let payload = &ethertalk_buf[14..read as usize];
                                addressing
                                    .received_pkt(payload, aarp::AddressSource::EtherTalkPhase1)
                                    .expect("failed to relay aarp pkt");
                            }
                        } else if protocol == libc::ETH_P_ATALK as u16
                            && data.len() > 14 {
                                let llap_data = &data[14..];
                                if let Ok(llap) = LlapPacket::parse(llap_data) {
                                    match llap.type_ {
                                        LlapType::DdpShort => {
                                            let payload = &ethertalk_buf
                                                [(14 + LlapPacket::LEN)..read as usize];
                                            if let Ok(headers) = DdpPacket::parse_short(
                                                payload,
                                                llap.dst_node,
                                                llap.src_node,
                                            ) && payload.len() >= 5
                                            {
                                                let ddp_payload = payload[5..].into();
                                                let source_mac: [u8; 6] =
                                                    ethertalk_buf[6..12].try_into().unwrap();
                                                ddp.received_parsed_pkt(
                                                    headers,
                                                    ddp_payload,
                                                    aarp::AddressSource::EtherTalkPhase1,
                                                    source_mac,
                                                );
                                            }
                                        }
                                        LlapType::DdpLong => {
                                            let payload = &ethertalk_buf
                                                [(14 + LlapPacket::LEN)..read as usize];
                                            if let Ok(headers) = DdpPacket::parse(payload)
                                                && payload.len() >= DdpPacket::LEN {
                                                    let ddp_payload =
                                                        payload[DdpPacket::LEN..].into();
                                                    let source_mac: [u8; 6] =
                                                        ethertalk_buf[6..12].try_into().unwrap();
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
                    } else {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }
                        break;
                    }
                }
            });
        }

        let mut rx = self.outbound_rx;
        let sockets = self.sockets;
        let tashtalk_tx = self.tashtalk_tx;

        while let Some(pkt) = rx.recv().await {
            let mut output_buf: [u8; 1500] = [0u8; 1500];

            let final_size = match pkt.protocol {
                DataLinkProtocol::Ddp => {
                    match pkt.dest_node {
                        addressing::Node::EtherTalkPhase1(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&self.our_mac);
                            output_buf[12] = 0x80;
                            output_buf[13] = 0x9B;
                            let dst_node = if pkt.payload.len() > 8 {
                                pkt.payload[8]
                            } else {
                                0
                            };
                            let src_node = if pkt.payload.len() > 9 {
                                pkt.payload[9]
                            } else {
                                0
                            };
                            output_buf[14] = dst_node;
                            output_buf[15] = src_node;
                            output_buf[16] = 2;
                            let payload_len = pkt.payload.len();
                            output_buf[17..17 + payload_len].copy_from_slice(&pkt.payload);
                            17 + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&self.our_mac);
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
                            // LocalTalk always uses DDP Short — there are no routers,
                            // so network numbers are always 0 and the short 5-byte
                            // header is correct per the AppleTalk spec.
                            // src_node comes from our own LocalTalk node ID supplied
                            // by the DDP layer via DataLinkPacket::src_node_id.
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

                            // Do NOT append trailing zero CRC bytes here!
                            // If SetFeatures Bit 7 is enabled, TashTalk expects 2 dummy
                            // bytes at the end of the payload to overwrite with the real CRC,
                            // AND they MUST be included in the total size sent!
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
                            output_buf[6..12].copy_from_slice(&self.our_mac);
                            output_buf[12] = 0x80;
                            output_buf[13] = 0xF3;
                            output_buf[14..14 + payload_len].copy_from_slice(&pkt.payload);
                            14 + payload_len
                        }
                        addressing::Node::EtherTalkPhase2(mac) => {
                            output_buf[0..6].copy_from_slice(&mac);
                            output_buf[6..12].copy_from_slice(&self.our_mac);
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
                    let target_protocol = match pkt.protocol {
                        DataLinkProtocol::Ddp => libc::ETH_P_ATALK as u16,
                        DataLinkProtocol::Aarp => libc::ETH_P_AARP as u16,
                    };

                    if let Some(sock) = sockets.iter().find(|s| s.protocol == target_protocol) {
                        if let Err(e) = sock.socket.send(&output_buf[..final_size]) {
                            tracing::error!("failed to send packet: {}", e);
                        }
                    } else {
                        tracing::error!("No socket found for protocol {:04x}", target_protocol);
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
} // impl PacketProcessor

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
