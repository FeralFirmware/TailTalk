use anyhow::{Error, bail};
use socket2::Socket;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::time::SystemTime;
use tailtalk_packets::aarp;
use tailtalk_packets::ddp::DdpPacket;
use tailtalk_packets::ethertalk::{EtherTalkFrame, EtherTalkType};
use tailtalk_packets::llap::{LlapPacket, LlapType};
use tokio::sync::mpsc;

pub mod addressing;
pub mod adsp;
pub mod afp;
pub mod asp;
pub mod atp;

pub mod ddp;
pub mod echo;
pub mod nbp;
pub mod pap;

#[derive(Debug)]
pub struct EtherTalkPacket {
    pub dst_mac: [u8; 6],
    pub protocol: EtherTalkType,
    pub payload: Box<[u8]>,
    pub source_type: aarp::AddressSource,
}

struct BoundSocket {
    socket: Socket,
    protocol: u16,
}

pub struct PacketProcessor {
    sockets: Vec<BoundSocket>,
    outbound_rx: mpsc::Receiver<EtherTalkPacket>,
    our_mac: [u8; 6],
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
        // ETH_P_802_2 to capture 802.3 LLC/SNAP frames (EtherTalk Phase 2)
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
        };
        let handle = OutboundHandle { tx };

        Ok((processor, handle))
    }

    pub fn get_mac(&self) -> [u8; 6] {
        self.our_mac
    }

    pub fn run(mut self, addressing: addressing::AddressingHandle, ddp: ddp::DdpHandle) {
        // Build a reusable pollfd array — one entry per raw socket.
        // We also want to wake up every ~1ms to drain the outbound channel, so timeout=1.
        let mut pollfds: Vec<libc::pollfd> = self
            .sockets
            .iter()
            .map(|s| libc::pollfd {
                fd: s.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();

        loop {
            // Drain all pending outbound packets first (non-blocking).
            let mut disconnected = false;
            loop {
                let pkt = match self.outbound_rx.try_recv() {
                    Ok(p) => p,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                };
                let mut output_buf: [u8; 1500] = [0u8; 1500];

                let final_size = match pkt.protocol {
                    EtherTalkType::Ddp => {
                        // Ethernet Header (common to both formats)
                        output_buf[0..6].copy_from_slice(&pkt.dst_mac);
                        output_buf[6..12].copy_from_slice(&self.our_mac);

                        match pkt.source_type {
                            aarp::AddressSource::LocalTalk => {
                                // LLAP/LocalTalk format: ETH_P_ATALK + LLAP header
                                // EtherType [12..14] = ETH_P_ATALK (0x809B)
                                output_buf[12] = 0x80;
                                output_buf[13] = 0x9B;

                                // LLAP Header Construction
                                // Dst Node [14] - extract from DDP Long Header (offset 8 in payload)
                                let dst_node = if pkt.payload.len() > 8 {
                                    pkt.payload[8]
                                } else {
                                    0
                                };

                                // Src Node [15] - extract from DDP Long Header (offset 9 in payload)
                                let src_node = if pkt.payload.len() > 9 {
                                    pkt.payload[9]
                                } else {
                                    0
                                };

                                output_buf[14] = dst_node;
                                output_buf[15] = src_node;
                                // Type [16] = 2 (DDP Long)
                                output_buf[16] = 2;

                                let payload_len = pkt.payload.len();
                                output_buf[17..17 + payload_len].copy_from_slice(&pkt.payload);

                                17 + payload_len
                            }
                            aarp::AddressSource::EtherTalk => {
                                // EtherTalk format: 802.3 length + 802.2 LLC/SNAP header
                                let payload_len = pkt.payload.len();
                                let total_payload = 8 + payload_len; // 8 bytes LLC/SNAP + DDP payload

                                // 802.3 Length field [12..14] (big-endian)
                                output_buf[12] = (total_payload >> 8) as u8;
                                output_buf[13] = (total_payload & 0xFF) as u8;

                                // 802.2 LLC header [14..17]
                                output_buf[14] = 0xAA; // DSAP (SNAP)
                                output_buf[15] = 0xAA; // SSAP (SNAP)
                                output_buf[16] = 0x03; // Control (Unnumbered Information)

                                // SNAP header [17..22]
                                output_buf[17] = 0x08; // OUI: 08:00:07 (Apple)
                                output_buf[18] = 0x00;
                                output_buf[19] = 0x07;
                                output_buf[20] = 0x80; // Protocol ID: 0x809B (AppleTalk)
                                output_buf[21] = 0x9B;

                                // DDP payload [22..]
                                output_buf[22..22 + payload_len].copy_from_slice(&pkt.payload);

                                14 + total_payload
                            }
                        }
                    }
                    EtherTalkType::Aarp => {
                        // Ethernet Header (common)
                        output_buf[0..6].copy_from_slice(&pkt.dst_mac);
                        output_buf[6..12].copy_from_slice(&self.our_mac);

                        let payload_len = pkt.payload.len();

                        match pkt.source_type {
                            aarp::AddressSource::LocalTalk => {
                                // LocalTalk: Ethernet II with EtherType 0x80F3
                                output_buf[12] = 0x80;
                                output_buf[13] = 0xF3;
                                output_buf[14..14 + payload_len].copy_from_slice(&pkt.payload);
                                14 + payload_len
                            }
                            aarp::AddressSource::EtherTalk => {
                                // EtherTalk: 802.3 + LLC/SNAP
                                let total_payload = 8 + payload_len; // 8 bytes LLC/SNAP + AARP payload

                                // 802.3 Length field [12..14] (big-endian)
                                output_buf[12] = (total_payload >> 8) as u8;
                                output_buf[13] = (total_payload & 0xFF) as u8;

                                // 802.2 LLC header [14..17]
                                output_buf[14] = 0xAA; // DSAP (SNAP)
                                output_buf[15] = 0xAA; // SSAP (SNAP)
                                output_buf[16] = 0x03; // Control (Unnumbered Information)

                                // SNAP header [17..22]
                                output_buf[17] = 0x00; // OUI: 00:00:00 (standard for AARP)
                                output_buf[18] = 0x00;
                                output_buf[19] = 0x00;
                                output_buf[20] = 0x80; // Protocol ID: 0x80F3 (AARP)
                                output_buf[21] = 0xF3;

                                // AARP payload [22..]
                                output_buf[22..22 + payload_len].copy_from_slice(&pkt.payload);

                                14 + total_payload
                            }
                        }
                    }
                };

                // Find the correct socket based on the protocol
                let target_protocol = match pkt.protocol {
                    EtherTalkType::Ddp => libc::ETH_P_ATALK as u16,
                    EtherTalkType::Aarp => libc::ETH_P_AARP as u16,
                };

                if let Some(sock) = self.sockets.iter().find(|s| s.protocol == target_protocol) {
                    sock.socket
                        .send(&output_buf[..final_size])
                        .expect("failed to send packet");
                } else {
                    tracing::error!("No socket found for protocol {:04x}", target_protocol);
                }
            }

            if disconnected {
                tracing::info!("Outbound channel closed, shutting down PacketProcessor");
                break;
            }

            // Wait for any socket to become readable (or 1ms timeout to re-check outbound).
            // poll() is the key fix: instead of blocking sequentially on each socket,
            // we wait on all of them at once.
            for pfd in &mut pollfds {
                pfd.revents = 0;
            }
            let ready = unsafe {
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    1, // 1ms timeout — keeps outbound latency bounded
                )
            };
            if ready <= 0 {
                // Timeout or error — loop back to drain outbound then poll again.
                continue;
            }

            // Only recv() on sockets that poll() flagged as readable.
            for (i, sock) in self.sockets.iter().enumerate() {
                if pollfds[i].revents & libc::POLLIN == 0 {
                    continue;
                }

                let mut ethertalk_buf: [u8; 1000] = [0u8; 1000];
                unsafe {
                    let read = libc::recv(
                        sock.socket.as_raw_fd(),
                        &mut ethertalk_buf as *mut u8 as *mut libc::c_void,
                        1000,
                        libc::MSG_DONTWAIT, // non-blocking now that we know data is ready
                    );

                    if read > 0 {
                        let data = &ethertalk_buf[..read as usize];

                        // Check protocol type to determine parsing strategy
                        if sock.protocol == libc::ETH_P_802_2 as u16 {
                            // ETH_P_802_2: Kernel delivers 802.3 frames with LLC header
                            // These are EtherTalk Phase 2 frames
                            if data.len() >= 14 {
                                let ethertype_or_len = u16::from_be_bytes([data[12], data[13]]);

                                // 802.3 frames have length field <= 1500
                                if ethertype_or_len <= 1500 {
                                    if let Ok(header) = EtherTalkFrame::parse(data) {
                                        let payload =
                                            &ethertalk_buf[EtherTalkFrame::len()..read as usize];
                                        match header.protocol {
                                            EtherTalkType::Ddp => ddp.received_pkt(
                                                payload,
                                                aarp::AddressSource::EtherTalk,
                                                header.src_mac,
                                            ),
                                            EtherTalkType::Aarp => addressing
                                                .received_pkt(
                                                    payload,
                                                    aarp::AddressSource::EtherTalk,
                                                )
                                                .expect("failed to relay aarp pkt"),
                                        }
                                    } else {
                                        tracing::warn!(
                                            "Failed to parse 802.3 frame as EtherTalk LLC/SNAP"
                                        );
                                    }
                                }
                            }
                        } else if let Ok(header) = EtherTalkFrame::parse(data) {
                            // Try parsing as EtherTalk (802.2 SNAP) for non-802.3 protocols
                            let payload = &ethertalk_buf[EtherTalkFrame::len()..read as usize];
                            match header.protocol {
                                EtherTalkType::Ddp => ddp.received_pkt(
                                    payload,
                                    aarp::AddressSource::EtherTalk,
                                    header.src_mac,
                                ),
                                EtherTalkType::Aarp => addressing
                                    .received_pkt(payload, aarp::AddressSource::EtherTalk)
                                    .expect("failed to relay aarp pkt"),
                            }
                        } else if sock.protocol == libc::ETH_P_AARP as u16 {
                            if data.len() > 14 {
                                let payload = &ethertalk_buf[14..read as usize];
                                addressing
                                    .received_pkt(payload, aarp::AddressSource::LocalTalk)
                                    .expect("failed to relay aarp pkt");
                            }
                        } else if sock.protocol == libc::ETH_P_ATALK as u16 {
                            // Try parsing as LLAP first
                            if data.len() > 14 {
                                let llap_data = &data[14..];
                                if let Ok(llap) = LlapPacket::parse(llap_data) {
                                    match llap.type_ {
                                        LlapType::DdpShort => {
                                            tracing::info!(
                                                "LLAP (Short) pkt: dst_node: {} src_node: {}",
                                                llap.dst_node,
                                                llap.src_node
                                            );
                                            let payload = &ethertalk_buf
                                                [(14 + LlapPacket::LEN)..read as usize];
                                            if let Ok(headers) = DdpPacket::parse_short(
                                                payload,
                                                llap.dst_node,
                                                llap.src_node,
                                            ) && payload.len() >= 5
                                            {
                                                let ddp_payload = payload[5..].into();
                                                // Extract source MAC from Ethernet frame (bytes 6-11)
                                                let source_mac: [u8; 6] =
                                                    ethertalk_buf[6..12].try_into().unwrap();
                                                ddp.received_parsed_pkt(
                                                    headers,
                                                    ddp_payload,
                                                    aarp::AddressSource::LocalTalk,
                                                    source_mac,
                                                );
                                            }
                                        }
                                        LlapType::DdpLong => {
                                            tracing::info!(
                                                "LLAP (Long) pkt: dst_node: {} src_node: {}",
                                                llap.dst_node,
                                                llap.src_node
                                            );
                                            let payload = &ethertalk_buf
                                                [(14 + LlapPacket::LEN)..read as usize];
                                            if let Ok(headers) = DdpPacket::parse(payload) {
                                                // DdpPacket::parse handles length check
                                                if payload.len() >= DdpPacket::LEN {
                                                    let ddp_payload =
                                                        payload[DdpPacket::LEN..].into();
                                                    // Extract source MAC from Ethernet frame (bytes 6-11)
                                                    let source_mac: [u8; 6] =
                                                        ethertalk_buf[6..12].try_into().unwrap();
                                                    ddp.received_parsed_pkt(
                                                        headers,
                                                        ddp_payload,
                                                        aarp::AddressSource::LocalTalk,
                                                        source_mac,
                                                    );
                                                }
                                            }
                                        }
                                        LlapType::Other(n) => {
                                            tracing::info!("LLAP type {n} unknown");
                                        }
                                    }
                                } else {
                                    tracing::info!("LLAP pkt not handled");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
} // impl PacketProcessor

#[derive(Clone)]
pub struct OutboundHandle {
    tx: mpsc::Sender<EtherTalkPacket>,
}

impl OutboundHandle {
    pub fn new(tx: mpsc::Sender<EtherTalkPacket>) -> Self {
        Self { tx }
    }

    pub async fn send(&self, packet: EtherTalkPacket) -> Result<(), Error> {
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
