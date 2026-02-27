use crate::ddp::{DdpHandle, DdpSocket};
use std::collections::HashMap;
use std::io;
use tailtalk_packets::{
    atp::{AtpFunction, AtpPacket},
    ddp::{DdpPacket, DdpProtocolType},
};
use tokio::sync::{mpsc, oneshot};

/// Maximum data bytes per ATP packet.
/// DDP max datagram = 599 bytes; minus 13-byte DDP header = 586 bytes DDP payload;
/// minus 8-byte ATP header = 578 bytes of ATP data per packet.
pub const ATP_MAX_DATA_PER_PACKET: usize = 578;

// Type aliases for complex channel types
type AtpResponseChannel = oneshot::Sender<Result<(Vec<u8>, [u8; 4]), io::Error>>;

pub struct PendingRequestState {
    pub chan: AtpResponseChannel,
    pub xo: bool,
    pub received_packets: std::collections::BTreeMap<u8, Vec<u8>>,
    pub user_bytes: Option<[u8; 4]>,
    pub eom_seq: Option<u8>,
}

type AtpTransactionMap = HashMap<u16, PendingRequestState>;

// Helper struct since DdpAddress might be ambiguous if not imported carefully
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AtpAddress {
    pub network_number: u16,
    pub node_number: u8,
    pub socket_number: u8,
}

#[derive(Debug)]
pub struct AtpSendRequest {
    pub address: AtpAddress,
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
    pub chan: AtpResponseChannel,
}

#[derive(Debug)]
pub struct AtpResponse {
    pub data: Vec<u8>,
    pub user_bytes: [u8; 4],
}

#[derive(Debug)]
pub struct AtpSendResponse {
    pub destination: AtpAddress,
    pub tid: u16,
    pub packets: Vec<AtpResponse>,
}

#[derive(Debug)]
pub struct AtpSendRelease {
    pub destination: AtpAddress,
    pub tid: u16,
}

pub enum AtpCommand {
    SendRequest(AtpSendRequest),
    SendResponse(AtpSendResponse),
    SendRelease(AtpSendRelease),
}

pub struct AtpReceivedRequest {
    pub transaction_id: u16,
    pub source: AtpAddress,
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
    pub response_sender: mpsc::Sender<AtpCommand>,
    pub release_rx: Option<oneshot::Receiver<()>>,
    /// The ATP bitmap from the request: each set bit = one response packet the client will accept.
    /// bit 0 = packet 0, bit 1 = packet 1, ..., bit 7 = packet 7 (max 8 packets).
    pub bitmap: u8,
}

impl AtpReceivedRequest {
    /// Send a response with automatic fragmentation.
    ///
    /// Respects the client's ATP bitmap: only sends as many packets as the client
    /// declared it can receive (count of set bits in `self.bitmap`, max 8).
    /// Sending more packets than the bitmap allows causes ASP error -1067 (aspBufTooSmall).
    pub async fn send_response(&self, data: Vec<u8>, user_bytes: [u8; 4]) -> Result<(), io::Error> {
        // The client bitmap tells us how many response packets it will accept.
        // Each set bit in the bitmap corresponds to one acceptable packet (bit 0 = pkt 0, etc.).
        //
        // IMPORTANT: Classic Mac OS sends bitmap=0x00 in ASP SPCommand TReqs, which is non-standard
        // per the ATP spec (0x00 means "no buffers"), but in practice it means "no restriction" —
        // treat it the same as 0xFF (all 8 packets allowed). Clamping it to 1 packet would
        // silently truncate multi-packet responses and corrupt the client's file offset.
        let effective_bitmap = if self.bitmap == 0x00 {
            0xFF
        } else {
            self.bitmap
        };
        let max_packets = (effective_bitmap.count_ones() as usize).min(8).max(1);
        let max_data = max_packets * ATP_MAX_DATA_PER_PACKET;

        if data.len() > max_data {
            tracing::warn!(
                "ATP response truncated: {} bytes requested but client bitmap 0x{:02x} only allows {} bytes ({} packets)",
                data.len(),
                self.bitmap,
                max_data,
                max_packets
            );
        }

        // Split data into chunks, honouring the client's bitmap limit
        let mut packets: Vec<AtpResponse> = data[..data.len().min(max_data)]
            .chunks(ATP_MAX_DATA_PER_PACKET)
            .map(|chunk| AtpResponse {
                data: chunk.to_vec(),
                user_bytes,
            })
            .collect();

        // Always send at least one packet (e.g. empty ASP OpenSession replies)
        if packets.is_empty() {
            packets.push(AtpResponse {
                data: vec![],
                user_bytes,
            });
        }

        // Send via internal method
        self.send_response_internal(packets).await
    }

    /// Internal method for sending pre-split packets.
    async fn send_response_internal(&self, packets: Vec<AtpResponse>) -> Result<(), io::Error> {
        if packets.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot send more than 8 response packets",
            ));
        }
        let cmd = AtpCommand::SendResponse(AtpSendResponse {
            destination: self.source,
            tid: self.transaction_id,
            packets,
        });
        self.response_sender
            .send(cmd)
            .await
            .map_err(io::Error::other)
    }
}

#[derive(Clone, Debug)]
pub struct AtpRequestor {
    pub cmd_tx: mpsc::Sender<AtpCommand>,
    pub socket_number: u8,
}

impl AtpRequestor {
    pub async fn send_request(
        &self,
        address: AtpAddress,
        user_bytes: [u8; 4],
        data: Vec<u8>,
    ) -> Result<(Vec<u8>, [u8; 4]), io::Error> {
        let (tx, rx) = oneshot::channel();
        let cmd = AtpCommand::SendRequest(AtpSendRequest {
            address,
            user_bytes,
            data,
            chan: tx,
        });

        self.cmd_tx.send(cmd).await.map_err(io::Error::other)?;

        rx.await.map_err(io::Error::other)?
    }
}

#[derive(Debug)]
pub struct AtpResponder {
    pub incoming_rx: mpsc::Receiver<AtpReceivedRequest>,
}

impl AtpResponder {
    pub async fn next(&mut self) -> Option<AtpReceivedRequest> {
        self.incoming_rx.recv().await
    }
}

pub struct Atp {
    sock: DdpSocket,
    request_recv: mpsc::Receiver<AtpCommand>,
    incoming_req_tx: mpsc::Sender<AtpReceivedRequest>,
    cmd_tx: mpsc::Sender<AtpCommand>,
    // Map Transaction ID to pending request channel and XO status
    pending_transactions: AtpTransactionMap,
    // Map (Source, TID) to release signal channel
    pending_releases: HashMap<(AtpAddress, u16), oneshot::Sender<()>>,
    next_tid: u16,
}

impl Atp {
    pub async fn spawn(
        ddp: &DdpHandle,
        socket_number: Option<u8>,
    ) -> (u8, AtpRequestor, AtpResponder) {
        let sock = ddp
            .new_sock(DdpProtocolType::Atp, socket_number) // Use provided or dynamic socket
            .await
            .expect("failed to create ATP sock");

        let actual_socket = sock.socket_num();

        let (request_send, request_recv) = mpsc::channel(100);
        let (incoming_req_tx, incoming_req_rx) = mpsc::channel(1); // Capacity 1 queue

        let atp = Atp {
            sock,
            request_recv,
            incoming_req_tx,
            cmd_tx: request_send.clone(),
            pending_transactions: HashMap::new(),
            pending_releases: HashMap::new(),
            next_tid: 1, // Start TID at 1
        };

        tokio::spawn(async move {
            tracing::debug!("ATP actor starting");
            atp.run().await;
            tracing::debug!("ATP actor stopped");
        });

        (
            actual_socket,
            AtpRequestor {
                cmd_tx: request_send,
                socket_number: actual_socket,
            },
            AtpResponder {
                incoming_rx: incoming_req_rx,
            },
        )
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => {
                            self.handle_packet(pkt.headers, &mut pkt.payload).await;
                        },
                        Err(e) => {
                            tracing::error!("ATP socket error: {}", e);
                        },
                    }
                },
                req = self.request_recv.recv() => {
                    if let Some(command) = req {
                        match command {
                            AtpCommand::SendRequest(req) => self.handle_send_request(req).await,
                            AtpCommand::SendResponse(resp) => self.handle_send_response(resp).await,
                            AtpCommand::SendRelease(rel) => self.handle_send_release(rel).await,
                        }
                    } else {
                        tracing::info!("ATP command channel closed");
                        break;
                    }
                }
            }
        }
    }

    async fn handle_send_request(&mut self, req: AtpSendRequest) {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        let packet = AtpPacket {
            function: AtpFunction::Request,
            xo: true,   // internal assumption: always exactly once for now
            eom: false, // EOM must be 0 for TReq packets according to AppleTalk specs
            sts: false,
            bitmap_seq_num: 0xff, // 8 buffers/packets
            tid,
            user_bytes: req.user_bytes,
        };

        let mut buf = [0u8; 600]; // DDP max is 586

        let header_len = packet
            .to_bytes(&mut buf)
            .expect("failed to serialize ATP header");

        let total_len = header_len + req.data.len();
        if req.data.len() > ATP_MAX_DATA_PER_PACKET {
            tracing::error!(
                "ATP request data too large: {} (max {})",
                req.data.len(),
                ATP_MAX_DATA_PER_PACKET
            );
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("data too large (max {})", ATP_MAX_DATA_PER_PACKET),
            )));
            return;
        }

        buf[header_len..total_len].copy_from_slice(&req.data);

        // Construct DdpAddress
        let dest = crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: req.address.network_number,
                node_number: req.address.node_number,
            },
            req.address.socket_number,
        );

        if let Err(e) = self.sock.send_to(&buf[..total_len], dest).await {
            let _ = req.chan.send(Err(io::Error::other(e)));
        } else {
            self.pending_transactions.insert(
                tid,
                PendingRequestState {
                    chan: req.chan,
                    xo: true, // XO is always true for now
                    received_packets: std::collections::BTreeMap::new(),
                    user_bytes: None,
                    eom_seq: None,
                },
            );
        }
    }

    async fn handle_send_response(&mut self, resp: AtpSendResponse) {
        for (i, node) in resp.packets.iter().enumerate() {
            let packet = AtpPacket {
                function: AtpFunction::Response,
                xo: false,                        // Responses don't set XO
                eom: i == resp.packets.len() - 1, // Set EOM on last packet
                sts: false,
                bitmap_seq_num: i as u8,
                tid: resp.tid,
                user_bytes: node.user_bytes,
            };

            let mut buf = [0u8; 600];
            let header_len = packet
                .to_bytes(&mut buf)
                .expect("failed to serialize ATP response header");

            let total_len = header_len + node.data.len();
            if total_len > buf.len() {
                tracing::error!("Response chunk too large: {}", node.data.len());
                continue;
            }

            buf[header_len..total_len].copy_from_slice(&node.data);

            let dest = crate::ddp::DdpAddress::new(
                tailtalk_packets::aarp::AppleTalkAddress {
                    network_number: resp.destination.network_number,
                    node_number: resp.destination.node_number,
                },
                resp.destination.socket_number,
            );

            if let Err(e) = self.sock.send_to(&buf[..total_len], dest).await {
                tracing::error!("Failed to send ATP response packet {}: {}", i, e);
            }
        }

        // Ensure next_tid is higher than any response TID we've used
        // This maintains monotonic TID sequence across requests and responses
        if resp.tid >= self.next_tid {
            self.next_tid = resp.tid + 1;
        }
    }

    async fn handle_send_release(&mut self, rel: AtpSendRelease) {
        let packet = AtpPacket {
            function: AtpFunction::Release,
            xo: false,
            eom: false,
            sts: false,
            bitmap_seq_num: 0,
            tid: rel.tid,
            user_bytes: [0; 4],
        };

        tracing::debug!(
            "ATP Sending Release to {:?} tid={}",
            rel.destination,
            rel.tid
        );

        let mut buf = [0u8; 600];
        let header_len = packet
            .to_bytes(&mut buf)
            .expect("failed to serialize ATP release header");

        let dest = crate::ddp::DdpAddress::new(
            tailtalk_packets::aarp::AppleTalkAddress {
                network_number: rel.destination.network_number,
                node_number: rel.destination.node_number,
            },
            rel.destination.socket_number,
        );

        if let Err(e) = self.sock.send_to(&buf[..header_len], dest).await {
            tracing::error!("Failed to send ATP Release: {}", e);
        }
    }

    async fn handle_packet(&mut self, ddp: DdpPacket, payload: &mut [u8]) {
        let packet = match AtpPacket::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to parse ATP packet: {}", e);
                return;
            }
        };

        match packet.function {
            AtpFunction::Request => {
                // Ensure next_tid is higher than the request TID to maintain monotonic sequence
                if packet.tid >= self.next_tid {
                    self.next_tid = packet.tid.wrapping_add(1);
                }

                // Server-side: dispatch to responder
                let request_data = if payload.len() > AtpPacket::HEADER_LEN {
                    payload[AtpPacket::HEADER_LEN..].to_vec()
                } else {
                    Vec::new()
                };

                let from = AtpAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                    socket_number: ddp.src_sock_num,
                };

                let release_rx = if packet.xo {
                    let (tx, rx) = oneshot::channel();
                    self.pending_releases.insert((from, packet.tid), tx);
                    Some(rx)
                } else {
                    None
                };

                let req = AtpReceivedRequest {
                    transaction_id: packet.tid,
                    source: from,
                    user_bytes: packet.user_bytes,
                    data: request_data,
                    response_sender: self.cmd_tx.clone(),
                    release_rx,
                    bitmap: packet.bitmap_seq_num,
                };

                if let Err(e) = self.incoming_req_tx.try_send(req) {
                    tracing::debug!("Dropping incoming ATP request, queue full: {}", e);
                }
            }
            AtpFunction::Response => {
                // Client-side: handle response to our request
                if let std::collections::hash_map::Entry::Occupied(mut entry) =
                    self.pending_transactions.entry(packet.tid)
                {
                    if payload.len() >= AtpPacket::HEADER_LEN {
                        let data = payload[AtpPacket::HEADER_LEN..].to_vec();
                        let state = entry.get_mut();

                        state.received_packets.insert(packet.bitmap_seq_num, data);
                        if state.user_bytes.is_none() {
                            state.user_bytes = Some(packet.user_bytes);
                        }
                        if packet.eom {
                            state.eom_seq = Some(packet.bitmap_seq_num);
                        }

                        // Check if complete
                        let mut is_complete = false;
                        if let Some(eom) = state.eom_seq {
                            // if we have all packets from 0 to eom
                            if (0..=eom).all(|i| state.received_packets.contains_key(&i)) {
                                is_complete = true;
                            }
                        } else if state.received_packets.len() == 8 {
                            // 8 packets received and no EOM
                            is_complete = true;
                        }

                        if is_complete {
                            let (_, mut state) = entry.remove_entry();
                            let mut full_data = Vec::new();
                            let expected_count = state.eom_seq.map(|e| e + 1).unwrap_or(8);
                            for i in 0..expected_count {
                                if let Some(p) = state.received_packets.remove(&i) {
                                    full_data.extend_from_slice(&p);
                                }
                            }
                            let user_bytes = state.user_bytes.unwrap_or([0; 4]);

                            let _ = state.chan.send(Ok((full_data, user_bytes)));

                            if state.xo {
                                // send release
                                let rel = AtpSendRelease {
                                    destination: AtpAddress {
                                        network_number: ddp.src_network_num,
                                        node_number: ddp.src_node_id,
                                        socket_number: ddp.src_sock_num,
                                    },
                                    tid: packet.tid,
                                };
                                self.handle_send_release(rel).await;
                            }
                        }
                    } else {
                        tracing::warn!("ATP Response payload too short");
                        // We do not remove the transaction here, just ignore the bad packet
                    }
                }
            }
            AtpFunction::Release => {
                let from = AtpAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                    socket_number: ddp.src_sock_num,
                };
                tracing::debug!(
                    "Received ATP Release packet from {:?} tid={}",
                    from,
                    packet.tid
                );

                if let Some(chan) = self.pending_releases.remove(&(from, packet.tid)) {
                    let _ = chan.send(());
                }
            }
        }
    }
}
