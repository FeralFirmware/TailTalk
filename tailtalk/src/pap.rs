use crate::atp::{AtpAddress, AtpRequestor, AtpResponder};
use anyhow::{Result, anyhow};
use tailtalk_packets::pap::{PapFunction, PapPacket};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, interval};

/// My LaserWriter seems to get very upset over LocalTalk if the individual ATP packets
/// are any larger than 512 bytes. Not quite sure why, but if kept to 512 this then allows
/// us to respond with 8 (i.e quantum size) ATP fragments per SendData request.
pub const PAP_MAX_DATA_PER_PACKET: usize = 512;

#[derive(Debug)]
pub struct PapClient {
    atp_requestor: AtpRequestor,
    atp_responder: AtpResponder,
    connection_id: u8,
    flow_quantum: u8,
    remote_addr: AtpAddress,
    /// The printer's connection socket from OpenConnReply — used for all post-connect traffic.
    server_addr: AtpAddress,
    /// Override the read buffer size per SendData cycle. When `None`, capacity is
    /// `bitmap_count × PAP_MAX_DATA_PER_PACKET` derived from the printer's per-request bitmap.
    pub chunk_size: Option<usize>,
}

impl PapClient {
    pub fn new(atp_requestor: AtpRequestor, atp_responder: AtpResponder) -> Self {
        Self {
            atp_requestor,
            atp_responder,
            connection_id: 0,
            flow_quantum: 8,
            remote_addr: AtpAddress {
                network_number: 0,
                node_number: 0,
                socket_number: 0,
            },
            server_addr: AtpAddress {
                network_number: 0,
                node_number: 0,
                socket_number: 0,
            },
            chunk_size: None,
        }
    }

    pub async fn connect(&mut self, address: AtpAddress) -> Result<()> {
        self.connect_with_timeout(address, Duration::from_secs(60)).await
    }

    /// Per PAP spec, retry every 2 seconds on a non-zero result code (server busy).
    pub async fn connect_with_timeout(&mut self, address: AtpAddress, timeout: Duration) -> Result<()> {
        self.remote_addr = address;

        let open_packet = PapPacket {
            connection_id: self.atp_requestor.socket_number,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: vec![self.atp_requestor.socket_number, 0x08, 0x00, 0x00],
        };
        let (user_bytes, data) = open_packet.to_atp_parts();
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            tracing::info!("PAP: Sending OpenConn to {:?}", address);
            let (resp_data, resp_user_bytes) = self
                .atp_requestor
                .send_request(address, user_bytes, data.to_vec())
                .await?;

            let reply = PapPacket::parse_from_atp(resp_user_bytes, &resp_data)?;

            if reply.function != PapFunction::OpenConnReply {
                return Err(anyhow!("Unexpected response function: {:?}", reply.function));
            }

            self.connection_id = reply.connection_id;

            if reply.data.len() < 4 {
                return Err(anyhow!("PAP OpenConnReply too short ({} bytes)", reply.data.len()));
            }

            let server_socket = reply.data[0];
            self.flow_quantum = reply.data[1];
            let result = ((reply.data[2] as u16) << 8) | (reply.data[3] as u16);

            if result != 0 {
                if tokio::time::Instant::now() >= deadline {
                    return Err(anyhow!("PAP OpenConn failed with result code: {} (server busy)", result));
                }
                tracing::info!("PAP: Server busy (result={}), retrying in 2s", result);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            self.server_addr = AtpAddress {
                network_number: address.network_number,
                node_number: address.node_number,
                socket_number: server_socket,
            };

            tracing::info!("PAP connected! ID={}, Quantum={}", self.connection_id, self.flow_quantum);
            return Ok(());
        }
    }

    pub async fn print(&mut self, data: &[u8]) -> Result<()> {
        self.print_stream(std::io::Cursor::new(data)).await
    }

    pub async fn print_stream<R: AsyncRead + Unpin>(&mut self, mut source: R) -> Result<()> {
        tracing::info!("PAP: Starting streaming print job");

        let mut last_activity = tokio::time::Instant::now();
        let mut tickle_interval = interval(Duration::from_secs(30));
        tickle_interval.tick().await; // skip the immediate first tick
        let mut eof_sent = false;

        loop {
            tokio::select! {
                maybe_req = self.atp_responder.next() => {
                    let Some(req) = maybe_req else {
                        return Err(anyhow!("ATP responder closed unexpectedly"));
                    };

                    let pap_req = PapPacket::parse_from_atp(req.user_bytes, &req.data)?;

                    if pap_req.connection_id != self.connection_id {
                        tracing::warn!("Ignored PAP packet with mismatched ID: {}", pap_req.connection_id);
                        continue;
                    }

                    last_activity = tokio::time::Instant::now();

                    match pap_req.function {
                        PapFunction::SendData => {
                            let seq_num = pap_req.sequence_num;

                            let max_packets = if req.bitmap == 0x00 { 8 } else { req.bitmap.count_ones() as usize }.clamp(1, 8);
                            let capacity = self.chunk_size.unwrap_or(max_packets * PAP_MAX_DATA_PER_PACKET);

                            let (n, buf) = if eof_sent {
                                // Each ATP SendData is an XO transaction; the printer's slot stays
                                // locked until it gets a response, so drain in-flight ones with EOF.
                                (0, vec![])
                            } else {
                                tracing::info!("PAP received SendData seq={}", seq_num);
                                let mut buf = vec![0u8; capacity];
                                let n = source.read(&mut buf).await?;
                                buf.truncate(n);
                                (n, buf)
                            };

                            let pap_resp = PapPacket {
                                connection_id: self.connection_id,
                                function: PapFunction::Data,
                                sequence_num: seq_num,
                                eof: n == 0,
                                data: buf,
                            };
                            let (user_bytes, chunk_data) = pap_resp.to_atp_parts();
                            req.send_response_chunked(chunk_data.to_vec(), user_bytes, PAP_MAX_DATA_PER_PACKET).await?;

                            if n == 0 && !eof_sent {
                                tracing::info!("PAP: EOF sent");
                                eof_sent = true;
                            }
                        }
                        PapFunction::Tickle => {
                            tracing::debug!("PAP: Received Tickle from printer");
                            if eof_sent {
                                return Ok(());
                            }
                        }
                        PapFunction::CloseConn => {
                            let reply = PapPacket {
                                connection_id: self.connection_id,
                                function: PapFunction::CloseConnReply,
                                sequence_num: 0,
                                eof: false,
                                data: vec![],
                            };
                            let (ub, d) = reply.to_atp_parts();
                            let _ = req.send_response(d.to_vec(), ub).await;
                            if eof_sent {
                                return Ok(());
                            }
                            return Err(anyhow!("Printer closed the connection before the job completed"));
                        }
                        _ => {}
                    }
                }

                _ = tickle_interval.tick() => {
                    if last_activity.elapsed() > Duration::from_secs(120) {
                        return Err(anyhow!("PAP session timed out after 120 seconds of inactivity"));
                    }
                    tracing::debug!("PAP: Sending Tickle to printer");
                    let tickle = PapPacket {
                        connection_id: self.connection_id,
                        function: PapFunction::Tickle,
                        sequence_num: 0,
                        eof: false,
                        data: vec![],
                    };
                    let (ub, _) = tickle.to_atp_parts();
                    let _ = self.atp_requestor.send_alo(self.server_addr, ub).await;
                }
            }
        }
    }

    /// Pull the printer's PS stdout by issuing SendData requests until the printer sends EOF.
    pub async fn read_response(&mut self) -> Result<Vec<u8>> {
        let mut response = Vec::new();
        let mut seq: u8 = 1;

        loop {
            let pkt = PapPacket {
                connection_id: self.connection_id,
                function: PapFunction::SendData,
                sequence_num: seq as u16,
                eof: false,
                data: vec![],
            };
            let (ub, d) = pkt.to_atp_parts();
            let (resp_data, resp_ub) = self.atp_requestor
                .send_request(self.server_addr, ub, d.to_vec())
                .await?;
            let data_pkt = PapPacket::parse_from_atp(resp_ub, &resp_data)?;

            if data_pkt.function != PapFunction::Data {
                return Err(anyhow!("Expected PAP Data response, got {:?}", data_pkt.function));
            }

            response.extend_from_slice(&data_pkt.data);

            if data_pkt.eof {
                break;
            }

            seq = seq.wrapping_add(1);
        }

        Ok(response)
    }

    pub async fn close(&mut self) -> Result<()> {
        let close_pkt = PapPacket {
            connection_id: self.connection_id,
            function: PapFunction::CloseConn,
            sequence_num: 0,
            eof: false,
            data: vec![],
        };
        let (ub, d) = close_pkt.to_atp_parts();
        // Must go to server_addr (per-connection socket), not remote_addr (NBP listening socket).
        self.atp_requestor
            .send_request(self.server_addr, ub, d.to_vec())
            .await?;
        Ok(())
    }

    pub async fn get_status(atp: AtpRequestor, address: AtpAddress) -> Result<String> {
        let pkt = PapPacket {
            connection_id: 0,
            function: PapFunction::SendStatus,
            sequence_num: 0,
            eof: false,
            data: vec![],
        };
        let (ub, d) = pkt.to_atp_parts();
        let (resp_data, resp_ub) = atp.send_request(address, ub, d.to_vec()).await?;

        let reply = PapPacket::parse_from_atp(resp_ub, &resp_data)?;

        if reply.data.len() > 4 {
            Ok(String::from_utf8_lossy(&reply.data[4..]).to_string())
        } else {
            Ok("".to_string())
        }
    }
}
