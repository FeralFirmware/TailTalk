use crate::atp::{AtpAddress, AtpRequestor, AtpResponder, AtpResponse};
use anyhow::{Result, anyhow};
use tailtalk_packets::pap::{PapFunction, PapPacket};

#[derive(Debug)]
pub struct PapClient {
    atp_requestor: AtpRequestor,
    atp_responder: AtpResponder,
    connection_id: u8,
    flow_quantum: u8,
    remote_addr: AtpAddress,
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
        }
    }

    /// Open a PAP connection to the specified address
    pub async fn connect(&mut self, address: AtpAddress) -> Result<()> {
        self.remote_addr = address;

        // Send OpenConn request
        let open_packet = PapPacket {
            connection_id: self.atp_requestor.socket_number,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            // OpenConn data: [Socket(1), FlowQuantum(1), WaitTime(2)]
            // We request flow quantum of 8.
            data: vec![self.atp_requestor.socket_number, 0x08, 0x00, 0x00],
        };

        let (user_bytes, data) = open_packet.to_atp_parts();

        tracing::info!("PAP: Sending OpenConn to {:?}", address);
        let (resp_data, resp_user_bytes) = self
            .atp_requestor
            .send_request(address, user_bytes, data.to_vec())
            .await?;

        // Parse response
        let reply = PapPacket::parse_from_atp(resp_user_bytes, &resp_data)?;

        if reply.function != PapFunction::OpenConnReply {
            return Err(anyhow!(
                "Unexpected response function: {:?}",
                reply.function
            ));
        }

        self.connection_id = reply.connection_id;

        if reply.data.len() >= 4 {
            let _server_socket = reply.data[0];
            self.flow_quantum = reply.data[1];
            let result = ((reply.data[2] as u16) << 8) | (reply.data[3] as u16);
            if result != 0 {
                return Err(anyhow!("PAP OpenConn failed with result code: {}", result));
            }
        }

        tracing::info!(
            "PAP connected! ID={}, Quantum={}",
            self.connection_id,
            self.flow_quantum
        );

        Ok(())
    }

    /// Send data (print job) to the connected printer
    pub async fn print(&mut self, data: &[u8]) -> Result<()> {
        let mut data_offset = 0;
        let total_len = data.len();

        tracing::info!("PAP: Starting print job, {} bytes", total_len);

        // Loop handles incoming SendData requests from the printer
        while data_offset < total_len {
            // Wait for SendData request from printer
            // We expect the printer to initiate ATP transactions.
            if let Some(req) = self.atp_responder.next().await {
                let pap_req = PapPacket::parse_from_atp(req.user_bytes, &req.data)?;

                if pap_req.connection_id != self.connection_id {
                    tracing::warn!(
                        "Ignored PAP packet with mismatched ID: {}",
                        pap_req.connection_id
                    );
                    continue;
                }

                if pap_req.function == PapFunction::SendData {
                    // Printer wants data.
                    let seq_num = pap_req.sequence_num;
                    tracing::debug!(
                        "PAP received SendData seq={} offset={}",
                        seq_num,
                        data_offset
                    );

                    let mut response_packets = Vec::new();

                    for i in 0..self.flow_quantum {
                        if data_offset >= total_len {
                            break;
                        }

                        let chunk_size = std::cmp::min(512, total_len - data_offset);
                        let chunk = &data[data_offset..data_offset + chunk_size];

                        let pap_resp = PapPacket {
                            connection_id: self.connection_id,
                            function: PapFunction::Data,
                            sequence_num: seq_num + i as u16,
                            data: chunk.to_vec(),
                        };

                        let (user_bytes, chunk_data) = pap_resp.to_atp_parts();

                        response_packets.push(AtpResponse {
                            user_bytes,
                            data: chunk_data.to_vec(),
                        });

                        data_offset += chunk_size;
                    }

                    // Concatenate all response packets into single data buffer
                    // PAP uses multiple ATP packets, so we need to preserve the packet boundaries
                    // by concatenating the PAP packet data (which includes PAP headers)
                    let mut combined_data = Vec::new();
                    let mut first_user_bytes = [0u8; 4];

                    for (i, pkt) in response_packets.iter().enumerate() {
                        if i == 0 {
                            first_user_bytes = pkt.user_bytes;
                        }
                        combined_data.extend_from_slice(&pkt.data);
                    }

                    req.send_response(combined_data, first_user_bytes).await?;

                    // Wait for Release if available (XO mode)
                    if let Some(rx) = req.release_rx {
                        tracing::debug!("PAP: Waiting for ATP Release packet");
                        let _ = rx.await;
                        tracing::debug!("PAP: Received ATP Release");
                    }
                } else if pap_req.function == PapFunction::CloseConn {
                    tracing::info!("PAP: Printer closed connection");
                    return Ok(());
                }
            } else {
                return Err(anyhow!("ATP responder closed unexpectedly"));
            }
        }

        // Wait for next SendData to send empty EOF
        if let Some(req) = self.atp_responder.next().await {
            let pap_req = PapPacket::parse_from_atp(req.user_bytes, &req.data)?;
            if pap_req.function == PapFunction::SendData {
                let pap_resp = PapPacket {
                    connection_id: self.connection_id,
                    function: PapFunction::Data,
                    sequence_num: pap_req.sequence_num,
                    data: vec![], // Empty
                };
                let (user_bytes, chunk_data) = pap_resp.to_atp_parts();
                req.send_response(chunk_data.to_vec(), user_bytes).await?;
            }
        }

        tracing::info!("PAP: Print job finished, closing connection");
        self.close().await?;

        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        let close_pkt = PapPacket {
            connection_id: self.connection_id,
            function: PapFunction::CloseConn,
            sequence_num: 0,
            data: vec![],
        };
        let (ub, d) = close_pkt.to_atp_parts();
        self.atp_requestor
            .send_request(self.remote_addr, ub, d.to_vec())
            .await?;
        Ok(())
    }

    pub async fn get_status(atp: AtpRequestor, address: AtpAddress) -> Result<String> {
        let pkt = PapPacket {
            connection_id: 0,
            function: PapFunction::SendStatus,
            sequence_num: 0,
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
