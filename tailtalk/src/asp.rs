use crate::atp::Atp;
use crate::ddp::DdpHandle;
use crate::nbp::{NbpHandle, RegisteredName};
use anyhow::Result;
use tailtalk_packets::asp::{AspHeader, SPFunction};
use tailtalk_packets::nbp::EntityName;

use tokio::task;
use tokio::time::{Duration, interval};

pub struct Asp;

use tokio::sync::{mpsc, oneshot};

/// Represents an incoming ASP command from a client
#[derive(Debug)]
pub struct AspCommand {
    /// The sequence number of the command that initiated this transaction
    pub sequence_number: u16,
    /// The source address of the client that sent this command
    pub client_address: crate::atp::AtpAddress,
    /// The command data payload
    pub data: Vec<u8>,
    /// Channel to send the reply back to the client
    reply_tx: oneshot::Sender<AspCommandResponse>,
}

#[derive(Debug)]
pub struct AspCommandResponse {
    /// CmdResult code transported in the ATP user bytes
    pub result: [u8; 4],
    /// Optional response payload
    pub data: Vec<u8>,
}

impl AspCommand {
    /// Send a reply to this command
    pub fn send_reply(self, reply_data: AspCommandResponse) -> Result<()> {
        self.reply_tx
            .send(reply_data)
            .map_err(|_| anyhow::anyhow!("Failed to send reply"))
    }
}

#[derive(Debug, Clone)]
pub struct AspHandle {
    accept_tx: mpsc::Sender<oneshot::Sender<AspSession>>,
}

impl AspHandle {
    /// Wait for the next incoming session.
    pub async fn get_session(&self) -> Result<AspSession> {
        let (tx, rx) = oneshot::channel();
        self.accept_tx
            .send(tx)
            .await
            .map_err(|_| anyhow::anyhow!("ASP task is dead"))?;

        let session = rx.await?;
        Ok(session)
    }
}

// Session state: SessionID -> AspSession (Internal State tracking)
struct AspState {
    addr: crate::atp::AtpAddress,
    #[allow(dead_code)]
    match_addr_only: bool, // For future strict checking
    // Channel to send commands to the session owner
    command_tx: mpsc::Sender<AspCommand>,
}

// Public handle for a connected session (returned to user)
#[derive(Debug)]
pub struct AspSession {
    pub id: u8,
    pub remote_addr: crate::atp::AtpAddress,
    command_rx: mpsc::Receiver<AspCommand>,
    atp_req: crate::atp::AtpRequestor,
}

impl AspSession {
    /// Wait for the next incoming command on this session
    pub async fn get_command(&mut self) -> Option<AspCommand> {
        let cmd = self.command_rx.recv().await?;

        // Update our remote_addr in case the client changed its socket after OpenSess
        if self.remote_addr != cmd.client_address {
            tracing::info!(
                "ASP Session {} remote address updated from {:?} to {:?}",
                self.id,
                self.remote_addr,
                cmd.client_address
            );
            self.remote_addr = cmd.client_address;
        }

        Some(cmd)
    }

    /// Perform a Write transaction to read data from the client
    pub async fn write(&mut self, req_count: usize, sequence_number: u16) -> Result<Vec<u8>> {
        // SPWrite Logic:
        // Server sends ATP Request with SPWrite/WriteContinue function and available buffer size.
        // Client responds with the data.
        // If we limit the size to a chunk (like 1024 or 4624), we should NOT loop.
        // We just do one transaction, return the data, and let the AFP layer reply with the
        // actual bytes written. The client will issue a new FPWrite for the rest.

        let chunk_size = req_count.min(1024);
        let quantum = chunk_size as u16;

        let header = AspHeader {
            function: SPFunction::WriteContinue,
            session_id: self.id,
            sequence_number, // The sequence number of the original FPWrite command
        };

        let mut user_bytes = [0u8; 4];
        header
            .to_bytes(&mut user_bytes)
            .map_err(|e| anyhow::anyhow!("ASP header error: {:?}", e))?;

        // Data payload for SPWrite/WriteContinue request:
        let mut data = Vec::with_capacity(2);
        data.extend_from_slice(&quantum.to_be_bytes());

        tracing::info!(
            "ASP Session {} initiating WriteContinue, quantum={}",
            self.id,
            quantum
        );

        // Send ATP Request
        let (response_data, _response_user_bytes) = self
            .atp_req
            .send_request(self.remote_addr, user_bytes, data)
            .await?;

        Ok(response_data)
    }
}

impl Asp {
    pub async fn bind(
        ddp: &DdpHandle,
        nbp: &NbpHandle,
        socket_number: Option<u8>,
        entity_name: EntityName,
        status_data: Vec<u8>,
    ) -> Result<AspHandle> {
        let (actual_socket, atp_req, mut atp_resp) = Atp::spawn(ddp, socket_number).await;

        nbp.register(RegisteredName {
            name: entity_name,
            sock_num: actual_socket,
        })
        .await?;

        // Internal session state map
        let mut sessions: std::collections::HashMap<u8, AspState> =
            std::collections::HashMap::new();
        let mut next_session_id: u8 = 1;

        // Channel for user to accept sessions
        let (accept_tx, mut accept_rx) = mpsc::channel::<oneshot::Sender<AspSession>>(10);

        let atp_req_clone = atp_req.clone();

        task::spawn(async move {
            let mut tickle_interval = interval(Duration::from_secs(30));
            // The first tick fires immediately; skip it so we don't tickle on startup.
            tickle_interval.tick().await;

            loop {
                tokio::select! {
                    // ── Incoming ATP request ─────────────────────────────────────
                    maybe_req = atp_resp.next() => {
                        let Some(req) = maybe_req else { break };
                // Parse user bytes for ASP header / command
                // User bytes are [Function, SessionID, SequenceNumHi, SequenceNumLo]

                if let Ok(header) = AspHeader::parse(&req.user_bytes) {
                    match header.function {
                        SPFunction::GetStatus => {
                            tracing::info!("ASP responding to GetStatus request");
                            // ASP response user bytes should be:
                            // [ResultCode, SessionID, SequenceHi, SequenceLo]
                            let response_user_bytes = [
                                0, // Result code 0 = success
                                header.session_id,
                                (header.sequence_number >> 8) as u8,
                                (header.sequence_number & 0xFF) as u8,
                            ];

                            let _ = req
                                .send_response(status_data.clone(), response_user_bytes)
                                .await;
                        }
                        SPFunction::OpenSess => {
                            // Only accept if there is a pending acceptor
                            if let Ok(acceptor) = accept_rx.try_recv() {
                                let session_id = next_session_id;
                                // wrap around skipping 0
                                next_session_id = if next_session_id == 255 {
                                    1
                                } else {
                                    next_session_id + 1
                                };

                                tracing::info!(
                                    "ASP Opening Session {} for client {:?}",
                                    session_id,
                                    req.source
                                );

                                // Create command channel for this session
                                let (command_tx, command_rx) = mpsc::channel::<AspCommand>(10);

                                sessions.insert(
                                    session_id,
                                    AspState {
                                        addr: req.source,
                                        match_addr_only: true,
                                        command_tx,
                                    },
                                );

                                // Notify user
                                let _ = acceptor.send(AspSession {
                                    id: session_id,
                                    remote_addr: req.source,
                                    command_rx,
                                    atp_req: atp_req_clone.clone(),
                                });

                                // Respond Success
                                let response_user_bytes = [
                                    actual_socket, // Socket number for the remote side to talk to this new session on
                                    session_id,    // New Session ID
                                    0,
                                    0,
                                ];

                                let _ = req.send_response(vec![], response_user_bytes).await;
                            } else {
                                tracing::warn!(
                                    "ASP ServerBusy: No pending accept for OpenSess from {:?}",
                                    req.source
                                );
                                // Respond with ServerBusy error (-1071 => 0xFBD1)
                                let err = tailtalk_packets::asp::ASP_SERVER_BUSY;
                                let _err_bytes = err.to_be_bytes();

                                let response_user_bytes = err.to_be_bytes();

                                let _ = req.send_response(vec![], response_user_bytes).await;
                            }
                        }
                        SPFunction::CloseSess => {
                            let session_id = header.session_id;
                            if let Some(sess) = sessions.get(&session_id) {
                                // Only allow closing from the owner address
                                if sess.addr == req.source {
                                    tracing::info!("ASP Closing Session {}", session_id);
                                    sessions.remove(&session_id);

                                    // Respond Success
                                    let response_user_bytes = [0, session_id, 0, 0];
                                    let _ = req.send_response(vec![], response_user_bytes).await;
                                } else {
                                    tracing::warn!(
                                        "ASP CloseSess mismatch: Session {} owned by {:?}, req from {:?}",
                                        session_id,
                                        sess.addr,
                                        req.source
                                    );
                                }
                            } else {
                                tracing::warn!("ASP CloseSess: Session {} not found", session_id);
                                // Respond Success anyway to clear client state
                                let response_user_bytes = [0, session_id, 0, 0];
                                let _ = req.send_response(vec![], response_user_bytes).await;
                            }
                        }
                        SPFunction::Command | SPFunction::Write => {
                            let session_id = header.session_id;
                            if let Some(sess) = sessions.get_mut(&session_id) {
                                // Verify command is from the session owner (only check net+node, ignore socket)
                                if sess.addr.network_number == req.source.network_number
                                    && sess.addr.node_number == req.source.node_number
                                {
                                    tracing::debug!(
                                        "ASP Command/Write received for session {}, {} bytes",
                                        session_id,
                                        req.data.len()
                                    );

                                    // Update session address if the socket changed (Macs may open on port X and send commands from port Y)
                                    if sess.addr != req.source {
                                        tracing::debug!(
                                            "ASP Session {} updating address from {:?} to {:?}",
                                            session_id,
                                            sess.addr,
                                            req.source
                                        );
                                        sess.addr = req.source;
                                    }

                                    // Create reply channel
                                    let (reply_tx, reply_rx) = oneshot::channel();

                                    // Send command to session owner
                                    let command = AspCommand {
                                        sequence_number: header.sequence_number,
                                        client_address: req.source,
                                        data: req.data.clone(),
                                        reply_tx,
                                    };

                                    if sess.command_tx.send(command).await.is_ok() {
                                        // Wait for reply from application
                                        if let Ok(reply_data) = reply_rx.await {
                                            let _ = req
                                                .send_response(reply_data.data, reply_data.result)
                                                .await;
                                        } else {
                                            tracing::warn!(
                                                "ASP Command for session {}: application dropped reply channel",
                                                session_id
                                            );
                                        }
                                    } else {
                                        tracing::warn!(
                                            "ASP Command for session {}: session channel closed",
                                            session_id
                                        );
                                    }
                                } else {
                                    tracing::warn!(
                                        "ASP Command mismatch: Session {} owned by {}.{}, req from {}.{}",
                                        session_id,
                                        sess.addr.network_number,
                                        sess.addr.node_number,
                                        req.source.network_number,
                                        req.source.node_number
                                    );
                                }
                            } else {
                                tracing::warn!("ASP Command: Session {} not found", session_id);
                            }
                        }
                        SPFunction::Tickle => {
                            let session_id = header.session_id;
                            if let Some(sess) = sessions.get(&session_id) {
                                // Verify tickle is from the session owner (only check net+node, ignore socket)
                                if sess.addr.network_number == req.source.network_number
                                    && sess.addr.node_number == req.source.node_number
                                {
                                    tracing::debug!(
                                        "ASP Tickle received for session {}",
                                        session_id
                                    );

                                    // Respond with success to acknowledge the tickle
                                    let response_user_bytes = [0, session_id, 0, 0];
                                    let _ = req.send_response(vec![], response_user_bytes).await;
                                } else {
                                    tracing::warn!(
                                        "ASP Tickle mismatch: Session {} owned by {}.{}, req from {}.{}",
                                        session_id,
                                        sess.addr.network_number,
                                        sess.addr.node_number,
                                        req.source.network_number,
                                        req.source.node_number
                                    );
                                }
                            } else {
                                tracing::warn!("ASP Tickle: Session {} not found", session_id);
                            }
                        }
                        _ => {
                            tracing::debug!("ASP Unimplemented function: {:?}", header.function);
                        }
                    }
                }
                    } // end maybe_req arm

                    // ── 30-second tickle timer (temporarily disabled) ────────────
                    _ = tickle_interval.tick() => {
                        // TODO: re-enable tickles once session stability is confirmed
                        // for (session_id, sess) in &sessions {
                        //     tracing::debug!("ASP sending Tickle to session {}", session_id);
                        //     let user_bytes = [
                        //         SPFunction::Tickle as u8,
                        //         *session_id,
                        //         0,
                        //         0,
                        //     ];
                        //     let req_clone = atp_req_clone.clone();
                        //     let addr = sess.addr;
                        //     tokio::spawn(async move {
                        //         let _ = req_clone.send_request(addr, user_bytes, vec![]).await;
                        //     });
                        // }
                    }
                } // end select!
            } // end loop
        });

        Ok(AspHandle { accept_tx })
    }
}
