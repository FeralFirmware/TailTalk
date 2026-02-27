use crate::{
    addressing::AddressingHandle,
    ddp::{DdpHandle, DdpSocket},
};
use std::collections::HashMap;
use std::io;
use std::time::Duration;
use tailtalk_packets::{
    ddp::{DdpPacket, DdpProtocolType},
    nbp::{EntityName, NbpOperation, NbpPacket, NbpTuple},
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

struct NbpRegisterRequest {
    request: RegisteredName,
    chan: oneshot::Sender<Result<(), io::Error>>,
}

struct NbpLookupRequest {
    request: EntityName,
    chan: oneshot::Sender<Result<Vec<NbpTuple>, io::Error>>,
}

enum NbpCommand {
    Register(NbpRegisterRequest),
    Lookup(NbpLookupRequest),
}

#[derive(PartialEq, Eq)]
pub struct RegisteredName {
    pub name: EntityName,
    pub sock_num: u8,
}

struct PendingLookup {
    chan: oneshot::Sender<Result<Vec<NbpTuple>, io::Error>>,
    start_time: Instant,
    results: Vec<NbpTuple>,
}

pub struct Nbp {
    sock: DdpSocket,
    registered_names: Vec<RegisteredName>,
    addressing: AddressingHandle,
    request_recv: mpsc::Receiver<NbpCommand>,
    pending_lookups: HashMap<u8, PendingLookup>,
    next_tid: u8,
}

impl Nbp {
    pub async fn spawn(ddp: &DdpHandle, addressing: AddressingHandle) -> NbpHandle {
        let sock = ddp
            .new_sock(DdpProtocolType::Nbp, Some(2))
            .await
            .expect("failed to create NBP sock");

        let (request_send, request_recv) = mpsc::channel(100);

        let nbp = Nbp {
            sock,
            registered_names: Vec::new(),
            addressing,
            request_recv,
            pending_lookups: HashMap::new(),
            next_tid: 1,
        };

        tokio::spawn(async move { nbp.run().await });

        NbpHandle { request_send }
    }

    async fn run(mut self) {
        let mut timeout_check = tokio::time::interval(Duration::from_millis(500));
        timeout_check.tick().await; // First tick completes immediately

        loop {
            tokio::select! {
                _ = timeout_check.tick() => {
                    self.check_timeouts();
                },
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => {
                            self.handle_packet(pkt.headers, &mut pkt.payload).await;
                        },
                        Err(_e) => {

                        },
                    }
                },
                req = self.request_recv.recv() => {
                    if let Some(command) = req {
                        match command {
                            NbpCommand::Register(register) => {
                                self.handle_register_req(register);
                            },
                            NbpCommand::Lookup(lookup) => {
                                let tid = self.next_tid;
                                self.next_tid = self.next_tid.wrapping_add(1);

                                let our_addr = self.addressing.addr()
                                    .await
                                    .expect("failed to get our addr");

                                let tuple = NbpTuple {
                                    network_number: our_addr.network_number,
                                    node_id: our_addr.node_number,
                                    socket_number: 2, // Default NBP socket
                                    enumerator: 0,
                                    entity_name: lookup.request,
                                };

                                let packet = NbpPacket {
                                    operation: NbpOperation::Lookup,
                                    transaction_id: tid,
                                    tuples: vec![tuple],
                                };

                                let mut buf = [0u8; 1024];
                                let size = packet.to_bytes(&mut buf).expect("failed to serialize");
                                // Send to broadcast
                                let dest = crate::ddp::DdpAddress::new(
                                    tailtalk_packets::aarp::AppleTalkAddress {
                                        network_number: 0,
                                        node_number: 255,
                                    },
                                    2 // NBP socket
                                );

                                if let Err(e) = self.sock.send_to(&buf[..size], dest).await {
                                    let _ = lookup.chan.send(Err(e));
                                } else {
                                    self.pending_lookups.insert(tid, PendingLookup {
                                        chan: lookup.chan,
                                        start_time: Instant::now(),
                                        results: Vec::new(),
                                    });
                                }
                            },
                        }
                    } else {
                        break;
                    }
                },
            }
        }
    }

    fn check_timeouts(&mut self) {
        const TIMEOUT_DURATION: Duration = Duration::from_secs(3);
        let now = Instant::now();

        // Collect expired transaction IDs
        let expired: Vec<u8> = self
            .pending_lookups
            .iter()
            .filter(|(_, pending)| now.duration_since(pending.start_time) > TIMEOUT_DURATION)
            .map(|(tid, _)| *tid)
            .collect();

        // Send results and remove from pending
        for tid in expired {
            if let Some(pending) = self.pending_lookups.remove(&tid) {
                let _ = pending.chan.send(Ok(pending.results));
            }
        }
    }

    fn handle_register_req(&mut self, req: NbpRegisterRequest) {
        if !req.request.name.fully_qualified() {
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid entity name requested",
            )));

            return;
        }

        if self.registered_names.iter().any(|n| n == &req.request) {
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "entity name and sock num already registered",
            )));

            return;
        }

        let _ = req.chan.send(Ok(()));
        tracing::info!(
            "registered NBP: {} sock num {}",
            req.request.name,
            req.request.sock_num
        );
        self.registered_names.push(req.request);
    }

    async fn handle_packet(&mut self, ddp: DdpPacket, payload: &mut [u8]) {
        let packet = match NbpPacket::from_bytes(payload) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::warn!("Failed to parse NBP packet: {:?}", e);
                return;
            }
        };

        match packet.operation {
            NbpOperation::Lookup => {
                let response = self.generate_response(&packet).await;

                // Only send a reply if we have at least one matching tuple
                if !response.tuples.is_empty() {
                    let mut buf = [0u8; 1024];
                    let size = response
                        .to_bytes(&mut buf)
                        .expect("failed to serialize NBP response");

                    let dest = crate::ddp::DdpAddress::new(
                        tailtalk_packets::aarp::AppleTalkAddress {
                            network_number: ddp.src_network_num,
                            node_number: ddp.src_node_id,
                        },
                        ddp.src_sock_num,
                    );

                    if let Err(e) = self.sock.send_to(&buf[..size], dest).await {
                        tracing::error!("failed to send NBP response: {e}");
                    } else {
                        tracing::debug!(
                            "Sent NBP LookupReply with {} tuples to {}.{}",
                            response.tuples.len(),
                            ddp.src_network_num,
                            ddp.src_node_id
                        );
                    }
                } else {
                    tracing::debug!(
                        "No matches for NBP lookup from {}.{}, not sending response",
                        ddp.src_network_num,
                        ddp.src_node_id
                    );
                }
            }
            NbpOperation::LookupReply => {
                if let Some(pending) = self.pending_lookups.get_mut(&packet.transaction_id) {
                    tracing::debug!(
                        "Received NBP LookupReply with {} match(es) for tid {}",
                        packet.tuples.len(),
                        packet.transaction_id
                    );
                    pending.results.extend(packet.tuples);
                }
            }
            _ => {}
        }
    }

    async fn generate_response(&self, nbp: &NbpPacket) -> NbpPacket {
        let our_addr = self
            .addressing
            .addr()
            .await
            .expect("failed to get our addr");

        let mut tuples = Vec::new();

        for req_tuple in &nbp.tuples {
            for name in &self.registered_names {
                if name.name.matches(&req_tuple.entity_name) {
                    tuples.push(NbpTuple {
                        network_number: our_addr.network_number,
                        node_id: our_addr.node_number,
                        socket_number: name.sock_num,
                        enumerator: 0,
                        entity_name: EntityName {
                            object: name.name.object.clone(),
                            entity_type: name.name.entity_type.clone(),
                            zone: "*".into(),
                        },
                    });
                }
            }
        }

        NbpPacket {
            operation: NbpOperation::LookupReply,
            transaction_id: nbp.transaction_id,
            tuples,
        }
    }
}

#[derive(Clone)]
pub struct NbpHandle {
    request_send: mpsc::Sender<NbpCommand>,
}

impl NbpHandle {
    pub async fn register(&self, request: RegisteredName) -> Result<(), io::Error> {
        let (tx, rx) = oneshot::channel();

        let request = NbpCommand::Register(NbpRegisterRequest { request, chan: tx });

        self.request_send
            .send(request)
            .await
            .map_err(io::Error::other)?;

        rx.await.map_err(io::Error::other)?
    }

    pub async fn lookup(&self, request: EntityName) -> Result<Vec<NbpTuple>, io::Error> {
        let (tx, rx) = oneshot::channel();

        let request = NbpCommand::Lookup(NbpLookupRequest { request, chan: tx });

        self.request_send
            .send(request)
            .await
            .map_err(io::Error::other)?;

        rx.await.map_err(io::Error::other)?
    }
}
