use crate::{
    addressing::AddressingHandle,
    ddp::{DdpHandle, DdpSocket},
    route_table::{NbpDispatch, NbpZone, RouteTable},
};
use std::collections::HashMap;
use std::io;
use std::time::Duration;
use tailtalk_packets::{
    aarp::AppleTalkAddress,
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
    et_addressing: Option<AddressingHandle>,
    lt_addressing: Option<AddressingHandle>,
    request_recv: mpsc::Receiver<NbpCommand>,
    pending_lookups: HashMap<u8, PendingLookup>,
    next_tid: u8,
    route_table: RouteTable,
}

impl Nbp {
    pub async fn spawn(
        ddp: &DdpHandle,
        et_addressing: Option<AddressingHandle>,
        lt_addressing: Option<AddressingHandle>,
        route_table: RouteTable,
    ) -> NbpHandle {
        let sock = ddp
            .new_sock(DdpProtocolType::Nbp, Some(2))
            .await
            .expect("failed to create NBP sock");

        let (request_send, request_recv) = mpsc::channel(100);

        let nbp = Nbp {
            sock,
            registered_names: Vec::new(),
            et_addressing,
            lt_addressing,
            request_recv,
            pending_lookups: HashMap::new(),
            next_tid: 1,
            route_table,
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

                                // Use the primary address (ET if available, else LT) in the lookup tuple.
                                let primary_addr = if let Some(et) = &self.et_addressing {
                                    et.addr().await.expect("failed to get ET addr")
                                } else {
                                    self.lt_addressing.as_ref().expect("no addressing").addr().await.expect("failed to get LT addr")
                                };

                                // Derive dispatch strategy from the zone in the entity name.
                                let dispatch = match lookup.request.zone.as_str() {
                                    "*" => self.route_table.nbp_dispatch(NbpZone::Local),
                                    "=" => self.route_table.nbp_dispatch(NbpZone::All),
                                    z   => self.route_table.nbp_dispatch(NbpZone::Named(z)),
                                };

                                let dest_addr = match dispatch {
                                    NbpDispatch::RouterBroadcast(_routers) => {
                                        // TODO: send BrRq to each router once implemented.
                                        // For now fall back to network-wide broadcast.
                                        tailtalk_packets::aarp::AppleTalkAddress { network_number: 0, node_number: 255 }
                                    }
                                    NbpDispatch::LocalBroadcast | NbpDispatch::ZoneUnknown => {
                                        tailtalk_packets::aarp::AppleTalkAddress { network_number: 0, node_number: 255 }
                                    }
                                };

                                let tuple = NbpTuple {
                                    network_number: primary_addr.network_number,
                                    node_id: primary_addr.node_number,
                                    socket_number: 2,
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

                                let dest = crate::ddp::DdpAddress::new(dest_addr, 2);

                                if let Err(e) = self.sock.send_to(&buf[..size], dest).await {
                                    tracing::error!("NBP LkUp: failed to send: {e}");
                                    let _ = lookup.chan.send(Err(io::Error::other(
                                        "failed to send NBP lookup",
                                    )));
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
                let response = self.generate_response(&packet, ddp.src_network_num, ddp.src_node_id).await;

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

    async fn generate_response(&self, nbp: &NbpPacket, source_network: u16, source_node: u8) -> NbpPacket {
        // Respond with the address on the same interface the lookup arrived from.
        let our_addr = if source_network == 0 {
            // Network 0 is ambiguous between LocalTalk and nonextended
            // EtherTalk (Phase 1). With only one interface configured, it
            // must be that one. With both, check whether the requester has
            // been learned as an EtherTalk Phase 1 peer before assuming
            // LocalTalk.
            match (&self.lt_addressing, &self.et_addressing) {
                (Some(lt), None) => lt.addr().await.expect("failed to get LT addr"),
                (None, Some(et)) => et.addr().await.expect("failed to get ET addr"),
                (Some(lt), Some(et)) => {
                    let peer = AppleTalkAddress { network_number: 0, node_number: source_node };
                    if et.try_lookup(&peer).is_some() {
                        et.addr().await.expect("failed to get ET addr")
                    } else {
                        lt.addr().await.expect("failed to get LT addr")
                    }
                }
                (None, None) => panic!("no addressing configured"),
            }
        } else if let Some(et) = &self.et_addressing {
            et.addr().await.expect("failed to get ET addr")
        } else {
            self.lt_addressing.as_ref().expect("no addressing").addr().await.expect("failed to get LT addr")
        };

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

    /// Look up several entity names at once. Returns one result vector per
    /// request, in request order.
    ///
    /// All lookups run as concurrent NBP transactions (each with its own
    /// transaction ID), so N names share a single reply-collection window
    /// instead of waiting out one window per name.
    ///
    /// This is deliberately *not* a single multi-tuple LkUp packet: the NBP
    /// header's 4-bit tuple count would allow one, and our own responder
    /// even answers such packets, but Inside AppleTalk specifies that a
    /// LkUp request carries exactly one tuple — real devices only match
    /// against the first and would silently drop the rest of the query.
    pub async fn lookup_many(
        &self,
        requests: impl IntoIterator<Item = EntityName>,
    ) -> Result<Vec<Vec<NbpTuple>>, io::Error> {
        // Fire every request before awaiting any reply so their collection
        // windows overlap.
        let mut pending = Vec::new();
        for request in requests {
            let (tx, rx) = oneshot::channel();
            self.request_send
                .send(NbpCommand::Lookup(NbpLookupRequest { request, chan: tx }))
                .await
                .map_err(io::Error::other)?;
            pending.push(rx);
        }

        let mut results = Vec::with_capacity(pending.len());
        for rx in pending {
            results.push(rx.await.map_err(io::Error::other)??);
        }
        Ok(results)
    }
}
