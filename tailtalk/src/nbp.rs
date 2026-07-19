use crate::{
    addressing::AddressingHandle,
    ddp::{DdpHandle, DdpSocket},
    route_table::{Interface, NbpDispatch, NbpZone, RouteTable},
};
use std::collections::HashMap;
use std::io;
use std::time::Duration;
use tailtalk_packets::{
    aarp::{AddressSource, AppleTalkAddress},
    ddp::{DdpPacket, DdpProtocolType},
    nbp::{EntityName, NbpOperation, NbpPacket, NbpTuple},
};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

struct NbpRegisterRequest {
    request: RegisteredName,
    chan: oneshot::Sender<Result<(), io::Error>>,
}

struct NbpUnregisterRequest {
    request: RegisteredName,
    chan: oneshot::Sender<Result<(), io::Error>>,
}

struct NbpLookupRequest {
    request: EntityName,
    chan: oneshot::Sender<Result<Vec<NbpTuple>, io::Error>>,
}

enum NbpCommand {
    Register(NbpRegisterRequest),
    Unregister(NbpUnregisterRequest),
    Lookup(NbpLookupRequest),
}

#[derive(Clone, PartialEq, Eq)]
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
                            self.handle_packet(pkt.headers, &mut pkt.payload, pkt.source).await;
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
                            NbpCommand::Unregister(unregister) => {
                                self.handle_unregister_req(unregister);
                            },
                            NbpCommand::Lookup(lookup) => {
                                let tid = self.next_tid;
                                self.next_tid = self.next_tid.wrapping_add(1);

                                // Derive dispatch strategy from the zone in the entity name.
                                // "*" is the local zone, not just the local cable: with a
                                // router present it needs a BrRq to the router (which forwards
                                // the lookup onto other cables, like the far side of a bridge),
                                // falling back to a local broadcast only when there is none.
                                // That is exactly the "=" (all zones) dispatch; the two differ
                                // only in the zone carried in the request, which stays intact.
                                let dispatch = match lookup.request.zone.as_str() {
                                    "*" | "=" => self.route_table.nbp_dispatch(NbpZone::All),
                                    z => self.route_table.nbp_dispatch(NbpZone::Named(z)),
                                };

                                // The reply address we advertise in the tuple: when
                                // asking a router, use our address on that router's
                                // cable so replies forwarded from other networks can
                                // route back; otherwise the primary address.
                                let reply_iface = match &dispatch {
                                    NbpDispatch::RouterBroadcast(routers) => routers
                                        .first()
                                        .and_then(|r| self.route_table.interface_for_net(r.network_number)),
                                    _ => None,
                                };
                                let our_addr = self.addr_on(reply_iface).await;

                                let tuple = NbpTuple {
                                    network_number: our_addr.network_number,
                                    node_id: our_addr.node_number,
                                    socket_number: 2,
                                    enumerator: 0,
                                    entity_name: lookup.request,
                                };

                                let mut buf = [0u8; 1024];
                                let send_result = match dispatch {
                                    NbpDispatch::RouterBroadcast(routers) => {
                                        // A router is known (via RTMP): send BrRq directly
                                        // to it rather than broadcasting locally. Any single
                                        // router ("A-ROUTER") handles the whole request, so
                                        // stop at the first successful send — asking several
                                        // would only duplicate every reply.
                                        let packet = NbpPacket {
                                            operation: NbpOperation::BroadcastRequest,
                                            transaction_id: tid,
                                            tuples: vec![tuple],
                                        };
                                        let size = packet.to_bytes(&mut buf).expect("failed to serialize");

                                        let mut result = Err(io::Error::other("no routers to send BrRq to"));
                                        for router in routers {
                                            let dest = crate::ddp::DdpAddress::new(router, 2);
                                            match self.sock.send_to(&buf[..size], dest).await {
                                                Ok(()) => {
                                                    result = Ok(());
                                                    break;
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "NBP BrRq: failed to send to {}.{}: {e}",
                                                        router.network_number, router.node_number,
                                                    );
                                                    result = Err(e);
                                                }
                                            }
                                        }
                                        result
                                    }
                                    NbpDispatch::LocalBroadcast | NbpDispatch::ZoneUnknown => {
                                        let packet = NbpPacket {
                                            operation: NbpOperation::Lookup,
                                            transaction_id: tid,
                                            tuples: vec![tuple],
                                        };
                                        let size = packet.to_bytes(&mut buf).expect("failed to serialize");

                                        let dest_addr = tailtalk_packets::aarp::AppleTalkAddress { network_number: 0, node_number: 255 };
                                        let dest = crate::ddp::DdpAddress::new(dest_addr, 2);
                                        self.sock.send_to(&buf[..size], dest).await
                                    }
                                };

                                if let Err(e) = send_result {
                                    tracing::error!("NBP lookup: failed to send: {e}");
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

    fn handle_unregister_req(&mut self, req: NbpUnregisterRequest) {
        let before = self.registered_names.len();
        self.registered_names.retain(|n| n != &req.request);
        if self.registered_names.len() < before {
            tracing::info!(
                "unregistered NBP: {} sock num {}",
                req.request.name,
                req.request.sock_num
            );
            let _ = req.chan.send(Ok(()));
        } else {
            let _ = req.chan.send(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "entity name and sock num not registered",
            )));
        }
    }

    /// Our address on the given interface, falling back to the primary
    /// address (ET if available, else LT) when unspecified or unconfigured.
    async fn addr_on(&self, iface: Option<Interface>) -> AppleTalkAddress {
        let handle = match iface {
            Some(Interface::LocalTalk) if self.lt_addressing.is_some() => {
                self.lt_addressing.as_ref()
            }
            Some(Interface::EtherTalk) if self.et_addressing.is_some() => {
                self.et_addressing.as_ref()
            }
            _ => self.et_addressing.as_ref().or(self.lt_addressing.as_ref()),
        };
        handle
            .expect("no addressing configured")
            .addr()
            .await
            .expect("failed to get interface address")
    }

    async fn handle_packet(
        &mut self,
        ddp: DdpPacket,
        payload: &mut [u8],
        source: AddressSource,
    ) {
        let packet = match NbpPacket::from_bytes(payload) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::warn!("Failed to parse NBP packet: {:?}", e);
                return;
            }
        };

        match packet.operation {
            NbpOperation::Lookup => {
                let response = self
                    .generate_response(&packet, ddp.src_network_num, ddp.src_node_id, source)
                    .await;

                // Only send a reply if we have at least one matching tuple
                if !response.tuples.is_empty() {
                    // Reply to the tuple's address, not the DDP source: a
                    // router forwarding a BrRq as a broadcast Lookup sets the
                    // DDP source to itself, but the tuple names the original
                    // requester.
                    let Some(req_tuple) = packet.tuples.first() else {
                        tracing::warn!("NBP Lookup with no request tuple; dropping");
                        return;
                    };

                    let mut buf = [0u8; 1024];
                    let size = response
                        .to_bytes(&mut buf)
                        .expect("failed to serialize NBP response");

                    let dest = crate::ddp::DdpAddress::new(
                        tailtalk_packets::aarp::AppleTalkAddress {
                            network_number: req_tuple.network_number,
                            node_number: req_tuple.node_id,
                        },
                        req_tuple.socket_number,
                    );

                    if let Err(e) = self.sock.send_to(&buf[..size], dest).await {
                        tracing::error!("failed to send NBP response: {e}");
                    } else {
                        tracing::debug!(
                            "Sent NBP LookupReply with {} tuples to {}.{}",
                            response.tuples.len(),
                            req_tuple.network_number,
                            req_tuple.node_id
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

    async fn generate_response(
        &self,
        nbp: &NbpPacket,
        _source_network: u16,
        _source_node: u8,
        source: AddressSource,
    ) -> NbpPacket {
        let our_addr = self.addr_on(Some(Interface::from(source))).await;

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

    /// Remove a previously registered name so lookups no longer match it.
    pub async fn unregister(&self, request: RegisteredName) -> Result<(), io::Error> {
        let (tx, rx) = oneshot::channel();

        let request = NbpCommand::Unregister(NbpUnregisterRequest { request, chan: tx });

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
