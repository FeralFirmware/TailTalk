//! Server implementation for `tailtalkd`, the TailTalk underlay daemon.
//!
//! The daemon owns the physical AppleTalk interfaces and runs AARP/LLAP
//! addressing plus DDP in-process, serving clients over the protobuf
//! protocol defined in the `tailtalk-proto` crate.

use std::collections::HashMap;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tailtalk::addressing::AddressingHandle;
use tailtalk::ddp::{DdpAddress, DdpHandle, DdpSocket, DdpSocketSender};
use tailtalk::route_table::RouteTable;
use tailtalk::{CancellationToken, TalkStack};
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_proto as proto;
use tokio::sync::{broadcast, mpsc};

/// UDP sessions expire after this long without any traffic from the client.
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct DaemonConfig {
    /// EtherTalk network interface name (requires the `ethertalk` feature).
    pub ethernet: Option<String>,
    /// Fixed EtherTalk address; probes via AARP when `None`.
    pub ethernet_address: Option<(u16, u8)>,
    /// LocalTalk TashTalk serial device path.
    pub localtalk: Option<String>,
    /// Fixed LocalTalk node number; probes via LLAP ENQ when `None`.
    pub localtalk_node: Option<u8>,
    /// LocalTalk pcap capture path.
    pub pcap: Option<PathBuf>,
    /// Disable the daemon's own RTMP listener and ZIP client (DDP sockets 1
    /// and 6). Needed when a client such as netatalk's `atalkd` runs its own
    /// router engines over this daemon and must bind those sockets itself.
    pub no_router_discovery: bool,
}

// ── Daemon state ──────────────────────────────────────────────────────────────

pub struct InterfaceEntry {
    pub name: String,
    pub kind: proto::InterfaceType,
    pub addressing: AddressingHandle,
    /// Ethernet multicast groups enabled on this interface (EtherTalk only).
    /// The EtherTalk transport captures promiscuously, so reception already
    /// works; this records the membership requested by clients.
    pub multicast: std::sync::Mutex<std::collections::HashSet<[u8; 6]>>,
}

pub struct DaemonState {
    pub interfaces: Vec<InterfaceEntry>,
    pub ddp: DdpHandle,
    /// The authoritative routing table: DDP outbound routing and interface
    /// selection happen daemon-side against this table. Clients only cache it.
    pub route_table: RouteTable,
    /// Fan-out of routing-rule changes; every session forwards these to its
    /// client as unsolicited `routes_changed` messages.
    routes_tx: broadcast::Sender<proto::ListRoutesReply>,
}

pub struct Daemon {
    state: Arc<DaemonState>,
    transport_token: CancellationToken,
}

impl Daemon {
    /// Bring up the underlay (interfaces, addressing, DDP) per `config`.
    pub async fn start(config: DaemonConfig) -> anyhow::Result<Self> {
        let mut builder = TalkStack::builder();

        if let Some(ref serial) = config.localtalk {
            builder = builder.localtalk(serial);
            if let Some(node) = config.localtalk_node {
                builder = builder.localtalk_fixed_address(node);
            }
        }

        #[cfg(feature = "ethertalk")]
        if let Some(ref intf) = config.ethernet {
            builder = builder.ethernet(intf);
            if let Some((net, node)) = config.ethernet_address {
                builder = builder.fixed_address(net, node);
            }
        }
        #[cfg(not(feature = "ethertalk"))]
        if config.ethernet.is_some() {
            anyhow::bail!("this build has no EtherTalk support (rebuild with --features ethertalk)");
        }

        if let Some(ref path) = config.pcap {
            builder = builder.pcap_capture(path);
        }

        if config.no_router_discovery {
            builder = builder.disable_router_discovery();
        }

        let underlay = builder.build_underlay().await?;

        let mut interfaces = Vec::new();
        #[cfg(feature = "ethertalk")]
        if let (Some(name), Some(addressing)) =
            (config.ethernet.clone(), underlay.et_addressing.clone())
        {
            interfaces.push(InterfaceEntry {
                name,
                kind: proto::InterfaceType::Ethertalk,
                addressing,
                multicast: std::sync::Mutex::new(std::collections::HashSet::new()),
            });
        }
        if let (Some(name), Some(addressing)) =
            (config.localtalk.clone(), underlay.lt_addressing.clone())
        {
            interfaces.push(InterfaceEntry {
                name,
                kind: proto::InterfaceType::Localtalk,
                addressing,
                multicast: std::sync::Mutex::new(std::collections::HashSet::new()),
            });
        }

        // Broadcast every routing-rule change (from any session, or made
        // directly on this table) to all connected clients. Changes are
        // coalesced: a burst produces one snapshot broadcast.
        let (routes_tx, _) = broadcast::channel(16);
        let (change_tx, mut change_rx) = mpsc::unbounded_channel();
        underlay.route_table.set_publisher(change_tx);
        {
            let table = underlay.route_table.clone();
            let routes_tx = routes_tx.clone();
            tokio::spawn(async move {
                while change_rx.recv().await.is_some() {
                    while change_rx.try_recv().is_ok() {}
                    let _ = routes_tx.send(routes_to_proto(&table));
                }
            });
        }

        Ok(Self {
            state: Arc::new(DaemonState {
                interfaces,
                ddp: underlay.ddp,
                route_table: underlay.route_table,
                routes_tx,
            }),
            transport_token: underlay.transport_token,
        })
    }

    pub fn state(&self) -> &DaemonState {
        &self.state
    }

    pub fn route_table(&self) -> &RouteTable {
        &self.state.route_table
    }

    /// Stop the underlay and all serving tasks.
    pub fn shutdown(&self) {
        self.transport_token.cancel();
    }

    /// Wait until the daemon has been shut down.
    pub async fn wait_for_shutdown(&self) {
        self.transport_token.cancelled().await;
    }

    /// Serve the protocol on a Unix domain socket at `path`.
    ///
    /// A stale socket file from a previous run is removed first.
    #[cfg(unix)]
    pub fn serve_unix(&self, path: &Path) -> anyhow::Result<()> {
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to remove stale socket '{}'", path.display()))?;
        }
        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("failed to bind unix socket '{}'", path.display()))?;
        tracing::info!("listening on unix socket {}", path.display());

        let state = self.state.clone();
        let token = self.transport_token.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = token.cancelled() => break,
                    accepted = listener.accept() => accepted,
                };
                match accepted {
                    Ok((stream, _)) => {
                        tokio::spawn(run_unix_session(state.clone(), stream, token.clone()));
                    }
                    Err(e) => {
                        tracing::error!("unix accept error: {e}");
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    /// Serve the protocol over UDP. Returns the bound local address.
    pub async fn serve_udp(&self, addr: std::net::SocketAddr) -> anyhow::Result<std::net::SocketAddr> {
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(addr)
                .await
                .with_context(|| format!("failed to bind UDP socket {addr}"))?,
        );
        let local = socket.local_addr()?;
        tracing::info!("listening on udp {local}");

        let state = self.state.clone();
        let token = self.transport_token.clone();
        tokio::spawn(run_udp_server(state, socket, token));
        Ok(local)
    }
}

// ── Session (transport-independent request handling) ──────────────────────────

/// One open DDP socket owned by a session. Dropping it cancels the pump task,
/// which drops the underlying `DdpSocket` and deregisters it from DDP.
struct OpenSocket {
    outbound: mpsc::Sender<proto::SendDatagram>,
    cancel: CancellationToken,
}

impl Drop for OpenSocket {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Session {
    state: Arc<DaemonState>,
    out_tx: mpsc::Sender<proto::ServerMessage>,
    sockets: HashMap<u8, OpenSocket>,
}

impl Session {
    fn new(state: Arc<DaemonState>, out_tx: mpsc::Sender<proto::ServerMessage>) -> Self {
        Self {
            state,
            out_tx,
            sockets: HashMap::new(),
        }
    }

    /// Execute one request. Returns the reply to send, or `None` when the
    /// request was fire-and-forget (id 0).
    async fn handle(&mut self, req: proto::Request) -> Option<proto::Reply> {
        let id = req.id;
        let reply = match req.kind {
            None => proto::Reply::error(id, proto::ErrorCode::InvalidArgument, "missing request kind"),
            Some(kind) => self.dispatch(id, kind).await,
        };
        (id != 0).then_some(reply)
    }

    async fn dispatch(&mut self, id: u64, kind: proto::request::Kind) -> proto::Reply {
        use proto::request::Kind;
        match kind {
            Kind::ListInterfaces(_) => self.list_interfaces(id).await,
            Kind::SetAddress(r) => self.set_address(id, r).await,
            Kind::ProbeAddress(r) => self.probe_address(id, r).await,
            Kind::AddMulticast(r) => self.add_multicast(id, r),
            Kind::OpenSocket(r) => self.open_socket(id, r).await,
            Kind::CloseSocket(r) => {
                match u8::try_from(r.socket_id).ok().and_then(|s| self.sockets.remove(&s)) {
                    Some(_) => proto::Reply::ok(id),
                    None => proto::Reply::error(
                        id,
                        proto::ErrorCode::NotFound,
                        format!("socket {} is not open in this session", r.socket_id),
                    ),
                }
            }
            Kind::Send(r) => self.send_datagram(id, r),
            Kind::ListRoutes(_) => self.list_routes(id),
            Kind::AddRoute(r) => self.add_route(id, r),
            Kind::RemoveRoute(r) => match r.range.and_then(range_from_proto) {
                Some((lo, hi)) => {
                    self.state.route_table.remove_route(lo, hi);
                    proto::Reply::ok(id)
                }
                None => invalid(id, "remove_route requires a valid range"),
            },
            Kind::AddZone(r) => {
                let Some(ranges) = r
                    .ranges
                    .iter()
                    .map(|r| range_from_proto(*r))
                    .collect::<Option<Vec<_>>>()
                else {
                    return invalid(id, "zone range out of bounds");
                };
                if r.zone.is_empty() {
                    return invalid(id, "zone name must not be empty");
                }
                self.state.route_table.insert_zone(&r.zone, &ranges);
                proto::Reply::ok(id)
            }
            Kind::RemoveZone(r) => {
                self.state.route_table.remove_zone(&r.zone);
                proto::Reply::ok(id)
            }
            Kind::SetLocalRange(r) => match r.range.and_then(range_from_proto) {
                Some((lo, hi)) => {
                    self.state.route_table.set_local_range_for(tailtalk::route_table::Interface::EtherTalk, lo, hi);
                    proto::Reply::ok(id)
                }
                None => invalid(id, "set_local_range requires a valid range"),
            },
            Kind::Ping(_) => proto::Reply::ok(id),
        }
    }

    async fn list_interfaces(&self, id: u64) -> proto::Reply {
        let mut interfaces = Vec::with_capacity(self.state.interfaces.len());
        for iface in &self.state.interfaces {
            let address = iface.addressing.addr().await.ok().map(|a| {
                proto::AppleTalkAddress::new(a.network_number, a.node_number)
            });
            interfaces.push(proto::Interface {
                name: iface.name.clone(),
                r#type: iface.kind as i32,
                address,
            });
        }
        proto::Reply::new(
            id,
            proto::reply::Kind::Interfaces(proto::ListInterfacesReply { interfaces }),
        )
    }

    async fn set_address(&self, id: u64, r: proto::SetAddressRequest) -> proto::Reply {
        let Some(iface) = self.state.interfaces.iter().find(|i| i.name == r.interface) else {
            return proto::Reply::error(
                id,
                proto::ErrorCode::NotFound,
                format!("no interface named '{}'", r.interface),
            );
        };
        let Some(addr) = r.address else {
            return invalid(id, "set_address requires an address");
        };
        let (Ok(network), Ok(node)) = (u16::try_from(addr.network), u8::try_from(addr.node)) else {
            return invalid(id, "address out of range");
        };
        if node == 0 || node == 255 {
            return invalid(id, "node must be 1-254");
        }
        if iface.kind == proto::InterfaceType::Localtalk && network != 0 {
            return invalid(id, "LocalTalk network number must be 0");
        }

        match iface
            .addressing
            .set_addr(AppleTalkAddress {
                network_number: network,
                node_number: node,
            })
            .await
        {
            Ok(()) => proto::Reply::ok(id),
            Err(e) => proto::Reply::error(id, proto::ErrorCode::Internal, e.to_string()),
        }
    }

    async fn probe_address(&self, id: u64, r: proto::ProbeAddressRequest) -> proto::Reply {
        let Some(iface) = self.state.interfaces.iter().find(|i| i.name == r.interface) else {
            return proto::Reply::error(
                id,
                proto::ErrorCode::NotFound,
                format!("no interface named '{}'", r.interface),
            );
        };
        let Some(addr) = r.address else {
            return invalid(id, "probe_address requires an address");
        };
        let (Ok(network), Ok(node)) = (u16::try_from(addr.network), u8::try_from(addr.node)) else {
            return invalid(id, "address out of range");
        };
        if node == 0 || node == 255 {
            return invalid(id, "node must be 1-254");
        }
        if iface.kind == proto::InterfaceType::Localtalk && network != 0 {
            return invalid(id, "LocalTalk network number must be 0");
        }

        match iface
            .addressing
            .probe(AppleTalkAddress {
                network_number: network,
                node_number: node,
            })
            .await
        {
            Ok(available) => proto::Reply::new(
                id,
                proto::reply::Kind::ProbeAddress(proto::ProbeAddressReply { available }),
            ),
            Err(e) => proto::Reply::error(id, proto::ErrorCode::Internal, e.to_string()),
        }
    }

    fn add_multicast(&self, id: u64, r: proto::AddMulticastRequest) -> proto::Reply {
        let Some(iface) = self.state.interfaces.iter().find(|i| i.name == r.interface) else {
            return proto::Reply::error(
                id,
                proto::ErrorCode::NotFound,
                format!("no interface named '{}'", r.interface),
            );
        };
        // Multicast is an EtherTalk-only concept; LocalTalk has no hardware
        // multicast, so reject it rather than silently accept.
        if iface.kind != proto::InterfaceType::Ethertalk {
            return invalid(id, "multicast is only supported on EtherTalk interfaces");
        }
        let Ok(mac) = <[u8; 6]>::try_from(r.address.as_slice()) else {
            return invalid(id, "multicast address must be 6 bytes");
        };
        if mac[0] & 0x01 == 0 {
            return invalid(id, "not a multicast address (group bit clear)");
        }
        // The EtherTalk capture is promiscuous, so frames for this group are
        // already delivered; record the membership for correctness.
        let mut groups = iface.multicast.lock().unwrap();
        if groups.insert(mac) {
            tracing::info!(
                "interface {}: enabled multicast {:02x?} ({} group(s))",
                iface.name,
                mac,
                groups.len()
            );
        }
        proto::Reply::ok(id)
    }

    async fn open_socket(&mut self, id: u64, r: proto::OpenSocketRequest) -> proto::Reply {
        let Ok(ddp_type) = u8::try_from(r.ddp_type) else {
            return invalid(id, "ddp_type must be 0-255");
        };
        let requested = match r.socket {
            0 => None,
            n @ 1..=254 => Some(n as u8),
            _ => return invalid(id, "socket must be 0 (dynamic) or 1-254"),
        };

        let sock = match self
            .state
            .ddp
            .new_sock(DdpProtocolType::from(ddp_type), requested)
            .await
        {
            Ok(sock) => sock,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return proto::Reply::error(
                    id,
                    proto::ErrorCode::AddrInUse,
                    format!("DDP socket {} is already bound", r.socket),
                );
            }
            Err(e) => return proto::Reply::error(id, proto::ErrorCode::Internal, e.to_string()),
        };

        let socket_id = sock.socket_num();
        let (outbound_tx, outbound_rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();
        let send_handle = sock.send_handle();
        tokio::spawn(socket_pump_inbound(
            sock,
            socket_id,
            self.out_tx.clone(),
            cancel.clone(),
        ));
        tokio::spawn(socket_pump_outbound(
            send_handle,
            socket_id,
            outbound_rx,
            cancel.clone(),
        ));
        self.sockets.insert(
            socket_id,
            OpenSocket {
                outbound: outbound_tx,
                cancel,
            },
        );

        proto::Reply::new(
            id,
            proto::reply::Kind::Socket(proto::OpenSocketReply {
                socket_id: socket_id as u32,
            }),
        )
    }

    fn send_datagram(&self, id: u64, r: proto::SendDatagram) -> proto::Reply {
        let Some(open) = u8::try_from(r.socket_id).ok().and_then(|s| self.sockets.get(&s)) else {
            return proto::Reply::error(
                id,
                proto::ErrorCode::NotFound,
                format!("socket {} is not open in this session", r.socket_id),
            );
        };
        if r.payload.len() > 586 {
            return invalid(id, "DDP payload exceeds 586 bytes");
        }
        let socket_id = r.socket_id;
        // Best-effort, like DDP itself: drop on backpressure rather than
        // stalling the whole session behind one slow socket.
        if open.outbound.try_send(r).is_err() {
            tracing::warn!("socket {socket_id}: outbound queue full, dropping datagram");
        }
        proto::Reply::ok(id)
    }

    fn list_routes(&self, id: u64) -> proto::Reply {
        proto::Reply::new(
            id,
            proto::reply::Kind::Routes(routes_to_proto(&self.state.route_table)),
        )
    }

    fn add_route(&self, id: u64, r: proto::AddRouteRequest) -> proto::Reply {
        let Some(route) = r.route else {
            return invalid(id, "add_route requires a route");
        };
        let Some((lo, hi)) = route.range.and_then(range_from_proto) else {
            return invalid(id, "route range out of bounds");
        };
        let Some(nh) = route.next_hop else {
            return invalid(id, "add_route requires a next_hop");
        };
        let (Ok(network), Ok(node)) = (u16::try_from(nh.network), u8::try_from(nh.node)) else {
            return invalid(id, "next_hop out of range");
        };
        let interface = match route.interface {
            1 => Some(tailtalk::route_table::Interface::EtherTalk),
            2 => Some(tailtalk::route_table::Interface::EtherTalk),
            3 => Some(tailtalk::route_table::Interface::LocalTalk),
            _ => None,
        };
        self.state.route_table.insert_route(
            lo,
            hi,
            AppleTalkAddress {
                network_number: network,
                node_number: node,
            },
            interface.unwrap_or(tailtalk::route_table::Interface::EtherTalk),
        );
        proto::Reply::ok(id)
    }
}

fn invalid(id: u64, msg: &str) -> proto::Reply {
    proto::Reply::error(id, proto::ErrorCode::InvalidArgument, msg)
}

fn range_from_proto(r: proto::CableRange) -> Option<(u16, u16)> {
    let lo = u16::try_from(r.lo).ok()?;
    let hi = u16::try_from(r.hi).ok()?;
    (lo <= hi).then_some((lo, hi))
}

fn range_to_proto((lo, hi): (u16, u16)) -> proto::CableRange {
    proto::CableRange {
        lo: lo as u32,
        hi: hi as u32,
    }
}

/// Snapshot the routing table into its wire representation.
fn routes_to_proto(table: &RouteTable) -> proto::ListRoutesReply {
    let snapshot = table.snapshot();
    proto::ListRoutesReply {
        routes: snapshot
            .routes
            .into_iter()
            .map(|(lo, hi, next_hop, interface)| proto::Route {
                range: Some(range_to_proto((lo, hi))),
                next_hop: Some(proto::AppleTalkAddress::new(
                    next_hop.network_number,
                    next_hop.node_number,
                )),
                interface: match interface {
                    Some(tailtalk::route_table::Interface::EtherTalk) => 2,
                    Some(tailtalk::route_table::Interface::LocalTalk) => 3,
                    None => 0,
                },
            })
            .collect(),
        zones: snapshot
            .zones
            .into_iter()
            .map(|(name, ranges)| proto::Zone {
                name,
                ranges: ranges.into_iter().map(range_to_proto).collect(),
            })
            .collect(),
        local_range: snapshot.local_range.map(range_to_proto),
    }
}

/// Turn a route-broadcast receive result into the message to forward, or
/// `None` when the channel is closed. A lagged receiver recovers by sending
/// a fresh snapshot (the broadcast payload is always the complete rule set).
fn routes_broadcast_to_msg(
    res: Result<proto::ListRoutesReply, broadcast::error::RecvError>,
    table: &RouteTable,
) -> Option<proto::ServerMessage> {
    match res {
        Ok(reply) => Some(proto::ServerMessage::routes_changed(reply)),
        Err(broadcast::error::RecvError::Lagged(_)) => {
            Some(proto::ServerMessage::routes_changed(routes_to_proto(table)))
        }
        Err(broadcast::error::RecvError::Closed) => None,
    }
}

/// Per-socket inbound task: forwards DDP packets arriving on `sock` to the
/// session's writer channel. Owns the `DdpSocket`; dropping it deregisters
/// the socket from DDP. Ends when cancelled or the writer goes away.
async fn socket_pump_inbound(
    mut sock: DdpSocket,
    socket_id: u8,
    out_tx: mpsc::Sender<proto::ServerMessage>,
    cancel: CancellationToken,
) {
    loop {
        let pkt = tokio::select! {
            _ = cancel.cancelled() => break,
            pkt = sock.recv() => match pkt { Ok(p) => p, Err(_) => break },
        };
        let h = &pkt.headers;
        let datagram = proto::ReceivedDatagram {
            socket_id: socket_id as u32,
            source: Some(proto::AppleTalkAddress::new(h.src_network_num, h.src_node_id)),
            source_socket: h.src_sock_num as u32,
            dest: Some(proto::AppleTalkAddress::new(h.dest_network_num, h.dest_node_id)),
            dest_socket: h.dest_sock_num as u32,
            ddp_type: u8::from(h.protocol_typ) as u32,
            payload: pkt.payload.into_vec(),
            arrival_link: match pkt.source {
                tailtalk_packets::aarp::AddressSource::EtherTalkPhase1 => 1,
                tailtalk_packets::aarp::AddressSource::EtherTalkPhase2 => 2,
                tailtalk_packets::aarp::AddressSource::LocalTalk => 3,
            },
        };
        if out_tx.send(proto::ServerMessage::datagram(datagram)).await.is_err() {
            break;
        }
    }
}

/// Per-socket outbound task: forwards `SendDatagram`s from the client to DDP.
/// Runs independently of inbound delivery so slow LocalTalk writes don't
/// stall packet reception.
async fn socket_pump_outbound(
    sender: DdpSocketSender,
    socket_id: u8,
    mut outbound: mpsc::Receiver<proto::SendDatagram>,
    cancel: CancellationToken,
) {
    loop {
        let send = tokio::select! {
            _ = cancel.cancelled() => break,
            msg = outbound.recv() => match msg { Some(s) => s, None => break },
        };
        let Some(dest) = send.dest else {
            tracing::warn!("socket {socket_id}: dropping datagram with no destination");
            continue;
        };
        let addr = DdpAddress::new(
            AppleTalkAddress {
                network_number: dest.network as u16,
                node_number: dest.node as u8,
            },
            send.dest_socket as u8,
        );
        let protocol = match u8::try_from(send.ddp_type) {
            Ok(0) => None,
            Ok(t) => Some(DdpProtocolType::from(t)),
            Err(_) => {
                tracing::warn!(
                    "socket {socket_id}: dropping datagram with bad ddp_type {}",
                    send.ddp_type
                );
                continue;
            }
        };
        if let Err(e) = sender.send_to_typed(&send.payload, addr, protocol).await {
            tracing::warn!("socket {socket_id}: send failed: {e}");
        }
    }
}

// ── Unix transport ────────────────────────────────────────────────────────────

#[cfg(unix)]
async fn run_unix_session(
    state: Arc<DaemonState>,
    stream: tokio::net::UnixStream,
    token: CancellationToken,
) {
    let (read_half, write_half) = stream.into_split();
    let framed_read = tokio_util::codec::FramedRead::new(read_half, proto::TailTalkCodec::<proto::ServerMessage, proto::Request>::default());
    let framed_write = tokio_util::codec::FramedWrite::new(write_half, proto::TailTalkCodec::<proto::ServerMessage, proto::Request>::default());
    let (out_tx, out_rx) = mpsc::channel::<proto::ServerMessage>(256);
    tokio::spawn(unix_writer(framed_write, out_rx));

    let mut session = Session::new(state, out_tx);
    let mut routes_rx = session.state.routes_tx.subscribe();
    tokio::pin!(framed_read);
    use futures::StreamExt;
    loop {
        let msg = tokio::select! {
            _ = token.cancelled() => break,
            changed = routes_rx.recv() => {
                match routes_broadcast_to_msg(changed, &session.state.route_table) {
                    Some(msg) => {
                        if session.out_tx.send(msg).await.is_err() {
                            break;
                        }
                        continue;
                    }
                    None => break,
                }
            }
            msg = framed_read.next() => msg.transpose(),
        };
        match msg {
            Ok(Some(req)) => {
                if let Some(reply) = session.handle(req).await
                    && session
                        .out_tx
                        .send(proto::ServerMessage::reply(reply))
                        .await
                        .is_err()
                    {
                        break;
                    }
            }
            Ok(None) => break, // client hung up
            Err(e) => {
                tracing::warn!("client protocol error: {e}");
                break;
            }
        }
    }
    // Dropping the session cancels every socket pump, which deregisters the
    // session's DDP sockets.
}

#[cfg(unix)]
async fn unix_writer(
    mut write_half: tokio_util::codec::FramedWrite<tokio::net::unix::OwnedWriteHalf, proto::TailTalkCodec<proto::ServerMessage, proto::Request>>,
    mut out_rx: mpsc::Receiver<proto::ServerMessage>,
) {
    use futures::SinkExt;
    while let Some(msg) = out_rx.recv().await {
        if write_half.send(msg).await.is_err() {
            break;
        }
    }
}

// ── UDP transport ─────────────────────────────────────────────────────────────

struct UdpSessionHandle {
    req_tx: mpsc::Sender<proto::Request>,
    last_seen: Instant,
}

async fn run_udp_server(
    state: Arc<DaemonState>,
    socket: Arc<tokio::net::UdpSocket>,
    token: CancellationToken,
) {
    let mut sessions: HashMap<std::net::SocketAddr, UdpSessionHandle> = HashMap::new();
    let mut buf = vec![0u8; proto::MAX_MESSAGE_LEN + 8];
    let mut sweep = tokio::time::interval(Duration::from_secs(60));
    sweep.tick().await;

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = sweep.tick() => {
                sessions.retain(|peer, s| {
                    let live = s.last_seen.elapsed() < UDP_SESSION_TIMEOUT;
                    if !live {
                        tracing::info!("udp session {peer} expired");
                    }
                    live
                });
            }
            res = socket.recv_from(&mut buf) => {
                let (n, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!("udp receive error: {e}");
                        continue;
                    }
                };
                let requests = match proto::decode_datagram::<proto::Request>(&buf[..n]) {
                    Ok(msgs) => msgs,
                    Err(e) => {
                        tracing::warn!("bad datagram from {peer}: {e}");
                        continue;
                    }
                };
                let session = sessions.entry(peer).or_insert_with(|| {
                    tracing::info!("new udp session from {peer}");
                    spawn_udp_session(state.clone(), socket.clone(), peer)
                });
                session.last_seen = Instant::now();
                for req in requests {
                    if session.req_tx.try_send(req).is_err() {
                        tracing::warn!("udp session {peer}: request queue full, dropping");
                    }
                }
            }
        }
    }
}

fn spawn_udp_session(
    state: Arc<DaemonState>,
    socket: Arc<tokio::net::UdpSocket>,
    peer: std::net::SocketAddr,
) -> UdpSessionHandle {
    let (req_tx, mut req_rx) = mpsc::channel::<proto::Request>(256);
    let (out_tx, mut out_rx) = mpsc::channel::<proto::ServerMessage>(256);

    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if let Err(e) = socket.send_to(&proto::encode_frame(&msg), peer).await {
                tracing::warn!("udp send to {peer} failed: {e}");
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut session = Session::new(state, out_tx);
        let mut routes_rx = session.state.routes_tx.subscribe();
        loop {
            tokio::select! {
                changed = routes_rx.recv() => {
                    match routes_broadcast_to_msg(changed, &session.state.route_table) {
                        Some(msg) => {
                            if session.out_tx.send(msg).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                req = req_rx.recv() => {
                    let Some(req) = req else { break };
                    if let Some(reply) = session.handle(req).await
                        && session
                            .out_tx
                            .send(proto::ServerMessage::reply(reply))
                            .await
                            .is_err()
                        {
                            break;
                        }
                }
            }
        }
        // Session dropped: all its DDP sockets are deregistered.
    });

    UdpSessionHandle {
        req_tx,
        last_seen: Instant::now(),
    }
}
