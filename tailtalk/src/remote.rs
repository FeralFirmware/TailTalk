//! Client for a remote TailTalk daemon (`tailtalkd`).
//!
//! When a [`TalkStack`](crate::TalkStack) is built with
//! [`daemon_unix`](crate::TalkStackBuilder::daemon_unix) or
//! [`daemon_udp`](crate::TalkStackBuilder::daemon_udp), this module carries
//! DDP sockets, addressing, and routing over the protobuf wire protocol.

use std::collections::HashMap;
use std::io::{self, Error};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::{DdpPacket as DdpHeaders, DdpProtocolType};
use tailtalk_proto as proto;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::ddp::Packet;

/// Where to reach the daemon.
#[derive(Debug, Clone)]
pub enum DaemonEndpoint {
    /// SOCK_STREAM Unix domain socket path.
    #[cfg(unix)]
    Unix(PathBuf),
    /// UDP host:port.
    Udp(std::net::SocketAddr),
}

/// Interval between keepalive pings on UDP transports (sessions expire
/// daemon-side after 300 s idle).
const UDP_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Default)]
struct Shared {
    /// In-flight requests awaiting a reply, by correlation id.
    pending: Mutex<HashMap<u64, oneshot::Sender<proto::reply::Kind>>>,
    /// Receive queues for open DDP sockets, by socket number.
    sockets: Mutex<HashMap<u8, mpsc::Sender<Packet>>>,
    /// Local cache of the daemon's authoritative routing rules; replaced
    /// wholesale whenever the daemon pushes a `routes_changed` message.
    route_table: Mutex<Option<crate::route_table::RouteTable>>,
}

/// Cheaply cloneable connection to the daemon.
#[derive(Debug, Clone)]
pub(crate) struct RemoteClient {
    req_tx: mpsc::Sender<proto::Request>,
    shared: Arc<Shared>,
    next_id: Arc<AtomicU64>,
    /// Cancelled when the connection dies (or `shutdown` is called).
    closed: CancellationToken,
}

impl RemoteClient {
    pub(crate) async fn connect(endpoint: &DaemonEndpoint) -> io::Result<Self> {
        let (req_tx, req_rx) = mpsc::channel::<proto::Request>(100);
        let shared = Arc::new(Shared::default());
        let closed = CancellationToken::new();

        let client = Self {
            req_tx,
            shared: shared.clone(),
            next_id: Arc::new(AtomicU64::new(1)),
            closed: closed.clone(),
        };

        match endpoint {
            #[cfg(unix)]
            DaemonEndpoint::Unix(path) => {
                let stream = tokio::net::UnixStream::connect(path).await?;
                let (read_half, write_half) = stream.into_split();
                let framed_write = tokio_util::codec::FramedWrite::new(write_half, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());
                tokio::spawn(unix_writer(framed_write, req_rx, closed.clone()));
                tokio::spawn(unix_reader(read_half, shared, closed));
            }
            DaemonEndpoint::Udp(addr) => {
                let bind: std::net::SocketAddr = if addr.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let socket = Arc::new(tokio::net::UdpSocket::bind(bind).await?);
                socket.connect(addr).await?;
                tokio::spawn(udp_writer(socket.clone(), req_rx, closed.clone()));
                tokio::spawn(udp_reader(socket, shared, closed.clone()));
                tokio::spawn(udp_keepalive(client.clone(), closed));
            }
        }

        Ok(client)
    }

    /// Token cancelled when the daemon connection is gone.
    pub(crate) fn closed_token(&self) -> CancellationToken {
        self.closed.clone()
    }

    /// Register the local route-table cache to be kept in sync with the
    /// daemon's authoritative table via `routes_changed` pushes.
    pub(crate) fn sync_routes_to(&self, table: crate::route_table::RouteTable) {
        *self.shared.route_table.lock().unwrap() = Some(table);
    }

    /// Tear down the connection tasks.
    pub(crate) fn shutdown(&self) {
        self.closed.cancel();
    }

    /// Send a request and await its reply.
    pub(crate) async fn request(&self, kind: proto::request::Kind) -> io::Result<proto::reply::Kind> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(id, tx);

        let req = proto::Request { id, kind: Some(kind) };
        if self.req_tx.send(req).await.is_err() {
            self.shared.pending.lock().unwrap().remove(&id);
            return Err(Error::new(io::ErrorKind::BrokenPipe, "daemon connection closed"));
        }

        let kind = rx.await.map_err(|_| {
            Error::new(io::ErrorKind::BrokenPipe, "daemon connection closed")
        })?;

        if let proto::reply::Kind::Error(e) = kind {
            return Err(proto_error_to_io(&e));
        }
        Ok(kind)
    }

    /// Send a fire-and-forget request (id 0 — the daemon will not reply).
    fn send_no_reply(&self, kind: proto::request::Kind) {
        let _ = self.req_tx.try_send(proto::Request { id: 0, kind: Some(kind) });
    }

    // ── DDP sockets ──────────────────────────────────────────────────────────

    /// Open a DDP socket on the daemon. Returns the bound socket number and
    /// the receive queue that inbound datagrams are delivered on.
    pub(crate) async fn open_socket(
        &self,
        protocol: DdpProtocolType,
        sock_num: Option<u8>,
    ) -> io::Result<(u8, mpsc::Receiver<Packet>)> {
        let kind = self
            .request(proto::request::Kind::OpenSocket(proto::OpenSocketRequest {
                socket: sock_num.unwrap_or(0) as u32,
                ddp_type: u8::from(protocol) as u32,
            }))
            .await?;

        let proto::reply::Kind::Socket(reply) = kind else {
            return Err(unexpected_reply());
        };
        let socket_id = u8::try_from(reply.socket_id)
            .map_err(|_| Error::new(io::ErrorKind::InvalidData, "socket id out of range"))?;

        let (tx, rx) = mpsc::channel(100);
        self.shared.sockets.lock().unwrap().insert(socket_id, tx);
        Ok((socket_id, rx))
    }

    /// Close a previously opened socket (fire-and-forget).
    pub(crate) fn close_socket(&self, socket_id: u8) {
        self.shared.sockets.lock().unwrap().remove(&socket_id);
        self.send_no_reply(proto::request::Kind::CloseSocket(proto::CloseSocketRequest {
            socket_id: socket_id as u32,
        }));
    }

    /// Send a datagram out of an open socket. Applies channel backpressure
    /// but, like DDP itself, gives no delivery guarantee.
    pub(crate) async fn send_datagram(
        &self,
        socket_id: u8,
        dest: AppleTalkAddress,
        dest_socket: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let req = proto::Request {
            id: 0,
            kind: Some(proto::request::Kind::Send(proto::SendDatagram {
                socket_id: socket_id as u32,
                dest: Some(proto::AppleTalkAddress::new(
                    dest.network_number,
                    dest.node_number,
                )),
                dest_socket: dest_socket as u32,
                payload: payload.to_vec(),
                ddp_type: 0, // use the type the socket was opened with
            })),
        };
        self.req_tx
            .send(req)
            .await
            .map_err(|_| Error::new(io::ErrorKind::BrokenPipe, "daemon connection closed"))
    }

    // ── Interfaces ───────────────────────────────────────────────────────────

    pub(crate) async fn list_interfaces(&self) -> io::Result<Vec<proto::Interface>> {
        let kind = self
            .request(proto::request::Kind::ListInterfaces(
                proto::ListInterfacesRequest {},
            ))
            .await?;
        match kind {
            proto::reply::Kind::Interfaces(reply) => Ok(reply.interfaces),
            _ => Err(unexpected_reply()),
        }
    }

    pub(crate) async fn interface_addr(&self, name: &str) -> io::Result<AppleTalkAddress> {
        let interfaces = self.list_interfaces().await?;
        let iface = interfaces
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| Error::new(io::ErrorKind::NotFound, format!("interface '{name}' not found on daemon")))?;
        let addr = iface.address.ok_or_else(|| {
            Error::new(io::ErrorKind::NotConnected, format!("interface '{name}' has no address yet"))
        })?;
        Ok(AppleTalkAddress {
            network_number: addr.network as u16,
            node_number: addr.node as u8,
        })
    }

    pub(crate) async fn set_interface_addr(
        &self,
        name: &str,
        addr: AppleTalkAddress,
    ) -> io::Result<()> {
        self.request(proto::request::Kind::SetAddress(proto::SetAddressRequest {
            interface: name.to_string(),
            address: Some(proto::AppleTalkAddress::new(
                addr.network_number,
                addr.node_number,
            )),
        }))
        .await?;
        Ok(())
    }

    pub(crate) async fn probe_address(
        &self,
        name: &str,
        addr: AppleTalkAddress,
    ) -> io::Result<bool> {
        let kind = self
            .request(proto::request::Kind::ProbeAddress(proto::ProbeAddressRequest {
                interface: name.to_string(),
                address: Some(proto::AppleTalkAddress::new(
                    addr.network_number,
                    addr.node_number,
                )),
            }))
            .await?;
        match kind {
            proto::reply::Kind::ProbeAddress(reply) => Ok(reply.available),
            _ => Err(unexpected_reply()),
        }
    }

    // ── Routing rules ────────────────────────────────────────────────────────

    pub(crate) async fn list_routes(&self) -> io::Result<proto::ListRoutesReply> {
        let kind = self
            .request(proto::request::Kind::ListRoutes(proto::ListRoutesRequest {}))
            .await?;
        match kind {
            proto::reply::Kind::Routes(reply) => Ok(reply),
            _ => Err(unexpected_reply()),
        }
    }

    /// Forward a local route-table mutation to the daemon.
    pub(crate) async fn apply_route_change(
        &self,
        change: &crate::route_table::RouteChange,
    ) -> io::Result<()> {
        use crate::route_table::RouteChange;
        let kind = match change {
            RouteChange::SetLocalRange((lo, hi)) => {
                proto::request::Kind::SetLocalRange(proto::SetLocalRangeRequest {
                    range: Some(proto::CableRange { lo: *lo as u32, hi: *hi as u32 }),
                })
            }
            RouteChange::InsertRoute { lo, hi, next_hop, interface } => {
                proto::request::Kind::AddRoute(proto::AddRouteRequest {
                    route: Some(proto::Route {
                        range: Some(proto::CableRange { lo: *lo as u32, hi: *hi as u32 }),
                        next_hop: Some(proto::AppleTalkAddress::new(
                            next_hop.network_number,
                            next_hop.node_number,
                        )),
                        interface: match interface {
                            Some(crate::route_table::Interface::EtherTalk) => 2, // EtherTalkPhase2 by default for daemon
                            Some(crate::route_table::Interface::LocalTalk) => 3,
                            None => 0,
                        },
                    }),
                })
            }
            RouteChange::RemoveRoute { lo, hi } => {
                proto::request::Kind::RemoveRoute(proto::RemoveRouteRequest {
                    range: Some(proto::CableRange { lo: *lo as u32, hi: *hi as u32 }),
                })
            }
            RouteChange::InsertZone { zone, ranges } => {
                proto::request::Kind::AddZone(proto::AddZoneRequest {
                    zone: zone.clone(),
                    ranges: ranges
                        .iter()
                        .map(|(lo, hi)| proto::CableRange { lo: *lo as u32, hi: *hi as u32 })
                        .collect(),
                })
            }
            RouteChange::RemoveZone { zone } => {
                proto::request::Kind::RemoveZone(proto::RemoveZoneRequest { zone: zone.clone() })
            }
        };
        self.request(kind).await?;
        Ok(())
    }
}

// ── Reply dispatch ────────────────────────────────────────────────────────────

fn dispatch(shared: &Shared, msg: proto::ServerMessage) {
    match msg.kind {
        Some(proto::server_message::Kind::Reply(reply)) => {
            let Some(kind) = reply.kind else { return };
            if let Some(tx) = shared.pending.lock().unwrap().remove(&reply.id) {
                let _ = tx.send(kind);
            }
        }
        Some(proto::server_message::Kind::Datagram(dg)) => {
            let Ok(socket_id) = u8::try_from(dg.socket_id) else { return };
            let source = dg.source.unwrap_or_default();
            let dest = dg.dest.unwrap_or_default();
            let headers = DdpHeaders {
                hop_count: 0,
                len: dg.payload.len() + DdpHeaders::LEN,
                chksum: 0,
                dest_network_num: dest.network as u16,
                src_network_num: source.network as u16,
                dest_node_id: dest.node as u8,
                dest_sock_num: dg.dest_socket as u8,
                src_sock_num: dg.source_socket as u8,
                src_node_id: source.node as u8,
                protocol_typ: DdpProtocolType::from(dg.ddp_type as u8),
            };
            let packet = Packet {
                headers,
                payload: dg.payload.into_boxed_slice(),
                source: match dg.arrival_link {
                    1 => tailtalk_packets::aarp::AddressSource::EtherTalkPhase1,
                    2 => tailtalk_packets::aarp::AddressSource::EtherTalkPhase2,
                    3 => tailtalk_packets::aarp::AddressSource::LocalTalk,
                    _ => tailtalk_packets::aarp::AddressSource::EtherTalkPhase2, // default fallback
                },
            };
            let sockets = shared.sockets.lock().unwrap();
            if let Some(tx) = sockets.get(&socket_id)
                && tx.try_send(packet).is_err() {
                    tracing::warn!("remote DDP socket {socket_id}: receive queue full, dropping");
                }
        }
        Some(proto::server_message::Kind::RoutesChanged(reply)) => {
            let table = shared.route_table.lock().unwrap().clone();
            if let Some(table) = table {
                tracing::debug!("daemon routing rules changed, updating local cache");
                table.replace_contents(snapshot_from_proto(&reply));
            }
        }
        None => {}
    }
}

/// Convert the daemon's route listing into a local snapshot.
pub(crate) fn snapshot_from_proto(
    reply: &proto::ListRoutesReply,
) -> crate::route_table::RouteSnapshot {
    crate::route_table::RouteSnapshot {
        local_range: reply
            .local_range
            .as_ref()
            .map(|r| (r.lo as u16, r.hi as u16)),
        routes: reply
            .routes
            .iter()
            .filter_map(|route| {
                let range = route.range.as_ref()?;
                let next_hop = route.next_hop.as_ref()?;
                let interface = match route.interface {
                    1 | 2 => Some(crate::route_table::Interface::EtherTalk),
                    3 => Some(crate::route_table::Interface::LocalTalk),
                    _ => None,
                };
                Some((
                    range.lo as u16,
                    range.hi as u16,
                    AppleTalkAddress {
                        network_number: next_hop.network as u16,
                        node_number: next_hop.node as u8,
                    },
                    interface,
                ))
            })
            .collect(),
        zones: reply
            .zones
            .iter()
            .map(|zone| {
                (
                    zone.name.clone(),
                    zone.ranges.iter().map(|r| (r.lo as u16, r.hi as u16)).collect(),
                )
            })
            .collect(),
    }
}

/// Fail every in-flight request when the connection dies.
fn fail_pending(shared: &Shared) {
    shared.pending.lock().unwrap().clear();
    shared.sockets.lock().unwrap().clear();
}

// ── Unix transport tasks ──────────────────────────────────────────────────────

#[cfg(unix)]
async fn unix_writer(
    mut write_half: tokio_util::codec::FramedWrite<tokio::net::unix::OwnedWriteHalf, proto::TailTalkCodec<proto::Request, proto::ServerMessage>>,
    mut req_rx: mpsc::Receiver<proto::Request>,
    closed: CancellationToken,
) {
    use futures::SinkExt;
    loop {
        let req = tokio::select! {
            _ = closed.cancelled() => break,
            req = req_rx.recv() => match req { Some(r) => r, None => break },
        };
        if let Err(e) = write_half.send(req).await {
            tracing::error!("daemon connection write error: {e}");
            break;
        }
    }
    closed.cancel();
}

#[cfg(unix)]
async fn unix_reader(
    read_half: tokio::net::unix::OwnedReadHalf,
    shared: Arc<Shared>,
    closed: CancellationToken,
) {
    use futures::StreamExt;
    let mut reader = tokio_util::codec::FramedRead::new(read_half, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());
    loop {
        let msg = tokio::select! {
            _ = closed.cancelled() => break,
            msg = reader.next() => msg.transpose(),
        };
        match msg {
            Ok(Some(msg)) => dispatch(&shared, msg),
            Ok(None) => {
                tracing::info!("daemon closed the connection");
                break;
            }
            Err(e) => {
                tracing::error!("daemon connection read error: {e}");
                break;
            }
        }
    }
    closed.cancel();
    fail_pending(&shared);
}

// ── UDP transport tasks ───────────────────────────────────────────────────────

async fn udp_writer(
    socket: Arc<tokio::net::UdpSocket>,
    mut req_rx: mpsc::Receiver<proto::Request>,
    closed: CancellationToken,
) {
    loop {
        let req = tokio::select! {
            _ = closed.cancelled() => break,
            req = req_rx.recv() => match req { Some(r) => r, None => break },
        };
        if let Err(e) = socket.send(&proto::encode_frame(&req)).await {
            tracing::error!("daemon UDP send error: {e}");
            break;
        }
    }
    closed.cancel();
}

async fn udp_reader(
    socket: Arc<tokio::net::UdpSocket>,
    shared: Arc<Shared>,
    closed: CancellationToken,
) {
    let mut buf = vec![0u8; proto::MAX_MESSAGE_LEN + 8];
    loop {
        let res = tokio::select! {
            _ = closed.cancelled() => break,
            res = socket.recv(&mut buf) => res,
        };
        match res {
            Ok(n) => match proto::decode_datagram::<proto::ServerMessage>(&buf[..n]) {
                Ok(msgs) => {
                    for msg in msgs {
                        dispatch(&shared, msg);
                    }
                }
                Err(e) => tracing::warn!("bad datagram from daemon: {e}"),
            },
            Err(e) => {
                tracing::error!("daemon UDP receive error: {e}");
                break;
            }
        }
    }
    closed.cancel();
    fail_pending(&shared);
}

async fn udp_keepalive(client: RemoteClient, closed: CancellationToken) {
    let mut interval = tokio::time::interval(UDP_KEEPALIVE);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = closed.cancelled() => break,
            _ = interval.tick() => {
                if client
                    .request(proto::request::Kind::Ping(proto::PingRequest {}))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────────

fn proto_error_to_io(e: &proto::Error) -> Error {
    let kind = match proto::ErrorCode::try_from(e.code) {
        Ok(proto::ErrorCode::InvalidArgument) => io::ErrorKind::InvalidInput,
        Ok(proto::ErrorCode::NotFound) => io::ErrorKind::NotFound,
        Ok(proto::ErrorCode::AddrInUse) => io::ErrorKind::AddrInUse,
        _ => io::ErrorKind::Other,
    };
    Error::new(kind, format!("daemon error: {}", e.message))
}

fn unexpected_reply() -> Error {
    Error::new(io::ErrorKind::InvalidData, "unexpected reply kind from daemon")
}
