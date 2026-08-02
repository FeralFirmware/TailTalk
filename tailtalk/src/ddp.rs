use rand::RngExt;
use std::{
    collections::HashMap,
    io::{self, Error},
};
use tailtalk_packets::{
    aarp::{AddressSource as AppleTalkAddressSource, AppleTalkAddress},
    ddp::{DdpPacket as DdpHeaders, DdpProtocolType},
};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

use crate::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, AddressingHandle, Node},
    remote::RemoteClient,
    route_table::{Interface, NextHop, RouteTable},
};

pub struct Packet {
    pub headers: DdpHeaders,
    pub payload: Box<[u8]>,
    /// Which link the packet arrived on. Now carried by the daemon proto as well.
    pub source: AppleTalkAddressSource,
}

#[derive(Debug)]
pub struct DdpAddress {
    addr: AppleTalkAddress,
    sock: SockNum,
}

impl DdpAddress {
    pub fn new(network: AppleTalkAddress, sock: SockNum) -> Self {
        Self {
            addr: network,
            sock,
        }
    }
}

struct OutboundPacket {
    dest: DdpAddress,
    src_sock: SockNum,
    protocol: DdpProtocolType,
    payload: Box<[u8]>,
    /// Restricts a link-layer broadcast to a single cable.
    ///
    /// Only consulted for the `{0, 255}` network-wide broadcast, which
    /// otherwise goes out on every configured interface. Unicast is routed by
    /// destination address, so the cable is not the caller's to choose.
    iface: Option<Interface>,
}

#[derive(Debug, Clone)]
enum DdpSender {
    Local(mpsc::Sender<DdpCommand>),
    Remote(RemoteClient),
}

/// Clone-able, send-only half of a [`DdpSocket`].
///
/// Obtained via [`DdpSocket::send_handle`]. Allows sending datagrams from a
/// separate task while the socket's receive side lives elsewhere.
#[derive(Debug, Clone)]
pub struct DdpSocketSender {
    sock_num: u8,
    protocol: DdpProtocolType,
    sender: DdpSender,
}

impl DdpSocketSender {
    pub async fn send_to(&self, buf: &[u8], addr: DdpAddress) -> Result<(), Error> {
        self.send_to_typed(buf, addr, None, None).await
    }

    /// Like [`Self::send_to`], but stamps `protocol` on this datagram instead
    /// of the type the socket was opened with. Used to serve clients whose
    /// socket API carries the DDP type per datagram rather than per socket.
    ///
    /// `iface` restricts a `{0, 255}` broadcast to one cable; see
    /// [`DdpSocket::send_to_iface`].
    pub async fn send_to_typed(
        &self,
        buf: &[u8],
        addr: DdpAddress,
        protocol: Option<DdpProtocolType>,
        iface: Option<Interface>,
    ) -> Result<(), Error> {
        if buf.len() > 586 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "DDP payload length {} exceeds maximum allowed (586 bytes)",
                    buf.len()
                ),
            ));
        }
        match &self.sender {
            DdpSender::Local(sender) => {
                let pkt = OutboundPacket {
                    dest: addr,
                    payload: buf.into(),
                    src_sock: self.sock_num,
                    protocol: protocol.unwrap_or(self.protocol),
                    iface,
                };
                sender.send(DdpCommand::SendPkt(pkt)).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "DDP processor shut down")
                })?;
            }
            DdpSender::Remote(client) => {
                client
                    .send_datagram(self.sock_num, addr.addr, addr.sock, buf, iface)
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct DdpSocket {
    sock_num: u8,
    protocol: DdpProtocolType,
    receiver: mpsc::Receiver<Packet>,
    sender: DdpSender,
}

impl Drop for DdpSocket {
    fn drop(&mut self) {
        match &self.sender {
            DdpSender::Local(sender) => {
                let _ = sender.try_send(DdpCommand::Deregister(self.sock_num));
            }
            DdpSender::Remote(client) => client.close_socket(self.sock_num),
        }
    }
}

impl DdpSocket {
    pub async fn recv(&mut self) -> Result<Packet, io::Error> {
        let res = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;

        Ok(res)
    }

    pub async fn send_to(&self, buf: &[u8], addr: DdpAddress) -> Result<(), Error> {
        self.send_to_inner(buf, addr, None).await
    }

    /// Send a `{0, 255}` broadcast on one cable only, instead of on every
    /// configured interface.
    ///
    /// Needed whenever the payload itself names an address of ours — an NBP
    /// lookup's reply tuple, say — because that address differs per interface
    /// and only the one belonging to the cable the datagram goes out on is
    /// reachable by the nodes that receive it.
    pub async fn send_to_iface(
        &self,
        buf: &[u8],
        addr: DdpAddress,
        iface: Interface,
    ) -> Result<(), Error> {
        self.send_to_inner(buf, addr, Some(iface)).await
    }

    async fn send_to_inner(
        &self,
        buf: &[u8],
        addr: DdpAddress,
        iface: Option<Interface>,
    ) -> Result<(), Error> {
        if buf.len() > 586 {
            tracing::error!(
                "DDP payload length {} exceeds maximum allowed (586 bytes)",
                buf.len()
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "DDP payload length {} exceeds maximum allowed (586 bytes)",
                    buf.len()
                ),
            ));
        }

        match &self.sender {
            DdpSender::Local(sender) => {
                let pkt = OutboundPacket {
                    dest: addr,
                    payload: buf.into(),
                    src_sock: self.sock_num,
                    protocol: self.protocol,
                    iface,
                };
                sender.send(DdpCommand::SendPkt(pkt)).await.map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "DDP processor shut down")
                })?;
            }
            DdpSender::Remote(client) => {
                client
                    .send_datagram(self.sock_num, addr.addr, addr.sock, buf, iface)
                    .await?;
            }
        }

        Ok(())
    }

    /// Return a clone-able send-only handle for this socket.
    ///
    /// Use this to send datagrams from a separate task while the receive
    /// side remains on the original `DdpSocket`.
    pub fn send_handle(&self) -> DdpSocketSender {
        DdpSocketSender {
            sock_num: self.sock_num,
            protocol: self.protocol,
            sender: self.sender.clone(),
        }
    }

    pub fn socket_num(&self) -> u8 {
        self.sock_num
    }
}

type SockNum = u8;

/// Socket numbers available for dynamic assignment, 191 of them. Below 64 is
/// reserved for statically assigned sockets, and 255 is the broadcast socket.
pub const DYNAMIC_SOCKETS: std::ops::RangeInclusive<SockNum> = 64..=254;

pub struct DdpProcessor {
    sockets: HashMap<SockNum, mpsc::Sender<Packet>>,
    command_rx: mpsc::Receiver<DdpCommand>,
    command_tx: mpsc::Sender<DdpCommand>,
    ethertalk: OutboundHandle,
    et_addressing: Option<AddressingHandle>,
    lt_addressing: Option<AddressingHandle>,
    route_table: RouteTable,
}

impl DdpProcessor {
    async fn et_addr(&self) -> Result<AppleTalkAddress, Error> {
        if let Some(et) = &self.et_addressing {
            if let Some(watch) = et.addr_watch()
                && let Some(addr) = *watch.borrow() {
                    return Ok(addr);
                }
            et.addr().await
        } else {
            Err(Error::new(io::ErrorKind::NotFound, "no EtherTalk interface"))
        }
    }

    async fn lt_addr(&self) -> Result<AppleTalkAddress, Error> {
        if let Some(lt) = &self.lt_addressing {
            if let Some(watch) = lt.addr_watch()
                && let Some(addr) = *watch.borrow() {
                    return Ok(addr);
                }
            lt.addr().await
        } else {
            Err(Error::new(io::ErrorKind::NotFound, "no LocalTalk interface"))
        }
    }

    pub fn spawn(
        et_addressing: Option<AddressingHandle>,
        lt_addressing: Option<AddressingHandle>,
        ethertalk: OutboundHandle,
        route_table: RouteTable,
    ) -> DdpHandle {
        let (command_tx, command_rx) = mpsc::channel(100);

        let processor = Self {
            sockets: HashMap::new(),
            command_rx,
            command_tx: command_tx.clone(),
            ethertalk,
            et_addressing,
            lt_addressing,
            route_table,
        };

        tokio::spawn(async move { processor.run().await });

        DdpHandle {
            inner: DdpHandleInner::Local(command_tx),
        }
    }

    async fn run(mut self) {
        while let Some(command) = self.command_rx.recv().await {
            match command {
                DdpCommand::NewSocket(args) => {
                    let res = self.new_sock(args.protocol, args.sock_num);

                    args.response.send(res).expect("failed to send");
                }
                DdpCommand::ReceivedPkt(pkt) => {
                    self.handle_packet(pkt).await;
                }
                DdpCommand::SendPkt(pkt) => {
                    self.handle_outbound(pkt).await;
                }
                DdpCommand::Deregister(sock_num) => {
                    self.deregister(sock_num);
                }
            }
        }
    }

    /// Release a socket number on behalf of a dropped [`DdpSocket`].
    ///
    /// Ignored unless the registration is actually dead. Since `new_sock` reaps
    /// closed sockets itself, the number may already have been reissued by the
    /// time this is drained, and evicting that new owner would silently stop
    /// delivering their traffic. A `Sender` still open belongs to someone else.
    fn deregister(&mut self, sock_num: SockNum) {
        if self.sockets.get(&sock_num).is_some_and(|tx| tx.is_closed()) {
            self.sockets.remove(&sock_num);
        }
    }

    fn new_sock(
        &mut self,
        protocol: DdpProtocolType,
        sock_num: Option<SockNum>,
    ) -> Result<DdpSocket, io::Error> {
        // A socket whose owner is gone still holds its number until this runs:
        // `DdpSocket::drop` publishes `Deregister` with `try_send`, which is
        // dropped outright if the command channel is full. A closed `Sender`
        // here means the `DdpSocket` holding the matching `Receiver` is gone.
        self.sockets.retain(|_, tx| !tx.is_closed());

        let sock_num = if let Some(n) = sock_num {
            if self.sockets.contains_key(&n) {
                return Err(io::Error::from(io::ErrorKind::AddrInUse));
            }
            n
        } else {
            let mut rng = rand::rng();
            (0..DYNAMIC_SOCKETS.count())
                .map(|_| rng.random_range(DYNAMIC_SOCKETS))
                .find(|n| !self.sockets.contains_key(n))
                .ok_or_else(|| io::Error::from(io::ErrorKind::AddrInUse))?
        };

        let (tx, rx) = mpsc::channel(100);
        let sock = DdpSocket {
            protocol,
            sock_num,
            receiver: rx,
            sender: DdpSender::Local(self.command_tx.clone()),
        };

        self.sockets.insert(sock_num, tx);

        Ok(sock)
    }

    async fn handle_packet(&mut self, packet: DdpPacket) {
        // Auto-cache EtherTalk source addresses; LocalTalk is resolved directly by node number.
        let source_addr = AppleTalkAddress {
            network_number: packet.headers.src_network_num,
            node_number: packet.headers.src_node_id,
        };

        match packet.source {
            AppleTalkAddressSource::LocalTalk => {}
            _ => {
                if let Some(et) = &self.et_addressing
                    && et.try_lookup(&source_addr).is_none() {
                        let node = match packet.source {
                            AppleTalkAddressSource::EtherTalkPhase2 => Node::EtherTalkPhase2(packet.source_mac),
                            AppleTalkAddressSource::EtherTalkPhase1 => Node::EtherTalkPhase1(packet.source_mac),
                            AppleTalkAddressSource::LocalTalk => unreachable!(),
                        };
                        tracing::debug!(
                            "Learning new address from DDP packet: {}.{} ({:?})",
                            source_addr.network_number, source_addr.node_number, packet.source
                        );
                        et.learn(source_addr, node);
                }
            }
        }

        // Accept broadcast or any packet that matches one of our interface addresses.
        let dest = AppleTalkAddress {
            network_number: packet.headers.dest_network_num,
            node_number: packet.headers.dest_node_id,
        };
        let is_for_us = packet.headers.dest_node_id == 255 || {
            let mut matched = false;
            if self.et_addressing.is_some()
                && let Ok(our) = self.et_addr().await {
                    matched |= our.matches(&dest, packet.source);
            }
            if !matched
                && self.lt_addressing.is_some()
                && let Ok(our) = self.lt_addr().await {
                    matched |= our.matches(&dest, packet.source);
            }
            matched
        };

        if !is_for_us {
            return;
        }

        let sock_num = packet.headers.dest_sock_num;

        if let Some(socket) = self.sockets.get(&sock_num) {
            match socket.try_send(Packet {
                headers: packet.headers,
                payload: packet.payload,
                source: packet.source,
            }) {
                Ok(_) => {}
                Err(TrySendError::Closed(_)) => {
                    self.sockets.remove(&sock_num);
                }
                Err(TrySendError::Full(_)) => {
                    tracing::error!("sock is full!");
                }
            }
        } else {
            tracing::warn!("DDP no socket registered for sock_num {}", sock_num);
        }
    }

    /// Hand an outbound packet addressed to ourselves straight to the target
    /// local socket, synthesizing the headers a wire reception would carry.
    /// `source` is the link of the interface whose address matched.
    fn deliver_local(
        &mut self,
        packet: &OutboundPacket,
        our_addr: AppleTalkAddress,
        source: AppleTalkAddressSource,
    ) {
        let headers = DdpHeaders {
            hop_count: 0,
            len: packet.payload.len() + DdpHeaders::LEN,
            chksum: 0,
            dest_network_num: packet.dest.addr.network_number,
            dest_sock_num: packet.dest.sock,
            dest_node_id: packet.dest.addr.node_number,
            src_network_num: our_addr.network_number,
            src_sock_num: packet.src_sock,
            src_node_id: our_addr.node_number,
            protocol_typ: packet.protocol,
        };
        let sock_num = packet.dest.sock;
        if let Some(socket) = self.sockets.get(&sock_num) {
            match socket.try_send(Packet {
                headers,
                payload: packet.payload.clone(),
                source,
            }) {
                Ok(_) => {}
                Err(TrySendError::Closed(_)) => {
                    self.sockets.remove(&sock_num);
                }
                Err(TrySendError::Full(_)) => {
                    tracing::error!("sock is full!");
                }
            }
        } else {
            tracing::debug!("DDP: dropping loopback packet, no socket {}", sock_num);
        }
    }

    async fn handle_outbound(&mut self, packet: OutboundPacket) {
        // Network-wide broadcast {0, 255}: send on every configured interface so
        // all nodes on each cable receive it, regardless of their network number.
        // A caller that scoped the send to one cable gets only that one.
        if packet.dest.addr.network_number == 0 && packet.dest.addr.node_number == 255 {
            let wanted = |iface| packet.iface.is_none_or(|only| only == iface);
            let mut sent = false;
            if self.et_addressing.is_some() && wanted(Interface::EtherTalk) {
                let et_addr = self.et_addr().await.unwrap();
                let dest_node = Node::EtherTalkPhase2(Addressing::APPLETALK_BROADCAST_MULTICAST);
                self.send_ddp_to_node(&packet, dest_node, et_addr).await;
                sent = true;
            }
            if self.lt_addressing.is_some() && wanted(Interface::LocalTalk) {
                let lt_addr = self.lt_addr().await.unwrap();
                self.send_ddp_to_node(&packet, Node::LocalTalk(255), lt_addr).await;
                sent = true;
            }
            if !sent {
                tracing::error!(
                    "DDP: dropping packet to {}.{} — no interfaces configured{}",
                    packet.dest.addr.network_number,
                    packet.dest.addr.node_number,
                    match packet.iface {
                        Some(iface) => format!(" for the requested cable ({iface:?})"),
                        None => String::new(),
                    },
                );
            }
            return;
        }

        // A datagram addressed to one of our own interface addresses never
        // comes back off the wire (interfaces don't receive their own
        // frames), so deliver it to the local socket directly. Local clients
        // rely on this, e.g. to reach an NBP responder on their own node.
        // Address {0,0} ("any net, any node") conventionally means the node
        // itself — the kernel AppleTalk stacks loop it back the same way.
        // Network 0 acts as an "our net" wildcard only on links that natively
        // address with network 0 (LocalTalk, Phase 1 EtherTalk); on Phase 2
        // {0, N} names a node on such a cable, not us.
        let dest = packet.dest.addr;
        let to_self = dest.network_number == 0 && dest.node_number == 0;
        if let Some(et) = &self.et_addressing
            && let Ok(our) = self.et_addr().await
            && (to_self
                || (dest.node_number == our.node_number
                    && (dest.network_number == our.network_number
                        || (dest.network_number == 0
                            && et.phase != AppleTalkAddressSource::EtherTalkPhase2))))
        {
            self.deliver_local(&packet, our, et.phase);
            return;
        }
        if self.lt_addressing.is_some()
            && let Ok(our) = self.lt_addr().await
            && (to_self
                || (dest.node_number == our.node_number
                    && (dest.network_number == our.network_number || dest.network_number == 0)))
        {
            self.deliver_local(&packet, our, AppleTalkAddressSource::LocalTalk);
            return;
        }

        // Routing happens here, not in the caller: first resolve the
        // link-level next hop (the destination itself when it is on one of
        // our cables or unknown, otherwise the responsible router from the
        // route table), then pick the interface that reaches that hop. The
        // route table remembers which cable dynamic routes and local ranges
        // belong to; programmatic entries carry no tag, so the fallback
        // guesses from the address shape and what is configured.
        let (hop, route_iface) = if dest.network_number == 0 {
            // Network 0 is by definition on the local cable.
            (dest, None)
        } else {
            match self.route_table.resolve(dest.network_number) {
                Some(NextHop::Via { router, interface }) => (router, Some(interface)),
                // On our cable range, or no route known: try it directly.
                Some(NextHop::Local(interface)) => (dest, Some(interface)),
                None => (dest, None),
            }
        };

        let dest_node = match route_iface {
            Some(Interface::LocalTalk) if self.lt_addressing.is_some() => {
                Node::LocalTalk(hop.node_number)
            }
            Some(Interface::EtherTalk) if self.et_addressing.is_some() => {
                match self.et_addressing.as_ref().unwrap().lookup(hop).await {
                    Ok(node) => node,
                    Err(e) => {
                        tracing::error!(
                            "DDP: dropping packet to {}.{} — AARP lookup for next hop {}.{} failed: {e}",
                            dest.network_number, dest.node_number,
                            hop.network_number, hop.node_number,
                        );
                        return;
                    }
                }
            }
            // No (usable) interface recorded for this hop — fall back on the
            // address shape and the configured interfaces.
            _ if hop.network_number == 0 => {
                // Network 0 is ambiguous between LocalTalk and nonextended
                // (Phase 1) EtherTalk. With only one of the two configured,
                // there's nothing to disambiguate — it must be that one. With
                // both configured, check whether this node has actually been
                // learned as an EtherTalk Phase 1 peer (e.g. from a packet it
                // sent us); only fall back to LocalTalk if it hasn't.
                match (&self.lt_addressing, &self.et_addressing) {
                    (Some(_), None) => Node::LocalTalk(hop.node_number),
                    (None, Some(et)) => match et.try_lookup(&hop) {
                        Some(node) => node,
                        None => {
                            tracing::error!(
                                "DDP: dropping packet to {}.{} — next hop {}.{} is on network 0 but no EtherTalk Phase 1 binding is cached for it",
                                dest.network_number, dest.node_number,
                                hop.network_number, hop.node_number,
                            );
                            return;
                        }
                    },
                    (Some(_), Some(et)) => et.try_lookup(&hop).unwrap_or(Node::LocalTalk(hop.node_number)),
                    (None, None) => {
                        tracing::error!(
                            "DDP: dropping packet to {}.{} — next hop {}.{} is on network 0, but no interfaces are configured",
                            dest.network_number, dest.node_number,
                            hop.network_number, hop.node_number,
                        );
                        return;
                    }
                }
            }
            _ => {
                // Nonzero network, unknown cable: on a single-interface stack
                // the hop can only be on that interface. With both, try AARP
                // on EtherTalk first and treat silence as "must be the
                // LocalTalk cable".
                match (&self.lt_addressing, &self.et_addressing) {
                    (Some(_), None) => Node::LocalTalk(hop.node_number),
                    (None, Some(et)) | (Some(_), Some(et)) => match et.lookup(hop).await {
                        Ok(node) => node,
                        Err(e) if self.lt_addressing.is_some() => {
                            tracing::debug!(
                                "DDP: AARP found nothing for next hop {}.{} ({e}); assuming it is on the LocalTalk cable",
                                hop.network_number, hop.node_number,
                            );
                            Node::LocalTalk(hop.node_number)
                        }
                        Err(e) => {
                            tracing::error!(
                                "DDP: dropping packet to {}.{} — AARP lookup for next hop {}.{} failed: {e}",
                                dest.network_number, dest.node_number,
                                hop.network_number, hop.node_number,
                            );
                            return;
                        }
                    },
                    (None, None) => {
                        tracing::error!(
                            "DDP: dropping packet to {}.{} — no interfaces are configured",
                            dest.network_number, dest.node_number,
                        );
                        return;
                    }
                }
            }
        };

        let our_addr = match &dest_node {
            Node::LocalTalk(_) => self.lt_addr().await.unwrap(),
            _ => self.et_addr().await.unwrap(),
        };

        self.send_ddp_to_node(&packet, dest_node, our_addr).await;
    }

    async fn send_ddp_to_node(
        &self,
        packet: &OutboundPacket,
        dest_node: Node,
        our_addr: AppleTalkAddress,
    ) {
        // Short DDP (DDP-S, 5-byte header) is LocalTalk only, and only while
        // the segment is unrouted: it carries no network number, which is
        // fine in isolation but ambiguous once a router (seen via RTMP) puts
        // us in a multi-network topology. Once a router is known, switch to
        // long-form DDP even on LocalTalk, same as NBP switches to router
        // broadcast requests.
        let use_short = matches!(dest_node, Node::LocalTalk(_)) && !self.route_table.has_router();

        let header_len = if use_short { 5 } else { DdpHeaders::LEN };
        let headers = DdpHeaders {
            hop_count: 0,
            len: packet.payload.len() + header_len,
            chksum: 0,
            dest_network_num: packet.dest.addr.network_number,
            dest_sock_num: packet.dest.sock,
            dest_node_id: packet.dest.addr.node_number,
            src_network_num: our_addr.network_number,
            src_sock_num: packet.src_sock,
            src_node_id: our_addr.node_number,
            protocol_typ: packet.protocol,
        };

        let payload_len = header_len + packet.payload.len();
        let mut payload = vec![0u8; payload_len].into_boxed_slice();

        let header_size = if use_short {
            // Short DDP (LocalTalk) does not use checksums — leave chksum=0.
            headers
                .to_bytes_short(&mut payload)
                .expect("failed to encode short headers")
        } else {
            let size = headers
                .to_bytes(&mut payload)
                .expect("failed to encode headers");
            // Zero the checksum field before computing the checksum.
            payload[2] = 0;
            payload[3] = 0;
            size
        };

        payload[header_size..].copy_from_slice(&packet.payload);

        // Compute and insert DDP checksum for long DDP (EtherTalk).
        // Per the spec, the checksum covers bytes 4..end (everything after the
        // 4-byte hop/len+chksum fields). A result of 0 is replaced with 0xFFFF.
        if !use_short {
            let chksum = DdpHeaders::compute_checksum(&payload[4..]);
            payload[2] = (chksum >> 8) as u8;
            payload[3] = (chksum & 0xFF) as u8;
        }

        tracing::debug!("DDP: Sending packet with headers {:?}", headers);

        if let Err(e) = self
            .ethertalk
            .send(DataLinkPacket {
                dest_node,
                protocol: DataLinkProtocol::Ddp,
                payload,
                src_node_id: our_addr.node_number,
                ddp_long: !use_short,
            })
            .await
        {
            tracing::debug!("DDP: send dropped (stack shutting down): {e}");
        }
    }
}

struct SockArgs {
    protocol: DdpProtocolType,
    sock_num: Option<SockNum>,
    response: oneshot::Sender<Result<DdpSocket, Error>>,
}

struct DdpPacket {
    headers: DdpHeaders,
    payload: Box<[u8]>,
    source: AppleTalkAddressSource,
    source_mac: [u8; 6],
}

enum DdpCommand {
    NewSocket(SockArgs),
    ReceivedPkt(DdpPacket),
    SendPkt(OutboundPacket),
    Deregister(SockNum),
}

/// Handle to the DDP layer.
#[derive(Clone)]
pub struct DdpHandle {
    inner: DdpHandleInner,
}

#[derive(Clone)]
enum DdpHandleInner {
    Local(mpsc::Sender<DdpCommand>),
    Remote(RemoteClient),
}

impl DdpHandle {
    /// Create a handle whose sockets live in a remote daemon.
    pub(crate) fn remote(client: RemoteClient) -> Self {
        Self {
            inner: DdpHandleInner::Remote(client),
        }
    }

    pub async fn new_sock(
        &self,
        protocol: DdpProtocolType,
        sock_num: Option<SockNum>,
    ) -> Result<DdpSocket, Error> {
        match &self.inner {
            DdpHandleInner::Local(command) => {
                let (tx, rx) = oneshot::channel();

                let sock_args = SockArgs {
                    protocol,
                    sock_num,
                    response: tx,
                };

                command
                    .send(DdpCommand::NewSocket(sock_args))
                    .await
                    .expect("failed to send");

                rx.await.expect("no oneshot response")
            }
            DdpHandleInner::Remote(client) => {
                let (sock_num, receiver) = client.open_socket(protocol, sock_num).await?;
                Ok(DdpSocket {
                    sock_num,
                    protocol,
                    receiver,
                    sender: DdpSender::Remote(client.clone()),
                })
            }
        }
    }

    pub fn received_pkt(&self, pkt: &[u8], source: AppleTalkAddressSource, source_mac: [u8; 6]) {
        if let Ok(headers) = DdpHeaders::parse(pkt) {
            let payload = pkt[DdpHeaders::LEN..headers.len.min(pkt.len())].into();
            self.received_parsed_pkt(headers, payload, source, source_mac);
        }
    }

    pub fn received_parsed_pkt(
        &self,
        headers: DdpHeaders,
        payload: Box<[u8]>,
        source: AppleTalkAddressSource,
        source_mac: [u8; 6],
    ) {
        // Only meaningful when the underlay is in-process; a remote daemon
        // receives packets from its own interfaces.
        if let DdpHandleInner::Local(command) = &self.inner {
            let _ = command.try_send(DdpCommand::ReceivedPkt(DdpPacket {
                headers,
                payload,
                source,
                source_mac,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_table::LearningMode;

    /// A processor driven directly, so socket bookkeeping can be exercised
    /// without a runtime or any interfaces.
    fn processor() -> (DdpProcessor, mpsc::Receiver<DataLinkPacket>) {
        let (out_tx, out_rx) = mpsc::channel(16);
        let (command_tx, command_rx) = mpsc::channel(16);
        let processor = DdpProcessor {
            sockets: HashMap::new(),
            command_rx,
            command_tx,
            ethertalk: OutboundHandle::new(out_tx),
            et_addressing: None,
            lt_addressing: None,
            route_table: RouteTable::new(LearningMode::Static),
        };
        (processor, out_rx)
    }

    /// A dropped socket's number must come back even if its `Deregister` never
    /// arrives, since `DdpSocket::drop` publishes that with `try_send` and the
    /// command channel is shared with all packet traffic.
    #[test]
    fn a_dropped_socket_is_reaped_without_its_deregister() {
        let (mut p, _out_rx) = processor();

        let sock = p.new_sock(DdpProtocolType::Atp, Some(70)).unwrap();
        assert!(p.new_sock(DdpProtocolType::Atp, Some(70)).is_err());

        // Drop the socket but never deliver the Deregister it queued.
        drop(sock);

        assert!(
            p.new_sock(DdpProtocolType::Atp, Some(70)).is_ok(),
            "socket 70 was not reaped after its owner dropped"
        );
    }

    /// The reaping above means a `Deregister` can arrive after its number has
    /// already been reissued. Honouring it then would deregister an innocent
    /// socket, which on a live stack means a printer or server silently
    /// receiving nothing.
    #[test]
    fn a_stale_deregister_does_not_evict_the_new_owner() {
        let (mut p, _out_rx) = processor();

        let first = p.new_sock(DdpProtocolType::Atp, Some(70)).unwrap();
        drop(first);

        // Reissued to a new owner before the first owner's Deregister is drained.
        let second = p.new_sock(DdpProtocolType::Atp, Some(70)).unwrap();

        p.deregister(70);

        assert!(
            p.sockets.contains_key(&70),
            "a stale Deregister evicted the socket's new owner"
        );
        // Still wired to the live socket, not a leftover entry.
        assert!(!p.sockets.get(&70).unwrap().is_closed());
        drop(second);

        // And once that owner really is gone, the number is releasable again.
        p.deregister(70);
        assert!(!p.sockets.contains_key(&70));
    }
}
