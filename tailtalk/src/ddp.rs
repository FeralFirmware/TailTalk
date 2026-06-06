use rand::Rng;
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
};

pub struct Packet {
    pub headers: DdpHeaders,
    pub payload: Box<[u8]>,
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
}

#[derive(Debug)]
pub struct DdpSocket {
    sock_num: u8,
    protocol: DdpProtocolType,
    receiver: mpsc::Receiver<Packet>,
    sender: mpsc::Sender<DdpCommand>,
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

        let pkt = OutboundPacket {
            dest: addr,
            payload: buf.into(),
            src_sock: self.sock_num,
            protocol: self.protocol,
        };
        self.sender
            .send(DdpCommand::SendPkt(pkt))
            .await
            .expect("failed to ddp send");

        Ok(())
    }

    pub fn socket_num(&self) -> u8 {
        self.sock_num
    }
}

type SockNum = u8;

pub struct DdpProcessor {
    sockets: HashMap<SockNum, mpsc::Sender<Packet>>,
    command_rx: mpsc::Receiver<DdpCommand>,
    command_tx: mpsc::Sender<DdpCommand>,
    ethertalk: OutboundHandle,
    et_addressing: Option<AddressingHandle>,
    lt_addressing: Option<AddressingHandle>,
}

impl DdpProcessor {
    pub fn spawn(
        et_addressing: Option<AddressingHandle>,
        lt_addressing: Option<AddressingHandle>,
        ethertalk: OutboundHandle,
    ) -> DdpHandle {
        let (command_tx, command_rx) = mpsc::channel(100);

        let processor = Self {
            sockets: HashMap::new(),
            command_rx,
            command_tx: command_tx.clone(),
            ethertalk,
            et_addressing,
            lt_addressing,
        };

        tokio::spawn(async move { processor.run().await });

        DdpHandle {
            command: command_tx,
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
            }
        }
    }

    fn new_sock(
        &mut self,
        protocol: DdpProtocolType,
        sock_num: Option<SockNum>,
    ) -> Result<DdpSocket, io::Error> {
        let sock_num = sock_num.unwrap_or_else(|| {
            rand::rng().random_range(64..=255)
        });

        if self.sockets.contains_key(&sock_num) {
            return Err(io::Error::from(io::ErrorKind::AddrInUse));
        }

        let (tx, rx) = mpsc::channel(100);
        let sock = DdpSocket {
            protocol,
            sock_num,
            receiver: rx,
            sender: self.command_tx.clone(),
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
            if let Some(et) = &self.et_addressing
                && let Ok(our) = et.addr().await {
                    matched |= our.matches(&dest, packet.source);
            }
            if !matched
                && let Some(lt) = &self.lt_addressing
                && let Ok(our) = lt.addr().await {
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

    async fn handle_outbound(&mut self, packet: OutboundPacket) {
        // Network-wide broadcast {0, 255}: send on every configured interface so
        // all nodes on each cable receive it, regardless of their network number.
        if packet.dest.addr.network_number == 0 && packet.dest.addr.node_number == 255 {
            let mut sent = false;
            if let Some(et) = &self.et_addressing {
                let et_addr = et.addr().await.unwrap();
                let dest_node = Node::EtherTalkPhase2(Addressing::APPLETALK_BROADCAST_MULTICAST);
                self.send_ddp_to_node(&packet, dest_node, et_addr).await;
                sent = true;
            }
            if let Some(lt) = &self.lt_addressing {
                let lt_addr = lt.addr().await.unwrap();
                self.send_ddp_to_node(&packet, Node::LocalTalk(255), lt_addr).await;
                sent = true;
            }
            if !sent {
                tracing::error!(
                    "DDP: dropping packet to {}.{} — no interfaces configured",
                    packet.dest.addr.network_number,
                    packet.dest.addr.node_number,
                );
            }
            return;
        }

        let dest_node = if packet.dest.addr.network_number == 0 {
            if self.lt_addressing.is_none() {
                tracing::error!(
                    "DDP: dropping packet to {}.{} — LocalTalk (network 0) not configured",
                    packet.dest.addr.network_number,
                    packet.dest.addr.node_number,
                );
                return;
            }
            Node::LocalTalk(packet.dest.addr.node_number)
        } else {
            let Some(et) = &self.et_addressing else {
                tracing::error!(
                    "DDP: dropping packet to {}.{} — EtherTalk not configured",
                    packet.dest.addr.network_number,
                    packet.dest.addr.node_number,
                );
                return;
            };
            et.lookup(packet.dest.addr).await.expect("unknown addr")
        };

        let our_addr = match &dest_node {
            Node::LocalTalk(_) => self.lt_addressing.as_ref().unwrap().addr().await.unwrap(),
            _ => self.et_addressing.as_ref().unwrap().addr().await.unwrap(),
        };

        self.send_ddp_to_node(&packet, dest_node, our_addr).await;
    }

    async fn send_ddp_to_node(
        &self,
        packet: &OutboundPacket,
        dest_node: Node,
        our_addr: AppleTalkAddress,
    ) {
        // Short DDP (DDP-S, 5-byte header) is LocalTalk only.
        let use_short = matches!(dest_node, Node::LocalTalk(_));

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
}

#[derive(Clone)]
pub struct DdpHandle {
    command: mpsc::Sender<DdpCommand>,
}

impl DdpHandle {
    pub async fn new_sock(
        &self,
        protocol: DdpProtocolType,
        sock_num: Option<SockNum>,
    ) -> Result<DdpSocket, Error> {
        let (tx, rx) = oneshot::channel();

        let sock_args = SockArgs {
            protocol,
            sock_num,
            response: tx,
        };

        self.command
            .send(DdpCommand::NewSocket(sock_args))
            .await
            .expect("failed to send");

        rx.await.expect("no oneshot response")
    }

    pub fn received_pkt(&self, pkt: &[u8], source: AppleTalkAddressSource, source_mac: [u8; 6]) {
        if let Ok(headers) = DdpHeaders::parse(pkt) {
            let payload = pkt[DdpHeaders::LEN..headers.len.min(pkt.len())].into();

            let _ = self.command.try_send(DdpCommand::ReceivedPkt(DdpPacket {
                headers,
                payload,
                source,
                source_mac,
            }));
        }
    }

    pub fn received_parsed_pkt(
        &self,
        headers: DdpHeaders,
        payload: Box<[u8]>,
        source: AppleTalkAddressSource,
        source_mac: [u8; 6],
    ) {
        let _ = self.command.try_send(DdpCommand::ReceivedPkt(DdpPacket {
            headers,
            payload,
            source,
            source_mac,
        }));
    }
}
