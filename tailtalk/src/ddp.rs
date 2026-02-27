use rand::Rng;
use std::{
    collections::HashMap,
    io::{self, Error},
};
use tailtalk_packets::{
    aarp::{AddressSource as AppleTalkAddressSource, AppleTalkAddress},
    ddp::{DdpPacket as DdpHeaders, DdpProtocolType},
    ethertalk::EtherTalkType,
};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

use crate::{EtherTalkPacket, OutboundHandle, addressing::AddressingHandle};

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
    addressing: AddressingHandle,
}

impl DdpProcessor {
    pub fn spawn(addressing: AddressingHandle, ethertalk: OutboundHandle) -> DdpHandle {
        let (command_tx, command_rx) = mpsc::channel(100);

        let processor = Self {
            sockets: HashMap::new(),
            command_rx,
            command_tx: command_tx.clone(),
            ethertalk,
            addressing,
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
            let mut rng = rand::thread_rng();
            rng.gen_range(64..=255)
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
        let our_addr = self
            .addressing
            .addr()
            .await
            .expect("failed to get our addr");

        // Auto-cache the source address if we don't already know it
        let source_addr = AppleTalkAddress {
            network_number: packet.headers.src_network_num,
            node_number: packet.headers.src_node_id,
        };

        if self.addressing.try_lookup(&source_addr).is_none() {
            tracing::info!(
                "Learning new address from DDP packet: {}.{} -> {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ({})",
                source_addr.network_number,
                source_addr.node_number,
                packet.source_mac[0],
                packet.source_mac[1],
                packet.source_mac[2],
                packet.source_mac[3],
                packet.source_mac[4],
                packet.source_mac[5],
                match packet.source {
                    AppleTalkAddressSource::EtherTalk => "EtherTalk",
                    AppleTalkAddressSource::LocalTalk => "LocalTalk",
                }
            );
            // Cache it using the addressing handle's internal cache
            // We need to use the internal cache directly since try_lookup uses it
            self.addressing
                .cache
                .insert(source_addr, (packet.source_mac, packet.source));
        }

        // Accept packets addressed to us or broadcast (node 255)
        let is_for_us = packet.headers.dest_node_id == 255
            || our_addr.matches(
                &AppleTalkAddress {
                    network_number: packet.headers.dest_network_num,
                    node_number: packet.headers.dest_node_id,
                },
                packet.source,
            );

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
        let our_addr = self
            .addressing
            .addr()
            .await
            .expect("failed to get our addr");
        let (dst_mac, source_type) = self
            .addressing
            .lookup(packet.dest.addr)
            .await
            .expect("unknown addr");
        let headers = DdpHeaders {
            hop_count: 0,
            len: DdpHeaders::calc_len(&packet.payload) + 1,
            chksum: 0,
            dest_network_num: packet.dest.addr.network_number,
            dest_sock_num: packet.dest.sock,
            dest_node_id: packet.dest.addr.node_number,
            src_network_num: our_addr.network_number,
            src_sock_num: packet.src_sock,
            src_node_id: our_addr.node_number,
            protocol_typ: packet.protocol,
        };

        let payload_len = DdpHeaders::LEN + packet.payload.len();
        let mut payload = vec![0u8; payload_len].into_boxed_slice();
        let header_size = headers
            .to_bytes(&mut payload)
            .expect("failed to encode headers");

        payload[header_size..].copy_from_slice(&packet.payload);

        payload[2] = 0;
        payload[3] = 0;

        self.ethertalk
            .send(EtherTalkPacket {
                dst_mac,
                protocol: EtherTalkType::Ddp,
                payload,
                source_type,
            })
            .await
            .expect("failed to send");
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
            let payload = pkt[DdpHeaders::LEN..].into();

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
