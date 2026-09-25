//! Test plumbing: a tokio [`Platform`], an in-memory LocalTalk cable, a
//! bridge onto the desktop stack, and simulated printer ports.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_async::{ErrorType, Read, Write};
use tailtalk::addressing::{Addressing, Node};
use tailtalk::ddp::{DdpHandle, DdpProcessor};
use tailtalk::route_table::{LearningMode, RouteTable};
use tailtalk::{DataLinkPacket, DataLinkProtocol, OutboundHandle};
use tailtalk_net::{AppleTalkAddress, Link, Micros, Net, NetState, Platform, StackConfig};
use tailtalk_packets::aarp::AddressSource;
use tailtalk_packets::ddp::{DdpPacket as DdpHeaders, DdpProtocolType};
use tokio::sync::mpsc;

pub struct Tokio;

fn epoch() -> tokio::time::Instant {
    static EPOCH: OnceLock<tokio::time::Instant> = OnceLock::new();
    *EPOCH.get_or_init(tokio::time::Instant::now)
}

impl Platform for Tokio {
    type Mutex = NoopRawMutex;

    fn now() -> Micros {
        tokio::time::Instant::now()
            .duration_since(epoch())
            .as_micros() as Micros
    }

    fn sleep_until(deadline: Micros) -> impl Future<Output = ()> {
        tokio::time::sleep_until(epoch() + Duration::from_micros(deadline))
    }
}

/// Start a node on `link` and spawn its runner. Must be called inside a
/// `LocalSet`: the state uses a no-op mutex, so nothing here is `Send`.
pub fn start<L: Link + 'static>(seed: u32, link: L) -> Net<'static, Tokio> {
    let state = Box::leak(Box::new(NetState::<Tokio>::new(StackConfig {
        seed,
        // Nothing on these test cables answers ENQs in hardware.
        auto_ack_enq: true,
        ..Default::default()
    })));
    let (net, mut runner) = tailtalk_net::new(state, link);
    tokio::task::spawn_local(async move { runner.run().await });
    net
}

/// One tap on a shared in-memory cable. LocalTalk is a bus, so every frame
/// reaches every other tap and the stacks filter by destination.
pub struct CablePort {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    peers: Vec<mpsc::UnboundedSender<Vec<u8>>>,
}

pub fn cable(taps: usize) -> Vec<CablePort> {
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..taps).map(|_| mpsc::unbounded_channel()).unzip();
    rxs.into_iter()
        .enumerate()
        .map(|(i, rx)| CablePort {
            rx,
            peers: txs
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != i)
                .map(|(_, tx)| tx.clone())
                .collect(),
        })
        .collect()
}

impl Link for CablePort {
    async fn receive(&mut self, buf: &mut [u8]) -> usize {
        let frame = self.rx.recv().await.expect("cable cut");
        buf[..frame.len()].copy_from_slice(&frame);
        frame.len()
    }

    async fn transmit(&mut self, frame: &[u8]) {
        for peer in &self.peers {
            let _ = peer.send(frame.to_vec());
        }
    }
}

// ── The desktop stack, bridged onto a LocalTalk link ─────────────────

/// The cable's network number, announced by a fake router so both sides
/// use long-form DDP with real network numbers.
pub const NETWORK: u16 = 2;
pub const DESKTOP_ADDR: AppleTalkAddress = AppleTalkAddress {
    network_number: NETWORK,
    node_number: 5,
};
const ROUTER_NODE: u8 = 254;
const DESKTOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 5];
const PRINTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 77];

pub struct Desktop {
    pub ddp: DdpHandle,
    addressing: tailtalk::addressing::AddressingHandle,
}

impl Desktop {
    /// Tell the desktop where the node lives, as the bridge does no AARP.
    pub fn learn(&self, addr: AppleTalkAddress) {
        self.addressing.learn(addr, Node::EtherTalkPhase2(PRINTER_MAC));
    }
}

/// A desktop stack, and the link that bridges it to a `tailtalk-net` node.
pub fn desktop() -> (Desktop, BridgeLink) {
    let (out_tx, out_rx) = mpsc::channel(256);
    let outbound = OutboundHandle::new(out_tx);
    let addressing = Addressing::spawn(
        Some(DESKTOP_MAC),
        outbound.clone(),
        Some(DESKTOP_ADDR),
        AddressSource::EtherTalkPhase2,
    );
    let ddp = DdpProcessor::spawn(
        Some(addressing.clone()),
        None,
        outbound,
        RouteTable::new(LearningMode::Static),
    );
    let link = BridgeLink {
        from_desktop: out_rx,
        ddp: ddp.clone(),
        acquired: false,
        announced: false,
    };
    (Desktop { ddp, addressing }, link)
}

/// Frames the desktop's DDP output as LLAP for the node, and the node's
/// LLAP output as DDP for the desktop.
pub struct BridgeLink {
    from_desktop: mpsc::Receiver<DataLinkPacket>,
    ddp: DdpHandle,
    acquired: bool,
    announced: bool,
}

/// An AsanteTalk-style RTMP broadcast from `ROUTER_NODE` announcing
/// `NETWORK`.
fn rtmp_announcement() -> Vec<u8> {
    let payload = [0x00, NETWORK as u8, 0x08, ROUTER_NODE, 0x00, 0x00, 0x82, 0x00, 0x02, 0x00];
    let ddp = tailtalk_core::ddp::encode_ddp(
        true,
        AppleTalkAddress { network_number: 0, node_number: ROUTER_NODE },
        1,
        AppleTalkAddress { network_number: 0, node_number: 255 },
        1,
        DdpProtocolType::RtmpResponse,
        &payload,
    );
    let mut frame = vec![0xFF, ROUTER_NODE, 1];
    frame.extend_from_slice(&ddp);
    frame
}

impl Link for BridgeLink {
    async fn receive(&mut self, buf: &mut [u8]) -> usize {
        // A node ignores everything above LLAP until it has an address, so
        // the router speaks up only once it does.
        if self.acquired && !self.announced {
            self.announced = true;
            let frame = rtmp_announcement();
            buf[..frame.len()].copy_from_slice(&frame);
            return frame.len();
        }
        loop {
            let pkt = self.from_desktop.recv().await.expect("desktop stack gone");
            if pkt.protocol != DataLinkProtocol::Ddp {
                continue;
            }
            let Ok(headers) = DdpHeaders::parse(&pkt.payload) else {
                continue;
            };
            let end = headers.len.min(pkt.payload.len());
            let dst = if headers.dest_node_id == 255 { 0xFF } else { headers.dest_node_id };
            buf[0] = dst;
            buf[1] = headers.src_node_id;
            buf[2] = 2; // LLAP DDP, long form
            buf[3..3 + end].copy_from_slice(&pkt.payload[..end]);
            return 3 + end;
        }
    }

    async fn transmit(&mut self, frame: &[u8]) {
        let (dst, src, kind) = (frame[0], frame[1], frame[2]);
        let body = &frame[3..];
        let (mut headers, header_len) = match kind {
            1 => match DdpHeaders::parse_short(body, dst, src) {
                Ok(h) => (h, 5),
                Err(_) => return,
            },
            2 => match DdpHeaders::parse(body) {
                Ok(h) => (h, DdpHeaders::LEN),
                Err(_) => return,
            },
            // ENQ/ACK stay on the cable.
            _ => return,
        };
        let end = headers.len.min(body.len());
        if headers.src_network_num == 0 {
            headers.src_network_num = NETWORK;
            headers.dest_network_num = NETWORK;
        }
        // A short header was just widened to a long one, so the length
        // must count the long header.
        headers.len = DdpHeaders::LEN + (end - header_len);
        self.ddp.received_parsed_pkt(
            headers,
            body[header_len..end].to_vec().into_boxed_slice(),
            AddressSource::EtherTalkPhase2,
            PRINTER_MAC,
        );
    }

    fn node_acquired(&mut self, _node: u8) {
        self.acquired = true;
    }
}

/// Wait until the node has its address and has heard the router, and let
/// the desktop know where it is.
pub async fn settle(net: Net<'static, Tokio>, desktop: &Desktop) -> AppleTalkAddress {
    net.wait_address().await;
    loop {
        let addr = net.address().unwrap();
        if addr.network_number == NETWORK {
            assert_ne!(addr.node_number, ROUTER_NODE, "pick a seed that avoids the fake router");
            desktop.learn(addr);
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

// ── Simulated printer ports ──────────────────────────────────────────

/// What a printer does with the bytes it is sent: returns its replies.
pub trait Model: Send + 'static {
    fn feed(&mut self, input: &[u8]) -> Vec<u8>;
}

/// The printer end of a port: everything written, in order, and a model
/// answering it.
pub struct PortTx<M: Model> {
    pub written: Arc<Mutex<Vec<u8>>>,
    model: Arc<Mutex<M>>,
    replies: mpsc::UnboundedSender<Vec<u8>>,
    /// Simulated line time per write, for flow-control tests.
    pub delay: Option<Duration>,
}

pub struct PortRx {
    replies: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: VecDeque<u8>,
}

pub fn port<M: Model>(model: M) -> (PortTx<M>, PortRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        PortTx {
            written: Arc::default(),
            model: Arc::new(Mutex::new(model)),
            replies: tx,
            delay: None,
        },
        PortRx {
            replies: rx,
            pending: VecDeque::new(),
        },
    )
}

impl<M: Model> ErrorType for PortTx<M> {
    type Error = Infallible;
}

impl<M: Model> Write for PortTx<M> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Infallible> {
        if let Some(d) = self.delay {
            tokio::time::sleep(d).await;
        }
        self.written.lock().unwrap().extend_from_slice(buf);
        let reply = self.model.lock().unwrap().feed(buf);
        if !reply.is_empty() {
            let _ = self.replies.send(reply);
        }
        Ok(buf.len())
    }
}

impl ErrorType for PortRx {
    type Error = Infallible;
}

impl Read for PortRx {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Infallible> {
        if self.pending.is_empty() {
            // Cancel safe: a chunk is either still in the channel or
            // already moved into `pending`, never held across the await.
            let chunk = self.replies.recv().await.unwrap_or_default();
            self.pending.extend(chunk);
        }
        let n = buf.len().min(self.pending.len());
        for (dst, b) in buf.iter_mut().zip(self.pending.drain(..n)) {
            *dst = b;
        }
        Ok(n)
    }
}

/// A printer that never answers.
pub struct Silent;

impl Model for Silent {
    fn feed(&mut self, _: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

/// An ImageWriter II: answers the self ID query with `ident`.
pub struct ImageWriterModel {
    pub ident: Arc<Mutex<&'static [u8]>>,
}

impl Model for ImageWriterModel {
    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        if input == tailtalk_core::imagewriter::SELF_ID {
            self.ident.lock().unwrap().to_vec()
        } else {
            Vec::new()
        }
    }
}

/// A serial Color StyleWriter 2400: answers `?` with "CS\r" and the
/// `FF FF FF <q>` status queries with what a healthy printer shows.
#[derive(Default)]
pub struct StyleWriterModel {
    buf: Vec<u8>,
}

impl Model for StyleWriterModel {
    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(input);
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.buf.len() {
            match self.buf[i] {
                0xFF if self.buf.len() >= i + 4
                    && self.buf[i + 1] == 0xFF
                    && self.buf[i + 2] == 0xFF =>
                {
                    match self.buf[i + 3] {
                        b'p' => out.push(0x01), // CS submodel: 2400
                        b'H' => out.push(0x81), // colour cartridge installed
                        b'1' => out.push(0x00),
                        b'2' => out.push(0x80), // nothing wrong
                        b'B' => out.push(0xA3), // idle, paper loaded
                        _ => {}                 // 'I', 'S': no reply
                    }
                    i += 4;
                }
                0xFF => break, // incomplete escape, wait for more
                b'?' => {
                    out.extend_from_slice(b"CS\r");
                    i += 1;
                }
                _ => i += 1,
            }
        }
        self.buf.drain(..i);
        out
    }
}
