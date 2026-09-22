//! Cross-test: the embedded StyleWriter printer role served to the desktop
//! `StyleWriterSession` client over an in-process DDP loopback.
//!
//! The desktop client half is verified against real StyleWriter hardware
//! (see tailtalk/src/stylewriter.rs), which makes it the best available
//! oracle for the printer side: if `StyleWriterSession::connect` +
//! `query_info` + teardown succeed against this role, the two-connection
//! handshake, the attention plumbing, and the byte pipe are all right.
//!
//! Since the desktop ADSP actor moved onto the shared tailtalk-core
//! engine, both sides of this test run the same connection machinery, so
//! it validates the io shells and the role logic rather than two
//! independent protocol implementations. The independent oracles that
//! remain are the raw-capture replay in tailtalk/tests/adsp_test.rs and
//! real hardware.
//!
//! Topology: a desktop stack with one EtherTalk-style interface at 1.5, and
//! the embedded role playing a printer at 1.77 socket 129. A bridge task
//! shuttles DDP payloads between the desktop's outbound queue and the role,
//! and simulates a serial StyleWriter (identity "CS", submodel 2400, color
//! cartridge) behind the role's UART events.

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, Node},
    adsp::AdspAddress,
    ddp::DdpProcessor,
    route_table::{LearningMode, RouteTable},
    stylewriter::StyleWriterSession,
};
use tailtalk_core::stylewriter::{StyleWriterEvent, StyleWriterRole};
use tailtalk_packets::aarp::{AddressSource, AppleTalkAddress};
use tailtalk_packets::ddp::{DdpPacket as DdpHeaders, DdpProtocolType};
use tailtalk_packets::nbp::ServiceAddress;
use tokio::sync::mpsc;

const DESKTOP_ADDR: AppleTalkAddress = AppleTalkAddress {
    network_number: 1,
    node_number: 5,
};
const PRINTER_ADDR: AppleTalkAddress = AppleTalkAddress {
    network_number: 1,
    node_number: 77,
};
const PRINTER_CTRL_SOCKET: u8 = 129;
const DESKTOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 5];
const PRINTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 77];

/// A minimal serial Color StyleWriter 2400: answers `?` with "CS\r" and the
/// `FF FF FF <q>` status queries with the values a healthy printer shows.
/// Everything else (mode strings, 'D', 'L', raster, resets) is swallowed.
#[derive(Default)]
struct PrinterSim {
    buf: Vec<u8>,
}

impl PrinterSim {
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
                        b'H' => out.push(0x81), // color cartridge installed
                        b'1' => out.push(0x00),
                        b'2' => out.push(0x80), // nothing wrong
                        b'B' => out.push(0xA3), // idle, paper loaded
                        _ => {}                 // 'I', 'S': no reply
                    }
                    i += 4;
                }
                0xFF => break, // incomplete FF-escape, wait for more bytes
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

/// Spawn the embedded role in its own task, bridged to the desktop stack.
/// Returns a receiver of the role's job lifecycle events.
fn spawn_printer(
    mut out_rx: mpsc::Receiver<DataLinkPacket>,
    ddp: tailtalk::ddp::DdpHandle,
) -> mpsc::UnboundedReceiver<StyleWriterEvent> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut role = StyleWriterRole::new(PRINTER_CTRL_SOCKET, 0xC0FFEE);
        let mut sim = PrinterSim::default();
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
        loop {
            let now = start.elapsed().as_micros() as u64;
            tokio::select! {
                pkt = out_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    if pkt.protocol != DataLinkProtocol::Ddp {
                        continue;
                    }
                    let Ok(headers) = DdpHeaders::parse(&pkt.payload) else {
                        continue;
                    };
                    if headers.dest_node_id != PRINTER_ADDR.node_number
                        || headers.dest_sock_num != PRINTER_CTRL_SOCKET
                    {
                        continue;
                    }
                    let end = headers.len.min(pkt.payload.len());
                    let src = ServiceAddress {
                        network_number: headers.src_network_num,
                        node_number: headers.src_node_id,
                        socket_number: headers.src_sock_num,
                    };
                    role.handle_datagram(src, &pkt.payload[DdpHeaders::LEN..end], now);
                }
                _ = tick.tick() => {
                    role.poll(now);
                }
            }

            // Printer side: feed the sim, return its replies.
            while let Some(ev) = role.poll_event() {
                match ev {
                    StyleWriterEvent::ToPrinter(bytes) => {
                        let reply = sim.feed(&bytes);
                        if !reply.is_empty() {
                            role.printer_input(&reply);
                        }
                    }
                    other => {
                        let _ = event_tx.send(other);
                    }
                }
            }

            // Network side: inject the role's transmits into the desktop
            // stack as received packets.
            while let Some((dest, payload)) = role.poll_transmit() {
                let headers = DdpHeaders {
                    hop_count: 0,
                    len: DdpHeaders::LEN + payload.len(),
                    chksum: 0,
                    dest_network_num: dest.network_number,
                    dest_node_id: dest.node_number,
                    dest_sock_num: dest.socket_number,
                    src_network_num: PRINTER_ADDR.network_number,
                    src_node_id: PRINTER_ADDR.node_number,
                    src_sock_num: PRINTER_CTRL_SOCKET,
                    protocol_typ: DdpProtocolType::Adsp,
                };
                ddp.received_parsed_pkt(
                    headers,
                    payload.into_boxed_slice(),
                    AddressSource::EtherTalkPhase2,
                    PRINTER_MAC,
                );
            }
        }
    });
    event_rx
}

#[tokio::test]
async fn embedded_stylewriter_serves_desktop_session() {
    let (out_tx, out_rx) = mpsc::channel(256);
    let outbound = OutboundHandle::new(out_tx);

    let addressing = Addressing::spawn(
        Some(DESKTOP_MAC),
        outbound.clone(),
        Some(DESKTOP_ADDR),
        AddressSource::EtherTalkPhase2,
    );
    // Teach the desktop where the printer lives so no AARP round trip is
    // needed (the bridge does not implement AARP).
    addressing.learn(PRINTER_ADDR, Node::EtherTalkPhase2(PRINTER_MAC));

    let ddp = DdpProcessor::spawn(
        Some(addressing.clone()),
        None,
        outbound.clone(),
        RouteTable::new(LearningMode::Static),
    );

    let mut events = spawn_printer(out_rx, ddp.clone());

    let printer = AdspAddress {
        network_number: PRINTER_ADDR.network_number,
        node_number: PRINTER_ADDR.node_number,
        socket_number: PRINTER_CTRL_SOCKET,
    };

    // The full two-connection handshake: control connect, attention 0x000B,
    // in-band accept, control close, reverse data connection.
    let mut session = StyleWriterSession::connect(&ddp, printer, "CrossTest")
        .await
        .expect("StyleWriter handshake against embedded role failed");

    match events.recv().await {
        Some(StyleWriterEvent::JobStarted { user }) => assert_eq!(user, b"CrossTest"),
        other => panic!("expected JobStarted, got {other:?}"),
    }

    // Identify the simulated printer through the byte pipe.
    let info = session.query_info().await.expect("query_info failed");
    assert_eq!(info.identity, "CS");
    assert_eq!(info.model_name(), "Apple Color StyleWriter 2400");
    assert!(info.color_capable());
    assert!(!info.out_of_paper());
    assert_eq!(info.buffer_idle(), Some(true));

    // Clean teardown: in-band reset bytes, kill attention, close.
    session.abort().await.expect("teardown failed");

    match events.recv().await {
        Some(StyleWriterEvent::JobEnded { clean }) => assert!(clean, "teardown must be clean"),
        other => panic!("expected JobEnded, got {other:?}"),
    }
}
