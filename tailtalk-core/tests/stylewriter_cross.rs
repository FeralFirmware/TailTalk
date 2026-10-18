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
//! and simulates a serial StyleWriter behind the role's UART events (a Color
//! StyleWriter 2200 with a color cartridge, or a StyleWriter II), recording
//! every command it is sent.

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, Node},
    adsp::AdspAddress,
    ddp::DdpProcessor,
    route_table::{LearningMode, RouteTable},
    stylewriter::{
        BandKind, Imager, JobOptions, Page, PaperType, Pixels, PrintQuality, RawBand, Rendering, StyleWriterFamily,
        StyleWriterSession, encode_band,
    },
};
use tailtalk_core::stylewriter::{FastClock, StyleWriterEvent, StyleWriterRole};
use tailtalk_packets::aarp::{AddressSource, AppleTalkAddress};
use tailtalk_packets::ddp::{DdpPacket as DdpHeaders, DdpProtocolType};
use tailtalk_packets::nbp::ServiceAddress;
use std::sync::{Arc, Mutex};
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

/// One thing the simulated printer was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Sent {
    /// `FF FF FF <q>`.
    Query(u8),
    /// A rect, with its tag (`R` or `c`), its left edge and its top row.
    Rect { tag: u8, left: u16, top: u16 },
    /// A G block's raster bytes.
    Raster(Vec<u8>),
    /// Any other command, `m` with its digit.
    Command(Vec<u8>),
}

/// A minimal serial StyleWriter. It answers `?` with its identity and the `FF
/// FF FF <q>` status queries with the values a healthy, idle printer shows, and
/// records everything it is sent, with rects and raster blocks parsed out
/// whole.
struct PrinterSim {
    /// The reply to `?`, CR included.
    identity: &'static [u8],
    /// What 'B' reads with the buffer empty.
    idle_buffer: u8,
    buf: Vec<u8>,
    sent: Arc<Mutex<Vec<Sent>>>,
}

/// A Color StyleWriter 2200 with a color cartridge, paper loaded.
const CS2200: (&[u8], u8) = (b"CS\r", 0xA3);
/// A StyleWriter II, taken to read 0xF8 when its buffer is empty.
const SW_II: (&[u8], u8) = (b"SW\r", 0xF8);

impl PrinterSim {
    fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(input);
        let mut out = Vec::new();
        let mut sent = self.sent.lock().unwrap();
        let mut i = 0;
        while i < self.buf.len() {
            let rest = &self.buf[i..];
            let (used, item) = match rest[0] {
                0xFF if rest.len() < 4 => break, // incomplete FF-escape
                0xFF if rest[1] == 0xFF && rest[2] == 0xFF => {
                    match rest[3] {
                        b'p' => out.push(0x02), // CS submodel: 2200
                        b'H' => out.push(0x81), // color cartridge installed
                        b'1' => out.push(0x08), // everything printed
                        b'2' => out.push(0x00), // nothing wrong
                        b'B' => out.push(self.idle_buffer),
                        b'R' => out.push(0x50),
                        _ => {}                 // 'I', 'S': no reply
                    }
                    (4, Sent::Query(rest[3]))
                }
                b'?' => {
                    out.extend_from_slice(self.identity);
                    (1, Sent::Command(vec![b'?']))
                }
                b'R' | b'c' if rest.len() < 9 => break,
                b'R' | b'c' => (
                    9,
                    Sent::Rect {
                        tag: rest[0],
                        left: u16::from_le_bytes([rest[1], rest[2]]),
                        top: u16::from_le_bytes([rest[3], rest[4]]),
                    },
                ),
                b'G' if rest.len() < 3 => break,
                b'G' => {
                    let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
                    if rest.len() < 3 + len + 1 {
                        break;
                    }
                    (3 + len + 1, Sent::Raster(rest[3..3 + len].to_vec()))
                }
                b'm' if rest.len() < 2 => break,
                b'm' => (2, Sent::Command(rest[..2].to_vec())),
                other => (1, Sent::Command(vec![other])),
            };
            sent.push(item);
            i += used;
        }
        drop(sent);
        self.buf.drain(..i);
        out
    }
}

/// Spawn the embedded role in its own task, bridged to the desktop stack.
/// Returns a receiver of the role's job lifecycle events.
fn spawn_printer(
    mut out_rx: mpsc::Receiver<DataLinkPacket>,
    ddp: tailtalk::ddp::DdpHandle,
    (identity, idle_buffer): (&'static [u8], u8),
    fast_clock: FastClock,
    sent: Arc<Mutex<Vec<Sent>>>,
) -> mpsc::UnboundedReceiver<StyleWriterEvent> {
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut role = StyleWriterRole::new(PRINTER_CTRL_SOCKET, 0xC0FFEE, fast_clock);
        let mut sim = PrinterSim { identity, idle_buffer, buf: Vec::new(), sent };
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

/// A desktop stack wired to the embedded role, and the printer's record of
/// what it was sent.
struct Bench {
    ddp: tailtalk::ddp::DdpHandle,
    events: mpsc::UnboundedReceiver<StyleWriterEvent>,
    printer: AdspAddress,
    sent: Arc<Mutex<Vec<Sent>>>,
}

fn bench() -> Bench {
    bench_on(CS2200, FastClock::Unsupported)
}

/// [`bench`], with the printer `model` behind the role, behind a port that can
/// or cannot follow the printer's fast clock.
fn bench_on(model: (&'static [u8], u8), fast_clock: FastClock) -> Bench {
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

    let sent = Arc::new(Mutex::new(Vec::new()));
    let events = spawn_printer(out_rx, ddp.clone(), model, fast_clock, sent.clone());

    let printer = AdspAddress {
        network_number: PRINTER_ADDR.network_number,
        node_number: PRINTER_ADDR.node_number,
        socket_number: PRINTER_CTRL_SOCKET,
    };
    Bench { ddp, events, printer, sent }
}

#[tokio::test]
async fn embedded_stylewriter_serves_desktop_session() {
    let Bench { ddp, mut events, printer, .. } = bench();

    // The full two-connection handshake: control connect, attention 0x000B,
    // in-band accept, control close, reverse data connection.
    let mut session = StyleWriterSession::connect(&ddp, printer, "CrossTest", None)
        .await
        .expect("StyleWriter handshake against embedded role failed");

    match events.recv().await {
        Some(StyleWriterEvent::JobStarted { user }) => assert_eq!(user, b"CrossTest"),
        other => panic!("expected JobStarted, got {other:?}"),
    }

    // Identify the simulated printer through the byte pipe.
    let info = session.query_info().await.expect("query_info failed");
    assert_eq!(info.identity, "CS");
    assert_eq!(info.model_name(), "Apple Color StyleWriter 2200");
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

fn rgb_page(width: usize, height: usize, pixel: impl Fn(usize, usize) -> [u8; 3]) -> Page {
    let mut pixels = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            pixels.extend_from_slice(&pixel(x, y));
        }
    }
    Page { width, height, pixels: Pixels::Rgb(pixels) }
}

/// The commands a job sent the printer, in order, with rects and blocks as
/// their letters and status queries left out.
fn commands(sent: &[Sent]) -> Vec<Vec<u8>> {
    sent.iter()
        .filter_map(|s| match s {
            Sent::Command(c) => Some(c.clone()),
            Sent::Rect { tag, .. } => Some(vec![*tag]),
            Sent::Raster(_) => Some(b"G".to_vec()),
            Sent::Query(_) => None,
        })
        .collect()
}

/// The role's events up to and including the end of the job.
async fn events_to_job_end(events: &mut mpsc::UnboundedReceiver<StyleWriterEvent>) -> Vec<StyleWriterEvent> {
    let mut seen = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv()).await {
        let end = matches!(event, StyleWriterEvent::JobEnded { .. });
        seen.push(event);
        if end {
            break;
        }
    }
    seen
}

/// A whole colour job through the embedded role, behind a port that can follow
/// the printer's fast clock. The printer is reset and waited for, goes into its
/// fast mode with `x` after `D`, then gets the job commands, the page mode, and
/// each page's `L`, raster and form feed, then `E` and `l`. A clean job ends
/// without a reset. The second page has only black on it below a blank top, so
/// its blank rows never go to the printer and the rest prints at 1 bit in an `R`
/// band, still under the colour page mode.
#[tokio::test]
async fn embedded_stylewriter_prints_a_color_job_in_order() {
    let Bench { ddp, mut events, printer, sent } = bench_on(CS2200, FastClock::Supported);

    let mut session = StyleWriterSession::connect(&ddp, printer, "CrossTest", None)
        .await
        .expect("StyleWriter handshake against embedded role failed");
    assert!(matches!(events.recv().await, Some(StyleWriterEvent::JobStarted { .. })));

    let family = StyleWriterFamily::Color(tailtalk::stylewriter::ColorModel::Cs2200);
    let pages = [
        rgb_page(64, 8, |_, y| if y < 4 { [0, 0, 0] } else { [255, 0, 0] }),
        rgb_page(64, 12, |x, y| if (4..8).contains(&y) && x < 20 { [0, 0, 0] } else { [255, 255, 255] }),
    ];
    let job = JobOptions { rendering: Rendering::Color, quality: PrintQuality::Normal, ..JobOptions::default() };
    session.setup(family, job).await.expect("setup failed");
    let mut imager = Imager::new(family, &JobOptions { rendering: session.rendering(), ..job });
    for page in &pages {
        session.start_page().await.expect("start_page failed");
        for band in imager.bands(page) {
            session.write_band(&encode_band(&band, family)).await.expect("write_band failed");
        }
        session.end_page().await.expect("end_page failed");
    }
    session.finish().await.expect("finish failed");

    use StyleWriterEvent::{FastClockDisable, FastClockEnable, JobEnded};
    assert_eq!(events_to_job_end(&mut events).await, [FastClockEnable, FastClockDisable, JobEnded { clean: true }]);

    let sent = sent.lock().unwrap().clone();
    let expected: Vec<&[u8]> = vec![
        &[0x00], b"?", b"D", b"x", b"m2", b"n", b"Z", b"A", b"H", b"L", b"c", b"G", b"\x0C", b"L", b"R", b"G",
        b"\x0C", b"E", b"l",
    ];
    assert_eq!(commands(&sent), expected, "{sent:?}");
    let rects: Vec<&Sent> = sent.iter().filter(|s| matches!(s, Sent::Rect { .. })).collect();
    assert_eq!(rects, [&Sent::Rect { tag: b'c', left: 0, top: 0 }, &Sent::Rect { tag: b'R', left: 0, top: 4 }]);
    assert_eq!(sent.get(1), Some(&Sent::Query(b'I')));
    assert!(!sent.iter().skip(2).any(|s| s == &Sent::Query(b'I')), "no reset after the first");
}

/// A StyleWriter II job through the embedded role, behind a port that can
/// follow its fast mode. The printer is reset and waited for, goes into its fast
/// mode with `h`, then gets `u`, the quality, `D` and `A`, nothing between pages,
/// the raster, the form feed, then `E` and `l`. Its rects sit 16 dots further
/// right than a 2200's. It is asked for its cartridge but never for a submodel or
/// an 'R' reading, and there is no reset at the end.
#[tokio::test]
async fn embedded_stylewriter_prints_a_stylewriter_ii_job_in_order() {
    let Bench { ddp, mut events, printer, sent } = bench_on(SW_II, FastClock::Supported);

    let mut session = StyleWriterSession::connect(&ddp, printer, "CrossTest", None)
        .await
        .expect("StyleWriter handshake against embedded role failed");
    assert!(matches!(events.recv().await, Some(StyleWriterEvent::JobStarted { .. })));

    let family = StyleWriterFamily::StyleWriterII;
    let rows: Vec<Vec<Vec<u8>>> = (0..8u8).map(|r| vec![vec![0xF0 ^ r; 45]]).collect();
    let band = encode_band(&RawBand { top: 0, width: 360, kind: BandKind::Mono, rows }, family);

    let job = JobOptions { quality: PrintQuality::Best, paper: PaperType::Plain, ..JobOptions::default() };
    session.setup(family, job).await.expect("setup failed");
    for _ in 0..2 {
        session.start_page().await.expect("start_page failed");
        session.write_band(&band).await.expect("write_band failed");
        session.end_page().await.expect("end_page failed");
    }
    session.finish().await.expect("finish failed");

    let job_events = events_to_job_end(&mut events).await;
    assert!(job_events.contains(&StyleWriterEvent::FastClockEnable), "the port follows the printer's clock");
    assert_eq!(job_events.last(), Some(&StyleWriterEvent::JobEnded { clean: true }));

    let sent = sent.lock().unwrap().clone();
    let expected: Vec<&[u8]> = vec![
        &[0x00], b"?", b"h", b"u", b"b", b"D", b"A", b"R", b"G", b"\x0C", b"R", b"G", b"\x0C", b"E", b"l",
    ];
    assert_eq!(commands(&sent), expected, "{sent:?}");
    for s in &sent {
        if let Sent::Rect { left, .. } = s {
            assert_eq!(*left, 16);
        }
    }
    assert_eq!(sent.get(1), Some(&Sent::Query(b'I')));
    assert!(!sent.iter().skip(2).any(|s| s == &Sent::Query(b'I')), "no reset after the first");
    assert!(sent.contains(&Sent::Query(b'H')));
    for &query in b"pR" {
        assert!(!sent.contains(&Sent::Query(query)), "a StyleWriter II is never asked {}", query as char);
    }
}
