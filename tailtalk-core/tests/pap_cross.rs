//! Cross-tests: the embedded ImageWriter role served to the desktop
//! `PapClient`, which is verified against real ImageWriter option card
//! hardware, over an in-process DDP loopback.
//!
//! Since the desktop ATP actor moved onto the shared tailtalk-core engine,
//! the ATP layer under both sides of this test is the same code; the PAP
//! client logic itself is still independent of the embedded PAP server, so
//! the PAP-level exchange remains a genuine cross-check.
//!
//! Same topology as tests/stylewriter_cross.rs: desktop stack at 1.5, the
//! embedded role playing a printer at 1.77 (listener socket 190, connection
//! socket 191), with a bridge task shuttling DDP payloads.

use std::sync::{Arc, Mutex};

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, Node},
    atp::{Atp, AtpAddress},
    ddp::DdpProcessor,
    pap::PapClient,
    route_table::{LearningMode, RouteTable},
};
use tailtalk_core::imagewriter::{self, ImageWriterRole};
use tailtalk_core::pap::PapEvent;
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
const LISTENER_SOCKET: u8 = 190;
const CONN_SOCKET: u8 = 191;
const DESKTOP_MAC: [u8; 6] = [2, 0, 0, 0, 0, 5];
const PRINTER_MAC: [u8; 6] = [2, 0, 0, 0, 0, 77];
/// Long enough for a self ID query to go out on the next 20 ms tick, be
/// answered, and settle after the role's quiet-gap wait.
const IDENT_SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

fn desktop_stack() -> (mpsc::Receiver<DataLinkPacket>, tailtalk::ddp::DdpHandle) {
    let (out_tx, out_rx) = mpsc::channel(256);
    let outbound = OutboundHandle::new(out_tx);
    let addressing = Addressing::spawn(
        Some(DESKTOP_MAC),
        outbound.clone(),
        Some(DESKTOP_ADDR),
        AddressSource::EtherTalkPhase2,
    );
    addressing.learn(PRINTER_ADDR, Node::EtherTalkPhase2(PRINTER_MAC));
    let ddp = DdpProcessor::spawn(
        Some(addressing),
        None,
        outbound,
        RouteTable::new(LearningMode::Static),
    );
    (out_rx, ddp)
}

/// Extract role-bound datagrams from the desktop's outbound queue.
fn for_role(pkt: &DataLinkPacket) -> Option<(u8, ServiceAddress, Vec<u8>)> {
    if pkt.protocol != DataLinkProtocol::Ddp {
        return None;
    }
    let headers = DdpHeaders::parse(&pkt.payload).ok()?;
    if headers.dest_node_id != PRINTER_ADDR.node_number {
        return None;
    }
    let end = headers.len.min(pkt.payload.len());
    let src = ServiceAddress {
        network_number: headers.src_network_num,
        node_number: headers.src_node_id,
        socket_number: headers.src_sock_num,
    };
    Some((
        headers.dest_sock_num,
        src,
        pkt.payload[DdpHeaders::LEN..end].to_vec(),
    ))
}

fn inject(ddp: &tailtalk::ddp::DdpHandle, src_socket: u8, dest: ServiceAddress, payload: Vec<u8>) {
    let headers = DdpHeaders {
        hop_count: 0,
        len: DdpHeaders::LEN + payload.len(),
        chksum: 0,
        dest_network_num: dest.network_number,
        dest_node_id: dest.node_number,
        dest_sock_num: dest.socket_number,
        src_network_num: PRINTER_ADDR.network_number,
        src_node_id: PRINTER_ADDR.node_number,
        src_sock_num: src_socket,
        protocol_typ: DdpProtocolType::Atp,
    };
    ddp.received_parsed_pkt(
        headers,
        payload.into_boxed_slice(),
        AddressSource::EtherTalkPhase2,
        PRINTER_MAC,
    );
}

fn listener_addr() -> AtpAddress {
    AtpAddress {
        network_number: PRINTER_ADDR.network_number,
        node_number: PRINTER_ADDR.node_number,
        socket_number: LISTENER_SOCKET,
    }
}

/// A print job reaches the printer byte for byte, and the ribbon is read
/// off the wire around it.
///
/// The ImageWriter role is a pure pass-through: it appends no end-of-job
/// marker of its own, and its payload is binary. `ESC G` bitmap runs contain 0x11 and 0x13 as ordinary data,
/// which is exactly why XON/XOFF cannot be used as flow control on this
/// path, so those bytes are in the fixture deliberately - anything that
/// starts interpreting the stream will fail here.
///
/// The printer here answers the self ID query, and has its ribbon swapped
/// while the job is open, which is the case the between-jobs re-query
/// exists for.
#[tokio::test]
async fn embedded_imagewriter_streams_a_job_verbatim() {
    let (mut out_rx, ddp) = desktop_stack();

    let received = Arc::new(Mutex::new(Vec::<u8>::new()));
    let received_in_task = received.clone();
    // The ribbon currently in the printer, which the test swaps mid-job.
    let ribbon: Arc<Mutex<&'static [u8]>> = Arc::new(Mutex::new(b"IW10CF"));
    let ribbon_in_task = ribbon.clone();
    // Set if a self ID query is ever emitted between OpenConn and CloseConn.
    let identify_during_job = Arc::new(Mutex::new(false));
    let identify_in_task = identify_during_job.clone();

    let ddp_for_task = ddp.clone();
    tokio::spawn(async move {
        let mut role = ImageWriterRole::new(LISTENER_SOCKET, CONN_SOCKET);
        role.set_sink_credit(64 * 1024, 0);
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
        let mut job_open = false;
        loop {
            let now = start.elapsed().as_micros() as u64;
            tokio::select! {
                pkt = out_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    if let Some((sock, src, payload)) = for_role(&pkt) {
                        role.handle_datagram(sock, src, &payload, now);
                    }
                }
                _ = tick.tick() => role.poll(now),
            }
            while let Some(ev) = role.poll_event() {
                match ev {
                    PapEvent::ConnectionOpened { .. } => job_open = true,
                    PapEvent::ConnectionClosed => job_open = false,
                    // Stand in for the printer: answer the self ID query,
                    // and treat everything else as job data on paper.
                    PapEvent::ToPrinter(bytes) if bytes == imagewriter::SELF_ID => {
                        if job_open {
                            *identify_in_task.lock().unwrap() = true;
                        }
                        let reply = *ribbon_in_task.lock().unwrap();
                        role.printer_input(reply, now);
                    }
                    PapEvent::ToPrinter(bytes) => {
                        received_in_task.lock().unwrap().extend_from_slice(&bytes);
                    }
                    _ => {}
                }
            }
            while let Some((sock, dest, payload)) = role.poll_transmit() {
                inject(&ddp_for_task, sock, dest, payload);
            }
        }
    });

    // Let the idle-time query go out and settle before the job opens.
    tokio::time::sleep(IDENT_SETTLE).await;
    let (_s2, req2, _r2) = Atp::spawn(&ddp, None).await;
    let status = PapClient::get_status_bytes(req2, listener_addr())
        .await
        .expect("SendStatus failed");
    assert_eq!(
        status,
        vec![0x80, 0x00],
        "the printer answered `IW10CF`, so bit 7 is set"
    );

    // `ESC G <4-digit count>` then raw bitmap bytes, including the two that
    // would be flow control if this path used any, plus 0x00 and 0xFF.
    let mut job: Vec<u8> = b"\x1bG0016".to_vec();
    job.extend_from_slice(&[
        0x00, 0x11, 0x13, 0xFF, 0x1B, 0x04, 0x7F, 0x80, 0x11, 0x13, 0x00, 0xFF, 0x55, 0xAA, 0x0D,
        0x0A,
    ]);

    let (_s, req, resp) = Atp::spawn(&ddp, None).await;
    let mut client = PapClient::new(req, resp);
    client
        .connect(listener_addr())
        .await
        .expect("PAP OpenConn failed");
    client.print(&job).await.expect("print failed");

    // The operator swaps to a black ribbon while the job is running.
    *ribbon.lock().unwrap() = b"IW10";

    let all = received.lock().unwrap().clone();
    assert_eq!(
        all, job,
        "job data must stream untouched: no escaping, no reordering, no end-of-job byte of the card's own"
    );
    assert!(
        !*identify_during_job.lock().unwrap(),
        "the query must not be issued mid-job: the printer would not read it until the stream reached that point"
    );

    // Closing the job puts the query back in the queue, and this time the
    // printer answers without the `C`.
    client.close().await.expect("CloseConn failed");
    tokio::time::sleep(IDENT_SETTLE).await;

    let (_s3, req3, _r3) = Atp::spawn(&ddp, None).await;
    let status = PapClient::get_status_bytes(req3, listener_addr())
        .await
        .expect("SendStatus failed");
    assert_eq!(
        status,
        vec![0x00, 0x00],
        "a black ribbon clears bit 7 after the between-jobs re-query"
    );
}

#[tokio::test]
async fn embedded_imagewriter_reports_option_card_status() {
    let (mut out_rx, ddp) = desktop_stack();

    let ddp_for_task = ddp.clone();
    tokio::spawn(async move {
        let mut role = ImageWriterRole::new(LISTENER_SOCKET, CONN_SOCKET);
        role.set_sink_credit(64 * 1024, 0);
        let start = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(20));
        loop {
            let now = start.elapsed().as_micros() as u64;
            tokio::select! {
                pkt = out_rx.recv() => {
                    let Some(pkt) = pkt else { break };
                    if let Some((sock, src, payload)) = for_role(&pkt) {
                        role.handle_datagram(sock, src, &payload, now);
                    }
                }
                _ = tick.tick() => role.poll(now),
            }
            while role.poll_event().is_some() {}
            while let Some((sock, dest, payload)) = role.poll_transmit() {
                inject(&ddp_for_task, sock, dest, payload);
            }
        }
    });

    // The option card's status buffer: two statusBits bytes, low byte
    // first. The static ready word is 0x0080 (colour ribbon bit only).
    let (_sock, requestor, _responder) = Atp::spawn(&ddp, None).await;
    let status = PapClient::get_status_bytes(requestor, listener_addr())
        .await
        .expect("SendStatus failed");
    assert_eq!(status, vec![0x80, 0x00]);
}
