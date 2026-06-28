use tailtalk::DataLinkProtocol;
use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    DataLinkPacket, OutboundHandle,
    addressing::Addressing,
    adsp::{Adsp, AdspAddress},
    ddp::{DdpAddress, DdpProcessor},
    route_table::{LearningMode, RouteTable},
};
use tailtalk_packets::aarp::{AddressSource, AppleTalkAddress};
use tailtalk_packets::ddp::DdpProtocolType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc};

#[derive(Clone, Debug)]
struct WirePacket {
    packet: Arc<DataLinkPacket>,
    src_mac: [u8; 6],
}

struct TestHub {
    tx: broadcast::Sender<WirePacket>,
    _rx: broadcast::Receiver<WirePacket>,
}

impl TestHub {
    fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self { tx, _rx }
    }

    fn subscribe(&self) -> broadcast::Receiver<WirePacket> {
        self.tx.subscribe()
    }

    async fn run(&self, mut frame_rx: mpsc::Receiver<WirePacket>) {
        while let Some(pkt) = frame_rx.recv().await {
            let _ = self.tx.send(pkt);
        }
    }
}

struct TestClient {
    _mac: [u8; 6],
    addressing: tailtalk::addressing::AddressingHandle,
    ddp: tailtalk::ddp::DdpHandle,
}

impl TestClient {
    async fn new(
        mac: [u8; 6],
        hub_tx: mpsc::Sender<WirePacket>,
        hub_rx: broadcast::Receiver<WirePacket>,
    ) -> Self {
        let (out_tx, mut out_rx) = mpsc::channel(100);
        let outbound_handle = OutboundHandle::new(out_tx);

        let hub_tx_clone = hub_tx.clone();
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                let wire_pkt = WirePacket {
                    packet: Arc::new(pkt),
                    src_mac: mac,
                };
                let _ = hub_tx_clone.send(wire_pkt).await;
            }
        });

        let addressing = Addressing::spawn(Some(mac), outbound_handle.clone(), None, AddressSource::EtherTalkPhase2);
        let ddp = DdpProcessor::spawn(Some(addressing.clone()), None, outbound_handle.clone(), RouteTable::new(LearningMode::Static));

        let mut rx = hub_rx;
        let ddp_handle = ddp.clone();
        let addressing_handle = addressing.clone();

        tokio::spawn(async move {
            loop {
                if let Ok(wire_pkt) = rx.recv().await {
                    let src_mac = wire_pkt.src_mac;
                    let pkt = &wire_pkt.packet;

                    if src_mac == mac {
                        continue;
                    }

                    let dest_mac = if let tailtalk::addressing::Node::EtherTalkPhase2(m) = pkt.dest_node { m } else { [0; 6] };
                    if dest_mac == mac || tailtalk::addressing::Addressing::is_broadcast_mac(dest_mac, AddressSource::EtherTalkPhase2) {
                        match pkt.protocol {
                            DataLinkProtocol::Ddp => ddp_handle.received_pkt(
                                &pkt.payload,
                                AddressSource::EtherTalkPhase2,
                                src_mac,
                            ),
                            DataLinkProtocol::Aarp => {
                                let _ = addressing_handle
                                    .received_pkt(&pkt.payload, AddressSource::EtherTalkPhase2);
                            }
                            DataLinkProtocol::LlapEnq | DataLinkProtocol::LlapAck => {}
                        }
                    }
                }
            }
        });

        Self {
            _mac: mac,
            addressing,
            ddp,
        }
    }
}

#[tokio::test]
async fn test_adsp_connection() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Client A (server)
    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_a = TestClient::new(mac_a, hub_in_tx.clone(), hub_ref.subscribe()).await;

    // 3. Setup Client B (client)
    let mac_b = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let client_b = TestClient::new(mac_b, hub_in_tx.clone(), hub_ref.subscribe()).await;

    // Wait for addressing to settle
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 4. Get addresses
    let addr_a = client_a
        .addressing
        .addr()
        .await
        .expect("failed to get addr");
    let _addr_b = client_b
        .addressing
        .addr()
        .await
        .expect("failed to get addr");

    // 5. Start ADSP listener on Client A
    let (socket_a, mut listener) = Adsp::bind(&client_a.ddp, Some(100))
        .await
        .expect("failed to bind listener");

    tracing::info!("Client A listening on socket {}", socket_a);

    // Spawn task to accept connection
    let accept_task = tokio::spawn(async move { listener.accept().await });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 6. Client B connects to Client A
    let remote_addr = AdspAddress {
        network_number: addr_a.network_number,
        node_number: addr_a.node_number,
        socket_number: 100,
    };

    tracing::info!("Client B connecting to {:?}", remote_addr);

    let mut stream_b = Adsp::connect(&client_b.ddp, remote_addr)
        .await
        .expect("failed to connect");

    tracing::info!("Client B connected!");

    // 7. Accept the connection on Client A
    let mut stream_a = accept_task
        .await
        .expect("accept task failed")
        .expect("failed to accept");

    tracing::info!("Client A accepted connection!");

    // 8. Client B sends data
    let test_data = b"Hello from Client B!";
    stream_b
        .write_all(test_data)
        .await
        .expect("failed to write");
    stream_b.flush().await.expect("failed to flush");

    tracing::info!("Client B sent data");

    // Give some time for data to arrive
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 9. Client A reads data
    let mut buffer = vec![0u8; 1024];
    let n = stream_a.read(&mut buffer).await.expect("failed to read");

    assert!(n > 0, "No data received");
    assert_eq!(&buffer[..n], test_data, "Data mismatch");

    tracing::info!("Client A received data: {:?}", &buffer[..n]);

    // 10. Client A echoes data back
    stream_a
        .write_all(&buffer[..n])
        .await
        .expect("failed to write echo");
    stream_a.flush().await.expect("failed to flush echo");

    tokio::time::sleep(Duration::from_millis(500)).await;

    // 11. Client B reads echo
    let mut echo_buffer = vec![0u8; 1024];
    let echo_n = stream_b
        .read(&mut echo_buffer)
        .await
        .expect("failed to read echo");

    assert_eq!(&echo_buffer[..echo_n], test_data, "Echo data mismatch");

    tracing::info!("✓ ADSP test passed: bidirectional communication successful!");

    // 12. Close connections
    stream_a.close().await.expect("failed to close stream A");
    stream_b.close().await.expect("failed to close stream B");

    hub_task.abort();
}

// ── StyleWriter name-change session test ──────────────────────────────────────
//
// Replicates a session captured from a PowerBook G3 connecting to a StyleWriter
// 2200 over ADSP and issuing three attention-message commands to rename the
// adapter.  The raw "server" side below speaks correct ADSP per the spec
// (§12, Figure 12-2: ConnID first, descriptor last); the client side uses
// only the high-level AdspStream API.

// ── Raw server helpers (spec byte order) ─────────────────────────────────────

fn adsp_addr(net: u16, node: u8, sock: u8) -> DdpAddress {
    DdpAddress::new(AppleTalkAddress { network_number: net, node_number: node }, sock)
}

/// Parse a 13-byte ADSP header per spec (ConnID first, descriptor last).
/// Returns (conn_id, first_byte_seq, next_recv_seq, recv_window, descriptor).
fn parse_adsp_hdr(buf: &[u8]) -> (u16, u32, u32, u16, u8) {
    let conn_id  = u16::from_be_bytes([buf[0], buf[1]]);
    let first    = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    let next     = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]);
    let window   = u16::from_be_bytes([buf[10], buf[11]]);
    let desc     = buf[12];
    (conn_id, first, next, window, desc)
}

/// Build a 13-byte ADSP header per spec.
fn build_adsp_hdr(conn_id: u16, first: u32, next: u32, window: u16, desc: u8) -> [u8; 13] {
    let mut b = [0u8; 13];
    b[0..2].copy_from_slice(&conn_id.to_be_bytes());
    b[2..6].copy_from_slice(&first.to_be_bytes());
    b[6..10].copy_from_slice(&next.to_be_bytes());
    b[10..12].copy_from_slice(&window.to_be_bytes());
    b[12] = desc;
    b
}

// ── Raw StyleWriter server ────────────────────────────────────────────────────

const SW_CONN_ID:  u16 = 0x000a; // server ConnID from capture
const SW_WINDOW:   u16 = 0x06b4; // server receive window from capture
const ADSP_VER:    u16 = 0x0100; // ADSP version 1.0

/// Server-side state extracted from the OpenConnRequest.
struct ClientInfo {
    net:  u16,
    node: u8,
    sock: u8,
    conn_id: u16,
}

async fn recv_until(
    sock: &mut tailtalk::ddp::DdpSocket,
    want_desc: u8,
) -> (ClientInfo, Vec<u8>) {
    loop {
        let pkt = tokio::time::timeout(Duration::from_secs(5), sock.recv())
            .await
            .expect("server recv timed out")
            .expect("server recv error");

        let payload = pkt.payload.to_vec();
        if payload.len() < 13 {
            continue;
        }
        let (conn_id, _, _, _, desc) = parse_adsp_hdr(&payload);
        if desc == want_desc {
            return (
                ClientInfo {
                    net:  pkt.headers.src_network_num,
                    node: pkt.headers.src_node_id,
                    sock: pkt.headers.src_sock_num,
                    conn_id,
                },
                payload,
            );
        }
    }
}

async fn stylewriter_server(mut sock: tailtalk::ddp::DdpSocket) {
    // ── Handshake ──────────────────────────────────────────────────────────

    let (client, req_payload) = recv_until(&mut sock, 0x81).await;

    // Open-conn params follow the 13-byte header (spec §12, Figure 12-11):
    // version(2) | DestConnID(2) | PktAttnRecvSeq(4).
    // DestConnID is 0x0000 in the request — client doesn't know our ConnID yet.
    assert!(
        req_payload.len() >= 21,
        "OpenConnRequest must carry 8-byte open-conn params (got {} bytes)",
        req_payload.len()
    );
    let req_ver   = u16::from_be_bytes([req_payload[13], req_payload[14]]);
    let req_dcid  = u16::from_be_bytes([req_payload[15], req_payload[16]]);
    assert_eq!(req_ver,  ADSP_VER, "OpenConnRequest version mismatch");
    assert_eq!(req_dcid, 0x0000,   "OpenConnRequest DestConnID must be 0");

    let mut resp = vec![0u8; 13 + 8];
    resp[..13].copy_from_slice(&build_adsp_hdr(SW_CONN_ID, 0, 0, SW_WINDOW, 0x83));
    resp[13..15].copy_from_slice(&ADSP_VER.to_be_bytes());
    resp[15..17].copy_from_slice(&client.conn_id.to_be_bytes());
    sock.send_to(&resp, adsp_addr(client.net, client.node, client.sock))
        .await
        .expect("send OpenConnReqAck failed");

    // All three handshake packets carry 8-byte open-conn params (spec §12, Figure 12-11).
    // The real StyleWriter validates the params before completing the handshake.
    let (_, ack_payload) = recv_until(&mut sock, 0x82).await;
    assert!(
        ack_payload.len() >= 21,
        "OpenConnAck must carry 8-byte open-conn params (got {} bytes)",
        ack_payload.len()
    );
    let ack_ver  = u16::from_be_bytes([ack_payload[13], ack_payload[14]]);
    let ack_dcid = u16::from_be_bytes([ack_payload[15], ack_payload[16]]);
    assert_eq!(ack_ver,  ADSP_VER,   "OpenConnAck open-conn version mismatch");
    assert_eq!(ack_dcid, SW_CONN_ID, "OpenConnAck DestConnID must match server ConnID");

    // ── Three attention-message rounds ─────────────────────────────────────
    //
    // Each round: client sends an attention packet (desc=0x50), server replies
    // with an attention ack (desc=0x90) and a 2-byte [0x00, 0x00] data packet.
    //
    // Invariants verified per attention packet (from the captured session):
    //   - connection_id == client.conn_id  (client's own ConnID, not the server's)
    //   - first_byte_seq == round index    (attention sequence: 0, 1, 2)
    //   - recv_window == 0                 (spec §12 requires zero in attention packets)

    let expected_attention_codes: &[u16] = &[0x0011, 0x0009, 0x0012];

    let expected_attn_data: &[&[u8]] = &[
        &[0x00],
        b"\x16Color StyleWriter 2200",
        &[0x00],
    ];

    let mut attn_recv_seq: u32 = 0; // server's AttnRecvSeq: next attention seq expected
    let mut data_send_seq: u32 = 0; // server's data SendSeq: bytes sent so far

    for i in 0..3 {
        // Receive attention from client (descriptor = 0x50)
        let (_, attn_payload) = recv_until(&mut sock, 0x50).await;

        assert!(
            attn_payload.len() >= 15,
            "attention {} payload too short: {} bytes",
            i, attn_payload.len()
        );
        let (pkt_conn_id, pkt_first, _, pkt_window, _) = parse_adsp_hdr(&attn_payload);

        // Outgoing packets must carry the CLIENT's own ConnID (from its OpenConnRequest),
        // not the server's ConnID.  This is the invariant broken by the our_conn_id bug.
        assert_eq!(
            pkt_conn_id, client.conn_id,
            "attention {} connID 0x{:04x} != client connID 0x{:04x} \
             (client must use its own ConnID in outgoing packets, not the server's)",
            i, pkt_conn_id, client.conn_id
        );

        // Attention packets use a separate sequence number that starts at 0
        // and increments by 1 per attention message (pcap: F04=0, F08=1, F12=2).
        assert_eq!(
            pkt_first, i as u32,
            "attention {} first_byte_seq={} want {} (attn seq must increment per message)",
            i, pkt_first, i
        );

        // Per spec §12, recv_window must be 0 in attention packets.
        assert_eq!(
            pkt_window, 0,
            "attention {} recv_window={} want 0 (spec §12 requires zero in attention packets)",
            i, pkt_window
        );

        // ── Validate attention code and payload ───────────────────────────
        let code = u16::from_be_bytes([attn_payload[13], attn_payload[14]]);
        assert_eq!(
            code, expected_attention_codes[i],
            "attention {} wrong code: got 0x{:04x}, want 0x{:04x}",
            i, code, expected_attention_codes[i]
        );
        let attn_data = &attn_payload[15..];
        assert_eq!(
            attn_data, expected_attn_data[i],
            "attention {} wrong data",
            i
        );

        attn_recv_seq += 1;

        let ack_hdr = build_adsp_hdr(SW_CONN_ID, 0, attn_recv_seq, 0, 0x90);
        sock.send_to(&ack_hdr, adsp_addr(client.net, client.node, client.sock))
            .await
            .expect("send attn ack failed");

        let mut data_pkt = [0u8; 15];
        data_pkt[..13].copy_from_slice(&build_adsp_hdr(
            SW_CONN_ID, data_send_seq, 0, SW_WINDOW, 0x40,
        ));
        // bytes [13..15] = 0x00 0x00 (already zeroed)
        sock.send_to(&data_pkt, adsp_addr(client.net, client.node, client.sock))
            .await
            .expect("send data response failed");

        data_send_seq += 2;
    }

    recv_until(&mut sock, 0x85).await;
}

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_adsp_stylewriter_name_change() {
    let _ = tracing_subscriber::fmt().try_init();

    // Network hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);
    let hub_ref = Arc::new(hub);
    let hub_clone = hub_ref.clone();
    tokio::spawn(async move { hub_clone.run(hub_in_rx).await });

    // Two nodes on the simulated network
    let mac_server = [0x00, 0x00, 0xC5, 0x1C, 0x1F, 0x8A]; // StyleWriter MAC
    let mac_client = [0x00, 0x05, 0x02, 0x7C, 0x85, 0x93]; // PowerBook MAC

    let server_node = TestClient::new(mac_server, hub_in_tx.clone(), hub_ref.subscribe()).await;
    let client_node = TestClient::new(mac_client, hub_in_tx.clone(), hub_ref.subscribe()).await;

    // Allow AARP to assign node addresses
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let server_at_addr = server_node.addressing.addr().await.expect("server addr");

    // Bind a raw DDP socket on the well-known StyleWriter ADSP socket (129)
    let server_sock = server_node
        .ddp
        .new_sock(DdpProtocolType::Adsp, Some(129))
        .await
        .expect("bind server socket");

    // Run the raw StyleWriter server in the background
    let server_task = tokio::spawn(stylewriter_server(server_sock));

    let remote = AdspAddress {
        network_number: server_at_addr.network_number,
        node_number:    server_at_addr.node_number,
        socket_number:  129,
    };

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        Adsp::connect(&client_node.ddp, remote),
    )
    .await
    .expect("connect timed out — ADSP header byte order is likely wrong")
    .expect("connect returned error");

    stream
        .send_attention(0x0011, &[0x00])
        .await
        .expect("send_attention 0x0011 failed");

    let mut resp = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut resp))
        .await
        .expect("read timed out after attention 0x0011")
        .expect("read error after attention 0x0011");
    assert_eq!(resp, [0x00, 0x00], "unexpected response to attention 0x0011");

    stream
        .send_attention(0x0009, b"\x16Color StyleWriter 2200")
        .await
        .expect("send_attention 0x0009 failed");

    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut resp))
        .await
        .expect("read timed out after attention 0x0009")
        .expect("read error after attention 0x0009");
    assert_eq!(resp, [0x00, 0x00], "unexpected response to attention 0x0009");

    stream
        .send_attention(0x0012, &[0x00])
        .await
        .expect("send_attention 0x0012 failed");

    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut resp))
        .await
        .expect("read timed out after attention 0x0012")
        .expect("read error after attention 0x0012");
    assert_eq!(resp, [0x00, 0x00], "unexpected response to attention 0x0012");

    // Close the connection (sends CloseAdvice per spec §12)
    stream.close().await.expect("close failed");

    // Wait for the server to finish cleanly
    tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("server task timed out")
        .expect("server task panicked");
}
