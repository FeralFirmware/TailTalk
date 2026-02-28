use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    EtherTalkPacket, OutboundHandle, addressing::Addressing, asp::Asp, atp::Atp, ddp::DdpProcessor,
    echo::Echo, nbp::Nbp,
};
use tailtalk_packets::{
    aarp::AddressSource,
    afp::{AfpUam, AfpVersion, FPGetSrvrInfo},
    ethertalk::EtherTalkType,
};
use tokio::sync::{broadcast, mpsc};

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct WirePacket {
    packet: Arc<EtherTalkPacket>,
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
    #[allow(dead_code)]
    mac: [u8; 6],
    #[allow(dead_code)]
    addressing: tailtalk::addressing::AddressingHandle,
    #[allow(dead_code)]
    ddp: tailtalk::ddp::DdpHandle,
    nbp: tailtalk::nbp::NbpHandle,
    #[allow(dead_code)]
    echo: tailtalk::echo::EchoHandle,
    atp: tailtalk::atp::AtpRequestor,
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

        let addressing = Addressing::spawn(mac, outbound_handle.clone(), None);
        let ddp = DdpProcessor::spawn(addressing.clone(), outbound_handle.clone());

        let echo = Echo::spawn(&ddp).await;
        let (_atp_socket, atp_req, mut atp_resp) = Atp::spawn(&ddp, None).await;

        // Auto-responder for ATP (Echo behavior for testing)
        tokio::spawn(async move {
            while let Some(req) = atp_resp.next().await {
                let _ = req.send_response(req.data.clone(), req.user_bytes).await;
            }
        });

        let nbp = Nbp::spawn(&ddp, addressing.clone()).await;

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

                    // Accept packets for us, broadcast, or [0; 6]
                    let is_for_us = pkt.dst_mac == mac;
                    let is_broadcast_std = pkt.dst_mac == [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
                    let is_zeros = pkt.dst_mac == [0, 0, 0, 0, 0, 0];

                    if is_for_us || is_broadcast_std || is_zeros {
                        match pkt.protocol {
                            EtherTalkType::Ddp => ddp_handle.received_pkt(
                                &pkt.payload,
                                AddressSource::EtherTalk,
                                src_mac,
                            ),
                            EtherTalkType::Aarp => {
                                let _ = addressing_handle
                                    .received_pkt(&pkt.payload, AddressSource::EtherTalk);
                            }
                        }
                    }
                }
            }
        });

        Self {
            mac,
            addressing,
            ddp,
            nbp,
            echo,
            atp: atp_req,
        }
    }
}

#[tokio::test]
async fn test_asp_session_workflow() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let _hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Server
    let mac_server = [0x00, 0x01, 0x02, 0x03, 0x04, 0x0A];
    let (out_tx_s, mut out_rx_s) = mpsc::channel(100);
    let outbound_server = OutboundHandle::new(out_tx_s);

    // Server Hub connection
    let hub_tx_s = hub_in_tx.clone();
    tokio::spawn(async move {
        while let Some(pkt) = out_rx_s.recv().await {
            let wire_pkt = WirePacket {
                packet: Arc::new(pkt),
                src_mac: mac_server,
            };
            let _ = hub_tx_s.send(wire_pkt).await;
        }
    });

    let addr_server = Addressing::spawn(mac_server, outbound_server.clone(), None);
    let ddp_server = DdpProcessor::spawn(addr_server.clone(), outbound_server.clone());
    // Start NBP for server
    let nbp_server = Nbp::spawn(&ddp_server, addr_server.clone()).await;

    // Start incoming packet loop for server
    let mut rx_server = hub_ref.subscribe();
    let ddp_handle_s = ddp_server.clone();
    let addr_handle_s = addr_server.clone();

    tokio::spawn(async move {
        loop {
            if let Ok(wire_pkt) = rx_server.recv().await {
                let src = wire_pkt.src_mac;
                if src == mac_server {
                    continue;
                }
                let pkt = &wire_pkt.packet;
                if pkt.dst_mac == mac_server || pkt.dst_mac == [0xff; 6] || pkt.dst_mac == [0; 6] {
                    match pkt.protocol {
                        EtherTalkType::Ddp => {
                            ddp_handle_s.received_pkt(&pkt.payload, AddressSource::EtherTalk, src)
                        }
                        EtherTalkType::Aarp => {
                            let _ =
                                addr_handle_s.received_pkt(&pkt.payload, AddressSource::EtherTalk);
                        }
                    }
                }
            }
        }
    });

    // 3. Bind ASP on Server
    let status_info = FPGetSrvrInfo {
        machine_type: "Macintosh".into(),
        afp_versions: vec![AfpVersion::Version2],
        uams: vec![AfpUam::NoUserAuthent],
        volume_icon: None,
        flags: 0,
        server_name: "TestASP".into(),
    };
    let status_data = status_info.to_bytes().expect("failed to serialize status");

    let asp_handle = Asp::bind(
        &ddp_server,
        &nbp_server,
        Some(205),
        "TestASP:AFPServer@*".try_into().unwrap(),
        status_data.clone(),
    )
    .await
    .expect("Failed to bind ASP");

    // Spawn a task to accept the session
    tokio::spawn(async move {
        println!("Waiting for session...");
        match asp_handle.get_session().await {
            Ok(sess) => println!("Accepted session: {:?}", sess),
            Err(e) => println!("Failed to accept session: {:?}", e),
        }
    });

    // 4. Setup Client
    let mac_client = [0x00, 0x01, 0x02, 0x03, 0x04, 0x0B];
    let client = TestClient::new(mac_client, hub_in_tx.clone(), hub_ref.subscribe()).await;

    // Wait for addressing
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 5. Client looks up Server
    let lookup = client
        .nbp
        .lookup("TestASP:AFPServer@*".try_into().unwrap())
        .await
        .expect("Lookup failed");
    assert_eq!(lookup.len(), 1);
    let target = &lookup[0];

    // 6. Client sends OpenSess (Command 4)
    let atp_addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };

    let open_sess_bytes = [0x04, 0x00, 0x00, 0x00]; // Command 4 (OpenSess), SessID=0
    let req_data = vec![]; // Usually empty or version info

    println!("Sending OpenSess...");
    // Parse response
    let (_resp_data, user_bytes) = client
        .atp
        .send_request(atp_addr, open_sess_bytes, req_data)
        .await
        .expect("OpenSess Request failed");

    println!("OpenSess Response UserBytes: {:?}", user_bytes);

    let server_sess_socket = user_bytes[0];
    let session_id = user_bytes[1];

    assert_eq!(
        server_sess_socket, 205,
        "OpenSess should return valid Session Socket (205)"
    );
    assert!(session_id > 0, "Session ID should be non-zero");
    println!(
        "Session Opened: ID={} on Socket={}",
        session_id, server_sess_socket
    );

    // 7. Client sends CloseSess (Command 1)
    let close_sess_bytes = [0x01, session_id, 0, 0];

    println!("Sending CloseSess for ID {}...", session_id);
    let (_resp_data, close_user_bytes) = client
        .atp
        .send_request(atp_addr, close_sess_bytes, vec![])
        .await
        .expect("CloseSess Request failed");

    let close_result = close_user_bytes[0];
    assert_eq!(close_result, 0, "CloseSess Result Code should be 0");

    println!("✓ ASP Session test passed!");

    // 8. Test ServerBusy
    // Server has not called get_session again.
    // Client sends OpenSess (Command 4)
    println!("Sending OpenSess (expecting ServerBusy)...");
    let open_sess_bytes_2 = [0x04, 0x00, 0x00, 0x00];
    let (_resp_data_2, user_bytes_2) = client
        .atp
        .send_request(atp_addr, open_sess_bytes_2, vec![])
        .await
        .expect("OpenSess (2) Request failed");

    println!("ServerBusy Response UserBytes: {:?}", user_bytes_2);

    assert_eq!(user_bytes_2, (-1071i32).to_be_bytes());
    println!("✓ ASP ServerBusy test passed!");
}
