use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    EtherTalkPacket, OutboundHandle,
    addressing::Addressing,
    atp::Atp,
    ddp::DdpProcessor,
    echo::Echo,
    nbp::{Nbp, RegisteredName},
    pap::PapClient,
};
use tailtalk_packets::{
    aarp::AddressSource,
    ethertalk::EtherTalkType,
    pap::{PapFunction, PapPacket},
};
use tokio::sync::{broadcast, mpsc};

#[derive(Clone, Debug)]
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
    // We expose ATP parts to construct PapClient or Mock Server
    atp_req: tailtalk::atp::AtpRequestor,
    atp_resp: tailtalk::atp::AtpResponder,
}

impl TestClient {
    async fn new(
        mac: [u8; 6],
        hub_tx: mpsc::Sender<WirePacket>,
        hub_rx: broadcast::Receiver<WirePacket>,
        atp_socket: Option<u8>,
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
        // spawn returns (socket, req, resp)
        let (_sock, atp_req, atp_resp) = Atp::spawn(&ddp, atp_socket).await;

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
            atp_req,
            atp_resp,
        }
    }

    fn into_pap_client(self) -> PapClient {
        PapClient::new(self.atp_req, self.atp_resp)
    }
}

#[tokio::test]
async fn test_pap_print_job() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Printer (Server)
    let mac_printer = [0x00, 0x01, 0x02, 0x03, 0x04, 0xAA];
    // PAP usually on arbitrary socket, registered via NBP.

    // 3. Setup Workstation (Client)
    let mac_client = [0x00, 0x01, 0x02, 0x03, 0x04, 0xBB];
    let workstation =
        TestClient::new(mac_client, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // Wait for addressing
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 4. Printer registers "TestPrinter:LaserWriter@*"
    // Re-spawn printer with fixed socket 130
    let mut printer = TestClient::new(
        mac_printer,
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        Some(130),
    )
    .await;

    printer
        .nbp
        .register(RegisteredName {
            name: "TestPrinter:LaserWriter@*".try_into().unwrap(),
            sock_num: 130,
        })
        .await
        .expect("Printer registration failed");

    // 5. Workstation registers NBP

    // 6. Workstation looks up Printer
    tokio::time::sleep(Duration::from_millis(500)).await;
    let results = workstation
        .nbp
        .lookup("TestPrinter:LaserWriter@*".try_into().unwrap())
        .await
        .expect("Lookup failed");
    assert!(!results.is_empty());
    let target = &results[0];

    let printer_addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };

    // 7. Workstation connects to Printer
    let mut pap_client = workstation.into_pap_client();

    let connect_task = tokio::spawn(async move {
        pap_client
            .connect(printer_addr)
            .await
            .expect("Connect failed");
        pap_client
    });

    // 8. Printer handles OpenConn
    let conn_id;
    let workstation_addr;

    // We expect OpenConn
    if let Some(req) = printer.atp_resp.next().await {
        let pap_pkt =
            PapPacket::parse_from_atp(req.user_bytes, &req.data).expect("Failed to parse PAP");
        assert_eq!(pap_pkt.function, PapFunction::OpenConn);
        // Verify ConnectionID matches source socket (as per protocol/user request)
        assert_eq!(pap_pkt.connection_id, req.source.socket_number);
        // Verify Payload Socket matches source socket
        assert_eq!(pap_pkt.data[0], req.source.socket_number);

        // Save source address
        workstation_addr = req.source;

        // Respond with OpenConnReply
        // ConnID = 55 (arbitrary)
        conn_id = 55;
        let reply = PapPacket {
            connection_id: conn_id,
            function: PapFunction::OpenConnReply,
            sequence_num: 0,
            data: vec![130, 8, 0, 0], // Socket=130, Flow=8, Result=0
        };
        let (ub, d) = reply.to_atp_parts();
        req.send_response(d.to_vec(), ub)
            .await
            .expect("Failed to send OpenConnReply");
    } else {
        panic!("Printer received no request");
    }

    let mut pap_client = connect_task.await.expect("Connect task failed");
    println!("Workstation connected.");

    // 9. Workstation sends Print Data
    // Spawn task for workstation print
    let print_data = b"Hello, world! This is a print job.".to_vec();
    let print_data_clone = print_data.clone();

    let _print_task = tokio::spawn(async move {
        pap_client
            .print(&print_data_clone)
            .await
            .expect("Print failed");
        pap_client
    });

    // 10. Printer Request Data (SendData)
    // Wait for client to prepare
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("Printer sending SendData...");
    let send_data_pkt = PapPacket {
        connection_id: conn_id,
        function: PapFunction::SendData,
        sequence_num: 1,
        data: vec![],
    };
    let (ub, d) = send_data_pkt.to_atp_parts();

    // Printer sends request to Workstation using AtpRequestor
    let (resp_data, _resp_ub) = printer
        .atp_req
        .send_request(workstation_addr, ub, d.to_vec())
        .await
        .expect("SendData failed");

    println!("Printer got {} bytes", resp_data.len());
    assert_eq!(resp_data, print_data);

    println!("✓ PAP Print test passed!");

    // 11. Cleanup

    hub_task.abort();
}
