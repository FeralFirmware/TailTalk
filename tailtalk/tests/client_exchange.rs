use tailtalk::DataLinkProtocol;
use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    DataLinkPacket, OutboundHandle,
    addressing::Addressing,
    atp::Atp,
    ddp::DdpProcessor,
    route_table::{LearningMode, RouteTable},
    echo::Echo,
    nbp::{Nbp, RegisteredName},
};
use tailtalk_packets::aarp::{AddressSource, AppleTalkAddress};
use tailtalk_packets::ddp::DdpProtocolType;
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
    #[allow(dead_code)]
    mac: [u8; 6],
    #[allow(dead_code)]
    addressing: tailtalk::addressing::AddressingHandle,
    #[allow(dead_code)]
    ddp: tailtalk::ddp::DdpHandle,
    nbp: tailtalk::nbp::NbpHandle,
    echo: tailtalk::echo::EchoHandle,
    atp: tailtalk::atp::AtpRequestor,
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

        let addressing = Addressing::spawn(Some(mac), outbound_handle.clone(), None, AddressSource::EtherTalkPhase2);
        let ddp = DdpProcessor::spawn(Some(addressing.clone()), None, outbound_handle.clone(), RouteTable::new(LearningMode::Static));

        let echo = Echo::spawn(&ddp).await;
        let (_atp_socket, atp_req, mut atp_resp) = Atp::spawn(&ddp, atp_socket).await;

        // Auto-responder for ATP (Echo behavior for testing)
        tokio::spawn(async move {
            while let Some(req) = atp_resp.next().await {
                let _ = req.send_response(req.data.clone(), req.user_bytes).await;
            }
        });

        let nbp = Nbp::spawn(&ddp, Some(addressing.clone()), None, RouteTable::new(LearningMode::Static)).await;

        let mut rx = hub_rx;
        let ddp_handle = ddp.clone();
        let addressing_handle = addressing.clone();

        tokio::spawn(async move {
            loop {
                if let Ok(wire_pkt) = rx.recv().await {
                    let src_mac = wire_pkt.src_mac;
                    let pkt = &wire_pkt.packet;

                    tracing::info!(
                        "TestClient {:?} received pkt from {:?} type {:?}",
                        mac,
                        src_mac,
                        pkt.protocol
                    );

                    if src_mac == mac {
                        continue;
                    }

                    let dest_mac = if let tailtalk::addressing::Node::EtherTalkPhase2(m) = pkt.dest_node { m } else { [0; 6] };
                    if dest_mac == mac || tailtalk::addressing::Addressing::is_broadcast_mac(dest_mac, AddressSource::EtherTalkPhase2) {
                        tracing::info!(
                            "TestClient {:?} processing pkt (dst_mac: {:?})",
                            mac,
                            if let tailtalk::addressing::Node::EtherTalkPhase2(mac) = pkt.dest_node { mac } else { [0; 6] }
                        );
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
                    } else {
                        tracing::info!(
                            "TestClient {:?} IGNORING pkt (dst_mac: {:?})",
                            mac,
                            if let tailtalk::addressing::Node::EtherTalkPhase2(mac) = pkt.dest_node { mac } else { [0; 6] }
                        );
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
async fn test_client_exchange() {
    let _ = tracing_subscriber::fmt().try_init(); // Ignore error if already initialized

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    // Spawn Hub runner
    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Client A
    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_a = TestClient::new(mac_a, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // 3. Setup Client B
    let mac_b = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let client_b = TestClient::new(mac_b, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // 4. Client A registers name
    let name_str = "ClientA:Workstation@*";
    tokio::time::sleep(Duration::from_millis(1500)).await;

    client_a
        .nbp
        .register(RegisteredName {
            name: name_str.try_into().unwrap(),
            sock_num: 123,
        })
        .await
        .expect("Client A failed to register");

    // 5. Client B looks up Client A
    tokio::time::sleep(Duration::from_millis(100)).await;

    let lookup_name = "ClientA:Workstation@*".try_into().unwrap();
    let results = client_b
        .nbp
        .lookup(lookup_name)
        .await
        .expect("Client B lookup failed");

    assert!(!results.is_empty(), "Client B found no results");
    let target = &results[0];
    assert_eq!(target.entity_name.object.as_wire(), b"ClientA");

    println!(
        "Client B resolved Client A to: {}.{}",
        target.network_number, target.node_id
    );

    // 6. Client B sends Echo to Client A
    let target_addr = AppleTalkAddress {
        network_number: target.network_number,
        node_number: target.node_id,
    };

    let payload = b"Hello AppleTalk";
    client_b
        .echo
        .send(target_addr, payload)
        .await
        .expect("failed to send echo");

    println!("✓ Integration test passed: Two clients successfully exchanged packets!");

    // Clean up: abort background tasks so the test exits cleanly
    hub_task.abort();
}

#[tokio::test]
async fn test_nbp_lookup() {
    let _ = tracing_subscriber::fmt().try_init(); // Ignore error if already initialized

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Client A
    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_a = TestClient::new(mac_a, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // 3. Setup Client B
    let mac_b = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let client_b = TestClient::new(mac_b, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // Wait for addressing to settle
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 4. Client A registers multiple NBP names
    client_a
        .nbp
        .register(RegisteredName {
            name: "FileServer:AFPServer@*".try_into().unwrap(),
            sock_num: 100,
        })
        .await
        .expect("Failed to register FileServer");

    client_a
        .nbp
        .register(RegisteredName {
            name: "PrintServer:LaserWriter@*".try_into().unwrap(),
            sock_num: 101,
        })
        .await
        .expect("Failed to register PrintServer");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 5. Client B looks up specific name
    let results = client_b
        .nbp
        .lookup("FileServer:AFPServer@*".try_into().unwrap())
        .await
        .expect("Lookup failed");

    assert_eq!(results.len(), 1, "Should find exactly one FileServer");
    assert_eq!(results[0].entity_name.object.as_wire(), b"FileServer");
    assert_eq!(results[0].entity_name.entity_type.as_wire(), b"AFPServer");
    assert_eq!(results[0].socket_number, 100);

    // 6. Client B looks up with wildcard
    let results = client_b
        .nbp
        .lookup("=:=@*".try_into().unwrap())
        .await
        .expect("Wildcard lookup failed");

    assert_eq!(results.len(), 2, "Should find both registered names");

    // 7. Client B looks up non-existent name
    let results = client_b
        .nbp
        .lookup("NonExistent:Service@*".try_into().unwrap())
        .await
        .expect("Lookup should succeed even if no results");

    assert_eq!(results.len(), 0, "Should find no results");

    println!("✓ NBP test passed: Registration and lookup working correctly!");

    hub_task.abort();
}

#[tokio::test]
async fn test_atp_request_response() {
    let _ = tracing_subscriber::fmt().try_init();

    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_a = TestClient::new(mac_a, hub_in_tx.clone(), hub_ref.subscribe(), Some(201)).await;

    let mac_b = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let client_b = TestClient::new(mac_b, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Register Client A so Client B can look up its address
    client_a
        .nbp
        .register(RegisteredName {
            name: "TestServer:ATP@*".try_into().unwrap(),
            sock_num: 201, // ATP uses socket 201
        })
        .await
        .expect("Failed to register ATP server");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let results = client_b
        .nbp
        .lookup("TestServer:ATP@*".try_into().unwrap())
        .await
        .expect("NBP lookup failed");

    assert!(!results.is_empty(), "Could not find ATP server");
    let server_info = &results[0];

    let atp_address = tailtalk::atp::AtpAddress {
        network_number: server_info.network_number,
        node_number: server_info.node_id,
        socket_number: 201, // ATP uses socket 201
    };

    let user_bytes = [0xDE, 0xAD, 0xBE, 0xEF];
    let request_data = b"Hello ATP!".to_vec();

    let (response, _user_bytes) = client_b
        .atp
        .send_request(atp_address, user_bytes, request_data.clone())
        .await
        .expect("ATP request failed");

    assert_eq!(
        response, request_data,
        "Response data should match request data"
    );

    println!("✓ ATP test passed: Request/response exchange successful!");

    hub_task.abort();
}

/// Several AEP requests to the same node at once must all be answered.
///
/// The echo actor tracks outstanding requests per destination, matching each
/// reply to the request whose data it carries. Keying only on the address would
/// let a second request displace the first, stranding its caller and, worse,
/// crediting the first reply that lands to whichever request is outstanding by
/// then - a ping test would report round-trip times it never measured.
#[tokio::test]
async fn test_concurrent_echoes_to_one_node() {
    let _ = tracing_subscriber::fmt().try_init(); // Ignore error if already initialized

    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let mac_a = [0x00, 0x01, 0x02, 0x03, 0x04, 0x11];
    let client_a = TestClient::new(mac_a, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    let mac_b = [0x00, 0x01, 0x02, 0x03, 0x04, 0x12];
    let client_b = TestClient::new(mac_b, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    tokio::time::sleep(Duration::from_millis(1500)).await;

    client_a
        .nbp
        .register(RegisteredName {
            name: "EchoTarget:Workstation@*".try_into().unwrap(),
            sock_num: 123,
        })
        .await
        .expect("Client A failed to register");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let results = client_b
        .nbp
        .lookup("EchoTarget:Workstation@*".try_into().unwrap())
        .await
        .expect("Client B lookup failed");
    assert!(!results.is_empty(), "Client B found no results");

    let target_addr = AppleTalkAddress {
        network_number: results[0].network_number,
        node_number: results[0].node_id,
    };

    // Distinct payloads, and distinct lengths, so a reply can only be matched to
    // the request that produced it.
    const PROBES: u32 = 5;
    let sends = (0..PROBES).map(|seq| {
        let echo = client_b.echo.clone();
        async move {
            let mut payload = seq.to_be_bytes().to_vec();
            payload.extend(std::iter::repeat_n(seq as u8, seq as usize * 4));
            echo.send(target_addr, &payload).await
        }
    });

    let results = futures::future::join_all(sends).await;
    for (seq, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "echo {seq} of {PROBES} was not answered: {:?}",
            result.as_ref().err()
        );
    }

    hub_task.abort();
}

/// A node that answers AEP with data other than what it was sent.
///
/// Stands in for the case the matching in `Echo` exists to handle: a reply whose
/// data belongs to no outstanding request. The realistic source of one is a
/// probe that timed out and whose answer turns up afterwards, which is awkward
/// to stage; a peer that mangles the data reaches the same code path without
/// depending on timing.
async fn spawn_mangling_echoer(
    mac: [u8; 6],
    hub_tx: mpsc::Sender<WirePacket>,
    hub_rx: broadcast::Receiver<WirePacket>,
) -> AppleTalkAddress {
    let (out_tx, mut out_rx) = mpsc::channel(100);
    let outbound_handle = OutboundHandle::new(out_tx);

    let hub_tx_clone = hub_tx.clone();
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            let _ = hub_tx_clone
                .send(WirePacket { packet: Arc::new(pkt), src_mac: mac })
                .await;
        }
    });

    let addressing = Addressing::spawn(
        Some(mac),
        outbound_handle.clone(),
        None,
        AddressSource::EtherTalkPhase2,
    );
    let ddp = DdpProcessor::spawn(
        Some(addressing.clone()),
        None,
        outbound_handle.clone(),
        RouteTable::new(LearningMode::Static),
    );

    // Feed the hub's traffic in, exactly as TestClient does.
    let mut rx = hub_rx;
    let ddp_handle = ddp.clone();
    let addressing_handle = addressing.clone();
    tokio::spawn(async move {
        while let Ok(wire_pkt) = rx.recv().await {
            if wire_pkt.src_mac == mac {
                continue;
            }
            let pkt = &wire_pkt.packet;
            let dest_mac = if let tailtalk::addressing::Node::EtherTalkPhase2(m) = pkt.dest_node {
                m
            } else {
                [0; 6]
            };
            if dest_mac != mac
                && !tailtalk::addressing::Addressing::is_broadcast_mac(
                    dest_mac,
                    AddressSource::EtherTalkPhase2,
                )
            {
                continue;
            }
            match pkt.protocol {
                DataLinkProtocol::Ddp => ddp_handle.received_pkt(
                    &pkt.payload,
                    AddressSource::EtherTalkPhase2,
                    wire_pkt.src_mac,
                ),
                DataLinkProtocol::Aarp => {
                    let _ = addressing_handle
                        .received_pkt(&pkt.payload, AddressSource::EtherTalkPhase2);
                }
                DataLinkProtocol::LlapEnq | DataLinkProtocol::LlapAck => {}
            }
        }
    });

    // Socket 4 is the echoer socket; no `Echo` is spawned here, so it is free.
    let mut sock = ddp
        .new_sock(DdpProtocolType::Aep, Some(4))
        .await
        .expect("failed to open AEP socket");

    tokio::spawn(async move {
        while let Ok(mut pkt) = sock.recv().await {
            if pkt.payload.first() != Some(&1) {
                continue; // not an AEP Request
            }
            pkt.payload[0] = 2; // Reply
            // Replace the data with something that is neither equal to nor a
            // prefix of what was sent.
            for b in pkt.payload[1..].iter_mut() {
                *b = 0xEE;
            }
            let dst = AppleTalkAddress {
                network_number: pkt.headers.src_network_num,
                node_number: pkt.headers.src_node_id,
            };
            let _ = sock
                .send_to(
                    &pkt.payload,
                    tailtalk::ddp::DdpAddress::new(dst, pkt.headers.src_sock_num),
                )
                .await;
        }
    });

    addressing.addr().await.expect("echoer never got an address")
}

/// A reply carrying data we never sent must not resolve a pending request.
///
/// Crediting it to whichever request happens to be outstanding would report a
/// round-trip time nobody measured and mark a still-unanswered probe as
/// answered. Treating it as loss is the honest outcome.
#[tokio::test]
async fn test_unmatched_echo_reply_is_not_credited() {
    let _ = tracing_subscriber::fmt().try_init(); // Ignore error if already initialized

    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let echoer_addr = spawn_mangling_echoer(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x21],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
    )
    .await;

    let client = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0x22],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        None,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let result = client
        .echo
        .send_timeout(echoer_addr, b"probe-payload", Duration::from_millis(750))
        .await;

    let err = result.expect_err("a reply with data we never sent must not count as an answer");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "expected the probe to be reported as lost, got: {err}"
    );

    hub_task.abort();
}
