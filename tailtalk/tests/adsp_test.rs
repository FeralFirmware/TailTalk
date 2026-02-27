use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    EtherTalkPacket, OutboundHandle,
    addressing::Addressing,
    adsp::{Adsp, AdspAddress},
    ddp::DdpProcessor,
};
use tailtalk_packets::{aarp::AddressSource, ethertalk::EtherTalkType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    _mac: [u8; 6],
    #[allow(dead_code)]
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

        let addressing = Addressing::spawn(mac, outbound_handle.clone(), None);
        let ddp = DdpProcessor::spawn(addressing.clone(), outbound_handle.clone());

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
