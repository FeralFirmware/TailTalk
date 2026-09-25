//! ADSP streams: between two `tailtalk-net` nodes, and against the desktop
//! stack's own ADSP over an LLAP bridge.

mod common;

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use common::{Tokio, cable, desktop, settle, start};
use embassy_futures::select::{Either, select};
use embedded_io_async::Write as _;
use tailtalk::adsp::{Adsp, AdspAddress};
use tailtalk_net::adsp::{AdspError, AdspListener, AdspStream, RX_WINDOW, TX_BUFFER};
use tailtalk_net::ddp::DdpSocket;
use tailtalk_net::{Net, ServiceAddress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::LocalSet;

fn two_nodes() -> (Net<'static, Tokio>, Net<'static, Tokio>) {
    let mut taps = cable(2).into_iter();
    let a = start(0x1111, taps.next().unwrap());
    let b = start(0x2222, taps.next().unwrap());
    (a, b)
}

fn at(net: Net<'static, Tokio>, socket: u8) -> ServiceAddress {
    let addr = net.address().expect("no address yet");
    ServiceAddress {
        network_number: addr.network_number,
        node_number: addr.node_number,
        socket_number: socket,
    }
}

async fn read_exact(stream: &AdspStream<'_, Tokio>, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 300];
    while out.len() < len {
        let n = stream.read_data(&mut buf).await;
        assert!(n > 0, "closed after {} of {len} bytes", out.len());
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[tokio::test(start_paused = true)]
async fn streams_carry_data_both_ways() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let mut client = client.expect("connect failed");
            assert_eq!(server.remote().node_number, a.address().unwrap().node_number);

            // More than a packet, so it is cut and reassembled.
            let big: Vec<u8> = (0..3000).map(|i| i as u8).collect();
            client.write_all(&big).await.unwrap();
            client.write_eom().unwrap();
            assert_eq!(read_exact(&server, big.len()).await, big);

            (&server).write_all(b"and back").await.unwrap();
            assert_eq!(read_exact(&client, 8).await, b"and back");
            client.flush().await.unwrap();
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn attentions_are_out_of_band_and_acknowledged() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.unwrap();

            // Two in a row: the second waits for the first's ack.
            let send = async {
                client.send_attention(0x000B, b"hello").await.unwrap();
                client.send_attention(0x0006, b"").await.unwrap();
            };
            let receive = async {
                let mut buf = [0u8; 16];
                let mut seen = Vec::new();
                while seen.len() < 2 {
                    match select(server.read_data(&mut buf), server.attention()).await {
                        Either::First(n) => panic!("no data was sent, read {n}"),
                        Either::Second(m) => seen.push(m.unwrap()),
                    }
                }
                seen
            };
            let ((), seen) = tokio::join!(send, receive);
            assert_eq!(seen, vec![(0x000B, b"hello".to_vec()), (0x0006, vec![])]);
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn closing_ends_the_peers_stream() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.unwrap();

            client.write_data(b"last words").await.unwrap();
            client.close().await.unwrap();

            // Data before the close is still delivered, then end of stream.
            assert_eq!(read_exact(&server, 10).await, b"last words");
            let mut buf = [0u8; 8];
            assert_eq!(server.read_data(&mut buf).await, 0);
            assert_eq!(server.attention().await, None);
            assert_eq!(server.write_data(b"x").await, Err(AdspError::Closed));
        })
        .await;
}

/// A reader that stops reading holds the writer back, and everything
/// arrives once it starts again. Needs the window to be announced when it
/// reopens: the reader has nothing to send of its own.
#[tokio::test(start_paused = true)]
async fn slow_reader_pushes_back_on_the_writer() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.unwrap();

            let total = 32 * 1024;
            let data: Vec<u8> = (0..total).map(|i| (i % 253) as u8).collect();
            let taken = Rc::new(Cell::new(0usize));
            let writer = {
                let (data, taken) = (data.clone(), taken.clone());
                tokio::task::spawn_local(async move {
                    while taken.get() < data.len() {
                        let n = client.write_data(&data[taken.get()..]).await.unwrap();
                        taken.set(taken.get() + n);
                    }
                    client.flush_data().await.unwrap();
                })
            };

            // Nobody reads for a while. The writer must stall with no more
            // out than the reader's window and its own send queue.
            tokio::time::sleep(Duration::from_secs(5)).await;
            assert!(
                taken.get() <= RX_WINDOW + TX_BUFFER,
                "writer got {} bytes out to a reader that never read",
                taken.get()
            );

            // A window that reopens without telling the writer stalls here
            // forever, so fail rather than hang.
            let got = tokio::time::timeout(Duration::from_secs(60), read_exact(&server, total))
                .await
                .expect("writer never resumed: was the reopened window announced?");
            assert_eq!(got, data);
            writer.await.unwrap();
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn connecting_to_nobody_fails() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());
            let deaf = at(b, 200);
            assert_eq!(
                AdspStream::connect(a, deaf).await.err(),
                Some(AdspError::OpenFailed)
            );
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_closed_connection_gives_its_socket_back() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, _server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.unwrap();
            let socket = client.local_socket();
            assert!(DdpSocket::bind(a, Some(socket)).is_err());

            drop(client);
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(DdpSocket::bind(a, Some(socket)).is_ok(), "socket not reclaimed");
        })
        .await;
}

// ── Against the desktop stack ────────────────────────────────────────

#[tokio::test]
async fn desktop_client_talks_to_a_net_listener() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xBEEF, link);
            let addr = settle(net, &desk).await;

            let listener = AdspListener::bind(net, None).unwrap();
            let target = AdspAddress {
                network_number: addr.network_number,
                node_number: addr.node_number,
                socket_number: listener.socket(),
            };
            let (desktop_side, server) =
                tokio::join!(Adsp::connect(&desk.ddp, target), listener.accept());
            let mut desktop_side = desktop_side.expect("desktop connect failed");

            // Bigger than the listener's window, so the desktop's flush can
            // only finish while this side reads: back pressure across both
            // implementations.
            let big: Vec<u8> = (0..5000).map(|i| (i * 7) as u8).collect();
            let send = async {
                desktop_side.write_all(&big).await.unwrap();
                desktop_side.flush().await.unwrap();
            };
            let ((), got) = tokio::join!(send, read_exact(&server, big.len()));
            assert_eq!(got, big);

            (&server).write_all(b"pong").await.unwrap();
            let mut buf = [0u8; 4];
            desktop_side.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");

            desktop_side.send_attention(0x0012, b"kill").await.unwrap();
            assert_eq!(server.attention().await, Some((0x0012, b"kill".to_vec())));
            server.send_attention(0x0006, b"").await.unwrap();
            assert_eq!(desktop_side.attention().await, Some((0x0006, vec![])));

            desktop_side.close().await.unwrap();
            let mut buf = [0u8; 1];
            assert_eq!(server.read_data(&mut buf).await, 0);
        })
        .await;
}

#[tokio::test]
async fn net_client_talks_to_a_desktop_listener() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xBEEF, link);
            settle(net, &desk).await;

            let (socket, mut listener) = Adsp::bind(&desk.ddp, None).await.unwrap();
            let target = ServiceAddress {
                network_number: common::DESKTOP_ADDR.network_number,
                node_number: common::DESKTOP_ADDR.node_number,
                socket_number: socket,
            };
            let (client, desktop_side) = tokio::join!(AdspStream::connect(net, target), listener.accept());
            let mut client = client.expect("net connect failed");
            let mut desktop_side = desktop_side.unwrap();

            let big: Vec<u8> = (0..5000).map(|i| (i * 3) as u8).collect();
            client.write_all(&big).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; big.len()];
            desktop_side.read_exact(&mut got).await.unwrap();
            assert_eq!(got, big);

            desktop_side.write_all(b"ack").await.unwrap();
            desktop_side.flush().await.unwrap();
            assert_eq!(read_exact(&client, 3).await, b"ack");

            client.send_attention(0x000B, b"job").await.unwrap();
            assert_eq!(desktop_side.attention().await, Some((0x000B, b"job".to_vec())));
        })
        .await;
}
