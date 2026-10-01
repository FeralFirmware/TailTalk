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
use tailtalk_net::adsp::{AdspError, AdspListener, AdspStream, MessageError, RX_WINDOW, TX_BUFFER};
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

/// Pulls the ADSP data packets `node` sent out of the raw LLAP frames seen on
/// the cable, as (descriptor, data length).
fn adsp_data_packets(frames: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>, node: u8) -> Vec<(u8, usize)> {
    const LLAP_SHORT_DDP: u8 = 1;
    const LLAP_LONG_DDP: u8 = 2;
    const DDP_ADSP: u8 = 7;
    const ADSP_HEADER_LEN: usize = 13;
    let mut out = Vec::new();
    while let Ok(f) = frames.try_recv() {
        let (ddp_len, ddp_type) = match f.get(2) {
            Some(&LLAP_SHORT_DDP) => (5, f.get(3 + 4)),
            Some(&LLAP_LONG_DDP) => (13, f.get(3 + 12)),
            _ => continue,
        };
        if f[1] != node || ddp_type != Some(&DDP_ADSP) {
            continue;
        }
        let len = (u16::from_be_bytes([f[3], f[4]]) & 0x3FF) as usize;
        let Some(adsp) = f.get(3 + ddp_len..3 + len) else { continue };
        if adsp.len() < ADSP_HEADER_LEN {
            continue;
        }
        let descriptor = adsp[12];
        if descriptor & tailtalk_packets::adsp::AdspPacket::FLAG_CONTROL == 0 {
            out.push((descriptor, adsp.len() - ADSP_HEADER_LEN));
        }
    }
    out
}

#[tokio::test(start_paused = true)]
async fn a_message_carries_its_eom_on_its_last_packet() {
    LocalSet::new()
        .run_until(async {
            let mut taps = cable(3).into_iter();
            let a = start(0x1111, taps.next().unwrap());
            let b = start(0x2222, taps.next().unwrap());
            let mut frames = taps.next().unwrap().into_frames();
            tokio::join!(a.wait_address(), b.wait_address());

            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.expect("connect failed");

            // Let everything settle first so the reply can't get sent along
            // with anything else.
            tokio::time::sleep(Duration::from_millis(100)).await;
            while frames.try_recv().is_ok() {}

            server.write_message(b"reply one").await.unwrap();
            assert_eq!(read_exact(&client, 9).await, b"reply one");
            server.write_message(b"reply two").await.unwrap();
            assert_eq!(read_exact(&client, 9).await, b"reply two");
            server.flush_data().await.unwrap();

            let eom = tailtalk_packets::adsp::AdspPacket::FLAG_EOM;
            let sent = adsp_data_packets(&mut frames, b.address().unwrap().node_number);
            assert!(!sent.is_empty(), "no data packets seen");
            assert!(
                sent.iter().all(|&(d, len)| len > 0 && d & eom != 0),
                "every reply one packet, flagged EOM: {sent:?}"
            );
        })
        .await;
}

/// Messages come out one per read, however their end was marked, and the
/// stream's close ends them.
#[tokio::test(start_paused = true)]
async fn messages_are_read_whole_and_one_at_a_time() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());
            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.expect("connect failed");
            let mut buf = [0u8; 16];

            // Back to back, so they can share the receive queue.
            client.write_message(b"one").await.unwrap();
            client.write_message(b"two").await.unwrap();
            assert_eq!(server.read_message(&mut buf).await, Ok(3));
            assert_eq!(&buf[..3], b"one");
            assert_eq!(server.read_message(&mut buf).await, Ok(3));
            assert_eq!(&buf[..3], b"two");

            // The end marked in an empty packet after the data went out.
            (&client).write_all(b"three").await.unwrap();
            client.flush_data().await.unwrap();
            client.write_eom().unwrap();
            assert_eq!(server.read_message(&mut buf).await, Ok(5));
            assert_eq!(&buf[..5], b"three");

            drop(client);
            assert_eq!(server.read_message(&mut buf).await, Err(MessageError::Closed));
        })
        .await;
}

/// Reads stop where messages end, as `dspRead` does, so a message longer
/// than the receive window still comes through, in parts.
#[tokio::test(start_paused = true)]
async fn reads_stop_at_the_end_of_each_message() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());
            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.expect("connect failed");

            let long: Vec<u8> = (0..RX_WINDOW * 2).map(|i| i as u8).collect();
            let read = async {
                let mut got = Vec::new();
                let mut buf = [0u8; 1000];
                loop {
                    let (n, eom) = server.read_with_eom(&mut buf).await;
                    got.extend_from_slice(&buf[..n]);
                    if eom {
                        return got;
                    }
                    assert!(n > 0, "closed mid-message");
                }
            };
            let (sent, got) = tokio::join!(client.write_message(&long), read);
            sent.unwrap();
            assert_eq!(got, long);

            client.write_message(b"ab").await.unwrap();
            client.write_message(b"cd").await.unwrap();
            client.flush_data().await.unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(server.read_data(&mut buf).await, 2);
            assert_eq!(&buf[..2], b"ab");
        })
        .await;
}

/// A message too long for the buffer goes entirely, including the part
/// that only arrives after it was refused.
#[tokio::test(start_paused = true)]
async fn a_message_too_long_is_skipped_whole() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());
            let listener = AdspListener::bind(b, None).unwrap();
            let target = at(b, listener.socket());
            let (client, server) = tokio::join!(AdspStream::connect(a, target), listener.accept());
            let client = client.expect("connect failed");
            let mut buf = [0u8; 4];

            (&client).write_all(b"too long").await.unwrap();
            client.flush_data().await.unwrap();
            assert_eq!(server.read_message(&mut buf).await, Err(MessageError::TooLong));
            client.write_message(b" still").await.unwrap();
            client.write_message(b"ok").await.unwrap();
            assert_eq!(server.read_message(&mut buf).await, Ok(2));
            assert_eq!(&buf[..2], b"ok");
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

/// If the end of a message is marked after its data has already gone out,
/// the flag travels in an empty packet. A byte stream reader needs to read
/// past that instead of treating it as the end of the stream. InkTalk's
/// control socket used to reply like this, which is how we found it.
#[tokio::test]
async fn a_bare_eom_is_not_end_of_stream_to_the_desktop() {
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

            (&server).write_all(b"one").await.unwrap();
            server.flush_data().await.unwrap();
            server.write_eom().unwrap();
            (&server).write_all(b"two").await.unwrap();

            let mut buf = [0u8; 6];
            desktop_side.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"onetwo");
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
