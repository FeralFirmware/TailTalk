//! Two `tailtalk-net` nodes on one in-memory cable.

mod common;

use std::time::Duration;

use common::{Tokio, cable, start};
use tailtalk_net::atp::{AtpSocket, AtpTimeout};
use tailtalk_net::ddp::DdpSocket;
use tailtalk_net::{BindError, DdpProtocolType, Net, ServiceAddress};
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

#[tokio::test(start_paused = true)]
async fn nodes_claim_distinct_addresses() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            let (addr_a, addr_b) = tokio::join!(a.wait_address(), b.wait_address());
            assert_ne!(addr_a.node_number, addr_b.node_number);
            assert!((128..=254).contains(&addr_a.node_number));
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn ddp_datagrams_cross_the_cable() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let sa = DdpSocket::bind(a, None).unwrap();
            let sb = DdpSocket::bind(b, Some(100)).unwrap();
            sa.send_to(at(b, 100), DdpProtocolType::Other(99), b"hello")
                .unwrap();

            let dg = sb.recv().await;
            assert_eq!(dg.payload, b"hello");
            assert_eq!(dg.src_socket, sa.socket());
            assert_eq!(dg.src.node_number, a.address().unwrap().node_number);
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn datagrams_to_ourselves_loop_back() {
    LocalSet::new()
        .run_until(async {
            let (a, _b) = two_nodes();
            a.wait_address().await;
            let s1 = DdpSocket::bind(a, None).unwrap();
            let s2 = DdpSocket::bind(a, None).unwrap();
            s1.send_to(at(a, s2.socket()), DdpProtocolType::Other(99), b"me")
                .unwrap();
            assert_eq!(s2.recv().await.payload, b"me");
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn atp_transaction_round_trip() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let client = AtpSocket::bind(a, None).unwrap();
            let server = AtpSocket::bind(b, None).unwrap();
            let server_addr = at(b, server.socket());

            let serve = async {
                let req = server.next_request().await;
                assert_eq!(req.data, b"ping");
                assert_eq!(req.user_bytes, [1, 2, 3, 4]);
                // Big enough to need three packets.
                let reply = vec![0x5A; 1200];
                server.respond(&req, [9, 9, 9, 9], &reply);
            };
            let ask = client.request(server_addr, [1, 2, 3, 4], b"ping", 0xFF);
            let ((), response) = tokio::join!(serve, ask);

            let response = response.expect("request timed out");
            assert_eq!(response.user_bytes, [9, 9, 9, 9]);
            assert_eq!(response.data, vec![0x5A; 1200]);
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn concurrent_requests_get_their_own_responses() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let client = AtpSocket::bind(a, None).unwrap();
            let server = AtpSocket::bind(b, None).unwrap();
            let server_addr = at(b, server.socket());

            // Answer in reverse order, so each waiter must pick its own.
            let serve = async {
                let first = server.next_request().await;
                let second = server.next_request().await;
                server.respond(&second, [0; 4], &second.data);
                server.respond(&first, [0; 4], &first.data);
            };
            let one = client.request(server_addr, [0; 4], b"one", 0x01);
            let two = client.request(server_addr, [0; 4], b"two", 0x01);
            let ((), one, two) = tokio::join!(serve, one, two);
            assert_eq!(one.unwrap().data, b"one");
            assert_eq!(two.unwrap().data, b"two");
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn unanswered_request_times_out_after_the_retry_budget() {
    LocalSet::new()
        .run_until(async {
            let (a, b) = two_nodes();
            tokio::join!(a.wait_address(), b.wait_address());

            let client = AtpSocket::bind(a, None).unwrap();
            // An open socket nobody answers on.
            let deaf = AtpSocket::bind(b, None).unwrap();

            let started = tokio::time::Instant::now();
            let outcome = client
                .request(at(b, deaf.socket()), [0; 4], b"?", 0x01)
                .await;
            assert_eq!(outcome, Err(AtpTimeout));
            // Eight retransmits 2 s apart, then it gives up.
            assert!(started.elapsed() >= Duration::from_secs(18));
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn dropped_sockets_free_their_number() {
    LocalSet::new()
        .run_until(async {
            let (a, _b) = two_nodes();
            let s = DdpSocket::bind(a, Some(100)).unwrap();
            assert_eq!(
                DdpSocket::bind(a, Some(100)).err(),
                Some(BindError::SocketInUse)
            );
            drop(s);
            assert!(AtpSocket::bind(a, Some(100)).is_ok());
        })
        .await;
}
