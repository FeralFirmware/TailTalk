//! End-to-end tests: a daemon with an empty underlay served over Unix/UDP
#![cfg(unix)]
//! sockets, exercised both by a raw protobuf client (as a C client would)
//! and by a full `TalkStack` in remote-daemon mode.

use std::time::Duration;

use tailtalk::TalkStack;
use tailtalk::route_table::NextHop;
use tailtalk_daemon::{Daemon, DaemonConfig};
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_proto as proto;
#[cfg(unix)]
use tokio::net::UnixStream;
use futures::StreamExt;

fn addr(net: u16, node: u8) -> AppleTalkAddress {
    AppleTalkAddress {
        network_number: net,
        node_number: node,
    }
}

async fn start_daemon() -> (Daemon, tempfile::TempDir, std::path::PathBuf) {
    let daemon = Daemon::start(DaemonConfig::default()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tailtalkd.sock");
    daemon.serve_unix(&path).unwrap();
    (daemon, dir, path)
}

/// Send one request and wait for its correlated reply, skipping any
/// interleaved datagrams.
async fn request(
    stream: &mut tokio_util::codec::Framed<UnixStream, proto::TailTalkCodec<proto::Request, proto::ServerMessage>>,
    id: u64,
    kind: proto::request::Kind,
) -> proto::reply::Kind {
    use futures::{SinkExt, StreamExt};
    let req = proto::Request { id, kind: Some(kind) };
    stream.send(req).await.unwrap();
    loop {
        let msg: proto::ServerMessage = stream.next()
            .await
            .unwrap()
            .expect("daemon closed connection");
        if let Some(proto::server_message::Kind::Reply(reply)) = msg.kind {
            assert_eq!(reply.id, id, "reply correlation id mismatch");
            return reply.kind.unwrap();
        }
    }
}

fn expect_ok(kind: proto::reply::Kind) {
    assert!(
        matches!(kind, proto::reply::Kind::Ok(_)),
        "expected Ok reply, got {kind:?}"
    );
}

#[tokio::test]
async fn control_plane_over_unix_socket() {
    let (_daemon, _dir, path) = start_daemon().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_util::codec::Framed::new(stream, proto::TailTalkCodec::default());

    // No interfaces configured on this daemon.
    let kind = request(
        &mut stream,
        1,
        proto::request::Kind::ListInterfaces(proto::ListInterfacesRequest {}),
    )
    .await;
    let proto::reply::Kind::Interfaces(reply) = kind else {
        panic!("expected interfaces reply");
    };
    assert!(reply.interfaces.is_empty());

    // Ping round-trips.
    expect_ok(request(&mut stream, 2, proto::request::Kind::Ping(proto::PingRequest {})).await);

    // Setting an address on a nonexistent interface reports NotFound.
    let kind = request(
        &mut stream,
        3,
        proto::request::Kind::SetAddress(proto::SetAddressRequest {
            interface: "en99".into(),
            address: Some(proto::AppleTalkAddress::new(1, 42)),
        }),
    )
    .await;
    let proto::reply::Kind::Error(err) = kind else {
        panic!("expected error reply");
    };
    assert_eq!(err.code, proto::ErrorCode::NotFound as i32);

    // Enabling multicast on a nonexistent interface reports NotFound.
    let kind = request(
        &mut stream,
        4,
        proto::request::Kind::AddMulticast(proto::AddMulticastRequest {
            interface: "en99".into(),
            address: vec![0x09, 0x00, 0x07, 0xff, 0xff, 0xff],
        }),
    )
    .await;
    let proto::reply::Kind::Error(err) = kind else {
        panic!("expected error reply");
    };
    assert_eq!(err.code, proto::ErrorCode::NotFound as i32);
}

#[tokio::test]
async fn ddp_socket_lifecycle() {
    let (_daemon, _dir, path) = start_daemon().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_util::codec::Framed::new(stream, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());

    // Dynamic socket allocation lands in the dynamic range.
    let kind = request(
        &mut stream,
        1,
        proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 0, ddp_type: 3 }),
    )
    .await;
    let proto::reply::Kind::Socket(reply) = kind else {
        panic!("expected socket reply");
    };
    assert!((64..=254).contains(&reply.socket_id));

    // A specific socket number is honoured...
    let kind = request(
        &mut stream,
        2,
        proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 100, ddp_type: 3 }),
    )
    .await;
    let proto::reply::Kind::Socket(reply) = kind else {
        panic!("expected socket reply");
    };
    assert_eq!(reply.socket_id, 100);

    // ...and taken even from a second concurrent session.
    let stream2 = UnixStream::connect(&path).await.unwrap();
    let mut stream2 = tokio_util::codec::Framed::new(stream2, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());
    let kind = request(
        &mut stream2,
        1,
        proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 100, ddp_type: 3 }),
    )
    .await;
    let proto::reply::Kind::Error(err) = kind else {
        panic!("expected AddrInUse error");
    };
    assert_eq!(err.code, proto::ErrorCode::AddrInUse as i32);

    // Sending on an open socket succeeds (delivery is best-effort: with no
    // interfaces the daemon drops the packet, exactly like local mode).
    expect_ok(
        request(
            &mut stream,
            3,
            proto::request::Kind::Send(proto::SendDatagram {
                socket_id: 100,
                dest: Some(proto::AppleTalkAddress::new(0, 255)),
                dest_socket: 2,
                payload: vec![1, 2, 3],
                ddp_type: 0,
            }),
        )
        .await,
    );

    // Close and reopen from the other session: the number is free again.
    expect_ok(
        request(
            &mut stream,
            4,
            proto::request::Kind::CloseSocket(proto::CloseSocketRequest { socket_id: 100 }),
        )
        .await,
    );
    // Deregistration runs in a background pump task; poll briefly.
    let mut reopened = false;
    for attempt in 0..50u64 {
        let kind = request(
            &mut stream2,
            10 + attempt,
            proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 100, ddp_type: 3 }),
        )
        .await;
        if matches!(kind, proto::reply::Kind::Socket(_)) {
            reopened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(reopened, "socket 100 was not released after CloseSocket");

    // Session teardown releases sockets too: drop session 2 and reopen 100.
    drop(stream2);
    let mut reopened = false;
    for attempt in 0..50u64 {
        let kind = request(
            &mut stream,
            100 + attempt,
            proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 100, ddp_type: 3 }),
        )
        .await;
        if matches!(kind, proto::reply::Kind::Socket(_)) {
            reopened = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(reopened, "socket 100 was not released after session close");
}

#[tokio::test]
async fn routing_rules_over_unix_socket() {
    let (daemon, _dir, path) = start_daemon().await;
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_util::codec::Framed::new(stream, proto::TailTalkCodec::default());

    expect_ok(
        request(
            &mut stream,
            1,
            proto::request::Kind::SetLocalRange(proto::SetLocalRangeRequest {
                range: Some(proto::CableRange { lo: 100, hi: 105 }),
            }),
        )
        .await,
    );
    expect_ok(
        request(
            &mut stream,
            2,
            proto::request::Kind::AddRoute(proto::AddRouteRequest {
                route: Some(proto::Route {
                    range: Some(proto::CableRange { lo: 200, hi: 210 }),
                    next_hop: Some(proto::AppleTalkAddress::new(100, 1)),
                    interface: 2,
                }),
            }),
        )
        .await,
    );
    expect_ok(
        request(
            &mut stream,
            3,
            proto::request::Kind::AddZone(proto::AddZoneRequest {
                zone: "Engineering".into(),
                ranges: vec![proto::CableRange { lo: 200, hi: 210 }],
            }),
        )
        .await,
    );

    // The rules are visible over the API...
    let kind = request(
        &mut stream,
        4,
        proto::request::Kind::ListRoutes(proto::ListRoutesRequest {}),
    )
    .await;
    let proto::reply::Kind::Routes(routes) = kind else {
        panic!("expected routes reply");
    };
    assert_eq!(routes.local_range, Some(proto::CableRange { lo: 100, hi: 105 }));
    assert_eq!(routes.routes.len(), 1);
    assert_eq!(routes.zones.len(), 1);
    assert_eq!(routes.zones[0].name, "Engineering");

    // ...and actually applied to the daemon's forwarding table.
    assert_eq!(
        daemon.route_table().resolve(205),
        Some(NextHop::Via { router: addr(100, 1), interface: tailtalk::route_table::Interface::EtherTalk })
    );

    // Remove and verify.
    expect_ok(
        request(
            &mut stream,
            5,
            proto::request::Kind::RemoveRoute(proto::RemoveRouteRequest {
                range: Some(proto::CableRange { lo: 200, hi: 210 }),
            }),
        )
        .await,
    );
    assert_eq!(daemon.route_table().resolve(205), None);
}

#[tokio::test]
async fn route_changes_are_pushed_to_all_clients() {
    let (daemon, _dir, path) = start_daemon().await;

    // Client B just sits connected, never asking for routes.
    let watch_stream = UnixStream::connect(&path).await.unwrap();
    let mut watcher = tokio_util::codec::Framed::new(watch_stream, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());
    // Client A modifies the rules.
    let editor = UnixStream::connect(&path).await.unwrap();
    let mut editor = tokio_util::codec::Framed::new(editor, proto::TailTalkCodec::<proto::Request, proto::ServerMessage>::default());
    expect_ok(
        request(
            &mut editor,
            1,
            proto::request::Kind::AddRoute(proto::AddRouteRequest {
                route: Some(proto::Route {
                    range: Some(proto::CableRange { lo: 200, hi: 210 }),
                    next_hop: Some(proto::AppleTalkAddress::new(100, 1)),
                    interface: 2,
                }),
            }),
        )
        .await,
    );

    // The watcher receives an unsolicited routes_changed broadcast.
    let push = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg: proto::ServerMessage =
                watcher.next().await.unwrap().unwrap();
            if let Some(proto::server_message::Kind::RoutesChanged(routes)) = msg.kind {
                return routes;
            }
        }
    })
    .await
    .expect("no routes_changed push received");
    assert_eq!(push.routes.len(), 1);
    assert_eq!(
        push.routes[0].next_hop,
        Some(proto::AppleTalkAddress::new(100, 1))
    );

    // Changes made directly on the daemon (e.g. its CLI) are pushed too.
    daemon.route_table().set_local_range_for(tailtalk::route_table::Interface::EtherTalk, 10, 15);
    let push = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let msg: proto::ServerMessage =
                watcher.next().await.unwrap().unwrap();
            if let Some(proto::server_message::Kind::RoutesChanged(routes)) = msg.kind
                && routes.local_range.is_some()
            {
                return routes;
            }
        }
    })
    .await
    .expect("no routes_changed push for daemon-side change");
    assert_eq!(push.local_range, Some(proto::CableRange { lo: 10, hi: 15 }));
}

#[tokio::test]
async fn talkstack_mirror_follows_daemon_changes() {
    let (daemon, _dir, path) = start_daemon().await;
    let stack = TalkStack::builder().daemon_unix(&path).build().await.unwrap();

    // A rule added on the daemon after the client connected shows up in the
    // client's route table via the push channel — no RPC from the client.
    daemon.route_table().insert_route(200, 210, addr(100, 1), tailtalk::route_table::Interface::EtherTalk);
    let mut synced = false;
    for _ in 0..100 {
        if stack.route_table.resolve(205) == Some(NextHop::Via { router: addr(100, 1), interface: tailtalk::route_table::Interface::EtherTalk }) {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(synced, "daemon route change did not reach the client mirror");

    // And a daemon-side removal disappears from the client too.
    daemon.route_table().remove_route(200, 210);
    let mut synced = false;
    for _ in 0..100 {
        if stack.route_table.resolve(205).is_none() {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(synced, "daemon route removal did not reach the client mirror");
}

#[tokio::test]
async fn talkstack_remote_mode_over_unix() {
    let (daemon, _dir, path) = start_daemon().await;

    // Rules configured on the daemon before the client connects…
    daemon.route_table().insert_route(200, 210, addr(100, 1), tailtalk::route_table::Interface::EtherTalk);

    let stack = TalkStack::builder().daemon_unix(&path).build().await.unwrap();

    // …are mirrored into the client's route table at build time.
    assert_eq!(
        stack.route_table.resolve(205),
        Some(NextHop::Via { router: addr(100, 1), interface: tailtalk::route_table::Interface::EtherTalk })
    );

    // Client-side modifications propagate back to the daemon.
    stack.route_table.insert_route(300, 310, addr(100, 2), tailtalk::route_table::Interface::EtherTalk);
    let mut synced = false;
    for _ in 0..100 {
        if daemon.route_table().resolve(305) == Some(NextHop::Via { router: addr(100, 2), interface: tailtalk::route_table::Interface::EtherTalk }) {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(synced, "client route change did not reach the daemon");

    // The stack's DDP layer transparently opens sockets on the daemon.
    let sock = stack.ddp.new_sock(DdpProtocolType::Atp, Some(42)).await.unwrap();
    assert_eq!(sock.socket_num(), 42);

    // NBP and AEP grabbed their well-known sockets (2 and 4) on the daemon:
    // a raw client asking for them gets AddrInUse.
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_util::codec::Framed::new(stream, proto::TailTalkCodec::default());
    for (id, well_known) in [(1u64, 2u32), (2, 4)] {
        let kind = request(
            &mut stream,
            id,
            proto::request::Kind::OpenSocket(proto::OpenSocketRequest {
                socket: well_known,
                ddp_type: 2,
            }),
        )
        .await;
        assert!(
            matches!(&kind, proto::reply::Kind::Error(e) if e.code == proto::ErrorCode::AddrInUse as i32),
            "expected socket {well_known} to be held by the remote stack, got {kind:?}"
        );
    }

    // Dropping the client socket releases it on the daemon.
    drop(sock);
    let mut released = false;
    for attempt in 0..50u64 {
        let kind = request(
            &mut stream,
            10 + attempt,
            proto::request::Kind::OpenSocket(proto::OpenSocketRequest { socket: 42, ddp_type: 3 }),
        )
        .await;
        if matches!(kind, proto::reply::Kind::Socket(_)) {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(released, "dropped client socket was not released on the daemon");
}

#[tokio::test]
async fn talkstack_remote_mode_over_udp() {
    let daemon = Daemon::start(DaemonConfig::default()).await.unwrap();
    let local = daemon
        .serve_udp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let stack = TalkStack::builder().daemon_udp(local).build().await.unwrap();

    let sock = stack.ddp.new_sock(DdpProtocolType::Adsp, None).await.unwrap();
    assert!((64..=254).contains(&sock.socket_num()));

    stack.route_table.set_local_range_for(tailtalk::route_table::Interface::EtherTalk, 50, 55);
    let mut synced = false;
    for _ in 0..100 {
        if daemon.route_table().is_local(52) {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(synced, "local range change did not reach the daemon over UDP");
}
