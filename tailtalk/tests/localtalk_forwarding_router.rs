//! Learning the LocalTalk router from the traffic it forwards.
//!
//! A router that never gets its RTMP Data through to us (or sends none) and
//! does not answer ZIP GetNetInfo still relays a Chooser's lookup onto the
//! cable as a long-form DDP LkUp. Without learning anything from it, we
//! answered with short DDP from network 0 addressed straight to the
//! requester's node number, which is on another network, so the Mac never
//! saw the reply. These cases follow a capture from such a cable.

use std::time::Duration;

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, Node},
    ddp::{DdpHandle, DdpProcessor},
    nbp::{Nbp, NbpHandle, RegisteredName},
    route_table::{LearningMode, RouteTable},
};
use tailtalk_packets::{
    aarp::{AddressSource, AppleTalkAddress},
    ddp::{DdpPacket as DdpHeaders, DdpProtocolType},
    nbp::{EntityName, NbpOperation, NbpPacket, NbpTuple},
};
use tokio::sync::mpsc;

/// The cable's network number, which nothing has told us yet.
const CABLE: u16 = 35;
const ROUTER_NODE: u8 = 1;
const LT_NODE: u8 = 124;
/// The Mac running the Chooser, on a network behind the router.
const REQUESTER: AppleTalkAddress = AppleTalkAddress { network_number: 38, node_number: 207 };
const REQUESTER_SOCK: u8 = 0xFE;
const NBP_SOCK: u8 = 2;
const SERVICE_SOCK: u8 = 0x80;

struct Stack {
    _nbp: NbpHandle,
    ddp: DdpHandle,
    lt: tailtalk::addressing::AddressingHandle,
    route_table: RouteTable,
    out_rx: mpsc::Receiver<DataLinkPacket>,
}

async fn stack() -> Stack {
    let (out_tx, out_rx) = mpsc::channel(100);
    let outbound = OutboundHandle::new(out_tx);

    let lt = Addressing::spawn(
        None,
        outbound.clone(),
        Some(AppleTalkAddress { network_number: 0, node_number: LT_NODE }),
        AddressSource::LocalTalk,
    );

    let route_table = RouteTable::new(LearningMode::Dynamic);
    let ddp = DdpProcessor::spawn(None, Some(lt.clone()), outbound, route_table.clone());
    let nbp = Nbp::spawn(&ddp, None, Some(lt.clone()), route_table.clone()).await;

    tokio::time::sleep(Duration::from_millis(50)).await;

    nbp.register(RegisteredName {
        name: "ACR_LISA_MacXL:AFPServer@*".try_into().unwrap(),
        sock_num: SERVICE_SOCK,
    })
    .await
    .expect("register");

    Stack { _nbp: nbp, ddp, lt, route_table, out_rx }
}

fn long_headers(src: AppleTalkAddress, dest_net: u16, dest_node: u8, protocol: DdpProtocolType, len: usize) -> DdpHeaders {
    DdpHeaders {
        hop_count: 0,
        len: DdpHeaders::LEN + len,
        chksum: 0,
        dest_network_num: dest_net,
        src_network_num: src.network_number,
        dest_node_id: dest_node,
        dest_sock_num: NBP_SOCK,
        src_sock_num: NBP_SOCK,
        src_node_id: src.node_number,
        protocol_typ: protocol,
    }
}

/// The router's own LkUp for `=:AFPServer@Lisa_Net_LT`, broadcast on the
/// cable from its NBP socket on behalf of `requester`.
fn inject_router_lookup(ddp: &DdpHandle, requester: AppleTalkAddress) {
    let mut tuples = tailtalk_packets::heapless::Vec::new();
    tuples
        .push(NbpTuple {
            network_number: requester.network_number,
            node_id: requester.node_number,
            socket_number: REQUESTER_SOCK,
            enumerator: 0,
            entity_name: EntityName {
                object: "=".try_into().unwrap(),
                entity_type: "AFPServer".try_into().unwrap(),
                zone: "Lisa_Net_LT".try_into().unwrap(),
            },
        })
        .expect("one tuple fits");
    let packet = NbpPacket { operation: NbpOperation::Lookup, transaction_id: 0x17, tuples };
    let mut buf = [0u8; 128];
    let len = packet.to_bytes(&mut buf).expect("serialize LkUp");

    let router = AppleTalkAddress { network_number: CABLE, node_number: ROUTER_NODE };
    let headers = long_headers(router, CABLE, 255, DdpProtocolType::Nbp, len);
    ddp.received_localtalk_long_pkt(headers, buf[..len].into(), ROUTER_NODE);
}

/// Collect the NBP LookupReply frames the stack sent.
async fn replies(out_rx: &mut mpsc::Receiver<DataLinkPacket>) -> Vec<(DataLinkPacket, DdpHeaders, NbpPacket)> {
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut found = Vec::new();
    while let Ok(frame) = out_rx.try_recv() {
        if frame.protocol != DataLinkProtocol::Ddp || !frame.ddp_long {
            if frame.protocol == DataLinkProtocol::Ddp {
                panic!("reply went out as short DDP");
            }
            continue;
        }
        let headers = DdpHeaders::parse(&frame.payload).expect("long DDP header");
        if let Ok(packet) = NbpPacket::from_bytes(&frame.payload[DdpHeaders::LEN..])
            && matches!(packet.operation, NbpOperation::LookupReply)
        {
            found.push((frame, headers, packet));
        }
    }
    found
}

/// The captured case: the reply must go to the router as long DDP, from the
/// cable's real network number, and advertise that number in its tuple.
#[tokio::test]
async fn lookup_relayed_by_router_is_answered_through_it() {
    let mut s = stack().await;
    assert!(!s.route_table.has_router());

    inject_router_lookup(&s.ddp, REQUESTER);
    let got = replies(&mut s.out_rx).await;

    assert_eq!(got.len(), 1, "the relayed lookup must be answered");
    let (frame, headers, reply) = &got[0];
    assert!(
        matches!(frame.dest_node, Node::LocalTalk(ROUTER_NODE)),
        "reply must be handed to the router, went to {:?}",
        frame.dest_node
    );
    assert_eq!(headers.dest_network_num, REQUESTER.network_number);
    assert_eq!(headers.dest_node_id, REQUESTER.node_number);
    assert_eq!(headers.src_network_num, CABLE);
    assert_eq!(reply.tuples[0].network_number, CABLE);
    assert_eq!(reply.tuples[0].node_id, LT_NODE);

    assert!(s.route_table.has_router());
    assert_eq!(s.lt.addr().await.unwrap().network_number, CABLE);
}

/// Traffic forwarded from another network names the router by its LLAP
/// source, whatever the DDP source node is.
#[tokio::test]
async fn forwarded_packet_teaches_the_router() {
    let s = stack().await;

    let headers = long_headers(REQUESTER, CABLE, LT_NODE, DdpProtocolType::Atp, 0);
    s.ddp.received_localtalk_long_pkt(headers, Box::new([]), ROUTER_NODE);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        s.route_table.route_for(REQUESTER.network_number),
        Some(AppleTalkAddress { network_number: CABLE, node_number: ROUTER_NODE })
    );
    assert_eq!(s.lt.addr().await.unwrap().network_number, CABLE);
}

/// A Mac on our own cable using long DDP is not a router.
#[tokio::test]
async fn local_long_ddp_is_not_taken_for_a_router() {
    let s = stack().await;

    let neighbour = AppleTalkAddress { network_number: CABLE, node_number: 22 };
    let headers = long_headers(neighbour, CABLE, LT_NODE, DdpProtocolType::Atp, 0);
    s.ddp.received_localtalk_long_pkt(headers, Box::new([]), neighbour.node_number);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(!s.route_table.has_router());
    assert_eq!(s.lt.addr().await.unwrap().network_number, 0);
}

/// A static table is only ever filled programmatically.
#[tokio::test]
async fn static_table_learns_nothing() {
    let table = RouteTable::new(LearningMode::Static);
    assert!(!table.note_forwarding_router(
        AppleTalkAddress { network_number: CABLE, node_number: ROUTER_NODE },
        CABLE
    ));
    assert!(!table.has_router());
    assert!(!table.is_local(CABLE));
}
