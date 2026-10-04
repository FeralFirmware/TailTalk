//! Answering NBP lookups that name a zone.
//!
//! Services register as `Name:Type@*` ("my zone"). On a routerless cable the
//! requester also asks for `*`, so the literal comparison works. Once a
//! router is present a Chooser sends a BrRq for the zone it has selected and
//! the router forwards it as a LkUp carrying that zone's real name. A
//! responder that compares that name against the literal `*` never answers,
//! and the service disappears from every Chooser on a zoned network.

use std::time::Duration;

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::Addressing,
    ddp::{DdpHandle, DdpProcessor},
    nbp::{Nbp, NbpHandle, RegisteredName},
    route_table::{Interface, LearningMode, RouteTable},
};
use tailtalk_packets::{
    aarp::{AddressSource, AppleTalkAddress},
    ddp::{DdpPacket as DdpHeaders, DdpProtocolType},
    nbp::{EntityName, NbpOperation, NbpPacket, NbpTuple},
};
use tokio::sync::mpsc;

const ET_ADDR: AppleTalkAddress = AppleTalkAddress { network_number: 5501, node_number: 40 };
const LT_NODE: u8 = 12;

/// A Mac in another network doing the lookup, and the router relaying it.
const REQUESTER: AppleTalkAddress = AppleTalkAddress { network_number: 20, node_number: 7 };
/// A Mac on our own routerless LocalTalk cable.
const NEIGHBOUR: AppleTalkAddress = AppleTalkAddress { network_number: 0, node_number: 7 };
const REQUESTER_SOCK: u8 = 0xFD;
const ROUTER_NODE: u8 = 220;
const NBP_SOCK: u8 = 2;
const SERVICE_SOCK: u8 = 0x80;

struct Stack {
    nbp: NbpHandle,
    ddp: DdpHandle,
    route_table: RouteTable,
    out_rx: mpsc::Receiver<DataLinkPacket>,
}

async fn stack() -> Stack {
    let (out_tx, out_rx) = mpsc::channel(100);
    let outbound = OutboundHandle::new(out_tx);

    let et = Addressing::spawn(
        Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        outbound.clone(),
        Some(ET_ADDR),
        AddressSource::EtherTalkPhase2,
    );
    let lt = Addressing::spawn(
        None,
        outbound.clone(),
        Some(AppleTalkAddress { network_number: 0, node_number: LT_NODE }),
        AddressSource::LocalTalk,
    );

    let route_table = RouteTable::new(LearningMode::Static);
    let ddp = DdpProcessor::spawn(
        Some(et.clone()),
        Some(lt.clone()),
        outbound.clone(),
        route_table.clone(),
    );
    let nbp = Nbp::spawn(&ddp, Some(et), Some(lt), route_table.clone()).await;

    // Let the LocalTalk ENQ probe settle before anything asks for our address.
    tokio::time::sleep(Duration::from_millis(50)).await;

    nbp.register(RegisteredName {
        name: "TailTalk AFP:AFPServer@*".try_into().unwrap(),
        sock_num: SERVICE_SOCK,
    })
    .await
    .expect("register");

    Stack { nbp, ddp, route_table, out_rx }
}

/// Deliver a LkUp for `=:AFPServer@<zone>` as a router would forward it:
/// broadcast on the cable, DDP source the router, tuple naming `requester`.
fn inject_lookup(ddp: &DdpHandle, zone: &str, source: AddressSource, requester: AppleTalkAddress) {
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
                zone: zone.try_into().unwrap(),
            },
        })
        .expect("one tuple fits");
    let packet = NbpPacket { operation: NbpOperation::Lookup, transaction_id: 9, tuples };

    let mut buf = [0u8; 128];
    let len = packet.to_bytes(&mut buf).expect("serialize LkUp");

    let (net, src_node) = match source {
        AddressSource::LocalTalk => (0, ROUTER_NODE),
        _ => (ET_ADDR.network_number, ROUTER_NODE),
    };
    let headers = DdpHeaders {
        hop_count: 0,
        len: DdpHeaders::LEN + len,
        chksum: 0,
        dest_network_num: net,
        src_network_num: net,
        dest_node_id: 255,
        dest_sock_num: NBP_SOCK,
        src_sock_num: NBP_SOCK,
        src_node_id: src_node,
        protocol_typ: DdpProtocolType::Nbp,
    };
    ddp.received_parsed_pkt(headers, buf[..len].into(), source, [0x02, 0, 0, 0, 0, 0x99]);
}

/// Collect the NBP LookupReply packets the stack sent after an injection.
async fn replies(out_rx: &mut mpsc::Receiver<DataLinkPacket>) -> Vec<NbpPacket> {
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut found = Vec::new();
    while let Ok(frame) = out_rx.try_recv() {
        if frame.protocol != DataLinkProtocol::Ddp {
            continue;
        }
        // Short-form DDP (LocalTalk, no router known) has a 5-byte header.
        let header_len = if frame.ddp_long { DdpHeaders::LEN } else { 5 };
        if let Ok(packet) = NbpPacket::from_bytes(&frame.payload[header_len..])
            && matches!(packet.operation, NbpOperation::LookupReply)
        {
            found.push(packet);
        }
    }
    found
}

/// The routerless case, which already worked: both sides say "*".
#[tokio::test]
async fn star_lookup_is_answered() {
    let mut s = stack().await;
    let _keep = &s.nbp;
    inject_lookup(&s.ddp, "*", AddressSource::LocalTalk, NEIGHBOUR);

    let got = replies(&mut s.out_rx).await;
    assert_eq!(got.len(), 1, "a '*' lookup must be answered");
    assert_eq!(got[0].tuples[0].socket_number, SERVICE_SOCK);
}

/// The regression: a LocalTalk cable has exactly one zone, so a forwarded
/// LkUp naming it is for us even though we registered under "*".
#[tokio::test]
async fn named_zone_lookup_on_localtalk_is_answered() {
    let mut s = stack().await;
    let _keep = &s.nbp;
    // The router that forwarded the lookup is our way back to the requester.
    s.route_table.insert_route(
        REQUESTER.network_number,
        REQUESTER.network_number,
        AppleTalkAddress { network_number: 0, node_number: ROUTER_NODE },
        Interface::LocalTalk,
    );
    inject_lookup(&s.ddp, "Shop", AddressSource::LocalTalk, REQUESTER);

    let got = replies(&mut s.out_rx).await;
    assert_eq!(got.len(), 1, "a forwarded LkUp naming the cable's zone must be answered");
    let tuple = &got[0].tuples[0];
    assert_eq!(tuple.node_id, LT_NODE);
    assert_eq!(tuple.socket_number, SERVICE_SOCK);
}

/// On an extended network the zone must be one ZIP said our cable is in.
#[tokio::test]
async fn named_zone_lookup_on_ethertalk_checks_our_zone() {
    let mut s = stack().await;
    let _keep = &s.nbp;
    s.route_table.set_local_range_for(Interface::EtherTalk, 5500, 5510);
    s.route_table.insert_zone("Office", &[(5500, 5510)]);
    s.route_table.insert_route(
        REQUESTER.network_number,
        REQUESTER.network_number,
        AppleTalkAddress { network_number: ET_ADDR.network_number, node_number: ROUTER_NODE },
        Interface::EtherTalk,
    );

    inject_lookup(&s.ddp, "office", AddressSource::EtherTalkPhase2, REQUESTER);
    let got = replies(&mut s.out_rx).await;
    assert_eq!(got.len(), 1, "a lookup for our own zone must be answered");
    assert_eq!(got[0].tuples[0].node_id, ET_ADDR.node_number);

    inject_lookup(&s.ddp, "Warehouse", AddressSource::EtherTalkPhase2, REQUESTER);
    let got = replies(&mut s.out_rx).await;
    assert!(got.is_empty(), "a lookup for another zone on the cable must be ignored");
}
