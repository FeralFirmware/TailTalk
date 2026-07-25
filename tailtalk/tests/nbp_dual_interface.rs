//! NBP lookups on a stack with both cables configured.
//!
//! An NBP responder answers the address in the request's tuple, not the DDP
//! source address, so a lookup broadcast on two cables needs a tuple per
//! cable. Getting this wrong is invisible on a single-interface stack and
//! silently breaks discovery on the non-primary one: devices reply to an
//! address they have no route to.

use std::time::Duration;

use tailtalk::{
    DataLinkPacket, DataLinkProtocol, OutboundHandle,
    addressing::{Addressing, Node},
    ddp::DdpProcessor,
    nbp::Nbp,
    route_table::{LearningMode, RouteTable},
};
use tailtalk_packets::{
    aarp::{AddressSource, AppleTalkAddress},
    ddp::DdpPacket as DdpHeaders,
    nbp::{EntityName, NbpOperation, NbpPacket},
};
use tokio::sync::mpsc;

const ET_ADDR: AppleTalkAddress = AppleTalkAddress {
    network_number: 5501,
    node_number: 40,
};
const LT_NODE: u8 = 12;

/// An NBP packet lifted off the wire, with the cable it went out on.
struct SentNbp {
    dest_node: Node,
    packet: NbpPacket,
}

/// Pull NBP datagrams out of the link-layer frames the stack emits, ignoring
/// the AARP/LLAP traffic addressing produces on the way up.
fn extract_nbp(frames: &[DataLinkPacket]) -> Vec<SentNbp> {
    frames
        .iter()
        .filter(|f| f.protocol == DataLinkProtocol::Ddp)
        .filter_map(|f| {
            // Short-form DDP (LocalTalk, no router known) has a 5-byte header;
            // long form has the full 13.
            let header_len = if f.ddp_long { DdpHeaders::LEN } else { 5 };
            let packet = NbpPacket::from_bytes(&f.payload[header_len..]).ok()?;
            Some(SentNbp {
                dest_node: f.dest_node,
                packet,
            })
        })
        .collect()
}

/// Build a stack with an EtherTalk and a LocalTalk interface, returning its
/// NBP handle and the channel every outgoing frame lands in.
async fn dual_interface_stack() -> (tailtalk::nbp::NbpHandle, mpsc::Receiver<DataLinkPacket>) {
    let (out_tx, out_rx) = mpsc::channel(100);
    let outbound = OutboundHandle::new(out_tx);

    let et = Addressing::spawn(
        Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        outbound.clone(),
        Some(ET_ADDR),
        AddressSource::EtherTalkPhase2,
    );
    // No MAC means LocalTalk, which probes its node number via LLAP ENQ and
    // settles on network 0.
    let lt = Addressing::spawn(
        None,
        outbound.clone(),
        Some(AppleTalkAddress {
            network_number: 0,
            node_number: LT_NODE,
        }),
        AddressSource::LocalTalk,
    );

    let route_table = RouteTable::new(LearningMode::Static);
    let ddp = DdpProcessor::spawn(
        Some(et.clone()),
        Some(lt.clone()),
        outbound.clone(),
        route_table.clone(),
    );
    let nbp = Nbp::spawn(&ddp, Some(et), Some(lt), route_table).await;

    // Let the LocalTalk ENQ probe finish so its address is settled before the
    // lookup asks for it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    (nbp, out_rx)
}

/// The reply tuple must name our address on the cable each copy goes out on.
#[tokio::test]
async fn local_lookup_names_our_address_on_each_cable() {
    let (nbp, mut out_rx) = dual_interface_stack().await;

    // The lookup itself blocks for its reply-collection window; we only care
    // about what went out on the wire.
    tokio::spawn(async move {
        let _ = nbp
            .lookup(EntityName {
                object: "=".into(),
                entity_type: "LaserWriter".into(),
                zone: "*".into(),
            })
            .await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut frames = Vec::new();
    while let Ok(frame) = out_rx.try_recv() {
        frames.push(frame);
    }
    let sent = extract_nbp(&frames);

    let lookups: Vec<&SentNbp> = sent
        .iter()
        .filter(|s| matches!(s.packet.operation, NbpOperation::Lookup))
        .collect();
    assert_eq!(
        lookups.len(),
        2,
        "expected one LkUp per cable, got {}",
        lookups.len()
    );

    let et = lookups
        .iter()
        .find(|s| matches!(s.dest_node, Node::EtherTalkPhase2(_) | Node::EtherTalkPhase1(_)))
        .expect("no LkUp broadcast on the EtherTalk cable");
    let lt = lookups
        .iter()
        .find(|s| matches!(s.dest_node, Node::LocalTalk(255)))
        .expect("no LkUp broadcast on the LocalTalk cable");

    let et_tuple = &et.packet.tuples[0];
    assert_eq!(et_tuple.network_number, ET_ADDR.network_number);
    assert_eq!(et_tuple.node_id, ET_ADDR.node_number);

    // The regression: this used to carry the EtherTalk address, which no
    // LocalTalk device could route a reply to.
    let lt_tuple = &lt.packet.tuples[0];
    assert_eq!(lt_tuple.network_number, 0);
    assert_eq!(lt_tuple.node_id, LT_NODE);

    // Both copies belong to one transaction, so replies from either cable are
    // collected into the same lookup.
    assert_eq!(et.packet.transaction_id, lt.packet.transaction_id);
}
