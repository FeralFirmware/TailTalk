//! RTMP listener actor.
//!
//! Routers broadcast an RTMP Data packet on every directly-connected cable
//! roughly every 10 seconds. Seeing one means a router is present, so its
//! tuples are fed into the [`RouteTable`], which is what makes NBP dispatch
//! switch from local broadcast to a directed request at the router.
//!
//! Receive-only: TailTalk never originates RTMP packets of its own.

use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::{DdpPacket, DdpProtocolType};
use tailtalk_packets::rtmp::{RTMP_SOCKET, RtmpDataPacket, RtmpTuple};

use crate::ddp::{DdpHandle, DdpSocket};
use crate::route_table::RouteTable;

pub struct Rtmp {
    sock: DdpSocket,
    route_table: RouteTable,
}

impl Rtmp {
    /// Spawn the RTMP listener actor.
    pub async fn spawn(ddp: &DdpHandle, route_table: RouteTable) {
        let sock = ddp
            .new_sock(DdpProtocolType::RtmpResponse, Some(RTMP_SOCKET))
            .await
            .expect("failed to create RTMP sock");

        let rtmp = Rtmp { sock, route_table };
        tokio::spawn(async move { rtmp.run().await });
    }

    async fn run(mut self) {
        while let Ok(pkt) = self.sock.recv().await {
            self.handle_packet(&pkt.headers, &pkt.payload);
        }
    }

    fn handle_packet(&self, ddp: &DdpPacket, payload: &[u8]) {
        let data = match RtmpDataPacket::parse(payload) {
            Ok(data) => data,
            Err(e) => {
                tracing::debug!("RTMP: failed to parse Data packet: {e}");
                return;
            }
        };

        // Unlike a forwarded NBP Lookup, an RTMP Data packet is always sent
        // directly by the router itself, so the DDP source is its address.
        let router = AppleTalkAddress {
            network_number: ddp.src_network_num,
            node_number: ddp.src_node_id,
        };

        let tuples = tuples_for_route_table(&data);
        if tuples.is_empty() {
            return;
        }

        tracing::info!(
            "RTMP: router {}.{} advertises {} route(s); switching NBP to router broadcast",
            router.network_number,
            router.node_number,
            tuples.len(),
        );

        self.route_table.handle_rtmp(router, &tuples);
    }
}

/// Flatten an RTMP Data packet's tuples into `(range_lo, range_hi, hop_count)`
/// entries for [`RouteTable::handle_rtmp`]. The hop count recorded is the
/// distance from us, i.e. one more than the distance the router advertised
/// from itself.
fn tuples_for_route_table(data: &RtmpDataPacket) -> Vec<(u16, u16, u8)> {
    data.tuples
        .iter()
        .map(|t| match *t {
            RtmpTuple::NonExtended { network, distance } => {
                (network, network, distance.saturating_add(1))
            }
            RtmpTuple::Extended { range_start, distance, range_end } => {
                (range_start, range_end, distance.saturating_add(1))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_table::{LearningMode, NbpDispatch, NbpZone};

    fn addr(net: u16, node: u8) -> AppleTalkAddress {
        AppleTalkAddress { network_number: net, node_number: node }
    }

    /// Real RTMP Data packet captured from netatalk running tailtalkd
    /// (pcaps/netatalk.pcap, frame 42). Node 128 broadcasting on non-extended
    /// LocalTalk net 0, advertising a single route to its own net (net 0,
    /// distance 0). Same payload verified parseable in tailtalk-packets.
    const NETATALK_RTMP_PAYLOAD: &[u8] = &[
        0x00, 0x00, // Router network: 0
        0x08, // ID length: 8 bits
        0x80, // Node ID: 128
        0x00, 0x00, 0x82, // Non-extended version indicator ($000082)
        0x00, 0x00, 0x00, // Tuple 1: NonExtended, net 0, dist 0
    ];

    #[test]
    fn tuples_for_route_table_converts_and_increments_hop_count() {
        let data = RtmpDataPacket::parse(NETATALK_RTMP_PAYLOAD).unwrap();
        assert_eq!(tuples_for_route_table(&data), vec![(0, 0, 1)]);
    }

    /// End-to-end: a real captured RTMP broadcast, once fed into the route
    /// table, is enough to flip NBP dispatch from local to router broadcast.
    #[test]
    fn seeing_rtmp_broadcast_switches_nbp_to_router_broadcast() {
        let table = RouteTable::new(LearningMode::Dynamic);
        assert_eq!(table.nbp_dispatch(NbpZone::All), NbpDispatch::LocalBroadcast);

        let data = RtmpDataPacket::parse(NETATALK_RTMP_PAYLOAD).unwrap();
        let router = addr(0, 128);
        table.handle_rtmp(router, &tuples_for_route_table(&data));

        assert_eq!(
            table.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![router])
        );
    }
}
