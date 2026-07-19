//! RTMP listener actor.
//!
//! Routers broadcast an RTMP Data packet on every directly-connected cable
//! roughly every 10 seconds. Seeing one means a router is present, so its
//! tuples are fed into the [`RouteTable`] — tagged with the interface they
//! arrived on — which is what makes NBP dispatch switch from local broadcast
//! to a directed request at the router, and DDP switch to long-form headers
//! on LocalTalk.
//!
//! The broadcast also describes the local cable itself:
//!
//! * On a nonextended network (LocalTalk, Phase 1 EtherTalk) the RTMP header
//!   carries the cable's network number, which nodes glean to replace their
//!   provisional network 0 — classic "RTMP stub" behaviour.
//! * On an extended network the mandatory first tuple is the sender's own
//!   cable range.
//!
//! Both are recorded as the interface's local range. The first router seen on
//! a cable also triggers a ZIP GetNetInfo refresh, so a router that boots
//! after us still gets asked for the zone and (on EtherTalk) a proper
//! in-range address.
//!
//! Learned routes expire if not refreshed (see [`RouteTable`]); a periodic
//! tick here reclaims them. Tuples advertised at distance 31 ("notify
//! neighbor") are poisoned routes and are removed rather than inserted.
//!
//! Receive-only: TailTalk never originates RTMP packets of its own.

use std::collections::HashSet;
use std::time::Duration;

use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::rtmp::{RTMP_SOCKET, RtmpDataPacket, RtmpTuple};

use crate::addressing::AddressingHandle;
use crate::ddp::{DdpHandle, DdpSocket, Packet};
use crate::route_table::{CableRange, Interface, RouteTable};
use crate::zip::ZipHandle;

/// Distance at which a tuple means "this route is gone" (notify neighbor).
const RTMP_DISTANCE_UNREACHABLE: u8 = 31;

pub struct Rtmp {
    sock: DdpSocket,
    route_table: RouteTable,
    /// Used to adopt the gleaned network number on nonextended LocalTalk.
    lt_addressing: Option<AddressingHandle>,
    /// Poked to re-run GetNetInfo when a router first appears on a cable.
    zip: Option<ZipHandle>,
    /// Interfaces a router has already been seen on (ZIP refresh debounce).
    seen_router_on: HashSet<Interface>,
}

impl Rtmp {
    /// Spawn the RTMP listener actor.
    pub async fn spawn(
        ddp: &DdpHandle,
        route_table: RouteTable,
        lt_addressing: Option<AddressingHandle>,
        zip: Option<ZipHandle>,
    ) {
        let sock = ddp
            .new_sock(DdpProtocolType::RtmpResponse, Some(RTMP_SOCKET))
            .await
            .expect("failed to create RTMP sock");

        let rtmp = Rtmp {
            sock,
            route_table,
            lt_addressing,
            zip,
            seen_router_on: HashSet::new(),
        };
        tokio::spawn(async move { rtmp.run().await });
    }

    async fn run(mut self) {
        let mut purge = tokio::time::interval(Duration::from_secs(10));
        purge.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                recv = self.sock.recv() => {
                    match recv {
                        Ok(pkt) => self.handle_packet(&pkt).await,
                        Err(_) => break,
                    }
                }
                _ = purge.tick() => self.route_table.purge_expired(),
            }
        }
    }

    async fn handle_packet(&mut self, pkt: &Packet) {
        let data = match RtmpDataPacket::parse(&pkt.payload) {
            Ok(data) => data,
            Err(e) => {
                tracing::debug!("RTMP: failed to parse Data packet: {e}");
                return;
            }
        };

        // The actor only runs where the underlay is in-process, so the
        // arrival link is always known.
        let source = pkt.source;
        let iface = Interface::from(source);

        // Unlike a forwarded NBP Lookup, an RTMP Data packet is always sent
        // directly by the router itself, so the DDP source is its address. On
        // LocalTalk it arrives as short-form DDP with no network number (DDP
        // source network 0), so fall back to the cable number the RTMP header
        // advertises — otherwise we'd address the router as net 0 rather than
        // its real address, which not every router honours.
        let router = AppleTalkAddress {
            network_number: if pkt.headers.src_network_num != 0 {
                pkt.headers.src_network_num
            } else {
                data.router_network
            },
            node_number: pkt.headers.src_node_id,
        };

        self.learn_local_cable(iface, &data).await;

        // Hearing any RTMP broadcast means a router is on this cable. Record it
        // as the A-Router so off-cable traffic has a next hop even when the
        // broadcast carries no route tuples — the case for LocalTalk–EtherTalk
        // bridges like AsanteTalk, which announce themselves in the header only.
        self.route_table.note_router(router, iface);

        // First time we've seen a router on this cable: it implies zones and
        // (on EtherTalk) a real cable range to move into, so ask ZIP to
        // rediscover. Fires regardless of whether the broadcast carried route
        // tuples — a tupleless bridge is still a router worth querying.
        if self.seen_router_on.insert(iface) {
            tracing::info!(
                "RTMP: router {}.{} appeared on {iface:?}; switching NBP to router broadcast",
                router.network_number,
                router.node_number,
            );
            if let Some(zip) = &self.zip {
                let zip = zip.clone();
                tokio::spawn(async move {
                    let _ = zip.refresh().await;
                });
            }
        }

        let (tuples, poisoned) = tuples_for_route_table(&data);
        for &(lo, hi) in &poisoned {
            tracing::info!("RTMP: router {}.{} withdrew route {lo}-{hi}",
                router.network_number, router.node_number);
            self.route_table.remove_route(lo, hi);
        }
        if !tuples.is_empty() {
            self.route_table.handle_rtmp(router, iface, &tuples);
        }
    }

    /// Record what the broadcast says about the local cable itself, and on
    /// nonextended LocalTalk adopt the gleaned network number.
    async fn learn_local_cable(&self, iface: Interface, data: &RtmpDataPacket) {
        let Some((lo, hi)) = local_cable_range(iface, data) else {
            return;
        };
        self.route_table.set_local_range_for(iface, lo, hi);

        if iface == Interface::LocalTalk
            && let Some(lt) = &self.lt_addressing
            && let Ok(cur) = lt.addr().await
            && cur.network_number != lo
        {
            tracing::info!(
                "RTMP: gleaned LocalTalk network number {lo} from router broadcast (was {})",
                cur.network_number
            );
            let new = AppleTalkAddress { network_number: lo, node_number: cur.node_number };
            if let Err(e) = lt.set_addr(new).await {
                tracing::warn!("RTMP: failed to adopt network number {lo}: {e}");
            }
        }
    }
}

/// What an RTMP Data packet reveals about the sender's own cable: the header
/// network number on nonextended networks, the mandatory first range tuple on
/// extended ones. `None` when the broadcast predates configuration (net 0).
fn local_cable_range(iface: Interface, data: &RtmpDataPacket) -> Option<CableRange> {
    match (iface, data.tuples.first()) {
        // Extended cable: the first tuple is the sender's own range.
        (Interface::EtherTalk, Some(&RtmpTuple::Extended { range_start, distance: 0, range_end })) => {
            (range_start != 0).then_some((range_start, range_end))
        }
        // Nonextended cable (LocalTalk, or Phase 1 EtherTalk): the header
        // names the network the router is sending through.
        _ => (data.router_network != 0).then_some((data.router_network, data.router_network)),
    }
}

/// Flatten an RTMP Data packet's tuples into `(range_lo, range_hi, hop_count)`
/// entries for [`RouteTable::handle_rtmp`], and separately the ranges the
/// router has poisoned (advertised at distance 31, "notify neighbor"). The
/// hop count recorded is the distance from us, i.e. one more than the
/// distance the router advertised from itself.
type RouteTuples = Vec<(u16, u16, u8)>;
type PoisonedRanges = Vec<(u16, u16)>;

fn tuples_for_route_table(data: &RtmpDataPacket) -> (RouteTuples, PoisonedRanges) {
    let mut routes = Vec::new();
    let mut poisoned = Vec::new();
    for t in &data.tuples {
        let (lo, hi, distance) = match *t {
            RtmpTuple::NonExtended { network, distance } => (network, network, distance),
            RtmpTuple::Extended { range_start, distance, range_end } => {
                (range_start, range_end, distance)
            }
        };
        if distance >= RTMP_DISTANCE_UNREACHABLE {
            poisoned.push((lo, hi));
        } else {
            routes.push((lo, hi, distance.saturating_add(1)));
        }
    }
    (routes, poisoned)
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

    /// Real RTMP Data packet from an AsanteTalk bridge: router 2.254 on
    /// non-extended LocalTalk net 2, advertising net 2 (its own), the
    /// extended EtherTalk range 3-5, and net 1.
    const ASANTETALK_RTMP_PAYLOAD: &[u8] = &[
        0x00, 0x02, // Router network: 2
        0x08, // ID length: 8 bits
        0xfe, // Node ID: 254
        0x00, 0x00, 0x82, // Non-extended version indicator ($000082)
        0x00, 0x02, 0x00, // Tuple 1: NonExtended, net 2, dist 0
        0x00, 0x03, 0x80, 0x00, 0x05, 0x82, // Tuple 2: Extended, range 3-5, dist 0
        0x00, 0x01, 0x00, // Tuple 3: NonExtended, net 1, dist 0
    ];

    #[test]
    fn tuples_for_route_table_converts_and_increments_hop_count() {
        let data = RtmpDataPacket::parse(NETATALK_RTMP_PAYLOAD).unwrap();
        let (routes, poisoned) = tuples_for_route_table(&data);
        assert_eq!(routes, vec![(0, 0, 1)]);
        assert!(poisoned.is_empty());
    }

    #[test]
    fn poisoned_tuples_are_separated() {
        // Net 7 advertised at distance 31: withdrawn, not a route.
        let payload: &[u8] = &[
            0x00, 0x02, 0x08, 0xfe, // router 2.254
            0x00, 0x00, 0x82, // version indicator
            0x00, 0x07, 0x1f, // Tuple: NonExtended, net 7, dist 31
            0x00, 0x01, 0x00, // Tuple: NonExtended, net 1, dist 0
        ];
        let data = RtmpDataPacket::parse(payload).unwrap();
        let (routes, poisoned) = tuples_for_route_table(&data);
        assert_eq!(routes, vec![(1, 1, 1)]);
        assert_eq!(poisoned, vec![(7, 7)]);
    }

    #[test]
    fn local_cable_range_nonextended_header() {
        let data = RtmpDataPacket::parse(ASANTETALK_RTMP_PAYLOAD).unwrap();
        // Arriving on LocalTalk: the header's net 2 is our cable.
        assert_eq!(local_cable_range(Interface::LocalTalk, &data), Some((2, 2)));

        // An unconfigured router (net 0) reveals nothing.
        let data = RtmpDataPacket::parse(NETATALK_RTMP_PAYLOAD).unwrap();
        assert_eq!(local_cable_range(Interface::LocalTalk, &data), None);
    }

    #[test]
    fn local_cable_range_extended_first_tuple() {
        // The same router seen from its EtherTalk side: first tuple is the
        // extended cable range 3-5.
        let payload: &[u8] = &[
            0x00, 0x03, 0x08, 0xfe, // router 3.254
            0x00, 0x03, 0x80, 0x00, 0x05, 0x82, // Tuple 1: Extended, 3-5, dist 0
            0x00, 0x02, 0x00, // Tuple 2: NonExtended, net 2, dist 0
        ];
        let data = RtmpDataPacket::parse(payload).unwrap();
        assert_eq!(local_cable_range(Interface::EtherTalk, &data), Some((3, 5)));
    }

    /// End-to-end: a real captured RTMP broadcast, once fed into the route
    /// table, is enough to flip NBP dispatch from local to router broadcast.
    #[test]
    fn seeing_rtmp_broadcast_switches_nbp_to_router_broadcast() {
        let table = RouteTable::new(LearningMode::Dynamic);
        assert_eq!(table.nbp_dispatch(NbpZone::All), NbpDispatch::LocalBroadcast);

        let data = RtmpDataPacket::parse(NETATALK_RTMP_PAYLOAD).unwrap();
        let router = addr(0, 128);
        let (routes, _) = tuples_for_route_table(&data);
        table.handle_rtmp(router, Interface::LocalTalk, &routes);

        assert_eq!(
            table.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![router])
        );
    }

    /// The AsanteTalk topology end-to-end: routes learned on LocalTalk are
    /// tagged so DDP can reach the router over the LocalTalk cable even
    /// though it has a nonzero network number.
    #[test]
    fn asantetalk_routes_are_tagged_localtalk() {
        use crate::route_table::NextHop;

        let table = RouteTable::new(LearningMode::Dynamic);
        let data = RtmpDataPacket::parse(ASANTETALK_RTMP_PAYLOAD).unwrap();
        let router = addr(2, 254);

        if let Some((lo, hi)) = local_cable_range(Interface::LocalTalk, &data) {
            table.set_local_range_for(Interface::LocalTalk, lo, hi);
        }
        let (routes, _) = tuples_for_route_table(&data);
        table.handle_rtmp(router, Interface::LocalTalk, &routes);

        // The router itself is on our cable.
        assert_eq!(
            table.resolve(2),
            Some(NextHop::Local(Interface::LocalTalk))
        );
        // The EtherTalk range behind it routes via the router, on LocalTalk.
        assert_eq!(
            table.resolve(4),
            Some(NextHop::Via { router, interface: Interface::LocalTalk })
        );
    }
}
