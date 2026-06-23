use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tailtalk_packets::aarp::AppleTalkAddress;

#[derive(Debug)]
pub enum LearningMode {
    /// Populate tables from RTMP/ZIP broadcasts.
    Dynamic,
    /// Tables filled only via the programmatic API.
    Static,
}

/// Where to send a DDP packet for a given destination network.
#[derive(Debug, PartialEq, Eq)]
pub enum NextHop {
    /// Destination is on our cable; resolve with AARP and send directly.
    Local,
    /// Forward to this router.
    Via(AppleTalkAddress),
}

/// Zone portion of an NBP name.
#[derive(Debug)]
pub enum NbpZone<'a> {
    /// `*` — local zone only; never forwarded to a router.
    Local,
    /// `=` — all known zones.
    All,
    /// A specific zone name.
    Named(&'a str),
}

/// How to dispatch an NBP LkUp for a given zone.
#[derive(Debug, PartialEq, Eq)]
pub enum NbpDispatch {
    /// Broadcast on the local segment.
    ///
    /// Used when no router is known or zone is `NbpZone::Local`.
    LocalBroadcast,
    /// Send BrRq to each of these routers; they re-broadcast LkUp on their segment(s).
    RouterBroadcast(Vec<AppleTalkAddress>),
    /// Zone was requested but we have no ZIP/route info and no router is known.
    /// Caller may degrade to `LocalBroadcast`.
    ZoneUnknown,
}

// ── RTMP table ────────────────────────────────────────────────────────────────

struct RtmpEntry {
    range_lo: u16,
    range_hi: u16,
    #[allow(dead_code)] // retained for future route-age / best-path selection
    hop_count: u8,
    next_hop: AppleTalkAddress,
}

/// Sorted, non-overlapping list of cable range → next-hop mappings.
struct RtmpTable {
    entries: Vec<RtmpEntry>,
}

impl RtmpTable {
    fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// O(log n) lookup: find the entry whose range contains `net`.
    fn lookup(&self, net: u16) -> Option<&RtmpEntry> {
        let idx = self.entries.partition_point(|e| e.range_lo <= net);
        let idx = idx.checked_sub(1)?;
        let e = &self.entries[idx];
        (net <= e.range_hi).then_some(e)
    }

    /// Insert or replace a route covering [lo..=hi].
    ///
    /// Any existing entry that overlaps is removed wholesale — not trimmed.
    /// RTMP cable ranges are non-overlapping by protocol, so partial overlaps
    /// shouldn't arise in practice.
    fn insert(&mut self, lo: u16, hi: u16, next_hop: AppleTalkAddress, hop_count: u8) {
        self.entries.retain(|e| e.range_hi < lo || e.range_lo > hi);
        let pos = self.entries.partition_point(|e| e.range_lo < lo);
        self.entries.insert(pos, RtmpEntry { range_lo: lo, range_hi: hi, hop_count, next_hop });
    }

    fn remove(&mut self, lo: u16, hi: u16) {
        self.entries.retain(|e| !(e.range_lo == lo && e.range_hi == hi));
    }

    fn all_next_hops_deduped(&self) -> Vec<AppleTalkAddress> {
        let mut seen = HashSet::new();
        self.entries
            .iter()
            .filter_map(|e| seen.insert(e.next_hop).then_some(e.next_hop))
            .collect()
    }
}

// ── ZIP table ─────────────────────────────────────────────────────────────────

pub type CableRange = (u16, u16);

/// Bidirectional zone ↔ cable-range mapping.
struct ZipTable {
    range_to_zones: HashMap<CableRange, Vec<String>>,
    zone_to_ranges: HashMap<String, Vec<CableRange>>,
}

impl ZipTable {
    fn new() -> Self {
        Self {
            range_to_zones: HashMap::new(),
            zone_to_ranges: HashMap::new(),
        }
    }

    fn insert_zone_range(&mut self, zone: &str, range: CableRange) {
        let zones = self.range_to_zones.entry(range).or_default();
        if !zones.iter().any(|z| z == zone) {
            zones.push(zone.to_string());
        }
        let ranges = self.zone_to_ranges.entry(zone.to_string()).or_default();
        if !ranges.contains(&range) {
            ranges.push(range);
        }
    }

    fn remove_zone(&mut self, zone: &str) {
        if let Some(ranges) = self.zone_to_ranges.remove(zone) {
            for range in ranges {
                if let Some(zones) = self.range_to_zones.get_mut(&range) {
                    zones.retain(|z| z != zone);
                    if zones.is_empty() {
                        self.range_to_zones.remove(&range);
                    }
                }
            }
        }
    }

    fn ranges_for_zone(&self, zone: &str) -> &[CableRange] {
        self.zone_to_ranges.get(zone).map(|v| v.as_slice()).unwrap_or(&[])
    }
}

// ── Inner state ───────────────────────────────────────────────────────────────

struct Inner {
    mode: LearningMode,
    local_range: Option<CableRange>,
    rtmp: RtmpTable,
    zip: ZipTable,
}

impl Inner {
    fn is_local(&self, net: u16) -> bool {
        self.local_range.is_some_and(|(lo, hi)| lo <= net && net <= hi)
    }

    fn route_for(&self, net: u16) -> Option<NextHop> {
        if self.is_local(net) {
            return Some(NextHop::Local);
        }
        self.rtmp.lookup(net).map(|e| NextHop::Via(e.next_hop))
    }

    fn routers_for_zone(&self, zone: &str) -> Vec<AppleTalkAddress> {
        let mut seen = HashSet::new();
        self.zip
            .ranges_for_zone(zone)
            .iter()
            .filter_map(|&(lo, _)| self.rtmp.lookup(lo))
            .filter_map(|e| seen.insert(e.next_hop).then_some(e.next_hop))
            .collect()
    }

    fn nbp_dispatch(&self, zone: NbpZone<'_>) -> NbpDispatch {
        match zone {
            NbpZone::Local => NbpDispatch::LocalBroadcast,

            NbpZone::All => {
                let routers = self.rtmp.all_next_hops_deduped();
                if routers.is_empty() {
                    NbpDispatch::LocalBroadcast
                } else {
                    NbpDispatch::RouterBroadcast(routers)
                }
            }

            NbpZone::Named(name) => {
                let routers = self.routers_for_zone(name);
                if !routers.is_empty() {
                    return NbpDispatch::RouterBroadcast(routers);
                }
                // Zone not in ZIP — try any known router as a last resort.
                let any = self.rtmp.all_next_hops_deduped();
                if any.is_empty() {
                    NbpDispatch::ZoneUnknown
                } else {
                    NbpDispatch::RouterBroadcast(any)
                }
            }
        }
    }
}

// ── RouteTable ────────────────────────────────────────────────────────────────

/// Shared routing table. Clone to get additional handles to the same table.
#[derive(Clone)]
pub struct RouteTable(Arc<RwLock<Inner>>);

impl RouteTable {
    pub fn new(mode: LearningMode) -> Self {
        Self(Arc::new(RwLock::new(Inner {
            mode,
            local_range: None,
            rtmp: RtmpTable::new(),
            zip: ZipTable::new(),
        })))
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    /// Set the cable range for our own segment.
    ///
    /// Required for [`is_local`](Self::is_local) and
    /// [`route_for`](Self::route_for) to distinguish on-segment destinations.
    pub fn set_local_range(&self, lo: u16, hi: u16) {
        self.0.write().unwrap().local_range = Some((lo, hi));
    }

    // ── Programmatic inserts ──────────────────────────────────────────────────

    /// Insert or replace a route: DDP packets for `[lo..=hi]` go to `next_hop`.
    pub fn insert_route(&self, lo: u16, hi: u16, next_hop: AppleTalkAddress) {
        self.0.write().unwrap().rtmp.insert(lo, hi, next_hop, 1);
    }

    /// Remove the route covering exactly `[lo..=hi]`.
    pub fn remove_route(&self, lo: u16, hi: u16) {
        self.0.write().unwrap().rtmp.remove(lo, hi);
    }

    /// Associate `zone` with one or more cable ranges.
    ///
    /// The ranges should have (or will have) matching [`insert_route`](Self::insert_route)
    /// entries for NBP dispatch to resolve a router.
    pub fn insert_zone(&self, zone: &str, ranges: &[CableRange]) {
        let mut inner = self.0.write().unwrap();
        for &range in ranges {
            inner.zip.insert_zone_range(zone, range);
        }
    }

    /// Remove all cable-range associations for `zone`.
    pub fn remove_zone(&self, zone: &str) {
        self.0.write().unwrap().zip.remove_zone(zone);
    }

    // ── Dynamic learning ──────────────────────────────────────────────────────

    /// Process an RTMP data packet received from `src`.
    ///
    /// Each tuple is `(range_lo, range_hi, hop_count)`. No-op in
    /// [`LearningMode::Static`].
    pub fn handle_rtmp(&self, src: AppleTalkAddress, tuples: &[(u16, u16, u8)]) {
        if matches!(self.0.read().unwrap().mode, LearningMode::Static) {
            return;
        }
        let mut inner = self.0.write().unwrap();
        for &(lo, hi, hops) in tuples {
            inner.rtmp.insert(lo, hi, src, hops);
        }
    }

    /// Process a ZIP GetNetInfo / GetZoneList reply tying `range` to the given zones.
    /// No-op in [`LearningMode::Static`].
    pub fn handle_zip_reply(&self, range: CableRange, zones: &[&str]) {
        if matches!(self.0.read().unwrap().mode, LearningMode::Static) {
            return;
        }
        let mut inner = self.0.write().unwrap();
        for &zone in zones {
            inner.zip.insert_zone_range(zone, range);
        }
    }

    // ── Query surface ─────────────────────────────────────────────────────────

    /// Returns `true` if `net` falls within our own cable range.
    pub fn is_local(&self, net: u16) -> bool {
        self.0.read().unwrap().is_local(net)
    }

    /// Determine where to send a DDP packet destined for network `net`.
    ///
    /// Returns `None` when the destination is off-segment and no route is
    /// known; the caller should drop or error the packet.
    pub fn route_for(&self, net: u16) -> Option<NextHop> {
        self.0.read().unwrap().route_for(net)
    }

    /// Return the router addresses that can forward NBP requests for `zone`.
    ///
    /// Derived from ZIP (zone → ranges) then RTMP (range → next-hop).
    /// Returns an empty `Vec` if the zone is unknown.
    pub fn routers_for_zone(&self, zone: &str) -> Vec<AppleTalkAddress> {
        self.0.read().unwrap().routers_for_zone(zone)
    }

    /// Determine how to dispatch an NBP LkUp for the given zone.
    pub fn nbp_dispatch(&self, zone: NbpZone<'_>) -> NbpDispatch {
        self.0.read().unwrap().nbp_dispatch(zone)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(net: u16, node: u8) -> AppleTalkAddress {
        AppleTalkAddress { network_number: net, node_number: node }
    }

    // ── is_local / route_for ──────────────────────────────────────────────────

    #[test]
    fn local_range_membership() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range(100, 105);

        assert!(t.is_local(100));
        assert!(t.is_local(103));
        assert!(t.is_local(105));
        assert!(!t.is_local(99));
        assert!(!t.is_local(106));
    }

    #[test]
    fn route_for_local() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range(100, 105);
        assert_eq!(t.route_for(102), Some(NextHop::Local));
    }

    #[test]
    fn route_for_via_router() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range(100, 105);
        t.insert_route(200, 210, addr(100, 1));
        assert_eq!(t.route_for(205), Some(NextHop::Via(addr(100, 1))));
    }

    #[test]
    fn route_for_unknown_returns_none() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range(100, 105);
        assert_eq!(t.route_for(999), None);
    }

    #[test]
    fn insert_route_replaces_overlap() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(100, 200, addr(1, 1));
        t.insert_route(150, 160, addr(1, 2)); // overlaps; old entry removed wholesale
        assert_eq!(t.route_for(155), Some(NextHop::Via(addr(1, 2))));
        // Parts of the old range outside [150, 160] are gone
        assert_eq!(t.route_for(100), None);
    }

    #[test]
    fn remove_route() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1));
        t.remove_route(200, 210);
        assert_eq!(t.route_for(205), None);
    }

    // ── NBP dispatch ──────────────────────────────────────────────────────────

    #[test]
    fn nbp_local_always_broadcasts() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1)); // router present, still local
        assert_eq!(t.nbp_dispatch(NbpZone::Local), NbpDispatch::LocalBroadcast);
    }

    #[test]
    fn nbp_all_no_router() {
        let t = RouteTable::new(LearningMode::Static);
        assert_eq!(t.nbp_dispatch(NbpZone::All), NbpDispatch::LocalBroadcast);
    }

    #[test]
    fn nbp_all_with_router() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1));
        assert_eq!(
            t.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    #[test]
    fn nbp_named_zone_known() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1));
        t.insert_zone("Engineering", &[(200, 210)]);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    #[test]
    fn nbp_named_zone_unknown_fallback() {
        let t = RouteTable::new(LearningMode::Static);
        // No router at all — ZoneUnknown
        assert_eq!(t.nbp_dispatch(NbpZone::Named("Printers")), NbpDispatch::ZoneUnknown);

        // Router known but zone not in ZIP — falls back to that router
        t.insert_route(200, 210, addr(100, 1));
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Printers")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    // ── Dynamic learning ──────────────────────────────────────────────────────

    #[test]
    fn handle_rtmp_respects_mode() {
        let dynamic = RouteTable::new(LearningMode::Dynamic);
        dynamic.handle_rtmp(addr(100, 1), &[(200, 210, 1), (300, 305, 2)]);
        assert_eq!(dynamic.route_for(205), Some(NextHop::Via(addr(100, 1))));
        assert_eq!(dynamic.route_for(301), Some(NextHop::Via(addr(100, 1))));

        let static_ = RouteTable::new(LearningMode::Static);
        static_.handle_rtmp(addr(100, 1), &[(200, 210, 1)]);
        assert_eq!(static_.route_for(205), None);
    }

    #[test]
    fn handle_zip_reply_respects_mode() {
        let dynamic = RouteTable::new(LearningMode::Dynamic);
        dynamic.insert_route(200, 210, addr(100, 1));
        dynamic.handle_zip_reply((200, 210), &["Engineering", "Printers"]);
        assert_eq!(
            dynamic.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );

        let static_ = RouteTable::new(LearningMode::Static);
        static_.insert_route(200, 210, addr(100, 1));
        static_.handle_zip_reply((200, 210), &["Engineering"]);
        // ZIP entry not recorded; zone unknown but falls back to the known router
        assert_eq!(
            static_.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    #[test]
    fn remove_zone() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1));
        t.insert_zone("Engineering", &[(200, 210)]);
        t.remove_zone("Engineering");
        // Falls back to any-router since zone is gone but route remains
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    #[test]
    fn clone_shares_state() {
        let t1 = RouteTable::new(LearningMode::Static);
        let t2 = t1.clone();
        t1.insert_route(200, 210, addr(100, 1));
        assert_eq!(t2.route_for(205), Some(NextHop::Via(addr(100, 1))));
    }

    #[test]
    fn routers_for_zone_deduped() {
        let t = RouteTable::new(LearningMode::Static);

        // Consecutive duplicates: two ranges, same router
        t.insert_route(200, 210, addr(100, 1));
        t.insert_route(211, 220, addr(100, 1));
        t.insert_zone("Engineering", &[(200, 210), (211, 220)]);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );

        // Non-consecutive: zone spans A, B, A — router A must appear only once
        t.insert_route(221, 230, addr(100, 2)); // router B
        t.insert_route(231, 240, addr(100, 1)); // router A again
        t.insert_zone("Engineering", &[(221, 230), (231, 240)]);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1), addr(100, 2)])
        );
    }
}
