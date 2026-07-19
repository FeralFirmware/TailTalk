use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tailtalk_packets::aarp::{AddressSource, AppleTalkAddress};

/// How long an RTMP-learned route stays valid without being re-advertised.
///
/// Routers broadcast their table every ~10 seconds; Inside AppleTalk has
/// nodes discard entries after roughly a minute without refresh. Expiry is
/// what lets [`RouteTable::has_router`] fall back to `false` (resuming
/// short-form DDP and local NBP broadcast) when the router disappears.
const RTMP_ROUTE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum LearningMode {
    /// Populate tables from RTMP/ZIP broadcasts.
    Dynamic,
    /// Tables filled only via the programmatic API.
    Static,
}

/// Which physical interface (cable) an address, route, or local range belongs
/// to. Phase 1 and Phase 2 EtherTalk share a cable, so they map to one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interface {
    EtherTalk,
    LocalTalk,
}

impl From<AddressSource> for Interface {
    fn from(src: AddressSource) -> Self {
        match src {
            AddressSource::LocalTalk => Interface::LocalTalk,
            AddressSource::EtherTalkPhase1 | AddressSource::EtherTalkPhase2 => {
                Interface::EtherTalk
            }
        }
    }
}

/// Where to send a DDP packet for a given destination network.
///
/// Every route (whether dynamically learned or programmatically inserted)
/// must be explicitly bound to the `Interface` it can be reached on.
#[derive(Debug, PartialEq, Eq)]
pub enum NextHop {
    /// Destination is on our cable; resolve on the link and send directly.
    Local(Interface),
    /// Forward to this router.
    Via {
        router: AppleTalkAddress,
        interface: Interface,
    },
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
    #[allow(dead_code)] // retained for future best-path selection
    hop_count: u8,
    next_hop: AppleTalkAddress,
    /// Cable the route was learned on. Must be known.
    interface: Interface,
    /// When the entry stops being served; `None` for programmatic entries,
    /// which never expire.
    expires_at: Option<Instant>,
}

impl RtmpEntry {
    fn expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }
}

/// A router heard advertising on a cable, used as the endpoint "A-Router":
/// the next hop for any destination with no more-specific route.
///
/// Per Inside AppleTalk a non-router node needs no routing table — it forwards
/// every off-cable packet to a router it has heard and lets the router do the
/// work. That is the only way to reach nodes behind a LocalTalk–EtherTalk
/// bridge like AsanteTalk, which announces itself in the RTMP header but sends
/// no route tuples. Lowest priority: local ranges and specific routes win.
struct DefaultRouter {
    addr: AppleTalkAddress,
    interface: Interface,
    expires_at: Option<Instant>,
}

impl DefaultRouter {
    fn expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|at| now >= at)
    }
}

/// Sorted, non-overlapping list of cable range → next-hop mappings.
struct RtmpTable {
    entries: Vec<RtmpEntry>,
}

impl RtmpTable {
    fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// O(log n) lookup: find the live entry whose range contains `net`.
    fn lookup(&self, net: u16, now: Instant) -> Option<&RtmpEntry> {
        let idx = self.entries.partition_point(|e| e.range_lo <= net);
        let idx = idx.checked_sub(1)?;
        let e = &self.entries[idx];
        (net <= e.range_hi && !e.expired(now)).then_some(e)
    }

    /// Insert or replace a route covering [lo..=hi]. Returns `true` when the
    /// route is new or its next hop changed (as opposed to a pure refresh).
    ///
    /// Any existing entry that overlaps is removed wholesale — not trimmed.
    /// RTMP cable ranges are non-overlapping by protocol, so partial overlaps
    /// shouldn't arise in practice.
    fn insert(
        &mut self,
        lo: u16,
        hi: u16,
        next_hop: AppleTalkAddress,
        hop_count: u8,
        interface: Interface,
        expires_at: Option<Instant>,
    ) -> bool {
        let refresh = self
            .entries
            .iter()
            .any(|e| e.range_lo == lo && e.range_hi == hi && e.next_hop == next_hop);
        self.entries.retain(|e| e.range_hi < lo || e.range_lo > hi);
        let pos = self.entries.partition_point(|e| e.range_lo < lo);
        self.entries.insert(
            pos,
            RtmpEntry { range_lo: lo, range_hi: hi, hop_count, next_hop, interface, expires_at },
        );
        !refresh
    }

    fn remove(&mut self, lo: u16, hi: u16) {
        self.entries.retain(|e| !(e.range_lo == lo && e.range_hi == hi));
    }

    fn all_next_hops_deduped(&self, now: Instant) -> Vec<AppleTalkAddress> {
        let mut seen = HashSet::new();
        self.entries
            .iter()
            .filter(|e| !e.expired(now))
            .filter_map(|e| seen.insert(e.next_hop).then_some(e.next_hop))
            .collect()
    }

    /// Drop expired entries; returns how many were removed.
    fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.expired(now));
        before - self.entries.len()
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

// ── Change stream ─────────────────────────────────────────────────────────────

/// A single mutation applied through the programmatic API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteChange {
    SetLocalRange(CableRange),
    InsertRoute { lo: u16, hi: u16, next_hop: AppleTalkAddress, interface: Option<Interface> },
    RemoveRoute { lo: u16, hi: u16 },
    InsertZone { zone: String, ranges: Vec<CableRange> },
    RemoveZone { zone: String },
}

/// A point-in-time copy of the table contents, for querying over an API.
#[derive(Debug, Clone, Default)]
pub struct RouteSnapshot {
    pub local_range: Option<CableRange>,
    /// `(range_lo, range_hi, next_hop, interface)` for every RTMP entry.
    pub routes: Vec<(u16, u16, AppleTalkAddress, Option<Interface>)>,
    /// `(zone name, cable ranges)` for every known zone.
    pub zones: Vec<(String, Vec<CableRange>)>,
}

// ── Inner state ───────────────────────────────────────────────────────────────

/// A local cable range, tagged with the interface it belongs to.
struct LocalRange {
    interface: Interface,
    range: CableRange,
}

struct Inner {
    mode: LearningMode,
    local_ranges: Vec<LocalRange>,
    rtmp: RtmpTable,
    /// A router heard advertising but carrying no usable route to a given
    /// destination — the catch-all next hop. See [`DefaultRouter`].
    default_router: Option<DefaultRouter>,
    zip: ZipTable,
    publisher: Option<tokio::sync::mpsc::UnboundedSender<RouteChange>>,
}

impl Inner {
    fn publish(&self, change: RouteChange) {
        if let Some(tx) = &self.publisher {
            let _ = tx.send(change);
        }
    }

    /// Insert or update the local range slot for `interface` (one slot per
    /// tag, including the untagged slot). Returns `true` if the value changed.
    fn upsert_local_range(&mut self, interface: Interface, range: CableRange) -> bool {
        match self.local_ranges.iter_mut().find(|r| r.interface == interface) {
            Some(existing) if existing.range == range => false,
            Some(existing) => {
                existing.range = range;
                true
            }
            None => {
                self.local_ranges.push(LocalRange { interface, range });
                true
            }
        }
    }

    fn local_range_for(&self, net: u16) -> Option<&LocalRange> {
        self.local_ranges
            .iter()
            .find(|r| r.range.0 <= net && net <= r.range.1)
    }

    fn is_local(&self, net: u16) -> bool {
        self.local_range_for(net).is_some()
    }

    fn route_for(&self, net: u16, now: Instant) -> Option<NextHop> {
        if let Some(local) = self.local_range_for(net) {
            return Some(NextHop::Local(local.interface));
        }
        if let Some(e) = self.rtmp.lookup(net, now) {
            return Some(NextHop::Via { router: e.next_hop, interface: e.interface });
        }
        // Last resort: forward anything we have no specific route for to the
        // A-Router. This is what carries off-cable traffic when a bridge
        // advertises itself but sends no route tuples (e.g. AsanteTalk).
        self.live_default_router(now)
            .map(|r| NextHop::Via { router: r.addr, interface: r.interface })
    }

    fn live_default_router(&self, now: Instant) -> Option<&DefaultRouter> {
        self.default_router.as_ref().filter(|r| !r.expired(now))
    }

    /// Which cable network `net` sits on, if any tagged local range or
    /// tagged route covers it.
    fn interface_for_net(&self, net: u16, now: Instant) -> Option<Interface> {
        self.route_for(net, now).map(|hop| match hop {
            NextHop::Local(iface) => iface,
            NextHop::Via { interface, .. } => interface,
        })
    }

    fn has_router(&self, now: Instant) -> bool {
        self.rtmp.entries.iter().any(|e| !e.expired(now))
            || self.live_default_router(now).is_some()
    }

    /// Every distinct router we could hand an NBP request to: the specific
    /// RTMP next hops, plus the A-Router if one is live.
    fn all_routers(&self, now: Instant) -> Vec<AppleTalkAddress> {
        let mut routers = self.rtmp.all_next_hops_deduped(now);
        if let Some(r) = self.live_default_router(now)
            && !routers.contains(&r.addr)
        {
            routers.push(r.addr);
        }
        routers
    }

    fn routers_for_zone(&self, zone: &str, now: Instant) -> Vec<AppleTalkAddress> {
        let mut seen = HashSet::new();
        self.zip
            .ranges_for_zone(zone)
            .iter()
            .filter_map(|&(lo, _)| self.rtmp.lookup(lo, now))
            .filter_map(|e| seen.insert(e.next_hop).then_some(e.next_hop))
            .collect()
    }

    fn nbp_dispatch(&self, zone: NbpZone<'_>, now: Instant) -> NbpDispatch {
        match zone {
            NbpZone::Local => NbpDispatch::LocalBroadcast,

            NbpZone::All => {
                let routers = self.all_routers(now);
                if routers.is_empty() {
                    NbpDispatch::LocalBroadcast
                } else {
                    NbpDispatch::RouterBroadcast(routers)
                }
            }

            NbpZone::Named(name) => {
                let routers = self.routers_for_zone(name, now);
                if !routers.is_empty() {
                    return NbpDispatch::RouterBroadcast(routers);
                }
                // Zone not in ZIP — try any known router as a last resort.
                let any = self.all_routers(now);
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

impl std::fmt::Debug for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteTable").finish_non_exhaustive()
    }
}

impl RouteTable {
    pub fn new(mode: LearningMode) -> Self {
        Self(Arc::new(RwLock::new(Inner {
            mode,
            local_ranges: Vec::new(),
            rtmp: RtmpTable::new(),
            default_router: None,
            zip: ZipTable::new(),
            publisher: None,
        })))
    }

    // ── Configuration ─────────────────────────────────────────────────────────



    /// Set the cable range of a specific interface's segment.
    ///
    /// Called by ZIP (GetNetInfo reply) and RTMP (router's own-cable tuple)
    /// as the range is discovered. Idempotent: republishing the same range is
    /// a no-op, so periodic router broadcasts don't spam the change stream.
    pub fn set_local_range_for(&self, interface: Interface, lo: u16, hi: u16) {
        let mut inner = self.0.write().unwrap();
        if inner.upsert_local_range(interface, (lo, hi)) {
            inner.publish(RouteChange::SetLocalRange((lo, hi)));
        }
    }

    /// Attach a channel that receives every subsequent programmatic change.
    ///
    /// Seed the table *before* attaching the publisher to avoid echoing
    /// the seed back.
    pub fn set_publisher(&self, tx: tokio::sync::mpsc::UnboundedSender<RouteChange>) {
        self.0.write().unwrap().publisher = Some(tx);
    }

    // ── Programmatic inserts ──────────────────────────────────────────────────

    /// Insert or replace a route: DDP packets for `[lo..=hi]` go to `next_hop`.
    ///
    /// Programmatic routes carry no interface tag and never expire.
    pub fn insert_route(&self, lo: u16, hi: u16, next_hop: AppleTalkAddress, interface: Interface) {
        let mut inner = self.0.write().unwrap();
        if inner.rtmp.insert(lo, hi, next_hop, 0, interface, None) {
            inner.publish(RouteChange::InsertRoute { lo, hi, next_hop, interface: Some(interface) });
        }
    }

    /// Remove the route covering exactly `[lo..=hi]`.
    pub fn remove_route(&self, lo: u16, hi: u16) {
        let mut inner = self.0.write().unwrap();
        inner.rtmp.remove(lo, hi);
        inner.publish(RouteChange::RemoveRoute { lo, hi });
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
        inner.publish(RouteChange::InsertZone {
            zone: zone.to_string(),
            ranges: ranges.to_vec(),
        });
    }

    /// Remove all cable-range associations for `zone`.
    pub fn remove_zone(&self, zone: &str) {
        let mut inner = self.0.write().unwrap();
        inner.zip.remove_zone(zone);
        inner.publish(RouteChange::RemoveZone { zone: zone.to_string() });
    }

    /// Replace the entire table contents with `snapshot`, without publishing.
    pub fn replace_contents(&self, snapshot: RouteSnapshot) {
        let mut inner = self.0.write().unwrap();
        inner.local_ranges.clear();
        if let Some(range) = snapshot.local_range {
            // Static local range configuration defaults to EtherTalk
            inner.local_ranges.push(LocalRange { interface: Interface::EtherTalk, range });
        }
        inner.rtmp = RtmpTable::new();
        inner.default_router = None;
        for (lo, hi, next_hop, interface) in snapshot.routes {
            inner.rtmp.insert(lo, hi, next_hop, 0, interface.unwrap_or(Interface::EtherTalk), None);
        }
        inner.zip = ZipTable::new();
        for (zone, ranges) in snapshot.zones {
            for range in ranges {
                inner.zip.insert_zone_range(&zone, range);
            }
        }
    }

    /// Copy the entire table contents, for querying over an API.
    ///
    /// The snapshot format carries no interface tags or expiry: the untagged
    /// local range is preferred, and only live routes are included.
    pub fn snapshot(&self) -> RouteSnapshot {
        let now = Instant::now();
        let inner = self.0.read().unwrap();
        RouteSnapshot {
            local_range: inner.local_ranges.first().map(|r| r.range),
            routes: inner
                .rtmp
                .entries
                .iter()
                .filter(|e| !e.expired(now))
                .map(|e| (e.range_lo, e.range_hi, e.next_hop, Some(e.interface)))
                .collect(),
            zones: inner
                .zip
                .zone_to_ranges
                .iter()
                .map(|(name, ranges)| (name.clone(), ranges.clone()))
                .collect(),
        }
    }

    // ── Dynamic learning ──────────────────────────────────────────────────────

    /// Process an RTMP data packet received from `src` on `interface`.
    ///
    /// Each tuple is `(range_lo, range_hi, hop_count)`. Learned routes expire
    /// after [`RTMP_ROUTE_TTL`] unless refreshed by another broadcast. No-op
    /// in [`LearningMode::Static`].
    pub fn handle_rtmp(
        &self,
        src: AppleTalkAddress,
        interface: Interface,
        tuples: &[(u16, u16, u8)],
    ) {
        if matches!(self.0.read().unwrap().mode, LearningMode::Static) {
            return;
        }
        let expires_at = Some(Instant::now() + RTMP_ROUTE_TTL);
        let mut inner = self.0.write().unwrap();
        for &(lo, hi, hops) in tuples {
            // Publish only genuine changes, not the 10-second refreshes, so a
            // daemon doesn't rebroadcast its table to clients on every beacon.
            if inner.rtmp.insert(lo, hi, src, hops, interface, expires_at) {
                inner.publish(RouteChange::InsertRoute { lo, hi, next_hop: src, interface: Some(interface) });
            }
        }
    }

    /// Record that `router` is advertising on `interface`, making it the
    /// endpoint's A-Router: the next hop for any destination with no
    /// more-specific route. Refreshed on every RTMP broadcast and expiring on
    /// the same TTL as learned routes. No-op in [`LearningMode::Static`].
    ///
    /// This is what lets an endpoint reach off-cable nodes behind a bridge
    /// that announces itself but sends no route tuples (e.g. AsanteTalk).
    pub fn note_router(&self, router: AppleTalkAddress, interface: Interface) {
        let mut inner = self.0.write().unwrap();
        if matches!(inner.mode, LearningMode::Static) {
            return;
        }
        inner.default_router = Some(DefaultRouter {
            addr: router,
            interface,
            expires_at: Some(Instant::now() + RTMP_ROUTE_TTL),
        });
    }

    /// Drop expired RTMP-learned routes and, if it has lapsed, the A-Router.
    /// Meant to be called periodically (the RTMP listener does this); reads
    /// already ignore expired entries, this just reclaims them.
    pub fn purge_expired(&self) {
        let now = Instant::now();
        let mut inner = self.0.write().unwrap();
        let purged = inner.rtmp.purge_expired(now);
        if inner.default_router.as_ref().is_some_and(|r| r.expired(now)) {
            inner.default_router = None;
        }
        if purged > 0 {
            tracing::info!("route table: {purged} RTMP route(s) expired without refresh");
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

    /// Check whether a given network number falls into any of our local ranges.
    pub fn is_local(&self, net: u16) -> bool {
        self.0.read().unwrap().is_local(net)
    }

    /// Look up the next hop for a destination network.
    pub fn resolve(&self, net: u16) -> Option<NextHop> {
        self.0.read().unwrap().route_for(net, Instant::now())
    }

    /// Find the router for a remote network, if known.
    pub fn route_for(&self, net: u16) -> Option<AppleTalkAddress> {
        match self.resolve(net) {
            Some(NextHop::Via { router, .. }) => Some(router),
            _ => None,
        }
    }

    /// Which cable network `net` sits on, judged by tagged local ranges and
    /// tagged (dynamically learned) routes. `None` when unknown.
    pub fn interface_for_net(&self, net: u16) -> Option<Interface> {
        self.0.read().unwrap().interface_for_net(net, Instant::now())
    }

    /// Returns `true` while at least one live router is known, via RTMP
    /// advertisement (until it expires) or programmatic configuration.
    ///
    /// Used to decide when to stop using short-form (5-byte) DDP headers on
    /// LocalTalk: those omit the network number entirely, which is fine on
    /// an isolated LocalTalk segment but ambiguous as soon as a router makes
    /// off-segment addressing possible.
    pub fn has_router(&self) -> bool {
        self.0.read().unwrap().has_router(Instant::now())
    }

    /// Return the router addresses that can forward NBP requests for `zone`.
    ///
    /// Derived from ZIP (zone → ranges) then RTMP (range → next-hop).
    /// Returns an empty `Vec` if the zone is unknown.
    pub fn routers_for_zone(&self, zone: &str) -> Vec<AppleTalkAddress> {
        self.0.read().unwrap().routers_for_zone(zone, Instant::now())
    }

    /// Determine how to dispatch an NBP LkUp for the given zone.
    pub fn nbp_dispatch(&self, zone: NbpZone<'_>) -> NbpDispatch {
        self.0.read().unwrap().nbp_dispatch(zone, Instant::now())
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
        t.set_local_range_for(Interface::EtherTalk, 100, 105);

        assert!(t.is_local(100));
        assert!(t.is_local(103));
        assert!(t.is_local(105));
        assert!(!t.is_local(99));
        assert!(!t.is_local(106));
    }



    #[test]
    fn route_for_local() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range_for(Interface::EtherTalk, 100, 105);
        assert_eq!(t.resolve(102), Some(NextHop::Local(Interface::EtherTalk)));
    }

    #[test]
    fn route_for_via_router() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range_for(Interface::EtherTalk, 100, 105);
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        assert_eq!(t.route_for(205), Some(addr(100, 1)));
    }

    #[test]
    fn route_for_unknown_returns_none() {
        let t = RouteTable::new(LearningMode::Static);
        t.set_local_range_for(Interface::EtherTalk, 100, 105);
        assert_eq!(t.resolve(999), None);
    }

    #[test]
    fn insert_route_replaces_overlap() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(100, 200, addr(1, 1), Interface::EtherTalk);
        t.insert_route(150, 160, addr(1, 2), Interface::EtherTalk); // overlaps; old entry removed wholesale
        assert_eq!(t.route_for(155), Some(addr(1, 2)));
        // Parts of the old range outside [150, 160] are gone
        assert_eq!(t.route_for(100), None);
    }

    #[test]
    fn dynamic_routes_carry_interface_and_local_range_wins() {
        let t = RouteTable::new(LearningMode::Dynamic);
        t.set_local_range_for(Interface::LocalTalk, 2, 2);
        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(2, 2, 1), (3, 5, 1)]);

        // Our own cable range takes precedence over the router's own-net tuple.
        assert_eq!(t.resolve(2), Some(NextHop::Local(Interface::LocalTalk)));
        // Off-cable network routes via the router, tagged with its cable.
        assert_eq!(
            t.route_for(4),
            Some(addr(2, 254))
        );
        assert_eq!(t.interface_for_net(2), Some(Interface::LocalTalk));
        assert_eq!(t.interface_for_net(254), None);
    }

    #[test]
    fn a_router_forwards_unknown_nets() {
        // An AsanteTalk-style bridge that announces itself but sends no tuples:
        // note_router alone must make it the next hop for off-cable traffic.
        let t = RouteTable::new(LearningMode::Dynamic);
        t.set_local_range_for(Interface::LocalTalk, 65456, 65456);
        t.note_router(addr(65456, 190), Interface::LocalTalk);

        assert!(t.has_router());
        // Our own cable is still delivered directly, not via the router.
        assert_eq!(t.resolve(65456), Some(NextHop::Local(Interface::LocalTalk)));
        // Any off-cable net now routes via the A-Router on LocalTalk.
        assert_eq!(
            t.resolve(65309),
            Some(NextHop::Via { router: addr(65456, 190), interface: Interface::LocalTalk })
        );
        assert_eq!(
            t.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![addr(65456, 190)])
        );
    }

    #[test]
    fn specific_route_wins_over_a_router() {
        let t = RouteTable::new(LearningMode::Dynamic);
        t.note_router(addr(2, 254), Interface::LocalTalk);
        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(3, 5, 1)]);
        // A net with a specific route uses it; everything else falls to the A-Router.
        assert_eq!(
            t.resolve(4),
            Some(NextHop::Via { router: addr(2, 254), interface: Interface::LocalTalk })
        );
        assert_eq!(
            t.resolve(999),
            Some(NextHop::Via { router: addr(2, 254), interface: Interface::LocalTalk })
        );
        // The router appears once in NBP dispatch, not twice.
        assert_eq!(
            t.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![addr(2, 254)])
        );
    }

    #[test]
    fn a_router_is_static_mode_noop() {
        let t = RouteTable::new(LearningMode::Static);
        t.note_router(addr(65456, 190), Interface::LocalTalk);
        assert!(!t.has_router());
        assert_eq!(t.resolve(65309), None);
    }

    #[test]
    fn a_router_expires_and_purges() {
        let t = RouteTable::new(LearningMode::Dynamic);
        t.note_router(addr(65456, 190), Interface::LocalTalk);
        assert!(t.has_router());

        // Force the A-Router past its TTL.
        {
            let mut inner = t.0.write().unwrap();
            if let Some(r) = inner.default_router.as_mut() {
                r.expires_at = Some(Instant::now() - Duration::from_secs(1));
            }
        }

        // Reads ignore it even before purge.
        assert!(!t.has_router());
        assert_eq!(t.resolve(65309), None);
        assert_eq!(t.nbp_dispatch(NbpZone::All), NbpDispatch::LocalBroadcast);

        t.purge_expired();
        assert!(t.0.read().unwrap().default_router.is_none());
    }

    #[test]
    fn rtmp_routes_expire_and_purge() {
        let t = RouteTable::new(LearningMode::Dynamic);
        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(3, 5, 1)]);
        assert!(t.has_router());
        assert!(t.resolve(4).is_some());

        // Force the entry past its TTL.
        {
            let mut inner = t.0.write().unwrap();
            for e in &mut inner.rtmp.entries {
                e.expires_at = Some(Instant::now() - Duration::from_secs(1));
            }
        }

        // Reads ignore the expired entry even before it is purged.
        assert!(!t.has_router());
        assert_eq!(t.resolve(4), None);
        assert_eq!(t.nbp_dispatch(NbpZone::All), NbpDispatch::LocalBroadcast);

        t.purge_expired();
        assert!(t.0.read().unwrap().rtmp.entries.is_empty());

        // A fresh broadcast brings the route back.
        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(3, 5, 1)]);
        assert!(t.has_router());
    }

    #[test]
    fn set_local_range_publishes_only_changes() {
        let t = RouteTable::new(LearningMode::Dynamic);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        t.set_publisher(tx);

        t.set_local_range_for(Interface::EtherTalk, 3, 5);
        t.set_local_range_for(Interface::EtherTalk, 3, 5); // refresh, no publish
        t.set_local_range_for(Interface::EtherTalk, 3, 6); // change, publish

        assert_eq!(rx.try_recv(), Ok(RouteChange::SetLocalRange((3, 5))));
        assert_eq!(rx.try_recv(), Ok(RouteChange::SetLocalRange((3, 6))));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn handle_rtmp_publishes_only_new_routes() {
        let t = RouteTable::new(LearningMode::Dynamic);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        t.set_publisher(tx);

        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(3, 5, 1)]);
        t.handle_rtmp(addr(2, 254), Interface::LocalTalk, &[(3, 5, 1)]); // refresh
        assert_eq!(
            rx.try_recv(),
            Ok(RouteChange::InsertRoute { lo: 3, hi: 5, next_hop: addr(2, 254), interface: Some(Interface::LocalTalk) })
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn has_router_tracks_rtmp_entries() {
        let t = RouteTable::new(LearningMode::Static);
        assert!(!t.has_router());
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        assert!(t.has_router());
        t.remove_route(200, 210);
        assert!(!t.has_router());
    }

    #[test]
    fn remove_route() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        t.remove_route(200, 210);
        assert_eq!(t.resolve(205), None);
    }

    // ── NBP dispatch ──────────────────────────────────────────────────────────

    #[test]
    fn nbp_local_always_broadcasts() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk); // router present, still local
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
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        assert_eq!(
            t.nbp_dispatch(NbpZone::All),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    #[test]
    fn nbp_named_zone_known() {
        let t = RouteTable::new(LearningMode::Static);
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
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
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Printers")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );
    }

    // ── Dynamic learning ──────────────────────────────────────────────────────

    #[test]
    fn handle_rtmp_respects_mode() {
        let dynamic = RouteTable::new(LearningMode::Dynamic);
        dynamic.handle_rtmp(addr(100, 1), Interface::EtherTalk, &[(200, 210, 1), (300, 305, 2)]);
        assert_eq!(
            dynamic.route_for(205),
            Some(addr(100, 1))
        );
        assert_eq!(
            dynamic.resolve(301),
            Some(NextHop::Via { router: addr(100, 1), interface: Interface::EtherTalk })
        );

        let static_ = RouteTable::new(LearningMode::Static);
        static_.handle_rtmp(addr(100, 1), Interface::EtherTalk, &[(200, 210, 1)]);
        assert_eq!(static_.resolve(205), None);
    }

    #[test]
    fn handle_zip_reply_respects_mode() {
        let dynamic = RouteTable::new(LearningMode::Dynamic);
        dynamic.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        dynamic.handle_zip_reply((200, 210), &["Engineering", "Printers"]);
        assert_eq!(
            dynamic.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );

        let static_ = RouteTable::new(LearningMode::Static);
        static_.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
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
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
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
        t1.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        assert_eq!(t2.resolve(205), Some(NextHop::Via { router: addr(100, 1), interface: Interface::EtherTalk }));
    }

    #[test]
    fn routers_for_zone_deduped() {
        let t = RouteTable::new(LearningMode::Static);

        // Consecutive duplicates: two ranges, same router
        t.insert_route(200, 210, addr(100, 1), Interface::EtherTalk);
        t.insert_route(211, 220, addr(100, 1), Interface::EtherTalk);
        t.insert_zone("Engineering", &[(200, 210), (211, 220)]);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1)])
        );

        // Non-consecutive: zone spans A, B, A — router A must appear only once
        t.insert_route(221, 230, addr(100, 2), Interface::EtherTalk); // router B
        t.insert_route(231, 240, addr(100, 1), Interface::EtherTalk); // router A again
        t.insert_zone("Engineering", &[(221, 230), (231, 240)]);
        assert_eq!(
            t.nbp_dispatch(NbpZone::Named("Engineering")),
            NbpDispatch::RouterBroadcast(vec![addr(100, 1), addr(100, 2)])
        );
    }
}
