//! ZIP client actor.
//!
//! A resident service that owns the ZIP socket (socket 6) for the lifetime of
//! the stack. After the addressing layer self-assigns a provisional address
//! (LocalTalk settles on network 0, EtherTalk Phase 2 in the startup range
//! $FF00–$FFFE), it asks a router — via a broadcast ZIP GetNetInfo request,
//! which DDP sends on every configured cable — for each cable's real
//! network-number range and zone name, then threads the answer into the rest
//! of the stack. The reply's arrival interface decides which cable it
//! describes:
//!
//! * LocalTalk: [`AddressingHandle::set_addr`] adopts the real network number
//!   (0 → range start), so DDP source addresses become correct.
//! * EtherTalk: a fresh address *inside* the advertised range is probed via
//!   AARP and adopted, per the Phase 2 startup procedure.
//! * [`RouteTable::set_local_range_for`] / [`RouteTable::insert_zone`] record
//!   the cable range and zone, which is what NBP reads to answer zoned
//!   lookups and what DDP uses to pick the right cable for a next hop.
//!
//! Because it stays resident it also honours **ZIP Notify** (a router telling us
//! our zone/network changed) by re-running discovery, and exposes
//! [`ZipHandle::refresh`] to force a re-check on demand — the RTMP listener
//! calls this when a router first appears on a cable.
//!
//! If no router answers we keep the provisional addresses with no zone — the
//! correct state for an isolated cable — and NBP keeps using the "*"
//! (this-zone) convention. The zone is never cached in this actor:
//! [`RouteTable`] is the single source of truth; this actor's job is to keep
//! it fresh.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::zip::{GetNetInfoReply, GetNetInfoRequest, Notify, ZIP_SOCKET};
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use crate::addressing::AddressingHandle;
use crate::ddp::{DdpAddress, DdpHandle, DdpSocket, Packet};
use crate::route_table::{Interface, RouteTable};

/// How long to wait for a router to answer before resending GetNetInfo.
const GNI_TIMEOUT: Duration = Duration::from_secs(1);
/// GetNetInfo transmissions per discovery round before giving up (staying zoneless).
const GNI_MAX_ATTEMPTS: usize = 3;

enum ZipCommand {
    /// Force a fresh discovery round; the sender is signalled once it settles.
    Refresh(oneshot::Sender<()>),
}

pub struct Zip {
    sock: DdpSocket,
    et_addressing: Option<AddressingHandle>,
    lt_addressing: Option<AddressingHandle>,
    route_table: RouteTable,
    /// PRAM-style zone cache file: seeded into requests and rewritten on adopt.
    zone_cache: Option<PathBuf>,
    /// Last zone we sent to the router for re-confirmation.
    remembered_zone: Option<String>,
    request_rx: mpsc::Receiver<ZipCommand>,
    /// GetNetInfo sends remaining in the current round; 0 means idle (settled or
    /// gave up). Drives the retry timer.
    attempts_left: usize,
    /// Callers waiting for the current discovery round to settle.
    refresh_waiters: Vec<oneshot::Sender<()>>,
}

impl Zip {
    /// Spawn the ZIP actor and kick off the initial discovery round.
    pub async fn spawn(
        ddp: &DdpHandle,
        et_addressing: Option<AddressingHandle>,
        lt_addressing: Option<AddressingHandle>,
        route_table: RouteTable,
        zone_cache: Option<PathBuf>,
    ) -> ZipHandle {
        let sock = ddp
            .new_sock(DdpProtocolType::Zip, Some(ZIP_SOCKET))
            .await
            .expect("failed to create ZIP sock");

        let remembered_zone = zone_cache.as_deref().and_then(load_zone);

        let (request_tx, request_rx) = mpsc::channel(8);

        let zip = Self {
            sock,
            et_addressing,
            lt_addressing,
            route_table,
            zone_cache,
            remembered_zone,
            request_rx,
            attempts_left: 0,
            refresh_waiters: Vec::new(),
        };

        tokio::spawn(async move { zip.run().await });

        ZipHandle { request_tx }
    }

    async fn run(mut self) {
        let mut retry = tokio::time::interval(GNI_TIMEOUT);
        // Don't fire a catch-up burst if the loop is ever briefly starved.
        retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
        retry.tick().await; // consume the immediate first tick

        // Initial discovery round.
        self.start_discovery().await;

        loop {
            tokio::select! {
                recv = self.sock.recv() => {
                    match recv {
                        Ok(pkt) => self.handle_packet(&pkt).await,
                        Err(_) => break,
                    }
                }
                _ = retry.tick() => {
                    if self.attempts_left > 0 {
                        self.attempts_left -= 1;
                        if self.attempts_left == 0 {
                            tracing::info!(
                                "ZIP GetNetInfo: no router answered; staying on network 0 with no zone"
                            );
                            // Discovery gave up; wake any waiters (dropping the
                            // sender resolves their await).
                            self.refresh_waiters.clear();
                        } else if let Err(e) = self.send_request().await {
                            tracing::warn!("ZIP: failed to resend GetNetInfo: {e}");
                        }
                    }
                }
                cmd = self.request_rx.recv() => {
                    match cmd {
                        Some(ZipCommand::Refresh(done)) => {
                            self.refresh_waiters.push(done);
                            self.start_discovery().await;
                        }
                        None => break, // all handles dropped
                    }
                }
            }
        }
    }

    /// Begin a discovery round: send the first request and arm the retry budget.
    async fn start_discovery(&mut self) {
        self.attempts_left = GNI_MAX_ATTEMPTS;
        if let Err(e) = self.send_request().await {
            tracing::warn!("ZIP: failed to send GetNetInfo: {e}");
        }
    }

    /// Broadcast a GetNetInfo request to node 255 on the ZIP socket.
    async fn send_request(&self) -> Result<(), io::Error> {
        let mut buf = [0u8; 64];
        let n = GetNetInfoRequest {
            zone: self.remembered_zone.clone().unwrap_or_default(),
        }
        .to_bytes(&mut buf)
        .map_err(io::Error::other)?;

        let dest = DdpAddress::new(
            AppleTalkAddress { network_number: 0, node_number: 255 },
            ZIP_SOCKET,
        );
        self.sock.send_to(&buf[..n], dest).await
    }

    async fn handle_packet(&mut self, pkt: &Packet) {
        if let Ok(reply) = GetNetInfoReply::parse(&pkt.payload) {
            // The reply describes the cable it arrived on. The actor only
            // runs where the underlay is in-process, so the link is known.
            let source = pkt.source;
            self.adopt(reply, Interface::from(source)).await;
            self.attempts_left = 0;
            for waiter in self.refresh_waiters.drain(..) {
                let _ = waiter.send(());
            }
        } else if Notify::parse(&pkt.payload).is_ok() {
            tracing::info!("ZIP Notify received; re-running GetNetInfo");
            self.start_discovery().await;
        }
    }

    /// Thread a GetNetInfo reply into the addressing layer and route table.
    async fn adopt(&mut self, reply: GetNetInfoReply, iface: Interface) {
        let (lo, hi) = (reply.range_start, reply.range_end);

        // Prefer the default zone when the router rejected ours or we sent none.
        let zone = if reply.zone_invalid() || reply.zone.is_empty() {
            reply
                .default_zone
                .filter(|z| !z.is_empty())
                .or_else(|| (!reply.zone.is_empty()).then_some(reply.zone))
        } else {
            Some(reply.zone)
        };

        tracing::info!(
            "ZIP GetNetInfo ({iface:?}): network range {lo}-{hi}, zone {}",
            zone.as_deref().unwrap_or("<none>")
        );

        if lo != 0 {
            match iface {
                // Nonextended cable: adopt the real network number directly;
                // the LLAP-probed node number stays valid.
                Interface::LocalTalk => {
                    if let Some(lt) = self.lt_addressing.clone() {
                        lt.adopt_network_number(lo).await;
                    }
                }
                // Extended cable: if our provisional (startup-range) address
                // is outside the advertised range, probe for a fresh one
                // inside it, per the Phase 2 startup procedure.
                Interface::EtherTalk => {
                    if let Some(et) = self.et_addressing.clone() {
                        et.acquire_in_range(lo, hi).await;
                    }
                }
            }
            self.route_table.set_local_range_for(iface, lo, hi);
        }

        if let Some(zone) = zone {
            self.route_table.insert_zone(&zone, &[(lo, hi)]);
            if let Some(path) = &self.zone_cache {
                save_zone(path, &zone);
            }
            self.remembered_zone = Some(zone);
        }
    }
}

/// Handle to the ZIP actor. Cheap to clone; the actor lives until every handle
/// is dropped.
#[derive(Clone)]
pub struct ZipHandle {
    request_tx: mpsc::Sender<ZipCommand>,
}

impl ZipHandle {
    /// Force a fresh GetNetInfo exchange, returning once the actor has adopted a
    /// reply or exhausted its retry budget (no router present).
    pub async fn refresh(&self) -> Result<(), io::Error> {
        let (tx, rx) = oneshot::channel();
        self.request_tx
            .send(ZipCommand::Refresh(tx))
            .await
            .map_err(|_| io::Error::other("ZIP actor shut down"))?;
        // A dropped sender (discovery gave up) resolves as Err; either way the
        // round is over.
        let _ = rx.await;
        Ok(())
    }
}

/// Load a cached zone name (trimmed, non-empty) from `path`, if it exists.
fn load_zone(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Persist the learned zone name to `path` for the next startup.
fn save_zone(path: &Path, zone: &str) {
    if let Err(e) = std::fs::write(path, zone) {
        tracing::warn!("ZIP: failed to cache zone to {}: {e}", path.display());
    }
}
