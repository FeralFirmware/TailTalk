use crate::ddp::{DdpAddress, DdpHandle};
use std::time::Duration;
use tailtalk_packets::{
    aarp::AppleTalkAddress,
    ddp::DdpProtocolType,
    rtmp::RtmpData,
    zip::{ZipGetNetInfo, ZipGetNetInfoReply},
};

pub struct RouterInfo {
    pub router_addr: AppleTalkAddress,
    pub cable_range: (u16, u16),
}

/// Probe for a router by sending ZIPGetNetInfo and an RTMP Request simultaneously,
/// then waiting up to 2 seconds for whichever responds first.
///
/// EtherTalk routers typically reply via ZIPGetNetInfoReply.
/// LocalTalk routers often ignore ZIPGetNetInfo but respond to RTMP Requests
/// (and broadcast RTMP Data periodically regardless).
///
/// Returns `None` if no router is found within the timeout.
pub async fn probe_router(ddp: &DdpHandle) -> Option<RouterInfo> {
    // Ephemeral ZIP socket — the router replies to our source socket, so we
    // don't need to be on the well-known ZIP socket 6 ourselves.
    let mut zip_sock = ddp.new_sock(DdpProtocolType::Zip, None).await.ok()?;

    // RTMP socket on socket 1 — routers broadcast RTMP Data here, and also
    // send unicast responses to RTMP Requests back to socket 1.
    let mut rtmp_sock = match ddp.new_sock(DdpProtocolType::RtmpResponse, Some(1)).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!("ZIP probe: could not open RTMP socket: {e}");
            None
        }
    };

    // Send ZIPGetNetInfo broadcast.
    let query = ZipGetNetInfo { zone_name: String::new() };
    let mut buf = [0u8; 16];
    if let Ok(size) = query.to_bytes(&mut buf) {
        let dest = DdpAddress::new(AppleTalkAddress { network_number: 0, node_number: 255 }, 6);
        if let Err(e) = zip_sock.send_to(&buf[..size], dest).await {
            tracing::warn!("ZIP: failed to send GetNetInfo: {e}");
        } else {
            tracing::debug!("ZIP: sent GetNetInfo broadcast");
        }
    }

    // Send RTMP Request broadcast to solicit an immediate RTMP Data response
    // from any router on the cable (rather than waiting for the ~10s periodic broadcast).
    // Must use DdpProtocolType::RtmpRequest (type 5) — sending from zip_sock would
    // stamp the DDP header with type 6 (ZIP) and the router would discard it.
    if rtmp_sock.is_some() {
        if let Ok(req_sock) = ddp.new_sock(DdpProtocolType::RtmpRequest, None).await {
            let dest = DdpAddress::new(AppleTalkAddress { network_number: 0, node_number: 255 }, 1);
            if let Err(e) = req_sock.send_to(&[1u8], dest).await {
                tracing::warn!("ZIP: failed to send RTMP Request: {e}");
            } else {
                tracing::debug!("ZIP: sent RTMP Request broadcast");
            }
            // req_sock dropped here — we receive the reply on rtmp_sock (socket 1)
        }
    }

    // EtherTalk routers reply to ZIPGetNetInfo within milliseconds, so 2s is ample.
    // LocalTalk routers often ignore requests and only broadcast RTMP Data every ~10s,
    // so if we opened an RTMP socket we wait up to 12s to catch that broadcast.
    let timeout = if rtmp_sock.is_some() {
        Duration::from_secs(12)
    } else {
        Duration::from_secs(2)
    };
    let deadline = tokio::time::Instant::now() + timeout;
    let mut logged_rtmp_wait = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            tracing::info!("ZIP: no router found within {}s, assuming non-routed network", timeout.as_secs());
            return None;
        }

        // Log once after the quick 2s window closes so the user knows why startup is slow.
        if rtmp_sock.is_some() && !logged_rtmp_wait && remaining < Duration::from_secs(10) {
            tracing::info!("ZIP: no immediate router response, listening for RTMP broadcast...");
            logged_rtmp_wait = true;
        }

        // Poll both sockets; whichever replies first wins.
        let result = if let Some(ref mut rtmp) = rtmp_sock {
            tokio::select! {
                pkt = zip_sock.recv() => Some((true, pkt)),
                pkt = rtmp.recv() => Some((false, pkt)),
                _ = tokio::time::sleep(remaining) => None,
            }
        } else {
            match tokio::time::timeout(remaining, zip_sock.recv()).await {
                Ok(pkt) => Some((true, pkt)),
                Err(_) => None,
            }
        };

        let Some((is_zip, Ok(pkt))) = result else {
            return None;
        };

        if is_zip {
            if let Some(reply) = ZipGetNetInfoReply::from_bytes(&pkt.payload) {
                let (start, end) = (reply.cable_range_start, reply.cable_range_end);
                if start == 0 || end == 0 || start > end {
                    tracing::warn!("ZIP: router returned invalid cable range {start}-{end}, ignoring");
                    continue;
                }
                let router_addr = AppleTalkAddress {
                    network_number: pkt.headers.src_network_num,
                    node_number: pkt.headers.src_node_id,
                };
                tracing::info!(
                    "ZIP: router at {}.{} via GetNetInfo, cable range {start}-{end}",
                    router_addr.network_number,
                    router_addr.node_number,
                );
                return Some(RouterInfo { router_addr, cable_range: (start, end) });
            }
        } else if let Some(rtmp) = RtmpData::from_bytes(&pkt.payload) {
            let router_addr = AppleTalkAddress {
                network_number: rtmp.network,
                node_number: rtmp.node,
            };
            tracing::info!(
                "ZIP: router at {}.{} via RTMP Data",
                router_addr.network_number,
                router_addr.node_number,
            );
            // For a non-extended LocalTalk network the cable "range" is a single
            // network number; reprobe won't use it (LocalTalk stays at network 0).
            return Some(RouterInfo { router_addr, cable_range: (rtmp.network, rtmp.network) });
        }
    }
}

