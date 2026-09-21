//! RTMP listener, receive only.
//!
//! A router broadcasts an RTMP Data packet on every cable roughly every 10
//! seconds. Seeing one tells a node two things:
//!
//! * a router is present, so DDP must switch from short to long headers, and
//! * on a nonextended LocalTalk cable the RTMP header carries the cable's
//!   real network number, which replaces our provisional network 0 (classic
//!   "RTMP stub" behaviour).
//!
//! There is no route table: a single-homed node only ever needs the
//! A-Router as its next hop for off-cable traffic.

use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::rtmp::RtmpDataPacket;

/// What one RTMP broadcast taught us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtmpObservation {
    /// The router's own address, usable as the next hop for any off-cable
    /// destination. On LocalTalk the broadcast arrives as short-form DDP
    /// (source network 0), so the network number falls back to the cable
    /// number the RTMP header advertises - otherwise we would address the
    /// router as net 0, which not every router honours.
    pub router: AppleTalkAddress,
    /// Our cable's network number, if the router is configured (nonzero).
    pub cable_network: Option<u16>,
}

/// Digest an RTMP Data packet received on DDP socket 1. `src_network` and
/// `src_node` come from the DDP header of the datagram carrying it.
pub fn observe(payload: &[u8], src_network: u16, src_node: u8) -> Option<RtmpObservation> {
    let data = RtmpDataPacket::parse(payload).ok()?;
    let router = AppleTalkAddress {
        network_number: if src_network != 0 {
            src_network
        } else {
            data.router_network
        },
        node_number: src_node,
    };
    Some(RtmpObservation {
        router,
        cable_network: (data.router_network != 0).then_some(data.router_network),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real RTMP Data packet captured from an AsanteTalk bridge: router
    /// 2.254 on nonextended LocalTalk net 2.
    const ASANTETALK_RTMP_PAYLOAD: &[u8] = &[
        0x00, 0x02, 0x08, 0xfe, 0x00, 0x00, 0x82, 0x00, 0x02, 0x00, 0x00, 0x03, 0x80, 0x00, 0x05,
        0x82, 0x00, 0x01, 0x00,
    ];

    #[test]
    fn gleans_network_and_router_from_short_form_source() {
        // Short-form DDP arrival: source network is 0.
        let obs = observe(ASANTETALK_RTMP_PAYLOAD, 0, 254).unwrap();
        assert_eq!(obs.cable_network, Some(2));
        assert_eq!(
            obs.router,
            AppleTalkAddress {
                network_number: 2,
                node_number: 254
            }
        );
    }

    #[test]
    fn unconfigured_router_reveals_no_network() {
        // netatalk broadcasting before configuration: net 0 everywhere.
        let payload: &[u8] = &[0x00, 0x00, 0x08, 0x80, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00];
        let obs = observe(payload, 0, 128).unwrap();
        assert_eq!(obs.cable_network, None);
        assert_eq!(obs.router.network_number, 0);
    }
}
