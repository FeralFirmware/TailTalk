use thiserror::Error;

/// Well-known DDP socket for both RTMP Data and RTMP Request packets.
pub const RTMP_SOCKET: u8 = 1;

#[derive(Error, Debug)]
pub enum RtmpError {
    #[error("packet too short: expected at least {expected} bytes but found {found}")]
    TooShort { expected: usize, found: usize },
    #[error("unsupported node ID length {length}; only 8-bit (LocalTalk) node IDs are supported")]
    UnsupportedIdLength { length: u8 },
    #[error("unknown RTMP function code {code}")]
    UnknownFunction { code: u8 },
}

/// Function code carried in an RTMP Request or Route Data Request packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RtmpFunction {
    /// Node requests a router to respond with its network number and node ID.
    Request = 1,
    /// Route Data Request: router responds applying split-horizon processing.
    RouteDataSplitHorizon = 2,
    /// Route Data Request: router responds with the full routing table.
    RouteDataFull = 3,
}

impl TryFrom<u8> for RtmpFunction {
    type Error = RtmpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::RouteDataSplitHorizon),
            3 => Ok(Self::RouteDataFull),
            _ => Err(RtmpError::UnknownFunction { code: value }),
        }
    }
}

/// A routing tuple carried in an RTMP Data packet.
///
/// Non-extended tuples cover a single network number (Phase 1 networks). Extended
/// tuples cover a contiguous range of network numbers (Phase 2 / EtherTalk networks).
/// The range flag is the high bit of the distance field: 0 = non-extended, 1 = extended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtmpTuple {
    NonExtended { network: u16, distance: u8 },
    Extended { range_start: u16, distance: u8, range_end: u16 },
}

/// An RTMP Data or Response packet (DDP type 1).
///
/// Broadcast every 10 seconds by each router port. Contains the router's network
/// number and node ID for that port, followed by routing tuples from the routing table.
///
/// On non-extended networks the sender info is followed by a 3-byte version number
/// indicator (`$000082`). On extended networks the version is instead embedded as the
/// trailing byte (`$82`) of every extended tuple, including the mandatory first tuple
/// that identifies the sender's own network number range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtmpDataPacket {
    /// Network number of the router port through which this packet was sent.
    pub router_network: u16,
    /// Node ID of the router port through which this packet was sent.
    pub node_id: u8,
    /// Routing tuples from the sending router's routing table.
    pub tuples: Vec<RtmpTuple>,
}

impl RtmpDataPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, RtmpError> {
        let [net_hi, net_lo, id_length, node_id, rest @ ..] = buf else {
            return Err(RtmpError::TooShort {
                expected: 4,
                found: buf.len(),
            });
        };

        if *id_length != 8 {
            return Err(RtmpError::UnsupportedIdLength { length: *id_length });
        }

        let router_network = u16::from_be_bytes([*net_hi, *net_lo]);
        let node_id = *node_id;

        // On non-extended networks a 3-byte version indicator ($000082) follows
        // the sender info. Skip it if present; on extended networks the version is
        // embedded in the trailing byte of the first (extended) tuple instead.
        let mut rest: &[u8] = rest;
        if rest.starts_with(&[0x00, 0x00, 0x82]) {
            rest = &rest[3..];
        }

        let mut tuples = Vec::new();
        while !rest.is_empty() {
            match rest {
                // Non-extended tuple: network (2B) + distance (1B, high bit clear).
                [hi, lo, dist @ 0..=0x7F, tail @ ..] => {
                    tuples.push(RtmpTuple::NonExtended {
                        network: u16::from_be_bytes([*hi, *lo]),
                        distance: *dist,
                    });
                    rest = tail;
                }
                // Extended tuple: range_start (2B) + distance|0x80 (1B) + range_end (2B) + $82 (1B).
                [s_hi, s_lo, dist, e_hi, e_lo, _unused, tail @ ..] => {
                    tuples.push(RtmpTuple::Extended {
                        range_start: u16::from_be_bytes([*s_hi, *s_lo]),
                        distance: *dist & 0x7F,
                        range_end: u16::from_be_bytes([*e_hi, *e_lo]),
                    });
                    rest = tail;
                }
                _ => {
                    // Fewer bytes than the minimum tuple size (3 for non-extended, 6 for extended).
                    let expected = if rest.len() >= 3 && rest[2] & 0x80 != 0 {
                        6
                    } else {
                        3
                    };
                    return Err(RtmpError::TooShort {
                        expected,
                        found: rest.len(),
                    });
                }
            }
        }

        Ok(Self {
            router_network,
            node_id,
            tuples,
        })
    }
}

/// An RTMP Request or Route Data Request (RDR) packet (DDP type 5).
///
/// Sent by nodes that need to discover a router, or by nodes requesting a directed
/// copy of a router's routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtmpRequestPacket {
    pub function: RtmpFunction,
}

impl RtmpRequestPacket {
    pub fn parse(buf: &[u8]) -> Result<Self, RtmpError> {
        let [code, ..] = buf else {
            return Err(RtmpError::TooShort {
                expected: 1,
                found: 0,
            });
        };
        Ok(Self {
            function: (*code).try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies decoding of a real RTMP Data packet sent by an AsanteTalk
    /// LocalTalk-to-Ethernet bridge. The AsanteTalk was operating as a router on
    /// non-extended LocalTalk net 2 (node 254) and advertising three routes: its
    /// own LocalTalk net (2), the peer LocalTalk net (1), and the extended EtherTalk
    /// range (3–5). Decode verified against Wireshark 4.6.6.
    #[test]
    fn test_parse_rtmp_data_asantetalk() {
        // RTMP payload (LLAP + DDP long header stripped).
        //
        // Full on-wire bytes:
        //   LLAP:  ff fe 02
        //   DDP:   00 20 1f 5c  00 00 00 02  ff fe 01 01 01
        //   RTMP:  00 02 08 fe  00 00 82  00 02 00  00 03 80 00 05 82  00 01 00
        let rtmp_payload: &[u8] = &[
            0x00, 0x02, // Router network: 2
            0x08, // ID length: 8 bits
            0xfe, // Node ID: 254
            0x00, 0x00, 0x82, // Non-extended version indicator ($000082)
            0x00, 0x02, 0x00, // Tuple 1: NonExtended, net 2, dist 0
            0x00, 0x03, 0x80, 0x00, 0x05, 0x82, // Tuple 2: Extended, range 3–5, dist 0
            0x00, 0x01, 0x00, // Tuple 3: NonExtended, net 1, dist 0
        ];

        let packet =
            RtmpDataPacket::parse(rtmp_payload).expect("failed to parse RTMP Data packet");

        assert_eq!(packet.router_network, 2);
        assert_eq!(packet.node_id, 254);
        assert_eq!(packet.tuples.len(), 3);
        assert_eq!(
            packet.tuples[0],
            RtmpTuple::NonExtended {
                network: 2,
                distance: 0
            }
        );
        assert_eq!(
            packet.tuples[1],
            RtmpTuple::Extended {
                range_start: 3,
                distance: 0,
                range_end: 5
            }
        );
        assert_eq!(
            packet.tuples[2],
            RtmpTuple::NonExtended {
                network: 1,
                distance: 0
            }
        );
    }

    /// Verifies decoding of a real RTMP Data packet. Node 128 is broadcasting on
    /// non-extended LocalTalk net 0, advertising a single route to its own net
    /// (net 0, distance 0).
    #[test]
    fn test_parse_rtmp_data_netatalk_broadcast() {
        // RTMP payload (LLAP + DDP short header stripped).
        //
        // Full on-wire bytes (frame 42, 18 bytes total):
        //   LLAP:  ff 80 01
        //   DDP:   00 0f 01 01 01
        //   RTMP:  00 00 08 80  00 00 82  00 00 00
        let rtmp_payload: &[u8] = &[
            0x00, 0x00, // Router network: 0
            0x08, // ID length: 8 bits
            0x80, // Node ID: 128
            0x00, 0x00, 0x82, // Non-extended version indicator ($000082)
            0x00, 0x00, 0x00, // Tuple 1: NonExtended, net 0, dist 0
        ];

        let packet =
            RtmpDataPacket::parse(rtmp_payload).expect("failed to parse RTMP Data packet");

        assert_eq!(packet.router_network, 0);
        assert_eq!(packet.node_id, 128);
        assert_eq!(packet.tuples.len(), 1);
        assert_eq!(
            packet.tuples[0],
            RtmpTuple::NonExtended {
                network: 0,
                distance: 0
            }
        );
    }
}
