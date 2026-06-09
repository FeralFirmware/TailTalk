/// RTMP Request packet (DDP protocol type 5, destination socket 1).
/// Sent to solicit an immediate RTMP Data response from a router rather than
/// waiting for the next periodic broadcast (~10 s interval).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtmpRequest {
    /// Socket number on the requesting node where the RTMP Data reply should be sent.
    pub reply_socket: u8,
}

impl RtmpRequest {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        data.first().map(|&b| Self { reply_socket: b })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        if buf.is_empty() {
            return Err("buffer too small");
        }
        buf[0] = self.reply_socket;
        Ok(1)
    }
}

/// A routing-table entry carried inside an RTMP Data packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtmpTuple {
    /// Non-extended (single-network) entry used on Phase 1 / LocalTalk.
    NonExtended {
        network: u16,
        /// Hop count to the network (0 = directly connected).
        hops: u8,
    },
    /// Extended (cable-range) entry used on Phase 2 EtherTalk.
    Extended {
        range_start: u16,
        /// Hop count to the range (0 = directly connected).
        hops: u8,
        range_end: u16,
        /// RTMP protocol version byte (0x82 for AppleTalk Phase 2).
        version: u8,
    },
    /// Phase 2 version announcement: emitted as a tuple with range_start == 0
    /// followed by a single version byte (normally 0x82).
    Version(u8),
}

/// Parsed RTMP Data packet (DDP protocol type 1, sent to socket 1).
///
/// Broadcast by routers every ~10 s and also sent unicast in response to an
/// [`RtmpRequest`].  The packet identifies the router and carries its routing
/// table so nodes can discover the network topology.
#[derive(Debug, Clone)]
pub struct RtmpData {
    /// Router's network number.
    pub network: u16,
    /// Router's node ID.
    pub node: u8,
    /// Routing table entries broadcast by the router (may be empty).
    pub tuples: Vec<RtmpTuple>,
}

impl RtmpData {
    /// Minimum valid payload size: 2-byte network + 1-byte id_len + 1-byte node.
    pub const MIN_LEN: usize = 4;

    /// Parse an RTMP Data payload.
    ///
    /// Returns `None` if the payload is too short, has an unexpected ID-length
    /// field, or contains a zero network/node (which would not be a real router).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_LEN {
            return None;
        }

        let network = u16::from_be_bytes([data[0], data[1]]);
        let id_len = data[2];
        let node = data[3];

        // The ID-length field is always 8 bits (one byte node ID) for AppleTalk.
        if id_len != 8 {
            return None;
        }
        if network == 0 || node == 0 {
            return None;
        }

        let mut tuples = Vec::new();
        let mut offset = 4;

        // Parse routing tuples.  Each starts with a 2-byte range-start followed
        // by a 1-byte distance/flags byte, possibly trailed by more fields.
        while offset + 2 < data.len() {
            let range_start = u16::from_be_bytes([data[offset], data[offset + 1]]);
            offset += 2;

            if range_start == 0 {
                // Phase 2 version announcement: the next byte is the version.
                if offset >= data.len() {
                    break;
                }
                tuples.push(RtmpTuple::Version(data[offset]));
                offset += 1;
            } else {
                if offset >= data.len() {
                    break;
                }
                let dist_byte = data[offset];
                offset += 1;

                if dist_byte & 0x80 != 0 {
                    // Extended entry: range_end (2 bytes) + version (1 byte) follow.
                    if offset + 2 >= data.len() {
                        break;
                    }
                    let range_end = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let version = data[offset + 2];
                    offset += 3;
                    tuples.push(RtmpTuple::Extended {
                        range_start,
                        hops: dist_byte & 0x7F,
                        range_end,
                        version,
                    });
                } else {
                    // Non-extended entry: just the network number and hop count.
                    tuples.push(RtmpTuple::NonExtended {
                        network: range_start,
                        hops: dist_byte & 0x7F,
                    });
                }
            }
        }

        Some(Self { network, node, tuples })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Raw RTMP Data payload extracted from frame 9 of the LocalTalk capture
    // (mymac.pcap).  Full frame hex:
    //   ff be 01          LLAP: dst=255, src=190, type=Short-DDP
    //   00 0c 01 01 01    Short DDP: len=12, dst_sock=1, src_sock=1, protocol=1
    //   ff b0 08 be 00 00 82   RTMP payload
    //
    // tshark decodes this as:
    //   Net: 65456  Node Length: 8  Node: 190  Version: 0x82
    const RTMP_DATA_BYTES: &[u8] = &[0xff, 0xb0, 0x08, 0xbe, 0x00, 0x00, 0x82];

    #[test]
    fn parse_rtmp_data_from_capture() {
        let pkt = RtmpData::from_bytes(RTMP_DATA_BYTES).expect("should parse");
        assert_eq!(pkt.network, 65456);
        assert_eq!(pkt.node, 190);
        assert_eq!(pkt.tuples, vec![RtmpTuple::Version(0x82)]);
    }

    #[test]
    fn parse_rtmp_data_header_only() {
        // Minimal valid packet: just the 4-byte header, no routing tuples.
        let data = [0x01, 0x00, 0x08, 0x01];
        let pkt = RtmpData::from_bytes(&data).expect("should parse");
        assert_eq!(pkt.network, 256);
        assert_eq!(pkt.node, 1);
        assert!(pkt.tuples.is_empty());
    }

    #[test]
    fn parse_rtmp_data_non_extended_tuple() {
        // 4-byte header + 3-byte non-extended routing tuple (net=100, hops=2).
        let data = [0x01, 0x00, 0x08, 0x01, 0x00, 0x64, 0x02];
        let pkt = RtmpData::from_bytes(&data).expect("should parse");
        assert_eq!(pkt.tuples, vec![RtmpTuple::NonExtended { network: 100, hops: 2 }]);
    }

    #[test]
    fn parse_rtmp_data_extended_tuple() {
        // 4-byte header + 6-byte extended tuple:
        // range_start=100, dist_byte=0x80 (extended, 0 hops), range_end=200, version=0x82.
        let data = [0x01, 0x00, 0x08, 0x01, 0x00, 0x64, 0x80, 0x00, 0xc8, 0x82];
        let pkt = RtmpData::from_bytes(&data).expect("should parse");
        assert_eq!(pkt.tuples, vec![RtmpTuple::Extended {
            range_start: 100,
            hops: 0,
            range_end: 200,
            version: 0x82,
        }]);
    }

    #[test]
    fn parse_rtmp_data_rejects_zero_network() {
        let data = [0x00, 0x00, 0x08, 0x01];
        assert!(RtmpData::from_bytes(&data).is_none());
    }

    #[test]
    fn parse_rtmp_data_rejects_zero_node() {
        let data = [0x01, 0x00, 0x08, 0x00];
        assert!(RtmpData::from_bytes(&data).is_none());
    }

    #[test]
    fn parse_rtmp_data_rejects_wrong_id_len() {
        let data = [0x01, 0x00, 0x10, 0x01]; // id_len=16, not 8
        assert!(RtmpData::from_bytes(&data).is_none());
    }

    #[test]
    fn parse_rtmp_data_rejects_too_short() {
        assert!(RtmpData::from_bytes(&[]).is_none());
        assert!(RtmpData::from_bytes(&[0xff, 0xb0, 0x08]).is_none());
    }

    #[test]
    fn rtmp_request_roundtrip() {
        let req = RtmpRequest { reply_socket: 1 };
        let mut buf = [0u8; 4];
        let n = req.to_bytes(&mut buf).unwrap();
        assert_eq!(n, 1);
        let parsed = RtmpRequest::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed, req);
    }
}
