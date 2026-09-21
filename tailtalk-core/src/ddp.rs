//! DDP datagram types and header framing.
//!
//! The socket table itself lives in [`crate::stack`]; this module holds the
//! pieces shared with the transports: the datagram representation handed to
//! socket owners and the short/long header encode helpers.

use alloc::vec;
use alloc::vec::Vec;
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::{DdpPacket, DdpProtocolType};

/// Maximum DDP payload, from Inside AppleTalk (586 data bytes).
pub const MAX_DDP_PAYLOAD: usize = 586;

/// Socket numbers available for dynamic assignment. Below 64 is reserved for
/// statically assigned sockets, and 255 is the broadcast socket.
pub const DYNAMIC_SOCKET_LO: u8 = 64;
pub const DYNAMIC_SOCKET_HI: u8 = 254;

/// A received datagram delivered to a socket owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub src: AppleTalkAddress,
    pub src_socket: u8,
    pub dst_socket: u8,
    pub proto: DdpProtocolType,
    pub payload: Vec<u8>,
}

/// Encode a DDP datagram body (header + payload), short or long form.
///
/// Short form (5-byte header) is LocalTalk-only and valid only while the
/// segment is unrouted; once a router is known the caller must switch to
/// long form, which carries network numbers and a checksum.
pub fn encode_ddp(
    use_short: bool,
    src: AppleTalkAddress,
    src_socket: u8,
    dest: AppleTalkAddress,
    dest_socket: u8,
    proto: DdpProtocolType,
    payload: &[u8],
) -> Vec<u8> {
    let header_len = if use_short { 5 } else { DdpPacket::LEN };
    let headers = DdpPacket {
        hop_count: 0,
        len: payload.len() + header_len,
        chksum: 0,
        dest_network_num: dest.network_number,
        dest_sock_num: dest_socket,
        dest_node_id: dest.node_number,
        src_network_num: src.network_number,
        src_sock_num: src_socket,
        src_node_id: src.node_number,
        protocol_typ: proto,
    };

    let mut buf = vec![0u8; header_len + payload.len()];
    let written = if use_short {
        // Short DDP does not use checksums - leave chksum = 0.
        headers
            .to_bytes_short(&mut buf)
            .expect("short DDP header encode cannot fail with a sized buffer")
    } else {
        let n = headers
            .to_bytes(&mut buf)
            .expect("long DDP header encode cannot fail with a sized buffer");
        buf[2] = 0;
        buf[3] = 0;
        n
    };
    buf[written..].copy_from_slice(payload);

    // The long-form checksum covers everything after the 4-byte
    // hop/len + chksum fields; a result of 0 is sent as 0xFFFF
    // (compute_checksum handles that substitution).
    if !use_short {
        let chksum = DdpPacket::compute_checksum(&buf[4..]);
        buf[2] = (chksum >> 8) as u8;
        buf[3] = (chksum & 0xFF) as u8;
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(net: u16, node: u8) -> AppleTalkAddress {
        AppleTalkAddress {
            network_number: net,
            node_number: node,
        }
    }

    #[test]
    fn short_form_round_trips() {
        let body = encode_ddp(
            true,
            addr(0, 130),
            72,
            addr(0, 5),
            2,
            DdpProtocolType::Nbp,
            &[1, 2, 3],
        );
        assert_eq!(body.len(), 5 + 3);
        let hdr = DdpPacket::parse_short(&body, 5, 130).unwrap();
        assert_eq!(hdr.len, 8);
        assert_eq!(hdr.dest_sock_num, 2);
        assert_eq!(hdr.src_sock_num, 72);
        assert_eq!(hdr.protocol_typ, DdpProtocolType::Nbp);
        assert_eq!(&body[5..], &[1, 2, 3]);
    }

    #[test]
    fn long_form_carries_networks_and_checksum() {
        let body = encode_ddp(
            false,
            addr(3, 130),
            72,
            addr(5, 9),
            2,
            DdpProtocolType::Atp,
            &[9, 9],
        );
        let hdr = DdpPacket::parse(&body).unwrap();
        assert_eq!(hdr.src_network_num, 3);
        assert_eq!(hdr.dest_network_num, 5);
        assert_eq!(hdr.len, DdpPacket::LEN + 2);
        // Verify the checksum the way a receiver would.
        let mut check = body.clone();
        check[2] = 0;
        check[3] = 0;
        assert_eq!(hdr.chksum, DdpPacket::compute_checksum(&check[4..]));
    }
}
