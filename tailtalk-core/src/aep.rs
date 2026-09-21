//! AEP echo responder.
//!
//! Cheap to have and very useful during bring-up: any Mac with a ping tool
//! can verify the whole path - wire, LLAP, DDP - with
//! an echo round trip before any printer role exists.

use alloc::vec::Vec;
use tailtalk_packets::aep::{AepFunction, AepPacket};

/// The well-known AEP socket.
pub const AEP_SOCKET: u8 = 4;

/// If `payload` is an AEP Request, produce the Reply payload to send back.
pub fn respond(payload: &[u8]) -> Option<Vec<u8>> {
    let packet = AepPacket::parse(payload).ok()?;
    if packet.function != AepFunction::Request {
        return None;
    }
    let mut reply = payload.to_vec();
    reply[0] = AepFunction::Reply as u8;
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_becomes_reply_with_payload_intact() {
        let req = [1u8, 0xDE, 0xAD, 0xBE, 0xEF];
        let reply = respond(&req).unwrap();
        assert_eq!(reply, [2u8, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn replies_and_garbage_are_ignored() {
        assert!(respond(&[2u8, 1, 2]).is_none());
        assert!(respond(&[7u8]).is_none());
        assert!(respond(&[]).is_none());
    }
}
