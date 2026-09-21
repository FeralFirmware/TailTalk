//! LLAP frame types crossing the link boundary.
//!
//! The stack neither transmits nor receives by itself: the embedding code
//! (firmware, or a test harness) drains [`OutFrame`]s from
//! [`crate::stack::Stack::poll_transmit`] and feeds received frames into
//! [`crate::stack::Stack::handle_frame`]. Frames are exchanged without the
//! FCS: the wire engine appends the CRC on transmit, and strips or
//! validates it on receive.

use alloc::vec::Vec;
pub use tailtalk_packets::llap::LlapType;

/// An LLAP frame the stack wants on the wire. `payload` is empty for control
/// frames (ENQ, ACK). Data frames carry the DDP header plus payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutFrame {
    pub dst: u8,
    pub src: u8,
    pub kind: LlapType,
    pub payload: Vec<u8>,
}

impl OutFrame {
    /// Whether this frame is an immediate control response (ENQ or ACK) that
    /// should bypass the CSMA queue where the link layer distinguishes them.
    pub fn is_control(&self) -> bool {
        matches!(self.kind, LlapType::Enquiry | LlapType::Acknowledge)
    }

    /// Serialize to raw LLAP bytes (dst, src, type, payload), no FCS.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.payload.len());
        out.push(self.dst);
        out.push(self.src);
        out.push(match self.kind {
            LlapType::DdpShort => 1,
            LlapType::DdpLong => 2,
            LlapType::Enquiry => 0x81,
            LlapType::Acknowledge => 0x82,
            LlapType::Other(n) => n,
        });
        out.extend_from_slice(&self.payload);
        out
    }
}

/// Something the firmware implements to push frames toward the wire, for
/// embeddings that prefer a callback over draining the outbox. The stack
/// itself only uses its internal outbox; this trait is a convenience for
/// glue code.
pub trait FrameSink {
    fn send_frame(&mut self, frame: &OutFrame);
}
