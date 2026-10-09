//! LLAP frame assembly and the autonomous control-frame autoresponder.
//!
//! This module sits one layer above the SDLC bit-stuff/unstuff layer.
//! It takes the byte stream produced by the FM-0 + bit-unstuff path and:
//!
//! - assembles flag-delimited byte sequences into candidate frames,
//! - validates the frame CRC (the LocalTalk FCS),
//! - decides whether we should autonomously reply (ENQ → ACK, RTS → CTS),
//! - composes the reply.
//!
//! The PIC reference firmware does this in `DealWithFrame` at
//! `one-chip.asm:704`. Same behaviour, split into pure functions so it can
//! be tested on a host, and filtered against the one node this board owns
//! rather than a 32-byte register file of them.
//!
//! All functions are `no_std` and side-effect-free.

use crate::crc::{lt_crc, CrcCalculator};
use heapless::Vec;

/// Maximum LocalTalk frame size (LLAP); see `codec::MAX_FRAME_LEN`.
const MAX_FRAME_LEN: usize = 605;

/// LLAP type codes for the control frames we care about.
pub mod llap_type {
    pub const ENQ: u8 = 0x81;
    pub const ACK: u8 = 0x82;
    pub const RTS: u8 = 0x84;
    pub const CTS: u8 = 0x85;
}

/// A reassembled LLAP frame. Includes the trailing two FCS bytes.
pub type Frame = Vec<u8, MAX_FRAME_LEN>;

/// Validate a complete frame (LLAP header + body + 2 trailing FCS bytes).
/// Returns `true` if the CRC residue is the canonical SDLC value.
pub fn frame_crc_ok(frame: &[u8]) -> bool {
    if frame.len() < 5 {
        return false;
    }
    let mut crc = CrcCalculator::new();
    crc.feed(frame);
    crc.is_ok()
}

/// Compose a 5-byte ACK frame replying to an ENQ that targeted `node`.
///
/// LLAP convention: ACK carries `dest=src=node` because we are claiming
/// to own that ID - matches `SendAck` in `one-chip.asm:893`.
pub fn compose_ack(node: u8) -> [u8; 5] {
    let mut f = [0u8; 5];
    f[0] = node;
    f[1] = node;
    f[2] = llap_type::ACK;
    let crc = lt_crc(&f[..3]);
    f[3] = crc[0];
    f[4] = crc[1];
    f
}

/// Compose a 5-byte CTS frame replying to an RTS from `requester` that
/// targeted `our_node`. Matches `SendCts` in `one-chip.asm:933`.
pub fn compose_cts(requester: u8, our_node: u8) -> [u8; 5] {
    let mut f = [0u8; 5];
    f[0] = requester;
    f[1] = our_node;
    f[2] = llap_type::CTS;
    let crc = lt_crc(&f[..3]);
    f[3] = crc[0];
    f[4] = crc[1];
    f
}

/// Compose a 5-byte RTS frame: this node (src) is asking `dest` for
/// permission to send a data frame. Matches `SendRts` in
/// `one-chip.asm:853`.
pub fn compose_rts(dest: u8, src: u8) -> [u8; 5] {
    let mut f = [0u8; 5];
    f[0] = dest;
    f[1] = src;
    f[2] = llap_type::RTS;
    let crc = lt_crc(&f[..3]);
    f[3] = crc[0];
    f[4] = crc[1];
    f
}

/// `true` if `frame` is a CTS that matches an outstanding RTS sent by
/// `our_src` to `their_dest`. (The CTS we expect carries
/// `dest=our_src, src=their_dest, type=CTS`.)
pub fn cts_matches_pending(frame: &[u8], our_src: u8, their_dest: u8) -> bool {
    frame.len() >= 5
        && frame[0] == our_src
        && frame[1] == their_dest
        && frame[2] == llap_type::CTS
        && frame_crc_ok(frame)
}

/// Decision the autoresponder reaches for a received frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoReply {
    /// No reply - frame is for someone else, or is a data frame, or has
    /// a type the firmware does not handle autonomously.
    None,
    /// Send an ACK with `dest=src=node`.
    Ack { node: u8 },
    /// Send a CTS with `dest=requester, src=our_node`.
    Cts { requester: u8, our_node: u8 },
}

impl AutoReply {
    /// Serialize the reply to a 5-byte LLAP control frame ready for
    /// PIO TX. Returns `None` if no reply is required.
    pub fn into_frame(self) -> Option<[u8; 5]> {
        match self {
            AutoReply::None => None,
            AutoReply::Ack { node } => Some(compose_ack(node)),
            AutoReply::Cts {
                requester,
                our_node,
            } => Some(compose_cts(requester, our_node)),
        }
    }
}

/// Decide whether a received frame requires an autonomous reply.
///
/// Mirrors `DealWithFrame` (`one-chip.asm:704`):
/// - frame must have a valid CRC
/// - frame must be a *control* frame (LLAP type bit 7 set)
/// - destination must be in our node bitmap
/// - for ENQ (type 0x81): reply with ACK
/// - for RTS (type 0x84): reply with CTS
/// - for CTS (type 0x85): the firmware needs to know we have a pending
///   RTS to which this is the response; that pairing is stateful and
///   lives outside this pure function. We just return `None` here.
/// - other control frames (ACK and anything else): nothing to do.
pub fn auto_reply(frame: &[u8], our_node: u8) -> AutoReply {
    if !frame_crc_ok(frame) {
        return AutoReply::None;
    }
    if frame.len() < 5 {
        return AutoReply::None;
    }
    let dest = frame[0];
    let src = frame[1];
    let llap_type = frame[2];
    if dest != our_node {
        return AutoReply::None; // not addressed to us
    }
    if llap_type & 0x80 == 0 {
        return AutoReply::None; // data frame
    }
    match llap_type {
        llap_type::ENQ => AutoReply::Ack { node: dest },
        llap_type::RTS => AutoReply::Cts {
            requester: src,
            our_node: dest,
        },
        _ => AutoReply::None,
    }
}

// ── Frame assembler ─────────────────────────────────────────────────

/// Streaming SDLC frame assembler. Consumes the byte/flag/abort
/// stream produced by the FM-0 + bit-unstuff layer and emits
/// flag-delimited candidate frames.
///
/// Frames are NOT CRC-validated here - that's done separately, after
/// the caller has decided what to do with each candidate.
#[derive(Debug)]
pub struct FrameAssembler {
    state: AsmState,
    current: Frame,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AsmState {
    /// Waiting for the opening flag.
    Idle,
    /// Between two flags - accumulating frame bytes.
    InFrame,
}

/// Event produced by the assembler when feeding decoded events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsmEvent {
    /// A flag-delimited frame ended. The byte slice is the candidate
    /// frame (LLAP header + body + 2 FCS bytes if structurally valid).
    /// Caller must CRC-validate.
    FrameEnd,
    /// Abort marker received mid-frame. Current bytes have been
    /// discarded.
    Aborted,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self {
            state: AsmState::Idle,
            current: Frame::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state = AsmState::Idle;
        self.current.clear();
    }

    /// Borrow the bytes accumulated so far.
    pub fn current(&self) -> &[u8] {
        &self.current
    }

    /// Feed one event from the FM-0 layer. Returns `Some(AsmEvent)` if
    /// the event triggers a state transition the caller cares about
    /// (FrameEnd or Aborted).
    pub fn feed_byte(&mut self, byte: u8) -> Option<AsmEvent> {
        if self.state == AsmState::InFrame {
            let _ = self.current.push(byte);
        }
        None
    }

    pub fn feed_flag(&mut self) -> Option<AsmEvent> {
        match self.state {
            AsmState::Idle => {
                // Opening flag - start collecting.
                self.state = AsmState::InFrame;
                self.current.clear();
                None
            }
            AsmState::InFrame => {
                // Closing flag - frame ends here. The same flag also
                // opens the NEXT frame (per SDLC), so we stay in
                // InFrame after clearing.
                if self.current.is_empty() {
                    // Back-to-back flags (preamble run). No frame ended.
                    None
                } else {
                    Some(AsmEvent::FrameEnd)
                }
            }
        }
    }

    /// Tell the assembler the caller has consumed `current()` and we
    /// should start fresh for the next frame. Must be called after
    /// `feed_flag` returned `FrameEnd`.
    pub fn ack_frame_end(&mut self) {
        self.current.clear();
        // Stay in InFrame - the closing flag also opened the next frame.
    }

    pub fn feed_abort(&mut self) -> Option<AsmEvent> {
        let was_collecting = !self.current.is_empty();
        self.current.clear();
        self.state = AsmState::Idle;
        if was_collecting {
            Some(AsmEvent::Aborted)
        } else {
            None
        }
    }
}

impl Default for FrameAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crc::lt_crc;

    fn make_enq(dest: u8, src: u8) -> [u8; 5] {
        let mut f = [0u8; 5];
        f[0] = dest;
        f[1] = src;
        f[2] = llap_type::ENQ;
        let c = lt_crc(&f[..3]);
        f[3] = c[0];
        f[4] = c[1];
        f
    }

    fn make_rts(dest: u8, src: u8) -> [u8; 5] {
        let mut f = [0u8; 5];
        f[0] = dest;
        f[1] = src;
        f[2] = llap_type::RTS;
        let c = lt_crc(&f[..3]);
        f[3] = c[0];
        f[4] = c[1];
        f
    }

    #[test]
    fn ack_round_trip_validates() {
        let ack = compose_ack(0x42);
        assert_eq!(ack[0], 0x42);
        assert_eq!(ack[1], 0x42);
        assert_eq!(ack[2], 0x82);
        assert!(frame_crc_ok(&ack));
    }

    #[test]
    fn rts_round_trip_validates() {
        let rts = compose_rts(0x10, 0x42);
        assert_eq!(rts[0], 0x10);
        assert_eq!(rts[1], 0x42);
        assert_eq!(rts[2], llap_type::RTS);
        assert!(frame_crc_ok(&rts));
    }

    #[test]
    fn cts_matching() {
        // We sent RTS to node 0x10; we expect CTS back with
        // dest=us(0x42), src=them(0x10).
        let cts = compose_cts(0x42, 0x10);
        assert!(cts_matches_pending(&cts, 0x42, 0x10));
        // Wrong pairings don't match.
        assert!(!cts_matches_pending(&cts, 0x10, 0x42));
        assert!(!cts_matches_pending(&cts, 0x42, 0x11));
    }

    #[test]
    fn cts_round_trip_validates() {
        let cts = compose_cts(0x10, 0x42);
        assert_eq!(cts[0], 0x10);
        assert_eq!(cts[1], 0x42);
        assert_eq!(cts[2], 0x85);
        assert!(frame_crc_ok(&cts));
    }

    #[test]
    fn auto_reply_enq_to_known_node_yields_ack() {
        let our_node = 0x42;
        let enq = make_enq(0x42, 0xFF);
        assert_eq!(auto_reply(&enq, our_node), AutoReply::Ack { node: 0x42 });
    }

    #[test]
    fn auto_reply_enq_to_unknown_node_is_none() {
        let our_node = 0;
        let enq = make_enq(0x42, 0xFF);
        assert_eq!(auto_reply(&enq, our_node), AutoReply::None);
    }

    #[test]
    fn auto_reply_rts_to_known_node_yields_cts() {
        let our_node = 0x42;
        let rts = make_rts(0x42, 0x10);
        assert_eq!(
            auto_reply(&rts, our_node),
            AutoReply::Cts {
                requester: 0x10,
                our_node: 0x42,
            }
        );
    }

    #[test]
    fn auto_reply_data_frame_yields_ack() {
        let our_node = 0x42;
        // data frame: type byte's high bit is 0
        let mut data_frame = [0u8; 10];
        data_frame[0] = 0x42;
        data_frame[1] = 0xFF;
        data_frame[2] = 0x01;
        data_frame[3] = 0x00;
        data_frame[4] = 0x05;
        data_frame[5] = 0xAA;
        data_frame[6] = 0xBB;
        data_frame[7] = 0xCC;
        let c = lt_crc(&data_frame[..8]);
        data_frame[8] = c[0];
        data_frame[9] = c[1];
        assert_eq!(auto_reply(&data_frame, our_node), AutoReply::None);
    }

    #[test]
    fn auto_reply_bad_crc_is_none() {
        let our_node = 0x42;
        let mut enq = make_enq(0x42, 0xFF);
        enq[3] ^= 0xFF; // corrupt CRC
        assert_eq!(auto_reply(&enq, our_node), AutoReply::None);
    }

    #[test]
    fn assembler_extracts_frame_between_flags() {
        let mut asm = FrameAssembler::new();
        // opening flag
        assert_eq!(asm.feed_flag(), None);
        // frame body
        for b in [0x42, 0x42, 0x82, 0xAA, 0xBB] {
            assert_eq!(asm.feed_byte(b), None);
        }
        // closing flag
        assert_eq!(asm.feed_flag(), Some(AsmEvent::FrameEnd));
        assert_eq!(asm.current(), &[0x42, 0x42, 0x82, 0xAA, 0xBB]);
        asm.ack_frame_end();
        assert_eq!(asm.current(), &[]);
    }

    #[test]
    fn assembler_skips_back_to_back_preamble_flags() {
        let mut asm = FrameAssembler::new();
        for _ in 0..3 {
            assert_eq!(asm.feed_flag(), None);
        }
        // now the actual frame
        for b in [0x42, 0x42, 0x82, 0xAA, 0xBB] {
            asm.feed_byte(b);
        }
        assert_eq!(asm.feed_flag(), Some(AsmEvent::FrameEnd));
    }

    #[test]
    fn assembler_handles_abort() {
        let mut asm = FrameAssembler::new();
        asm.feed_flag();
        asm.feed_byte(0x42);
        asm.feed_byte(0x42);
        assert_eq!(asm.feed_abort(), Some(AsmEvent::Aborted));
        assert!(asm.current().is_empty());
    }
}
