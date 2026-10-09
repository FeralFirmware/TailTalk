//! HDLC frame builder for the LocalTalk TX path.
//!
//! Constructs a complete HDLC bitstream from an LLAP frame:
//!
//! ```text
//! [Flag][Flag][bit-stuffed payload+CRC][Flag][Abort]
//! ```
//!
//! The output is a sequence of raw bits (one bit per `u8`, value 0 or 1)
//! ready for FM-0 encoding. Flags and abort are NOT bit-stuffed; only
//! the payload + CRC region is.
//!
//! LLAP's synchronization pulse (a transition, then over two bit times of
//! idle) is not sent: the firmware enables the driver and the flags follow.

use heapless::Vec;

use crate::bitstuff::FLAG;
use crate::MAX_FRAME_LEN;

/// Number of opening flag bytes.
const NUM_OPENING_FLAGS: usize = 2;

/// Number of abort bits (continuous 1s) appended after the closing flag.
/// The spec says 12-18; we use 16 (2 bytes worth).
const NUM_ABORT_BITS: usize = 16;

/// Maximum output bits for a fully framed HDLC bitstream.
///
/// Breakdown (worst case):
/// - 2 flags × 8 bits = 16
/// - 605 payload bytes × 8 = 4840 data bits, ≤ 968 stuff bits = ~5808
/// - 2 CRC bytes × 8 = 16 data bits, ≤ 4 stuff bits = ~20
/// - 1 closing flag = 8
/// - 16 abort bits
///
/// Total ≤ ~5868 bits. We round up.
pub const MAX_HDLC_BITS: usize = 8192;

/// Bit vector type for HDLC output.
pub type HdlcBits = Vec<u8, MAX_HDLC_BITS>;

/// Build a complete HDLC bitstream from an LLAP frame that already
/// includes the trailing 2-byte FCS (CRC-CCITT).
///
/// The input `frame` must be the complete LLAP frame WITH CRC appended
/// (e.g. 5 bytes for a control frame, or header+data+2 CRC for data).
/// This function does NOT compute or append CRC - it only adds HDLC
/// framing (flags, bit-stuffing, abort).
///
/// Output: one `u8` per bit (value 0 or 1), LSB-first within each byte
/// of the original frame. Ready for FM-0 encoding.
///
/// Returns `None` if the frame is too short (< 5 bytes: 3 header + 2 CRC).
pub fn build_hdlc_bitstream(frame: &[u8]) -> Option<HdlcBits> {
    let mut bits = HdlcBits::new();
    build_hdlc_bitstream_into(frame, &mut bits)?;
    Some(bits)
}

/// Like [`build_hdlc_bitstream`] but writes into a caller-provided buffer.
/// Avoids allocating 8KB on the stack.
pub fn build_hdlc_bitstream_into(frame: &[u8], bits: &mut HdlcBits) -> Option<usize> {
    if frame.len() < 5 || frame.len() > MAX_FRAME_LEN {
        return None;
    }

    bits.clear();

    // Opening flags (not bit-stuffed).
    for _ in 0..NUM_OPENING_FLAGS {
        push_byte_as_bits(bits, FLAG);
    }

    // Bit-stuff the frame bytes (which already include CRC).
    let mut ones: u8 = 0;
    for &byte in frame.iter() {
        for bit_idx in 0..8u8 {
            let bit = (byte >> bit_idx) & 1;
            let _ = bits.push(bit);
            if bit == 1 {
                ones += 1;
                if ones == 5 {
                    let _ = bits.push(0); // stuff bit
                    ones = 0;
                }
            } else {
                ones = 0;
            }
        }
    }

    // Closing flag (not bit-stuffed).
    push_byte_as_bits(bits, FLAG);

    // Abort sequence: continuous 1s.
    for _ in 0..NUM_ABORT_BITS {
        let _ = bits.push(1);
    }

    Some(bits.len())
}

/// Push 8 bits of a byte (LSB first) into the bit vector.
fn push_byte_as_bits(bits: &mut HdlcBits, byte: u8) {
    for i in 0..8u8 {
        let _ = bits.push((byte >> i) & 1);
    }
}

// ── Full TX pipeline ──────────────────────────────────────────────────

use crate::fm0::{Fm0Encoder, MAX_FM0_SYMBOLS};

/// FM-0 encoded symbol buffer, ready for PIO shift-out.
pub type Fm0Buffer = Vec<u8, MAX_FM0_SYMBOLS>;

/// Build a PIO-ready FM-0 symbol buffer for a CSMA/CA transmission.
///
/// The output is the HDLC frame FM-0 encoded: flags + bit-stuffed
/// payload+CRC + closing flag + abort. DE is controlled by software
/// so no padding is needed.
///
/// Returns `None` if the frame is invalid.
pub fn build_tx_buffer(frame: &[u8]) -> Option<Fm0Buffer> {
    let mut hdlc = HdlcBits::new();
    let mut fm0 = Fm0Buffer::new();
    build_tx_buffer_into(frame, &mut hdlc, &mut fm0)?;
    Some(fm0)
}

/// Like [`build_tx_buffer`] but writes into caller-provided buffers.
/// Avoids allocating 16KB + 8KB on the stack. Returns the FM-0 symbol
/// count on success.
pub fn build_tx_buffer_into(
    frame: &[u8],
    hdlc_scratch: &mut HdlcBits,
    fm0: &mut Fm0Buffer,
) -> Option<usize> {
    fm0.clear();
    build_hdlc_bitstream_into(frame, hdlc_scratch)?;
    let mut enc = Fm0Encoder::new();
    for &bit in hdlc_scratch.iter() {
        let (a, b) = enc.encode_bit(bit);
        let _ = fm0.push(a);
        let _ = fm0.push(b);
    }
    Some(fm0.len())
}

/// The FM-0 buffer for a frame sent inside a dialog (CTS, ACK, data after
/// CTS), which goes out within the IFG (200 µs) without CSMA. The encoding
/// is the same as [`build_tx_buffer`].
///
/// Returns `None` if the frame is invalid.
pub fn build_immediate_tx_buffer(frame: &[u8]) -> Option<Fm0Buffer> {
    build_tx_buffer(frame)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitstuff::BitUnstuffer;
    use crate::bitstuff::UnstuffEvent;
    use crate::crc::lt_crc;

    /// Helper: feed all bits from an HDLC bitstream through the
    /// unstuffer, collecting events.
    fn unstuff_bitstream(bits: &[u8]) -> std::vec::Vec<UnstuffEvent> {
        let mut u = BitUnstuffer::new();
        let mut events = std::vec::Vec::new();
        for &bit in bits {
            let ev = u.feed_bit(bit);
            if ev != UnstuffEvent::None {
                events.push(ev);
            }
        }
        events
    }

    #[test]
    fn basic_control_frame() {
        // ENQ frame: [dest=0x42, src=0x01, type=0x81, CRC1, CRC2]
        let header = [0x42u8, 0x01, 0x81];
        let crc = lt_crc(&header);
        let frame = [header[0], header[1], header[2], crc[0], crc[1]];
        let bits = build_hdlc_bitstream(&frame).unwrap();

        let events = unstuff_bitstream(&bits);

        // Expect: Flag, Flag, 0x42, 0x01, 0x81, CRC1, CRC2, Flag, Abort
        assert!(events.len() >= 7, "events: {:?}", events);
        assert_eq!(events[0], UnstuffEvent::Flag);
        assert_eq!(events[1], UnstuffEvent::Flag);
        assert_eq!(events[2], UnstuffEvent::Byte(0x42));
        assert_eq!(events[3], UnstuffEvent::Byte(0x01));
        assert_eq!(events[4], UnstuffEvent::Byte(0x81));
        assert_eq!(events[5], UnstuffEvent::Byte(crc[0]));
        assert_eq!(events[6], UnstuffEvent::Byte(crc[1]));
        assert_eq!(events[7], UnstuffEvent::Flag);
        assert_eq!(events[8], UnstuffEvent::Abort);
    }

    #[test]
    fn crc_validates_after_unstuff() {
        let header = [0x42u8, 0x01, 0x81];
        let crc = lt_crc(&header);
        let frame = [header[0], header[1], header[2], crc[0], crc[1]];
        let bits = build_hdlc_bitstream(&frame).unwrap();
        let events = unstuff_bitstream(&bits);

        // Collect payload bytes (between first non-flag and closing flag).
        let payload_bytes: std::vec::Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                UnstuffEvent::Byte(b) => Some(*b),
                _ => None,
            })
            .collect();

        // Feed all payload bytes (including CRC) through CRC calculator.
        let mut crc_calc = crate::crc::CrcCalculator::new();
        crc_calc.feed(&payload_bytes);
        assert!(crc_calc.is_ok(), "CRC validation failed, reg=0x{:04X}", crc_calc.reg());
    }

    #[test]
    fn data_frame_with_payload() {
        // Data frame with some payload bytes + CRC.
        let mut body = [0u8; 10];
        body[0] = 0xFF; // dest (broadcast)
        body[1] = 0x42; // src
        body[2] = 0x01; // type (DDP short)
        body[3..10].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]);
        let crc = lt_crc(&body);
        let mut frame = [0u8; 12];
        frame[..10].copy_from_slice(&body);
        frame[10] = crc[0];
        frame[11] = crc[1];

        let bits = build_hdlc_bitstream(&frame).unwrap();
        let events = unstuff_bitstream(&bits);

        // Verify structure: Flag, Flag, bytes..., Flag, Abort
        assert_eq!(events[0], UnstuffEvent::Flag);
        assert_eq!(events[1], UnstuffEvent::Flag);

        // Collect data bytes.
        let payload: std::vec::Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                UnstuffEvent::Byte(b) => Some(*b),
                _ => None,
            })
            .collect();

        // payload = frame bytes (already including CRC)
        assert_eq!(payload.len(), frame.len());
        assert_eq!(&payload[..], &frame);

        // CRC should validate.
        let mut crc_calc = crate::crc::CrcCalculator::new();
        crc_calc.feed(&payload);
        assert!(crc_calc.is_ok());
    }

    #[test]
    fn all_ff_payload_bitstuffs_correctly() {
        // 0xFF bytes have runs of 8 ones, which must be bit-stuffed.
        let header = [0xFF, 0xFF, 0xFF];
        let crc = lt_crc(&header);
        let frame = [0xFF, 0xFF, 0xFF, crc[0], crc[1]];
        let bits = build_hdlc_bitstream(&frame).unwrap();
        let events = unstuff_bitstream(&bits);

        let payload: std::vec::Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                UnstuffEvent::Byte(b) => Some(*b),
                _ => None,
            })
            .collect();

        assert_eq!(&payload[..3], &[0xFF, 0xFF, 0xFF]);

        let mut crc_calc = crate::crc::CrcCalculator::new();
        crc_calc.feed(&payload);
        assert!(crc_calc.is_ok());
    }

    #[test]
    fn rejects_too_short_frame() {
        // Need at least 5 bytes (3 header + 2 CRC)
        assert!(build_hdlc_bitstream(&[0x42, 0x01, 0x81, 0x00]).is_none());
        assert!(build_hdlc_bitstream(&[]).is_none());
    }

    #[test]
    fn minimum_frame_works() {
        // Minimum valid LLAP: 3 header + 2 CRC = 5 bytes.
        let header = [0x42, 0x42, 0x82]; // ACK
        let crc = lt_crc(&header);
        let frame = [header[0], header[1], header[2], crc[0], crc[1]];
        let bits = build_hdlc_bitstream(&frame).unwrap();
        assert!(!bits.is_empty());

        let events = unstuff_bitstream(&bits);
        assert!(events.contains(&UnstuffEvent::Flag));
        assert!(events.contains(&UnstuffEvent::Abort));
    }

    #[test]
    fn bitstream_starts_with_flags_ends_with_abort() {
        let header = [0x42, 0x01, 0x81];
        let crc = lt_crc(&header);
        let frame = [header[0], header[1], header[2], crc[0], crc[1]];
        let bits = build_hdlc_bitstream(&frame).unwrap();

        // First 16 bits should be two flag bytes (0x7E LSB-first).
        let flag_bits_expected = [0u8, 1, 1, 1, 1, 1, 1, 0];
        assert_eq!(&bits[0..8], &flag_bits_expected);
        assert_eq!(&bits[8..16], &flag_bits_expected);

        // Last NUM_ABORT_BITS should all be 1.
        let abort_region = &bits[bits.len() - NUM_ABORT_BITS..];
        assert!(
            abort_region.iter().all(|&b| b == 1),
            "abort region: {:?}",
            abort_region
        );
    }

    // ── TX pipeline tests ─────────────────────────────────────────────

    #[test]
    fn tx_buffer_matches_immediate() {
        // With SM1 removed, CSMA and immediate buffers produce identical
        // FM-0 output (the only difference is CSMA/CA timing in the caller).
        let header = [0x42, 0x01, 0x81];
        let crc = lt_crc(&header);
        let frame = [header[0], header[1], header[2], crc[0], crc[1]];
        let csma = build_tx_buffer(&frame).unwrap();
        let imm = build_immediate_tx_buffer(&frame).unwrap();
        assert_eq!(csma.as_slice(), imm.as_slice());
    }

    #[test]
    fn tx_buffer_rejects_invalid_frame() {
        assert!(build_tx_buffer(&[0x42]).is_none());
        assert!(build_immediate_tx_buffer(&[]).is_none());
    }
}
