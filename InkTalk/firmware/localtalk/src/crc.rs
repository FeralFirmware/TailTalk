//! LocalTalk frame CRC (FCS).
//!
//! CRC-16 / CCITT-false as used by SDLC and LLAP - init `0xFFFF`, polynomial
//! `0x1021` reflected, transmit the complement of the running register as
//! the trailing two bytes, with magic residue `0xF0B8` after the CRC has
//! been fed back through.
//!
//! In TashTalk's PIC firmware (`one-chip.asm`) the
//! 256-entry 16-bit table is split into two page-aligned 256-byte tables
//! (`CrcLut1` at `org 0x600` carrying the low byte of each entry, `CrcLut2`
//! at `org 0x700` carrying the high byte) so the PIC can index each with a
//! single-byte `callw`. Here we use one `[u16; 256]` table - the result is
//! mathematically identical and was already ported (with tests) in
//! TailTalk's `tashtalk` crate.

/// Pre-computed lookup table for the LocalTalk CRC-16.
///
/// `LT_CRC_LUT[i] & 0xFF` corresponds to `CrcLut1[i]` in the PIC asm;
/// `LT_CRC_LUT[i] >> 8` corresponds to `CrcLut2[i]`.
#[rustfmt::skip]
const LT_CRC_LUT: [u16; 256] = [
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
];

/// The post-frame residue. After feeding (frame_bytes ++ crc_bytes) through
/// the calculator, the register should equal this value if the frame is intact.
/// In the PIC asm, the same check is `crc1 == 0xB8 && crc2 == 0xF0`.
const POST_FRAME_RESIDUE: u16 = 0xF0B8;

/// Streaming LocalTalk CRC-16 calculator.
///
/// Feed the frame bytes (excluding the trailing CRC) through [`feed_byte`]
/// (or [`feed`] for a slice), then read off the two CRC bytes with
/// [`byte1`] and [`byte2`].
///
/// To verify a received frame, feed everything *including* the two trailing
/// CRC bytes and then call [`is_ok`].
///
/// [`feed_byte`]: Self::feed_byte
/// [`feed`]: Self::feed
/// [`byte1`]: Self::byte1
/// [`byte2`]: Self::byte2
/// [`is_ok`]: Self::is_ok
#[derive(Debug, Clone, Copy)]
pub struct CrcCalculator {
    reg: u16,
}

impl Default for CrcCalculator {
    fn default() -> Self {
        Self::new()
    }
}

impl CrcCalculator {
    pub const fn new() -> Self {
        Self { reg: 0xFFFF }
    }

    pub fn reset(&mut self) {
        self.reg = 0xFFFF;
    }

    pub fn feed_byte(&mut self, byte: u8) {
        let index = (self.reg as u8) ^ byte;
        self.reg = LT_CRC_LUT[index as usize] ^ (self.reg >> 8);
    }

    pub fn feed(&mut self, data: &[u8]) {
        for &b in data {
            self.feed_byte(b);
        }
    }

    /// First trailing CRC byte (sent on the wire right after the payload).
    pub fn byte1(&self) -> u8 {
        (self.reg as u8) ^ 0xFF
    }

    /// Second trailing CRC byte.
    pub fn byte2(&self) -> u8 {
        ((self.reg >> 8) as u8) ^ 0xFF
    }

    /// `true` if frame + CRC has been fully fed and the running register
    /// equals the SDLC residue.
    pub fn is_ok(&self) -> bool {
        self.reg == POST_FRAME_RESIDUE
    }

    /// Raw 16-bit running register (low byte = CRC1 in the PIC asm, high byte = CRC2).
    pub fn reg(&self) -> u16 {
        self.reg
    }
}

/// Convenience: compute the two CRC bytes for `data`.
pub fn lt_crc(data: &[u8]) -> [u8; 2] {
    let mut calc = CrcCalculator::new();
    calc.feed(data);
    [calc.byte1(), calc.byte2()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let calc = CrcCalculator::new();
        assert_eq!(calc.reg, 0xFFFF);
    }

    #[test]
    fn round_trip_ascii() {
        let data = b"Hello, LocalTalk!";
        let crc = lt_crc(data);
        let mut calc = CrcCalculator::new();
        calc.feed(data);
        calc.feed(&crc);
        assert!(calc.is_ok());
    }

    /// A minimal LLAP control frame (5 bytes: dest, src, type, two CRC bytes).
    /// We exercise the same bytes a TashTalk ENQ→ACK exchange would produce:
    /// ACK is `<requester_id, requester_id, 0x82>` followed by the FCS.
    #[test]
    fn ack_frame_crc_residue() {
        let frame = [0x12, 0x12, 0x82];
        let crc = lt_crc(&frame);
        let mut calc = CrcCalculator::new();
        calc.feed(&frame);
        calc.feed(&crc);
        assert!(calc.is_ok(), "ACK frame should validate");
    }

    #[test]
    fn reset_restores_state() {
        let mut calc = CrcCalculator::new();
        calc.feed(b"random junk that should be wiped");
        calc.reset();
        calc.feed(b"test");
        assert_eq!([calc.byte1(), calc.byte2()], lt_crc(b"test"));
    }

    /// The asm's `InFlag` checks `crc1 == 0xB8 && crc2 == 0xF0` after the
    /// trailing CRC bytes have been fed through. Confirm that `reg`'s byte
    /// layout matches that exactly.
    #[test]
    fn pic_residue_byte_layout() {
        let data = b"some payload";
        let crc = lt_crc(data);
        let mut calc = CrcCalculator::new();
        calc.feed(data);
        calc.feed(&crc);
        assert_eq!(calc.reg as u8, 0xB8, "low byte (CRC1) of residue");
        assert_eq!((calc.reg >> 8) as u8, 0xF0, "high byte (CRC2) of residue");
    }

    #[test]
    fn verify_enq_42_01_81_crc() {
        let header = [0x42u8, 0x01, 0x81];
        let crc = lt_crc(&header);
        assert_eq!(crc, [0x5b, 0xf9], "ENQ CRC for [0x42, 0x01, 0x81]");
    }

    /// Cross-check that the unified 16-bit table is bit-identical to the
    /// PIC's two split 8-bit tables. We just spot-check a few entries
    /// against the values in `one-chip.asm`:
    ///   CrcLut1 = 0x00,0x89,0x12,0x9B,...
    ///   CrcLut2 = 0x00,0x11,0x23,0x32,...
    #[test]
    fn split_table_layout_matches_pic_asm() {
        // (index, expected_lut1, expected_lut2) from one-chip.asm lines 1427/1464.
        let cases = [
            (0, 0x00, 0x00),
            (1, 0x89, 0x11),
            (2, 0x12, 0x23),
            (3, 0x9B, 0x32),
            (15, 0xF7, 0xF8),
            (255, 0x78, 0x0F),
        ];
        for (i, l1, l2) in cases {
            assert_eq!(LT_CRC_LUT[i] as u8, l1, "CrcLut1[{i}]");
            assert_eq!((LT_CRC_LUT[i] >> 8) as u8, l2, "CrcLut2[{i}]");
        }
    }
}
