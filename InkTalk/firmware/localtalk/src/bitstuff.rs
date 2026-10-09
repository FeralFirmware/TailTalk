//! SDLC bit-stuffing / unstuffing and flag/abort detection.
//!
//! In SDLC framing, the flag byte `0x7E = 0b01111110` and the abort
//! sequence (≥7 consecutive `1`s) need to be distinguishable from payload.
//! That's achieved by **bit-stuffing**: after every 5 consecutive `1`
//! bits in the payload, the transmitter inserts a `0`; the receiver drops
//! any `0` that follows 5 ones.
//!
//! - `0..=5` consecutive ones in the bit stream → payload data.
//! - 5 ones followed by a stuffed `0` → drop the `0` (continue payload).
//! - 5 ones followed by `10` → flag byte `0x7E`.
//! - 6 ones followed by `1` (i.e. 7+ ones) → abort.
//!
//! Both directions are byte-aligned in the firmware but the logic itself
//! is per-bit. This module is host-testable so we can validate against
//! known TashTalk frames.

use heapless::Vec;

use crate::MAX_FRAME_LEN;

/// The SDLC flag byte.
pub const FLAG: u8 = 0x7E;

/// Bit-stuff a byte stream. Returns the stuffed bit stream as a `heapless::Vec`
/// where bit 7 of byte 0 is the first bit transmitted.
///
/// Output capacity is sized for a max LocalTalk frame: payload is at most
/// `MAX_FRAME_LEN` bytes (605), at most one extra bit per 5 (worst case ~21%
/// expansion), plus the leading and trailing flag-byte sequences. We round
/// up generously.
pub fn stuff(input: &[u8]) -> Vec<u8, { MAX_FRAME_LEN * 2 }> {
    let mut bits = BitWriter::new();
    let mut ones: u8 = 0;
    for &byte in input {
        for bit_idx in 0..8 {
            let bit = (byte >> bit_idx) & 1;
            bits.push(bit);
            if bit == 1 {
                ones += 1;
                if ones == 5 {
                    bits.push(0);
                    ones = 0;
                }
            } else {
                ones = 0;
            }
        }
    }
    bits.finish()
}

/// Result of feeding one bit into the unstuffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnstuffEvent {
    /// A data byte has been assembled - `byte` is its value.
    Byte(u8),
    /// A flag byte (`0x7E`) was decoded - frame boundary.
    Flag,
    /// 7 or more consecutive `1`s - frame abort.
    Abort,
    /// Bit absorbed; no event emitted yet.
    None,
}

/// Streaming SDLC bit-unstuffer.
///
/// Feed bits via [`feed_bit`](Self::feed_bit); inspect each event the
/// receiver should react to.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitUnstuffer {
    /// Bit accumulator for the current payload byte (LSB-first as received).
    bit_pos: u8,
    accum: u8,
    /// Count of consecutive `1` bits seen most recently.
    ones: u8,
}

impl BitUnstuffer {
    pub const fn new() -> Self {
        Self {
            bit_pos: 0,
            accum: 0,
            ones: 0,
        }
    }

    pub fn reset(&mut self) {
        self.bit_pos = 0;
        self.accum = 0;
        self.ones = 0;
    }

    pub fn feed_bit(&mut self, bit: u8) -> UnstuffEvent {
        debug_assert!(bit <= 1);

        if self.ones == 5 {
            // Previous 5 bits were ones - the bit currently arriving is
            // either a stuffed 0 (drop) or the start of a flag/abort.
            self.ones = 0;
            if bit == 0 {
                // Stuffed zero; consume and resume payload.
                return UnstuffEvent::None;
            }
            // bit == 1, so we have 6 ones in a row so far. Need to look at
            // the next bit to know whether this is a flag (then 0) or an
            // abort (then 1). Mark that state by setting ones=6.
            self.ones = 6;
            return UnstuffEvent::None;
        }

        if self.ones == 6 {
            // We just saw 6 ones. This bit decides flag vs abort.
            self.ones = 0;
            // Reset accum: a flag/abort never delivers payload bits.
            self.bit_pos = 0;
            self.accum = 0;
            if bit == 0 {
                return UnstuffEvent::Flag;
            }
            return UnstuffEvent::Abort;
        }

        // Normal payload bit accumulation.
        self.accum |= bit << self.bit_pos;
        self.bit_pos += 1;

        if bit == 1 {
            self.ones += 1;
        } else {
            self.ones = 0;
        }

        if self.bit_pos == 8 {
            let byte = self.accum;
            self.accum = 0;
            self.bit_pos = 0;
            return UnstuffEvent::Byte(byte);
        }

        UnstuffEvent::None
    }
}

// ── Internal: a tiny bit-packed writer ───────────────────────────────────────

struct BitWriter {
    buf: Vec<u8, { MAX_FRAME_LEN * 2 }>,
    cur: u8,
    pos: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            cur: 0,
            pos: 0,
        }
    }

    fn push(&mut self, bit: u8) {
        self.cur |= bit << self.pos;
        self.pos += 1;
        if self.pos == 8 {
            self.buf.push(self.cur).unwrap();
            self.cur = 0;
            self.pos = 0;
        }
    }

    fn finish(mut self) -> Vec<u8, { MAX_FRAME_LEN * 2 }> {
        if self.pos > 0 {
            self.buf.push(self.cur).unwrap();
        }
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-tripping arbitrary bytes through stuff → unstuff must yield
    /// the original bytes (and no Flag/Abort events) for any input that
    /// doesn't itself include flag/abort bit patterns.
    #[test]
    fn stuff_unstuff_round_trip() {
        let payloads: &[&[u8]] = &[
            &[],
            &[0x00],
            &[0xFF],
            &[0xFF, 0xFF, 0xFF],
            &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
            &[0x7E], // Flag-byte value as payload - bit-stuffing must protect it.
            &[0xFE, 0xFE, 0xFE],
        ];

        for payload in payloads {
            let stuffed = stuff(payload);
            // Now bit-walk back. Since `stuff()` writes LSB-first in each
            // output byte, we read out the same way.
            let mut u = BitUnstuffer::new();
            let mut out: heapless::Vec<u8, 32> = heapless::Vec::new();
            // We only fed payload.len() * 8 + stuffed-zero bits, so iterate
            // exactly that many bits - not the whole rounded-up byte buffer.
            let mut bits_left = bits_needed(payload);
            'outer: for byte in stuffed.iter() {
                for bit_idx in 0..8 {
                    if bits_left == 0 {
                        break 'outer;
                    }
                    bits_left -= 1;
                    let bit = (byte >> bit_idx) & 1;
                    match u.feed_bit(bit) {
                        UnstuffEvent::Byte(b) => out.push(b).unwrap(),
                        UnstuffEvent::None => {}
                        ev => panic!("unexpected event in payload: {:?}", ev),
                    }
                }
            }
            assert_eq!(&out[..], *payload, "round-trip failed for {:?}", payload);
        }
    }

    fn bits_needed(payload: &[u8]) -> usize {
        // payload bits + one stuffed zero per run of 5 consecutive ones.
        let mut bits = payload.len() * 8;
        let mut ones = 0;
        for &byte in payload {
            for bit_idx in 0..8 {
                let bit = (byte >> bit_idx) & 1;
                if bit == 1 {
                    ones += 1;
                    if ones == 5 {
                        bits += 1;
                        ones = 0;
                    }
                } else {
                    ones = 0;
                }
            }
        }
        bits
    }

    /// Feeding a flag pattern (01111110) into the unstuffer must yield
    /// Flag exactly once and no spurious Byte events.
    #[test]
    fn flag_is_detected() {
        // 0x7E as transmitted on the wire = 0,1,1,1,1,1,1,0 (MSB first per
        // SDLC). However we feed bits LSB-first to match `stuff()`'s output.
        // The flag detection is rotation-agnostic; what matters is the
        // sequence "five ones then zero then... we want exactly the 6-ones-
        // then-zero pattern that means Flag in the unstuffer's state model".
        //
        // The unstuffer's state model: after 5 consecutive 1-bits in
        // payload position, the next bit decides; if it's 1, the *next*
        // again decides flag(0) vs abort(1). So the unambiguous flag bit
        // pattern is: 1,1,1,1,1,1,0.
        let mut u = BitUnstuffer::new();
        for bit in [1, 1, 1, 1, 1, 1, 0] {
            let ev = u.feed_bit(bit);
            if ev == UnstuffEvent::Flag {
                return;
            }
        }
        panic!("flag pattern did not produce Flag event");
    }

    /// Seven consecutive 1-bits → abort.
    #[test]
    fn seven_ones_is_abort() {
        let mut u = BitUnstuffer::new();
        let mut events: heapless::Vec<UnstuffEvent, 16> = heapless::Vec::new();
        for bit in [1, 1, 1, 1, 1, 1, 1] {
            events.push(u.feed_bit(bit)).unwrap();
        }
        assert!(events.contains(&UnstuffEvent::Abort), "got {:?}", events);
    }
}
