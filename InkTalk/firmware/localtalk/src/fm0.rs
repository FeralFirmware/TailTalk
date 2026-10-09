//! Stateful FM-0 (differential Manchester) decoder with clock recovery.
//!
//! Receives a stream of binary samples taken at 8× the bit rate from a
//! LocalTalk wire and yields one [`Fm0Event`] per decoded byte / SDLC
//! marker (`Flag`, `Abort`).
//!
//! ## Why interval timing, not a free-running counter
//!
//! FM-0 guarantees a line transition at **every** bit-cell boundary (the
//! "clock edge"), plus an **extra** transition at mid-cell for a `0`:
//!
//! - **Bit `1`**: one transition per cell → successive edges are one full
//!   cell apart (~8 samples).
//! - **Bit `0`**: two transitions per cell → a mid-cell edge then a
//!   boundary edge, each ~half a cell apart (~4 samples).
//!
//! So the bit stream can be recovered purely from the *time between
//! transitions*: a long gap is a `1`; a pair of short gaps is a `0`. The
//! decoder re-anchors on every edge, which is essential when the source
//! clock is **independent of our sample clock**, as it is for a real Mac.
//! A decoder that assumes exactly 8 samples per cell drifts off phase
//! within a byte or two. A self-loopback won't show it, since there TX and
//! RX share the RP2040's crystal.
//!
//! ## Sample-interval thresholds (8× oversampling)
//!
//! `interval` is the number of non-transition samples observed between
//! two transitions. At nominal timing a half cell is 4 samples (interval
//! 3) and a full cell is 8 samples (interval 7). We classify with wide
//! margins so a few percent of clock offset or sampling jitter is
//! harmless:
//!
//! | interval        | meaning                              |
//! | --------------- | ------------------------------------ |
//! | `< MIN`         | glitch / double edge → resync        |
//! | `MIN..=SHORT`   | half cell (part of a `0`)            |
//! | `SHORT+1..=LONG`| full cell (`1`, or boundary of a `0`)|
//! | `> LONG`        | line went idle → resync              |

use crate::bitstuff::{BitUnstuffer, UnstuffEvent};

/// One output event from the stateful decoder, after FM-0 → bit →
/// SDLC bit-unstuff has been applied. Mirrors [`UnstuffEvent`] but
/// drops the `None` variant since callers don't see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fm0Event {
    Byte(u8),
    Flag,
    Abort,
}

/// Shortest interval we accept as a real half-cell. Anything below this
/// is two transitions too close together - line noise or a glitch.
const MIN_INTERVAL: u16 = 2;
/// Largest interval still counted as a half cell. Nominal half = 3.
const SHORT_MAX: u16 = 4;
/// Largest interval still counted as a full cell. Nominal full = 7.
/// Beyond this the line has gone quiet and we resync.
const LONG_MAX: u16 = 11;

/// Interval-timed FM-0 decoder feeding through SDLC bit-unstuffing.
#[derive(Debug, Clone)]
pub struct Fm0Decoder {
    /// Last raw sample, or `None` before the very first sample.
    prev_sample: Option<u8>,
    /// `true` once we've seen a transition to time intervals against.
    seen_first_edge: bool,
    /// Non-transition samples observed since the last transition.
    since_edge: u16,
    /// We saw the first half of a `0` (one short interval) and are
    /// waiting for the second short interval that completes it.
    half_pending: bool,
    /// SDLC bit-unstuffer / flag detector / abort detector.
    unstuffer: BitUnstuffer,
}

impl Fm0Decoder {
    pub const fn new() -> Self {
        Self {
            prev_sample: None,
            seen_first_edge: false,
            since_edge: 0,
            half_pending: false,
            unstuffer: BitUnstuffer::new(),
        }
    }

    /// Reset the decoder to its initial unsynced state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// `true` once the decoder has locked onto a transition and is
    /// timing bit cells.
    pub fn is_synced(&self) -> bool {
        self.seen_first_edge
    }

    /// Feed one binary sample. Returns an event when a complete bit has
    /// been decoded AND the bit-unstuffer produced something non-trivial
    /// (a byte, a flag, or an abort).
    pub fn feed_sample(&mut self, sample: u8) -> Option<Fm0Event> {
        debug_assert!(sample <= 1);

        let prev = match self.prev_sample {
            None => {
                self.prev_sample = Some(sample);
                return None;
            }
            Some(p) => p,
        };
        self.prev_sample = Some(sample);

        if sample == prev {
            // No transition this sample. Grow the interval; if it grows
            // far past a full cell the line has gone idle (or this is a
            // real abort) - drop sync so the next frame re-locks cleanly.
            self.since_edge = self.since_edge.saturating_add(1);
            if self.seen_first_edge && self.since_edge > LONG_MAX {
                return self.resync();
            }
            return None;
        }

        // A transition. Measure and reset the inter-edge interval.
        let interval = self.since_edge;
        self.since_edge = 0;

        if !self.seen_first_edge {
            // First edge: nothing to time against yet.
            self.seen_first_edge = true;
            self.half_pending = false;
            return None;
        }

        if interval < MIN_INTERVAL {
            // Two transitions implausibly close - glitch.
            self.resync()
        } else if interval <= SHORT_MAX {
            // Half cell: half of a `0`.
            if self.half_pending {
                self.half_pending = false;
                self.emit_bit(0)
            } else {
                self.half_pending = true;
                None
            }
        } else if interval <= LONG_MAX {
            // Full cell: a `1` (or, if we were mid-`0`, the phase has
            // slipped - resync rather than emit a corrupt bit).
            if self.half_pending {
                self.resync()
            } else {
                self.emit_bit(1)
            }
        } else {
            // Interval longer than a full cell: idle gap.
            self.resync()
        }
    }

    /// Push one recovered bit through the unstuffer and map its result.
    fn emit_bit(&mut self, bit: u8) -> Option<Fm0Event> {
        match self.unstuffer.feed_bit(bit) {
            UnstuffEvent::Byte(b) => Some(Fm0Event::Byte(b)),
            UnstuffEvent::Flag => Some(Fm0Event::Flag),
            UnstuffEvent::Abort => {
                self.drop_sync();
                Some(Fm0Event::Abort)
            }
            UnstuffEvent::None => None,
        }
    }

    /// Drop bit-cell sync and clear the unstuffer, then report an Abort so
    /// the frame assembler discards any partial frame. The next
    /// transition is treated as a fresh first edge.
    fn resync(&mut self) -> Option<Fm0Event> {
        self.drop_sync();
        Some(Fm0Event::Abort)
    }

    fn drop_sync(&mut self) {
        self.seen_first_edge = false;
        self.half_pending = false;
        self.since_edge = 0;
        self.unstuffer.reset();
    }
}

impl Default for Fm0Decoder {
    fn default() -> Self {
        Self::new()
    }
}

// ── FM-0 Encoder (TX path) ────────────────────────────────────────────
//
// Converts a stream of HDLC bits into FM-0 half-cell symbols suitable
// for direct shift-out by the PIO TX state machine at 2× the bit rate
// (460.8 kHz for LocalTalk's 230.4 kbps).
//
// FM-0 encoding rules:
//   - At every bit-cell boundary: toggle the output level.
//   - For a `0` bit: also toggle at mid-cell.
//   - For a `1` bit: hold through mid-cell (no toggle).
//
// Each data bit produces exactly 2 half-cell symbols.

/// Stateful FM-0 encoder.
///
/// Tracks the current output level across successive calls to
/// [`encode_bit`](Self::encode_bit) so that the mandatory boundary
/// toggle is correct even when bits are fed one at a time.
#[derive(Debug, Clone, Copy)]
pub struct Fm0Encoder {
    /// Current output level (`false` = LOW, `true` = HIGH).
    level: bool,
}

impl Fm0Encoder {
    /// Create a new encoder starting with output LOW.
    pub const fn new() -> Self {
        Self { level: false }
    }

    /// Encode one data bit, returning the two half-cell symbols
    /// `(boundary, mid)` as `u8` values (0 or 1).
    #[inline]
    pub fn encode_bit(&mut self, bit: u8) -> (u8, u8) {
        // Boundary: always toggle.
        self.level = !self.level;
        let boundary = self.level as u8;

        if bit == 0 {
            // Mid-cell: toggle again for '0'.
            self.level = !self.level;
        }
        // For '1': hold (no toggle).
        let mid = self.level as u8;

        (boundary, mid)
    }

    /// Encode a slice of bits, appending half-cell symbols to `out`.
    /// Each bit produces 2 symbols.
    pub fn encode_bits(&mut self, bits: &[u8], out: &mut heapless::Vec<u8, MAX_FM0_SYMBOLS>) {
        for &b in bits {
            let (a, b) = self.encode_bit(b);
            let _ = out.push(a);
            let _ = out.push(b);
        }
    }

    /// Current output level.
    pub fn level(&self) -> bool {
        self.level
    }
}

impl Default for Fm0Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum FM-0 symbol buffer size.
///
/// Worst case: a max-length LLAP frame (605 bytes) bit-stuffed (≤~726
/// bytes) + 2 flags (16 bits) + 1 closing flag (8 bits) + 16 abort bits
/// ≈ 6000 bits → 12000 half-cell symbols. We round up generously.
pub const MAX_FM0_SYMBOLS: usize = 16384;

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;

    /// Encode one bit as FM-0 samples at `half` samples per half-cell
    /// (so a full cell is `2 * half` samples), given the line level
    /// before the leading clock edge. Returns the samples and the level
    /// the line ends at.
    fn encode_bit(prev_level: u8, bit: u8, half: usize) -> (alloc::vec::Vec<u8>, u8) {
        // Mandatory clock edge at the start of the cell.
        let post_edge = prev_level ^ 1;
        let mut s = alloc::vec::Vec::with_capacity(2 * half);
        if bit == 1 {
            // No mid-cell transition: hold post_edge for the whole cell.
            s.extend(core::iter::repeat(post_edge).take(2 * half));
            (s, post_edge)
        } else {
            // Mid-cell transition back toward prev_level.
            s.extend(core::iter::repeat(post_edge).take(half));
            s.extend(core::iter::repeat(prev_level).take(half));
            (s, prev_level)
        }
    }

    /// Encode a bit sequence at `half` samples per half-cell.
    fn encode_bits(prev_level: u8, bits: &[u8], half: usize) -> (u8, alloc::vec::Vec<u8>) {
        let mut samples = alloc::vec::Vec::new();
        let mut level = prev_level;
        for &b in bits {
            let (cell, end) = encode_bit(level, b, half);
            samples.extend_from_slice(&cell);
            level = end;
        }
        (level, samples)
    }

    /// Feed idle padding then `samples`, returning all decoder events.
    /// A trailing transition is appended so the final bit's closing clock
    /// edge exists - real LocalTalk frames always have one (the postamble
    /// / following idle), only hand-built sample vectors don't.
    fn decode(mut samples: alloc::vec::Vec<u8>, half: usize) -> alloc::vec::Vec<Fm0Event> {
        let mut d = Fm0Decoder::new();
        // Idle-low padding so the first encoded edge is the first edge.
        let mut stream = alloc::vec::Vec::new();
        stream.extend(core::iter::repeat(0u8).take(2 * half));
        let last = samples.last().copied().unwrap_or(0);
        // Trailing closing edge + a little settle.
        samples.extend(core::iter::repeat(last ^ 1).take(2 * half));
        stream.extend(samples);

        let mut events = alloc::vec::Vec::new();
        for s in stream {
            if let Some(e) = d.feed_sample(s) {
                events.push(e);
            }
        }
        events
    }

    #[test]
    fn syncs_on_first_edge() {
        let mut d = Fm0Decoder::new();
        for _ in 0..32 {
            assert_eq!(d.feed_sample(0), None);
            assert!(!d.is_synced());
        }
        assert_eq!(d.feed_sample(1), None);
        assert!(d.is_synced());
    }

    #[test]
    fn round_trip_byte_nominal() {
        // 0x55 has no run of 5+ ones, so it can't be confused with a flag.
        let bits: alloc::vec::Vec<u8> = (0..8).map(|i| (0x55 >> i) & 1).collect();
        let (_, samples) = encode_bits(0, &bits, 4);
        let events = decode(samples, 4);
        assert!(
            events.contains(&Fm0Event::Byte(0x55)),
            "events: {:?}",
            events
        );
    }

    #[test]
    fn round_trip_byte_slow_clock() {
        // Source clock slower than ours: 5 samples per half-cell (cell 10
        // vs our nominal 8). A decoder that assumed a fixed cell length
        // would lose this one.
        let bits: alloc::vec::Vec<u8> = (0..8).map(|i| (0x55 >> i) & 1).collect();
        let (_, samples) = encode_bits(0, &bits, 5);
        let events = decode(samples, 5);
        assert!(
            events.contains(&Fm0Event::Byte(0x55)),
            "events: {:?}",
            events
        );
    }

    #[test]
    fn round_trip_byte_fast_clock() {
        // Source clock faster than ours: 3 samples per half-cell (cell 6).
        let bits: alloc::vec::Vec<u8> = (0..8).map(|i| (0x55 >> i) & 1).collect();
        let (_, samples) = encode_bits(0, &bits, 3);
        let events = decode(samples, 3);
        assert!(
            events.contains(&Fm0Event::Byte(0x55)),
            "events: {:?}",
            events
        );
    }

    #[test]
    fn round_trip_byte_with_zeros() {
        // A byte containing 0 bits exercises the mid-cell-transition path.
        let val = 0x24u8; // 0b00100100
        let bits: alloc::vec::Vec<u8> = (0..8).map(|i| (val >> i) & 1).collect();
        let (_, samples) = encode_bits(0, &bits, 4);
        let events = decode(samples, 4);
        assert!(
            events.contains(&Fm0Event::Byte(val)),
            "events: {:?}",
            events
        );
    }

    #[test]
    fn detects_flag() {
        // SDLC flag: 0 1 1 1 1 1 1 0.
        let bits = [0u8, 1, 1, 1, 1, 1, 1, 0];
        let (_, samples) = encode_bits(0, &bits, 4);
        let events = decode(samples, 4);
        assert!(events.contains(&Fm0Event::Flag), "events: {:?}", events);
    }

    // ── Encoder tests ─────────────────────────────────────────────────

    #[test]
    fn encoder_zero_bit_toggles_twice() {
        let mut enc = Fm0Encoder::new();
        // Starting LOW. Bit 0: boundary→HIGH, mid→LOW.
        let (a, b) = enc.encode_bit(0);
        assert_eq!((a, b), (1, 0));
        assert!(!enc.level());
    }

    #[test]
    fn encoder_one_bit_toggles_once() {
        let mut enc = Fm0Encoder::new();
        // Starting LOW. Bit 1: boundary→HIGH, hold→HIGH.
        let (a, b) = enc.encode_bit(1);
        assert_eq!((a, b), (1, 1));
        assert!(enc.level());
    }

    #[test]
    fn encoder_level_continuity() {
        let mut enc = Fm0Encoder::new();
        // Bit 1 from LOW: → HIGH (boundary), HIGH (hold). Level=HIGH.
        assert_eq!(enc.encode_bit(1), (1, 1));
        // Bit 1 from HIGH: → LOW (boundary), LOW (hold). Level=LOW.
        assert_eq!(enc.encode_bit(1), (0, 0));
        // Bit 0 from LOW: → HIGH (boundary), LOW (mid-toggle). Level=LOW.
        assert_eq!(enc.encode_bit(0), (1, 0));
        // Bit 0 from LOW again: → HIGH, LOW. Level=LOW.
        assert_eq!(enc.encode_bit(0), (1, 0));
    }

    #[test]
    fn encoder_always_transitions_at_boundary() {
        // The defining rule of FM-0: every bit cell starts with a transition.
        let mut enc = Fm0Encoder::new();
        let test_bits = [0u8, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0];
        let mut prev_mid = 0u8; // encoder starts LOW, first boundary must differ
        for (i, &bit) in test_bits.iter().enumerate() {
            let (boundary, mid) = enc.encode_bit(bit);
            if i == 0 {
                // First bit: boundary must differ from initial level (0).
                assert_ne!(boundary, 0, "bit {i}: boundary must toggle from initial");
            } else {
                // Boundary must differ from the previous mid (= end of prev cell).
                assert_ne!(
                    boundary, prev_mid,
                    "bit {i}: boundary must toggle from prev mid"
                );
            }
            prev_mid = mid;
        }
    }

    /// Feed FM-0 encoder output (1 sample per half-cell) through the
    /// decoder (which expects N samples per half-cell) by stretching.
    fn decode_from_encoder(symbols: &[u8], half: usize) -> alloc::vec::Vec<Fm0Event> {
        // Stretch each symbol to `half` samples.
        let mut samples: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for &s in symbols {
            for _ in 0..half {
                samples.push(s);
            }
        }
        decode(samples, half)
    }

    #[test]
    fn encoder_decoder_round_trip_byte() {
        // Encode a flag + byte + flag, decode, verify byte comes back.
        let flag_bits = [0u8, 1, 1, 1, 1, 1, 1, 0];
        let val = 0xA5u8;
        let data_bits: alloc::vec::Vec<u8> = (0..8).map(|i| (val >> i) & 1).collect();

        let mut enc = Fm0Encoder::new();
        let mut symbols = alloc::vec::Vec::new();
        for &b in &flag_bits {
            let (a, c) = enc.encode_bit(b);
            symbols.push(a);
            symbols.push(c);
        }
        for &b in &data_bits {
            let (a, c) = enc.encode_bit(b);
            symbols.push(a);
            symbols.push(c);
        }
        for &b in &flag_bits {
            let (a, c) = enc.encode_bit(b);
            symbols.push(a);
            symbols.push(c);
        }

        let events = decode_from_encoder(&symbols, 4);
        assert!(
            events.contains(&Fm0Event::Byte(val)),
            "expected Byte(0x{val:02X}), got: {:?}",
            events
        );
    }

    #[test]
    fn encoder_decoder_round_trip_flag() {
        let flag_bits = [0u8, 1, 1, 1, 1, 1, 1, 0];
        let mut enc = Fm0Encoder::new();
        let mut symbols = alloc::vec::Vec::new();
        for &b in &flag_bits {
            let (a, c) = enc.encode_bit(b);
            symbols.push(a);
            symbols.push(c);
        }

        let events = decode_from_encoder(&symbols, 4);
        assert!(
            events.contains(&Fm0Event::Flag),
            "expected Flag, got: {:?}",
            events
        );
    }
}
