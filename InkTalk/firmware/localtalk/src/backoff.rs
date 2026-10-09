//! CSMA/CA backoff state, ported from the PIC reference firmware.
//!
//! LocalTalk uses CSMA/CA (Carrier Sense, Multiple Access with
//! Collision Avoidance - *not* detection). Before transmitting, a node
//! must:
//!
//! 1. **Defer**: wait until the bus has been idle for ≥ IDG (inter-dialog
//!    gap, 200 µs) for broadcast data frames, or ≥ IFG (inter-frame
//!    gap, 200 µs) for control frames following a dialog partner.
//! 2. **Random backoff**: wait an additional pseudorandom interval to
//!    reduce simultaneous collisions when multiple nodes have been
//!    waiting for the bus. The backoff window expands on collisions
//!    and shrinks under low-load conditions.
//!
//! The PIC firmware encodes this in two history shift registers
//! (collision + deferral) tracked over the last 8 transmissions, plus
//! a 4-bit `GBACKOFF` "global" mask and per-frame `LBACKOFF` "local"
//! mask. This module ports that logic verbatim - see
//! `one-chip.asm:439` (`PrepForNextFrame`),
//! `:570` (`TryAgain`), `:635` (`Deferred`), `:641` (`Collided`).
//!
//! The actual unit of backoff is "100 µs steps", same as the asm.

/// The minimum interdialog gap, in 100 µs units (= 400 µs).
///
/// Even with backoff mask = 0, the wait is at least IDG_UNITS × 100 µs.
pub const IDG_UNITS: u8 = 4;

/// Cap on the 4-bit backoff masks (`0b1111` = 15 → up to 1.5 ms of
/// pseudorandom delay above the IDG).
pub const MAX_BACKOFF_MASK: u8 = 0x0F;

/// Maximum retransmission attempts per frame, matching the PIC's
/// `ATTEMPTS = 32` initialiser at `one-chip.asm:491`.
pub const MAX_ATTEMPTS: u8 = 32;

/// CSMA/CA backoff state machine.
///
/// Methods correspond 1:1 with the PIC firmware:
/// - [`Self::prep_for_next_frame`] mirrors `PrepForNextFrame`
/// - [`Self::record_collision`] mirrors `Collided`
/// - [`Self::record_deferral`] mirrors `Deferred`
/// - [`Self::next_backoff_units`] mirrors `SetTimer2`
///
/// The caller is responsible for supplying entropy (typically the
/// low bits of a free-running timer XORed together, like the PIC
/// firmware does with `TMR1H ^ TMR1L`).
#[derive(Debug, Clone, Copy)]
pub struct BackoffState {
    /// `GBACKOFF` - global backoff mask, grows on bursts of
    /// collisions, shrinks under low-load.
    global_mask: u8,
    /// `LBACKOFF` - per-frame local mask, starts at `global_mask`
    /// and grows further on each per-frame collision.
    local_mask: u8,
    /// `COL_HIST` - 8-bit history of collisions over the last 8
    /// frames. Bit 0 = most recent.
    col_history: u8,
    /// `DEF_HIST` - 8-bit history of deferrals over the last 8
    /// frames. Bit 0 = most recent.
    def_history: u8,
    /// `ATTEMPTS` - remaining attempts for the current frame.
    attempts: u8,
}

impl BackoffState {
    pub const fn new() -> Self {
        Self {
            global_mask: 0,
            local_mask: 0,
            col_history: 0,
            def_history: 0,
            attempts: MAX_ATTEMPTS,
        }
    }

    /// Called before each new frame.
    ///
    /// Updates `global_mask` based on the last 8 frames' history:
    /// - If more than 2 collisions in the last 8 frames, grow the
    ///   global mask by left-shifting in a 1 (up to MAX_BACKOFF_MASK).
    ///   Clears the collision history if the mask was extended.
    /// - If fewer than 2 deferrals in the last 8 frames, shrink the
    ///   global mask by right-shift. Re-fills the deferral history.
    ///
    /// Mirrors `PrepForNextFrame` at `one-chip.asm:439`.
    pub fn prep_for_next_frame(&mut self) {
        let col_count = self.col_history.count_ones() as u8;
        let def_count = self.def_history.count_ones() as u8;

        if col_count > 2 {
            // Grow global mask. The asm does this by left-shifting a 1
            // into GBACKOFF, masked to 4 bits (so growth caps at 0xF).
            self.global_mask = ((self.global_mask << 1) | 1) & MAX_BACKOFF_MASK;
            self.col_history = 0;
        }
        if def_count < 2 {
            // Shrink global mask and fill deferral history (the asm
            // sets DEF_HIST = 0xFF to suppress further shrinks until
            // we accumulate real new deferral data).
            self.global_mask >>= 1;
            self.def_history = 0xFF;
        }

        // Shift in a zero at bit 0 of both history registers: the
        // collision / deferral that may occur on this NEW frame will
        // be recorded by record_collision / record_deferral.
        self.col_history <<= 1;
        self.def_history <<= 1;

        // Ensure at least 2 bits of randomness (0–300 µs jitter above
        // IDG) even when the global mask is 0. Without this, all nodes
        // on a quiet bus use the same fixed IDG delay and collide every
        // time they transmit simultaneously.
        self.local_mask = self.global_mask | 0x03;
        self.attempts = MAX_ATTEMPTS;
    }

    /// Compute the per-attempt backoff, in 100 µs units.
    ///
    /// `entropy` should be a free-running, fast-changing byte (e.g.
    /// XOR of timer halves, ROSC random output, etc.). The PIC uses
    /// `TMR1H ^ TMR1L`.
    ///
    /// Returns `entropy & local_mask + IDG_UNITS` per `SetTimer2`.
    pub fn next_backoff_units(&self, entropy: u8) -> u8 {
        (entropy & self.local_mask).saturating_add(IDG_UNITS)
    }

    /// Record that the current frame collided (we sent an RTS but
    /// never received a CTS, or our broadcast got interrupted by
    /// another node's traffic). Grows local mask, sets collision bit.
    ///
    /// Mirrors `Collided` at `one-chip.asm:641`.
    pub fn record_collision(&mut self) {
        self.col_history |= 1;
        // Left-shift, fill with 1, cap at MAX_BACKOFF_MASK.
        self.local_mask = ((self.local_mask << 1) | 1) & MAX_BACKOFF_MASK;
    }

    /// Record that the current frame had to defer (we wanted the bus
    /// but it was busy when we tried).
    ///
    /// Mirrors `Deferred` at `one-chip.asm:635`.
    pub fn record_deferral(&mut self) {
        self.def_history |= 1;
        // The asm uses `bsf LBACKOFF,0` - guarantees the mask is at
        // least 1, so the next backoff has SOME randomness.
        self.local_mask |= 1;
    }

    /// Decrement attempts. Returns the previous value (before
    /// decrement), so a caller can check `if state.consume_attempt()
    /// == 0 { give_up() }`.
    pub fn consume_attempt(&mut self) -> u8 {
        let prev = self.attempts;
        if self.attempts > 0 {
            self.attempts -= 1;
        }
        prev
    }

    /// `true` if we've used up our 32 attempts and should give up
    /// transmitting the current frame.
    pub fn exhausted(&self) -> bool {
        self.attempts == 0
    }

    // Test-only accessors.
    #[cfg(test)]
    pub fn global_mask(&self) -> u8 {
        self.global_mask
    }
    #[cfg(test)]
    pub fn local_mask(&self) -> u8 {
        self.local_mask
    }
    #[cfg(test)]
    pub fn col_history(&self) -> u8 {
        self.col_history
    }
    #[cfg(test)]
    pub fn def_history(&self) -> u8 {
        self.def_history
    }
    #[cfg(test)]
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}

impl Default for BackoffState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_has_min_backoff() {
        let s = BackoffState::new();
        // local_mask = 0 → only the IDG floor applies.
        for entropy in [0, 0x55, 0xFF] {
            assert_eq!(s.next_backoff_units(entropy), IDG_UNITS);
        }
    }

    #[test]
    fn collision_grows_local_mask() {
        let mut s = BackoffState::new();
        s.record_collision();
        assert_eq!(s.local_mask(), 0b0001);
        s.record_collision();
        assert_eq!(s.local_mask(), 0b0011);
        s.record_collision();
        assert_eq!(s.local_mask(), 0b0111);
        s.record_collision();
        assert_eq!(s.local_mask(), 0b1111);
        // Saturates.
        s.record_collision();
        assert_eq!(s.local_mask(), 0b1111);
    }

    #[test]
    fn backoff_is_idg_plus_masked_entropy() {
        let mut s = BackoffState::new();
        s.record_collision();
        s.record_collision();
        // local_mask = 0b11; entropy & 0b11 yields 0..=3.
        assert_eq!(s.next_backoff_units(0b00), IDG_UNITS);
        assert_eq!(s.next_backoff_units(0b11), IDG_UNITS + 3);
        assert_eq!(s.next_backoff_units(0xFF), IDG_UNITS + 3);
    }

    #[test]
    fn many_collisions_grow_global_mask() {
        let mut s = BackoffState::new();
        // Simulate 8 frames with many collisions.
        for _ in 0..8 {
            s.prep_for_next_frame();
            s.record_collision();
        }
        // After 8 collisions in a row, the global mask should have
        // grown several times. Exact value depends on the col_count>2
        // threshold; the property we want is "grew above 0".
        assert!(s.global_mask() > 0, "got {}", s.global_mask());
    }

    #[test]
    fn deferral_keeps_local_mask_nonzero() {
        let mut s = BackoffState::new();
        s.record_deferral();
        assert_eq!(s.local_mask(), 0b0001);
        // Repeated deferrals don't grow it further (just keep it ≥1).
        s.record_deferral();
        assert_eq!(s.local_mask(), 0b0001);
    }

    #[test]
    fn exhaustion_after_32_attempts() {
        let mut s = BackoffState::new();
        for _ in 0..MAX_ATTEMPTS {
            s.consume_attempt();
        }
        assert!(s.exhausted());
    }

    #[test]
    fn prep_resets_attempts() {
        let mut s = BackoffState::new();
        for _ in 0..MAX_ATTEMPTS {
            s.consume_attempt();
        }
        assert!(s.exhausted());
        s.prep_for_next_frame();
        assert!(!s.exhausted());
        assert_eq!(s.attempts(), MAX_ATTEMPTS);
    }
}
