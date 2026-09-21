//! LocalTalk node address acquisition.
//!
//! The LLAP ENQ probe loop: pick a random candidate, send ENQ frames
//! addressed to it (with the candidate as the source too), and claim it if
//! no ACK comes back. Any ACK whose source is the candidate means the
//! address is defended; pick another and retry.
//!
//! Inside AppleTalk has nodes transmit a burst of ENQs rather than one, so
//! that a lost frame does not read as a free address. This sends
//! [`Acquisition::DEFAULT_PROBES`] of them, spaced by
//! [`Acquisition::DEFAULT_INTERVAL_US`], before claiming.
//!
//! The claimed node must be programmed into the wire engine's auto-reply
//! node bitmap only after [`AcquireEvent::Claimed`], never before: with the
//! candidate in the bitmap the engine would ACK our own probes (they carry
//! dst == src == candidate) and every candidate would look taken.

use crate::{Micros, Rand};

/// Server nodes (printers, file servers) allocate from 128..=254 per Inside
/// AppleTalk; user nodes from 1..=127.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    User,
    Server,
}

impl NodeClass {
    fn range(self) -> (u8, u8) {
        match self {
            NodeClass::User => (1, 127),
            NodeClass::Server => (128, 254),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireEvent {
    /// Transmit an ENQ with dst = src = the given candidate node.
    SendEnq(u8),
    /// The candidate went unanswered; it is now our node address.
    Claimed(u8),
}

#[derive(Debug)]
pub struct Acquisition {
    rng: Rand,
    class: NodeClass,
    probes_per_candidate: u8,
    probe_interval: Micros,
    candidate: u8,
    probes_sent: u8,
    /// When the next ENQ (or, after the last ENQ, the claim) is due.
    next_action_at: Micros,
    done: bool,
}

impl Acquisition {
    /// Default probes per candidate. Inside AppleTalk retransmits the ENQ
    /// many times; 8 at 200 us spacing keeps acquisition under 2 ms per
    /// candidate while still riding out a few lost frames.
    pub const DEFAULT_PROBES: u8 = 8;
    pub const DEFAULT_INTERVAL_US: Micros = 200;

    pub fn new(class: NodeClass, seed: u32, now: Micros) -> Self {
        let mut rng = Rand::new(seed);
        let (lo, hi) = class.range();
        let candidate = rng.in_range(lo, hi);
        Self {
            rng,
            class,
            probes_per_candidate: Self::DEFAULT_PROBES,
            probe_interval: Self::DEFAULT_INTERVAL_US,
            candidate,
            probes_sent: 0,
            next_action_at: now,
            done: false,
        }
    }

    pub fn candidate(&self) -> u8 {
        self.candidate
    }

    /// An ACK arrived from the wire. If its source is our candidate, some
    /// node is defending that address: restart with a fresh candidate.
    pub fn on_ack(&mut self, src_node: u8, now: Micros) {
        if self.done || src_node != self.candidate {
            return;
        }
        let (lo, hi) = self.class.range();
        // Avoid immediately re-picking the same taken node.
        let mut next = self.rng.in_range(lo, hi);
        if next == self.candidate {
            next = if next == hi { lo } else { next + 1 };
        }
        self.candidate = next;
        self.probes_sent = 0;
        self.next_action_at = now;
    }

    /// Deadline of the next timed action, for schedulers that sleep.
    pub fn next_deadline(&self) -> Option<Micros> {
        (!self.done).then_some(self.next_action_at)
    }

    /// Advance the probe schedule. Returns at most one event per call; call
    /// until `None` to drain.
    pub fn poll(&mut self, now: Micros) -> Option<AcquireEvent> {
        if self.done || now < self.next_action_at {
            return None;
        }
        if self.probes_sent < self.probes_per_candidate {
            self.probes_sent += 1;
            self.next_action_at = now + self.probe_interval;
            Some(AcquireEvent::SendEnq(self.candidate))
        } else {
            // The full burst went unanswered for a probe interval: claim it.
            self.done = true;
            Some(AcquireEvent::Claimed(self.candidate))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(acq: &mut Acquisition, now: &mut Micros) -> AcquireEvent {
        loop {
            if let Some(ev) = acq.poll(*now) {
                return ev;
            }
            *now = acq.next_deadline().unwrap();
        }
    }

    #[test]
    fn claims_after_unanswered_probes() {
        let mut now = 0;
        let mut acq = Acquisition::new(NodeClass::Server, 42, now);
        let candidate = acq.candidate();
        assert!((128..=254).contains(&candidate));

        let mut enqs = 0;
        loop {
            match drive(&mut acq, &mut now) {
                AcquireEvent::SendEnq(n) => {
                    assert_eq!(n, candidate);
                    enqs += 1;
                }
                AcquireEvent::Claimed(n) => {
                    assert_eq!(n, candidate);
                    break;
                }
            }
        }
        assert_eq!(enqs, Acquisition::DEFAULT_PROBES);
        assert!(acq.poll(now + 1_000_000).is_none());
    }

    #[test]
    fn ack_forces_a_new_candidate() {
        let mut now = 0;
        let mut acq = Acquisition::new(NodeClass::Server, 7, now);
        let first = acq.candidate();

        // First probe goes out, then the address's owner answers.
        assert_eq!(drive(&mut acq, &mut now), AcquireEvent::SendEnq(first));
        acq.on_ack(first, now);
        let second = acq.candidate();
        assert_ne!(first, second);

        // An ACK from an unrelated node must not restart the probe.
        acq.on_ack(second.wrapping_add(1), now);
        assert_eq!(acq.candidate(), second);

        loop {
            match drive(&mut acq, &mut now) {
                AcquireEvent::SendEnq(n) => assert_eq!(n, second),
                AcquireEvent::Claimed(n) => {
                    assert_eq!(n, second);
                    break;
                }
            }
        }
    }

    #[test]
    fn user_class_picks_low_range() {
        let acq = Acquisition::new(NodeClass::User, 99, 0);
        assert!((1..=127).contains(&acq.candidate()));
    }
}
