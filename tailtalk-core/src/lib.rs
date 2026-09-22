//! Sans-io AppleTalk transport state machines, shared by the desktop
//! `tailtalk` crate and embedded firmware.
//!
//! Every layer here is a plain state machine with no I/O, no async runtime
//! and no clock of its own. Each is driven by three inputs:
//!
//! 1. received datagrams (`handle_datagram`),
//! 2. the passage of time (`poll`, with a caller-supplied monotonic
//!    microsecond timestamp),
//! 3. application requests (open a connection, send data, respond to a
//!    transaction).
//!
//! Outputs are drained with `poll_transmit` (datagrams to put on the wire)
//! and `poll_event` (things the caller must react to), and `next_deadline`
//! says when `poll` next needs calling.
//!
//! The caller supplies the I/O and the clock, so the same state machines run
//! under tokio on the desktop and Embassy on the firmware.
//!
//! Layering: [`atp`] and [`adsp`] are the transports, each standalone. The
//! protocols built on them - PAP, and the printer roles - belong here too,
//! so that no protocol is implemented twice in this workspace.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod addressing;
pub mod adsp;
pub mod aep;
pub mod atp;
pub mod ddp;
pub mod link;
pub mod nbp;
pub mod rtmp;
pub mod stack;
pub mod stylewriter;

/// Monotonic time in microseconds, supplied by the caller on every input.
/// The zero point is arbitrary; only differences are used.
pub type Micros = u64;

/// A tiny xorshift PRNG for protocol-level randomness (connection IDs,
/// transaction IDs). Not cryptographic; seed it from any convenient source -
/// `rand::random()` on a host, ROSC entropy on an RP2040.
#[derive(Debug, Clone)]
pub struct Rand(u32);

impl Rand {
    pub fn new(seed: u32) -> Self {
        // A zero state would stay zero forever.
        Self(if seed == 0 { 0x1234_5678 } else { seed })
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    /// Uniform-ish value in `lo..=hi`. The modulo bias is irrelevant at the
    /// ranges used here (node and socket numbers).
    pub fn in_range(&mut self, lo: u8, hi: u8) -> u8 {
        let span = (hi - lo) as u32 + 1;
        lo + (self.next_u32() % span) as u8
    }
}
