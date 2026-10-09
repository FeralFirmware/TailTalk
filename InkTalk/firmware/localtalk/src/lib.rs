//! The LocalTalk wire codec: everything between a frame's bytes and the
//! half-cell symbols on the differential pair.
//!
//! Pure computation with no hardware in it, which is what lets the whole
//! layer be tested on a host rather than only on a board. The PIO programs
//! that clock these symbols in and out live in the firmware, next to the
//! peripheral they configure.
//!
//! Layering, bytes outward: [`crc`] appends the frame check sequence,
//! [`hdlc`] frames it, [`bitstuff`] inserts the zero bits that keep a flag
//! unambiguous, and [`fm0`] turns the bit stream into the self-clocking
//! symbols the wire carries. [`llap`] is the link layer above all of it -
//! frame assembly, the RTS/CTS dialog and the auto-replies that have to
//! happen faster than software can manage - and [`backoff`] is the CSMA
//! deference schedule.
//!
//! Much of this is ported from TashTalk's PIC firmware; references like
//! `one-chip.asm:704` point into that project's `firmware/one-chip.asm`.

#![cfg_attr(not(test), no_std)]

pub mod backoff;
pub mod bitstuff;
pub mod crc;
pub mod fm0;
pub mod hdlc;
pub mod llap;

/// Maximum LocalTalk frame payload, per LLAP. Buffers are sized from it.
pub const MAX_FRAME_LEN: usize = 605;
