//! LocalTalk PHY setup. `phy.rs` configures the PIO state machines and
//! pins; everything after that (RX decode, TX, CSMA, auto-reply) runs on
//! core 1, in `core1.rs`.

pub mod phy;
