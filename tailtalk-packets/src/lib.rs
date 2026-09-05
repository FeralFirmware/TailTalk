#![cfg_attr(not(feature = "std"), no_std)]

/// Re-exported so consumers can name the fixed-capacity types in this crate's
/// public API without depending on a matching `heapless` version themselves.
pub use heapless;

pub mod aarp;
pub mod adsp;
#[cfg(feature = "afp")]
pub mod afp;
pub mod asp;

pub mod aep;
pub mod atp;
pub mod ddp;
pub mod ethertalk;
pub mod headers;
pub mod limits;
pub mod llap;
pub mod nbp;
pub mod pap;
pub mod rtmp;
pub mod zip;
