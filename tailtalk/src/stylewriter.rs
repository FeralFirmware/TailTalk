//! Printing to a StyleWriter behind an AppleTalk adapter. This covers the
//! client half of the adapter's two-connection ADSP handshake, the printer's
//! commands and status, and its raster format.
//!
//! StyleWriters fall into two series that print alike within themselves. One is
//! the Color StyleWriter 2200, 2400 and 2500, and the other is the 1200 series,
//! which is the original StyleWriter, the II, the 1200 and the Color
//! StyleWriter 1500. [`StyleWriterFamily`] says which a printer is, and what
//! follows from it.

pub mod encode;
mod family;
mod job;
pub mod raster;
mod session;
mod status;

pub use encode::{Band, BandKind, chunky_to_mono_plane, chunky_to_planes, encode_band};
pub use family::StyleWriterFamily;
pub use job::{Cartridge, Cleaning, JobOptions, PaperType, PrintQuality, Rendering};
pub use raster::{Halftone, Imager, Page, Pixels, RawBand};
pub use session::{PrinterBusy, QUEUE_POLL_INTERVAL, StyleWriterSession};
pub use status::{PrinterFault, StyleWriterInfo};
pub use tailtalk_core::stylewriter::ColorModel;
