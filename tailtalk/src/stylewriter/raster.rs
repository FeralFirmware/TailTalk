//! Turning a page into the bands a StyleWriter prints.
//!
//! A page prints in bands of up to the engine's band height. On a grayscale or
//! color page, rows with nothing on them are skipped wherever a band would
//! start. A band whose rows hold only black and white prints at 1 bit, and a
//! band with anything else in it prints at the page's own depth. A black and
//! white page prints every row, at 1 bit.
//!
//! Color is separated with full black generation and undercolor removal, after
//! a tone curve. K is `255 - max(R, G, B)`, and each color is what is left
//! over, `max - R` for cyan and so on, so gray and black print with black ink
//! alone. Gray and color are then halftoned, with a 16 by 16 threshold pattern
//! or by scattering dots at random, each through a tone curve of its own. The
//! Color StyleWriter 2200, 2400 and 2500 have one pair of curves, and the 1200
//! series another.

use super::encode::BandKind;
use super::{JobOptions, PaperType, PrintQuality, Rendering, StyleWriterFamily};

/// How a page's continuous tones become dots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Halftone {
    /// A random scattering of dots. Each dot's error goes partly to the next
    /// dot along and partly to the dot below, in a random share and against
    /// a random threshold, with rows run in alternate directions. The
    /// smoothest gradients, for photographs.
    #[default]
    Diffusion,
    /// A pattern of dots from a fixed 16 by 16 threshold pattern, for flat
    /// color and text, where the scattering's grain would show.
    Pattern,
}

/// The tone curve for [`Halftone::Pattern`] on a Color StyleWriter 2200,
/// 2400 or 2500. Copied from the Color SW 2200 driver's `GAMA` 1 resource.
pub const TONE_PATTERN_2200: [u8; 256] = [
    0x00, 0x03, 0x06, 0x09, 0x0C, 0x0F, 0x12, 0x15, 0x18, 0x1B, 0x1E, 0x21, 0x24, 0x27, 0x2A, 0x2D,
    0x30, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3A, 0x3B, 0x3C, 0x3D,
    0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
    0x4D, 0x4E, 0x4F, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5A,
    0x5B, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
    0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
    0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
    0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
    0xA0, 0xA0, 0xA1, 0xA2, 0xA3, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA7, 0xA8, 0xA9, 0xAA, 0xAA, 0xAB,
    0xAC, 0xAD, 0xAE, 0xAE, 0xAF, 0xB0, 0xB1, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB5, 0xB6, 0xB7, 0xB8,
    0xB9, 0xB9, 0xBA, 0xBB, 0xBC, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC0, 0xC1, 0xC2, 0xC3, 0xC3, 0xC4,
    0xC5, 0xC6, 0xC7, 0xC7, 0xC8, 0xC9, 0xCA, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCE, 0xCF, 0xD0, 0xD1,
    0xD2, 0xD2, 0xD3, 0xD4, 0xD4, 0xD5, 0xD6, 0xD7, 0xD7, 0xD8, 0xD9, 0xD9, 0xDA, 0xDB, 0xDC, 0xDC,
    0xDD, 0xDE, 0xDF, 0xDF, 0xE0, 0xE1, 0xE1, 0xE2, 0xE3, 0xE4, 0xE4, 0xE5, 0xE6, 0xE6, 0xE7, 0xE8,
    0xE9, 0xE9, 0xEA, 0xEB, 0xEC, 0xEC, 0xED, 0xEE, 0xEE, 0xEF, 0xF0, 0xF1, 0xF1, 0xF2, 0xF3, 0xF3,
    0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFB, 0xFC, 0xFD, 0xFD, 0xFE, 0xFF, 0xFF, 0xFF,
];

/// The tone curve for [`Halftone::Diffusion`] on a Color StyleWriter 2200,
/// 2400 or 2500. Copied from the Color SW 2200 driver's `GAMA` 2 resource.
pub const TONE_DIFFUSION_2200: [u8; 256] = [
    0x00, 0x03, 0x06, 0x09, 0x0C, 0x0F, 0x12, 0x15, 0x18, 0x1B, 0x1E, 0x21, 0x24, 0x27, 0x2A, 0x2D,
    0x30, 0x32, 0x35, 0x38, 0x3B, 0x3D, 0x40, 0x43, 0x46, 0x48, 0x4B, 0x4E, 0x51, 0x53, 0x56, 0x59,
    0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x63, 0x64, 0x65, 0x66, 0x67, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
    0x82, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
    0x91, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC0, 0xC1, 0xC1, 0xC2, 0xC2, 0xC3, 0xC4, 0xC4, 0xC5, 0xC5, 0xC6, 0xC7, 0xC7, 0xC8, 0xC8,
    0xC9, 0xCA, 0xCA, 0xCB, 0xCB, 0xCC, 0xCD, 0xCD, 0xCE, 0xCE, 0xCF, 0xD0, 0xD0, 0xD1, 0xD1, 0xD2,
    0xD3, 0xD3, 0xD4, 0xD4, 0xD5, 0xD5, 0xD6, 0xD7, 0xD7, 0xD8, 0xD8, 0xD9, 0xDA, 0xDA, 0xDB, 0xDB,
    0xDC, 0xDD, 0xDD, 0xDE, 0xDE, 0xDF, 0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5,
    0xE6, 0xE6, 0xE6, 0xE7, 0xE7, 0xE8, 0xE8, 0xE8, 0xE9, 0xE9, 0xEA, 0xEA, 0xEA, 0xEB, 0xEB, 0xEC,
    0xEC, 0xEC, 0xED, 0xED, 0xEE, 0xEE, 0xEE, 0xEF, 0xEF, 0xF0, 0xF0, 0xF0, 0xF1, 0xF1, 0xF2, 0xF2,
    0xF2, 0xF3, 0xF3, 0xF4, 0xF4, 0xF4, 0xF5, 0xF5, 0xF6, 0xF6, 0xF6, 0xF7, 0xF7, 0xF8, 0xF8, 0xF8,
    0xF9, 0xF9, 0xFA, 0xFA, 0xFA, 0xFB, 0xFB, 0xFC, 0xFC, 0xFC, 0xFD, 0xFD, 0xFD, 0xFF, 0xFF, 0xFF,
];

/// The tone curve for [`Halftone::Pattern`] on the original StyleWriter, the
/// II, the 1200 and the Color StyleWriter 1500. Copied from the Color SW 1500
/// driver's `GAMA` 1 resource.
pub const TONE_PATTERN_1500: [u8; 256] = [
    0x00, 0x04, 0x06, 0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1C, 0x1E, 0x20,
    0x22, 0x23, 0x25, 0x27, 0x28, 0x2A, 0x2C, 0x2D, 0x2F, 0x30, 0x32, 0x33, 0x35, 0x36, 0x38, 0x39,
    0x3B, 0x3C, 0x3E, 0x3F, 0x40, 0x42, 0x43, 0x44, 0x45, 0x47, 0x48, 0x49, 0x4A, 0x4C, 0x4D, 0x4E,
    0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x58, 0x5A, 0x5B, 0x5C, 0x5D, 0x5F, 0x60, 0x61, 0x62,
    0x63, 0x64, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
    0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
    0x96, 0x97, 0x98, 0x99, 0x9A, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
    0xA5, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
    0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC1, 0xC2, 0xC3, 0xC3, 0xC4, 0xC5, 0xC5, 0xC6, 0xC7, 0xC8, 0xC8, 0xC9, 0xCA, 0xCA,
    0xCB, 0xCC, 0xCD, 0xCD, 0xCE, 0xCF, 0xCF, 0xD0, 0xD1, 0xD1, 0xD2, 0xD3, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD6, 0xD7, 0xD8, 0xD8, 0xD9, 0xDA, 0xDA, 0xDB, 0xDC, 0xDC, 0xDD, 0xDE, 0xDE, 0xDF, 0xE0, 0xE1,
    0xE1, 0xE2, 0xE3, 0xE4, 0xE4, 0xE5, 0xE6, 0xE6, 0xE7, 0xE8, 0xE8, 0xE9, 0xEA, 0xEB, 0xEB, 0xEC,
    0xED, 0xED, 0xEE, 0xEE, 0xEF, 0xF0, 0xF0, 0xF1, 0xF2, 0xF2, 0xF3, 0xF3, 0xF4, 0xF5, 0xF5, 0xF6,
    0xF6, 0xF7, 0xF7, 0xF8, 0xF8, 0xF9, 0xF9, 0xFA, 0xFA, 0xFB, 0xFB, 0xFC, 0xFD, 0xFE, 0xFE, 0xFF,
];

/// The tone curve for [`Halftone::Diffusion`] on the original StyleWriter,
/// the II, the 1200 and the Color StyleWriter 1500. Copied from the Color SW
/// 1500 driver's `GAMA` 2 resource.
pub const TONE_DIFFUSION_1500: [u8; 256] = [
    0x00, 0x06, 0x0A, 0x0D, 0x10, 0x13, 0x16, 0x18, 0x1B, 0x1E, 0x20, 0x23, 0x25, 0x27, 0x2A, 0x2C,
    0x2E, 0x30, 0x33, 0x35, 0x37, 0x39, 0x3B, 0x3D, 0x3F, 0x41, 0x43, 0x45, 0x47, 0x48, 0x4A, 0x4C,
    0x4E, 0x50, 0x51, 0x53, 0x55, 0x57, 0x58, 0x5A, 0x5C, 0x5D, 0x5F, 0x60, 0x62, 0x64, 0x65, 0x67,
    0x68, 0x6A, 0x6C, 0x6D, 0x6F, 0x70, 0x72, 0x73, 0x75, 0x76, 0x77, 0x79, 0x7A, 0x7C, 0x7D, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8F, 0x90, 0x91, 0x92,
    0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xAF, 0xB0, 0xB1,
    0xB2, 0xB2, 0xB3, 0xB4, 0xB5, 0xB5, 0xB6, 0xB7, 0xB8, 0xB8, 0xB9, 0xBA, 0xBA, 0xBB, 0xBC, 0xBD,
    0xBD, 0xBE, 0xBF, 0xC0, 0xC0, 0xC1, 0xC2, 0xC3, 0xC3, 0xC4, 0xC5, 0xC5, 0xC6, 0xC7, 0xC7, 0xC8,
    0xC9, 0xC9, 0xCA, 0xCB, 0xCC, 0xCC, 0xCD, 0xCE, 0xCE, 0xCF, 0xD0, 0xD0, 0xD1, 0xD2, 0xD2, 0xD3,
    0xD3, 0xD4, 0xD5, 0xD5, 0xD6, 0xD6, 0xD7, 0xD8, 0xD8, 0xD9, 0xD9, 0xDA, 0xDB, 0xDB, 0xDC, 0xDC,
    0xDD, 0xDD, 0xDE, 0xDF, 0xDF, 0xE0, 0xE0, 0xE1, 0xE1, 0xE2, 0xE3, 0xE3, 0xE4, 0xE4, 0xE5, 0xE5,
    0xE6, 0xE6, 0xE7, 0xE7, 0xE7, 0xE8, 0xE8, 0xE8, 0xE9, 0xE9, 0xEA, 0xEA, 0xEA, 0xEB, 0xEB, 0xEB,
    0xEC, 0xEC, 0xEC, 0xED, 0xED, 0xEE, 0xEE, 0xEE, 0xEF, 0xEF, 0xEF, 0xF0, 0xF0, 0xF1, 0xF1, 0xF1,
    0xF2, 0xF2, 0xF2, 0xF3, 0xF3, 0xF4, 0xF4, 0xF4, 0xF5, 0xF5, 0xF5, 0xF6, 0xF6, 0xF6, 0xF7, 0xF7,
    0xF8, 0xF8, 0xF8, 0xF9, 0xF9, 0xF9, 0xFA, 0xFA, 0xFB, 0xFB, 0xFC, 0xFC, 0xFD, 0xFD, 0xFE, 0xFF,
];

/// The 16 by 16 threshold pattern for [`Halftone::Pattern`], row by row. A
/// color prints where its amount exceeds the threshold, and black where it
/// exceeds the threshold mirrored about [`HALFTONE_MAX`], so black dots fall
/// where color dots are least likely. A gray prints where its toned
/// lightness is below the threshold. Copied from the `HTSC` 1 resource, the
/// same in the Color SW 1500 and 2200 drivers.
pub const HALFTONE_PATTERN: [u8; 256] = [
    0x23, 0x6B, 0x9B, 0xA4, 0xDC, 0x94, 0x61, 0x59, 0x21, 0x69, 0x99, 0xA6, 0xDE, 0x96, 0x63, 0x5B,
    0xB3, 0x8B, 0x7C, 0x34, 0x4C, 0x74, 0x84, 0xC9, 0xB1, 0x89, 0x7E, 0x36, 0x4E, 0x76, 0x86, 0xCB,
    0xF3, 0xC4, 0x44, 0x14, 0x0C, 0x3C, 0xBC, 0xEC, 0xF1, 0xC6, 0x46, 0x16, 0x0E, 0x3E, 0xBE, 0xEE,
    0xF8, 0xAC, 0x2C, 0x1C, 0x05, 0x54, 0xD4, 0xE4, 0xFA, 0xAE, 0x2E, 0x1E, 0x07, 0x56, 0xD6, 0xE6,
    0xD8, 0x90, 0x64, 0x5C, 0x24, 0x6C, 0x9C, 0xA2, 0xDA, 0x92, 0x66, 0x5E, 0x26, 0x6E, 0x9E, 0xA0,
    0x48, 0x70, 0x80, 0xCC, 0xB4, 0x8C, 0x7A, 0x32, 0x4A, 0x72, 0x82, 0xCE, 0xB6, 0x8E, 0x78, 0x30,
    0x08, 0x38, 0xB8, 0xE8, 0xF4, 0xC2, 0x42, 0x12, 0x0A, 0x3A, 0xBA, 0xEA, 0xF6, 0xC0, 0x40, 0x10,
    0x01, 0x50, 0xD0, 0xE0, 0xFC, 0xAA, 0x2A, 0x1A, 0x03, 0x52, 0xD2, 0xE2, 0xFE, 0xA8, 0x28, 0x18,
    0x20, 0x68, 0x98, 0xA7, 0xDF, 0x97, 0x62, 0x5A, 0x22, 0x6A, 0x9A, 0xA5, 0xDD, 0x95, 0x60, 0x58,
    0xB0, 0x87, 0x7F, 0x37, 0x4F, 0x77, 0x87, 0xCA, 0xB2, 0x8A, 0x7D, 0x35, 0x4D, 0x75, 0x85, 0xC8,
    0xF0, 0xC7, 0x47, 0x17, 0x0F, 0x3F, 0xBF, 0xEF, 0xF2, 0xC5, 0x45, 0x15, 0x0D, 0x3D, 0xBD, 0xED,
    0xFA, 0xAF, 0x2F, 0x1F, 0x07, 0x57, 0xD7, 0xE7, 0xF8, 0xAD, 0x2D, 0x1D, 0x05, 0x55, 0xD5, 0xE5,
    0xDB, 0x93, 0x67, 0x5F, 0x27, 0x6F, 0x9F, 0xA1, 0xD9, 0x91, 0x65, 0x5D, 0x25, 0x6D, 0x9D, 0xA3,
    0x4B, 0x73, 0x83, 0xCF, 0xB7, 0x8F, 0x79, 0x31, 0x49, 0x71, 0x81, 0xCD, 0xB5, 0x8D, 0x7B, 0x33,
    0x0B, 0x3B, 0xBB, 0xEB, 0xF7, 0xC1, 0x41, 0x11, 0x09, 0x39, 0xB9, 0xE9, 0xF5, 0xC3, 0x43, 0x13,
    0x03, 0x53, 0xD3, 0xE3, 0xFE, 0xA9, 0x29, 0x19, 0x01, 0x51, 0xD1, 0xE1, 0xFC, 0xAB, 0x2B, 0x1B,
];

/// The side of [`HALFTONE_PATTERN`].
pub const HALFTONE_SIZE: usize = 16;

/// The largest threshold in [`HALFTONE_PATTERN`].
pub const HALFTONE_MAX: u8 = 254;

/// How many rows the scattering takes at a time, each stretch of them
/// starting its random numbers afresh.
const SCATTER_ROWS: usize = 5;

/// Of each error the scattering carries, the share that goes to the next dot
/// along is this less a random 0 to 255, out of 1024. The rest goes down.
/// This and the other scattering numbers are the Color SW drivers' own.
const SCATTER_SPLIT: i32 = 0x2FF;

/// The same at Draft quality, which sends more of the error down.
const SCATTER_SPLIT_DRAFT: i32 = 0x175;

/// The tone curve `family` takes for `halftone`.
pub const fn tone_curve(family: StyleWriterFamily, halftone: Halftone) -> &'static [u8; 256] {
    match (family.is_1200_series(), halftone) {
        (false, Halftone::Pattern) => &TONE_PATTERN_2200,
        (false, Halftone::Diffusion) => &TONE_DIFFUSION_2200,
        (true, Halftone::Pattern) => &TONE_PATTERN_1500,
        (true, Halftone::Diffusion) => &TONE_DIFFUSION_1500,
    }
}

/// Separate one RGB pixel, after its tone curve, into C, M, Y and K amounts
/// (0 none, 255 full). White takes no ink at all.
pub fn separate(rgb: [u8; 3], tone: &[u8; 256]) -> [u8; 4] {
    if rgb == [0xFF; 3] {
        return [0; 4];
    }
    let [r, g, b] = rgb.map(|v| tone[v as usize]);
    let max = r.max(g).max(b);
    [max - r, max - g, max - b, 255 - max]
}

/// A color moved a tenth of the way to white, as Normal-quality color on
/// transparencies prints on a Color StyleWriter 2200, 2400 or 2500.
pub fn lighten(rgb: [u8; 3]) -> [u8; 3] {
    let max = rgb[0].max(rgb[1]).max(rgb[2]);
    let lift = (u16::from(255 - max) * 10 / 100) as u8;
    rgb.map(|v| v + lift)
}

/// A page to print, cropped to the printable area, top row first.
#[derive(Debug, Clone)]
pub struct Page {
    /// Dots across.
    pub width: usize,
    /// Rows down.
    pub height: usize,
    pub pixels: Pixels,
}

/// A page's pixels, row after row.
#[derive(Debug, Clone)]
pub enum Pixels {
    /// 1 bit a pixel, MSB first, 1 for black, each row padded to a whole byte.
    BlackAndWhite(Vec<u8>),
    /// 1 byte a pixel, from 0 for black to 255 for white.
    Gray(Vec<u8>),
    /// 3 bytes a pixel, for red, green and blue.
    Rgb(Vec<u8>),
}

/// One band before it is coded. It holds its rows from `top` down, each of
/// `kind.planes()` planes of 1-bit pixels, MSB first, 1 for ink, with each
/// plane padded to a whole byte.
#[derive(Debug, Clone)]
pub struct RawBand {
    pub top: usize,
    /// Dots across.
    pub width: usize,
    pub kind: BandKind,
    pub rows: Vec<Vec<Vec<u8>>>,
}

/// Images the pages of one job into bands. What a halftone carries goes from
/// one band to the next, and for the scattering from one page to the next.
pub struct Imager {
    family: StyleWriterFamily,
    rendering: Rendering,
    halftone: Halftone,
    tone: &'static [u8; 256],
    mirrored: bool,
    lighten: bool,
    split: i32,
    rand: CRand,
    color_scatter: Scatter<4>,
    gray_scatter: Scatter<1>,
    /// Rows of the current page halftoned so far, which picks the pattern's
    /// row. The first takes the pattern's second row, and so on.
    pattern_rows: usize,
}

impl Imager {
    /// An imager for a job on `family`. `job.rendering` is what the pages
    /// print as, which [`super::StyleWriterSession::rendering`] gives once
    /// the job is set up.
    pub fn new(family: StyleWriterFamily, job: &JobOptions) -> Self {
        Self {
            family,
            rendering: job.rendering,
            halftone: job.halftone,
            tone: tone_curve(family, job.halftone),
            mirrored: job.paper.mirrored(),
            lighten: family.lightens_transparencies()
                && job.rendering == Rendering::Color
                && job.quality == PrintQuality::Normal
                && job.paper == PaperType::Transparency,
            split: if job.quality == PrintQuality::Draft { SCATTER_SPLIT_DRAFT } else { SCATTER_SPLIT },
            rand: CRand(1),
            color_scatter: Scatter::new(),
            gray_scatter: Scatter::new(),
            pattern_rows: 0,
        }
    }

    /// The bands a page prints in, top to bottom.
    pub fn bands(&mut self, page: &Page) -> Vec<RawBand> {
        self.pattern_rows = 0;
        let band_rows = self.family.max_band_rows();
        let mut bands = Vec::new();
        let mut top = 0;
        if self.rendering == Rendering::BlackAndWhite {
            while top < page.height {
                let end = (top + band_rows).min(page.height);
                let rows = (top..end).map(|y| vec![self.black_and_white_row(page, y)]).collect();
                bands.push(RawBand { top, width: page.width, kind: BandKind::Mono, rows });
                top = end;
            }
            return bands;
        }
        while top < page.height {
            let first = self.source_row(page, top);
            if first.blank() {
                top += 1;
                continue;
            }
            let end = (top + band_rows).min(page.height);
            let mut rows = vec![first];
            rows.extend((top + 1..end).map(|y| self.source_row(page, y)));
            let band = if rows.iter().any(SourceRow::needs_depth) {
                self.deep_band(top, page.width, rows)
            } else if self.lighten {
                self.lightened_band(top, page.width, rows)
            } else {
                let rows = rows.iter().map(|row| vec![row.black_bits()]).collect();
                RawBand { top, width: page.width, kind: BandKind::Mono, rows }
            };
            bands.push(band);
            top = end;
        }
        bands
    }

    /// Row `y` of a black and white page, mirrored for back-print film.
    /// Grayscale and color pixels print black where they are darker than
    /// mid gray.
    fn black_and_white_row(&self, page: &Page, y: usize) -> Vec<u8> {
        if let Pixels::BlackAndWhite(bits) = &page.pixels {
            let row_bytes = page.width.div_ceil(8);
            let mut row = bits[y * row_bytes..(y + 1) * row_bytes].to_vec();
            if self.mirrored {
                mirror_bits(&mut row, page.width);
            }
            return row;
        }
        let mut bits = vec![0u8; page.width.div_ceil(8)];
        if let SourceRow::Gray(gray) = self.source_row(page, y) {
            for (x, _) in gray.iter().enumerate().filter(|&(_, &g)| g < 0x80) {
                bits[x / 8] |= 0x80 >> (x % 8);
            }
        }
        bits
    }

    /// Row `y` of a grayscale or color page as it is drawn. It is in gray
    /// unless the job prints color, and mirrored for back-print film.
    fn source_row(&self, page: &Page, y: usize) -> SourceRow {
        let w = page.width;
        let mut row = match (&page.pixels, self.rendering) {
            (Pixels::Rgb(rgb), Rendering::Color) => {
                SourceRow::Rgb(rgb[y * w * 3..(y + 1) * w * 3].as_chunks::<3>().0.to_vec())
            }
            (Pixels::Rgb(rgb), _) => {
                let pixels = rgb[y * w * 3..(y + 1) * w * 3].as_chunks::<3>().0;
                SourceRow::Gray(pixels.iter().map(|&px| luma(px)).collect())
            }
            (Pixels::Gray(gray), Rendering::Color) => {
                SourceRow::Rgb(gray[y * w..(y + 1) * w].iter().map(|&g| [g; 3]).collect())
            }
            (Pixels::Gray(gray), _) => SourceRow::Gray(gray[y * w..(y + 1) * w].to_vec()),
            (Pixels::BlackAndWhite(bits), _) => {
                let row_bytes = w.div_ceil(8);
                let row = &bits[y * row_bytes..(y + 1) * row_bytes];
                SourceRow::Gray((0..w).map(|x| if row[x / 8] & (0x80 >> (x % 8)) != 0 { 0 } else { 0xFF }).collect())
            }
        };
        if self.mirrored {
            match &mut row {
                SourceRow::Gray(pixels) => pixels.reverse(),
                SourceRow::Rgb(pixels) => pixels.reverse(),
            }
        }
        row
    }

    fn toned_color(&self, rgb: [u8; 3]) -> [u8; 3] {
        if self.lighten { lighten(rgb) } else { rgb }
    }

    /// A band at the page's own depth, with four planes on a color page or one
    /// of gray on a grayscale page.
    fn deep_band(&mut self, top: usize, width: usize, rows: Vec<SourceRow>) -> RawBand {
        let tone = self.tone;
        if self.rendering == Rendering::Color {
            let ink = |rgb| separate(self.toned_color(rgb), tone);
            let mut inks: Vec<Vec<[u8; 4]>> = rows
                .iter()
                .map(|row| match row {
                    SourceRow::Rgb(pixels) => pixels.iter().map(|&px| ink(px)).collect(),
                    SourceRow::Gray(pixels) => pixels.iter().map(|&g| ink([g; 3])).collect(),
                })
                .collect();
            let planes = match self.halftone {
                Halftone::Pattern => inks.iter().map(|row| self.pattern_color(row)).collect(),
                Halftone::Diffusion => {
                    self.scatter_color(&mut inks);
                    inks.iter().map(|row| self.dots(row)).collect()
                }
            };
            return RawBand { top, width, kind: BandKind::Color, rows: planes };
        }
        let mut lightness: Vec<Vec<u8>> = rows
            .iter()
            .map(|row| match row {
                SourceRow::Gray(pixels) => pixels.iter().map(|&g| tone[g as usize]).collect(),
                SourceRow::Rgb(pixels) => pixels.iter().map(|&px| tone[luma(px) as usize]).collect(),
            })
            .collect();
        let planes = match self.halftone {
            Halftone::Pattern => lightness.iter().map(|row| vec![self.pattern_gray(row)]).collect(),
            Halftone::Diffusion => {
                self.scatter_gray(&mut lightness);
                lightness
                    .iter()
                    .map(|row| {
                        self.next_pattern_row();
                        vec![pack(row.iter().map(|&dot| dot != 0))]
                    })
                    .collect()
            }
        };
        RawBand { top, width, kind: BandKind::Mono, rows: planes }
    }

    /// A band of black and white on a color page that prints lighter. It prints
    /// in gray, as black lightened takes some white.
    fn lightened_band(&mut self, top: usize, width: usize, rows: Vec<SourceRow>) -> RawBand {
        let rows = rows
            .into_iter()
            .map(|row| match row {
                SourceRow::Rgb(pixels) => SourceRow::Gray(pixels.iter().map(|&px| luma(lighten(px))).collect()),
                gray => gray,
            })
            .collect();
        let rendering = std::mem::replace(&mut self.rendering, Rendering::Grayscale);
        let band = self.deep_band(top, width, rows);
        self.rendering = rendering;
        band
    }

    /// The offset into [`HALFTONE_PATTERN`] of the row the next halftoned row
    /// takes.
    fn next_pattern_row(&mut self) -> usize {
        self.pattern_rows += 1;
        (self.pattern_rows % HALFTONE_SIZE) * HALFTONE_SIZE
    }

    fn pattern_color(&mut self, row: &[[u8; 4]]) -> Vec<Vec<u8>> {
        let base = self.next_pattern_row();
        let mut planes = vec![vec![0u8; row.len().div_ceil(8)]; 4];
        for (x, ink) in row.iter().enumerate().filter(|(_, ink)| **ink != [0; 4]) {
            let threshold = HALFTONE_PATTERN[base + x % HALFTONE_SIZE];
            let bit = 0x80 >> (x % 8);
            for (plane, &amount) in planes.iter_mut().zip(&ink[..3]) {
                if threshold < amount {
                    plane[x / 8] |= bit;
                }
            }
            if HALFTONE_MAX - threshold < ink[3] {
                planes[3][x / 8] |= bit;
            }
        }
        planes
    }

    fn pattern_gray(&mut self, row: &[u8]) -> Vec<u8> {
        let base = self.next_pattern_row();
        pack(row.iter().enumerate().map(|(x, &light)| light < HALFTONE_PATTERN[base + x % HALFTONE_SIZE]))
    }

    /// The planes of a row of scattered inks, each 0 or 0xFF.
    fn dots(&mut self, row: &[[u8; 4]]) -> Vec<Vec<u8>> {
        self.next_pattern_row();
        (0..4).map(|ch| pack(row.iter().map(|ink| ink[ch] != 0))).collect()
    }

    /// Scatter a band of separated inks, leaving each 0xFF for a dot and 0
    /// for none. A pixel with no ink at all clears what was carried to it.
    fn scatter_color(&mut self, rows: &mut [Vec<[u8; 4]>]) {
        let width = rows.first().map_or(0, Vec::len);
        let split = self.split;
        self.color_scatter.fit(width);
        for stretch in rows.chunks_mut(SCATTER_ROWS) {
            let mut lcg = self.rand.next() << 16;
            let s = &mut self.color_scatter;
            for row in stretch.iter_mut() {
                let order: [usize; 4] = if s.backward { [3, 2, 1, 0] } else { [0, 1, 2, 3] };
                for i in 0..row.len() {
                    let x = if s.backward { row.len() - 1 - i } else { i };
                    let ink = &mut row[x];
                    if *ink == [0; 4] {
                        s.carry = [0; 4];
                        s.down[x] = [0; 4];
                        continue;
                    }
                    for ch in order {
                        let dot = scatter_step(ink[ch], &mut s.carry[ch], &mut s.down[x][ch], &mut lcg, split);
                        ink[ch] = if dot { 0xFF } else { 0 };
                    }
                }
                s.backward = !s.backward;
            }
            // Between stretches cyan's carry is kept in 15 bits, the rest in 16.
            s.carry[0] = (s.carry[0] << 17) >> 17;
            for carry in &mut s.carry[1..] {
                *carry = i32::from(*carry as i16);
            }
        }
    }

    /// Scatter a band of toned lightness, leaving each 0xFF for a dot and 0
    /// for none. A white pixel clears what was carried to it.
    fn scatter_gray(&mut self, rows: &mut [Vec<u8>]) {
        let width = rows.first().map_or(0, Vec::len);
        let split = self.split;
        self.gray_scatter.fit(width);
        for stretch in rows.chunks_mut(SCATTER_ROWS) {
            let mut lcg = self.rand.next() << 16;
            let s = &mut self.gray_scatter;
            for row in stretch.iter_mut() {
                for i in 0..row.len() {
                    let x = if s.backward { row.len() - 1 - i } else { i };
                    if row[x] == 0xFF {
                        s.carry = [0];
                        s.down[x] = [0];
                        row[x] = 0;
                        continue;
                    }
                    let white = scatter_step(row[x], &mut s.carry[0], &mut s.down[x][0], &mut lcg, split);
                    row[x] = if white { 0 } else { 0xFF };
                }
                s.backward = !s.backward;
            }
            s.carry[0] = i32::from(s.carry[0] as i16);
        }
    }
}

/// A row of a grayscale or color page, ready to image.
enum SourceRow {
    Gray(Vec<u8>),
    Rgb(Vec<[u8; 3]>),
}

impl SourceRow {
    /// Nothing but white.
    fn blank(&self) -> bool {
        match self {
            SourceRow::Gray(pixels) => pixels.iter().all(|&g| g == 0xFF),
            SourceRow::Rgb(pixels) => pixels.iter().all(|&px| px == [0xFF; 3]),
        }
    }

    /// Anything but black and white.
    fn needs_depth(&self) -> bool {
        match self {
            SourceRow::Gray(pixels) => pixels.iter().any(|&g| g != 0 && g != 0xFF),
            SourceRow::Rgb(pixels) => pixels.iter().any(|&px| px != [0; 3] && px != [0xFF; 3]),
        }
    }

    /// The row at 1 bit, as its black pixels.
    fn black_bits(&self) -> Vec<u8> {
        match self {
            SourceRow::Gray(pixels) => pack(pixels.iter().map(|&g| g == 0)),
            SourceRow::Rgb(pixels) => pack(pixels.iter().map(|&px| px == [0; 3])),
        }
    }
}

/// What the scattering carries, for pixels of `N` channels.
struct Scatter<const N: usize> {
    /// The error going to the next dot along, per channel.
    carry: [i32; N],
    /// Whether the next row runs right to left.
    backward: bool,
    /// The error going down to the next row, per column and channel, kept in
    /// a byte that wraps.
    down: Vec<[i8; N]>,
}

impl<const N: usize> Scatter<N> {
    fn new() -> Self {
        Self { carry: [0; N], backward: false, down: Vec::new() }
    }

    /// Make room for rows `width` pixels wide. Rows wider than any before
    /// start from nothing carried.
    fn fit(&mut self, width: usize) {
        if self.down.len() < width {
            *self = Self { carry: [0; N], backward: false, down: vec![[0; N]; width] };
        }
    }
}

/// One dot of the scattering, for one channel. It compares `value`, plus the
/// error carried to it, with a random threshold, returns whether it reached the
/// threshold, and passes on what is left over.
fn scatter_step(value: u8, carry: &mut i32, down: &mut i8, lcg: &mut u32, split: i32) -> bool {
    let mut v = *carry + i32::from(value) + i32::from(*down);
    *lcg = lcg.wrapping_mul(513).wrapping_add(1);
    let r = (*lcg >> 24) as i32;
    let reached = (r >> 3) + 0x6F < v;
    if reached {
        v -= 0xFF;
    }
    *carry = ((split - r) * v) >> 10;
    *down = (v - *carry) as i8;
    reached
}

/// The C library's `rand`, which starts each stretch of the scattering's own
/// random numbers.
struct CRand(u32);

impl CRand {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        (self.0 >> 16) & 0x7FFF
    }
}

fn luma([r, g, b]: [u8; 3]) -> u8 {
    ((u32::from(r) * 30 + u32::from(g) * 59 + u32::from(b) * 11) / 100) as u8
}

/// Pack dots into a 1-bit row, MSB first.
fn pack(dots: impl Iterator<Item = bool>) -> Vec<u8> {
    let mut row = Vec::new();
    for (x, dot) in dots.enumerate() {
        if x % 8 == 0 {
            row.push(0);
        }
        if dot {
            *row.last_mut().expect("pushed above") |= 0x80 >> (x % 8);
        }
    }
    row
}

/// Reverse the first `width` pixels of a 1-bit row, MSB first, for paper
/// printed from the back.
pub fn mirror_bits(row: &mut [u8], width: usize) {
    let get = |row: &[u8], x: usize| row[x / 8] & (0x80 >> (x % 8)) != 0;
    for x in 0..width / 2 {
        let y = width - 1 - x;
        let (a, b) = (get(row, x), get(row, y));
        if a != b {
            row[x / 8] ^= 0x80 >> (x % 8);
            row[y / 8] ^= 0x80 >> (y % 8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailtalk_core::stylewriter::ColorModel;

    const CS2200: StyleWriterFamily = StyleWriterFamily::Color(ColorModel::Cs2200);

    fn job(rendering: Rendering, halftone: Halftone) -> JobOptions {
        JobOptions { rendering, halftone, ..JobOptions::default() }
    }

    fn rgb_page(width: usize, height: usize, pixel: impl Fn(usize, usize) -> [u8; 3]) -> Page {
        let mut pixels = Vec::with_capacity(width * height * 3);
        for y in 0..height {
            for x in 0..width {
                pixels.extend_from_slice(&pixel(x, y));
            }
        }
        Page { width, height, pixels: Pixels::Rgb(pixels) }
    }

    fn gray_page(width: usize, height: usize, gray: u8) -> Page {
        Page { width, height, pixels: Pixels::Gray(vec![gray; width * height]) }
    }

    fn bit(plane: &[u8], x: usize) -> bool {
        plane[x / 8] & (0x80 >> (x % 8)) != 0
    }

    /// Black and grays print with black ink alone, and the gray in a color
    /// moves into black.
    #[test]
    fn separation_moves_grey_into_black() {
        let identity: [u8; 256] = std::array::from_fn(|i| i as u8);
        assert_eq!(separate([0, 0, 0], &identity), [0, 0, 0, 255]);
        assert_eq!(separate([255, 255, 255], &identity), [0, 0, 0, 0]);
        assert_eq!(separate([100, 100, 100], &identity), [0, 0, 0, 155]);
        assert_eq!(separate([255, 0, 0], &identity), [0, 255, 255, 0]);
        assert_eq!(separate([200, 50, 0], &identity), [0, 150, 200, 55]);
    }

    /// Black and gray print with black ink alone, with both halftones. Solid
    /// black in a band at depth is solid black ink, a mid gray is a share of
    /// black dots in color and grayscale jobs alike, and a white page sends no
    /// band at all. A grayscale job prints a color page in one plane of gray.
    #[test]
    fn neutrals_print_with_black_ink_alone() {
        for halftone in [Halftone::Diffusion, Halftone::Pattern] {
            let mut imager = Imager::new(CS2200, &job(Rendering::Color, halftone));
            let rows = (0..20).map(|_| SourceRow::Rgb(vec![[0; 3]; 40])).collect();
            let band = imager.deep_band(0, 40, rows);
            assert_eq!(band.kind, BandKind::Color);
            for planes in &band.rows {
                assert!((0..40).all(|x| bit(&planes[3], x)), "{halftone:?}");
                assert!(planes[..3].iter().all(|p| p.iter().all(|&b| b == 0)), "{halftone:?}");
            }

            for rendering in [Rendering::Color, Rendering::Grayscale] {
                let mut imager = Imager::new(CS2200, &job(rendering, halftone));
                assert!(imager.bands(&rgb_page(40, 20, |_, _| [255; 3])).is_empty(), "{halftone:?}");
                let mut on = 0;
                for band in imager.bands(&gray_page(64, 32, 128)) {
                    for planes in &band.rows {
                        let k = planes.last().unwrap();
                        on += (0..64).filter(|&x| bit(k, x)).count();
                        if rendering == Rendering::Color {
                            assert!(planes[..3].iter().all(|p| p.iter().all(|&b| b == 0)));
                        }
                    }
                }
                let share = on as f32 / (64 * 32) as f32;
                assert!((0.1..0.9).contains(&share), "{halftone:?} {rendering:?}: {share}");
            }
        }

        let mut imager = Imager::new(CS2200, &job(Rendering::Grayscale, Halftone::Pattern));
        let bands = imager.bands(&rgb_page(16, 8, |_, _| [200, 30, 30]));
        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].kind, BandKind::Mono);
        assert!(bands[0].rows.iter().all(|planes| planes.len() == 1));
    }

    /// Blank rows are skipped where a band would start. A band with only
    /// black and white in it prints at 1 bit. A band with anything else in it
    /// prints at the page's depth.
    #[test]
    fn bands_skip_blank_rows_and_print_black_and_white_at_one_bit() {
        let rows = CS2200.max_band_rows();
        let page = rgb_page(16, rows * 3, |x, y| match y {
            y if y < 10 => [255; 3],
            y if y < rows + 10 => if x < 4 { [0; 3] } else { [255; 3] },
            y if y < 2 * rows + 10 => [255; 3],
            _ => if x < 4 { [255, 0, 0] } else { [255; 3] },
        });
        let mut imager = Imager::new(CS2200, &job(Rendering::Color, Halftone::Pattern));
        let bands = imager.bands(&page);
        let shape: Vec<(usize, usize, BandKind)> = bands.iter().map(|b| (b.top, b.rows.len(), b.kind)).collect();
        assert_eq!(
            shape,
            [(10, rows, BandKind::Mono), (2 * rows + 10, rows - 10, BandKind::Color)],
            "the black rows at 1 bit, the red ones at depth"
        );
        assert!(bit(&bands[0].rows[0][0], 0) && !bit(&bands[0].rows[0][0], 4));

        // A black and white page prints every row, blank or not.
        let blank = Page { width: 16, height: 30, pixels: Pixels::BlackAndWhite(vec![0; 2 * 30]) };
        let mut imager = Imager::new(CS2200, &job(Rendering::BlackAndWhite, Halftone::Pattern));
        let bands = imager.bands(&blank);
        assert_eq!(bands.len(), 1);
        assert_eq!((bands[0].top, bands[0].rows.len(), bands[0].kind), (0, 30, BandKind::Mono));
    }

    /// Normal-quality color on transparencies prints a tenth of the way lighter
    /// toward white. Black and white bands print in gray, and the rest with
    /// lightened color.
    #[test]
    fn transparencies_print_lighter_at_normal_quality() {
        assert_eq!(lighten([0, 0, 0]), [25, 25, 25]);
        assert_eq!(lighten([105, 155, 55]), [115, 165, 65]);
        assert_eq!(lighten([255, 255, 255]), [255, 255, 255]);

        let film = JobOptions {
            quality: PrintQuality::Normal,
            paper: PaperType::Transparency,
            ..job(Rendering::Color, Halftone::Pattern)
        };
        let text = rgb_page(64, 16, |x, _| if x < 32 { [0; 3] } else { [255; 3] });
        let bands = Imager::new(CS2200, &film).bands(&text);
        assert_eq!(bands.len(), 1);
        assert_eq!(bands[0].kind, BandKind::Mono, "black and white prints in gray");
        let dots: usize = bands[0].rows.iter().map(|planes| (0..32).filter(|&x| bit(&planes[0], x)).count()).sum();
        assert!(dots < 32 * 16, "lightened black is not solid");

        // Elsewhere it prints black as black, and the 1200 series never
        // lightens.
        let plain = JobOptions { paper: PaperType::Plain, ..film };
        let bands = Imager::new(CS2200, &plain).bands(&text);
        assert!(bands[0].rows.iter().all(|planes| (0..32).all(|x| bit(&planes[0], x))));
        let cs1500 = StyleWriterFamily::Color(ColorModel::Cs1500);
        let bands = Imager::new(cs1500, &film).bands(&text);
        assert!(bands[0].rows.iter().all(|planes| (0..32).all(|x| bit(&planes[0], x))));
    }

    #[test]
    fn back_print_film_is_mirrored() {
        let film = JobOptions { paper: PaperType::BackPrintFilm, ..job(Rendering::BlackAndWhite, Halftone::Pattern) };
        let mut bits = vec![0u8; 2 * 4];
        bits[0] = 0x80;
        let page = Page { width: 12, height: 4, pixels: Pixels::BlackAndWhite(bits) };
        let bands = Imager::new(CS2200, &film).bands(&page);
        assert_eq!(bands[0].rows[0][0], [0x00, 0x10]);

        let color = JobOptions { paper: PaperType::BackPrintFilm, ..job(Rendering::Color, Halftone::Pattern) };
        let page = rgb_page(12, 4, |x, _| if x == 0 { [0; 3] } else { [255; 3] });
        let bands = Imager::new(CS2200, &color).bands(&page);
        assert_eq!(bands[0].rows[0][0], [0x00, 0x10]);
    }

}
