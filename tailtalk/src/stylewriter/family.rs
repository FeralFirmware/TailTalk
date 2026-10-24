//! Which StyleWriter a printer is, and what follows from it. That covers the
//! page area its engine prints, its buffer, and how its rows are coded.

use tailtalk_core::stylewriter::{COLOR_FAMILY, ColorModel};

use super::encode::BandKind;

/// Which StyleWriter a printer is, as far as printing to it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StyleWriterFamily {
    /// A Color StyleWriter 1500, 2200, 2400 or 2500, which identify as "CS"
    /// and tell each other apart by submodel. The 2200's path is the one
    /// verified on hardware.
    Color(ColorModel),
    /// The StyleWriter II ("SW"). Black only, and not yet verified on one.
    StyleWriterII,
    /// The StyleWriter 1200 ("SW3"), which is a StyleWriter II with a few
    /// commands of its own. Black only, and not yet verified on one.
    StyleWriter1200,
    /// The original StyleWriter ("IJ10"). Black only, with an 8 KB buffer and
    /// no row delta. It answers status queries and `?` on real hardware, but
    /// printing to one has not been verified.
    Original,
}

/// A Color StyleWriter of unknown model, which prints like a 2200.
impl Default for StyleWriterFamily {
    fn default() -> Self {
        StyleWriterFamily::Color(ColorModel::Unknown)
    }
}

/// The page area and banding of a printer engine, at 360 dpi.
struct Engine {
    /// Dots across the printable area.
    width: usize,
    left_margin: usize,
    right_margin: usize,
    top_margin: usize,
    bottom_margin: usize,
    /// Rows the engine takes in one band.
    band_rows: usize,
    /// Dots a band's rect is moved right by.
    rect_offset: u16,
}

/// The Color StyleWriter 2200, 2400 and 2500 are 973/120 inch across, with 0.2
/// inch margins either side, 0.125 inch at the top and 0.275 inch at the
/// bottom. Taken from the Color SW 2200 driver's `ENGC` 1 resource.
const COLOR_ENGINE: Engine = Engine {
    width: 2919,
    left_margin: 72,
    right_margin: 72,
    top_margin: 45,
    bottom_margin: 99,
    band_rows: 400,
    rect_offset: 0,
};

/// The original StyleWriter, the II, the 1200 and the Color StyleWriter 1500
/// are 8 inches across, with 0.2 inch margins either side and at the top, and
/// 38/120 inch at the bottom, from the Color SW 1500 driver's `ENGC` 1
/// resource. All but the original take their rects 16 dots further right for
/// the same page.
const ENGINE_1200: Engine = Engine {
    width: 2880,
    left_margin: 72,
    right_margin: 72,
    top_margin: 72,
    bottom_margin: 114,
    band_rows: 800,
    rect_offset: 16,
};

const ORIGINAL_ENGINE: Engine = Engine {
    rect_offset: 0,
    ..ENGINE_1200
};

/// How big a black and white or grayscale block grows on a Color StyleWriter
/// 2200, 2400 or 2500 before it goes out, framing included. One block can be no
/// bigger than 0x8000 bytes, whatever 'B' says is free. A block of 32863 stalls
/// the printer with 'B' = 0x00 and a blank page ejected. This and the sizes
/// below are the limits the drivers use.
const COLOR_BLOCK_ROOM_MONO: usize = 0x7E77;

/// The same for a color block.
const COLOR_BLOCK_ROOM_COLOR: usize = 0x79FA;

/// The same for the original StyleWriter, the II, the 1200 and the Color
/// StyleWriter 1500, less a row of every plane in the block.
const BLOCK_ROOM_1200: usize = 0x76ED;

/// A Color StyleWriter 2200 reads 'B' as 0xA2 (no paper) or 0xA3 (paper
/// loaded) when its buffer is empty. Mid-page readings like 0x23 are a nearly
/// full buffer, which testing bit 0x20 alone would call empty.
const CS2200_IDLE_MASK: u8 = 0xA0;

impl StyleWriterFamily {
    /// The family for a `?` reply, and for a Color StyleWriter the model its
    /// 'p' reply names. `None` for a reply no StyleWriter sends.
    pub fn from_identity(identity: &str, submodel: Option<u8>) -> Option<Self> {
        Some(match identity.as_bytes() {
            b"IJ10" => StyleWriterFamily::Original,
            b"SW" => StyleWriterFamily::StyleWriterII,
            b"SW3" => StyleWriterFamily::StyleWriter1200,
            COLOR_FAMILY => StyleWriterFamily::Color(ColorModel::from_submodel(submodel)),
            _ => return None,
        })
    }

    /// Whether a `?` reply comes from a printer that prints like this one.
    pub(super) fn identifies_as(self, identity: &str) -> bool {
        use StyleWriterFamily::*;
        matches!(
            (self, Self::from_identity(identity, None)),
            (Color(_), Some(Color(_)))
                | (StyleWriterII, Some(StyleWriterII))
                | (StyleWriter1200, Some(StyleWriter1200))
                | (Original, Some(Original))
        )
    }

    /// The original StyleWriter, the II, the 1200 and the Color StyleWriter
    /// 1500. These are the printers that register as `StyleWriter1200AT`, share
    /// an engine's page area, and report their status alike.
    pub(super) const fn is_1200_series(self) -> bool {
        !matches!(
            self,
            StyleWriterFamily::Color(ColorModel::Cs2200 | ColorModel::Cs2400 | ColorModel::Cs2500 | ColorModel::Unknown)
        )
    }

    const fn engine(self) -> &'static Engine {
        match self {
            StyleWriterFamily::Original => &ORIGINAL_ENGINE,
            _ if self.is_1200_series() => &ENGINE_1200,
            _ => &COLOR_ENGINE,
        }
    }

    /// Dots across the printable area. Narrower paper prints narrower rows.
    pub const fn print_width(self) -> usize {
        self.engine().width
    }

    /// Bytes in a row as wide as the printable area.
    pub const fn print_rowbytes(self) -> usize {
        self.engine().width.div_ceil(8)
    }

    /// The left edge of every band's rect. This is the engine's own offset, as
    /// a band always starts at the left of the printable area.
    pub const fn rect_left(self) -> u16 {
        self.engine().rect_offset
    }

    /// Dots cropped off the left of the page, a whole number of bytes.
    pub const fn left_margin_px(self) -> usize {
        self.engine().left_margin
    }

    /// Dots always left unprinted at the right of the page. Paper wide enough
    /// to outreach [`Self::print_width`] leaves more.
    pub const fn min_right_margin_px(self) -> usize {
        self.engine().right_margin
    }

    /// Rows cropped off the top of the page.
    pub const fn top_margin_rows(self) -> usize {
        self.engine().top_margin
    }

    /// Rows cropped off the bottom of the page.
    pub const fn bottom_margin_rows(self) -> usize {
        self.engine().bottom_margin
    }

    /// The printable width in dots on paper `paper_width` dots wide.
    pub const fn printable_width(self, paper_width: usize) -> usize {
        let room = paper_width.saturating_sub(self.left_margin_px() + self.min_right_margin_px());
        if room < self.print_width() { room } else { self.print_width() }
    }

    /// The most rows one band covers.
    pub const fn max_band_rows(self) -> usize {
        self.engine().band_rows
    }

    /// Only the Color StyleWriters take a color cartridge.
    pub const fn can_print_color(self) -> bool {
        matches!(self, StyleWriterFamily::Color(_))
    }

    /// Whether the cartridge cleans on command, which every StyleWriter but the
    /// original does.
    pub const fn can_clean(self) -> bool {
        !matches!(self, StyleWriterFamily::Original)
    }

    /// Whether each row is sent XOR'd with the one before it, which every
    /// StyleWriter but the original undoes as it prints.
    pub(super) const fn delta_rows(self) -> bool {
        !matches!(self, StyleWriterFamily::Original)
    }

    /// Whether Normal-quality color on transparencies prints a tenth lighter,
    /// which it does on the Color StyleWriter 2200, 2400 and 2500.
    pub(super) const fn lightens_transparencies(self) -> bool {
        !self.is_1200_series()
    }

    /// Free bytes in the printer's buffer for a status 'B' reading. It counts
    /// 64-byte units on the original StyleWriter and 256-byte units on the
    /// others, less 2 KB, so the buffer reads highest when empty.
    pub const fn free_bytes(self, b: u8) -> i32 {
        let unit = match self {
            StyleWriterFamily::Original => 64,
            _ => 256,
        };
        b as i32 * unit - 2048
    }

    /// How big a `G` block grows, framing included, before it goes out, for
    /// rows `row_bytes` bytes a plane. A block that grows past it goes with
    /// the row that took it past.
    pub const fn block_room(self, kind: BandKind, row_bytes: usize) -> usize {
        match (self.is_1200_series(), kind) {
            (true, _) => BLOCK_ROOM_1200 - row_bytes * kind.planes(),
            (false, BandKind::Mono) => COLOR_BLOCK_ROOM_MONO,
            (false, BandKind::Color) => COLOR_BLOCK_ROOM_COLOR,
        }
    }

    /// Whether status 'B' reads as an empty buffer. Each model reads its own
    /// value when empty, and readings mid-page are only free space, so the
    /// empty reading is matched exactly. A 1500's depends on its cartridge,
    /// which `color_cartridge` gives. The II's and 1200's have not been seen,
    /// and are taken to be the 2400's.
    pub(super) const fn buffer_idle(self, b: u8, color_cartridge: bool) -> bool {
        match self {
            StyleWriterFamily::Color(ColorModel::Cs2200 | ColorModel::Unknown) => {
                b & CS2200_IDLE_MASK == CS2200_IDLE_MASK
            }
            StyleWriterFamily::Color(ColorModel::Cs1500) => b == if color_cartridge { 0x87 } else { 0x9F },
            StyleWriterFamily::Color(ColorModel::Cs2500) => b == 0x80,
            StyleWriterFamily::Color(ColorModel::Cs2400)
            | StyleWriterFamily::StyleWriterII
            | StyleWriterFamily::StyleWriter1200 => b == 0xF8,
            StyleWriterFamily::Original => b == 0xA0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use StyleWriterFamily::*;

    const CS2200: StyleWriterFamily = Color(ColorModel::Cs2200);
    const CS1500: StyleWriterFamily = Color(ColorModel::Cs1500);

    #[test]
    fn identify_strings_choose_the_family() {
        assert_eq!(StyleWriterFamily::from_identity("IJ10", None), Some(Original));
        assert_eq!(StyleWriterFamily::from_identity("SW", None), Some(StyleWriterII));
        assert_eq!(StyleWriterFamily::from_identity("SW3", None), Some(StyleWriter1200));
        assert_eq!(StyleWriterFamily::from_identity("CS", Some(0x04)), Some(CS1500));
        assert_eq!(StyleWriterFamily::from_identity("CS", None), Some(Color(ColorModel::Unknown)));
        assert_eq!(StyleWriterFamily::from_identity("XY", None), None);
        assert_eq!(StyleWriterFamily::from_identity("", None), None);

        // A job only goes ahead once the printer answers as what it was
        // started for.
        assert!(StyleWriterII.identifies_as("SW") && !StyleWriterII.identifies_as("SW3"));
        assert!(StyleWriter1200.identifies_as("SW3") && !Original.identifies_as("SW"));
        assert!(CS2200.identifies_as("CS") && !StyleWriterII.identifies_as("XY"));
    }

    #[test]
    fn each_series_has_its_own_page_area() {
        for family in [Original, StyleWriterII, StyleWriter1200, CS1500] {
            assert!(family.is_1200_series(), "{family:?}");
            assert_eq!(family.print_rowbytes(), 360, "{family:?}");
            assert_eq!(
                (family.left_margin_px(), family.min_right_margin_px(), family.top_margin_rows(), family.bottom_margin_rows()),
                (72, 72, 72, 114)
            );
            assert_eq!(family.max_band_rows(), 800);
        }
        for model in [ColorModel::Cs2200, ColorModel::Cs2400, ColorModel::Cs2500, ColorModel::Unknown] {
            let family = Color(model);
            assert!(!family.is_1200_series(), "{model:?}");
            assert_eq!(family.print_rowbytes(), 365);
            assert_eq!(
                (family.left_margin_px(), family.min_right_margin_px(), family.top_margin_rows(), family.bottom_margin_rows()),
                (72, 72, 45, 99)
            );
            assert_eq!(family.max_band_rows(), 400);
        }
        // Rects start 16 dots further right on all but the original
        // StyleWriter and the 2200's engine.
        assert_eq!(Original.rect_left(), 0);
        assert_eq!(StyleWriterII.rect_left(), 16);
        assert_eq!(CS1500.rect_left(), 16);
        assert_eq!(CS2200.rect_left(), 0);

        // Letter at 360 dpi is 3060 dots, and 0.2 inch either side leaves 2916.
        assert_eq!(CS2200.printable_width(3060), 2916);
        assert_eq!(StyleWriterII.printable_width(3060), 2880);
        // A4 is 2976 dots.
        assert_eq!(CS2200.printable_width(2976), 2832);
        assert_eq!(CS2200.printable_width(4000), 2919);
    }

    /// 'B' reads free space in each model's own units, and an empty buffer as
    /// each model's own value. A block's room follows the series and, on a
    /// 2200, 2400 or 2500, whether the band is in color.
    #[test]
    fn buffer_readings_and_block_room_by_model() {
        assert_eq!(CS2200.free_bytes(0xA3), 39680);
        assert_eq!(CS2200.free_bytes(0x08), 0);
        assert_eq!(Original.free_bytes(0xA0), 8192);

        // The 2200 needs both 0x80 and 0x20.
        assert!(CS2200.buffer_idle(0xA3, true) && CS2200.buffer_idle(0xA2, true));
        assert!(!CS2200.buffer_idle(0x23, true) && !CS2200.buffer_idle(0x00, true));
        assert!(Color(ColorModel::Cs2400).buffer_idle(0xF8, true));
        assert!(Color(ColorModel::Cs2500).buffer_idle(0x80, true));
        // The 1500's changes with the cartridge.
        assert!(CS1500.buffer_idle(0x87, true) && !CS1500.buffer_idle(0x9F, true));
        assert!(CS1500.buffer_idle(0x9F, false) && !CS1500.buffer_idle(0x87, false));
        assert!(Original.buffer_idle(0xA0, false) && !Original.buffer_idle(0xF8, false));

        for model in [ColorModel::Cs2200, ColorModel::Cs2400, ColorModel::Cs2500] {
            assert_eq!(Color(model).block_room(BandKind::Mono, 365), 0x7E77);
            assert_eq!(Color(model).block_room(BandKind::Color, 365), 0x79FA);
        }
        for family in [Original, StyleWriterII, StyleWriter1200, CS1500] {
            assert_eq!(family.block_room(BandKind::Mono, 360), 0x76ED - 360, "{family:?}");
            assert_eq!(family.block_room(BandKind::Color, 360), 0x76ED - 4 * 360, "{family:?}");
        }
    }

}
