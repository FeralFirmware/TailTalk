//! What a job prints with, and the commands that set a printer up for it.
//! Every command goes to the printer as an ADSP message of its own.

use tailtalk_core::stylewriter::ColorModel;

use super::StyleWriterFamily;
use super::raster::Halftone;

/// Print quality, set by a command at the start of the job. The raster is the
/// same at every quality, and the printer runs fewer or more passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintQuality {
    Draft,
    #[default]
    Normal,
    Best,
}

/// How a job's pages are rendered, which is the choice a Mac's print dialog
/// offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rendering {
    /// Black and white, with no shades of gray, at 1 bit a pixel.
    #[default]
    BlackAndWhite,
    /// Shades of gray, halftoned in black ink.
    Grayscale,
    /// Color, separated into cyan, magenta, yellow and black and halftoned.
    /// Only a Color StyleWriter that can print colour prints it, and any other
    /// prints the job in grayscale.
    Color,
}

/// The paper loaded. A Color StyleWriter is told with `m` and a digit. Best
/// quality on transparencies also changes how a 1200, and a 1500 with a black
/// cartridge, start their first page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaperType {
    #[default]
    Plain,
    Coated,
    Transparency,
    /// Back-print film, which is printed on from the back.
    BackPrintFilm,
    Glossy,
}

impl PaperType {
    /// The digit sent after `m`. A 1500 has one for every paper, and the 2200,
    /// 2400 and 2500 share `0` among coated paper, transparencies and glossy.
    pub const fn media_code(self, model: ColorModel) -> u8 {
        match (self, model) {
            (PaperType::Plain, _) => b'2',
            (PaperType::BackPrintFilm, _) => b'3',
            (PaperType::Coated, ColorModel::Cs1500) => b'1',
            (PaperType::Glossy, ColorModel::Cs1500) => b'5',
            (PaperType::Coated | PaperType::Transparency | PaperType::Glossy, _) => b'0',
        }
    }

    /// Whether every row is mirrored left to right, so the page reads
    /// correctly through back-print film.
    pub const fn mirrored(self) -> bool {
        matches!(self, PaperType::BackPrintFilm)
    }
}

/// Cleaning the cartridge's nozzles at the start of a job, which every
/// StyleWriter but the original does on command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cleaning {
    #[default]
    None,
    /// `P`, once.
    Clean,
    /// `P` twice, for when a simple cleaning does not fix the print quality.
    SuperClean,
}

impl Cleaning {
    fn commands(self) -> impl Iterator<Item = Vec<u8>> {
        let times = match self {
            Cleaning::None => 0,
            Cleaning::Clean => 1,
            Cleaning::SuperClean => 2,
        };
        std::iter::repeat_n(b"P".to_vec(), times)
    }
}

/// The cartridges a Color StyleWriter reports for status 'H'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cartridge {
    /// Colour can be printed. On a 2200, 2400 or 2500 the black and colour
    /// cartridges are both installed, and on a 1500 its colour cartridge is.
    Color,
    /// Only black can be printed.
    Black,
}

impl Cartridge {
    /// The cartridges for an 'H' reply. A 1500 sets bit 0x80 for its colour
    /// cartridge. A 2200, 2400 or 2500 answers exactly 0x81 for black and colour,
    /// or 0x01 for black only, and any other reply is an error.
    pub fn from_query(h: u8, model: ColorModel) -> Option<Self> {
        match (model, h) {
            (ColorModel::Cs1500, h) if h & 0x80 != 0 => Some(Cartridge::Color),
            (ColorModel::Cs1500, _) => Some(Cartridge::Black),
            (_, 0x81) => Some(Cartridge::Color),
            (_, 0x01) => Some(Cartridge::Black),
            _ => None,
        }
    }

    /// The command that sets a Color StyleWriter 2200, 2400 or 2500's mode for
    /// a page. That is `H` for a color page and `B` for black and white or
    /// grayscale. A 1500 takes neither.
    pub const fn page_mode(self, color: bool) -> u8 {
        match (self, color) {
            (Cartridge::Color, true) => b'H',
            _ => b'B',
        }
    }
}

/// What a job prints with, set once per job by
/// [`super::StyleWriterSession::setup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JobOptions {
    pub rendering: Rendering,
    pub quality: PrintQuality,
    pub paper: PaperType,
    pub cleaning: Cleaning,
    /// How grayscale and color pages are halftoned.
    pub halftone: Halftone,
    /// The paper is narrower than [`Self::NARROW_PAPER_WIDTH_IN`], as an
    /// envelope fed short edge first is. Every StyleWriter but the original
    /// is told with `F` just before `A`.
    pub narrow_paper: bool,
}

impl JobOptions {
    /// Paper narrower than this, in inches, is [`Self::narrow_paper`].
    pub const NARROW_PAPER_WIDTH_IN: f32 = 5.5;

    /// `F` for narrow paper, then `A`, which end every job's setup but the
    /// original StyleWriter's.
    fn closing_commands(&self) -> impl Iterator<Item = Vec<u8>> {
        self.narrow_paper
            .then(|| b"F".to_vec())
            .into_iter()
            .chain([b"A".to_vec()])
    }

    /// The commands that set a Color StyleWriter up for the job. These are the
    /// paper, the quality, any cleaning, `F` for narrow paper, then `A`.
    /// Quality is `d` for Draft and `s` for Best. Normal is `n` then `Z` with
    /// the colour cartridge and `b` with only black, or `Z` alone on a 1500.
    pub fn color_commands(&self, model: ColorModel, cartridge: Cartridge) -> Vec<Vec<u8>> {
        let mut commands = vec![vec![b'm', self.paper.media_code(model)]];
        match (self.quality, cartridge, model) {
            (PrintQuality::Draft, _, _) => commands.push(b"d".to_vec()),
            (PrintQuality::Normal, _, ColorModel::Cs1500) => commands.push(b"Z".to_vec()),
            (PrintQuality::Normal, Cartridge::Color, _) => {
                commands.push(b"n".to_vec());
                commands.push(b"Z".to_vec());
            }
            (PrintQuality::Normal, Cartridge::Black, _) => commands.push(b"b".to_vec()),
            (PrintQuality::Best, _, _) => commands.push(b"s".to_vec()),
        }
        commands.extend(self.cleaning.commands());
        commands.extend(self.closing_commands());
        commands
    }

    /// The commands that set a black-only StyleWriter up for the job. The II
    /// and the 1200 take `u`, the quality (`d`, `n` or `b`), `D`, any
    /// cleaning, `F` for narrow paper, then `A`. The original StyleWriter
    /// prints at 360 dpi with `n` and `u`, then `A`, whatever the quality and
    /// paper. Empty for a Color StyleWriter, which takes
    /// [`Self::color_commands`].
    pub fn black_commands(&self, family: StyleWriterFamily) -> Vec<Vec<u8>> {
        match family {
            StyleWriterFamily::Color(_) => Vec::new(),
            StyleWriterFamily::Original => vec![b"n".to_vec(), b"u".to_vec(), b"A".to_vec()],
            StyleWriterFamily::StyleWriterII | StyleWriterFamily::StyleWriter1200 => {
                let quality = match self.quality {
                    PrintQuality::Draft => b"d".to_vec(),
                    PrintQuality::Normal => b"n".to_vec(),
                    PrintQuality::Best => b"b".to_vec(),
                };
                let mut commands = vec![b"u".to_vec(), quality, b"D".to_vec()];
                commands.extend(self.cleaning.commands());
                commands.extend(self.closing_commands());
                commands
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PrintQuality::*;

    fn job(quality: PrintQuality, paper: PaperType, cleaning: Cleaning) -> JobOptions {
        JobOptions { quality, paper, cleaning, ..JobOptions::default() }
    }

    /// A 1500 takes `Z` alone for Normal, whatever the cartridge, and has a
    /// paper code of its own for coated and glossy paper. Narrow paper takes `F`
    /// just before `A`, after any cleaning.
    #[test]
    fn color_commands_follow_the_model_cartridge_quality_paper_and_cleaning() {
        use Cartridge::*;
        let commands = |model, cartridge, quality, paper, cleaning| {
            job(quality, paper, cleaning).color_commands(model, cartridge).concat()
        };
        let cs2200 = |cartridge, quality, paper, cleaning| commands(ColorModel::Cs2200, cartridge, quality, paper, cleaning);
        assert_eq!(cs2200(Color, Normal, PaperType::Plain, Cleaning::None), b"m2nZA");
        assert_eq!(cs2200(Color, Best, PaperType::Plain, Cleaning::None), b"m2sA");
        assert_eq!(cs2200(Color, Draft, PaperType::Glossy, Cleaning::None), b"m0dA");
        assert_eq!(cs2200(Black, Normal, PaperType::Plain, Cleaning::None), b"m2bA");
        assert_eq!(cs2200(Black, Best, PaperType::BackPrintFilm, Cleaning::Clean), b"m3sPA");
        assert_eq!(cs2200(Color, Normal, PaperType::Coated, Cleaning::SuperClean), b"m0nZPPA");

        let cs1500 = |cartridge, quality, paper| commands(ColorModel::Cs1500, cartridge, quality, paper, Cleaning::None);
        assert_eq!(cs1500(Color, Normal, PaperType::Plain), b"m2ZA");
        assert_eq!(cs1500(Black, Normal, PaperType::Coated), b"m1ZA");
        assert_eq!(cs1500(Color, Best, PaperType::Glossy), b"m5sA");
        assert_eq!(cs1500(Black, Draft, PaperType::Transparency), b"m0dA");
        assert_eq!(cs1500(Color, Best, PaperType::BackPrintFilm), b"m3sA");

        let envelope = JobOptions { cleaning: Cleaning::Clean, narrow_paper: true, ..JobOptions::default() };
        assert_eq!(envelope.color_commands(ColorModel::Cs2200, Color).concat(), b"m2nZPFA");
        assert_eq!(envelope.color_commands(ColorModel::Cs1500, Black).concat(), b"m2ZPFA");

        // Each command is a message of its own.
        assert_eq!(
            JobOptions::default().color_commands(ColorModel::Cs2200, Color),
            vec![b"m2".to_vec(), b"n".to_vec(), b"Z".to_vec(), b"A".to_vec()]
        );
    }

    /// Narrow paper takes `F` just before `A`, after any cleaning, on every
    /// black-only StyleWriter but the original.
    #[test]
    fn black_only_printers_take_their_own_commands() {
        use StyleWriterFamily::*;
        let commands = |family, quality, cleaning| job(quality, PaperType::Plain, cleaning).black_commands(family).concat();
        for family in [StyleWriterII, StyleWriter1200] {
            assert_eq!(commands(family, Normal, Cleaning::None), b"unDA");
            assert_eq!(commands(family, Draft, Cleaning::None), b"udDA");
            assert_eq!(commands(family, Best, Cleaning::Clean), b"ubDPA");
            assert_eq!(commands(family, Normal, Cleaning::SuperClean), b"unDPPA");
        }
        assert_eq!(commands(Original, Best, Cleaning::Clean), b"nuA");
        assert!(JobOptions::default().black_commands(Color(ColorModel::Cs2200)).is_empty());

        let envelope = JobOptions { cleaning: Cleaning::Clean, narrow_paper: true, ..JobOptions::default() };
        assert_eq!(envelope.black_commands(StyleWriterII).concat(), b"unDPFA");
        assert_eq!(envelope.black_commands(StyleWriter1200).concat(), b"unDPFA");
        assert_eq!(envelope.black_commands(Original).concat(), b"nuA");
    }

    /// A 1500 goes by bit 0x80 alone. The others take only 0x81 and 0x01,
    /// so a reply with stray bits stops the job instead of printing color.
    #[test]
    fn h_replies_name_the_cartridge_by_each_models_rule() {
        use Cartridge::*;
        assert_eq!(Cartridge::from_query(0x80, ColorModel::Cs1500), Some(Color));
        assert_eq!(Cartridge::from_query(0x00, ColorModel::Cs1500), Some(Black));
        for model in [ColorModel::Cs2200, ColorModel::Cs2400, ColorModel::Cs2500, ColorModel::Unknown] {
            assert_eq!(Cartridge::from_query(0x81, model), Some(Color));
            assert_eq!(Cartridge::from_query(0x01, model), Some(Black));
            for stray in [0x00, 0x80, 0x83, 0x03] {
                assert_eq!(Cartridge::from_query(stray, model), None, "{model:?} H=0x{stray:02X}");
            }
        }
    }
}
