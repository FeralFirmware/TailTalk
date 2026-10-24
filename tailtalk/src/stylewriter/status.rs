//! What a StyleWriter reports about itself. That covers the faults in its
//! status '1' and '2' replies, and what a look at an idle printer finds.

use tailtalk_core::stylewriter::{self as core, ColorModel, status1, status2};

use super::StyleWriterFamily;

/// A condition the printer reports in status '1' or '2'. See [`core::status1`]
/// and [`core::status2`] for the bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrinterFault {
    PrinterError,
    HardwareError,
    DoorOpen,
    WasteInkFull,
    CartridgeJammed,
    InkOut,
    OutOfPaper,
    PaperJam,
    CheckConnections,
    CartridgeMissing,
    PaperTooSmall,
    /// Bit 0x02 of status '1' or '2' on a printer of the 1200 series, which
    /// does not say what it is and clears it itself. Printing waits for it.
    Holding,
    /// The printer did not answer status '1' or '2'.
    NoResponse,
}

impl PrinterFault {
    /// What to tell the user.
    pub fn message(self) -> &'static str {
        match self {
            PrinterFault::PrinterError => "Error in the printer",
            PrinterFault::HardwareError => "Hardware error: check for anything obstructing the ink cartridge",
            PrinterFault::DoorOpen => "The door is open",
            PrinterFault::WasteInkFull => "The waste ink container is full",
            PrinterFault::CartridgeJammed => "The ink cartridge has jammed",
            PrinterFault::InkOut => "An ink tank or the cartridge needs replacing",
            PrinterFault::OutOfPaper => "Out of paper",
            PrinterFault::PaperJam => "Paper jam",
            PrinterFault::CheckConnections => "Error in the printer: check the connections",
            PrinterFault::CartridgeMissing => "The ink cartridge is missing or not installed correctly",
            PrinterFault::PaperTooSmall => "The paper is smaller than the page size",
            PrinterFault::Holding => "The printer is holding the job",
            PrinterFault::NoResponse => "No response to status queries",
        }
    }

    /// Whether status '2' reports it, so that `S` clears it.
    pub const fn from_error_status(self) -> bool {
        !matches!(
            self,
            PrinterFault::PrinterError
                | PrinterFault::HardwareError
                | PrinterFault::DoorOpen
                | PrinterFault::WasteInkFull
                | PrinterFault::Holding
                | PrinterFault::NoResponse
        )
    }
}

impl StyleWriterFamily {
    /// The faults in status '1' and '2' replies, where `None` is a query the
    /// printer did not answer.
    ///
    /// The 1200 series reports a hardware error in '1', and a full waste ink
    /// container too on the 1500. Bit 0x02 of either reply is
    /// [`PrinterFault::Holding`]. The Color StyleWriter 2200, 2400 and 2500
    /// report an error, a hardware error, the door and the waste ink in '1',
    /// and nothing else there. Every bit of '2' counts on every StyleWriter,
    /// 0x10 and 0x80 alike.
    pub fn faults(self, status: Option<u8>, error: Option<u8>) -> Vec<PrinterFault> {
        use PrinterFault::*;
        let mut faults = Vec::new();
        let mut check = |set: bool, fault: PrinterFault| {
            if set && !faults.contains(&fault) {
                faults.push(fault);
            }
        };
        check(status.is_none() || error.is_none(), NoResponse);
        let s = status.unwrap_or(0);
        let e = error.unwrap_or(0);
        if self.is_1200_series() {
            let waste_ink = self == StyleWriterFamily::Color(ColorModel::Cs1500);
            check(s & status1::PRINTER_ERROR != 0, Holding);
            check(s & status1::HARDWARE_ERROR != 0, HardwareError);
            check(waste_ink && s & status1::WASTE_INK_FULL != 0, WasteInkFull);
        } else {
            check(s & status1::PRINTER_ERROR != 0, PrinterError);
            check(s & status1::HARDWARE_ERROR != 0, HardwareError);
            check(s & status1::DOOR_OPEN != 0, DoorOpen);
            check(s & status1::WASTE_INK_FULL != 0, WasteInkFull);
        }
        let ink_out = if self.is_1200_series() { Holding } else { InkOut };
        check(e & status2::CARTRIDGE_JAMMED != 0, CartridgeJammed);
        check(e & status2::INK_OUT != 0, ink_out);
        check(e & status2::OUT_OF_PAPER != 0, OutOfPaper);
        check(e & status2::PAPER_JAM != 0, PaperJam);
        check(e & (status2::PRINTER_ERROR | status2::PRINTER_ERROR_HIGH) != 0, CheckConnections);
        check(e & status2::CARTRIDGE_MISSING != 0, CartridgeMissing);
        check(e & status2::PAPER_TOO_SMALL != 0, PaperTooSmall);
        faults
    }
}

pub(super) fn faults_text(faults: &[PrinterFault]) -> String {
    faults.iter().map(|f| f.message()).collect::<Vec<_>>().join("; ")
}

/// What [`super::StyleWriterSession::query_info`] found out about a printer.
#[derive(Debug, Clone)]
pub struct StyleWriterInfo {
    /// Raw reply to the `?` identify command ("IJ10", "SW", "SW3", "CS", …).
    pub identity: String,
    /// Color StyleWriter submodel from status query 'p' (0x01 = 2400, 0x02 =
    /// 2200, 0x04 = 1500, 0x05 = 2500), or `None` for the others or no reply.
    pub submodel: Option<u8>,
    /// Status 'H' reported a color cartridge.
    pub color_cartridge: bool,
    /// Raw reply to status query 'H' (0x01 = black cartridge, 0x81 = color).
    pub config_raw: Option<u8>,
    /// Raw reply to status query '1'. See [`core::status1`].
    pub status_general: Option<u8>,
    /// Raw reply to status query '2'. See [`core::status2`].
    pub status_error: Option<u8>,
    /// Raw reply to status query 'B', the free buffer space, which reads
    /// differently on every model. See [`Self::buffer_idle`].
    pub status_buffer: Option<u8>,
}

impl StyleWriterInfo {
    /// The model's name, or a plain "Apple StyleWriter" for an identify string
    /// no StyleWriter is known to send.
    pub fn model_name(&self) -> &'static str {
        core::model_name(self.identity.as_bytes(), self.submodel).unwrap_or("Apple StyleWriter")
    }

    /// How to print to this printer. `None` for an identify string no
    /// StyleWriter sends, which no job prints to.
    pub fn family(&self) -> Option<StyleWriterFamily> {
        StyleWriterFamily::from_identity(&self.identity, self.submodel)
    }

    /// Whether it can print color, which needs a Color StyleWriter whose 'H'
    /// reply says colour is installed.
    pub fn color_capable(&self) -> bool {
        self.family().is_some_and(StyleWriterFamily::can_print_color) && self.color_cartridge
    }

    /// What status '1' and '2' report, read as a Color StyleWriter's for a
    /// printer of no known family.
    pub fn faults(&self) -> Vec<PrinterFault> {
        self.family().unwrap_or_default().faults(self.status_general, self.status_error)
    }

    /// Status '1' and '2' for the user.
    pub fn error_text(&self) -> String {
        let faults = self.faults();
        if faults.is_empty() {
            "Ready, no error reported".to_string()
        } else {
            faults_text(&faults)
        }
    }

    /// Whether the printer reports being out of paper.
    pub fn out_of_paper(&self) -> bool {
        self.faults().contains(&PrinterFault::OutOfPaper)
    }

    /// Whether the print buffer reads empty, by the model's own reading.
    /// `None` when the printer didn't answer, or is of no known family.
    pub fn buffer_idle(&self) -> Option<bool> {
        let b = self.status_buffer?;
        Some(self.family()?.buffer_idle(b, self.color_cartridge))
    }

    /// Which ink cartridge is in, by status 'H'.
    pub fn cartridge_text(&self) -> &'static str {
        match self.config_raw {
            None => "unknown (no response)",
            Some(_) if self.color_cartridge => "Color (CMYK)",
            Some(_) => "Black only",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use PrinterFault::*;
    use StyleWriterFamily::*;

    const CS2200: StyleWriterFamily = Color(ColorModel::Cs2200);

    /// A Color StyleWriter 2200 that answered 'H' with `config`, '2' with
    /// `err` and 'B' with `buf`.
    fn cs_info(config: Option<u8>, err: Option<u8>, buf: Option<u8>) -> StyleWriterInfo {
        StyleWriterInfo {
            identity: "CS".to_string(),
            submodel: Some(0x02),
            color_cartridge: config == Some(0x81),
            config_raw: config,
            status_general: Some(0x00),
            status_error: err,
            status_buffer: buf,
        }
    }

    /// Each series names the bits it sets. Busy and printed are progress, not
    /// faults, and no reply is not a reply of zero.
    #[test]
    fn faults_follow_each_series_bits() {
        assert_eq!(
            CS2200.faults(Some(0x02 | 0x04 | 0x40 | 0x80), Some(0x00)),
            vec![PrinterError, HardwareError, DoorOpen, WasteInkFull]
        );
        assert_eq!(
            CS2200.faults(Some(0x00), Some(0x7F)),
            vec![CartridgeJammed, InkOut, OutOfPaper, PaperJam, CheckConnections, CartridgeMissing, PaperTooSmall]
        );
        assert!(CS2200.faults(Some(0x01 | 0x08), Some(0x00)).is_empty());
        // 0x80 of '2' is an error in the printer on every model.
        for model in [ColorModel::Cs2200, ColorModel::Cs2400, ColorModel::Cs2500, ColorModel::Unknown] {
            assert_eq!(Color(model).faults(Some(0x00), Some(0x80)), vec![CheckConnections], "{model:?}");
        }

        let cs1500 = Color(ColorModel::Cs1500);
        for family in [StyleWriterII, StyleWriter1200, Original, cs1500] {
            assert_eq!(
                family.faults(Some(0x02 | 0x04), Some(0xFF)),
                vec![
                    Holding,
                    HardwareError,
                    CartridgeJammed,
                    OutOfPaper,
                    PaperJam,
                    CheckConnections,
                    CartridgeMissing,
                    PaperTooSmall
                ],
                "{family:?}"
            );
            assert_eq!(family.faults(Some(0x00), Some(0x80)), vec![CheckConnections]);
            assert!(family.faults(Some(0x01 | 0x08 | 0x40), Some(0x00)).is_empty());
        }
        // Only the 1500 has a waste ink container to report.
        assert_eq!(cs1500.faults(Some(0x80), Some(0x00)), vec![WasteInkFull]);
        assert!(StyleWriterII.faults(Some(0x80), Some(0x00)).is_empty());

        assert_eq!(CS2200.faults(None, Some(0x00)), vec![NoResponse]);
    }

    #[test]
    fn only_a_color_stylewriter_with_a_color_cartridge_prints_color() {
        let color = cs_info(Some(0x81), None, None);
        assert!(color.color_capable());
        assert!(!cs_info(Some(0x01), None, None).color_capable());
        // Not even with bit 0x80 of 'H' set.
        let original = StyleWriterInfo { identity: "IJ10".to_string(), submodel: None, ..color };
        assert!(!original.color_capable());
    }

}
