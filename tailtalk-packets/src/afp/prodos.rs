use crate::afp::FinderInfo;

/// Wire length of the ProDOS Info parameter, the same for files and directories.
pub const PRODOS_INFO_LEN: usize = 6;

/// Creator code the spec assigns to any file whose type came from the ProDOS side.
const PDOS_CREATOR: [u8; 4] = *b"pdos";

/// ProDOS Info: the AFP 2.0 file and directory parameter (bit 13 of both bitmaps)
/// that ProDOS workstations use in place of Finder Info.
///
/// Inside AppleTalk chapter 13 calls it a 2-byte file type and a 4-byte aux type,
/// then notes that ProDOS-8 defines them as 1 and 2 bytes with the rest reserved.
/// Figure 13-4 puts the real bytes first, so the aux type is little endian where
/// every other AFP integer is big endian: the reader is a 6502 and copies the
/// field straight into ProDOS memory.
///
/// ```text
///   0  ProDOS file type
///   1  0                    reserved
///   2  aux type, low byte
///   3  aux type, high byte
///   4  0                    reserved
///   5  0                    reserved
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProdosInfo {
    pub file_type: u8,
    pub aux_type: u16,
}

impl ProdosInfo {
    /// Every directory reports file type $0F. The aux type is unrestricted and is
    /// $0200 from creation onward, so with nowhere to store a per-directory value
    /// this constant is the whole of our directory answer.
    pub const DIRECTORY: Self = Self {
        file_type: 0x0F,
        aux_type: 0x0200,
    };

    pub fn to_bytes(self) -> [u8; PRODOS_INFO_LEN] {
        let [aux_high, aux_low] = self.aux_type.to_be_bytes();
        [self.file_type, 0, aux_low, aux_high, 0, 0]
    }

    pub fn from_bytes(raw: [u8; PRODOS_INFO_LEN]) -> Self {
        Self {
            file_type: raw[0],
            aux_type: u16::from_le_bytes([raw[2], raw[3]]),
        }
    }

    /// Derive ProDOS Info from Finder Info, per the Finder-to-ProDOS table in
    /// chapter 13. Four rows of that table leave the aux type "unchanged", which
    /// assumes a server storing both parameters. We keep only Finder Info and
    /// derive this on every read, so those rows report $0000 and only the packed
    /// `'p'XYY` form carries an aux type back out again.
    pub fn from_finder_info(info: &FinderInfo) -> Self {
        // 'TEXT' maps regardless of creator; every other row requires 'pdos'.
        if &info.file_type == b"TEXT" {
            return Self {
                file_type: 0x04,
                aux_type: 0x0000,
            };
        }
        if info.creator != PDOS_CREATOR {
            return Self::default();
        }

        match &info.file_type {
            b"PSYS" => Self {
                file_type: 0xFF,
                aux_type: 0,
            },
            b"PS16" => Self {
                file_type: 0xB3,
                aux_type: 0,
            },
            b"BINA" => Self {
                file_type: 0x00,
                aux_type: 0,
            },
            // Special format #1: 'p', a file type byte, then a two-byte aux type,
            // high order byte first.
            [b'p', file_type, aux_high, aux_low] => Self {
                file_type: *file_type,
                aux_type: u16::from_be_bytes([*aux_high, *aux_low]),
            },
            // Special format #2: a two-character hex number followed by two
            // spaces, e.g. 'B3  '. 'p' is not a hex digit, so this can never
            // collide with the form above.
            [high, low, b' ', b' '] => match hex_byte(*high, *low) {
                Some(file_type) => Self {
                    file_type,
                    aux_type: 0,
                },
                None => Self::default(),
            },
            _ => Self::default(),
        }
    }

    /// The ProDOS-to-Finder table from chapter 13, applied over `current` so that
    /// changing the type doesn't cost the file its flags or icon position.
    pub fn to_finder_info(self, current: &FinderInfo) -> FinderInfo {
        let file_type = match (self.file_type, self.aux_type) {
            (0x04, 0x0000) => *b"TEXT",
            (0xFF, _) => *b"PSYS",
            (0xB3, _) => *b"PS16",
            (0x00, _) => *b"BINA",
            // Everything else packs both fields into the type so the values
            // survive a round trip. That includes $04 with a non-zero aux type,
            // since the text row is specified as $04 paired with $0000.
            (file_type, aux_type) => {
                let [aux_high, aux_low] = aux_type.to_be_bytes();
                [b'p', file_type, aux_high, aux_low]
            }
        };

        FinderInfo {
            file_type,
            creator: PDOS_CREATOR,
            ..*current
        }
    }
}

/// Parse two ASCII hex digits into a byte, for special format #2.
fn hex_byte(high: u8, low: u8) -> Option<u8> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    Some(digit(high)? << 4 | digit(low)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::afp::FinderFlags;

    fn finder(file_type: &[u8; 4], creator: &[u8; 4]) -> FinderInfo {
        FinderInfo {
            file_type: *file_type,
            creator: *creator,
            flags: FinderFlags::IS_INVISIBLE,
            reserved: [0xAB; 22],
        }
    }

    #[test]
    fn byte_layout_matches_the_spec() {
        for (info, bytes) in [
            // The directory constant from chapter 13: type $0F, aux type $0200.
            (ProdosInfo::DIRECTORY, [0x0F, 0x00, 0x00, 0x02, 0x00, 0x00]),
            // Aux type low byte first, so not [.., 0x57, 0x75, ..].
            (
                ProdosInfo {
                    file_type: 0x32,
                    aux_type: 0x5775,
                },
                [0x32, 0x00, 0x75, 0x57, 0x00, 0x00],
            ),
            (ProdosInfo::default(), [0x00; 6]),
        ] {
            assert_eq!(info.to_bytes(), bytes, "{info:?}");
            assert_eq!(ProdosInfo::from_bytes(bytes), info);
        }
    }

    /// The rows of the two chapter 13 tables that name each other, walked both
    /// ways. A wrong row here is silent, the file just turns up on the other side
    /// with a type that won't open.
    #[test]
    fn mapping_table_rows_round_trip() {
        for (file_type, aux_type, fd_type) in [
            (0x04, 0x0000, b"TEXT"),
            (0xFF, 0x0000, b"PSYS"),
            (0xB3, 0x0000, b"PS16"),
            (0x00, 0x0000, b"BINA"),
            // No Finder equivalent, so both fields pack into the type. $04 with
            // an aux type lands here too: the text row is specified as $04 with
            // $0000, and packing keeps the aux type rather than dropping it.
            (0x32, 0x5775, b"p2Wu"),
            (0x04, 0x1234, &[b'p', 0x04, 0x12, 0x34]),
        ] {
            let prodos = ProdosInfo {
                file_type,
                aux_type,
            };
            let current = finder(b"????", b"????");
            let mapped = prodos.to_finder_info(&current);

            assert_eq!(&mapped.file_type, fd_type, "{prodos:?}");
            assert_eq!(&mapped.creator, b"pdos", "{prodos:?}");
            assert_eq!(ProdosInfo::from_finder_info(&mapped), prodos);
            // The rest of the blob has to survive the type change.
            assert_eq!(mapped.flags, current.flags);
            assert_eq!(mapped.reserved, current.reserved);
        }
    }

    /// Rows that only run Finder to ProDOS, including the ones that decline.
    /// 'ptch' is a real Mac type shaped like special format #1, so only the
    /// creator tells the two apart.
    #[test]
    fn finder_types_without_a_reverse_mapping() {
        for (info, expected) in [
            // 'TEXT' is the one row that matches on any creator.
            (finder(b"TEXT", b"ttxt"), ProdosInfo { file_type: 0x04, aux_type: 0 }),
            // Special format #2: two hex digits and two spaces. We never generate
            // it, but a IIgs may send it.
            (finder(b"B3  ", b"pdos"), ProdosInfo { file_type: 0xB3, aux_type: 0 }),
            (finder(b"zz  ", b"pdos"), ProdosInfo::default()),
            (finder(b"ptch", b"MPS "), ProdosInfo::default()),
            (finder(b"APPL", b"MACS"), ProdosInfo::default()),
            (finder(b"PSYS", b"MACS"), ProdosInfo::default()),
        ] {
            assert_eq!(
                ProdosInfo::from_finder_info(&info),
                expected,
                "{:?}/{:?}",
                std::str::from_utf8(&info.file_type),
                std::str::from_utf8(&info.creator)
            );
        }
    }
}
