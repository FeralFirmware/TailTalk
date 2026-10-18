//! The raster format. A band goes to the printer as a rect naming the rows
//! it covers, then its rows in one or more `G` blocks. Each row is run-length
//! coded a plane at a time, and every row of a band but its first goes as its
//! difference from the row before, on every StyleWriter but the original.

use super::StyleWriterFamily;
use super::raster::RawBand;

/// The 4 bytes a G block adds to its raster, which are `G`, the u16 length, and
/// the trailing byte.
pub(super) const G_FRAMING: usize = 4;

/// The longest count one code carries.
const MAX_RUN: usize = 0x3E;
const DATA_WHITE: u8 = 0x00;
const DATA_BLACK: u8 = 0xFF;
/// A count of bytes copied as they are, from the bytes that follow.
const MASK_LITERAL: u8 = 0x00;
/// A count of one byte, the one that follows.
const MASK_REPEAT: u8 = 0x40;
/// A count of white bytes.
const MASK_RUNWHT: u8 = 0x80;
/// A count of black bytes.
const MASK_RUNBLK: u8 = 0xC0;

/// What a band carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandKind {
    /// Black alone, in one plane, under an `R` rect.
    Mono,
    /// Cyan, magenta, yellow and black, in four planes, under a `c` rect.
    Color,
}

impl BandKind {
    pub const fn planes(self) -> usize {
        match self {
            BandKind::Mono => 1,
            BandKind::Color => 4,
        }
    }

    /// The letter its rect starts with.
    pub const fn tag(self) -> u8 {
        match self {
            BandKind::Mono => b'R',
            BandKind::Color => b'c',
        }
    }
}

/// One band, coded. It holds the rows it covers from `top` down, each with all
/// its planes coded one after another.
#[derive(Debug, Clone)]
pub struct Band {
    pub top: u16,
    /// Dots across.
    pub width: u16,
    pub kind: BandKind,
    pub rows: Vec<Vec<u8>>,
}

impl Band {
    /// The last row the band covers.
    pub fn bottom(&self) -> u16 {
        self.top + self.rows.len().saturating_sub(1) as u16
    }

    /// Bytes in one plane of a row.
    pub fn row_bytes(&self) -> usize {
        usize::from(self.width).div_ceil(8)
    }
}

/// Code a band's rows. Every plane is padded with white to the band's width,
/// and every row after the band's first is XOR'd with the one before it
/// first, on every StyleWriter but the original.
pub fn encode_band(raw: &RawBand, family: StyleWriterFamily) -> Band {
    let row_bytes = raw.width.div_ceil(8);
    let padded = |plane: &[u8]| {
        let mut row = plane.to_vec();
        row.resize(row_bytes, DATA_WHITE);
        row
    };
    let mut rows = Vec::with_capacity(raw.rows.len());
    let mut last: Option<&Vec<Vec<u8>>> = None;
    for planes in &raw.rows {
        let mut coded = Vec::new();
        for (i, plane) in planes.iter().enumerate() {
            let mut row = padded(plane);
            if family.delta_rows()
                && let Some(last) = last
            {
                for (byte, before) in row.iter_mut().zip(padded(&last[i])) {
                    *byte ^= before;
                }
            }
            coded.extend_from_slice(&scanline(&row, row_bytes));
        }
        rows.push(coded);
        last = Some(planes);
    }
    Band {
        top: raw.top as u16,
        width: raw.width as u16,
        kind: raw.kind,
        rows,
    }
}

/// A band's rows in the `G` blocks they go out in when the printer always has
/// room for them. A block goes once it grows past `room` bytes, framing
/// included, with the row that took it past.
pub fn band_blocks(band: &Band, room: usize) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut block = Vec::new();
    for row in &band.rows {
        block.extend_from_slice(row);
        if block.len() + G_FRAMING > room {
            blocks.push(g_block(&std::mem::take(&mut block)));
        }
    }
    if !block.is_empty() {
        blocks.push(g_block(&block));
    }
    blocks
}

/// Unpack one chunky (4bpp, nibble bits 8=C 4=M 2=Y 1=K) scanline into raw
/// CMYK planes.
pub fn chunky_to_planes(chunky: &[u8], planar_input_len: usize) -> [Vec<u8>; 4] {
    let mut planes = [
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
        Vec::with_capacity(planar_input_len),
    ];
    for chunk_block in chunky.chunks(4) {
        let (mut c, mut m, mut y, mut k) = (0u8, 0u8, 0u8, 0u8);
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            c = (c << 2) | ((b >> 6) & 2) | ((b >> 3) & 1);
            m = (m << 2) | ((b >> 5) & 2) | ((b >> 2) & 1);
            y = (y << 2) | ((b >> 4) & 2) | ((b >> 1) & 1);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        planes[0].push(c);
        planes[1].push(m);
        planes[2].push(y);
        planes[3].push(k);
    }
    planes
}

/// Unpack one chunky scanline's K bits alone into a raw plane.
pub fn chunky_to_mono_plane(chunky: &[u8], planar_input_len: usize) -> Vec<u8> {
    let mut plane = Vec::with_capacity(planar_input_len);
    for chunk_block in chunky.chunks(4) {
        let mut k = 0u8;
        for i in 0..4 {
            let b = chunk_block.get(i).copied().unwrap_or(0);
            k = (k << 2) | ((b >> 3) & 2) | (b & 1);
        }
        plane.push(k);
    }
    plane
}

/// The rect ahead of a band's blocks. It is the letter `R` or `c`, then
/// little-endian left, top, right and bottom, all inclusive. The printer waits
/// until every row up to the bottom one has arrived.
pub fn rect(tag: u8, left: u16, top: u16, right: u16, bottom: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(9);
    buf.push(tag);
    for edge in [left, top, right, bottom] {
        buf.extend_from_slice(&edge.to_le_bytes());
    }
    buf
}

/// Frame coded rows as a raster block, which is `G`, the u16 little-endian
/// length, the rows, and a trailing zero byte.
pub fn g_block(coded: &[u8]) -> Vec<u8> {
    debug_assert!(coded.len() <= u16::MAX as usize, "G block length {} overflows its size field", coded.len());
    let mut buf = Vec::with_capacity(G_FRAMING + coded.len());
    buf.push(b'G');
    buf.extend_from_slice(&(coded.len() as u16).to_le_bytes());
    buf.extend_from_slice(coded);
    buf.push(0x00);
    buf
}

/// Code one plane of a row, after padding it with white to `width_bytes`.
///
/// Each code carries a count of 1 to 62 in its low six bits and a kind in its
/// top two. 0x00 copies that many bytes that follow, 0x40 repeats the one byte
/// that follows, and 0x80 and 0xC0 are runs of white and black. A run starts at
/// a pair of white or black bytes. A repeat starts at three of any other byte
/// with at least five bytes left in the row. A blank plane is the single byte
/// 0x80.
pub fn scanline(src: &[u8], width_bytes: usize) -> Vec<u8> {
    let mut row = src.to_vec();
    row.resize(width_bytes, DATA_WHITE);
    if row.iter().all(|&b| b == DATA_WHITE) {
        return vec![MASK_RUNWHT];
    }
    let mut out = Vec::new();
    let mut p = 0;
    while p < row.len() {
        let remaining = row.len() - p;
        if remaining == 1 {
            out.push(MASK_LITERAL + 1);
            out.push(row[p]);
            break;
        }
        let (a, b) = (row[p], row[p + 1]);
        // Scan on from the third byte, with `left` more bytes allowed in this
        // code's count.
        let mut q = p + 2;
        let mut left = remaining.min(MAX_RUN) - 2;
        if a == b && (a == DATA_WHITE || a == DATA_BLACK) {
            while left > 0 && row[q] == a {
                q += 1;
                left -= 1;
            }
            let mask = if a == DATA_WHITE { MASK_RUNWHT } else { MASK_RUNBLK };
            out.push(mask + (q - p) as u8);
        } else if a == b && left >= 3 && row[q] == b {
            while left > 0 && row[q] == b {
                q += 1;
                left -= 1;
            }
            out.push(MASK_REPEAT + (q - p) as u8);
            out.push(b);
        } else {
            // Literal bytes, up to the next pair of white or black bytes or
            // three of any other.
            let mut prev = b;
            while left > 0 {
                let c = row[q];
                q += 1;
                left -= 1;
                if c != prev {
                    prev = c;
                    continue;
                }
                if c == DATA_WHITE || c == DATA_BLACK || (left > 0 && row[q] == c) {
                    q -= 2;
                    break;
                }
            }
            out.push(MASK_LITERAL + (q - p) as u8);
            out.extend_from_slice(&row[p..q]);
        }
        p = q;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailtalk_core::stylewriter::ColorModel;

    const CS2200: StyleWriterFamily = StyleWriterFamily::Color(ColorModel::Cs2200);

    /// Decode [`scanline`]'s output back to a row `width` bytes wide.
    fn decode(enc: &[u8], width: usize) -> Vec<u8> {
        if enc == [MASK_RUNWHT] {
            return vec![0; width];
        }
        let mut out = Vec::new();
        let mut i = 0;
        while i < enc.len() {
            let n = (enc[i] & 0x3F) as usize;
            assert!((1..=62).contains(&n), "count {n} at {i}");
            match enc[i] & 0xC0 {
                MASK_LITERAL => {
                    out.extend_from_slice(&enc[i + 1..i + 1 + n]);
                    i += 1 + n;
                }
                MASK_REPEAT => {
                    out.extend(std::iter::repeat_n(enc[i + 1], n));
                    i += 2;
                }
                MASK_RUNWHT => {
                    out.extend(std::iter::repeat_n(DATA_WHITE, n));
                    i += 1;
                }
                _ => {
                    out.extend(std::iter::repeat_n(DATA_BLACK, n));
                    i += 1;
                }
            }
        }
        out
    }

    fn raw_band(kind: BandKind, width: usize, rows: Vec<Vec<Vec<u8>>>) -> RawBand {
        RawBand { top: 10, width, kind, rows }
    }

    /// A band goes as its rect, then its rows in `G` blocks. A block goes once
    /// it is past the room, with the row that took it past, and what is left
    /// goes as the last block.
    #[test]
    fn bands_go_out_as_a_rect_then_g_blocks() {
        assert_eq!(rect(b'R', 20, 10, 40, 30), [b'R', 20, 0, 10, 0, 40, 0, 30, 0]);
        assert_eq!(rect(BandKind::Color.tag(), 20, 10, 40, 30)[0], b'c');
        assert_eq!(g_block(&[0xAB, 0xCD, 0xEF]), [b'G', 3, 0, 0xAB, 0xCD, 0xEF, 0]);

        let band = Band { top: 0, width: 8, kind: BandKind::Mono, rows: vec![vec![1; 10]; 5] };
        let blocks = band_blocks(&band, G_FRAMING + 25);
        let sizes: Vec<usize> = blocks.iter().map(|b| b.len() - G_FRAMING).collect();
        assert_eq!(sizes, [30, 20]);
        assert_eq!(band_blocks(&band, 1000).len(), 1);
    }

    /// Each kind of code where it belongs, and every row coded so it decodes
    /// back to itself.
    #[test]
    fn scanline_coding() {
        // A blank row, whichever plane, is the single white code.
        assert_eq!(scanline(&[0; 10], 365), vec![MASK_RUNWHT]);
        // Black, then padding to the width in white runs of at most 62.
        assert_eq!(scanline(&[0xFF; 3], 70), vec![MASK_RUNBLK + 3, MASK_RUNWHT + 62, MASK_RUNWHT + 5]);
        // Three or more of another byte repeat, and two stay literal.
        assert_eq!(scanline(&[0x55; 5], 5), vec![MASK_REPEAT + 5, 0x55]);
        assert_eq!(scanline(&[0x11, 0x55, 0x55, 0x22], 4), vec![4, 0x11, 0x55, 0x55, 0x22]);
        // A literal stops before a white pair or a repeat.
        assert_eq!(scanline(&[0x11, 0x22, 0, 0], 4), vec![2, 0x11, 0x22, MASK_RUNWHT + 2]);
        assert_eq!(
            scanline(&[0x11, 0x22, 0x33, 0x33, 0x33, 0x33, 0x33], 7),
            vec![2, 0x11, 0x22, MASK_REPEAT + 5, 0x33]
        );
        // A last lone byte is a literal of one.
        assert_eq!(scanline(&[0xFF, 0xFF, 0x12], 3), vec![MASK_RUNBLK + 2, 1, 0x12]);

        let mut seed = 0x1234_5678u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for _ in 0..500 {
            // Runs of a few likely bytes, so every code turns up.
            let len = (next() % 400) as usize;
            let mut row = Vec::with_capacity(len);
            while row.len() < len {
                let byte = [0x00, 0xFF, 0x55, (next() & 0xFF) as u8][(next() % 4) as usize];
                let run = 1 + (next() % 80) as usize;
                row.extend(std::iter::repeat_n(byte, run.min(len - row.len())));
            }
            let width = len.max(365);
            let mut want = row.clone();
            want.resize(width, 0);
            assert_eq!(decode(&scanline(&row, width), width), want);
        }
    }

    /// Rows are coded at the band's own width, with every plane of a color row
    /// in turn. Each row after the first goes as its difference from the one
    /// before, except on the original StyleWriter, which takes every row whole.
    #[test]
    fn bands_are_coded_at_their_width_with_each_familys_delta() {
        let row = vec![vec![0x11, 0x22, 0x33]];
        let band = encode_band(&raw_band(BandKind::Mono, 20, vec![row.clone(), row.clone()]), CS2200);
        assert_eq!((band.top, band.bottom(), band.row_bytes()), (10, 11, 3));
        assert_eq!(decode(&band.rows[0], 3), [0x11, 0x22, 0x33]);
        // The same row again XORs to blank.
        assert_eq!(band.rows[1], [MASK_RUNWHT]);
        // Pixels past the width are padding.
        let narrow = encode_band(&raw_band(BandKind::Mono, 9, vec![vec![vec![0xFF]]]), CS2200);
        assert_eq!(decode(&narrow.rows[0], 2), [0xFF, 0x00]);

        let planes = vec![vec![0x80; 2], vec![0; 2], vec![0; 2], vec![0; 2]];
        let color = encode_band(&raw_band(BandKind::Color, 16, vec![planes]), CS2200);
        assert!(color.rows[0].ends_with(&[MASK_RUNWHT, MASK_RUNWHT, MASK_RUNWHT]), "{:?}", color.rows[0]);

        let raw = raw_band(BandKind::Mono, 24, vec![row.clone(), row]);
        let original = encode_band(&raw, StyleWriterFamily::Original);
        assert_eq!(original.rows[0], original.rows[1]);
        let ii = encode_band(&raw, StyleWriterFamily::StyleWriterII);
        assert_eq!(ii.rows[1], [MASK_RUNWHT]);
    }

}
