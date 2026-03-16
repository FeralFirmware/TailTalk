pub struct StyleWriterEncoder;

// StyleWriter Encoding Protocol Constants
pub const MAX_RUN: u8 = 0x3E;
pub const MAX_BLOCK: u8 = 0x3E;
pub const RUN_THRESH: u8 = 0x01;
pub const DATA_WHITE: u8 = 0x00;
pub const DATA_BLACK: u8 = 0xFF;
pub const MASK_RUNWHT: u8 = 0x80;
pub const MASK_RUNBLK: u8 = 0xC0;

impl StyleWriterEncoder {
    /// Create the bounding box header (`R` for monochrome, `c` for color)
    pub fn encode_rect(top: u16, left: u16, bottom: u16, right: u16, is_color: bool) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9);
        if is_color {
            buf.push(b'c');
        } else {
            buf.push(b'R');
        }
        buf.extend_from_slice(&left.to_le_bytes());
        buf.extend_from_slice(&top.to_le_bytes());
        buf.extend_from_slice(&right.to_le_bytes());
        buf.extend_from_slice(&bottom.to_le_bytes());
        buf
    }

    /// Prepend the Apple `'G'` 2-byte chunk sizes to an encoded RLE block
    pub fn wrap_raster_chunk(encoded_data: &[u8]) -> Vec<u8> {
        let size = encoded_data.len() as u16;
        let mut buf = Vec::with_capacity(4 + size as usize);
        buf.push(b'G');
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(encoded_data);
        buf.push(0x00); // Null terminator required for G blocks
        buf
    }

    /// Encode a single raw bitmap scanline into the proprietary Apple RLE format
    /// Ported directly from lpstyl.c `encodescanline()`
    pub fn encode_scanline(src: &[u8], print_width_bytes: usize) -> Vec<u8> {
        let mut dst = Vec::with_capacity(src.len());

        // SPECIAL CASE: Check for a completely blank line
        if src.iter().all(|&b| b == DATA_WHITE) {
            dst.push(MASK_RUNWHT);
            return dst;
        }

        let mut s = 0;
        let src_len = src.len();

        while s < src_len {
            let mut run_start = 0;
            let mut run_len = 0;
            let mut run_char = 0x0A; // DATA_OTHER (just not black or white)

            // Find the first run
            let mut found_break = false;
            let mut i = s;
            while i < src_len {
                if run_char == DATA_WHITE || run_char == DATA_BLACK {
                    if src[i] != run_char {
                        // This run is over
                        if (i - run_start) >= RUN_THRESH as usize {
                            // Run was long enough to count. Break out.
                            found_break = true;
                            break;
                        } else {
                            run_char = 0x0A; // Too short to count.
                        }
                    } else if (i - run_start) >= MAX_RUN as usize {
                        // Enough of a run to encode
                        found_break = true;
                        break;
                    }
                } else {
                    // run_char == DATA_OTHER
                    if src[i] == DATA_WHITE || src[i] == DATA_BLACK {
                        // Start a run
                        run_char = src[i];
                        run_start = i;
                    } else if (i - s) >= MAX_BLOCK as usize {
                        // Block is maximum length
                        found_break = true;
                        break;
                    }
                }
                i += 1;
            }

            if found_break || run_char != 0x0A {
                if run_char != 0x0A {
                    run_len = i - run_start;
                } else {
                    run_start = i;
                }
            } else {
                run_start = i;
            }

            if run_start != s {
                // Encode a run of random data
                dst.push((run_start - s) as u8);
                while s < run_start {
                    dst.push(src[s]);
                    s += 1;
                }
            }

            if run_len > 0 {
                // Encode a run of black or white
                if run_char == DATA_BLACK {
                    dst.push(MASK_RUNBLK + run_len as u8);
                } else if (s + run_len) < src_len {
                    dst.push(MASK_RUNWHT + run_len as u8);
                } else {
                    break; // Let padding handle it
                }
                s += run_len;
            }
        }

        // Pad out to the width of the page with white
        while s < print_width_bytes {
            let mut run_len = print_width_bytes - s;
            if run_len > MAX_RUN as usize {
                run_len = MAX_RUN as usize;
            }
            dst.push(MASK_RUNWHT + run_len as u8);
            s += run_len;
        }

        dst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_rect() {
        // R (0x52) or c (0x63), then little-endian left, top, right, bottom
        let bw = StyleWriterEncoder::encode_rect(10, 20, 30, 40, false);
        assert_eq!(bw, vec![b'R', 20, 0, 10, 0, 40, 0, 30, 0]);

        let color = StyleWriterEncoder::encode_rect(10, 20, 30, 40, true);
        assert_eq!(color, vec![b'c', 20, 0, 10, 0, 40, 0, 30, 0]);
    }

    #[test]
    fn test_wrap_raster_chunk() {
        let chunk = vec![0xAB, 0xCD, 0xEF];
        let wrapped = StyleWriterEncoder::wrap_raster_chunk(&chunk);

        assert_eq!(wrapped.len(), 7);
        assert_eq!(wrapped[0], b'G');
        assert_eq!(wrapped[1], 0x03); // Length LSB (3 bytes)
        assert_eq!(wrapped[2], 0x00); // Length MSB
        assert_eq!(&wrapped[3..6], &[0xAB, 0xCD, 0xEF]);
        assert_eq!(wrapped.last(), Some(&0x00)); // Null terminator
    }

    #[test]
    fn test_encode_scanline() {
        // Test a pure white line (all 0s)
        let white_line = vec![DATA_WHITE; 100];
        let encoded = StyleWriterEncoder::encode_scanline(&white_line, 100);
        assert_eq!(encoded, vec![MASK_RUNWHT]);

        // Test a line padded with white at the end
        let src = vec![DATA_BLACK, DATA_BLACK, DATA_BLACK]; // 3 black pixels
        let encoded = StyleWriterEncoder::encode_scanline(&src, 10);
        // Expect: MASK_RUNBLK + 3, MASK_RUNWHT + 7
        assert_eq!(encoded, vec![MASK_RUNBLK + 3, MASK_RUNWHT + 7]);

        // Test random data
        let src = vec![0x11, 0x22, 0x33, DATA_WHITE, DATA_WHITE];
        let encoded = StyleWriterEncoder::encode_scanline(&src, 5);
        // Expect: random length 3 | 0x11 | 0x22 | 0x33 | then white pad/run
        assert_eq!(encoded[0], 3); // 3 bytes of raw data
        assert_eq!(&encoded[1..4], &[0x11, 0x22, 0x33]);
        assert_eq!(encoded[4], MASK_RUNWHT + 2); // 2 bytes of white
    }
}
