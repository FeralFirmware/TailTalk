use crate::afp::types::AfpError;
use encoding_rs::MACINTOSH;

pub const AFP2_MAX_NAME_LEN: usize = 31;

/// Encodes a name to MacRoman and mangles it to fit the AFP 2.x 31-byte limit.
/// Names that already fit are returned as-is. Longer names are mangled to
/// exactly 31 bytes using a CRC-16/CCITT suffix for collision resistance.
///
/// If the name has a `.ext`, the extension is preserved:
///   `<stem>~<XXXX><.ext>` where stem fills the remaining space.
/// If the extension is too long to leave at least one stem byte, or there is
/// no extension, the fallback form is used: `<26 bytes>~<XXXX>`.
pub fn mangle_name(name: &str) -> Vec<u8> {
    let (encoded, _, _) = MACINTOSH.encode(name);
    if encoded.len() <= AFP2_MAX_NAME_LEN {
        return encoded.into_owned();
    }

    let crc = crc16_ccitt(&encoded);
    let crc_hex = format!("{:04X}", crc);
    // MacRoman is single-byte, so byte-level slicing is always on character boundaries.
    const TILDE_AND_CRC: usize = 5; // '~' + 4 hex digits

    // Preserve the file extension when there is room for at least one stem byte.
    if let Some(dot_pos) = encoded.iter().rposition(|&b| b == b'.') {
        let ext = &encoded[dot_pos..]; // includes '.'
        let stem_capacity = AFP2_MAX_NAME_LEN.saturating_sub(TILDE_AND_CRC + ext.len());
        if stem_capacity >= 1 {
            let mut result = Vec::with_capacity(AFP2_MAX_NAME_LEN);
            result.extend_from_slice(&encoded[..stem_capacity]);
            result.push(b'~');
            result.extend_from_slice(crc_hex.as_bytes());
            result.extend_from_slice(ext);
            return result;
        }
    }

    // No extension, or extension too long — use the first 26 bytes of the name.
    let mut result = encoded[..AFP2_MAX_NAME_LEN - TILDE_AND_CRC].to_vec();
    result.push(b'~');
    result.extend_from_slice(crc_hex.as_bytes());
    result
}

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// A utility type for handling Macintosh Pascal strings (1-byte length prefix followed by MacRoman encoded data).
///
/// When decoded from the wire the number of bytes the string occupied is recorded
/// alongside the decoded text. MacRoman decoding is not round-trip length
/// preserving: a byte with no MacRoman mapping comes back from `encoding_rs` as an
/// HTML numeric character reference (the literal ASCII `&#65533;`), so
/// re-encoding a decoded string can be several times longer than the bytes it was
/// read from. Parsers advance their offsets by [`Self::byte_len`], so that value
/// has to be the real wire length or the offset walks past the end of the packet.
#[derive(Debug, Clone, Default)]
pub struct MacString {
    value: String,
    /// Bytes this string occupied on the wire (length prefix included), when it
    /// came from [`TryFrom<&[u8]>`]. `None` for strings built in memory, which
    /// have no wire representation yet.
    wire_len: Option<usize>,
}

/// Compares the decoded text only. `wire_len` records where a string came from,
/// not what it is, so a name parsed off the wire compares equal to the same name
/// built in memory - which is what round-trip encode/decode checks rely on.
impl PartialEq for MacString {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for MacString {}

impl std::hash::Hash for MacString {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl MacString {
    pub fn new(s: String) -> Self {
        Self {
            value: s,
            wire_len: None,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn into_string(self) -> String {
        self.value
    }

    /// Encodes the string to MacRoman and writes it as a Pascal string to the provided buffer.
    /// Returns the number of bytes written (1 byte length + data).
    pub fn bytes(&self, buf: &mut [u8]) -> Result<usize, AfpError> {
        let (encoded, _, _) = MACINTOSH.encode(&self.value);
        let len = encoded.len().min(255);

        if buf.len() < 1 + len {
            return Err(AfpError::InvalidSize);
        }

        buf[0] = len as u8;
        buf[1..1 + len].copy_from_slice(&encoded[..len]);

        Ok(1 + len)
    }

    /// Bytes this Pascal string occupies on the wire, length prefix included.
    ///
    /// For a string decoded from a packet this is exactly the number of bytes
    /// consumed, so parsers can safely use it to advance an offset. For a string
    /// built in memory it falls back to the encoded length, which is what a
    /// subsequent [`Self::bytes`] call would write.
    ///
    /// Use [`Self::encoded_len`] instead when sizing a buffer to encode into:
    /// the two differ whenever the MacRoman round trip is not length preserving.
    pub fn byte_len(&self) -> usize {
        match self.wire_len {
            Some(len) => len,
            None => self.encoded_len(),
        }
    }

    /// Bytes [`Self::bytes`] would write for this string, length prefix included.
    ///
    /// This is the value to size an encode buffer with. It can exceed
    /// [`Self::byte_len`] for a string decoded from bytes that have no MacRoman
    /// round trip.
    pub fn encoded_len(&self) -> usize {
        let (encoded, _, _) = MACINTOSH.encode(&self.value);
        1 + encoded.len().min(255)
    }
}

impl TryFrom<&[u8]> for MacString {
    type Error = AfpError;

    /// Attempts to convert from a byte array to a MacString based on the indicated length.
    /// As part of decoding the string will be decoded from MacRoman to UTF-8. A string length of zero
    /// (i.e buf contains a single byte with a value of 0) is valid and will result in an empty string.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.is_empty() {
            return Err(AfpError::InvalidSize);
        }

        let len = buf[0] as usize;
        if len == 0 {
            // A zero-length name still occupies its length byte.
            return Ok(MacString {
                value: String::new(),
                wire_len: Some(1),
            });
        }

        if buf.len() < 1 + len {
            return Err(AfpError::InvalidSize);
        }

        let string_data = &buf[1..1 + len];
        let (decoded, _, _) = MACINTOSH.decode(string_data);

        Ok(MacString {
            value: decoded.into_owned(),
            // Record what was actually consumed rather than recomputing it from
            // the decoded text, which can re-encode to a different length.
            wire_len: Some(1 + len),
        })
    }
}

impl AsRef<str> for MacString {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

impl std::ops::Deref for MacString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl From<String> for MacString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for MacString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl AsRef<std::ffi::OsStr> for MacString {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(&self.value)
    }
}

impl std::fmt::Display for MacString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name whose bytes have no MacRoman round trip must still report the
    /// number of bytes it actually occupied. `0xFF 0xFE 0x0A` re-encodes to the
    /// literal ASCII `&#65533;`, so the old implementation reported 9 for a
    /// 4-byte field and pushed callers' offsets past the end of the packet.
    #[test]
    fn byte_len_reports_wire_length_not_reencoded_length() {
        let wire: &[u8] = &[3, 0xFF, 0xFE, 0x0A];
        let s = MacString::try_from(wire).expect("should decode");

        assert_eq!(s.byte_len(), 4, "byte_len must be the bytes consumed");
        assert!(
            s.encoded_len() > s.byte_len(),
            "this input is only interesting if re-encoding grows it",
        );
    }

    /// Every valid Pascal string must report a wire length that fits the buffer
    /// it was decoded from, for any length prefix and any byte values.
    #[test]
    fn byte_len_never_exceeds_source_buffer() {
        for len in 0u8..=8 {
            for filler in [0x00u8, 0x41, 0x80, 0xFE, 0xFF] {
                let mut wire = vec![len];
                wire.extend(std::iter::repeat_n(filler, len as usize));
                let s = MacString::try_from(wire.as_slice()).expect("should decode");
                assert!(
                    s.byte_len() <= wire.len(),
                    "byte_len {} exceeds the {}-byte source (len={len}, filler={filler:#04x})",
                    s.byte_len(),
                    wire.len(),
                );
            }
        }
    }

    /// Re-encoding can also *shrink* a name, so no ordering holds between
    /// `byte_len` and `encoded_len`. `0xFF 0xFE` is the UTF-16 byte order mark,
    /// which the decoder consumes whole, leaving an empty string from two wire
    /// bytes. Recomputing `byte_len` from the decoded text would under-report
    /// here just as it over-reports elsewhere.
    #[test]
    fn byte_len_survives_a_name_that_decodes_to_nothing() {
        let wire: &[u8] = &[2, 0xFF, 0xFE];
        let s = MacString::try_from(wire).expect("should decode");

        assert_eq!(s.as_str(), "", "the BOM is consumed by the decoder");
        assert_eq!(s.byte_len(), 3, "byte_len must still be the bytes consumed");
        assert!(s.byte_len() > s.encoded_len(), "re-encoding shrinks this name");
    }

    /// `encoded_len` is the buffer-sizing method, so `bytes` must always fit in
    /// exactly that much space.
    #[test]
    fn encoded_len_sizes_a_buffer_that_bytes_fits() {
        let wire: &[u8] = &[3, 0xFF, 0xFE, 0x0A];
        let s = MacString::try_from(wire).expect("should decode");

        let mut buf = vec![0u8; s.encoded_len()];
        let written = s.bytes(&mut buf).expect("must fit encoded_len bytes");
        assert_eq!(written, s.encoded_len());
    }

    /// Provenance must not leak into equality: the same name compares equal
    /// whether it came off the wire or was built in memory.
    #[test]
    fn equality_ignores_wire_provenance() {
        let parsed = MacString::try_from([5u8, b'M', b'a', b'c', b'O', b'S'].as_slice())
            .expect("should decode");
        let in_memory = MacString::from("MacOS");

        assert_eq!(parsed, in_memory);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let hash = |s: &MacString| {
            let mut h = DefaultHasher::new();
            s.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash(&parsed), hash(&in_memory), "Hash must match Eq");
    }

    #[test]
    fn short_name_passes_through_unchanged() {
        let name = "hello.txt";
        let result = mangle_name(name);
        let (expected, _, _) = MACINTOSH.encode(name);
        assert_eq!(result, expected.as_ref());
        assert!(result.len() <= AFP2_MAX_NAME_LEN);
    }

    #[test]
    fn exactly_31_byte_name_passes_through_unchanged() {
        // 31 ASCII chars → 31 MacRoman bytes, should not be mangled
        let name = "abcdefghijklmnopqrstuvwxyz12345";
        assert_eq!(name.len(), 31);
        let result = mangle_name(name);
        let (expected, _, _) = MACINTOSH.encode(name);
        assert_eq!(result, expected.as_ref());
        assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
    }

    #[test]
    fn name_one_byte_over_limit_is_mangled_to_exactly_31_bytes() {
        // 32 ASCII bytes — the first length that triggers mangling.
        let name = "abcdefghijklmnopqrstuvwxyz123456";
        assert_eq!(name.len(), AFP2_MAX_NAME_LEN + 1);
        let result = mangle_name(name);
        assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
    }

    #[test]
    fn long_name_is_mangled_to_exactly_31_bytes() {
        let name = "This is a very long filename that exceeds the AFP 2.x limit.txt";
        assert!(name.len() > AFP2_MAX_NAME_LEN);
        let result = mangle_name(name);
        assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
    }

    // No extension: the first 26 bytes of the name are followed by ~XXXX.
    #[test]
    fn no_extension_tilde_is_at_byte_26() {
        let name = "This is a very long filename that exceeds the AFP 2x limit noext";
        assert!(!name.contains('.'));
        let result = mangle_name(name);
        assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
        assert_eq!(result[26], b'~');
        let hex = std::str::from_utf8(&result[27..31]).unwrap();
        assert!(
            hex.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')),
            "hex suffix {hex:?} should be 4 uppercase hex digits"
        );
    }

    // Extension present: extension is preserved at the end, ~XXXX precedes it.
    #[test]
    fn extension_is_preserved_in_mangled_name() {
        // "myreallylongsuperamazingfileforme.bin" — 37 bytes, ".bin" extension (4 bytes).
        // stem_capacity = 31 - 5 - 4 = 22 → first 22 bytes of stem + ~XXXX + .bin = 31.
        let name = "myreallylongsuperamazingfileforme.bin";
        assert!(name.len() > AFP2_MAX_NAME_LEN);
        let result = mangle_name(name);
        assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
        assert!(result.ends_with(b".bin"), "extension must be preserved");
        // The five bytes before the extension must be ~XXXX.
        let before_ext = &result[..AFP2_MAX_NAME_LEN - 4]; // strip ".bin"
        assert_eq!(before_ext[before_ext.len() - 5], b'~');
        let hex = std::str::from_utf8(&before_ext[before_ext.len() - 4..]).unwrap();
        assert!(
            hex.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')),
            "hex suffix {hex:?} should be 4 uppercase hex digits"
        );
    }

    #[test]
    fn extension_too_long_falls_back_to_no_extension_form() {
        // Extension of 27 bytes leaves no room for even a 1-byte stem.
        let name = "ab.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // ext > 25 bytes
        let (encoded, _, _) = MACINTOSH.encode(name);
        let ext_len = encoded.len() - encoded.iter().rposition(|&b| b == b'.').unwrap();
        assert!(ext_len > AFP2_MAX_NAME_LEN - 5 - 1, "pre-condition: extension too long");

        if encoded.len() > AFP2_MAX_NAME_LEN {
            let result = mangle_name(name);
            assert_eq!(result.len(), AFP2_MAX_NAME_LEN);
            // Falls back: last byte is a hex digit, not part of an extension.
            assert!(result[26] == b'~');
        }
    }

    #[test]
    fn mangle_is_deterministic() {
        let name = "This is a very long filename that exceeds the AFP 2.x limit.txt";
        assert_eq!(mangle_name(name), mangle_name(name));
    }

    #[test]
    fn different_long_names_produce_different_mangles() {
        // Names share the same stem prefix after truncation; only the CRC suffix differentiates them.
        let a = mangle_name("This is a very long filename that exceeds limit - version A.txt");
        let b = mangle_name("This is a very long filename that exceeds limit - version B.txt");
        assert_ne!(a, b, "CRC suffix should differ for distinct long names");
    }
}
