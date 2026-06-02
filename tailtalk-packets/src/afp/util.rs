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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacString(String);

impl MacString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Encodes the string to MacRoman and writes it as a Pascal string to the provided buffer.
    /// Returns the number of bytes written (1 byte length + data).
    pub fn bytes(&self, buf: &mut [u8]) -> Result<usize, AfpError> {
        let (encoded, _, _) = MACINTOSH.encode(&self.0);
        let len = encoded.len().min(255);

        if buf.len() < 1 + len {
            return Err(AfpError::InvalidSize);
        }

        buf[0] = len as u8;
        buf[1..1 + len].copy_from_slice(&encoded[..len]);

        Ok(1 + len)
    }

    /// Returns the length in bytes of the MacRoman encoded Pascal string (1 byte length prefix + data).
    pub fn byte_len(&self) -> usize {
        let (encoded, _, _) = MACINTOSH.encode(&self.0);
        let len = encoded.len().min(255);
        1 + len
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
            return Ok(MacString(String::new()));
        }

        if buf.len() < 1 + len {
            return Err(AfpError::InvalidSize);
        }

        let string_data = &buf[1..1 + len];
        let (decoded, _, _) = MACINTOSH.decode(string_data);

        Ok(MacString(decoded.into_owned()))
    }
}

impl AsRef<str> for MacString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for MacString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<String> for MacString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for MacString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<std::ffi::OsStr> for MacString {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(&self.0)
    }
}

impl std::fmt::Display for MacString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
