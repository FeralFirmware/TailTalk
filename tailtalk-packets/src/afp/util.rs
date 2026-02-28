use crate::afp::types::AfpError;
use encoding_rs::MACINTOSH;

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
