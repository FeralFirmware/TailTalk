//! Capacity bounds for the fixed-size containers used across the packet types.
//!
//! Every bound here comes from the AppleTalk wire format itself, so a packet
//! that parses at all fits within these limits.

/// Largest DDP datagram payload: the 599-byte datagram minus its 13-byte header.
pub const DDP_MAX_PAYLOAD: usize = 586;

/// Longest entity-name component NBP can express with its 1-byte length prefix.
pub const MAX_NBP_NAME: usize = 32;

/// NBP packs the tuple count into the low nibble of the control byte.
pub const MAX_NBP_TUPLES: usize = 15;

/// Smallest RTMP routing tuple: network number (2 bytes) plus distance (1 byte).
const RTMP_MIN_TUPLE_LEN: usize = 3;

/// Sender info preceding the tuples: network number (2 bytes), ID length, node ID.
const RTMP_SENDER_INFO_LEN: usize = 4;

/// Most routing tuples an RTMP Data packet can carry in one DDP datagram.
pub const MAX_RTMP_TUPLES: usize = (DDP_MAX_PAYLOAD - RTMP_SENDER_INFO_LEN) / RTMP_MIN_TUPLE_LEN;

/// Hardware multicast address length on EtherTalk.
pub const MAX_MULTICAST_LEN: usize = 6;

/// An entity-name component, held in the MacRoman encoding it has on the wire.
///
/// MacRoman is not a subset of UTF-8, so names such as `Microsoft(r) Windows(tm)`
/// are not valid UTF-8 once encoded. Storing the wire bytes keeps those names
/// intact; use [`MacRomanStr::decode`] to render one as text.
pub type NbpName = MacRomanStr<MAX_NBP_NAME>;

/// A zone name bounded by the ZIP limit, held in its on-the-wire MacRoman encoding.
pub type ZoneName = MacRomanStr<{ crate::zip::MAX_ZONE_LENGTH }>;

/// Worst-case UTF-8 expansion when decoding MacRoman: every byte can become a
/// 3-byte code point.
pub const UTF8_EXPANSION: usize = 3;

/// Buffer size that holds any name in this module once decoded to UTF-8.
pub const MAX_NAME_UTF8_LEN: usize = MAX_NBP_NAME * UTF8_EXPANSION;

/// A multicast address as carried in a ZIP GetNetInfo reply.
pub type MulticastAddr = heapless::Vec<u8, MAX_MULTICAST_LEN, u8>;

/// A length-bounded string stored in the MacRoman encoding used on the AppleTalk wire.
///
/// The bytes are kept exactly as they appear in the packet, so encoding a parsed
/// name reproduces the original datagram byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacRomanStr<const N: usize> {
    bytes: [u8; N],
    len: u8,
}

impl<const N: usize> MacRomanStr<N> {
    /// Builds a name from its on-the-wire MacRoman bytes.
    pub fn from_wire(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > N {
            return None;
        }
        let mut stored = [0u8; N];
        stored[..bytes.len()].copy_from_slice(bytes);
        Some(Self {
            bytes: stored,
            len: bytes.len() as u8,
        })
    }

    /// Encodes UTF-8 text into MacRoman. Returns `None` if the text does not
    /// fit, or contains characters MacRoman cannot represent.
    pub fn from_text(text: &str) -> Option<Self> {
        let mut stored = [0u8; N];
        let encoder = &mut encoding_rs::MACINTOSH.new_encoder();
        let (result, _, written) = encoder.encode_from_utf8_without_replacement(text, &mut stored, true);
        match result {
            encoding_rs::EncoderResult::InputEmpty => Some(Self {
                bytes: stored,
                len: written as u8,
            }),
            _ => None,
        }
    }

    /// The name as it appears on the wire.
    pub fn as_wire(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Decodes the name to UTF-8 in `buf`, which must hold [`UTF8_EXPANSION`]
    /// bytes per wire byte. Returns `None` if `buf` is too small.
    pub fn decode<'b>(&self, buf: &'b mut [u8]) -> Option<&'b str> {
        let decoder = &mut encoding_rs::MACINTOSH.new_decoder_without_bom_handling();
        let (result, _, written) =
            decoder.decode_to_utf8_without_replacement(self.as_wire(), buf, true);
        match result {
            encoding_rs::DecoderResult::InputEmpty => {
                core::str::from_utf8(&buf[..written]).ok()
            }
            _ => None,
        }
    }
}

impl<const N: usize> Default for MacRomanStr<N> {
    fn default() -> Self {
        Self { bytes: [0; N], len: 0 }
    }
}

impl<const N: usize> TryFrom<&str> for MacRomanStr<N> {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_text(value).ok_or(())
    }
}

impl<const N: usize> core::fmt::Display for MacRomanStr<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut buf = [0u8; MAX_NAME_UTF8_LEN];
        match self.decode(&mut buf) {
            Some(text) => f.write_str(text),
            None => Err(core::fmt::Error),
        }
    }
}

#[cfg(feature = "std")]
impl<const N: usize> MacRomanStr<N> {
    /// Decodes the name to an owned UTF-8 string, replacing anything MacRoman
    /// cannot round-trip.
    pub fn to_utf8_string(&self) -> String {
        encoding_rs::MACINTOSH.decode(self.as_wire()).0.into_owned()
    }
}
