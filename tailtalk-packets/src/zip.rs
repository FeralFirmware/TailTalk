//! Zone Information Protocol (ZIP) GetNetInfo request/reply.
//!
//! ZIP is how an AppleTalk node discovers which zone it belongs to. A node that
//! has just acquired its DDP node address broadcasts a **GetNetInfo request**
//! (ZIP op 5) to the local routers, including the zone name it currently
//! believes it belongs to (kept in PRAM), or an empty name if it has none. A
//! router answers with a **GetNetInfo reply** (ZIP op 6) carrying the cable's
//! network number range, the zone's multicast address, and — if the requested
//! zone was invalid — the cable's default zone name.
//!
//! ZIP rides on DDP protocol type 6 ([`crate::ddp::DdpProtocolType::Zip`]),
//! delivered to socket 6 ([`ZIP_SOCKET`]) on both ends. This module parses and
//! builds the ZIP payload only, starting at the ZIP operation byte; the DDP type
//! byte lives in the DDP header, not here.
//!
//! Op codes, flag bits, and the wire layout mirror Netatalk's
//! `include/atalk/zip.h` and `bin/getzones/getzones.c`.

use thiserror::Error;

/// ZIP is carried on DDP socket 6 (the ZIP socket) on both ends.
pub const ZIP_SOCKET: u8 = 6;

/// Maximum length of an AppleTalk zone name (`MAX_ZONE_LENGTH` in Netatalk).
pub const MAX_ZONE_LENGTH: usize = 32;

// ZIP operation codes (first byte of the ZIP payload); see ZIPOP_* in zip.h.
const ZIPOP_GNI: u8 = 5;
const ZIPOP_GNIREPLY: u8 = 6;
const ZIPOP_NOTIFY: u8 = 7;

/// GetNetInfo reply flag: the zone name the node supplied is no longer valid;
/// the node should adopt [`GetNetInfoReply::default_zone`] instead.
pub const ZIPGNI_INVALID: u8 = 0x80;
/// GetNetInfo reply flag: the zone has no multicast address; use broadcast for
/// zone-scoped delivery.
pub const ZIPGNI_USE_BROADCAST: u8 = 0x40;
/// GetNetInfo reply flag: this cable carries only a single zone.
pub const ZIPGNI_ONE_ZONE: u8 = 0x20;

#[derive(Error, Debug)]
pub enum ZipError {
    #[error("packet too short: expected at least {expected} bytes but found {found}")]
    TooShort { expected: usize, found: usize },
    #[error("unexpected ZIP operation {found}; expected {expected}")]
    UnexpectedOp { expected: u8, found: u8 },
    #[error("zone name is {length} bytes; the ZIP maximum is {MAX_ZONE_LENGTH}")]
    ZoneTooLong { length: usize },
    #[error("buffer too small: need {needed} bytes but only {available} available")]
    BufferTooSmall { needed: usize, available: usize },
}

/// A ZIP GetNetInfo request (ZIP operation 5), sent node → routers.
///
/// The layout is: op (1) + five reserved zero bytes + a length-prefixed zone
/// name. An empty `zone` means "I have no zone; give me the default".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GetNetInfoRequest {
    /// Zone name the node is asking the router to confirm; empty if it has none.
    pub zone: String,
}

impl GetNetInfoRequest {
    /// Minimum size: op (1) + 5 reserved zero bytes + zone length byte (1).
    const MIN_LEN: usize = 7;

    pub fn parse(buf: &[u8]) -> Result<Self, ZipError> {
        if buf.len() < Self::MIN_LEN {
            return Err(ZipError::TooShort {
                expected: Self::MIN_LEN,
                found: buf.len(),
            });
        }
        if buf[0] != ZIPOP_GNI {
            return Err(ZipError::UnexpectedOp {
                expected: ZIPOP_GNI,
                found: buf[0],
            });
        }
        // buf[1..6] are five reserved bytes, always zero on the wire.
        let (zone, _) = read_pstring(buf, 6)?;
        Ok(Self { zone })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ZipError> {
        let (zone_cow, _, _) = encoding_rs::MACINTOSH.encode(&self.zone);
        if zone_cow.len() > MAX_ZONE_LENGTH {
            return Err(ZipError::ZoneTooLong {
                length: zone_cow.len(),
            });
        }
        let needed = Self::MIN_LEN + zone_cow.len();
        if buf.len() < needed {
            return Err(ZipError::BufferTooSmall {
                needed,
                available: buf.len(),
            });
        }
        buf[0] = ZIPOP_GNI;
        buf[1..6].fill(0);
        write_pbytes(buf, 6, &zone_cow);
        Ok(needed)
    }
}

/// A ZIP GetNetInfo reply (ZIP operation 6), sent router → node.
///
/// Layout: op (1) + flags (1) + network range start (2, big-endian) + network
/// range end (2, big-endian) + length-prefixed echoed zone name +
/// length-prefixed multicast address + optional length-prefixed default zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNetInfoReply {
    /// Flag bits; interpret via [`Self::zone_invalid`], [`Self::use_broadcast`],
    /// and [`Self::one_zone`], or the `ZIPGNI_*` constants.
    pub flags: u8,
    /// First network number of the cable range (equals `range_end` on a
    /// non-extended LocalTalk network).
    pub range_start: u16,
    /// Last network number of the cable range.
    pub range_end: u16,
    /// The zone name echoed back from the request.
    pub zone: String,
    /// Multicast (hardware) address for the zone; empty when the reply sets
    /// [`ZIPGNI_USE_BROADCAST`] or the link has no multicast.
    pub multicast: Vec<u8>,
    /// Default zone name for the cable. Present (and adopted by the node) when
    /// the requested zone was invalid.
    pub default_zone: Option<String>,
}

impl GetNetInfoReply {
    /// Minimum size: op (1) + flags (1) + range start (2) + range end (2) +
    /// zone length byte (1).
    const MIN_LEN: usize = 7;

    /// The zone name the node supplied is invalid; it should adopt
    /// [`Self::default_zone`].
    pub fn zone_invalid(&self) -> bool {
        self.flags & ZIPGNI_INVALID != 0
    }

    /// The zone has no multicast address; zone-scoped traffic must use broadcast.
    pub fn use_broadcast(&self) -> bool {
        self.flags & ZIPGNI_USE_BROADCAST != 0
    }

    /// This cable carries only a single zone.
    pub fn one_zone(&self) -> bool {
        self.flags & ZIPGNI_ONE_ZONE != 0
    }

    pub fn parse(buf: &[u8]) -> Result<Self, ZipError> {
        if buf.len() < Self::MIN_LEN {
            return Err(ZipError::TooShort {
                expected: Self::MIN_LEN,
                found: buf.len(),
            });
        }
        if buf[0] != ZIPOP_GNIREPLY {
            return Err(ZipError::UnexpectedOp {
                expected: ZIPOP_GNIREPLY,
                found: buf[0],
            });
        }
        let flags = buf[1];
        let range_start = u16::from_be_bytes([buf[2], buf[3]]);
        let range_end = u16::from_be_bytes([buf[4], buf[5]]);

        let mut offset = 6;
        let (zone, consumed) = read_pstring(buf, offset)?;
        offset += consumed;
        let (multicast, consumed) = read_pbytes(buf, offset)?;
        let multicast = multicast.to_vec();
        offset += consumed;

        // The default zone is only present when the router chose to send it
        // (typically when the requested zone was invalid). A zero length byte,
        // or no trailing bytes at all, both mean "no default zone".
        let default_zone = if offset < buf.len() {
            let (zone, _) = read_pstring(buf, offset)?;
            (!zone.is_empty()).then_some(zone)
        } else {
            None
        };

        Ok(Self {
            flags,
            range_start,
            range_end,
            zone,
            multicast,
            default_zone,
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ZipError> {
        let (zone, _, _) = encoding_rs::MACINTOSH.encode(&self.zone);
        if zone.len() > MAX_ZONE_LENGTH {
            return Err(ZipError::ZoneTooLong { length: zone.len() });
        }
        let default_zone = self
            .default_zone
            .as_ref()
            .map(|z| encoding_rs::MACINTOSH.encode(z).0);
        if let Some(default_zone) = &default_zone
            && default_zone.len() > MAX_ZONE_LENGTH {
                return Err(ZipError::ZoneTooLong {
                    length: default_zone.len(),
                });
            }

        let needed = 6
            + (1 + zone.len())
            + (1 + self.multicast.len())
            + default_zone.as_ref().map_or(0, |z| 1 + z.len());
        if buf.len() < needed {
            return Err(ZipError::BufferTooSmall {
                needed,
                available: buf.len(),
            });
        }

        buf[0] = ZIPOP_GNIREPLY;
        buf[1] = self.flags;
        buf[2..4].copy_from_slice(&self.range_start.to_be_bytes());
        buf[4..6].copy_from_slice(&self.range_end.to_be_bytes());
        let mut offset = 6;
        offset += write_pbytes(buf, offset, &zone);
        offset += write_pbytes(buf, offset, &self.multicast);
        if let Some(default_zone) = &default_zone {
            offset += write_pbytes(buf, offset, default_zone);
        }
        Ok(offset)
    }
}

/// A ZIP Notify (ZIP operation 7), sent router → node when the zone information
/// for the node's cable changes (e.g. a network renumber). The node should
/// re-run GetNetInfo to refresh its zone.
///
/// The Notify body is intentionally not interpreted: the authoritative new zone
/// comes from the follow-up GetNetInfo reply, so this is treated purely as a
/// trigger (as Netatalk's `atalkd` does).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    /// Flag byte, carried but not interpreted.
    pub flags: u8,
}

impl Notify {
    pub fn parse(buf: &[u8]) -> Result<Self, ZipError> {
        // op (1) + flags (1)
        if buf.len() < 2 {
            return Err(ZipError::TooShort {
                expected: 2,
                found: buf.len(),
            });
        }
        if buf[0] != ZIPOP_NOTIFY {
            return Err(ZipError::UnexpectedOp {
                expected: ZIPOP_NOTIFY,
                found: buf[0],
            });
        }
        Ok(Self { flags: buf[1] })
    }
}

/// Reads a length-prefixed byte string at `offset`: a single length byte
/// followed by that many bytes. Returns the bytes and the total consumed
/// (length byte included).
fn read_pbytes(buf: &[u8], offset: usize) -> Result<(&[u8], usize), ZipError> {
    let len = *buf.get(offset).ok_or(ZipError::TooShort {
        expected: offset + 1,
        found: buf.len(),
    })? as usize;
    let start = offset + 1;
    let end = start + len;
    let slice = buf.get(start..end).ok_or(ZipError::TooShort {
        expected: end,
        found: buf.len(),
    })?;
    Ok((slice, 1 + len))
}

/// Like [`read_pbytes`] but decodes the payload as a MacRoman zone name.
fn read_pstring(buf: &[u8], offset: usize) -> Result<(String, usize), ZipError> {
    let (bytes, consumed) = read_pbytes(buf, offset)?;
    let (name, _, _) = encoding_rs::MACINTOSH.decode(bytes);
    Ok((name.into_owned(), consumed))
}

/// Writes `data` as a length-prefixed byte string at `offset`. The caller must
/// have ensured the buffer is large enough; returns bytes written.
fn write_pbytes(buf: &mut [u8], offset: usize, data: &[u8]) -> usize {
    buf[offset] = data.len() as u8;
    buf[offset + 1..offset + 1 + data.len()].copy_from_slice(data);
    1 + data.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GetNetInfo request with an empty zone name, exactly as embedded in the
    /// `ddp.rs` capture (op 5, five reserved zeros, zero-length zone).
    #[test]
    fn test_getnetinfo_request_empty_zone() {
        const WIRE: &[u8] = &[0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let req = GetNetInfoRequest::parse(WIRE).expect("failed to parse GNI request");
        assert_eq!(req.zone, "");

        let mut buf = [0u8; WIRE.len()];
        let n = req.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(&buf[..n], WIRE);
    }

    #[test]
    fn test_getnetinfo_request_named_zone() {
        let req = GetNetInfoRequest {
            zone: "Bandley3".into(),
        };
        let mut buf = [0u8; 64];
        let n = req.to_bytes(&mut buf).expect("failed to encode");

        // op + 5 zeros + len(8) + "Bandley3"
        assert_eq!(buf[0], ZIPOP_GNI);
        assert_eq!(&buf[1..6], &[0, 0, 0, 0, 0]);
        assert_eq!(buf[6], 8);
        assert_eq!(&buf[7..n], b"Bandley3");

        let round = GetNetInfoRequest::parse(&buf[..n]).expect("failed to parse");
        assert_eq!(round, req);
    }

    /// A non-extended LocalTalk reply: single zone "MyZone", net range 1–1, no
    /// multicast, no default zone.
    #[test]
    fn test_getnetinfo_reply_localtalk() {
        const WIRE: &[u8] = &[
            0x06, // op = GetNetInfo reply
            0x20, // flags = ZIPGNI_ONE_ZONE
            0x00, 0x01, // range start = 1
            0x00, 0x01, // range end = 1
            0x06, b'M', b'y', b'Z', b'o', b'n', b'e', // zone "MyZone"
            0x00, // multicast length = 0
        ];

        let reply = GetNetInfoReply::parse(WIRE).expect("failed to parse GNI reply");
        assert_eq!(reply.flags, ZIPGNI_ONE_ZONE);
        assert!(reply.one_zone());
        assert!(!reply.zone_invalid());
        assert_eq!(reply.range_start, 1);
        assert_eq!(reply.range_end, 1);
        assert_eq!(reply.zone, "MyZone");
        assert!(reply.multicast.is_empty());
        assert_eq!(reply.default_zone, None);

        let mut buf = [0u8; 64];
        let n = reply.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(&buf[..n], WIRE);
    }

    /// An extended reply that invalidates the requested zone and hands back a
    /// multicast address plus a default zone. Exercises every optional field.
    #[test]
    fn test_getnetinfo_reply_invalid_with_default() {
        let reply = GetNetInfoReply {
            flags: ZIPGNI_INVALID,
            range_start: 3,
            range_end: 5,
            zone: "BogusZone".into(),
            multicast: vec![0x09, 0x00, 0x07, 0xff, 0xff, 0xff],
            default_zone: Some("Engineering".into()),
        };

        let mut buf = [0u8; 128];
        let n = reply.to_bytes(&mut buf).expect("failed to encode");
        let round = GetNetInfoReply::parse(&buf[..n]).expect("failed to parse");

        assert_eq!(round, reply);
        assert!(round.zone_invalid());
        assert_eq!(round.multicast.len(), 6);
        assert_eq!(round.default_zone.as_deref(), Some("Engineering"));
    }

    #[test]
    fn test_notify_parse() {
        let notify = Notify::parse(&[0x07, 0x00]).expect("failed to parse Notify");
        assert_eq!(notify.flags, 0);
        // Wrong op is rejected.
        assert!(matches!(
            Notify::parse(&[0x06, 0x00]),
            Err(ZipError::UnexpectedOp { .. })
        ));
        // A GNI reply is not a Notify.
        assert!(GetNetInfoReply::parse(&[0x07, 0x00]).is_err());
    }

    #[test]
    fn test_wrong_op_is_rejected() {
        // A GNI reply fed to the request parser (and vice versa) must fail.
        let reply_bytes = &[0x06, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00];
        assert!(matches!(
            GetNetInfoRequest::parse(reply_bytes),
            Err(ZipError::UnexpectedOp {
                expected: ZIPOP_GNI,
                found: ZIPOP_GNIREPLY
            })
        ));
    }

    #[test]
    fn test_truncated_zone_is_rejected() {
        // Claims an 8-byte zone but only supplies 3.
        let bytes = &[0x05, 0, 0, 0, 0, 0, 0x08, b'a', b'b', b'c'];
        assert!(matches!(
            GetNetInfoRequest::parse(bytes),
            Err(ZipError::TooShort { .. })
        ));
    }
}
