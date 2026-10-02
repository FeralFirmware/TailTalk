//! The InkTalk control protocol, which we carry over ADSP on
//! `<name>:InkTalk@*`.
//!
//! The client we have in mind is a 68k Mac running System 6 or later (only because
//! that is the first version that actually supports ADSP), so the format is laid
//! out to be easy to use from those. Everything is big-endian, every 16 and 32-bit
//! field sits on an even offset (so a plain `struct` or `RECORD` lines up with the wire),
//! commands and tags are four character `OSType` codes, strings are Str31
//! Pascal strings and results are `OSErr` codes.
//!
//! Each frame is one ADSP message, and ADSP's end-of-message flag is what
//! marks where it ends. A Mac client sends one with a single `dspWrite`
//! with `eom` set, and reads one with a single `dspRead` into a buffer of
//! [`MAX_FRAME_LEN`] bytes.
//!
//! A frame is a fixed header followed by tagged items:
//!
//! ```text
//! UInt16  seq       chosen by the client, echoed in the reply
//! OSType  command   'HELO' 'INFO' 'SETC' 'BOOT'
//! OSErr   result    0 in requests, the outcome in replies
//!
//! then, to the end of the message:
//! OSType  tag
//! UInt16  size      data bytes, not counting the pad
//! data              padded with one zero byte if `size` is odd
//! ```
//!
//! Readers skip any tag they don't know, which lets us add new ones later
//! without breaking older clients.

#![cfg_attr(not(test), no_std)]

/// Bumped when an existing command or tag changes meaning. Adding tags or
/// commands does not bump it.
pub const PROTOCOL_VERSION: u16 = 1;

/// The NBP type the control listener registers under.
pub const NBP_TYPE: &str = "InkTalk";

/// Header bytes.
pub const HEADER_LEN: usize = 8;

/// Item header bytes: tag and size.
pub const ITEM_HEADER_LEN: usize = 6;

/// Largest frame either side sends. Reported in the `'HELO'` reply so a
/// client can size its buffers.
pub const MAX_FRAME_LEN: usize = 1024;

/// Longest printer name, in bytes: a Str31.
pub const MAX_NAME_LEN: usize = 31;

/// Printer port baud rates the device accepts.
pub const BAUD_RANGE: core::ops::RangeInclusive<u32> = 300..=1_000_000;

/// A Mac `OSType`: four characters, big-endian.
pub type OSType = u32;

/// `ostype(b"INFO")` is the `'INFO'` literal a Mac compiler would give.
pub const fn ostype(code: &[u8; 4]) -> OSType {
    u32::from_be_bytes(*code)
}

/// Commands, in the header's `command` field.
pub mod cmd {
    use super::{OSType, ostype};

    /// Replies with `PROTOCOL`, `FIRMWARE` and `MAX_FRAME`. This is optional,
    /// but a client can send it first to check we speak the same protocol.
    pub const HELLO: OSType = ostype(b"HELO");
    /// Replies with the configuration and status items.
    pub const INFO: OSType = ostype(b"INFO");
    /// Changes any of the `NAME`, `ROLE` and `BAUD` settings and saves them.
    /// Either every item is applied or none are. A new name is registered
    /// right away, but a new role or baud rate needs a restart, which the
    /// device does by itself after replying (the reply's `REBOOTING` item
    /// says so). Role and baud changes are refused with `BUSY` while a job
    /// is printing.
    pub const SET_CONFIG: OSType = ostype(b"SETC");
    /// Restarts the device once the reply is acknowledged. Refused while a
    /// job is printing.
    pub const REBOOT: OSType = ostype(b"BOOT");
}

/// Item tags, with the type each carries.
pub mod tag {
    use super::{OSType, ostype};

    /// UInt16: the protocol version.
    pub const PROTOCOL: OSType = ostype(b"prot");
    /// Str31: firmware build identity.
    pub const FIRMWARE: OSType = ostype(b"fwvr");
    /// UInt16: the largest frame the device sends or accepts.
    pub const MAX_FRAME: OSType = ostype(b"maxf");

    /// Str31: the configured printer name.
    pub const NAME: OSType = ostype(b"name");
    /// UInt16: the configured role, see [`super::role`].
    pub const ROLE: OSType = ostype(b"role");
    /// UInt32: the configured printer port baud rate.
    pub const BAUD: OSType = ostype(b"baud");

    /// Str31: the name the printer is currently registered under. This only
    /// differs from `NAME` if the config was changed some other way (like the
    /// debug shell) and hasn't been applied yet.
    pub const LIVE_NAME: OSType = ostype(b"lnam");
    /// Boolean: the saved config differs from what is running, which again
    /// only happens after a change from the debug shell.
    pub const REBOOT_NEEDED: OSType = ostype(b"rbot");
    /// Boolean: sent in a `SETC` or `BOOT` reply when the device is going to
    /// restart once the reply is acknowledged. Reconnect after a few seconds.
    pub const REBOOTING: OSType = ostype(b"boot");
    /// Boolean: a print job is in progress.
    pub const JOB_ACTIVE: OSType = ostype(b"job ");
    /// Boolean: the printer's handshake line says it is ready.
    pub const PRINTER_READY: OSType = ostype(b"rdy ");
    /// UInt32: seconds since boot.
    pub const UPTIME: OSType = ostype(b"uptm");
    /// UInt16 network, UInt8 node, UInt8 zero: our AppleTalk address.
    pub const ADDRESS: OSType = ostype(b"addr");
    /// UInt32: bytes sent to the printer since boot.
    pub const PRINTER_TX: OSType = ostype(b"ptxb");
    /// UInt32: bytes received from the printer since boot.
    pub const PRINTER_RX: OSType = ostype(b"prxb");
    /// Str31: the attached printer's model, as it identified itself (like
    /// "Apple StyleWriter"), or its raw identify string if that names no
    /// known model. Empty when the printer did not answer. Only sent in the
    /// StyleWriter role, and not while the device is still asking.
    pub const PRINTER_MODEL: OSType = ostype(b"modl");

    /// OSType: in an error reply, the tag the request was refused over.
    pub const ERROR_TAG: OSType = ostype(b"etag");
}

/// `ROLE` values.
pub mod role {
    pub const STYLEWRITER: u16 = 0;
    pub const IMAGEWRITER: u16 = 1;
}

/// `OSErr` results. We reuse the standard Mac OS codes where one fits, and
/// the rest are in a private range of our own.
pub mod err {
    pub const NO_ERR: i16 = 0;
    /// Unknown command (Mac OS `unimpErr`).
    pub const UNIMPLEMENTED: i16 = -4;
    /// An item's value is out of range or the wrong size (Mac OS
    /// `paramErr`). `ERROR_TAG` names it.
    pub const PARAM: i16 = -50;
    /// The items do not add up to the frame.
    pub const BAD_FRAME: i16 = -29001;
    /// Refused while a print job is in progress.
    pub const BUSY: i16 = -29002;
    /// Writing flash failed.
    pub const FLASH: i16 = -29003;
    /// `SETC` carried a tag that cannot be set. `ERROR_TAG` names it.
    pub const UNKNOWN_TAG: i16 = -29004;
    /// The device couldn't build its reply, which means a firmware bug.
    pub const INTERNAL: i16 = -29005;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Fewer bytes than a header.
    Short,
    /// More than [`MAX_FRAME_LEN`] bytes.
    TooLong,
    /// An item runs past the end of the frame.
    BadItem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub seq: u16,
    pub command: OSType,
    pub result: i16,
}

impl Header {
    /// Read the header of one whole frame: one complete ADSP message.
    pub fn parse(frame: &[u8]) -> Result<Self, FrameError> {
        if frame.len() < HEADER_LEN {
            return Err(FrameError::Short);
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(FrameError::TooLong);
        }
        Ok(Self {
            seq: be16(frame),
            command: be32(&frame[2..]),
            result: be16(&frame[6..]) as i16,
        })
    }
}

/// One item, borrowed from its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item<'a> {
    pub tag: OSType,
    pub data: &'a [u8],
}

impl<'a> Item<'a> {
    pub fn boolean(&self) -> Option<bool> {
        match self.data {
            [b] => Some(*b != 0),
            _ => None,
        }
    }

    pub fn u16(&self) -> Option<u16> {
        let b: [u8; 2] = self.data.try_into().ok()?;
        Some(u16::from_be_bytes(b))
    }

    pub fn u32(&self) -> Option<u32> {
        let b: [u8; 4] = self.data.try_into().ok()?;
        Some(u32::from_be_bytes(b))
    }

    /// The characters of a Pascal string, if the length byte matches the
    /// item size exactly.
    pub fn pstr(&self) -> Option<&'a [u8]> {
        let (&n, chars) = self.data.split_first()?;
        (chars.len() == n as usize).then_some(chars)
    }
}

/// The items of a frame body, checked to fit it exactly.
#[derive(Debug, Clone, Copy)]
pub struct Items<'a> {
    body: &'a [u8],
}

impl<'a> Items<'a> {
    /// The items after `frame`'s header. `frame` should have passed
    /// [`Header::parse`].
    pub fn of_frame(frame: &'a [u8]) -> Result<Self, FrameError> {
        Self::parse(frame.get(HEADER_LEN..).ok_or(FrameError::Short)?)
    }

    pub fn parse(body: &'a [u8]) -> Result<Self, FrameError> {
        let mut rest = body;
        while !rest.is_empty() {
            let (_, next) = split_item(rest).ok_or(FrameError::BadItem)?;
            rest = next;
        }
        Ok(Self { body })
    }

    pub fn iter(&self) -> ItemIter<'a> {
        ItemIter { rest: self.body }
    }

    /// The first item carrying `tag`.
    pub fn find(&self, tag: OSType) -> Option<Item<'a>> {
        self.iter().find(|i| i.tag == tag)
    }
}

pub struct ItemIter<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for ItemIter<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        // Items::parse already checked the whole body, so a failure here just
        // means we've reached the end.
        let (item, rest) = split_item(self.rest)?;
        self.rest = rest;
        Some(item)
    }
}

/// The first item of `buf` and whatever follows it. We allow the very last
/// pad byte to be missing, since there's nothing after it to misalign.
fn split_item(buf: &[u8]) -> Option<(Item<'_>, &[u8])> {
    if buf.len() < ITEM_HEADER_LEN {
        return None;
    }
    let tag = be32(buf);
    let size = be16(&buf[4..]) as usize;
    let end = ITEM_HEADER_LEN + size;
    let data = buf.get(ITEM_HEADER_LEN..end)?;
    let next = (end + (size & 1)).min(buf.len());
    Some((Item { tag, data }, &buf[next..]))
}

/// Ran out of room in the frame buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// Builds one frame in a caller's buffer.
pub struct FrameWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> FrameWriter<'a> {
    /// Start a frame. `buf` should hold [`MAX_FRAME_LEN`] bytes; the result
    /// is written by [`FrameWriter::finish`].
    pub fn new(buf: &'a mut [u8], seq: u16, command: OSType) -> Result<Self, Overflow> {
        if buf.len() < HEADER_LEN {
            return Err(Overflow);
        }
        buf[..2].copy_from_slice(&seq.to_be_bytes());
        buf[2..6].copy_from_slice(&command.to_be_bytes());
        Ok(Self { buf, len: HEADER_LEN })
    }

    pub fn item(&mut self, tag: OSType, data: &[u8]) -> Result<(), Overflow> {
        let padded = data.len() + (data.len() & 1);
        let end = self.len + ITEM_HEADER_LEN + padded;
        if end > self.buf.len().min(MAX_FRAME_LEN) || data.len() > u16::MAX as usize {
            return Err(Overflow);
        }
        let b = &mut self.buf[self.len..end];
        b[..4].copy_from_slice(&tag.to_be_bytes());
        b[4..6].copy_from_slice(&(data.len() as u16).to_be_bytes());
        b[6..6 + data.len()].copy_from_slice(data);
        if padded != data.len() {
            b[ITEM_HEADER_LEN + data.len()] = 0;
        }
        self.len = end;
        Ok(())
    }

    pub fn boolean(&mut self, tag: OSType, v: bool) -> Result<(), Overflow> {
        self.item(tag, &[v as u8])
    }

    pub fn u16(&mut self, tag: OSType, v: u16) -> Result<(), Overflow> {
        self.item(tag, &v.to_be_bytes())
    }

    pub fn u32(&mut self, tag: OSType, v: u32) -> Result<(), Overflow> {
        self.item(tag, &v.to_be_bytes())
    }

    /// A Pascal string. Anything over 255 bytes is refused instead of being
    /// truncated.
    pub fn pstr(&mut self, tag: OSType, chars: &[u8]) -> Result<(), Overflow> {
        let n = u8::try_from(chars.len()).map_err(|_| Overflow)?;
        let mut s = [0u8; 256];
        s[0] = n;
        s[1..=chars.len()].copy_from_slice(chars);
        self.item(tag, &s[..=chars.len()])
    }

    /// Write `result`, and return the frame, to be sent as one message.
    pub fn finish(self, result: i16) -> &'a [u8] {
        let FrameWriter { buf, len } = self;
        buf[6..8].copy_from_slice(&result.to_be_bytes());
        &buf[..len]
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply a Mac client can be tested against byte for byte.
    const INFO_REPLY: &[u8] = &[
        0x00, 0x07, // seq 7
        b'I', b'N', b'F', b'O', // command
        0x00, 0x00, // noErr
        b'n', b'a', b'm', b'e', 0x00, 0x04, 3, b'I', b'n', b'k', // Str31 "Ink", even
        b'r', b'o', b'l', b'e', 0x00, 0x02, 0x00, 0x01, // UInt16 1
        b'j', b'o', b'b', b' ', 0x00, 0x01, 0x01, 0x00, // Boolean true, padded
    ];

    fn build_info(buf: &mut [u8]) -> &[u8] {
        let mut w = FrameWriter::new(buf, 7, cmd::INFO).unwrap();
        w.pstr(tag::NAME, b"Ink").unwrap();
        w.u16(tag::ROLE, role::IMAGEWRITER).unwrap();
        w.boolean(tag::JOB_ACTIVE, true).unwrap();
        w.finish(err::NO_ERR)
    }

    #[test]
    fn writer_matches_the_reference_bytes() {
        let mut buf = [0xAAu8; MAX_FRAME_LEN];
        assert_eq!(build_info(&mut buf), INFO_REPLY);
    }

    #[test]
    fn reference_bytes_parse_back() {
        let h = Header::parse(INFO_REPLY).unwrap();
        assert_eq!(h, Header { seq: 7, command: cmd::INFO, result: err::NO_ERR });
        let items = Items::of_frame(INFO_REPLY).unwrap();
        assert_eq!(items.find(tag::NAME).unwrap().pstr(), Some(&b"Ink"[..]));
        assert_eq!(items.find(tag::ROLE).unwrap().u16(), Some(1));
        assert_eq!(items.find(tag::JOB_ACTIVE).unwrap().boolean(), Some(true));
        assert_eq!(items.find(tag::BAUD), None);
        assert_eq!(items.iter().count(), 3);
    }

    #[test]
    fn a_missing_final_pad_is_accepted() {
        let body = [b'j', b'o', b'b', b' ', 0x00, 0x01, 0x01];
        let items = Items::parse(&body).unwrap();
        assert_eq!(items.find(tag::JOB_ACTIVE).unwrap().boolean(), Some(true));
    }

    #[test]
    fn an_item_past_the_end_is_refused() {
        let body = [b'b', b'a', b'u', b'd', 0x00, 0x04, 0x00, 0x00];
        assert_eq!(Items::parse(&body).err(), Some(FrameError::BadItem));
        assert_eq!(Items::parse(&body[..4]).err(), Some(FrameError::BadItem));
    }

    #[test]
    fn wrong_sizes_read_as_none() {
        let item = Item { tag: tag::BAUD, data: &[0, 1] };
        assert_eq!(item.u32(), None);
        assert_eq!(item.u16(), Some(1));
        let item = Item { tag: tag::NAME, data: &[4, b'I', b'n', b'k'] };
        assert_eq!(item.pstr(), None);
    }

    #[test]
    fn a_frame_must_hold_a_header_and_fit_the_limit() {
        assert_eq!(Header::parse(&INFO_REPLY[..HEADER_LEN - 1]).err(), Some(FrameError::Short));
        assert_eq!(Header::parse(&[0; MAX_FRAME_LEN + 1]).err(), Some(FrameError::TooLong));
    }

    #[test]
    fn writer_refuses_to_overflow() {
        let mut buf = [0u8; HEADER_LEN + 8];
        let mut w = FrameWriter::new(&mut buf, 1, cmd::INFO).unwrap();
        w.u16(tag::ROLE, 0).unwrap();
        assert_eq!(w.u16(tag::ROLE, 0), Err(Overflow));
        assert_eq!(w.finish(0).len(), HEADER_LEN + 8);
    }
}
