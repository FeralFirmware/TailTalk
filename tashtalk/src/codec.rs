use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::crc::{lt_crc, CrcCalculator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TashTalkCommand {
    Noop,
    TransmitFrame(Vec<u8>),
    SetNodeIds([u8; 32]),
    SetFeatures(u8),
}

/// A recoverable framing problem, from TashTalk or our own CRC check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("LocalTalk framing error")]
    FramingError,
    #[error("LocalTalk frame aborted")]
    FrameAborted,
    #[error("LocalTalk CRC check failed")]
    CrcCheckFailed,
    #[error("unknown escape sequence 0x00 {0:#04X}")]
    UnknownEscape(u8),
}

/// An item from the receive side of the codec. Framing problems arrive as
/// [`TashTalkEvent::Error`] rather than terminating the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TashTalkEvent {
    /// A complete, CRC-valid frame (LLAP header + payload + 2 trailing CRC bytes).
    Frame(Vec<u8>),
    /// A bad frame; its bytes have been discarded.
    Error(FrameError),
}

/// Fatal codec error. Framing glitches are events, not errors — only I/O
/// failures terminate the stream.
#[derive(Debug, thiserror::Error)]
pub enum TashTalkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct TashTalkCodec;

impl Encoder<TashTalkCommand> for TashTalkCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: TashTalkCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            TashTalkCommand::Noop => {
                dst.put_u8(0x00);
            }
            TashTalkCommand::TransmitFrame(frame) => {
                dst.put_u8(0x01);
                dst.extend_from_slice(&frame);
            }
            TashTalkCommand::SetNodeIds(nodes) => {
                dst.put_u8(0x02);
                dst.extend_from_slice(&nodes);
            }
            TashTalkCommand::SetFeatures(features) => {
                dst.put_u8(0x03);
                dst.put_u8(features);
            }
        }

        Ok(())
    }
}

/// Minimum length of a well-formed LocalTalk frame: a 3-byte control frame plus
/// its two trailing CRC bytes.
const MIN_FRAME_LEN: usize = 5;

/// Undo TashTalk's `0x00 0xFF` escaping. The result still includes the CRC bytes.
fn unescape(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len());
    let mut j = 0;
    while j < frame.len() {
        if frame[j] == 0x00 {
            out.push(0x00);
            j += 2; // skip the trailing 0xFF marker
        } else {
            out.push(frame[j]);
            j += 1;
        }
    }
    out
}

/// Verify a frame's CRC in software. `frame` must include the two CRC bytes.
fn crc_ok(frame: &[u8]) -> bool {
    let mut crc = CrcCalculator::new();
    crc.feed(frame);
    crc.is_okay()
}

impl Decoder for TashTalkCodec {
    type Item = TashTalkEvent;
    type Error = TashTalkError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut i = 0;

        while i < src.len() {
            if src[i] != 0x00 {
                i += 1;
                continue;
            }

            // Need the escape's argument byte.
            if i + 1 >= src.len() {
                return Ok(None);
            }

            match src[i + 1] {
                // Escaped literal 0x00 — frame data, keep scanning.
                0xFF => i += 2,

                // Frame Done: the bytes before the marker are a complete frame.
                0xFD => {
                    let frame = unescape(&src[..i]);
                    src.advance(i + 2);

                    // Verify in software; the device only checks when its
                    // CRC-checking feature is enabled.
                    if frame.len() < MIN_FRAME_LEN || !crc_ok(&frame) {
                        return Ok(Some(TashTalkEvent::Error(FrameError::CrcCheckFailed)));
                    }
                    return Ok(Some(TashTalkEvent::Frame(frame)));
                }

                // Framing error / abort / CRC failure: discard the frame but keep
                // the stream alive so a following buffered frame is still delivered.
                marker @ (0xFE | 0xFA | 0xFC) => {
                    src.advance(i + 2);
                    let err = match marker {
                        0xFE => FrameError::FramingError,
                        0xFA => FrameError::FrameAborted,
                        _ => FrameError::CrcCheckFailed,
                    };
                    return Ok(Some(TashTalkEvent::Error(err)));
                }

                unknown => {
                    src.advance(i + 2);
                    return Ok(Some(TashTalkEvent::Error(FrameError::UnknownEscape(unknown))));
                }
            }
        }

        Ok(None)
    }
}

/// Append the LocalTalk CRC to a frame. `frame` is the LLAP header and payload
/// without CRC bytes.
pub fn frame_with_crc(frame: &[u8]) -> Vec<u8> {
    let crc = lt_crc(frame);
    let mut out = Vec::with_capacity(frame.len() + 2);
    out.extend_from_slice(frame);
    out.extend_from_slice(&crc);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a frame (CRC included) as TashTalk would send it: escape 0x00,
    /// then append the Frame-Done marker.
    fn to_wire(frame_with_crc: &[u8]) -> BytesMut {
        let mut w = BytesMut::new();
        for &b in frame_with_crc {
            if b == 0x00 {
                w.extend_from_slice(&[0x00, 0xFF]);
            } else {
                w.put_u8(b);
            }
        }
        w.extend_from_slice(&[0x00, 0xFD]);
        w
    }

    /// A valid 3-byte control frame plus its computed CRC.
    fn sample_frame() -> Vec<u8> {
        frame_with_crc(&[0x01, 0x02, 0x81])
    }

    #[test]
    fn test_encode() {
        let mut codec = TashTalkCodec;
        let mut buf = BytesMut::new();

        codec.encode(TashTalkCommand::Noop, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0x00]);
        buf.clear();

        codec
            .encode(TashTalkCommand::TransmitFrame(vec![0xAA, 0xBB]), &mut buf)
            .unwrap();
        assert_eq!(&buf[..], &[0x01, 0xAA, 0xBB]);
        buf.clear();

        codec
            .encode(TashTalkCommand::SetNodeIds([0x11; 32]), &mut buf)
            .unwrap();
        let mut expected = vec![0x02];
        expected.extend_from_slice(&[0x11; 32]);
        assert_eq!(&buf[..], &expected[..]);
        buf.clear();

        codec
            .encode(TashTalkCommand::SetFeatures(0xC0), &mut buf)
            .unwrap();
        assert_eq!(&buf[..], &[0x03, 0xC0]);
    }

    #[test]
    fn decode_good_frame() {
        let mut codec = TashTalkCodec;
        let frame = sample_frame();
        let mut buf = to_wire(&frame);
        let ev = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(ev, TashTalkEvent::Frame(frame));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_unescapes_literal_zero() {
        let mut codec = TashTalkCodec;
        // A frame whose data contains a 0x00 byte, forcing 0x00 0xFF escaping.
        let frame = frame_with_crc(&[0x00, 0x02, 0x81]);
        let mut buf = to_wire(&frame);
        let ev = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(ev, TashTalkEvent::Frame(frame));
    }

    #[test]
    fn decode_rejects_bad_crc() {
        let mut codec = TashTalkCodec;
        let mut frame = sample_frame();
        *frame.last_mut().unwrap() ^= 0xFF; // corrupt the CRC
        let mut buf = to_wire(&frame);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::CrcCheckFailed))
        );
    }

    #[test]
    fn decode_rejects_runt_frame() {
        let mut codec = TashTalkCodec;
        // Fewer than MIN_FRAME_LEN bytes before the marker.
        let mut buf = BytesMut::from(&[0xAA, 0xBB, 0x00, 0xFD][..]);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::CrcCheckFailed))
        );
    }

    #[test]
    fn decode_error_markers() {
        let mut codec = TashTalkCodec;

        let mut buf = BytesMut::from(&[0x00, 0xFE][..]);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::FramingError))
        );
        assert!(buf.is_empty());

        let mut buf = BytesMut::from(&[0xAA, 0xBB, 0x00, 0xFA][..]);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::FrameAborted))
        );
        assert!(buf.is_empty());

        let mut buf = BytesMut::from(&[0xAA, 0xBB, 0x00, 0xFC][..]);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::CrcCheckFailed))
        );
        assert!(buf.is_empty());

        let mut buf = BytesMut::from(&[0x00, 0x01][..]);
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::UnknownEscape(0x01)))
        );
        assert!(buf.is_empty());
    }

    /// A bad frame must not stall a good one buffered behind it: the good frame
    /// is delivered on the next `decode` call, with no further I/O.
    #[test]
    fn error_does_not_swallow_following_frame() {
        let mut codec = TashTalkCodec;
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xDE, 0xAD, 0x00, 0xFA]); // aborted frame
        let frame = sample_frame();
        buf.extend_from_slice(&to_wire(&frame));

        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Error(FrameError::FrameAborted))
        );
        assert_eq!(
            codec.decode(&mut buf).unwrap(),
            Some(TashTalkEvent::Frame(frame))
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_incomplete() {
        let mut codec = TashTalkCodec;

        let mut buf = BytesMut::from(&[0xAA, 0xBB][..]);
        assert_eq!(codec.decode(&mut buf).unwrap(), None);

        // Escape start with no argument byte yet.
        let mut buf = BytesMut::from(&[0xAA, 0x00][..]);
        assert_eq!(codec.decode(&mut buf).unwrap(), None);
    }
}
