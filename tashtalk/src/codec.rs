use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TashTalkCommand {
    Noop,
    TransmitFrame(Vec<u8>),
    SetNodeIds([u8; 32]),
    SetFeatures(u8),
}

#[derive(Debug, thiserror::Error)]
pub enum TashTalkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Framing error inside TashTalk")]
    FramingError,
    #[error("Frame aborted")]
    FrameAborted,
    #[error("CRC check failed")]
    CrcCheckFailed,
    #[error("Unknown escape sequence 0x00 {0:#04X}")]
    UnknownEscape(u8),
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

impl Decoder for TashTalkCodec {
    type Item = Vec<u8>;
    type Error = TashTalkError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut i = 0;

        while i < src.len() {
            if src[i] == 0x00 {
                // Need at least one more byte for the escape sequence
                if i + 1 >= src.len() {
                    return Ok(None);
                }

                match src[i + 1] {
                    0xFF => {
                        i += 2; // Skip literal 0x00
                    }
                    0xFD | 0xFE | 0xFA | 0xFC => {
                        // Found end of frame marker
                        let end_index = i + 2;
                        let frame_slice = &src[..i]; // everything up to the 0x00 escape
                        let code = src[i + 1];

                        // Unescape the slice
                        let mut unescaped = Vec::with_capacity(frame_slice.len());
                        let mut j = 0;
                        while j < frame_slice.len() {
                            if frame_slice[j] == 0x00 {
                                unescaped.push(0x00);
                                j += 2; // skip 0xFF
                            } else {
                                unescaped.push(frame_slice[j]);
                                j += 1;
                            }
                        }

                        // Consume from buffer
                        src.advance(end_index);

                        return match code {
                            0xFD => Ok(Some(unescaped)),
                            0xFE => Err(TashTalkError::FramingError),
                            0xFA => Err(TashTalkError::FrameAborted),
                            0xFC => Err(TashTalkError::CrcCheckFailed),
                            _ => unreachable!(),
                        };
                    }
                    unknown => {
                        src.advance(i + 2);
                        return Err(TashTalkError::UnknownEscape(unknown));
                    }
                }
            } else {
                i += 1;
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_decode() {
        let mut codec = TashTalkCodec;

        // Normal frame end
        let mut buf = BytesMut::from(&[0xAA, 0xBB, 0x00, 0xFD][..]);
        let res = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(res, vec![0xAA, 0xBB]);

        // Escape 0x00 literal
        let mut buf = BytesMut::from(&[0xAA, 0x00, 0xFF, 0xBB, 0x00, 0xFD][..]);
        let res = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(res, vec![0xAA, 0x00, 0xBB]);

        // Framing Error
        let mut buf = BytesMut::from(&[0x00, 0xFE][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, TashTalkError::FramingError));

        // Unknown escape -> error
        let mut buf = BytesMut::from(&[0x00, 0x01][..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(err, TashTalkError::UnknownEscape(0x01)));

        // Incomplete
        let mut buf = BytesMut::from(&[0xAA, 0xBB][..]);
        let res = codec.decode(&mut buf).unwrap();
        assert_eq!(res, None);

        // Incomplete escape
        let mut buf = BytesMut::from(&[0xAA, 0x00][..]);
        let res = codec.decode(&mut buf).unwrap();
        assert_eq!(res, None);
    }
}
