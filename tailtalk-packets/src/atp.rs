use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AtpError {
    #[error("invalid size - expected at least {expected} bytes but found {found}")]
    InvalidSize { expected: usize, found: usize },
    #[error("unknown function code {code}")]
    UnknownFunction { code: u8 },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AtpFunction {
    Request = 1,
    Response = 2,
    Release = 3,
}

impl TryFrom<u8> for AtpFunction {
    type Error = AtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AtpFunction::Request),
            2 => Ok(AtpFunction::Response),
            3 => Ok(AtpFunction::Release),
            _ => Err(AtpError::UnknownFunction { code: value }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpPacket {
    pub function: AtpFunction,
    pub xo: bool,
    pub eom: bool,
    pub sts: bool,
    pub bitmap_seq_num: u8,
    pub tid: u16,
    pub user_bytes: [u8; 4],
}

impl AtpPacket {
    pub const HEADER_LEN: usize = 8;

    pub fn parse(buf: &[u8]) -> Result<Self, AtpError> {
        if buf.len() < Self::HEADER_LEN {
            return Err(AtpError::InvalidSize {
                expected: Self::HEADER_LEN,
                found: buf.len(),
            });
        }

        let control = buf[0];
        // Function code is in bits 7-6
        let function_code = (control >> 6) & 0x03;
        let function = AtpFunction::try_from(function_code)?;

        // XO: Bit 5
        let xo = (control & 0x20) != 0;
        // EOM: Bit 4
        let eom = (control & 0x10) != 0;
        // STS: Bit 3
        let sts = (control & 0x08) != 0;

        let bitmap_seq_num = buf[1];
        let tid = BigEndian::read_u16(&buf[2..4]);
        let mut user_bytes = [0u8; 4];
        user_bytes.copy_from_slice(&buf[4..8]);

        Ok(Self {
            function,
            xo,
            eom,
            sts,
            bitmap_seq_num,
            tid,
            user_bytes,
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, AtpError> {
        let total_len = Self::HEADER_LEN;
        if buf.len() < total_len {
            return Err(AtpError::InvalidSize {
                expected: total_len,
                found: buf.len(),
            });
        }

        let mut control = (self.function as u8) << 6;
        if self.xo {
            control |= 0x20;
        }
        if self.eom {
            control |= 0x10;
        }
        if self.sts {
            control |= 0x08;
        }

        buf[0] = control;
        buf[1] = self.bitmap_seq_num;
        BigEndian::write_u16(&mut buf[2..4], self.tid);
        buf[4..8].copy_from_slice(&self.user_bytes);

        Ok(total_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_atp_request() {
        // Request (01), XO (1), EOM (0), STS (0)
        // Control: 01100000 = 0x60
        // Bitmap: 0xFF
        // TID: 0x1234
        // User Bytes: 0x01, 0x02, 0x03, 0x04
        // Data: 0xAA, 0xBB
        let data: &[u8] = &[0x60, 0xFF, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB];

        let packet = AtpPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.function, AtpFunction::Request);
        assert!(packet.xo);
        assert!(!packet.eom);
        assert!(!packet.sts);
        assert_eq!(packet.bitmap_seq_num, 0xFF);
        assert_eq!(packet.tid, 0x1234);
        assert_eq!(packet.user_bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn test_encode_atp_response() {
        let packet = AtpPacket {
            function: AtpFunction::Response,
            xo: false,
            eom: true,
            sts: false,
            bitmap_seq_num: 1, // Sequence number 1
            tid: 0x5678,
            user_bytes: [0xDE, 0xAD, 0xBE, 0xEF],
        };

        // Response (10), XO (0), EOM (1), STS (0)
        // Control: 10010000 = 0x90
        let expected: &[u8] = &[0x90, 0x01, 0x56, 0x78, 0xDE, 0xAD, 0xBE, 0xEF];

        let mut buf = [0u8; 8];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, 8);
        assert_eq!(&buf, expected);
    }

    #[test]
    fn test_round_trip() {
        let original = AtpPacket {
            function: AtpFunction::Release,
            xo: false, // Release usually doesn't use XO/EOM/STS same way but structure allows it
            eom: false,
            sts: true,
            bitmap_seq_num: 0,
            tid: 9999,
            user_bytes: [5, 6, 7, 8],
        };

        let mut buf = [0u8; 8];
        let len = original.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(len, 8);

        let parsed = AtpPacket::parse(&buf).expect("failed to parse");
        assert_eq!(original, parsed);
    }
}
