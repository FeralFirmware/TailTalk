/// Packets encapsulated in LocalTalk Link Access Protocol format. Typically only seen on actual LocalTalk
/// networks but interestingly AsanteTalk (and maybe others) default to this format if they do not see
/// other Ethernet traffic on the port during boot up.
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum LlapType {
    DdpShort = 1,
    DdpLong = 2,
    Enquiry = 0x81,
    Acknowledge = 0x82,
    Other(u8),
}

impl From<u8> for LlapType {
    fn from(orig: u8) -> Self {
        match orig {
            1 => LlapType::DdpShort,
            2 => LlapType::DdpLong,
            0x81 => LlapType::Enquiry,
            0x82 => LlapType::Acknowledge,
            n => LlapType::Other(n),
        }
    }
}

#[derive(Debug)]
pub struct LlapPacket {
    pub dst_node: u8,
    pub src_node: u8,
    pub type_: LlapType,
}

#[derive(Error, Debug)]
pub enum LlapError {
    #[error("packet too short")]
    TooShort,
}

impl LlapPacket {
    pub const LEN: usize = 3;

    pub fn parse(buf: &[u8]) -> Result<Self, LlapError> {
        if buf.len() < Self::LEN {
            return Err(LlapError::TooShort);
        }
        Ok(Self {
            dst_node: buf[0],
            src_node: buf[1],
            type_: buf[2].into(),
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, LlapError> {
        if buf.len() < Self::LEN {
            return Err(LlapError::TooShort);
        }
        buf[0] = self.dst_node;
        buf[1] = self.src_node;
        buf[2] = match self.type_ {
            LlapType::DdpShort => 1,
            LlapType::DdpLong => 2,
            LlapType::Enquiry => 0x81,
            LlapType::Acknowledge => 0x82,
            LlapType::Other(n) => n,
        };
        Ok(Self::LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet() {
        let packet = LlapPacket {
            dst_node: 0x42,
            src_node: 0x24,
            type_: LlapType::DdpShort,
        };
        let mut buf = [0u8; 3];
        let len = packet.to_bytes(&mut buf).unwrap();
        assert_eq!(len, 3);
        assert_eq!(buf, [0x42, 0x24, 1]);

        let parsed = LlapPacket::parse(&buf).unwrap();
        assert_eq!(parsed.dst_node, 0x42);
        assert_eq!(parsed.src_node, 0x24);
        assert_eq!(parsed.type_, LlapType::DdpShort);
    }

    #[test]
    fn test_localtalk_data() {
        let packet = LlapPacket {
            dst_node: 0x42,
            src_node: 0x24,
            type_: LlapType::DdpLong,
        };
        let mut buf = [0u8; 3];
        let len = packet.to_bytes(&mut buf).unwrap();
        assert_eq!(len, 3);
        assert_eq!(buf[0], 0x42);
        assert_eq!(buf[1], 0x24);
        assert_eq!(buf[2], 2);

        let parsed = LlapPacket::parse(&buf).unwrap();
        assert_eq!(parsed.dst_node, 0x42);
        assert_eq!(parsed.src_node, 0x24);
        assert_eq!(parsed.type_, LlapType::DdpLong);
    }

    #[test]
    fn test_localtalk_control() {
        let packet = LlapPacket {
            dst_node: 0xFF,
            src_node: 0x11,
            type_: LlapType::Enquiry, // ENQ
        };
        let mut buf = [0u8; 3];
        let len = packet.to_bytes(&mut buf).unwrap();
        assert_eq!(len, 3);
        assert_eq!(buf, [0xFF, 0x11, 0x81]);

        let parsed = LlapPacket::parse(&buf).unwrap();
        assert_eq!(parsed.dst_node, 0xFF);
        assert_eq!(parsed.src_node, 0x11);
        assert_eq!(parsed.type_, LlapType::Enquiry);
    }
}
