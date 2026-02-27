/// Packets encapsulated in LocalTalk Link Access Protocol format. Typically only seen on actual LocalTalk
/// networks but interestingly AsanteTalk (and maybe others) default to this format if they do not see
/// other Ethernet traffic on the port during boot up.
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum LlapType {
    DdpShort = 1,
    DdpLong = 2,
    Other(u8),
}

impl From<u8> for LlapType {
    fn from(orig: u8) -> Self {
        match orig {
            1 => LlapType::DdpShort,
            2 => LlapType::DdpLong,
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
            LlapType::Other(n) => n,
        };
        Ok(Self::LEN)
    }
}
