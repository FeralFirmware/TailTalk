#[derive(Debug)]
pub enum AspError {
    UnknownFunction(u8),
    InvalidSize { expected: usize, found: usize },
}

pub const ASP_SERVER_BUSY: i32 = -1071;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SPFunction {
    CloseSess = 0x01,
    Command = 0x02,
    GetStatus = 0x03,
    OpenSess = 0x04,
    Tickle = 0x05,
    Write = 0x06,
    WriteContinue = 0x07,
    Attention = 0x08,
}

impl TryFrom<u8> for SPFunction {
    type Error = AspError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::CloseSess),
            0x02 => Ok(Self::Command),
            0x03 => Ok(Self::GetStatus),
            0x04 => Ok(Self::OpenSess),
            0x05 => Ok(Self::Tickle),
            0x06 => Ok(Self::Write),
            0x07 => Ok(Self::WriteContinue),
            0x08 => Ok(Self::Attention),
            _ => Err(AspError::UnknownFunction(value)),
        }
    }
}

#[derive(Debug)]
pub struct AspHeader {
    pub function: SPFunction,
    pub session_id: u8,
    pub sequence_number: u16,
}

impl AspHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, AspError> {
        if buf.len() < 4 {
            return Err(AspError::InvalidSize {
                expected: 4,
                found: buf.len(),
            });
        }

        Ok(Self {
            function: SPFunction::try_from(buf[0])?,
            session_id: buf[1],
            sequence_number: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, AspError> {
        if buf.len() < 4 {
            return Err(AspError::InvalidSize {
                expected: 4,
                found: buf.len(),
            });
        }

        buf[0] = self.function as u8;
        buf[1] = self.session_id;
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());

        Ok(4)
    }
}

/// Payload for SPWrite command (server to client)
#[derive(Debug)]
pub struct SPWritePayload {
    pub sequence_number: u16,
    pub session_id: u8,
}
