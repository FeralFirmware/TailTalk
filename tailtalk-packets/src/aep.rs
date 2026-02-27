use thiserror::Error;

const REQUEST: u8 = 1;
const REPLY: u8 = 2;

#[derive(Error, Debug)]
pub enum AepError {
    #[error("unknown AEP function code {code:?}")]
    UnknownFunction { code: u8 },
    #[error("invalid size - expected at least {expected:?} byte(s), but found {found:?}")]
    InvalidSize { found: usize, expected: usize },
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AepFunction {
    Request = REQUEST,
    Reply = REPLY,
}

impl TryFrom<u8> for AepFunction {
    type Error = AepError;

    fn try_from(data: u8) -> Result<Self, Self::Error> {
        match data {
            REQUEST => Ok(Self::Request),
            REPLY => Ok(Self::Reply),
            _ => Err(AepError::UnknownFunction { code: data }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AepPacket {
    pub function: AepFunction,
}

impl AepPacket {
    pub fn parse(data: &[u8]) -> Result<Self, AepError> {
        if data.is_empty() {
            return Err(AepError::InvalidSize {
                found: 0,
                expected: 1,
            });
        }
        let code = AepFunction::try_from(data[0])?;

        Ok(Self { function: code })
    }

    pub fn set_code(&mut self, code: AepFunction) {
        self.function = code;
    }

    pub fn to_bytes(self, buf: &mut [u8]) -> Result<usize, AepError> {
        if buf.is_empty() {
            return Err(AepError::InvalidSize {
                found: buf.len(),
                expected: 1,
            });
        }

        buf[0] = self.function as u8;

        Ok(1)
    }

    pub const fn len(&self) -> usize {
        1
    }

    pub const fn is_empty(&self) -> bool {
        false
    }
}
