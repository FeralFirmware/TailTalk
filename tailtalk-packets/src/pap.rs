use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PapError {
    #[error("invalid size - expected at least {expected} bytes but found {found}")]
    InvalidSize { expected: usize, found: usize },
    #[error("unknown function code {code}")]
    UnknownFunction { code: u8 },
}

/// PAP function codes
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PapFunction {
    OpenConn = 1,
    OpenConnReply = 2,
    SendData = 3,
    Data = 4,
    Tickle = 5,
    CloseConn = 6,
    CloseConnReply = 7,
    SendStatus = 8,
    Status = 9,
}

impl TryFrom<u8> for PapFunction {
    type Error = PapError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PapFunction::OpenConn),
            2 => Ok(PapFunction::OpenConnReply),
            3 => Ok(PapFunction::SendData),
            4 => Ok(PapFunction::Data),
            5 => Ok(PapFunction::Tickle),
            6 => Ok(PapFunction::CloseConn),
            7 => Ok(PapFunction::CloseConnReply),
            8 => Ok(PapFunction::SendStatus),
            9 => Ok(PapFunction::Status),
            _ => Err(PapError::UnknownFunction { code: value }),
        }
    }
}

/// PAP packet structure
///
/// PAP packets are sent over ATP and have the following format:
/// - Byte 0: Connection ID
/// - Byte 1: Function code
/// - Bytes 2-3: Sequence number (for some functions)
/// - Remaining bytes: Function-specific data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PapPacket {
    pub connection_id: u8,
    pub function: PapFunction,
    pub sequence_num: u16,
    pub data: Vec<u8>,
}

impl PapPacket {
    /// Minimum header length (connection_id + function)
    pub const MIN_HEADER_LEN: usize = 2;

    /// Parse a PAP packet from bytes
    pub fn parse(buf: &[u8]) -> Result<Self, PapError> {
        if buf.len() < Self::MIN_HEADER_LEN {
            return Err(PapError::InvalidSize {
                expected: Self::MIN_HEADER_LEN,
                found: buf.len(),
            });
        }

        let connection_id = buf[0];
        let function = PapFunction::try_from(buf[1])?;

        // Some functions include a sequence number, others don't
        let (sequence_num, data_start) = match function {
            PapFunction::SendData | PapFunction::Data => {
                if buf.len() < 4 {
                    return Err(PapError::InvalidSize {
                        expected: 4,
                        found: buf.len(),
                    });
                }
                (BigEndian::read_u16(&buf[2..4]), 4)
            }
            _ => (0, 2),
        };

        let data = buf[data_start..].to_vec();

        Ok(Self {
            connection_id,
            function,
            sequence_num,
            data,
        })
    }

    /// Encode a PAP packet to bytes
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, PapError> {
        let has_seq_num = matches!(self.function, PapFunction::SendData | PapFunction::Data);

        let header_len = if has_seq_num { 4 } else { 2 };
        let total_len = header_len + self.data.len();

        if buf.len() < total_len {
            return Err(PapError::InvalidSize {
                expected: total_len,
                found: buf.len(),
            });
        }

        buf[0] = self.connection_id;
        buf[1] = self.function as u8;

        if has_seq_num {
            BigEndian::write_u16(&mut buf[2..4], self.sequence_num);
            buf[4..total_len].copy_from_slice(&self.data);
        } else {
            buf[2..total_len].copy_from_slice(&self.data);
        }

        Ok(total_len)
    }

    /// Get the total length of this packet when encoded
    pub fn len(&self) -> usize {
        let header_len = match self.function {
            PapFunction::SendData | PapFunction::Data => 4,
            _ => 2,
        };
        header_len + self.data.len()
    }

    /// Check if the packet is empty (no data)
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to ATP user bytes and data payload
    ///
    /// PAP transmits its header in the ATP user bytes.
    /// - Byte 0: Connection ID
    /// - Byte 1: Function code
    /// - Bytes 2-3: Sequence number (or unused/zero)
    pub fn to_atp_parts(&self) -> ([u8; 4], &[u8]) {
        let mut user_bytes = [0u8; 4];
        user_bytes[0] = self.connection_id;
        user_bytes[1] = self.function as u8;

        if matches!(self.function, PapFunction::SendData | PapFunction::Data) {
            BigEndian::write_u16(&mut user_bytes[2..4], self.sequence_num);
        }
        // All other PAP functions: bytes 2-3 in user_bytes remain zero

        (user_bytes, &self.data)
    }

    /// Parse from ATP user bytes and data payload
    pub fn parse_from_atp(user_bytes: [u8; 4], data: &[u8]) -> Result<Self, PapError> {
        let connection_id = user_bytes[0];
        let function = PapFunction::try_from(user_bytes[1])?;

        let sequence_num = match function {
            PapFunction::SendData | PapFunction::Data => BigEndian::read_u16(&user_bytes[2..4]),
            _ => 0,
        };

        Ok(Self {
            connection_id,
            function,
            sequence_num,
            data: data.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_conn() {
        // OpenConn packet: conn_id=0, function=1, socket_num=0x42, flow_quantum=8
        let data: &[u8] = &[0x00, 0x01, 0x42, 0x00, 0x08];

        let packet = PapPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.connection_id, 0);
        assert_eq!(packet.function, PapFunction::OpenConn);
        assert_eq!(packet.sequence_num, 0);
        assert_eq!(packet.data, vec![0x42, 0x00, 0x08]);
    }

    #[test]
    fn test_parse_send_data() {
        // SendData packet: conn_id=5, function=3, seq=0x0001, data="Hello"
        let data: &[u8] = &[0x05, 0x03, 0x00, 0x01, b'H', b'e', b'l', b'l', b'o'];

        let packet = PapPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.connection_id, 5);
        assert_eq!(packet.function, PapFunction::SendData);
        assert_eq!(packet.sequence_num, 1);
        assert_eq!(packet.data, b"Hello");
    }

    #[test]
    fn test_encode_open_conn_reply() {
        let packet = PapPacket {
            connection_id: 7,
            function: PapFunction::OpenConnReply,
            sequence_num: 0,                          // Not used for OpenConnReply
            data: vec![0x42, 0x00, 0x08, 0x00, 0x01], // socket, flow_quantum, result
        };

        let mut buf = [0u8; 32];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, 7); // 2 byte header + 5 bytes data
        assert_eq!(&buf[..len], &[0x07, 0x02, 0x42, 0x00, 0x08, 0x00, 0x01]);
    }

    #[test]
    fn test_encode_data() {
        let packet = PapPacket {
            connection_id: 3,
            function: PapFunction::Data,
            sequence_num: 42,
            data: b"PostScript data".to_vec(),
        };

        let mut buf = [0u8; 64];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, 4 + 15); // 4 byte header + 15 bytes data
        assert_eq!(buf[0], 3); // connection_id
        assert_eq!(buf[1], 4); // function code for Data
        assert_eq!(BigEndian::read_u16(&buf[2..4]), 42); // sequence_num
        assert_eq!(&buf[4..len], b"PostScript data");
    }

    #[test]
    fn test_round_trip_tickle() {
        let original = PapPacket {
            connection_id: 10,
            function: PapFunction::Tickle,
            sequence_num: 0,
            data: vec![],
        };

        let mut buf = [0u8; 32];
        let len = original.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(len, 2); // Just header, no data

        let parsed = PapPacket::parse(&buf[..len]).expect("failed to parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_round_trip_with_data() {
        let original = PapPacket {
            connection_id: 15,
            function: PapFunction::SendData,
            sequence_num: 100,
            data: b"Test print job data".to_vec(),
        };

        let mut buf = [0u8; 64];
        let len = original.to_bytes(&mut buf).expect("failed to encode");

        let parsed = PapPacket::parse(&buf[..len]).expect("failed to parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_function_code() {
        let data: &[u8] = &[0x01, 0xFF]; // Invalid function code

        let result = PapPacket::parse(data);
        assert!(result.is_err());
        match result {
            Err(PapError::UnknownFunction { code: 0xFF }) => {}
            _ => panic!("Expected UnknownFunction error"),
        }
    }

    #[test]
    fn test_buffer_too_small() {
        let packet = PapPacket {
            connection_id: 1,
            function: PapFunction::Status,
            sequence_num: 0,
            data: vec![1, 2, 3, 4, 5],
        };

        let mut buf = [0u8; 4]; // Too small
        let result = packet.to_bytes(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_atp_helpers() {
        let original = PapPacket {
            connection_id: 10,
            function: PapFunction::SendData,
            sequence_num: 12345,
            data: b"Data Payload".to_vec(),
        };

        let (user_bytes, data) = original.to_atp_parts();
        assert_eq!(user_bytes[0], 10);
        assert_eq!(user_bytes[1], 3); // SendData
        assert_eq!(BigEndian::read_u16(&user_bytes[2..4]), 12345);
        assert_eq!(data, b"Data Payload");

        let parsed = PapPacket::parse_from_atp(user_bytes, data).expect("failed to parse from atp");
        assert_eq!(original, parsed);
    }
}
