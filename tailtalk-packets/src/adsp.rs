use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdspError {
    #[error("invalid size - expected at least {expected} bytes but found {found}")]
    InvalidSize { expected: usize, found: usize },
    #[error("unknown descriptor code {code}")]
    UnknownDescriptor { code: u8 },
}

/// ADSP descriptor (packet type) codes
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum AdspDescriptor {
    /// Control packet (probe, acknowledgment)
    ControlPacket = 0x80,
    /// Connection open request
    OpenConnRequest = 0x81,
    /// Connection open acknowledgment
    OpenConnAck = 0x82,
    /// Combined open request and acknowledgment
    OpenConnReqAck = 0x83,
    /// Connection denied
    OpenConnDeny = 0x84,
    /// Close connection advice
    CloseAdvice = 0x85,
    /// Forward reset
    ForwardReset = 0x86,
    /// Retransmit advice
    RetransmitAdvice = 0x87,
    /// Acknowledgment
    Acknowledgment = 0x88,
}

impl TryFrom<u8> for AdspDescriptor {
    type Error = AdspError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x80 => Ok(AdspDescriptor::ControlPacket),
            0x81 => Ok(AdspDescriptor::OpenConnRequest),
            0x82 => Ok(AdspDescriptor::OpenConnAck),
            0x83 => Ok(AdspDescriptor::OpenConnReqAck),
            0x84 => Ok(AdspDescriptor::OpenConnDeny),
            0x85 => Ok(AdspDescriptor::CloseAdvice),
            0x86 => Ok(AdspDescriptor::ForwardReset),
            0x87 => Ok(AdspDescriptor::RetransmitAdvice),
            0x88 => Ok(AdspDescriptor::Acknowledgment),
            _ => Err(AdspError::UnknownDescriptor { code: value }),
        }
    }
}

/// ADSP packet header structure
///
/// ADSP (AppleTalk Data Stream Protocol) provides connection-oriented,
/// full-duplex byte-stream communication over DDP.
///
/// Packet format:
/// - Byte 0: Descriptor (packet type)
/// - Bytes 1-2: Connection ID (u16, big-endian)
/// - Bytes 3-6: First Byte Sequence number (u32, big-endian)
/// - Bytes 7-10: Next Receive Sequence number (u32, big-endian)
/// - Bytes 11-12: Receive Window size (u16, big-endian)
/// - Remaining bytes: Data payload (not owned by this struct)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdspPacket {
    /// Packet type/descriptor
    pub descriptor: AdspDescriptor,
    /// Connection identifier
    pub connection_id: u16,
    /// Sequence number of the first data byte in this packet
    pub first_byte_seq: u32,
    /// Next expected receive sequence number
    pub next_recv_seq: u32,
    /// Receive window size (flow control)
    pub recv_window: u16,
}

impl AdspPacket {
    /// ADSP header length in bytes
    pub const HEADER_LEN: usize = 13;

    /// Parse an ADSP header from bytes
    ///
    /// Returns the parsed header. The caller is responsible for
    /// handling any data following the header in the buffer.
    pub fn parse(buf: &[u8]) -> Result<Self, AdspError> {
        if buf.len() < Self::HEADER_LEN {
            return Err(AdspError::InvalidSize {
                expected: Self::HEADER_LEN,
                found: buf.len(),
            });
        }

        let descriptor = AdspDescriptor::try_from(buf[0])?;
        let connection_id = BigEndian::read_u16(&buf[1..3]);
        let first_byte_seq = BigEndian::read_u32(&buf[3..7]);
        let next_recv_seq = BigEndian::read_u32(&buf[7..11]);
        let recv_window = BigEndian::read_u16(&buf[11..13]);

        Ok(Self {
            descriptor,
            connection_id,
            first_byte_seq,
            next_recv_seq,
            recv_window,
        })
    }

    /// Encode the ADSP header to bytes
    ///
    /// Returns the number of bytes written (always HEADER_LEN).
    /// The caller is responsible for appending any data payload.
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, AdspError> {
        if buf.len() < Self::HEADER_LEN {
            return Err(AdspError::InvalidSize {
                expected: Self::HEADER_LEN,
                found: buf.len(),
            });
        }

        buf[0] = self.descriptor as u8;
        BigEndian::write_u16(&mut buf[1..3], self.connection_id);
        BigEndian::write_u32(&mut buf[3..7], self.first_byte_seq);
        BigEndian::write_u32(&mut buf[7..11], self.next_recv_seq);
        BigEndian::write_u16(&mut buf[11..13], self.recv_window);

        Ok(Self::HEADER_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_conn_request() {
        // OpenConnRequest: descriptor=0x81, conn_id=0x1234,
        // first_byte_seq=0, next_recv_seq=0, recv_window=4096
        let data: &[u8] = &[
            0x81, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::OpenConnRequest);
        assert_eq!(packet.connection_id, 0x1234);
        assert_eq!(packet.first_byte_seq, 0);
        assert_eq!(packet.next_recv_seq, 0);
        assert_eq!(packet.recv_window, 4096);
    }

    #[test]
    fn test_parse_control_packet() {
        // ControlPacket with sequence numbers and window
        let data: &[u8] = &[
            0x80, 0xAB, 0xCD, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00,
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::ControlPacket);
        assert_eq!(packet.connection_id, 0xABCD);
        assert_eq!(packet.first_byte_seq, 0x00010000);
        assert_eq!(packet.next_recv_seq, 0x00020000);
        assert_eq!(packet.recv_window, 8192);
    }

    #[test]
    fn test_parse_acknowledgment() {
        // Acknowledgment packet
        let data: &[u8] = &[
            0x88, 0x00, 0x42, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x07, 0xD0, 0x08, 0x00,
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::Acknowledgment);
        assert_eq!(packet.connection_id, 0x0042);
        assert_eq!(packet.first_byte_seq, 1000);
        assert_eq!(packet.next_recv_seq, 2000);
        assert_eq!(packet.recv_window, 2048);
    }

    #[test]
    fn test_encode_open_conn_ack() {
        let packet = AdspPacket {
            descriptor: AdspDescriptor::OpenConnAck,
            connection_id: 0x5678,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 8192,
        };

        let expected: &[u8] = &[
            0x82, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
        ];

        let mut buf = [0u8; 13];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, AdspPacket::HEADER_LEN);
        assert_eq!(&buf, expected);
    }

    #[test]
    fn test_encode_close_advice() {
        let packet = AdspPacket {
            descriptor: AdspDescriptor::CloseAdvice,
            connection_id: 0x9999,
            first_byte_seq: 1234567,
            next_recv_seq: 7654321,
            recv_window: 0,
        };

        let mut buf = [0u8; 13];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, AdspPacket::HEADER_LEN);
        assert_eq!(buf[0], 0x85); // CloseAdvice
        assert_eq!(BigEndian::read_u16(&buf[1..3]), 0x9999);
        assert_eq!(BigEndian::read_u32(&buf[3..7]), 1234567);
        assert_eq!(BigEndian::read_u32(&buf[7..11]), 7654321);
        assert_eq!(BigEndian::read_u16(&buf[11..13]), 0);
    }

    #[test]
    fn test_round_trip() {
        let original = AdspPacket {
            descriptor: AdspDescriptor::ForwardReset,
            connection_id: 0xBEEF,
            first_byte_seq: 0xDEADBEEF,
            next_recv_seq: 0xCAFEBABE,
            recv_window: 0xFFFF,
        };

        let mut buf = [0u8; 13];
        let len = original.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(len, AdspPacket::HEADER_LEN);

        let parsed = AdspPacket::parse(&buf).expect("failed to parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_descriptor() {
        // Invalid descriptor code 0x99
        let data: &[u8] = &[
            0x99, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = AdspPacket::parse(data);
        assert!(result.is_err());
        match result {
            Err(AdspError::UnknownDescriptor { code: 0x99 }) => {}
            _ => panic!("Expected UnknownDescriptor error"),
        }
    }

    #[test]
    fn test_buffer_too_small_parse() {
        let data: &[u8] = &[0x80, 0x00, 0x00]; // Only 3 bytes

        let result = AdspPacket::parse(data);
        assert!(result.is_err());
        match result {
            Err(AdspError::InvalidSize {
                expected: 13,
                found: 3,
            }) => {}
            _ => panic!("Expected InvalidSize error"),
        }
    }

    #[test]
    fn test_buffer_too_small_encode() {
        let packet = AdspPacket {
            descriptor: AdspDescriptor::ControlPacket,
            connection_id: 1,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 1024,
        };

        let mut buf = [0u8; 5]; // Too small
        let result = packet.to_bytes(&mut buf);
        assert!(result.is_err());
        match result {
            Err(AdspError::InvalidSize {
                expected: 13,
                found: 5,
            }) => {}
            _ => panic!("Expected InvalidSize error"),
        }
    }

    #[test]
    fn test_parse_with_data_payload() {
        // ADSP header followed by data payload
        let data: &[u8] = &[
            0x80, 0x11, 0x22, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x10, 0x00,
            // Data payload follows:
            b'H', b'e', b'l', b'l', b'o',
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::ControlPacket);
        assert_eq!(packet.connection_id, 0x1122);
        assert_eq!(packet.first_byte_seq, 1);
        assert_eq!(packet.next_recv_seq, 2);
        assert_eq!(packet.recv_window, 4096);

        // Verify caller can access data after header
        let payload = &data[AdspPacket::HEADER_LEN..];
        assert_eq!(payload, b"Hello");
    }
}
