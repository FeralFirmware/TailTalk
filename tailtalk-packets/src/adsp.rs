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
///
/// The descriptor byte is the LAST byte of the 13-byte ADSP header (per spec Figure 12-2).
/// Bit 7 = Control flag. When clear, the packet carries stream data (DataPacket).
/// When set, bits 3-0 encode the control code; bits 6-4 are additional flags
/// (AckReq, EOM, Attention) stored separately in `AdspPacket::flags`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum AdspDescriptor {
    /// Data packet (Control bit = 0); flag bits live in `AdspPacket::flags`
    DataPacket = 0x00,
    /// Control packet / probe-ack (Control=1, code=0)
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
    /// Forward reset acknowledgment
    ForwardResetAck = 0x87,
    /// Retransmit advice — the receiver is missing data from
    /// `next_recv_seq` onward and asks the sender to roll back its send
    /// queue and retransmit from there (Inside AppleTalk ch. 12, code 8).
    /// Not a routine ack — plain acks are `ControlPacket` (code 0).
    RetransmitAdvice = 0x88,
}

impl TryFrom<u8> for AdspDescriptor {
    type Error = AdspError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value & 0x80 == 0 {
            return Ok(AdspDescriptor::DataPacket);
        }
        match value & 0x8F {
            0x80 => Ok(AdspDescriptor::ControlPacket),
            0x81 => Ok(AdspDescriptor::OpenConnRequest),
            0x82 => Ok(AdspDescriptor::OpenConnAck),
            0x83 => Ok(AdspDescriptor::OpenConnReqAck),
            0x84 => Ok(AdspDescriptor::OpenConnDeny),
            0x85 => Ok(AdspDescriptor::CloseAdvice),
            0x86 => Ok(AdspDescriptor::ForwardReset),
            0x87 => Ok(AdspDescriptor::ForwardResetAck),
            0x88 => Ok(AdspDescriptor::RetransmitAdvice),
            _ => Err(AdspError::UnknownDescriptor { code: value }),
        }
    }
}

/// ADSP packet header structure
///
/// ADSP (AppleTalk Data Stream Protocol) provides connection-oriented,
/// full-duplex byte-stream communication over DDP.
///
/// Packet format (per spec Figure 12-2):
/// - Bytes 0-1:  Connection ID (u16, big-endian)
/// - Bytes 2-5:  First Byte Sequence number (u32, big-endian)
/// - Bytes 6-9:  Next Receive Sequence number (u32, big-endian)
/// - Bytes 10-11: Receive Window size (u16, big-endian)
/// - Byte 12:    Descriptor (packet type + flag bits)
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
    /// Flags (Control, Ack, EOM, Attention)
    pub flags: u8,
}

impl AdspPacket {
    /// ADSP header length in bytes
    pub const HEADER_LEN: usize = 13;

    pub const FLAG_CONTROL: u8 = 0x80;
    pub const FLAG_ACK: u8 = 0x40;
    pub const FLAG_EOM: u8 = 0x20;
    pub const FLAG_ATTENTION: u8 = 0x10;

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

        let connection_id = BigEndian::read_u16(&buf[0..2]);
        let first_byte_seq = BigEndian::read_u32(&buf[2..6]);
        let next_recv_seq = BigEndian::read_u32(&buf[6..10]);
        let recv_window = BigEndian::read_u16(&buf[10..12]);
        let desc_byte = buf[12];
        let descriptor = AdspDescriptor::try_from(desc_byte)?;
        let flags = desc_byte & 0xF0;

        Ok(Self {
            descriptor,
            connection_id,
            first_byte_seq,
            next_recv_seq,
            recv_window,
            flags,
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

        BigEndian::write_u16(&mut buf[0..2], self.connection_id);
        BigEndian::write_u32(&mut buf[2..6], self.first_byte_seq);
        BigEndian::write_u32(&mut buf[6..10], self.next_recv_seq);
        BigEndian::write_u16(&mut buf[10..12], self.recv_window);
        buf[12] = (self.descriptor as u8) | self.flags;

        Ok(Self::HEADER_LEN)
    }
}

/// An ADSP Attention data packet (out-of-band message)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdspAttentionPacket<'a> {
    pub header: AdspPacket,
    pub attention_code: u16,
    pub data: &'a [u8],
}

impl<'a> AdspAttentionPacket<'a> {
    /// Parse an Attention packet from a raw ADSP payload
    pub fn parse(buf: &'a [u8]) -> Result<Self, AdspError> {
        let header = AdspPacket::parse(buf)?;

        if header.flags & AdspPacket::FLAG_ATTENTION == 0 {
            return Err(AdspError::UnknownDescriptor { code: buf[0] }); // Not an attention packet
        }

        let payload = &buf[AdspPacket::HEADER_LEN..];
        if payload.len() < 2 {
            return Err(AdspError::InvalidSize {
                expected: AdspPacket::HEADER_LEN + 2,
                found: buf.len(),
            });
        }

        let attention_code = BigEndian::read_u16(&payload[0..2]);
        let data = &payload[2..];

        Ok(Self {
            header,
            attention_code,
            data,
        })
    }

    /// Write the Attention code into the buffer following the ADSP header
    pub fn write_payload_to(&self, buf: &mut [u8]) -> Result<usize, AdspError> {
        if buf.len() < 2 + self.data.len() {
            return Err(AdspError::InvalidSize {
                expected: 2 + self.data.len(),
                found: buf.len(),
            });
        }

        BigEndian::write_u16(&mut buf[0..2], self.attention_code);
        buf[2..2 + self.data.len()].copy_from_slice(self.data);

        Ok(2 + self.data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_open_conn_request() {
        let data: &[u8] = &[
            0x12, 0x34, // conn_id
            0x00, 0x00, 0x00, 0x00, // first_byte_seq
            0x00, 0x00, 0x00, 0x00, // next_recv_seq
            0x10, 0x00, // recv_window = 4096
            0x81,       // descriptor = OpenConnRequest
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
        let data: &[u8] = &[
            0xAB, 0xCD, // conn_id
            0x00, 0x01, 0x00, 0x00, // first_byte_seq
            0x00, 0x02, 0x00, 0x00, // next_recv_seq
            0x20, 0x00, // recv_window = 8192
            0x80,       // descriptor = ControlPacket
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::ControlPacket);
        assert_eq!(packet.connection_id, 0xABCD);
        assert_eq!(packet.first_byte_seq, 0x00010000);
        assert_eq!(packet.next_recv_seq, 0x00020000);
        assert_eq!(packet.recv_window, 8192);
    }

    #[test]
    fn test_parse_retransmit_advice() {
        let data: &[u8] = &[
            0x00, 0x42, // conn_id
            0x00, 0x00, 0x03, 0xE8, // first_byte_seq = 1000
            0x00, 0x00, 0x07, 0xD0, // next_recv_seq = 2000
            0x08, 0x00, // recv_window = 2048
            0x88,       // descriptor = RetransmitAdvice (control code 8)
        ];

        let packet = AdspPacket::parse(data).expect("failed to parse");

        assert_eq!(packet.descriptor, AdspDescriptor::RetransmitAdvice);
        assert_eq!(packet.connection_id, 0x0042);
        assert_eq!(packet.first_byte_seq, 1000);
        assert_eq!(packet.next_recv_seq, 2000);
        assert_eq!(packet.recv_window, 2048);
    }

    #[test]
    fn test_parse_data_packet() {
        let data: &[u8] = &[
            0x00, 0x0A, // conn_id = 10
            0x00, 0x00, 0x00, 0x00, // first_byte_seq
            0x00, 0x00, 0x00, 0x00, // next_recv_seq
            0x06, 0xB4, // recv_window = 1716
            0x40,       // descriptor = DataPacket (AckReq flag)
        ];
        let packet = AdspPacket::parse(data).expect("failed to parse");
        assert_eq!(packet.descriptor, AdspDescriptor::DataPacket);
        assert_eq!(packet.connection_id, 0x000A);
        assert_eq!(packet.flags & AdspPacket::FLAG_ACK, AdspPacket::FLAG_ACK);
        assert_eq!(packet.flags & AdspPacket::FLAG_ATTENTION, 0);
    }

    #[test]
    fn test_parse_attention_ack() {
        let data: &[u8] = &[
            0x00, 0x0A, // conn_id
            0x00, 0x00, 0x00, 0x00, // first_byte_seq
            0x00, 0x00, 0x00, 0x01, // next_recv_seq
            0x00, 0x00, // recv_window
            0x90,       // Control=1, Attention=1, code=0
        ];
        let packet = AdspPacket::parse(data).expect("failed to parse");
        assert_eq!(packet.descriptor, AdspDescriptor::ControlPacket);
        assert_ne!(packet.flags & AdspPacket::FLAG_ATTENTION, 0);
    }

    #[test]
    fn test_encode_open_conn_ack() {
        let packet = AdspPacket {
            descriptor: AdspDescriptor::OpenConnAck,
            connection_id: 0x5678,
            first_byte_seq: 0,
            next_recv_seq: 0,
            recv_window: 8192,
            flags: 0,
        };

        let expected: &[u8] = &[
            0x56, 0x78, // conn_id
            0x00, 0x00, 0x00, 0x00, // first_byte_seq
            0x00, 0x00, 0x00, 0x00, // next_recv_seq
            0x20, 0x00, // recv_window = 8192
            0x82,       // descriptor = OpenConnAck
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
            flags: 0,
        };

        let mut buf = [0u8; 13];
        let len = packet.to_bytes(&mut buf).expect("failed to encode");

        assert_eq!(len, AdspPacket::HEADER_LEN);
        assert_eq!(BigEndian::read_u16(&buf[0..2]), 0x9999);
        assert_eq!(BigEndian::read_u32(&buf[2..6]), 1234567);
        assert_eq!(BigEndian::read_u32(&buf[6..10]), 7654321);
        assert_eq!(BigEndian::read_u16(&buf[10..12]), 0);
        assert_eq!(buf[12], 0x85);
    }

    #[test]
    fn test_round_trip() {
        let original = AdspPacket {
            descriptor: AdspDescriptor::ForwardReset,
            connection_id: 0xBEEF,
            first_byte_seq: 0xDEADBEEF,
            next_recv_seq: 0xCAFEBABE,
            recv_window: 0xFFFF,
            flags: 0x80,
        };

        let mut buf = [0u8; 13];
        let len = original.to_bytes(&mut buf).expect("failed to encode");
        assert_eq!(len, AdspPacket::HEADER_LEN);

        let parsed = AdspPacket::parse(&buf).expect("failed to parse");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_descriptor() {
        let data: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99,
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
            flags: 0,
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
        let data: &[u8] = &[
            0x11, 0x22, // conn_id
            0x00, 0x00, 0x00, 0x01, // first_byte_seq
            0x00, 0x00, 0x00, 0x02, // next_recv_seq
            0x10, 0x00, // recv_window = 4096
            0x80,       // descriptor = ControlPacket
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
