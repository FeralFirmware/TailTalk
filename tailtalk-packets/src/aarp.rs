use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, BytesMut};
use std::io::{Cursor, Error, Read};

const AARP_MIN_LEN: usize = 28;

pub type EthernetMac = [u8; 6];

#[derive(Debug)]
pub enum AarpError {
    InvalidSize,
    UnknownOpcode(u16),
    StdIoError(Error),
}

impl From<Error> for AarpError {
    fn from(err: Error) -> AarpError {
        AarpError::StdIoError(err)
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub struct AppleTalkAddress {
    pub network_number: u16,
    pub node_number: u8,
}

impl AppleTalkAddress {
    pub fn decode(address_bytes: [u8; 4]) -> Self {
        let network_number = u16::from_be_bytes([address_bytes[1], address_bytes[2]]);
        let node_number = address_bytes[3];

        AppleTalkAddress {
            network_number,
            node_number,
        }
    }

    pub fn encode(&self, encoded_address: &mut [u8; 4]) {
        encoded_address[0] = 0;
        encoded_address[1..=2].copy_from_slice(&self.network_number.to_be_bytes());
        encoded_address[3] = self.node_number;
    }

    pub fn matches(&self, other: &AppleTalkAddress, source: AddressSource) -> bool {
        match source {
            AddressSource::LocalTalk => self.node_number == other.node_number,
            AddressSource::EtherTalk => self == other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    EtherTalk,
    LocalTalk,
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AarpOpcode {
    Request = 1,
    Response = 2,
    Probe = 3,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AarpPacket {
    pub hardware_type: u16,
    pub protocol_type: u16,
    pub hardware_size: u8, // Always 6 for EtherTalk networks - Only case supported
    pub protocol_size: u8, // Always 4 for typical AppleTalk networks
    pub opcode: AarpOpcode,
    pub sender_addr: EthernetMac,
    pub sender_protocol: AppleTalkAddress,
    pub target_addr: EthernetMac,
    pub target_protocol: AppleTalkAddress,
}

impl AarpPacket {
    pub const LEN: usize = 28;

    pub fn parse(buf: &[u8]) -> Result<Self, AarpError> {
        if buf.len() < AARP_MIN_LEN {
            return Err(AarpError::InvalidSize);
        }

        let mut cursor = Cursor::new(buf);
        let hardware_type = cursor.read_u16::<BigEndian>()?;
        let protocol_type = cursor.read_u16::<BigEndian>()?;
        let hardware_size = cursor.read_u8()?;
        let protocol_size = cursor.read_u8()?;
        let opcode = {
            let opcode = cursor.read_u16::<BigEndian>()?;

            match opcode {
                1 => AarpOpcode::Request,
                2 => AarpOpcode::Response,
                3 => AarpOpcode::Probe,
                _ => return Err(AarpError::UnknownOpcode(opcode)),
            }
        };

        let mut sender_addr: [u8; 6] = [0u8; 6];
        cursor.read_exact(&mut sender_addr)?;

        let mut protocol: [u8; 4] = [0u8; 4];
        cursor.read_exact(&mut protocol)?;
        let sender_protocol = AppleTalkAddress::decode(protocol);

        let mut target_addr: [u8; 6] = [0u8; 6];
        cursor.read_exact(&mut target_addr)?;

        cursor.read_exact(&mut protocol)?;
        let target_protocol = AppleTalkAddress::decode(protocol);

        Ok(Self {
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            opcode,
            sender_addr,
            sender_protocol,
            target_addr,
            target_protocol,
        })
    }

    pub fn to_bytes(&self, buffer: &mut [u8]) -> usize {
        let mut buf = BytesMut::with_capacity(buffer.len());
        buf.put_u16(self.hardware_type);
        buf.put_u16(self.protocol_type);
        buf.put_u8(self.hardware_size);
        buf.put_u8(self.protocol_size);
        buf.put_u16(self.opcode as u16);

        buf.put_slice(&self.sender_addr);

        let mut sender_protocol_encoded = [0u8; 4];
        self.sender_protocol.encode(&mut sender_protocol_encoded);
        buf.put_slice(&sender_protocol_encoded);

        buf.put_slice(&self.target_addr);

        let mut target_protocol_encoded = [0u8; 4];
        self.target_protocol.encode(&mut target_protocol_encoded);
        buf.put_slice(&target_protocol_encoded);

        let used = buf.chunk();
        buffer[..used.len()].copy_from_slice(used);

        used.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_hex::assert_eq_hex;

    #[test]
    fn test_parse_aarp() {
        let test_data: &[u8] = &[
            0x00, 0x01, 0x80, 0x9b, 0x06, 0x04, 0x00, 0x03, 0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3,
            0x00, 0xff, 0x54, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x54, 0x44,
        ];

        let packet = AarpPacket::parse(test_data).expect("failed to parse");

        assert_eq_hex!(packet.hardware_type, 1);
        assert_eq_hex!(packet.protocol_type, 0x809b);
        assert_eq_hex!(packet.hardware_size, 6);
        assert_eq_hex!(packet.protocol_size, 4);
        assert_eq_hex!(packet.opcode, AarpOpcode::Probe);
        assert_eq_hex!(packet.sender_addr, [0x00u8, 0x0c, 0x29, 0x0d, 0x56, 0xe3]);
        assert_eq_hex!(packet.sender_protocol.network_number, 65364);
        assert_eq_hex!(packet.sender_protocol.node_number, 68);
        assert_eq_hex!(packet.target_addr, [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq_hex!(packet.target_protocol.network_number, 65364);
        assert_eq_hex!(packet.target_protocol.node_number, 68);
    }

    #[test]
    fn test_generate_aarp() {
        let test_pkt = AarpPacket {
            hardware_type: 1,
            protocol_type: 0x809b,
            hardware_size: 6,
            protocol_size: 4,
            opcode: AarpOpcode::Probe,
            sender_addr: [0x00u8, 0x0c, 0x29, 0x0d, 0x56, 0xe3],
            sender_protocol: AppleTalkAddress {
                network_number: 65310,
                node_number: 248,
            },
            target_addr: [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x00],
            target_protocol: AppleTalkAddress {
                network_number: 65310,
                node_number: 248,
            },
        };

        let mut test_buf: [u8; 100] = [0u8; 100];

        let pkt_size = test_pkt.to_bytes(&mut test_buf);
        let sized = &test_buf[..pkt_size];
        let expected_bin_data = &[
            0x00u8, 0x01, 0x80, 0x9b, 0x06, 0x04, 0x00, 0x03, 0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3,
            0x00, 0xff, 0x1e, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1e, 0xf8,
        ];

        assert_eq_hex!(sized, expected_bin_data);
    }

    #[test]
    fn test_dogfood() {
        let test_pkt = AarpPacket {
            hardware_type: 1,
            protocol_type: 0x809b,
            hardware_size: 6,
            protocol_size: 4,
            opcode: AarpOpcode::Request,
            sender_addr: [0x00u8, 0x0c, 0x29, 0x0d, 0x56, 0xe3],
            sender_protocol: AppleTalkAddress {
                network_number: 12345,
                node_number: 100,
            },
            target_addr: [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05],
            target_protocol: AppleTalkAddress {
                network_number: 54321,
                node_number: 200,
            },
        };

        let mut test_buf: [u8; 100] = [0u8; 100];
        let pkt_size = test_pkt.to_bytes(&mut test_buf);
        let sized = &test_buf[..pkt_size];

        let parsed = AarpPacket::parse(sized).expect("failed to parse");

        assert_eq!(test_pkt, parsed);
    }
}
