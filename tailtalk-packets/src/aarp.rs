use byteorder::{BigEndian, ByteOrder};

pub type EthernetMac = [u8; 6];

#[derive(Debug)]
pub enum AarpError {
    InvalidSize,
    UnknownOpcode(u16),
    UnsupportedHardwareSize(u8),
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
            AddressSource::EtherTalkPhase1 => self.node_number == other.node_number,
            AddressSource::EtherTalkPhase2 => self == other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    EtherTalkPhase2,
    EtherTalkPhase1,
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
    pub hardware_size: u8,
    pub protocol_size: u8,
    pub opcode: AarpOpcode,
    pub sender_addr: EthernetMac,
    pub sender_protocol: AppleTalkAddress,
    pub target_addr: EthernetMac,
    pub target_protocol: AppleTalkAddress,
}

impl AarpPacket {
    pub const LEN: usize = 28;

    pub fn parse(buf: &[u8]) -> Result<Self, AarpError> {
        if buf.len() < Self::LEN {
            return Err(AarpError::InvalidSize);
        }

        let hardware_type = BigEndian::read_u16(&buf[0..2]);
        let protocol_type = BigEndian::read_u16(&buf[2..4]);
        let hardware_size = buf[4];
        let protocol_size = buf[5];
        let opcode = match BigEndian::read_u16(&buf[6..8]) {
            1 => AarpOpcode::Request,
            2 => AarpOpcode::Response,
            3 => AarpOpcode::Probe,
            n => return Err(AarpError::UnknownOpcode(n)),
        };

        if hardware_size != 6 {
            return Err(AarpError::UnsupportedHardwareSize(hardware_size));
        }

        let mut proto_buf = [0u8; 4];

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&buf[8..14]);
        proto_buf.copy_from_slice(&buf[14..18]);
        let sender_protocol = AppleTalkAddress::decode(proto_buf);

        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&buf[18..24]);
        proto_buf.copy_from_slice(&buf[24..28]);
        let target_protocol = AppleTalkAddress::decode(proto_buf);

        Ok(Self {
            hardware_type,
            protocol_type,
            hardware_size,
            protocol_size,
            opcode,
            sender_addr: sender_mac,
            sender_protocol,
            target_addr: target_mac,
            target_protocol,
        })
    }

    pub fn to_bytes(&self, buffer: &mut [u8]) -> usize {
        BigEndian::write_u16(&mut buffer[0..2], self.hardware_type);
        BigEndian::write_u16(&mut buffer[2..4], self.protocol_type);
        buffer[4] = self.hardware_size;
        buffer[5] = self.protocol_size;
        BigEndian::write_u16(&mut buffer[6..8], self.opcode as u16);

        buffer[8..14].copy_from_slice(&self.sender_addr);

        let mut encoded = [0u8; 4];
        self.sender_protocol.encode(&mut encoded);
        buffer[14..18].copy_from_slice(&encoded);

        buffer[18..24].copy_from_slice(&self.target_addr);

        self.target_protocol.encode(&mut encoded);
        buffer[24..28].copy_from_slice(&encoded);

        Self::LEN
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
