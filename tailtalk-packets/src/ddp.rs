use byteorder::{BigEndian, ByteOrder};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DdpError {
    #[error("invalid size - expected {expected:?} bytes but found {found:?}")]
    InvalidSize { expected: usize, found: usize },
    #[error("unknown header type - expected 1 or 2, but found {header:?}")]
    UnknownHeader { header: u8 },
    #[error("unknown protocol type {found:?}")]
    UnknownProtocol { found: u8 },
}

const RTMP_RESPONSE: u8 = 1;
const NBP: u8 = 2;
const ATP: u8 = 3;
const AEP: u8 = 4;
const RTMP_REQUEST: u8 = 5;
const ZIP: u8 = 6;
const ADSP: u8 = 7;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DdpProtocolType {
    RtmpResponse = RTMP_RESPONSE,
    Nbp = NBP,
    Atp = ATP,
    Aep = AEP,
    RtmpRequest = RTMP_REQUEST,
    Zip = ZIP,
    Adsp = ADSP,
}

impl TryFrom<u8> for DdpProtocolType {
    type Error = DdpError;

    fn try_from(data: u8) -> Result<Self, Self::Error> {
        match data {
            RTMP_RESPONSE => Ok(DdpProtocolType::RtmpResponse),
            NBP => Ok(DdpProtocolType::Nbp),
            ATP => Ok(DdpProtocolType::Atp),
            AEP => Ok(DdpProtocolType::Aep),
            RTMP_REQUEST => Ok(DdpProtocolType::RtmpRequest),
            ZIP => Ok(DdpProtocolType::Zip),
            ADSP => Ok(DdpProtocolType::Adsp),
            _ => Err(DdpError::UnknownProtocol { found: data }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DdpPacket {
    pub hop_count: u8,
    pub len: usize,
    pub chksum: u16,
    pub dest_network_num: u16,
    pub src_network_num: u16,
    pub dest_node_id: u8,
    pub dest_sock_num: u8,
    pub src_sock_num: u8,
    pub src_node_id: u8,
    pub protocol_typ: DdpProtocolType,
}

impl DdpPacket {
    pub const LEN: usize = 13;

    pub const fn calc_len(buf: &[u8]) -> usize {
        Self::LEN + buf.len() - 1
    }

    pub fn compute_checksum(buf: &[u8]) -> u16 {
        let mut csum: u16 = 0;

        for &byte in buf {
            csum = csum.wrapping_add(byte as u16);
            csum = csum.rotate_left(1);
        }
        if csum == 0 { 0xFFFF } else { csum }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, DdpError> {
        if bytes.len() < 13 {
            return Err(DdpError::InvalidSize {
                expected: 13,
                found: bytes.len(),
            });
        }

        let hop_count = (bytes[0] & 0x3C) >> 2;
        let data_len = (BigEndian::read_u16(bytes) & 0x3FF) as usize;
        let chksum = BigEndian::read_u16(&bytes[2..]);
        let dest_network_num = BigEndian::read_u16(&bytes[4..]);
        let src_network_num = BigEndian::read_u16(&bytes[6..]);
        let dest_node_id = bytes[8];
        let src_node_id = bytes[9];
        let dest_sock_num = bytes[10];
        let src_sock_num = bytes[11];
        let protocol_typ = bytes[12].try_into()?;

        Ok(Self {
            dest_node_id,
            hop_count,
            len: data_len,
            chksum,
            dest_network_num,
            src_network_num,
            src_node_id,
            dest_sock_num,
            src_sock_num,
            protocol_typ,
        })
    }

    pub fn parse_short(bytes: &[u8], dst_node: u8, src_node: u8) -> Result<Self, DdpError> {
        if bytes.len() < 5 {
            return Err(DdpError::InvalidSize {
                expected: 5,
                found: bytes.len(),
            });
        }

        let len = (BigEndian::read_u16(bytes) & 0x3FF) as usize;
        let dest_sock_num = bytes[2];
        let src_sock_num = bytes[3];
        let protocol_typ = bytes[4].try_into()?;

        Ok(Self {
            dest_node_id: dst_node,
            hop_count: 0,
            len,
            chksum: 0,
            dest_network_num: 0,
            src_network_num: 0,
            src_node_id: src_node,
            dest_sock_num,
            src_sock_num,
            protocol_typ,
        })
    }

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, DdpError> {
        if buf.len() < 13 {
            return Err(DdpError::InvalidSize {
                expected: 13,
                found: buf.len(),
            });
        }

        BigEndian::write_u16(buf, ((self.hop_count as u16 & 0xF) << 2) | self.len as u16);
        BigEndian::write_u16(&mut buf[2..], self.chksum);
        BigEndian::write_u16(&mut buf[4..], self.dest_network_num);
        BigEndian::write_u16(&mut buf[6..], self.src_network_num);
        buf[8] = self.dest_node_id;
        buf[9] = self.src_node_id;
        buf[10] = self.dest_sock_num;
        buf[11] = self.src_sock_num;
        buf[12] = self.protocol_typ as u8;

        Ok(13)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ddp() {
        let test_data: &[u8] = &[
            0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0xff, 0x54, 0xff, 0x44, 0x06, 0x06, 0x06, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet: DdpPacket = DdpPacket::parse(test_data).expect("failed to parse");

        assert_eq!(packet.hop_count, 0);
        assert_eq!(packet.len, 20);
        assert_eq!(packet.chksum, 0);
        assert_eq!(packet.src_network_num, 65364);
        assert_eq!(packet.dest_network_num, 0);
        assert_eq!(packet.src_node_id, 68);
        assert_eq!(packet.dest_node_id, 255);
        assert_eq!(packet.src_sock_num, 6);
        assert_eq!(packet.dest_sock_num, 6);
        assert_eq!(packet.protocol_typ, DdpProtocolType::Zip);
    }

    #[test]
    fn test_generate_ddp() {
        let test_data: &[u8] = &[
            0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0xff, 0x54, 0xff, 0x44, 0x06, 0x06, 0x06,
        ];

        let packet = DdpPacket {
            hop_count: 0,
            len: 20,
            chksum: 0,
            src_network_num: 65364,
            dest_network_num: 0,
            src_node_id: 68,
            dest_node_id: 255,
            src_sock_num: 6,
            dest_sock_num: 6,
            protocol_typ: DdpProtocolType::Zip,
        };

        let mut buffer: [u8; 13] = [0u8; 13];

        packet
            .to_bytes(&mut buffer)
            .expect("failed to generate packet");

        assert_eq!(test_data, &buffer);
    }

    #[test]
    fn test_parse_ddp_short() {
        // Short DDP packet: Length 5, DstSock 1, SrcSock 2, Type 6 (ZIP)
        let test_data: &[u8] = &[0x00, 0x05, 0x01, 0x02, 0x06];

        let dst_node = 10;
        let src_node = 20;

        let packet =
            DdpPacket::parse_short(test_data, dst_node, src_node).expect("failed to parse");

        assert_eq!(packet.len, 5);
        assert_eq!(packet.dest_node_id, dst_node);
        assert_eq!(packet.src_node_id, src_node);
        assert_eq!(packet.dest_sock_num, 1);
        assert_eq!(packet.src_sock_num, 2);
        assert_eq!(packet.protocol_typ, DdpProtocolType::Zip);
    }
}
