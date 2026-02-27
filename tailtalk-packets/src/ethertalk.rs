// Implementation of EtherTalk Phase II frames using 802.2 LLC + SNAP
use thiserror::Error;

// EtherTalk frames can be one of two types - Aarp, which has an OUI of 0 and a protocol ID of
// 0x80F3, or DDP with an OUI of 08:00:07 and protocol ID of 0x809B.
#[derive(Debug, PartialEq, Eq)]
pub enum EtherTalkType {
    Aarp,
    Ddp,
}

#[derive(Debug)]
pub struct EtherTalkFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub len: u16,
    pub protocol: EtherTalkType,
}

#[derive(Error, Debug)]
pub enum EtherTalkError {
    #[error("invalid size - expected frame to be at least 20 bytes, but found {found:?}")]
    InvalidSize { found: usize },
    #[error("not a SNAP frame")]
    NotSNAP,
    #[error("unknown OUI+protocol ID")]
    UnknownHeader,
}

impl EtherTalkFrame {
    pub const LLC_LEN: usize = 8;
    const FRAME_LEN: usize = 22;
    const SNAP_MARKER: [u8; 3] = [0xAA, 0xAA, 0x03];
    const AARP_OUI: [u8; 5] = [0x00, 0x00, 0x00, 0x80, 0xF3];
    const DDP_OUI: [u8; 5] = [0x08, 0x00, 0x07, 0x80, 0x9B];
    const DST_MAC_OFF: usize = 0;
    const SRC_MAC_OFF: usize = 6;
    const MAC_LEN: usize = 6;
    const LEN_OFF: usize = 12;
    const SNAP_OFF: usize = 14;
    const OUI_OFF: usize = 17;

    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, EtherTalkError> {
        assert!(buf.len() >= Self::FRAME_LEN);

        buf[Self::DST_MAC_OFF..(Self::DST_MAC_OFF + self.dst_mac.len())]
            .copy_from_slice(&self.dst_mac);
        buf[Self::SRC_MAC_OFF..(Self::SRC_MAC_OFF + self.src_mac.len())]
            .copy_from_slice(&self.src_mac);
        buf[Self::LEN_OFF..(Self::LEN_OFF + 2)].copy_from_slice(&u16::to_be_bytes(self.len));

        // Signifies that this is a SNAP frame
        buf[Self::SNAP_OFF..(Self::SNAP_OFF + Self::SNAP_MARKER.len())]
            .copy_from_slice(&Self::SNAP_MARKER);

        match self.protocol {
            EtherTalkType::Aarp => {
                buf[Self::OUI_OFF..(Self::OUI_OFF + Self::AARP_OUI.len())]
                    .copy_from_slice(&Self::AARP_OUI);
                Ok(Self::FRAME_LEN)
            }
            EtherTalkType::Ddp => {
                buf[Self::OUI_OFF..(Self::OUI_OFF + Self::DDP_OUI.len())]
                    .copy_from_slice(&Self::DDP_OUI);
                Ok(Self::FRAME_LEN)
            }
        }
    }

    pub const fn len() -> usize {
        Self::FRAME_LEN
    }

    pub fn parse(buf: &[u8]) -> Result<Self, EtherTalkError> {
        use EtherTalkError::*;

        if buf.len() < Self::FRAME_LEN {
            return Err(InvalidSize { found: buf.len() });
        } else if buf[Self::SNAP_OFF..(Self::SNAP_OFF + Self::SNAP_MARKER.len())]
            != Self::SNAP_MARKER
        {
            return Err(NotSNAP);
        }

        let dst_mac = &buf[Self::DST_MAC_OFF..(Self::DST_MAC_OFF + Self::MAC_LEN)];
        let src_mac = &buf[Self::SRC_MAC_OFF..(Self::SRC_MAC_OFF + Self::MAC_LEN)];

        if buf[Self::OUI_OFF..(Self::OUI_OFF + Self::AARP_OUI.len())] == Self::AARP_OUI {
            return Ok(Self {
                dst_mac: dst_mac.try_into().unwrap(),
                src_mac: src_mac.try_into().unwrap(),
                len: 10,
                protocol: EtherTalkType::Aarp,
            });
        } else if buf[Self::OUI_OFF..(Self::OUI_OFF + Self::DDP_OUI.len())] == Self::DDP_OUI {
            return Ok(Self {
                dst_mac: dst_mac.try_into().unwrap(),
                src_mac: src_mac.try_into().unwrap(),
                len: 10,
                protocol: EtherTalkType::Ddp,
            });
        }

        Err(UnknownHeader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_hex::assert_eq_hex;

    #[test]
    fn test_parse_ethertalk_aarp() {
        let test_data: &[u8] = &[
            0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3, 0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe4, 0x00, 0x04,
            0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0xf3, 0x00, 0x01, 0x80, 0x9b, 0x06, 0x04,
            0x00, 0x03, 0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3, 0x00, 0xff, 0x1e, 0xf8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1e, 0xf8,
        ];
        let dst_mac: [u8; 6] = [0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3];
        let src_mac: [u8; 6] = [0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe4];

        let packet = EtherTalkFrame::parse(test_data).expect("failed to parse");

        assert_eq_hex!(
            packet.dst_mac,
            dst_mac,
            "Destination MAC did not match expected"
        );
        assert_eq_hex!(packet.src_mac, src_mac, "Source MAC did not match expected");

        match packet.protocol {
            EtherTalkType::Aarp => {}
            _ => panic!("parsed as wrong type"),
        };
    }

    #[test]
    fn test_parse_ethertalk_ddp() {
        let test_data: &[u8] = &[
            0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe3, 0x00, 0x0c, 0x29, 0x0d, 0x56, 0xe4, 0x00, 0x04,
            0xaa, 0xaa, 0x03, 0x08, 0x00, 0x07, 0x80, 0x9b, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0xff, 0x1e, 0xff, 0xf8, 0x06, 0x06, 0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet = EtherTalkFrame::parse(test_data).expect("failed to parse");

        if EtherTalkType::Ddp != packet.protocol {
            panic!("parsed as wrong type");
        }
    }
}
