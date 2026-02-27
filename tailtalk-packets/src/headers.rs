use crate::{
    aarp::{AarpError, AarpPacket},
    aep::{AepError, AepPacket},
    atp::{AtpError, AtpPacket},
    ddp::{DdpError, DdpPacket, DdpProtocolType},
    ethertalk::{EtherTalkError, EtherTalkFrame, EtherTalkType},
};
use thiserror::Error;

#[derive(Debug)]
pub enum NetHeader {
    Aarp(AarpPacket),
    Ddp(DdpPacket),
}

#[derive(Debug)]
pub enum TransportHeader {
    Aep(AepPacket),
    Atp(AtpPacket),
}

#[derive(Debug)]
pub struct AppleTalkHeaders {
    pub link: EtherTalkFrame,
    pub net: NetHeader,
    pub transport: Option<TransportHeader>,
    pub payload: Option<Box<[u8]>>,
}

#[derive(Error, Debug)]
pub enum AppleTalkError {
    #[error("invalid input buffer size - expected {expected:?} bytes but found {found:?}")]
    InvalidSize { expected: usize, found: usize },
    #[error("Exceeded maximum possible packet size of 65536")]
    ExceededMax,
    #[error("failed to encode/decode link header")]
    LinkHeaderError(EtherTalkError),
    #[error("failed to encode DDP header")]
    DdpError(DdpError),
    #[error("failed to encode/decode AARP header")]
    AarpError(AarpError),
    #[error("failed to encode AEP header")]
    AepError(AepError),
    #[error("failed to encode ATP header")]
    AtpError(AtpError),
}

impl AppleTalkHeaders {
    pub fn encode(mut self, buffer: &mut [u8]) -> Result<usize, AppleTalkError> {
        let net_size = match self.net {
            NetHeader::Ddp(_) => DdpPacket::LEN,
            NetHeader::Aarp(_) => AarpPacket::LEN,
        };
        let transport_size = match self.transport {
            Some(TransportHeader::Aep(ref pkt)) => pkt.len(),
            Some(TransportHeader::Atp(_)) => AtpPacket::HEADER_LEN,
            None => 0,
        };
        let total_len = EtherTalkFrame::LLC_LEN
            + net_size
            + transport_size
            + self.payload.as_ref().map_or(0, |p| p.len());

        if total_len >= u16::MAX as usize {
            return Err(AppleTalkError::ExceededMax);
        }
        self.link.len = total_len as u16;

        let mut pos = self
            .link
            .to_bytes(buffer)
            .map_err(AppleTalkError::LinkHeaderError)?;

        pos += match self.net {
            NetHeader::Aarp(pkt) => pkt.to_bytes(&mut buffer[pos..]),
            NetHeader::Ddp(pkt) => pkt
                .to_bytes(&mut buffer[pos..])
                .map_err(AppleTalkError::DdpError)?,
        };

        pos += match self.transport {
            Some(TransportHeader::Aep(pkt)) => pkt
                .to_bytes(&mut buffer[pos..])
                .map_err(AppleTalkError::AepError)?,
            Some(TransportHeader::Atp(pkt)) => pkt
                .to_bytes(&mut buffer[pos..])
                .map_err(AppleTalkError::AtpError)?,
            None => 0,
        };

        if let Some(payload) = self.payload {
            if buffer.len() - pos < payload.len() {
                return Err(AppleTalkError::InvalidSize {
                    expected: pos + payload.len(),
                    found: buffer.len(),
                });
            }
            buffer[pos..(pos + payload.len())].copy_from_slice(&payload);
            pos += payload.len();
        }

        Ok(pos)
    }

    pub fn decode(pkt: &[u8]) -> Result<AppleTalkHeaders, AppleTalkError> {
        let link = EtherTalkFrame::parse(pkt).map_err(AppleTalkError::LinkHeaderError)?;

        let net = match link.protocol {
            EtherTalkType::Ddp => {
                let ddp_pkt = DdpPacket::parse(&pkt[EtherTalkFrame::len()..])
                    .map_err(AppleTalkError::DdpError)?;
                NetHeader::Ddp(ddp_pkt)
            }
            EtherTalkType::Aarp => {
                let aarp_pkt = AarpPacket::parse(&pkt[EtherTalkFrame::len()..])
                    .map_err(AppleTalkError::AarpError)?;
                NetHeader::Aarp(aarp_pkt)
            }
        };

        let (transport, payload) = match net {
            NetHeader::Ddp(ref ddp) => match ddp.protocol_typ {
                DdpProtocolType::Aep => (
                    Some(TransportHeader::Aep(
                        AepPacket::parse(&pkt[EtherTalkFrame::len() + DdpPacket::LEN..])
                            .map_err(AppleTalkError::AepError)?,
                    )),
                    None,
                ),
                DdpProtocolType::Atp => {
                    let offset = EtherTalkFrame::len() + DdpPacket::LEN;
                    let atp_pkt = AtpPacket::parse(&pkt[offset..])
                        .map_err(AppleTalkError::AtpError)?;
                    let payload_offset = offset + AtpPacket::HEADER_LEN;
                    let payload = if payload_offset < pkt.len() {
                        Some(pkt[payload_offset..].to_vec().into_boxed_slice())
                    } else {
                        None
                    };
                    (Some(TransportHeader::Atp(atp_pkt)), payload)
                }
                _ => (None, None),
            },
            _ => (None, None),
        };

        Ok(AppleTalkHeaders {
            link,
            net,
            transport,
            payload,
        })
    }
}
