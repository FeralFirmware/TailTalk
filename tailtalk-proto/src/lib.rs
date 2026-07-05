//! Wire protocol for the TailTalk daemon (`tailtalkd`).
//!
//! Message types are generated from `proto/tailtalk.proto`; see that file for
//! the protocol documentation (framing, correlation, session semantics).
//! This crate also provides the varint-delimited framing helpers used by both
//! the daemon and the in-process client.

use bytes::{Buf, BytesMut};
use prost::Message;
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};

mod generated {
    include!(concat!(env!("OUT_DIR"), "/tailtalk.v1.rs"));
}

pub use generated::*;
pub use prost;

/// Largest accepted encoded message, matching the limit documented in the
/// .proto file. Far above any legal DDP payload (586 bytes) plus overhead.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Encode `msg` varint-length-delimited into a fresh buffer.
pub fn encode_frame(msg: &impl Message) -> Vec<u8> {
    let mut buf = Vec::with_capacity(msg.encoded_len() + 4);
    msg.encode_length_delimited(&mut buf)
        .expect("Vec<u8> write cannot fail");
    buf
}

pub struct TailTalkCodec<In, Out>(PhantomData<(In, Out)>);

impl<In, Out> Default for TailTalkCodec<In, Out> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<In: Message, Out> Encoder<In> for TailTalkCodec<In, Out> {
    type Error = std::io::Error;

    fn encode(&mut self, item: In, dst: &mut BytesMut) -> Result<(), Self::Error> {
        item.encode_length_delimited(dst)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl<In, Out: Message + Default> Decoder for TailTalkCodec<In, Out> {
    type Item = Out;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut len: usize = 0;
        let mut shift = 0u32;
        let mut prefix_len = 0;

        // Decode the LEB128 length prefix
        loop {
            if prefix_len >= src.len() {
                return Ok(None);
            }
            let byte = src[prefix_len];
            prefix_len += 1;

            len |= ((byte & 0x7f) as usize) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "varint length prefix too long",
                ));
            }
        }

        if len > MAX_MESSAGE_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame length {len} exceeds maximum {MAX_MESSAGE_LEN}"),
            ));
        }

        if src.len() < prefix_len + len {
            return Ok(None);
        }

        src.advance(prefix_len);
        let payload = src.split_to(len);
        let msg = Out::decode(payload.freeze())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Some(msg))
    }
}

/// Decode all varint-length-delimited messages packed into one datagram.
///
/// Used for the UDP transport, where a datagram carries one or more complete
/// frames. Trailing garbage or a truncated frame is an error.
pub fn decode_datagram<M: Message + Default>(mut buf: &[u8]) -> std::io::Result<Vec<M>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let msg = M::decode_length_delimited(&mut buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        out.push(msg);
    }
    Ok(out)
}

impl AppleTalkAddress {
    pub fn new(network: u16, node: u8) -> Self {
        Self {
            network: network as u32,
            node: node as u32,
        }
    }
}

impl Reply {
    /// Convenience constructor for a reply carrying the given kind.
    pub fn new(id: u64, kind: reply::Kind) -> Self {
        Self {
            id,
            kind: Some(kind),
        }
    }

    /// A generic success reply.
    pub fn ok(id: u64) -> Self {
        Self::new(id, reply::Kind::Ok(Ok {}))
    }

    /// An error reply.
    pub fn error(id: u64, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(
            id,
            reply::Kind::Error(Error {
                code: code as i32,
                message: message.into(),
            }),
        )
    }
}

impl ServerMessage {
    pub fn reply(reply: Reply) -> Self {
        Self {
            kind: Some(server_message::Kind::Reply(reply)),
        }
    }

    pub fn datagram(datagram: ReceivedDatagram) -> Self {
        Self {
            kind: Some(server_message::Kind::Datagram(datagram)),
        }
    }

    pub fn routes_changed(routes: ListRoutesReply) -> Self {
        Self {
            kind: Some(server_message::Kind::RoutesChanged(routes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> Request {
        Request {
            id: 42,
            kind: Some(request::Kind::Send(SendDatagram {
                socket_id: 129,
                dest: Some(AppleTalkAddress::new(1, 7)),
                dest_socket: 2,
                payload: vec![0xAA; 100],
                ddp_type: 0,
            })),
        }
    }

    #[test]
    fn frame_roundtrip_stream() {
        let req = sample_request();
        let mut buf = BytesMut::new();
        let mut codec = TailTalkCodec::<Request, Request>::default();

        codec.encode(req.clone(), &mut buf).unwrap();
        codec.encode(req.clone(), &mut buf).unwrap();

        let a = codec.decode(&mut buf).unwrap().unwrap();
        let b = codec.decode(&mut buf).unwrap().unwrap();
        
        assert_eq!(a, req);
        assert_eq!(b, req);
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn truncated_frame_awaits_more_data() {
        let req = sample_request();
        let mut buf = BytesMut::new();
        let mut codec = TailTalkCodec::<Request, Request>::default();

        codec.encode(req, &mut buf).unwrap();
        buf.truncate(buf.len() - 1);

        // Decoding incomplete frame returns Ok(None) to wait for more data.
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn datagram_roundtrip() {
        let req = sample_request();
        let mut buf = encode_frame(&req);
        buf.extend_from_slice(&encode_frame(&req));
        let msgs: Vec<Request> = decode_datagram(&buf).unwrap();
        assert_eq!(msgs, vec![req.clone(), req]);
    }

    #[test]
    fn oversize_frame_rejected() {
        // Hand-craft a frame claiming a 1 MiB body.
        let buf = [0x80u8, 0x80, 0x40, 0x00];
        let mut bytes = BytesMut::from(&buf[..]);
        let mut codec = TailTalkCodec::<Request, Request>::default();
        let res = codec.decode(&mut bytes);
        assert!(res.is_err());
    }
}
