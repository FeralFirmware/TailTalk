use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

pub mod codec;
pub use codec::{TashTalkCodec, TashTalkCommand, TashTalkError};

pub mod crc;
pub use crc::{lt_crc, CrcCalculator};

/// Features that can be enabled on firmware v2.1.0+
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TashTalkFeatures {
    /// Enables CRC generation on the TashTalk itself - The two bytes provided at the end of a frame will be ignored
    /// and replaced by the correct CRC values.
    crc_calculation: bool,
    /// Enables CRC verification on the TashTalk itself. Frames that do not match the CRC will be dropped, and an error
    /// will be returned in the receive_frame() stream.
    crc_checking: bool,
}

impl TashTalkFeatures {
    /// Create a new empty feature set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable CRC calculation on the device.
    pub fn with_crc_calculation(mut self) -> Self {
        self.crc_calculation = true;
        self
    }

    /// Enable CRC checking on the device.
    pub fn with_crc_checking(mut self) -> Self {
        self.crc_checking = true;
        self
    }

    /// Convenience method to enable both CRC calculation and checking.
    pub fn with_crc(self) -> Self {
        self.with_crc_calculation().with_crc_checking()
    }
}

impl From<TashTalkFeatures> for u8 {
    fn from(features: TashTalkFeatures) -> u8 {
        let mut val = 0;
        if features.crc_calculation {
            val |= 0x80;
        }
        if features.crc_checking {
            val |= 0x40;
        }
        val
    }
}

/// A client for interacting with a TashTalk device.
/// Wraps a Framed stream from `tokio_util::codec` and provides
/// ergonomic methods for interacting with the hardware.
pub struct TashTalk<T> {
    framed: Framed<T, TashTalkCodec>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> TashTalk<T> {
    /// Create a new TashTalk instance wrapping an AsyncRead + AsyncWrite stream.
    /// E.g., a tokio_serial::SerialStream.
    /// *NOTE:* Hardware flow control needs to be enabled for transmitting to the TashTalk.
    /// It is up to the caller to enable this.
    pub fn new(io: T) -> Self {
        Self {
            framed: Framed::new(io, TashTalkCodec),
        }
    }

    /// Transmit a frame.
    /// `frame` must include the LLAP header and the 2 CRC bytes at the end.
    /// Note: if SetFeatures bit 7 (CRC Calculation) is enabled on TashTalk,
    /// it will overwrite the 2 CRC bytes with the correct values.
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), std::io::Error> {
        tracing::info!("sending frame of len: {}", frame.len());
        self.framed
            .send(TashTalkCommand::TransmitFrame(frame.to_vec()))
            .await
    }

    /// Reset the TashTalk device by sending 1024 Noop (0x00) commands.
    /// This ensures any internal hardware buffers are flushed.
    pub async fn reset(&mut self) -> Result<(), std::io::Error> {
        for _ in 0..1024 {
            self.framed.send(TashTalkCommand::Noop).await?;
        }
        Ok(())
    }

    /// Set the LocalTalk node IDs that this device will respond to.
    /// Bit 0 of byte 0 corresponds to ID 0; Bit 7 of byte 31 corresponds to ID 255.
    pub async fn set_node_ids(&mut self, nodes: [u8; 32]) -> Result<(), std::io::Error> {
        self.framed.send(TashTalkCommand::SetNodeIds(nodes)).await
    }

    /// Set features (for firmware v2.1.0+).
    /// Bit 7: CRC Calculation, Bit 6: CRC Checking.
    pub async fn set_features(&mut self, features: impl Into<u8>) -> Result<(), std::io::Error> {
        self.framed
            .send(TashTalkCommand::SetFeatures(features.into()))
            .await
    }

    /// Wait for and receive the next frame from the LocalTalk bus.
    pub async fn receive_frame(&mut self) -> Result<Option<Vec<u8>>, TashTalkError> {
        self.framed.next().await.transpose()
    }
}
