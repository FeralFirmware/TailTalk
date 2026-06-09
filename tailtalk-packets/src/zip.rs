const GET_NET_INFO: u8 = 5;
const GET_NET_INFO_REPLY: u8 = 6;

/// ZIP GetNetInfo query (function code 5).
/// Broadcast to discover the local cable range and zone name.
pub struct ZipGetNetInfo {
    pub zone_name: String,
}

/// ZIP GetNetInfoReply (function code 6), sent by a router in response to GetNetInfo.
pub struct ZipGetNetInfoReply {
    pub flags: u8,
    pub cable_range_start: u16,
    pub cable_range_end: u16,
    pub zone_name: String,
}

impl ZipGetNetInfo {
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let zone = self.zone_name.as_bytes();
        let needed = 7 + zone.len();
        if buf.len() < needed {
            return Err("buffer too small");
        }
        buf[0] = GET_NET_INFO;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = zone.len() as u8;
        buf[7..needed].copy_from_slice(zone);
        Ok(needed)
    }
}

impl ZipGetNetInfoReply {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 7 || data[0] != GET_NET_INFO_REPLY {
            return None;
        }
        let flags = data[1];
        let cable_range_start = u16::from_be_bytes([data[2], data[3]]);
        let cable_range_end = u16::from_be_bytes([data[4], data[5]]);
        let zone_len = data[6] as usize;
        if data.len() < 7 + zone_len {
            return None;
        }
        let zone_name = String::from_utf8_lossy(&data[7..7 + zone_len]).into_owned();
        Some(Self {
            flags,
            cable_range_start,
            cable_range_end,
            zone_name,
        })
    }
}
