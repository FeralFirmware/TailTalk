use super::types::{AfpError, AfpUam, AfpVersion};
use crate::afp::util::MacString;
use crate::afp::{
    FPAccessRights, FPByteRangeLockFlags, FPDirectoryBitmap, FPFileAttributes, FPFileBitmap,
    FPVolumeBitmap,
};

/// AFP Command Codes
pub const AFP_CMD_BYTE_RANGE_LOCK: u8 = 1;
pub const AFP_CMD_CLOSE_VOL: u8 = 2;
pub const AFP_CMD_CLOSE_FORK: u8 = 4;
pub const AFP_CMD_CREATE_DIR: u8 = 6;
pub const AFP_CMD_CREATE_FILE: u8 = 7;
pub const AFP_CMD_DELETE: u8 = 8;
pub const AFP_CMD_ENUMERATE: u8 = 9;
pub const AFP_CMD_FLUSH: u8 = 10;
pub const AFP_CMD_GET_FORK_PARMS: u8 = 14;
pub const AFP_CMD_GET_SRVR_PARMS: u8 = 16;
pub const AFP_CMD_GET_VOL_PARMS: u8 = 17;
pub const AFP_CMD_LOGIN: u8 = 18;
pub const AFP_CMD_OPEN_VOL: u8 = 24;
pub const AFP_CMD_OPEN_FORK: u8 = 26;
pub const AFP_CMD_READ: u8 = 27;
pub const AFP_CMD_SET_DIR_PARMS: u8 = 29;
pub const AFP_CMD_SET_FORK_PARMS: u8 = 31;
pub const AFP_CMD_WRITE: u8 = 33;
pub const AFP_CMD_GET_FILE_DIR_PARMS: u8 = 34;
pub const AFP_CMD_SET_FILE_DIR_PARMS: u8 = 35;
pub const AFP_CMD_GET_SRVR_MSG: u8 = 38;
pub const AFP_CMD_OPEN_DT: u8 = 48;
pub const AFP_CMD_CLOSE_DT: u8 = 49;
pub const AFP_CMD_GET_ICON: u8 = 51;
pub const AFP_CMD_GTICNINFO: u8 = 52;
pub const AFP_CMD_ADD_APPL: u8 = 53;
pub const AFP_CMD_ADD_COMMENT: u8 = 56;
pub const AFP_CMD_REMOVE_COMMENT: u8 = 57;
pub const AFP_CMD_GET_COMMENT: u8 = 58;
pub const AFP_CMD_ADD_ICON: u8 = 192;

/// Authentication payload for FPLogin, varies by UAM
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FPLoginAuth {
    /// No authentication required
    NoUserAuthent,

    /// Clear text password authentication
    CleartxtPasswrd {
        username: MacString,
        password: [u8; 8], // Exactly 8 bytes, padded with nulls
    },
}

/// FPLogin command - authentication request from client to server
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FPLogin {
    /// AFP version the client wants to use
    pub afp_version: AfpVersion,

    /// User authentication method and credentials
    pub auth: FPLoginAuth,
}

impl FPLogin {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 2 {
            return Err(AfpError::InvalidSize);
        }

        let mut offset = 0;

        // Helper to read a Pascal string
        let read_pstr = |offset: usize| -> Result<(MacString, usize), AfpError> {
            let parsed = MacString::try_from(&buf[offset..])?;
            let next_offset = offset + parsed.byte_len();
            Ok((parsed, next_offset))
        };

        // Parse AFP version
        let (afp_version_str, next_offset) = read_pstr(offset)?;
        let afp_version = AfpVersion::try_from(afp_version_str.as_str())?;
        offset = next_offset;

        // Parse UAM
        let (uam_str, next_offset) = read_pstr(offset)?;
        let uam = AfpUam::try_from(uam_str.as_str())?;
        offset = next_offset;

        // Parse auth data based on UAM
        let auth = match uam {
            AfpUam::NoUserAuthent => FPLoginAuth::NoUserAuthent,

            AfpUam::CleartxtPasswrd => {
                // Parse username
                let (username, next_offset) = read_pstr(offset)?;
                offset = next_offset;

                // Parse 8-byte password
                if offset + 8 > buf.len() {
                    return Err(AfpError::InvalidSize);
                }
                let mut password = [0u8; 8];
                password.copy_from_slice(&buf[offset..offset + 8]);

                FPLoginAuth::CleartxtPasswrd { username, password }
            }

            _ => return Err(AfpError::BadUam),
        };

        Ok(FPLogin { afp_version, auth })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AfpError> {
        let mut buf = Vec::new();

        // Serialize AFP version
        let afp_version_str = self.afp_version.as_str();
        let len = afp_version_str.len() as u8;
        buf.push(len);
        buf.extend_from_slice(afp_version_str.as_bytes());

        // Serialize UAM and auth data based on variant
        match &self.auth {
            FPLoginAuth::NoUserAuthent => {
                let uam_str = AfpUam::NoUserAuthent.as_str();
                let len = uam_str.len() as u8;
                buf.push(len);
                buf.extend_from_slice(uam_str.as_bytes());
                // No additional data for NoUserAuthent
            }

            FPLoginAuth::CleartxtPasswrd { username, password } => {
                let uam_str = AfpUam::CleartxtPasswrd.as_str();
                let len = uam_str.len() as u8;
                buf.push(len);
                buf.extend_from_slice(uam_str.as_bytes());

                // Serialize username
                let mut username_buf = [0u8; 256];
                let written = username.bytes(&mut username_buf)?;
                buf.extend_from_slice(&username_buf[..written]);

                // Serialize 8-byte password
                buf.extend_from_slice(password);
            }
        }

        Ok(buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FPGetSrvrInfo {
    pub machine_type: MacString,
    pub afp_versions: Vec<AfpVersion>,
    pub uams: Vec<AfpUam>,
    pub volume_icon: Option<[u8; 256]>,
    pub flags: u16,
    pub server_name: MacString,
}

impl FPGetSrvrInfo {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 11 {
            // 10 bytes header + at least 1 byte server name len
            return Err(AfpError::InvalidSize);
        }

        let machine_type_offset = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        let afp_versions_offset = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let uams_offset = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let volume_icon_offset = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let flags = u16::from_be_bytes([buf[8], buf[9]]);

        // Server Name is inline at offset 10
        let server_name_len = buf[10] as usize;
        if 10 + 1 + server_name_len > buf.len() {
            return Err(AfpError::InvalidSize);
        }
        let server_name = MacString::try_from(&buf[10..10 + 1 + server_name_len])?;

        // Helper to read a pascal string at a given offset
        let read_pstr = |offset: usize| -> Result<MacString, AfpError> {
            if offset >= buf.len() {
                return Err(AfpError::InvalidSize);
            }
            let len = buf[offset] as usize;
            if offset + 1 + len > buf.len() {
                return Err(AfpError::InvalidSize);
            }
            Ok(MacString::try_from(&buf[offset..offset + 1 + len])?)
        };

        // Helper to read a list of pascal strings (Count byte + Strings)
        let read_pstr_list = |offset: usize| -> Result<Vec<MacString>, AfpError> {
            if offset >= buf.len() {
                return Err(AfpError::InvalidSize);
            }
            let count = buf[offset] as usize;
            let mut strings: Vec<MacString> = Vec::with_capacity(count);
            let mut current_pos = offset + 1;

            for _ in 0..count {
                if current_pos >= buf.len() {
                    return Err(AfpError::InvalidSize);
                }

                let new_string = MacString::try_from(&buf[current_pos..])?;
                current_pos += new_string.byte_len();
                strings.push(new_string);
            }
            Ok(strings)
        };

        let machine_type = read_pstr(machine_type_offset)?;
        let afp_versions_strings: Vec<MacString> = read_pstr_list(afp_versions_offset)?;
        let afp_versions: Vec<AfpVersion> = afp_versions_strings
            .iter()
            .map(|s| AfpVersion::try_from(s.as_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AfpError::BadVersNum)?;
        let uams_strings: Vec<MacString> = read_pstr_list(uams_offset)?;
        let uams: Vec<AfpUam> = uams_strings
            .iter()
            .map(|s| AfpUam::try_from(s.as_str()).map_err(|_| AfpError::BadUam))
            .collect::<Result<Vec<_>, _>>()?;

        // server_name already read

        let volume_icon = if volume_icon_offset != 0 {
            if volume_icon_offset + 256 > buf.len() {
                return Err(AfpError::InvalidSize);
            }
            let mut icon = [0u8; 256];
            icon.copy_from_slice(&buf[volume_icon_offset..volume_icon_offset + 256]);
            Some(icon)
        } else {
            None
        };

        Ok(Self {
            machine_type,
            afp_versions,
            uams,
            volume_icon,
            flags,
            server_name,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, AfpError> {
        let mut buf = Vec::new();

        // Header size = 10 bytes (offsets + flags) + Server Name (1 + 32 bytes).

        // TODO: Do we actually need to pad this? Classic MacOS does but Inside AppleTalk does not mention it
        const SERVER_NAME_FIELD_SIZE: u16 = 1 + 32; // length byte + 32-byte fixed field

        let mut current_offset = 10 + SERVER_NAME_FIELD_SIZE;

        let mut variable_data = Vec::new();

        let mut tmp_macstr = [0u8; 256];
        let machine_type_ptr = current_offset;
        {
            let written = self.machine_type.bytes(&mut tmp_macstr)?;
            variable_data.extend_from_slice(&tmp_macstr[..written]);
        }
        current_offset = 10 + SERVER_NAME_FIELD_SIZE + variable_data.len() as u16;

        let afp_versions_ptr = current_offset;
        variable_data.push(self.afp_versions.len() as u8);
        for v in &self.afp_versions {
            let s = v.as_str();
            let len = s.len() as u8;
            variable_data.push(len);
            variable_data.extend_from_slice(s.as_bytes());
        }
        current_offset = 10 + SERVER_NAME_FIELD_SIZE + variable_data.len() as u16;

        let uams_ptr = current_offset;
        variable_data.push(self.uams.len() as u8);
        for u in &self.uams {
            let s = u.as_str();
            let len = s.len() as u8;
            variable_data.push(len);
            variable_data.extend_from_slice(s.as_bytes());
        }
        current_offset = 10 + SERVER_NAME_FIELD_SIZE + variable_data.len() as u16;

        let volume_icon_ptr = if let Some(icon) = &self.volume_icon {
            let ptr = current_offset;
            variable_data.extend_from_slice(icon);
            ptr
        } else {
            0
        };

        buf.extend_from_slice(&machine_type_ptr.to_be_bytes());
        buf.extend_from_slice(&afp_versions_ptr.to_be_bytes());
        buf.extend_from_slice(&uams_ptr.to_be_bytes());
        buf.extend_from_slice(&volume_icon_ptr.to_be_bytes());
        buf.extend_from_slice(&self.flags.to_be_bytes());

        // Write fixed length 32-byte server name (plus length byte)
        let written = self.server_name.bytes(&mut tmp_macstr)?;
        let server_name_len = (written - 1).min(31);
        buf.push(server_name_len as u8);
        buf.extend_from_slice(&tmp_macstr[1..1 + server_name_len]);

        let padding_needed = 32 - server_name_len;
        buf.extend(std::iter::repeat_n(0x20, padding_needed));
        buf.extend_from_slice(&variable_data);

        Ok(buf)
    }
}

pub struct FPVolume {
    pub has_password: bool,
    pub has_config_info: bool,
    pub name: MacString,
}

impl FPVolume {
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, AfpError> {
        // Size is 1 byte for flags, 1 byte for name length, and then name bytes
        let target_size = 2 + self.name.len();

        if buf.len() < target_size {
            return Err(AfpError::InvalidSize);
        }

        // Reslice to avoid bounds check on each copy
        let target = &mut buf[..target_size];

        target[0] = (self.has_password as u8) << 7 | (self.has_config_info as u8) << 6;
        target[1] = (self.name.byte_len() - 1) as u8;
        self.name.bytes(&mut target[1..])?;

        Ok(target_size)
    }

    pub fn size(&self) -> usize {
        2 + self.name.byte_len() - 1
    }
}

pub struct FPGetSrvrParms {
    pub server_time: u32,
    pub volumes: Vec<FPVolume>,
}

impl FPGetSrvrParms {
    pub fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, AfpError> {
        let mut offset = 0;

        // Size is 4 bytes for server time + 1 byte for volume count + sum of all volume sizes
        let target_size = 5 + self.volumes.iter().map(|v| v.size()).sum::<usize>();

        if buf.len() < target_size {
            return Err(AfpError::InvalidSize);
        }

        // Reslice to avoid bounds check on each copy
        let target = &mut buf[..target_size];

        target[offset..offset + 4].copy_from_slice(&self.server_time.to_be_bytes());
        offset += 4;
        target[offset] = self.volumes.len() as u8;
        offset += 1;

        for volume in &self.volumes {
            let volume_size = volume.to_bytes(&mut target[offset..])?;
            offset += volume_size;
        }

        Ok(target_size)
    }
}

#[derive(Debug)]
pub struct FPEnumerate {
    pub volume_id: u16,
    pub directory_id: u32,
    pub file_bitmap: FPFileBitmap,
    pub directory_bitmap: FPDirectoryBitmap,
    pub req_count: u16,
    pub start_index: u16,
    pub max_reply_size: u16,
    pub path: MacString,
}

impl FPEnumerate {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let volume_id = u16::from_be_bytes(*buf[0..2].as_array().unwrap());
        let directory_id = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let file_bitmap = FPFileBitmap::from(u16::from_be_bytes(*buf[6..8].as_array().unwrap()));
        let directory_bitmap =
            FPDirectoryBitmap::from(u16::from_be_bytes(*buf[8..10].as_array().unwrap()));
        let req_count = u16::from_be_bytes(*buf[10..12].as_array().unwrap());
        let start_index = u16::from_be_bytes(*buf[12..14].as_array().unwrap());
        let max_reply_size = u16::from_be_bytes(*buf[14..16].as_array().unwrap());
        let _path_type = buf[16];
        let path = MacString::try_from(&buf[17..])?;

        Ok(Self {
            volume_id,
            directory_id,
            file_bitmap,
            directory_bitmap,
            req_count,
            start_index,
            max_reply_size,
            path,
        })
    }
}

#[derive(Debug)]
pub struct FPByteRangeLock {
    pub fork_id: u16,
    pub offset: i32,
    pub length: u32,
    pub flags: FPByteRangeLockFlags,
}

impl FPByteRangeLock {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        // Here Be Dragons:
        // This command also does not match Inside AppleTalk. Perhaps a version difference? Very confusing.
        let flags = FPByteRangeLockFlags::from(buf[0]);
        let fork_id = u16::from_be_bytes(*buf[1..3].as_array().unwrap());
        let offset = i32::from_be_bytes(*buf[3..7].as_array().unwrap());
        let length = u32::from_be_bytes(*buf[7..11].as_array().unwrap());

        Ok(Self {
            fork_id,
            offset,
            length,
            flags,
        })
    }
}

#[derive(Debug)]
pub struct FPCloseFork {
    pub fork_id: u16,
}

impl FPCloseFork {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let fork_id = u16::from_be_bytes(*buf[0..2].as_array().unwrap());

        Ok(Self { fork_id })
    }
}

#[derive(Debug)]
pub struct FPSetDirParms {
    pub volume_id: u16,
    pub directory_id: u32,
    pub dir_bitmap: FPDirectoryBitmap,
    pub path: MacString,
    pub attributes: Option<FPFileAttributes>,
    pub finder_info: Option<[u8; 32]>,
    pub owner_id: Option<u32>,
    pub group_id: Option<u32>,
    pub owner_access: Option<FPAccessRights>,
    pub group_access: Option<FPAccessRights>,
    pub everyone_access: Option<FPAccessRights>,
    pub user_access: Option<FPAccessRights>,
}

impl FPSetDirParms {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let volume_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let directory_id = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let dir_bitmap =
            FPDirectoryBitmap::from(u16::from_be_bytes(*buf[6..8].as_array().unwrap()));
        let _path_type = buf[8];
        let path = MacString::try_from(&buf[9..])?;

        let mut offset = 9 + path.byte_len();

        let mut parsed_parms = Self {
            volume_id,
            directory_id,
            dir_bitmap,
            path,
            attributes: None,
            finder_info: None,
            owner_id: None,
            group_id: None,
            owner_access: None,
            group_access: None,
            everyone_access: None,
            user_access: None,
        };

        if dir_bitmap.contains(FPDirectoryBitmap::ATTRIBUTES) {
            let attributes = FPFileAttributes::from(u16::from_be_bytes(
                *buf[offset..offset + 2].as_array().unwrap(),
            ));
            parsed_parms.attributes = Some(attributes);
            offset += 2;
        }

        if dir_bitmap.contains(FPDirectoryBitmap::FINDER_INFO) {
            let mut finder_info = [0u8; 32];
            finder_info.copy_from_slice(&buf[offset..offset + 32]);
            parsed_parms.finder_info = Some(finder_info);
            offset += 32;
        }

        if dir_bitmap.contains(FPDirectoryBitmap::OWNER_ID) {
            let owner_id = u32::from_be_bytes(*buf[offset..offset + 4].as_array().unwrap());
            parsed_parms.owner_id = Some(owner_id);
            offset += 4;
        }

        if dir_bitmap.contains(FPDirectoryBitmap::GROUP_ID) {
            let group_id = u32::from_be_bytes(*buf[offset..offset + 4].as_array().unwrap());
            parsed_parms.group_id = Some(group_id);
            offset += 4;
        }

        if dir_bitmap.contains(FPDirectoryBitmap::ACCESS_RIGHTS) {
            let owner_access = FPAccessRights::from(buf[offset]);
            parsed_parms.owner_access = Some(owner_access);
            offset += 1;

            let group_access = FPAccessRights::from(buf[offset]);
            parsed_parms.group_access = Some(group_access);
            offset += 1;

            let everyone_access = FPAccessRights::from(buf[offset]);
            parsed_parms.everyone_access = Some(everyone_access);
            offset += 1;

            let user_access = FPAccessRights::from(buf[offset]);
            parsed_parms.everyone_access = Some(user_access);
        }

        Ok(parsed_parms)
    }
}

#[derive(Debug)]
pub struct FPRead {
    /// The Fork ID this request is wanting to read from. Must be open already.
    pub fork_id: u16,
    /// The offset into the fork to start reading from.
    pub offset: u32,
    /// The number of bytes requested to be read. Note that this can be higher than the ASP QuantumSize.
    /// The server should truncate the response to the QuantumSize.
    pub req_count: u32,
    /// The newline mask to use when reading the file. If set to a non-zero value it is to be AND'd with each
    /// byte read from the fork and the result compared to to [Self::newline_char]. If they match the read should be
    /// terminated at this point and the server should return the number of bytes read.
    pub newline_mask: u8,
    /// The newline character to be searching for where to terminate the read.
    pub newline_char: u8,
}

impl FPRead {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let fork_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let offset = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let req_count = u32::from_be_bytes(*buf[6..10].as_array().unwrap());
        let newline_mask = buf[10];
        let newline_char = buf[11];

        Ok(Self {
            fork_id,
            offset,
            req_count,
            newline_mask,
            newline_char,
        })
    }

    /// Checks if a byte matches the newline mask and character. If true the read should be terminated.
    pub fn byte_matches_newline(&self, byte: u8) -> bool {
        (byte & self.newline_mask) == self.newline_char
    }
}

pub struct FPFlush {
    pub volume_id: u16,
}

impl FPFlush {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let volume_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        Ok(Self { volume_id })
    }
}

pub struct FPGetVolParms {
    pub volume_id: u16,
    pub bitmap: FPVolumeBitmap,
}

impl FPGetVolParms {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let volume_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let bitmap = FPVolumeBitmap::from(u16::from_be_bytes(*buf[2..4].as_array().unwrap()));
        Ok(Self { volume_id, bitmap })
    }
}

pub struct FPDelete {
    pub volume_id: u16,
    pub directory_id: u32,
    pub path: MacString,
}

impl FPDelete {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let volume_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let directory_id = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let _path_type = buf[6];
        let path = MacString::try_from(&buf[7..])?;

        Ok(Self {
            volume_id,
            directory_id,
            path,
        })
    }
}

#[derive(Debug)]
pub struct FPAddIcon {
    pub dt_ref_num: u16,
    pub file_creator: [u8; 4],
    pub file_type: [u8; 4],
    pub icon_type: u8,
    pub icon_tag: u32,
    pub size: u16,
}

impl FPAddIcon {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 18 {
            return Err(AfpError::InvalidSize);
        }
        let dt_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let file_creator: [u8; 4] = *buf[2..6].as_array().unwrap();
        let file_type: [u8; 4] = *buf[6..10].as_array().unwrap();
        let icon_type = buf[10];
        // pad byte at 11
        let icon_tag = u32::from_be_bytes(*buf[12..16].as_array().unwrap());
        let size = u16::from_be_bytes(*buf[16..18].as_array().unwrap());

        Ok(Self {
            dt_ref_num,
            file_creator,
            file_type,
            icon_type,
            icon_tag,
            size,
        })
    }
}

#[derive(Debug)]
pub struct FPGetIcon {
    pub dt_ref_num: u16,
    pub file_creator: [u8; 4],
    pub file_type: [u8; 4],
    pub icon_type: u8,
    pub size: u16,
}

impl FPGetIcon {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let dt_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let file_creator: [u8; 4] = *buf[2..6].as_array().unwrap();
        let file_type: [u8; 4] = *buf[6..10].as_array().unwrap();
        let icon_type = buf[10];
        // Pad byte here, skip one.
        let size = u16::from_be_bytes(*buf[12..14].as_array().unwrap());

        Ok(Self {
            dt_ref_num,
            file_creator,
            file_type,
            icon_type,
            size,
        })
    }
}

#[derive(Debug)]
pub struct FPGetIconInfo {
    pub dt_ref_num: u16,
    pub file_creator: [u8; 4],
    pub icon_type: u16,
}

impl FPGetIconInfo {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 8 {
            return Err(AfpError::InvalidSize);
        }
        let dt_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let file_creator: [u8; 4] = *buf[2..6].as_array().unwrap();
        // 2 byte icon type
        let icon_type = u16::from_be_bytes(*buf[6..8].as_array().unwrap());

        Ok(Self {
            dt_ref_num,
            file_creator,
            icon_type,
        })
    }
}

#[derive(Debug)]
pub struct FPGetComment {
    pub dt_ref_num: u16,
    pub directory_id: u32,
    pub path: MacString,
}

impl FPGetComment {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let dt_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let directory_id = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let _path_type = buf[6];
        let path = MacString::try_from(&buf[7..])?;

        Ok(Self {
            dt_ref_num,
            directory_id,
            path,
        })
    }
}

#[derive(Debug)]
pub struct FPRemoveComment {
    pub directory_id: u32,
    pub path: MacString,
}

impl FPRemoveComment {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let directory_id = u32::from_be_bytes(*buf[1..5].as_array().unwrap());
        let _path_type = buf[5];
        let path = MacString::try_from(&buf[6..])?;

        Ok(Self { directory_id, path })
    }
}

#[derive(Debug)]
pub struct FPAddComment {
    pub dt_ref_num: u16,
    pub directory_id: u32,
    pub path: MacString,
    pub comment: Vec<u8>,
}

impl FPAddComment {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let dt_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let directory_id = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let _path_type = buf[6];
        let path = if buf.len() > 7 {
            MacString::try_from(&buf[7..])?
        } else {
            MacString::from("")
        };

        // Comment starts after the variable length path. It must be padded to be even.
        let mut comment_offset = 7 + path.byte_len() - 1;
        // Commands are word-aligned, so start of comment string is at an even offset from the START of the command
        // Since buf here starts from the command payload, we know DSI header was before it.
        // It's safer to just skip padding dynamically.
        if comment_offset % 2 != 0 {
            comment_offset += 1;
        }

        let comment_data = if comment_offset < buf.len() {
            let comment_len = buf[comment_offset] as usize;
            if comment_len > 0 && comment_offset + 1 + comment_len <= buf.len() {
                buf[comment_offset + 1..comment_offset + 1 + comment_len].to_vec()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        Ok(Self {
            dt_ref_num,
            directory_id,
            path,
            comment: comment_data,
        })
    }
}

#[derive(Debug)]
pub struct FPWrite {
    pub fork_id: u16,
    pub offset: u32,
    pub req_count: u32,
    pub start_end_flag: bool,
}

impl FPWrite {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 10 {
            return Err(AfpError::InvalidSize);
        }
        let fork_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let offset = u32::from_be_bytes(*buf[2..6].as_array().unwrap());
        let req_count_raw = u32::from_be_bytes(*buf[6..10].as_array().unwrap());

        // High bit of req_count is the Start/End flag
        let start_end_flag = (req_count_raw & 0x8000_0000) != 0;
        let req_count = req_count_raw & 0x7FFF_FFFF;

        Ok(Self {
            fork_id,
            offset,
            req_count,
            start_end_flag,
        })
    }
}

/// Indicates a request from a client to either increase or decrease the size of a fork on disk. If neither
/// data fork length or resource fork length are set, this command is a no-op but a success code should
/// still be returned to the client.
#[derive(Debug)]
pub struct FPSetForkParms {
    /// which fork ref this command is for
    pub fork_ref_num: u16,
    /// the file bitmap describing what arguments will be set. _only_ fork length is allowed to be set.
    pub file_bitmap: FPFileBitmap,
    /// Requested new data fork length value, if the data fork length bit was set in the bitmap.
    pub data_fork_length: Option<u32>,
    /// Requested new resource fork length value, if the resource fork length bit was set in the bitmap.
    pub resource_fork_length: Option<u32>,
}

impl FPSetForkParms {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        let fork_ref_num = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        let file_bitmap = FPFileBitmap::from(u16::from_be_bytes(*buf[2..4].as_array().unwrap()));

        let mut offset = 4;

        let data_fork_length = if file_bitmap.contains(FPFileBitmap::DATA_FORK_LENGTH) {
            if offset + 4 > buf.len() {
                return Err(AfpError::InvalidSize);
            }
            let val = u32::from_be_bytes(*buf[offset..offset + 4].as_array().unwrap());
            offset += 4;
            Some(val)
        } else {
            None
        };

        let resource_fork_length = if file_bitmap.contains(FPFileBitmap::RESOURCE_FORK_LENGTH) {
            if offset + 4 > buf.len() {
                return Err(AfpError::InvalidSize);
            }
            let val = u32::from_be_bytes(*buf[offset..offset + 4].as_array().unwrap());
            Some(val)
        } else {
            None
        };

        Ok(Self {
            fork_ref_num,
            file_bitmap,
            data_fork_length,
            resource_fork_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp_enumerate_parse() {
        let buf = &[
            0x9u8, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x4, 0x7, 0x7f, 0x13, 0x7f, 0x0, 0x45, 0x0, 0x1,
            0x12, 0x0, 0x2, 0x0,
        ];
        let _enumerate = FPEnumerate::parse(&buf[2..]).unwrap();
    }
}

#[derive(Debug)]
pub struct FPOpenDT {
    pub volume_id: u16,
}

impl FPOpenDT {
    pub fn parse(buf: &[u8]) -> Result<Self, AfpError> {
        if buf.len() < 2 {
            return Err(AfpError::InvalidSize);
        }
        let volume_id = u16::from_be_bytes(*buf[..2].as_array().unwrap());
        Ok(Self { volume_id })
    }
}
