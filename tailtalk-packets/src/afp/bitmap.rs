use bitflags::bitflags;

bitflags! {
    /// Bitmap of requested volume information. One or more of these can be set in a request
    /// by FPGetVolParms or during FPOpenVol. The response should be packed in the same order
    /// as the bits are defined below.
    /// E.g. If ATTRIBUTES and CREATION_DATE are set, the first 2 bytes of the payload
    /// will be the attributes flag, and the next 4 bytes are the creation date.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FPVolumeBitmap: u16 {
        /// Request for volume attributes. Single bit flag response of read-only, 1 is true, 0 is false.
        const ATTRIBUTES = 0x0001;
        /// Request for volume signature, i.e a flat without directories, fixed directory ID, or variable directory IDs.
        const SIGNATURE = 0x0002;
        /// Request for creation date of this volume (In 32-bit Macintosh time)
        const CREATION_DATE = 0x0004;
        /// Request for last modified date of this volume (In 32-bit Macintosh time)
        const MODIFICATION_DATE = 0x0008;
        /// Request for the last time this volume was backed up (In 32-bit Macintosh time)
        const BACKUP_DATE = 0x0010;
        /// Request for the volume's 16-bit ID assigned by the server.
        const VOLUME_ID = 0x0020;
        /// Request for the number of bytes free for this volume as a 32-bit value.
        const BYTES_FREE = 0x0040;
        /// Request for the size of this volume in bytes as a 32-bit value.
        const BYTES_TOTAL = 0x0080;
        /// Request for the name of this volume as a Pascal string.
        const VOLUME_NAME = 0x0100;
    }
}

/// Converts from a host-endian u16 to a FPVolumeBitmap. Note that this
/// does not convert endianness - the caller must convert from network byte order first if applicable.
impl From<u16> for FPVolumeBitmap {
    fn from(value: u16) -> Self {
        Self::from_bits_truncate(value)
    }
}

/// Converts from a FPVolumeBitmap to a host-endian u16. Note that this
/// does not convert endianness - the caller must convert to network byte order after calling this if applicable.
impl From<FPVolumeBitmap> for u16 {
    fn from(val: FPVolumeBitmap) -> Self {
        val.bits()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct FPDirectoryBitmap: u16 {
        /// Request for the attributes of this directory.
        /// TODO: Implement attributes bit flag response
        const ATTRIBUTES = 1;
        /// Request for the parent directory ID of this directory.
        /// Response: 32-bit directory ID
        const PARENT_DIR_ID = 1 << 1;
        /// Request for the creation date of this directory.
        /// Response: 32-bit Macintosh time
        const CREATE_DATE = 1 << 2;
        /// Request for the last modification date of ths directory.
        /// Response: 32-bit Macintosh time
        const MODIFICATION_DATE = 1 << 3;
        /// Request for the last backup date of this directory.
        /// Response: 32-bit Macintosh time
        const BACKUP_DATE = 1 << 4;
        /// Request for the Finder information of this directory.
        /// Response: 32-byte Finder information
        const FINDER_INFO = 1 << 5;
        /// Request for the long name of this directory.
        /// Response: Offset returned in order to a pascal string with the long name
        const LONG_NAME = 1 << 6;
        /// Request for the short name of this directory.
        /// Response: Offset returned in order to a pascal string with the short name
        const SHORT_NAME = 1 << 7;
        /// Request for the directory ID of this directory.
        /// Response: 32-bit directory ID
        const DIR_ID = 1 << 8;
        /// Request for the number of offspring of this directory.
        /// Response: 16-bit number of offspring
        const OFFSPRING_COUNT = 1 << 9;
        /// Request for the owner ID of this directory.
        /// Response: 32-bit owner ID
        const OWNER_ID = 1 << 10;
        /// Request for the group ID of this directory.
        /// Response: 32-bit group ID
        const GROUP_ID = 1 << 11;
        /// Request for the access rights of this directory.
        /// Response: 4-byte value in the order of owner, group, and world followed by a User Access Rights summary byte
        const ACCESS_RIGHTS = 1 << 12;
        /// TODO: What is this?
        const PRODOS_INFO = 1 << 13;
    }
}

/// Converts from a host-endian u16 to a FPDirectoryBitmap. Note that this
/// does not convert endianness - the caller must convert from network byte order first if applicable.
impl From<u16> for FPDirectoryBitmap {
    fn from(value: u16) -> Self {
        Self::from_bits_truncate(value)
    }
}

/// Converts from a FPDirectoryBitmap to a host-endian u16. Note that this
/// does not convert endianness - the caller must convert to network byte order after calling this if applicable.
impl From<FPDirectoryBitmap> for u16 {
    fn from(val: FPDirectoryBitmap) -> Self {
        val.bits()
    }
}

impl FPDirectoryBitmap {
    /// Returns the expected offset of the long_name value based on the set bitmap values.
    pub fn long_name_offset(&self) -> usize {
        let mut offset = 0;
        if self.contains(FPDirectoryBitmap::ATTRIBUTES) {
            offset += 2;
        }
        if self.contains(FPDirectoryBitmap::PARENT_DIR_ID) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::CREATE_DATE) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::MODIFICATION_DATE) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::BACKUP_DATE) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::FINDER_INFO) {
            offset += 32;
        }
        if self.contains(FPDirectoryBitmap::LONG_NAME) {
            offset += 2;
        }
        if self.contains(FPDirectoryBitmap::SHORT_NAME) {
            offset += 2;
        }
        if self.contains(FPDirectoryBitmap::DIR_ID) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::OFFSPRING_COUNT) {
            offset += 2;
        }
        if self.contains(FPDirectoryBitmap::OWNER_ID) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::GROUP_ID) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::ACCESS_RIGHTS) {
            offset += 4;
        }
        if self.contains(FPDirectoryBitmap::PRODOS_INFO) {
            offset += 6;
        }
        offset
    }

    pub fn response_len(&self, name_len: usize) -> usize {
        self.long_name_offset() + name_len + 1
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FPFileBitmap: u16 {
        const ATTRIBUTES = 1;
        const PARENT_DIR_ID = 1 << 1;
        const CREATE_DATE = 1 << 2;
        const MODIFICATION_DATE = 1 << 3;
        const BACKUP_DATE = 1 << 4;
        const FINDER_INFO = 1 << 5;
        const LONG_NAME = 1 << 6;
        const SHORT_NAME = 1 << 7;
        const FILE_NUMBER = 1 << 8;
        const DATA_FORK_LENGTH = 1 << 9;
        const RESOURCE_FORK_LENGTH = 1 << 10;
        const PRODOS_INFO = 1 << 13;
    }
}

/// Converts from a host-endian u16 to a FPFileBitmap. Note that this
/// does not convert endianness - the caller must convert from network byte order first if applicable.
impl From<u16> for FPFileBitmap {
    fn from(value: u16) -> Self {
        Self::from_bits_truncate(value)
    }
}

/// Converts from a FPFileBitmap to a host-endian u16. Note that this
/// does not convert endianness - the caller must convert to network byte order after calling this if applicable.
impl From<FPFileBitmap> for u16 {
    fn from(val: FPFileBitmap) -> Self {
        val.bits()
    }
}

impl FPFileBitmap {
    /// Returns the expected offset of the long_name value based on the set bitmap values.
    pub fn long_name_offset(&self) -> usize {
        let mut offset = 0;
        if self.contains(FPFileBitmap::ATTRIBUTES) {
            offset += 2;
        }
        if self.contains(FPFileBitmap::PARENT_DIR_ID) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::CREATE_DATE) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::MODIFICATION_DATE) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::BACKUP_DATE) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::FINDER_INFO) {
            offset += 32;
        }
        if self.contains(FPFileBitmap::LONG_NAME) {
            offset += 2;
        }
        if self.contains(FPFileBitmap::SHORT_NAME) {
            offset += 2;
        }
        if self.contains(FPFileBitmap::FILE_NUMBER) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::DATA_FORK_LENGTH) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::RESOURCE_FORK_LENGTH) {
            offset += 4;
        }
        if self.contains(FPFileBitmap::PRODOS_INFO) {
            offset += 6;
        }
        offset
    }

    pub fn response_len(&self, name_len: usize) -> usize {
        self.long_name_offset() + name_len + 1
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FPFileAttributes: u16 {
        const INVISIBLE = 1;
        const MULTI_USER = 1 << 1;
        const SYSTEM = 1 << 2;
        const DAlreadyOpen = 1 << 3;
        const RAlreadyOpen = 1 << 4;
        const ReadOnly = 1 << 5;
        const BackupNeeded = 1 << 6;
        const RenameInhibit = 1 << 7;
        const DeleteInhibit = 1 << 8;
        const CopyProtect = 1 << 10;
        const SetClear = 1 << 15;
    }
}

impl From<u16> for FPFileAttributes {
    fn from(value: u16) -> Self {
        Self::from_bits_truncate(value)
    }
}

impl From<FPFileAttributes> for u16 {
    fn from(val: FPFileAttributes) -> Self {
        val.bits()
    }
}

bitflags! {
    /// AFP Directory Access Rights bitmap. This represents the access privileges for a single
    /// category (owner, group, or everyone). The full Access Rights parameter is a 4-byte value
    /// consisting of:
    /// - Byte 0: User Access Rights Summary (effective privileges for current user, includes OWNER flag)
    /// - Byte 1: Owner's access privileges
    /// - Byte 2: Group's access privileges
    /// - Byte 3: Everyone's access privileges
    ///
    /// Each byte uses the same bit format defined here.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FPAccessRights: u8 {
        /// Search access - Can list directory parameters and traverse into subdirectories
        const SEARCH = 0x01;
        /// Read access - Can list file parameters and read file contents
        const READ = 0x02;
        /// Write access - Can modify, add, and delete files/directories
        const WRITE = 0x04;
        /// Owner flag - Only valid in User Access Rights Summary byte (byte 0).
        /// Set if the current user is the owner of the directory.
        const OWNER = 0x80;
    }
}

impl From<u8> for FPAccessRights {
    fn from(value: u8) -> Self {
        Self::from_bits_truncate(value)
    }
}

impl From<FPAccessRights> for u8 {
    fn from(rights: FPAccessRights) -> u8 {
        rights.bits()
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FPByteRangeLockFlags: u8 {
        const UNLOCK = 0b00000001;
        const END = 0b10000000;
    }
}

impl From<u8> for FPByteRangeLockFlags {
    fn from(value: u8) -> Self {
        Self::from_bits_truncate(value)
    }
}

impl From<FPByteRangeLockFlags> for u8 {
    fn from(val: FPByteRangeLockFlags) -> Self {
        val.bits()
    }
}
