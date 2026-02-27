/// AFP Error Codes. For AppleTalk implementations these result codes are passed via the
/// ASP CmdResult field (i.e the 4 user bytes of an ATP packet)
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(i16)]
pub enum AfpError {
    /// Packet could not be parsed as it was of insufficient size
    InvalidSize = -1,
    /// End of File reached
    EoFErr = -39,
    /// Unknown or unsupported AFP version
    BadVersNum = -1072,
    /// Unknown or unsupported UAM
    BadUam = -1073,
    /// User does not have the correct access rights
    AccessDenied = -5000,
    /// A request to operate on a directory that is not empty
    DirNotEmpty = -5007,
    /// Bitmap is invalid
    BitmapErr = -5006,
    /// A request to operate on a file that is currently in use
    FileBusy = -5010,
    /// Item not found
    ItemNotFound = -5012,
    /// General lock error
    LockErr = -5013,
    /// Object (file or directory) already exists
    ObjectExists = -5017,
    /// Object (file or directory) not found
    ObjectNotFound = -5018,
    /// AFP command block size is zero or invalid
    ParamError = -5019,
    /// Attempt to unlock a byte range that is not locked
    RangeNotLocked = -5020,
    /// Attempt to lock a byte range that overlaps with an existing lock
    RangeOverlap = -5021,
    /// Object is the wrong type (e.g. file vs directory)
    ObjectTypeErr = -5025,
    /// Miscellaneous error
    MiscErr = -10000,
}

#[repr(u16)]
pub enum VolumeSignature {
    /// Indicates no directories, only files, i.e MFS. Only supported in old AFP versions.
    Flat = 1,
    /// Indicates directory IDs do not change. Should be the default.
    FixedDirectoryID = 2,
    /// Indicates directory IDs can change. No need to implement this one.
    VariableDirectoryID = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfpVersion {
    Version1,
    Version1_1,
    Version2,
    Version2_1,
}

impl TryFrom<&str> for AfpVersion {
    type Error = AfpError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "AFPVersion 1.0" => Ok(AfpVersion::Version1),
            "AFPVersion 1.1" => Ok(AfpVersion::Version1_1),
            "AFPVersion 2.0" => Ok(AfpVersion::Version2),
            "AFPVersion 2.1" => Ok(AfpVersion::Version2_1),
            _ => Err(AfpError::BadVersNum),
        }
    }
}

impl AfpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            AfpVersion::Version1 => "AFPVersion 1.0",
            AfpVersion::Version1_1 => "AFPVersion 1.1",
            AfpVersion::Version2 => "AFPVersion 2.0",
            AfpVersion::Version2_1 => "AFPVersion 2.1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AfpUam {
    NoUserAuthent,
    CleartxtPasswrd,
    RandnumExchange,
    TwoWayRandnumExchange,
}

impl TryFrom<&str> for AfpUam {
    type Error = AfpError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        // Inside AppleTalk shows these with capitalised values, but
        // the actual values are case insensitive.
        let value_lower = value.to_lowercase();
        match value_lower.as_str() {
            "no user authent" => Ok(AfpUam::NoUserAuthent),
            "cleartxt passwrd" => Ok(AfpUam::CleartxtPasswrd),
            "randnum exchange" => Ok(AfpUam::RandnumExchange),
            "2-way randnum exchange" => Ok(AfpUam::TwoWayRandnumExchange),
            _ => Err(AfpError::BadUam),
        }
    }
}

impl AfpUam {
    pub fn as_str(&self) -> &'static str {
        match self {
            AfpUam::NoUserAuthent => "No User Authent",
            AfpUam::CleartxtPasswrd => "Cleartxt Passwrd",
            AfpUam::RandnumExchange => "Randnum Exchange",
            AfpUam::TwoWayRandnumExchange => "2-Way Randnum Exchange",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkType {
    Data,
    Resource,
}

impl From<u8> for ForkType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Data,
            0b10000000 => Self::Resource,
            _ => panic!("Invalid fork type"),
        }
    }
}

impl From<ForkType> for u8 {
    fn from(val: ForkType) -> Self {
        match val {
            ForkType::Data => 0,
            ForkType::Resource => 0b10000000,
        }
    }
}

pub enum CreateFlag {
    Soft,
    Hard,
}

impl From<u8> for CreateFlag {
    fn from(value: u8) -> Self {
        match value {
            0b10000000 => Self::Hard,
            _ => Self::Soft,
        }
    }
}

impl From<CreateFlag> for u8 {
    fn from(val: CreateFlag) -> Self {
        match val {
            CreateFlag::Hard => 0b10000000,
            CreateFlag::Soft => 0,
        }
    }
}

pub enum FileType {
    Directory,
    File,
}

impl From<u8> for FileType {
    fn from(value: u8) -> Self {
        match value {
            0b10000000 => Self::Directory,
            _ => Self::File,
        }
    }
}

impl From<FileType> for u8 {
    fn from(val: FileType) -> Self {
        match val {
            FileType::Directory => 0b10000000,
            FileType::File => 0,
        }
    }
}
