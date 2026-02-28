use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tailtalk_packets::afp::{
    AfpError, CreateFlag, FPAccessRights, FPByteRangeLockFlags, FPDelete, FPDirectoryBitmap,
    FPEnumerate, FPFileBitmap, FPRead, FPSetForkParms, FPVolume, FPVolumeBitmap, FileType,
    ForkType, VolumeSignature,
};

use crate::{time_to_afp, time_to_afp_v1};
use tracing::{error, warn};
use xattr;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Node {
    pub id: u32,
    pub parent_id: u32,
    pub name: String,
    pub is_dir: bool,
    pub path: PathBuf,
    pub data_fork: Option<tokio::fs::File>,
}

impl Node {
    pub async fn open_data_fork(&mut self, absolute_path: &PathBuf) -> std::io::Result<()> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(absolute_path)
            .await?;
        self.data_fork = Some(file);
        Ok(())
    }

    pub async fn close_data_fork(&mut self) {
        // Dropping the file closes it
        self.data_fork = None;
    }

    /// Read Finder Info from xattr "user.com.apple.FinderInfo"
    pub fn get_finder_info(&self, volume_root: &Path) -> [u8; 32] {
        let absolute_path = volume_root.join(&self.path);
        match xattr::get(&absolute_path, "user.com.apple.FinderInfo") {
            Ok(Some(data)) => {
                let mut info = [0u8; 32];
                if data.len() >= 32 {
                    info.copy_from_slice(&data[0..32]);
                }
                info
            }
            Ok(None) => [0u8; 32],
            Err(_) => [0u8; 32],
        }
    }

    /// Write Finder Info to xattr "user.com.apple.FinderInfo"
    pub fn set_finder_info(&self, volume_root: &Path, info: &[u8; 32]) -> Result<(), AfpError> {
        let absolute_path = volume_root.join(&self.path);
        xattr::set(&absolute_path, "user.com.apple.FinderInfo", info).map_err(|e| {
            error!("Failed to set Finder Info for {:?}: {:?}", self.path, e);
            AfpError::AccessDenied
        })
    }

    /// Get AFP Attributes from Finder Info (e.g. Invisible bit)
    pub fn get_attributes(&self, volume_root: &Path) -> u16 {
        let finder_info = self.get_finder_info(volume_root);
        // fdFlags is at offset 8 (u16 big endian) in FInfo (first 16 bytes)
        // Bit 14 of fdFlags is kIsInvisible (0x4000)
        let fd_flags = u16::from_be_bytes([finder_info[8], finder_info[9]]);

        let mut attributes = 0;
        // Map kIsInvisible (0x4000) to AFP Attribute Invisible (Bit 0, 0x0001)
        if (fd_flags & 0x4000) != 0 {
            attributes |= 1;
        }

        attributes
    }

    /// Set AFP Attributes by updating Finder Info (e.g. Invisible bit)
    pub fn set_attributes(&self, volume_root: &Path, attributes: u16) -> Result<(), AfpError> {
        let mut finder_info = self.get_finder_info(volume_root);
        let mut fd_flags = u16::from_be_bytes([finder_info[8], finder_info[9]]);

        // AFP Attribute Invisible (Bit 0) -> kIsInvisible (Bit 14, 0x4000)
        if (attributes & 0x0001) != 0 {
            fd_flags |= 0x4000;
        } else {
            fd_flags &= !0x4000;
        }

        let fd_flags_bytes = fd_flags.to_be_bytes();
        finder_info[8] = fd_flags_bytes[0];
        finder_info[9] = fd_flags_bytes[1];

        self.set_finder_info(volume_root, &finder_info)
    }

    /// Process file parameter bitmap and write response to output buffer.
    /// Returns the number of bytes written.
    pub async fn get_file_parms_resp(
        &self,
        volume_root: &Path,
        bitmap: FPFileBitmap,
        output: &mut [u8],
        afp_v2: bool,
    ) -> Result<usize, AfpError> {
        let mut offset = 0;
        let mut variable_len_offset = 0;

        let full_path = volume_root.join(&self.path);
        let metadata = tokio::fs::metadata(&full_path)
            .await
            .map_err(|_| AfpError::ObjectNotFound)?;

        if bitmap.contains(FPFileBitmap::ATTRIBUTES) {
            let attributes = self.get_attributes(volume_root);
            output[offset..offset + 2].copy_from_slice(&attributes.to_be_bytes());
            offset += 2;
        }

        if bitmap.contains(FPFileBitmap::PARENT_DIR_ID) {
            output[offset..offset + 4].copy_from_slice(&self.parent_id.to_be_bytes());
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::CREATE_DATE) {
            let created_at_bytes = if afp_v2 {
                time_to_afp(metadata.created().unwrap())
            } else {
                time_to_afp_v1(metadata.created().unwrap())
            }
            .to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&created_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::MODIFICATION_DATE) {
            let modified_at_bytes = if afp_v2 {
                time_to_afp(metadata.modified().unwrap())
            } else {
                time_to_afp_v1(metadata.modified().unwrap())
            }
            .to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&modified_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::BACKUP_DATE) {
            let backup_at_bytes = if afp_v2 {
                time_to_afp(metadata.modified().unwrap())
            } else {
                time_to_afp_v1(metadata.modified().unwrap())
            }
            .to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&backup_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::FINDER_INFO) {
            let finder_info = self.get_finder_info(volume_root);
            output[offset..offset + 32].copy_from_slice(&finder_info);
            offset += 32;
        }

        if bitmap.contains(FPFileBitmap::LONG_NAME) {
            let mut long_name_offset = bitmap.long_name_offset();
            output[offset..offset + 2].copy_from_slice(&(long_name_offset as u16).to_be_bytes());
            offset += 2;

            output[long_name_offset] = self.name.len() as u8;
            long_name_offset += 1;
            output[long_name_offset..long_name_offset + self.name.len()]
                .copy_from_slice(self.name.as_bytes());

            variable_len_offset += self.name.len() + 1;
        }

        if bitmap.contains(FPFileBitmap::FILE_NUMBER) {
            output[offset..offset + 4].copy_from_slice(&self.id.to_be_bytes());
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::DATA_FORK_LENGTH) {
            output[offset..offset + 4].copy_from_slice(&(metadata.len() as u32).to_be_bytes());
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::RESOURCE_FORK_LENGTH) {
            // TODO: Add some kind of resource fork support
            output[offset..offset + 4].fill(0);
            offset += 4;
        }

        if bitmap.contains(FPFileBitmap::PRODOS_INFO) {
            output[offset..offset + 6].fill(0);
            offset += 6;
        }

        Ok(offset + variable_len_offset)
    }
}

pub struct Volume {
    /// Name of the volume as it appears on the network
    name: String,
    /// Path to the volume on the local filesystem
    path: PathBuf,
    /// Time this volume was created at. TODO: Actually get this from the filesystem
    created_at: u32,
    /// The ID of this volume. This is used for all AFP requests to identify this volume.
    volume_id: u16,
    /// Whether the session negotiated AFP 2.x (true) or AFP 1.x (false).
    /// AFP 2.x uses seconds since Jan 1, 2000; AFP 1.x uses seconds since Jan 1, 1904.
    afp_v2: bool,
    nodes: HashMap<u32, Node>,
    path_to_id: HashMap<PathBuf, u32>,
    next_id: u32,
    fork_ref_to_node_id: HashMap<u16, (u32, ForkType)>,
    next_fork_ref_num: u16,
    /// Tracks byte-range locks per fork. Key is fork_ref_num, value is a vector of (offset, length) tuples
    fork_locks: HashMap<u16, Vec<(u64, u64)>>,
    desktop_database: Option<crate::afp::DesktopDatabase>,
}

impl Volume {
    pub async fn new(name: String, path: PathBuf, volume_id: u16, afp_v2: bool) -> Self {
        let created_at = if afp_v2 {
            time_to_afp(SystemTime::now())
        } else {
            time_to_afp_v1(SystemTime::now())
        };
        let mut new_self = Self {
            name,
            path,
            created_at,
            afp_v2,
            volume_id,
            nodes: HashMap::new(),
            path_to_id: HashMap::new(),
            next_id: 3, // Start IDs at 3 (1=Parent of Root, 2=Root)
            fork_ref_to_node_id: HashMap::new(),
            next_fork_ref_num: 1,
            fork_locks: HashMap::new(),
            desktop_database: None,
        };

        // Initialize root node
        // ID 2 is the root of the volume. Parent is 1.
        let root_node = Node {
            id: 2,
            parent_id: 1,
            name: new_self.name.clone(),
            is_dir: true,
            path: PathBuf::new(),
            data_fork: None,
        };
        new_self.nodes.insert(2, root_node);
        new_self.path_to_id.insert(PathBuf::new(), 2);

        new_self.walk_dir(PathBuf::new()).await.unwrap();
        new_self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn get_node_path(&self, id: u32) -> Option<PathBuf> {
        self.nodes.get(&id).map(|node| node.path.clone())
    }

    pub fn path_to_id(&self) -> &HashMap<PathBuf, u32> {
        &self.path_to_id
    }

    pub fn nodes_mut(&mut self) -> &mut HashMap<u32, Node> {
        &mut self.nodes
    }

    /// Resolve a Node ID from a Directory ID and relative path name.
    /// Handles empty paths (identity lookup) and relative paths.
    pub fn resolve_node(&self, directory_id: u32, path_name: &Path) -> Result<u32, AfpError> {
        let is_empty_path = path_name.as_os_str().is_empty()
            || path_name
                .as_os_str()
                .to_str()
                .is_some_and(|s| s.chars().all(|c| c == '\0'));

        let base_path = if directory_id == 2 {
            PathBuf::new() // Root
        } else {
            self.get_node_path(directory_id)
                .ok_or(AfpError::ObjectNotFound)?
        };

        if is_empty_path {
            if self.nodes.contains_key(&directory_id) {
                return Ok(directory_id);
            } else {
                return Err(AfpError::ObjectNotFound);
            }
        }

        let full_relative_path = base_path.join(path_name);
        self.path_to_id
            .get(&full_relative_path)
            .copied()
            .ok_or(AfpError::ObjectNotFound)
    }

    /// Get unified parameters for a node (file or directory).
    /// Returns (is_dir, bytes_written)
    pub async fn get_node_parms(
        &self,
        node_id: u32,
        file_bitmap: FPFileBitmap,
        dir_bitmap: FPDirectoryBitmap,
        output: &mut [u8],
    ) -> Result<(bool, usize), AfpError> {
        let node = self.nodes.get(&node_id).ok_or(AfpError::ObjectNotFound)?;
        let mut offset = 0;

        if node.is_dir {
            offset += self
                .get_directory_parms_resp(dir_bitmap, &node.path, output)
                .await?;
            Ok((true, offset))
        } else {
            offset += self
                .get_file_parms_resp(file_bitmap, &node.path, output)
                .await?;
            Ok((false, offset))
        }
    }

    /// Set parameters for a node (file or directory).
    pub fn set_node_parms(
        &mut self,
        node_id: u32,
        dir_bitmap: FPDirectoryBitmap,
        data: &[u8],
    ) -> Result<(), AfpError> {
        // We need volume_root for xattr operations
        let volume_root = self.path.clone();

        // Find node
        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(AfpError::ObjectNotFound)?;
        let is_dir = node.is_dir;

        // Calculate param offset (parsing logic should ideally be here if server.rs just passes the slice)
        // But for now, let's assume server.rs passes the slice STARTING at the parameters.
        let mut offset = 0;

        // Handle Attributes (Bit 0)
        if is_dir && dir_bitmap.contains(FPDirectoryBitmap::ATTRIBUTES) {
            let attributes = u16::from_be_bytes([data[offset], data[offset + 1]]);
            node.set_attributes(&volume_root, attributes)?;
            offset += 2;
        }

        // Handle Finder Info (Bit 5)
        if is_dir && dir_bitmap.contains(FPDirectoryBitmap::FINDER_INFO) {
            let mut finder_info = [0u8; 32];
            finder_info.copy_from_slice(&data[offset..offset + 32]);
            node.set_finder_info(&volume_root, &finder_info)?;
        }

        Ok(())
    }

    pub async fn create_dir(
        &mut self,
        directory_id: u32,
        path_name: PathBuf,
    ) -> Result<u32, AfpError> {
        // Find the parent directory node
        let parent_node = self
            .nodes
            .get(&directory_id)
            .ok_or(AfpError::ObjectNotFound)?;

        // Construct the full relative path from the parent's path
        let full_relative_path = parent_node.path.join(&path_name);
        let absolute_path = self.path.join(&full_relative_path);

        tracing::info!("Creating directory: {:?}", absolute_path);
        // Create the directory on the filesystem if it doesn't exist
        if !absolute_path.exists() {
            tokio::fs::create_dir(&absolute_path).await.map_err(|e| {
                error!("Failed to create directory: {:?}", e);
                AfpError::AccessDenied
            })?;
        }

        // Check if we already have an ID for this path
        if let Some(&id) = self.path_to_id.get(&full_relative_path) {
            return Ok(id);
        }

        // Create a new node for this directory
        let new_id = self.next_id;
        self.next_id += 1;

        let node = Node {
            id: new_id,
            parent_id: directory_id,
            name: path_name
                .file_name()
                .ok_or(AfpError::ObjectNotFound)?
                .to_string_lossy()
                .to_string(),
            is_dir: true,
            path: full_relative_path.clone(),
            data_fork: None,
        };

        self.nodes.insert(new_id, node);
        self.path_to_id.insert(full_relative_path, new_id);

        Ok(new_id)
    }

    pub async fn create_file(
        &mut self,
        create_flag: CreateFlag,
        directory_id: u32,
        relative_path: PathBuf,
    ) -> Result<u32, AfpError> {
        let parent_node = self
            .nodes
            .get(&directory_id)
            .ok_or(AfpError::ObjectNotFound)?;
        let full_relative_path = parent_node.path.join(relative_path);
        let absolute_path = self.path.join(&full_relative_path);
        let exists = absolute_path.exists();

        match create_flag {
            CreateFlag::Soft => {
                if exists {
                    return Err(AfpError::ObjectExists);
                }
            }
            CreateFlag::Hard => {
                if exists {
                    tokio::fs::remove_file(&absolute_path).await.map_err(|e| {
                        error!("Failed to remove file: {:?}", e);
                        AfpError::AccessDenied
                    })?;
                }
            }
        }

        // Create the file on disk
        tokio::fs::File::create(&absolute_path).await.map_err(|e| {
            error!("Failed to create file {:?}: {:?}", absolute_path, e);
            AfpError::AccessDenied
        })?;

        let new_id = self.next_id;
        self.next_id += 1;

        let node = Node {
            id: new_id,
            parent_id: directory_id,
            name: full_relative_path
                .file_name()
                .ok_or(AfpError::ObjectNotFound)?
                .to_string_lossy()
                .to_string(),
            is_dir: false,
            path: full_relative_path.clone(),
            data_fork: None,
        };

        self.nodes.insert(new_id, node);
        self.path_to_id.insert(full_relative_path, new_id);

        Ok(new_id)
    }

    /// Walk the directory (volume root or specified path) and generate IDs for all files and folders.
    pub async fn walk_dir(&mut self, relative_path: PathBuf) -> std::io::Result<()> {
        let full_path = self.path.join(&relative_path);

        // Ensure the start path has an ID (if it's root, it was init in new(), otherwise lookup)
        let mut start_id = 2; // Default to root
        if let Some(&id) = self.path_to_id.get(&relative_path) {
            start_id = id;
        }

        // Stack contains (current_full_path, current_node_id)
        let mut stack = vec![(full_path, start_id)];

        while let Some((current_dir, parent_id)) = stack.pop() {
            let mut read_dir = tokio::fs::read_dir(&current_dir).await?;
            while let Some(entry) = read_dir.next_entry().await? {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == ".tailtalk" {
                    continue;
                }

                let entry_path = entry.path();
                // Get path relative to volume root
                if let Ok(rel_path) = entry_path.strip_prefix(&self.path) {
                    let rel_path_buf = rel_path.to_path_buf();

                    let new_id = self.next_id;
                    self.next_id += 1;

                    let is_dir = entry.file_type().await?.is_dir();

                    let node = Node {
                        id: new_id,
                        parent_id,
                        name: entry.file_name().to_string_lossy().to_string(),
                        is_dir,
                        path: rel_path_buf.clone(),
                        data_fork: None,
                    };

                    self.nodes.insert(new_id, node);
                    self.path_to_id.insert(rel_path_buf, new_id);

                    if is_dir {
                        stack.push((entry_path, new_id));
                    }
                }
            }
        }

        Ok(())
    }

    /// Get volume parameters for FPGetVolParms
    /// Returns the attributes flags for AFP. Currently only bit 0 is relevant, which signifies if
    /// this volume is read-only or not.
    // TODO: Currently hard coded to 0 (read/write)
    pub fn get_attributes(&self) -> u16 {
        0
    }

    /// Returns the creation time of the volume as a u32 in Macintosh time format.
    pub fn get_created_at(&self) -> u32 {
        self.created_at
    }

    /// Returns the last modified time of the volume as a u32 in Macintosh time format.
    // TODO: Actually get this from the filesystem
    pub fn get_modified_at(&self) -> u32 {
        self.created_at
    }

    /// Returns the last backup time of the volume as a u32 in Macintosh time format.
    // TODO: Set this to something? Not really sure what makes sense here
    pub fn get_backup_at(&self) -> u32 {
        self.created_at
    }

    /// Update the AFP epoch used for date encoding based on the negotiated version.
    /// Call this after FPLogin to reflect the client's chosen AFP version.
    pub fn set_afp_v2(&mut self, afp_v2: bool) {
        self.afp_v2 = afp_v2;
        // Recompute created_at with the correct epoch now that we know the version.
        self.created_at = if afp_v2 {
            time_to_afp(SystemTime::now())
        } else {
            time_to_afp_v1(SystemTime::now())
        };
    }
    /// Returns the assigned volume ID. This ID is used for all AFP requests to identify this volume.
    pub fn get_volume_id(&self) -> u16 {
        self.volume_id
    }

    /// Returns the current free bytes as a 32-bit value.
    /// TODO: Set this to some sane value. 4GiB is the limit for AFP 2.1 and earlier, which we want
    /// to support.
    pub fn get_bytes_free(&self) -> u32 {
        // Just hard code to 1GiB for now
        1024 * 1024 * 1024
    }

    /// Returns the total bytes on the volume as a 64-bit value.
    /// TODO: Set this to some sane value. 4GiB is the limit for AFP 2.1 and earlier, which we want
    /// to support.
    pub fn get_bytes_total(&self) -> u32 {
        // Just hard code to 1GiB for now
        1024 * 1024 * 1024
    }

    /// Returns an FPVolume struct with the current volume information.
    pub fn get_fp_volume(&self) -> FPVolume {
        FPVolume {
            has_password: false,
            has_config_info: false,
            name: self.name.clone().into(),
        }
    }

    /// Given a bitmap request from a client, will generate a packed response in the output.
    /// On success returns the number of bytes written to the output buffer.
    /// # Error
    /// Returns an error if the output buffer is too small to hold the response.
    pub fn get_bitmap_resp(
        &self,
        bitmap: FPVolumeBitmap,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let mut offset = 0;

        output[offset..offset + 2].copy_from_slice(&bitmap.bits().to_be_bytes());
        offset += 2;

        if bitmap.contains(FPVolumeBitmap::ATTRIBUTES) {
            let attr_bytes = self.get_attributes().to_be_bytes();
            output[offset..offset + 2].copy_from_slice(&attr_bytes);
            offset += 2;
        }

        if bitmap.contains(FPVolumeBitmap::SIGNATURE) {
            let signature_bytes = (VolumeSignature::FixedDirectoryID as u16).to_be_bytes();
            output[offset..offset + 2].copy_from_slice(&signature_bytes);
            offset += 2;
        }

        if bitmap.contains(FPVolumeBitmap::CREATION_DATE) {
            let created_at_bytes = self.get_created_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&created_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPVolumeBitmap::MODIFICATION_DATE) {
            let modified_at_bytes = self.get_modified_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&modified_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPVolumeBitmap::BACKUP_DATE) {
            let backup_at_bytes = self.get_backup_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&backup_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPVolumeBitmap::VOLUME_ID) {
            let volume_id_bytes = self.get_volume_id().to_be_bytes();
            output[offset..offset + 2].copy_from_slice(&volume_id_bytes);
            offset += 2;
        }

        if bitmap.contains(FPVolumeBitmap::BYTES_FREE) {
            let bytes_free_bytes = self.get_bytes_free().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&bytes_free_bytes);
            offset += 4;
        }

        if bitmap.contains(FPVolumeBitmap::BYTES_TOTAL) {
            let bytes_total_bytes = self.get_bytes_total().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&bytes_total_bytes);
            offset += 4;
        }

        if bitmap.contains(FPVolumeBitmap::VOLUME_NAME) {
            let pascal_offset = offset + 2;
            output[offset..pascal_offset].copy_from_slice(&(pascal_offset as u16).to_be_bytes());
            offset += 2;

            output[offset] = self.name.len() as u8;
            offset += 1;

            output[offset..(offset + self.name.len())].copy_from_slice(self.name.as_bytes());
            offset += self.name.len();
        }

        Ok(offset)
    }

    /// Count the number of entries (files and folders) in a directory.
    /// This excludes "." and ".." entries automatically.
    /// Returns the total count as a u16 for the AFP OFFSPRING_COUNT parameter.
    pub async fn count_directory_entries(path: &PathBuf) -> std::io::Result<u16> {
        let mut entries = tokio::fs::read_dir(path).await?;
        let mut count: u16 = 0;

        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".tailtalk" {
                continue;
            }
            count = count.saturating_add(1);
        }

        Ok(count)
    }

    pub async fn get_directory_parms_resp(
        &self,
        bitmap: FPDirectoryBitmap,
        relative_path: &PathBuf,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let mut offset = 0;
        let mut variable_len_offset = 0;

        let id = *self
            .path_to_id
            .get(relative_path)
            .ok_or(AfpError::ObjectNotFound)?;
        let node = self.nodes.get(&id).ok_or(AfpError::ObjectNotFound)?;

        // Needed for OFFSPRING_COUNT if we rely on FS
        let full_path = self.path.join(relative_path);

        if bitmap.contains(FPDirectoryBitmap::ATTRIBUTES) {
            let attributes = node.get_attributes(&self.path);
            output[offset..offset + 2].copy_from_slice(&attributes.to_be_bytes());
            offset += 2;
        }

        if bitmap.contains(FPDirectoryBitmap::PARENT_DIR_ID) {
            output[offset..offset + 4].copy_from_slice(&node.parent_id.to_be_bytes());
            offset += 4;
        }

        if bitmap.contains(FPDirectoryBitmap::CREATE_DATE) {
            let created_at_bytes = self.get_created_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&created_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPDirectoryBitmap::MODIFICATION_DATE) {
            let modified_at_bytes = self.get_modified_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&modified_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPDirectoryBitmap::BACKUP_DATE) {
            let backup_at_bytes = self.get_backup_at().to_be_bytes();
            output[offset..offset + 4].copy_from_slice(&backup_at_bytes);
            offset += 4;
        }

        if bitmap.contains(FPDirectoryBitmap::FINDER_INFO) {
            let finder_info = node.get_finder_info(&self.path);
            output[offset..offset + 32].copy_from_slice(&finder_info);
            offset += 32;
        }

        if bitmap.contains(FPDirectoryBitmap::LONG_NAME) {
            let mut long_name_offset = bitmap.long_name_offset();
            output[offset..offset + 2].copy_from_slice(&(long_name_offset as u16).to_be_bytes());
            offset += 2;

            output[long_name_offset] = node.name.len() as u8;
            long_name_offset += 1;
            output[long_name_offset..long_name_offset + node.name.len()]
                .copy_from_slice(node.name.as_bytes());

            variable_len_offset += node.name.len() + 1;
        }

        if bitmap.contains(FPDirectoryBitmap::DIR_ID) {
            output[offset..offset + 4].copy_from_slice(&node.id.to_be_bytes());
            offset += 4;
        }

        if bitmap.contains(FPDirectoryBitmap::OFFSPRING_COUNT) {
            let count = Volume::count_directory_entries(&full_path)
                .await
                .map_err(|_| AfpError::ObjectNotFound)?;
            output[offset..offset + 2].copy_from_slice(&count.to_be_bytes());
            offset += 2;
        }

        if bitmap.contains(FPDirectoryBitmap::ACCESS_RIGHTS) {
            let summary = FPAccessRights::READ
                | FPAccessRights::WRITE
                | FPAccessRights::SEARCH
                | FPAccessRights::OWNER;
            let owner = FPAccessRights::READ | FPAccessRights::WRITE | FPAccessRights::SEARCH;
            let group = FPAccessRights::READ | FPAccessRights::SEARCH;
            let other = FPAccessRights::READ | FPAccessRights::SEARCH;

            // Write the 4-byte access rights structure
            output[offset] = summary.bits();
            output[offset + 1] = owner.bits();
            output[offset + 2] = group.bits();
            output[offset + 3] = other.bits();
            offset += 4;
        }

        Ok(offset + variable_len_offset)
    }

    pub async fn get_file_parms_resp(
        &self,
        bitmap: FPFileBitmap,
        relative_path: &PathBuf,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let id = *self
            .path_to_id
            .get(relative_path)
            .ok_or(AfpError::ObjectNotFound)?;
        let node = self.nodes.get(&id).ok_or(AfpError::ObjectNotFound)?;

        node.get_file_parms_resp(&self.path, bitmap, output, self.afp_v2)
            .await
    }

    pub async fn get_fork_parms(
        &self,
        bitmap: FPFileBitmap,
        fork_id: u16,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let (node_id, _fork_type) = self
            .fork_ref_to_node_id
            .get(&fork_id)
            .ok_or(AfpError::ObjectNotFound)?;
        let node = self.nodes.get(node_id).ok_or(AfpError::ObjectNotFound)?;

        node.get_file_parms_resp(&self.path, bitmap, output, self.afp_v2)
            .await
    }

    pub async fn open_fork(
        &mut self,
        fork_type: ForkType,
        bitmap: FPFileBitmap,
        dir_id: u32,
        relative_path: &PathBuf,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let mut offset = 0;

        match fork_type {
            ForkType::Data => {
                let parent_path = if dir_id == 2 {
                    PathBuf::new() // Root
                } else {
                    self.nodes
                        .get(&dir_id)
                        .ok_or(AfpError::ObjectNotFound)?
                        .path
                        .clone()
                };

                let full_relative_path = parent_path.join(relative_path);

                let id = *self
                    .path_to_id
                    .get(&full_relative_path)
                    .ok_or(AfpError::ObjectNotFound)?;
                let node = self.nodes.get_mut(&id).ok_or(AfpError::ObjectNotFound)?;

                let absolute_path = self.path.join(&full_relative_path);
                node.open_data_fork(&absolute_path).await.map_err(|e| {
                    eprintln!("Error opening data fork: {:?}", e);
                    AfpError::AccessDenied
                })?;

                let fork_ref_num = self.next_fork_ref_num;
                self.next_fork_ref_num = self.next_fork_ref_num.wrapping_add(1);
                if self.next_fork_ref_num == 0 {
                    self.next_fork_ref_num = 1;
                }
                self.fork_ref_to_node_id
                    .insert(fork_ref_num, (id, fork_type));

                output[offset..offset + 2].copy_from_slice(&bitmap.bits().to_be_bytes());
                offset += 2;
                output[offset..offset + 2].copy_from_slice(&fork_ref_num.to_be_bytes());
                offset += 2;

                match self
                    .get_file_parms_resp(bitmap, &full_relative_path, &mut output[offset..])
                    .await
                {
                    Ok(len) => {
                        offset += len;
                        Ok(offset)
                    }
                    Err(e) => Err(e),
                }
            }
            ForkType::Resource => Err(AfpError::ObjectNotFound),
        }
    }

    pub async fn open_dt(&mut self) -> Result<u16, AfpError> {
        if let Some(ref db) = self.desktop_database {
            return Ok(db.dt_ref_num);
        }

        let db = crate::afp::DesktopDatabase::new(&self.path, 1)?;
        let ref_num = db.dt_ref_num;
        self.desktop_database = Some(db);
        Ok(ref_num)
    }

    pub fn add_icon(
        &self,
        dt_ref_num: u16,
        req: &tailtalk_packets::afp::FPAddIcon,
        data: &[u8],
    ) -> Result<(), AfpError> {
        if let Some(ref db) = self.desktop_database
            && db.dt_ref_num == dt_ref_num
        {
            return db.add_icon(
                req.file_creator,
                req.file_type,
                req.icon_type,
                data,
            );
        }
        Err(AfpError::ItemNotFound)
    }

    pub fn get_icon(
        &self,
        dt_ref_num: u16,
        req: &tailtalk_packets::afp::FPGetIcon,
    ) -> Result<Vec<u8>, AfpError> {
        if let Some(ref db) = self.desktop_database
            && db.dt_ref_num == dt_ref_num
        {
            return db.get_icon(
                req.file_creator,
                req.file_type,
                req.icon_type,
                req.size,
            );
        }
        Err(AfpError::ItemNotFound)
    }

    pub fn get_icon_info(
        &self,
        dt_ref_num: u16,
        req: &tailtalk_packets::afp::FPGetIconInfo,
    ) -> Result<(u32, u32, u16), AfpError> {
        if let Some(ref db) = self.desktop_database
            && db.dt_ref_num == dt_ref_num
        {
            return db.get_icon_info(req.file_creator, req.icon_type);
        }
        Err(AfpError::ItemNotFound)
    }

    /// Close an open fork.
    ///
    /// # Arguments
    /// * `fork_id` - The fork reference number to close
    ///
    /// # Returns
    /// Ok(()) if the fork was successfully closed, or an error if the fork_id is invalid
    pub async fn close_fork(&mut self, fork_id: u16) -> Result<(), AfpError> {
        let (node_id, _fork_type) = self
            .fork_ref_to_node_id
            .get(&fork_id)
            .ok_or(AfpError::ObjectNotFound)?;

        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or(AfpError::ObjectNotFound)?;
        node.close_data_fork().await;

        self.fork_ref_to_node_id.remove(&fork_id);
        self.fork_locks.remove(&fork_id);

        Ok(())
    }

    /// Read data from an open fork.
    ///
    /// # Arguments
    /// * `read_req` - The FPRead request containing fork_id, offset, req_count, and newline parameters
    /// * `output` - Buffer to write the read data into
    ///
    /// # Returns
    /// Ok(bytes_read) if successful, or an error if the fork_id is invalid or read fails
    pub async fn read(
        &mut self,
        read_req: &FPRead,
        output: &mut [u8],
    ) -> Result<(usize, bool), AfpError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let &(node_id, _) = self
            .fork_ref_to_node_id
            .get(&read_req.fork_id)
            .ok_or(AfpError::ObjectNotFound)?;

        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(AfpError::ObjectNotFound)?;

        let file = node.data_fork.as_mut().ok_or(AfpError::ObjectNotFound)?;

        file.seek(std::io::SeekFrom::Start(read_req.offset as u64))
            .await
            .map_err(|e| {
                error!("Failed to seek to offset {}: {:?}", read_req.offset, e);
                AfpError::AccessDenied
            })?;

        let max_bytes = std::cmp::min(read_req.req_count as usize, output.len());

        let (bytes_read, is_eof) = if read_req.newline_mask != 0 {
            let mut total_read = 0;
            let mut hit_eof = false;
            for i in 0..max_bytes {
                match file.read_exact(&mut output[i..i + 1]).await {
                    Ok(_) => {
                        total_read += 1;
                        if read_req.byte_matches_newline(output[i]) {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        hit_eof = true;
                        break;
                    }
                    Err(e) => {
                        error!("Failed to read from fork: {:?}", e);
                        return Err(AfpError::AccessDenied);
                    }
                }
            }
            (total_read, hit_eof)
        } else {
            // tokio::fs::File::read() may return fewer bytes than requested even when
            // the file has more data (kernel buffer boundaries, page faults etc.).
            // We must loop until we fill max_bytes or hit a real EOF.
            let mut total_read = 0;
            let mut hit_eof = false;
            while total_read < max_bytes {
                match file.read(&mut output[total_read..max_bytes]).await {
                    Ok(0) => {
                        hit_eof = true;
                        break;
                    }
                    Ok(n) => {
                        total_read += n;
                    }
                    Err(e) => {
                        error!("Failed to read from fork: {:?}", e);
                        return Err(AfpError::AccessDenied);
                    }
                }
            }
            (total_read, hit_eof)
        };

        Ok((bytes_read, is_eof))
    }

    pub async fn set_fork_parms(&mut self, cmd: FPSetForkParms) -> Result<(), AfpError> {
        let (node_id, fork_type) = *self
            .fork_ref_to_node_id
            .get(&cmd.fork_ref_num)
            .ok_or(AfpError::ObjectNotFound)?;

        let node = self
            .nodes
            .get_mut(&node_id)
            .ok_or(AfpError::ObjectNotFound)?;

        match fork_type {
            ForkType::Data => {
                if cmd.resource_fork_length.is_some() {
                    return Err(AfpError::BitmapErr);
                }
                if let Some(len) = cmd.data_fork_length {
                    let file = node.data_fork.as_mut().ok_or(AfpError::ObjectNotFound)?;
                    file.set_len(len as u64).await.map_err(|e| {
                        error!("Failed to set fork length: {:?}", e);
                        AfpError::AccessDenied
                    })?;
                }
            }
            ForkType::Resource => {
                if cmd.data_fork_length.is_some() {
                    return Err(AfpError::BitmapErr);
                }
                if cmd.resource_fork_length.is_some() {
                    warn!("Setting resource fork length not supported yet");
                }
            }
        }

        Ok(())
    }

    pub async fn enumerate(
        &self,
        enumerate_cmd: FPEnumerate,
        output: &mut [u8],
    ) -> Result<usize, AfpError> {
        let node_id =
            self.resolve_node(enumerate_cmd.directory_id, Path::new(&enumerate_cmd.path))?;

        let node = self.nodes.get(&node_id).ok_or(AfpError::ObjectNotFound)?;

        if !node.is_dir {
            return Err(AfpError::ObjectTypeErr);
        }

        let full_path = self.path.join(&node.path);
        let mut entries = Vec::new();

        let mut read_dir = tokio::fs::read_dir(&full_path)
            .await
            .map_err(|_| AfpError::ObjectNotFound)?;

        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|_| AfpError::ObjectNotFound)?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".tailtalk" {
                continue;
            }

            let file_type = entry
                .file_type()
                .await
                .map_err(|_| AfpError::ObjectNotFound)?;
            let is_dir = file_type.is_dir();

            entries.push((entry, is_dir, name));
        }

        entries.sort_by(|a, b| match (a.1, b.1) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.2.cmp(&b.2),
        });

        let start_index = enumerate_cmd.start_index as usize;

        if start_index > entries.len() {
            return Err(AfpError::ObjectNotFound);
        }

        let start_idx = start_index - 1;
        let end_idx = std::cmp::min(start_idx + enumerate_cmd.req_count as usize, entries.len());

        let entries_to_return = &entries[start_idx..end_idx];

        let mut offset = 0;
        let count_offset = offset;
        offset += 2;
        let mut actual_count: u16 = 0;

        for (_entry, is_dir, name) in entries_to_return {
            let entry_relative_path = node.path.join(name);
            let mut entry_offset = offset;

            if *is_dir {
                let mut pad_byte = false;
                let mut directory_bitmap_len =
                    enumerate_cmd.directory_bitmap.response_len(name.len());
                if directory_bitmap_len.is_multiple_of(2) {
                    directory_bitmap_len += 1;
                    pad_byte = true;
                }

                output[entry_offset] = (directory_bitmap_len + 2) as u8;
                entry_offset += 1;

                output[entry_offset] = FileType::Directory.into();
                entry_offset += 1;

                match self
                    .get_directory_parms_resp(
                        enumerate_cmd.directory_bitmap,
                        &entry_relative_path,
                        &mut output[entry_offset..],
                    )
                    .await
                {
                    Ok(len) => {
                        entry_offset += len;
                        if pad_byte {
                            output[entry_offset] = 0;
                            entry_offset += 1;
                        }
                        offset = entry_offset;
                        actual_count += 1;
                    }
                    Err(e) => {
                        tracing::error!(
                            "BUG: failed to get parms for {:?}: {:?}",
                            entry_relative_path,
                            e
                        );
                        continue;
                    }
                }
            } else {
                let mut pad_byte = false;
                let mut file_bitmap_len = enumerate_cmd.file_bitmap.response_len(name.len());
                if file_bitmap_len.is_multiple_of(2) {
                    file_bitmap_len += 1;
                    pad_byte = true;
                }

                output[entry_offset] = (file_bitmap_len + 2) as u8;
                entry_offset += 1;

                output[entry_offset] = FileType::File.into();
                entry_offset += 1;

                match self
                    .get_file_parms_resp(
                        enumerate_cmd.file_bitmap,
                        &entry_relative_path,
                        &mut output[entry_offset..],
                    )
                    .await
                {
                    Ok(len) => {
                        entry_offset += len;
                        if pad_byte {
                            output[entry_offset] = 0;
                            entry_offset += 1;
                        }
                        offset = entry_offset;
                        actual_count += 1;
                    }
                    Err(e) => {
                        tracing::error!(
                            "BUG: failed to get parms for {:?}: {:?}",
                            entry_relative_path,
                            e
                        );
                        continue;
                    }
                }
            }

            if offset >= enumerate_cmd.max_reply_size as usize {
                break;
            }
        }

        output[count_offset..count_offset + 2].copy_from_slice(&actual_count.to_be_bytes());

        Ok(offset)
    }

    /// Lock or unlock a byte range in an open fork.
    ///
    /// # Arguments
    /// * `lock_req` - The FPByteRangeLock request containing fork_id, offset, length, and flags
    ///
    /// # Returns
    /// On success, returns the first byte of the locked range (for lock operations) or 0 (for unlock operations).
    /// Returns an error if:
    /// - The fork_id is invalid
    /// - A conflicting lock exists (when locking)
    /// - The lock doesn't exist (when unlocking)
    pub async fn byte_range_lock(
        &mut self,
        lock_req: &tailtalk_packets::afp::FPByteRangeLock,
    ) -> Result<u32, AfpError> {
        // Verify the fork exists
        let (node_id, _fork_type) = self
            .fork_ref_to_node_id
            .get(&lock_req.fork_id)
            .ok_or(AfpError::ObjectNotFound)?;

        // Get the fork size to calculate absolute offset if needed
        let node = self.nodes.get(node_id).ok_or(AfpError::ObjectNotFound)?;
        let absolute_path = self.path.join(&node.path);
        let metadata = tokio::fs::metadata(&absolute_path)
            .await
            .map_err(|_| AfpError::ObjectNotFound)?;
        let fork_size = metadata.len();

        // Calculate the absolute offset based on start_end_flag
        let absolute_offset: u64 = match lock_req.flags.contains(FPByteRangeLockFlags::END) {
            false => {
                // Offset from start - treat as unsigned
                if lock_req.offset < 0 {
                    // Negative offset from start doesn't make sense, treat as 0
                    0
                } else {
                    lock_req.offset as u64
                }
            }
            true => {
                // Offset from end - can be negative
                if lock_req.offset < 0 {
                    // Negative offset from end (e.g., -10 means 10 bytes before EOF)
                    fork_size.saturating_sub((-lock_req.offset) as u64)
                } else {
                    // Positive offset from end (beyond EOF)
                    fork_size.saturating_add(lock_req.offset as u64)
                }
            }
        };

        let lock_end = absolute_offset.saturating_add(lock_req.length as u64);

        // Get or create the lock list for this fork
        let locks = self.fork_locks.entry(lock_req.fork_id).or_default();

        match lock_req.flags.contains(FPByteRangeLockFlags::UNLOCK) {
            false => {
                // Check for conflicting locks
                for (existing_offset, existing_length) in locks.iter() {
                    let existing_end = existing_offset.saturating_add(*existing_length);

                    // Check if ranges overlap
                    if absolute_offset < existing_end && lock_end > *existing_offset {
                        return Err(AfpError::RangeOverlap);
                    }
                }

                // Add the new lock
                locks.push((absolute_offset, lock_req.length as u64));
                // Return the first byte of the locked range
                Ok(absolute_offset as u32)
            }
            true => {
                // Find and remove the matching lock
                if let Some(pos) = locks.iter().position(|(off, len)| {
                    *off == absolute_offset && *len == lock_req.length as u64
                }) {
                    locks.remove(pos);
                    // Return 0 for unlock operations
                    Ok(0)
                } else {
                    // Lock not found - return RangeNotLocked error
                    Err(AfpError::RangeNotLocked)
                }
            }
        }
    }

    pub async fn delete(&mut self, delete_req: &FPDelete) -> Result<(), AfpError> {
        let node_id = self.resolve_node(delete_req.directory_id, Path::new(&delete_req.path))?;

        // Cannot delete root
        if node_id == 2 {
            return Err(AfpError::AccessDenied);
        }

        let (is_dir, full_path, relative_path, is_open) = {
            let node = self.nodes.get(&node_id).ok_or(AfpError::ObjectNotFound)?;
            (
                node.is_dir,
                self.path.join(&node.path),
                node.path.clone(),
                node.data_fork.is_some(),
            )
        };

        if !is_dir {
            // Check if file is open
            if is_open {
                return Err(AfpError::FileBusy);
            }

            tokio::fs::remove_file(&full_path).await.map_err(|e| {
                error!("Failed to remove file {:?}: {:?}", full_path, e);
                AfpError::AccessDenied
            })?;
        } else {
            // Check if directory is empty
            let mut read_dir = tokio::fs::read_dir(&full_path).await.map_err(|e| {
                error!("Failed to read directory {:?}: {:?}", full_path, e);
                AfpError::ObjectNotFound
            })?;

            if let Ok(Some(_)) = read_dir.next_entry().await {
                return Err(AfpError::DirNotEmpty);
            }

            tokio::fs::remove_dir(&full_path).await.map_err(|e| {
                error!("Failed to remove directory {:?}: {:?}", full_path, e);
                AfpError::AccessDenied
            })?;
        }

        // Update internal state
        self.nodes.remove(&node_id);
        self.path_to_id.remove(&relative_path);

        Ok(())
    }

    /// Sync all open file handles to disk.
    ///
    /// This ensures that both file content and metadata are written to persistent storage
    /// for all currently open forks in the volume.
    ///
    /// # Returns
    /// Ok(()) if all syncs succeeded, or an error if any sync operation failed
    pub async fn sync(&mut self) -> Result<(), AfpError> {
        for node in self.nodes.values_mut() {
            if let Some(file) = &mut node.data_fork {
                file.sync_all().await.map_err(|e| {
                    error!("Failed to sync file {:?}: {:?}", node.path, e);
                    AfpError::AccessDenied
                })?;
            }
        }
        Ok(())
    }

    pub async fn write_fork(
        &mut self,
        fork_id: u16,
        offset: u64,
        data: &[u8],
    ) -> Result<usize, AfpError> {
        let (node_id, fork_type) = self
            .fork_ref_to_node_id
            .get(&fork_id)
            .ok_or(AfpError::AccessDenied)?;

        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or(AfpError::ObjectNotFound)?;

        tracing::info!(
            "Writing {} bytes to fork {} at offset {}",
            data.len(),
            fork_id,
            offset
        );

        match fork_type {
            ForkType::Data => {
                if let Some(file) = &mut node.data_fork {
                    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

                    file.seek(tokio::io::SeekFrom::Start(offset))
                        .await
                        .map_err(|_| AfpError::MiscErr)?;

                    file.write_all(data).await.map_err(|_| AfpError::MiscErr)?;

                    Ok(data.len())
                } else {
                    Err(AfpError::AccessDenied)
                }
            }
            ForkType::Resource => Err(AfpError::AccessDenied),
        }
    }

    pub fn set_comment(
        &self,
        directory_id: u32,
        path: &Path,
        comment: &[u8],
    ) -> Result<(), AfpError> {
        let node_id = self.resolve_node(directory_id, path)?;
        tracing::info!("Setting comment for node {}", node_id);
        if let Some(db) = &self.desktop_database {
            db.set_comment(node_id, comment)
        } else {
            Err(AfpError::AccessDenied)
        }
    }

    pub fn get_comment(&self, directory_id: u32, path: &Path) -> Result<Vec<u8>, AfpError> {
        let node_id = self.resolve_node(directory_id, path)?;
        if let Some(db) = &self.desktop_database {
            db.get_comment(node_id)
        } else {
            Err(AfpError::AccessDenied)
        }
    }

    pub fn remove_comment(&self, directory_id: u32, path: &Path) -> Result<(), AfpError> {
        let node_id = self.resolve_node(directory_id, path)?;
        if let Some(db) = &self.desktop_database {
            db.remove_comment(node_id)
        } else {
            Err(AfpError::AccessDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailtalk_packets::afp::{FPDirectoryBitmap, FPEnumerate, FPFileBitmap};
    use tempfile::tempdir;
    use tokio::fs::File;

    #[tokio::test]
    async fn test_enumerate_volume_root() {
        let dir = tempdir().unwrap();
        let root_path = dir.path().to_path_buf();
        let volume_name = "TestVol".to_string();

        let file1_path = root_path.join("file1.txt");
        let file2_path = root_path.join("file2.txt");

        File::create(&file1_path).await.unwrap();
        File::create(&file2_path).await.unwrap();

        let volume = Volume::new(volume_name, root_path.clone(), 1, true).await;

        let enumerate_cmd = FPEnumerate {
            volume_id: 1,
            directory_id: 2,
            file_bitmap: FPFileBitmap::LONG_NAME | FPFileBitmap::FILE_NUMBER, // Request simple info
            directory_bitmap: FPDirectoryBitmap::LONG_NAME | FPDirectoryBitmap::DIR_ID,
            req_count: 69,
            start_index: 1,
            max_reply_size: 1024,
            path: "".into(), // Empty path
        };

        let mut output = [0u8; 1024];

        let result = volume.enumerate(enumerate_cmd, &mut output).await;

        assert!(result.is_ok(), "Enumerate failed: {:?}", result.err());

        let count = u16::from_be_bytes(output[0..2].try_into().unwrap());
        println!("Enumerated {} items", count);

        assert_eq!(count, 2, "Should have found 2 files");
    }
}
