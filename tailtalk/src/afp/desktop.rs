use std::path::Path;
use tailtalk_packets::afp::AfpError;
use tracing::error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IconKey {
    pub creator: [u8; 4],
    pub file_type: [u8; 4],
    pub icon_type: u8,
}

impl IconKey {
    pub fn to_bytes(&self) -> [u8; 9] {
        let mut bytes = [0u8; 9];
        // AFP creator and file_type are exactly 4 bytes (Mac OS OSType format)
        bytes[0..4].copy_from_slice(&self.creator);
        bytes[4..8].copy_from_slice(&self.file_type);

        bytes[8] = self.icon_type;
        bytes
    }
}

pub struct DesktopDatabase {
    pub dt_ref_num: u16,
    db: sled::Db,
}

impl DesktopDatabase {
    pub fn new(volume_root: &Path, dt_ref_num: u16) -> Result<Self, AfpError> {
        let db_path = volume_root.join(".tailtalk").join("desktop.db");

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                error!(
                    "Failed to create Desktop Database directory at {:?}: {}",
                    parent, e
                );
                AfpError::AccessDenied
            })?;
        }

        let db = sled::open(&db_path).map_err(|e| {
            error!("Failed to open Desktop Database at {:?}: {}", db_path, e);
            AfpError::AccessDenied
        })?;

        Ok(Self { dt_ref_num, db })
    }

    pub fn add_icon(
        &self,
        creator: [u8; 4],
        file_type: [u8; 4],
        icon_type: u8,
        icon_data: &[u8],
    ) -> Result<(), AfpError> {
        let key = IconKey {
            creator,
            file_type,
            icon_type,
        };

        let tree = self.db.open_tree(b"icons").map_err(|e| {
            error!("Failed to open 'icons' tree: {}", e);
            AfpError::AccessDenied
        })?;

        tree.insert(key.to_bytes(), icon_data).map_err(|e| {
            error!("Failed to insert icon: {}", e);
            AfpError::AccessDenied
        })?;
        Ok(())
    }

    pub fn get_icon(
        &self,
        creator: [u8; 4],
        file_type: [u8; 4],
        icon_type: u8,
        _size: u16,
    ) -> Result<Vec<u8>, AfpError> {
        let key = IconKey {
            creator,
            file_type,
            icon_type,
        };

        let tree = self.db.open_tree(b"icons").map_err(|e| {
            error!("Failed to open 'icons' tree: {}", e);
            AfpError::AccessDenied
        })?;

        if let Some(data) = tree.get(key.to_bytes()).map_err(|e| {
            error!("Failed to get icon: {}", e);
            AfpError::AccessDenied
        })? {
            Ok(data.to_vec())
        } else {
            Err(AfpError::ItemNotFound)
        }
    }
    pub fn get_icon_info(
        &self,
        creator: [u8; 4],
        _icon_type: u16,
    ) -> Result<(u32, u32, u16), AfpError> {
        // Since sqlite/sled stores the entire icon, we can iterate over the keys matching the creator
        // and find an icon type that matches the request. Or return basic size info.
        let tree = self.db.open_tree(b"icons").map_err(|e| {
            error!("Failed to open 'icons' tree: {}", e);
            AfpError::AccessDenied
        })?;

        // Format is:
        // tag (4 bytes)
        // file_type (4 bytes)
        // icon_type (1 byte, padding, or matching requested size)
        // size (2 bytes)

        for result in tree.iter() {
            if let Ok((key, value)) = result
                && key.len() == 9
            {
                let mut key_creator = [0u8; 4];
                key_creator.copy_from_slice(&key[0..4]);
                if key_creator == creator {
                    let mut file_type = [0u8; 4];
                    file_type.copy_from_slice(&key[4..8]);

                    // We just return the first icon we find for this creator
                    // For a full implementation we would want to correctly parse the icon_type u16 request into the actual icon_type u8
                    // Return: IconTag (4 bytes), FileCreator/Type (4 bytes), Size (2 bytes)
                    let icon_tag = 0; // Or whatever tag you want
                    let file_type_u32 = u32::from_be_bytes(file_type);
                    let size = value.len() as u16;

                    return Ok((icon_tag, file_type_u32, size));
                }
            }
        }

        Err(AfpError::ItemNotFound)
    }

    pub fn set_comment(&self, node_id: u32, comment: &[u8]) -> Result<(), AfpError> {
        let tree = self.db.open_tree(b"comments").map_err(|e| {
            error!("Failed to open 'comments' tree: {}", e);
            AfpError::AccessDenied
        })?;

        tree.insert(node_id.to_be_bytes(), comment).map_err(|e| {
            error!("Failed to insert comment: {}", e);
            AfpError::AccessDenied
        })?;

        tracing::info!(
            "Set comment of length {} for node {}",
            comment.len(),
            node_id
        );
        Ok(())
    }

    pub fn get_comment(&self, node_id: u32) -> Result<Vec<u8>, AfpError> {
        let tree = self.db.open_tree(b"comments").map_err(|e| {
            error!("Failed to open 'comments' tree: {}", e);
            AfpError::AccessDenied
        })?;

        tracing::info!("Get comment for node {}", node_id);
        if let Some(data) = tree.get(node_id.to_be_bytes()).map_err(|e| {
            error!("Failed to get comment: {}", e);
            AfpError::AccessDenied
        })? {
            Ok(data.to_vec())
        } else {
            Err(AfpError::ItemNotFound)
        }
    }

    pub fn remove_comment(&self, node_id: u32) -> Result<(), AfpError> {
        let tree = self.db.open_tree(b"comments").map_err(|e| {
            error!("Failed to open 'comments' tree: {}", e);
            AfpError::AccessDenied
        })?;

        tree.remove(node_id.to_be_bytes()).map_err(|e| {
            error!("Failed to remove comment: {}", e);
            AfpError::AccessDenied
        })?;
        Ok(())
    }
}
