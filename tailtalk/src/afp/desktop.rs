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
    icons: sled::Tree,
    comments: sled::Tree,
    appls: sled::Tree,
    pub mangle_names: sled::Tree,
}

impl DesktopDatabase {
    /// Open (or create) the desktop database at the standard path under `volume_root`.
    pub fn open_or_create(volume_root: &Path) -> Result<sled::Db, AfpError> {
        let db_path = volume_root.join(".tailtalk").join("desktop.db");

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                error!(
                    "Failed to create Desktop Database directory at {:?}: {}",
                    parent, e
                );
                AfpError::AccessDenied
            })?;
        }

        sled::open(&db_path).map_err(|e| {
            error!("Failed to open Desktop Database at {:?}: {}", db_path, e);
            AfpError::AccessDenied
        })
    }

    /// Construct a `DesktopDatabase` from an already-open `sled::Db` handle.
    /// Use this to share a single DB handle across multiple AFP sessions.
    pub fn from_db(db: sled::Db, dt_ref_num: u16) -> Result<Self, AfpError> {
        let icons = db.open_tree(b"icons").map_err(|e| {
            error!("Failed to open 'icons' tree: {}", e);
            AfpError::AccessDenied
        })?;
        let comments = db.open_tree(b"comments").map_err(|e| {
            error!("Failed to open 'comments' tree: {}", e);
            AfpError::AccessDenied
        })?;
        let appls = db.open_tree(b"appls").map_err(|e| {
            error!("Failed to open 'appls' tree: {}", e);
            AfpError::AccessDenied
        })?;
        let mangle_names = db.open_tree(b"mangle_names").map_err(|e| {
            error!("Failed to open 'mangle_names' tree: {}", e);
            AfpError::AccessDenied
        })?;
        Ok(Self { dt_ref_num, icons, comments, appls, mangle_names })
    }

    /// Open (or create) the desktop database at the standard path and wrap it.
    /// Prefer `open_or_create` + `from_db` when sharing across sessions.
    pub fn new(volume_root: &Path, dt_ref_num: u16) -> Result<Self, AfpError> {
        let db = Self::open_or_create(volume_root)?;
        Self::from_db(db, dt_ref_num)
    }

    /// Record a mangled name → original POSIX filename mapping so it survives restarts.
    /// `mangled_mac_bytes` is the raw MacRoman output of `mangle_name`; `posix_name` is
    /// the on-disk filename (UTF-8, no AFP colon/slash substitution).
    pub fn register_mangle(&self, mangled_mac_bytes: &[u8], posix_name: &str) {
        if let Err(e) = self.mangle_names.insert(mangled_mac_bytes, posix_name.as_bytes()) {
            error!("Failed to register mangle entry: {}", e);
        }
    }

    /// Look up a mangled name and return the original POSIX filename, if known.
    pub fn lookup_mangle(&self, mangled_mac_bytes: &[u8]) -> Option<String> {
        self.mangle_names
            .get(mangled_mac_bytes)
            .ok()
            .flatten()
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
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

        self.icons.insert(key.to_bytes(), icon_data).map_err(|e| {
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
        // AFP wire format includes an iconSize field; we store one copy per type and ignore it.
        _size: u16,
    ) -> Result<Vec<u8>, AfpError> {
        let key = IconKey {
            creator,
            file_type,
            icon_type,
        };

        if let Some(data) = self.icons.get(key.to_bytes()).map_err(|e| {
            error!("Failed to get icon: {}", e);
            AfpError::AccessDenied
        })? {
            Ok(data.to_vec())
        } else {
            Err(AfpError::ItemNotFound)
        }
    }

    /// Return (IconTag, FileType, Size) for the 1-based `index`-th icon
    /// registered for `creator`; clients walk index 1, 2, … until ItemNotFound.
    pub fn get_icon_info(
        &self,
        creator: [u8; 4],
        index: u16,
    ) -> Result<(u32, u32, u16), AfpError> {
        let target = index.saturating_sub(1) as usize;
        let mut seen = 0usize;

        for result in self.icons.iter() {
            if let Ok((key, value)) = result
                && key.len() == 9
            {
                let mut key_creator = [0u8; 4];
                key_creator.copy_from_slice(&key[0..4]);
                if key_creator == creator {
                    if seen == target {
                        let mut file_type = [0u8; 4];
                        file_type.copy_from_slice(&key[4..8]);
                        let icon_tag = 0;
                        let file_type_u32 = u32::from_be_bytes(file_type);
                        let size = value.len() as u16;
                        return Ok((icon_tag, file_type_u32, size));
                    }
                    seen += 1;
                }
            }
        }

        Err(AfpError::ItemNotFound)
    }

    pub fn set_comment(&self, rel_path: &std::path::Path, comment: &[u8]) -> Result<(), AfpError> {
        let key = rel_path.to_string_lossy();
        self.comments.insert(key.as_bytes(), comment).map_err(|e| {
            error!("Failed to insert comment: {}", e);
            AfpError::AccessDenied
        })?;

        tracing::info!(
            "Set comment of length {} for path {:?}",
            comment.len(),
            rel_path
        );
        Ok(())
    }

    pub fn get_comment(&self, rel_path: &std::path::Path) -> Result<Vec<u8>, AfpError> {
        tracing::info!("Get comment for path {:?}", rel_path);
        let key = rel_path.to_string_lossy();
        if let Some(data) = self.comments.get(key.as_bytes()).map_err(|e| {
            error!("Failed to get comment: {}", e);
            AfpError::AccessDenied
        })? {
            Ok(data.to_vec())
        } else {
            Err(AfpError::ItemNotFound)
        }
    }

    pub fn remove_comment(&self, rel_path: &std::path::Path) -> Result<(), AfpError> {
        let key = rel_path.to_string_lossy();
        self.comments.remove(key.as_bytes()).map_err(|e| {
            error!("Failed to remove comment: {}", e);
            AfpError::AccessDenied
        })?;
        Ok(())
    }

    /// Move a comment from `old_path` to `new_path`, used when a file is renamed or moved.
    /// Silently succeeds if no comment exists for `old_path`.
    pub fn move_comment(
        &self,
        old_path: &std::path::Path,
        new_path: &std::path::Path,
    ) -> Result<(), AfpError> {
        let old_key = old_path.to_string_lossy();
        if let Some(data) = self.comments.remove(old_key.as_bytes()).map_err(|e| {
            error!("Failed to remove old comment key: {}", e);
            AfpError::AccessDenied
        })? {
            let new_key = new_path.to_string_lossy();
            self.comments.insert(new_key.as_bytes(), data).map_err(|e| {
                error!("Failed to insert comment at new key: {}", e);
                AfpError::AccessDenied
            })?;
        }
        Ok(())
    }

    /// Copy a comment from `src_path` to `dst_path`, used when a file is copied.
    /// Silently succeeds if no comment exists for `src_path`.
    pub fn copy_comment(
        &self,
        src_path: &std::path::Path,
        dst_path: &std::path::Path,
    ) -> Result<(), AfpError> {
        let src_key = src_path.to_string_lossy();
        if let Some(data) = self.comments.get(src_key.as_bytes()).map_err(|e| {
            error!("Failed to read comment for copy: {}", e);
            AfpError::AccessDenied
        })? {
            let dst_key = dst_path.to_string_lossy();
            self.comments.insert(dst_key.as_bytes(), data).map_err(|e| {
                error!("Failed to insert copied comment: {}", e);
                AfpError::AccessDenied
            })?;
        }
        Ok(())
    }

    /// Update the stored path in every APPL entry that matches `old_path`, used when
    /// a file is renamed or moved.  Silently succeeds if no matching entry exists.
    pub fn move_appl_path(
        &self,
        old_path: &str,
        new_path: &str,
        old_dir_id: u32,
        new_dir_id: u32,
    ) -> Result<(), AfpError> {
        let old_dir_bytes = old_dir_id.to_be_bytes();
        let old_path_bytes = old_path.as_bytes();

        let matches: Vec<(sled::IVec, sled::IVec)> = self.appls
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(_, v)| {
                v.len() >= 5
                    && v[0..4] == old_dir_bytes
                    && {
                        let path_len = v[4] as usize;
                        v.len() >= 5 + path_len && &v[5..5 + path_len] == old_path_bytes
                    }
            })
            .collect();

        let new_path_bytes = new_path.as_bytes();
        let new_dir_bytes = new_dir_id.to_be_bytes();
        for (key, _) in matches {
            let mut value = Vec::with_capacity(5 + new_path_bytes.len());
            value.extend_from_slice(&new_dir_bytes);
            value.push(new_path_bytes.len() as u8);
            value.extend_from_slice(new_path_bytes);
            self.appls.insert(key, value).map_err(|e| {
                error!("Failed to update APPL path: {}", e);
                AfpError::AccessDenied
            })?;
        }
        Ok(())
    }

    /// Copy APPL entries from `src_path` to `dst_path`, used when a file is copied.
    /// Silently succeeds if no matching entry exists.
    pub fn copy_appl(
        &self,
        src_path: &str,
        dst_path: &str,
        src_dir_id: u32,
        dst_dir_id: u32,
    ) -> Result<(), AfpError> {
        let src_dir_bytes = src_dir_id.to_be_bytes();
        let src_path_bytes = src_path.as_bytes();

        let matches: Vec<(sled::IVec, sled::IVec)> = self.appls
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(_, v)| {
                v.len() >= 5
                    && v[0..4] == src_dir_bytes
                    && {
                        let path_len = v[4] as usize;
                        v.len() >= 5 + path_len && &v[5..5 + path_len] == src_path_bytes
                    }
            })
            .collect();

        let dst_path_bytes = dst_path.as_bytes();
        let dst_dir_bytes = dst_dir_id.to_be_bytes();
        for (key, _) in matches {
            let mut value = Vec::with_capacity(5 + dst_path_bytes.len());
            value.extend_from_slice(&dst_dir_bytes);
            value.push(dst_path_bytes.len() as u8);
            value.extend_from_slice(dst_path_bytes);
            self.appls.insert(key, value).map_err(|e| {
                error!("Failed to insert copied APPL: {}", e);
                AfpError::AccessDenied
            })?;
        }
        Ok(())
    }

    /// Remove all APPL entries whose stored path matches `path` and directory ID matches
    /// `dir_id`. Used when a file is deleted. Silently succeeds if no match exists.
    pub fn delete_appls_for_path(&self, dir_id: u32, path: &str) -> Result<(), AfpError> {
        let dir_bytes = dir_id.to_be_bytes();
        let path_bytes = path.as_bytes();

        let keys: Vec<sled::IVec> = self.appls
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(_, v)| {
                v.len() >= 5
                    && v[0..4] == dir_bytes
                    && {
                        let path_len = v[4] as usize;
                        v.len() >= 5 + path_len && &v[5..5 + path_len] == path_bytes
                    }
            })
            .map(|(k, _)| k)
            .collect();

        for key in keys {
            self.appls.remove(key).map_err(|e| {
                error!("Failed to remove APPL entry: {}", e);
                AfpError::AccessDenied
            })?;
        }
        Ok(())
    }

    /// Register an application in the Desktop DB.
    ///
    /// Key: creator (4) + tag (4, big-endian) — one entry per (creator, tag) pair.
    /// Value: directory_id (4) + path_len (1) + path bytes.
    pub fn add_appl(
        &self,
        creator: [u8; 4],
        tag: u32,
        directory_id: u32,
        path: &str,
    ) -> Result<(), AfpError> {
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&creator);
        key[4..8].copy_from_slice(&tag.to_be_bytes());

        let path_bytes = path.as_bytes();
        if path_bytes.len() > 255 {
            return Err(AfpError::ParamError);
        }
        let mut value = Vec::with_capacity(5 + path_bytes.len());
        value.extend_from_slice(&directory_id.to_be_bytes());
        value.push(path_bytes.len() as u8);
        value.extend_from_slice(path_bytes);

        self.appls.insert(key, value).map_err(|e| {
            error!("Failed to insert APPL: {}", e);
            AfpError::AccessDenied
        })?;
        Ok(())
    }

    /// Deregister an application identified by (creator, directory_id, path).
    pub fn remove_appl(
        &self,
        creator: [u8; 4],
        directory_id: u32,
        path: &str,
    ) -> Result<(), AfpError> {
        let dir_bytes = directory_id.to_be_bytes();
        let path_bytes = path.as_bytes();

        for result in self.appls.scan_prefix(creator) {
            let (key, value) = result.map_err(|e| {
                error!("Failed to scan APPLs: {}", e);
                AfpError::AccessDenied
            })?;

            if value.len() >= 5 {
                let path_len = value[4] as usize;
                if value[0..4] == dir_bytes
                    && value.len() >= 5 + path_len
                    && &value[5..5 + path_len] == path_bytes
                {
                    self.appls.remove(&key).map_err(|e| {
                        error!("Failed to remove APPL: {}", e);
                        AfpError::AccessDenied
                    })?;
                    return Ok(());
                }
            }
        }

        Err(AfpError::ItemNotFound)
    }

    /// Retrieve a registered application by creator and 1-based index.
    ///
    /// Returns (tag, directory_id, path).
    pub fn get_appl(
        &self,
        creator: [u8; 4],
        index: u16,
    ) -> Result<(u32, u32, String), AfpError> {
        let target = index.saturating_sub(1) as usize;
        for (i, result) in self.appls.scan_prefix(creator).enumerate() {
            let (key, value) = result.map_err(|e| {
                error!("Failed to scan APPLs: {}", e);
                AfpError::AccessDenied
            })?;

            if i == target {
                if key.len() < 8 || value.len() < 5 {
                    return Err(AfpError::ItemNotFound);
                }
                let tag = u32::from_be_bytes(key[4..8].try_into().unwrap());
                let directory_id = u32::from_be_bytes(value[0..4].try_into().unwrap());
                let path_len = value[4] as usize;
                let path = if value.len() >= 5 + path_len {
                    String::from_utf8_lossy(&value[5..5 + path_len]).into_owned()
                } else {
                    String::new()
                };
                return Ok((tag, directory_id, path));
            }
        }

        Err(AfpError::ItemNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tailtalk_packets::afp::mangle_name;
    use tempfile::tempdir;

    fn open_db(root: &std::path::Path) -> DesktopDatabase {
        let db = DesktopDatabase::open_or_create(root).unwrap();
        DesktopDatabase::from_db(db, 1).unwrap()
    }

    #[test]
    fn register_then_lookup_returns_original_name() {
        let dir = tempdir().unwrap();
        let dt = open_db(dir.path());

        let long_name = "This is a very long filename that exceeds the AFP 2.x limit.txt";
        let mangled = mangle_name(long_name);

        dt.register_mangle(&mangled, long_name);
        assert_eq!(dt.lookup_mangle(&mangled).as_deref(), Some(long_name));
    }

    #[test]
    fn lookup_unknown_key_returns_none() {
        let dir = tempdir().unwrap();
        let dt = open_db(dir.path());
        assert_eq!(dt.lookup_mangle(b"not-registered"), None);
    }

    #[test]
    fn mangle_mapping_survives_db_reopen() {
        let dir = tempdir().unwrap();

        let long_name = "This is a very long filename that exceeds the AFP 2.x limit.txt";
        let mangled = mangle_name(long_name);

        // Session 1: register and close.
        {
            let dt = open_db(dir.path());
            dt.register_mangle(&mangled, long_name);
        }

        // Session 2: reopen the same on-disk DB and verify the entry is still there.
        let dt2 = open_db(dir.path());
        assert_eq!(
            dt2.lookup_mangle(&mangled).as_deref(),
            Some(long_name),
            "mangle entry should survive a DB close and reopen"
        );
    }

    #[test]
    fn multiple_distinct_long_names_are_stored_independently() {
        let dir = tempdir().unwrap();
        let dt = open_db(dir.path());

        let name_a = "This is a very long filename that exceeds limit - variant A.txt";
        let name_b = "This is a very long filename that exceeds limit - variant B.txt";
        let mangled_a = mangle_name(name_a);
        let mangled_b = mangle_name(name_b);

        assert_ne!(mangled_a, mangled_b);

        dt.register_mangle(&mangled_a, name_a);
        dt.register_mangle(&mangled_b, name_b);

        assert_eq!(dt.lookup_mangle(&mangled_a).as_deref(), Some(name_a));
        assert_eq!(dt.lookup_mangle(&mangled_b).as_deref(), Some(name_b));
    }

    /// Simulate the full unmangle round-trip that happens on the wire:
    ///   1. Server mangles the name and sends the raw MacRoman bytes to the client.
    ///   2. Client stores/displays the name (opaque bytes to it).
    ///   3. Client sends the name back; our packet parser decodes it from MacRoman to UTF-8.
    ///   4. We re-encode to MacRoman to key into the sled table.
    ///   5. lookup_mangle returns the original POSIX filename.
    #[test]
    fn unmangle_survives_macroman_decode_reencode_roundtrip() {
        use encoding_rs::MACINTOSH;

        let dir = tempdir().unwrap();
        let dt = open_db(dir.path());

        let long_name = "This is a very long filename that exceeds the AFP 2.x limit.txt";
        let mangled_bytes = mangle_name(long_name);

        dt.register_mangle(&mangled_bytes, long_name);

        // Simulate what our packet parser does: decode the raw MacRoman bytes to UTF-8.
        let (decoded_utf8, _, _) = MACINTOSH.decode(&mangled_bytes);

        // Simulate what resolve_node does: re-encode the UTF-8 string back to MacRoman.
        let (reencoded, _, _) = MACINTOSH.encode(decoded_utf8.as_ref());

        // The re-encoded bytes must match the original mangled bytes so the lookup succeeds.
        assert_eq!(
            reencoded.as_ref(),
            mangled_bytes.as_slice(),
            "MacRoman decode→encode must be lossless for mangled names"
        );
        assert_eq!(
            dt.lookup_mangle(&reencoded).as_deref(),
            Some(long_name),
            "lookup_mangle must return the original name after a decode/re-encode round-trip"
        );
    }
}
