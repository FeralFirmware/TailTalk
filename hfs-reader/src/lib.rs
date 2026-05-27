//! Read-only parser for classic HFS disk images.
//!
//! Supports both common HFS signatures (`0xD2D7` and `0x4244`) and handles
//! Disk Copy 4.2 containers transparently by stripping the 84-byte header
//! before parsing.  HFS+ (`0x482B`) is rejected with an explicit error.
//!
//! # Usage
//!
//! ```no_run
//! use hfs_reader::HfsVolume;
//!
//! let image_bytes = std::fs::read("my_disk.dsk").unwrap();
//! let vol = HfsVolume::parse(&image_bytes).unwrap();
//!
//! for file in &vol.files {
//!     let data = vol.read_data_fork(file).unwrap();
//!     let rsrc = vol.read_rsrc_fork(file).unwrap();
//!     println!("{}: data={} rsrc={}", file.rel_path.display(), data.len(), rsrc.len());
//! }
//! ```

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

// Each extent descriptor is (first_alloc_block, block_count).
type Extents = [(u16, u16); 3];

// Accumulates raw catalog data for a file before path-building.  Directory
// names for parent CNIDs may appear after their children in tree order, so
// everything is collected first and paths are resolved in a second pass.
struct RawFile {
    cnid: u32,
    parent_cnid: u32,
    file_type: [u8; 4],
    creator: [u8; 4],
    data_logical: u32,
    data_ext: Extents,
    rsrc_logical: u32,
    rsrc_ext: Extents,
}

/// A file entry decoded from the HFS catalog B-tree.
pub struct HfsFileEntry {
    /// Relative path from the volume root.
    pub rel_path: PathBuf,
    /// CNID of the parent directory.
    pub parent_cnid: u32,
    /// Mac OS four-character file type (e.g. `b"APPL"`).
    pub file_type: [u8; 4],
    /// Mac OS four-character creator code (e.g. `b"MACS"`).
    pub creator: [u8; 4],

    pub(crate) data_logical: u32,
    pub(crate) data_extents: Vec<Extents>,
    pub(crate) rsrc_logical: u32,
    pub(crate) rsrc_extents: Vec<Extents>,
}

/// A directory entry decoded from the HFS catalog B-tree.
pub struct HfsDirEntry {
    /// Relative path from the volume root.
    pub rel_path: PathBuf,
}

/// A parsed HFS volume.
///
/// Holds a reference to the raw image bytes — call [`HfsVolume::parse`] with
/// a slice that lives long enough for all the reads you need.
pub struct HfsVolume<'a> {
    img: &'a [u8],
    block_size: u32,
    first_alloc_sector: u32,
    /// Volume name from the MDB (drVN).  Non-printable MacRoman bytes become `_`.
    pub volume_name: String,
    /// All files found in the catalog, in catalog order.
    pub files: Vec<HfsFileEntry>,
    /// All directories found in the catalog (excluding the volume root).
    pub dirs: Vec<HfsDirEntry>,
}

impl<'a> HfsVolume<'a> {
    /// Parse an HFS disk image.  Both raw sector dumps and Disk Copy 4.2
    /// containers are accepted.
    #[allow(clippy::missing_errors_doc)]
    pub fn parse(img: &'a [u8]) -> Result<Self, String> {
        // DC42 images carry a magic value at bytes 82–83.  Strip the header so
        // the rest of the parser sees a plain sector dump.
        let img = if img.get(82..84) == Some(&[0x01, 0x00]) {
            const DC42_HEADER: usize = 84;
            let data_size = img
                .get(64..68)
                .ok_or("DC42 image too small to read data_size field")
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)?;
            img.get(DC42_HEADER..DC42_HEADER + data_size)
                .ok_or("DC42 image truncated: sector data extends past end of file")?
        } else {
            img
        };

        let mdb = img
            .get(1024..1024 + 162)
            .ok_or("Image too small to contain MDB")?;

        let sig = u16::from_be_bytes([mdb[0], mdb[1]]);
        if sig != 0xD2D7 && sig != 0x4244 {
            if sig == 0x482B {
                return Err("Image is HFS+, not HFS — only classic HFS is supported".to_string());
            }
            return Err(format!("Not an HFS volume (MDB signature {sig:#06x})"));
        }

        let block_size = u32::from_be_bytes([mdb[20], mdb[21], mdb[22], mdb[23]]);
        if block_size == 0 {
            return Err("HFS block size is zero".to_string());
        }
        let first_alloc_sector = u32::from(u16::from_be_bytes([mdb[28], mdb[29]]));

        let vn_len = mdb[36] as usize;
        let volume_name: String = mdb
            .get(37..37 + vn_len)
            .unwrap_or(&[])
            .iter()
            .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '_' })
            .collect();

        // MDB offsets per Inside Macintosh: Files:
        //   130  drXTFlSize  extents overflow B-tree logical size
        //   134  drXTExtRec  extents overflow B-tree extent record
        //   146  drCTFlSize  catalog B-tree logical size
        //   150  drCTExtRec  catalog B-tree extent record
        let ext_logical = u32::from_be_bytes([mdb[130], mdb[131], mdb[132], mdb[133]]);
        let ext_extents = read_extent_record(mdb, 134);
        let cat_logical = u32::from_be_bytes([mdb[146], mdb[147], mdb[148], mdb[149]]);
        let cat_extents = read_extent_record(mdb, 150);

        let mut vol = HfsVolume {
            img,
            block_size,
            first_alloc_sector,
            volume_name,
            files: Vec::new(),
            dirs: Vec::new(),
        };

        let ext_data = vol.read_raw(&[ext_extents], ext_logical)?;
        let overflow = ExtentsOverflow::parse(&ext_data);

        let cat_data = vol.read_raw(&[cat_extents], cat_logical)?;
        vol.parse_catalog(&cat_data, &overflow)?;

        Ok(vol)
    }

    /// Read the data fork of a file entry.
    #[allow(clippy::missing_errors_doc)]
    pub fn read_data_fork(&self, entry: &HfsFileEntry) -> Result<Vec<u8>, String> {
        self.read_raw(&entry.data_extents, entry.data_logical)
    }

    /// Read the resource fork of a file entry.  Returns an empty `Vec` when
    /// the resource fork is absent or zero-length.
    #[allow(clippy::missing_errors_doc)]
    pub fn read_rsrc_fork(&self, entry: &HfsFileEntry) -> Result<Vec<u8>, String> {
        self.read_raw(&entry.rsrc_extents, entry.rsrc_logical)
    }

    const fn byte_offset_of_block(&self, block: u32) -> usize {
        self.first_alloc_sector as usize * 512 + block as usize * self.block_size as usize
    }

    fn read_raw(&self, extents: &[Extents], logical_size: u32) -> Result<Vec<u8>, String> {
        if logical_size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(logical_size as usize);
        'outer: for ext_set in extents {
            for &(start_block, block_count) in ext_set {
                if block_count == 0 {
                    break 'outer;
                }
                let byte_off = self.byte_offset_of_block(u32::from(start_block));
                let byte_len = block_count as usize * self.block_size as usize;
                let end = byte_off + byte_len;
                let chunk = self.img.get(byte_off..end).ok_or_else(|| {
                    format!(
                        "Extent [{start_block}+{block_count}] is out of bounds \
                         (bytes {byte_off}..{end}, image is {} bytes)",
                        self.img.len()
                    )
                })?;
                out.extend_from_slice(chunk);
                if out.len() >= logical_size as usize {
                    break 'outer;
                }
            }
        }
        out.truncate(logical_size as usize);
        Ok(out)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_catalog(&mut self, cat_data: &[u8], overflow: &ExtentsOverflow) -> Result<(), String> {
        if cat_data.len() < 512 {
            return Err("Catalog B-tree is too small to be valid".to_string());
        }

        // Node 0 is the header node; the root node index lives at header+2.
        let root_node = u32::from_be_bytes(
            cat_data[16..20]
                .try_into()
                .map_err(|_| "Catalog header too small")?,
        );

        let mut cnid_to_name: HashMap<u32, String> = HashMap::new();
        let mut cnid_to_parent: HashMap<u32, u32> = HashMap::new();
        // CNID 2 is the volume root; give it an empty name so it drops out of paths.
        cnid_to_name.insert(1, String::new());
        cnid_to_name.insert(2, String::new());
        cnid_to_parent.insert(2, 1);

        let mut raw_files: Vec<RawFile> = Vec::new();

        let node_size = 512usize;
        let mut stack: Vec<u32> = vec![root_node];
        let mut visited: HashSet<u32> = HashSet::new();

        while let Some(node_idx) = stack.pop() {
            if node_idx == 0 || !visited.insert(node_idx) {
                continue;
            }
            let node_off = node_idx as usize * node_size;
            let Some(node) = cat_data.get(node_off..node_off + node_size) else {
                continue;
            };

            let node_kind = node[8];
            let num_records = u16::from_be_bytes([node[10], node[11]]) as usize;

            // Record offsets are packed at the node tail, last record first
            // (record 0's offset is at byte 510).
            for i in 0..num_records {
                let ptr_off = node_size - 2 * (i + 1);
                let Some(ptr_bytes) = node.get(ptr_off..ptr_off + 2) else {
                    continue;
                };
                let rec_off = u16::from_be_bytes([ptr_bytes[0], ptr_bytes[1]]) as usize;
                let Some(rec) = node.get(rec_off..) else {
                    continue;
                };

                let key_len = rec[0] as usize;
                if key_len < 6 || rec.len() < 1 + key_len {
                    continue;
                }
                let parent_cnid = u32::from_be_bytes([rec[2], rec[3], rec[4], rec[5]]);
                let name_len = rec[6] as usize;
                let name_bytes = rec.get(7..7 + name_len).unwrap_or(&[]);

                // Pass through printable ASCII; replace other MacRoman bytes with '_'.
                let name: String = name_bytes
                    .iter()
                    .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '_' })
                    .collect();

                // HFS catalog keys have an odd key_len (37), so no padding byte is
                // needed.  We apply the general rule anyway for correctness.
                let data_off = 1 + key_len + usize::from(key_len.is_multiple_of(2));

                match node_kind {
                    0xFF => {
                        let Some(rec_data) = rec.get(data_off..) else {
                            continue;
                        };
                        if rec_data.len() < 2 {
                            continue;
                        }
                        // Record type is stored little-endian.
                        let rec_type = i16::from_le_bytes([rec_data[0], rec_data[1]]);
                        match rec_type {
                            1 => {
                                // Directory record; CNID at offset 6.
                                if rec_data.len() < 10 {
                                    continue;
                                }
                                let cnid = u32::from_be_bytes(
                                    rec_data[6..10].try_into().unwrap(),
                                );
                                cnid_to_name.insert(cnid, name);
                                cnid_to_parent.insert(cnid, parent_cnid);
                            }

                            2 => {
                                // File record.  Field offsets per Inside Macintosh: Files:
                                //   4   FInfo (type+creator)   20  CNID
                                //  26   data logical len       36  rsrc logical len
                                //  74   data extents           86  rsrc extents
                                if rec_data.len() < 98 {
                                    continue;
                                }
                                let file_type: [u8; 4] = rec_data[4..8].try_into().unwrap();
                                let creator: [u8; 4]   = rec_data[8..12].try_into().unwrap();
                                let cnid = u32::from_be_bytes(rec_data[20..24].try_into().unwrap());
                                let data_logical = u32::from_be_bytes(rec_data[26..30].try_into().unwrap());
                                let rsrc_logical = u32::from_be_bytes(rec_data[36..40].try_into().unwrap());
                                let data_ext = read_extent_record(rec_data, 74);
                                let rsrc_ext = read_extent_record(rec_data, 86);

                                cnid_to_name.insert(cnid, name);
                                cnid_to_parent.insert(cnid, parent_cnid);
                                raw_files.push(RawFile {
                                    cnid,
                                    parent_cnid,
                                    file_type,
                                    creator,
                                    data_logical,
                                    data_ext,
                                    rsrc_logical,
                                    rsrc_ext,
                                });
                            }

                            _ => {}
                        }
                    }

                    0x00 => {
                        // Index node — payload is a 4-byte child node index.
                        let Some(ptr_data) = rec.get(data_off..data_off + 4) else {
                            continue;
                        };
                        let child = u32::from_be_bytes(ptr_data.try_into().unwrap());
                        stack.push(child);
                    }

                    _ => {}
                }
            }

            // Follow fLink to catch sibling nodes not reachable via an index record.
            if node_kind == 0x00 || node_kind == 0xFF {
                let flink = u32::from_be_bytes([node[0], node[1], node[2], node[3]]);
                if flink != 0 {
                    stack.push(flink);
                }
            }
        }

        let build_path = |cnid: u32| -> PathBuf {
            let mut parts: Vec<String> = Vec::new();
            let mut cur = cnid;
            for _ in 0..64 {
                let Some(&parent) = cnid_to_parent.get(&cur) else {
                    break;
                };
                if parent <= 2 {
                    if cur != 2
                        && let Some(n) = cnid_to_name.get(&cur)
                        && !n.is_empty()
                    {
                        parts.push(n.clone());
                    }
                    break;
                }
                if let Some(n) = cnid_to_name.get(&cur)
                    && !n.is_empty()
                {
                    parts.push(n.clone());
                }
                cur = parent;
            }
            parts.reverse();
            parts.iter().collect()
        };

        for &cnid in cnid_to_name.keys() {
            if cnid <= 2 {
                continue;
            }
            if cnid_to_parent.values().any(|&p| p == cnid) {
                let rel = build_path(cnid);
                if !rel.as_os_str().is_empty() {
                    self.dirs.push(HfsDirEntry { rel_path: rel });
                }
            }
        }

        for rf in raw_files {
            let rel = build_path(rf.cnid);
            if rel.as_os_str().is_empty() {
                continue;
            }
            let data_extents = overflow.get_extents(
                rf.cnid, 0x00, &rf.data_ext, rf.data_logical, self.block_size,
            );
            let rsrc_extents = overflow.get_extents(
                rf.cnid, 0xFF, &rf.rsrc_ext, rf.rsrc_logical, self.block_size,
            );
            self.files.push(HfsFileEntry {
                rel_path: rel,
                parent_cnid: rf.parent_cnid,
                file_type: rf.file_type,
                creator: rf.creator,
                data_logical: rf.data_logical,
                data_extents,
                rsrc_logical: rf.rsrc_logical,
                rsrc_extents,
            });
        }

        Ok(())
    }
}

struct ExtentsOverflow {
    entries: HashMap<(u32, u8, u32), Extents>,
}

impl ExtentsOverflow {
    fn parse(data: &[u8]) -> Self {
        let mut entries = HashMap::new();
        let node_size = 512usize;
        if data.len() < node_size {
            return Self { entries };
        }

        // First leaf node index is at header record offset 10 (bytes 24..28 of node 0).
        let first_leaf =
            u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        let mut node_idx = first_leaf;
        let mut visited: HashSet<u32> = HashSet::new();

        while node_idx != 0 && visited.insert(node_idx) {
            let off = node_idx as usize * node_size;
            let Some(node) = data.get(off..off + node_size) else {
                break;
            };
            let flink = u32::from_be_bytes([node[0], node[1], node[2], node[3]]);
            let num_records = u16::from_be_bytes([node[10], node[11]]) as usize;

            for i in 0..num_records {
                let ptr_off = node_size - 2 * (i + 1);
                let Some(ptr_bytes) = node.get(ptr_off..ptr_off + 2) else {
                    continue;
                };
                let rec_off = u16::from_be_bytes([ptr_bytes[0], ptr_bytes[1]]) as usize;
                let Some(rec) = node.get(rec_off..) else {
                    continue;
                };

                let key_len = rec[0] as usize;
                if key_len < 7 || rec.len() < 1 + key_len + 12 {
                    continue;
                }
                let fork_type   = rec[1];
                let cnid        = u32::from_be_bytes([rec[2], rec[3], rec[4], rec[5]]);
                let start_block = u32::from(u16::from_be_bytes([rec[6], rec[7]]));

                let data_off = 1 + key_len + usize::from(key_len.is_multiple_of(2));
                let Some(ext_data) = rec.get(data_off..data_off + 12) else {
                    continue;
                };
                entries.insert(
                    (cnid, fork_type, start_block),
                    read_extent_record(ext_data, 0),
                );
            }

            node_idx = flink;
        }

        Self { entries }
    }

    fn get_extents(
        &self,
        cnid: u32,
        fork_type: u8,
        catalog_ext: &Extents,
        logical_size: u32,
        block_size: u32,
    ) -> Vec<Extents> {
        let mut result = vec![*catalog_ext];
        if block_size == 0 {
            return result;
        }

        let catalog_blocks: u32 = catalog_ext.iter().map(|e| u32::from(e.1)).sum();
        let blocks_needed = logical_size.div_ceil(block_size);
        if catalog_blocks >= blocks_needed {
            return result;
        }

        // Each overflow record is keyed by the block where the previous set ended.
        let mut covered = catalog_blocks;
        while let Some(&ext) = self.entries.get(&(cnid, fork_type, covered)) {
            result.push(ext);
            let added: u32 = ext.iter().map(|e| u32::from(e.1)).sum();
            if added == 0 {
                break;
            }
            covered += added;
            if covered >= blocks_needed {
                break;
            }
        }
        result
    }
}

/// Read three HFS extent descriptors from `data` at `offset`.
/// Each descriptor is two big-endian u16 values: (first_alloc_block, block_count).
fn read_extent_record(data: &[u8], offset: usize) -> Extents {
    let mut e = [(0u16, 0u16); 3];
    for (i, slot) in e.iter_mut().enumerate() {
        let o = offset + i * 4;
        if o + 4 <= data.len() {
            *slot = (
                u16::from_be_bytes([data[o], data[o + 1]]),
                u16::from_be_bytes([data[o + 2], data[o + 3]]),
            );
        }
    }
    e
}

/// Sanitise a path so it can be safely joined onto a host filesystem path.
/// Strips `.`, `..`, and empty components.
#[must_use]
pub fn sanitise_path(raw: &Path) -> PathBuf {
    use std::path::Component::Normal;
    raw.components()
        .filter(|c| matches!(c, Normal(_)))
        .collect()
}
