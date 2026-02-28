use crate::afp::Volume;
use crate::asp::{Asp, AspCommandResponse, AspHandle, AspSession};
use crate::ddp::DdpHandle;
use crate::nbp::NbpHandle;
use std::path::PathBuf;
use std::sync::Arc;
use tailtalk_packets::afp::{
    AfpError, AfpUam, AfpVersion, CreateFlag, FPByteRangeLock, FPCloseFork, FPDelete,
    FPDirectoryBitmap, FPEnumerate, FPFileBitmap, FPFlush, FPGetSrvrInfo, FPGetSrvrParms,
    FPGetVolParms, FPRead, FPSetDirParms, FPSetForkParms, FPVolumeBitmap, ForkType, MacString,
};
use tailtalk_packets::nbp::EntityName;
use tracing::{error, info, warn};

/// AFP Server configuration
pub struct AfpServerConfig {
    pub server_name: String,
    pub machine_type: String,
    pub afp_versions: Vec<AfpVersion>,
    pub uams: Vec<AfpUam>,
    pub volume_icon: Option<[u8; 256]>,
    pub flags: u16,
    pub volume_path: PathBuf,
}

impl Default for AfpServerConfig {
    fn default() -> Self {
        // Default volume icon (same as example)
        let volume_icon = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x9f, 0xe0, 0x0,
            0x4, 0x50, 0x30, 0x0, 0x8, 0x30, 0x28, 0x0, 0x10, 0x10, 0x3c, 0x7, 0xa0, 0x8, 0x4,
            0x18, 0x7f, 0x4, 0x4, 0x10, 0x0, 0x82, 0x4, 0x10, 0x0, 0x81, 0x4, 0x10, 0x0, 0x82, 0x4,
            0x10, 0x0, 0x84, 0x4, 0x10, 0x0, 0x88, 0x4, 0x10, 0x0, 0x90, 0x4, 0x10, 0x0, 0xb0, 0x4,
            0x10, 0x0, 0xd0, 0x4, 0xff, 0xff, 0xff, 0xff, 0x40, 0x0, 0x0, 0x2, 0x3f, 0xff, 0xff,
            0xfc, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x5, 0x0,
            0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0x8, 0x80, 0x0, 0x0, 0x8, 0x80, 0x0, 0x0, 0xf, 0x80,
            0x0, 0x0, 0xa, 0x80, 0xbf, 0xff, 0xf2, 0x74, 0x0, 0x0, 0x5, 0x0, 0xbf, 0xff, 0xf8,
            0xf4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3, 0x9f, 0xe0,
            0x0, 0x7, 0xdf, 0xf0, 0x0, 0xf, 0xff, 0xf8, 0x0, 0x1f, 0xff, 0xfc, 0x7, 0xbf, 0xff,
            0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f,
            0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff,
            0xfc, 0x1f, 0xff, 0xff, 0xfc, 0x1f, 0xff, 0xff, 0xfc, 0xff, 0xff, 0xff, 0xff, 0x7f,
            0xff, 0xff, 0xfe, 0x3f, 0xff, 0xff, 0xfc, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0,
            0x0, 0x7, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0,
            0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0x0, 0x0, 0xf, 0x80, 0xbf, 0xff, 0xff, 0xf4, 0xbf,
            0xff, 0xfd, 0xf4, 0xbf, 0xff, 0xf8, 0xf4,
        ];

        Self {
            server_name: "TailTalk AFP".to_string(),
            machine_type: "Unix".to_string(),
            afp_versions: vec![
                AfpVersion::Version1,
                AfpVersion::Version1_1,
                AfpVersion::Version2,
            ],
            uams: vec![AfpUam::NoUserAuthent],
            volume_icon: Some(volume_icon),
            flags: 0x800b,
            volume_path: PathBuf::from("./"),
        }
    }
}

/// AFP Server
pub struct AfpServer {
    asp_handle: AspHandle,
    config: Arc<AfpServerConfig>,
}

impl AfpServer {
    /// Spawn a new AFP server
    pub async fn spawn(
        ddp: &DdpHandle,
        nbp: &NbpHandle,
        socket: Option<u8>,
        config: AfpServerConfig,
    ) -> anyhow::Result<Self> {
        let config = Arc::new(config);

        // Create server status information
        let status = FPGetSrvrInfo {
            machine_type: config.machine_type.clone().into(),
            afp_versions: config.afp_versions.clone(),
            uams: config.uams.clone(),
            volume_icon: config.volume_icon,
            flags: config.flags,
            server_name: config.server_name.clone().into(),
        };

        let status_data = status
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize AFP status: {:?}", e))?;

        // Create NBP entity name
        let entity_name = EntityName {
            object: config.server_name.clone(),
            entity_type: "AFPServer".to_string(),
            zone: "*".to_string(),
        };

        // Bind ASP service
        let asp_handle = Asp::bind(ddp, nbp, socket, entity_name, status_data).await?;

        info!("AFP server '{}' started", config.server_name);

        let server = Self { asp_handle, config };

        // Spawn session handler
        let server_clone_config = server.config.clone();
        let server_clone_handle = server.asp_handle.clone();
        tokio::spawn(async move {
            run_server(server_clone_handle, server_clone_config).await;
        });

        Ok(server)
    }
}

/// Run the AFP server session loop
async fn run_server(asp_handle: AspHandle, config: Arc<AfpServerConfig>) {
    info!(
        "AFP server '{}' waiting for sessions...",
        config.server_name
    );

    let mut session_count = 0;

    loop {
        match asp_handle.get_session().await {
            Ok(session) => {
                session_count += 1;
                info!(
                    "AFP session {} accepted from {:?}",
                    session_count, session.remote_addr
                );

                // Spawn handler for this session
                let session_config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = session.handle_session(session_config).await {
                        error!("Session error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept AFP session: {}", e);
                break;
            }
        }
    }
}

impl AspSession {
    /// Handle an AFP session
    async fn handle_session(mut self, config: Arc<AfpServerConfig>) -> anyhow::Result<()> {
        info!("Session {} handler started", self.id);

        let mut our_volume = Volume::new(
            "TailDrive".to_string(),
            config.volume_path.clone(),
            1,    // TODO: How should these IDs be created?
            true, // Default to AFP 2.x epoch; updated after FPLogin
        )
        .await;

        loop {
            // Get command from client
            let command = match self.get_command().await {
                Some(cmd) => cmd,
                None => {
                    info!("Session {} closed", self.id);
                    break;
                }
            };

            if command.data.is_empty() {
                warn!("Session {} received empty command", self.id);
                command.send_reply(create_error_reply(AfpError::ParamError))?;
                continue;
            }

            // Parse AFP command code (first byte)
            let cmd_code = command.data[0];
            info!("Session {} received command code: {}", self.id, cmd_code);

            // Handle commands
            match cmd_code {
                tailtalk_packets::afp::AFP_CMD_BYTE_RANGE_LOCK => {
                    self.handle_byte_range_lock(command, &mut our_volume)
                        .await?;
                }
                tailtalk_packets::afp::AFP_CMD_LOGIN => {
                    let data = command.data[1..].to_vec();
                    if let Some(version) = self.handle_login(&data, command)? {
                        // Update the volume's epoch to match the negotiated AFP version.
                        // AFP 2.x uses Jan 1 2000; AFP 1.x uses Jan 1 1904.
                        let afp_v2 =
                            matches!(version, AfpVersion::Version2 | AfpVersion::Version2_1);
                        our_volume.set_afp_v2(afp_v2);
                    }
                }
                tailtalk_packets::afp::AFP_CMD_GET_SRVR_PARMS => {
                    let vol_response = FPGetSrvrParms {
                        server_time: crate::time_to_afp(std::time::SystemTime::now()),
                        volumes: vec![our_volume.get_fp_volume()],
                    };
                    let mut output_buf = [0u8; 128];
                    let offset = vol_response.to_bytes(&mut output_buf).map_err(|e| {
                        anyhow::anyhow!("Failed to serialize AFP GetSrvrParms: {:?}", e)
                    })?;
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_CLOSE_VOL => {
                    // TODO: Implement proper volume opening / closing checks
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: vec![],
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_OPEN_VOL => {
                    let bitmap_req = FPVolumeBitmap::from(u16::from_be_bytes(
                        command.data[2..=3].try_into().unwrap(),
                    ));
                    let mut output_buf = [0u8; 128];
                    let offset = our_volume
                        .get_bitmap_resp(bitmap_req, &mut output_buf)
                        .map_err(|e| {
                            anyhow::anyhow!("insufficient buffer size for AFP OpenVol: {:?}", e)
                        })?;
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_VOL_PARMS => {
                    let vol_parms_req = FPGetVolParms::parse(&command.data[2..]).unwrap();
                    let mut output_buf = [0u8; 128];
                    let offset = our_volume
                        .get_bitmap_resp(vol_parms_req.bitmap, &mut output_buf)
                        .map_err(|e| {
                            anyhow::anyhow!("insufficient buffer size for AFP GetVolParms: {:?}", e)
                        })?;
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_READ => {
                    self.handle_read(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_FILE_DIR_PARMS => {
                    self.handle_get_file_dir_parms(command, &our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_SET_FILE_DIR_PARMS => {
                    self.handle_set_file_dir_parms(command, &mut our_volume)
                        .await?;
                }
                tailtalk_packets::afp::AFP_CMD_SET_DIR_PARMS => {
                    self.handle_set_dir_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_CREATE_DIR => {
                    self.handle_create_dir(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_CREATE_FILE => {
                    self.handle_create_file(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_DELETE => {
                    self.handle_delete(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_ENUMERATE => {
                    self.handle_enumerate(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_SRVR_MSG => {
                    // FPGetSrvrMsg - Return an empty server message
                    // Response format:
                    // Bytes 0-1: MessageType (0 = no message)
                    // Bytes 2-3: MessageBitmap (0 = no flags set)
                    // Bytes 4+: Message string (empty Pascal string = just length byte 0)
                    let response = vec![0, 0, 0, 1, 6, b'H', b'e', b'l', b'l', b'o', b'!'];
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: response,
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_OPEN_FORK => {
                    self.handle_open_fork(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_CLOSE_FORK => {
                    self.handle_close_fork(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_FORK_PARMS => {
                    self.handle_get_fork_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_SET_FORK_PARMS => {
                    self.handle_set_fork_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_FLUSH => {
                    self.handle_flush(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_OPEN_DT => match our_volume.open_dt().await {
                    Ok(ref_num) => {
                        command.send_reply(AspCommandResponse {
                            result: [0u8; 4],
                            data: ref_num.to_be_bytes().to_vec(),
                        })?;
                    }
                    Err(e) => {
                        command.send_reply(AspCommandResponse {
                            result: (e as u32).to_be_bytes(),
                            data: Vec::new(),
                        })?;
                    }
                },
                tailtalk_packets::afp::AFP_CMD_GET_ICON => {
                    self.handle_get_icon(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_ADD_ICON => {
                    self.handle_add_icon(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GTICNINFO => {
                    self.handle_get_icon_info(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_COMMENT => {
                    self.handle_get_comment(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_WRITE => {
                    self.handle_write(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_REMOVE_COMMENT => {
                    self.handle_remove_comment(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_ADD_COMMENT => {
                    self.handle_add_comment(command, &mut our_volume).await?;
                }
                _ => {
                    warn!("Session {} unsupported command: {}", self.id, cmd_code);
                    // Return error: command not supported
                    command.send_reply(create_error_reply(AfpError::BadVersNum))?;
                }
            }
        }

        Ok(())
    }

    async fn handle_byte_range_lock(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let lock_req = FPByteRangeLock::parse(&command.data[1..]).unwrap();

        tracing::info!("Session {} byte range lock: {:?}", self.id, lock_req);

        match our_volume.byte_range_lock(&lock_req).await {
            Ok(first_byte) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: first_byte.to_be_bytes().to_vec(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_create_dir(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let _volume_id = u16::from_be_bytes(command.data[2..=3].try_into().unwrap());
        let directory_id = u32::from_be_bytes(command.data[4..=7].try_into().unwrap());
        let _path_type = command.data[8];
        let path_name = MacString::try_from(&command.data[9..]).unwrap();

        let dir_id = our_volume
            .create_dir(directory_id, PathBuf::from(path_name.to_string()))
            .await
            .map_err(|e| anyhow::anyhow!("CreateDir failed: {:?}", e))?;

        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: dir_id.to_be_bytes().to_vec(),
        })?;

        Ok(())
    }

    async fn handle_create_file(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        // Note to future readers - This does not match Inside AppleTalk's format and I dont know why.
        // The book has the order as RefNum, Volume ID, Directory ID and Create Flag but the actual order
        // I see from my client is as below.
        let create_flag = CreateFlag::from(command.data[1]);
        let _volume_id = u16::from_be_bytes(command.data[2..=3].try_into().unwrap());
        let directory_id = u32::from_be_bytes(command.data[4..=7].try_into().unwrap());
        let _path_type = command.data[8];
        let path_name = MacString::try_from(&command.data[9..]).unwrap();

        match our_volume
            .create_file(
                create_flag,
                directory_id,
                PathBuf::from(path_name.to_string()),
            )
            .await
        {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_delete(
        &mut self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let delete_req = FPDelete::parse(&command.data[2..]).unwrap();
        match our_volume.delete(&delete_req).await {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }
        Ok(())
    }

    /// Handle AFP_CMD_GET_FILE_DIR_PARMS
    async fn handle_get_file_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &Volume,
    ) -> anyhow::Result<()> {
        let _volume_id = u16::from_be_bytes(command.data[2..=3].try_into().unwrap());
        let directory_id = u32::from_be_bytes(command.data[4..=7].try_into().unwrap());
        let file_bitmap =
            FPFileBitmap::from(u16::from_be_bytes(command.data[8..=9].try_into().unwrap()));
        let dir_bitmap = FPDirectoryBitmap::from(u16::from_be_bytes(
            command.data[10..=11].try_into().unwrap(),
        ));
        let _path_type = command.data[12];
        let path_name = MacString::try_from(&command.data[13..]).unwrap_or_default();

        let path_name_buf = PathBuf::from(path_name.to_string());

        let node_id = match our_volume.resolve_node(directory_id, &path_name_buf) {
            Ok(node_id) => node_id,
            Err(e) => {
                tracing::error!("look up for {:?} failed: {:?}", path_name_buf, e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
                return Ok(());
            }
        };

        let mut output_buf = [0u8; 1024];
        let (is_dir, bytes_written) = match our_volume
            .get_node_parms(node_id, file_bitmap, dir_bitmap, &mut output_buf[6..])
            .await
        {
            Ok((is_dir, bytes_written)) => (is_dir, bytes_written),
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
                return Ok(());
            }
        };

        // Fill in fixed header
        output_buf[0..=1].copy_from_slice(&file_bitmap.bits().to_be_bytes());
        output_buf[2..=3].copy_from_slice(&dir_bitmap.bits().to_be_bytes());
        output_buf[4] = if is_dir { 1 << 7 } else { 0 };
        output_buf[5] = 0; // Padding

        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: output_buf[..6 + bytes_written].to_vec(),
        })?;

        Ok(())
    }

    async fn handle_set_file_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let directory_id = u32::from_be_bytes(command.data[4..=7].try_into().unwrap());
        let dir_bitmap =
            FPDirectoryBitmap::from(u16::from_be_bytes(command.data[8..=9].try_into().unwrap()));
        let _path_type = command.data[10];
        let path_name = MacString::try_from(&command.data[11..]).unwrap_or_default();

        let path_name_buf = PathBuf::from(path_name.to_string());

        // Parameters start after path name
        let mut param_offset = 11 + path_name.byte_len();
        if param_offset % 2 != 0 {
            param_offset += 1;
        }

        let node_id = match our_volume.resolve_node(directory_id, &path_name_buf) {
            Ok(node_id) => node_id,
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
                return Ok(());
            }
        };

        match our_volume.set_node_parms(node_id, dir_bitmap, &command.data[param_offset..]) {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        };

        Ok(())
    }

    async fn handle_set_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        _our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let dir_cmd = FPSetDirParms::parse(&command.data[2..]).unwrap();

        tracing::warn!("STUB: FPSetDirParms: {:?}", dir_cmd);

        /*our_volume
        .set_dir_parms(dir_cmd.directory_id, dir_cmd.dir_bitmap)
        .await?;*/

        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: Vec::new(),
        })?;

        Ok(())
    }

    async fn handle_flush(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let _flush_cmd = FPFlush::parse(&command.data[2..]).unwrap();

        let _ = our_volume.sync().await;

        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: Vec::new(),
        })?;

        Ok(())
    }

    async fn handle_read(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let read_cmd = FPRead::parse(&command.data[2..]).unwrap();

        tracing::info!("Handling read command: {read_cmd:?}");

        let mut output_buf = [0u8; 4096];

        match our_volume.read(&read_cmd, &mut output_buf).await {
            Ok((bytes_read, is_eof)) => {
                tracing::info!("Returning {bytes_read} bytes");
                let mut result_code = [0u8; 4];
                if is_eof && read_cmd.req_count > 0 {
                    // Sign-extend the i16 AFP error to u32 before getting bytes
                    result_code = (AfpError::EoFErr as i16 as i32 as u32).to_be_bytes();
                }

                command.send_reply(AspCommandResponse {
                    result: result_code,
                    data: output_buf[..bytes_read].to_vec(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_write(
        &mut self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        // Parse FPWrite command from SPCommand payload
        let write_cmd = match tailtalk_packets::afp::FPWrite::parse(&command.data[2..]) {
            Ok(cmd) => cmd,
            Err(_) => {
                command.send_reply(create_error_reply(AfpError::ParamError))?;
                return Ok(());
            }
        };

        tracing::info!("Session {} FPWrite: {:?}", self.id, write_cmd);

        // Perform SPWrite transaction to get the data
        // We ask for the amount the client wants to write
        let data = match self
            .write(write_cmd.req_count as usize, command.sequence_number)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("SPWrite failed: {:?}", e);
                // If the pull failed, we can't really do much but fail the command
                command.send_reply(create_error_reply(AfpError::MiscErr))?;
                return Ok(());
            }
        };

        // Write data to fork
        match our_volume
            .write_fork(write_cmd.fork_id, write_cmd.offset as u64, &data)
            .await
        {
            Ok(bytes_written) => {
                // Respond with offset + actual bytes written (the offset of the last byte written)
                let last_byte_offset = write_cmd.offset + bytes_written as u32;
                let mut reply_data = [0u8; 4];
                reply_data.copy_from_slice(&last_byte_offset.to_be_bytes());

                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: reply_data.to_vec(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_open_fork(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let _volume_id = u16::from_be_bytes(command.data[2..=3].try_into().unwrap());
        let directory_id = u32::from_be_bytes(command.data[4..=7].try_into().unwrap());
        let file_bitmap =
            FPFileBitmap::from(u16::from_be_bytes(command.data[8..=9].try_into().unwrap()));
        let _access_mode = u16::from_be_bytes(command.data[10..=11].try_into().unwrap());
        let _path_type = command.data[12];
        let path_name = MacString::try_from(&command.data[13..]).unwrap_or_default();

        let path_name_buf = PathBuf::from(path_name.to_string());

        let mut output_buf = [0u8; 256];

        match our_volume
            .open_fork(
                ForkType::Data, // We only support data fork
                file_bitmap,
                directory_id,
                &path_name_buf,
                &mut output_buf,
            )
            .await
        {
            Ok(offset) => Ok(command.send_reply(AspCommandResponse {
                result: [0u8; 4],
                data: output_buf[..offset].to_vec(),
            })?),
            Err(e) => Ok(command.send_reply(AspCommandResponse {
                result: (e as u32).to_be_bytes(),
                data: Vec::new(),
            })?),
        }
    }

    async fn handle_close_fork(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let fork_cmd = FPCloseFork::parse(&command.data[2..]).unwrap();

        match our_volume.close_fork(fork_cmd.fork_id).await {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_set_fork_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let fork_cmd = FPSetForkParms::parse(&command.data[2..]).unwrap();

        match our_volume.set_fork_parms(fork_cmd).await {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_get_fork_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let fork_id = u16::from_be_bytes(command.data[2..=3].try_into().unwrap());
        let file_bitmap =
            FPFileBitmap::from(u16::from_be_bytes(command.data[4..=5].try_into().unwrap()));

        let mut output_buf = [0u8; 256];

        output_buf[..2].copy_from_slice(&file_bitmap.bits().to_be_bytes());
        match our_volume
            .get_fork_parms(file_bitmap, fork_id, &mut output_buf[2..])
            .await
        {
            Ok(offset) => Ok(command.send_reply(AspCommandResponse {
                result: [0u8; 4],
                data: output_buf[..offset + 2].to_vec(),
            })?),
            Err(e) => Ok(command.send_reply(AspCommandResponse {
                result: (e as u32).to_be_bytes(),
                data: Vec::new(),
            })?),
        }
    }

    async fn handle_enumerate(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let enumerate = FPEnumerate::parse(&command.data[2..]).unwrap();

        let mut output_buf = [0u8; 5000];
        output_buf[..2].copy_from_slice(&enumerate.file_bitmap.bits().to_be_bytes());
        output_buf[2..4].copy_from_slice(&enumerate.directory_bitmap.bits().to_be_bytes());

        let start_offset = 4;

        match our_volume
            .enumerate(enumerate, &mut output_buf[start_offset..])
            .await
        {
            Ok(offset) => Ok(command.send_reply(AspCommandResponse {
                result: [0u8; 4],
                data: output_buf[..offset + start_offset].to_vec(),
            })?),
            Err(e) => Ok(command.send_reply(AspCommandResponse {
                result: (e as u32).to_be_bytes(),
                data: Vec::new(),
            })?),
        }
    }

    /// Handle FPLogin command
    fn handle_login(
        &self,
        data: &[u8],
        command: crate::asp::AspCommand,
    ) -> anyhow::Result<Option<AfpVersion>> {
        match tailtalk_packets::afp::FPLogin::parse(data) {
            Ok(login) => {
                info!(
                    "Session {} FPLogin: version={:?}",
                    self.id, login.afp_version
                );

                let negotiated = login.afp_version.clone();

                match login.auth {
                    tailtalk_packets::afp::FPLoginAuth::NoUserAuthent => {
                        info!("Session {} login: No User Authentication", self.id);
                        // Success: cmdResult=0, sessRefnum=session_id
                        let reply = create_login_success_reply(self.id as i16);
                        command.send_reply(reply)?;
                        info!("Session {} login accepted", self.id);
                    }
                    tailtalk_packets::afp::FPLoginAuth::CleartxtPasswrd {
                        ref username, ..
                    } => {
                        info!(
                            "Session {} login: Clear Text Password, user={}",
                            self.id, username
                        );
                        // For demo purposes, accept any password
                        let reply = create_login_success_reply(self.id as i16);
                        command.send_reply(reply)?;
                        info!("Session {} login accepted", self.id);
                    }
                }

                Ok(Some(negotiated))
            }
            Err(e) => {
                warn!("Session {} FPLogin parse error: {:?}", self.id, e);
                command.send_reply(create_error_reply(e))?;
                Ok(None)
            }
        }
    }

    async fn handle_get_icon(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let get_icon = tailtalk_packets::afp::FPGetIcon::parse(&command.data[2..]).unwrap();

        match our_volume.get_icon(get_icon.dt_ref_num, &get_icon) {
            Ok(data) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data,
                })?;
            }
            Err(e) => {
                // AfpError is an i16 as per spec for results
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_get_icon_info(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let get_icon_info =
            tailtalk_packets::afp::FPGetIconInfo::parse(&command.data[2..]).unwrap();

        match our_volume.get_icon_info(get_icon_info.dt_ref_num, &get_icon_info) {
            Ok((icon_tag, file_type, size)) => {
                let mut output = [0u8; 10];
                output[0..4].copy_from_slice(&icon_tag.to_be_bytes());
                output[4..8].copy_from_slice(&file_type.to_be_bytes());
                output[8..10].copy_from_slice(&size.to_be_bytes());

                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: output.to_vec(),
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_add_icon(
        &mut self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let add_icon = tailtalk_packets::afp::FPAddIcon::parse(&command.data[2..]).unwrap();

        let data = match self
            .write(add_icon.size as usize, command.sequence_number)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("SPWrite failed for AddIcon: {:?}", e);
                command.send_reply(create_error_reply(AfpError::MiscErr))?;
                return Ok(());
            }
        };

        match our_volume.add_icon(add_icon.dt_ref_num, &add_icon, &data) {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_add_comment(
        &mut self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let add_comment = tailtalk_packets::afp::FPAddComment::parse(&command.data[2..]).unwrap();

        tracing::info!("Add Comment command: {:?}", add_comment);

        match our_volume.set_comment(
            add_comment.directory_id,
            &PathBuf::from(add_comment.path.as_str()),
            &add_comment.comment,
        ) {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_get_comment(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let get_comment = tailtalk_packets::afp::FPGetComment::parse(&command.data[2..]).unwrap();

        tracing::info!("Get Comment command: {:?}", get_comment);

        match our_volume.get_comment(
            get_comment.directory_id,
            &PathBuf::from(get_comment.path.as_str()),
        ) {
            Ok(comment) => {
                let mut data = vec![];
                // Comment is returned as a pascal string (1 byte length + data)
                // However, AFP specs say it returns just the string without pascal length. Let's return raw bytes.
                // Wait, Inside AppleTalk says: "The comment string is returned in the data buffer."
                // For safety we should check if we just return the raw string bytes.
                // Wait, it says "The String parameter is returned as a Pascal string." So we do need the length byte.
                data.push(comment.len() as u8);
                data.extend_from_slice(&comment);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data,
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_remove_comment(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let remove_comment =
            tailtalk_packets::afp::FPRemoveComment::parse(&command.data[2..]).unwrap();

        match our_volume.remove_comment(
            remove_comment.directory_id,
            &PathBuf::from(remove_comment.path.as_str()),
        ) {
            Ok(_) => {
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }
}

/// Create a successful login reply
fn create_login_success_reply(session_ref_num: i16) -> AspCommandResponse {
    AspCommandResponse {
        result: [0u8; 4],
        data: session_ref_num.to_be_bytes().to_vec(),
    }
}

/// Create an error reply
fn create_error_reply(error: AfpError) -> AspCommandResponse {
    // cmdResult = error code (4 bytes, big-endian, sign-extended from i16)
    let error_code = error as i16;
    AspCommandResponse {
        result: (error_code as i32).to_be_bytes(),
        data: vec![],
    }
}
