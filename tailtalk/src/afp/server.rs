use crate::afp::volume::afp_path_to_posix;
use crate::afp::Volume;
use encoding_rs::MACINTOSH;
use crate::asp::{Asp, AspCommandResponse, AspHandle, AspSession};
use crate::ddp::DdpHandle;
use crate::nbp::NbpHandle;
use crate::CancellationToken;
use std::path::PathBuf;
use std::sync::Arc;
use tailtalk_packets::afp::{
    AFP_CMD_COPY_FILE, AFP_CMD_LOGOUT, AFP_CMD_MOVE_AND_RENAME, AFP_CMD_RENAME, AfpError, AfpUam,
    AfpVersion, FPByteRangeLock, FPCloseFork, FPCopyFile, FPCreateDir, FPCreateFile, FPDelete,
    FPDirectoryBitmap, FPEnumerate, FPFileBitmap, FPFlush, FPGetDirParms, FPGetFileDirParms,
    FPGetFileParms, FPGetForkParms, FPGetSrvrInfo, FPGetSrvrParms, FPGetVolParms, FPMoveAndRename,
    FPOpenFork, FPRead, FPRename, FPSetDirParms, FPSetFileDirParms, FPSetFileParms, FPSetForkParms,
    FPVolumeBitmap, ForkType,
};
use tailtalk_packets::nbp::EntityName;
use tracing::{debug, error, info, warn};

/// Volume ID advertised to clients and echoed back on per-volume commands.
/// A single volume is served, so any stable non-zero value works.
const AFP_VOLUME_ID: u16 = 1234;

/// Parse a client-supplied AFP request at byte offset `$off`, or reply with
/// the parse error and return. Uses `.get()` instead of slicing so a
/// truncated packet is rejected by `parse` rather than panicking.
macro_rules! parse_or_reply {
    ($command:expr, $ty:ty, $off:expr) => {
        match <$ty>::parse($command.data.get($off..).unwrap_or(&[])) {
            Ok(v) => v,
            Err(e) => {
                debug!("AFP {} parse error: {:?}", stringify!($ty), e);
                $command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        }
    };
}

/// AFP Server configuration
pub struct AfpServerConfig {
    pub server_name: String,
    pub machine_type: String,
    pub afp_versions: Vec<AfpVersion>,
    pub uams: Vec<AfpUam>,
    pub volume_icon: Option<[u8; 256]>,
    pub flags: u16,
    pub volume_path: PathBuf,
    /// The volume name shown to AFP clients.
    pub volume_name: String,
}

impl Default for AfpServerConfig {
    fn default() -> Self {
        // Default volume icon taken from Mac OS 9
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
            server_name: "TailTalk".to_string(),
            machine_type: "Macintosh".to_string(),
            afp_versions: vec![AfpVersion::Version2, AfpVersion::Version2_1],
            uams: vec![AfpUam::NoUserAuthent],
            volume_icon: Some(volume_icon),
            flags: 0x3,
            volume_path: PathBuf::from("./"),
            volume_name: "MacShare".to_string(),
        }
    }
}

/// AFP Server
pub struct AfpServer {
    asp_handle: AspHandle,
    config: Arc<AfpServerConfig>,
    db: sled::Db,
    shutdown: CancellationToken,
}

impl AfpServer {
    /// Spawn a new AFP server.
    ///
    /// `shutdown` should be the token from [`TalkStack::token()`](crate::TalkStack::token)
    /// so the server stops when the stack shuts down.
    pub async fn spawn(
        ddp: &DdpHandle,
        nbp: &NbpHandle,
        socket: Option<u8>,
        config: AfpServerConfig,
        shutdown: CancellationToken,
        services_done: CancellationToken,
    ) -> anyhow::Result<()> {
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
        let asp_handle = Asp::bind(ddp, nbp, socket, entity_name, status_data, shutdown.clone(), services_done).await?;

        info!("AFP server '{}' started", config.server_name);

        // Open the desktop DB before spawning so failures surface as errors to the caller.
        // sled::Db is internally reference-counted so all clones share the same on-disk DB.
        let db = crate::afp::DesktopDatabase::open_or_create(&config.volume_path)
            .map_err(|e| anyhow::anyhow!("Failed to open desktop database: {e:?}"))?;

        tokio::spawn(Self { asp_handle, config, db, shutdown }.run());

        Ok(())
    }

    async fn run(self) {
        info!("AFP server '{}' waiting for sessions...", self.config.server_name);

        let mut session_count = 0;

        loop {
            let session = tokio::select! {
                _ = self.shutdown.cancelled() => break,
                result = self.asp_handle.get_session() => match result {
                    Ok(s) => s,
                    Err(e) => { error!("Failed to accept AFP session: {}", e); break; }
                },
            };

            session_count += 1;
            info!(
                "AFP session {} accepted from {:?}",
                session_count, session.remote_addr
            );

            let session_config = self.config.clone();
            let session_db = self.db.clone();
            tokio::spawn(async move {
                if let Err(e) = session.handle_session(session_config, session_db).await {
                    error!("Session error: {}", e);
                }
            });
        }
    }
}

impl AspSession {
    /// Handle an AFP session
    async fn handle_session(mut self, config: Arc<AfpServerConfig>, desktop_db: sled::Db) -> anyhow::Result<()> {
        info!("Session {} handler started", self.id);

        let volume_name = config.volume_name.clone();

        let mut our_volume = Volume::new(
            volume_name,
            config.volume_path.clone(),
            AFP_VOLUME_ID,
            desktop_db.clone(),
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
            debug!(
                "Session {} AFP {} ({})",
                self.id,
                afp_cmd_name(cmd_code),
                cmd_code
            );

            // Handle commands
            match cmd_code {
                tailtalk_packets::afp::AFP_CMD_BYTE_RANGE_LOCK => {
                    self.handle_byte_range_lock(command, &mut our_volume)
                        .await?;
                }
                AFP_CMD_COPY_FILE => {
                    self.handle_copy_file(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_LOGIN => {
                    let data = command.data[1..].to_vec();
                    self.handle_login(&data, command)?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_SRVR_PARMS => {
                    debug!("AFP FPGetSrvrParms req: (no params)");
                    let vol_response = FPGetSrvrParms {
                        server_time: crate::time_to_afp_v1(std::time::SystemTime::now()),
                        volumes: vec![our_volume.get_fp_volume()],
                    };
                    debug!(
                        "AFP FPGetSrvrParms resp: OK volumes=[{:?}]",
                        vol_response
                            .volumes
                            .iter()
                            .map(|v| v.name.to_string())
                            .collect::<Vec<_>>()
                    );
                    let mut output_buf = [0u8; 512];
                    let offset = vol_response.to_bytes(&mut output_buf).map_err(|e| {
                        anyhow::anyhow!("Failed to serialize AFP GetSrvrParms: {:?}", e)
                    })?;
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_CLOSE_VOL => {
                    let vol_id = if command.data.len() >= 4 {
                        u16::from_be_bytes([command.data[2], command.data[3]])
                    } else {
                        0
                    };
                    debug!("AFP FPCloseVol req: vol_id={}", vol_id);
                    // TODO: Implement proper volume opening / closing checks
                    debug!("AFP FPCloseVol resp: OK");
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: vec![],
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_OPEN_VOL => {
                    if command.data.len() < 4 {
                        command.send_reply(create_error_reply(AfpError::ParamError))?;
                        continue;
                    }
                    let bitmap_req = FPVolumeBitmap::from(u16::from_be_bytes(
                        [command.data[2], command.data[3]],
                    ));
                    debug!("AFP FPOpenVol req: bitmap={:?}", bitmap_req);
                    let mut output_buf = [0u8; 512];
                    let offset = our_volume
                        .get_bitmap_resp(bitmap_req, &mut output_buf)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("insufficient buffer size for AFP OpenVol: {:?}", e)
                        })?;
                    debug!(
                        "AFP FPOpenVol resp: OK vol_id={} {} bytes",
                        our_volume.get_volume_id(),
                        offset
                    );
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_VOL_PARMS => {
                    let vol_parms_req = match FPGetVolParms::parse(command.data.get(2..).unwrap_or(&[])) {
                        Ok(c) => c,
                        Err(e) => {
                            debug!("AFP FPGetVolParms parse error: {:?}", e);
                            command.send_reply(create_error_reply(e))?;
                            continue;
                        }
                    };
                    debug!(
                        "AFP FPGetVolParms req: vol_id={}, bitmap={:?}",
                        vol_parms_req.volume_id, vol_parms_req.bitmap
                    );
                    let mut output_buf = [0u8; 512];
                    let offset = our_volume
                        .get_bitmap_resp(vol_parms_req.bitmap, &mut output_buf)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("insufficient buffer size for AFP GetVolParms: {:?}", e)
                        })?;
                    debug!("AFP FPGetVolParms resp: OK {} bytes", offset);
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: output_buf[..offset].to_vec(),
                    })?;
                }
                tailtalk_packets::afp::AFP_CMD_READ => {
                    self.handle_read(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_FILE_PARMS => {
                    self.handle_get_file_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_DIR_PARMS => {
                    self.handle_get_dir_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_SET_FILE_PARMS => {
                    self.handle_set_file_parms(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_FILE_DIR_PARMS => {
                    self.handle_get_file_dir_parms(command, &mut our_volume).await?;
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
                    debug!("AFP FPGetSrvrMsg req: (stub)");
                    debug!("AFP FPGetSrvrMsg resp: OK empty message");
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: vec![0, 0, 0, 0],
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
                tailtalk_packets::afp::AFP_CMD_FLUSH_FORK => {
                    self.handle_flush_fork(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_OPEN_DT => {
                    debug!("AFP FPOpenDT req: (no params)");
                    match our_volume.open_dt().await {
                        Ok(ref_num) => {
                            debug!("AFP FPOpenDT resp: OK dt_ref_num={}", ref_num);
                            command.send_reply(AspCommandResponse {
                                result: [0u8; 4],
                                data: ref_num.to_be_bytes().to_vec(),
                            })?;
                        }
                        Err(e) => {
                            debug!("AFP FPOpenDT resp: err={:?}", e);
                            command.send_reply(AspCommandResponse {
                                result: (e as u32).to_be_bytes(),
                                data: Vec::new(),
                            })?;
                        }
                    }
                }
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
                tailtalk_packets::afp::AFP_CMD_ADD_APPL => {
                    self.handle_add_appl(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_REMOVE_APPL => {
                    self.handle_remove_appl(command, &mut our_volume).await?;
                }
                tailtalk_packets::afp::AFP_CMD_GET_APPL => {
                    self.handle_get_appl(command, &mut our_volume).await?;
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
                AFP_CMD_MOVE_AND_RENAME => {
                    self.handle_move_and_rename(command, &mut our_volume)
                        .await?;
                }
                AFP_CMD_RENAME => {
                    self.handle_rename(command, &mut our_volume).await?;
                }
                AFP_CMD_LOGOUT => {
                    debug!("AFP FPLogout req: (no params)");
                    debug!("AFP FPLogout resp: OK session ending");
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: vec![],
                    })?;
                    break;
                }
                tailtalk_packets::afp::AFP_CMD_CLOSE_DT => {
                    let dt_ref = if command.data.len() >= 4 {
                        u16::from_be_bytes([command.data[2], command.data[3]])
                    } else {
                        0
                    };
                    debug!("AFP FPCloseDT req: dt_ref_num={}", dt_ref);
                    debug!("AFP FPCloseDT resp: OK");
                    command.send_reply(AspCommandResponse {
                        result: [0u8; 4],
                        data: vec![],
                    })?;
                }
                _ => {
                    warn!(
                        "AFP unknown command {} ({}): returning FP error",
                        afp_cmd_name(cmd_code),
                        cmd_code
                    );
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
        let lock_req = parse_or_reply!(command, FPByteRangeLock, 1);
        debug!(
            "AFP FPByteRangeLock req: fork_id={}, flags={:?}, offset={}, length={}",
            lock_req.fork_id, lock_req.flags, lock_req.offset, lock_req.length
        );

        match our_volume.byte_range_lock(&lock_req).await {
            Ok(first_byte) => {
                debug!("AFP FPByteRangeLock resp: OK first_byte={}", first_byte);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: first_byte.to_be_bytes().to_vec(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPByteRangeLock resp: err={:?}", e);
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
        let cmd = parse_or_reply!(command, FPCreateDir, 2);
        debug!(
            "AFP FPCreateDir req: dir_id={}, path={:?}",
            cmd.directory_id,
            cmd.path.to_string()
        );

        match our_volume
            .create_dir(cmd.directory_id, afp_path_to_posix(cmd.path.as_str()))
            .await
        {
            Ok(dir_id) => {
                debug!("AFP FPCreateDir resp: OK new_dir_id={}", dir_id);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: dir_id.to_be_bytes().to_vec(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPCreateDir resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
            }
        }

        Ok(())
    }

    async fn handle_create_file(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = parse_or_reply!(command, FPCreateFile, 1);
        debug!(
            "AFP FPCreateFile req: flag={:?}, dir_id={}, path={:?}",
            cmd.create_flag,
            cmd.directory_id,
            cmd.path.to_string()
        );

        match our_volume
            .create_file(
                cmd.create_flag,
                cmd.directory_id,
                afp_path_to_posix(cmd.path.as_str()),
            )
            .await
        {
            Ok(_) => {
                debug!("AFP FPCreateFile resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPCreateFile resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_copy_file(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = match FPCopyFile::parse(&command.data[2..]) {
            Ok(c) => c,
            Err(e) => {
                debug!("AFP FPCopyFile resp: parse err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        let src_path = afp_path_to_posix(cmd.src_path.as_str());
        let dst_path = afp_path_to_posix(cmd.dst_path.as_str());
        debug!(
            "AFP FPCopyFile req: src_vol={}, src_dir={}, dst_vol={}, dst_dir={}, src={:?}, dst={:?}, new_name={:?}",
            cmd.src_volume_id, cmd.src_directory_id, cmd.dst_volume_id, cmd.dst_directory_id,
            src_path, dst_path, cmd.new_name
        );

        // We only support single-volume copies.
        if cmd.src_volume_id != cmd.dst_volume_id
            && cmd.src_volume_id != 0
            && cmd.dst_volume_id != 0
        {
            debug!("AFP FPCopyFile resp: err=ParamError (cross-volume)");
            command.send_reply(create_error_reply(AfpError::ParamError))?;
            return Ok(());
        }

        match our_volume
            .copy_file(
                cmd.src_directory_id,
                &src_path,
                cmd.dst_directory_id,
                &dst_path,
                cmd.new_name.as_str(),
            )
            .await
        {
            Ok(_) => {
                debug!("AFP FPCopyFile resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPCopyFile resp: err={:?}", e);
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
        let delete_req = parse_or_reply!(command, FPDelete, 2);
        debug!(
            "AFP FPDelete req: dir_id={}, path={:?}",
            delete_req.directory_id, delete_req.path
        );

        match our_volume.delete(&delete_req).await {
            Ok(_) => {
                debug!("AFP FPDelete resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPDelete resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }
        Ok(())
    }

    /// Handle AFP_CMD_GET_FILE_DIR_PARMS
    async fn handle_get_file_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = parse_or_reply!(command, FPGetFileParms, 2);
        let file_bitmap = cmd.file_bitmap;
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPGetFileParms req: dir_id={}, path={:?}, file_bitmap={:?}",
            cmd.directory_id, path_name_buf, file_bitmap
        );

        if cmd.directory_id == 1 {
            debug!("AFP FPGetFileParms resp: err=ObjectNotFound (dir_id=1)");
            command.send_reply(create_error_reply(AfpError::ObjectNotFound))?;
            return Ok(());
        }

        let node_id = match our_volume.resolve_node_lazy(cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!("AFP FPGetFileParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        let mut output_buf = [0u8; 1024];
        let (is_dir, bytes_written) = match our_volume
            .get_node_parms(node_id, file_bitmap, FPDirectoryBitmap::empty(), &mut output_buf[4..])
            .await
        {
            Ok(result) => result,
            Err(e) => {
                debug!("AFP FPGetFileParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        if is_dir {
            debug!("AFP FPGetFileParms resp: err=ObjectTypeErr (node is a directory)");
            command.send_reply(create_error_reply(AfpError::ObjectTypeErr))?;
            return Ok(());
        }

        output_buf[0..2].copy_from_slice(&file_bitmap.bits().to_be_bytes());
        output_buf[2..4].copy_from_slice(&[0, 0]); // pad

        debug!(
            "AFP FPGetFileParms resp: OK node_id={}, {} param bytes",
            node_id, bytes_written
        );
        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: output_buf[..4 + bytes_written].to_vec(),
        })?;

        Ok(())
    }

    async fn handle_get_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = parse_or_reply!(command, FPGetDirParms, 2);
        let dir_bitmap = cmd.dir_bitmap;
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPGetDirParms req: dir_id={}, path={:?}, dir_bitmap={:?}",
            cmd.directory_id, path_name_buf, dir_bitmap
        );

        if cmd.directory_id == 1 {
            debug!("AFP FPGetDirParms resp: err=ObjectNotFound (dir_id=1)");
            command.send_reply(create_error_reply(AfpError::ObjectNotFound))?;
            return Ok(());
        }

        let node_id = match our_volume.resolve_node_lazy(cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!("AFP FPGetDirParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        let mut output_buf = [0u8; 1024];
        let (is_dir, bytes_written) = match our_volume
            .get_node_parms(node_id, FPFileBitmap::empty(), dir_bitmap, &mut output_buf[4..])
            .await
        {
            Ok(result) => result,
            Err(e) => {
                debug!("AFP FPGetDirParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        if !is_dir {
            debug!("AFP FPGetDirParms resp: err=ObjectTypeErr (node is a file)");
            command.send_reply(create_error_reply(AfpError::ObjectTypeErr))?;
            return Ok(());
        }

        output_buf[0..2].copy_from_slice(&dir_bitmap.bits().to_be_bytes());
        output_buf[2..4].copy_from_slice(&[0, 0]); // pad

        debug!(
            "AFP FPGetDirParms resp: OK node_id={}, {} param bytes",
            node_id, bytes_written
        );
        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: output_buf[..4 + bytes_written].to_vec(),
        })?;

        Ok(())
    }

    async fn handle_set_file_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = parse_or_reply!(command, FPSetFileParms, 2);
        let file_bitmap = cmd.file_bitmap;
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPSetFileParms req: dir_id={}, path={:?}, bitmap={:?}",
            cmd.directory_id, path_name_buf, file_bitmap
        );

        let node_id = match our_volume.resolve_node_lazy(cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!("AFP FPSetFileParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        match our_volume
            .set_node_parms(node_id, file_bitmap, FPDirectoryBitmap::empty(), &cmd.params)
            .await
        {
            Ok(_) => {
                debug!("AFP FPSetFileParms resp: OK node_id={}", node_id);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPSetFileParms resp: err={:?}", e);
                command.send_reply(create_error_reply(e))?;
            }
        }

        Ok(())
    }

    async fn handle_get_file_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = parse_or_reply!(command, FPGetFileDirParms, 2);
        let file_bitmap = cmd.file_bitmap;
        let dir_bitmap = cmd.dir_bitmap;
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPGetFileDirParms req: dir_id={}, path={:?}, file_bitmap={:?}, dir_bitmap={:?}",
            cmd.directory_id, path_name_buf, file_bitmap, dir_bitmap
        );

        if cmd.directory_id == 1 {
            debug!("AFP FPGetFileDirParms resp: err=ObjectNotFound (dir_id=1)");
            command.send_reply(create_error_reply(AfpError::ObjectNotFound))?;
            return Ok(());
        }

        let node_id = match our_volume.resolve_node_lazy(cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!(
                    "AFP FPGetFileDirParms resp: err={:?} (resolve failed for dir_id={}, path={:?})",
                    e, cmd.directory_id, path_name_buf
                );
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
                debug!(
                    "AFP FPGetFileDirParms resp: err={:?} (get_node_parms node_id={})",
                    e, node_id
                );
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

        debug!(
            "AFP FPGetFileDirParms resp: OK node_id={}, is_dir={}, {} param bytes",
            node_id, is_dir, bytes_written
        );
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
        let cmd = parse_or_reply!(command, FPSetFileDirParms, 2);
        let file_bitmap = cmd.file_bitmap;
        let dir_bitmap = FPDirectoryBitmap::from(cmd.file_bitmap.bits());
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPSetFileDirParms req: dir_id={}, path={:?}, bitmap={:?}",
            cmd.directory_id, path_name_buf, file_bitmap
        );

        if cmd.directory_id == 1 {
            debug!("AFP FPSetFileDirParms resp: err=ObjectNotFound (dir_id=1)");
            command.send_reply(create_error_reply(AfpError::ObjectNotFound))?;
            return Ok(());
        }

        let node_id = match our_volume.resolve_node_lazy(cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!("AFP FPSetFileDirParms resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
                return Ok(());
            }
        };

        match our_volume
            .set_node_parms(node_id, file_bitmap, dir_bitmap, &cmd.params)
            .await
        {
            Ok(_) => {
                debug!("AFP FPSetFileDirParms resp: OK node_id={}", node_id);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPSetFileDirParms resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        };

        Ok(())
    }

    async fn handle_move_and_rename(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = match FPMoveAndRename::parse(&command.data[2..]) {
            Ok(c) => c,
            Err(e) => {
                debug!("AFP FPMoveAndRename resp: parse err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        let src_path = afp_path_to_posix(cmd.src_path.as_str());
        let dst_path = afp_path_to_posix(cmd.dst_path.as_str());
        debug!(
            "AFP FPMoveAndRename req: src_dir={}, dst_dir={}, src={:?}, dst={:?}, new_name={:?}",
            cmd.src_directory_id, cmd.dst_directory_id, src_path, dst_path, cmd.new_name
        );

        match our_volume
            .move_and_rename(
                cmd.src_directory_id,
                cmd.dst_directory_id,
                &src_path,
                &dst_path,
                cmd.new_name.as_str(),
            )
            .await
        {
            Ok(()) => {
                debug!("AFP FPMoveAndRename resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPMoveAndRename resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_rename(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let cmd = match FPRename::parse(&command.data[2..]) {
            Ok(c) => c,
            Err(e) => {
                debug!("AFP FPRename resp: parse err={:?}", e);
                command.send_reply(create_error_reply(e))?;
                return Ok(());
            }
        };

        debug!(
            "AFP FPRename req: dir_id={}, path={:?}, new_name={:?}",
            cmd.directory_id,
            cmd.path.to_string(),
            cmd.new_name
        );

        match our_volume
            .rename(
                cmd.directory_id,
                &afp_path_to_posix(cmd.path.as_str()),
                cmd.new_name.as_str(),
            )
            .await
        {
            Ok(()) => {
                debug!("AFP FPRename resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPRename resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_set_dir_parms(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let dir_cmd = parse_or_reply!(command, FPSetDirParms, 2);
        let path_name_buf = afp_path_to_posix(dir_cmd.path.as_str());
        debug!(
            "AFP FPSetDirParms req: dir_id={}, path={:?}, bitmap={:?}",
            dir_cmd.directory_id, path_name_buf, dir_cmd.dir_bitmap
        );

        let node_id = match our_volume.resolve_node_lazy(dir_cmd.directory_id, &path_name_buf).await {
            Ok(node_id) => node_id,
            Err(e) => {
                debug!("AFP FPSetDirParms resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
                return Ok(());
            }
        };

        // Extract raw params from the command data.
        // FPSetDirParms header is 2(vol_id) + 4(dir_id) + 2(bitmap) + 1(path_type) = 9 bytes + path.
        // But we must account for word alignment of the params field.
        let mut param_offset = 9 + dir_cmd.path.byte_len();
        if !param_offset.is_multiple_of(2) {
            param_offset += 1;
        }

        match our_volume
            .set_node_parms(
                node_id,
                FPFileBitmap::empty(),
                dir_cmd.dir_bitmap,
                &command.data[2 + param_offset..],
            )
            .await
        {
            Ok(_) => {
                debug!("AFP FPSetDirParms resp: OK node_id={}", node_id);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPSetDirParms resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_flush(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let flush_cmd = parse_or_reply!(command, FPFlush, 2);
        debug!("AFP FPFlush req: vol_id={}", flush_cmd.volume_id);

        let _ = our_volume.sync().await;

        debug!("AFP FPFlush resp: OK");
        command.send_reply(AspCommandResponse {
            result: [0u8; 4],
            data: Vec::new(),
        })?;

        Ok(())
    }

    async fn handle_flush_fork(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let flush_cmd = parse_or_reply!(command, tailtalk_packets::afp::FPFlushFork, 2);
        debug!("AFP FPFlushFork req: fork_id={}", flush_cmd.fork_id);

        let _ = our_volume.sync_fork(flush_cmd.fork_id).await;

        debug!("AFP FPFlushFork resp: OK");
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
        let read_cmd = parse_or_reply!(command, FPRead, 2);
        debug!(
            "AFP FPRead req: fork_id={}, offset={}, req_count={}",
            read_cmd.fork_id, read_cmd.offset, read_cmd.req_count
        );

        // Cap the output buffer to the ATP transport limit for this request.
        // req_count is allowed to exceed the ATP QuantumSize per spec; the server
        // must truncate to what fits so the client can issue a follow-up read.
        let atp_limit = command.atp_max_response_bytes;
        let effective_len = (read_cmd.req_count as usize).min(atp_limit).min(4096);
        let mut output_buf = vec![0u8; effective_len];

        match our_volume.read(&read_cmd, &mut output_buf).await {
            Ok((bytes_read, is_eof)) => {
                let mut result_code = [0u8; 4];
                if is_eof && read_cmd.req_count > 0 {
                    // Sign-extend the i16 AFP error to u32 before getting bytes
                    result_code = (AfpError::EoFErr as i16 as i32 as u32).to_be_bytes();
                }
                debug!(
                    "AFP FPRead resp: OK bytes_read={}, eof={}",
                    bytes_read, is_eof
                );
                command.send_reply(AspCommandResponse {
                    result: result_code,
                    data: output_buf[..bytes_read].to_vec(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPRead resp: err={:?}", e);
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
                debug!("AFP FPWrite resp: parse err=ParamError");
                command.send_reply(create_error_reply(AfpError::ParamError))?;
                return Ok(());
            }
        };

        debug!(
            "AFP FPWrite req: fork_id={}, offset={}, req_count={}",
            write_cmd.fork_id, write_cmd.offset, write_cmd.req_count
        );

        // Perform SPWrite transaction to get the data
        // We ask for the amount the client wants to write
        let data = match self
            .write(write_cmd.req_count as usize, command.sequence_number)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                error!("AFP FPWrite SPWrite failed: {:?}", e);
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
                debug!(
                    "AFP FPWrite resp: OK bytes_written={}, last_byte_offset={}",
                    bytes_written, last_byte_offset
                );
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: reply_data.to_vec(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPWrite resp: err={:?}", e);
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
        // Fork type is in bit 7 of the flag byte (command.data[1]):
        // 0x00 = data fork, 0x80 = resource fork.
        let fork_type = ForkType::from(command.data.get(1).copied().unwrap_or(0) & 0x80);
        let cmd = parse_or_reply!(command, FPOpenFork, 2);
        let path_name_buf = afp_path_to_posix(cmd.path.as_str());
        debug!(
            "AFP FPOpenFork req: fork={:?}, dir_id={}, path={:?}, bitmap={:?}, access={:#06x}",
            fork_type, cmd.directory_id, path_name_buf, cmd.file_bitmap, cmd.access_mode
        );

        let mut output_buf = [0u8; 256];

        match our_volume
            .open_fork(
                fork_type,
                cmd.file_bitmap,
                cmd.access_mode,
                cmd.directory_id,
                &path_name_buf,
                &mut output_buf,
            )
            .await
        {
            Ok(offset) => {
                // Fork ref num is in bytes 2-3 of the response
                let fork_ref = if offset >= 4 {
                    u16::from_be_bytes([output_buf[2], output_buf[3]])
                } else {
                    0
                };
                debug!(
                    "AFP FPOpenFork resp: OK fork_ref={}, {} bytes",
                    fork_ref, offset
                );
                Ok(command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: output_buf[..offset].to_vec(),
                })?)
            }
            Err(e) => {
                debug!("AFP FPOpenFork resp: err={:?}", e);
                Ok(command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?)
            }
        }
    }

    async fn handle_close_fork(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let fork_cmd = parse_or_reply!(command, FPCloseFork, 2);
        debug!("AFP FPCloseFork req: fork_id={}", fork_cmd.fork_id);

        match our_volume.close_fork(fork_cmd.fork_id).await {
            Ok(_) => {
                debug!("AFP FPCloseFork resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPCloseFork resp: err={:?}", e);
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
        let fork_cmd = parse_or_reply!(command, FPSetForkParms, 2);
        debug!(
            "AFP FPSetForkParms req: fork_ref={}, data_len={:?}, rsrc_len={:?}",
            fork_cmd.fork_ref_num, fork_cmd.data_fork_length, fork_cmd.resource_fork_length
        );

        match our_volume.set_fork_parms(fork_cmd).await {
            Ok(_) => {
                debug!("AFP FPSetForkParms resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: Vec::new(),
                })?;
            }
            Err(e) => {
                debug!("AFP FPSetForkParms resp: err={:?}", e);
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
        let cmd = parse_or_reply!(command, FPGetForkParms, 2);
        debug!(
            "AFP FPGetForkParms req: fork_id={}, bitmap={:?}",
            cmd.fork_id, cmd.file_bitmap
        );

        let mut output_buf = [0u8; 256];

        output_buf[..2].copy_from_slice(&cmd.file_bitmap.bits().to_be_bytes());
        match our_volume
            .get_fork_parms(cmd.file_bitmap, cmd.fork_id, &mut output_buf[2..])
            .await
        {
            Ok(offset) => {
                debug!("AFP FPGetForkParms resp: OK {} param bytes", offset);
                Ok(command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: output_buf[..offset + 2].to_vec(),
                })?)
            }
            Err(e) => {
                debug!("AFP FPGetForkParms resp: err={:?}", e);
                Ok(command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?)
            }
        }
    }

    async fn handle_enumerate(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let mut enumerate = parse_or_reply!(command, FPEnumerate, 2);
        debug!(
            "AFP FPEnumerate req: dir_id={}, path={:?}, start={}, req_count={}, max_reply={}",
            enumerate.directory_id,
            enumerate.path,
            enumerate.start_index,
            enumerate.req_count,
            enumerate.max_reply_size
        );

        let mut output_buf = [0u8; 5000];
        output_buf[..2].copy_from_slice(&enumerate.file_bitmap.bits().to_be_bytes());
        output_buf[2..4].copy_from_slice(&enumerate.directory_bitmap.bits().to_be_bytes());

        let start_offset = 4u16;
        // max_reply_size can exceed what ATP will actually deliver, so clamp to whichever is tighter.
        let atp_payload_limit = command.atp_max_response_bytes.saturating_sub(start_offset as usize);
        enumerate.max_reply_size = enumerate.max_reply_size
            .saturating_sub(start_offset)
            .min(atp_payload_limit as u16);

        match our_volume
            .enumerate(enumerate, &mut output_buf[start_offset as usize..])
            .await
        {
            Ok(offset) => {
                // Entry count is the first 2 bytes of the enumerate result
                let so = start_offset as usize;
                let count =
                    u16::from_be_bytes([output_buf[so], output_buf[so + 1]]);
                // AFP spec: when no entries are returned, signal end-of-directory with
                // ObjectNotFound but still include the bitmap/count data so the client
                // can distinguish this from a hard error.
                let result = if count == 0 {
                    (AfpError::ObjectNotFound as i16 as i32 as u32).to_be_bytes()
                } else {
                    [0u8; 4]
                };
                debug!(
                    "AFP FPEnumerate resp: count={}, {} total bytes",
                    count,
                    offset + so
                );
                Ok(command.send_reply(AspCommandResponse {
                    result,
                    data: output_buf[..offset + so].to_vec(),
                })?)
            }
            Err(e) => {
                debug!("AFP FPEnumerate resp: err={:?}", e);
                Ok(command.send_reply(AspCommandResponse {
                    result: (e as u32).to_be_bytes(),
                    data: Vec::new(),
                })?)
            }
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
                debug!(
                    "AFP FPLogin req: version={:?}, uam={:?}",
                    login.afp_version, login.auth
                );

                let negotiated = login.afp_version.clone();

                match login.auth {
                    tailtalk_packets::afp::FPLoginAuth::NoUserAuthent => {
                        let reply = create_login_success_reply(self.id as i16);
                        debug!("AFP FPLogin resp: OK sess_ref={} (NoUserAuthent)", self.id);
                        command.send_reply(reply)?;
                    }
                    tailtalk_packets::afp::FPLoginAuth::CleartxtPasswrd {
                        ref username, ..
                    } => {
                        let reply = create_login_success_reply(self.id as i16);
                        debug!(
                            "AFP FPLogin resp: OK sess_ref={} (CleartxtPasswrd user={})",
                            self.id, username
                        );
                        command.send_reply(reply)?;
                    }
                }

                Ok(Some(negotiated))
            }
            Err(e) => {
                warn!("AFP FPLogin resp: parse err={:?}", e);
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
        let get_icon = parse_or_reply!(command, tailtalk_packets::afp::FPGetIcon, 2);
        debug!(
            "AFP FPGetIcon req: dt_ref={}, creator={:#010x}, type={:#010x}, icon_type={}, size={}",
            get_icon.dt_ref_num,
            u32::from_be_bytes(get_icon.file_creator),
            u32::from_be_bytes(get_icon.file_type),
            get_icon.icon_type,
            get_icon.size
        );

        match our_volume.get_icon(get_icon.dt_ref_num, &get_icon) {
            Ok(data) => {
                debug!("AFP FPGetIcon resp: OK {} bytes", data.len());
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data,
                })?;
            }
            Err(e) => {
                debug!("AFP FPGetIcon resp: err={:?}", e);
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
        let get_icon_info = parse_or_reply!(command, tailtalk_packets::afp::FPGetIconInfo, 2);
        debug!(
            "AFP FPGetIconInfo req: dt_ref={}, creator={:#010x}, icon_type={}",
            get_icon_info.dt_ref_num,
            u32::from_be_bytes(get_icon_info.file_creator),
            get_icon_info.icon_type
        );

        match our_volume.get_icon_info(get_icon_info.dt_ref_num, &get_icon_info) {
            Ok((icon_tag, file_type, size)) => {
                debug!(
                    "AFP FPGetIconInfo resp: OK tag={:#010x}, type={:#010x}, size={}",
                    icon_tag, file_type, size
                );
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
                debug!("AFP FPGetIconInfo resp: err={:?}", e);
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
        let add_icon = parse_or_reply!(command, tailtalk_packets::afp::FPAddIcon, 2);
        debug!(
            "AFP FPAddIcon req: dt_ref={}, creator={:#010x}, type={:#010x}, icon_type={}, size={}",
            add_icon.dt_ref_num,
            u32::from_be_bytes(add_icon.file_creator),
            u32::from_be_bytes(add_icon.file_type),
            add_icon.icon_type,
            add_icon.size
        );

        let data = match self
            .write(add_icon.size as usize, command.sequence_number)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                error!("AFP FPAddIcon SPWrite failed: {:?}", e);
                command.send_reply(create_error_reply(AfpError::MiscErr))?;
                return Ok(());
            }
        };

        match our_volume.add_icon(add_icon.dt_ref_num, &add_icon, &data) {
            Ok(_) => {
                debug!("AFP FPAddIcon resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPAddIcon resp: err={:?}", e);
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
        let add_comment = parse_or_reply!(command, tailtalk_packets::afp::FPAddComment, 2);
        debug!(
            "AFP FPAddComment req: dir_id={}, path={:?}, comment={:?}",
            add_comment.directory_id,
            add_comment.path.as_str(),
            add_comment.comment
        );

        match our_volume.set_comment(
            add_comment.directory_id,
            &afp_path_to_posix(add_comment.path.as_str()),
            &add_comment.comment,
        ) {
            Ok(_) => {
                debug!("AFP FPAddComment resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPAddComment resp: err={:?}", e);
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
        let get_comment = parse_or_reply!(command, tailtalk_packets::afp::FPGetComment, 2);
        debug!(
            "AFP FPGetComment req: dir_id={}, path={:?}",
            get_comment.directory_id,
            get_comment.path.as_str()
        );

        match our_volume.get_comment(
            get_comment.directory_id,
            &afp_path_to_posix(get_comment.path.as_str()),
        ) {
            Ok(comment) => {
                debug!("AFP FPGetComment resp: OK {} bytes", comment.len());
                let mut data = vec![];
                data.push(comment.len() as u8);
                data.extend_from_slice(&comment);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data,
                })?;
            }
            Err(e) => {
                debug!("AFP FPGetComment resp: err={:?}", e);
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
        let remove_comment = parse_or_reply!(command, tailtalk_packets::afp::FPRemoveComment, 2);
        debug!(
            "AFP FPRemoveComment req: dir_id={}, path={:?}",
            remove_comment.directory_id,
            remove_comment.path.as_str()
        );

        match our_volume.remove_comment(
            remove_comment.directory_id,
            &afp_path_to_posix(remove_comment.path.as_str()),
        ) {
            Ok(_) => {
                debug!("AFP FPRemoveComment resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPRemoveComment resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_add_appl(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let req = parse_or_reply!(command, tailtalk_packets::afp::FPAddAPPL, 2);
        debug!(
            "AFP FPAddAPPL req: dt_ref={}, creator={:#010x}, tag={:#010x}, dir_id={}, path={:?}",
            req.dt_ref_num,
            u32::from_be_bytes(req.file_creator),
            req.tag,
            req.directory_id,
            req.path.as_str()
        );

        match our_volume.add_appl(&req) {
            Ok(_) => {
                debug!("AFP FPAddAPPL resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPAddAPPL resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_remove_appl(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let req = parse_or_reply!(command, tailtalk_packets::afp::FPRemoveAPPL, 2);
        debug!(
            "AFP FPRemoveAPPL req: dt_ref={}, creator={:#010x}, dir_id={}, path={:?}",
            req.dt_ref_num,
            u32::from_be_bytes(req.file_creator),
            req.directory_id,
            req.path.as_str()
        );

        match our_volume.remove_appl(&req) {
            Ok(_) => {
                debug!("AFP FPRemoveAPPL resp: OK");
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data: vec![],
                })?;
            }
            Err(e) => {
                debug!("AFP FPRemoveAPPL resp: err={:?}", e);
                command.send_reply(AspCommandResponse {
                    result: (e as i32).to_be_bytes(),
                    data: Vec::new(),
                })?;
            }
        }

        Ok(())
    }

    async fn handle_get_appl(
        &self,
        command: crate::asp::AspCommand,
        our_volume: &mut Volume,
    ) -> anyhow::Result<()> {
        let req = parse_or_reply!(command, tailtalk_packets::afp::FPGetAPPL, 2);
        debug!(
            "AFP FPGetAPPL req: dt_ref={}, creator={:#010x}, index={}",
            req.dt_ref_num,
            u32::from_be_bytes(req.file_creator),
            req.appl_index
        );

        match our_volume.get_appl(&req) {
            Ok((tag, directory_id, path)) => {
                debug!(
                    "AFP FPGetAPPL resp: OK tag={:#010x}, dir_id={}, path={:?}",
                    tag, directory_id, path
                );
                let (encoded_path, _, _) = MACINTOSH.encode(&path);
                let path_len = encoded_path.len().min(255);
                let mut data = Vec::with_capacity(9 + path_len);
                data.extend_from_slice(&tag.to_be_bytes());
                data.extend_from_slice(&directory_id.to_be_bytes());
                data.push(0x02); // PathType: LongName
                data.push(path_len as u8);
                data.extend_from_slice(&encoded_path[..path_len]);
                command.send_reply(AspCommandResponse {
                    result: [0u8; 4],
                    data,
                })?;
            }
            Err(e) => {
                debug!("AFP FPGetAPPL resp: err={:?}", e);
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
    let mut data = session_ref_num.to_be_bytes().to_vec();
    data.extend_from_slice(&[0, 0]); // Append 2-byte IDNumber (unused for NoUserAuthent/Cleartxt)

    AspCommandResponse {
        result: [0u8; 4],
        data,
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

fn afp_cmd_name(code: u8) -> &'static str {
    match code {
        1 => "FPByteRangeLock",
        2 => "FPCloseVol",
        4 => "FPCloseFork",
        5 => "FPCopyFile",
        6 => "FPCreateDir",
        7 => "FPCreateFile",
        8 => "FPDelete",
        9 => "FPEnumerate",
        10 => "FPFlush",
        11 => "FPFlushFork",
        13 => "FPGetFileParms",
        14 => "FPGetForkParms",
        15 => "FPGetDirParms",
        16 => "FPGetSrvrParms",
        17 => "FPGetVolParms",
        18 => "FPLogin",
        20 => "FPLogout",
        23 => "FPMoveAndRename",
        24 => "FPOpenVol",
        26 => "FPOpenFork",
        27 => "FPRead",
        28 => "FPRename",
        29 => "FPSetDirParms",
        30 => "FPSetFileParms",
        31 => "FPSetForkParms",
        33 => "FPWrite",
        34 => "FPGetFileDirParms",
        35 => "FPSetFileDirParms",
        38 => "FPGetSrvrMsg",
        48 => "FPOpenDT",
        49 => "FPCloseDT",
        51 => "FPGetIcon",
        52 => "FPGetIconInfo",
        53 => "FPAddAPPL",
        54 => "FPRemoveAPPL",
        55 => "FPGetAPPL",
        56 => "FPAddComment",
        57 => "FPRemoveComment",
        58 => "FPGetComment",
        192 => "FPAddIcon",
        _ => "FPUnknown",
    }
}
