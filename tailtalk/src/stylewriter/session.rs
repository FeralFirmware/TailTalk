//! A print job on a StyleWriter behind an AppleTalk adapter.

use std::time::Duration;

use tailtalk_core::stylewriter::{self as core, ColorModel, status1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Instant;

use super::encode::{self, Band, G_FRAMING};
use super::status::faults_text;
use super::{
    Cartridge, Cleaning, JobOptions, PaperType, PrintQuality, PrinterFault, Rendering, StyleWriterFamily,
    StyleWriterInfo,
};
use crate::{
    adsp::{Adsp, AdspAddress, AdspListener, AdspStream},
    ddp::DdpHandle,
};

/// How long to wait for the printer to report a job printed, and as long
/// again whenever a fault has been cleared or the buffer's free space has
/// grown in the meantime.
const PRINTED_TIMEOUT: Duration = Duration::from_secs(180);

/// How long the adapter has to report everything sent gone out to the
/// printer before the printer counts as stopped.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the adapter has to answer an attention or a print request.
const REPLY_TIMEOUT: Duration = Duration::from_secs(90);

/// How often a job waiting to be called back looks at the queue, and how
/// often a print request the queue turned away is made again.
pub const QUEUE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long a printer needs after a reset before it is asked anything.
const RESET_SETTLE: Duration = Duration::from_secs(2);

/// The same for an original StyleWriter, and for any printer that did not
/// answer after the shorter wait.
const LONG_RESET_SETTLE: Duration = Duration::from_secs(8);

/// How long to keep checking on a printer that reports a fault, or that has
/// not come back after its reset, before giving up on it.
const FAULT_TIMEOUT: Duration = Duration::from_secs(180);

/// How long a status reply may take before the query is sent again.
const STATUS_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the printer has to act on a switch to its fast mode before the
/// port moves to its clock.
const FAST_SWITCH_SETTLE: Duration = Duration::from_millis(33);

/// How long a printer told to clean its cartridge has to start reading busy.
/// One that never does is taken to have cleaned already.
const CLEAN_START_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a cleaning may keep the printer busy. A Color StyleWriter 2200
/// takes over three minutes to super clean.
const CLEAN_TIMEOUT: Duration = Duration::from_secs(600);

/// The status message a job shows while it prints, which other Macs asking
/// the adapter see too, and its text.
const STATUS_PRINTING: (u16, &str) = (0x0647, "Printing");

/// The printer answered the print request with a "busy" result, because another
/// host holds the print connection or the queue is full. Retry later. Carried
/// inside the `anyhow::Error` returned by [`StyleWriterSession::connect`] so
/// callers can tell "queue behind someone else" from a hard failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrinterBusy(pub u16);

impl std::fmt::Display for PrinterBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Printer busy (result 0x{:04X}); retry later", self.0)
    }
}

impl std::error::Error for PrinterBusy {}

/// The print request's payload. It is the data socket as a u32, then the user
/// name as a Pascal string of up to 32 characters, zero padded to 70. The
/// second Pascal string after it, at offset 37, stays empty.
fn build_print_request(socket_num: u8, username: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(core::PRINT_REQUEST_LEN);
    payload.extend_from_slice(&(socket_num as u32).to_be_bytes());
    let name = username.as_bytes();
    let name_len = name.len().min(core::USER_NAME_MAX);
    payload.push(name_len as u8);
    payload.extend_from_slice(&name[..name_len]);
    payload.resize(core::PRINT_REQUEST_LEN, 0);
    payload
}

async fn control_attention(ctrl: &mut AdspStream, code: u16, payload: &[u8]) -> anyhow::Result<[u8; 2]> {
    let reply = control_query(ctrl, code, payload, 2).await?;
    Ok([reply[0], reply[1]])
}

async fn control_query(ctrl: &mut AdspStream, code: u16, payload: &[u8], reply_len: usize) -> anyhow::Result<Vec<u8>> {
    ctrl.send_attention(code, payload).await?;
    let mut reply = vec![0; reply_len];
    tokio::time::timeout(REPLY_TIMEOUT, ctrl.read_exact(&mut reply))
        .await
        .map_err(|_| anyhow::anyhow!("No reply to attention 0x{code:04X}"))??;
    Ok(reply)
}

async fn end_control_session(mut ctrl: AdspStream) {
    let _ = control_attention(&mut ctrl, core::ATTN_END_SESSION, &[0x00]).await;
    let _ = ctrl.close().await;
}

/// Ask about the queue on a control connection of its own. This asks the place
/// of the job in `request`, the number of jobs, and who the printing one is for
/// and what it shows. Returns the number of jobs.
async fn poll_queue(ddp: &DdpHandle, printer_addr: AdspAddress, request: &[u8]) -> anyhow::Result<u16> {
    let mut ctrl = Adsp::connect(ddp, printer_addr).await?;
    let result: anyhow::Result<u16> = async {
        let position = u16::from_be_bytes(control_attention(&mut ctrl, core::ATTN_QUEUE_POSITION, request).await?);
        let count = u16::from_be_bytes(control_attention(&mut ctrl, core::ATTN_JOB_COUNT, &[0x00]).await?);
        let user = control_query(&mut ctrl, core::ATTN_JOB_USER, &[0x00, 0x00], core::PRINT_REQUEST_LEN + 2).await?;
        let status = control_query(&mut ctrl, core::ATTN_JOB_STATUS, &[0x00], 2 + core::JOB_STATUS_TEXT_LEN + 2).await?;
        let pascal = |bytes: &[u8]| {
            let len = usize::from(bytes[0]).min(bytes.len() - 1);
            String::from_utf8_lossy(&bytes[1..1 + len]).into_owned()
        };
        tracing::info!(
            "StyleWriter queue: {count} job(s), this one #{position}; printing for {:?}: {:?}",
            pascal(&user[4..37]),
            pascal(&status[2..2 + core::JOB_STATUS_TEXT_LEN]),
        );
        Ok(count)
    }
    .await;
    end_control_session(ctrl).await;
    result
}

async fn withdraw(ddp: &DdpHandle, printer_addr: AdspAddress, request: &[u8]) {
    match Adsp::connect(ddp, printer_addr).await {
        Ok(mut ctrl) => {
            let _ = control_attention(&mut ctrl, core::ATTN_WITHDRAW, request).await;
            end_control_session(ctrl).await;
        }
        Err(e) => tracing::debug!("could not reach the printer to withdraw the job: {e}"),
    }
}

/// Wait for the adapter to call back on `listener`, looking at the queue
/// first and then every [`QUEUE_POLL_INTERVAL`] until it does. A job the
/// queue no longer counts was deleted. Past `give_up`, the job is withdrawn.
async fn wait_for_call_back(
    ddp: &DdpHandle,
    printer_addr: AdspAddress,
    request: &[u8],
    listener: &mut AdspListener,
    give_up: Option<Instant>,
) -> anyhow::Result<AdspStream> {
    loop {
        if let Ok(accepted) = tokio::time::timeout(Duration::ZERO, listener.accept()).await {
            return Ok(accepted?);
        }
        if give_up.is_some_and(|t| Instant::now() >= t) {
            withdraw(ddp, printer_addr, request).await;
            anyhow::bail!("The printer did not take the job in time, so it was withdrawn from the queue");
        }
        match poll_queue(ddp, printer_addr, request).await {
            Ok(0) => anyhow::bail!("The printer deleted the job from its queue"),
            Ok(_) => {}
            Err(e) => tracing::debug!("could not ask the printer about its queue: {e:#}"),
        }
        let wait = give_up.map_or(QUEUE_POLL_INTERVAL, |t| {
            QUEUE_POLL_INTERVAL.min(t.saturating_duration_since(Instant::now()))
        });
        if let Ok(accepted) = tokio::time::timeout(wait, listener.accept()).await {
            return Ok(accepted?);
        }
    }
}

/// A print job on a StyleWriter behind an AppleTalk adapter, from the
/// two-connection handshake to the teardown.
///
/// A job is [`Self::setup`], then for each page [`Self::start_page`],
/// [`Self::write_band`] for each band and [`Self::end_page`], then
/// [`Self::finish`]. [`Self::abort`] ends a job that failed part way. Every
/// command, query and block goes as an ADSP message of its own.
///
/// The printer is reset at the start of every job, and the job only goes ahead
/// once it identifies as the printer the job was set up for. Every band waits
/// for status '1' and '2' to be clear and for the adapter to have sent
/// everything so far. Its blocks then go as the printer's buffer has room for
/// them, as tracked from 'B'.
///
/// The teardown sends attention 0x0012 and reads its reply before closing.
/// Without it the printer tries to open a new connection to the control socket
/// after the disconnect.
pub struct StyleWriterSession {
    data: AdspStream,
    /// Set by [`Self::setup`]. Until then, a Color StyleWriter of unknown model.
    family: StyleWriterFamily,
    /// Set by [`Self::setup`].
    job: JobOptions,
    /// What the pages print as (see [`Self::rendering`]).
    rendering: Rendering,
    /// The cartridge status 'H' reported in [`Self::setup`], on a Color
    /// StyleWriter.
    cartridge: Option<Cartridge>,
    /// The page mode command last sent, so it goes out only when it changes.
    page_mode: Option<u8>,
    /// Pages started so far in the job.
    pages: usize,
    /// Bytes free in the printer's buffer, as the last 'B' reading less what
    /// has been sent since.
    free: i32,
    /// The free space read at the start of the job, with the buffer empty.
    max_free: i32,
}

impl StyleWriterSession {
    /// Make the two-connection handshake. This connects to the printer's
    /// control socket, sends the print request, ends the exchange and closes
    /// the control connection, then waits for the adapter's connection back on
    /// our data socket. A request the adapter turns away is [`PrinterBusy`].
    /// Past `give_up`, a job the adapter has queued but not called back is
    /// withdrawn. With no `give_up`, the wait lasts until it calls back or
    /// deletes the job.
    pub async fn connect(
        ddp: &DdpHandle,
        printer_addr: AdspAddress,
        username: &str,
        give_up: Option<Instant>,
    ) -> anyhow::Result<Self> {
        let (data_socket_num, mut data_listener) = Adsp::bind(ddp, None).await?;
        let request = build_print_request(data_socket_num, username);

        let mut ctrl = Adsp::connect(ddp, printer_addr).await?;
        let result = control_attention(&mut ctrl, core::ATTN_PRINT_REQUEST, &request).await;
        end_control_session(ctrl).await;
        let result = u16::from_be_bytes(result?);
        if result != 0 {
            return Err(anyhow::Error::new(PrinterBusy(result)));
        }

        let data = wait_for_call_back(ddp, printer_addr, &request, &mut data_listener, give_up).await?;
        Ok(Self {
            data,
            family: StyleWriterFamily::default(),
            job: JobOptions::default(),
            rendering: Rendering::default(),
            cartridge: None,
            page_mode: None,
            pages: 0,
            free: 0,
            max_free: 0,
        })
    }

    /// What the job's pages print as once [`Self::setup`] has run. This is the
    /// job's own rendering, or grayscale for a color job on a printer that
    /// cannot print colour.
    pub fn rendering(&self) -> Rendering {
        self.rendering
    }

    /// Send `bytes` as one ADSP message.
    async fn send(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.data.write_all(bytes).await?;
        self.data.write_eom().await?;
        Ok(())
    }

    /// Discard bytes already buffered from the printer. `poll_status` sends
    /// its query again after a timeout, so a merely late reply would
    /// otherwise answer the next query instead, and every one after.
    async fn drain_stale_input(&mut self) {
        let mut buf = [0u8; 16];
        while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(5), self.data.read(&mut buf)).await {
            if n == 0 {
                break;
            }
            tracing::debug!("discarded {} stale printer reply byte(s)", n);
        }
    }

    /// Send attention `code` on the data connection and read its two-byte
    /// in-band reply.
    async fn attention(&mut self, code: u16, payload: &[u8]) -> anyhow::Result<[u8; 2]> {
        self.drain_stale_input().await;
        self.data.send_attention(code, payload).await?;
        let mut reply = [0u8; 2];
        tokio::time::timeout(REPLY_TIMEOUT, self.data.read_exact(&mut reply))
            .await
            .map_err(|_| anyhow::anyhow!("No reply to attention 0x{code:04X}"))??;
        Ok(reply)
    }

    /// Wait until the adapter has acknowledged everything sent to it.
    async fn wait_sent(&self) -> anyhow::Result<()> {
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while self.data.unacknowledged().await? != 0 {
            anyhow::ensure!(Instant::now() < deadline, "The adapter stopped taking data");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    /// Send status query `query` and read its one-byte reply. `None` on a
    /// write or read error, or once `deadline` passes. A reply that does not
    /// come within [`STATUS_REPLY_TIMEOUT`] is asked for again.
    async fn poll_status(&mut self, query: u8, deadline: Instant) -> Option<u8> {
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            self.drain_stale_input().await;
            if self.send(&core::status_query(query)).await.is_err() {
                return None;
            }
            let mut s = [0u8; 1];
            match tokio::time::timeout(STATUS_REPLY_TIMEOUT, self.data.read_exact(&mut s)).await {
                Ok(Ok(_)) => return Some(s[0]),
                Ok(Err(_)) => return None,
                Err(_) => {}
            }
        }
    }

    /// Send `?` and read the identity string. `None` when the printer says
    /// nothing at all.
    async fn identify(&mut self) -> anyhow::Result<Option<String>> {
        self.drain_stale_input().await;
        self.send(&[core::IDENTIFY]).await?;
        let mut identity = Vec::new();
        loop {
            let mut b = [0u8; 1];
            match tokio::time::timeout(STATUS_REPLY_TIMEOUT, self.data.read_exact(&mut b)).await {
                Ok(Ok(_)) if b[0] == 0x0D => break,
                Ok(Ok(_)) if identity.len() < 32 => identity.push(b[0]),
                Ok(Ok(_)) => break,
                Ok(Err(e)) => return Err(e.into()),
                // The reply ends with a carriage return, but one that stops
                // without it still counts.
                Err(_) if !identity.is_empty() => break,
                Err(_) => return Ok(None),
            }
        }
        Ok(Some(String::from_utf8_lossy(&identity).trim().to_string()))
    }

    /// Send the eject-and-reset bytes, each a message of its own.
    async fn reset(&mut self) -> anyhow::Result<()> {
        self.send(&[0x00]).await?;
        self.send(&core::status_query(core::QUERY_RESET)).await
    }

    /// Reset the printer and ask `?` once it has settled. A printer that does
    /// not answer is reset again and given the longer settle an original
    /// StyleWriter needs.
    async fn reset_and_identify(&mut self) -> anyhow::Result<Option<String>> {
        for settle in [RESET_SETTLE, LONG_RESET_SETTLE] {
            self.reset().await?;
            tokio::time::sleep(settle).await;
            if let Some(identity) = self.identify().await? {
                return Ok(Some(identity));
            }
        }
        Ok(None)
    }

    /// Identify the printer and, on a Color StyleWriter, its submodel and
    /// cartridge, and read its status, without feeding paper. Meant for a
    /// session of its own, which connects, calls this, then calls
    /// [`Self::abort`].
    ///
    /// A printer that ignores the first `?` is reset and asked again, as an
    /// original StyleWriter left idle ignores `?` until it has been reset. A
    /// Color StyleWriter answers without one.
    pub async fn query_info(&mut self) -> anyhow::Result<StyleWriterInfo> {
        let identity = match self.identify().await? {
            Some(identity) => identity,
            None => {
                tracing::debug!("no reply to '?'; resetting the printer and asking again");
                self.reset_and_identify()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("No reply to printer identify query '?'"))?
            }
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        let color = identity.as_bytes() == core::COLOR_FAMILY;

        let submodel = if color {
            self.poll_status(core::QUERY_SUBMODEL, deadline).await
        } else {
            None
        };

        // A Color StyleWriter reports its cartridge after `D`. The others
        // only take a black one.
        let config_raw = if color {
            self.send(b"D").await?;
            Some(
                self.poll_status(core::QUERY_CARTRIDGE, deadline)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("No reply to cartridge query 'H'"))?,
            )
        } else {
            None
        };
        let color_cartridge = match StyleWriterFamily::from_identity(&identity, submodel) {
            Some(StyleWriterFamily::Color(model)) => config_raw.and_then(|h| Cartridge::from_query(h, model)),
            _ => None,
        } == Some(Cartridge::Color);

        // A printer that answers `?` but not these still has a model to
        // report, with its status shown as unavailable.
        let status_general = self.poll_status(core::QUERY_STATUS, deadline).await;
        let status_error = self.poll_status(core::QUERY_ERROR, deadline).await;
        let status_buffer = self.poll_status(core::QUERY_BUFFER, deadline).await;

        Ok(StyleWriterInfo {
            identity,
            submodel,
            color_cartridge,
            config_raw,
            status_general,
            status_error,
            status_buffer,
        })
    }

    /// Act on status '1' and '2' replies and return the faults they report.
    /// `S` clears whatever '2' reports except paper out. A 1200-series printer
    /// is sent it for any reading but 0, named or not. Out of paper, `S` waits
    /// until paper is loaded, and on an original StyleWriter until its Ready
    /// button is pressed too.
    async fn act_on_status(&mut self, status: Option<u8>, error: Option<u8>) -> anyhow::Result<Vec<PrinterFault>> {
        let faults = self.family.faults(status, error);
        let out_of_paper = faults.contains(&PrinterFault::OutOfPaper);
        let resume_now = !out_of_paper
            && if self.family.is_1200_series() {
                error.is_some_and(|e| e != 0)
            } else {
                faults.iter().any(|f| f.from_error_status())
            };
        if !faults.is_empty() {
            tracing::warn!("Printer reports: {}", faults_text(&faults));
        }
        let resume = core::status_query(core::QUERY_RESUME);
        if out_of_paper {
            if self.family == StyleWriterFamily::Original {
                tracing::warn!("Load paper, then press Ready on the printer");
            }
            self.send(&resume).await?;
            tokio::time::sleep(Duration::from_secs(5)).await;
        } else if resume_now {
            self.send(&resume).await?;
        }
        Ok(faults)
    }

    /// Poll status '1' and '2' once and act on them with
    /// [`Self::act_on_status`].
    async fn check_condition(&mut self, deadline: Instant) -> anyhow::Result<Vec<PrinterFault>> {
        let status = self.poll_status(core::QUERY_STATUS, deadline).await;
        let error = self.poll_status(core::QUERY_ERROR, deadline).await;
        self.act_on_status(status, error).await
    }

    /// Poll status '1' and '2' until they report no faults, acting on them as
    /// [`Self::act_on_status`] does, for up to [`FAULT_TIMEOUT`]. An open door
    /// or a missing cartridge gets two seconds between checks.
    async fn wait_until_clear(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + FAULT_TIMEOUT;
        loop {
            let faults = self.check_condition(deadline).await?;
            if faults.is_empty() {
                return Ok(());
            }
            anyhow::ensure!(Instant::now() < deadline, "Printer reports: {}", faults_text(&faults));
            let slow = faults.iter().any(|f| matches!(f, PrinterFault::DoorOpen | PrinterFault::CartridgeMissing));
            tokio::time::sleep(Duration::from_secs(if slow { 2 } else { 1 })).await;
        }
    }

    /// Reset the printer and wait for it to come back. Once it has settled, '1'
    /// and '2' have to be clear and `?` has to name the printer the job is for.
    /// A printer that does not answer is reset again, first with the longer
    /// settle on a black-only StyleWriter, then from its fast mode on any but
    /// the original, in case an earlier job left it there.
    async fn reset_for_job(&mut self) -> anyhow::Result<()> {
        self.reset().await?;
        let deadline = Instant::now() + FAULT_TIMEOUT;
        let mut settle = match self.family {
            StyleWriterFamily::Original => LONG_RESET_SETTLE,
            _ => RESET_SETTLE,
        };
        let mut retries = 0;
        loop {
            tokio::time::sleep(settle).await;
            let faults = self.check_condition(Instant::now() + STATUS_REPLY_TIMEOUT).await?;
            if !faults.contains(&PrinterFault::NoResponse) {
                if !faults.is_empty() {
                    self.wait_until_clear().await?;
                }
                if let Some(identity) = self.identify().await? {
                    anyhow::ensure!(
                        self.family.identifies_as(&identity),
                        "The printer identifies as '{identity}', which is not the {:?} the job is for",
                        self.family
                    );
                    return Ok(());
                }
            }
            anyhow::ensure!(Instant::now() < deadline, "Printer did not come back after its reset");
            use StyleWriterFamily::*;
            match (self.family, retries) {
                (Color(_), 0) => {
                    self.color_fast_clock(true).await?;
                    self.reset().await?;
                    self.color_fast_clock(false).await?;
                }
                (StyleWriterII | StyleWriter1200 | Original, 0) => {
                    settle = LONG_RESET_SETTLE;
                    self.reset().await?;
                }
                (StyleWriterII | StyleWriter1200, 1) => {
                    self.sw_fast_mode(true).await?;
                    self.reset().await?;
                    self.sw_fast_mode(false).await?;
                }
                _ => self.reset().await?,
            }
            retries += 1;
        }
    }

    /// Switch a Color StyleWriter into its fast mode, or the port back out of
    /// it, if attention 0x0005 says the adapter's port can follow the printer's
    /// clock. On the way in, `x` tells the printer, and once the adapter has
    /// it, attention 0x0004 moves the port to the printer's clock.
    async fn color_fast_clock(&mut self, on: bool) -> anyhow::Result<()> {
        if self.attention(core::ATTN_FAST_CLOCK_QUERY, &[0x00]).await?[1] != 0 {
            return Ok(());
        }
        if on {
            self.send(&[core::FAST_CLOCK]).await?;
            tokio::time::sleep(FAST_SWITCH_SETTLE).await;
        }
        self.wait_sent().await?;
        let option = if on { core::SERIAL_EXTERNAL_CLOCK } else { 0x00 };
        self.attention(core::ATTN_SERIAL_OPTIONS, &[option]).await?;
        Ok(())
    }

    /// Switch a StyleWriter II or 1200 into its fast mode, if attention
    /// 0x0007 with 0 says the adapter's port can follow it, with 0x0008,
    /// `h` and 0x0007 with 1. Otherwise, and on the way out, the port goes
    /// back to 57600 baud.
    async fn sw_fast_mode(&mut self, on: bool) -> anyhow::Result<()> {
        if on && self.attention(core::ATTN_SERIAL_CONTROL_JF, &[0x00, 0x00]).await? == [0x00, 0x00] {
            self.attention(core::ATTN_SERIAL_CONTROL_LOWER_JF, &[0x01, 0x01]).await?;
            self.send(&[core::FAST_CLOCK_SW]).await?;
            tokio::time::sleep(FAST_SWITCH_SETTLE).await;
            self.attention(core::ATTN_SERIAL_CONTROL_JF, &[0x00, 0x01]).await?;
        } else {
            self.attention(core::ATTN_SERIAL_CONFIG, &core::SERIAL_CONFIG_57600.to_be_bytes())
                .await?;
        }
        Ok(())
    }

    /// Set the printer up for a job.
    ///
    /// The printer is reset, and waited for until it reports no faults and
    /// identifies as the family the job is for. A Color StyleWriter then takes
    /// `D` and a 1200 `N`. Every printer has its buffer's free space read while
    /// the buffer is empty, and is switched to its fast mode where the adapter
    /// can follow it. Every printer but the original has its cartridge read. A
    /// Color StyleWriter takes [`JobOptions::color_commands`], and the
    /// black-only StyleWriters [`JobOptions::black_commands`]. A color job
    /// prints in grayscale on a printer that cannot print colour (see
    /// [`Self::rendering`]).
    pub async fn setup(&mut self, family: StyleWriterFamily, job: JobOptions) -> anyhow::Result<()> {
        self.family = family;
        self.job = job;
        self.rendering = job.rendering;
        self.cartridge = None;
        self.page_mode = None;
        self.pages = 0;
        if !family.can_clean() && job.cleaning != Cleaning::None {
            tracing::debug!("the original StyleWriter has no cleaning command; printing without one");
        }

        self.reset_for_job()
            .await
            .map_err(|e| e.context("waiting for the printer after its reset"))?;
        match family {
            StyleWriterFamily::Color(_) => self.send(b"D").await?,
            StyleWriterFamily::StyleWriter1200 => self.send(b"N").await?,
            StyleWriterFamily::StyleWriterII | StyleWriterFamily::Original => {}
        }
        self.read_free_space().await?;
        match family {
            StyleWriterFamily::Original => {}
            StyleWriterFamily::StyleWriterII | StyleWriterFamily::StyleWriter1200 => self.sw_fast_mode(true).await?,
            StyleWriterFamily::Color(_) => self.color_fast_clock(true).await?,
        }

        if family != StyleWriterFamily::Original {
            let deadline = Instant::now() + Duration::from_secs(60);
            let h = self
                .poll_status(core::QUERY_CARTRIDGE, deadline)
                .await
                .ok_or_else(|| anyhow::anyhow!("No reply to cartridge query 'H'"))?;
            if let StyleWriterFamily::Color(model) = family {
                let cartridge = Cartridge::from_query(h, model)
                    .ok_or_else(|| anyhow::anyhow!("Unknown cartridge (H=0x{h:02X})"))?;
                self.cartridge = Some(cartridge);
            }
        }
        if job.rendering == Rendering::Color && self.cartridge != Some(Cartridge::Color) {
            tracing::info!("no color cartridge in the printer; printing the job in grayscale");
            self.rendering = Rendering::Grayscale;
        }

        let commands = match (family, self.cartridge) {
            (StyleWriterFamily::Color(model), Some(cartridge)) => job.color_commands(model, cartridge),
            _ => job.black_commands(family),
        };
        for command in commands {
            self.send(&command).await?;
        }
        Ok(())
    }

    /// Read the buffer's free space ('B') with the buffer as empty as it gets.
    /// Every block is paced by it, so a printer that does not answer fails the
    /// job here.
    async fn read_free_space(&mut self) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        let b = self
            .poll_status(core::QUERY_BUFFER, deadline)
            .await
            .ok_or_else(|| anyhow::anyhow!("No reply to buffer query 'B'"))?;
        self.free = self.family.free_bytes(b);
        self.max_free = self.free;
        Ok(())
    }

    /// Tell the adapter the status message the job shows, for other Macs asking
    /// it. This is a u16 message ID, then the text as a Pascal string.
    async fn set_status(&mut self, (id, text): (u16, &str)) -> anyhow::Result<()> {
        let text = &text.as_bytes()[..text.len().min(core::JOB_STATUS_TEXT_LEN - 1)];
        let mut payload = id.to_be_bytes().to_vec();
        payload.push(text.len() as u8);
        payload.extend_from_slice(text);
        payload.resize(2 + core::JOB_STATUS_TEXT_LEN, 0);
        self.attention(core::ATTN_SET_STATUS, &payload).await?;
        Ok(())
    }

    /// Start a page. The first one tells the adapter the job is printing.
    ///
    /// A Color StyleWriter 2200, 2400 or 2500 takes its page mode
    /// ([`Cartridge::page_mode`]) when that changes, then `L`. With a black
    /// cartridge at Best on plain paper or transparencies, the mode is
    /// followed by `N` or `s`, as status 'R' decides (see [`core::QUERY_R`]).
    ///
    /// A 1500 takes no mode, just `L`, with `N` ahead of the first page for a
    /// black and white job on a black cartridge at Best on transparencies,
    /// and `s` for a grayscale one. A 1200 takes `L`, with `s` ahead of the
    /// first page at Best on transparencies, or `b` for grayscale. The
    /// StyleWriter II and the original StyleWriter take nothing between
    /// pages.
    pub async fn start_page(&mut self) -> anyhow::Result<()> {
        let first_page = self.pages == 0;
        self.pages += 1;
        if first_page {
            self.set_status(STATUS_PRINTING).await?;
        }
        let black_and_white = self.rendering == Rendering::BlackAndWhite;
        let best = self.job.quality == PrintQuality::Best;
        let paper = self.job.paper;
        let model = match self.family {
            StyleWriterFamily::Color(model) => model,
            StyleWriterFamily::StyleWriter1200 => {
                if first_page && best && paper == PaperType::Transparency {
                    self.send(if black_and_white { b"s" } else { b"b" }).await?;
                }
                return self.send(b"L").await;
            }
            StyleWriterFamily::StyleWriterII | StyleWriterFamily::Original => return Ok(()),
        };

        let cartridge = self
            .cartridge
            .ok_or_else(|| anyhow::anyhow!("start_page() before setup()"))?;
        if model == ColorModel::Cs1500 {
            if first_page && best && cartridge == Cartridge::Black && paper == PaperType::Transparency {
                self.send(if black_and_white { b"N" } else { b"s" }).await?;
            }
            return self.send(b"L").await;
        }
        let mode = cartridge.page_mode(self.rendering == Rendering::Color);
        if self.page_mode != Some(mode) {
            self.send(&[mode]).await?;
            if cartridge == Cartridge::Black && best && matches!(paper, PaperType::Plain | PaperType::Transparency) {
                let deadline = Instant::now() + Duration::from_secs(20);
                let r = self
                    .poll_status(core::QUERY_R, deadline)
                    .await
                    .filter(|&r| r != 0)
                    .ok_or_else(|| anyhow::anyhow!("No reply to status query 'R'"))?;
                let fine = black_and_white && r < core::QUERY_R_FINE_LIMIT;
                self.send(if fine { b"N" } else { b"s" }).await?;
            }
            self.page_mode = Some(mode);
        }
        self.send(b"L").await
    }

    /// Send one band, which is its rect followed by its rows in `G` blocks.
    ///
    /// The band waits for status '1' and '2' to report no faults and for the
    /// adapter to report everything sent so far gone out to the printer. Rows
    /// then go into a block until it no longer fits the printer's free space,
    /// tracked from 'B', or grows past the block size. The block goes with the
    /// row that made it so, once the printer has room for it.
    pub async fn write_band(&mut self, band: &Band) -> anyhow::Result<()> {
        self.wait_until_clear()
            .await
            .map_err(|e| e.context("checking printer status before a band"))?;
        self.wait_output_drained()
            .await
            .map_err(|e| e.context("waiting for the last band to go out"))?;
        let left = self.family.rect_left();
        let right = left + band.width - 1;
        self.send(&encode::rect(band.kind.tag(), left, band.top, right, band.bottom()))
            .await?;
        let room = self.family.block_room(band.kind, band.row_bytes());
        let mut block = Vec::new();
        for row in &band.rows {
            block.extend_from_slice(row);
            let block_len = block.len() + G_FRAMING;
            if self.free < block_len as i32 || block_len > room {
                self.make_room(block.len())
                    .await
                    .map_err(|e| e.context("waiting for room in the printer's buffer"))?;
                self.free -= block_len as i32;
                self.send(&encode::g_block(&std::mem::take(&mut block))).await?;
            }
        }
        if !block.is_empty() {
            self.free -= (block.len() + G_FRAMING) as i32;
            self.send(&encode::g_block(&block)).await?;
        }
        Ok(())
    }

    /// Ask the adapter with attention 0x0006 whether everything sent so far
    /// has gone out to the printer, until it says yes in the reply's low
    /// byte, for up to [`DRAIN_TIMEOUT`].
    async fn wait_output_drained(&mut self) -> anyhow::Result<()> {
        let start = Instant::now();
        loop {
            if self.attention(core::ATTN_OUTPUT_DRAINED, &[0x00]).await?[1] != 0 {
                return Ok(());
            }
            anyhow::ensure!(start.elapsed() < DRAIN_TIMEOUT, "The printer stopped taking data");
            tokio::task::yield_now().await;
        }
    }

    /// Wait for room for a block of `len` bytes in the printer's buffer, or
    /// for the buffer to be as empty as at the start of the job, checking
    /// status '2' and '1' as well.
    async fn make_room(&mut self, len: usize) -> anyhow::Result<()> {
        let need = len as i32;
        let deadline = Instant::now() + FAULT_TIMEOUT;
        while self.free < need && self.free < self.max_free {
            anyhow::ensure!(
                Instant::now() < deadline,
                "The printer's buffer did not drain ({} of {} bytes free)",
                self.free,
                self.max_free
            );
            let error = self.poll_status(core::QUERY_ERROR, deadline).await;
            let status = self.poll_status(core::QUERY_STATUS, deadline).await;
            if !self.act_on_status(status, error).await?.is_empty() {
                self.wait_until_clear().await?;
            }
            let b = self
                .poll_status(core::QUERY_BUFFER, deadline)
                .await
                .ok_or_else(|| anyhow::anyhow!("No reply to buffer query 'B'"))?;
            self.free = self.family.free_bytes(b);
        }
        Ok(())
    }

    /// End a page with a form feed, straight after the last band. The printer
    /// takes it in turn behind the raster.
    pub async fn end_page(&mut self) -> anyhow::Result<()> {
        self.send(b"\x0C").await
    }

    /// Finish the job and tear the connection down. On every StyleWriter but
    /// the original this waits for status '1' to report everything printed,
    /// then sends `E`, `Y` on a 1200, and `l`. A printer that stopped printing
    /// is sent nothing more.
    pub async fn finish(mut self) -> anyhow::Result<()> {
        if self.family != StyleWriterFamily::Original
            && let Err(e) = self.wait_printed().await
        {
            let _ = self.teardown(false).await;
            return Err(e);
        }
        self.send(b"E").await?;
        if self.family == StyleWriterFamily::StyleWriter1200 {
            self.send(b"Y").await?;
        }
        self.send(b"l").await?;
        self.teardown(false).await
    }

    /// Wait for status '1' to report everything printed, checking '2' for
    /// faults meanwhile. The time allowed starts again once a fault has been
    /// cleared, and whenever the buffer's free space has grown since it last
    /// ran out, as a printer still emptying its buffer is still printing.
    async fn wait_printed(&mut self) -> anyhow::Result<()> {
        let mut deadline = Instant::now() + PRINTED_TIMEOUT;
        let mut last_free = self.poll_status(core::QUERY_BUFFER, deadline).await;
        loop {
            while Instant::now() < deadline {
                if self.printed(deadline).await {
                    return Ok(());
                }
                let error = self.poll_status(core::QUERY_ERROR, deadline).await;
                if error != Some(0) {
                    self.act_on_status(Some(0), error).await?;
                    self.wait_until_clear().await?;
                    deadline = Instant::now() + PRINTED_TIMEOUT;
                }
                tokio::task::yield_now().await;
            }
            if self.printed(Instant::now() + STATUS_REPLY_TIMEOUT).await {
                return Ok(());
            }
            let free = self
                .poll_status(core::QUERY_BUFFER, Instant::now() + Duration::from_secs(20))
                .await;
            anyhow::ensure!(free > last_free, "The printer stopped printing");
            last_free = free;
            deadline = Instant::now() + PRINTED_TIMEOUT;
        }
    }

    async fn printed(&mut self, deadline: Instant) -> bool {
        self.poll_status(core::QUERY_STATUS, deadline)
            .await
            .is_some_and(|s| s & status1::PRINTED != 0)
    }

    /// Abort a job that failed part way. This skips the finish and goes
    /// straight to the teardown, whose eject-and-reset ejects any loaded page
    /// and resets the printer. A black-only StyleWriter takes `E` first.
    /// Without this a failed job leaves paper sitting in the feed path until
    /// the next job.
    pub async fn abort(mut self) -> anyhow::Result<()> {
        if !self.family.can_print_color() {
            let _ = self.send(b"E").await;
        }
        self.teardown(true).await
    }

    /// Clean the cartridge's nozzles, as a job with no pages. The cleaning
    /// commands go at the start of a job, and the job ends once the printer has
    /// finished cleaning. Every StyleWriter but the original cleans on command.
    pub async fn clean_cartridge(mut self, family: StyleWriterFamily, cleaning: Cleaning) -> anyhow::Result<()> {
        if !family.can_clean() {
            let _ = self.abort().await;
            anyhow::bail!("The original StyleWriter does not clean its cartridge on command");
        }
        let job = JobOptions { cleaning, ..JobOptions::default() };
        let cleaned = match self.setup(family, job).await {
            Ok(()) => self.wait_cleaned().await,
            Err(e) => Err(e),
        };
        if let Err(e) = cleaned {
            let _ = self.abort().await;
            return Err(e);
        }
        self.finish().await
    }

    /// Wait for a cleaning to finish. Status '1' reads busy while the printer
    /// cleans. Its printed bit is no help, since with no page sent it stays set
    /// throughout. Busy has [`CLEAN_START_TIMEOUT`] to come on, then up to
    /// [`CLEAN_TIMEOUT`] to go off again.
    async fn wait_cleaned(&mut self) -> anyhow::Result<()> {
        let start = Instant::now();
        let deadline = start + CLEAN_TIMEOUT;
        let mut seen_busy = false;
        loop {
            let status = self.poll_status(core::QUERY_STATUS, deadline).await;
            let status = match status {
                Some(status) => status,
                None if Instant::now() >= deadline => {
                    anyhow::bail!("The printer was still cleaning after {} s", CLEAN_TIMEOUT.as_secs())
                }
                None => anyhow::bail!("No reply to status query '1' while cleaning"),
            };
            if status & status1::BUSY != 0 {
                seen_busy = true;
            } else if seen_busy || start.elapsed() >= CLEAN_START_TIMEOUT {
                tracing::debug!("cleaning done after {:.1} s", start.elapsed().as_secs_f64());
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// End the session by sending the eject-and-reset bytes when `reset`, then
    /// attention 0x0012 and its reply, then closing.
    async fn teardown(mut self, reset: bool) -> anyhow::Result<()> {
        if reset {
            self.reset().await?;
        }
        let _ = self.attention(core::ATTN_END_SESSION, &[0x00]).await;
        self.data.close().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_print_request_carries_up_to_32_characters() {
        let req = build_print_request(70, &"u".repeat(40));
        assert_eq!(req.len(), 70);
        assert_eq!(req[..5], [0, 0, 0, 70, 32]);
        assert!(req[5..37].iter().all(|&b| b == b'u'));
        // The second string, at offset 37, stays empty.
        assert!(req[37..].iter().all(|&b| b == 0));
    }
}
