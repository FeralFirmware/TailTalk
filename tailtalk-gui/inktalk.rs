//! A client for an InkTalk's control channel, which is the `<name>:InkTalk@*`
//! ADSP socket speaking the frames from the `inkproto` crate. The Network
//! Explorer uses this to show an InkTalk's settings and let you change them.

use inkproto::{FrameWriter, Header, Items, OSType, cmd, err, tag};
use tailtalk::adsp::{Adsp, AdspAddress, AdspStream};
use tailtalk::ddp::DdpHandle;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

/// Long enough for a reply that has to wait for a flash save.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The printer the device is emulating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    StyleWriter,
    ImageWriter,
}

impl Mode {
    /// Index order must match the Mode ComboBox in `network_explorer.slint`.
    pub fn from_index(i: i32) -> Mode {
        if i == 1 { Mode::ImageWriter } else { Mode::StyleWriter }
    }

    pub fn index(self) -> i32 {
        match self {
            Mode::StyleWriter => 0,
            Mode::ImageWriter => 1,
        }
    }

    fn from_wire(v: u16) -> Option<Mode> {
        match v {
            inkproto::role::STYLEWRITER => Some(Mode::StyleWriter),
            inkproto::role::IMAGEWRITER => Some(Mode::ImageWriter),
            _ => None,
        }
    }

    fn wire(self) -> u16 {
        match self {
            Mode::StyleWriter => inkproto::role::STYLEWRITER,
            Mode::ImageWriter => inkproto::role::IMAGEWRITER,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::StyleWriter => "Color StyleWriter",
            Mode::ImageWriter => "ImageWriter",
        }
    }
}

/// What `'HELO'` and `'INFO'` report. Every field is optional, since we skip
/// anything we don't recognise and a device might leave out things it
/// doesn't have.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub protocol: Option<u16>,
    pub firmware: Option<String>,
    pub name: Option<String>,
    pub live_name: Option<String>,
    pub mode: Option<Mode>,
    pub baud: Option<u32>,
    pub pending: Option<bool>,
    pub job_active: Option<bool>,
    pub printer_ready: Option<bool>,
    pub uptime_secs: Option<u32>,
    pub address: Option<(u16, u8)>,
    pub printer_tx: Option<u32>,
    pub printer_rx: Option<u32>,
    /// Empty when the printer did not answer the device's identify.
    pub printer_model: Option<String>,
}

/// One connection to the control socket.
struct Session {
    stream: AdspStream,
    seq: u16,
}

impl Session {
    async fn open(ddp: &DdpHandle, addr: AdspAddress) -> anyhow::Result<Session> {
        let stream = timeout(CONNECT_TIMEOUT, Adsp::connect(ddp, addr))
            .await
            .map_err(|_| anyhow::anyhow!("the InkTalk did not answer the connection"))??;
        Ok(Session { stream, seq: 0 })
    }

    /// Send one command and return the reply's result and body.
    async fn request(
        &mut self,
        command: OSType,
        items: impl FnOnce(&mut FrameWriter<'_>) -> Result<(), inkproto::Overflow>,
    ) -> anyhow::Result<(i16, Vec<u8>)> {
        self.seq = self.seq.wrapping_add(1);
        let mut buf = [0u8; inkproto::MAX_FRAME_LEN];
        let mut w = FrameWriter::new(&mut buf, self.seq, command)
            .map_err(|_| anyhow::anyhow!("request buffer too small"))?;
        items(&mut w).map_err(|_| anyhow::anyhow!("request too large"))?;
        let frame = w.finish(err::NO_ERR);
        self.stream.write_all(frame).await?;
        self.stream.write_eom().await?;

        let reply = timeout(REPLY_TIMEOUT, self.read_frame())
            .await
            .map_err(|_| anyhow::anyhow!("the InkTalk did not reply"))??;
        let header = Header::parse(&reply).map_err(|e| anyhow::anyhow!("malformed reply: {e:?}"))?;
        if header.seq != self.seq || header.command != command {
            anyhow::bail!("reply does not match the request");
        }
        Items::of_frame(&reply).map_err(|e| anyhow::anyhow!("malformed reply: {e:?}"))?;
        Ok((header.result, reply))
    }

    /// The next frame: one whole ADSP message.
    async fn read_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        self.stream
            .read_message()
            .await?
            .ok_or_else(|| anyhow::anyhow!("the InkTalk closed the connection"))
    }

    async fn close(self) {
        let _ = self.stream.close().await;
    }
}

/// Read the device's identity, settings and status.
pub async fn query(ddp: &DdpHandle, addr: AdspAddress) -> anyhow::Result<Info> {
    let mut session = Session::open(ddp, addr).await?;
    let result = query_on(&mut session).await;
    session.close().await;
    result
}

async fn query_on(session: &mut Session) -> anyhow::Result<Info> {
    let mut info = Info::default();
    for command in [cmd::HELLO, cmd::INFO] {
        let (result, reply) = session.request(command, |_| Ok(())).await?;
        check(result, &reply)?;
        let items = Items::of_frame(&reply).expect("checked by request");
        for item in items.iter() {
            match item.tag {
                tag::PROTOCOL => info.protocol = item.u16(),
                tag::FIRMWARE => info.firmware = item.pstr().map(mac_roman),
                tag::NAME => info.name = item.pstr().map(mac_roman),
                tag::LIVE_NAME => info.live_name = item.pstr().map(mac_roman),
                tag::ROLE => info.mode = item.u16().and_then(Mode::from_wire),
                tag::BAUD => info.baud = item.u32(),
                tag::REBOOT_NEEDED => info.pending = item.boolean(),
                tag::JOB_ACTIVE => info.job_active = item.boolean(),
                tag::PRINTER_READY => info.printer_ready = item.boolean(),
                tag::UPTIME => info.uptime_secs = item.u32(),
                tag::ADDRESS => {
                    if let [hi, lo, node, _] = *item.data {
                        info.address = Some((u16::from_be_bytes([hi, lo]), node));
                    }
                }
                tag::PRINTER_TX => info.printer_tx = item.u32(),
                tag::PRINTER_RX => info.printer_rx = item.u32(),
                tag::PRINTER_MODEL => info.printer_model = item.pstr().map(mac_roman),
                _ => {}
            }
        }
    }
    Ok(info)
}

/// Apply and save new settings. Returns whether the device is restarting to
/// pick them up, which it does for a new mode or baud rate.
pub async fn configure(
    ddp: &DdpHandle,
    addr: AdspAddress,
    name: &str,
    mode: Mode,
    baud: u32,
) -> anyhow::Result<bool> {
    validate_name(name)?;
    if !inkproto::BAUD_RANGE.contains(&baud) {
        anyhow::bail!(
            "baud rate must be {}–{}",
            inkproto::BAUD_RANGE.start(),
            inkproto::BAUD_RANGE.end()
        );
    }
    let mut session = Session::open(ddp, addr).await?;
    let result = session
        .request(cmd::SET_CONFIG, |w| {
            w.pstr(tag::NAME, name.as_bytes())?;
            w.u16(tag::ROLE, mode.wire())?;
            w.u32(tag::BAUD, baud)
        })
        .await;
    // Only close the connection if the device is staying up. A restarting
    // device drops the connection itself, and closing it would just time out.
    let (result, reply) = match result {
        Ok(r) => r,
        Err(e) => {
            session.close().await;
            return Err(e);
        }
    };
    check(result, &reply)?;
    let rebooting = Items::of_frame(&reply)
        .expect("checked by request")
        .find(tag::REBOOTING)
        .and_then(|i| i.boolean())
        .unwrap_or(false);
    if !rebooting {
        session.close().await;
    }
    Ok(rebooting)
}

/// Uses the same rules as the device, so we can catch a bad name here with a
/// clear message instead of having it refused over the wire.
pub fn validate_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() > inkproto::MAX_NAME_LEN {
        anyhow::bail!("name must be 1–{} characters (got {})", inkproto::MAX_NAME_LEN, name.len());
    }
    if !name.chars().all(|c| (' '..='~').contains(&c)) {
        anyhow::bail!("name must be plain ASCII");
    }
    if name.contains([':', '@', '=', '*']) {
        anyhow::bail!("name cannot contain ':', '@', '=' or '*'");
    }
    Ok(())
}

/// Turn a reply's result into an error, including the item that was refused
/// if the device told us.
fn check(result: i16, reply: &[u8]) -> anyhow::Result<()> {
    if result == err::NO_ERR {
        return Ok(());
    }
    let item = Items::of_frame(reply)
        .ok()
        .and_then(|items| items.find(tag::ERROR_TAG))
        .and_then(|i| i.u32())
        .map(|t| format!(" ('{}')", String::from_utf8_lossy(&t.to_be_bytes())));
    let item = item.unwrap_or_default();
    let what = match result {
        err::UNIMPLEMENTED => "the InkTalk does not know this command; its firmware may be older",
        err::PARAM => "the InkTalk refused a value",
        err::BAD_FRAME => "the InkTalk could not read the request",
        err::BUSY => "the InkTalk is printing; try again when the job is done",
        err::FLASH => "the InkTalk could not save its settings",
        err::UNKNOWN_TAG => "the InkTalk does not know a setting",
        err::INTERNAL => "the InkTalk failed to build its reply",
        _ => "the InkTalk reported an error",
    };
    anyhow::bail!("{what}{item} (error {result})")
}

/// Strings on the wire are MacRoman. The device only sends ASCII for now, and
/// we'd rather show anything else oddly than drop it.
fn mac_roman(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
