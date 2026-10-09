//! Persistent configuration in the last flash sector.
//!
//! The W25Q16 is 2 MB; the last 4 KB sector (offset 0x1FF000) holds one
//! 256-byte config block. Saving requires core 1 to be parked in RAM first
//! (see core1.rs PARK_REQUEST), because core 1 otherwise executes from XIP
//! flash and an erase would stall it mid-fetch.
//!
//! Role and baud changes take effect at the next boot; the printer name
//! re-registers live.

use core::sync::atomic::Ordering;

use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Timer;

use crate::core1::{PARKED, PARK_REQUEST, SharedState};

pub const FLASH_SIZE: usize = 2 * 1024 * 1024;
pub const CONFIG_OFFSET: u32 = (FLASH_SIZE - 4096) as u32;
const MAGIC: u32 = 0x496E_6B54; // "InkT"
const VERSION: u8 = 1;
const BLOCK_LEN: usize = 256;

/// Printer port baud rates we accept, whether from a client or the debug
/// shell.
pub const BAUD_RANGE: core::ops::RangeInclusive<u32> = inkproto::BAUD_RANGE;

/// Checks a printer name the way the config wants it: 1-31 bytes, with none
/// of the NBP delimiters or wildcards in it.
pub fn parse_name(name: &str) -> Option<heapless::String<31>> {
    if name.is_empty() || name.contains([':', '@', '=', '*']) {
        return None;
    }
    heapless::String::try_from(name).ok()
}

pub type ConfigFlash = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

pub static FLASH_HANDLE: Mutex<ThreadModeRawMutex, Option<ConfigFlash>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    StyleWriter = 0,
    ImageWriter = 1,
}

impl Role {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Role::StyleWriter),
            1 => Some(Role::ImageWriter),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::StyleWriter => "stylewriter",
            Role::ImageWriter => "imagewriter",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub role: Role,
    /// NBP object name: a Str31, like the adapters we emulate.
    pub name: heapless::String<31>,
    pub baud: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            role: Role::StyleWriter,
            name: heapless::String::try_from("InkTalk").unwrap(),
            // lpstyl drives serial StyleWriters at 57600; the default role
            // is StyleWriter, so default the port to match.
            baud: 57_600,
        }
    }
}

impl Config {
    fn to_block(&self) -> [u8; BLOCK_LEN] {
        let mut b = [0xFFu8; BLOCK_LEN];
        b[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[4] = VERSION;
        b[5] = self.role as u8;
        b[6] = self.name.len() as u8;
        b[7..7 + self.name.len()].copy_from_slice(self.name.as_bytes());
        b[40..44].copy_from_slice(&self.baud.to_le_bytes());
        b
    }

    fn from_block(b: &[u8]) -> Option<Self> {
        if b.len() < BLOCK_LEN || u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != MAGIC {
            return None;
        }
        if b[4] != VERSION {
            return None;
        }
        let role = Role::from_u8(b[5])?;
        let name_len = (b[6] as usize).min(31);
        let name_str = core::str::from_utf8(&b[7..7 + name_len]).ok()?;
        let name = heapless::String::try_from(name_str).ok()?;
        let baud = u32::from_le_bytes([b[40], b[41], b[42], b[43]]);
        if !BAUD_RANGE.contains(&baud) {
            return None;
        }
        Some(Self { role, name, baud })
    }
}

/// The active configuration, loaded once at boot.
pub static ACTIVE: Mutex<ThreadModeRawMutex, Option<Config>> = Mutex::new(None);

/// Load config from flash (falling back to defaults) before the executor
/// starts. Called from main with the flash handle it created.
pub fn load(flash: &mut ConfigFlash) -> Config {
    let mut block = [0u8; BLOCK_LEN];
    match flash.blocking_read(CONFIG_OFFSET, &mut block) {
        Ok(()) => Config::from_block(&block).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// Persist `cfg`: park core 1 in RAM, erase the sector, write, unpark.
pub async fn save(shared: &'static SharedState, cfg: &Config) -> Result<(), &'static str> {
    let mut guard = FLASH_HANDLE.lock().await;
    let flash = guard.as_mut().ok_or("flash not initialised")?;

    // Park core 1 out of XIP.
    shared.flags.fetch_or(PARK_REQUEST, Ordering::Release);
    let deadline = embassy_time::Instant::now() + embassy_time::Duration::from_millis(500);
    while shared.flags.load(Ordering::Acquire) & PARKED == 0 {
        if embassy_time::Instant::now() >= deadline {
            shared.flags.fetch_and(!PARK_REQUEST, Ordering::Release);
            return Err("core 1 did not park");
        }
        Timer::after_micros(50).await;
    }

    let block = cfg.to_block();
    let result = flash
        .blocking_erase(CONFIG_OFFSET, CONFIG_OFFSET + 4096)
        .and_then(|()| flash.blocking_write(CONFIG_OFFSET, &block))
        .map_err(|_| "flash write failed");

    shared.flags.fetch_and(!PARK_REQUEST, Ordering::Release);
    result
}
