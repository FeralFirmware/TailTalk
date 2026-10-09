//! Log channel any task can write to; the debug shell prints it. Each line
//! starts with the milliseconds since boot.

use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::channel::Channel;
use heapless::String;

/// Maximum log line length (bytes).
pub const LINE_LEN: usize = 128;

/// Capacity of the channel.
pub const CHANNEL_DEPTH: usize = 32;

pub type LogLine = String<LINE_LEN>;

pub static CHANNEL: Channel<ThreadModeRawMutex, LogLine, CHANNEL_DEPTH> = Channel::new();

/// Format and enqueue a log message with timestamp prefix.
#[macro_export]
macro_rules! tt_log {
    ($($t:tt)*) => {{
        let mut s: $crate::tt_log::LogLine = ::heapless::String::new();
        let ms = ::embassy_time::Instant::now().as_millis();
        let _ = ::core::fmt::Write::write_fmt(&mut s, ::core::format_args!("[{:06}] ", ms));
        let _ = ::core::fmt::Write::write_fmt(&mut s, ::core::format_args!($($t)*));
        let _ = $crate::tt_log::CHANNEL.try_send(s);
    }};
}
