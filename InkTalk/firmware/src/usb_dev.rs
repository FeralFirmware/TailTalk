//! The USB device: one CDC-ACM interface carrying the debug shell. Nothing
//! on USB takes part in printing.

use embassy_rp::peripherals::USB;
use embassy_rp::usb::Driver;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config};
use static_cell::StaticCell;

/// Type alias for the concrete CDC-ACM class we hand to consumer tasks.
pub type Cdc = CdcAcmClass<'static, Driver<'static, USB>>;

/// Type alias for the `embassy-usb` device future driven by `usb_run_task`.
pub type UsbDevice = embassy_usb::UsbDevice<'static, Driver<'static, USB>>;

/// USB serial number (flash unique ID, 16 hex chars). Set during `build`.
static mut SERIAL_PTR: Option<&'static str> = None;

/// Get the USB serial number string. Returns "" if called before `build`.
pub fn serial() -> &'static str {
    unsafe { SERIAL_PTR.unwrap_or("") }
}

/// Build the USB device and its CDC class for the debug shell. `uid` is the
/// flash chip's unique ID, used as the serial number so each board gets its
/// own udev symlink.
pub fn build(driver: Driver<'static, USB>, uid: [u8; 8]) -> (UsbDevice, Cdc) {
    static SERIAL_BUF: StaticCell<[u8; 17]> = StaticCell::new();
    let serial: &'static str = {
        let buf = SERIAL_BUF.init([0u8; 17]);
        // Format as 16-char hex string.
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for (i, &b) in uid.iter().enumerate() {
            buf[i * 2] = HEX[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX[(b & 0xF) as usize];
        }
        core::str::from_utf8(&buf[..16]).unwrap()
    };
    unsafe { SERIAL_PTR = Some(serial); }

    // 16C0:27DD is the shared V-USB ID for CDC-ACM devices. The IAD class
    // triplet (EF/02/01) lets Windows bind its CDC driver to the function.
    let mut config = Config::new(0x16c0, 0x27dd);
    config.manufacturer = Some("FeralFirmware");
    config.product = Some("InkTalk");
    config.serial_number = Some(serial);
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    config.device_class = 0xEF;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
    static STATE_DEBUG: StaticCell<State> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 256]),
        CONTROL_BUF.init([0; 64]),
    );

    let class_debug = CdcAcmClass::new(&mut builder, STATE_DEBUG.init(State::new()), 64);

    let usb = builder.build();
    (usb, class_debug)
}
