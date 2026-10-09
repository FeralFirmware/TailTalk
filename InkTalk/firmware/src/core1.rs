//! Core 1 - bare-metal wire engine: PIO FM-0 decode from a DMA ring,
//! ENQ->ACK and RTS->CTS auto-replies, and CSMA/CA transmission with the
//! RTS/CTS/DATA dialog.
//!
//! Frames pass between the cores through two small rings:
//!
//! - `rx_slots`, 4 deep: core 1 writes `rx_head`, core 0 writes `rx_tail`.
//!   An ATP burst arrives about one inter-frame gap apart, faster than core
//!   0 can always take frames one at a time.
//! - `tx_slots`, 2 deep: core 0 writes `tx_head`, core 1 writes `tx_tail`,
//!   so the stack can queue the next frame while one goes out.
//!
//! Core 1 runs from XIP flash, so core 0 must not erase or program flash
//! while it runs. Setting PARK_REQUEST makes core 1 spin in a RAM-resident
//! loop and raise PARKED until core 0 clears the request.

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::sync::atomic::{compiler_fence, Ordering};

use embassy_rp::pac;
use embassy_rp::pac::dma::vals::{DataSize, TreqSel};
use portable_atomic::AtomicU32;
use localtalk::backoff::BackoffState;
use localtalk::bitstuff::{BitUnstuffer, UnstuffEvent, FLAG};
use localtalk::MAX_FRAME_LEN;
use localtalk::crc::CrcCalculator;
use localtalk::fm0::Fm0Encoder;
use localtalk::llap::{auto_reply, cts_matches_pending, frame_crc_ok, AsmEvent, FrameAssembler};

// ── Atomic flag bits ───────────────────────────────────────────────
/// Core 0 has written a new node for the auto-reply engine.
pub const NODE_UPDATED: u32 = 1 << 4;
pub const CORE1_ALIVE: u32   = 1 << 5;
/// Core 0 wants core 1 parked in RAM (flash op pending).
pub const PARK_REQUEST: u32  = 1 << 6;
/// Core 1 acknowledges it is parked.
pub const PARKED: u32        = 1 << 7;

// ── Queue depths ─────────────────────────────────────────────────
pub const RX_SLOT_COUNT: usize = 4;
pub const TX_SLOT_COUNT: usize = 2;

// ── Hardware constants ───────────────────────────────────────────
const DE_PIN: u32 = 3;
const DBG0_PIN: u32 = 6;
const DBG1_PIN: u32 = 7;
const TX_DMA_CH: usize = 1;
const RX_DMA_CH: usize = 0;
const DREQ_PIO0_TX0: u8 = 0;
const DREQ_PIO1_RX0: u8 = 12;

// ── RX DMA ring buffer ───────────────────────────────────────────
const RX_RING_SIZE: usize = 4096;
const RX_RING_MASK: usize = RX_RING_SIZE - 1;
#[repr(C, align(16384))] // 4096 * 4 = 16KB
pub struct RxRingBuf(pub [u32; RX_RING_SIZE]);
pub static mut RX_RING: RxRingBuf = RxRingBuf([0u32; RX_RING_SIZE]);
static mut RX_READ_IDX: usize = 0;

// ── Debug counters (core 1 writes, core 0 reads; approximate) ─────
pub static mut LAST_BAD_FRAME: [u8; 8] = [0u8; 8];
pub static mut LAST_BAD_LEN: u16 = 0;
pub static mut BAD_CRC_COUNT: u32 = 0;
pub static mut GOOD_CRC_COUNT: u32 = 0;
pub static mut AUTOREPLY_COUNT: u32 = 0;
/// Auto-replies we dropped because the line didn't go quiet in time.
pub static mut AUTOREPLY_LATE: u32 = 0;
/// The longest we've waited between a closing flag and the line going
/// quiet before sending a reply.
pub static mut AUTOREPLY_WAIT_MAX_US: u32 = 0;
pub static mut LAST_GOOD_FRAME: [u8; 8] = [0u8; 8];
pub static mut LAST_GOOD_LEN: u16 = 0;
pub static mut BAD_REAL_COUNT: u32 = 0;
pub static mut LOOP_COUNT: u32 = 0;
pub static mut RING_OVERRUN_COUNT: u32 = 0;
pub static mut DIRECTED_TX_ATTEMPTS: u32 = 0;
pub static mut DIRECTED_TX_CTS_OK: u32 = 0;
pub static mut DIRECTED_TX_TIMEOUT: u32 = 0;
pub static mut LAST_CTS_WAIT_START: u64 = 0;
pub static mut LAST_CTS_WAIT_END: u64 = 0;
pub static mut LAST_CTS_ENTRIES: u32 = 0;
pub static mut DIRECTED_RX_COUNT: u32 = 0;
pub static mut ECHO_SKIP_COUNT: u32 = 0;
/// Frames dropped because the RX slot ring was full.
pub static mut RX_DROP_COUNT: u32 = 0;
/// Low 32 bits of the microsecond timer, stamped by core 1 while it makes
/// progress: core 1's liveness signal for the watchdog. It is stamped
/// inside the long waits too, since one pass of the main loop can spend a
/// whole CSMA backoff and RTS/CTS dialog in `csma_transmit`.
pub static CORE1_HEARTBEAT: AtomicU32 = AtomicU32::new(0);

/// Stamp the heartbeat. Cheap enough to call in tight polling loops.
#[inline(always)]
fn beat() {
    CORE1_HEARTBEAT.store(read_timer_us() as u32, Ordering::Relaxed);
}
/// CSMA transmissions that exhausted their backoff budget.
pub static mut TX_FAIL_COUNT: u32 = 0;
/// Times `wait_bus_idle` gave up waiting for a quiet bus.
pub static mut BUS_IDLE_TIMEOUTS: u32 = 0;

/// Longest core 1 will wait for the carrier to fall idle before pressing on
/// and letting backoff sort it out.
const MAX_BUS_IDLE_WAIT_US: u64 = 500_000;

pub fn clear_counters() {
    unsafe {
        GOOD_CRC_COUNT = 0;
        BAD_CRC_COUNT = 0;
        AUTOREPLY_COUNT = 0;
        AUTOREPLY_LATE = 0;
        AUTOREPLY_WAIT_MAX_US = 0;
        LAST_GOOD_LEN = 0;
        LAST_GOOD_FRAME = [0u8; 8];
        LAST_BAD_LEN = 0;
        LAST_BAD_FRAME = [0u8; 8];
        BAD_REAL_COUNT = 0;
        RING_OVERRUN_COUNT = 0;
        DIRECTED_TX_ATTEMPTS = 0;
        DIRECTED_TX_CTS_OK = 0;
        DIRECTED_TX_TIMEOUT = 0;
        DIRECTED_RX_COUNT = 0;
        ECHO_SKIP_COUNT = 0;
        RX_DROP_COUNT = 0;
        TX_FAIL_COUNT = 0;
        BUS_IDLE_TIMEOUTS = 0;
    }
}

// ── DMA buffers (core 1 exclusive) ────────────────────────────────
pub const TX_DMA_BUF_WORDS: usize = 512;
static mut AUTOREPLY_DMA_BUF: [u32; 16] = [0u32; 16];

// ── RX constants ──────────────────────────────────────────────────
const FRAME_END_MARKER: u32 = 0xFFFF_FFFF;

static mut LAST_ACTIVITY_US: u64 = 0;
const CARRIER_IDLE_US: u64 = 50;

/// How long after a frame's closing flag we can still send its auto-reply.
///
/// The sender keeps driving the line for its abort sequence (12-18 one bits,
/// up to ~78 us) after the closing flag, so we hold the reply until the line
/// goes quiet. Inside AppleTalk gives the responder 200 us. If the line is
/// still busy after that it's probably someone else's frame, and the sender
/// will retry anyway.
const REPLY_WINDOW_US: u64 = 200;

/// How long to wait for a peer's CTS to begin arriving after our RTS.
///
/// Inside AppleTalk gives the responder 200 us to answer an RTS; the extra
/// margin covers decode latency at both ends. Once any activity is seen the
/// deadline is extended (see `directed_tx`) so the whole frame can arrive.
const CTS_START_WINDOW_US: u64 = 400;

// ── Shared state ───────────────────────────────────────────────────

/// Pre-encoded frame for CSMA TX, written by core 0, read by core 1.
#[repr(C)]
pub struct TxSlot {
    pub dma_buf: [u32; TX_DMA_BUF_WORDS],
    pub word_count: u16,
    pub fm0_len: u16,
    pub rts_dma_buf: [u32; 16],
    pub rts_word_count: u16,
    pub rts_fm0_len: u16,
    pub frame_dest: u8,
    pub frame_src: u8,
    pub is_directed: bool,
}

impl TxSlot {
    pub const fn empty() -> Self {
        Self {
            dma_buf: [0u32; TX_DMA_BUF_WORDS],
            word_count: 0,
            fm0_len: 0,
            rts_dma_buf: [0u32; 16],
            rts_word_count: 0,
            rts_fm0_len: 0,
            frame_dest: 0,
            frame_src: 0,
            is_directed: false,
        }
    }
}

/// Received frame, written by core 1, read by core 0.
#[repr(C)]
pub struct RxSlot {
    pub buf: [u8; MAX_FRAME_LEN],
    pub len: u16,
    /// 0=good, 1=bad_crc
    pub status: u8,
}

impl RxSlot {
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; MAX_FRAME_LEN],
            len: 0,
            status: 0,
        }
    }
}

/// Shared state between core 0 and core 1.
///
/// Ring index protocol: `head` is only written by the producer, `tail` only
/// by the consumer; both are free-running and compared modulo the ring
/// length. A slot is written before its index is published (Release), and
/// read after observing the index (Acquire).
#[repr(C, align(32))]
pub struct SharedState {
    // Core 0 writes slots + head; core 1 reads slots + writes tail.
    pub tx_slots: [UnsafeCell<TxSlot>; TX_SLOT_COUNT],
    pub tx_head: AtomicU32,
    pub tx_tail: AtomicU32,

    // Core 1 writes slots + head; core 0 reads slots + writes tail.
    pub rx_slots: [UnsafeCell<RxSlot>; RX_SLOT_COUNT],
    pub rx_head: AtomicU32,
    pub rx_tail: AtomicU32,

    /// The one node this board answers for, 0 while none is claimed. Core 0
    /// writes, core 1 reads, synchronized by [`NODE_UPDATED`].
    pub node: UnsafeCell<u8>,

    // Both cores (atomic).
    pub flags: AtomicU32,
}

unsafe impl Sync for SharedState {}

impl SharedState {
    pub const fn new() -> Self {
        Self {
            tx_slots: [
                UnsafeCell::new(TxSlot::empty()),
                UnsafeCell::new(TxSlot::empty()),
            ],
            tx_head: AtomicU32::new(0),
            tx_tail: AtomicU32::new(0),
            rx_slots: [
                UnsafeCell::new(RxSlot::empty()),
                UnsafeCell::new(RxSlot::empty()),
                UnsafeCell::new(RxSlot::empty()),
                UnsafeCell::new(RxSlot::empty()),
            ],
            rx_head: AtomicU32::new(0),
            rx_tail: AtomicU32::new(0),
            node: UnsafeCell::new(0),
            flags: AtomicU32::new(0),
        }
    }

    /// Core 0 side: whether the TX ring has room for another frame.
    pub fn tx_has_space(&self) -> bool {
        let head = self.tx_head.load(Ordering::Relaxed);
        let tail = self.tx_tail.load(Ordering::Acquire);
        head.wrapping_sub(tail) < TX_SLOT_COUNT as u32
    }

    /// Core 0 side: pop one received frame, if available. The closure runs
    /// with the slot borrowed; the index is released afterwards.
    pub fn with_rx<R>(&self, f: impl FnOnce(&RxSlot) -> R) -> Option<R> {
        let tail = self.rx_tail.load(Ordering::Relaxed);
        let head = self.rx_head.load(Ordering::Acquire);
        if tail == head {
            return None;
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: tail != head means core 1 has published this slot and
        // will not rewrite it until we advance rx_tail.
        let slot = unsafe { &*self.rx_slots[tail as usize % RX_SLOT_COUNT].get() };
        let r = f(slot);
        compiler_fence(Ordering::SeqCst);
        self.rx_tail.store(tail.wrapping_add(1), Ordering::Release);
        Some(r)
    }
}

/// Core 1 side: push a received frame into the RX ring, dropping when full.
fn push_rx(shared: &SharedState, frame: &[u8], crc_ok: bool) {
    let head = shared.rx_head.load(Ordering::Relaxed);
    let tail = shared.rx_tail.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RX_SLOT_COUNT as u32 {
        unsafe { RX_DROP_COUNT += 1; }
        return;
    }
    let n = frame.len().min(MAX_FRAME_LEN);
    // SAFETY: the slot at head is not visible to core 0 until rx_head is
    // advanced below.
    let slot = unsafe { &mut *shared.rx_slots[head as usize % RX_SLOT_COUNT].get() };
    slot.buf[..n].copy_from_slice(&frame[..n]);
    slot.len = n as u16;
    slot.status = if crc_ok { 0 } else { 1 };
    compiler_fence(Ordering::SeqCst);
    shared.rx_head.store(head.wrapping_add(1), Ordering::Release);
}

// ── RX via DMA ring buffer ────────────────────────────────────────

fn init_rx_dma() {
    let ch = pac::DMA.ch(RX_DMA_CH);
    ch.ctrl_trig().write(|w| w.set_en(false));
    ch.read_addr().write_value(pac::PIO1.rxf(0).as_ptr() as u32);
    ch.write_addr().write_value(unsafe { RX_RING.0.as_ptr() } as u32);
    ch.trans_count().write_value(0xFFFF_FFFF);
    compiler_fence(Ordering::SeqCst);
    ch.ctrl_trig().write(|w| {
        w.set_treq_sel(TreqSel(DREQ_PIO1_RX0));
        w.set_data_size(DataSize::SIZE_WORD);
        w.set_incr_read(false);
        w.set_incr_write(true);
        w.set_ring_sel(true);
        w.set_ring_size(14); // 2^14 = 16384 bytes = 4096 u32 entries
        w.set_chain_to(RX_DMA_CH as u8);
        w.set_en(true);
    });
    compiler_fence(Ordering::SeqCst);
}

#[inline(always)]
fn try_read_rx() -> Option<u32> {
    let write_addr = pac::DMA.ch(RX_DMA_CH).write_addr().read() as usize;
    let base = unsafe { RX_RING.0.as_ptr() } as usize;
    let write_idx = (write_addr.wrapping_sub(base)) / 4;

    let read_idx = unsafe { RX_READ_IDX };
    if read_idx == write_idx {
        return None;
    }

    let distance = (write_idx.wrapping_sub(read_idx)) & RX_RING_MASK;
    if distance > RX_RING_SIZE / 2 {
        unsafe {
            RING_OVERRUN_COUNT += 1;
            RX_READ_IDX = write_idx;
        }
        return None;
    }

    let val = unsafe { core::ptr::read_volatile(&RX_RING.0[read_idx]) };
    unsafe { RX_READ_IDX = (read_idx + 1) & RX_RING_MASK; }
    Some(val)
}

pub fn rx_dma_diag() -> (u32, u32, u32, bool, u32) {
    let ch = pac::DMA.ch(RX_DMA_CH);
    let base = unsafe { RX_RING.0.as_ptr() } as u32;
    let waddr = ch.write_addr().read();
    let ridx = unsafe { RX_READ_IDX } as u32;
    let en = ch.ctrl_trig().read().en();
    let remain = ch.trans_count().read();
    (base, waddr, ridx, en, remain)
}

// ── PAC: TX (PIO0 SM0 + DMA + DE) ────────────────────────────────

#[inline(always)]
fn set_de(high: bool) {
    if high {
        pac::SIO.gpio_out(0).value_set().write_value(1 << DE_PIN);
    } else {
        pac::SIO.gpio_out(0).value_clr().write_value(1 << DE_PIN);
    }
}

#[inline(always)]
fn carrier_sense_active() -> bool {
    let now = read_timer_us();
    let last = unsafe { LAST_ACTIVITY_US };
    now.wrapping_sub(last) < CARRIER_IDLE_US
}

#[inline(always)]
fn mark_activity() {
    unsafe { LAST_ACTIVITY_US = read_timer_us(); }
}

fn enable_pio0_sm0() {
    pac::PIO0.ctrl().modify(|w| {
        w.set_sm_enable(w.sm_enable() | 1);
    });
}

fn disable_pio0_sm0() {
    pac::PIO0.ctrl().modify(|w| {
        w.set_sm_enable(w.sm_enable() & !1);
    });
}

fn restart_pio0_sm0() {
    pac::PIO0.ctrl().modify(|w| {
        w.set_sm_restart(1);
    });
}

fn pio0_tx_fifo_empty() -> bool {
    pac::PIO0.fstat().read().txempty() & 1 != 0
}

fn start_tx_dma(read_addr: *const u32, word_count: usize) {
    let ch = pac::DMA.ch(TX_DMA_CH);
    ch.ctrl_trig().write(|w| w.set_en(false));
    ch.read_addr().write_value(read_addr as u32);
    ch.write_addr().write_value(pac::PIO0.txf(0).as_ptr() as u32);
    ch.trans_count().write_value(word_count as u32);
    compiler_fence(Ordering::SeqCst);
    ch.ctrl_trig().write(|w| {
        w.set_treq_sel(TreqSel(DREQ_PIO0_TX0));
        w.set_data_size(DataSize::SIZE_WORD);
        w.set_incr_read(true);
        w.set_incr_write(false);
        w.set_chain_to(TX_DMA_CH as u8);
        w.set_en(true);
    });
    compiler_fence(Ordering::SeqCst);
}

fn wait_tx_dma() {
    let ch = pac::DMA.ch(TX_DMA_CH);
    let deadline = read_timer_us() + 500_000;
    while ch.ctrl_trig().read().busy() {
        if read_timer_us() >= deadline {
            ch.ctrl_trig().write(|w| w.set_en(false));
            return;
        }
    }
}

fn abort_tx_dma() {
    pac::DMA.ch(TX_DMA_CH).ctrl_trig().write(|w| w.set_en(false));
}

fn transmit_dma(read_addr: *const u32, word_count: usize, fm0_len: usize) {
    set_de(true);
    cortex_m::asm::delay(625); // ~5 us settle

    start_tx_dma(read_addr, word_count);
    enable_pio0_sm0();

    wait_tx_dma();

    let drain_deadline = read_timer_us() + 500_000;
    while !pio0_tx_fifo_empty() {
        if read_timer_us() >= drain_deadline { break; }
    }

    let last_bits = fm0_len % 32;
    let last_bits = if last_bits == 0 { 32 } else { last_bits };
    busy_wait_us((last_bits as u64 + 2) * 3);

    disable_pio0_sm0();
    abort_tx_dma();
    restart_pio0_sm0();

    set_de(false);
}

/// Build HDLC + FM-0 for a small control frame (5 bytes with CRC).
fn build_small_frame_dma(frame: &[u8; 5]) -> (usize, usize) {
    let mut bits = [0u8; 256];
    let mut bpos = 0;

    macro_rules! push_bit {
        ($b:expr) => { bits[bpos] = $b; bpos += 1; }
    }

    for _ in 0..2 {
        for i in 0..8 {
            push_bit!((FLAG >> i) & 1);
        }
    }

    let mut crc = CrcCalculator::new();
    let mut ones_count = 0u8;
    for &byte in frame.iter() {
        crc.feed_byte(byte);
        for i in 0..8 {
            let bit = (byte >> i) & 1;
            push_bit!(bit);
            if bit == 1 {
                ones_count += 1;
                if ones_count == 5 {
                    push_bit!(0);
                    ones_count = 0;
                }
            } else {
                ones_count = 0;
            }
        }
    }

    for i in 0..8 {
        push_bit!((FLAG >> i) & 1);
    }

    for _ in 0..16 {
        push_bit!(1);
    }

    let mut enc = Fm0Encoder::new();
    let mut fm0_count = 0usize;
    let mut word_count = 0usize;
    let mut current_word = 0u32;
    let mut bit_in_word = 0;

    for &bit in &bits[..bpos] {
        let (boundary, mid) = enc.encode_bit(bit);
        for &sym in &[boundary, mid] {
            current_word |= (sym as u32) << bit_in_word;
            bit_in_word += 1;
            fm0_count += 1;
            if bit_in_word == 32 {
                unsafe { AUTOREPLY_DMA_BUF[word_count] = current_word; }
                word_count += 1;
                current_word = 0;
                bit_in_word = 0;
            }
        }
    }
    if bit_in_word > 0 {
        unsafe { AUTOREPLY_DMA_BUF[word_count] = current_word; }
        word_count += 1;
    }

    (word_count, fm0_count)
}

// ── Debug GPIO ────────────────────────────────────────────────────

fn init_debug_gpio() {
    let pads = pac::PADS_BANK0;
    let io = pac::IO_BANK0;
    for pin in [DBG0_PIN, DBG1_PIN] {
        pads.gpio(pin as usize).modify(|w| { w.set_ie(true); w.set_od(false); });
        io.gpio(pin as usize).ctrl().write(|w| w.set_funcsel(5));
        pac::SIO.gpio_oe(0).value_set().write_value(1 << pin);
        pac::SIO.gpio_out(0).value_clr().write_value(1 << pin);
    }
}

#[inline(always)]
fn dbg0_high() { pac::SIO.gpio_out(0).value_set().write_value(1 << DBG0_PIN); }
#[inline(always)]
fn dbg0_low() { pac::SIO.gpio_out(0).value_clr().write_value(1 << DBG0_PIN); }

// ── Timer ─────────────────────────────────────────────────────────

#[inline(always)]
fn read_timer_us() -> u64 {
    let timer = pac::TIMER;
    let lo = timer.timelr().read() as u64;
    let hi = timer.timehr().read() as u64;
    (hi << 32) | lo
}

fn busy_wait_us(us: u64) {
    let start = read_timer_us();
    while read_timer_us() - start < us {
        cortex_m::asm::nop();
    }
}

// ── Flash-op parking ──────────────────────────────────────────────

/// Spin in RAM while core 0 erases/programs flash. Placed in .data so no
/// instruction fetch touches XIP; the atomic load compiles to a plain
/// in-RAM ldr on thumbv6m.
#[unsafe(link_section = ".data.core1_park")]
#[inline(never)]
fn park_in_ram(flags: &AtomicU32) {
    flags.fetch_or(PARKED, Ordering::Release);
    while flags.load(Ordering::Acquire) & PARK_REQUEST != 0 {
        cortex_m::asm::nop();
    }
    flags.fetch_and(!PARKED, Ordering::Release);
}

/// Core 1's heartbeat, for the watchdog on core 0.
pub fn heartbeat_us() -> u32 {
    CORE1_HEARTBEAT.load(Ordering::Relaxed)
}

/// The same microsecond clock core 1 stamps with, readable from core 0.
pub fn timer_us() -> u64 {
    read_timer_us()
}

// ── Receive engine ────────────────────────────────────────────────

/// An auto-reply that's been encoded into AUTOREPLY_DMA_BUF and is waiting
/// for the line to go quiet.
struct PendingReply {
    word_count: usize,
    fm0_len: usize,
    /// When we decoded the closing flag of the frame this is answering.
    since: u64,
}

/// Decodes the RX ring into frames and answers ENQs and RTSes. The main loop
/// owns it and hands it to the CSMA waits as well, so we keep decoding and
/// answering frames even while we're waiting to transmit.
struct RxEngine {
    unstuffer: BitUnstuffer,
    assembler: FrameAssembler,
    our_node: u8,
    frames_seen: u32,
    pending: Option<PendingReply>,
}

impl RxEngine {
    fn new() -> Self {
        Self {
            unstuffer: BitUnstuffer::new(),
            assembler: FrameAssembler::new(),
            our_node: 0,
            frames_seen: 0,
            pending: None,
        }
    }

    /// Decode everything waiting in the RX ring.
    fn service(&mut self, shared: &SharedState) {
        while let Some(word) = try_read_rx() {
            self.feed(word, shared);
        }
        self.expire_pending();
    }

    fn feed(&mut self, word: u32, shared: &SharedState) {
        if word == FRAME_END_MARKER {
            if let Some(AsmEvent::FrameEnd) = self.assembler.feed_flag() {
                self.frame_end(shared);
                self.assembler.ack_frame_end();
            }
            self.unstuffer.reset();
            self.assembler.feed_abort();
            // The PIO pushes this ~1.75 cells after the last transition, so by
            // now the sender has finished and let go of the line.
            self.send_pending();
            return;
        }

        mark_activity();
        let byte = ((word >> 24) & 0xFF) as u8;
        for bit_idx in 0..8u32 {
            let bit = (byte >> bit_idx) & 1;
            match self.unstuffer.feed_bit(bit) {
                UnstuffEvent::Byte(b) => {
                    self.assembler.feed_byte(b);
                }
                UnstuffEvent::Flag => {
                    if let Some(AsmEvent::FrameEnd) = self.assembler.feed_flag() {
                        self.frame_end(shared);
                        self.assembler.ack_frame_end();
                    }
                }
                UnstuffEvent::Abort => {
                    self.assembler.feed_abort();
                    self.unstuffer.reset();
                }
                UnstuffEvent::None => {}
            }
        }
    }

    fn frame_end(&mut self, shared: &SharedState) {
        let our_node = self.our_node;
        self.frames_seen = self.frames_seen.wrapping_add(1);
        let frame = self.assembler.current();
        let crc_ok = frame_crc_ok(frame);

        let analyzer = crate::debug::ANALYZER_MODE.load(Ordering::Relaxed);

        let is_echo = frame.len() >= 2 && frame[1] == our_node && our_node != 0;
        if is_echo && !analyzer {
            unsafe { ECHO_SKIP_COUNT += 1; }
            return;
        }

        if !frame.is_empty() && frame[0] == our_node && our_node != 0 {
            unsafe { DIRECTED_RX_COUNT += 1; }
        }

        if crc_ok {
            unsafe {
                GOOD_CRC_COUNT += 1;
                LAST_GOOD_LEN = frame.len() as u16;
                let n = frame.len().min(8);
                LAST_GOOD_FRAME = [0u8; 8];
                LAST_GOOD_FRAME[..n].copy_from_slice(&frame[..n]);
            }
        } else {
            unsafe {
                BAD_CRC_COUNT += 1;
                if frame.len() > 5 { BAD_REAL_COUNT += 1; }
                LAST_BAD_LEN = frame.len() as u16;
                let n = frame.len().min(8);
                LAST_BAD_FRAME = [0u8; 8];
                LAST_BAD_FRAME[..n].copy_from_slice(&frame[..n]);
            }
        }

        let reply = if crc_ok {
            auto_reply(frame, our_node).into_frame()
        } else {
            None
        };

        if crc_ok || analyzer {
            push_rx(shared, frame, crc_ok);
        }

        // Encode it now while the sender is still on its abort sequence, so
        // all we have left to do once the line goes quiet is start the DMA.
        if let Some(reply_frame) = reply {
            let (word_count, fm0_len) = build_small_frame_dma(&reply_frame);
            self.pending = Some(PendingReply {
                word_count,
                fm0_len,
                since: read_timer_us(),
            });
        }
    }

    fn send_pending(&mut self) {
        let Some(p) = self.pending.take() else { return };
        let waited = read_timer_us().wrapping_sub(p.since);
        if waited > REPLY_WINDOW_US {
            unsafe { AUTOREPLY_LATE += 1; }
            return;
        }
        transmit_dma(unsafe { AUTOREPLY_DMA_BUF.as_ptr() }, p.word_count, p.fm0_len);
        // Count our own reply as bus activity, so the silence a CSMA wait
        // needs is measured from the end of it. Our echo only comes back if
        // the connector box joins the pairs, so it can't be relied on.
        mark_activity();
        unsafe {
            AUTOREPLY_COUNT += 1;
            AUTOREPLY_WAIT_MAX_US = AUTOREPLY_WAIT_MAX_US.max(waited as u32);
        }
    }

    /// Drop the reply if its window closed before the line went quiet.
    fn expire_pending(&mut self) {
        if let Some(p) = &self.pending
            && read_timer_us().wrapping_sub(p.since) > REPLY_WINDOW_US
        {
            self.pending = None;
            unsafe { AUTOREPLY_LATE += 1; }
        }
    }
}

// ── CSMA/CA helpers ───────────────────────────────────────────────

/// Wait for the bus to go idle, but never forever: a transceiver fault or
/// a jabbering peer would otherwise pin core 1 in this loop with no way
/// out. On timeout we return anyway and let the CSMA backoff handle the
/// collision, which is a far better failure mode than a wedged core.
fn wait_bus_idle(rx: &mut RxEngine, shared: &SharedState) {
    let deadline = read_timer_us() + MAX_BUS_IDLE_WAIT_US;
    while carrier_sense_active() {
        beat();
        rx.service(shared);
        if read_timer_us() >= deadline {
            unsafe { BUS_IDLE_TIMEOUTS += 1; }
            return;
        }
    }
}

/// Wait for `us` of silence, decoding and answering anything that arrives
/// in the meantime.
fn wait_idle_for(us: u64, rx: &mut RxEngine, shared: &SharedState) -> bool {
    let deadline = read_timer_us() + us;
    while read_timer_us() < deadline {
        beat();
        rx.service(shared);
        if carrier_sense_active() || rx.pending.is_some() {
            return false;
        }
    }
    rx.service(shared);
    !carrier_sense_active() && rx.pending.is_none()
}

fn csma_transmit(shared: &SharedState, slot: &TxSlot, backoff: &mut BackoffState, rx: &mut RxEngine) -> bool {
    if slot.is_directed {
        return directed_tx(shared, slot, backoff, rx);
    }

    backoff.prep_for_next_frame();

    loop {
        if backoff.exhausted() {
            return false;
        }

        wait_bus_idle(rx, shared);

        let entropy = (read_timer_us() as u8)
            ^ ((read_timer_us() >> 8) as u8);
        let delay_units = backoff.next_backoff_units(entropy);
        // next_backoff_units already includes the 400 us inter-dialog gap.
        let delay_us = delay_units as u64 * 100;
        if !wait_idle_for(delay_us, rx, shared) {
            backoff.record_deferral();
            backoff.consume_attempt();
            continue;
        }

        transmit_dma(
            slot.dma_buf.as_ptr(),
            slot.word_count as usize,
            slot.fm0_len as usize,
        );
        return true;
    }
}

fn directed_tx(
    shared: &SharedState,
    slot: &TxSlot,
    backoff: &mut BackoffState,
    rx: &mut RxEngine,
) -> bool {
    let our_src = slot.frame_src;
    let their_dest = slot.frame_dest;

    unsafe { DIRECTED_TX_ATTEMPTS += 1; }
    backoff.prep_for_next_frame();

    loop {
        if backoff.exhausted() {
            return false;
        }

        wait_bus_idle(rx, shared);

        let entropy = (read_timer_us() as u8)
            ^ ((read_timer_us() >> 8) as u8);
        let delay_units = backoff.next_backoff_units(entropy);
        // next_backoff_units already includes the 400 us inter-dialog gap.
        let delay_us = delay_units as u64 * 100;
        if !wait_idle_for(delay_us, rx, shared) {
            backoff.record_deferral();
            backoff.consume_attempt();
            continue;
        }

        transmit_dma(
            slot.rts_dma_buf.as_ptr(),
            slot.rts_word_count as usize,
            slot.rts_fm0_len as usize,
        );

        // Listen for the CTS straight away: it is due within 200 us. If our
        // own RTS echoes back, cts_matches_pending rejects it.
        let cts_wait_start = read_timer_us();
        // Window for the CTS to START arriving. The spec allows the peer
        // 200 us; this adds margin for its decode latency and ours, and
        // still expires long before the peer would give up and retry.
        let mut cts_deadline = cts_wait_start + CTS_START_WINDOW_US;
        let mut saw_activity = false;
        let mut cts_unstuffer = BitUnstuffer::new();
        let mut cts_assembler = FrameAssembler::new();
        let mut got_cts = false;
        let mut entries_processed: u32 = 0;

        unsafe { LAST_CTS_WAIT_START = cts_wait_start; }

        loop {
            beat();
            if read_timer_us() > cts_deadline {
                break;
            }

            match try_read_rx() {
                Some(FRAME_END_MARKER) => {
                    if let Some(AsmEvent::FrameEnd) = cts_assembler.feed_flag() {
                        let frame = cts_assembler.current();
                        if frame_crc_ok(frame)
                            && cts_matches_pending(frame, our_src, their_dest)
                        {
                            push_rx(shared, frame, true);
                            got_cts = true;
                            unsafe { DIRECTED_TX_CTS_OK += 1; }
                        }
                        cts_assembler.ack_frame_end();
                    }
                    cts_unstuffer.reset();
                }
                Some(word) => {
                    entries_processed += 1;
                    if !saw_activity {
                        saw_activity = true;
                        cts_deadline = read_timer_us() + 600;
                    }
                    let byte = ((word >> 24) & 0xFF) as u8;
                    for bit_idx in 0..8u32 {
                        let bit = (byte >> bit_idx) & 1;
                        match cts_unstuffer.feed_bit(bit) {
                            UnstuffEvent::Byte(b) => {
                                cts_assembler.feed_byte(b);
                            }
                            UnstuffEvent::Flag => {
                                if let Some(AsmEvent::FrameEnd) = cts_assembler.feed_flag() {
                                    let frame = cts_assembler.current();
                                    if frame_crc_ok(frame)
                                        && cts_matches_pending(frame, our_src, their_dest)
                                    {
                                        push_rx(shared, frame, true);
                                        got_cts = true;
                                        unsafe { DIRECTED_TX_CTS_OK += 1; }
                                    }
                                    cts_assembler.ack_frame_end();
                                }
                            }
                            UnstuffEvent::Abort => {
                                cts_assembler.feed_abort();
                                cts_unstuffer.reset();
                            }
                            UnstuffEvent::None => {}
                        }
                    }
                }
                None => {}
            }

            if got_cts {
                break;
            }
        }

        unsafe {
            LAST_CTS_WAIT_END = read_timer_us();
            LAST_CTS_ENTRIES = entries_processed;
        }

        if got_cts {
            if slot.fm0_len > 1000 {
                dbg0_high();
            }
            transmit_dma(
                slot.dma_buf.as_ptr(),
                slot.word_count as usize,
                slot.fm0_len as usize,
            );
            dbg0_low();
            return true;
        }

        unsafe { DIRECTED_TX_TIMEOUT += 1; }
        backoff.record_collision();
        backoff.consume_attempt();
    }
}

// ── Core 1 entry point ─────────────────────────────────────────────

pub fn core1_main(shared: &'static SharedState) -> ! {
    init_debug_gpio();
    init_rx_dma();

    shared.flags.fetch_or(CORE1_ALIVE, Ordering::Release);
    compiler_fence(Ordering::SeqCst);

    let mut rx = RxEngine::new();
    let mut backoff = BackoffState::new();

    loop {
        unsafe { LOOP_COUNT = LOOP_COUNT.wrapping_add(1); }
        beat();

        let flags = shared.flags.load(Ordering::Relaxed);

        if flags & PARK_REQUEST != 0 {
            park_in_ram(&shared.flags);
        }

        if flags & NODE_UPDATED != 0 {
            compiler_fence(Ordering::SeqCst);
            // SAFETY: NODE_UPDATED set means core 0 finished writing.
            rx.our_node = unsafe { *shared.node.get() };
            shared.flags.fetch_and(!NODE_UPDATED, Ordering::Release);
        }

        match try_read_rx() {
            Some(word) => rx.feed(word, shared),
            None => {
                rx.expire_pending();
                // ── FIFO empty: drain the TX queue ────────────────
                // Hold off while a reply is waiting for the line to go quiet.
                // It goes out within REPLY_WINDOW_US at most, and a CSMA wait
                // would just get deferred by it anyway.
                let tail = shared.tx_tail.load(Ordering::Relaxed);
                let head = shared.tx_head.load(Ordering::Acquire);
                if tail != head && rx.pending.is_none() {
                    compiler_fence(Ordering::SeqCst);
                    // SAFETY: tail != head means core 0 published this
                    // slot and will not rewrite it until tx_tail advances.
                    let slot = unsafe { &*shared.tx_slots[tail as usize % TX_SLOT_COUNT].get() };
                    let ok = csma_transmit(shared, slot, &mut backoff, &mut rx);
                    if !ok {
                        unsafe { TX_FAIL_COUNT += 1; }
                    }
                    compiler_fence(Ordering::SeqCst);
                    shared.tx_tail.store(tail.wrapping_add(1), Ordering::Release);
                }
            }
        }
    }
}
