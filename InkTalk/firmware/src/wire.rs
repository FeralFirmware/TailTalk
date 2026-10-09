//! Submitting frames to core 1's CSMA transmit queue.
//!
//! The path from a composed LLAP frame to the wire. Both the AppleTalk stack
//! task and the debug shell submit, so an async mutex gives the static
//! encode buffers a single owner at a time.

use crate::core1::{self, SharedState};
use core::sync::atomic::{compiler_fence, Ordering};
use defmt::warn;
use embassy_sync::blocking_mutex::raw::ThreadModeRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::Timer;
use localtalk::MAX_FRAME_LEN;
use localtalk::hdlc::{build_tx_buffer_into, Fm0Buffer, HdlcBits};
use localtalk::llap::compose_rts;

static TX_LOCK: Mutex<ThreadModeRawMutex, ()> = Mutex::new(());

/// Encode scratch, static because it is far too large for a task stack.
/// TX_LOCK is what gives it a single owner at a time.
static mut TX_HDLC_BUF: HdlcBits = HdlcBits::new();
static mut TX_FM0_BUF: Fm0Buffer = Fm0Buffer::new();

/// Encode an LLAP frame (FCS attached) and queue it for core 1 to send,
/// with its RTS if it is directed. Waits for a free slot.
pub async fn submit_tx(shared: &SharedState, frame: &[u8]) {
    if frame.len() < 5 || frame.len() > MAX_FRAME_LEN {
        warn!("TX: invalid frame len={}", frame.len());
        return;
    }

    let _guard = TX_LOCK.lock().await;

    // Wait for a free slot.
    while !shared.tx_has_space() {
        Timer::after_micros(50).await;
    }

    // SAFETY: TX_LOCK is held, so this is the only user of the buffers, and
    // no await point occurs between here and publishing the slot.
    let fm0_len = unsafe {
        match build_tx_buffer_into(frame, &mut TX_HDLC_BUF, &mut TX_FM0_BUF) {
            Some(len) => len,
            None => {
                warn!("TX: build_tx_buffer failed");
                return;
            }
        }
    };

    let head = shared.tx_head.load(Ordering::Relaxed);
    // SAFETY: tx_has_space above means core 1 is not reading this slot.
    let slot = unsafe { &mut *shared.tx_slots[head as usize % core1::TX_SLOT_COUNT].get() };
    let fm0 = unsafe { &TX_FM0_BUF };
    let word_count = pack_fm0_into_dma_buf(fm0, &mut slot.dma_buf);
    slot.word_count = word_count as u16;
    slot.fm0_len = fm0_len as u16;
    slot.frame_dest = if !frame.is_empty() { frame[0] } else { 0 };
    slot.frame_src = if frame.len() >= 2 { frame[1] } else { 0 };
    let is_directed = frame.len() >= 3 && frame[2] < 0x80 && frame[0] != 0xFF;
    slot.is_directed = is_directed;

    if is_directed {
        let rts = compose_rts(slot.frame_dest, slot.frame_src);
        let rts_ok = unsafe {
            build_tx_buffer_into(&rts, &mut TX_HDLC_BUF, &mut TX_FM0_BUF)
        };
        if let Some(rts_len) = rts_ok {
            let rts_fm0 = unsafe { &TX_FM0_BUF };
            let rts_words = pack_fm0_into_rts_buf(rts_fm0, &mut slot.rts_dma_buf);
            slot.rts_word_count = rts_words as u16;
            slot.rts_fm0_len = rts_len as u16;
        }
    } else {
        slot.rts_word_count = 0;
        slot.rts_fm0_len = 0;
    }

    compiler_fence(Ordering::SeqCst);
    shared.tx_head.store(head.wrapping_add(1), Ordering::Release);
    crate::led::pulse_localtalk_tx();
}

/// [`submit_tx`] for the debug shell, which then waits for the queue to
/// drain so its command can report whether the frame went out.
pub async fn submit_tx_from_debug(shared: &'static SharedState, frame: &[u8]) {
    submit_tx(shared, frame).await;
    let deadline = embassy_time::Instant::now() + embassy_time::Duration::from_secs(2);
    loop {
        let head = shared.tx_head.load(Ordering::Relaxed);
        let tail = shared.tx_tail.load(Ordering::Acquire);
        if head == tail || embassy_time::Instant::now() >= deadline {
            break;
        }
        Timer::after_micros(100).await;
    }
}

/// Pack FM-0 symbols into 32-bit DMA words. Returns word count.
fn pack_fm0_into_dma_buf(fm0: &Fm0Buffer, dma_buf: &mut [u32; core1::TX_DMA_BUF_WORDS]) -> usize {
    let mut count = 0;
    for chunk in fm0.chunks(32) {
        let mut word = 0u32;
        for (i, &bit) in chunk.iter().enumerate() {
            word |= (bit as u32) << i;
        }
        dma_buf[count] = word;
        count += 1;
    }
    count
}

/// Pack FM-0 symbols into the RTS DMA buffer (16 words max). Returns word count.
fn pack_fm0_into_rts_buf(fm0: &Fm0Buffer, rts_buf: &mut [u32; 16]) -> usize {
    let mut count = 0;
    for chunk in fm0.chunks(32) {
        if count >= 16 { break; }
        let mut word = 0u32;
        for (i, &bit) in chunk.iter().enumerate() {
            word |= (bit as u32) << i;
        }
        rts_buf[count] = word;
        count += 1;
    }
    count
}

/// Tell core 1 which node to answer for, or 0 for none. It must stay 0 while
/// the address is still being probed, or core 1 would answer our own ENQs.
pub fn set_node(shared: &SharedState, node: u8) {
    while shared.flags.load(Ordering::Relaxed) & core1::NODE_UPDATED != 0 {
        cortex_m::asm::nop();
    }
    // SAFETY: NODE_UPDATED is clear, so core 1 is not reading.
    unsafe { *shared.node.get() = node };
    compiler_fence(Ordering::SeqCst);
    shared.flags.fetch_or(core1::NODE_UPDATED, Ordering::Release);
}

