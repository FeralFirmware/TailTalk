//! Full round-trip integration tests for the LocalTalk TX/RX pipeline.
//!
//! These tests exercise the complete path:
//!   LLAP frame (with CRC) → HDLC framing → FM-0 encode → (simulated wire) →
//!   FM-0 decode → HDLC deframe → verify original LLAP frame
//!
//! The "simulated wire" stretches each FM-0 half-cell symbol into N
//! samples (mimicking the 8× oversampling that the PIO RX edge timer
//! + software decoder would produce).

use localtalk::crc::lt_crc;
use localtalk::fm0::{Fm0Decoder, Fm0Encoder, Fm0Event};
use localtalk::hdlc::{build_hdlc_bitstream, build_immediate_tx_buffer, build_tx_buffer};
use localtalk::llap::{
    compose_ack, compose_cts, compose_rts, frame_crc_ok, FrameAssembler, AsmEvent,
};

/// Build a frame with CRC from a header slice.
fn with_crc(header: &[u8]) -> Vec<u8> {
    let crc = lt_crc(header);
    let mut frame = header.to_vec();
    frame.extend_from_slice(&crc);
    frame
}

/// Simulate the wire: stretch FM-0 half-cell symbols to `samples_per_half`
/// samples each, prepend idle, append trailing edge + idle.
fn simulate_wire(fm0_symbols: &[u8], samples_per_half: usize) -> Vec<u8> {
    let mut wire = Vec::new();

    // Leading idle (LOW) so the decoder sees a clean first edge.
    wire.extend(std::iter::repeat(0u8).take(samples_per_half * 4));

    // Stretch each half-cell symbol to `samples_per_half` samples.
    for &sym in fm0_symbols {
        for _ in 0..samples_per_half {
            wire.push(sym);
        }
    }

    // Trailing edge + idle so the last bit's closing edge is visible.
    let last = fm0_symbols.last().copied().unwrap_or(0);
    wire.extend(std::iter::repeat(last ^ 1).take(samples_per_half * 2));
    wire.extend(std::iter::repeat(last ^ 1).take(samples_per_half * 4));

    wire
}

/// Decode a wire sample stream through FM-0 decoder + frame assembler.
/// Returns all complete frames (as byte vectors).
fn decode_wire(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut decoder = Fm0Decoder::new();
    let mut assembler = FrameAssembler::new();
    let mut frames = Vec::new();

    for &sample in wire {
        if let Some(event) = decoder.feed_sample(sample) {
            match event {
                Fm0Event::Byte(b) => {
                    assembler.feed_byte(b);
                }
                Fm0Event::Flag => {
                    if let Some(AsmEvent::FrameEnd) = assembler.feed_flag() {
                        frames.push(assembler.current().to_vec());
                        assembler.ack_frame_end();
                    }
                }
                Fm0Event::Abort => {
                    assembler.feed_abort();
                }
            }
        }
    }

    frames
}

/// Full round-trip helper: build HDLC bitstream from a frame WITH CRC,
/// FM-0 encode, simulate wire, decode, return recovered frames.
fn round_trip(frame_with_crc: &[u8], samples_per_half: usize) -> Vec<Vec<u8>> {
    let hdlc_bits = build_hdlc_bitstream(frame_with_crc).expect("valid frame");

    // FM-0 encode the HDLC bitstream.
    let mut enc = Fm0Encoder::new();
    let mut fm0_symbols = Vec::new();
    for &bit in hdlc_bits.iter() {
        let (a, b) = enc.encode_bit(bit);
        fm0_symbols.push(a);
        fm0_symbols.push(b);
    }

    let wire = simulate_wire(&fm0_symbols, samples_per_half);
    decode_wire(&wire)
}

// ── Round-trip tests ──────────────────────────────────────────────────

#[test]
fn round_trip_enq_frame() {
    let frame = with_crc(&[0x42u8, 0x01, 0x81]); // ENQ

    let recovered = round_trip(&frame, 4);
    assert_eq!(recovered.len(), 1, "expected 1 frame, got {:?}", recovered);
    assert_eq!(recovered[0], frame);
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_ack_frame() {
    let ack = compose_ack(0x42); // already includes CRC
    let recovered = round_trip(&ack, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], ack.to_vec());
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_rts_frame() {
    let rts = compose_rts(0x10, 0x42);
    let recovered = round_trip(&rts, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], rts.to_vec());
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_cts_frame() {
    let cts = compose_cts(0x42, 0x10);
    let recovered = round_trip(&cts, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], cts.to_vec());
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_data_frame() {
    let mut header = vec![0u8; 20];
    header[0] = 0xFF; // broadcast
    header[1] = 0x42;
    header[2] = 0x01; // DDP short
    for i in 3..20 {
        header[i] = i as u8;
    }
    let frame = with_crc(&header);

    let recovered = round_trip(&frame, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_max_control_types() {
    for (dest, src, ltype, label) in [
        (0x42, 0x01, 0x81u8, "ENQ"),
        (0x42, 0x42, 0x82, "ACK"),
        (0x10, 0x42, 0x84, "RTS"),
        (0x42, 0x10, 0x85, "CTS"),
    ] {
        let frame = with_crc(&[dest, src, ltype]);

        let recovered = round_trip(&frame, 4);
        assert_eq!(recovered.len(), 1, "{label}: wrong frame count");
        assert_eq!(recovered[0], frame, "{label}: content mismatch");
        assert!(frame_crc_ok(&recovered[0]), "{label}: CRC failed");
    }
}

#[test]
fn round_trip_all_ff_data() {
    let mut header = vec![0xFFu8; 50];
    header[0] = 0xFF; // broadcast
    header[1] = 0x42;
    header[2] = 0x02;
    let frame = with_crc(&header);

    let recovered = round_trip(&frame, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
    assert!(frame_crc_ok(&recovered[0]));
}

#[test]
fn round_trip_all_zero_data() {
    let mut header = vec![0x00u8; 30];
    header[0] = 0xFF;
    header[1] = 0x42;
    header[2] = 0x02;
    let frame = with_crc(&header);

    let recovered = round_trip(&frame, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
    assert!(frame_crc_ok(&recovered[0]));
}

// ── Clock tolerance tests ─────────────────────────────────────────────

#[test]
fn round_trip_slow_clock() {
    let frame = with_crc(&[0x42u8, 0x01, 0x81]);
    let recovered = round_trip(&frame, 5);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
}

#[test]
fn round_trip_fast_clock() {
    let frame = with_crc(&[0x42u8, 0x01, 0x81]);
    let recovered = round_trip(&frame, 3);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
}

// ── TX pipeline tests ─────────────────────────────────────────────────

#[test]
fn tx_buffer_round_trip() {
    let frame = with_crc(&[0x42u8, 0x01, 0x81]);
    let buf = build_tx_buffer(&frame).unwrap();

    let wire = simulate_wire(&buf, 4);
    let recovered = decode_wire(&wire);
    assert_eq!(recovered.len(), 1);
    assert!(frame_crc_ok(&recovered[0]));
    assert_eq!(recovered[0], frame);
}

#[test]
fn immediate_tx_buffer_round_trip() {
    let cts = compose_cts(0x42, 0x10); // already includes CRC
    let buf = build_immediate_tx_buffer(&cts).unwrap();

    let wire = simulate_wire(&buf, 4);
    let recovered = decode_wire(&wire);
    assert_eq!(recovered.len(), 1);
    assert!(frame_crc_ok(&recovered[0]));
    assert_eq!(recovered[0], cts.to_vec());
}

// ── Dialog simulation tests ───────────────────────────────────────────

#[test]
fn rts_cts_data_dialog() {
    let rts = compose_rts(0x10, 0x42);
    let cts = compose_cts(0x42, 0x10);
    let mut data_header = vec![0u8; 15];
    data_header[0] = 0x10;
    data_header[1] = 0x42;
    data_header[2] = 0x01;
    for i in 3..15 {
        data_header[i] = (i * 7) as u8;
    }
    let data_frame = with_crc(&data_header);

    let rts_recovered = round_trip(&rts, 4);
    assert_eq!(rts_recovered.len(), 1);
    assert!(frame_crc_ok(&rts_recovered[0]));
    assert_eq!(rts_recovered[0][2], 0x84); // RTS type

    let cts_recovered = round_trip(&cts, 4);
    assert_eq!(cts_recovered.len(), 1);
    assert!(frame_crc_ok(&cts_recovered[0]));
    assert_eq!(cts_recovered[0][2], 0x85); // CTS type

    let data_recovered = round_trip(&data_frame, 4);
    assert_eq!(data_recovered.len(), 1);
    assert!(frame_crc_ok(&data_recovered[0]));
    assert_eq!(data_recovered[0], data_frame);
}

#[test]
fn enq_ack_dialog() {
    let enq = with_crc(&[0x42u8, 0x01, 0x81]);
    let ack = compose_ack(0x42);

    let enq_recovered = round_trip(&enq, 4);
    assert_eq!(enq_recovered.len(), 1);
    assert!(frame_crc_ok(&enq_recovered[0]));

    let ack_recovered = round_trip(&ack, 4);
    assert_eq!(ack_recovered.len(), 1);
    assert!(frame_crc_ok(&ack_recovered[0]));
    assert_eq!(ack_recovered[0], ack.to_vec());
}

// ── Larger frame stress test ──────────────────────────────────────────

#[test]
fn round_trip_large_data_frame() {
    let mut header = vec![0u8; 200];
    header[0] = 0x10;
    header[1] = 0x42;
    header[2] = 0x02;
    for i in 3..200 {
        header[i] = ((i * 37 + 13) & 0xFF) as u8;
    }
    let frame = with_crc(&header);

    let recovered = round_trip(&frame, 4);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0], frame);
    assert!(frame_crc_ok(&recovered[0]));
}
