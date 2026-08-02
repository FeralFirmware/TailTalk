//! Dynamic DDP socket numbers are a finite resource. Every short-lived ATP user
//! (a PAP status poll, an ImageWriter job, a Printer Tool query) takes one and
//! must give it back, or a long-running stack runs out and `Atp::spawn` panics.

use std::time::Duration;
use tailtalk::{
    OutboundHandle,
    atp::{Atp, AtpRequestor, AtpResponder},
    ddp::{DYNAMIC_SOCKETS, DdpHandle, DdpProcessor},
    route_table::{LearningMode, RouteTable},
};
use tailtalk_packets::ddp::DdpProtocolType;
use tokio::sync::mpsc;

/// Give the actor a chance to notice its handles are gone and release the socket.
///
/// A bare `yield_now` is not enough: the actor opens by skipping the first tick
/// of its retransmit `interval`, and that tick is not ready on its first poll.
/// A current-thread runtime only advances its timer when it parks, which
/// yielding never does. Under `start_paused` this costs no wall clock.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(20)).await;
}

/// A DDP layer with no interfaces. Enough to allocate and release socket
/// numbers, which is all these tests exercise.
fn ddp_only() -> (DdpHandle, mpsc::Receiver<tailtalk::DataLinkPacket>) {
    let (out_tx, out_rx) = mpsc::channel(100);
    let ddp = DdpProcessor::spawn(
        None,
        None,
        OutboundHandle::new(out_tx),
        RouteTable::new(LearningMode::Static),
    );
    // Hand the receiver back so the outbound channel stays open for the
    // processor's lifetime rather than closing under it.
    (ddp, out_rx)
}

/// Whether `sock` is claimable again, i.e. its previous owner released it.
/// Claims and immediately releases it when it is.
async fn can_claim(ddp: &DdpHandle, sock: u8) -> bool {
    ddp.new_sock(DdpProtocolType::Atp, Some(sock)).await.is_ok()
}

/// Assert that whichever half `keep` returns holds the socket open on its own,
/// and that dropping it frees the number. Both halves are handles to one
/// socket, so either must suffice.
async fn outlives_its_sibling<T>(keep: impl FnOnce(AtpRequestor, AtpResponder) -> T) {
    let (ddp, _out_rx) = ddp_only();
    let (sock, requestor, responder) = Atp::spawn(&ddp, None).await;

    // The half the closure does not return is dropped as it goes out of scope.
    let kept = keep(requestor, responder);
    settle().await;
    assert!(
        !can_claim(&ddp, sock).await,
        "socket {sock} released too early"
    );

    drop(kept);
    settle().await;
    assert!(
        can_claim(&ddp, sock).await,
        "socket {sock} was never released"
    );
}

/// Servers are handed only a responder: `TalkStack::pap_server` drops the
/// requestor outright.
#[tokio::test(start_paused = true)]
async fn responder_alone_keeps_the_socket_open() {
    outlives_its_sibling(|_, responder| responder).await;
}

/// Clients keep only a requestor, as `PapStatusHandle` does.
#[tokio::test(start_paused = true)]
async fn requestor_alone_keeps_the_socket_open() {
    outlives_its_sibling(|requestor, _| requestor).await;
}

/// The responder holds the socket by owning the requesting half of it, not an
/// inert token, so a server can send from the number it serves on.
#[tokio::test(start_paused = true)]
async fn responder_lends_out_its_requestor() {
    let (ddp, _out_rx) = ddp_only();
    let (sock, _requestor, responder) = Atp::spawn(&ddp, None).await;

    assert_eq!(responder.requestor().socket_number, sock);
}

/// Cycling far more sockets than exist at once, which only completes if each
/// one's number returns to the pool.
#[tokio::test(start_paused = true)]
async fn the_socket_pool_does_not_run_out() {
    let (ddp, _out_rx) = ddp_only();

    for i in 0..DYNAMIC_SOCKETS.count() * 2 {
        let (sock, requestor, responder) = Atp::spawn(&ddp, None).await;
        assert!(
            DYNAMIC_SOCKETS.contains(&sock),
            "iteration {i}: socket {sock} outside the dynamic range"
        );
        drop(requestor);
        drop(responder);
        settle().await;
    }
}
