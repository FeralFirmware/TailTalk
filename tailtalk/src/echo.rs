use crate::ddp::{DdpAddress, DdpHandle, DdpSocket};
use std::{
    collections::HashMap,
    io::Error,
    time::{Duration, Instant},
};
use tailtalk_packets::{
    aarp::AppleTalkAddress,
    aep::{AepFunction, AepPacket},
    ddp::{DdpPacket, DdpProtocolType},
};
use tokio::sync::{mpsc, oneshot};

struct EchoRequest {
    addr: AppleTalkAddress,
    payload: Box<[u8]>,
    timeout: Duration,
    chan: oneshot::Sender<Result<Duration, Error>>,
}

struct PendingRequest {
    start_time: Instant,
    deadline: Instant,
    /// The data we sent. AEP echoes it back untouched, so it tells replies for
    /// several in-flight requests to the same node apart.
    payload: Box<[u8]>,
    tx: oneshot::Sender<Result<Duration, Error>>,
}

/// How long an unanswered request waits before [`EchoHandle::send`] gives up.
pub const ECHO_TIMEOUT: Duration = Duration::from_secs(5);

/// The most echo data one request can carry: a DDP datagram holds 586 bytes and
/// the AEP function code takes the first.
pub const MAX_ECHO_DATA: usize = 585;

/// How often the actor sweeps for requests whose deadline has passed. Bounds how
/// late a timeout can be reported, so keep it well under the shortest timeout a
/// caller is likely to ask for.
const TIMEOUT_TICK: Duration = Duration::from_millis(250);

pub struct Echo {
    request_rx: mpsc::Receiver<EchoRequest>,
    sock: DdpSocket,
    /// Outstanding requests per destination, oldest first. A ping run keeps
    /// several open at once, so this cannot be a single request per address.
    pending: HashMap<AppleTalkAddress, Vec<PendingRequest>>,
}

impl Echo {
    pub async fn spawn(ddp: &DdpHandle) -> EchoHandle {
        let (tx, rx) = mpsc::channel(10);

        let sock = ddp
            .new_sock(DdpProtocolType::Aep, Some(4))
            .await
            .expect("failed to create AEP sock");

        let echo = Self {
            request_rx: rx,
            sock,
            pending: HashMap::new(),
        };

        tokio::spawn(async move { echo.run().await });

        EchoHandle { request_tx: tx }
    }

    async fn run(mut self) {
        let mut timeout_check = tokio::time::interval(TIMEOUT_TICK);
        timeout_check.tick().await; // first tick completes immediately
        loop {
            tokio::select! {
                try_req = self.request_rx.recv() => {
                    match try_req {
                        Some(req) => self.send_echo(req).await,
                        None => break,
                    }
                }
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => self.handle_packet(pkt.headers, &mut pkt.payload).await,
                        Err(_) => break,
                    }
                }
                _ = timeout_check.tick() => {
                    self.check_timeouts();
                }
            }
        }
    }

    fn check_timeouts(&mut self) {
        let now = Instant::now();
        let mut expired: Vec<(AppleTalkAddress, PendingRequest)> = Vec::new();
        for (addr, queue) in self.pending.iter_mut() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].deadline <= now {
                    expired.push((*addr, queue.remove(i)));
                } else {
                    i += 1;
                }
            }
        }
        self.pending.retain(|_, queue| !queue.is_empty());

        for (addr, req) in expired {
            tracing::debug!(
                "AEP echo to {}.{} timed out",
                addr.network_number,
                addr.node_number
            );
            let elapsed = req.start_time.elapsed();
            let _ = req.tx.send(Err(Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "echo to {}.{} timed out after {}ms",
                    addr.network_number,
                    addr.node_number,
                    elapsed.as_millis()
                ),
            )));
        }
    }

    async fn handle_packet(&mut self, ddp: DdpPacket, payload: &mut [u8]) {
        let Ok(mut packet) = AepPacket::parse(payload) else {
            tracing::debug!("ignoring malformed AEP packet");
            return;
        };

        match packet.function {
            AepFunction::Request => {
                tracing::debug!("received an AEP request");
                packet.set_code(AepFunction::Reply);
                if packet.to_bytes(payload).is_err() {
                    return;
                }

                let dst = AppleTalkAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                };
                if let Err(e) = self
                    .sock
                    .send_to(payload, DdpAddress::new(dst, ddp.src_sock_num))
                    .await
                {
                    tracing::warn!("failed to send AEP reply: {e}");
                }
            }
            AepFunction::Reply => {
                let now = Instant::now();
                let addr = AppleTalkAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                };
                let Some(queue) = self.pending.get_mut(&addr) else {
                    tracing::debug!(
                        "unsolicited AEP reply from {}.{}",
                        addr.network_number,
                        addr.node_number
                    );
                    return;
                };

                // Match on the echoed data so a late reply is credited to the
                // request that actually produced it rather than to whichever one
                // happens to be outstanding now. The prefix fallback covers a
                // link layer that pads a short frame and leaves trailing bytes
                // on the datagram.
                let echoed = &payload[packet.len()..];
                let matched = queue
                    .iter()
                    .position(|p| *p.payload == *echoed)
                    .or_else(|| queue.iter().position(|p| echoed.starts_with(&p.payload)));
                let Some(index) = matched else {
                    // Falling back to the oldest request here would be worse
                    // than dropping this: it would report a round trip nobody
                    // measured and mark a still-unanswered probe as answered,
                    // which is the whole failure the data matching prevents.
                    tracing::debug!(
                        "AEP reply from {}.{} matches no outstanding request; ignoring",
                        addr.network_number,
                        addr.node_number
                    );
                    return;
                };
                let req = queue.remove(index);
                if queue.is_empty() {
                    self.pending.remove(&addr);
                }
                let _ = req.tx.send(Ok(now - req.start_time));
            }
        }
    }

    async fn send_echo(&mut self, req: EchoRequest) {
        // Build packet: AEP header + payload
        let aep_packet = AepPacket {
            function: AepFunction::Request,
        };
        let header_len = aep_packet.len();
        let mut buf = vec![0u8; header_len + req.payload.len()];
        aep_packet
            .to_bytes(&mut buf)
            .expect("failed to serialize AEP header");
        buf[header_len..].copy_from_slice(&req.payload);

        let start = Instant::now();
        if let Err(e) = self.sock.send_to(&buf, DdpAddress::new(req.addr, 4)).await {
            let _ = req.chan.send(Err(e));
            return;
        }

        self.pending.entry(req.addr).or_default().push(PendingRequest {
            start_time: start,
            deadline: start + req.timeout,
            payload: req.payload,
            tx: req.chan,
        });
    }
}

#[derive(Clone)]
pub struct EchoHandle {
    request_tx: mpsc::Sender<EchoRequest>,
}

impl EchoHandle {
    /// Send one AEP request and wait up to [`ECHO_TIMEOUT`] for the reply.
    pub async fn send(&self, addr: AppleTalkAddress, payload: &[u8]) -> Result<Duration, Error> {
        self.send_timeout(addr, payload, ECHO_TIMEOUT).await
    }

    /// Send one AEP request, giving up after `timeout`. Repeated probes want a
    /// deadline far shorter than [`ECHO_TIMEOUT`], so the whole run does not
    /// stall on one unreachable node.
    pub async fn send_timeout(
        &self,
        addr: AppleTalkAddress,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Duration, Error> {
        if payload.len() > MAX_ECHO_DATA {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "echo payload of {} bytes exceeds the {MAX_ECHO_DATA} byte maximum",
                    payload.len()
                ),
            ));
        }

        let (tx, rx) = oneshot::channel();
        let req = EchoRequest {
            addr,
            payload: payload.into(),
            timeout,
            chan: tx,
        };

        tracing::debug!("dispatching echo req to: {addr:?}");
        self.request_tx
            .send(req)
            .await
            .map_err(|_| Error::other("failed to send request"))?;

        let res = rx
            .await
            .map_err(|_| Error::other("failed to receive response"))??;

        tracing::debug!("ping response time: {}ms", res.as_millis());
        Ok(res)
    }
}
