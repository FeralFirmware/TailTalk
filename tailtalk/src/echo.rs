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
    chan: oneshot::Sender<Result<Duration, Error>>,
}

struct PendingRequest {
    start_time: Instant,
    tx: oneshot::Sender<Result<Duration, Error>>,
}

pub struct Echo {
    request_rx: mpsc::Receiver<EchoRequest>,
    sock: DdpSocket,
    pending: HashMap<AppleTalkAddress, PendingRequest>,
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
        loop {
            tokio::select! {
                try_req = self.request_rx.recv() => {
                    if let Some(req) = try_req {
                        self.send_echo(req).await.expect("failed to send echo request");
                    }
                }
                sock_recv = self.sock.recv() => {
                    match sock_recv {
                        Ok(mut pkt) => {
                            self.handle_packet(pkt.headers, &mut pkt.payload).await;
                        },
                        Err(_e) => {

                        },
                    }
                }
            }
        }
    }

    async fn handle_packet(&mut self, ddp: DdpPacket, payload: &mut [u8]) {
        let mut packet = AepPacket::parse(payload).unwrap();

        match packet.function {
            AepFunction::Request => {
                tracing::info!("received an AEP request");
                packet.set_code(AepFunction::Reply);
                packet.to_bytes(payload).unwrap();

                let dst = AppleTalkAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                };
                self.sock
                    .send_to(payload, DdpAddress::new(dst, ddp.src_sock_num))
                    .await
                    .expect("failed to send aep response");
            }
            AepFunction::Reply => {
                tracing::info!("received an AEP reply");
                let addr = AppleTalkAddress {
                    network_number: ddp.src_network_num,
                    node_number: ddp.src_node_id,
                };
                if let Some(req) = self.pending.remove(&addr) {
                    req.tx.send(Ok(Instant::now() - req.start_time)).unwrap();
                }
            }
        }
    }

    async fn send_echo(&mut self, req: EchoRequest) -> Result<(), Error> {
        let start = Instant::now();

        // Create AEP packet with Request function code
        let aep_packet = AepPacket {
            function: AepFunction::Request,
        };

        // Build packet: AEP header + payload
        let mut buf = vec![0u8; 1 + req.payload.len()];
        aep_packet
            .to_bytes(&mut buf)
            .expect("failed to serialize AEP header");
        buf[1..].copy_from_slice(&req.payload);

        tracing::info!("sending off DDP sock write");
        self.sock
            .send_to(&buf, DdpAddress::new(req.addr, 4))
            .await?;

        let pending = PendingRequest {
            start_time: start,
            tx: req.chan,
        };

        self.pending.insert(req.addr, pending);

        Ok(())
    }
}

#[derive(Clone)]
pub struct EchoHandle {
    request_tx: mpsc::Sender<EchoRequest>,
}

impl EchoHandle {
    pub async fn send(&self, addr: AppleTalkAddress, payload: &[u8]) -> Result<Duration, Error> {
        let (tx, rx) = oneshot::channel();
        let req = EchoRequest {
            addr,
            payload: payload.into(),
            chan: tx,
        };

        tracing::info!("dispatching echo req to: {addr:?}");
        self.request_tx
            .send(req)
            .await
            .map_err(|_| Error::other("failed to send request"))?;

        let res = rx
            .await
            .map_err(|_| Error::other("failed to receive response"))??;

        tracing::info!("ping response time: {}ms", res.as_millis());
        Ok(res)
    }
}
