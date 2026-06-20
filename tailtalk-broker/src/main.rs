use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use prost::Message;
use tailtalk::addressing::AddressingHandle;
use tailtalk::ddp::{DdpAddress, DdpHandle};
use tailtalk::{CancellationToken, PacketProcessor};
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

mod proto {
    include!(concat!(env!("OUT_DIR"), "/tailtalk.rs"));
}
use proto::{command::Msg, AtalkAddr, Command, IfaceInfo, IfaceList, Opened, Recv, SetAddrOk};

#[derive(Parser)]
#[command(name = "tailtalk-broker")]
struct Cli {
    #[arg(long, default_value = "/var/run/tailtalk-broker.sock")]
    socket: PathBuf,
    #[arg(long)]
    localtalk: String,
    #[arg(long)]
    pcap: Option<PathBuf>,
}

type SharedAddr = Arc<RwLock<Option<AppleTalkAddress>>>;
type LocalSockets = Arc<RwLock<HashMap<u8, mpsc::Sender<Bytes>>>>;

async fn read_varint(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Option<usize>> {
    let mut result = 0usize;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        match stream.read_exact(&mut byte).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        result |= ((byte[0] & 0x7f) as usize) << shift;
        if byte[0] & 0x80 == 0 { return Ok(Some(result)); }
        shift += 7;
        if shift >= 64 { anyhow::bail!("varint overflow"); }
    }
}

async fn read_cmd(stream: &mut (impl AsyncReadExt + Unpin)) -> Result<Option<Command>> {
    let len = match read_varint(stream).await? {
        Some(n) => n,
        None => return Ok(None),
    };
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(Command::decode(buf.as_slice())?))
}

async fn write_cmd(stream: &mut UnixStream, cmd: &Command) -> Result<()> {
    stream.write_all(&cmd.encode_length_delimited_to_vec()).await?;
    Ok(())
}

fn at_addr(net: u16, node: u8) -> AtalkAddr {
    AtalkAddr { net: net as u32, node: node as u32 }
}

fn recv_cmd(src: AppleTalkAddress, src_port: u8, ddptype: u8, payload: Vec<u8>) -> Command {
    Command {
        msg: Some(Msg::Recv(Recv {
            src: Some(at_addr(src.network_number, src.node_number)),
            src_port: src_port as u32,
            ddptype: ddptype as u32,
            payload,
            interface: "localtalk0".to_string(),
        })),
    }
}

async fn handle_control(
    mut stream: UnixStream,
    hint_node: u8,
    lt_addressing: AddressingHandle,
    shared_addr: SharedAddr,
) {
    info!("broker: SetAddr hint_node={hint_node}");

    let addr = match lt_addressing.addr().await {
        Ok(a) => a,
        Err(e) => { error!("broker: addressing failed: {e}"); return; }
    };

    *shared_addr.write().await = Some(addr);
    info!("broker: node settled at {}", addr.node_number);

    let reply = Command { msg: Some(Msg::SetAddrOk(SetAddrOk { node: addr.node_number as u32 })) };
    if let Err(e) = write_cmd(&mut stream, &reply).await {
        error!("broker: write SetAddrOk: {e}");
        return;
    }

    loop {
        match read_cmd(&mut stream).await {
            Ok(None) | Err(_) => break,
            Ok(Some(_)) => {}
        }
    }
    info!("broker: control connection closed");
}

async fn handle_ddp_client(
    mut stream: UnixStream,
    open: proto::Open,
    ddp: DdpHandle,
    shared_addr: SharedAddr,
    local_sockets: LocalSockets,
) {
    let requested_port = if open.port == 0 { None } else { Some(open.port as u8) };

    let our_addr = match open.hint {
        Some(h) if h.net != 0 || h.node != 0 => {
            AppleTalkAddress { network_number: h.net as u16, node_number: h.node as u8 }
        }
        _ => match *shared_addr.read().await {
            Some(a) => a,
            None => {
                error!("broker: Open with no address — rejecting");
                return;
            }
        },
    };

    let mut sock = match ddp.new_sock(DdpProtocolType::Atp, requested_port).await {
        Ok(s) => s,
        Err(e) => { error!("broker: new_sock: {e}"); return; }
    };
    let port = sock.socket_num();

    let opened = Command {
        msg: Some(Msg::Opened(Opened {
            port: port as u32,
            addr: Some(at_addr(our_addr.network_number, our_addr.node_number)),
        })),
    };
    if let Err(e) = write_cmd(&mut stream, &opened).await {
        error!("broker: write Opened: {e}");
        return;
    }
    info!("broker: socket {port} opened ({}:{})", our_addr.network_number, our_addr.node_number);

    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Bytes>(64);
    local_sockets.write().await.insert(port, tx.clone());

    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if writer.write_all(&frame).await.is_err() { break; }
        }
    });

    loop {
        tokio::select! {
            result = sock.recv() => {
                let pkt = match result {
                    Ok(p) => p,
                    Err(e) => { error!("broker: recv on socket {port}: {e}"); break; }
                };
                let src = AppleTalkAddress {
                    network_number: pkt.headers.src_network_num,
                    node_number: pkt.headers.src_node_id,
                };
                info!("broker: recv socket {port} ← {}:{} port={} type={:#04x}",
                    src.network_number, src.node_number,
                    pkt.headers.src_sock_num, pkt.headers.protocol_typ as u8);
                let cmd = recv_cmd(src, pkt.headers.src_sock_num, pkt.headers.protocol_typ as u8, pkt.payload.to_vec());
                let _ = tx.send(Bytes::from(cmd.encode_length_delimited_to_vec())).await;
            }

            result = read_varint(&mut reader) => {
                let len = match result {
                    Ok(Some(n)) => n,
                    Ok(None) => break,
                    Err(e) => { error!("broker: read varint: {e}"); break; }
                };
                let mut buf = vec![0u8; len];
                if let Err(e) = reader.read_exact(&mut buf).await {
                    error!("broker: read payload: {e}"); break;
                }
                let send = match Command::decode(buf.as_slice()).ok().and_then(|c| c.msg) {
                    Some(Msg::Send(s)) => s,
                    other => { warn!("broker: unexpected message: {other:?}"); continue; }
                };

                let dest_net  = send.dest.as_ref().map(|a| a.net  as u16).unwrap_or(0);
                let dest_node = send.dest.as_ref().map(|a| a.node as u8).unwrap_or(0);
                let dest_sock = send.dest_port as u8;
                let ddptype   = send.ddptype as u8;

                info!("broker: send socket {port} → {dest_net}:{dest_node} port={dest_sock}");

                let our_node = shared_addr.read().await.map(|a| a.node_number).unwrap_or(0);
                if dest_node == our_node && our_node != 0 {
                    if let Some(dest_tx) = local_sockets.read().await.get(&dest_sock).cloned() {
                        let cmd = recv_cmd(our_addr, port, ddptype, send.payload);
                        let _ = dest_tx.send(Bytes::from(cmd.encode_length_delimited_to_vec())).await;
                    } else {
                        warn!("broker: loopback to port {dest_sock} — no socket");
                    }
                } else {
                    let dest = DdpAddress::new(
                        AppleTalkAddress { network_number: dest_net, node_number: dest_node },
                        dest_sock,
                    );
                    let proto = DdpProtocolType::try_from(ddptype).unwrap_or(DdpProtocolType::Atp);
                    if let Err(e) = sock.send_to_typed(&send.payload, dest, proto).await {
                        error!("broker: send: {e}");
                    }
                }
            }
        }
    }

    local_sockets.write().await.remove(&port);
    info!("broker: socket {port} closed");
}

async fn handle_connection(
    mut stream: UnixStream,
    ddp: DdpHandle,
    lt_addressing: AddressingHandle,
    shared_addr: SharedAddr,
    local_sockets: LocalSockets,
) {
    let cmd = match read_cmd(&mut stream).await {
        Ok(Some(c)) => c,
        Ok(None) => return,
        Err(e) => { error!("broker: read first msg: {e}"); return; }
    };

    match cmd.msg {
        Some(Msg::ListIfaces(_)) => {
            let reply = Command {
                msg: Some(Msg::IfaceList(IfaceList {
                    ifaces: vec![IfaceInfo {
                        name:   "localtalk0".to_string(),
                        kind:   proto::IfaceKind::Localtalk as i32,
                        phase:  None,
                        addr:   None,
                        net_lo: 0,
                        net_hi: 0,
                        zone:   String::new(),
                    }],
                })),
            };
            let _ = write_cmd(&mut stream, &reply).await;
        }
        Some(Msg::SetAddr(sa)) => {
            handle_control(stream, sa.hint_node as u8, lt_addressing, shared_addr).await;
        }
        Some(Msg::Open(open)) => {
            info!("broker: Open port={} net={} node={}",
                open.port,
                open.hint.as_ref().map(|h| h.net).unwrap_or(0),
                open.hint.as_ref().map(|h| h.node).unwrap_or(0));
            handle_ddp_client(stream, open, ddp, shared_addr, local_sockets).await;
        }
        other => error!("broker: unexpected first message: {other:?}"),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("tailtalk_broker=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    let mut builder = PacketProcessor::builder().localtalk(&cli.localtalk);
    if let Some(p) = cli.pcap { builder = builder.pcap_capture(p); }
    let (processor, outbound) = builder.build().context("PacketProcessor::build")?;

    let lt_addressing = tailtalk::addressing::Addressing::spawn(
        None, outbound.clone(), None,
        tailtalk_packets::aarp::AddressSource::LocalTalk,
    );
    let ddp = tailtalk::ddp::DdpProcessor::spawn(None, Some(lt_addressing.clone()), outbound);

    let token = CancellationToken::new();
    tokio::spawn(processor.run(None, Some(lt_addressing.clone()), ddp.clone(), token.clone()));

    let shared_addr: SharedAddr = Arc::new(RwLock::new(None));
    let local_sockets: LocalSockets = Arc::new(RwLock::new(HashMap::new()));

    if cli.socket.exists() {
        std::fs::remove_file(&cli.socket)
            .with_context(|| format!("removing stale socket {:?}", cli.socket))?;
    }

    let listener = UnixListener::bind(&cli.socket)
        .with_context(|| format!("binding {:?}", cli.socket))?;

    info!("broker: listening on {:?}", cli.socket);

    loop {
        let (stream, _) = listener.accept().await.context("accept")?;
        tokio::spawn(handle_connection(
            stream, ddp.clone(), lt_addressing.clone(),
            shared_addr.clone(), local_sockets.clone(),
        ));
    }
}
