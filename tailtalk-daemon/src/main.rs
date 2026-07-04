use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tailtalk_daemon::{Daemon, DaemonConfig};
use tailtalk_packets::aarp::AppleTalkAddress;

/// TailTalk AppleTalk underlay daemon.
///
/// Owns the EtherTalk / LocalTalk interfaces (AARP, LLAP, DDP) and serves
/// them to clients over a varint-delimited protobuf protocol on a Unix
/// domain socket and/or UDP. See tailtalk-proto/proto/tailtalk.proto for the
/// wire protocol.
#[derive(Parser, Debug)]
#[command(name = "tailtalkd", version, about)]
struct Cli {
    /// EtherTalk network interface (e.g. en0). Requires an 'ethertalk' build.
    #[arg(long)]
    ethernet: Option<String>,

    /// Fixed EtherTalk address as NET.NODE (e.g. 1.42) instead of AARP probing.
    #[arg(long, value_parser = parse_address)]
    ethernet_address: Option<AddressArg>,

    /// LocalTalk TashTalk serial device (e.g. /dev/ttyUSB0).
    #[arg(long)]
    localtalk: Option<String>,

    /// Fixed LocalTalk node number (1-254) instead of LLAP probing.
    #[arg(long)]
    localtalk_node: Option<u8>,

    /// Unix socket path to listen on.
    #[cfg(unix)]
    #[arg(long, default_value = "/tmp/tailtalkd.sock")]
    unix: PathBuf,

    /// Do not listen on the Unix socket.
    #[cfg(unix)]
    #[arg(long)]
    no_unix: bool,

    /// UDP address to listen on (e.g. 127.0.0.1:1954).
    #[arg(long)]
    udp: Option<SocketAddr>,

    /// Write a LocalTalk pcap capture to this path.
    #[arg(long)]
    pcap: Option<PathBuf>,

    /// Cable range of the local segment, as LO-HI (e.g. 100-105).
    #[arg(long, value_parser = parse_range)]
    local_range: Option<RangeArg>,

    /// Static route as LO-HI=NET.NODE (repeatable).
    #[arg(long = "route", value_parser = parse_route)]
    routes: Vec<RouteArg>,

    /// Zone mapping as NAME=LO-HI[,LO-HI...] (repeatable).
    #[arg(long = "zone", value_parser = parse_zone)]
    zones: Vec<ZoneArg>,
}

#[derive(Debug, Clone)]
struct AddressArg(u16, u8);

#[derive(Debug, Clone)]
struct RangeArg(u16, u16);

#[derive(Debug, Clone)]
struct RouteArg(u16, u16, u16, u8);

#[derive(Debug, Clone)]
struct ZoneArg(String, Vec<(u16, u16)>);

fn parse_address(s: &str) -> Result<AddressArg, String> {
    let (net, node) = s
        .split_once('.')
        .ok_or_else(|| format!("expected NET.NODE, got '{s}'"))?;
    Ok(AddressArg(
        net.parse().map_err(|_| format!("bad network number '{net}'"))?,
        node.parse().map_err(|_| format!("bad node number '{node}'"))?,
    ))
}

fn parse_range(s: &str) -> Result<RangeArg, String> {
    let (lo, hi) = s
        .split_once('-')
        .ok_or_else(|| format!("expected LO-HI, got '{s}'"))?;
    let lo: u16 = lo.parse().map_err(|_| format!("bad range start '{lo}'"))?;
    let hi: u16 = hi.parse().map_err(|_| format!("bad range end '{hi}'"))?;
    if lo > hi {
        return Err(format!("range start {lo} is greater than end {hi}"));
    }
    Ok(RangeArg(lo, hi))
}

fn parse_route(s: &str) -> Result<RouteArg, String> {
    let (range, addr) = s
        .split_once('=')
        .ok_or_else(|| format!("expected LO-HI=NET.NODE, got '{s}'"))?;
    let RangeArg(lo, hi) = parse_range(range)?;
    let AddressArg(net, node) = parse_address(addr)?;
    Ok(RouteArg(lo, hi, net, node))
}

fn parse_zone(s: &str) -> Result<ZoneArg, String> {
    let (name, ranges) = s
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=LO-HI[,LO-HI...], got '{s}'"))?;
    if name.is_empty() {
        return Err("zone name must not be empty".to_string());
    }
    let ranges = ranges
        .split(',')
        .map(|r| parse_range(r).map(|RangeArg(lo, hi)| (lo, hi)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ZoneArg(name.to_string(), ranges))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    if cli.ethernet.is_none() && cli.localtalk.is_none() {
        tracing::warn!("no interfaces configured; serving an empty underlay (use --ethernet / --localtalk)");
    }
    #[cfg(unix)]
    if cli.no_unix && cli.udp.is_none() {
        anyhow::bail!("nothing to serve: --no-unix given and no --udp address");
    }
    #[cfg(not(unix))]
    if cli.udp.is_none() {
        anyhow::bail!("nothing to serve: no --udp address (Unix sockets are unsupported on Windows)");
    }

    let daemon = Daemon::start(DaemonConfig {
        ethernet: cli.ethernet,
        ethernet_address: cli.ethernet_address.map(|AddressArg(net, node)| (net, node)),
        localtalk: cli.localtalk,
        localtalk_node: cli.localtalk_node,
        pcap: cli.pcap,
    })
    .await?;

    // Static routing rules from the command line. Clients can inspect and
    // modify these later through the API.
    let table = daemon.route_table();
    if let Some(RangeArg(lo, hi)) = cli.local_range {
        table.set_local_range(lo, hi);
    }
    for RouteArg(lo, hi, net, node) in &cli.routes {
        table.insert_route(
            *lo,
            *hi,
            AppleTalkAddress {
                network_number: *net,
                node_number: *node,
            },
        );
    }
    for ZoneArg(name, ranges) in &cli.zones {
        table.insert_zone(name, ranges);
    }

    #[cfg(unix)]
    if !cli.no_unix {
        daemon.serve_unix(&cli.unix)?;
    }
    if let Some(addr) = cli.udp {
        daemon.serve_udp(addr).await?;
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            daemon.shutdown();
        }
        _ = daemon.wait_for_shutdown() => {}
    }

    #[cfg(unix)]
    if !cli.no_unix {
        let _ = std::fs::remove_file(&cli.unix);
    }
    Ok(())
}
