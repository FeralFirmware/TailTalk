# TailTalk Daemon (`tailtalkd`) Wire Protocol

`tailtalkd` owns the physical AppleTalk interfaces — EtherTalk (raw
Ethernet + AARP) and/or LocalTalk (TashTalk serial + LLAP) — and exposes the
DDP layer to any number of client processes. TailTalk stacks use it via
`TalkStack::builder().daemon_unix(..)` / `.daemon_udp(..)`, but the protocol
is deliberately simple so that C programs (or anything with a protobuf
library) can speak it directly.

The authoritative message definitions live in
[`tailtalk-proto/proto/tailtalk.proto`](../tailtalk-proto/proto/tailtalk.proto).
For C, generate bindings with [protobuf-c](https://github.com/protobuf-c/protobuf-c)
or [nanopb](https://jpa.kapsi.fi/nanopb/).

## Transports and framing

The daemon listens on a SOCK_STREAM **Unix domain socket** (default
`/tmp/tailtalkd.sock`, `--unix PATH`) and/or **UDP** (`--udp ADDR:PORT`).

Every message is **varint-length-delimited**: a LEB128 varint carrying the
encoded length, followed by that many bytes of protobuf message. This is the
same framing as protobuf-java's `writeDelimitedTo` / prost's
`encode_length_delimited`.

* On the Unix stream, messages are concatenated back to back.
* On UDP, each datagram holds one or more *complete* messages; a message may
  not span datagrams.
* Messages over 65535 encoded bytes are rejected.

Clients send `Request`; the daemon sends `ServerMessage`, which is either a
`Reply` or an unsolicited `ReceivedDatagram`.

## Correlation

`Request.id` is client-chosen. Non-zero ids get exactly one `Reply` with the
same id. **Id 0 means fire-and-forget** — the daemon executes the request but
never replies, which is the intended mode for `SendDatagram`. Replies carry
either a result kind (`Ok`, `ListInterfacesReply`, `OpenSocketReply`,
`ListRoutesReply`) or an `Error { code, message }`.

## Sessions

All DDP sockets a client opens belong to its session and are closed
automatically when the session ends:

* **Unix**: the session is the connection. Closing it frees everything.
* **UDP**: the session is keyed by the client's source address and expires
  after **300 s** without traffic. Send `PingRequest` (e.g. every 30 s) to
  keep it alive. There is no explicit close; just stop talking.

## Operations

| Request | Reply | Notes |
|---|---|---|
| `ListInterfacesRequest` | `ListInterfacesReply` | Name, type (EtherTalk/LocalTalk), current AppleTalk address of each interface. |
| `SetAddressRequest` | `Ok` | Force an interface's address (no probe). LocalTalk: network must be 0, node 1-254. Reprograms TashTalk node bits on LocalTalk. |
| `OpenSocketRequest` | `OpenSocketReply` | `socket` 1-254 or 0 for dynamic (64-254); `ddp_type` stamps outbound datagrams (2=NBP, 3=ATP, 4=AEP, 7=ADSP, …). `ERROR_CODE_ADDR_IN_USE` if taken — socket numbers are one namespace shared by all sessions. |
| `CloseSocketRequest` | `Ok` | Frees the socket number. |
| `SendDatagram` | `Ok` (usually sent with id 0) | Max 586-byte payload. Best-effort, like DDP: errors after acceptance are not reported. |
| — | `ReceivedDatagram` (unsolicited) | Delivered for any open socket: source/dest address+socket, DDP type, payload. `dest.node == 255` marks broadcasts. |
| `ListRoutesRequest` | `ListRoutesReply` | Routes (cable range → next-hop router), zone→range mappings, and the local cable range. |
| `AddRouteRequest`, `RemoveRouteRequest`, `AddZoneRequest`, `RemoveZoneRequest`, `SetLocalRangeRequest` | `Ok` | Modify the daemon's routing rules. Affects DDP forwarding for every client. |
| — | `routes_changed` (unsolicited `ListRoutesReply`) | Broadcast to every session whenever the rules change — by any client or the daemon itself. Carries the complete new rule set; replace any cached copy with it. |
| `PingRequest` | `Ok` | Keepalive / liveness. |

## A minimal client, step by step

1. Connect to the Unix socket (or bind a UDP socket and remember to ping).
2. `ListInterfacesRequest` → learn your interfaces and current addresses.
3. `OpenSocketRequest { socket: 0, ddp_type: 3 }` → get e.g. socket 129.
4. Send: `Request { id: 0, send: SendDatagram { socket_id: 129, dest: {network: 0, node: 255}, dest_socket: 2, payload: … } }`.
5. Read `ServerMessage`s in a loop: replies resolve your pending requests,
   `ReceivedDatagram`s are inbound traffic for your sockets.

## Semantics worth knowing

* **The daemon owns the routing layer** — it fills the role of the old Linux
  AppleTalk kernel module. Clients name a destination network/node/socket
  and the daemon picks the path: it resolves the link-level next hop (the
  destination itself when it is on a local cable or unknown, otherwise the
  responsible router from the route table), then transmits on whichever
  interface reaches that hop — LocalTalk for hops on network 0, EtherTalk
  (with AARP resolution) otherwise. Network 0 addresses the local cable;
  `{0, 255}` broadcasts on every interface. Routing rules are shared,
  daemon-global state: a change made by one client affects forwarding for
  all, and every session is notified via `routes_changed`. Clients never
  need their own routing logic; TailTalk stacks in remote mode keep only a
  passive cache of the rules (for NBP zone dispatch), synchronized by these
  pushes.
* **Well-known sockets are first come, first served.** A full TailTalk stack
  in remote mode binds NBP (2) and AEP (4); a second such stack on the same
  daemon will fail to build. Plain DDP/ATP/ADSP clients with dynamic sockets
  coexist freely.
* **Interface addresses are acquired before serving starts** (AARP probe on
  EtherTalk, LLAP ENQ on LocalTalk), so `ListInterfacesReply` normally always
  carries addresses. After `SetAddressRequest` the daemon answers AARP/LLAP
  for the new address immediately.

## Running the daemon

```sh
# LocalTalk via TashTalk, Unix socket at the default path
tailtalkd --localtalk /dev/ttyUSB0

# EtherTalk (build with --features ethertalk), plus UDP for remote clients
tailtalkd --ethernet en0 --udp 0.0.0.0:1954

# Static routing rules, fixed node address
tailtalkd --localtalk /dev/ttyUSB0 --localtalk-node 129 \
          --local-range 100-105 --route 200-210=100.1 --zone 'Engineering=200-210'
```

And a TailTalk client:

```rust
let stack = TalkStack::builder()
    .daemon_unix("/tmp/tailtalkd.sock")
    .build()
    .await?;
// Everything above DDP (NBP, ATP, ADSP, ASP, AFP, PAP…) works unchanged.
```
