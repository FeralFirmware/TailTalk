//! ATP sockets: transactions, as a requester and as a responder, on one
//! DDP socket.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec;
use alloc::vec::Vec;

use tailtalk_core::Micros;
use tailtalk_core::atp::{ATP_MAX_DATA_PER_PACKET, AtpEndpoint, AtpEvent};
use tailtalk_core::ddp::Datagram;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Platform;
use crate::net::{BindError, Hosted, Net, Transmit};

/// Inbound requests held for a responder that is not reading. Past this,
/// new requests are dropped; the requester's retransmit brings them back.
const REQUEST_QUEUE_LEN: usize = 16;

/// An inbound transaction. Answer it with [`AtpSocket::respond`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpRequest {
    pub source: ServiceAddress,
    pub tid: u16,
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
    /// Response packets the requester will accept, already widened from a
    /// classic Mac OS bitmap of 0x00.
    pub bitmap: u8,
    /// Exactly-once: the response is cached for retransmits until released.
    pub xo: bool,
}

impl AtpRequest {
    /// How many response bytes fit the requester's bitmap at the full
    /// per-packet size.
    pub fn max_response_bytes(&self) -> usize {
        self.bitmap.count_ones().clamp(1, 8) as usize * ATP_MAX_DATA_PER_PACKET
    }
}

/// A complete response to one of our requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtpResponse {
    pub user_bytes: [u8; 4],
    pub data: Vec<u8>,
}

/// The request went unanswered through every retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtpTimeout;

struct AtpState {
    ep: AtpEndpoint,
    requests: VecDeque<AtpRequest>,
    /// Outcomes of our own requests, keyed by handle. An entry exists only
    /// while someone is waiting for it, so an outcome whose waiter gave up
    /// has nowhere to land and is dropped.
    outcomes: BTreeMap<u16, Option<Result<AtpResponse, AtpTimeout>>>,
}

impl AtpState {
    fn sort_events(&mut self) {
        while let Some(ev) = self.ep.poll_event() {
            match ev {
                AtpEvent::Request {
                    source,
                    tid,
                    user_bytes,
                    data,
                    bitmap,
                    xo,
                } => {
                    if self.requests.len() < REQUEST_QUEUE_LEN {
                        self.requests.push_back(AtpRequest {
                            source,
                            tid,
                            user_bytes,
                            data,
                            bitmap,
                            xo,
                        });
                    }
                }
                AtpEvent::Response {
                    handle,
                    user_bytes,
                    data,
                } => {
                    if let Some(slot) = self.outcomes.get_mut(&handle) {
                        *slot = Some(Ok(AtpResponse { user_bytes, data }));
                    }
                }
                AtpEvent::RequestFailed { handle } => {
                    if let Some(slot) = self.outcomes.get_mut(&handle) {
                        *slot = Some(Err(AtpTimeout));
                    }
                }
            }
        }
    }
}

impl Hosted for AtpState {
    fn handle_datagram(&mut self, dg: Datagram, now: Micros) {
        let src = ServiceAddress {
            network_number: dg.src.network_number,
            node_number: dg.src.node_number,
            socket_number: dg.src_socket,
        };
        self.ep.handle_datagram(src, &dg.payload, now);
        self.sort_events();
    }

    fn poll(&mut self, now: Micros) {
        self.ep.poll(now);
        self.sort_events();
    }

    fn next_deadline(&self) -> Option<Micros> {
        self.ep.next_deadline()
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let (dest, payload) = self.ep.poll_transmit()?;
        Some(Transmit {
            src_socket: self.ep.local_socket(),
            dest,
            proto: DdpProtocolType::Atp,
            payload,
        })
    }
}

/// An ATP socket. One socket both issues and answers transactions, as ATP
/// sockets are symmetric. Closed when dropped.
pub struct AtpSocket<'a, P: Platform> {
    net: Net<'a, P>,
    id: usize,
    socket: u8,
}

impl<'a, P: Platform> AtpSocket<'a, P> {
    /// Open `socket`, or a free dynamic socket for `None`.
    pub fn bind(net: Net<'a, P>, socket: Option<u8>) -> Result<Self, BindError> {
        net.with(|inner| {
            let socket = inner.stack.open_socket(socket)?;
            let state = AtpState {
                ep: AtpEndpoint::new(socket),
                requests: VecDeque::new(),
                outcomes: BTreeMap::new(),
            };
            let id = inner.insert(Box::new(state), vec![socket]);
            Ok(Self { net, id, socket })
        })
    }

    pub fn socket(&self) -> u8 {
        self.socket
    }

    /// Send an exactly-once request and wait for the whole response, or
    /// [`AtpTimeout`] after eight retransmits 2 s apart (18 s in all).
    pub async fn request(
        &self,
        dest: ServiceAddress,
        user_bytes: [u8; 4],
        data: &[u8],
        bitmap: u8,
    ) -> Result<AtpResponse, AtpTimeout> {
        let handle = self.net.with(|inner| {
            let state = inner.get::<AtpState>(self.id);
            let handle = state.ep.request(dest, user_bytes, data, bitmap, P::now());
            state.outcomes.insert(handle, None);
            inner.kick();
            handle
        });
        // Forget the handle if this future is dropped early, so its outcome
        // is discarded rather than kept forever.
        let guard = OutcomeGuard {
            socket: self,
            handle,
        };
        let outcome = self
            .net
            .wait_on::<AtpState, _>(self.id, |s| match s.outcomes.get(&handle) {
                Some(Some(_)) => s.outcomes.remove(&handle).flatten(),
                _ => None,
            })
            .await;
        core::mem::forget(guard);
        outcome
    }

    /// Send an at-least-once packet with no transaction behind it (a PAP
    /// tickle, say). Any response is discarded.
    pub fn send_alo(&self, dest: ServiceAddress, user_bytes: [u8; 4]) {
        self.net.with(|inner| {
            inner.get::<AtpState>(self.id).ep.send_alo(dest, user_bytes);
            inner.kick();
        });
    }

    /// The next inbound request.
    pub async fn next_request(&self) -> AtpRequest {
        self.net
            .wait_on::<AtpState, _>(self.id, |s| s.requests.pop_front())
            .await
    }

    /// Answer `request`, split at the full ATP packet size. See
    /// [`AtpSocket::respond_chunked`] for protocols that cap packets lower.
    pub fn respond(&self, request: &AtpRequest, user_bytes: [u8; 4], data: &[u8]) {
        self.respond_chunked(request, user_bytes, data, ATP_MAX_DATA_PER_PACKET);
    }

    /// Answer `request` with packets of at most `chunk_size` bytes, all
    /// carrying `user_bytes`. At most eight packets are sent.
    pub fn respond_chunked(&self, request: &AtpRequest, user_bytes: [u8; 4], data: &[u8], chunk_size: usize) {
        self.net.with(|inner| {
            inner.get::<AtpState>(self.id).ep.respond(
                request.source,
                request.tid,
                user_bytes,
                data,
                chunk_size,
                P::now(),
            );
            inner.kick();
        });
    }
}

impl<P: Platform> Drop for AtpSocket<'_, P> {
    fn drop(&mut self) {
        self.net.with(|inner| inner.remove(self.id));
    }
}

struct OutcomeGuard<'s, 'a, P: Platform> {
    socket: &'s AtpSocket<'a, P>,
    handle: u16,
}

impl<P: Platform> Drop for OutcomeGuard<'_, '_, P> {
    fn drop(&mut self) {
        let (id, handle) = (self.socket.id, self.handle);
        self.socket.net.with(|inner| {
            inner.get::<AtpState>(id).outcomes.remove(&handle);
        });
    }
}
