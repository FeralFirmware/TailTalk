//! Raw DDP sockets: unreliable datagrams, for protocols this crate does not
//! implement itself.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;

use tailtalk_core::Micros;
use tailtalk_core::ddp::Datagram;
use tailtalk_core::stack::SendError;
use tailtalk_packets::aarp::AppleTalkAddress;
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::nbp::ServiceAddress;

use crate::Platform;
use crate::net::{BindError, Hosted, Net, Transmit};

/// Datagrams held for a socket nobody is reading. Past this, new arrivals
/// are dropped, as DDP is entitled to.
const RX_QUEUE_LEN: usize = 8;

struct RawState {
    rx: VecDeque<Datagram>,
}

impl Hosted for RawState {
    fn handle_datagram(&mut self, dg: Datagram, _now: Micros) {
        if self.rx.len() < RX_QUEUE_LEN {
            self.rx.push_back(dg);
        }
    }

    fn poll(&mut self, _now: Micros) {}

    fn next_deadline(&self) -> Option<Micros> {
        None
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        // Sends go straight into the stack; see DdpSocket::send_to.
        None
    }
}

/// A DDP socket. Closed when dropped.
pub struct DdpSocket<'a, P: Platform> {
    net: Net<'a, P>,
    id: usize,
    socket: u8,
}

impl<'a, P: Platform> DdpSocket<'a, P> {
    /// Open `socket`, or a free dynamic socket for `None`.
    pub fn bind(net: Net<'a, P>, socket: Option<u8>) -> Result<Self, BindError> {
        net.with(|inner| {
            let socket = inner.stack.open_socket(socket)?;
            let state = RawState {
                rx: VecDeque::new(),
            };
            let id = inner.insert(Box::new(state), vec![socket]);
            Ok(Self { net, id, socket })
        })
    }

    pub fn socket(&self) -> u8 {
        self.socket
    }

    /// Queue a datagram. DDP makes no delivery promise, so this returns once
    /// the stack has it; it fails only while the node has no address yet or
    /// when the payload exceeds 586 bytes.
    pub fn send_to(&self, dest: ServiceAddress, proto: DdpProtocolType, payload: &[u8]) -> Result<(), SendError> {
        self.net.with(|inner| {
            let addr = AppleTalkAddress {
                network_number: dest.network_number,
                node_number: dest.node_number,
            };
            inner
                .stack
                .send_ddp(addr, dest.socket_number, self.socket, proto, payload)?;
            inner.kick();
            Ok(())
        })
    }

    /// The next datagram addressed to this socket.
    pub async fn recv(&self) -> Datagram {
        self.net
            .wait_on::<RawState, _>(self.id, |s| s.rx.pop_front())
            .await
    }
}

impl<P: Platform> Drop for DdpSocket<'_, P> {
    fn drop(&mut self) {
        self.net.with(|inner| inner.remove(self.id));
    }
}
