//! Printers served on the network, backed by a byte port.
//!
//! A [`Printer`] is what a Mac sees in the Chooser: an NBP name, and behind
//! it one of the printer protocols from `tailtalk-core` - a StyleWriter's
//! ADSP handshake, an ImageWriter option card's PAP, or plain PAP. The bytes
//! a job carries go to a port you supply, and whatever the printer says back
//! goes the other way. On InkTalk the port is the printer UART; in a test it
//! can be anything that implements `embedded_io_async`.
//!
//! Flow control is the port's own back pressure. Job bytes are taken off
//! the network only as fast as [`Printer::run`] can write them: the ADSP
//! receive window and the PAP pull schedule both follow the room left in a
//! fixed [`WINDOW`], and a write that blocks is room that stops coming back.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use embassy_futures::select::{Either, select};
use embedded_io_async::{Error as _, ErrorKind, Read, Write};
use tailtalk_core::Micros;
use tailtalk_core::ddp::Datagram;
use tailtalk_core::imagewriter::{self, ImageWriterEvent, ImageWriterRole};
use tailtalk_core::pap::{self, PapEvent, PapServer};
use tailtalk_core::stylewriter::{self, StyleWriterEvent, StyleWriterRole};
use tailtalk_packets::ddp::DdpProtocolType;
use tailtalk_packets::nbp::{EntityName, ServiceAddress};

use crate::Platform;
use crate::net::{BindError, Hosted, Inner, Net, Transmit};

/// Job bytes the printer may have taken off the network but not yet
/// written to the port. One full PAP pull, since a pull is only issued when
/// its whole reply fits.
pub const WINDOW: usize = pap::PULL_CAPACITY;

/// What [`Printer::run`] returns: something the application may want to act
/// on. Job bytes never surface here; they go straight to the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrinterEvent {
    /// A client connected and a job began.
    JobStarted,
    /// The client marked the end of its data. PAP emulations only.
    JobEof,
    /// The job is over. `clean` is false when a StyleWriter client vanished
    /// without its teardown, in which case a printer reset has already been
    /// written to the port. PAP cannot tell a close from a timeout, so PAP
    /// emulations always report it clean.
    JobEnded { clean: bool },
    /// A client renamed the printer. The new NBP name is already registered;
    /// persist it if the device keeps its name across a power cycle, as the
    /// hardware being emulated does.
    Renamed(String),
    /// A client asked for a name this node cannot register (not UTF-8,
    /// carrying an NBP delimiter, or too long). The old name stands.
    RenameRejected,
}

/// Why [`Printer::run`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrinterError {
    Read(ErrorKind),
    Write(ErrorKind),
    /// The port's reader reported end of stream.
    PortClosed,
}

/// The core printer roles, made uniform. Each has the same shape, with
/// small differences in what it needs passed.
trait Role: Send + 'static {
    fn handle_datagram(&mut self, dst_socket: u8, src: ServiceAddress, payload: &[u8], now: Micros);
    fn poll(&mut self, now: Micros);
    fn next_deadline(&self) -> Option<Micros>;
    fn poll_transmit(&mut self) -> Option<Transmit>;
    /// Room for job bytes, in bytes.
    fn set_credit(&mut self, bytes: usize, now: Micros);
    fn printer_input(&mut self, data: &[u8], now: Micros);
    fn poll_event(&mut self) -> Option<RoleEvent>;
    fn colour_ribbon(&self) -> Option<bool> {
        None
    }
}

enum RoleEvent {
    ToPrinter(Vec<u8>),
    Rename(Vec<u8>),
    Event(PrinterEvent),
}

impl Role for StyleWriterRole {
    fn handle_datagram(&mut self, _dst: u8, src: ServiceAddress, payload: &[u8], now: Micros) {
        StyleWriterRole::handle_datagram(self, src, payload, now);
    }

    fn poll(&mut self, now: Micros) {
        StyleWriterRole::poll(self, now);
    }

    fn next_deadline(&self) -> Option<Micros> {
        StyleWriterRole::next_deadline(self)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let (dest, payload) = StyleWriterRole::poll_transmit(self)?;
        Some(Transmit {
            src_socket: self.control_socket(),
            dest,
            proto: DdpProtocolType::Adsp,
            payload,
        })
    }

    fn set_credit(&mut self, bytes: usize, _now: Micros) {
        self.set_printer_credit(bytes);
    }

    fn printer_input(&mut self, data: &[u8], _now: Micros) {
        StyleWriterRole::printer_input(self, data);
    }

    fn poll_event(&mut self) -> Option<RoleEvent> {
        Some(match StyleWriterRole::poll_event(self)? {
            StyleWriterEvent::JobStarted { .. } => RoleEvent::Event(PrinterEvent::JobStarted),
            StyleWriterEvent::ToPrinter(bytes) => RoleEvent::ToPrinter(bytes),
            StyleWriterEvent::JobEnded { clean } => RoleEvent::Event(PrinterEvent::JobEnded { clean }),
            StyleWriterEvent::Rename(name) => RoleEvent::Rename(name),
        })
    }
}

impl Role for ImageWriterRole {
    fn handle_datagram(&mut self, dst: u8, src: ServiceAddress, payload: &[u8], now: Micros) {
        ImageWriterRole::handle_datagram(self, dst, src, payload, now);
    }

    fn poll(&mut self, now: Micros) {
        ImageWriterRole::poll(self, now);
    }

    fn next_deadline(&self) -> Option<Micros> {
        ImageWriterRole::next_deadline(self)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let (src_socket, dest, payload) = ImageWriterRole::poll_transmit(self)?;
        Some(Transmit {
            src_socket,
            dest,
            proto: DdpProtocolType::Atp,
            payload,
        })
    }

    fn set_credit(&mut self, bytes: usize, now: Micros) {
        self.set_sink_credit(bytes, now);
    }

    fn printer_input(&mut self, data: &[u8], now: Micros) {
        ImageWriterRole::printer_input(self, data, now);
    }

    fn poll_event(&mut self) -> Option<RoleEvent> {
        Some(match ImageWriterRole::poll_event(self)? {
            ImageWriterEvent::ConnectionOpened { .. } => RoleEvent::Event(PrinterEvent::JobStarted),
            ImageWriterEvent::ToPrinter(bytes) => RoleEvent::ToPrinter(bytes),
            ImageWriterEvent::JobEof => RoleEvent::Event(PrinterEvent::JobEof),
            ImageWriterEvent::ConnectionClosed => {
                RoleEvent::Event(PrinterEvent::JobEnded { clean: true })
            }
            ImageWriterEvent::Rename(name) => RoleEvent::Rename(name),
        })
    }

    fn colour_ribbon(&self) -> Option<bool> {
        Some(ImageWriterRole::colour_ribbon(self))
    }
}

impl Role for PapServer {
    fn handle_datagram(&mut self, dst: u8, src: ServiceAddress, payload: &[u8], now: Micros) {
        PapServer::handle_datagram(self, dst, src, payload, now);
    }

    fn poll(&mut self, now: Micros) {
        PapServer::poll(self, now);
    }

    fn next_deadline(&self) -> Option<Micros> {
        PapServer::next_deadline(self)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let (src_socket, dest, payload) = PapServer::poll_transmit(self)?;
        Some(Transmit {
            src_socket,
            dest,
            proto: DdpProtocolType::Atp,
            payload,
        })
    }

    fn set_credit(&mut self, bytes: usize, now: Micros) {
        self.set_sink_credit(bytes, now);
    }

    fn printer_input(&mut self, data: &[u8], now: Micros) {
        self.queue_output(data, now);
    }

    fn poll_event(&mut self) -> Option<RoleEvent> {
        Some(match PapServer::poll_event(self)? {
            PapEvent::ConnectionOpened { .. } => RoleEvent::Event(PrinterEvent::JobStarted),
            PapEvent::ToPrinter(bytes) => RoleEvent::ToPrinter(bytes),
            PapEvent::JobEof => RoleEvent::Event(PrinterEvent::JobEof),
            PapEvent::ConnectionClosed => RoleEvent::Event(PrinterEvent::JobEnded { clean: true }),
        })
    }
}

enum PortEvent {
    Event(PrinterEvent),
    Rename(Vec<u8>),
}

/// A role and the byte queue in front of its port.
struct PortState {
    role: Box<dyn Role>,
    /// Job bytes taken off the network, not yet handed to the port.
    to_printer: VecDeque<u8>,
    /// Bytes handed to a port write that has not returned yet.
    writing: usize,
    /// Running totals of job bytes queued and written, so an event is not
    /// reported ahead of the bytes that came before it.
    queued_total: u64,
    written_total: u64,
    /// Each event with the `queued_total` it followed.
    events: VecDeque<(u64, PortEvent)>,
    /// The NBP registration. It lives here instead of in the [`Printer`] so a
    /// [`PrinterName`] handle can change it from another task.
    socket: u8,
    nbp_type: String,
    name: String,
    registered: Option<EntityName>,
}

impl PortState {
    /// Sort the role's events, then tell it how much room is left.
    fn settle(&mut self, now: Micros) {
        while let Some(ev) = self.role.poll_event() {
            match ev {
                RoleEvent::ToPrinter(bytes) => {
                    self.queued_total += bytes.len() as u64;
                    self.to_printer.extend(bytes);
                }
                RoleEvent::Rename(name) => {
                    self.events
                        .push_back((self.queued_total, PortEvent::Rename(name)));
                }
                RoleEvent::Event(e) => {
                    self.events.push_back((self.queued_total, PortEvent::Event(e)));
                }
            }
        }
        let held = self.to_printer.len() + self.writing;
        self.role.set_credit(WINDOW.saturating_sub(held), now);
    }

    /// The next event whose preceding bytes have all been written.
    fn next_event(&mut self) -> Option<PortEvent> {
        match self.events.front() {
            Some(&(after, _)) if after <= self.written_total => {
                self.events.pop_front().map(|(_, e)| e)
            }
            _ => None,
        }
    }
}

impl Hosted for PortState {
    fn handle_datagram(&mut self, dg: Datagram, now: Micros) {
        let src = ServiceAddress {
            network_number: dg.src.network_number,
            node_number: dg.src.node_number,
            socket_number: dg.src_socket,
        };
        self.role
            .handle_datagram(dg.dst_socket, src, &dg.payload, now);
        self.settle(now);
    }

    fn poll(&mut self, now: Micros) {
        self.role.poll(now);
        self.settle(now);
    }

    fn next_deadline(&self) -> Option<Micros> {
        self.role.next_deadline()
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.role.poll_transmit()
    }
}

/// A printer this node serves. Registered in NBP from the moment it is
/// bound; withdrawn and closed when dropped.
pub struct Printer<'a, P: Platform> {
    net: Net<'a, P>,
    id: usize,
    generation: u32,
    socket: u8,
}

impl<'a, P: Platform> Printer<'a, P> {
    /// A Color StyleWriter 2400 with a LocalTalk adapter, registered as
    /// `<name>:ColorStyleWriter2400AT@*`. The port speaks the StyleWriter's
    /// serial command language, which passes through untouched.
    pub fn stylewriter(net: Net<'a, P>, name: &str) -> Result<Self, BindError> {
        Self::bind(net, name, stylewriter::NBP_TYPE, 1, |inner, sockets| {
            // ADSP connection IDs want to differ across boots, so a Mac does
            // not mistake a fresh connection for a stale one.
            let seed = inner.stack.next_random();
            Box::new(StyleWriterRole::new(sockets[0], seed))
        })
    }

    /// An ImageWriter II with its LocalTalk option card, registered as
    /// `<name>:ImageWriter@*`. The port speaks ImageWriter command bytes.
    pub fn imagewriter(net: Net<'a, P>, name: &str) -> Result<Self, BindError> {
        Self::bind(net, name, imagewriter::NBP_TYPE, 2, |_, sockets| {
            Box::new(ImageWriterRole::new(sockets[0], sockets[1]))
        })
    }

    /// A plain PAP printer registered as `<name>:<nbp_type>@*`, answering
    /// status requests with `status`. What the port speaks is between the
    /// client and whatever is on the other end of it; for a LaserWriter,
    /// PostScript.
    pub fn pap(net: Net<'a, P>, name: &str, nbp_type: &str, status: &[u8]) -> Result<Self, BindError> {
        Self::bind(net, name, nbp_type, 2, |_, sockets| {
            let mut server = PapServer::new(sockets[0], sockets[1]);
            server.set_status(status);
            Box::new(server)
        })
    }

    fn bind(
        net: Net<'a, P>,
        name: &str,
        nbp_type: &str,
        socket_count: usize,
        make: impl FnOnce(&mut Inner, &[u8]) -> Box<dyn Role>,
    ) -> Result<Self, BindError> {
        let entity = entity_name(name, nbp_type).ok_or(BindError::BadName)?;
        net.with(|inner| {
            let mut sockets = Vec::with_capacity(socket_count);
            for _ in 0..socket_count {
                match inner.stack.open_socket(None) {
                    Ok(s) => sockets.push(s),
                    Err(e) => {
                        for &s in &sockets {
                            inner.stack.close_socket(s);
                        }
                        return Err(e.into());
                    }
                }
            }
            if inner.stack.nbp_register(entity.clone(), sockets[0]).is_err() {
                for &s in &sockets {
                    inner.stack.close_socket(s);
                }
                return Err(BindError::NameTableFull);
            }
            let mut state = PortState {
                role: make(inner, &sockets),
                // Reserved whole, with room for the few bytes a role queues
                // outside the window (a StyleWriter reset, the ImageWriter's
                // self ID query), so a busy job never makes it reallocate:
                // on a small heap, growing means doubling.
                to_printer: VecDeque::with_capacity(WINDOW + 64),
                writing: 0,
                queued_total: 0,
                written_total: 0,
                events: VecDeque::new(),
                socket: sockets[0],
                nbp_type: nbp_type.to_string(),
                name: name.to_string(),
                registered: Some(entity),
            };
            // Grant the first window now, or a PAP server would never pull.
            state.settle(P::now());
            let socket = sockets[0];
            let id = inner.insert(Box::new(state), sockets);
            let generation = inner.generation(id);
            inner.kick();
            Ok(Self { net, id, generation, socket })
        })
    }

    /// The name the printer is registered under.
    pub fn name(&self) -> String {
        self.net
            .with(|inner| inner.get::<PortState>(self.id).name.clone())
    }

    /// The socket its NBP name points at.
    pub fn socket(&self) -> u8 {
        self.socket
    }

    /// A handle for reading and changing the printer's name from another task
    /// while this one is busy inside [`Printer::run`].
    pub fn name_handle(&self) -> PrinterName<'a, P> {
        PrinterName {
            net: self.net,
            id: self.id,
            generation: self.generation,
        }
    }

    /// For an ImageWriter, whether a colour ribbon is reported: the printer's
    /// own answer once it has given one, optimistic until then.
    pub fn colour_ribbon(&self) -> Option<bool> {
        self.net
            .with(|inner| inner.get::<PortState>(self.id).role.colour_ribbon())
    }

    /// Serve the printer: write job bytes to `tx`, feed what `rx` produces
    /// back to the client, and return at the next [`PrinterEvent`]. Call it
    /// in a loop. The protocol keeps running between calls, and while a
    /// write is blocked, so status requests and keep-alives are answered
    /// regardless.
    ///
    /// `rx` must be cancel safe, as a UART or channel reader is: a read is
    /// abandoned whenever there are job bytes to write instead.
    pub async fn run<W: Write, R: Read>(&mut self, tx: &mut W, rx: &mut R) -> Result<PrinterEvent, PrinterError> {
        let id = self.id;
        let mut out = [0u8; 256];
        let mut input = [0u8; 64];
        loop {
            let event = self
                .net
                .with(|inner| inner.get::<PortState>(id).next_event());
            match event {
                Some(PortEvent::Event(e)) => return Ok(e),
                Some(PortEvent::Rename(raw)) => return Ok(self.rename(&raw)),
                None => {}
            }

            let n = self.net.with(|inner| {
                let s = inner.get::<PortState>(id);
                let n = s.to_printer.len().min(out.len());
                for (dst, b) in out.iter_mut().zip(s.to_printer.drain(..n)) {
                    *dst = b;
                }
                s.writing += n;
                n
            });
            if n > 0 {
                // A guard, not a call after the await, so a write abandoned
                // mid-way still gives its bytes back to the window.
                let guard = WriteGuard { net: self.net, id, n };
                let result = tx.write_all(&out[..n]).await;
                drop(guard);
                result.map_err(|e| PrinterError::Write(e.kind()))?;
                continue;
            }

            let ready = self.net.wait_on::<PortState, _>(id, |s| {
                let event_ready = s
                    .events
                    .front()
                    .is_some_and(|&(after, _)| after <= s.written_total);
                (event_ready || !s.to_printer.is_empty()).then_some(())
            });
            match select(rx.read(&mut input), ready).await {
                Either::First(Ok(0)) => return Err(PrinterError::PortClosed),
                Either::First(Ok(n)) => self.net.with(|inner| {
                    let now = P::now();
                    let s = inner.get::<PortState>(id);
                    s.role.printer_input(&input[..n], now);
                    s.settle(now);
                    inner.kick();
                }),
                Either::First(Err(e)) => return Err(PrinterError::Read(e.kind())),
                Either::Second(()) => {}
            }
        }
    }

    /// Re-register under a client's new name, or keep the old one.
    fn rename(&mut self, raw: &[u8]) -> PrinterEvent {
        // The wire carries MacRoman. Read as UTF-8 that accepts ASCII and
        // refuses nearly everything else, which beats registering a name
        // the Chooser would show mangled.
        let Ok(name) = core::str::from_utf8(raw) else {
            return PrinterEvent::RenameRejected;
        };
        match self.name_handle().set(name) {
            Ok(()) => PrinterEvent::Renamed(name.to_string()),
            Err(_) => PrinterEvent::RenameRejected,
        }
    }
}

/// Why [`PrinterName::set`] did not rename the printer. The old name stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameError {
    /// The name is empty, too long, or carries an NBP delimiter or wildcard.
    BadName,
    /// The printer this handle came from has been dropped.
    Gone,
}

/// Reads and changes a [`Printer`]'s NBP name from outside the task that's
/// running it. It's `Copy`, and can outlive the printer: once the printer is
/// dropped, [`PrinterName::get`] returns `None` and [`PrinterName::set`]
/// fails with [`RenameError::Gone`], even if another printer has taken its
/// place.
pub struct PrinterName<'a, P: Platform> {
    net: Net<'a, P>,
    id: usize,
    generation: u32,
}

impl<P: Platform> Clone for PrinterName<'_, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P: Platform> Copy for PrinterName<'_, P> {}

impl<P: Platform> PrinterName<'_, P> {
    /// The name the printer is registered under, or `None` once it has been
    /// dropped.
    pub fn get(&self) -> Option<String> {
        self.net.with(|inner| {
            inner
                .try_get::<PortState>(self.id, self.generation)
                .map(|s| s.name.clone())
        })
    }

    /// Re-register the printer as `name` right away. If that fails the old
    /// name stays registered. Unlike a client's rename, [`Printer::run`]
    /// doesn't report this one, since the caller already knows about it.
    pub fn set(&self, name: &str) -> Result<(), RenameError> {
        let (id, generation) = (self.id, self.generation);
        self.net.with(|inner| {
            let (socket, new_entity, old) = {
                let s = inner
                    .try_get::<PortState>(id, generation)
                    .ok_or(RenameError::Gone)?;
                let new_entity = entity_name(name, &s.nbp_type).ok_or(RenameError::BadName)?;
                (s.socket, new_entity, s.registered.clone())
            };
            if let Some(old) = &old {
                inner.stack.nbp_unregister(old, socket);
            }
            if inner.stack.nbp_register(new_entity.clone(), socket).is_err() {
                // Not expected: `entity_name` only passes names NBP accepts,
                // and the old name is out of the way. Put it back rather than
                // leave the printer invisible.
                if let Some(old) = old {
                    let _ = inner.stack.nbp_register(old, socket);
                }
                return Err(RenameError::BadName);
            }
            let s = inner.get::<PortState>(id);
            s.registered = Some(new_entity);
            s.name = name.to_string();
            Ok(())
        })
    }
}

impl<P: Platform> Drop for Printer<'_, P> {
    fn drop(&mut self) {
        self.net.with(|inner| {
            if let Some(name) = inner.get::<PortState>(self.id).registered.take() {
                inner.stack.nbp_unregister(&name, self.socket);
            }
            inner.remove(self.id);
        });
    }
}

struct WriteGuard<'a, P: Platform> {
    net: Net<'a, P>,
    id: usize,
    n: usize,
}

/// Hands a write's bytes back to the window when the write is over, however
/// it ended.
impl<P: Platform> Drop for WriteGuard<'_, P> {
    fn drop(&mut self) {
        let (id, n) = (self.id, self.n);
        self.net.with(|inner| {
            let s = inner.get::<PortState>(id);
            s.writing -= n;
            // Counted even when the write failed or was abandoned: those
            // bytes are gone, and an event queued behind them must not wait
            // forever.
            s.written_total += n as u64;
            s.settle(P::now());
            inner.kick();
        });
    }
}

/// `<name>:<nbp_type>@*`, or `None` if `name` cannot be one: empty, too
/// long, or carrying a delimiter that would split it.
/// `name:nbp_type@*`, if NBP will register it: no delimiters, no wildcards,
/// and short enough.
fn entity_name(name: &str, nbp_type: &str) -> Option<EntityName> {
    if name.is_empty() || name.contains([':', '@']) {
        return None;
    }
    EntityName::try_from(format!("{name}:{nbp_type}@*").as_str())
        .ok()
        .filter(EntityName::fully_qualified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_names_refuse_delimiters() {
        assert!(entity_name("Inky", "ImageWriter").is_some());
        assert!(entity_name("", "ImageWriter").is_none());
        assert!(entity_name("a:b", "ImageWriter").is_none());
        assert!(entity_name("a@b", "ImageWriter").is_none());
        assert!(entity_name(&"x".repeat(33), "ImageWriter").is_none());
    }

    #[test]
    fn entity_names_refuse_wildcards() {
        // NBP's registry refuses these, so catch them up front as bad names.
        assert!(entity_name("=", "ImageWriter").is_none());
        assert!(entity_name("Ink=", "ImageWriter").is_none());
        assert!(entity_name("Ink*", "ImageWriter").is_none());
        // The same names parse; it is only the wildcards that rule them out.
        assert!(EntityName::try_from("Ink=:ImageWriter@*").is_ok());
    }
}
