//! Printers served by a `tailtalk-net` node to the desktop's clients, which
//! are verified against real hardware, over an LLAP bridge.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{ImageWriterModel, Silent, StyleWriterModel, desktop, port, settle, start};
use tailtalk::adsp::{Adsp, AdspAddress, AdspStream};
use tailtalk::atp::{Atp, AtpAddress};
use tailtalk::imagewriter::ImageWriter;
use tailtalk::pap::PapClient;
use tailtalk::stylewriter::StyleWriterSession;
use tailtalk_core::stylewriter;
use tailtalk_net::printer::{FastClock, Printer, PrinterEvent, RenameError, WINDOW};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::LocalSet;

/// Long enough for an idle-time self ID query to be answered and settle.
const IDENT_SETTLE: Duration = Duration::from_millis(300);

/// Serve `printer` on its port in the background, forwarding its events.
fn serve<M: common::Model>(
    mut printer: Printer<'static, common::Tokio>,
    mut tx: common::PortTx<M>,
    mut rx: common::PortRx,
) -> mpsc::UnboundedReceiver<PrinterEvent> {
    let (events_tx, events) = mpsc::unbounded_channel();
    tokio::task::spawn_local(async move {
        loop {
            let ev = printer.run(&mut tx, &mut rx).await.expect("port failed");
            if events_tx.send(ev).is_err() {
                break;
            }
        }
    });
    events
}

fn atp_addr(addr: tailtalk_net::AppleTalkAddress, socket: u8) -> AtpAddress {
    AtpAddress {
        network_number: addr.network_number,
        node_number: addr.node_number,
        socket_number: socket,
    }
}

#[tokio::test]
async fn stylewriter_serves_a_desktop_session() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xC0FFEE, link);
            let addr = settle(net, &desk).await;

            let printer = Printer::stylewriter(net, "Sty", FastClock::Unsupported).unwrap();
            let socket = printer.socket();
            let (tx, rx) = port(StyleWriterModel::default());
            let mut events = serve(printer, tx, rx);

            // The full two-connection handshake: control connect, attention
            // 0x000B, in-band accept, control close, reverse data connection.
            let target = AdspAddress {
                network_number: addr.network_number,
                node_number: addr.node_number,
                socket_number: socket,
            };
            let mut session = StyleWriterSession::connect(&desk.ddp, target, "CrossTest", None)
                .await
                .expect("StyleWriter handshake failed");
            assert_eq!(events.recv().await, Some(PrinterEvent::JobStarted));

            // Identify the simulated printer through the byte pipe, which
            // needs the reverse direction working as well.
            let info = session.query_info().await.expect("query_info failed");
            assert_eq!(info.identity, "CS");
            assert!(info.color_capable());
            assert_eq!(info.buffer_idle(), Some(true));

            session.abort().await.expect("teardown failed");
            assert_eq!(
                events.recv().await,
                Some(PrinterEvent::JobEnded { clean: true })
            );
        })
        .await;
}

#[tokio::test]
async fn imagewriter_streams_a_job_verbatim_and_reads_the_ribbon() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xBEEF, link);
            let addr = settle(net, &desk).await;

            let printer = Printer::imagewriter(net, "Inky").unwrap();
            let listener = atp_addr(addr, printer.socket());
            let ident = Arc::new(Mutex::new(&b"IW10CF"[..]));
            let (tx, rx) = port(ImageWriterModel { ident: ident.clone() });
            let written = tx.written.clone();
            let mut events = serve(printer, tx, rx);

            // The idle-time self ID query goes out and is answered first.
            tokio::time::sleep(IDENT_SETTLE).await;
            let (_s, req, _r) = Atp::spawn(&desk.ddp, None).await;
            let status = PapClient::get_status_bytes(req, listener).await.unwrap();
            assert_eq!(status, vec![0x80, 0x00], "`IW10CF` means a colour ribbon");
            written.lock().unwrap().clear();

            // Bitmap bytes that would be flow control if this path used any.
            let mut job: Vec<u8> = b"\x1bG0016".to_vec();
            job.extend_from_slice(&[
                0x00, 0x11, 0x13, 0xFF, 0x1B, 0x04, 0x7F, 0x80, 0x11, 0x13, 0x00, 0xFF, 0x55,
                0xAA, 0x0D, 0x0A,
            ]);
            let (_s, req, resp) = Atp::spawn(&desk.ddp, None).await;
            let mut client = PapClient::new(req, resp);
            client.connect(listener).await.expect("OpenConn failed");
            assert_eq!(events.recv().await, Some(PrinterEvent::JobStarted));
            client.print(&job).await.expect("print failed");
            assert_eq!(events.recv().await, Some(PrinterEvent::JobEof));
            assert_eq!(*written.lock().unwrap(), job, "job bytes must pass untouched");

            // A black ribbon goes in; the between-jobs query notices.
            *ident.lock().unwrap() = b"IW10";
            client.close().await.expect("CloseConn failed");
            assert_eq!(
                events.recv().await,
                Some(PrinterEvent::JobEnded { clean: true })
            );
            tokio::time::sleep(IDENT_SETTLE).await;
            let (_s, req, _r) = Atp::spawn(&desk.ddp, None).await;
            let status = PapClient::get_status_bytes(req, listener).await.unwrap();
            assert_eq!(status, vec![0x00, 0x00]);
        })
        .await;
}

#[tokio::test]
async fn imagewriter_rename_reregisters_and_reports() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xBEEF, link);
            let addr = settle(net, &desk).await;

            let printer = Printer::imagewriter(net, "Inky").unwrap();
            let listener = atp_addr(addr, printer.socket());
            let (tx, rx) = port(Silent);
            let written = tx.written.clone();
            let mut events = serve(printer, tx, rx);

            let mut iw = ImageWriter::connect(&desk.ddp, listener).await.unwrap();
            iw.set_name("Renamed").await.unwrap();
            iw.close().await.unwrap();

            let mut seen = Vec::new();
            while let Some(ev) = events.recv().await {
                let done = matches!(ev, PrinterEvent::JobEnded { .. });
                seen.push(ev);
                if done {
                    break;
                }
            }
            assert!(
                seen.contains(&PrinterEvent::Renamed("Renamed".into())),
                "events: {seen:?}"
            );
            // The rename is the card's, not the printer's: `ESC b` must never
            // reach the port, where the printer would print the name.
            assert!(!written.lock().unwrap().windows(2).any(|w| w == b"\x1bb"));
        })
        .await;
}

/// A rename and a move to another NBP type both keep the printer running. A
/// StyleWriter moves to the type a Mac looks up for its model and keeps its
/// name, a rename keeps the type, and a name or type NBP could not register
/// leaves the printer as it was.
#[tokio::test]
async fn name_handle_renames_while_the_printer_runs() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xF00D, link);
            settle(net, &desk).await;

            let printer = Printer::stylewriter(net, "Inky", FastClock::Unsupported).unwrap();
            let name = printer.name_handle();
            let (tx, rx) = port(Silent);
            let mut events = serve(printer, tx, rx);

            assert_eq!(name.nbp_type().as_deref(), Some(stylewriter::NBP_TYPE));
            name.set_type(stylewriter::NBP_TYPE_1200).unwrap();
            assert_eq!(name.nbp_type().as_deref(), Some(stylewriter::NBP_TYPE_1200));
            assert_eq!(name.get().as_deref(), Some("Inky"));
            assert_eq!(name.set_type("Bad:Type"), Err(RenameError::BadName));
            assert_eq!(name.nbp_type().as_deref(), Some(stylewriter::NBP_TYPE_1200));

            name.set("Renamed").unwrap();
            assert_eq!(name.get().as_deref(), Some("Renamed"));
            assert_eq!(name.nbp_type().as_deref(), Some(stylewriter::NBP_TYPE_1200));
            assert_eq!(name.set("No:colons"), Err(RenameError::BadName));
            assert_eq!(name.get().as_deref(), Some("Renamed"));
            // We made the rename ourselves, so the printer shouldn't report it
            // back as an event.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(events.try_recv().is_err());
        })
        .await;
}

/// A handle kept after its printer is dropped refers to nothing, even once
/// another printer has taken the dropped one's place.
#[tokio::test]
async fn name_handle_outliving_its_printer_touches_no_other() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xFEED, link);
            settle(net, &desk).await;

            let first = Printer::stylewriter(net, "First", FastClock::Unsupported).unwrap();
            let stale = first.name_handle();
            drop(first);
            let second = Printer::stylewriter(net, "Second", FastClock::Unsupported).unwrap();

            assert_eq!(stale.get(), None);
            assert_eq!(stale.set("Hijacked"), Err(RenameError::Gone));
            assert_eq!(second.name(), "Second");
            assert_eq!(second.name_handle().get().as_deref(), Some("Second"));
        })
        .await;
}

/// A port slower than the network holds the client back, rather than the
/// job piling up in memory.
#[tokio::test]
async fn slow_port_pushes_back_on_the_client() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xBEEF, link);
            let addr = settle(net, &desk).await;

            let printer = Printer::pap(net, "Slow", "LaserWriter", b"idle").unwrap();
            let listener = atp_addr(addr, printer.socket());
            let (mut tx, rx) = port(Silent);
            // 256-byte writes at 5 ms each: about 50 KB/s.
            tx.delay = Some(Duration::from_millis(5));
            let written = tx.written.clone();
            let _events = serve(printer, tx, rx);

            let job: Vec<u8> = (0..24 * 1024).map(|i| (i % 251) as u8).collect();
            let (_s, req, resp) = Atp::spawn(&desk.ddp, None).await;
            let mut client = PapClient::new(req, resp);
            client.connect(listener).await.unwrap();
            client.print(&job).await.unwrap();

            // The client is done once the last pull is answered. At that
            // point at most one window can still be on its way to the port.
            let behind = job.len() - written.lock().unwrap().len();
            assert!(
                behind <= WINDOW,
                "{behind} bytes buffered when the client finished, window is {WINDOW}"
            );

            client.close().await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert_eq!(*written.lock().unwrap(), job);
        })
        .await;
}

/// Ask a StyleWriter's adapter, with attention 0x0006, whether its output has
/// drained, returning the in-band reply.
async fn output_drained(data: &mut AdspStream) -> [u8; 2] {
    data.send_attention(0x0006, &[0x00]).await.unwrap();
    let mut reply = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), data.read_exact(&mut reply))
        .await
        .expect("no reply to 0x0006")
        .unwrap();
    reply
}

/// Attention 0x0006 says "not yet" while job bytes wait on a slow port, and
/// "drained" once every one of them has been written.
#[tokio::test]
async fn stylewriter_reports_when_its_output_has_drained() {
    LocalSet::new()
        .run_until(async {
            let (desk, link) = desktop();
            let net = start(0xD0D0, link);
            let addr = settle(net, &desk).await;

            let printer = Printer::stylewriter(net, "Sty", FastClock::Unsupported).unwrap();
            let target = AdspAddress {
                network_number: addr.network_number,
                node_number: addr.node_number,
                socket_number: printer.socket(),
            };
            let (mut tx, rx) = port(StyleWriterModel::default());
            tx.delay = Some(Duration::from_millis(300));
            let written = tx.written.clone();
            let mut events = serve(printer, tx, rx);

            // The handshake, as the Mac makes it.
            let (data_socket, mut listener) = Adsp::bind(&desk.ddp, None).await.unwrap();
            let mut ctrl = Adsp::connect(&desk.ddp, target).await.unwrap();
            let mut request = vec![0, 0, 0, data_socket, 0];
            request.resize(70, 0);
            ctrl.send_attention(0x000B, &request).await.unwrap();
            let mut result = [0u8; 2];
            ctrl.read_exact(&mut result).await.unwrap();
            assert_eq!(result, [0x00, 0x00]);
            ctrl.close().await.unwrap();
            let mut data = listener.accept().await.unwrap();
            assert_eq!(events.recv().await, Some(PrinterEvent::JobStarted));

            let job = vec![0x55; 2048];
            data.write_all(&job).await.unwrap();
            data.write_eom().await.unwrap();
            assert_eq!(output_drained(&mut data).await, [0x00, 0x00], "the port is still writing");

            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while written.lock().unwrap().len() < job.len() {
                assert!(tokio::time::Instant::now() < deadline, "the port never took the job");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(output_drained(&mut data).await, [0xFF, 0xFF]);
        })
        .await;
}
