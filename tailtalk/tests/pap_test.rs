use tailtalk::DataLinkProtocol;
use std::sync::Arc;
use std::time::Duration;
use tailtalk::{
    DataLinkPacket, OutboundHandle,
    addressing::Addressing,
    atp::Atp,
    ddp::DdpProcessor,
    route_table::{LearningMode, RouteTable},
    echo::Echo,
    nbp::{Nbp, RegisteredName},
    pap::PapClient,
};
use tailtalk_packets::{
    aarp::AddressSource,
    pap::{PapFunction, PapPacket},
};
use tokio::sync::{broadcast, mpsc};

#[derive(Clone, Debug)]
struct WirePacket {
    packet: Arc<DataLinkPacket>,
    src_mac: [u8; 6],
}

struct TestHub {
    tx: broadcast::Sender<WirePacket>,
    _rx: broadcast::Receiver<WirePacket>,
}

impl TestHub {
    fn new() -> Self {
        let (tx, _rx) = broadcast::channel(100);
        Self { tx, _rx }
    }

    fn subscribe(&self) -> broadcast::Receiver<WirePacket> {
        self.tx.subscribe()
    }

    async fn run(&self, mut frame_rx: mpsc::Receiver<WirePacket>) {
        while let Some(pkt) = frame_rx.recv().await {
            let _ = self.tx.send(pkt);
        }
    }
}

struct TestClient {
    #[allow(dead_code)]
    mac: [u8; 6],
    #[allow(dead_code)]
    addressing: tailtalk::addressing::AddressingHandle,
    #[allow(dead_code)]
    ddp: tailtalk::ddp::DdpHandle,
    nbp: tailtalk::nbp::NbpHandle,
    #[allow(dead_code)]
    echo: tailtalk::echo::EchoHandle,
    // We expose ATP parts to construct PapClient or Mock Server
    atp_req: tailtalk::atp::AtpRequestor,
    atp_resp: tailtalk::atp::AtpResponder,
}

impl TestClient {
    async fn new(
        mac: [u8; 6],
        hub_tx: mpsc::Sender<WirePacket>,
        hub_rx: broadcast::Receiver<WirePacket>,
        atp_socket: Option<u8>,
    ) -> Self {
        let (out_tx, mut out_rx) = mpsc::channel(100);
        let outbound_handle = OutboundHandle::new(out_tx);

        let hub_tx_clone = hub_tx.clone();
        tokio::spawn(async move {
            while let Some(pkt) = out_rx.recv().await {
                let wire_pkt = WirePacket {
                    packet: Arc::new(pkt),
                    src_mac: mac,
                };
                let _ = hub_tx_clone.send(wire_pkt).await;
            }
        });

        let addressing = Addressing::spawn(Some(mac), outbound_handle.clone(), None, AddressSource::EtherTalkPhase2);
        let ddp = DdpProcessor::spawn(Some(addressing.clone()), None, outbound_handle.clone(), RouteTable::new(LearningMode::Static));

        let echo = Echo::spawn(&ddp).await;
        // spawn returns (socket, req, resp)
        let (_sock, atp_req, atp_resp) = Atp::spawn(&ddp, atp_socket).await;

        let nbp = Nbp::spawn(&ddp, Some(addressing.clone()), None, RouteTable::new(LearningMode::Static)).await;

        let mut rx = hub_rx;
        let ddp_handle = ddp.clone();
        let addressing_handle = addressing.clone();

        tokio::spawn(async move {
            loop {
                if let Ok(wire_pkt) = rx.recv().await {
                    let src_mac = wire_pkt.src_mac;
                    let pkt = &wire_pkt.packet;

                    if src_mac == mac {
                        continue;
                    }

                    // Accept packets for us, broadcast, or [0; 6]
                    let dest_mac = if let tailtalk::addressing::Node::EtherTalkPhase2(m) = pkt.dest_node { m } else { [0; 6] };
                    if dest_mac == mac || tailtalk::addressing::Addressing::is_broadcast_mac(dest_mac, AddressSource::EtherTalkPhase2) {
                        match pkt.protocol {
                            DataLinkProtocol::Ddp => ddp_handle.received_pkt(
                                &pkt.payload,
                                AddressSource::EtherTalkPhase2,
                                src_mac,
                            ),
                            DataLinkProtocol::Aarp => {
                                let _ = addressing_handle
                                    .received_pkt(&pkt.payload, AddressSource::EtherTalkPhase2);
                            }
                            DataLinkProtocol::LlapEnq | DataLinkProtocol::LlapAck => {}
                        }
                    }
                }
            }
        });

        Self {
            mac,
            addressing,
            ddp,
            nbp,
            echo,
            atp_req,
            atp_resp,
        }
    }

    fn into_pap_client(self) -> PapClient {
        PapClient::new(self.atp_req, self.atp_resp)
    }
}

#[tokio::test]
async fn test_pap_print_job() {
    let _ = tracing_subscriber::fmt().try_init();

    // 1. Setup Hub
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);

    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    // 2. Setup Printer (Server)
    let mac_printer = [0x00, 0x01, 0x02, 0x03, 0x04, 0xAA];
    // PAP usually on arbitrary socket, registered via NBP.

    // 3. Setup Workstation (Client)
    let mac_client = [0x00, 0x01, 0x02, 0x03, 0x04, 0xBB];
    let workstation =
        TestClient::new(mac_client, hub_in_tx.clone(), hub_ref.subscribe(), None).await;

    // Wait for addressing
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // 4. Printer registers "TestPrinter:LaserWriter@*"
    // Re-spawn printer with fixed socket 130
    let mut printer = TestClient::new(
        mac_printer,
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        Some(130),
    )
    .await;

    printer
        .nbp
        .register(RegisteredName {
            name: "TestPrinter:LaserWriter@*".try_into().unwrap(),
            sock_num: 130,
        })
        .await
        .expect("Printer registration failed");

    // 5. Workstation registers NBP

    // 6. Workstation looks up Printer
    tokio::time::sleep(Duration::from_millis(500)).await;
    let results = workstation
        .nbp
        .lookup("TestPrinter:LaserWriter@*".try_into().unwrap())
        .await
        .expect("Lookup failed");
    assert!(!results.is_empty());
    let target = &results[0];

    let printer_addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };

    // 7. Workstation connects to Printer
    let mut pap_client = workstation.into_pap_client();

    let connect_task = tokio::spawn(async move {
        pap_client
            .connect(printer_addr)
            .await
            .expect("Connect failed");
        pap_client
    });

    // 8. Printer handles OpenConn
    let conn_id;
    let workstation_addr;

    // We expect OpenConn
    if let Some(req) = printer.atp_resp.next().await {
        let pap_pkt =
            PapPacket::parse_from_atp(req.user_bytes, &req.data).expect("Failed to parse PAP");
        assert_eq!(pap_pkt.function, PapFunction::OpenConn);
        // Verify ConnectionID matches source socket (as per protocol/user request)
        assert_eq!(pap_pkt.connection_id, req.source.socket_number);
        // Verify Payload Socket matches source socket
        assert_eq!(pap_pkt.data[0], req.source.socket_number);

        // Save source address
        workstation_addr = req.source;

        // Respond with OpenConnReply
        // ConnID = 55 (arbitrary)
        conn_id = 55;
        let reply = PapPacket {
            connection_id: conn_id,
            function: PapFunction::OpenConnReply,
            sequence_num: 0,
            eof: false,
            data: vec![130, 8, 0, 0], // Socket=130, Flow=8, Result=0
        };
        let (ub, d) = reply.to_atp_parts();
        req.send_response(d.to_vec(), ub)
            .await
            .expect("Failed to send OpenConnReply");
    } else {
        panic!("Printer received no request");
    }

    let mut pap_client = connect_task.await.expect("Connect task failed");
    println!("Workstation connected.");

    // 9. Workstation sends Print Data
    // Spawn task for workstation print
    let print_data = b"Hello, world! This is a print job.".to_vec();
    let print_data_clone = print_data.clone();

    let _print_task = tokio::spawn(async move {
        pap_client
            .print(&print_data_clone)
            .await
            .expect("Print failed");
        pap_client
    });

    // 10. Printer Request Data (SendData)
    // Wait for client to prepare
    tokio::time::sleep(Duration::from_millis(200)).await;

    println!("Printer sending SendData...");
    let send_data_pkt = PapPacket {
        connection_id: conn_id,
        function: PapFunction::SendData,
        sequence_num: 1,
        eof: false,
        data: vec![],
    };
    let (ub, d) = send_data_pkt.to_atp_parts();

    // Printer sends request to Workstation using AtpRequestor
    let (resp_data, _resp_ub) = printer
        .atp_req
        .send_request(workstation_addr, ub, d.to_vec())
        .await
        .expect("SendData failed");

    println!("Printer got {} bytes", resp_data.len());
    assert_eq!(resp_data, print_data);

    println!("✓ PAP Print test passed!");

    // 11. Cleanup

    hub_task.abort();
}

/// A sink that collects received jobs for assertions.
struct CollectSink(Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>);

impl tailtalk::pap::PrintSink for CollectSink {
    fn receive_job(
        &self,
        job: tailtalk::pap::PrintJob,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + '_>> {
        let store = self.0.clone();
        Box::pin(async move {
            store.lock().await.push(job.data);
            Ok(())
        })
    }
}

/// A PQP query job and a print job over one connection, each followed by a
/// stdout read, then a client-initiated close.
#[tokio::test]
async fn test_pap_server_query_session() {
    let _ = tracing_subscriber::fmt().try_init();

    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);
    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let mac_printer = [0x00, 0x01, 0x02, 0x03, 0x04, 0xCC];
    let mac_client = [0x00, 0x01, 0x02, 0x03, 0x04, 0xDD];

    let workstation =
        TestClient::new(mac_client, hub_in_tx.clone(), hub_ref.subscribe(), None).await;
    // A second workstation that polls status / tries to connect mid-session.
    let observer = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0xEE],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        None,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let printer = TestClient::new(
        mac_printer,
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        Some(131),
    )
    .await;
    printer
        .nbp
        .register(RegisteredName {
            name: "QueryPrinter:LaserWriter@*".try_into().unwrap(),
            sock_num: 131,
        })
        .await
        .expect("Printer registration failed");

    let jobs = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut server = tailtalk::pap::PapServer::new(
        printer.atp_resp,
        printer.ddp.clone(),
        131,
        tailtalk::pap::PrinterAttributes::default(),
        Box::new(CollectSink(jobs.clone())),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(500)).await;
    let results = workstation
        .nbp
        .lookup("QueryPrinter:LaserWriter@*".try_into().unwrap())
        .await
        .expect("Lookup failed");
    assert!(!results.is_empty());
    let target = &results[0];
    let printer_addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };

    let mut pap = workstation.into_pap_client();
    pap.connect(printer_addr).await.expect("Connect failed");

    // The listener must keep answering while a session is open: status polls
    // succeed, but another client's OpenConn gets a busy result.
    let status = PapClient::get_status(observer.atp_req.clone(), printer_addr)
        .await
        .expect("Status poll during session failed");
    assert!(
        status.contains("busy"),
        "status during a session should report busy, got: {status}"
    );
    let mut second = observer.into_pap_client();
    assert!(
        second
            .connect_with_timeout(printer_addr, Duration::from_millis(100))
            .await
            .is_err(),
        "second connection during a session must be refused as busy"
    );

    // 1. PQP query job.
    let query = b"%!PS-Adobe-3.0 Query\r%%?BeginQuery: RBIUAMListQuery\r(*)= flush\r%%?EndQuery: *\r%%EOF\r";
    pap.print(query).await.expect("Query job failed");
    let answer = pap.read_response().await.expect("Query answer failed");
    assert_eq!(
        answer,
        b"*\r",
        "RBIUAMListQuery must be answered with '*' (no authentication)"
    );

    // 2. A real print job over the same connection.
    let ps_job = b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r".to_vec();
    pap.print(&ps_job).await.expect("Print job failed");
    let stdout = pap.read_response().await.expect("Job stdout read failed");
    assert!(stdout.is_empty(), "print job should produce no stdout");

    // 3. Client closes the connection; the server must answer CloseConnReply.
    tokio::time::timeout(Duration::from_secs(10), pap.close())
        .await
        .expect("Close timed out")
        .expect("Close failed");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let jobs = jobs.lock().await;
    assert_eq!(jobs.len(), 1, "sink must receive exactly the one print job");
    assert_eq!(jobs[0], ps_job);

    println!("✓ PAP query session test passed!");

    hub_task.abort();
}

/// Stands in for a pre-3.0 LaserWriter driver, which `PapClient` cannot impersonate:
/// it writes a job without ever setting the PAP eof flag, then blocks on the read
/// waiting for the printer to speak first.
struct LegacyDriver {
    conn_id: u8,
    conn_addr: tailtalk::atp::AtpAddress,
    atp_req: tailtalk::atp::AtpRequestor,
    /// The driver's own read sequence number, advanced once each read is answered.
    read_seq: u16,
    /// ATP bitmap on a read, i.e. how many response packets the driver will take.
    read_bitmap: u8,
    writer: tokio::task::JoinHandle<()>,
}

impl LegacyDriver {
    /// OpenConn by hand, then answer the server's SendData polls out of `writes`,
    /// one `(block, eof)` per poll, going quiet once they run out.
    async fn connect(
        client: TestClient,
        listener_addr: tailtalk::atp::AtpAddress,
        read_bitmap: u8,
        writes: Vec<(Vec<u8>, bool)>,
    ) -> Self {
        let conn_id = client.atp_req.socket_number;
        let open = PapPacket {
            connection_id: conn_id,
            function: PapFunction::OpenConn,
            sequence_num: 0,
            eof: false,
            data: vec![client.atp_req.socket_number, 0x08, 0x00, 0x00],
        };
        let (ub, data) = open.to_atp_parts();
        let (reply_data, reply_ub) = client
            .atp_req
            .send_request_with_bitmap(listener_addr, ub, data.to_vec(), 0x01)
            .await
            .expect("OpenConn failed");
        let reply = PapPacket::parse_from_atp(reply_ub, &reply_data).expect("OpenConnReply parse");
        assert_eq!(reply.function, PapFunction::OpenConnReply);
        assert_eq!(&reply.data[2..4], &[0, 0], "OpenConn must succeed, not report busy");
        let conn_addr = tailtalk::atp::AtpAddress {
            socket_number: reply.data[0],
            ..listener_addr
        };

        let mut atp_resp = client.atp_resp;
        let writer = tokio::spawn(async move {
            let mut writes = writes.into_iter();
            while let Some(req) = atp_resp.next().await {
                let Ok(pap) = PapPacket::parse_from_atp(req.user_bytes, &req.data) else {
                    continue;
                };
                if pap.function != PapFunction::SendData {
                    continue;
                }
                let Some((block, eof)) = writes.next() else {
                    continue; // Nothing left to say until the printer answers.
                };
                let resp = PapPacket {
                    connection_id: conn_id,
                    function: PapFunction::Data,
                    sequence_num: pap.sequence_num,
                    eof,
                    data: block,
                };
                let (ub, d) = resp.to_atp_parts();
                let _ = req.send_response(d, ub).await;
            }
        });

        Self { conn_id, conn_addr, atp_req: client.atp_req, read_seq: 1, read_bitmap, writer }
    }

    /// Post the read the driver blocks on and wait for the printer to speak. Before
    /// the fix this waited forever, retransmitting with nothing ever coming back.
    async fn read(&mut self) -> PapPacket {
        let read = PapPacket {
            connection_id: self.conn_id,
            function: PapFunction::SendData,
            sequence_num: self.read_seq,
            eof: false,
            data: vec![],
        };
        let (ub, d) = read.to_atp_parts();
        let (data, user_bytes) = tokio::time::timeout(
            Duration::from_secs(10),
            self.atp_req
                .send_request_with_bitmap(self.conn_addr, ub, d.to_vec(), self.read_bitmap),
        )
        .await
        .expect("no answer: the pre-3.0 query deadlock is back")
        .expect("read failed");
        self.read_seq += 1;
        let answer = PapPacket::parse_from_atp(user_bytes, &data).expect("answer parse");
        assert_eq!(answer.function, PapFunction::Data);
        answer
    }
}

/// Spin up a printer emulator and return the workstation, its address, and the
/// jobs its sink collects.
async fn legacy_printer(
    name: &str,
    socket: u8,
    mac: u8,
    attrs: tailtalk::pap::PrinterAttributes,
) -> (
    TestClient,
    tailtalk::atp::AtpAddress,
    Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>,
    tokio::task::JoinHandle<()>,
) {
    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);
    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let workstation = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, mac, 0xDD],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        None,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let printer = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, mac, 0xCC],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        Some(socket),
    )
    .await;
    printer
        .nbp
        .register(RegisteredName {
            name: name.try_into().unwrap(),
            sock_num: socket,
        })
        .await
        .expect("Printer registration failed");

    let jobs = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut server = tailtalk::pap::PapServer::new(
        printer.atp_resp,
        printer.ddp.clone(),
        socket,
        attrs,
        Box::new(CollectSink(jobs.clone())),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let found = workstation
        .nbp
        .lookup(name.try_into().unwrap())
        .await
        .expect("Lookup failed");
    let target = found.first().expect("printer not found");
    let addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };
    (workstation, addr, jobs, hub_task)
}

/// A pre-3.0 driver's query: written with no eof flag, then the driver blocks on
/// the read waiting for the printer to speak first.
///
/// LaserWriter 8 ends a query job with the PAP eof flag, which is what tells the
/// server the job is complete and can be answered. The LaserWriter 7.x-era drivers
/// (this is a System 7 Mac talking to us as a "Color LaserWriter 12/600") never
/// send it, so a server that waits for eof and a driver that waits for an answer
/// sit staring at each other until the user gives up. Captured in the wild as an
/// endless exchange of unanswered SendData polls in both directions.
#[tokio::test]
async fn test_pap_server_answers_query_without_eof() {
    let _ = tracing_subscriber::fmt().try_init();

    let (workstation, listener_addr, jobs, hub_task) = legacy_printer(
        "OldPrinter:LaserWriter@*",
        133,
        0x04,
        tailtalk::pap::PrinterAttributes::default(),
    )
    .await;

    let query = b"%!PS-Adobe-2.0 Query\r\
        %%Title: Query for PatchPrep\r\
        %%?BeginProcSetQuery: \"(AppleDict md)\" 71 0\r\
        userdict/PV known{userdict begin PV 1 ge{(1)}{(2)}ifelse end}\
        {/md where{pop(2)}{(0)}ifelse}ifelse = flush\r\
        %%?EndProcSetQuery: unknown\r"
        .to_vec();
    let mut driver = LegacyDriver::connect(workstation, listener_addr, 0x0f, vec![(query, false)]).await;

    let answer = driver.read().await;
    assert_eq!(
        answer.data, b"0\r",
        "the AppleDict ProcSet is not resident, so the answer is 0"
    );
    assert!(answer.eof, "eof ends the response so the driver stops reading");

    assert!(
        jobs.lock().await.is_empty(),
        "a query must never be handed to the print sink"
    );

    println!("✓ PAP pre-3.0 query test passed!");

    driver.writer.abort();
    hub_task.abort();
}

/// The other pre-3.0 shape, captured from a IIgs-era driver over EtherTalk.
///
/// Three things here that the first capture did not have: a `statusdict/jobname`
/// prologue arriving in its own packet ahead of the job, so the `%!PS-Adobe` header
/// is not at the front of the buffer; two query blocks crammed into one PAP packet,
/// which is off-spec but which Netatalk and Apple's spoolers accept; and a font list
/// query, whose answer has to come back one write per PAP packet rather than all at
/// once. The driver still never sets eof, and its reads take one packet each.
#[tokio::test]
async fn test_pap_server_answers_printer_and_font_list_query() {
    let _ = tracing_subscriber::fmt().try_init();

    let attrs = tailtalk::pap::PrinterAttributes {
        product_name: "LaserWriter Plus".to_string(),
        ps_version: "47.0".to_string(),
        ps_revision: 1,
        resident_fonts: vec!["Times-Roman".to_string(), "Helvetica".to_string()],
        ..tailtalk::pap::PrinterAttributes::default()
    };
    let (workstation, listener_addr, jobs, hub_task) =
        legacy_printer("OldGSPrinter:LaserWriter@*", 134, 0x05, attrs).await;

    let prologue = b"statusdict/jobname(User - Byte Knight, Document - BK.Greet.f.IIgs)put\r".to_vec();
    let query = b"%!PS-Adobe-2.0 Query\r\
        %%?BeginPrinterQuery\r\
        statusdict begin revision == version == product == end flush\r\
        %%?EndPrinterQuery: Unknown\r\
        %%?BeginFontListQuery\r\
        FontDirectory{pop = flush}forall/* = flush\r\
        %%?EndFontListQuery: /*\r\
        %%EOF\r"
        .to_vec();
    let mut driver =
        LegacyDriver::connect(workstation, listener_addr, 0x01, vec![(prologue, false), (query, false)]).await;

    // The printer query flushes once, after all three `==`, so its three lines are
    // one write. It is not the last one, so no eof yet.
    let first = driver.read().await;
    assert_eq!(first.data, b"1 \n(47.0)\n(LaserWriter Plus)\n");
    assert!(!first.eof, "the font list still has to follow");

    // The font list flushes per name, so each one has to come back in a packet of
    // its own, and so does the `*` that terminates the list. Batching them into one
    // response is what the driver will not accept.
    for expected in [&b"Times-Roman\n"[..], b"Helvetica\n"] {
        let write = driver.read().await;
        assert_eq!(write.data, expected);
        assert!(!write.eof, "the font list is not finished yet");
    }
    let last = driver.read().await;
    assert_eq!(last.data, b"*\n");
    assert!(last.eof, "the last write of the job's output ends it");

    assert!(
        jobs.lock().await.is_empty(),
        "a query must never be handed to the print sink"
    );

    println!("✓ PAP printer/font-list query test passed!");

    driver.writer.abort();
    hub_task.abort();
}

/// What the pre-3.0 drivers actually do next: print, over the same connection.
///
/// Their query job ends with neither a PAP eof nor a `%%EOF`, so nothing in the
/// stream says where it stopped. The print job that follows is what says so, by
/// arriving with a header of its own. Get that wrong and the print job reads as
/// more of the query, produces no answers, and is dropped without a trace, which
/// is a worse bug than the deadlock it comes from: the Mac believes it printed.
///
/// The driver here also hands the print job over before collecting its query
/// answer, so the answer has to survive being overtaken.
#[tokio::test]
async fn test_pap_server_prints_after_an_unterminated_query() {
    let _ = tracing_subscriber::fmt().try_init();

    let (workstation, listener_addr, jobs, hub_task) = legacy_printer(
        "OldPrinter2:LaserWriter@*",
        135,
        0x06,
        tailtalk::pap::PrinterAttributes::default(),
    )
    .await;

    // No %%EOF, no eof flag: this query just stops.
    let query = b"%!PS-Adobe-2.0 Query\r\
        %%?BeginProcSetQuery: \"(AppleDict md)\" 71 0\r\
        userdict/PV known{pop(2)}{(0)}ifelse = flush\r\
        %%?EndProcSetQuery: unknown\r"
        .to_vec();
    let ps_job = b"%!PS-Adobe-3.0\r%%Title: (Greetings)\rshowpage\r%%EOF\r".to_vec();
    let mut driver = LegacyDriver::connect(
        workstation,
        listener_addr,
        0x0f,
        vec![(query, false), (ps_job.clone(), true)],
    )
    .await;

    // Both writes go over before anything is read back, so the query answer is
    // still sitting unread when the print job completes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while jobs.lock().await.is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the print job never reached the sink: it was swallowed by the query buffer"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        *jobs.lock().await,
        vec![ps_job],
        "the sink must get the print job alone, with no query text glued to the front"
    );

    let answer = driver.read().await;
    assert_eq!(
        answer.data, b"0\r",
        "the query answer must outlive the print job that overtook it"
    );

    println!("✓ PAP print-after-query test passed!");

    driver.writer.abort();
    hub_task.abort();
}

/// A printer emulator built the way the real callers build it: handed only a
/// responder, with the requesting half dropped.
///
/// `TalkStack::pap_server` and the GUI's LaserWriter bridge both do that, so
/// the responder alone has to hold the ATP socket open. Not covered by the test
/// above, which only partially moves its `TestClient` and so keeps `atp_req`
/// alive throughout. The failure guarded against is silent: the socket is
/// released as the server is built, leaving a printer that answers NBP lookups
/// but never a PAP packet.
#[tokio::test]
async fn test_pap_server_survives_requestor_drop() {
    let _ = tracing_subscriber::fmt().try_init();

    let hub = TestHub::new();
    let (hub_in_tx, hub_in_rx) = mpsc::channel(100);
    let hub_ref = Arc::new(hub);
    let hub_runner = hub_ref.clone();
    let hub_task = tokio::spawn(async move {
        hub_runner.run(hub_in_rx).await;
    });

    let workstation = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0xDD],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        None,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    const PRINTER_SOCKET: u8 = 132;
    let printer = TestClient::new(
        [0x00, 0x01, 0x02, 0x03, 0x04, 0xCC],
        hub_in_tx.clone(),
        hub_ref.subscribe(),
        Some(PRINTER_SOCKET),
    )
    .await;
    printer
        .nbp
        .register(RegisteredName {
            name: "DropPrinter:LaserWriter@*".try_into().unwrap(),
            sock_num: PRINTER_SOCKET,
        })
        .await
        .expect("Printer registration failed");

    // Underscore bindings still own their values to the end of the test, so
    // every other handle stays up exactly as a real stack would keep it.
    let TestClient {
        mac: _mac,
        addressing: _addressing,
        ddp,
        nbp: _nbp,
        echo: _echo,
        atp_req,
        atp_resp,
    } = printer;

    // The point of the test: the responder is now the only thing holding the
    // socket. Wait out the actor's 250 ms retransmit tick so one that was going
    // to shut down has had the chance.
    drop(atp_req);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let jobs = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let mut server = tailtalk::pap::PapServer::new(
        atp_resp,
        ddp.clone(),
        PRINTER_SOCKET,
        tailtalk::pap::PrinterAttributes::default(),
        Box::new(CollectSink(jobs.clone())),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // NBP lives on its own socket, so discovery still works even with the ATP
    // socket gone. It is the PAP exchange below that actually proves anything.
    let results = workstation
        .nbp
        .lookup("DropPrinter:LaserWriter@*".try_into().unwrap())
        .await
        .expect("Lookup failed");
    assert!(!results.is_empty(), "printer did not answer NBP");
    let target = &results[0];
    let printer_addr = tailtalk::atp::AtpAddress {
        network_number: target.network_number,
        node_number: target.node_id,
        socket_number: target.socket_number,
    };

    let mut pap = workstation.into_pap_client();
    // A released socket means DDP drops OpenConn with nothing to answer it, so
    // this burns the ATP retry budget rather than failing fast. Bound it.
    pap.connect_with_timeout(printer_addr, Duration::from_secs(10))
        .await
        .expect("PAP connect failed: the server's socket was released when its requestor dropped");

    let ps_job = b"%!PS-Adobe-3.0\rshowpage\r%%EOF\r".to_vec();
    pap.print(&ps_job).await.expect("Print job failed");
    let stdout = pap.read_response().await.expect("Job stdout read failed");
    assert!(stdout.is_empty(), "print job should produce no stdout");

    tokio::time::timeout(Duration::from_secs(10), pap.close())
        .await
        .expect("Close timed out")
        .expect("Close failed");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let jobs = jobs.lock().await;
    assert_eq!(jobs.len(), 1, "sink must receive the print job");
    assert_eq!(jobs[0], ps_job);

    println!("✓ PAP server survived its requestor being dropped!");

    hub_task.abort();
}
