use crate::messages::{
    MESSAGE_TYPE_PROPOSE_TEMPLATE, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
    REQUIRES_JOB_VALIDATION,
};
use crate::test_chain::shared_regtest;
use crate::testutil::TpClient;
use crate::transport::MAX_PROPOSE_TEMPLATE_PAYLOAD;
use crate::{
    run_sv2_tp, Sv2TpConfig, FEE_DELTA, MAX_SESSIONS, MAX_STALE_GRACE, MAX_TEMPLATE_INTERVAL,
    MIN_TEMPLATE_INTERVAL, PROVIDE_TIMEOUT, SETUP_TIMEOUT, TEMPLATE_INTERVAL, WRITE_TIMEOUT,
};
use common_messages_sv2::{
    SetupConnectionError, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use template_distribution_sv2::{
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR, MESSAGE_TYPE_SUBMIT_SOLUTION,
};

const TDP: u8 = 2;

async fn connect_when_free(addr: SocketAddr, pk: [u8; 32]) -> TpClient {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TpClient::connect(addr, pk).await {
            Ok(c) => return c,
            Err(e) if Instant::now() > deadline => panic!("no free session slot: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

async fn expect_error(c: &mut TpClient, flags: u32, code: &str) {
    let mut f = c.recv().await.expect("setup reply");
    assert_eq!(f.msg_type, MESSAGE_TYPE_SETUP_CONNECTION_ERROR);
    let e: SetupConnectionError = binary_sv2::from_bytes(&mut f.payload).expect("decode");
    assert_eq!(e.flags, flags);
    assert_eq!(e.error_code.as_utf8_or_hex(), code);
    assert_closed(c, "SetupConnection.Error").await;
}

async fn assert_closed(c: &mut TpClient, what: &str) {
    let closed = tokio::time::timeout(Duration::from_secs(5), c.recv()).await;
    assert!(
        matches!(closed, Ok(Err(_))),
        "{what} must close the session, got {:?}",
        closed.map(|r| r.map(|f| f.msg_type))
    );
}

async fn expect_success(c: &mut TpClient) -> SetupConnectionSuccess {
    let mut f = c.recv().await.expect("setup reply");
    assert_eq!(f.msg_type, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS);
    binary_sv2::from_bytes(&mut f.payload).expect("decode")
}

#[tokio::test]
async fn setup_connection_success_errors_and_session_cap() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    let (addr, pk) = (tp.local_addr, tp.authority_pubkey);

    let mut live = Vec::new();
    for _ in 0..MAX_SESSIONS {
        let mut c = TpClient::connect(addr, pk).await.expect("handshake");
        c.setup_connection(TDP, 2, 2, 0).await.unwrap();
        let ok = expect_success(&mut c).await;
        assert_eq!((ok.used_version, ok.flags), (2, 0));
        live.push(c);
    }

    let extra = TpClient::connect(addr, pk).await;
    assert!(
        extra.is_err(),
        "session over the cap must close before the handshake"
    );
    for c in live.iter_mut().step_by(MAX_SESSIONS - 1) {
        let still_open = tokio::time::timeout(Duration::from_millis(200), c.recv()).await;
        assert!(
            still_open.is_err(),
            "existing session must stay up at the cap"
        );
    }
    drop(live);

    let mut c = connect_when_free(addr, pk).await;
    c.setup_connection(TDP, 2, 2, REQUIRES_JOB_VALIDATION)
        .await
        .unwrap();
    assert_eq!(
        expect_success(&mut c).await.flags,
        REQUIRES_JOB_VALIDATION,
        "REQUIRES_JOB_VALIDATION is accepted and echoed"
    );

    let mut c = connect_when_free(addr, pk).await;
    c.setup_connection(TDP, 2, 2, 0b101).await.unwrap();
    expect_error(&mut c, 0b101, "unsupported-feature-flags").await;

    let mut c = connect_when_free(addr, pk).await;
    c.setup_connection(0, 2, 2, 0).await.unwrap();
    expect_error(&mut c, 0, "unsupported-protocol").await;

    let mut c = connect_when_free(addr, pk).await;
    c.setup_connection(TDP, 3, 4, 0).await.unwrap();
    expect_error(&mut c, 0, "protocol-version-mismatch").await;

    tp.shutdown().await;
}

/// key-utils 1.2.0 vector: SRI clients configure the TP authority key in
/// this form, so the handle must print it, and a client must connect with it.
#[tokio::test]
async fn authority_key_prints_in_key_utils_base58check() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let secret = bitcoin::base58::decode_check("zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi")
        .expect("vector secret");
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: secret.try_into().expect("32-byte secret"),
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    let key = tp.authority_key();
    assert_eq!(key, "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan");

    let decoded = bitcoin::base58::decode_check(&key).unwrap();
    let pk: [u8; 32] = decoded[2..].try_into().unwrap();
    let mut c = TpClient::connect(tp.local_addr, pk)
        .await
        .expect("handshake against the printed key");
    c.setup_connection(TDP, 2, 2, 0).await.unwrap();
    expect_success(&mut c).await;
    tp.shutdown().await;
}

/// Silent sockets take every slot at accept; the setup deadline must close
/// them so a real client gets in.
#[tokio::test]
async fn silent_sockets_are_dropped_at_the_setup_deadline() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    use tokio::io::AsyncReadExt;

    let setup_timeout = Duration::from_millis(300);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    let (addr, pk) = (tp.local_addr, tp.authority_pubkey);

    let mut silent = Vec::new();
    for _ in 0..MAX_SESSIONS {
        silent.push(tokio::net::TcpStream::connect(addr).await.expect("tcp"));
    }
    for s in &mut silent {
        let mut b = [0u8; 1];
        let closed = tokio::time::timeout(setup_timeout * 10, s.read(&mut b)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "silent socket must be closed after the setup deadline"
        );
    }

    let mut c = connect_when_free(addr, pk).await;
    c.setup_connection(TDP, 2, 2, 0).await.unwrap();
    expect_success(&mut c).await;
    tp.shutdown().await;
}

/// A TDP session without `CoinbaseOutputConstraints` never gets a template
/// and never writes, so the setup deadline also covers the first constraints.
/// Other frames before them do not reset it.
#[tokio::test]
async fn session_without_constraints_is_dropped_at_the_setup_deadline() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let setup_timeout = Duration::from_millis(300);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    let (addr, pk) = (tp.local_addr, tp.authority_pubkey);

    let mut idle = TpClient::connect(addr, pk).await.expect("handshake");
    idle.setup_connection(TDP, 2, 2, 0).await.unwrap();
    idle.recv().await.expect("setup reply");
    idle.request_transaction_data(1).await.unwrap();
    let f = idle
        .recv()
        .await
        .expect("request answered before constraints");
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);

    let mut ok = TpClient::connect(addr, pk).await.expect("handshake");
    ok.setup_connection(TDP, 2, 2, 0).await.unwrap();
    ok.recv().await.expect("setup reply");
    ok.coinbase_output_constraints(1, 1).await.unwrap();

    let closed = tokio::time::timeout(setup_timeout * 10, async {
        while idle.recv().await.is_ok() {}
    })
    .await;
    assert!(closed.is_ok(), "session without constraints must be closed");

    tokio::time::sleep(setup_timeout * 2).await;
    ok.request_transaction_data(u64::MAX).await.unwrap();
    loop {
        let f = ok
            .recv()
            .await
            .expect("session with constraints stays open");
        if f.msg_type == MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR {
            break;
        }
    }
    tp.shutdown().await;
}

/// A client that floods requests and never reads jams the TP's writes; the
/// write deadline must close the session instead of stalling it forever.
#[tokio::test]
async fn client_that_stops_reading_is_dropped_at_the_write_deadline() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let write_timeout = Duration::from_millis(200);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    // This listener only. Drop removes the entry.
    #[cfg(target_os = "linux")]
    let _send_buf = crate::test_send_buffer::pin(tp.local_addr, 8 * 1024);
    // Pin the receive window too. A small SO_SNDBUF still drains while this
    // socket ACKs into an autotuned window, so write() never stalls.
    let mut c = TpClient::connect_recv_buffer(tp.local_addr, tp.authority_pubkey, Some(2048))
        .await
        .expect("handshake");
    c.setup_connection(TDP, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    // Without constraints the setup deadline closes the session at
    // SETUP_TIMEOUT: the flood must lose only to the write deadline. The
    // stale tip holds the template, so constraints add no traffic.
    c.coinbase_output_constraints(0, 0).await.unwrap();

    // Each unknown id answers RequestTransactionData.Error. This client never
    // reads those frames. Keep sending until the stalled write closes the
    // socket: a cancelled send is not a full window, and stopping there
    // leaves the session idle so the deadline never starts. Yield so the
    // session task runs; a ready send does not, and the flood only fills
    // the kernel buffer.
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(5), async {
        for id in 1..=1_000_000u64 {
            c.request_transaction_data(id).await?;
            tokio::task::yield_now().await;
        }
        Ok::<(), io::Error>(())
    })
    .await;
    match outcome {
        Ok(Err(e)) if e.kind() != io::ErrorKind::TimedOut => {}
        Ok(Err(e)) => panic!("client write timed out; session stayed open: {e}"),
        Ok(Ok(())) => panic!("socket buffers never filled"),
        Err(_) => panic!("session must close once its write stalls past the deadline"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "stalled write took {:?}",
        started.elapsed()
    );
    tp.shutdown().await;
}

/// Each client message type has its own payload cap: the largest legitimate
/// `SubmitSolution`, a `ProposeTemplate` well past it, and a
/// `ProvideMissingTransactions.Success` past the `ProposeTemplate` cap keep
/// the session; a frame over the cap for its type closes it.
#[tokio::test]
async fn oversized_client_frame_closes_the_session() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let tp = run_sv2_tp(Sv2TpConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        chain,
        authority_secret: [7; 32],
        cert_validity: Duration::from_secs(3600),
        stale_grace: Duration::from_secs(10),
        setup_timeout: SETUP_TIMEOUT,
        write_timeout: WRITE_TIMEOUT,
        provide_timeout: PROVIDE_TIMEOUT,
        fee_delta: FEE_DELTA,
        template_interval: TEMPLATE_INTERVAL,
    })
    .await
    .expect("listen");
    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(TDP, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");

    let coinbase = vec![0u8; usize::from(u16::MAX)];
    c.submit_solution(1, 0, 0, 0, &coinbase).await.unwrap();
    c.request_transaction_data(1).await.unwrap();
    let f = c
        .recv()
        .await
        .expect("open after a max-size SubmitSolution");
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);

    // Without the flag a ProposeTemplate under its own cap is read and
    // ignored.
    let big = vec![0u8; 200 << 10];
    c.send_bytes(MESSAGE_TYPE_PROPOSE_TEMPLATE, &big)
        .await
        .unwrap();
    c.request_transaction_data(1).await.unwrap();
    let f = c
        .recv()
        .await
        .expect("open after a 200 KiB ProposeTemplate");
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);

    let _ = c.send_bytes(MESSAGE_TYPE_SUBMIT_SOLUTION, &big).await;
    c.request_transaction_data(1).await.ok();
    assert_closed(&mut c, "a 200 KiB SubmitSolution").await;

    let mut c = TpClient::connect(tp.local_addr, tp.authority_pubkey)
        .await
        .expect("handshake");
    c.setup_connection(TDP, 2, 2, 0).await.unwrap();
    c.recv().await.expect("setup reply");
    let over = vec![0u8; MAX_PROPOSE_TEMPLATE_PAYLOAD + 1];
    c.send_bytes(MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS, &over)
        .await
        .unwrap();
    c.request_transaction_data(1).await.unwrap();
    let f = c
        .recv()
        .await
        .expect("open after a ProvideMissingTransactions.Success past the ProposeTemplate cap");
    assert_eq!(f.msg_type, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR);
    let _ = c.send_bytes(MESSAGE_TYPE_PROPOSE_TEMPLATE, &over).await;
    c.request_transaction_data(1).await.ok();
    assert_closed(&mut c, "a ProposeTemplate over its cap").await;
    tp.shutdown().await;
}

#[tokio::test]
async fn out_of_range_timing_refuses_to_start() {
    let tc = shared_regtest(0);
    let chain = Arc::clone(&tc.chain);
    let hour = Duration::from_secs(3600);
    let over = Duration::from_secs(1);
    for (cert_validity, stale_grace, template_interval) in [
        (
            Duration::from_secs(u64::from(u32::MAX) + 1),
            Duration::ZERO,
            TEMPLATE_INTERVAL,
        ),
        (hour, MAX_STALE_GRACE + over, TEMPLATE_INTERVAL),
        (hour, Duration::ZERO, Duration::ZERO),
        (
            hour,
            Duration::ZERO,
            MIN_TEMPLATE_INTERVAL - Duration::from_millis(1),
        ),
        (hour, Duration::ZERO, MAX_TEMPLATE_INTERVAL + over),
    ] {
        let e = run_sv2_tp(Sv2TpConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            chain: Arc::clone(&chain),
            authority_secret: [7; 32],
            cert_validity,
            stale_grace,
            setup_timeout: SETUP_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            provide_timeout: PROVIDE_TIMEOUT,
            fee_delta: FEE_DELTA,
            template_interval,
        })
        .await
        .err()
        .expect("out-of-range config must not start");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    }
}
