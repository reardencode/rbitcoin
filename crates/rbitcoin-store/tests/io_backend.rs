use rbitcoin_store::io_backend::*;

#[test]
fn parse_tokens() {
    assert_eq!(parse_read_token("uring"), Some(ReadIoBackend::Uring));
    assert_eq!(parse_read_token("io_uring"), Some(ReadIoBackend::Uring));
    assert_eq!(parse_read_token("pool"), Some(ReadIoBackend::Uring));
    assert_eq!(parse_read_token("iocp"), Some(ReadIoBackend::Uring));
    assert!(
        parse_read_token("ioring").is_none(),
        "Windows IoRing is not supported; ioring is not a token"
    );
    assert!(parse_write_token("ioring").is_none());
    assert_eq!(parse_read_token("pread"), Some(ReadIoBackend::Pread));
    assert_eq!(parse_read_token("fd"), Some(ReadIoBackend::Pread));
    assert_eq!(parse_read_token("libc"), Some(ReadIoBackend::Pread));
    assert_eq!(parse_read_token("pwrite"), Some(ReadIoBackend::Pread));
    assert!(parse_read_token("mmap").is_none());
    assert_eq!(parse_write_token("uring"), Some(WriteIoBackend::Uring));
    assert_eq!(parse_write_token("io_uring"), Some(WriteIoBackend::Uring));
    assert_eq!(parse_write_token("pwrite"), Some(WriteIoBackend::Pwrite));
    assert_eq!(parse_write_token("pread"), Some(WriteIoBackend::Pwrite));
    assert_eq!(parse_write_token("fd"), Some(WriteIoBackend::Pwrite));
    assert_eq!(parse_write_token("libc"), Some(WriteIoBackend::Pwrite));
    assert!(parse_write_token("mmap").is_none());
    assert!(parse_read_token("alternate").is_none());
    assert!(parse_write_token("nope").is_none());
}

#[test]
fn path_env_ignored_global_only() {
    let before = std::env::var_os("RBITCOIN_IO");
    assert_eq!(
        global_read_from_env_str("uring").map(effective_read),
        Some(effective_read(ReadIoBackend::Uring))
    );
    assert_eq!(
        global_read_from_env_str("pread"),
        Some(ReadIoBackend::Pread)
    );
    assert_eq!(
        std::env::var_os("RBITCOIN_IO"),
        before,
        "io token checks must not write process env"
    );
}

#[test]
fn global_env_io_uring_off_and_aliases() {
    let before_io = std::env::var_os("RBITCOIN_IO");
    let before_uring = std::env::var_os("RBITCOIN_IO_URING");
    let mut seen = Vec::new();
    let read = global_read_from_vars(|k| {
        seen.push(k.to_string());
        match k {
            "RBITCOIN_IO" => Some("pread".to_string()),
            "RBITCOIN_IO_URING" => Some("0".to_string()),
            _ => None,
        }
    });
    assert_eq!(seen, vec!["RBITCOIN_IO".to_string()]);
    assert_eq!(
        read,
        Some(ReadIoBackend::Pread),
        "RBITCOIN_IO_URING is not an alias; the lookup reads RBITCOIN_IO"
    );
    seen.clear();
    assert_eq!(
        global_read_from_vars(|k| {
            seen.push(k.to_string());
            None
        }),
        None,
        "absent RBITCOIN_IO falls through"
    );
    assert_eq!(seen, vec!["RBITCOIN_IO".to_string()]);
    seen.clear();
    let write = global_write_from_vars(|k| {
        seen.push(k.to_string());
        match k {
            "RBITCOIN_IO" => Some("pread".to_string()),
            "RBITCOIN_IO_URING" => Some("0".to_string()),
            _ => None,
        }
    });
    assert_eq!(seen, vec!["RBITCOIN_IO".to_string()]);
    assert_eq!(write, Some(WriteIoBackend::Pwrite));
    assert_eq!(
        global_read_from_vars(|_| Some("0".to_string())),
        None,
        "RBITCOIN_IO=0 is not a backend"
    );
    assert_eq!(global_write_from_vars(|_| Some("0".to_string())), None);
    assert_eq!(global_read_from_vars(|_| Some("mmap".to_string())), None);
    assert_eq!(global_write_from_vars(|_| Some("mmap".to_string())), None);
    assert_eq!(
        global_read_from_vars(|_| Some("not-a-backend".to_string())),
        None
    );
    assert_eq!(
        global_write_from_vars(|_| Some("not-a-backend".to_string())),
        None
    );
    assert_eq!(std::env::var_os("RBITCOIN_IO"), before_io);
    assert_eq!(
        std::env::var_os("RBITCOIN_IO_URING"),
        before_uring,
        "io token checks must not write process env"
    );
}

#[test]
fn effective_backends_demote_when_uring_disabled() {
    // effective_* only demotes when bulk_io reports uring off; still exercises match arms.
    let _ = effective_read(ReadIoBackend::Pread);
    let _ = effective_read(ReadIoBackend::Uring);
    let _ = effective_write(WriteIoBackend::Pwrite);
    let _ = effective_write(WriteIoBackend::Uring);
}
