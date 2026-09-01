use super::*;

#[test]
fn generation_parser_rejects_zero_and_non_numeric() {
    assert!(parse_generation("0").is_err());
    assert!(parse_generation("not-a-number").is_err());
    assert_eq!(parse_generation("7").unwrap(), 7);
}

#[test]
fn client_deadline_is_bounded() {
    assert_eq!(
        client_timeout(br#"{"deadline_budget_ms":999999}"#),
        Duration::from_secs(9)
    );
    assert_eq!(client_timeout(br#"{}"#), Duration::from_millis(750));
}

#[test]
fn client_stream_frames_are_bounded_and_binary_safe() {
    use std::io::Cursor;

    let payload = b"{\"raw_payload\":\"line\\nvalue\"}";
    let mut framed = (payload.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(payload);
    let mut input = Cursor::new(framed);
    assert_eq!(
        read_client_stream_frame(&mut input).unwrap(),
        Some(payload.to_vec())
    );

    let mut output = Vec::new();
    write_client_stream_frame(&mut output, payload).unwrap();
    assert_eq!(&output[..4], &(payload.len() as u32).to_be_bytes());
    assert_eq!(&output[4..], payload);
}

#[test]
fn client_stream_rejects_truncated_and_oversized_frames() {
    use std::io::Cursor;

    let mut truncated = Cursor::new((4u32).to_be_bytes().to_vec());
    assert_eq!(
        read_client_stream_frame(&mut truncated).unwrap_err(),
        "native_client_stream_frame_truncated"
    );
    let oversized = (crate::MAX_NATIVE_REQUEST_BYTES as u32 + 1).to_be_bytes();
    let mut input = Cursor::new(oversized);
    assert_eq!(
        read_client_stream_frame(&mut input).unwrap_err(),
        "native_client_stream_request_too_large"
    );
}

#[test]
fn stale_process_identity_errors_are_platform_scoped() {
    let stale_unavailable =
        is_stale_process_identity_error("native_resident_process_identity_unavailable");
    let stale_mismatch =
        is_stale_process_identity_error("native_resident_process_identity_mismatch");
    if cfg!(windows) {
        assert!(stale_unavailable);
        assert!(stale_mismatch);
    } else {
        assert!(!stale_unavailable);
        assert!(!stale_mismatch);
    }
    assert!(!is_stale_process_identity_error(
        "native_resident_state_mac_invalid"
    ));
    assert!(!is_stale_process_identity_error(
        "native_client_auth_rejected"
    ));
}

#[cfg(unix)]
#[test]
fn managed_owner_lock_is_exclusive_for_resident_lifetime() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();

    let first = acquire_managed_owner_lock(&root).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    let marker = root.join(MANAGED_OWNER_LOCK_FILE_NAME);
    let displaced = root.join("managed-resident-owner.v1.lock.displaced");
    fs::rename(&marker, &displaced).unwrap();
    fs::write(&marker, []).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        acquire_managed_owner_lock(&root),
        Err(error) if error == "native_resident_owner_busy"
    ));
    drop(first);
    let second = acquire_managed_owner_lock(&root).unwrap();
    drop(second);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn managed_owner_lock_rejects_second_process() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

    if let Some(root) = std::env::var_os("HOL_GUARD_OWNER_LOCK_CHILD") {
        let root = PathBuf::from(root);
        let _lock = acquire_managed_owner_lock(&root).unwrap();
        fs::write(root.join("child-ready"), []).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        return;
    }

    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-owner-lock-process-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let marker = root.join("child-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("managed_owner_lock_rejects_second_process")
        .arg("--nocapture")
        .env(
            "HOL_GUARD_OWNER_LOCK_CHILD",
            root.to_string_lossy().as_ref(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let mut child_ready = false;
    for _ in 0..200 {
        if marker.exists() {
            child_ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = if child_ready {
        acquire_managed_owner_lock(&root)
    } else {
        Err("child_not_ready".to_owned())
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&root);

    assert!(child_ready, "child process did not acquire the owner lock");
    assert!(matches!(
        result,
        Err(error) if error == "native_resident_owner_busy"
    ));
}
