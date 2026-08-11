#![forbid(unsafe_code)]

use guard_command::{parse_command, CommandModelRequestV1};
use guard_contracts::{
    NativeHookRequestV1, RuntimeCapabilitiesV1, MAX_NATIVE_REQUEST_BYTES,
    MAX_NATIVE_RESPONSE_BYTES, NATIVE_PROTOCOL_VERSION,
};
use guard_hook_core::review_post_tool;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

const BUILD_SHA: &str = match option_env!("HOL_GUARD_BUILD_SHA") {
    Some(value) => value,
    None => "unknown",
};
const PACKAGE_VERSION: &str = match option_env!("HOL_GUARD_PACKAGE_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const MAX_RESIDENT_CONCURRENCY: usize = 16;
const AUTH_TOKEN_BYTES: usize = 32;
const AUTH_NONCE_BYTES: usize = 32;
const AUTH_PROOF_BYTES: usize = 32;
const AUTH_TIMEOUT: Duration = Duration::from_secs(1);
const SERVER_PROOF_LABEL: &[u8] = b"hol-guard-resident-server-v1\0";
const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\0";

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResidentRequestV1 {
    Operation(ResidentOperationV1),
    Hook(NativeHookRequestV1),
}

fn capabilities() -> RuntimeCapabilitiesV1 {
    let mut features = vec![
        "post-tool-inline-v1".into(),
        "post-tool-source-read-v1".into(),
        "oneshot-v1".into(),
        "framed-serve-v1".into(),
        "bounded-concurrency-v1".into(),
        "rule-contract-v2".into(),
        "pre-tool-command-model-shadow-v1".into(),
        "resident-command-model-shadow-v1".into(),
    ];
    if cfg!(windows) {
        features.push("authenticated-loopback-resident-v1".into());
    }
    RuntimeCapabilitiesV1 {
        protocol_version: NATIVE_PROTOCOL_VERSION,
        runtime_version: PACKAGE_VERSION.to_owned(),
        rule_digest: guard_rule_contract::rule_digest(),
        build_sha: BUILD_SHA.to_owned(),
        target: format!("{}-{}", env::consts::ARCH, env::consts::OS),
        features,
    }
}

fn read_stdin_bounded() -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_NATIVE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "native_request_read_failed".to_owned())?;
    if bytes.len() > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    Ok(bytes)
}

fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: NativeHookRequestV1 =
        serde_json::from_slice(bytes).map_err(|_| "native_request_invalid_json".to_owned())?;
    let response = review_post_tool(&request);
    encode_response(&response)
}

fn evaluate_command_model_request(request: &CommandModelRequestV1) -> Result<Vec<u8>, String> {
    let response = parse_command(request)?;
    encode_response(&response)
}

fn evaluate_command_model_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: CommandModelRequestV1 = serde_json::from_slice(bytes)
        .map_err(|_| "native_command_model_invalid_json".to_owned())?;
    evaluate_command_model_request(&request)
}

fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let request: ResidentRequestV1 = serde_json::from_slice(bytes)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
    match request {
        ResidentRequestV1::Operation(ResidentOperationV1::CommandModel(request)) => {
            evaluate_command_model_request(&request)
        }
        ResidentRequestV1::Hook(request) => encode_response(&review_post_tool(&request)),
    }
}

fn encode_response<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| "native_response_encode_failed".to_owned())?;
    if encoded.len() > MAX_NATIVE_RESPONSE_BYTES {
        return Err("native_response_too_large".into());
    }
    Ok(encoded)
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "native_response_encode_failed".to_owned())?;
    println!();
    Ok(())
}

fn handle_framed_stream<S: Read + Write>(stream: &mut S) -> Result<(), String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| "native_frame_read_failed".to_owned())?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_NATIVE_REQUEST_BYTES {
        return Err("native_request_too_large".into());
    }
    let mut request = vec![0u8; length];
    stream
        .read_exact(&mut request)
        .map_err(|_| "native_frame_read_failed".to_owned())?;
    let response = evaluate_resident_bytes(&request)?;
    stream
        .write_all(&(response.len() as u32).to_be_bytes())
        .map_err(|_| "native_frame_write_failed".to_owned())?;
    stream
        .write_all(&response)
        .map_err(|_| "native_frame_write_failed".to_owned())?;
    Ok(())
}

fn take_resident_permit(permits: &Arc<(Mutex<usize>, Condvar)>) -> Result<(), String> {
    let (lock, available) = &**permits;
    let mut remaining = lock
        .lock()
        .map_err(|_| "native_runtime_concurrency_poisoned".to_owned())?;
    while *remaining == 0 {
        remaining = available
            .wait(remaining)
            .map_err(|_| "native_runtime_concurrency_poisoned".to_owned())?;
    }
    *remaining -= 1;
    Ok(())
}

fn release_resident_permit(permits: &Arc<(Mutex<usize>, Condvar)>) {
    let (lock, available) = &**permits;
    if let Ok(mut remaining) = lock.lock() {
        *remaining = (*remaining + 1).min(MAX_RESIDENT_CONCURRENCY);
        available.notify_one();
    }
}

#[cfg(unix)]
fn serve(socket_path: &str) -> Result<(), String> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    let path = Path::new(socket_path);
    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "native_socket_stat_failed".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("native_socket_symlink_rejected".into());
        }
        fs::remove_file(path).map_err(|_| "native_socket_cleanup_failed".to_owned())?;
    }
    let listener = UnixListener::bind(path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;

    let permits = Arc::new((Mutex::new(MAX_RESIDENT_CONCURRENCY), Condvar::new()));
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|_| "native_socket_accept_failed".to_owned())?;
        take_resident_permit(&permits)?;
        let thread_permits = Arc::clone(&permits);
        thread::spawn(move || {
            let _ = handle_framed_stream(&mut stream);
            release_resident_permit(&thread_permits);
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve(_socket_path: &str) -> Result<(), String> {
    Err("native_unix_socket_not_available".into())
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn read_resident_auth_token() -> Result<[u8; AUTH_TOKEN_BYTES], String> {
    let mut encoded = String::new();
    io::stdin()
        .take((AUTH_TOKEN_BYTES * 2 + 2) as u64)
        .read_to_string(&mut encoded)
        .map_err(|_| "native_resident_auth_read_failed".to_owned())?;
    let encoded = encoded.trim();
    if encoded.len() != AUTH_TOKEN_BYTES * 2 {
        return Err("native_resident_auth_invalid".into());
    }
    let mut token = [0u8; AUTH_TOKEN_BYTES];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        token[index] = (high << 4) | low;
    }
    Ok(token)
}

fn hmac_sha256(key: &[u8], label: &[u8], nonce: &[u8]) -> [u8; AUTH_PROOF_BYTES] {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(label);
    inner.update(nonce);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut proof = [0u8; AUTH_PROOF_BYTES];
    proof.copy_from_slice(&digest);
    proof
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn authenticate_loopback_stream(
    stream: &mut TcpStream,
    token: &[u8; AUTH_TOKEN_BYTES],
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    stream
        .set_write_timeout(Some(AUTH_TIMEOUT))
        .map_err(|_| "native_resident_auth_timeout_failed".to_owned())?;
    let _ = stream.set_nodelay(true);

    let mut nonce = [0u8; AUTH_NONCE_BYTES];
    stream
        .read_exact(&mut nonce)
        .map_err(|_| "native_resident_auth_nonce_failed".to_owned())?;
    let server_proof = hmac_sha256(token, SERVER_PROOF_LABEL, &nonce);
    stream
        .write_all(&server_proof)
        .map_err(|_| "native_resident_auth_proof_failed".to_owned())?;

    let mut client_proof = [0u8; AUTH_PROOF_BYTES];
    stream
        .read_exact(&mut client_proof)
        .map_err(|_| "native_resident_auth_client_failed".to_owned())?;
    let expected = hmac_sha256(token, CLIENT_PROOF_LABEL, &nonce);
    if !constant_time_eq(&client_proof, &expected) {
        return Err("native_resident_auth_rejected".into());
    }
    Ok(())
}

fn serve_loopback(address: &str) -> Result<(), String> {
    let requested: SocketAddr = address
        .parse()
        .map_err(|_| "native_resident_address_invalid".to_owned())?;
    if requested.ip() != Ipv4Addr::LOCALHOST.into() || requested.port() == 0 {
        return Err("native_resident_address_not_loopback".into());
    }
    let token = Arc::new(read_resident_auth_token()?);
    let listener = TcpListener::bind(requested)
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let local = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if local != requested {
        return Err("native_resident_loopback_addr_changed".into());
    }

    let permits = Arc::new((Mutex::new(MAX_RESIDENT_CONCURRENCY), Condvar::new()));
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|_| "native_resident_loopback_accept_failed".to_owned())?;
        take_resident_permit(&permits)?;
        let thread_permits = Arc::clone(&permits);
        let thread_token = Arc::clone(&token);
        thread::spawn(move || {
            if authenticate_loopback_stream(&mut stream, &thread_token).is_ok() {
                let _ = handle_framed_stream(&mut stream);
            }
            release_resident_permit(&thread_permits);
        });
    }
    Ok(())
}

fn write_bytes_response(response: &[u8]) -> Result<(), String> {
    io::stdout()
        .write_all(response)
        .map_err(|_| "native_response_write_failed".to_owned())?;
    io::stdout()
        .write_all(b"\n")
        .map_err(|_| "native_response_write_failed".to_owned())?;
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command] if command == "capabilities" => write_json(&capabilities()),
        [command, flag] if command == "capabilities" && flag == "--json" => {
            write_json(&capabilities())
        }
        [command] if command == "rule-contract" => write_json(&guard_rule_contract::rule_contract()),
        [command, flag] if command == "rule-contract" && flag == "--json" => {
            write_json(&guard_rule_contract::rule_contract())
        }
        [command] if command == "self-test" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "self-test" && flag == "--json" => {
            write_json(&serde_json::json!({"ok": true, "capabilities": capabilities()}))
        }
        [command, flag] if command == "hook" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_hook_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag] if command == "command-model" && flag == "--stdin" => {
            let bytes = read_stdin_bounded()?;
            let response = evaluate_command_model_bytes(&bytes)?;
            write_bytes_response(&response)
        }
        [command, flag, path] if command == "serve" && flag == "--socket" => serve(path),
        [command, flag, address] if command == "serve" && flag == "--tcp-loopback" => {
            serve_loopback(address)
        }
        _ => Err(
            "usage: hol-guard-runtime capabilities --json | rule-contract --json | self-test --json | hook --stdin | command-model --stdin | serve --socket PATH | serve --tcp-loopback 127.0.0.1:PORT"
                .into(),
        ),
    }
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_hmac_matches_cross_language_vectors() {
        let token = [7u8; AUTH_TOKEN_BYTES];
        let nonce = [9u8; AUTH_NONCE_BYTES];
        let server = hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce);
        let client = hmac_sha256(&token, CLIENT_PROOF_LABEL, &nonce);
        assert_eq!(
            server,
            [
                0xb8, 0x19, 0x89, 0x8f, 0x11, 0x87, 0x8c, 0x1c, 0x14, 0x84, 0x23, 0xd0,
                0x36, 0x1a, 0x9d, 0xe2, 0x0d, 0x9e, 0xca, 0x3b, 0xb8, 0x6c, 0xe1, 0x21,
                0x4c, 0xee, 0x95, 0x7f, 0x95, 0xbb, 0x06, 0xc4,
            ]
        );
        assert_eq!(
            client,
            [
                0xfe, 0xf8, 0x3d, 0x9f, 0xf5, 0x98, 0x89, 0x22, 0xef, 0x5c, 0x4c, 0x7b,
                0x54, 0xd9, 0xc6, 0x66, 0xab, 0xf4, 0x2f, 0xdf, 0xa8, 0x39, 0x44, 0x8b,
                0x57, 0x9f, 0x65, 0x07, 0x41, 0xd0, 0x6d, 0x97,
            ]
        );
        assert_eq!(server, hmac_sha256(&token, SERVER_PROOF_LABEL, &nonce));
        assert_ne!(server, client);
        assert!(constant_time_eq(&server, &server));
        assert!(!constant_time_eq(&server, &client));
    }

    #[test]
    fn resident_hmac_changes_with_nonce() {
        let token = [3u8; AUTH_TOKEN_BYTES];
        let mut first_nonce = [1u8; AUTH_NONCE_BYTES];
        let second_nonce = [2u8; AUTH_NONCE_BYTES];
        let first = hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce);
        let second = hmac_sha256(&token, SERVER_PROOF_LABEL, &second_nonce);
        assert_ne!(first, second);
        first_nonce[0] ^= 1;
        assert_ne!(first, hmac_sha256(&token, SERVER_PROOF_LABEL, &first_nonce));
    }
}
