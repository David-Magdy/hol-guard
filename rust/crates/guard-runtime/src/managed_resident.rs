#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[path = "managed_resident_client_stream.rs"]
mod client_stream;
#[path = "managed_resident_transport.rs"]
mod managed_resident_transport;
#[path = "resident_restart_budget.rs"]
mod restart_budget;
#[path = "managed_resident_stop.rs"]
mod stop;
#[path = "managed_resident_supervisor.rs"]
mod supervisor;

pub(crate) fn client_stream(state_base: &Path) -> Result<(), String> {
    let parent_identity = crate::resident_state::package_process_start_marker(std::process::id())?;
    client_stream::run(state_base, &parent_identity)
}
pub(crate) use client_stream::client_timeout;
#[cfg(test)]
use client_stream::{
    read_frame as read_client_stream_frame, write_frame as write_client_stream_frame,
};

use crate::resident_state::{
    acquire_startup_lock, clear_stale_startup_lock, next_generation, runtime_digest, state_scope,
};

pub(crate) use stop::stop_managed;
pub(crate) use supervisor::ParentIdentity;

#[cfg(test)]
fn is_stale_process_identity_error(error: &str) -> bool {
    stop::is_stale_process_identity_error(error)
}

const CLIENT_START_TIMEOUT: Duration = Duration::from_millis(600);
const CLIENT_RETRY_DELAY: Duration = Duration::from_millis(5);
const MANAGED_STOP_TIMEOUT: Duration = Duration::from_millis(750);
const MANAGED_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MANAGED_OWNER_LOCK_FILE_NAME: &str = "managed-resident-owner.v1.lock";
static MANAGED_SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static MANAGED_SHUTDOWN_READY: AtomicBool = AtomicBool::new(false);
static MANAGED_SHUTDOWN_MANAGED: AtomicBool = AtomicBool::new(false);
static MANAGED_SHUTDOWN_RESPONSE_SENT: AtomicBool = AtomicBool::new(false);

/// Lifetime owner lock for the resident scope.
///
/// Unix keeps an open, verified directory descriptor and locks both the
/// directory and its named marker. This prevents an ordinary second process
/// from starting a second resident even if the marker pathname is replaced.
/// A same-UID actor that can deliberately mutate the private directory while
/// this process runs remains an OS-account trust limitation; callers must
/// still validate published state and process identity on every connection.
struct ManagedOwnerLock {
    _file: File,
    #[cfg(unix)]
    _directory: File,
}

fn acquire_managed_owner_lock(scope: &Path) -> Result<ManagedOwnerLock, String> {
    #[cfg(unix)]
    let directory = {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let mut directory_options = OpenOptions::new();
        directory_options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = directory_options
            .open(scope)
            .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
        let metadata = directory
            .metadata()
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let path_metadata = std::fs::symlink_metadata(scope)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        if !metadata.is_dir()
            || path_metadata.file_type().is_symlink()
            || !path_metadata.is_dir()
            || metadata.dev() != path_metadata.dev()
            || metadata.ino() != path_metadata.ino()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
        fs2::FileExt::try_lock_exclusive(&directory).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                "native_resident_owner_busy".to_owned()
            } else {
                "native_resident_owner_lock_failed".to_owned()
            }
        })?;
        directory
    };
    let path = scope.join(MANAGED_OWNER_LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_SHARE_WRITE: u32 = 0x0000_0002;
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .map_err(|_| "native_resident_owner_lock_failed".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
    if !metadata.is_file() {
        return Err("native_resident_owner_lock_invalid".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path_metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| "native_resident_owner_lock_invalid".to_owned())?;
        let parent_uid = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .map(|parent| parent.uid());
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || metadata.nlink() != 1
            || parent_uid != Some(metadata.uid())
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("native_resident_owner_lock_not_private".to_owned());
        }
    }
    #[cfg(windows)]
    crate::resident_state::verify_windows_private_path(&path, false)?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            "native_resident_marker_busy".to_owned()
        } else {
            "native_resident_owner_lock_failed".to_owned()
        }
    })?;
    Ok(ManagedOwnerLock {
        _file: file,
        #[cfg(unix)]
        _directory: directory,
    })
}

pub(crate) fn request_shutdown() {
    MANAGED_SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

pub(crate) fn wait_for_shutdown() -> bool {
    // The ordinary `serve` command has no managed owner lock to release. Its
    // parent-liveness contract still uses the historical immediate response.
    // Only the supervised resident needs the linearizable acknowledgement.
    if !MANAGED_SHUTDOWN_MANAGED.load(Ordering::Acquire) {
        return true;
    }
    let deadline = Instant::now() + CLIENT_START_TIMEOUT;
    while Instant::now() < deadline {
        if MANAGED_SHUTDOWN_READY.load(Ordering::Acquire) {
            return true;
        }
        thread::sleep(CLIENT_RETRY_DELAY);
    }
    MANAGED_SHUTDOWN_READY.load(Ordering::Acquire)
}

pub(crate) fn shutdown_response_sent() {
    if MANAGED_SHUTDOWN_MANAGED.load(Ordering::Acquire) && shutdown_requested() {
        MANAGED_SHUTDOWN_RESPONSE_SENT.store(true, Ordering::Release);
    }
}

fn wait_for_shutdown_response() {
    let deadline = Instant::now() + CLIENT_START_TIMEOUT;
    while Instant::now() < deadline {
        if MANAGED_SHUTDOWN_RESPONSE_SENT.load(Ordering::Acquire) {
            return;
        }
        thread::sleep(CLIENT_RETRY_DELAY);
    }
}

fn shutdown_requested() -> bool {
    MANAGED_SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

pub(crate) fn client_request(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    client_request_with_parent(state_base, payload, timeout, None)
}

pub(crate) fn client_request_with_parent(
    state_base: &Path,
    payload: &[u8],
    timeout: Duration,
    parent_start_marker: Option<&str>,
) -> Result<Vec<u8>, String> {
    if timeout.is_zero() {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let overall_deadline = Instant::now() + timeout;
    let digest = runtime_digest()?;
    let scope = state_scope(state_base, &digest)?;
    if let Some(response) = stop::try_states(&scope, &digest, payload, overall_deadline)? {
        return Ok(response);
    }
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    let mut lock = acquire_startup_lock(&scope)?;
    if lock.is_none() && clear_stale_startup_lock(&scope, &digest)? {
        lock = acquire_startup_lock(&scope)?;
    }
    if lock.is_none() {
        let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
        while Instant::now() < deadline {
            if let Some(response) = stop::try_states(&scope, &digest, payload, overall_deadline)? {
                return Ok(response);
            }
            thread::sleep(CLIENT_RETRY_DELAY);
        }
        if clear_stale_startup_lock(&scope, &digest)? {
            lock = acquire_startup_lock(&scope)?;
        }
    }
    let _startup_lock = lock.ok_or_else(|| "native_resident_start_in_progress".to_owned())?;
    if Instant::now() >= overall_deadline {
        return Err("native_client_deadline_exceeded".to_owned());
    }
    if let Some(response) = stop::try_states(&scope, &digest, payload, overall_deadline)? {
        return Ok(response);
    }
    restart_budget::consume(&scope)?;
    let generation = next_generation(&scope, &digest)?;
    let mut token = [0u8; crate::AUTH_TOKEN_BYTES];
    getrandom::fill(&mut token).map_err(|_| "native_client_random_failed".to_owned())?;
    supervisor::spawn_managed(
        state_base,
        generation,
        &digest,
        &token,
        parent_start_marker.map(|start_marker| supervisor::ParentIdentity {
            process_id: std::process::id(),
            start_marker: start_marker.to_owned(),
        }),
    )?;
    let deadline = overall_deadline.min(Instant::now() + CLIENT_START_TIMEOUT);
    while Instant::now() < deadline {
        if let Some(response) = stop::try_states(&scope, &digest, payload, overall_deadline)? {
            return Ok(response);
        }
        thread::sleep(CLIENT_RETRY_DELAY);
    }
    Err("native_resident_start_timeout".to_owned())
}

pub(crate) fn reset_shutdown_state() {
    MANAGED_SHUTDOWN_REQUESTED.store(false, Ordering::Release);
    MANAGED_SHUTDOWN_READY.store(false, Ordering::Release);
    MANAGED_SHUTDOWN_MANAGED.store(false, Ordering::Release);
    MANAGED_SHUTDOWN_RESPONSE_SENT.store(false, Ordering::Release);
}

pub(crate) fn serve_managed(
    state_base: &Path,
    generation: u64,
    owner_process_id: u32,
    expected_digest: &str,
) -> Result<(), String> {
    reset_shutdown_state();
    if generation == 0 || owner_process_id == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let scope = state_scope(state_base, expected_digest)?;
    let owner_lock = acquire_managed_owner_lock(&scope)?;
    MANAGED_SHUTDOWN_MANAGED.store(true, Ordering::Release);
    let policy_store = std::sync::Arc::new(
        crate::policy_store::PolicySnapshotStore::new_with_resident_generation(
            state_base,
            expected_digest,
            generation,
        )?,
    );
    let token = crate::read_resident_auth_token()?;
    let owner_alive = crate::resident_stdin_liveness();
    let result = if cfg!(unix) {
        managed_resident_transport::serve_unix_managed(
            &scope,
            policy_store,
            generation,
            owner_process_id,
            expected_digest,
            token,
            owner_alive,
        )
    } else {
        managed_resident_transport::serve_loopback_managed(
            &scope,
            policy_store,
            generation,
            owner_process_id,
            expected_digest,
            token,
            owner_alive,
        )
    };
    let stopped = shutdown_requested();
    drop(owner_lock);
    if stopped {
        MANAGED_SHUTDOWN_READY.store(true, Ordering::Release);
        // The shutdown request is handled by a worker. Keep the serving
        // process alive until that worker has attempted to publish the final
        // response, otherwise the process can exit between teardown and ACK.
        wait_for_shutdown_response();
    }
    result
}

pub(crate) fn supervise_managed(
    state_base: &Path,
    generation: u64,
    expected_digest: &str,
    parent_identity: Option<supervisor::ParentIdentity>,
) -> Result<(), String> {
    if generation == 0 || runtime_digest()? != expected_digest {
        return Err("native_resident_runtime_identity_mismatch".to_owned());
    }
    let token = crate::read_resident_auth_token()?;
    supervisor::supervise_managed(
        state_base,
        generation,
        expected_digest,
        &token,
        parent_identity,
    )
}

pub(crate) fn parse_generation(value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation > 0)
        .ok_or_else(|| "native_resident_generation_invalid".to_owned())
}

pub(crate) fn parse_process_id(value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .ok()
        .filter(|process_id| *process_id > 0)
        .ok_or_else(|| "native_resident_owner_process_invalid".to_owned())
}

pub(crate) fn parse_process_start_marker(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err("native_resident_parent_identity_invalid".to_owned());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
#[path = "managed_resident_tests.rs"]
mod tests;
