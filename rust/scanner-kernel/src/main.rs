use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const PROTOCOL: &str = "hol-guard-scanner-kernel.v1";
const PREFIX_LIMIT: usize = 2 * 1024 * 1024;
const EXCLUDED: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "dist",
    "build",
    "__pycache__",
];

#[derive(Clone, Debug, Default)]
struct Record {
    path: String,
    kind: String,
    size: u64,
    sha256: Option<String>,
    format: Option<String>,
    executable: bool,
    symlink_target: Option<String>,
    symlink_escapes_root: bool,
    indicators: Vec<String>,
    hardening: Vec<String>,
    error: Option<String>,
}

#[derive(Debug)]
struct ScanState {
    records: Vec<Record>,
    files_seen: u64,
    bytes_hashed: u64,
    max_files: u64,
    max_bytes: u64,
    truncated: bool,
    excluded_directories: u64,
    errors: Vec<String>,
}

impl ScanState {
    fn new(max_files: u64, max_bytes: u64) -> Self {
        Self {
            records: Vec::new(),
            files_seen: 0,
            bytes_hashed: 0,
            max_files,
            max_bytes,
            truncated: false,
            excluded_directories: 0,
            errors: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    bit_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffer_len: 0,
            bit_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        if self.buffer_len > 0 {
            let remaining = 64 - self.buffer_len;
            let take = remaining.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.transform(&block);
                self.bit_len = self.bit_len.wrapping_add(512);
                self.buffer_len = 0;
            }
        }
        while input.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[..64]);
            self.transform(&block);
            self.bit_len = self.bit_len.wrapping_add(512);
            input = &input[64..];
        }
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let total_bits = self
            .bit_len
            .wrapping_add((self.buffer_len as u64).wrapping_mul(8));
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..] {
                *byte = 0;
            }
            let block = self.buffer;
            self.transform(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.transform(&block);
        let mut output = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    fn transform(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98,
            0x71374491,
            0xb5c0fbcf,
            0xe9b5dba5,
            0x3956c25b,
            0x59f111f1,
            0x923f82a4,
            0xab1c5ed5,
            0xd807aa98,
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe,
            0x9bdc06a7,
            0xc19bf174,
            0xe49b69c1,
            0xefbe4786,
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152,
            0xa831c66d,
            0xb00327c8,
            0xbf597fc7,
            0xc6e00bf3,
            0xd5a79147,
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e,
            0x92722c85,
            0xa2bfe8a1,
            0xa81a664b,
            0xc24b8b70,
            0xc76c51a3,
            0xd192e819,
            0xd6990624,
            0xf40e3585,
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814,
            0x8cc70208,
            0x90befffa,
            0xa4506ceb,
            0xbef9a3f7,
            0xc67178f2,
        ];
        let mut words = [0u32; 64];
        for index in 0..16 {
            words[index] = u32::from_be_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn escape_json(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < ' ' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn json_string_option(value: &Option<String>) -> String {
    match value {
        Some(value) => escape_json(value),
        None => "null".to_owned(),
    }
}

fn json_string_array(values: &[String]) -> String {
    let encoded: Vec<String> = values.iter().map(|value| escape_json(value)).collect();
    format!("[{}]", encoded.join(","))
}

fn read_u16(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn read_u32(data: &[u8], offset: usize, little: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64(data: &[u8], offset: usize, little: bool) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(if little {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn classify(prefix: &[u8], suffix: &str) -> &'static str {
    if prefix.starts_with(b"\x7fELF") {
        "elf"
    } else if prefix.starts_with(b"MZ") {
        "pe"
    } else if prefix.len() >= 4
        && matches!(
            &prefix[..4],
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
        )
    {
        "mach-o"
    } else if prefix.starts_with(b"\x00asm") {
        "wasm"
    } else if prefix.starts_with(b"PK\x03\x04") {
        "zip"
    } else if prefix.starts_with(b"\x1f\x8b") {
        "gzip"
    } else if prefix.starts_with(b"7z\xbc\xaf\x27\x1c") {
        "7z"
    } else if prefix.starts_with(b"Rar!\x1a\x07") {
        "rar"
    } else if matches!(suffix, "tar" | "tgz" | "tbz" | "txz") {
        "archive"
    } else if prefix.iter().take(4096).any(|byte| *byte == 0) {
        "binary"
    } else {
        "text"
    }
}

fn elf_hardening(data: &[u8]) -> Vec<String> {
    if data.len() < 64 || !data.starts_with(b"\x7fELF") {
        return Vec::new();
    }
    let class = data[4];
    let little = data[5] == 1;
    let mut values = BTreeSet::new();
    if read_u16(data, 16, little) == Some(3) {
        values.insert("pie".to_owned());
    }
    let (phoff, entsize, phnum, type_offset, flags_offset) = if class == 2 {
        (
            read_u64(data, 32, little).unwrap_or(0) as usize,
            read_u16(data, 54, little).unwrap_or(0) as usize,
            read_u16(data, 56, little).unwrap_or(0) as usize,
            0usize,
            4usize,
        )
    } else {
        (
            read_u32(data, 28, little).unwrap_or(0) as usize,
            read_u16(data, 42, little).unwrap_or(0) as usize,
            read_u16(data, 44, little).unwrap_or(0) as usize,
            0usize,
            24usize,
        )
    };
    for index in 0..phnum.min(4096) {
        let offset = phoff.saturating_add(index.saturating_mul(entsize));
        if offset.saturating_add(entsize) > data.len() || entsize < flags_offset + 4 {
            break;
        }
        let kind = read_u32(data, offset + type_offset, little).unwrap_or(0);
        if kind == 0x6474_e552 {
            values.insert("relro".to_owned());
        }
        if kind == 0x6474_e551 {
            let flags = read_u32(data, offset + flags_offset, little).unwrap_or(0);
            if flags & 1 == 0 {
                values.insert("nx-stack".to_owned());
            }
        }
    }
    values.into_iter().collect()
}

fn pe_hardening(data: &[u8]) -> Vec<String> {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return Vec::new();
    }
    let pe_offset = read_u32(data, 0x3c, true).unwrap_or(0) as usize;
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return Vec::new();
    }
    let optional = pe_offset + 24;
    let magic = read_u16(data, optional, true).unwrap_or(0);
    let mut values = BTreeSet::new();
    let characteristics = read_u16(data, optional + 70, true).unwrap_or(0);
    if characteristics & 0x0040 != 0 {
        values.insert("aslr".to_owned());
    }
    if characteristics & 0x0100 != 0 {
        values.insert("nx".to_owned());
    }
    if characteristics & 0x4000 != 0 {
        values.insert("control-flow-guard".to_owned());
    }
    let data_directory = if magic == 0x20b {
        optional + 112
    } else {
        optional + 96
    };
    let certificate_size = read_u32(data, data_directory + 8 * 4 + 4, true).unwrap_or(0);
    if certificate_size > 0 {
        values.insert("authenticode-table".to_owned());
    }
    values.into_iter().collect()
}

fn macho_hardening(data: &[u8]) -> Vec<String> {
    if data.len() < 32 {
        return Vec::new();
    }
    let magic = &data[..4];
    let little = matches!(magic, b"\xce\xfa\xed\xfe" | b"\xcf\xfa\xed\xfe");
    let fat = matches!(magic, b"\xca\xfe\xba\xbe" | b"\xbe\xba\xfe\xca");
    if fat {
        return vec!["fat-binary".to_owned()];
    }
    let mut values = BTreeSet::new();
    let flags = read_u32(data, 24, little).unwrap_or(0);
    if flags & 0x0020_0000 != 0 {
        values.insert("pie".to_owned());
    }
    let commands = read_u32(data, 16, little).unwrap_or(0) as usize;
    let is_64 = matches!(magic, b"\xfe\xed\xfa\xcf" | b"\xcf\xfa\xed\xfe");
    let mut offset = if is_64 { 32usize } else { 28usize };
    for _ in 0..commands.min(4096) {
        let command = read_u32(data, offset, little).unwrap_or(0);
        let size = read_u32(data, offset + 4, little).unwrap_or(0) as usize;
        if size < 8 || offset.saturating_add(size) > data.len() {
            break;
        }
        if command == 0x1d {
            values.insert("code-signature-command".to_owned());
        }
        offset = offset.saturating_add(size);
    }
    values.into_iter().collect()
}

fn wasm_hardening(data: &[u8]) -> Vec<String> {
    if data.len() >= 8 && data.starts_with(b"\x00asm") && data[4..8] == [1, 0, 0, 0] {
        vec!["validated-header".to_owned()]
    } else {
        Vec::new()
    }
}

fn extract_strings(data: &[u8]) -> String {
    let mut strings = String::new();
    let mut ascii = Vec::new();
    for byte in data {
        if (32..=126).contains(byte) || matches!(*byte, b'\t' | b'\n' | b'\r') {
            ascii.push(*byte);
        } else {
            if ascii.len() >= 5 {
                strings.push_str(&String::from_utf8_lossy(&ascii));
                strings.push('\n');
            }
            ascii.clear();
        }
    }
    if ascii.len() >= 5 {
        strings.push_str(&String::from_utf8_lossy(&ascii));
        strings.push('\n');
    }
    let mut utf16 = Vec::new();
    let mut index = 0usize;
    while index + 1 < data.len() {
        if (32..=126).contains(&data[index]) && data[index + 1] == 0 {
            utf16.push(data[index]);
            index += 2;
        } else {
            if utf16.len() >= 5 {
                strings.push_str(&String::from_utf8_lossy(&utf16));
                strings.push('\n');
            }
            utf16.clear();
            index += 1;
        }
    }
    if utf16.len() >= 5 {
        strings.push_str(&String::from_utf8_lossy(&utf16));
    }
    strings.to_lowercase()
}

fn indicators(data: &[u8]) -> Vec<String> {
    let haystack = extract_strings(data);
    let needles = [
        ("169.254.169.254", "cloud-metadata"),
        ("metadata.google.internal", "cloud-metadata"),
        ("/var/run/docker.sock", "container-socket"),
        ("docker_engine", "container-socket"),
        ("/.aws/credentials", "credential-store"),
        (".aws\\credentials", "credential-store"),
        ("login data", "browser-credential-store"),
        ("wallet.dat", "wallet-store"),
        ("keychain", "credential-store"),
        ("credential manager", "credential-store"),
        ("createprocess", "process-execution"),
        ("winexec", "process-execution"),
        ("system(", "process-execution"),
        ("popen(", "process-execution"),
        ("execve", "process-execution"),
        ("writeprocessmemory", "process-injection"),
        ("createremotethread", "process-injection"),
        ("process_vm_writev", "process-injection"),
        ("ptrace", "process-injection"),
        ("launchagents", "persistence"),
        ("currentversion\\run", "persistence"),
        ("/etc/cron", "persistence"),
        ("systemd", "persistence"),
        ("stratum+tcp", "crypto-mining"),
        ("xmrig", "crypto-mining"),
        ("getasynckeystate", "input-capture"),
        ("setwindowshookex", "input-capture"),
    ];
    let mut values = BTreeSet::new();
    for (needle, label) in needles {
        if haystack.contains(needle) {
            values.insert(label.to_owned());
        }
    }
    values.into_iter().collect()
}

fn hash_file(path: &Path, remaining: u64) -> io::Result<(Option<String>, u64, Option<String>)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    let mut read_total = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        read_total = read_total.saturating_add(read as u64);
        if read_total > remaining {
            return Ok((None, read_total, Some("total-byte-limit".to_owned())));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((Some(hex(&hasher.finalize())), read_total, None))
}

fn relative_string(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    let value = relative.to_string_lossy().replace('\\', "/");
    if value.is_empty() || value.starts_with('/') || value.split('/').any(|part| part == "..") {
        None
    } else {
        Some(value)
    }
}

#[cfg(unix)]
fn executable(metadata: &fs::Metadata, format: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
        || matches!(format, "elf" | "pe" | "mach-o" | "wasm")
}

#[cfg(not(unix))]
fn executable(_metadata: &fs::Metadata, format: &str) -> bool {
    matches!(format, "elf" | "pe" | "mach-o" | "wasm")
}

fn scan_file(root: &Path, path: &Path, metadata: &fs::Metadata, state: &mut ScanState) {
    let Some(relative) = relative_string(root, path) else {
        state.errors.push("unsafe-relative-path".to_owned());
        return;
    };
    state.files_seen = state.files_seen.saturating_add(1);
    if state.files_seen > state.max_files || state.bytes_hashed >= state.max_bytes {
        state.truncated = true;
        return;
    }
    let mut prefix = Vec::new();
    let prefix_result = File::open(path).and_then(|mut file| {
        file.by_ref()
            .take(PREFIX_LIMIT as u64)
            .read_to_end(&mut prefix)
            .map(|_| ())
    });
    let suffix = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let format = classify(&prefix, &suffix).to_owned();
    let remaining = state.max_bytes.saturating_sub(state.bytes_hashed);
    let (sha256, hashed, hash_error) = match hash_file(path, remaining) {
        Ok(result) => result,
        Err(error) => (
            None,
            0,
            Some(format!("read-error:{}", error.kind() as u32)),
        ),
    };
    state.bytes_hashed = state.bytes_hashed.saturating_add(hashed);
    if hash_error.as_deref() == Some("total-byte-limit") {
        state.truncated = true;
    }
    let hardening = match format.as_str() {
        "elf" => elf_hardening(&prefix),
        "pe" => pe_hardening(&prefix),
        "mach-o" => macho_hardening(&prefix),
        "wasm" => wasm_hardening(&prefix),
        _ => Vec::new(),
    };
    let sensitive = if matches!(format.as_str(), "elf" | "pe" | "mach-o" | "wasm" | "binary") {
        indicators(&prefix)
    } else {
        Vec::new()
    };
    let error = prefix_result
        .err()
        .map(|error| format!("prefix-read-error:{}", error.kind() as u32))
        .or(hash_error);
    state.records.push(Record {
        path: relative,
        kind: "file".to_owned(),
        size: metadata.len(),
        sha256,
        format: Some(format.clone()),
        executable: executable(metadata, &format),
        indicators: sensitive,
        hardening,
        error,
        ..Record::default()
    });
}

fn walk(root: &Path, directory: &Path, state: &mut ScanState) {
    if state.truncated {
        return;
    }
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            state.errors.push(format!(
                "directory-read:{}:{}",
                directory.file_name().and_then(|value| value.to_str()).unwrap_or("?"),
                error.kind() as u32
            ));
            return;
        }
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(Result::ok).map(|entry| entry.path()).collect();
    paths.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let mut directories = Vec::new();
    for path in paths {
        if state.truncated {
            break;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                if let Some(relative) = relative_string(root, &path) {
                    state.records.push(Record {
                        path: relative,
                        kind: "file".to_owned(),
                        error: Some(format!("metadata-error:{}", error.kind() as u32)),
                        ..Record::default()
                    });
                }
                continue;
            }
        };
        if metadata.file_type().is_symlink() {
            if let Some(relative) = relative_string(root, &path) {
                let target = fs::read_link(&path).ok();
                let resolved = target
                    .as_ref()
                    .and_then(|target| path.parent().map(|parent| parent.join(target)))
                    .and_then(|target| fs::canonicalize(target).ok());
                let escapes = resolved.as_ref().map(|target| !target.starts_with(root)).unwrap_or(false);
                state.records.push(Record {
                    path: relative,
                    kind: "symlink".to_owned(),
                    symlink_target: target.map(|target| target.to_string_lossy().into_owned()),
                    symlink_escapes_root: escapes,
                    ..Record::default()
                });
            }
        } else if metadata.is_dir() {
            let name = path.file_name().and_then(|value| value.to_str()).unwrap_or("");
            if EXCLUDED.contains(&name) {
                state.excluded_directories = state.excluded_directories.saturating_add(1);
            } else {
                directories.push(path);
            }
        } else if metadata.is_file() {
            scan_file(root, &path, &metadata, state);
        } else if let Some(relative) = relative_string(root, &path) {
            state.records.push(Record {
                path: relative,
                kind: "special".to_owned(),
                error: Some("unsupported-file-type".to_owned()),
                ..Record::default()
            });
        }
    }
    for child in directories {
        walk(root, &child, state);
    }
}

fn record_json(record: &Record) -> String {
    format!(
        concat!(
            "{{\"path\":{},\"kind\":{},\"size\":{},\"sha256\":{},",
            "\"format\":{},\"executable\":{},\"symlinkTarget\":{},",
            "\"symlinkEscapesRoot\":{},\"indicators\":{},\"hardening\":{},\"error\":{}}}"
        ),
        escape_json(&record.path),
        escape_json(&record.kind),
        record.size,
        json_string_option(&record.sha256),
        json_string_option(&record.format),
        record.executable,
        json_string_option(&record.symlink_target),
        record.symlink_escapes_root,
        json_string_array(&record.indicators),
        json_string_array(&record.hardening),
        json_string_option(&record.error),
    )
}

fn scan(root: &Path, max_files: u64, max_bytes: u64) -> Result<String, String> {
    let canonical = fs::canonicalize(root).map_err(|error| format!("cannot canonicalize root: {error}"))?;
    if !canonical.is_dir() {
        return Err("scan root is not a directory".to_owned());
    }
    let mut state = ScanState::new(max_files, max_bytes);
    walk(&canonical, &canonical, &mut state);
    state.records.sort_by(|left, right| left.path.cmp(&right.path));
    state.records.dedup_by(|left, right| left.path == right.path);
    let records: Vec<String> = state.records.iter().map(record_json).collect();
    let errors: Vec<String> = state.errors.iter().map(|value| escape_json(value)).collect();
    Ok(format!(
        concat!(
            "{{\"protocol\":{},\"root\":{},\"filesSeen\":{},",
            "\"bytesHashed\":{},\"truncated\":{},\"excludedDirectories\":{},",
            "\"errors\":[{}],\"records\":[{}]}}"
        ),
        escape_json(PROTOCOL),
        escape_json(&canonical.to_string_lossy()),
        state.files_seen,
        state.bytes_hashed,
        state.truncated,
        state.excluded_directories,
        errors.join(","),
        records.join(","),
    ))
}

fn parse_u64(value: Option<String>, name: &str) -> Result<u64, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}"))
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("scan") {
        return Err("usage: hol-guard-scanner-kernel scan <root> --max-files N --max-bytes N".to_owned());
    }
    let root = PathBuf::from(arguments.next().ok_or_else(|| "missing scan root".to_owned())?);
    let mut max_files = 20_000u64;
    let mut max_bytes = 512 * 1024 * 1024u64;
    while let Some(flag) = arguments.next() {
        match flag.as_str() {
            "--max-files" => max_files = parse_u64(arguments.next(), "max-files")?,
            "--max-bytes" => max_bytes = parse_u64(arguments.next(), "max-bytes")?,
            _ => return Err(format!("unsupported argument: {flag}")),
        }
    }
    if max_files == 0 || max_files > 1_000_000 {
        return Err("max-files is outside the supported range".to_owned());
    }
    if max_bytes == 0 || max_bytes > 32 * 1024 * 1024 * 1024 {
        return Err("max-bytes is outside the supported range".to_owned());
    }
    println!("{}", scan(&root, max_files, max_bytes)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert_eq!(
            hex(&hasher.finalize()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn classifies_common_executable_formats() {
        assert_eq!(classify(b"\x7fELFrest", ""), "elf");
        assert_eq!(classify(b"MZrest", "exe"), "pe");
        assert_eq!(classify(b"\x00asm\x01\x00\x00\x00", "wasm"), "wasm");
        assert_eq!(classify(b"PK\x03\x04rest", "zip"), "zip");
    }

    #[test]
    fn extracts_sensitive_indicators_without_returning_strings() {
        let result = indicators(b"prefix /var/run/docker.sock and 169.254.169.254 suffix");
        assert_eq!(
            result,
            vec!["cloud-metadata".to_owned(), "container-socket".to_owned()]
        );
    }

    #[test]
    fn json_escape_blocks_control_character_breakout() {
        assert_eq!(escape_json("a\n\"b"), "\"a\\n\\\"b\"");
    }
}
