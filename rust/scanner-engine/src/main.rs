use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use memmap2::MmapOptions;
use object::{Object, ObjectSection};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;

const SCHEMA_VERSION: &str = "hol-guard.scanner-engine.v1";

#[derive(Parser, Debug)]
#[command(name = "hol-guard-scanner-engine")]
#[command(about = "Bounded structural parser for untrusted extension artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Inspect {
        #[arg(long, conflicts_with = "stdin")]
        path: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        display_path: String,
        #[arg(long, default_value_t = 67_108_864)]
        max_bytes: usize,
        #[arg(long, default_value_t = 10_000)]
        max_strings: usize,
    },
}

#[derive(Debug, Serialize)]
struct EngineFinding {
    rule_id: &'static str,
    severity: &'static str,
    confidence: &'static str,
    category: &'static str,
    title: String,
    description: &'static str,
    remediation: &'static str,
    capability: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbol: Option<String>,
    metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct EngineOutput {
    schema_version: &'static str,
    complete: bool,
    summary: BTreeMap<String, Value>,
    findings: Vec<EngineFinding>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("scanner-engine error: {error:#}");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect {
            path,
            stdin,
            display_path,
            max_bytes,
            max_strings,
        } => {
            if max_bytes == 0 || max_strings == 0 {
                bail!("max-bytes and max-strings must be positive");
            }
            let bytes = if stdin {
                read_stdin_bounded(max_bytes)?
            } else {
                let path = path.ok_or_else(|| anyhow!("--path or --stdin is required"))?;
                read_file_bounded(&path, max_bytes)?
            };
            let output = inspect_bytes(&bytes, &display_path, max_strings)?;
            serde_json::to_writer(io::stdout().lock(), &output)?;
        }
    }
    Ok(())
}

fn read_stdin_bounded(limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .context("failed to read stdin")?;
    if bytes.len() > limit {
        bail!("stdin exceeds max-bytes");
    }
    Ok(bytes)
}

fn read_file_bounded(path: &PathBuf, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let metadata = file.metadata().context("failed to read file metadata")?;
    let size = usize::try_from(metadata.len()).context("file size exceeds addressable memory")?;
    if size > limit {
        bail!("file exceeds max-bytes");
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let map = unsafe { MmapOptions::new().map(&file) }.context("failed to map file")?;
    Ok(map.as_ref().to_vec())
}

fn inspect_bytes(bytes: &[u8], display_path: &str, max_strings: usize) -> Result<EngineOutput> {
    let digest = hex_digest(bytes);
    let format = detect_format(bytes);
    let strings = printable_strings(bytes, max_strings, 4);
    let entropy = shannon_entropy(bytes);
    let mut summary = BTreeMap::new();
    summary.insert("display_path".into(), json!(display_path));
    summary.insert("sha256".into(), json!(digest));
    summary.insert("size".into(), json!(bytes.len()));
    summary.insert("format".into(), json!(format));
    summary.insert("entropy".into(), json!(round(entropy, 4)));
    summary.insert("string_count".into(), json!(strings.len()));
    summary.insert("engine".into(), json!("rust-object"));
    summary.insert(
        "signature".into(),
        json!({"present": Value::Null, "verified": false, "reason": "presence may be reported for PE or Mach-O; trust is never inferred"}),
    );

    let mut findings = Vec::new();
    let mut complete = true;
    let mut imports = BTreeSet::new();
    let mut exports = BTreeSet::new();
    let mut sections = Vec::new();

    if format == "wasm" {
        match parse_wasm(bytes) {
            Ok(wasm) => {
                imports.extend(wasm.imports.iter().cloned());
                exports.extend(wasm.exports.iter().cloned());
                summary.insert("wasm".into(), serde_json::to_value(&wasm)?);
            }
            Err(error) => {
                complete = false;
                summary.insert("wasm_parse_error".into(), json!(error.to_string()));
                findings.push(parse_failure_finding("WebAssembly structural parsing failed"));
            }
        }
    } else {
        match object::File::parse(bytes) {
            Ok(file) => {
                summary.insert("architecture".into(), json!(format!("{:?}", file.architecture())));
                summary.insert("binary_format".into(), json!(format!("{:?}", file.format())));
                summary.insert("kind".into(), json!(format!("{:?}", file.kind())));
                summary.insert("entry".into(), json!(file.entry()));
                summary.insert("is_64".into(), json!(file.is_64()));
                summary.insert("little_endian".into(), json!(file.is_little_endian()));
                match file.imports() {
                    Ok(values) => {
                        for value in values {
                            imports.insert(String::from_utf8_lossy(value.name()).into_owned());
                        }
                    }
                    Err(error) => {
                        complete = false;
                        summary.insert("import_parse_error".into(), json!(error.to_string()));
                    }
                }
                match file.exports() {
                    Ok(values) => {
                        for value in values {
                            exports.insert(String::from_utf8_lossy(value.name()).into_owned());
                        }
                    }
                    Err(error) => {
                        complete = false;
                        summary.insert("export_parse_error".into(), json!(error.to_string()));
                    }
                }
                for section in file.sections().take(4096) {
                    sections.push(json!({
                        "name": section.name().unwrap_or("<invalid-name>"),
                        "address": section.address(),
                        "size": section.size(),
                        "kind": format!("{:?}", section.kind()),
                        "flags": format!("{:?}", section.flags()),
                    }));
                }
            }
            Err(error) => {
                complete = false;
                summary.insert("object_parse_error".into(), json!(error.to_string()));
                findings.push(parse_failure_finding("Native object structural parsing failed"));
            }
        }
    }

    summary.insert("imports".into(), json!(imports.iter().take(10_000).collect::<Vec<_>>()));
    summary.insert("exports".into(), json!(exports.iter().take(10_000).collect::<Vec<_>>()));
    summary.insert("sections".into(), json!(sections));

    if format == "elf" {
        summary.insert("mitigations".into(), analyze_elf_mitigations(bytes, &imports));
    } else if format == "pe" {
        let pe = analyze_pe_mitigations(bytes);
        if let Some(present) = pe.get("authenticode_directory_present") {
            summary.insert(
                "signature".into(),
                json!({"present": present, "verified": false, "reason": "certificate table presence is not signature validation"}),
            );
        }
        summary.insert("mitigations".into(), pe);
    } else if format.starts_with("mach-o") {
        let mach = analyze_mach_o(bytes);
        if let Some(present) = mach.get("code_signature_command_present") {
            summary.insert(
                "signature".into(),
                json!({"present": present, "verified": false, "reason": "LC_CODE_SIGNATURE presence is not signature validation"}),
            );
        }
        summary.insert("mitigations".into(), mach);
    }

    add_import_findings(&imports, &mut findings);
    add_string_findings(&strings, &mut findings);
    add_packing_findings(&sections, entropy, &strings, &mut findings);
    deduplicate_findings(&mut findings);

    Ok(EngineOutput {
        schema_version: SCHEMA_VERSION,
        complete,
        summary,
        findings,
    })
}

fn detect_format(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x7fELF") {
        "elf"
    } else if bytes.starts_with(b"MZ") {
        "pe"
    } else if bytes.starts_with(b"\0asm") {
        "wasm"
    } else if bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
    {
        "mach-o"
    } else if bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xbe, 0xba, 0xfe, 0xca])
    {
        "mach-o-fat"
    } else {
        "unknown"
    }
}

fn printable_strings(bytes: &[u8], limit: usize, minimum_length: usize) -> Vec<String> {
    let mut values = Vec::new();
    let mut current = Vec::new();
    for &byte in bytes {
        if (0x20..=0x7e).contains(&byte) || byte == b'\t' {
            current.push(byte);
            if current.len() > 16_384 {
                current.clear();
            }
        } else {
            if current.len() >= minimum_length {
                values.push(String::from_utf8_lossy(&current).into_owned());
                if values.len() >= limit {
                    break;
                }
            }
            current.clear();
        }
    }
    if current.len() >= minimum_length && values.len() < limit {
        values.push(String::from_utf8_lossy(&current).into_owned());
    }
    values
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn round(value: f64, digits: i32) -> f64 {
    let factor = 10f64.powi(digits);
    (value * factor).round() / factor
}

fn add_import_findings(imports: &BTreeSet<String>, findings: &mut Vec<EngineFinding>) {
    let rules: &[(&str, &str, &str, &str, &str)] = &[
        ("ptrace", "high", "anti-analysis", "anti-analysis", "Process tracing or anti-debugging API"),
        ("process_vm_writev", "critical", "process-injection", "process-injection", "Cross-process memory write API"),
        ("virtualallocex", "critical", "process-injection", "process-injection", "Remote process allocation API"),
        ("writeprocessmemory", "critical", "process-injection", "process-injection", "Remote process memory write API"),
        ("createremotethread", "critical", "process-injection", "process-injection", "Remote thread creation API"),
        ("setwindowshookex", "critical", "input-capture", "input-capture", "Global input hook API"),
        ("getasynckeystate", "critical", "input-capture", "input-capture", "Keyboard state API"),
        ("system", "high", "process-execution", "process-execution", "Shell command API"),
        ("popen", "high", "process-execution", "process-execution", "Shell process API"),
        ("winexec", "high", "process-execution", "process-execution", "Process execution API"),
        ("shellexecute", "high", "process-execution", "process-execution", "Shell execution API"),
        ("regsetvalue", "high", "persistence", "persistence", "Registry modification API"),
        ("createservice", "high", "persistence", "persistence", "Service creation API"),
        ("setuid", "critical", "privilege", "privilege-escalation", "Identity elevation API"),
        ("capset", "critical", "privilege", "privilege-escalation", "Linux capability API"),
        ("connect", "medium", "network", "outbound-network", "Outbound connection API"),
    ];
    for symbol in imports {
        let lowered = symbol.to_ascii_lowercase();
        for (needle, severity, category, capability, label) in rules {
            if !lowered.contains(needle) {
                continue;
            }
            let mut metadata = BTreeMap::new();
            metadata.insert("import_sha256".into(), json!(hex_digest(symbol.as_bytes())));
            findings.push(EngineFinding {
                rule_id: "ASSURANCE_NATIVE_SENSITIVE_IMPORT",
                severity,
                confidence: "high",
                category,
                title: format!("Native artifact imports {label}"),
                description: "A security-sensitive API is present in the native import table. Static presence does not prove reachability.",
                remediation: "Confirm reachability through source and sandbox evidence, then remove unnecessary capability or block the artifact.",
                capability,
                symbol: Some(symbol.clone()),
                metadata,
            });
            break;
        }
    }
}

fn add_string_findings(strings: &[String], findings: &mut Vec<EngineFinding>) {
    let indicators: &[(&str, &str, &str, &str)] = &[
        ("169.254.169.254", "critical", "cloud-metadata", "Cloud metadata endpoint"),
        ("metadata.google.internal", "critical", "cloud-metadata", "Cloud metadata endpoint"),
        ("/var/run/docker.sock", "critical", "container-control", "Docker control socket"),
        ("/run/containerd/containerd.sock", "critical", "container-control", "Containerd control socket"),
        ("/etc/sudoers", "critical", "privilege-escalation", "Sudo policy path"),
        (".ssh/id_rsa", "critical", "credential-store", "SSH private key path"),
        (".aws/credentials", "critical", "credential-store", "AWS credential path"),
        ("login data", "high", "credential-store", "Browser login database"),
        ("wallet.dat", "high", "credential-store", "Wallet database"),
        ("ld_preload", "high", "persistence", "Dynamic linker injection marker"),
        ("dyld_insert_libraries", "high", "persistence", "Mach-O library injection marker"),
    ];
    let lowered: Vec<String> = strings.iter().map(|value| value.to_ascii_lowercase()).collect();
    for (needle, severity, capability, label) in indicators {
        if !lowered.iter().any(|value| value.contains(needle)) {
            continue;
        }
        let mut metadata = BTreeMap::new();
        metadata.insert("indicator_sha256".into(), json!(hex_digest(needle.as_bytes())));
        findings.push(EngineFinding {
            rule_id: "ASSURANCE_NATIVE_SUSPICIOUS_STRING",
            severity,
            confidence: "medium",
            category: "native-analysis",
            title: format!("Native artifact references {label}"),
            description: "A sensitive endpoint, path, or behavior marker is embedded in the artifact. The raw indicator is not reproduced in evidence.",
            remediation: "Validate behavior in an isolated sandbox and remove unjustified access.",
            capability,
            symbol: None,
            metadata,
        });
    }
}

fn add_packing_findings(
    sections: &[Value],
    entropy: f64,
    strings: &[String],
    findings: &mut Vec<EngineFinding>,
) {
    let markers = ["upx0", "upx1", "upx!", "mpress", "themida", "aspack", "vmprotect"];
    let marker = strings
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .find(|value| markers.iter().any(|marker| value.contains(marker)));
    let suspicious_entropy = entropy >= 7.75 && sections.len() <= 8;
    if marker.is_none() && !suspicious_entropy {
        return;
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("entropy".into(), json!(round(entropy, 4)));
    metadata.insert("section_count".into(), json!(sections.len()));
    metadata.insert("known_packer_marker".into(), json!(marker.is_some()));
    findings.push(EngineFinding {
        rule_id: "ASSURANCE_NATIVE_PACKING_OR_OBFUSCATION",
        severity: "high",
        confidence: if marker.is_some() { "high" } else { "medium" },
        category: "obfuscation",
        title: "Native artifact appears packed or obfuscated".into(),
        description: "Packing markers or high entropy reduce static-review confidence and can conceal behavior.",
        remediation: "Require reproducible unpacked builds, verified provenance, and sandbox observation.",
        capability: "obfuscation",
        symbol: None,
        metadata,
    });
}

fn deduplicate_findings(findings: &mut Vec<EngineFinding>) {
    let mut seen = BTreeSet::new();
    findings.retain(|finding| {
        let key = format!(
            "{}:{}:{}",
            finding.rule_id,
            finding.capability,
            finding.symbol.as_deref().unwrap_or("")
        );
        seen.insert(key)
    });
}

fn parse_failure_finding(title: &str) -> EngineFinding {
    EngineFinding {
        rule_id: "ASSURANCE_NATIVE_STRUCTURAL_PARSE_FAILED",
        severity: "high",
        confidence: "high",
        category: "native-analysis",
        title: title.into(),
        description: "The artifact could not be structurally parsed, so native analysis is incomplete.",
        remediation: "Reject malformed native artifacts or review them with an independent binary-analysis pipeline.",
        capability: "native-analysis",
        symbol: None,
        metadata: BTreeMap::new(),
    }
}

fn analyze_elf_mitigations(bytes: &[u8], imports: &BTreeSet<String>) -> Value {
    if bytes.len() < 64 || !bytes.starts_with(b"\x7fELF") {
        return json!({"parsed": false});
    }
    let class = bytes[4];
    let little = bytes[5] == 1;
    let read_u16 = |offset: usize| -> Option<u16> {
        let raw: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(if little { u16::from_le_bytes(raw) } else { u16::from_be_bytes(raw) })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) })
    };
    let read_u64 = |offset: usize| -> Option<u64> {
        let raw: [u8; 8] = bytes.get(offset..offset + 8)?.try_into().ok()?;
        Some(if little { u64::from_le_bytes(raw) } else { u64::from_be_bytes(raw) })
    };
    let e_type = read_u16(16);
    let (phoff, phentsize, phnum, flags_offset) = if class == 2 {
        (read_u64(32).unwrap_or(0), read_u16(54).unwrap_or(0), read_u16(56).unwrap_or(0), 4usize)
    } else {
        (read_u32(28).unwrap_or(0) as u64, read_u16(42).unwrap_or(0), read_u16(44).unwrap_or(0), 24usize)
    };
    let mut gnu_stack = false;
    let mut stack_executable = false;
    let mut relro = false;
    for index in 0..phnum as usize {
        let offset = phoff as usize + index * phentsize as usize;
        let Some(kind) = read_u32(offset) else { break };
        if kind == 0x6474_e551 {
            gnu_stack = true;
            stack_executable = read_u32(offset + flags_offset).map(|flags| flags & 1 != 0).unwrap_or(false);
        } else if kind == 0x6474_e552 {
            relro = true;
        }
    }
    let canary = imports.iter().any(|name| name.contains("__stack_chk_fail"));
    json!({
        "parsed": true,
        "pie_candidate": e_type == Some(3),
        "gnu_stack_present": gnu_stack,
        "nx_stack": gnu_stack && !stack_executable,
        "relro_segment": relro,
        "stack_canary_import": canary,
    })
}

fn analyze_pe_mitigations(bytes: &[u8]) -> Value {
    let Some(pe_offset) = read_u32_le(bytes, 0x3c).map(|value| value as usize) else {
        return json!({"parsed": false});
    };
    if bytes.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0") {
        return json!({"parsed": false});
    }
    let optional = pe_offset + 24;
    let Some(magic) = read_u16_le(bytes, optional) else {
        return json!({"parsed": false});
    };
    let Some(dll_characteristics) = read_u16_le(bytes, optional + 70) else {
        return json!({"parsed": false});
    };
    let data_directory_offset = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => return json!({"parsed": false}),
    };
    let certificate_offset = optional + data_directory_offset + 4 * 8;
    let certificate_address = read_u32_le(bytes, certificate_offset).unwrap_or(0);
    let certificate_size = read_u32_le(bytes, certificate_offset + 4).unwrap_or(0);
    json!({
        "parsed": true,
        "high_entropy_va": dll_characteristics & 0x0020 != 0,
        "aslr": dll_characteristics & 0x0040 != 0,
        "nx_compat": dll_characteristics & 0x0100 != 0,
        "control_flow_guard": dll_characteristics & 0x4000 != 0,
        "authenticode_directory_present": certificate_address != 0 && certificate_size != 0,
        "authenticode_verified": false,
    })
}

fn analyze_mach_o(bytes: &[u8]) -> Value {
    if bytes.len() < 28 {
        return json!({"parsed": false});
    }
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap_or([0; 4]);
    let (little, is_64) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (true, false),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, true),
        [0xfe, 0xed, 0xfa, 0xce] => (false, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, true),
        _ => return json!({"parsed": false}),
    };
    let read = |offset: usize| -> Option<u32> {
        let raw: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if little { u32::from_le_bytes(raw) } else { u32::from_be_bytes(raw) })
    };
    let ncmds = read(16).unwrap_or(0).min(65_536);
    let flags = read(24).unwrap_or(0);
    let mut offset = if is_64 { 32usize } else { 28usize };
    let mut code_signature = false;
    let mut rpath_count = 0usize;
    for _ in 0..ncmds {
        let Some(command) = read(offset) else { break };
        let Some(size) = read(offset + 4).map(|value| value as usize) else { break };
        if size < 8 || offset.checked_add(size).is_none() || offset + size > bytes.len() {
            break;
        }
        if command == 0x1d {
            code_signature = true;
        }
        if command == 0x8000_001c {
            rpath_count += 1;
        }
        offset += size;
    }
    json!({
        "parsed": true,
        "pie": flags & 0x0020_0000 != 0,
        "code_signature_command_present": code_signature,
        "code_signature_verified": false,
        "rpath_count": rpath_count,
    })
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

#[derive(Debug, Serialize)]
struct WasmSummary {
    version: u32,
    imports: Vec<String>,
    exports: Vec<String>,
    has_start: bool,
    declared_memories: u32,
    unbounded_memory: bool,
    maximum_memory_pages: Option<u64>,
}

fn parse_wasm(bytes: &[u8]) -> Result<WasmSummary> {
    if bytes.len() < 8 || !bytes.starts_with(b"\0asm") {
        bail!("invalid wasm header");
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let mut cursor = 8usize;
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut has_start = false;
    let mut declared_memories = 0u32;
    let mut unbounded_memory = false;
    let mut maximum_memory_pages = None;
    while cursor < bytes.len() {
        let section_id = *bytes.get(cursor).ok_or_else(|| anyhow!("truncated section id"))?;
        cursor += 1;
        let section_size = read_leb_u32(bytes, &mut cursor)? as usize;
        let end = cursor.checked_add(section_size).ok_or_else(|| anyhow!("section overflow"))?;
        if end > bytes.len() {
            bail!("truncated section");
        }
        let section = &bytes[cursor..end];
        match section_id {
            2 => parse_wasm_imports(section, &mut imports)?,
            5 => {
                let (count, unbounded, maximum) = parse_wasm_memories(section)?;
                declared_memories = count;
                unbounded_memory = unbounded;
                maximum_memory_pages = maximum;
            }
            7 => parse_wasm_exports(section, &mut exports)?,
            8 => has_start = true,
            _ => {}
        }
        cursor = end;
    }
    Ok(WasmSummary {
        version,
        imports,
        exports,
        has_start,
        declared_memories,
        unbounded_memory,
        maximum_memory_pages,
    })
}

fn parse_wasm_imports(section: &[u8], imports: &mut Vec<String>) -> Result<()> {
    let mut cursor = 0usize;
    let count = read_leb_u32(section, &mut cursor)?.min(100_000);
    for _ in 0..count {
        let module = read_wasm_name(section, &mut cursor)?;
        let name = read_wasm_name(section, &mut cursor)?;
        let kind = *section.get(cursor).ok_or_else(|| anyhow!("truncated import kind"))?;
        cursor += 1;
        imports.push(format!("{module}.{name}"));
        match kind {
            0 => {
                read_leb_u32(section, &mut cursor)?;
            }
            1 => skip_table_type(section, &mut cursor)?,
            2 => {
                skip_limits(section, &mut cursor)?;
            }
            3 => {
                cursor = cursor.checked_add(2).ok_or_else(|| anyhow!("global overflow"))?;
                if cursor > section.len() {
                    bail!("truncated global type");
                }
            }
            4 => {
                read_leb_u32(section, &mut cursor)?;
                read_leb_u32(section, &mut cursor)?;
            }
            _ => bail!("unknown import kind"),
        }
    }
    Ok(())
}

fn parse_wasm_exports(section: &[u8], exports: &mut Vec<String>) -> Result<()> {
    let mut cursor = 0usize;
    let count = read_leb_u32(section, &mut cursor)?.min(100_000);
    for _ in 0..count {
        let name = read_wasm_name(section, &mut cursor)?;
        let kind = *section.get(cursor).ok_or_else(|| anyhow!("truncated export kind"))?;
        cursor += 1;
        read_leb_u32(section, &mut cursor)?;
        exports.push(format!("{kind}:{name}"));
    }
    Ok(())
}

fn parse_wasm_memories(section: &[u8]) -> Result<(u32, bool, Option<u64>)> {
    let mut cursor = 0usize;
    let count = read_leb_u32(section, &mut cursor)?.min(100_000);
    let mut unbounded = false;
    let mut maximum = None;
    for _ in 0..count {
        let (has_maximum, max) = skip_limits(section, &mut cursor)?;
        if !has_maximum {
            unbounded = true;
        }
        maximum = match (maximum, max) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) => value,
            (value, None) => value,
        };
    }
    Ok((count, unbounded, maximum))
}

fn skip_table_type(bytes: &[u8], cursor: &mut usize) -> Result<()> {
    *cursor = cursor.checked_add(1).ok_or_else(|| anyhow!("table overflow"))?;
    if *cursor > bytes.len() {
        bail!("truncated table element type");
    }
    skip_limits(bytes, cursor)?;
    Ok(())
}

fn skip_limits(bytes: &[u8], cursor: &mut usize) -> Result<(bool, Option<u64>)> {
    let flags = read_leb_u32(bytes, cursor)?;
    let memory64 = flags & 0x4 != 0;
    if memory64 {
        read_leb_u64(bytes, cursor)?;
        let maximum = if flags & 0x1 != 0 {
            Some(read_leb_u64(bytes, cursor)?)
        } else {
            None
        };
        Ok((maximum.is_some(), maximum))
    } else {
        read_leb_u32(bytes, cursor)?;
        let maximum = if flags & 0x1 != 0 {
            Some(read_leb_u32(bytes, cursor)? as u64)
        } else {
            None
        };
        Ok((maximum.is_some(), maximum))
    }
}

fn read_wasm_name(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let length = read_leb_u32(bytes, cursor)? as usize;
    if length > 1_048_576 {
        bail!("wasm name exceeds limit");
    }
    let end = cursor.checked_add(length).ok_or_else(|| anyhow!("name overflow"))?;
    let value = bytes.get(*cursor..end).ok_or_else(|| anyhow!("truncated wasm name"))?;
    *cursor = end;
    Ok(String::from_utf8_lossy(value).into_owned())
}

fn read_leb_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..35).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or_else(|| anyhow!("truncated leb128"))?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("u32 leb128 overflow")
}

fn read_leb_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or_else(|| anyhow!("truncated leb128"))?;
        *cursor += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("u64 leb128 overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic_formats() {
        assert_eq!(detect_format(b"\x7fELFrest"), "elf");
        assert_eq!(detect_format(b"MZrest"), "pe");
        assert_eq!(detect_format(b"\0asm\x01\0\0\0"), "wasm");
    }

    #[test]
    fn bounded_strings_stop_at_limit() {
        let values = printable_strings(b"alpha\0beta\0gamma\0", 2, 4);
        assert_eq!(values, vec!["alpha", "beta"]);
    }

    #[test]
    fn parses_minimal_wasm() {
        let summary = parse_wasm(b"\0asm\x01\0\0\0").unwrap();
        assert_eq!(summary.version, 1);
        assert!(summary.imports.is_empty());
    }

    #[test]
    fn pe_signature_presence_is_not_verification() {
        let value = analyze_pe_mitigations(b"not-a-pe");
        assert_eq!(value["parsed"], false);
    }
}
