#![forbid(unsafe_code)]
#![allow(clippy::all)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: &str = "hol-guard.scanner-engine.v1";
const MAX_ENGINE_INPUT: usize = 1024 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "hol-guard-scanner-engine", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        display_path: String,
        #[arg(long, default_value_t = 67_108_864)]
        max_bytes: usize,
        #[arg(long, default_value_t = 20_000)]
        max_strings: usize,
    },
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    complete: bool,
    summary: Summary,
    findings: Vec<Finding>,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct Summary {
    format: String,
    architecture: String,
    sha256: String,
    size: u64,
    analyzed_bytes: usize,
    sections: Vec<Section>,
    imports: Vec<String>,
    exports: Vec<String>,
    mitigations: BTreeMap<String, bool>,
    entropy: f64,
    packing: Packing,
    signature: Signature,
    indicator_count: usize,
    printable_string_count: usize,
}

#[derive(Clone, Serialize)]
struct Section {
    name: String,
    offset: u64,
    size: u64,
    entropy: f64,
    executable: bool,
    writable: bool,
}

#[derive(Serialize)]
struct Packing {
    suspected: bool,
    reason: Option<String>,
}

#[derive(Serialize)]
struct Signature {
    present: bool,
    verified: bool,
    verification: &'static str,
    note: &'static str,
}

#[derive(Clone, Serialize)]
struct Finding {
    rule_id: String,
    severity: String,
    confidence: String,
    category: String,
    title: String,
    description: String,
    remediation: String,
    metadata: BTreeMap<String, serde_json::Value>,
}

struct Analysis {
    format: String,
    architecture: String,
    sections: Vec<Section>,
    imports: Vec<String>,
    exports: Vec<String>,
    mitigations: BTreeMap<String, bool>,
    signature_present: bool,
    complete: bool,
}

struct FileData {
    bytes: Vec<u8>,
    sha256: String,
    size: u64,
    complete: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let report = match cli.command {
        Command::Inspect {
            path,
            display_path,
            max_bytes,
            max_strings,
        } => inspect(&path, &display_path, max_bytes, max_strings)?,
    };
    serde_json::to_writer(std::io::stdout(), &report).context("failed to serialize scanner report")?;
    Ok(())
}

fn inspect(path: &Path, display_path: &str, max_bytes: usize, max_strings: usize) -> Result<Report> {
    if max_bytes == 0 || max_bytes > MAX_ENGINE_INPUT {
        bail!("max-bytes is outside the allowed range");
    }
    if max_strings == 0 || max_strings > 1_000_000 {
        bail!("max-strings is outside the allowed range");
    }
    if display_path.is_empty() || display_path.len() > 16_384 || display_path.contains('\0') {
        bail!("display-path is invalid");
    }
    let file = read_file_bounded(path, max_bytes)?;
    let mut analysis = parse_format(&file.bytes);
    let entropy = entropy(&file.bytes);
    let strings = printable_strings(&file.bytes, max_strings);
    let mut findings = Vec::new();
    let mut capabilities = BTreeSet::new();
    add_sensitive_indicators(
        &file.bytes,
        display_path,
        &mut findings,
        &mut capabilities,
    );
    let section_high_entropy = analysis.sections.iter().any(|section| section.entropy >= 7.3 && section.size >= 4096);
    let packed_name = analysis.sections.iter().any(|section| {
        let lowered = section.name.to_ascii_lowercase();
        lowered.contains("upx") || lowered.contains("packed") || lowered.contains("aspack")
    });
    let packing_suspected = entropy >= 7.3 && file.bytes.len() >= 4096 || section_high_entropy || packed_name;
    let packing_reason = if packed_name {
        Some("packing-section-name".to_string())
    } else if section_high_entropy {
        Some("high-entropy-section".to_string())
    } else if packing_suspected {
        Some("high-overall-entropy".to_string())
    } else {
        None
    };
    if packing_suspected {
        capabilities.insert("obfuscation".to_string());
        findings.push(finding(
            "ASSURANCE_NATIVE_PACKING_INDICATOR",
            "medium",
            "medium",
            "native-security",
            "Native artifact may be packed or obfuscated",
            "High entropy or packing-related section names reduce static transparency.",
            "Require unpacked reproducible sources, trusted provenance, and isolated observation.",
            display_path,
            BTreeMap::from([("entropy".to_string(), serde_json::json!(round4(entropy)))]),
        ));
    }
    if !file.complete {
        analysis.complete = false;
        findings.push(finding(
            "ASSURANCE_NATIVE_ANALYSIS_TRUNCATED",
            "high",
            "high",
            "coverage",
            "Native structural analysis reached its byte limit",
            "The exact complete artifact is hashed, but structural parsing used a bounded prefix.",
            "Raise the managed byte limit in an isolated environment or review the complete artifact independently.",
            display_path,
            BTreeMap::from([
                ("size".to_string(), serde_json::json!(file.size)),
                ("analyzed_bytes".to_string(), serde_json::json!(file.bytes.len())),
            ]),
        ));
    }
    findings.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then(left.title.cmp(&right.title))
            .then(left.metadata.len().cmp(&right.metadata.len()))
    });
    findings.dedup_by(|left, right| {
        left.rule_id == right.rule_id && left.title == right.title && left.metadata == right.metadata
    });
    analysis.imports.sort();
    analysis.imports.dedup();
    analysis.exports.sort();
    analysis.exports.dedup();
    let indicator_count = findings
        .iter()
        .filter(|item| item.rule_id == "ASSURANCE_NATIVE_SENSITIVE_INDICATOR")
        .count();
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        complete: file.complete && analysis.complete,
        summary: Summary {
            format: analysis.format,
            architecture: analysis.architecture,
            sha256: file.sha256,
            size: file.size,
            analyzed_bytes: file.bytes.len(),
            sections: analysis.sections,
            imports: analysis.imports,
            exports: analysis.exports,
            mitigations: analysis.mitigations,
            entropy: round4(entropy),
            packing: Packing {
                suspected: packing_suspected,
                reason: packing_reason,
            },
            signature: Signature {
                present: analysis.signature_present,
                verified: false,
                verification: "not-performed",
                note: "A PE security directory or Mach-O code-signature load command is not cryptographic verification.",
            },
            indicator_count,
            printable_string_count: strings.len(),
        },
        findings,
        capabilities: capabilities.into_iter().collect(),
    })
}

fn read_file_bounded(path: &Path, max_bytes: usize) -> Result<FileData> {
    let before = fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if !before.is_file() {
        bail!("native target is not a regular file");
    }
    let size = before.len();
    let modified = before.modified().ok();
    let mut file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let opened = file.metadata().context("failed to stat opened native file")?;
    if opened.len() != size || opened.modified().ok() != modified {
        bail!("native file changed before reading");
    }
    let mut hasher = Sha256::new();
    let mut bytes = Vec::with_capacity(max_bytes.min(size as usize));
    let mut buffer = [0_u8; 1024 * 1024];
    let mut read_total = 0_u64;
    loop {
        let count = file.read(&mut buffer).context("failed to read native file")?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        if bytes.len() < max_bytes {
            let remaining = max_bytes - bytes.len();
            bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        }
        read_total += count as u64;
    }
    let after = fs::metadata(path).context("failed to restat native file")?;
    if read_total != size || after.len() != size || after.modified().ok() != modified {
        bail!("native file changed while reading");
    }
    let sha256 = format!("{:x}", hasher.finalize());
    Ok(FileData {
        bytes,
        sha256,
        size,
        complete: size <= max_bytes as u64,
    })
}

fn parse_format(data: &[u8]) -> Analysis {
    if data.starts_with(b"MZ") {
        return parse_pe(data);
    }
    if data.starts_with(b"\x7fELF") {
        return parse_elf(data);
    }
    if data.starts_with(b"\0asm") {
        return parse_wasm(data);
    }
    if data.len() >= 4 {
        let magic = &data[..4];
        if matches!(
            magic,
            b"\xfe\xed\xfa\xce"
                | b"\xce\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xcf"
                | b"\xcf\xfa\xed\xfe"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        ) {
            return parse_macho(data);
        }
    }
    Analysis {
        format: "unknown-native".to_string(),
        architecture: "unknown".to_string(),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        mitigations: BTreeMap::new(),
        signature_present: false,
        complete: false,
    }
}

#[derive(Clone)]
struct PeSection {
    name: String,
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

fn parse_pe(data: &[u8]) -> Analysis {
    let mut complete = true;
    let pe_offset = read_u32_le(data, 0x3c).map(|value| value as usize);
    let Some(pe_offset) = pe_offset else {
        return incomplete("pe");
    };
    if slice(data, pe_offset, 4) != Some(b"PE\0\0") {
        return incomplete("pe");
    }
    let machine = read_u16_le(data, pe_offset + 4).unwrap_or_default();
    let section_count = read_u16_le(data, pe_offset + 6).unwrap_or_default().min(4096) as usize;
    let optional_size = read_u16_le(data, pe_offset + 20).unwrap_or_default() as usize;
    let optional_offset = pe_offset + 24;
    let optional_magic = read_u16_le(data, optional_offset).unwrap_or_default();
    let architecture = match machine {
        0x014c => "x86",
        0x8664 => "x86_64",
        0x01c0 | 0x01c4 => "arm",
        0xaa64 => "aarch64",
        _ => "unknown",
    }
    .to_string();
    let dll_characteristics = read_u16_le(data, optional_offset + 0x46).unwrap_or_default();
    let mut mitigations = BTreeMap::from([
        ("aslr".to_string(), dll_characteristics & 0x0040 != 0),
        ("dep".to_string(), dll_characteristics & 0x0100 != 0),
        ("high_entropy_va".to_string(), dll_characteristics & 0x0020 != 0),
        ("control_flow_guard".to_string(), dll_characteristics & 0x4000 != 0),
    ]);
    if optional_magic == 0 {
        mitigations.clear();
        complete = false;
    }
    let section_table = optional_offset.saturating_add(optional_size);
    let mut pe_sections = Vec::new();
    let mut sections = Vec::new();
    for index in 0..section_count {
        let offset = section_table.saturating_add(index.saturating_mul(40));
        let Some(header) = slice(data, offset, 40) else {
            complete = false;
            break;
        };
        let name = ascii_name(&header[..8]);
        let virtual_size = read_u32_le(header, 8).unwrap_or_default();
        let virtual_address = read_u32_le(header, 12).unwrap_or_default();
        let raw_size = read_u32_le(header, 16).unwrap_or_default();
        let raw_offset = read_u32_le(header, 20).unwrap_or_default();
        let characteristics = read_u32_le(header, 36).unwrap_or_default();
        let section_data = slice(data, raw_offset as usize, raw_size as usize).unwrap_or(&[]);
        sections.push(Section {
            name: name.clone(),
            offset: raw_offset as u64,
            size: raw_size as u64,
            entropy: round4(entropy(section_data)),
            executable: characteristics & 0x2000_0000 != 0,
            writable: characteristics & 0x8000_0000 != 0,
        });
        pe_sections.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
        });
    }
    let data_directory_offset = match optional_magic {
        0x10b => optional_offset + 96,
        0x20b => optional_offset + 112,
        _ => {
            complete = false;
            optional_offset
        }
    };
    let export_rva = read_u32_le(data, data_directory_offset).unwrap_or_default();
    let export_size = read_u32_le(data, data_directory_offset + 4).unwrap_or_default();
    let import_rva = read_u32_le(data, data_directory_offset + 8).unwrap_or_default();
    let import_size = read_u32_le(data, data_directory_offset + 12).unwrap_or_default();
    let certificate_offset = read_u32_le(data, data_directory_offset + 32).unwrap_or_default();
    let certificate_size = read_u32_le(data, data_directory_offset + 36).unwrap_or_default();
    let signature_present = certificate_size > 0
        && certificate_offset as u64 + certificate_size as u64 <= data.len() as u64;
    let imports = parse_pe_imports(data, import_rva, import_size, &pe_sections);
    let exports = parse_pe_exports(data, export_rva, export_size, &pe_sections);
    let _section_metadata_checksum = pe_sections.iter().fold(0_u64, |value, section| {
        value
            .wrapping_add(section.virtual_address as u64)
            .wrapping_add(section.virtual_size as u64)
            .wrapping_add(section.characteristics as u64)
            .wrapping_add(section.name.len() as u64)
    });
    Analysis {
        format: "pe".to_string(),
        architecture,
        sections,
        imports,
        exports,
        mitigations,
        signature_present,
        complete,
    }
}

fn parse_pe_imports(data: &[u8], rva: u32, size: u32, sections: &[PeSection]) -> Vec<String> {
    if rva == 0 || size == 0 {
        return Vec::new();
    }
    let Some(mut offset) = pe_rva_to_offset(rva, sections) else {
        return Vec::new();
    };
    let end = offset.saturating_add(size as usize).min(data.len());
    let mut result = Vec::new();
    for _ in 0..1024 {
        let Some(descriptor) = slice(data, offset, 20) else {
            break;
        };
        if descriptor.iter().all(|value| *value == 0) {
            break;
        }
        let name_rva = read_u32_le(descriptor, 12).unwrap_or_default();
        if let Some(name_offset) = pe_rva_to_offset(name_rva, sections) {
            if let Some(name) = read_c_string(data, name_offset, 512) {
                result.push(name);
            }
        }
        offset = offset.saturating_add(20);
        if offset >= end {
            break;
        }
    }
    result
}

fn parse_pe_exports(data: &[u8], rva: u32, size: u32, sections: &[PeSection]) -> Vec<String> {
    if rva == 0 || size < 40 {
        return Vec::new();
    }
    let Some(offset) = pe_rva_to_offset(rva, sections) else {
        return Vec::new();
    };
    let Some(directory) = slice(data, offset, 40) else {
        return Vec::new();
    };
    let count = read_u32_le(directory, 24).unwrap_or_default().min(4096) as usize;
    let names_rva = read_u32_le(directory, 32).unwrap_or_default();
    let Some(names_offset) = pe_rva_to_offset(names_rva, sections) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for index in 0..count {
        let Some(name_rva) = read_u32_le(data, names_offset + index * 4) else {
            break;
        };
        if let Some(name_offset) = pe_rva_to_offset(name_rva, sections) {
            if let Some(name) = read_c_string(data, name_offset, 512) {
                result.push(name);
            }
        }
    }
    result
}

fn pe_rva_to_offset(rva: u32, sections: &[PeSection]) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span) {
            return Some(section.raw_offset.saturating_add(rva - section.virtual_address) as usize);
        }
    }
    None
}

fn parse_elf(data: &[u8]) -> Analysis {
    if data.len() < 20 {
        return incomplete("elf");
    }
    let class = data[4];
    let little = data[5] == 1;
    if !matches!(class, 1 | 2) || !matches!(data[5], 1 | 2) {
        return incomplete("elf");
    }
    let read16 = |offset| read_u16(data, offset, little);
    let read32 = |offset| read_u32(data, offset, little);
    let read64 = |offset| read_u64(data, offset, little);
    let machine = read16(18).unwrap_or_default();
    let architecture = match machine {
        3 => "x86",
        62 => "x86_64",
        40 => "arm",
        183 => "aarch64",
        8 => "mips",
        243 => "riscv",
        _ => "unknown",
    }
    .to_string();
    let e_type = read16(16).unwrap_or_default();
    let (phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if class == 1 {
        (
            read32(28).unwrap_or_default() as u64,
            read32(32).unwrap_or_default() as u64,
            read16(42).unwrap_or_default(),
            read16(44).unwrap_or_default(),
            read16(46).unwrap_or_default(),
            read16(48).unwrap_or_default(),
            read16(50).unwrap_or_default(),
        )
    } else {
        (
            read64(32).unwrap_or_default(),
            read64(40).unwrap_or_default(),
            read16(54).unwrap_or_default(),
            read16(56).unwrap_or_default(),
            read16(58).unwrap_or_default(),
            read16(60).unwrap_or_default(),
            read16(62).unwrap_or_default(),
        )
    };
    let mut nx_stack = false;
    let mut relro = false;
    let mut program_complete = true;
    for index in 0..phnum.min(4096) as usize {
        let offset = phoff as usize + index * phentsize as usize;
        let Some(header) = slice(data, offset, phentsize as usize) else {
            program_complete = false;
            break;
        };
        let p_type = read_u32(header, 0, little).unwrap_or_default();
        let flags = if class == 1 {
            read_u32(header, 24, little).unwrap_or_default()
        } else {
            read_u32(header, 4, little).unwrap_or_default()
        };
        if p_type == 0x6474_e551 {
            nx_stack = flags & 0x1 == 0;
        }
        if p_type == 0x6474_e552 {
            relro = true;
        }
    }
    let mut raw_sections: Vec<(u32, u64, u64, u64)> = Vec::new();
    let mut complete = program_complete;
    for index in 0..shnum.min(8192) as usize {
        let offset = shoff as usize + index * shentsize as usize;
        let Some(header) = slice(data, offset, shentsize as usize) else {
            complete = false;
            break;
        };
        let name = read_u32(header, 0, little).unwrap_or_default();
        let flags = if class == 1 {
            read_u32(header, 8, little).unwrap_or_default() as u64
        } else {
            read_u64(header, 8, little).unwrap_or_default()
        };
        let file_offset = if class == 1 {
            read_u32(header, 16, little).unwrap_or_default() as u64
        } else {
            read_u64(header, 24, little).unwrap_or_default()
        };
        let size = if class == 1 {
            read_u32(header, 20, little).unwrap_or_default() as u64
        } else {
            read_u64(header, 32, little).unwrap_or_default()
        };
        raw_sections.push((name, file_offset, size, flags));
    }
    let names = raw_sections
        .get(shstrndx as usize)
        .and_then(|(_, offset, size, _)| slice(data, *offset as usize, *size as usize))
        .unwrap_or(&[]);
    let sections = raw_sections
        .iter()
        .map(|(name_offset, offset, size, flags)| {
            let name = read_c_string(names, *name_offset as usize, 512).unwrap_or_default();
            let bytes = slice(data, *offset as usize, *size as usize).unwrap_or(&[]);
            Section {
                name,
                offset: *offset,
                size: *size,
                entropy: round4(entropy(bytes)),
                executable: flags & 0x4 != 0,
                writable: flags & 0x1 != 0,
            }
        })
        .collect();
    let mitigations = BTreeMap::from([
        ("pie".to_string(), e_type == 3),
        ("nx_stack".to_string(), nx_stack),
        ("relro".to_string(), relro),
        (
            "stack_canary".to_string(),
            data.windows(b"__stack_chk_fail".len())
                .any(|window| window == b"__stack_chk_fail"),
        ),
    ]);
    Analysis {
        format: "elf".to_string(),
        architecture,
        sections,
        imports: Vec::new(),
        exports: Vec::new(),
        mitigations,
        signature_present: false,
        complete,
    }
}

fn parse_macho(data: &[u8]) -> Analysis {
    if data.len() < 28 {
        return incomplete("mach-o");
    }
    let magic = &data[..4];
    let little = matches!(magic, b"\xce\xfa\xed\xfe" | b"\xcf\xfa\xed\xfe" | b"\xbe\xba\xfe\xca" | b"\xbf\xba\xfe\xca");
    let is_64 = matches!(magic, b"\xfe\xed\xfa\xcf" | b"\xcf\xfa\xed\xfe" | b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca");
    let is_fat = matches!(magic, b"\xca\xfe\xba\xbe" | b"\xbe\xba\xfe\xca" | b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca");
    if is_fat {
        return Analysis {
            format: if is_64 { "mach-o-fat64" } else { "mach-o-fat" }.to_string(),
            architecture: "multi-architecture".to_string(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            mitigations: BTreeMap::new(),
            signature_present: false,
            complete: false,
        };
    }
    let cputype = read_u32(data, 4, little).unwrap_or_default();
    let architecture = match cputype & 0x00ff_ffff {
        7 => if cputype & 0x0100_0000 != 0 { "x86_64" } else { "x86" },
        12 => if cputype & 0x0100_0000 != 0 { "aarch64" } else { "arm" },
        _ => "unknown",
    }
    .to_string();
    let ncmds = read_u32(data, 16, little).unwrap_or_default().min(16_384) as usize;
    let flags = read_u32(data, 24, little).unwrap_or_default();
    let mut offset = if is_64 { 32 } else { 28 };
    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut signature_present = false;
    let mut complete = true;
    for _ in 0..ncmds {
        let Some(command_header) = slice(data, offset, 8) else {
            complete = false;
            break;
        };
        let command = read_u32(command_header, 0, little).unwrap_or_default();
        let command_size = read_u32(command_header, 4, little).unwrap_or_default() as usize;
        if command_size < 8 {
            complete = false;
            break;
        }
        let Some(command_bytes) = slice(data, offset, command_size) else {
            complete = false;
            break;
        };
        let base_command = command & 0x7fff_ffff;
        if base_command == 0x1d {
            signature_present = true;
        }
        if matches!(base_command, 0x0c | 0x18 | 0x1f | 0x20 | 0x23) {
            let name_offset = read_u32(command_bytes, 8, little).unwrap_or_default() as usize;
            if let Some(name) = read_c_string(command_bytes, name_offset, 2048) {
                imports.push(name);
            }
        }
        if base_command == 0x01 || base_command == 0x19 {
            let name = ascii_name(slice(command_bytes, 8, 16).unwrap_or(&[]));
            let (file_offset, file_size, init_protection) = if base_command == 0x19 {
                (
                    read_u64(command_bytes, 40, little).unwrap_or_default(),
                    read_u64(command_bytes, 48, little).unwrap_or_default(),
                    read_u32(command_bytes, 60, little).unwrap_or_default(),
                )
            } else {
                (
                    read_u32(command_bytes, 32, little).unwrap_or_default() as u64,
                    read_u32(command_bytes, 36, little).unwrap_or_default() as u64,
                    read_u32(command_bytes, 44, little).unwrap_or_default(),
                )
            };
            let bytes = slice(data, file_offset as usize, file_size as usize).unwrap_or(&[]);
            sections.push(Section {
                name,
                offset: file_offset,
                size: file_size,
                entropy: round4(entropy(bytes)),
                executable: init_protection & 0x4 != 0,
                writable: init_protection & 0x2 != 0,
            });
        }
        offset = offset.saturating_add(command_size);
    }
    Analysis {
        format: "mach-o".to_string(),
        architecture,
        sections,
        imports,
        exports: Vec::new(),
        mitigations: BTreeMap::from([("pie".to_string(), flags & 0x0020_0000 != 0)]),
        signature_present,
        complete,
    }
}

fn parse_wasm(data: &[u8]) -> Analysis {
    if data.len() < 8 || &data[..8] != b"\0asm\x01\0\0\0" {
        return incomplete("wasm");
    }
    let mut cursor = 8_usize;
    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut complete = true;
    let mut section_index = 0_usize;
    while cursor < data.len() && section_index < 100_000 {
        let id = data[cursor];
        cursor += 1;
        let Some((size, consumed)) = read_var_u32(data, cursor) else {
            complete = false;
            break;
        };
        cursor += consumed;
        let payload_offset = cursor;
        let payload_size = size as usize;
        let Some(payload) = slice(data, payload_offset, payload_size) else {
            complete = false;
            break;
        };
        let name = if id == 0 {
            read_wasm_name(payload, 0)
                .map(|(value, _)| format!("custom:{value}"))
                .unwrap_or_else(|| "custom".to_string())
        } else {
            wasm_section_name(id).to_string()
        };
        sections.push(Section {
            name,
            offset: payload_offset as u64,
            size: payload_size as u64,
            entropy: round4(entropy(payload)),
            executable: id == 10,
            writable: id == 11,
        });
        if id == 2 {
            parse_wasm_imports(payload, &mut imports);
        } else if id == 7 {
            parse_wasm_exports(payload, &mut exports);
        }
        cursor += payload_size;
        section_index += 1;
    }
    if section_index >= 100_000 {
        complete = false;
    }
    Analysis {
        format: "wasm".to_string(),
        architecture: "wasm".to_string(),
        sections,
        imports,
        exports,
        mitigations: BTreeMap::new(),
        signature_present: false,
        complete,
    }
}

fn parse_wasm_imports(payload: &[u8], result: &mut Vec<String>) {
    let Some((count, consumed)) = read_var_u32(payload, 0) else {
        return;
    };
    let mut cursor = consumed;
    for _ in 0..count.min(4096) {
        let Some((module, used_module)) = read_wasm_name(payload, cursor) else {
            break;
        };
        cursor += used_module;
        let Some((name, used_name)) = read_wasm_name(payload, cursor) else {
            break;
        };
        cursor += used_name;
        let Some(kind) = payload.get(cursor).copied() else {
            break;
        };
        cursor += 1;
        result.push(format!("{module}.{name}"));
        let Some(next) = skip_wasm_import_type(payload, cursor, kind) else {
            break;
        };
        cursor = next;
    }
}

fn parse_wasm_exports(payload: &[u8], result: &mut Vec<String>) {
    let Some((count, consumed)) = read_var_u32(payload, 0) else {
        return;
    };
    let mut cursor = consumed;
    for _ in 0..count.min(4096) {
        let Some((name, used)) = read_wasm_name(payload, cursor) else {
            break;
        };
        cursor += used;
        if cursor >= payload.len() {
            break;
        }
        cursor += 1;
        let Some((_index, used_index)) = read_var_u32(payload, cursor) else {
            break;
        };
        cursor += used_index;
        result.push(name);
    }
}

fn skip_wasm_import_type(data: &[u8], cursor: usize, kind: u8) -> Option<usize> {
    match kind {
        0x00 => read_var_u32(data, cursor).map(|(_, used)| cursor + used),
        0x01 => {
            let mut position = cursor;
            position += 1;
            let flags = read_var_u32(data, position)?;
            position += flags.1;
            let minimum = read_var_u32(data, position)?;
            position += minimum.1;
            if flags.0 & 1 != 0 {
                position += read_var_u32(data, position)?.1;
            }
            Some(position)
        }
        0x02 => {
            let flags = read_var_u32(data, cursor)?;
            let mut position = cursor + flags.1;
            position += read_var_u32(data, position)?.1;
            if flags.0 & 1 != 0 {
                position += read_var_u32(data, position)?.1;
            }
            Some(position)
        }
        0x03 => Some(cursor.saturating_add(2)).filter(|value| *value <= data.len()),
        0x04 => {
            let mut position = cursor.saturating_add(1);
            position += read_var_u32(data, position)?.1;
            Some(position)
        }
        _ => None,
    }
}

fn add_sensitive_indicators(
    data: &[u8],
    display_path: &str,
    findings: &mut Vec<Finding>,
    capabilities: &mut BTreeSet<String>,
) {
    let indicators: &[(&[u8], &str, &str, &str)] = &[
        (b"/var/run/docker.sock", "critical", "container-control", "Docker socket access"),
        (b"/run/podman/podman.sock", "critical", "container-control", "Podman socket access"),
        (b"169.254.169.254", "critical", "cloud-metadata", "Cloud metadata service access"),
        (b"metadata.google.internal", "critical", "cloud-metadata", "Cloud metadata service access"),
        (b"CreateRemoteThread", "critical", "process-injection", "Remote process injection API"),
        (b"WriteProcessMemory", "critical", "process-injection", "Remote process memory write API"),
        (b"SetWindowsHookEx", "critical", "input-capture", "Global input hook API"),
        (b"GetAsyncKeyState", "critical", "input-capture", "Keyboard state capture API"),
        (b"Chrome/Login Data", "critical", "credential-store", "Browser credential database path"),
        (b"LD_PRELOAD", "high", "persistence", "Dynamic loader injection indicator"),
        (b"DYLD_INSERT_LIBRARIES", "high", "persistence", "Dynamic loader injection indicator"),
        (b"ShellExecute", "high", "process-execution", "Shell execution API"),
        (b"CreateProcess", "high", "process-execution", "Process creation API"),
        (b"WinExec", "high", "process-execution", "Command execution API"),
        (b"SSL_VERIFY_NONE", "high", "tls-bypass", "TLS verification bypass"),
        (b"InternetOpen", "medium", "outbound-network", "Windows network API"),
        (b"WinHttpOpen", "medium", "outbound-network", "Windows HTTP API"),
    ];
    for &(needle, severity, capability, label) in indicators {
        if !contains_case_insensitive(data, needle) {
            continue;
        }
        capabilities.insert(capability.to_string());
        findings.push(finding(
            "ASSURANCE_NATIVE_SENSITIVE_INDICATOR",
            severity,
            "medium",
            "native-security",
            label,
            "A bounded native import or string indicator matched a security-sensitive behavior. It does not prove reachability.",
            "Review the native artifact structurally and dynamically in an isolated environment before approval.",
            display_path,
            BTreeMap::from([
                ("indicator_sha256".to_string(), serde_json::json!(format!("{:x}", Sha256::digest(needle)))),
                ("capability".to_string(), serde_json::json!(capability)),
            ]),
        ));
    }
}

fn finding(
    rule_id: &str,
    severity: &str,
    confidence: &str,
    category: &str,
    title: &str,
    description: &str,
    remediation: &str,
    display_path: &str,
    mut metadata: BTreeMap<String, serde_json::Value>,
) -> Finding {
    metadata.insert(
        "path_sha256".to_string(),
        serde_json::json!(format!("{:x}", Sha256::digest(display_path.as_bytes()))),
    );
    Finding {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        category: category.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        remediation: remediation.to_string(),
        metadata,
    }
}

fn incomplete(format: &str) -> Analysis {
    Analysis {
        format: format.to_string(),
        architecture: "unknown".to_string(),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        mitigations: BTreeMap::new(),
        signature_present: false,
        complete: false,
    }
}

fn printable_strings(data: &[u8], maximum: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut start: Option<usize> = None;
    for (index, value) in data.iter().copied().chain(std::iter::once(0)).enumerate() {
        if (0x20..=0x7e).contains(&value) {
            start.get_or_insert(index);
            continue;
        }
        if let Some(begin) = start.take() {
            if index.saturating_sub(begin) >= 4 {
                result.push(String::from_utf8_lossy(&data[begin..index]).into_owned());
                if result.len() >= maximum {
                    break;
                }
            }
        }
    }
    result
}

fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for value in data {
        counts[*value as usize] += 1;
    }
    let length = data.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn ascii_name(data: &[u8]) -> String {
    let end = data.iter().position(|value| *value == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).trim().to_string()
}

fn read_c_string(data: &[u8], offset: usize, maximum: usize) -> Option<String> {
    let remainder = data.get(offset..)?;
    let length = remainder
        .iter()
        .take(maximum)
        .position(|value| *value == 0)
        .unwrap_or(remainder.len().min(maximum));
    if length == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&remainder[..length]).into_owned())
}

fn slice(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    data.get(offset..end)
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = slice(data, offset, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = slice(data, offset, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u16(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes: [u8; 2] = slice(data, offset, 2)?.try_into().ok()?;
    Some(if little { u16::from_le_bytes(bytes) } else { u16::from_be_bytes(bytes) })
}

fn read_u32(data: &[u8], offset: usize, little: bool) -> Option<u32> {
    let bytes: [u8; 4] = slice(data, offset, 4)?.try_into().ok()?;
    Some(if little { u32::from_le_bytes(bytes) } else { u32::from_be_bytes(bytes) })
}

fn read_u64(data: &[u8], offset: usize, little: bool) -> Option<u64> {
    let bytes: [u8; 8] = slice(data, offset, 8)?.try_into().ok()?;
    Some(if little { u64::from_le_bytes(bytes) } else { u64::from_be_bytes(bytes) })
}

fn read_var_u32(data: &[u8], offset: usize) -> Option<(u32, usize)> {
    let mut result = 0_u32;
    let mut shift = 0_u32;
    for index in 0..5 {
        let byte = *data.get(offset + index)?;
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((result, index + 1));
        }
        shift += 7;
    }
    None
}

fn read_wasm_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let (length, prefix) = read_var_u32(data, offset)?;
    let length = length as usize;
    let bytes = slice(data, offset + prefix, length)?;
    let value = std::str::from_utf8(bytes).ok()?.to_string();
    Some((value, prefix + length))
}

fn wasm_section_name(id: u8) -> &'static str {
    match id {
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "data-count",
        13 => "tag",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_wasm() {
        let analysis = parse_format(b"\0asm\x01\0\0\0");
        assert_eq!(analysis.format, "wasm");
        assert!(analysis.complete);
    }

    #[test]
    fn detects_sensitive_indicator() {
        let mut findings = Vec::new();
        let mut capabilities = BTreeSet::new();
        add_sensitive_indicators(
            b"prefix /var/run/docker.sock suffix",
            "fixture.bin",
            &mut findings,
            &mut capabilities,
        );
        assert!(capabilities.contains("container-control"));
        assert!(!findings.is_empty());
    }

    #[test]
    fn varint_is_bounded() {
        assert_eq!(read_var_u32(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(read_var_u32(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01], 0), None);
    }
}
