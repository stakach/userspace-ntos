use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use nt_pe_loader::PeFile;
use sha2::{Digest, Sha256};

pub const WINE_COMMIT: &str = "2ecc2f84b45ec42afbf1725d756181180a8204b1";
pub const WINE_SPEC_BLOB: &str = "10d42eeb1387204518711814923e19b6bbed25cf";
pub const WINE_SPEC_SHA256: &str =
    "25fafa3c7f9c2f981f1dcd70ee4315d8dedb13a695a20528a80843df86fff15c";
const TRACKED_MANIFEST: &str = include_str!("../fixtures/wine-ntdll-x86_64-2ecc2f84.tsv");
const TRACKED_MANIFEST_SHA256: &str =
    "bea27b141201215aebc8bc82b2ab6a75913f3a348ec0146690d5cea273627177";
const TRACKED_RECONCILIATION: &str =
    include_str!("../fixtures/wine-ntdll-reconciliation-2ecc2f84.tsv");
const EXPECTED_BASELINE_GAP_SHA256: &str =
    "a42e5d3ab87a3d9538e1451c109ceb06f3c7bd4dbf131ac48f017ab002e206e6";
const EXPECTED_CLASSIFICATION_SHA256: &str =
    "dfe7d4e030b44e7da62020a10b1820895513cc16d9f783e12fd05a973d8573f6";

const EXPECTED_ACTIVE_ROWS: usize = 1_536;
const EXPECTED_X64_ROWS: usize = 1_477;
const EXPECTED_EXTENSIONS: usize = 16;
const EXPECTED_WINDOWS_ROWS: usize = 1_461;
const EXPECTED_HANDLER_ALIASES: usize = 282;
const EXPECTED_KIND_COUNTS: &[(ExportKind, usize)] = &[
    (ExportKind::Stdcall, 1_178),
    (ExportKind::Cdecl, 178),
    (ExportKind::Varargs, 13),
    (ExportKind::Stub, 101),
    (ExportKind::Extern, 7),
];

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ExportKind {
    Stdcall,
    Cdecl,
    Varargs,
    Stub,
    Extern,
}

impl ExportKind {
    fn parse(token: &str, line: usize) -> Result<Self, String> {
        match token {
            "stdcall" => Ok(Self::Stdcall),
            "cdecl" => Ok(Self::Cdecl),
            "varargs" => Ok(Self::Varargs),
            "stub" => Ok(Self::Stub),
            "extern" => Ok(Self::Extern),
            _ => Err(format!(
                "line {line}: unsupported Wine export kind {token:?}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stdcall => "stdcall",
            Self::Cdecl => "cdecl",
            Self::Varargs => "varargs",
            Self::Stub => "stub",
            Self::Extern => "extern",
        }
    }

    fn is_function(self) -> bool {
        self != Self::Extern
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ExportFlags {
    arch: Vec<String>,
    fastcall: bool,
    norelay: bool,
    private: bool,
    ret64: bool,
    syscall: Option<Option<u16>>,
}

impl ExportFlags {
    fn parse(tokens: &[String], cursor: &mut usize, line: usize) -> Result<Self, String> {
        let mut flags = Self::default();
        while let Some(token) = tokens.get(*cursor).filter(|token| token.starts_with('-')) {
            *cursor += 1;
            match token.as_str() {
                "-fastcall" if !flags.fastcall => flags.fastcall = true,
                "-norelay" if !flags.norelay => flags.norelay = true,
                "-private" if !flags.private => flags.private = true,
                "-ret64" if !flags.ret64 => flags.ret64 = true,
                "-syscall" if flags.syscall.is_none() => flags.syscall = Some(None),
                _ if token.starts_with("-syscall=") && flags.syscall.is_none() => {
                    let value = token.trim_start_matches("-syscall=");
                    let value = value
                        .strip_prefix("0x")
                        .or_else(|| value.strip_prefix("0X"))
                        .ok_or_else(|| {
                            format!("line {line}: syscall id must be hexadecimal: {token:?}")
                        })?;
                    let value = u16::from_str_radix(value, 16)
                        .map_err(|_| format!("line {line}: invalid syscall id {token:?}"))?;
                    if value >= 0x4000 {
                        return Err(format!(
                            "line {line}: syscall id is out of range: {token:?}"
                        ));
                    }
                    flags.syscall = Some(Some(value));
                }
                _ if token.starts_with("-arch=") && flags.arch.is_empty() => {
                    let predicates = token.trim_start_matches("-arch=");
                    if predicates.is_empty() {
                        return Err(format!("line {line}: empty architecture predicate"));
                    }
                    for predicate in predicates.split(',') {
                        let architecture = predicate.strip_prefix('!').unwrap_or(predicate);
                        if !matches!(
                            architecture,
                            "i386" | "x86_64" | "arm" | "arm64" | "arm64ec" | "win32" | "win64"
                        ) || predicate.starts_with('!')
                            && matches!(architecture, "win32" | "win64")
                        {
                            return Err(format!(
                                "line {line}: unknown architecture predicate {predicate:?}"
                            ));
                        }
                        flags.arch.push(predicate.to_string());
                    }
                }
                _ => return Err(format!("line {line}: unknown or duplicate flag {token:?}")),
            }
        }
        Ok(flags)
    }

    fn matches_x86_64(&self) -> bool {
        if self.arch.is_empty() {
            return true;
        }
        let positive_match = self
            .arch
            .iter()
            .any(|arch| !arch.starts_with('!') && matches!(arch.as_str(), "x86_64" | "win64"));
        let has_negative = self.arch.iter().any(|arch| arch.starts_with('!'));
        let negative_match = self
            .arch
            .iter()
            .any(|arch| matches!(arch.as_str(), "!x86_64"));
        positive_match || has_negative && !negative_match
    }

    fn normalized(&self) -> String {
        let mut values = Vec::new();
        if !self.arch.is_empty() {
            values.push(format!("arch={}", self.arch.join(",")));
        }
        if self.fastcall {
            values.push("fastcall".to_string());
        }
        if self.norelay {
            values.push("norelay".to_string());
        }
        if self.private {
            values.push("private".to_string());
        }
        if self.ret64 {
            values.push("ret64".to_string());
        }
        if let Some(syscall) = self.syscall {
            values.push(match syscall {
                Some(number) => format!("syscall=0x{number:04x}"),
                None => "syscall".to_string(),
            });
        }
        if values.is_empty() {
            "-".to_string()
        } else {
            values.join(";")
        }
    }
}

fn validate_flags_for_kind(
    kind: ExportKind,
    flags: &ExportFlags,
    line: usize,
) -> Result<(), String> {
    if flags.fastcall && kind != ExportKind::Stdcall {
        return Err(format!("line {line}: -fastcall requires a stdcall export"));
    }
    if flags.syscall.is_some() && !matches!(kind, ExportKind::Stdcall | ExportKind::Stub) {
        return Err(format!("line {line}: -syscall requires stdcall or stub"));
    }
    Ok(())
}

fn parse_normalized_flags(field: &str, line: usize) -> Result<ExportFlags, String> {
    if field == "-" {
        return Ok(ExportFlags::default());
    }
    let tokens: Vec<_> = field.split(';').map(|flag| format!("-{flag}")).collect();
    let mut cursor = 0;
    let flags = ExportFlags::parse(&tokens, &mut cursor, line)?;
    if cursor != tokens.len() || flags.normalized() != field {
        return Err(format!(
            "manifest line {line} has non-canonical flags {field:?}"
        ));
    }
    if !flags.matches_x86_64() {
        return Err(format!(
            "manifest line {line} does not select the x86-64 target"
        ));
    }
    Ok(flags)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SpecRow {
    line: usize,
    name: String,
    kind: ExportKind,
    args: Vec<String>,
    flags: ExportFlags,
    alias: Option<String>,
}

impl SpecRow {
    fn is_wine_extension(&self) -> bool {
        self.name.starts_with("wine_") || self.name.starts_with("__wine_")
    }
}

fn valid_export_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'$' | b':' | b'-' | b'_' | b'@' | b'?' | b'<' | b'>'
                )
        })
}

fn valid_argument(argument: &str) -> bool {
    matches!(
        argument,
        "word"
            | "s_word"
            | "segptr"
            | "segstr"
            | "long"
            | "ptr"
            | "str"
            | "wstr"
            | "int64"
            | "int128"
            | "float"
            | "double"
    )
}

fn tokenize(line: &str, line_number: usize) -> Result<Vec<String>, String> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor == bytes.len() || bytes[cursor] == b'#' {
            break;
        }
        if matches!(bytes[cursor], b'(' | b')') {
            tokens.push((bytes[cursor] as char).to_string());
            cursor += 1;
            continue;
        }
        let mut token = String::new();
        while cursor < bytes.len()
            && !bytes[cursor].is_ascii_whitespace()
            && !matches!(bytes[cursor], b'(' | b')' | b'#')
        {
            if bytes[cursor] == b'\\' {
                cursor += 1;
                if cursor == bytes.len() {
                    return Err(format!("line {line_number}: trailing escape"));
                }
            }
            token.push(bytes[cursor] as char);
            cursor += 1;
        }
        if token.is_empty() {
            return Err(format!("line {line_number}: empty token"));
        }
        tokens.push(token);
        if cursor < bytes.len() && bytes[cursor] == b'#' {
            break;
        }
    }
    Ok(tokens)
}

fn parse_row(line: &str, line_number: usize) -> Result<Option<SpecRow>, String> {
    let tokens = tokenize(line, line_number)?;
    if tokens.is_empty() {
        return Ok(None);
    }
    if tokens.first().map(String::as_str) != Some("@") {
        return Err(format!(
            "line {line_number}: only anonymous '@' ordinals are accepted"
        ));
    }
    let kind = tokens
        .get(1)
        .ok_or_else(|| format!("line {line_number}: missing export kind"))
        .and_then(|kind| ExportKind::parse(kind, line_number))?;
    let mut cursor = 2usize;
    let flags = ExportFlags::parse(&tokens, &mut cursor, line_number)?;
    let name = tokens
        .get(cursor)
        .ok_or_else(|| format!("line {line_number}: missing export name"))?
        .clone();
    cursor += 1;
    if !valid_export_name(&name) {
        return Err(format!("line {line_number}: invalid export name {name:?}"));
    }

    let mut args = Vec::new();
    if kind.is_function() && kind != ExportKind::Stub {
        if tokens.get(cursor).map(String::as_str) != Some("(") {
            return Err(format!(
                "line {line_number}: function {name} has no argument list"
            ));
        }
        cursor += 1;
        while tokens.get(cursor).map(String::as_str) != Some(")") {
            let arg = tokens
                .get(cursor)
                .ok_or_else(|| format!("line {line_number}: unterminated argument list"))?;
            if !valid_argument(arg) {
                return Err(format!("line {line_number}: unknown argument type {arg:?}"));
            }
            args.push(arg.clone());
            cursor += 1;
        }
        cursor += 1;
    } else if kind == ExportKind::Stub && tokens.get(cursor).map(String::as_str) == Some("(") {
        cursor += 1;
        while tokens.get(cursor).map(String::as_str) != Some(")") {
            let arg = tokens
                .get(cursor)
                .ok_or_else(|| format!("line {line_number}: unterminated stub arguments"))?;
            if !valid_argument(arg) {
                return Err(format!(
                    "line {line_number}: unknown stub argument type {arg:?}"
                ));
            }
            args.push(arg.clone());
            cursor += 1;
        }
        cursor += 1;
    }
    let alias = tokens.get(cursor).cloned();
    cursor += usize::from(alias.is_some());
    if cursor != tokens.len() {
        return Err(format!(
            "line {line_number}: unexpected trailing tokens {:?}",
            &tokens[cursor..]
        ));
    }
    if let Some(alias) = alias.as_deref().filter(|alias| !valid_export_name(alias)) {
        return Err(format!(
            "line {line_number}: invalid handler name {alias:?}"
        ));
    }
    validate_flags_for_kind(kind, &flags, line_number)?;
    Ok(Some(SpecRow {
        line: line_number,
        name,
        kind,
        args,
        flags,
        alias,
    }))
}

fn parse_spec(spec: &str) -> Result<Vec<SpecRow>, String> {
    spec.lines()
        .enumerate()
        .filter_map(|(index, line)| match parse_row(line, index + 1) {
            Ok(Some(row)) => Some(Ok(row)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn validate_aggregate_counts(
    rows: impl IntoIterator<Item = (ExportKind, bool)>,
    context: &str,
) -> Result<(), String> {
    let mut counts = BTreeMap::new();
    let mut aliases = 0usize;
    for (kind, has_alias) in rows {
        *counts.entry(kind).or_insert(0usize) += 1;
        aliases += usize::from(has_alias);
    }
    for (kind, expected) in EXPECTED_KIND_COUNTS {
        let actual = counts.get(kind).copied().unwrap_or(0);
        if actual != *expected {
            return Err(format!(
                "{context} {} count changed: expected {expected}, found {actual}",
                kind.as_str()
            ));
        }
    }
    if aliases != EXPECTED_HANDLER_ALIASES {
        return Err(format!(
            "{context} handler-alias count changed: expected {EXPECTED_HANDLER_ALIASES}, found {aliases}"
        ));
    }
    Ok(())
}

fn validate_frozen_rows(rows: &[SpecRow]) -> Result<Vec<SpecRow>, String> {
    if rows.len() != EXPECTED_ACTIVE_ROWS {
        return Err(format!(
            "Wine active-row count changed: expected {EXPECTED_ACTIVE_ROWS}, found {}",
            rows.len()
        ));
    }
    let mut selected = BTreeMap::new();
    for row in rows.iter().filter(|row| row.flags.matches_x86_64()) {
        if let Some(previous) = selected.insert(row.name.clone(), row.clone()) {
            return Err(format!(
                "x86-64 Wine export {} is duplicated on lines {} and {}",
                row.name, previous.line, row.line
            ));
        }
    }
    let selected: Vec<_> = selected.into_values().collect();
    let extensions = selected
        .iter()
        .filter(|row| row.is_wine_extension())
        .count();
    if selected.len() != EXPECTED_X64_ROWS || extensions != EXPECTED_EXTENSIONS {
        return Err(format!(
            "Wine x86-64 inventory changed: rows={}/{} extensions={}/{}",
            selected.len(),
            EXPECTED_X64_ROWS,
            extensions,
            EXPECTED_EXTENSIONS
        ));
    }
    validate_aggregate_counts(
        selected.iter().map(|row| (row.kind, row.alias.is_some())),
        "Wine x86-64 source",
    )?;
    Ok(selected)
}

pub fn generate_manifest(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read Wine spec {}: {error}", path.display()))?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    if sha256 != WINE_SPEC_SHA256 {
        return Err(format!(
            "Wine spec content does not match pinned commit {WINE_COMMIT}: SHA-256 {sha256}"
        ));
    }
    let spec =
        std::str::from_utf8(&bytes).map_err(|error| format!("Wine spec is not UTF-8: {error}"))?;
    let rows = validate_frozen_rows(&parse_spec(spec)?)?;
    let mut output = String::new();
    writeln!(output, "# wine-commit\t{WINE_COMMIT}").unwrap();
    writeln!(output, "# wine-spec-blob\t{WINE_SPEC_BLOB}").unwrap();
    writeln!(output, "# wine-spec-sha256\t{WINE_SPEC_SHA256}").unwrap();
    writeln!(output, "# architecture\tx86_64").unwrap();
    writeln!(
        output,
        "# line\tname\tkind\targs\tflags\talias\twine-extension"
    )
    .unwrap();
    for row in rows {
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            row.line,
            row.name,
            row.kind.as_str(),
            if row.args.is_empty() {
                "-".to_string()
            } else {
                row.args.join(",")
            },
            row.flags.normalized(),
            row.alias.as_deref().unwrap_or("-"),
            u8::from(row.is_wine_extension()),
        )
        .unwrap();
    }
    Ok(output)
}

#[derive(Debug)]
struct ManifestRow {
    name: String,
    kind: ExportKind,
    args: String,
    flags: String,
    alias: Option<String>,
    wine_extension: bool,
}

fn parse_manifest(manifest: &str) -> Result<Vec<ManifestRow>, String> {
    if sha256_hex(manifest.as_bytes()) != TRACKED_MANIFEST_SHA256 {
        return Err("tracked Wine manifest content changed".to_string());
    }
    for (key, value) in [
        ("wine-commit", WINE_COMMIT),
        ("wine-spec-blob", WINE_SPEC_BLOB),
        ("wine-spec-sha256", WINE_SPEC_SHA256),
        ("architecture", "x86_64"),
    ] {
        let expected = format!("# {key}\t{value}");
        if !manifest.lines().any(|line| line == expected) {
            return Err(format!("tracked Wine manifest is missing {expected:?}"));
        }
    }
    let mut names = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, line) in manifest.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 7 {
            return Err(format!(
                "manifest line {} has {} fields",
                index + 1,
                fields.len()
            ));
        }
        fields[0]
            .parse::<usize>()
            .map_err(|_| format!("manifest line {} has invalid source line", index + 1))?;
        if !valid_export_name(fields[1]) {
            return Err(format!(
                "manifest line {} has invalid export name {:?}",
                index + 1,
                fields[1]
            ));
        }
        if !names.insert(fields[1].to_string()) {
            return Err(format!("manifest duplicates export {}", fields[1]));
        }
        let kind = ExportKind::parse(fields[2], index + 1)?;
        if fields[3] != "-" && !fields[3].split(',').all(valid_argument) {
            return Err(format!(
                "manifest line {} has invalid arguments {:?}",
                index + 1,
                fields[3]
            ));
        }
        if kind == ExportKind::Extern && fields[3] != "-" {
            return Err(format!(
                "manifest line {} gives an extern export arguments",
                index + 1
            ));
        }
        let flags = parse_normalized_flags(fields[4], index + 1)?;
        validate_flags_for_kind(kind, &flags, index + 1)?;
        let alias = (fields[5] != "-").then(|| fields[5].to_string());
        if alias
            .as_deref()
            .is_some_and(|alias| !valid_export_name(alias))
        {
            return Err(format!(
                "manifest line {} has invalid handler {:?}",
                index + 1,
                fields[5]
            ));
        }
        let wine_extension = match fields[6] {
            "0" => false,
            "1" => true,
            _ => return Err(format!("manifest line {} has invalid exclusion", index + 1)),
        };
        if wine_extension != (fields[1].starts_with("wine_") || fields[1].starts_with("__wine_")) {
            return Err(format!(
                "manifest line {} has inconsistent Wine-extension classification",
                index + 1
            ));
        }
        rows.push(ManifestRow {
            name: fields[1].to_string(),
            kind,
            args: fields[3].to_string(),
            flags: fields[4].to_string(),
            alias,
            wine_extension,
        });
    }
    let extensions = rows.iter().filter(|row| row.wine_extension).count();
    let windows = rows.len() - extensions;
    if rows.len() != EXPECTED_X64_ROWS
        || extensions != EXPECTED_EXTENSIONS
        || windows != EXPECTED_WINDOWS_ROWS
    {
        return Err(format!(
            "tracked Wine manifest inventory changed: rows={} extensions={extensions} windows={windows}",
            rows.len(),
        ));
    }
    validate_aggregate_counts(
        rows.iter().map(|row| (row.kind, row.alias.is_some())),
        "tracked Wine manifest",
    )?;
    Ok(rows)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationState {
    Planned,
    BlockedAbi,
    Implemented,
}

#[derive(Debug)]
struct ReconciliationRow {
    name: String,
    alias: Option<String>,
    group: String,
    owner: String,
    abi_authority: String,
    effective_args: String,
    return_class: String,
    state: ReconciliationState,
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_exact_export_alias(pe: &PeFile<'_>, alias_rva: u32, target_rva: u32) -> bool {
    if alias_rva == target_rva {
        return true;
    }
    let Some(jump) = pe.bytes_at_rva(alias_rva, 5) else {
        return false;
    };
    if jump[0] != 0xe9 {
        return false;
    }
    let displacement = i32::from_le_bytes(jump[1..5].try_into().unwrap());
    i64::from(alias_rva) + 5 + i64::from(displacement) == i64::from(target_rva)
}

fn parse_reconciliation(
    manifest: &[ManifestRow],
    reconciliation: &str,
) -> Result<Vec<ReconciliationRow>, String> {
    for (key, value) in [
        ("wine-commit", WINE_COMMIT),
        ("baseline-gap-sha256", EXPECTED_BASELINE_GAP_SHA256),
        ("architecture", "x86_64"),
    ] {
        let expected = format!("# {key}\t{value}");
        if !reconciliation.lines().any(|line| line == expected) {
            return Err(format!(
                "tracked Wine reconciliation is missing {expected:?}"
            ));
        }
    }

    let manifest_by_name: BTreeMap<_, _> = manifest
        .iter()
        .map(|row| (row.name.as_str(), row))
        .collect();
    let mut rows = Vec::new();
    let mut previous_name: Option<&str> = None;
    let mut names = String::new();
    let mut classification = String::new();
    for (index, line) in reconciliation.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 11 {
            return Err(format!(
                "reconciliation line {} has {} fields",
                index + 1,
                fields.len()
            ));
        }
        let name = fields[0];
        if previous_name.is_some_and(|previous| previous >= name) {
            return Err(format!(
                "reconciliation export {name:?} is duplicated or out of order"
            ));
        }
        previous_name = Some(name);
        let source = manifest_by_name.get(name).ok_or_else(|| {
            format!("reconciliation export {name:?} is absent from the pinned Wine manifest")
        })?;
        if source.wine_extension {
            return Err(format!(
                "reconciliation export {name:?} is a Wine host extension"
            ));
        }
        let expected_alias = source.alias.as_deref().unwrap_or("-");
        if fields[1] != source.kind.as_str()
            || fields[2] != source.args
            || fields[3] != source.flags
            || fields[4] != expected_alias
        {
            return Err(format!(
                "reconciliation export {name:?} disagrees with the pinned kind/ABI/alias row"
            ));
        }
        if fields[5].is_empty()
            || !fields[5]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!(
                "reconciliation export {name:?} has invalid group {:?}",
                fields[5]
            ));
        }
        if !matches!(fields[6], "kernel" | "alias" | "ntdll" | "ntdll-data") {
            return Err(format!(
                "reconciliation export {name:?} has invalid owner {:?}",
                fields[6]
            ));
        }
        if !matches!(
            fields[7],
            "wine-spec"
                | "nt5-source"
                | "reactos-source"
                | "reactos-sysfuncs"
                | "source-override"
                | "unknown"
        ) {
            return Err(format!(
                "reconciliation export {name:?} has invalid ABI authority {:?}",
                fields[7]
            ));
        }
        if fields[8] != "unresolved"
            && fields[8] != "-"
            && !fields[8].split(',').all(|argument| {
                valid_argument(argument) || matches!(argument, "u32" | "usize" | "isize")
            })
        {
            return Err(format!(
                "reconciliation export {name:?} has invalid effective arguments {:?}",
                fields[8]
            ));
        }
        if !matches!(
            fields[9],
            "ntstatus"
                | "i32"
                | "i64"
                | "u32"
                | "u64"
                | "isize"
                | "usize"
                | "ptr"
                | "bool"
                | "void"
                | "noreturn"
                | "f64"
                | "data-i32"
                | "data-block"
                | "unresolved"
        ) {
            return Err(format!(
                "reconciliation export {name:?} has invalid return class {:?}",
                fields[9]
            ));
        }
        let state = match fields[10] {
            "planned" => ReconciliationState::Planned,
            "blocked-abi" => ReconciliationState::BlockedAbi,
            "implemented" => ReconciliationState::Implemented,
            value => {
                return Err(format!(
                    "reconciliation export {name:?} has invalid state {value:?}"
                ))
            }
        };
        let unresolved =
            fields[7] == "unknown" || fields[8] == "unresolved" || fields[9] == "unresolved";
        if unresolved != (state == ReconciliationState::BlockedAbi)
            || (state == ReconciliationState::BlockedAbi
                && !(fields[7] == "unknown"
                    && fields[8] == "unresolved"
                    && fields[9] == "unresolved"))
        {
            return Err(format!(
                "reconciliation export {name:?} has inconsistent ABI/state classification"
            ));
        }
        let data_export = matches!(fields[9], "data-i32" | "data-block");
        if data_export && fields[6] != "ntdll-data" {
            return Err(format!(
                "reconciliation export {name:?} classifies data under a non-data owner"
            ));
        }
        if name.starts_with("Zw")
            && (fields[5] != "A-native"
                || fields[6] != "alias"
                || expected_alias != format!("Nt{}", &name[2..]))
        {
            return Err(format!(
                "reconciliation export {name:?} is not a canonical native alias"
            ));
        }
        writeln!(names, "{name}").unwrap();
        writeln!(
            classification,
            "{name}\t{}\t{}\t{}\t{}\t{}",
            fields[5], fields[6], fields[7], fields[8], fields[9]
        )
        .unwrap();
        rows.push(ReconciliationRow {
            name: name.to_string(),
            alias: (fields[4] != "-").then(|| fields[4].to_string()),
            group: fields[5].to_string(),
            owner: fields[6].to_string(),
            abi_authority: fields[7].to_string(),
            effective_args: fields[8].to_string(),
            return_class: fields[9].to_string(),
            state,
        });
    }
    if rows.len() != 372 || sha256_hex(names.as_bytes()) != EXPECTED_BASELINE_GAP_SHA256 {
        return Err(format!(
            "tracked Wine reconciliation does not cover the exact 372-name baseline gap"
        ));
    }
    if sha256_hex(classification.as_bytes()) != EXPECTED_CLASSIFICATION_SHA256 {
        return Err("tracked Wine reconciliation classification changed".to_string());
    }
    let reconciliation_by_name: BTreeMap<_, _> =
        rows.iter().map(|row| (row.name.as_str(), row)).collect();
    for row in rows.iter().filter(|row| row.name.starts_with("Zw")) {
        let nt_name = format!("Nt{}", &row.name[2..]);
        let nt_row = reconciliation_by_name
            .get(nt_name.as_str())
            .ok_or_else(|| {
                format!(
                    "native alias {} has no matching reconciliation row {nt_name}",
                    row.name
                )
            })?;
        if row.state != nt_row.state
            || row.effective_args != nt_row.effective_args
            || row.return_class != nt_row.return_class
        {
            return Err(format!(
                "native service {nt_name} and alias {} have different effective ABI or states",
                row.name
            ));
        }
    }
    Ok(rows)
}

fn category(name: &str) -> &'static str {
    for (prefix, category) in [
        ("Ntdll", "Ntdll"),
        ("Nt", "Nt"),
        ("Zw", "Zw"),
        ("Rtl", "Rtl"),
        ("Tp", "Tp"),
        ("Ldr", "Ldr"),
        ("Csr", "Csr"),
        ("ApiSet", "ApiSet"),
        ("WinSqm", "WinSqm"),
    ] {
        if name.starts_with(prefix) {
            return category;
        }
    }
    "CRT/data/other"
}

pub fn report(path: &Path) -> Result<String, String> {
    let rows = parse_manifest(TRACKED_MANIFEST)?;
    let reconciliation = parse_reconciliation(&rows, TRACKED_RECONCILIATION)?;
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read ntdll DLL {}: {error}", path.display()))?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("cannot parse ntdll DLL: {error:?}"))?;
    let exports = pe
        .exports()
        .map_err(|error| format!("cannot parse ntdll exports: {error:?}"))?;
    let exported: BTreeSet<_> = exports.iter().map(|export| export.name.as_str()).collect();
    let exported_by_name: BTreeMap<_, _> = exports
        .iter()
        .map(|export| (export.name.as_str(), export))
        .collect();
    let export_directory = pe
        .headers()
        .data_directory(nt_pe_loader::DIRECTORY_ENTRY_EXPORT);
    let export_directory_end = export_directory
        .virtual_address
        .checked_add(export_directory.size)
        .ok_or_else(|| "ntdll export directory overflows its RVA range".to_string())?;
    for row in reconciliation
        .iter()
        .filter(|row| row.state == ReconciliationState::Implemented)
    {
        let export = exported_by_name.get(row.name.as_str()).ok_or_else(|| {
            format!(
                "implemented reconciliation export {} is absent from the DLL",
                row.name
            )
        })?;
        if export.rva >= export_directory.virtual_address && export.rva < export_directory_end {
            return Err(format!(
                "implemented reconciliation export {} is a forwarder",
                row.name
            ));
        }
        let data_export = matches!(row.return_class.as_str(), "data-i32" | "data-block");
        let protection = pe.protection_at(export.rva);
        if data_export && (!protection.writable() || protection.executable()) {
            return Err(format!(
                "implemented reconciliation data export {} is not writable non-executable data",
                row.name
            ));
        }
        if !data_export && !protection.executable() {
            return Err(format!(
                "implemented reconciliation function export {} is not executable code",
                row.name
            ));
        }
        if let Some(alias) = row.alias.as_deref() {
            if let Some(target) = exported_by_name.get(alias) {
                if !is_exact_export_alias(&pe, export.rva, target.rva) {
                    return Err(format!(
                        "implemented reconciliation alias {} neither shares nor tail-jumps to {alias}'s RVA",
                        row.name
                    ));
                }
            } else if row.name.starts_with("Zw") {
                return Err(format!(
                    "implemented native alias {} has no target export {alias}",
                    row.name
                ));
            }
        }
    }
    let windows: Vec<_> = rows.iter().filter(|row| !row.wine_extension).collect();
    let missing: Vec<_> = windows
        .iter()
        .copied()
        .filter(|row| !exported.contains(row.name.as_str()))
        .collect();
    let current_missing: BTreeSet<_> = missing.iter().map(|row| row.name.as_str()).collect();
    let catalog_open: BTreeSet<_> = reconciliation
        .iter()
        .filter(|row| row.state != ReconciliationState::Implemented)
        .map(|row| row.name.as_str())
        .collect();
    if current_missing != catalog_open {
        let unclassified: Vec<_> = current_missing.difference(&catalog_open).copied().collect();
        let stale: Vec<_> = catalog_open.difference(&current_missing).copied().collect();
        return Err(format!(
            "Wine reconciliation drift: unclassified missing={unclassified:?}, stale open={stale:?}"
        ));
    }
    let mut categories: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for row in &missing {
        categories
            .entry(category(&row.name))
            .or_default()
            .push(&row.name);
    }

    let mut output = String::new();
    writeln!(output, "wine commit: {WINE_COMMIT}").unwrap();
    writeln!(output, "wine spec blob: {WINE_SPEC_BLOB}").unwrap();
    writeln!(output, "wine spec sha256: {WINE_SPEC_SHA256}").unwrap();
    writeln!(output, "architecture: x86_64").unwrap();
    writeln!(output, "applicable rows: {}", rows.len()).unwrap();
    writeln!(
        output,
        "wine-only exclusions: {}",
        rows.len() - windows.len()
    )
    .unwrap();
    writeln!(output, "windows-visible names: {}", windows.len()).unwrap();
    for kind in [
        ExportKind::Stdcall,
        ExportKind::Cdecl,
        ExportKind::Varargs,
        ExportKind::Stub,
        ExportKind::Extern,
    ] {
        writeln!(
            output,
            "applicable {} rows: {}",
            kind.as_str(),
            rows.iter().filter(|row| row.kind == kind).count()
        )
        .unwrap();
    }
    writeln!(
        output,
        "applicable handler aliases: {}",
        rows.iter().filter(|row| row.alias.is_some()).count()
    )
    .unwrap();
    writeln!(output, "dll exports: {}", exported.len()).unwrap();
    writeln!(
        output,
        "covered wine names: {}",
        windows.len() - missing.len()
    )
    .unwrap();
    writeln!(output, "missing wine names: {}", missing.len()).unwrap();
    for state in [
        ReconciliationState::Planned,
        ReconciliationState::BlockedAbi,
        ReconciliationState::Implemented,
    ] {
        let label = match state {
            ReconciliationState::Planned => "planned",
            ReconciliationState::BlockedAbi => "blocked-abi",
            ReconciliationState::Implemented => "implemented",
        };
        writeln!(
            output,
            "reconciliation {label}: {}",
            reconciliation
                .iter()
                .filter(|row| row.state == state)
                .count()
        )
        .unwrap();
    }
    writeln!(
        output,
        "reconciliation groups/owners/abi-authorities: {}/{}/{}",
        reconciliation
            .iter()
            .map(|row| row.group.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        reconciliation
            .iter()
            .map(|row| row.owner.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        reconciliation
            .iter()
            .map(|row| row.abi_authority.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap();
    writeln!(
        output,
        "reconciliation effective-argument/return shapes: {}/{}",
        reconciliation
            .iter()
            .map(|row| row.effective_args.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        reconciliation
            .iter()
            .map(|row| row.return_class.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap();
    for (category, names) in categories {
        writeln!(
            output,
            "missing {category} ({}): {}",
            names.len(),
            names.join(",")
        )
        .unwrap();
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actual_function_stub_data_alias_and_inline_comment_forms() {
        let spec = "\
@ stdcall -syscall=0x000f NtClose(long)\n\
@ stub CsrProbeForRead\n\
@ extern LdrSystemDllInitBlock\n\
@ stdcall -arch=x86_64 RtlCopyMemoryNonTemporal(ptr ptr long) RtlCopyMemory\n\
@ cdecl -arch=i386 -ret64 _ftol2_sse() _ftol # FIXME\n";
        let rows = parse_spec(spec).unwrap();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].flags.syscall, Some(Some(0x0f)));
        assert_eq!(rows[1].kind, ExportKind::Stub);
        assert_eq!(rows[2].kind, ExportKind::Extern);
        assert_eq!(rows[3].alias.as_deref(), Some("RtlCopyMemory"));
        assert!(rows[3].flags.matches_x86_64());
        assert!(!rows[4].flags.matches_x86_64());
    }

    #[test]
    fn x86_64_architecture_predicates_match_wine_masks() {
        let matches = |predicate: &str| {
            let tokens = vec![format!("-arch={predicate}"), "Name".to_string()];
            let mut cursor = 0;
            ExportFlags::parse(&tokens, &mut cursor, 1)
                .unwrap()
                .matches_x86_64()
        };
        assert!(matches("x86_64"));
        assert!(matches("win64"));
        assert!(matches("!i386"));
        assert!(matches("arm,x86_64"));
        assert!(!matches("i386"));
        assert!(!matches("win32"));
        assert!(!matches("arm,arm64,arm64ec"));
        assert!(!matches("!x86_64"));
    }

    #[test]
    fn malformed_rows_fail_closed() {
        for malformed in [
            "@ mystery Name()",
            "@ stdcall -unknown Name()",
            "@ stdcall Name(mystery)",
            "@ cdecl -fastcall Name()",
            "@ extern Name trailing extra",
            "1 stdcall Name()",
        ] {
            assert!(parse_row(malformed, 7).is_err(), "accepted {malformed:?}");
        }
    }

    #[test]
    fn normalized_manifest_flags_use_source_validation() {
        for malformed in [
            "syscall=0xffff",
            "arch=!win64",
            "fastcall;fastcall",
            "arch=i386",
            "norelay;arch=x86_64",
        ] {
            assert!(
                parse_normalized_flags(malformed, 7).is_err(),
                "accepted {malformed:?}"
            );
        }
        let flags = parse_normalized_flags("arch=x86_64;norelay;syscall=0x000f", 7).unwrap();
        assert!(validate_flags_for_kind(ExportKind::Stdcall, &flags, 7).is_ok());
        assert!(validate_flags_for_kind(ExportKind::Cdecl, &flags, 7).is_err());
    }

    #[test]
    fn category_uses_the_longest_nt_prefix() {
        assert_eq!(category("NtdllDefWindowProc_A"), "Ntdll");
        assert_eq!(category("NtClose"), "Nt");
    }

    #[test]
    fn tracked_manifest_freezes_complete_x86_64_inventory() {
        let rows = parse_manifest(TRACKED_MANIFEST).unwrap();
        assert_eq!(rows.len(), EXPECTED_X64_ROWS);
        assert_eq!(rows.iter().filter(|row| row.wine_extension).count(), 16);
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind == ExportKind::Stub)
                .count(),
            101
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind == ExportKind::Extern)
                .count(),
            7
        );
        assert_eq!(rows.iter().filter(|row| row.alias.is_some()).count(), 282);
        assert_eq!(
            rows.iter()
                .filter(|row| row.kind == ExportKind::Extern && !row.wine_extension)
                .count(),
            4
        );
        for (kind, expected) in EXPECTED_KIND_COUNTS {
            assert_eq!(
                rows.iter().filter(|row| row.kind == *kind).count(),
                *expected
            );
        }
        assert_eq!(
            rows.iter().filter(|row| row.alias.is_some()).count(),
            EXPECTED_HANDLER_ALIASES
        );
        assert_eq!(rows.iter().filter(|row| !row.wine_extension).count(), 1_461);
    }

    #[test]
    fn tracked_manifest_rows_are_cryptographically_bound() {
        let tampered = TRACKED_MANIFEST.replacen("NtClose\tstdcall", "NtClose\tcdecl", 1);
        assert!(parse_manifest(&tampered).is_err());
    }

    #[test]
    fn reconciliation_catalog_covers_and_classifies_the_exact_baseline_gap() {
        let manifest = parse_manifest(TRACKED_MANIFEST).unwrap();
        let rows = parse_reconciliation(&manifest, TRACKED_RECONCILIATION).unwrap();
        assert_eq!(rows.len(), 372);
        assert_eq!(
            rows.iter()
                .filter(|row| row.state == ReconciliationState::Planned)
                .count(),
            366
        );
        assert_eq!(
            rows.iter()
                .filter(|row| row.state == ReconciliationState::BlockedAbi)
                .count(),
            6
        );
        assert_eq!(rows.iter().filter(|row| row.owner == "kernel").count(), 71);
        assert_eq!(rows.iter().filter(|row| row.owner == "alias").count(), 71);
        assert_eq!(
            rows.iter()
                .map(|row| row.group.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            49
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.name == "_vsnprintf_s")
                .map(|row| {
                    (
                        row.abi_authority.as_str(),
                        row.effective_args.as_str(),
                        row.return_class.as_str(),
                    )
                }),
            Some(("source-override", "ptr,usize,usize,str,ptr", "i32"))
        );
        assert_eq!(
            rows.iter().find(|row| row.name == "_fltused").map(|row| {
                (
                    row.owner.as_str(),
                    row.abi_authority.as_str(),
                    row.return_class.as_str(),
                )
            }),
            Some(("ntdll-data", "source-override", "data-i32"))
        );
    }

    #[test]
    fn native_service_and_alias_states_cannot_diverge() {
        let manifest = parse_manifest(TRACKED_MANIFEST).unwrap();
        let tampered = TRACKED_RECONCILIATION.replacen(
            "NtAccessCheckByTypeAndAuditAlarm\tstdcall\tptr,long,ptr,ptr,ptr,ptr,long,long,long,ptr,long,ptr,long,ptr,ptr,ptr\tsyscall=0x0059\t-\tK-security\tkernel\twine-spec\tptr,long,ptr,ptr,ptr,ptr,long,long,long,ptr,long,ptr,long,ptr,ptr,ptr\tntstatus\tplanned",
            "NtAccessCheckByTypeAndAuditAlarm\tstdcall\tptr,long,ptr,ptr,ptr,ptr,long,long,long,ptr,long,ptr,long,ptr,ptr,ptr\tsyscall=0x0059\t-\tK-security\tkernel\twine-spec\tptr,long,ptr,ptr,ptr,ptr,long,long,long,ptr,long,ptr,long,ptr,ptr,ptr\tntstatus\timplemented",
            1,
        );
        assert_ne!(tampered, TRACKED_RECONCILIATION);
        assert!(parse_reconciliation(&manifest, &tampered).is_err());
    }
}
