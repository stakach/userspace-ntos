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
    alias: Option<String>,
    wine_extension: bool,
}

fn parse_manifest(manifest: &str) -> Result<Vec<ManifestRow>, String> {
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
    let bytes = std::fs::read(path)
        .map_err(|error| format!("cannot read ntdll DLL {}: {error}", path.display()))?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("cannot parse ntdll DLL: {error:?}"))?;
    let exports = pe
        .exports()
        .map_err(|error| format!("cannot parse ntdll exports: {error:?}"))?;
    let exported: BTreeSet<_> = exports.iter().map(|export| export.name.as_str()).collect();
    let windows: Vec<_> = rows.iter().filter(|row| !row.wine_extension).collect();
    let missing: Vec<_> = windows
        .iter()
        .copied()
        .filter(|row| !exported.contains(row.name.as_str()))
        .collect();
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
}
