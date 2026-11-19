//! Evidence from the pinned installed image, never from a second export ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use nt_pe_loader::{ImportRef, PeFile, DIRECTORY_ENTRY_EXPORT};

struct Exports {
    by_name: BTreeMap<String, u16>,
    by_ordinal: BTreeMap<u16, BTreeSet<String>>,
}

fn read_u32(pe: &PeFile<'_>, rva: u32) -> Result<u32, String> {
    let bytes = pe
        .bytes_at_rva(rva, 4)
        .ok_or(format!("invalid export RVA {rva:#x}"))?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn read_exports(path: &Path) -> Result<Exports, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pe = PeFile::parse(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
    let names: BTreeMap<String, u16> = pe
        .exports()
        .map_err(|e| format!("{}: {e:?}", path.display()))?
        .into_iter()
        .map(|export| (export.name, export.ordinal))
        .collect();
    let dir = pe.headers().data_directory(DIRECTORY_ENTRY_EXPORT);
    if dir.virtual_address == 0 {
        return Err(format!("{}: missing export directory", path.display()));
    }
    let base = read_u32(&pe, dir.virtual_address + 16)?;
    let count = read_u32(&pe, dir.virtual_address + 20)?;
    let functions = read_u32(&pe, dir.virtual_address + 28)?;
    if count > 65_536 {
        return Err(format!(
            "{}: excessive export count {count}",
            path.display()
        ));
    }
    let mut names_by_ordinal: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for (name, ordinal) in &names {
        names_by_ordinal
            .entry(*ordinal)
            .or_default()
            .insert(name.clone());
    }
    let mut by_ordinal = BTreeMap::new();
    for index in 0..count {
        let ordinal = base
            .checked_add(index)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| format!("{}: export ordinal overflow", path.display()))?;
        let slot = functions
            .checked_add(index * 4)
            .ok_or_else(|| format!("{}: export table overflow", path.display()))?;
        if read_u32(&pe, slot)? != 0 {
            by_ordinal.insert(
                ordinal,
                names_by_ordinal.remove(&ordinal).unwrap_or_default(),
            );
        }
    }
    Ok(Exports {
        by_name: names,
        by_ordinal,
    })
}

fn installed_pe_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(root).map_err(|e| format!("{}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", root.display()))?;
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        if kind.is_dir() {
            installed_pe_files(&entry.path(), files)?;
        } else if kind.is_file()
            && entry.path().extension().is_some_and(|extension| {
                matches!(
                    extension.to_string_lossy().to_ascii_lowercase().as_str(),
                    "exe" | "dll" | "sys"
                )
            })
        {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn is_amd64_pe(bytes: &[u8]) -> bool {
    if bytes.get(0..2) != Some(b"MZ") {
        return false;
    }
    let Some(offset) = bytes.get(0x3c..0x40) else {
        return false;
    };
    let offset = u32::from_le_bytes(offset.try_into().expect("four bytes")) as usize;
    bytes
        .get(offset..offset.saturating_add(6))
        .is_some_and(|header| {
            header.get(0..4) == Some(b"PE\0\0") && header.get(4..6) == Some(&[0x64, 0x86])
        })
}

fn ordinal_consumers(root: &Path) -> Result<BTreeMap<u16, BTreeSet<String>>, String> {
    let mut files = Vec::new();
    installed_pe_files(root, &mut files)?;
    files.sort();
    let mut consumers: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for path in files {
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !is_amd64_pe(&bytes) {
            continue;
        }
        let pe = PeFile::parse(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
        let relative = path.strip_prefix(root).expect("collected below root");
        let consumer = relative.to_string_lossy().replace('\\', "/");
        for imported in pe
            .imports()
            .map_err(|e| format!("{}: {e:?}", path.display()))?
        {
            if imported.name.eq_ignore_ascii_case("ntdll.dll") {
                for function in imported.functions {
                    if let ImportRef::ByOrdinal { ordinal, .. } = function {
                        consumers
                            .entry(ordinal)
                            .or_default()
                            .insert(consumer.clone());
                    }
                }
            }
        }
    }
    Ok(consumers)
}

fn escape_tsv(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn ordinal_target_matches(
    expected: &BTreeMap<u16, BTreeSet<String>>,
    actual: &BTreeMap<u16, BTreeSet<String>>,
    ordinal: u16,
) -> bool {
    match (expected.get(&ordinal), actual.get(&ordinal)) {
        (Some(required), Some(provided)) => required.is_subset(provided),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NameStatus {
    /// The release name is not exported.
    Missing,
    /// The name is exported but its ordinal has no function.
    EmptyEntry,
    OrdinalDiff,
    Ok,
}

impl NameStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::EmptyEntry => "empty_entry",
            Self::OrdinalDiff => "ordinal_diff",
            Self::Ok => "ok",
        }
    }
}

/// Every release export name with the source-built DLL's ordinal for it and its status.
fn name_statuses<'a>(
    expected: &'a Exports,
    actual: &'a Exports,
) -> impl Iterator<Item = (&'a str, u16, Option<u16>, NameStatus)> + 'a {
    expected.by_name.iter().map(|(name, ordinal)| {
        let found = actual.by_name.get(name).copied();
        let status = match found {
            None => NameStatus::Missing,
            Some(found) if !actual.by_ordinal.contains_key(&found) => NameStatus::EmptyEntry,
            Some(found) if found != *ordinal => NameStatus::OrdinalDiff,
            Some(_) => NameStatus::Ok,
        };
        (name.as_str(), *ordinal, found, status)
    })
}

pub fn compare_exports(reference: &Path, built: &Path) -> Result<(), String> {
    let expected = read_exports(reference)?;
    let actual = read_exports(built)?;
    let system32 = reference
        .parent()
        .ok_or("reference DLL has no parent directory")?;
    let consumers = ordinal_consumers(system32)?;

    // Stable TSV is intentionally emitted even on failure, so a failed build retains evidence.
    println!("kind\tconsumer\tsymbol\treference_ordinal\tbuilt_ordinal\tstatus");
    let mut missing_names = 0;
    for (name, ordinal, found, status) in name_statuses(&expected, &actual) {
        if matches!(status, NameStatus::Missing | NameStatus::EmptyEntry) {
            missing_names += 1;
        }
        println!(
            "name\t-\t{}\t{ordinal}\t{}\t{}",
            escape_tsv(name),
            found.map(|ordinal| ordinal.to_string()).unwrap_or_default(),
            status.label()
        );
    }
    let mut bad_ordinals = 0;
    for (ordinal, users) in &consumers {
        if !expected.by_ordinal.contains_key(ordinal) {
            return Err(format!(
                "installed consumer imports absent ntdll ordinal {ordinal}"
            ));
        }
        let found = actual.by_ordinal.get(ordinal);
        let status = if ordinal_target_matches(&expected.by_ordinal, &actual.by_ordinal, *ordinal) {
            "ok"
        } else {
            bad_ordinals += 1;
            if found.is_none() {
                "missing"
            } else {
                "wrong_target"
            }
        };
        for user in users {
            println!(
                "ordinal\t{}\t#{ordinal}\t{ordinal}\t{}\t{status}",
                escape_tsv(user),
                found.map(|_| ordinal.to_string()).unwrap_or_default()
            );
        }
    }
    eprintln!("LiberNT ntdll: {} required names, {} built names, {} missing names, {} ordinal imports, {} bad ordinal targets", expected.by_name.len(), actual.by_name.len(), missing_names, consumers.values().map(BTreeSet::len).sum::<usize>(), bad_ordinals);
    if missing_names != 0 || bad_ordinals != 0 {
        Err("source-built ntdll does not satisfy installed LiberNT imports".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exports(entries: &[(&str, u16)]) -> Exports {
        let mut by_name = BTreeMap::new();
        let mut by_ordinal: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
        for (name, ordinal) in entries {
            by_name.insert(name.to_string(), *ordinal);
            by_ordinal.entry(*ordinal).or_default().insert(name.to_string());
        }
        Exports { by_name, by_ordinal }
    }

    #[test]
    fn a_release_export_absent_from_the_built_dll_fails_the_gate() {
        let release = exports(&[("LdrLoadDll", 1), ("RtlGetVersion", 2), ("NtClose", 3)]);
        let built = exports(&[("NtClose", 7), ("LdrLoadDll", 1), ("RtlExtra", 9)]);
        let statuses: Vec<_> = name_statuses(&release, &built)
            .map(|(name, _, _, status)| (name, status))
            .collect();
        assert_eq!(
            statuses,
            [
                ("LdrLoadDll", NameStatus::Ok),
                ("NtClose", NameStatus::OrdinalDiff),
                ("RtlGetVersion", NameStatus::Missing),
            ]
        );
    }

    #[test]
    fn a_name_without_a_function_counts_as_missing() {
        let release = exports(&[("NtClose", 3)]);
        let mut built = exports(&[("NtClose", 3)]);
        built.by_ordinal.clear();
        let (_, _, found, status) = name_statuses(&release, &built).next().unwrap();
        assert_eq!((found, status), (Some(3), NameStatus::EmptyEntry));
    }
}
