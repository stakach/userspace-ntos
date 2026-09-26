//! Identify an installed OS tree from checked, complete FAT directory snapshots.

use alloc::vec::Vec;

use crate::{FatDirectoryRecord, FatDirectoryWalkEnd, FILE_ATTRIBUTE_DIRECTORY};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledRoot {
    /// The physical directory name, retained for namespace-link targets.
    pub name: Vec<u16>,
    pub first_cluster: u32,
}

pub struct FatDirectorySnapshot {
    pub entries: Vec<FatDirectoryRecord>,
    pub end: FatDirectoryWalkEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstalledRootError {
    Read(u32),
    Incomplete,
    Missing,
    Ambiguous,
    Corrupt,
}

fn snapshot(
    cluster: u32,
    read_directory: &mut impl FnMut(u32) -> Result<FatDirectorySnapshot, u32>,
) -> Result<Vec<FatDirectoryRecord>, InstalledRootError> {
    if cluster < 2 {
        return Err(InstalledRootError::Corrupt);
    }
    let result = read_directory(cluster).map_err(InstalledRootError::Read)?;
    if result.end != FatDirectoryWalkEnd::Complete {
        return Err(InstalledRootError::Incomplete);
    }
    Ok(result.entries)
}

fn names_equal(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(&a, &b)| {
            if a <= 0x7f && b <= 0x7f {
                (a as u8).eq_ignore_ascii_case(&(b as u8))
            } else {
                a == b
            }
        })
}

fn witness<'a>(
    entries: &'a [FatDirectoryRecord],
    name: &[u8],
) -> Result<Option<&'a FatDirectoryRecord>, InstalledRootError> {
    let mut found = None;
    for entry in entries {
        if entry.entry.name().len() == name.len()
            && entry
                .entry
                .name()
                .iter()
                .zip(name)
                .all(|(&unit, &byte)| unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(&byte))
        {
            if found.replace(entry).is_some() {
                return Err(InstalledRootError::Ambiguous);
            }
        }
    }
    Ok(found)
}

fn is_directory(entry: &FatDirectoryRecord) -> bool {
    entry.entry.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

fn is_nonempty_file(entry: &FatDirectoryRecord) -> bool {
    !is_directory(entry) && entry.entry.end_of_file != 0
}

/// Find a unique top-level installation directory by on-disk witnesses, not its name.
/// `read_directory` must report the checked walk end, including visitor stops.
pub fn discover_installed_root(
    root_cluster: u32,
    mut read_directory: impl FnMut(u32) -> Result<FatDirectorySnapshot, u32>,
) -> Result<InstalledRoot, InstalledRootError> {
    let top = snapshot(root_cluster, &mut read_directory)?;
    let mut installed = None;
    for (index, candidate) in top.iter().enumerate() {
        if !is_directory(candidate)
            || candidate.entry.name() == [b'.' as u16]
            || candidate.entry.name() == [b'.' as u16, b'.' as u16]
        {
            continue;
        }
        if top[..index].iter().any(|other| {
            is_directory(other) && names_equal(other.entry.name(), candidate.entry.name())
        }) {
            return Err(InstalledRootError::Ambiguous);
        }
        let root_entries = snapshot(candidate.first_cluster, &mut read_directory)?;
        let Some(system32) = witness(&root_entries, b"System32")? else {
            continue;
        };
        let Some(explorer) = witness(&root_entries, b"explorer.exe")? else {
            continue;
        };
        if !is_directory(system32) || !is_nonempty_file(explorer) {
            continue;
        }
        let system32_entries = snapshot(system32.first_cluster, &mut read_directory)?;
        let Some(smss) = witness(&system32_entries, b"smss.exe")? else {
            continue;
        };
        let Some(ntdll) = witness(&system32_entries, b"ntdll.dll")? else {
            continue;
        };
        let Some(config) = witness(&system32_entries, b"Config")? else {
            continue;
        };
        if !is_nonempty_file(smss) || !is_nonempty_file(ntdll) || !is_directory(config) {
            continue;
        }
        let config_entries = snapshot(config.first_cluster, &mut read_directory)?;
        if !witness(&config_entries, b"SYSTEM")?.is_some_and(is_nonempty_file) {
            continue;
        }
        if installed.is_some() {
            return Err(InstalledRootError::Ambiguous);
        }
        // Current bootstrap path consumers accept ASCII volume-relative names only.
        if candidate.entry.name().is_empty()
            || candidate.entry.name().iter().any(|unit| {
                *unit == 0
                    || *unit > 0x7f
                    || *unit == b'\\' as u16
                    || *unit == b'/' as u16
                    || *unit == b':' as u16
            })
        {
            return Err(InstalledRootError::Corrupt);
        }
        installed = Some(InstalledRoot {
            name: candidate.entry.name().to_vec(),
            first_cluster: candidate.first_cluster,
        });
    }
    installed.ok_or(InstalledRootError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DirectoryEntry;
    use alloc::vec;

    fn record(name: &str, cluster: u32, directory: bool, size: u64) -> FatDirectoryRecord {
        let mut entry = DirectoryEntry::default();
        assert!(entry.set_name(&name.encode_utf16().collect::<Vec<_>>()));
        entry.attributes = if directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            0x20
        };
        entry.end_of_file = size;
        FatDirectoryRecord {
            entry,
            first_cluster: cluster,
        }
    }

    fn disk(cluster: u32) -> Result<FatDirectorySnapshot, u32> {
        let entries = match cluster {
            2 => vec![
                record("Profiles", 3, true, 0),
                record("OS-Tree", 4, true, 0),
            ],
            3 => vec![record("readme.txt", 0, false, 4)],
            4 => vec![
                record("explorer.exe", 0, false, 42),
                record("System32", 5, true, 0),
            ],
            5 => vec![
                record("ntdll.dll", 0, false, 123),
                record("smss.exe", 0, false, 45),
                record("Config", 6, true, 0),
            ],
            6 => vec![record("SYSTEM", 0, false, 789)],
            _ => return Err(0xc000_00a3),
        };
        Ok(FatDirectorySnapshot {
            entries,
            end: FatDirectoryWalkEnd::Complete,
        })
    }

    #[test]
    fn discovers_physical_root_without_a_literal_directory_name() {
        assert_eq!(
            discover_installed_root(2, disk),
            Ok(InstalledRoot {
                name: "OS-Tree".encode_utf16().collect(),
                first_cluster: 4
            })
        );
    }

    #[test]
    fn missing_or_empty_witness_cannot_select_a_root() {
        let missing = discover_installed_root(2, |cluster| {
            let mut result = disk(cluster)?;
            if cluster == 5 {
                result.entries.retain(|entry| {
                    entry.entry.name() != "smss.exe".encode_utf16().collect::<Vec<_>>()
                });
            }
            Ok(result)
        });
        assert_eq!(missing, Err(InstalledRootError::Missing));
        let empty = discover_installed_root(2, |cluster| {
            let mut result = disk(cluster)?;
            if cluster == 6 {
                result.entries[0].entry.end_of_file = 0;
            }
            Ok(result)
        });
        assert_eq!(empty, Err(InstalledRootError::Missing));
    }

    #[test]
    fn incomplete_and_failed_walks_are_not_silent_absence() {
        assert_eq!(
            discover_installed_root(2, |cluster| {
                let mut result = disk(cluster)?;
                if cluster == 5 {
                    result.end = FatDirectoryWalkEnd::VisitorStopped;
                }
                Ok(result)
            }),
            Err(InstalledRootError::Incomplete)
        );
        assert_eq!(
            discover_installed_root(2, |cluster| if cluster == 3 {
                Err(0xc000_00a3)
            } else {
                disk(cluster)
            }),
            Err(InstalledRootError::Read(0xc000_00a3))
        );
    }

    #[test]
    fn duplicate_witness_or_installation_root_is_ambiguous() {
        assert_eq!(
            discover_installed_root(2, |cluster| {
                let mut result = disk(cluster)?;
                if cluster == 5 {
                    result.entries.push(record("NTDLL.DLL", 0, false, 123));
                }
                Ok(result)
            }),
            Err(InstalledRootError::Ambiguous)
        );
        assert_eq!(
            discover_installed_root(2, |cluster| {
                let mut result = if cluster == 7 {
                    disk(4)?
                } else {
                    disk(cluster)?
                };
                if cluster == 2 {
                    result.entries.push(record("Other-OS", 7, true, 0));
                }
                Ok(result)
            }),
            Err(InstalledRootError::Ambiguous)
        );
    }

    #[test]
    fn duplicate_top_level_name_and_invalid_root_name_fail_closed() {
        assert_eq!(
            discover_installed_root(2, |cluster| {
                let mut result = disk(cluster)?;
                if cluster == 2 {
                    result.entries.push(record("os-tree", 7, true, 0));
                }
                Ok(result)
            }),
            Err(InstalledRootError::Ambiguous)
        );
        assert_eq!(
            discover_installed_root(2, |cluster| {
                let mut result = disk(cluster)?;
                if cluster == 2 {
                    result.entries[1].entry.set_name(&['é' as u16]);
                }
                Ok(result)
            }),
            Err(InstalledRootError::Corrupt)
        );
    }
}
