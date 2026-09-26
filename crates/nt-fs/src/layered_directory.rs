//! Deterministic directory view over immutable installed and writable overlay entries.

use alloc::vec::Vec;

use crate::{directory::fold, DirectoryEntry, STATUS_DATA_ERROR, STATUS_INSUFFICIENT_RESOURCES};

fn same_name(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| fold(*left) == fold(*right))
}

fn aliases_overlap(left: &DirectoryEntry, right: &DirectoryEntry) -> bool {
    [left.name(), left.short_name()]
        .into_iter()
        .filter(|name| !name.is_empty())
        .any(|left_name| {
            [right.name(), right.short_name()]
                .into_iter()
                .filter(|name| !name.is_empty())
                .any(|right_name| same_name(left_name, right_name))
        })
}

fn is_dot(entry: &DirectoryEntry) -> bool {
    matches!(entry.name(), [46] | [46, 46])
}

fn is_self_dot(entry: &DirectoryEntry) -> bool {
    entry.name() == [46]
}

/// Keep FAT stream order, replace shadowed entries in place, then append overlay-only children.
/// Multiple installed aliases resolving to one overlay entry are corrupt rather than a partial
/// union: callers must not publish an ambiguous namespace as a successful directory query.
pub fn merge_layered_directory_entries(
    installed: &[DirectoryEntry],
    overlay: &[DirectoryEntry],
) -> Result<Vec<DirectoryEntry>, u32> {
    let capacity = installed
        .len()
        .checked_add(overlay.len())
        .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut merged = Vec::new();
    merged
        .try_reserve_exact(capacity)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    merged.extend_from_slice(installed);
    for entry in overlay {
        if is_dot(entry) {
            if !merged
                .iter()
                .any(|existing| same_name(existing.name(), entry.name()))
            {
                let index = if is_self_dot(entry) {
                    0
                } else if merged.first().is_some_and(is_self_dot) {
                    1
                } else {
                    0
                };
                merged.insert(index, *entry);
            }
            continue;
        }
        let mut shadow = None;
        for (index, existing) in merged.iter().enumerate() {
            if aliases_overlap(existing, entry) {
                if shadow.is_some() {
                    return Err(STATUS_DATA_ERROR);
                }
                shadow = Some(index);
            }
        }
        if let Some(index) = shadow {
            merged[index] = *entry;
        } else {
            merged.push(*entry);
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, short: &str, file_id: u64) -> DirectoryEntry {
        let mut entry = DirectoryEntry {
            file_id,
            ..DirectoryEntry::default()
        };
        assert!(entry.set_name(&name.encode_utf16().collect::<Vec<_>>()));
        assert!(entry.set_short_name(&short.encode_utf16().collect::<Vec<_>>()));
        entry
    }

    fn names(entries: &[DirectoryEntry]) -> Vec<Vec<u16>> {
        entries.iter().map(|entry| entry.name().to_vec()).collect()
    }

    #[test]
    fn shadowing_keeps_installed_order_and_appends_overlay_only_children() {
        let installed = [
            entry(".", "", 1),
            entry("..", "", 2),
            entry("A.TXT", "", 3),
            entry("C.TXT", "", 4),
        ];
        let overlay = [
            entry(".", "", 10),
            entry("..", "", 20),
            entry("a.txt", "", 30),
            entry("B.TXT", "", 40),
        ];
        let merged = merge_layered_directory_entries(&installed, &overlay).unwrap();
        assert_eq!(
            names(&merged),
            [".", "..", "a.txt", "C.TXT", "B.TXT"]
                .map(|name| name.encode_utf16().collect::<Vec<_>>())
        );
        assert_eq!(
            merged.iter().map(|entry| entry.file_id).collect::<Vec<_>>(),
            [1, 2, 30, 4, 40]
        );
    }

    #[test]
    fn physical_short_alias_is_shadowed_by_overlay_long_name() {
        let installed = [entry("Long File Name.txt", "LONGFI~1.TXT", 7)];
        let overlay = [entry("longfi~1.txt", "", 9)];
        let merged = merge_layered_directory_entries(&installed, &overlay).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].file_id, 9);
    }

    #[test]
    fn ambiguous_aliases_do_not_publish_a_partial_union() {
        let installed = [
            entry("Long File Name.txt", "LONGFI~1.TXT", 7),
            entry("LONGFI~1.TXT", "", 8),
        ];
        let overlay = [entry("longfi~1.txt", "", 9)];
        assert_eq!(
            merge_layered_directory_entries(&installed, &overlay),
            Err(STATUS_DATA_ERROR)
        );
    }

    #[test]
    fn overlay_supplies_dot_entries_when_installed_stream_has_none() {
        let installed = [entry("FIRST", "", 1)];
        let overlay = [entry(".", "", 2), entry("..", "", 3)];
        let merged = merge_layered_directory_entries(&installed, &overlay).unwrap();
        assert_eq!(
            merged.iter().map(|entry| entry.file_id).collect::<Vec<_>>(),
            [2, 3, 1]
        );
    }
}
