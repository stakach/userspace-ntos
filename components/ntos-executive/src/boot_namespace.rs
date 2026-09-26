//! Boot-volume aliases shared by the canonical Object Manager and native query mirror.

use alloc::{format, string::String};

use crate::*;

struct Alias {
    path: String,
    target: String,
    parent: &'static [u8],
}

fn parent_index(entries: &[ObjEntry], name: &[u8]) -> Option<usize> {
    entries.iter().position(|entry| {
        entry.kind == OBJ_KIND_DIRECTORY && entry.parent == 0 && entry.name() == name
    })
}

fn leaf(alias: &Alias) -> &[u8] {
    alias.path.rsplit('\\').next().unwrap_or("").as_bytes()
}

unsafe fn rollback(aliases: &[Alias; 3], ids: &[u64; 3], count: usize) {
    for (created, id) in aliases[..count].iter().zip(&ids[..count]).rev() {
        unsafe { object_manager_delete_symbolic_link_exact(&created.path, *id) }
            .expect("boot alias rollback requires exact ObjectId deletion");
    }
}

/// Publish aliases only for a registered volume and a validated physical installation root.
pub(crate) unsafe fn publish(
    device_path: &str,
    boot_paths: &nt_fs::BootPaths,
) -> Result<(), nt_status::NtStatus> {
    let drive = core::str::from_utf8(boot_paths.drive())
        .map_err(|_| nt_status::NtStatus::OBJECT_NAME_INVALID)?;
    let system_root_suffix = core::str::from_utf8(&boot_paths.system_root()[2..])
        .map_err(|_| nt_status::NtStatus::OBJECT_NAME_INVALID)?;
    let aliases = [
        Alias {
            path: format!("\\??\\{drive}"),
            target: String::from(device_path),
            parent: b"??",
        },
        Alias {
            path: format!("\\DosDevices\\{drive}"),
            target: String::from(device_path),
            parent: b"dosdevices",
        },
        Alias {
            path: String::from("\\SystemRoot"),
            target: format!("{device_path}{system_root_suffix}"),
            parent: b"",
        },
    ];
    let parents = unsafe {
        dispatcher_bootstrap::with_object_namespace(|entries| {
            entries
                .try_reserve(aliases.len())
                .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
            let mut parents = [0usize; 3];
            for (index, alias) in aliases.iter().enumerate() {
                if alias.target.len() > OBJ_NAME_CAP || leaf(alias).len() > OBJ_NAME_CAP {
                    return Err(nt_status::NtStatus::OBJECT_NAME_INVALID);
                }
                let parent = if alias.parent.is_empty() {
                    0
                } else {
                    parent_index(entries, alias.parent)
                        .ok_or(nt_status::NtStatus::OBJECT_PATH_NOT_FOUND)?
                };
                if entries.iter().any(|entry| {
                    entry.is_live()
                        && entry.parent == parent
                        && entry.name().eq_ignore_ascii_case(leaf(alias))
                }) {
                    return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
                }
                parents[index] = parent;
            }
            Ok(parents)
        })
    }
    .map_err(|status| nt_status::NtStatus(status as i32))??;

    let mut ids = [0u64; 3];
    for (index, alias) in aliases.iter().enumerate() {
        match unsafe {
            object_manager_create_symbolic_link_path_with_permanence(
                &alias.path,
                &alias.target,
                true,
            )
        } {
            Ok(id) => ids[index] = id,
            Err(status) => {
                unsafe { rollback(&aliases, &ids, index) };
                return Err(status);
            }
        }
    }

    let expected_device = match unsafe { object_manager_lookup_path(device_path) } {
        Ok(id) => id,
        Err(status) => {
            unsafe { rollback(&aliases, &ids, aliases.len()) };
            return Err(status);
        }
    };
    let expected_suffix: alloc::vec::Vec<u16> =
        format!("{system_root_suffix}\\System32").encode_utf16().collect();
    for alias in &aliases {
        let path = if alias.parent.is_empty() {
            format!("{}\\System32", alias.path)
        } else {
            format!("{}{}\\System32", alias.path, system_root_suffix)
        };
        let wide: alloc::vec::Vec<u16> = path.encode_utf16().collect();
        let resolved = unsafe { object_manager_resolve_file_target_owned(&wide, true) };
        if !resolved.is_ok_and(|(id, suffix)| {
            id.0 == expected_device && suffix == expected_suffix
        }) {
            unsafe { rollback(&aliases, &ids, aliases.len()) };
            return Err(nt_status::NtStatus::OBJECT_PATH_NOT_FOUND);
        }
    }

    unsafe {
        dispatcher_bootstrap::with_object_namespace(|entries| {
            for (index, alias) in aliases.iter().enumerate() {
                let folded_leaf: alloc::vec::Vec<u8> =
                    leaf(alias).iter().map(u8::to_ascii_lowercase).collect();
                let slot = ObjEntry::push_symlink(
                    entries,
                    &folded_leaf,
                    parents[index],
                    alias.target.as_bytes(),
                    true,
                )
                .expect("preflighted boot alias mirror capacity");
                entries[slot].payload = ids[index];
            }
        })
    }
    .expect("bootstrap namespace must remain owned until alias publication");
    Ok(())
}
