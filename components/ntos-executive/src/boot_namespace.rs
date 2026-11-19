//! Boot-volume aliases shared by the canonical Object Manager and native query mirror.
//!
//! The canonical drive links (`\??\<drive>`, `\Global??\<drive>`) and `\SystemRoot` are derived
//! by `nt_fs::boot_volume_links` from the registered mounted-volume Device's own name and the
//! validated installation root. They are published only while that exact mount generation is
//! live, read back from the Object Manager, and only then mirrored for native queries.

use alloc::{string::String, vec::Vec};

use crate::*;
use nt_status::NtStatus;

/// The registered Device no longer belongs to the live physical/logical mount pair.
const STATUS_VOLUME_DISMOUNTED: NtStatus = NtStatus(0xC000_026Eu32 as i32);

fn parent_index(entries: &[ObjEntry], name: &[u8]) -> Option<usize> {
    entries.iter().position(|entry| {
        entry.kind == OBJ_KIND_DIRECTORY && entry.parent == 0
            && entry.name().eq_ignore_ascii_case(name)
    })
}

unsafe fn rollback(links: &[nt_fs::VolumeLink], ids: &[u64], count: usize) {
    for (created, id) in links[..count].iter().zip(&ids[..count]).rev() {
        unsafe { object_manager_delete_symbolic_link_exact(&created.path(), *id) }
            .expect("boot alias rollback requires exact ObjectId deletion");
    }
}

/// The exact Device of the live mount pair; a numeric identity from an earlier generation is
/// not authority to name the installed volume.
fn live_registered_volume(device_id: u64) -> Result<(), NtStatus> {
    if mounted_volume::exec_volume_device() == Some(device_id) {
        Ok(())
    } else {
        Err(STATUS_VOLUME_DISMOUNTED)
    }
}

fn registered_volume_name(device_id: u64) -> Result<String, NtStatus> {
    let io = driver_launch::io_manager_mut();
    let record = io.device(nt_io_manager::DeviceId(device_id)).ok_or(STATUS_VOLUME_DISMOUNTED)?;
    if record.delete_pending {
        return Err(STATUS_VOLUME_DISMOUNTED);
    }
    let name = record.name.as_ref().ok_or(NtStatus::OBJECT_NAME_INVALID)?;
    String::from_utf16(name.to_unicode_string().as_units())
        .map_err(|_| NtStatus::OBJECT_NAME_INVALID)
}

/// Publish aliases only for a registered volume and a validated physical installation root.
pub(crate) unsafe fn publish(
    device_id: u64,
    boot_paths: &nt_fs::BootPaths,
) -> Result<(), NtStatus> {
    live_registered_volume(device_id)?;
    let device_path = registered_volume_name(device_id)?;
    let derived = nt_fs::boot_volume_links(&device_path, boot_paths)
        .map_err(|_| NtStatus::OBJECT_NAME_INVALID)?;
    let links = &derived.links;
    let parents = unsafe {
        dispatcher_bootstrap::with_object_namespace(|entries| {
            entries
                .try_reserve(links.len())
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            let mut parents = Vec::new();
            parents.try_reserve(links.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
            if !entries.iter().any(|entry| {
                entry.kind == OBJ_KIND_SYMBOLIC_LINK
                    && entry.parent == 0
                    && entry.name().eq_ignore_ascii_case(b"dosdevices")
                    && entry.target() == b"\\??"
            }) {
                return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
            }
            for link in links {
                if link.target.len() > OBJ_NAME_CAP || link.leaf.len() > OBJ_NAME_CAP {
                    return Err(NtStatus::OBJECT_NAME_INVALID);
                }
                let parent = match link.directory {
                    nt_fs::LinkDirectory::Root => 0,
                    directory => parent_index(entries, directory.name().as_bytes())
                        .ok_or(NtStatus::OBJECT_PATH_NOT_FOUND)?,
                };
                if entries.iter().any(|entry| {
                    entry.is_live()
                        && entry.parent == parent
                        && entry.name().eq_ignore_ascii_case(link.leaf.as_bytes())
                }) {
                    return Err(NtStatus::OBJECT_NAME_COLLISION);
                }
                parents.push(parent);
            }
            Ok(parents)
        })
    }
    .map_err(|status| NtStatus(status as i32))??;

    let mut ids = Vec::new();
    ids.try_reserve(links.len()).map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    for (index, link) in links.iter().enumerate() {
        match unsafe {
            object_manager_create_symbolic_link_path_with_permanence(&link.path(), &link.target, true)
        } {
            Ok(id) => ids.push(id),
            Err(status) => {
                unsafe { rollback(links, &ids, index) };
                return Err(status);
            }
        }
    }
    if let Err(status) = verify(&device_path, &derived) {
        unsafe { rollback(links, &ids, links.len()) };
        return Err(status);
    }
    if let Err(status) = live_registered_volume(device_id) {
        unsafe { rollback(links, &ids, links.len()) };
        return Err(status);
    }

    unsafe {
        dispatcher_bootstrap::with_object_namespace(|entries| {
            for ((link, parent), id) in links.iter().zip(&parents).zip(&ids) {
                let folded_leaf: Vec<u8> =
                    link.leaf.bytes().map(|byte| byte.to_ascii_lowercase()).collect();
                let slot = entries.push_symlink(&folded_leaf, *parent, link.target.as_bytes(), true)
                    .expect("preflighted boot alias mirror capacity");
                entries[slot].payload = *id;
            }
        })
    }
    .expect("bootstrap namespace must remain owned until alias publication");
    for link in links {
        print_str(b"[boot-namespace] published ");
        print_str(link.path().as_bytes());
        print_str(b" -> ");
        print_str(link.target.as_bytes());
        print_str(b"\n");
    }
    Ok(())
}

/// Each canonical link stores exactly its derived target, and every published spelling resolves
/// to the registered Device with the installation root's System32 remainder.
unsafe fn verify(device_path: &str, derived: &nt_fs::BootVolumeLinks) -> Result<(), NtStatus> {
    for link in &derived.links {
        let stored = unsafe { object_manager_query_symbolic_link(&link.path()) }?;
        if !stored.iter().copied().eq(link.target.encode_utf16()) {
            return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
        }
    }
    let expected_device = unsafe { object_manager_lookup_path(device_path) }?;
    let expected_suffix: Vec<u16> = derived.system32_suffix.encode_utf16().collect();
    for probe in &derived.probes {
        let wide: Vec<u16> = probe.encode_utf16().collect();
        let resolved = unsafe { object_manager_resolve_file_target_owned(&wide, true) };
        if !resolved.is_ok_and(|(id, suffix)| id.0 == expected_device && suffix == expected_suffix) {
            return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
        }
    }
    Ok(())
}
