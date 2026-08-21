//! Live kernel-module registry used by `SystemModuleInformation`.
//!
//! The table is populated by actual image load paths. It is intentionally not a name oracle:
//! enumeration reports modules that were registered after a PE was loaded and mapped.

use alloc::vec::Vec;
use nt_syscall::system_information::{SystemModuleEntry, RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE};

static mut SYSTEM_MODULES: Option<Vec<SystemModuleEntry>> = None;
static mut SYSTEM_MODULE_SNAPSHOT_WORK: Option<Vec<SystemModuleEntry>> = None;

unsafe fn system_modules_mut() -> &'static mut Vec<SystemModuleEntry> {
    let slot = &mut *core::ptr::addr_of_mut!(SYSTEM_MODULES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn system_modules() -> Option<&'static Vec<SystemModuleEntry>> {
    (&*core::ptr::addr_of!(SYSTEM_MODULES)).as_ref()
}

unsafe fn system_module_snapshot_work_mut() -> &'static mut Vec<SystemModuleEntry> {
    let slot = &mut *core::ptr::addr_of_mut!(SYSTEM_MODULE_SNAPSHOT_WORK);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

pub(crate) fn register_system_module(path: &[u8], image_base: u64, image_size: u32) -> bool {
    register_system_module_ex(path, image_base, image_base, image_size, 0, 1)
}

pub(crate) fn register_system_module_ex(
    path: &[u8],
    mapped_base: u64,
    image_base: u64,
    image_size: u32,
    flags: u32,
    load_count: u16,
) -> bool {
    if mapped_base == 0 || image_base == 0 || image_size == 0 {
        return false;
    }
    let Some(path_len) = canonical_module_path_len(path) else {
        return false;
    };

    unsafe {
        let modules = system_modules_mut();
        let mut empty = None;
        for index in 0..modules.len() {
            let existing = &modules[index];
            if existing.full_path_name_len == 0 {
                empty.get_or_insert(index);
                continue;
            }
            if canonical_module_path_eq(path, existing.path()) {
                write_system_module_entry(
                    &mut modules[index],
                    path,
                    path_len,
                    mapped_base,
                    image_base,
                    image_size,
                    flags,
                    load_count,
                );
                return true;
            }
        }

        let index = match empty {
            Some(index) => index,
            None => {
                modules.push(SystemModuleEntry::EMPTY);
                modules.len() - 1
            }
        };
        write_system_module_entry(
            &mut modules[index],
            path,
            path_len,
            mapped_base,
            image_base,
            image_size,
            flags,
            load_count,
        );
        true
    }
}

pub(crate) fn system_module_snapshot_scratch() -> (&'static [SystemModuleEntry], usize) {
    unsafe {
        let snapshot = system_module_snapshot_work_mut();
        snapshot.clear();
        if let Some(modules) = system_modules() {
            for module in modules {
                if module.full_path_name_len == 0 {
                    continue;
                }
                let mut entry = *module;
                entry.load_order_index = snapshot.len().min(u16::MAX as usize) as u16;
                snapshot.push(entry);
            }
        }
        let count = snapshot.len();
        (&snapshot[..count], count)
    }
}

fn write_system_module_entry(
    entry: &mut SystemModuleEntry,
    path: &[u8],
    path_len: usize,
    mapped_base: u64,
    image_base: u64,
    image_size: u32,
    flags: u32,
    load_count: u16,
) {
    entry.section = 0;
    entry.mapped_base = mapped_base;
    entry.image_base = image_base;
    entry.image_size = image_size;
    entry.flags = flags;
    entry.load_order_index = 0;
    entry.init_order_index = 0;
    entry.load_count = load_count;
    entry.full_path_name_len = path_len as u16;
    entry.full_path_name.fill(0);
    let written = canonical_module_path(path, &mut entry.full_path_name).unwrap_or(0);
    entry.full_path_name_len = written as u16;
    entry.offset_to_file_name = module_file_name_offset(entry.path());
}

fn canonical_module_path_len(path: &[u8]) -> Option<usize> {
    let (prefix, src) = canonical_module_path_parts(path)?;
    let len = prefix.len().checked_add(src.len())?;
    if len > RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE {
        return None;
    }
    Some(len)
}

fn canonical_module_path_eq(path: &[u8], canonical: &[u8]) -> bool {
    let Some(path_len) = canonical_module_path_len(path) else {
        return false;
    };
    if path_len != canonical.len() {
        return false;
    }
    let Some((prefix, src)) = canonical_module_path_parts(path) else {
        return false;
    };
    let mut index = 0usize;
    for &byte in prefix {
        if canonical[index].to_ascii_lowercase() != byte.to_ascii_lowercase() {
            return false;
        }
        index += 1;
    }
    for &byte in src {
        let normalized = if byte == b'/' { b'\\' } else { byte };
        if canonical[index].to_ascii_lowercase() != normalized.to_ascii_lowercase() {
            return false;
        }
        index += 1;
    }
    true
}

fn canonical_module_path(path: &[u8], out: &mut [u8]) -> Option<usize> {
    let (prefix, src) = canonical_module_path_parts(path)?;
    let mut n = append_bytes(out, 0, prefix)?;

    for &byte in src {
        if n >= out.len() {
            return None;
        }
        out[n] = if byte == b'/' { b'\\' } else { byte };
        n += 1;
    }
    Some(n)
}

fn canonical_module_path_parts(path: &[u8]) -> Option<(&'static [u8], &[u8])> {
    if path.is_empty() {
        return None;
    }

    let system_root = b"\\SystemRoot\\";
    let reactos_prefix = b"reactos";
    if path.len() > reactos_prefix.len()
        && ascii_eq_ignore_case(&path[..reactos_prefix.len()], reactos_prefix)
        && (path[reactos_prefix.len()] == b'\\' || path[reactos_prefix.len()] == b'/')
    {
        return Some((system_root.as_slice(), &path[reactos_prefix.len() + 1..]));
    }
    Some((&[], path))
}

fn append_bytes(out: &mut [u8], mut n: usize, bytes: &[u8]) -> Option<usize> {
    if n + bytes.len() > out.len() {
        return None;
    }
    out[n..n + bytes.len()].copy_from_slice(bytes);
    n += bytes.len();
    Some(n)
}

fn module_file_name_offset(path: &[u8]) -> u16 {
    let mut offset = 0usize;
    for (index, &byte) in path.iter().enumerate() {
        if byte == b'\\' || byte == b'/' {
            offset = index + 1;
        }
    }
    offset.min(u16::MAX as usize) as u16
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for index in 0..a.len() {
        if a[index].to_ascii_lowercase() != b[index].to_ascii_lowercase() {
            return false;
        }
    }
    true
}
