//! Live kernel-module registry used by `SystemModuleInformation`.
//!
//! The table is populated by actual image load paths. It is intentionally not a name oracle:
//! enumeration reports modules that were registered after a PE was loaded and mapped.

use nt_syscall::system_information::{SystemModuleEntry, RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE};

pub(crate) const SYSTEM_MODULE_REGISTRY_CAP: usize = 64;

static mut SYSTEM_MODULES: [SystemModuleEntry; SYSTEM_MODULE_REGISTRY_CAP] =
    [SystemModuleEntry::EMPTY; SYSTEM_MODULE_REGISTRY_CAP];

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
    let mut canonical = [0u8; RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE];
    let Some(path_len) = canonical_module_path(path, &mut canonical) else {
        return false;
    };
    let Some(entry) = SystemModuleEntry::new(
        &canonical[..path_len],
        mapped_base,
        image_base,
        image_size,
        flags,
        0,
        0,
        load_count,
    ) else {
        return false;
    };

    unsafe {
        let modules = &mut *core::ptr::addr_of_mut!(SYSTEM_MODULES);
        let mut empty = None;
        for (index, existing) in modules.iter().enumerate() {
            if existing.full_path_name_len == 0 {
                empty.get_or_insert(index);
                continue;
            }
            if ascii_eq_ignore_case(existing.path(), entry.path()) {
                modules[index] = entry;
                return true;
            }
        }

        let Some(index) = empty else {
            return false;
        };
        modules[index] = entry;
        true
    }
}

pub(crate) fn snapshot_system_modules(out: &mut [SystemModuleEntry]) -> usize {
    let modules = unsafe { &*core::ptr::addr_of!(SYSTEM_MODULES) };
    let mut count = 0usize;
    for module in modules {
        if module.full_path_name_len == 0 {
            continue;
        }
        if count >= out.len() {
            break;
        }
        let mut entry = *module;
        entry.load_order_index = count.min(u16::MAX as usize) as u16;
        out[count] = entry;
        count += 1;
    }
    count
}

fn canonical_module_path(path: &[u8], out: &mut [u8]) -> Option<usize> {
    if path.is_empty() {
        return None;
    }

    let system_root = b"\\SystemRoot\\";
    let reactos_prefix = b"reactos";
    let mut n = 0usize;
    let mut src = path;
    if path.len() > reactos_prefix.len()
        && ascii_eq_ignore_case(&path[..reactos_prefix.len()], reactos_prefix)
        && (path[reactos_prefix.len()] == b'\\' || path[reactos_prefix.len()] == b'/')
    {
        n = append_bytes(out, n, system_root)?;
        src = &path[reactos_prefix.len() + 1..];
    }

    for &byte in src {
        if n >= out.len() {
            return None;
        }
        out[n] = if byte == b'/' { b'\\' } else { byte };
        n += 1;
    }
    Some(n)
}

fn append_bytes(out: &mut [u8], mut n: usize, bytes: &[u8]) -> Option<usize> {
    if n + bytes.len() > out.len() {
        return None;
    }
    out[n..n + bytes.len()].copy_from_slice(bytes);
    n += bytes.len();
    Some(n)
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
