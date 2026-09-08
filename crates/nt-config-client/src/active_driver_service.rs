//! One atomic CM-owned active-service path resolution and binding snapshot, with no key leases.

use super::*;
use nt_config_abi::{CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES,
    CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION};

pub(super) fn decode(bytes: &[u8]) -> Result<ActiveDriverServiceBinding, i32> {
    let invalid = STATUS_INVALID_PARAMETER;
    if bytes.len() < CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES { return Err(invalid); }
    let mut reader = SnapshotReader::new(bytes);
    if reader.u32() != Some(CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC)
        || reader.u16() != Some(CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION)
        || reader.u16() != Some(CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES as u16)
    { return Err(invalid); }
    let generation = reader.u64().ok_or(invalid)?;
    let path_len = reader.u32().ok_or(invalid)? as usize;
    let binding_len = reader.u32().ok_or(invalid)? as usize;
    if reader.u64() != Some(0) || generation == 0 || path_len == 0 || path_len > CM_MAX_HIVE_PATH_UNITS * 4
        || binding_len < CM_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES
        || CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES.checked_add(path_len).and_then(|end| end.checked_add(binding_len)) != Some(bytes.len())
    { return Err(invalid); }
    let path_end = CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES + path_len;
    let path = core::str::from_utf8(&bytes[CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES..path_end]).map_err(|_| invalid)?;
    if path.contains('\0') { return Err(invalid); }
    let binding = decode_driver_service_binding(&bytes[path_end..]).ok_or(invalid)?;
    if physical_service_leaf(path).is_none_or(|leaf| !leaf.eq_ignore_ascii_case(&binding.service_name)) {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let mut physical_path = String::new();
    physical_path.try_reserve_exact(path_len).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    physical_path.push_str(path);
    Ok(ActiveDriverServiceBinding { mount_generation: generation, physical_path, binding })
}

fn physical_service_leaf(path: &str) -> Option<&str> {
    let mut parts = path.strip_prefix('\\')?.split('\\');
    for expected in ["Registry", "Machine", "System"] {
        if !parts.next()?.eq_ignore_ascii_case(expected) { return None; }
    }
    if parts.next()?.is_empty() || !parts.next()?.eq_ignore_ascii_case("Services") { return None; }
    let leaf = parts.next()?;
    (!leaf.is_empty() && parts.next().is_none()).then_some(leaf)
}

#[cfg(test)]
pub(crate) mod tests;
