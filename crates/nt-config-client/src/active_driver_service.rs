//! One atomic CM-owned active-service path resolution and binding snapshot, with no key leases.

use super::*;
use nt_config_abi::{CmActiveDriverServiceRequest, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES,
    CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_MAGIC, CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_VERSION};

impl<B: Backend> ConfigClient<B> {
    /// Resolve a genuine mounted-hive immediate child of the active Services key. CM derives the
    /// binding and physical path from the same mounted-hive snapshot, without acquiring key leases.
    pub fn query_active_driver_service_by_registry_path(&mut self, path: &str) -> Result<ActiveDriverServiceBinding, i32> {
        let units = path.encode_utf16().count();
        if units == 0 || units > CM_MAX_HIVE_PATH_UNITS || path.contains('\0') { return Err(STATUS_INVALID_PARAMETER); }
        let header_len = core::mem::size_of::<CmActiveDriverServiceRequest>();
        let mut request = Vec::new();
        request.try_reserve_exact(header_len + units * 2).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        request.resize(header_len, 0);
        for unit in path.encode_utf16() { request.extend_from_slice(&unit.to_le_bytes()); }
        let mut bytes = Vec::new();
        let mut total = None;
        let mut token = 0;
        let mut bank = [0; CM_DRIVER_SERVICE_CHUNK_BYTES];
        loop {
            let offset = u32::try_from(bytes.len()).map_err(|_| STATUS_INVALID_PARAMETER)?;
            let response = self.active_driver_service_call(&mut request,
                if token == 0 { driver_service_transfer::BEGIN } else { driver_service_transfer::PULL },
                token, offset, CM_DRIVER_SERVICE_CHUNK_BYTES as u32, &mut bank);
            let cleanup_token = if token == 0 { response.detail1 } else { token };
            if response.status != STATUS_SUCCESS {
                self.abort_active_driver_service(&mut request, cleanup_token);
                return Err(response.status);
            }
            let required = usize::try_from(response.detail0).ok();
            let written = response.information as usize;
            let valid = required.is_some_and(|required| {
                required >= CM_ACTIVE_DRIVER_SERVICE_SNAPSHOT_HEADER_BYTES
                    && required <= u32::MAX as usize
                    && total.is_none_or(|expected| expected == required)
                    && written <= bank.len() && written != 0
                    && bytes.len().checked_add(written).is_some_and(|end| end <= required)
                    && if token == 0 {
                        (written == required && response.detail1 == 0)
                            || (written < required && response.detail1 != 0)
                    } else { response.detail1 == token }
            });
            if !valid {
                self.abort_active_driver_service(&mut request, cleanup_token);
                return Err(STATUS_INVALID_PARAMETER);
            }
            let required = required.unwrap();
            if total.is_none() {
                if bytes.try_reserve_exact(required).is_err() {
                    self.abort_active_driver_service(&mut request, cleanup_token);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                total = Some(required);
            }
            bytes.extend_from_slice(&bank[..written]);
            if bytes.len() == required { return decode(&bytes); }
            token = response.detail1;
        }
    }

    fn active_driver_service_call(&mut self, request: &mut [u8], operation: u16, token: u64,
        offset: u32, capacity: u32, bank: &mut [u8]) -> CmReply
    {
        let size = core::mem::size_of::<CmActiveDriverServiceRequest>();
        let header = CmActiveDriverServiceRequest {
            abi_size: size as u16, abi_version: CM_ABI_VERSION, operation, _reserved: 0,
            value_offset: offset, chunk_capacity: capacity, path_offset: size as u32,
            path_len_bytes: (request.len() - size) as u32, transfer_token: token,
        };
        request[..size].copy_from_slice(header.as_bytes());
        self.backend.call(opcode::CM_OP_QUERY_ACTIVE_DRIVER_SERVICE, request, bank)
    }

    fn abort_active_driver_service(&mut self, request: &mut [u8], token: u64) {
        if token != 0 {
            let _ = self.active_driver_service_call(request, driver_service_transfer::ABORT, token, 0, 0, &mut []);
        }
    }
}

fn decode(bytes: &[u8]) -> Result<ActiveDriverServiceBinding, i32> {
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
mod tests;
