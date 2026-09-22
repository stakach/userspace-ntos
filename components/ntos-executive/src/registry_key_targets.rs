//! Canonical CM-backed Key targets, shared by bootstrap driver and hosted handle publication.
//!
//! All store borrows are local memory operations. Snapshots are owned; no reference into these
//! vectors may survive a CM exchange, which can re-enter executive dispatch. CM lease cleanup
//! remains owned by cm_key_ownership even after a target's final handle has disappeared.

use super::*;
use nt_process::STATUS_INSUFFICIENT_RESOURCES;

static mut SYSTEM: Vec<Option<CmSystemKeyTarget>> = Vec::new();
#[derive(Clone)]
pub(crate) struct CmRuntimeKeyTarget {
    pub key: u64,
    pub path: alloc::string::String,
}
static mut RUNTIME: Vec<Option<CmRuntimeKeyTarget>> = Vec::new();

pub(crate) fn install_system(target: CmSystemKeyTarget) -> Result<KeyRef, u32> {
    let _durable = allocator::enter_durable();
    unsafe {
        let entries = &mut *core::ptr::addr_of_mut!(SYSTEM);
        if let Some(index) = entries.iter().position(Option::is_none) {
            entries[index] = Some(target);
            return Ok(CM_SYSTEM_KEY_TAG | index as u32);
        }
        if entries.len() >= CM_SYSTEM_KEY_MAX as usize {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        entries
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let index = entries.len();
        entries.push(Some(target));
        Ok(CM_SYSTEM_KEY_TAG | index as u32)
    }
}

pub(crate) fn install_runtime(path: alloc::string::String, key: u64) -> Result<KeyRef, u32> {
    let _durable = allocator::enter_durable();
    unsafe {
        let entries = &mut *core::ptr::addr_of_mut!(RUNTIME);
        if let Some(index) = entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.key == key))
        {
            return Ok(CM_RUNTIME_KEY_TAG | index as u32);
        }
        if let Some(index) = entries.iter().position(Option::is_none) {
            entries[index] = Some(CmRuntimeKeyTarget { key, path });
            return Ok(CM_RUNTIME_KEY_TAG | index as u32);
        }
        if entries.len() >= CM_RUNTIME_KEY_MAX as usize {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        entries
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let index = entries.len();
        entries.push(Some(CmRuntimeKeyTarget { key, path }));
        Ok(CM_RUNTIME_KEY_TAG | index as u32)
    }
}

pub(crate) fn system(target: KeyRef) -> Option<CmSystemKeyTarget> {
    unsafe {
        (&*core::ptr::addr_of!(SYSTEM))
            .get(cm_system_key_idx(target)?)?
            .clone()
    }
}

pub(crate) fn runtime(target: KeyRef) -> Option<CmRuntimeKeyTarget> {
    unsafe {
        (&*core::ptr::addr_of!(RUNTIME))
            .get(cm_runtime_key_idx(target)?)?
            .clone()
    }
}

/// Final target cleanup only; close the canonical PM handle before invoking this function.
/// Removal precedes the CM effect, whose uncertain outcome stays in its existing lease journal.
pub(crate) fn take_unreferenced(
    pm: &nt_process::ProcessManager,
    target: KeyRef,
) -> Option<CmSystemKeyTarget> {
    if pm.handle_object_reference_count(nt_process::HandleObject::RegistryKey(target)) != 0 {
        return None;
    }
    unsafe {
        if let Some(index) = cm_runtime_key_idx(target) {
            if let Some(entry) = (&mut *core::ptr::addr_of_mut!(RUNTIME)).get_mut(index) {
                *entry = None;
            }
            return None;
        }
        cm_system_key_idx(target).and_then(|index| {
            (&mut *core::ptr::addr_of_mut!(SYSTEM))
                .get_mut(index)
                .and_then(Option::take)
        })
    }
}

pub(crate) unsafe fn retire(entry: CmSystemKeyTarget) {
    match crate::config_manager_retire_system_hive_key(entry.lease) {
        Ok(()) => {
            CM_NATIVE_SYSTEM_KEY_LEASE_CLOSES.fetch_add(1, Ordering::Relaxed);
        }
        Err(_) => {
            CM_NATIVE_SYSTEM_KEY_LEASE_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) unsafe fn release(pm: &nt_process::ProcessManager, target: KeyRef) {
    let entry = take_unreferenced(pm, target);
    if let Some(entry) = entry {
        retire(entry);
    }
}
