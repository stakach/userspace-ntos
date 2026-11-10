//! One root-owned debug-filter frame mapped read-only into an exact hosted process.
//! The process VSpace owner records the destination cap before copy or map effects.

use crate::*;
use crate::img_spawn::DebugFilterAliasCopy;

const USER_VA: u64 = nt_ntdll_layout::debug_filter::HOSTED_USER_VA;
const PAGE_SIZE: u64 = nt_ntdll_layout::debug_filter::PAGE_SIZE as u64;
const _: () = assert!(USER_VA >= HOSTED_CLIENT_ENV_BASE
    && USER_VA + PAGE_SIZE <= HOSTED_CLIENT_ENV_BASE + 0x20_0000);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UserAliasError {
    pub(crate) status: u32,
    /// An entered native effect or structural conflict has no safe replay path.
    pub(crate) retained_uncertain: bool,
}

impl UserAliasError {
    fn retryable(status: u32) -> Self { Self { status, retained_uncertain: false } }
    fn retained(status: u32) -> Self { Self { status, retained_uncertain: true } }
}

/// Install the alias before the suspended process's first thread is started.
/// A retry reuses a copied cap only after the previous map returned a known error.
///
/// # Safety
/// Runs in the serialized executive context with the exact process VSpace published.
pub(crate) unsafe fn install_hosted_user_alias(
    handler: &mut ExecNtHandler,
    pi: usize,
) -> Result<(), UserAliasError> {
    let process = handler.capture_process_identity(pi)
        .ok_or_else(|| UserAliasError::retryable(nt_process::STATUS_INVALID_HANDLE))?;
    let frame = unsafe { crate::debug_filter_shared::frame() }
        .map_err(|status| {
            if crate::debug_filter_shared::root_init_uncertain() {
                UserAliasError::retained(status.raw() as u32)
            } else {
                UserAliasError::retryable(status.raw() as u32)
            }
        })?;
    let mut update = handler.process_vspace_caps.begin_update(pi, process)
        .map_err(UserAliasError::retryable)?
        .ok_or_else(|| UserAliasError::retryable(nt_process::STATUS_INVALID_HANDLE))?;
    let caps = update.caps_mut();
    if caps.generation == 0 || caps.pml4 == 0 {
        return Err(UserAliasError::retained(nt_process::STATUS_INVALID_HANDLE));
    }
    let alias = &mut caps.debug_filter;
    if !alias.vm_registered {
        let registration_status = unsafe { process_committed_mapping_register_status(
            pi as u64,
            nt_address_space::VmCommittedRange::mapped(
                USER_VA, PAGE_SIZE, nt_address_space::PAGE_READONLY),
        ) };
        if registration_status != 0 {
            return Err(match nt_hosted_runtime::classify_alias_registration_status(registration_status) {
                nt_hosted_runtime::AliasRetryDisposition::Retry =>
                    UserAliasError::retryable(registration_status),
                nt_hosted_runtime::AliasRetryDisposition::Retain =>
                    UserAliasError::retained(registration_status),
            });
        }
        alias.vm_registered = true;
    }
    if alias.mapped {
        return if alias.cap != 0 && alias.copy == DebugFilterAliasCopy::Present {
            Ok(())
        } else {
            Err(UserAliasError::retained(nt_process::STATUS_INVALID_HANDLE))
        };
    }
    if alias.map_entered || alias.copy == DebugFilterAliasCopy::Entered {
        return Err(UserAliasError::retained(nt_process::STATUS_DEVICE_BUSY));
    }
    if alias.copy == DebugFilterAliasCopy::Vacant {
        if alias.cap != 0 { return Err(UserAliasError::retained(nt_process::STATUS_INVALID_HANDLE)); }
        let cap = try_alloc_slot()
            .ok_or_else(|| UserAliasError::retryable(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32))?;
        alias.cap = cap;
        alias.copy = DebugFilterAliasCopy::Entered;
        let copy_error = unsafe { copy_cap_into_r(frame, cap) };
        if copy_error != 0 {
            // The destination slot may have been occupied before the copy. A
            // returned error alone does not authorize reusing or deleting it.
            return Err(UserAliasError::retained(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32));
        }
        alias.copy = DebugFilterAliasCopy::Present;
    }
    if alias.copy != DebugFilterAliasCopy::Present || alias.cap == 0 {
        return Err(UserAliasError::retained(nt_process::STATUS_INVALID_HANDLE));
    }
    alias.map_entered = true;
    let map_error = unsafe { page_map_r(alias.cap, USER_VA, RO_NX, caps.pml4) };
    if map_error != 0 {
        // The kernel rejects before installing a mapping. Keep the copied cap
        // owned, but do not spin on a structural conflict: seL4_DeleteFirst
        // (8) means the VA is occupied, and seL4_FailedLookup (6) means its
        // page-table path is absent. Only resource exhaustion (10) can retry.
        alias.map_entered = false;
        return Err(match map_error {
            10 => UserAliasError::retryable(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32),
            8 => UserAliasError::retained(nt_status::NtStatus::CONFLICTING_ADDRESSES.raw() as u32),
            _ => UserAliasError::retained(nt_process::STATUS_DEVICE_BUSY),
        });
    }
    alias.mapped = true;
    Ok(())
}
