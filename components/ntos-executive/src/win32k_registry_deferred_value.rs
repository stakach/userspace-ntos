//! Deferred SYSTEM value requests from the win32k registry provider lane.

use super::*;
use alloc::string::String;
use crate::registry_mutation_work::{
    DeferredRegistryExisting, ProviderRegistryResult, ProviderValueMutation,
};

pub(super) unsafe fn route(
    channel: &crate::spawn_hosts::PumpChannel,
    operation: u64,
    handle: u64,
    token: u64,
    total_len: u64,
) -> Option<ProviderRegistryResult> {
    let op = operation & !WIN32K_REGISTRY_USE_PREVIOUS_MODE;
    if !matches!(op, WIN32K_REGISTRY_OP_COMMIT_SET_VALUE | WIN32K_REGISTRY_OP_DELETE_VALUE) {
        return None;
    }
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(ProviderRegistryResult::Ready((status as i32, 0, 0))),
    };
    let caller = if operation & WIN32K_REGISTRY_USE_PREVIOUS_MODE != 0
        && channel.logical_caller.is_some()
    {
        match crate::with_provider_process_manager(|pm| pm.capture_native_handle_caller(
            caller.original_thread(), nt_types::AccessMode::UserMode,
        )) {
            Ok(caller) => caller,
            Err(status) => return Some(ProviderRegistryResult::Ready((status as i32, 0, 0))),
        }
    } else {
        caller
    };
    let slot = match crate::driver_launch::driver_registry_handles::driver_registry_handle_slot(
        caller, handle, 2,
    ) {
        Ok(slot) => slot,
        Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
    };
    if !matches!(slot.target, crate::driver_launch::DriverRegistryHandleTarget::System { .. }) {
        return None;
    }
    let dispatch = match crate::driver_launch::driver_registry_handles::RegistryPublicationDispatch::capture(channel) {
        Ok(dispatch) => dispatch,
        Err(status) => return Some(ProviderRegistryResult::Ready((status as i32, 0, 0))),
    };
    let (mutation, transfer) = if op == WIN32K_REGISTRY_OP_COMMIT_SET_VALUE {
        let Ok(total) = usize::try_from(total_len) else {
            return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER_I32, 0, 0)));
        };
        let transfer = match crate::driver_launch::driver_registry_value_transfers::snapshot_complete(
            caller, handle, token, total,
        ) {
            Ok(transfer) => transfer,
            Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
        };
        if !matches!(transfer.target, crate::driver_launch::DriverRegistryHandleTarget::System { .. }) {
            return Some(ProviderRegistryResult::Ready((STATUS_INVALID_HANDLE_I32, 0, 0)));
        }
        (
            ProviderValueMutation::Set {
                name: transfer.name, value_type: transfer.value_type, data: transfer.data,
            },
            Some(transfer.identity),
        )
    } else {
        let name = match read_win32k_registry_bytes(WIN32K_REGISTRY_VALUE_LEN, WIN32K_REGISTRY_VALUE_OFF)
            .ok_or(STATUS_INVALID_PARAMETER_I32)
            .and_then(|name| String::from_utf8(name).map_err(|_| STATUS_INVALID_PARAMETER_I32))
        {
            Ok(name) => name,
            Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
        };
        (ProviderValueMutation::Delete { name }, None)
    };
    let admission = match DeferredRegistryExisting::admit(caller, dispatch, handle, mutation) {
        Ok(admission) => admission,
        Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
    };
    let result = crate::registry_mutation_work::submit_provider_existing(channel, admission);
    if matches!(result, ProviderRegistryResult::Deferred) {
        if let Some(identity) = transfer {
            crate::driver_launch::driver_registry_value_transfers::retire_completed(identity);
        }
    }
    Some(result)
}
