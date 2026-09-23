//! Deferred SYSTEM value requests for driver-host registry service lanes.

use super::*;
use crate::registry_mutation_work::{
    DeferredRegistryExisting, ProviderRegistryResult, ProviderValueMutation,
};

pub(super) unsafe fn route(
    channel: &crate::spawn_hosts::PumpChannel,
    op: u64,
    handle: u64,
    value_type_or_token: u64,
    length: u64,
    active_reply_cap: u64,
) -> Option<ProviderRegistryResult> {
    if !matches!(
        op,
        HOSTED_REGISTRY_OP_SET_HANDLE_VALUE
            | HOSTED_REGISTRY_OP_COMMIT_SET_HANDLE_VALUE
            | HOSTED_REGISTRY_OP_DELETE_HANDLE_VALUE
    ) {
        return None;
    }
    let Some((_instance, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
    };
    let arg = inst.exec_arg_va;
    if arg == 0 {
        return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
    }
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(ProviderRegistryResult::Ready((status as i32, 0, 0))),
    };
    let slot = match driver_registry_handles::driver_registry_handle_slot(caller, handle, 2) {
        Ok(slot) => slot,
        Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
    };
    if !matches!(slot.target, DriverRegistryHandleTarget::System { .. }) {
        return None;
    }
    let dispatch = match driver_registry_handles::RegistryPublicationDispatch::capture(channel) {
        Ok(dispatch) => dispatch,
        Err(status) => return Some(ProviderRegistryResult::Ready((status as i32, 0, 0))),
    };
    let (mutation, transfer) = match op {
        HOSTED_REGISTRY_OP_SET_HANDLE_VALUE => {
            let Some(name) = read_registry_arg_ascii_at::<HOSTED_REGISTRY_PATH_MAX>(
                arg, HOSTED_REGISTRY_ARG_VALUE_LEN, HOSTED_REGISTRY_ARG_VALUE_OFF, true,
            ) else {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
            };
            let Ok(value_type) = u32::try_from(value_type_or_token) else {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
            };
            if length > HOSTED_REGISTRY_ARG_DATA_CAP {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_BUFFER_SIZE as i32, 0, 0)));
            }
            let source = core::slice::from_raw_parts(
                (arg + HOSTED_REGISTRY_ARG_DATA_OFF) as *const u8, length as usize,
            );
            let mut data = Vec::new();
            if data.try_reserve_exact(source.len()).is_err() {
                return Some(ProviderRegistryResult::Ready((STATUS_INSUFFICIENT_RESOURCES, 0, 0)));
            }
            data.extend_from_slice(source);
            (
                ProviderValueMutation::Set {
                    name: String::from(name.as_str()), value_type, data,
                },
                None,
            )
        }
        HOSTED_REGISTRY_OP_COMMIT_SET_HANDLE_VALUE => {
            let Ok(total) = usize::try_from(length) else {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
            };
            let transfer = match driver_registry_value_transfers::snapshot_complete(
                caller, handle, value_type_or_token, total,
            ) {
                Ok(transfer) => transfer,
                Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
            };
            if !matches!(transfer.target, DriverRegistryHandleTarget::System { .. }) {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_HANDLE, 0, 0)));
            }
            (
                ProviderValueMutation::Set {
                    name: transfer.name, value_type: transfer.value_type, data: transfer.data,
                },
                Some(transfer.identity),
            )
        }
        HOSTED_REGISTRY_OP_DELETE_HANDLE_VALUE => {
            let Some(name) = read_registry_arg_ascii_at::<HOSTED_REGISTRY_PATH_MAX>(
                arg, HOSTED_REGISTRY_ARG_VALUE_LEN, HOSTED_REGISTRY_ARG_VALUE_OFF, true,
            ) else {
                return Some(ProviderRegistryResult::Ready((STATUS_INVALID_PARAMETER, 0, 0)));
            };
            (ProviderValueMutation::Delete { name: String::from(name.as_str()) }, None)
        }
        _ => unreachable!(),
    };
    let admission = match DeferredRegistryExisting::admit(caller, dispatch, handle, mutation) {
        Ok(admission) => admission,
        Err(status) => return Some(ProviderRegistryResult::Ready((status, 0, 0))),
    };
    let result = crate::registry_mutation_work::submit_provider_existing(channel, admission);
    if matches!(result, ProviderRegistryResult::Deferred) {
        if let Some(identity) = transfer {
            driver_registry_value_transfers::retire_completed(identity);
        }
    }
    Some(result)
}
