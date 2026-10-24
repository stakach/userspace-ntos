//! Hosted-driver directory creation over the canonical transactional namespace
//! broker. The driver has a distinct admitted label; the broker and handle
//! authority remain shared with native user and win32k directory objects.

use super::*;

pub(super) const LABEL: u64 = 0x7C5;

/// `ZwCreateDirectoryObject` uses the shared component-side name upload with
/// this driver-domain label. The transport sends only scalar words and packed
/// UTF-16 units; it never passes a component pointer into the executive.
pub(super) extern "win64" fn zw_create_directory_object(
    handle_out: *mut u64,
    desired_access: u32,
    object_attributes: u64,
) -> i32 {
    crate::win32k_subsystem::directory_object::create_with_label(
        LABEL,
        handle_out,
        desired_access,
        object_attributes,
    )
}

/// Called by the dedicated hosted-driver pump label after the physical badge
/// and Reply have been authenticated. Broker ownership includes the exact
/// route, dispatch identity, and canonical native caller.
pub(crate) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    active_reply_cap: u64,
    op: u64,
    m1: u64,
    m2: u64,
    m3: u64,
) -> (i32, u64, u64, u64) {
    use crate::spawn_hosts::shared_ingress::owner::runtime;
    let Some((_instance, _inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let route = match unsafe { runtime::channel_route(channel) } {
        Ok(Some(route)) => route,
        _ => return (STATUS_INVALID_HANDLE, 0, 0, 0),
    };
    let dispatch = match unsafe { runtime::dispatch(route) } {
        Ok(dispatch) => dispatch,
        Err(_) => return (STATUS_INVALID_HANDLE, 0, 0, 0),
    };
    if !matches!(unsafe { runtime::current_reply(route) }, Ok(reply) if reply == active_reply_cap) {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let caller = match unsafe { crate::provider_registry_caller::resolve(channel) } {
        Ok(caller) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let handler = match crate::service_sec_image::registry_live_handler_pointer() {
        Ok(handler) => handler,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    unsafe {
        crate::provider_directory_broker::dispatch(
            &mut *handler,
            route,
            dispatch,
            caller,
            op,
            m1,
            m2,
            m3,
        )
    }
}
