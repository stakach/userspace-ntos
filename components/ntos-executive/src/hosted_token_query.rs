//! Authenticated provider queries against retained token projections.

use super::*;

const STATUS_INVALID_HANDLE_LOCAL: i32 = 0xc000_0008u32 as i32;
const STATUS_INVALID_PARAMETER_LOCAL: i32 = 0xc000_000du32 as i32;

pub(super) fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    token_address: u64,
    selector: u64,
) -> (i32, u64) {
    let Some((_, provider)) = instance_for_pump_channel(channel, reply_cap) else {
        return (STATUS_INVALID_HANDLE_LOCAL, 0);
    };
    if hosted_driver_pump_caller_tcb(channel, reply_cap, caller_badge).is_none() {
        return (STATUS_INVALID_HANDLE_LOCAL, 0);
    }
    if token_address == 0 || !matches!(selector, 1 | 2) {
        return (STATUS_INVALID_PARAMETER_LOCAL, 0);
    }
    let metadata = unsafe {
        crate::with_provider_security_managers(|_, tokens| {
            driver_hosted_token_projection::query(provider, token_address, tokens)
                .map_err(|status| status as u32)
        })
    };
    let metadata = match metadata {
        Ok(metadata) => metadata,
        Err(status) => return (status as i32, 0),
    };
    match selector {
        1 => (STATUS_SUCCESS, u64::from(metadata.session_id)),
        2 => {
            let luid = metadata.authentication_id;
            let value = u64::from(luid.low) | (u64::from(luid.high as u32) << 32);
            (STATUS_SUCCESS, value)
        }
        _ => unreachable!(),
    }
}
