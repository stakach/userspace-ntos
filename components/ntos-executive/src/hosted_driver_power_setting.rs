//! Power-setting subscriptions require a real current value before success.
//!
//! The pinned dxgkrnl requests AC/DC and lid values. Neither value has an
//! authoritative publisher in the hosted Power Manager yet. Windows calls the
//! registered callback with the current value before registration returns;
//! therefore this boundary reports unavailable and issues no handle or
//! callback until a real publisher and retained callback tickets exist.

use super::*;

pub(super) const LABEL: u64 = 0x7D1;
const REGISTER: u64 = 1;
const UNREGISTER: u64 = 2;
const GUID_BYTES: usize = 16;

pub(super) extern "win64" fn register(
    device_object: u64,
    setting_guid: u64,
    callback: u64,
    context: u64,
    handle_out: u64,
) -> i32 {
    if handle_out == 0 || setting_guid == 0 || callback == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        write_unaligned(handle_out as *mut u64, 0);
        let _guard = component_device_reply_lock();
        core::ptr::copy_nonoverlapping(
            setting_guid as *const u8,
            FSD_ARG_VADDR as *mut u8,
            GUID_BYTES,
        );
        let (info, status, handle, _, _) = call_on4_raw(
            (LABEL << 12) | 4, REGISTER, device_object, callback, context,
        );
        if info != 2 || status as u32 as i32 == STATUS_SUCCESS || handle != 0 {
            // A registration cannot have succeeded without a current-value
            // callback and an owner established before that native effect.
            crate::provider_bugcheck::report(0xc4, [LABEL, REGISTER, info, status]);
        }
        status as u32 as i32
    }
}

pub(super) extern "win64" fn unregister(handle: u64) -> i32 {
    if handle == 0 { return STATUS_INVALID_PARAMETER; }
    let (info, status, value, _, _) = unsafe {
        call_on4_raw((LABEL << 12) | 4, UNREGISTER, handle, 0, 0)
    };
    if info != 2 || value != 0 || status as u32 as i32 == STATUS_SUCCESS {
        unsafe { crate::provider_bugcheck::report(0xc4, [LABEL, UNREGISTER, info, status]); }
    }
    status as u32 as i32
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    device_or_handle: u64,
    callback: u64,
    context: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else { return (STATUS_ACCESS_DENIED, 0); };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0);
    }
    if op == UNREGISTER {
        if device_or_handle == 0 || callback != 0 || context != 0 {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        // No registration handle has been issued while current values lack
        // authoritative publishers. A guessed/stale handle owns nothing.
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if op != REGISTER || callback == 0 || inst.exec_arg_va == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    if device_or_handle != 0
        && authenticated_hosted_device(ch, device_or_handle, reply_cap).is_err()
    {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(singleton) = (unsafe { hosted_provider_singletons() })
        .and_then(|rows| rows.iter().find(|row| row.present
            && row.instance == index && row.owner_domain == domain))
    else { return (STATUS_ACCESS_DENIED, 0); };
    if !singleton.run_va.checked_add(singleton.image_len as u64)
        .is_some_and(|end| callback >= singleton.run_va && callback < end)
    {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let _guid: [u8; GUID_BYTES] = unsafe { read_unaligned(inst.exec_arg_va as *const _) };
    let _ = context;
    // PowerManager has no observed AC/DC or lid setting publication. Returning
    // success would require an immediate callback carrying a made-up value.
    (STATUS_DEVICE_NOT_READY, 0)
}
