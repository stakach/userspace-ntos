//! Kernel `RtlWriteRegistryValue` over the existing authenticated Zw registry transport.

use super::*;
use nt_config_client::plan_rtl_registry_write;

static RTL_WRITE_TRACE_COUNT: AtomicU64 = AtomicU64::new(0);

fn trace_rtl_write(ordinal: u64, stage: u64, status: i32) {
    if ordinal > 32 && !hosted_video_port_control::video_create_hw_initialize_active() { return; }
    print_str(b"[rtl-registry-write-stage] ordinal="); print_u64(ordinal);
    print_str(b" stage="); print_u64(stage);
    print_str(b" status=0x"); print_hex_u64(status as u32 as u64);
    print_str(b"\n");
}

/// Create/open the selected key, preserve the caller's exact value type and byte length, then
/// close only the key opened here. The HANDLE form borrows the caller's existing key handle.
pub(super) extern "win64" fn write_registry_value(
    relative_to: u32,
    path: u64,
    value_name: u64,
    value_type: u32,
    value_data: u64,
    value_length: u32,
) -> i32 {
    let ordinal = RTL_WRITE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    trace_rtl_write(ordinal, 1, 0);
    unsafe {
        let path_ascii = if relative_to & 0x4000_0000 != 0 {
            None
        } else {
            match wide_cstr_to_hosted_ascii::<HOSTED_REGISTRY_PATH_MAX>(path) {
                Some(value) => Some(value),
                None if path == 0 => None,
                None => return STATUS_INVALID_PARAMETER,
            }
        };
        let plan = match plan_rtl_registry_write(
            relative_to,
            path_ascii.as_ref().map(HostedAscii::as_str),
            value_type,
            value_data != 0,
            value_length,
        ) {
            Ok(plan) => plan,
            Err(status) => return status,
        };
        let value_ascii = if value_name == 0 {
            HostedAscii::<HOSTED_REGISTRY_PATH_MAX>::empty()
        } else {
            match wide_cstr_to_hosted_ascii::<HOSTED_REGISTRY_PATH_MAX>(value_name) {
                Some(value) => value,
                None => return STATUS_INVALID_PARAMETER,
            }
        };
        let mut value_wide = [0u16; HOSTED_REGISTRY_PATH_MAX];
        for (index, byte) in value_ascii.as_bytes().iter().enumerate() {
            value_wide[index] = u16::from(*byte);
        }
        let value_bytes = (value_ascii.len * 2) as u64;
        let value_unicode = [
            value_bytes | ((value_bytes + 2) << 16),
            value_wide.as_ptr() as u64,
        ];
        let (handle, owned) = match hosted_rtl_registry_delete::open_planned_target(plan.target, path) {
            Ok(target) => target,
            Err(status) => return status,
        };
        trace_rtl_write(ordinal, 2, 0);
        let status = s_zw_set_value_key(
            handle,
            value_unicode.as_ptr() as u64,
            0,
            plan.value_type,
            value_data,
            plan.value_length,
        );
        trace_rtl_write(ordinal, 3, status);
        if owned {
            let _ = s_zw_close(handle);
        }
        trace_rtl_write(ordinal, 4, status);
        status
    }
}
