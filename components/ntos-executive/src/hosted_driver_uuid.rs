//! One kernel UUID allocator shared by every hosted driver VSpace.

use super::*;
use core::sync::atomic::AtomicBool;
use nt_kernel_exec::uuid_v1::{UuidV1Generator, RPC_NT_UUID_LOCAL_ONLY};

static UUID_LOCK: AtomicBool = AtomicBool::new(false);
static UUID_INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut UUID_GENERATOR: UuidV1Generator = UuidV1Generator::new(0);

struct UuidLock;

impl UuidLock {
    fn acquire() -> Self {
        while UUID_LOCK
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for UuidLock {
    fn drop(&mut self) {
        UUID_LOCK.store(false, Ordering::Release);
    }
}

/// `NTSTATUS ExUuidCreate(UUID*)`. The UUID pointer never crosses the service boundary.
pub(super) extern "win64" fn s_ex_uuid_create(uuid_out: u64) -> i32 {
    if uuid_out == 0 || uuid_out.checked_add(16).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    let (label, status, low, high, _) = unsafe {
        call_on4(FSD_SERVICE_UUID_CREATE_LABEL << 12, 0, 0, 0, 0)
    };
    let status = status as u32 as i32;
    if label != 0 || status != RPC_NT_UUID_LOCAL_ONLY {
        return if label == 0 { status } else { STATUS_INVALID_DEVICE_REQUEST };
    }
    unsafe {
        write_unaligned(uuid_out as *mut u64, low);
        write_unaligned((uuid_out + 8) as *mut u64, high);
    }
    status
}

pub(crate) fn service_hosted_driver_uuid_create(
    channel: &crate::spawn_hosts::PumpChannel,
    caller_badge: u64,
    reply_cap: u64,
) -> (i32, u64, u64) {
    let Some((instance, inst)) = instance_for_pump_channel(channel, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0, 0);
    };
    if hosted_driver_caller(instance, inst, caller_badge).is_none() {
        return (STATUS_ACCESS_DENIED, 0, 0);
    }
    let now = nt_system_time_100ns();
    let _guard = UuidLock::acquire();
    if !UUID_INITIALIZED.load(Ordering::Relaxed) {
        let seed = (nt_system_boot_time_100ns() ^ now) as u16;
        unsafe { *core::ptr::addr_of_mut!(UUID_GENERATOR) = UuidV1Generator::new(seed); }
        UUID_INITIALIZED.store(true, Ordering::Relaxed);
    }
    let Some(bytes) = (unsafe { (&mut *core::ptr::addr_of_mut!(UUID_GENERATOR)).next(now) }) else {
        return (0xC000_0095u32 as i32, 0, 0); // STATUS_INTEGER_OVERFLOW
    };
    let low = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let high = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    (RPC_NT_UUID_LOCAL_ONLY, low, high)
}
