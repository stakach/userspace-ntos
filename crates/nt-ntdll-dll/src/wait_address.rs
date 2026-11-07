//! Released ntdll's process-local wait and wake exports.

use core::ffi::c_void;

use nt_ntdll::rtl::wait_address::ADDRESS_WAITS;

#[cfg(target_arch = "x86_64")]
fn current_thread_id() -> u64 {
    let thread_id: u64;
    // SAFETY: x64 NT stores the current client thread ID at TEB GS:[0x48].
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x48]",
            out(reg) thread_id,
            options(nostack, preserves_flags, readonly)
        );
    }
    thread_id
}

#[cfg(not(target_arch = "x86_64"))]
fn current_thread_id() -> u64 {
    0
}

/// `RtlWaitOnAddress(Address, CompareAddress, AddressSize, Timeout) -> NTSTATUS`.
///
/// # Safety
/// `address` and `compare` must point to readable memory of `size` bytes. `timeout`, when
/// present, must point to a readable `LARGE_INTEGER` through the native wait call.
#[export_name = "RtlWaitOnAddress"]
pub unsafe extern "system" fn rtl_wait_on_address(
    address: *const c_void,
    compare: *const c_void,
    size: usize,
    timeout: *const i64,
) -> u32 {
    // SAFETY: this export forwards the caller's pointer contract to the process-local queue.
    unsafe {
        ADDRESS_WAITS.wait(
            address.cast(),
            compare.cast(),
            size,
            current_thread_id(),
            timeout,
            |timeout| {
                #[cfg(target_arch = "x86_64")]
                // SAFETY: timeout remains live for this synchronous native wait.
                unsafe {
                    nt_ntdll::trap_stubs::nt_wait_for_alert_by_thread_id(0, timeout as u64) as u32
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    let _ = timeout;
                    nt_ntdll::STATUS_NOT_IMPLEMENTED
                }
            },
        )
    }
}

fn alert_thread(thread_id: u64) -> u32 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the target is an ID selected from a waiter in this process's queue.
    unsafe {
        nt_ntdll::trap_stubs::nt_alert_thread_by_thread_id(thread_id) as u32
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = thread_id;
        nt_ntdll::STATUS_NOT_IMPLEMENTED
    }
}

/// `RtlWakeAddressSingle(Address)`.
#[export_name = "RtlWakeAddressSingle"]
pub extern "system" fn rtl_wake_address_single(address: *const c_void) {
    ADDRESS_WAITS.wake_one(address.cast(), alert_thread);
}

/// `RtlWakeAddressAll(Address)`.
#[export_name = "RtlWakeAddressAll"]
pub extern "system" fn rtl_wake_address_all(address: *const c_void) {
    ADDRESS_WAITS.wake_all(address.cast(), alert_thread);
}

#[used]
pub static WAIT_ADDRESS_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = wait_address_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// This routine is stored only in a `#[used]` static.
pub unsafe extern "C" fn wait_address_export_anchor() {
    core::hint::black_box([
        rtl_wait_on_address as *const () as usize,
        rtl_wake_address_single as *const () as usize,
        rtl_wake_address_all as *const () as usize,
    ]);
}
