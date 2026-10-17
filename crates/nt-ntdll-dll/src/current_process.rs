//! Process-handle identity query used by kernelbase and WOW64 helpers.

use core::ffi::c_void;

#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: u32,
    reserved: u32,
    peb_base: u64,
    affinity_mask: u64,
    base_priority: i32,
    reserved2: u32,
    unique_process_id: u64,
    inherited_from_unique_process_id: u64,
}

const _: () = assert!(core::mem::size_of::<ProcessBasicInformation>() == 48);

fn current_with(
    handle: u64,
    current_pid: u64,
    query: impl FnOnce(u64, &mut ProcessBasicInformation) -> u32,
) -> u8 {
    if handle == u64::MAX {
        return 1;
    } // NtCurrentProcess pseudo-handle.
    let mut information = ProcessBasicInformation::default();
    let status = query(handle, &mut information);
    u8::from(status & 0x8000_0000 == 0 && information.unique_process_id == current_pid)
}

/// `RtlIsCurrentProcess(HANDLE) -> BOOLEAN`.
#[export_name = "RtlIsCurrentProcess"]
pub extern "system" fn rtl_is_current_process(handle: *mut c_void) -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let current_pid: u64;
        // SAFETY: the current NT TEB holds ClientId.UniqueProcess at GS:[0x40].
        unsafe {
            core::arch::asm!(
                "mov {}, gs:[0x40]",
                out(reg) current_pid,
                options(nostack, preserves_flags, readonly)
            );
        }
        current_with(handle as u64, current_pid, |handle, information| {
            // SAFETY: the local output has the x64 PROCESS_BASIC_INFORMATION layout.
            unsafe {
                nt_ntdll::trap_stubs::nt_query_information_process(
                    handle,
                    0,
                    information as *mut ProcessBasicInformation as u64,
                    core::mem::size_of::<ProcessBasicInformation>() as u64,
                    0,
                ) as u32
            }
        })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        current_with(handle as u64, 0, |_, _| 0xC000_0002)
    }
}

#[used]
pub static CURRENT_PROCESS_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = current_process_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Only stored in a `#[used]` static.
pub unsafe extern "C" fn current_process_export_anchor() {
    core::hint::black_box(rtl_is_current_process as *const () as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_and_queried_process_identity_are_distinguished() {
        assert_eq!(
            current_with(u64::MAX, 7, |_, _| panic!("queried pseudo-handle")),
            1
        );
        assert_eq!(
            current_with(44, 7, |handle, output| {
                assert_eq!(handle, 44);
                output.unique_process_id = 7;
                0
            }),
            1
        );
        assert_eq!(
            current_with(44, 7, |_, output| {
                output.unique_process_id = 8;
                0
            }),
            0
        );
        assert_eq!(
            current_with(44, 7, |_, output| {
                output.unique_process_id = 7;
                0xC000_0008
            }),
            0
        );
    }
}
