//! Selected logical-thread execution state, retained on the provider continuation stack.

use super::*;
use nt_kernel_abi::ps_reactos_x64::{self as abi, ThreadPreviousMode};

unsafe fn selected_body() -> u64 {
    let body = current_ethread();
    let tid = WIN32K_CURRENT_THREAD_ID.load(Ordering::Relaxed);
    if body == 0
        || tid == 0
        || read_volatile(body as *const u8) != 6
        || read_volatile((body + abi::ETHREAD_CLIENT_ID_THREAD as u64) as *const u64) != tid
    {
        crate::provider_bugcheck::report(0xc4, [0x54485245, body, tid, 1]);
    }
    body
}

unsafe fn body_bytes(body: u64) -> &'static mut [u8] {
    core::slice::from_raw_parts_mut(body as *mut u8, abi::ETHREAD_BODY_BYTES)
}

pub(super) extern "win64" fn previous_mode() -> u8 {
    unsafe {
        let body = selected_body();
        abi::thread_previous_mode(body_bytes(body)).unwrap_or_else(|_| {
            crate::provider_bugcheck::report(0xc4, [0x54485245, body, 0, 2]);
        }) as u8
    }
}

pub(super) extern "win64" fn set_stack_swap_enable(enable: u8) -> u8 {
    unsafe {
        let body = selected_body();
        u8::from(
            abi::exchange_thread_stack_swap_enable(body_bytes(body), enable != 0).unwrap_or_else(
                |_| {
                    crate::provider_bugcheck::report(
                        0xc4,
                        [0x54485245, body, u64::from(enable), 3],
                    );
                },
            ),
        )
    }
}

pub(super) struct PreviousModeScope {
    body: u64,
    previous: ThreadPreviousMode,
}

impl PreviousModeScope {
    pub(super) unsafe fn enter(mode: ThreadPreviousMode) -> Self {
        let body = selected_body();
        let previous =
            abi::exchange_thread_previous_mode(body_bytes(body), mode).unwrap_or_else(|_| {
                crate::provider_bugcheck::report(0xc4, [0x54485245, body, mode as u64, 4]);
            });
        Self { body, previous }
    }
}

impl Drop for PreviousModeScope {
    fn drop(&mut self) {
        unsafe {
            if abi::exchange_thread_previous_mode(body_bytes(self.body), self.previous).is_err() {
                crate::provider_bugcheck::report(0xc4, [0x54485245, self.body, 0, 5]);
            }
        }
    }
}
