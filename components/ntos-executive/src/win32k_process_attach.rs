//! Native KAPC_STATE changes paired with the root's exact process-window transition.

use super::*;
use nt_kernel_exec::apc_state;

const APC_PROCESS_OFF: u64 = apc_state::KAPC_PROCESS_OFFSET as u64;
const ATTACH_BUGCHECK: u64 = 0x4b415443;

#[inline(never)]
fn invalid(operation: u64, value: u64, reason: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [ATTACH_BUGCHECK, operation, value, reason]) }
}

unsafe fn move_apc_state(source: u64, destination: u64) {
    if apc_state::move_state(source, destination).is_err() {
        invalid(0, source, 1);
    }
}

unsafe fn thread_state() -> (u64, u64, u64, u64) {
    let thread = current_ethread();
    if thread == 0 || thread_context_index_for_ethread(thread).is_none() {
        invalid(0, thread, 2);
    }
    let current = thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE as u64;
    let saved = thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_SAVED_APC_STATE as u64;
    let index = thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_INDEX as u64;
    (thread, current, saved, index)
}

pub(super) unsafe fn selected_process(thread: u64, original: u64) -> u64 {
    if thread == 0 {
        return original;
    }
    let index = read_volatile(
        (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_INDEX as u64) as *const u8,
    );
    if index > 1 {
        invalid(0, thread, 13);
    }
    if index == 0 {
        return original;
    }
    let current = read_volatile(
        (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_PROCESS as u64) as *const u64,
    );
    if current == 0 || current == original {
        invalid(0, current, 14);
    }
    current
}

pub(super) unsafe fn selected_win32process(thread: u64, original: u64, original_w32: u64) -> u64 {
    let process = selected_process(thread, original);
    if process == original {
        original_w32
    } else {
        read_volatile((process + EPROCESS_WIN32PROCESS_OFF) as *const u64)
    }
}

unsafe fn exchange(operation: u64, process: u64, saved: u64, thread: u64) -> (u64, u64, u8) {
    let (words, status, current, marker, index) = crate::driver_launch::call_on4_raw(
        (W32_PROCESS_ATTACH_LABEL << 12) | 4,
        operation,
        process,
        saved,
        thread,
    );
    if words != 4 || status != 0 || current == 0 || index > 1 {
        invalid(operation, process, status);
    }
    (current, marker, index as u8)
}

unsafe fn publish_process(thread: u64, current: u64, index: u8) {
    write_volatile(
        (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_INDEX as u64) as *mut u8,
        index,
    );
    write_volatile((WIN32K_KPCR_VA + 0x60) as *mut u64, current);
    write_volatile(
        SLOT_W32PROCESS as *mut u64,
        read_volatile((current + EPROCESS_WIN32PROCESS_OFF) as *const u64),
    );
}

pub(super) extern "win64" fn ke_attach_process(process: u64) {
    unsafe {
        let (thread, active, saved, index_va) = thread_state();
        let old = read_volatile((active + APC_PROCESS_OFF) as *const u64);
        let index = read_volatile(index_va as *const u8);
        if process == 0 || index > 1 || (old != process && index != 0) {
            invalid(W32_ATTACH_PLAIN, process, 3);
        }
        let (current, _, attached) = exchange(W32_ATTACH_PLAIN, process, 0, thread);
        if current != old {
            move_apc_state(active, saved);
            apc_state::initialize(active, current);
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64) as *mut u64,
                saved,
            );
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64 + 8) as *mut u64,
                active,
            );
        }
        publish_process(thread, current, attached);
    }
}

pub(super) extern "win64" fn ke_detach_process() {
    unsafe {
        let (thread, active, saved, index_va) = thread_state();
        let index = read_volatile(index_va as *const u8);
        if index > 1 || (index != 0 && !apc_state::can_detach(active)) {
            invalid(W32_ATTACH_DETACH, thread, 4);
        }
        let (current, _, attached) = exchange(W32_ATTACH_DETACH, 0, 0, thread);
        if index != 0 {
            move_apc_state(saved, active);
            write_volatile((saved + APC_PROCESS_OFF) as *mut u64, 0);
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64) as *mut u64,
                active,
            );
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64 + 8) as *mut u64,
                saved,
            );
        }
        if read_volatile((active + APC_PROCESS_OFF) as *const u64) != current {
            invalid(W32_ATTACH_DETACH, current, 5);
        }
        publish_process(thread, current, attached);
    }
}

pub(super) extern "win64" fn ke_stack_attach_process(process: u64, apc_state: u64) {
    unsafe {
        let (thread, active, saved, index_va) = thread_state();
        let old = read_volatile((active + APC_PROCESS_OFF) as *const u64);
        let old_index = read_volatile(index_va as *const u8);
        if process == 0 || apc_state == 0 || apc_state & 7 != 0 || old_index > 1 {
            invalid(W32_ATTACH_STACK, process, 6);
        }
        let (current, marker, attached) = exchange(W32_ATTACH_STACK, process, apc_state, thread);
        if marker == 1 {
            if current != old || attached != old_index {
                invalid(W32_ATTACH_STACK, current, 7);
            }
            write_volatile((apc_state + APC_PROCESS_OFF) as *mut u64, 1);
            return;
        }
        if current == old || (marker != 0 && marker != old) {
            invalid(W32_ATTACH_STACK, current, 8);
        }
        let destination = if old_index == 0 { saved } else { apc_state };
        move_apc_state(active, destination);
        apc_state::initialize(active, current);
        write_volatile((apc_state + APC_PROCESS_OFF) as *mut u64, marker);
        if old_index == 0 {
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64) as *mut u64,
                saved,
            );
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64 + 8) as *mut u64,
                active,
            );
        }
        publish_process(thread, current, attached);
    }
}

pub(super) extern "win64" fn ke_unstack_detach_process(apc_state: u64) {
    unsafe {
        let (thread, active, saved, index_va) = thread_state();
        let index = read_volatile(index_va as *const u8);
        if apc_state == 0 || apc_state & 7 != 0 || index > 1 {
            invalid(W32_ATTACH_UNSTACK, apc_state, 9);
        }
        let marker = read_volatile((apc_state + APC_PROCESS_OFF) as *const u64);
        if marker != 1 && (index == 0 || !apc_state::can_detach(active)) {
            invalid(W32_ATTACH_UNSTACK, apc_state, 10);
        }
        let (current, expected, attached) = exchange(W32_ATTACH_UNSTACK, 0, apc_state, thread);
        if expected != 0 || marker == 1 {
            if marker != 1 || current != read_volatile((active + APC_PROCESS_OFF) as *const u64) {
                invalid(W32_ATTACH_UNSTACK, current, 11);
            }
            return;
        }
        let source = if marker == 0 { saved } else { apc_state };
        move_apc_state(source, active);
        if marker == 0 {
            write_volatile((saved + APC_PROCESS_OFF) as *mut u64, 0);
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64) as *mut u64,
                active,
            );
            write_volatile(
                (thread + nt_kernel_abi::ps_reactos_x64::KTHREAD_APC_STATE_POINTERS as u64 + 8) as *mut u64,
                saved,
            );
        }
        if read_volatile((active + APC_PROCESS_OFF) as *const u64) != current {
            invalid(W32_ATTACH_UNSTACK, current, 12);
        }
        publish_process(thread, current, attached);
    }
}
