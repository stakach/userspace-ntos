//! Driver-domain Ps state queries and genuine pointer-valued data exports.
//!
//! Callable queries use the authenticated ProcessManager broker in
//! `hosted_driver_process_identity`. Data IAT entries instead point to cells
//! in this driver's mapped DATA page. The cells hold canonical bodies from
//! the shared component image; no executive-only pointer is published.

use super::*;

pub(super) const INITIAL_SYSTEM_PROCESS_CELL_OFF: u64 = 0x220;
pub(super) const PROCESS_TYPE_CELL_OFF: u64 = 0x228;
pub(super) const THREAD_TYPE_CELL_OFF: u64 = 0x230;

pub(super) const INITIAL_SYSTEM_PROCESS_CELL_VA: u64 =
    FSD_DATA_VADDR + INITIAL_SYSTEM_PROCESS_CELL_OFF;
pub(super) const PROCESS_TYPE_CELL_VA: u64 = FSD_DATA_VADDR + PROCESS_TYPE_CELL_OFF;
pub(super) const THREAD_TYPE_CELL_VA: u64 = FSD_DATA_VADDR + THREAD_TYPE_CELL_OFF;

const _: () = assert!(THREAD_TYPE_CELL_OFF + 8 <= 0x300);

/// Initialize all three pointer-valued Ps data exports for an isolated driver.
/// The initial process body and object-type descriptors live in executive-image
/// pages retained and mapped into every hosted driver's component address space.
/// This function runs against this driver's executive-side DATA alias before
/// its image IAT is patched or DriverEntry is called.
pub(super) unsafe fn initialize_data_cells(exec_data_va: u64) -> Result<(), u32> {
    let initial = crate::ps_bootstrap::initial_system_projection()
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if initial.process_body == 0 || initial.thread_body == 0 {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let process_type = nt_object_manager::object_type::process_object_type_addr();
    let thread_type = nt_object_manager::object_type::thread_object_type_addr();
    if process_type == 0 || thread_type == 0 || process_type == thread_type {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    unsafe {
        write_volatile(
            (exec_data_va + INITIAL_SYSTEM_PROCESS_CELL_OFF) as *mut u64,
            initial.process_body,
        );
        write_volatile((exec_data_va + PROCESS_TYPE_CELL_OFF) as *mut u64, process_type);
        write_volatile((exec_data_va + THREAD_TYPE_CELL_OFF) as *mut u64, thread_type);
    }
    Ok(())
}

/// `NTSTATUS PsGetProcessExitStatus(PEPROCESS)` reads the exact live or
/// retained ProcessManager object. Running processes return STATUS_PENDING.
pub(super) extern "win64" fn ps_get_process_exit_status(process: u64) -> i32 {
    hosted_driver_process_identity::query_state(
        hosted_driver_process_identity::QUERY_PROCESS_EXIT_STATUS,
        process,
    ) as u32 as i32
}

/// `ULONG PsGetProcessSessionId(PEPROCESS)` reads the exact published process
/// body's session, including an attached process in a numbered GUI session.
pub(super) extern "win64" fn ps_get_process_session_id(process: u64) -> u32 {
    let value = hosted_driver_process_identity::query_state(
        hosted_driver_process_identity::QUERY_PROCESS_SESSION_ID,
        process,
    );
    match u32::try_from(value) {
        Ok(session_id) => session_id,
        Err(_) => unsafe { crate::provider_bugcheck::report(0xc4, [0x7C4, 8, process, value]) },
    }
}

/// `BOOLEAN PsIsSystemProcess(PEPROCESS)` compares the canonical designated
/// initial System process, regardless of PID, image name, or token subject.
pub(super) extern "win64" fn ps_is_system_process(process: u64) -> u8 {
    let value = hosted_driver_process_identity::query_state(
        hosted_driver_process_identity::QUERY_IS_SYSTEM_PROCESS,
        process,
    );
    if value > 1 {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x7C4, 6, process, value]); }
    }
    value as u8
}

/// `BOOLEAN PsIsThreadTerminating(PETHREAD)` reads the canonical ETHREAD state.
pub(super) extern "win64" fn ps_is_thread_terminating(thread: u64) -> u8 {
    let value = hosted_driver_process_identity::query_state(
        hosted_driver_process_identity::QUERY_IS_THREAD_TERMINATING,
        thread,
    );
    if value > 1 {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x7C4, 7, thread, value]); }
    }
    value as u8
}
