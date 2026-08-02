//! `rendezvous` — the SM/CSR loop-thread spawn + authentic SM/CSR rendezvous glue
//! (sm_fill_page/csr_fill_page + sm_rendezvous/csr_rendezvous + the loop-thread
//! spawners). Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

fn live_hosted_pi_for_leaf(nt_handler: &ExecNtHandler, leaf: &[u8]) -> Option<usize> {
    for pi in 0..MAX_PI {
        let Some(pid) = nt_handler.pm_pid_for_pi(pi) else {
            continue;
        };
        let Some(process) = nt_handler.pm.process(pid) else {
            continue;
        };
        let Some(image) = nt_exe_image::hosted_image_for_path(process.image_file_name.as_bytes())
        else {
            continue;
        };
        if image.leaf.eq_ignore_ascii_case(leaf) {
            return Some(pi);
        }
    }
    None
}

fn live_hosted_pid_for_leaf(
    nt_handler: &ExecNtHandler,
    leaf: &[u8],
) -> Option<nt_process::ProcessId> {
    let pi = live_hosted_pi_for_leaf(nt_handler, leaf)?;
    nt_handler.pm_pid_for_pi(pi)
}

fn live_hosted_main_tid_for_leaf(
    nt_handler: &ExecNtHandler,
    leaf: &[u8],
) -> Option<nt_process::ThreadId> {
    let pi = live_hosted_pi_for_leaf(nt_handler, leaf)?;
    nt_handler.pm_main_tid_for_pi(pi)
}

fn live_hosted_cid_for_pi(nt_handler: &ExecNtHandler, pi: usize) -> (u64, u64) {
    (
        nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
        nt_handler.pm_main_tid_for_pi(pi).unwrap_or(0) as u64,
    )
}

fn hosted_role_tid(nt_handler: &ExecNtHandler, pi: usize, role: HostedThreadRole) -> u64 {
    nt_handler.hosted_thread_tid_for_role(pi, role).unwrap_or(0)
}

unsafe fn csr_api_worker_create_thread(
    nt_handler: &mut ExecNtHandler,
    main_fault_ep: u64,
    thread_handle_out: u64,
    desired_access: u32,
    process_handle: u64,
    sp: u64,
) -> u32 {
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    if thread_handle_out == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    if thread_handle_out & 7 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if !csr_stack_has_range(thread_handle_out, 8) {
        return STATUS_ACCESS_VIOLATION;
    }

    let Some(client_id_out) = sp
        .checked_add(0x28)
        .and_then(|address| csr_stack_read(address))
    else {
        return STATUS_ACCESS_VIOLATION;
    };
    let Some(context_va) = sp
        .checked_add(0x30)
        .and_then(|address| csr_stack_read(address))
    else {
        return STATUS_ACCESS_VIOLATION;
    };
    let Some(create_suspended_raw) = sp
        .checked_add(0x40)
        .and_then(|address| csr_stack_read(address))
    else {
        return STATUS_ACCESS_VIOLATION;
    };
    if client_id_out != 0 && !csr_stack_has_range(client_id_out, 16) {
        return STATUS_ACCESS_VIOLATION;
    }
    if context_va == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    let start = nt_thread_start::Amd64ThreadContext::read(
        |address| {
            let mut bytes = [0u8; 8];
            if unsafe { csr_stack_copyin(address, &mut bytes) } {
                u64::from_le_bytes(bytes)
            } else {
                0
            }
        },
        context_va,
    );
    if start.rip == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let create_suspended = create_suspended_raw != 0;

    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);

    let status = (|| {
        let caller_pid = nt_handler.pm_pid_for_pi(1).ok_or(STATUS_INVALID_HANDLE)?;
        let (target_pid, target_pi) = if process_handle == u64::MAX {
            (caller_pid, 1usize)
        } else {
            nt_handler.resolve_process_for_access(process_handle, PROCESS_CREATE_THREAD)?
        };
        if target_pi >= TP_WORKER_PI_COUNT {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let Some(target_pml4) = nt_handler.hosted_process_vspace(target_pi) else {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        if main_fault_ep == 0 {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let Some(worker_slot) = nt_handler.first_free_hosted_tp_worker_slot(target_pi) else {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        let Some((pool_slot, tid)) =
            nt_handler.claim_pool_thread(target_pi, start.rip, create_suspended)
        else {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        };
        let tid_id = tid as nt_process::ThreadId;
        let handle = match nt_handler.pm.insert_handle(
            caller_pid,
            nt_process::HandleObject::Thread(tid_id),
            desired_access,
        ) {
            Ok(handle) => handle as u64,
            Err(status) => {
                let _ = nt_handler
                    .pm
                    .set_thread_state(tid_id, nt_process::ThreadState::Initialized);
                nt_handler.release_pool_usage_slot(target_pi, pool_slot);
                return Err(status);
            }
        };
        if !nt_handler.set_pool_thread_suspended(target_pi, pool_slot, create_suspended) {
            let _ = nt_handler.close_process_handle(caller_pid, handle);
            let _ = nt_handler
                .pm
                .set_thread_state(tid_id, nt_process::ThreadState::Initialized);
            nt_handler.release_pool_usage_slot(target_pi, pool_slot);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        if !nt_handler.reserve_hosted_tp_worker_slot(target_pi, worker_slot, tid) {
            let _ = nt_handler.close_process_handle(caller_pid, handle);
            let _ = nt_handler
                .pm
                .set_thread_state(tid_id, nt_process::ThreadState::Initialized);
            nt_handler.set_pool_thread_suspended(target_pi, pool_slot, false);
            nt_handler.release_pool_usage_slot(target_pi, pool_slot);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let badged_fault_ep = mint_badged(main_fault_ep, tp_worker_badge(target_pi, worker_slot));
        let tcb = spawn_slot_thread(&RemoteThreadSpawn {
            target_pi,
            slot: worker_slot,
            pml4: target_pml4,
            start,
            cid_proc: target_pid as u64,
            cid_thread: tid,
            fault_ep: badged_fault_ep,
            use_loader: true,
            native: true,
            resume: !create_suspended,
        });
        if tcb == 0 {
            let _ = nt_handler.release_hosted_thread_runtime(tid);
            let _ = nt_handler.close_process_handle(caller_pid, handle);
            let _ = nt_handler
                .pm
                .set_thread_state(tid_id, nt_process::ThreadState::Initialized);
            nt_handler.set_pool_thread_suspended(target_pi, pool_slot, false);
            nt_handler.release_pool_usage_slot(target_pi, pool_slot);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }

        nt_handler
            .pm
            .set_thread_teb(tid_id, tp_worker_teb_va(worker_slot));
        let _ = nt_handler
            .pm
            .set_thread_create_time(tid_id, nt_system_time_100ns() as i64);
        nt_handler.register_hosted_thread_tcb(
            target_pi,
            tid,
            tcb,
            tp_worker_badge(target_pi, worker_slot),
            HostedThreadRole::TpWorker { slot: worker_slot },
        );
        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
        if target_pi == 1 {
            PM_GENERAL_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
        } else {
            PM_REMOTE_THREADS_CREATED.fetch_add(1, Ordering::Relaxed);
            PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
        }
        if !csr_stack_copyout(thread_handle_out, &handle.to_le_bytes()) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        if client_id_out != 0 {
            if !csr_stack_copyout(client_id_out, &(target_pid as u64).to_le_bytes())
                || !csr_stack_copyout(client_id_out + 8, &tid.to_le_bytes())
            {
                return Err(STATUS_ACCESS_VIOLATION);
            }
        }
        print_str(b"[csr-api] worker NtCreateThread target_pi=");
        print_u64(target_pi as u64);
        print_str(b" worker_slot=");
        print_u64(worker_slot as u64);
        print_str(b" pool_slot=");
        print_u64(pool_slot as u64);
        print_str(b" tid=");
        print_u64(tid);
        print_str(b" tcb=0x");
        print_hex(tcb as u32);
        print_str(b" entry=0x");
        print_hex((start.rip >> 32) as u32);
        print_hex(start.rip as u32);
        print_str(b" suspended=");
        print_u64(create_suspended as u64);
        print_str(b"\n");
        Ok(0)
    })()
    .unwrap_or_else(|status| status);

    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    status
}

/// Spawn the AUTHENTIC SM-loop thread (path B): the general hosted thread running smss's real
/// `SmpApiLoop` (`entry_rip`) with RCX = the `\SmApiPort` handle (`port_handle`). Its stack is
/// MIRRORED into the executive so `sm_rendezvous` can write its syscall out-params. It faults to
/// `SM_FAULT_EP` (no standing receiver) and is resumed at spawn → PARKS on its first fault.
pub(crate) unsafe fn spawn_sm_loop_thread(
    smss_pml4: u64,
    entry_rip: u64,
    port_handle: u64,
    cid_proc: u64,
    cid_thread: u64,
) -> u64 {
    // BATCH 6: smss (pi 0) runs on OUR ntdll's NATIVE seL4-Call transport, so its SmpApiLoop 2nd
    // thread must too. The hosted-syscalls flag is hybrid now: OUR ntdll's `Call(CT_FAULT,
    // label=0x4E54)` still arrives natively with MR0=SSN, while raw Windows syscall stubs fault as NT
    // syscalls. Its private IPC frame lives at the VA ntdll derives from the active TEB.
    spawn_hosted_thread(&HostedThread {
        pml4: smss_pml4,
        client_pi: 0,
        entry_rip,
        arg0: port_handle,
        arg1: 0,
        loader_context: None,
        scr: SM_ENV_SCRATCH_VA,
        teb_va: SM_TEB_VA,
        stack_base: SM_STACK_BASE,
        stack_frames: SM_STACK_FRAMES,
        ipcbuf_va: SM_IPCBUF_VA,
        tramp_va: SM_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: SM_STACK_MIRROR_VA,
        fault_ep: SM_FAULT_EP.load(Ordering::Relaxed),
        cid_proc,
        cid_thread,
        resume: true,
        prio: 0,
        native: true,
        diag: false,
    })
}

/// Write a u64 to the SM-loop thread's stack (via the executive's SM_STACK_MIRROR alias), for a
/// syscall out-param that lives on its stack (RequestMsg / PortHandle / PROCESS_BASIC_INFORMATION).
pub(crate) unsafe fn sm_stack_write(va: u64, v: u64) {
    if va >= SM_STACK_BASE && va + 8 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u64, v);
    } else if va >= SMSS_ALLOC_VA && va + 8 <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        core::ptr::write_volatile((SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)) as *mut u64, v);
    }
}
/// Write a u16 to the SM-loop thread's stack (for PORT_MESSAGE.Type@0x04).
pub(crate) unsafe fn sm_stack_write16(va: u64, v: u16) {
    if va >= SM_STACK_BASE && va + 2 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u16, v);
    } else if va >= SMSS_ALLOC_VA && va + 2 <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        core::ptr::write_volatile((SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)) as *mut u16, v);
    }
}
pub(crate) unsafe fn sm_stack_write32(va: u64, v: u32) {
    if va >= SM_STACK_BASE && va + 4 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u32, v);
    } else if va >= SMSS_ALLOC_VA && va + 4 <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        core::ptr::write_volatile((SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)) as *mut u32, v);
    }
}
pub(crate) unsafe fn sm_stack_read(va: u64) -> u64 {
    if va >= SM_STACK_BASE && va + 8 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::read_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *const u64)
    } else if va >= SMSS_ALLOC_VA && va + 8 <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW {
        core::ptr::read_volatile((SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)) as *const u64)
    } else {
        0
    }
}
fn sm_stack_has_range(va: u64, len: usize) -> bool {
    let Some(end) = va.checked_add(len as u64) else {
        return false;
    };
    va >= SM_STACK_BASE && end <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000
        || va >= SMSS_ALLOC_VA && end <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW
}

unsafe fn sm_stack_copyout(va: u64, bytes: &[u8]) -> bool {
    if !sm_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= SM_STACK_BASE {
        SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)
    } else {
        SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), mirror as *mut u8, bytes.len());
    true
}
unsafe fn sm_stack_copyin(va: u64, bytes: &mut [u8]) -> bool {
    if !sm_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= SM_STACK_BASE {
        SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)
    } else {
        SMSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(mirror as *const u8, bytes.as_mut_ptr(), bytes.len());
    true
}

unsafe fn sm_capture_object_attributes(address: u64) -> Option<nt_ntdll_layout::ObjectAttributes> {
    let mut value = core::mem::MaybeUninit::<nt_ntdll_layout::ObjectAttributes>::uninit();
    let bytes = core::slice::from_raw_parts_mut(
        value.as_mut_ptr().cast::<u8>(),
        core::mem::size_of::<nt_ntdll_layout::ObjectAttributes>(),
    );
    sm_stack_copyin(address, bytes).then(|| value.assume_init())
}

unsafe fn sm_capture_client_id(address: u64) -> Option<nt_ntdll_layout::ClientId> {
    let mut value = core::mem::MaybeUninit::<nt_ntdll_layout::ClientId>::uninit();
    let bytes = core::slice::from_raw_parts_mut(
        value.as_mut_ptr().cast::<u8>(),
        core::mem::size_of::<nt_ntdll_layout::ClientId>(),
    );
    sm_stack_copyin(address, bytes).then(|| value.assume_init())
}

unsafe fn sm_open_process_call(
    nt_handler: &mut ExecNtHandler,
    process_handle: u64,
    desired_access: u32,
    object_attributes: u64,
    client_id: u64,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    if !sm_stack_has_range(process_handle, core::mem::size_of::<u64>()) {
        return STATUS_ACCESS_VIOLATION;
    }
    let client_id = if client_id == 0 {
        None
    } else {
        if client_id & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let Some(client_id) = sm_capture_client_id(client_id) else {
            return STATUS_ACCESS_VIOLATION;
        };
        Some(client_id)
    };
    if object_attributes & 3 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    let Some(object_attributes) = sm_capture_object_attributes(object_attributes) else {
        return STATUS_ACCESS_VIOLATION;
    };
    let saved_pi = nt_handler.pi;
    nt_handler.pi = 0;
    let result =
        match nt_handler.open_process_captured(object_attributes, client_id, desired_access) {
            Ok((owner, handle)) => {
                if sm_stack_copyout(process_handle, &(handle as u64).to_le_bytes()) {
                    nt_handler.account_published_pm_handle(owner);
                    0
                } else {
                    let _ = nt_handler.pm.take_handle(owner, handle);
                    STATUS_ACCESS_VIOLATION
                }
            }
            Err(status) => status as u64,
        };
    nt_handler.pi = saved_pi;
    result
}

unsafe fn sm_open_thread_call(
    nt_handler: &mut ExecNtHandler,
    thread_handle: u64,
    desired_access: u32,
    object_attributes: u64,
    client_id: u64,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    if !sm_stack_has_range(thread_handle, core::mem::size_of::<u64>()) {
        return STATUS_ACCESS_VIOLATION;
    }
    let client_id = if client_id == 0 {
        None
    } else {
        if client_id & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let Some(client_id) = sm_capture_client_id(client_id) else {
            return STATUS_ACCESS_VIOLATION;
        };
        Some(client_id)
    };
    if object_attributes & 3 != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    let Some(object_attributes) = sm_capture_object_attributes(object_attributes) else {
        return STATUS_ACCESS_VIOLATION;
    };
    let saved_pi = nt_handler.pi;
    nt_handler.pi = 0;
    let result = match nt_handler.open_thread_captured(object_attributes, client_id, desired_access)
    {
        Ok((owner, handle)) => {
            if sm_stack_copyout(thread_handle, &(handle as u64).to_le_bytes()) {
                nt_handler.account_published_pm_handle(owner);
                0
            } else {
                let _ = nt_handler.pm.take_handle(owner, handle);
                STATUS_ACCESS_VIOLATION
            }
        }
        Err(status) => status as u64,
    };
    nt_handler.pi = saved_pi;
    result
}

unsafe fn sm_set_thread_information_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information_class: u32,
    information: u64,
    information_length: u32,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    let expected = match ExecNtHandler::thread_set_length(information_class) {
        Ok(length) => length,
        Err(status) => return status as u64,
    };
    if information_length as usize != expected {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as u64;
    }
    let mut value = [0u8; 0x10];
    if expected != 0 {
        let alignment_mask = if information_class == 38 { 7 } else { 3 };
        if information & alignment_mask != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !sm_stack_copyin(information, &mut value[..expected]) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if information_class == 38 {
        let raw_byte_length = u16::from_le_bytes(value[..2].try_into().unwrap()) as usize;
        let mut byte_length = raw_byte_length & !1;
        let buffer = u64::from_le_bytes(value[8..16].try_into().unwrap());
        if buffer == 0 {
            byte_length = 0;
        }
        let saved_pi = nt_handler.pi;
        let saved_tid = nt_handler.current_tid;
        nt_handler.pi = 0;
        nt_handler.current_tid = hosted_role_tid(nt_handler, 0, HostedThreadRole::SmLoop);
        let target = nt_handler.resolve_thread_for_set(handle);
        nt_handler.pi = saved_pi;
        nt_handler.current_tid = saved_tid;
        let target = match target {
            Ok(tid) => tid,
            Err(status) => return status as u64,
        };
        if buffer != 0 && raw_byte_length != 0 {
            if buffer & 1 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            let mut last = [0u8; 1];
            let Some(last_address) = buffer.checked_add(raw_byte_length as u64 - 1) else {
                return STATUS_ACCESS_VIOLATION;
            };
            if !sm_stack_copyin(last_address, &mut last) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if byte_length > nt_process::THREAD_NAME_MAX_UNITS * 2 {
            return 0xC000_009A;
        }
        let mut bytes = [0u8; nt_process::THREAD_NAME_MAX_UNITS * 2];
        if byte_length != 0 && !sm_stack_copyin(buffer, &mut bytes[..byte_length]) {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
        for (index, chunk) in bytes[..byte_length].chunks_exact(2).enumerate() {
            name[index] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        return nt_handler.set_thread_name_resolved(target, &name[..byte_length / 2]) as u64;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 0;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 0, HostedThreadRole::SmLoop);
    let status = nt_handler.set_thread_information_captured(
        handle,
        information_class,
        u64::from_le_bytes(value[..8].try_into().unwrap()),
    );
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    status as u64
}

unsafe fn sm_query_thread_information_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information_class: u32,
    information: u64,
    information_length: u32,
    return_length: u64,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
    if information_class == 38 {
        if information != 0 {
            if information & 7 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if !sm_stack_has_range(information, information_length as usize) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        if return_length != 0 && !sm_stack_has_range(return_length, 4) {
            return STATUS_ACCESS_VIOLATION;
        }
        let saved_pi = nt_handler.pi;
        let saved_tid = nt_handler.current_tid;
        nt_handler.pi = 0;
        nt_handler.current_tid = hosted_role_tid(nt_handler, 0, HostedThreadRole::SmLoop);
        let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
        let query = nt_handler.query_thread_name_captured(handle, &mut name);
        nt_handler.pi = saved_pi;
        nt_handler.current_tid = saved_tid;
        let mut required = 0u32;
        let mut status = match query {
            Ok(units) => {
                required = (0x10 + units * 2) as u32;
                if information_length < required {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    let mut output = [0u8; 0x10 + nt_process::THREAD_NAME_MAX_UNITS * 2];
                    if units != 0 {
                        let bytes = (units * 2) as u16;
                        output[..2].copy_from_slice(&bytes.to_le_bytes());
                        output[2..4].copy_from_slice(&bytes.to_le_bytes());
                        output[8..16].copy_from_slice(&(information + 0x10).to_le_bytes());
                        for (index, unit) in name[..units].iter().enumerate() {
                            output[0x10 + index * 2..0x12 + index * 2]
                                .copy_from_slice(&unit.to_le_bytes());
                        }
                    }
                    if sm_stack_copyout(information, &output[..required as usize]) {
                        0
                    } else {
                        STATUS_ACCESS_VIOLATION
                    }
                }
            }
            Err(status) => status as u64,
        };
        if return_length != 0 && !sm_stack_copyout(return_length, &required.to_le_bytes()) {
            status = STATUS_ACCESS_VIOLATION;
        }
        return status;
    }

    let expected = match ExecNtHandler::thread_query_length(information_class) {
        Ok(length) => length,
        Err(status) => return status as u64,
    };
    if information_length as usize != expected {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as u64;
    }
    if information != 0 {
        if information & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let mut probe = [0u8; 0x30];
        if !sm_stack_copyin(information, &mut probe[..expected]) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if return_length != 0 && !sm_stack_has_range(return_length, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 0;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 0, HostedThreadRole::SmLoop);
    let mut status = match nt_handler.query_thread_information_captured(handle, information_class) {
        Ok((output, length)) => {
            if sm_stack_copyout(information, &output[..length]) {
                0
            } else {
                STATUS_ACCESS_VIOLATION
            }
        }
        Err(status) => status as u64,
    };
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    if return_length != 0 && !sm_stack_copyout(return_length, &(expected as u32).to_le_bytes()) {
        status = STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Demand-fill one code/data page for the SM-loop thread during the rendezvous. The page is in smss's
/// own image (PE_LOAD_BASE..img_end → `smss_pe`) or ntdll (nt_base..nt_end → `ntdll_pe`); it is filled
/// through an isolated executive scratch (SM_FILL_SCRATCH_BASE, its own PT) then mapped into smss's
/// VSpace (shared with the main thread, so this only happens once per page). Returns false if the page
/// belongs to neither image (a genuine fault the rendezvous can't resolve).
pub(crate) unsafe fn sm_fill_page(
    page: u64,
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    fill_idx: &mut u64,
) -> bool {
    let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
        (PE_LOAD_BASE, smss_pe)
    } else if nt_base != 0 && page >= nt_base && page < nt_end {
        match ntdll_pe {
            Some(p) => (nt_base, p),
            None => return false,
        }
    } else {
        return false;
    };
    // Ensure the isolated fill-scratch PT exists (once).
    if SM_FILL_PT_DONE.swap(1, Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(
            spt,
            LBL_X86_PAGE_TABLE_MAP,
            SM_FILL_SCRATCH_BASE,
            CAP_INIT_THREAD_VSPACE,
        );
    }
    // Monotonic scratch slot (one PT = 512 pages; the SM-loop thread faults far fewer, so no wrap).
    let scratch = SM_FILL_SCRATCH_BASE + (*fill_idx).min(511) * 0x1000;
    *fill_idx += 1;
    let f = alloc_frame();
    let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    let rights = fill_image_page(tpe, (page - base) as u32, scratch);
    let _ = page_map(copy_cap(f), page, rights, smss_pml4);
    true
}

/// AUTHENTIC SM accept (path B): drive smss's REAL `SmpApiLoop` thread through one connection
/// rendezvous. Called synchronously from the main loop when csrss's `NtConnectPort` leaves the broker
/// connection `conn_id` Pending (Manual policy). A nested loop on `SM_FAULT_EP`/`REPLY_SMLOOP`
/// (mirroring `win32k_dispatch`, but the SM-loop thread is a HOSTED faulter, not a Call peer) services
/// its real syscalls until `NtCompleteConnectPort`: the preamble (RtlSetThreadIsCritical →
/// NtSetInformationThread no-op; NtQueryInformationProcess ProcessBasicInformation → write
/// UniqueProcessId = PID_SMSS), then NtReplyWaitReceivePort (drain the pending connection from the
/// broker + marshal the PORT_MESSAGE: Type=LPC_CONNECTION_REQUEST, ClientId.UniqueProcess=PID_SMSS →
/// the "SM connecting to itself" branch of SmpHandleConnectionRequest, no NtOpenProcess/SB connect-back)
/// → NtAcceptConnectPort (broker accept) → NtCompleteConnectPort (broker complete). Demand-fills the
/// thread's code/data faults + skips int-0x2d DPRINTs. Returns the client comm-port handle (0 on
/// failure), which the caller writes to csrss's *PortHandle. Leaves the thread re-parked on its next
/// NtReplyWaitReceivePort (no pending connection).
pub(crate) unsafe fn sm_rendezvous(
    conn_id: u64,
    connector_pi: usize,
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    csrss_img_end: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &mut ExecNtHandler,
) -> u64 {
    const SSN_SET_INFO_THREAD: u64 = 238;
    const SSN_QUERY_INFO_THREAD: u64 = 162;
    const SSN_QUERY_INFO_PROCESS: u64 = 161;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    const SSN_CONNECT_PORT: u64 = 33;
    const SSN_SET_EVENT: u64 = 228;
    const SSN_CLOSE: u64 = 27;
    let ep = SM_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_SMLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return 0;
    }
    let mut client_handle = 0u64;
    let mut fill_idx = 0u64;
    let mut guard = 0u64;
    let (connector_pid, connector_tid) = live_hosted_cid_for_pi(nt_handler, connector_pi);
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) =
        if SM_RECEIVE_PARKED.swap(0, Ordering::Relaxed) != 0 {
            let recvmsg = SM_RECVMSG.load(Ordering::Relaxed);
            let port = SM_RECVPORT.load(Ordering::Relaxed);
            let Some(received) = lpc_client().and_then(|c| c.reply_wait_receive(port).ok()) else {
                SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                return 0;
            };
            if received.connection_id != conn_id {
                SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                return 0;
            }
            sm_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
            sm_stack_write(recvmsg + 0x08, connector_pid);
            sm_stack_write(recvmsg + 0x10, connector_tid);
            sm_stack_write32(recvmsg + 0x28, received.subsystem_type);
            for (i, chunk) in received
                .connection_info
                .chunks_exact(2)
                .take(120)
                .enumerate()
            {
                sm_stack_write16(
                    recvmsg + 0x2c + i as u64 * 2,
                    u16::from_le_bytes([chunk[0], chunk[1]]),
                );
            }
            print_str(b"[sm-rdv] resumed parked receive for pi=");
            print_u64(connector_pi as u64);
            print_str(b" cid=");
            print_u64(connector_pid);
            print_str(b"/");
            print_u64(connector_tid);
            print_str(b"\n");
            set_reply_mr(15, 0);
            set_reply_mr(16, SM_RECV_SP.load(Ordering::Relaxed));
            set_reply_mr(17, SM_RECV_FLAGS.load(Ordering::Relaxed));
            client_reply_on(reply, 18, 0, 0, 0, SM_RECV_RDX.load(Ordering::Relaxed));
            recv_full_r12(ep, reply)
        } else {
            recv_full_r12(ep, reply)
        };
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[sm-rdv] WALL: guard exhausted\n");
            break;
        }
        // BATCH 6: the SM-loop thread runs on OUR ntdll's NATIVE seL4-Call transport, so its Nt*
        // syscalls arrive as a native `Call` (label NT_NATIVE_SYSCALL_LABEL), NOT an UnknownSyscall
        // fault (label 2). NORMALIZE it into the label-2 register-slot layout the accept body below
        // reads — exactly like the main service loop (`service_sec_image.rs`): MR0=SSN, MR1=rsp,
        // MR2/MR3=arg1/arg2, MR4/MR5=arg3/arg4 (from the executive's recv IPC buffer) → the fault
        // frame slots R10@9=arg1, R8@7=arg3, R9@8=arg4, SP@16=rsp, FLAGS@17=0; then re-label as 2.
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0; // MR0
            let rsp = m1; // MR1 = caller rsp
            let arg1 = m2; // MR2
            let arg3 = get_recv_mr(4); // MR4 (IPC buffer)
            let arg4 = get_recv_mr(5); // MR5 (IPC buffer)
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn; // the accept body reads ssn = m0
            m2 = 0; // resume_ip unused for a native reply (no fault restart)
            mi = (2u64 << 12) | (mi & 0x7F);
        }
        let label = mi >> 12;
        if label == 6 {
            // VMFault: demand-fill an smss/ntdll code or data page for the SM-loop thread.
            let page = m1 & !0xFFFu64;
            if m1 < 0x10000
                || !sm_fill_page(
                    page,
                    smss_pml4,
                    smss_pe,
                    img_end,
                    nt_base,
                    nt_end,
                    ntdll_pe,
                    &mut fill_idx,
                )
            {
                print_str(b"[sm-rdv] WALL: unresolved fault ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((m1 >> 32) as u32);
                print_hex(m1 as u32);
                print_str(b"\n");
                break;
            }
            client_reply_on(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        if label == 3 {
            // Debug ntdll int-0x2d (DbgPrint from a DPRINT1) — skip the `int 0x2d; int3` (3 bytes),
            // like the main loop. m0 = FaultIP.
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base
                    && fip < nt_end
                    && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD)
                {
                    client_reply_on(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
            }
            print_str(b"[sm-rdv] WALL: exception fip=0x");
            print_hex((fip >> 32) as u32);
            print_hex(fip as u32);
            print_str(b" num=");
            print_u64(m3);
            print_str(b"\n");
            break;
        }
        if label == 2 {
            // A real Nt* syscall from SmpApiLoop.
            let ssn = m0;
            let resume_ip = m2;
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let rdx = m3;
            let mut result = 0u64;
            let mut stop_rdv = false;
            if guard < 64 {
                print_str(b"[sm-rdv] worker SSN=");
                print_u64(ssn);
                print_str(b"\n");
            }
            match ssn {
                SSN_SET_INFO_THREAD => {
                    result = sm_set_thread_information_call(
                        nt_handler,
                        get_recv_mr(9),
                        rdx as u32,
                        get_recv_mr(7),
                        get_recv_mr(8) as u32,
                    );
                }
                SSN_QUERY_INFO_THREAD => {
                    result = match sp
                        .checked_add(0x28)
                        .filter(|address| sm_stack_has_range(*address, 8))
                    {
                        Some(address) => sm_query_thread_information_call(
                            nt_handler,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8) as u32,
                            sm_stack_read(address),
                        ),
                        None => 0xC000_0005,
                    };
                }
                SSN_NT_OPEN_PROCESS => {
                    // SmpHandleConnectionRequest opens the connecting CSRSS process by the real CID.
                    // Mint the handle in SMSS's real table; SmpSbCreateSession later uses the saved
                    // CSRSS process handle as NtDuplicateObject's target process.
                    result = sm_open_process_call(
                        nt_handler,
                        get_recv_mr(9),
                        rdx as u32,
                        get_recv_mr(7),
                        get_recv_mr(8),
                    );
                }
                SSN_NT_OPEN_THREAD => {
                    result = sm_open_thread_call(
                        nt_handler,
                        get_recv_mr(9),
                        rdx as u32,
                        get_recv_mr(7),
                        get_recv_mr(8),
                    );
                }
                SSN_QUERY_INFO_PROCESS => {
                    // ProcessBasicInformation initializes SmUniqueProcessId from the real SMSS
                    // EPROCESS identity; the later SMSS connection request carries the same CID.
                    let class = rdx;
                    let buf = get_recv_mr(7); // R8 = buffer
                    if class == 0 {
                        sm_stack_write(
                            buf + 0x20,
                            live_hosted_pid_for_leaf(nt_handler, b"smss.exe").unwrap_or(0) as u64,
                        );
                    } else if class == 24 {
                        sm_stack_write32(buf, 0); // ProcessSessionInformation: session 0
                    }
                }
                SSN_REPLY_WAIT_RECV => {
                    let recvmsg = get_recv_mr(8); // R9 = &RequestMsg.h
                    let port = get_recv_mr(9); // R10 = SmApiPort handle
                    let got = lpc_client().and_then(|c| c.reply_wait_receive(port).ok());
                    match got {
                        Some(r) if r.connection_id != 0 => {
                            // Marshal the connection-request PORT_MESSAGE onto the SM-loop stack.
                            sm_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST); // u2.s2.Type
                            sm_stack_write(recvmsg + 0x08, connector_pid);
                            sm_stack_write(recvmsg + 0x10, connector_tid);
                            sm_stack_write32(recvmsg + 0x28, r.subsystem_type);
                            for (i, chunk) in
                                r.connection_info.chunks_exact(2).take(120).enumerate()
                            {
                                sm_stack_write16(
                                    recvmsg + 0x2c + i as u64 * 2,
                                    u16::from_le_bytes([chunk[0], chunk[1]]),
                                );
                            }
                            print_str(b"[sm-rdv] delivered connection cid=");
                            print_u64(connector_pid);
                            print_str(b"/");
                            print_u64(connector_tid);
                            print_str(b" subsystem=");
                            print_u64(r.subsystem_type as u64);
                            print_str(b" info_len=");
                            print_u64(r.connection_info.len() as u64);
                            print_str(b"\n");
                        }
                        _ => {
                            // No pending connection (the 2nd receive): leave the thread PARKED — do NOT
                            // reply. It re-blocks on this NtReplyWaitReceivePort until the next connect.
                            SM_RECVMSG.store(recvmsg, Ordering::Relaxed);
                            SM_RECVPORT.store(port, Ordering::Relaxed);
                            SM_RECV_SP.store(sp, Ordering::Relaxed);
                            SM_RECV_FLAGS.store(flags, Ordering::Relaxed);
                            SM_RECV_RDX.store(rdx, Ordering::Relaxed);
                            SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                            stop_rdv = true;
                        }
                    }
                }
                SSN_ACCEPT_CONNECT => {
                    let porthandle_out = get_recv_mr(9); // R10 = *PortHandle
                    let accept = get_recv_mr(8); // R9 = Accept BOOLEAN
                    let sh = lpc_client()
                        .and_then(|c| c.accept_connect(conn_id, accept != 0, rdx).ok())
                        .unwrap_or(0);
                    sm_stack_write(porthandle_out, sh);
                }
                SSN_COMPLETE_CONNECT => {
                    if let Some((ch, _)) =
                        lpc_client().and_then(|c| c.complete_connect(conn_id).ok())
                    {
                        client_handle = ch;
                    }
                    print_str(b"[sm-rdv] forward NtCompleteConnectPort replied; awaiting reverse connect\n");
                    // Continue into SmpHandleConnectionRequest's reverse connection and real event set.
                }
                SSN_CONNECT_PORT => {
                    let out = get_recv_mr(9);
                    let sb_name: alloc::vec::Vec<u16> =
                        "\\Windows\\SbApiPort".encode_utf16().collect();
                    let reverse = lpc_client().and_then(|c| c.connect_port(&sb_name, 0, &[]).ok());
                    match reverse {
                        Some(r) if r.pending => {
                            let handle = csr_sb_accept_connection(
                                r.connection_id,
                                csrss_pml4,
                                csrss_pe,
                                csrss_img_end,
                                nt_base,
                                nt_end,
                                ntdll_pe,
                                reg,
                                dll_pes,
                                nt_handler,
                            );
                            if handle == 0 {
                                result = 0xC000_0001;
                                stop_rdv = true;
                            } else {
                                sm_stack_write(out, handle);
                            }
                        }
                        Some(r) if r.handle != 0 => sm_stack_write(out, r.handle),
                        _ => {
                            result = 0xC000_0001;
                            stop_rdv = true;
                        }
                    }
                }
                SSN_SET_EVENT => {
                    let event_handle = get_recv_mr(9);
                    let saved_pi = nt_handler.pi;
                    nt_handler.pi = 0;
                    result =
                        match nt_handler.event_index_for_handle(event_handle, EVENT_MODIFY_STATE) {
                            Ok(index) => match nt_handler.events.set_existing(index as u64) {
                                Some(previous) => {
                                    if !previous {
                                        wait_wake_dispatcher_set(nt_handler);
                                    }
                                    print_str(
                                        b"[sm-rdv] real NtSetEvent completed subsystem readiness\n",
                                    );
                                    0
                                }
                                None => 0xC000_0008,
                            },
                            Err(status) => status as u64,
                        };
                    nt_handler.pi = saved_pi;
                }
                SSN_CLOSE => {
                    let saved_pi = nt_handler.pi;
                    nt_handler.pi = 0;
                    nt_handler.close_current_handle(get_recv_mr(9));
                    nt_handler.pi = saved_pi;
                }
                _ => {
                    print_str(b"[sm-rdv] WALL: unexpected SSN=");
                    print_u64(ssn);
                    print_str(b"\n");
                    stop_rdv = true;
                }
            }
            if stop_rdv {
                break;
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            client_reply_on(reply, 18, result, 0, 0, rdx);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        print_str(b"[sm-rdv] WALL: unexpected label=");
        print_u64(label);
        print_str(b"\n");
        break;
    }
    client_handle
}

/// Deliver one synchronous SMSS request to the already-parked real `SmpApiLoop`. The LPC broker
/// owns the byte queues and listen-port reply association; this driver owns the two seL4
/// continuations and services the worker's nested kernel calls until it either replies or reaches
/// the nested SB request that the next increment must dispatch.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn sm_api_request_rendezvous(
    client_port: u64,
    request_va: u64,
    reply_va: u64,
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    csrss_img_end: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &mut ExecNtHandler,
) -> bool {
    const SSN_QUERY_INFO_PROCESS: u64 = 161;
    const SSN_DUPLICATE_OBJECT: u64 = 71;
    const SSN_REQUEST_WAIT_REPLY: u64 = 208;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_CLOSE: u64 = 27;
    const SSN_SET_INFO_THREAD: u64 = 238;
    const SSN_QUERY_INFO_THREAD: u64 = 162;
    const DUPLICATE_CLOSE_SOURCE: u32 = 1;
    const DUPLICATE_SAME_ACCESS: u32 = 2;

    let ep = SM_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_SMLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 || SM_RECEIVE_PARKED.swap(0, Ordering::Relaxed) == 0 {
        return false;
    }

    let mut length_bytes = [0u8; 4];
    if !nt_handler.xas_read(request_va, &mut length_bytes) {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let request_len = u16::from_le_bytes([length_bytes[2], length_bytes[3]]) as usize;
    if !(0x28..=0x148).contains(&request_len) {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let mut request = [0u8; 0x148];
    if !nt_handler.xas_read(request_va, &mut request[..request_len]) {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let smss_pid = live_hosted_pid_for_leaf(nt_handler, b"smss.exe").unwrap_or(0) as u64;
    let smss_tid = live_hosted_main_tid_for_leaf(nt_handler, b"smss.exe").unwrap_or(0) as u64;
    request[4..6].copy_from_slice(&nt_lpc_abi::msg_type::LPC_REQUEST.to_le_bytes());
    request[8..16].copy_from_slice(&smss_pid.to_le_bytes());
    request[16..24].copy_from_slice(&smss_tid.to_le_bytes());
    if request_len >= 0x7c {
        print_str(b"[sm-api] SmExecPgm wire subsystem=");
        print_u64(u32::from_le_bytes(request[0x78..0x7c].try_into().unwrap()) as u64);
        print_str(b"\n");
    }
    let sent = lpc_client()
        .and_then(|client| {
            client
                .request_wait_reply(client_port, &request[..request_len])
                .ok()
        })
        .is_some();
    if !sent {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }

    let listen_port = SM_RECVPORT.load(Ordering::Relaxed);
    let Some(received) =
        lpc_client().and_then(|client| client.reply_wait_receive(listen_port).ok())
    else {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    };
    let recvmsg = SM_RECVMSG.load(Ordering::Relaxed);
    if received.connection_info.len() != request_len
        || !sm_stack_copyout(recvmsg, &received.connection_info)
    {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    sm_stack_write16(recvmsg + 4, nt_lpc_abi::msg_type::LPC_REQUEST);
    sm_stack_write(recvmsg + 8, smss_pid);
    sm_stack_write(recvmsg + 16, smss_tid);
    let context_out = SM_RECV_RDX.load(Ordering::Relaxed);
    if context_out != 0 {
        sm_stack_write(context_out, received.port_context);
    }
    set_reply_mr(15, 0);
    set_reply_mr(16, SM_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, SM_RECV_FLAGS.load(Ordering::Relaxed));
    client_reply_on(reply, 18, 0, 0, 0, 0);

    let mut fill_idx = 0;
    let (_badge, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    for _ in 0..8000 {
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0;
            let rsp = m1;
            let arg1 = m2;
            let arg3 = get_recv_mr(4);
            let arg4 = get_recv_mr(5);
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn;
            m2 = 0;
            mi = (2u64 << 12) | (mi & 0x7f);
        }
        match mi >> 12 {
            6 => {
                let page = m1 & !0xfff;
                if m1 < 0x10000
                    || !sm_fill_page(
                        page,
                        smss_pml4,
                        smss_pe,
                        img_end,
                        nt_base,
                        nt_end,
                        ntdll_pe,
                        &mut fill_idx,
                    )
                {
                    print_str(b"[sm-api] unresolved worker fault\n");
                    return false;
                }
                client_reply_on(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                client_reply_on(reply, 3, m0 + 3, m1, m2, 0);
            }
            2 => {
                let ssn = m0;
                let sp = get_recv_mr(16);
                let flags = get_recv_mr(17);
                let rdx = m3;
                let mut result = 0u64;
                print_str(b"[sm-api] worker SSN=");
                print_u64(ssn);
                print_str(b"\n");
                match ssn {
                    SSN_SET_INFO_THREAD => {
                        result = sm_set_thread_information_call(
                            nt_handler,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8) as u32,
                        );
                    }
                    SSN_QUERY_INFO_THREAD => {
                        result = match sp
                            .checked_add(0x28)
                            .filter(|address| sm_stack_has_range(*address, 8))
                        {
                            Some(address) => sm_query_thread_information_call(
                                nt_handler,
                                get_recv_mr(9),
                                rdx as u32,
                                get_recv_mr(7),
                                get_recv_mr(8) as u32,
                                sm_stack_read(address),
                            ),
                            None => 0xC000_0005,
                        };
                    }
                    SSN_NT_OPEN_PROCESS => {
                        result = sm_open_process_call(
                            nt_handler,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8),
                        );
                    }
                    SSN_NT_OPEN_THREAD => {
                        result = sm_open_thread_call(
                            nt_handler,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8),
                        );
                    }
                    SSN_QUERY_INFO_PROCESS => {
                        let class = rdx;
                        let buffer = get_recv_mr(7);
                        if class == 0 {
                            sm_stack_write(buffer + 0x20, smss_pid);
                        } else if class == 24 {
                            sm_stack_write32(buffer, 0);
                        }
                    }
                    SSN_DUPLICATE_OBJECT => {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 0;
                        let source_process = get_recv_mr(9);
                        let source_handle = rdx;
                        let target_process = get_recv_mr(7);
                        let target_out = get_recv_mr(8);
                        let options = sm_stack_read(sp + 0x38) as u32;
                        let source_pid = nt_handler.resolve_process_handle(source_process);
                        let target_pid = nt_handler.resolve_process_handle(target_process);
                        result = match (source_pid, target_pid) {
                            (Some(source_pid), Some(target_pid)) => {
                                let desired_access = (options & DUPLICATE_SAME_ACCESS == 0)
                                    .then_some(sm_stack_read(sp + 0x28) as u32);
                                match nt_handler.duplicate_process_handle_with_access(
                                    source_pid,
                                    source_handle as nt_process::Handle,
                                    target_pid,
                                    desired_access,
                                ) {
                                    Ok(handle) => {
                                        sm_stack_write(target_out, handle as u64);
                                        PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                                        0
                                    }
                                    Err(status) => status as u64,
                                }
                            }
                            _ => nt_process::STATUS_INVALID_HANDLE as u64,
                        };
                        if options & DUPLICATE_CLOSE_SOURCE != 0 {
                            if let Some(source_pid) = source_pid {
                                let _ = nt_handler.close_process_handle(source_pid, source_handle);
                            }
                        }
                        nt_handler.pi = saved_pi;
                    }
                    SSN_CLOSE => {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 0;
                        nt_handler.close_current_handle(get_recv_mr(9));
                        nt_handler.pi = saved_pi;
                    }
                    SSN_REQUEST_WAIT_REPLY => {
                        print_str(b"[sm-api] driving nested SbpCreateSession request\n");
                        if !csr_sb_api_request_rendezvous(
                            get_recv_mr(9),
                            rdx,
                            get_recv_mr(7),
                            csrss_pml4,
                            csrss_pe,
                            csrss_img_end,
                            nt_base,
                            nt_end,
                            ntdll_pe,
                            reg,
                            dll_pes,
                            nt_handler,
                        ) {
                            return false;
                        }
                    }
                    SSN_REPLY_WAIT_RECV => {
                        let reply_msg = get_recv_mr(7);
                        let mut reply_bytes = [0u8; 0x148];
                        let reply_len = if reply_msg != 0 {
                            let total = ((sm_stack_read(reply_msg) >> 16) as u16) as usize;
                            if !(0x28..=0x148).contains(&total)
                                || !sm_stack_copyin(reply_msg, &mut reply_bytes[..total])
                            {
                                return false;
                            }
                            total
                        } else {
                            0
                        };
                        let _ = lpc_client().and_then(|client| {
                            client
                                .reply_wait_receive_with_reply(
                                    listen_port,
                                    &reply_bytes[..reply_len],
                                )
                                .ok()
                        });
                        let Some(response) = lpc_client()
                            .and_then(|client| client.reply_wait_receive(client_port).ok())
                        else {
                            return false;
                        };
                        if response.connection_info.is_empty()
                            || !nt_handler.xas_try_write_buf(reply_va, &response.connection_info)
                        {
                            return false;
                        }
                        SM_RECVMSG.store(get_recv_mr(8), Ordering::Relaxed);
                        SM_RECVPORT.store(get_recv_mr(9), Ordering::Relaxed);
                        SM_RECV_SP.store(sp, Ordering::Relaxed);
                        SM_RECV_FLAGS.store(flags, Ordering::Relaxed);
                        SM_RECV_RDX.store(rdx, Ordering::Relaxed);
                        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                        print_str(b"[sm-api] real SmpApiLoop reply completed\n");
                        return true;
                    }
                    _ => {
                        print_str(b"[sm-api] unexpected worker SSN=");
                        print_u64(ssn);
                        print_str(b"\n");
                        return false;
                    }
                }
                set_reply_mr(15, 0);
                set_reply_mr(16, sp);
                set_reply_mr(17, flags);
                client_reply_on(reply, 18, result, 0, 0, rdx);
            }
            _ => return false,
        }
        let (_badge, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    false
}

/// Drive one ordinary `\Windows\ApiPort` request through the real CsrApiRequestThread. The worker
/// receives the brokered bytes on its listen port, executes csrsrv's dispatcher, sends the reply from
/// its next NtReplyWaitReceivePort, and remains parked for the following CSR API request.
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn csr_api_request_rendezvous(
    client_port: u64,
    request_va: u64,
    reply_va: u64,
    csrss_pml4: u64,
    main_fault_ep: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &mut ExecNtHandler,
) -> bool {
    const CSR_API_MSG_MAX: usize = 0x178;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_MAP_VIEW: u64 = 113;
    const SSN_SET_EVENT: u64 = 228;
    const SSN_CLOSE: u64 = 27;
    const SSN_QUERY_OBJECT: u64 = 170;
    const SSN_SET_INFO_OBJECT: u64 = 236;
    const SSN_RESUME_THREAD: u64 = 214;
    const SSN_DUPLICATE_OBJECT: u64 = 71;
    const DUPLICATE_CLOSE_SOURCE: u32 = 1;
    const DUPLICATE_SAME_ACCESS: u32 = 2;

    let ep = CSR_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSRLOOP_SLOT.load(Ordering::Relaxed);
    let was_parked = CSR_API_RECEIVE_PARKED.swap(0, Ordering::Relaxed);
    if ep == 0 || reply == 0 || was_parked == 0 {
        if was_parked != 0 {
            CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        }
        return false;
    }

    let mut length_bytes = [0u8; 4];
    if !nt_handler.xas_read(request_va, &mut length_bytes) {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let request_len = u16::from_le_bytes([length_bytes[2], length_bytes[3]]) as usize;
    if !(0x28..=CSR_API_MSG_MAX).contains(&request_len) {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let mut request = [0u8; CSR_API_MSG_MAX];
    if !nt_handler.xas_read(request_va, &mut request[..request_len]) {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }

    let client_pid = nt_handler.pm_pid_for_pi(nt_handler.pi).unwrap_or(0) as u64;
    let client_tid = nt_handler.current_tid;
    request[4..6].copy_from_slice(&nt_lpc_abi::msg_type::LPC_DATAGRAM.to_le_bytes());
    request[8..16].copy_from_slice(&client_pid.to_le_bytes());
    request[16..24].copy_from_slice(&client_tid.to_le_bytes());
    let api_number = if request_len >= 0x34 {
        u32::from_le_bytes(request[0x30..0x34].try_into().unwrap())
    } else {
        0xFFFF_FFFF
    };

    if lpc_client()
        .and_then(|client| {
            client
                .request_wait_reply(client_port, &request[..request_len])
                .ok()
        })
        .is_none()
    {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let listen_port = CSR_API_RECVPORT.load(Ordering::Relaxed);
    let Some(received) =
        lpc_client().and_then(|client| client.reply_wait_receive(listen_port).ok())
    else {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    };
    let delivered_recvmsg = CSR_API_RECVMSG.load(Ordering::Relaxed);
    if received.connection_info.len() != request_len
        || !csr_stack_copyout(delivered_recvmsg, &received.connection_info)
    {
        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    csr_stack_write16(delivered_recvmsg + 4, nt_lpc_abi::msg_type::LPC_DATAGRAM);
    csr_stack_write(delivered_recvmsg + 8, client_pid);
    csr_stack_write(delivered_recvmsg + 16, client_tid);
    let context_out = CSR_API_RECV_RDX.load(Ordering::Relaxed);
    if context_out != 0 {
        csr_stack_write(context_out, received.port_context);
    }

    print_str(b"[csr-api] delivered ApiNumber=0x");
    print_hex(api_number);
    print_str(b" bytes=");
    print_u64(request_len as u64);
    print_str(b" to real CsrApiRequestThread\n");

    set_reply_mr(15, 0);
    set_reply_mr(16, CSR_API_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, CSR_API_RECV_FLAGS.load(Ordering::Relaxed));
    client_reply_on(reply, 18, 0, 0, 0, CSR_API_RECV_RDX.load(Ordering::Relaxed));

    let mut fill_idx = 0;
    let (_badge, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    for _ in 0..8000 {
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0;
            let rsp = m1;
            let arg1 = m2;
            let arg3 = get_recv_mr(4);
            let arg4 = get_recv_mr(5);
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn;
            m2 = 0;
            mi = (2u64 << 12) | (mi & 0x7f);
        }
        match mi >> 12 {
            6 => {
                let page = m1 & !0xfff;
                if m1 < 0x10000
                    || !csr_fill_page(
                        page,
                        csrss_pml4,
                        csrss_pe,
                        img_end,
                        nt_base,
                        nt_end,
                        ntdll_pe,
                        reg,
                        dll_pes,
                        &mut fill_idx,
                    )
                {
                    print_str(b"[csr-api] unresolved worker fault\n");
                    return false;
                }
                client_reply_on(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                client_reply_on(reply, 3, m0 + 3, m1, m2, 0);
            }
            2 => {
                let ssn = m0;
                let resume_ip = m2;
                let sp = get_recv_mr(16);
                let flags = get_recv_mr(17);
                let rdx = m3;
                let mut result = 0u64;
                match ssn {
                    SSN_NT_ALLOCATE_VM => {
                        let stack_arg4 = sp
                            .checked_add(0x28)
                            .and_then(|address| csr_stack_read(address));
                        let stack_arg5 = sp
                            .checked_add(0x30)
                            .and_then(|address| csr_stack_read(address));
                        result = match (stack_arg4, stack_arg5) {
                            (Some(allocation_type), Some(protection)) => {
                                let alloc_args = [
                                    get_recv_mr(9),
                                    rdx,
                                    get_recv_mr(7),
                                    get_recv_mr(8),
                                    allocation_type,
                                    protection,
                                ];
                                let saved_pi = nt_handler.pi;
                                let saved_tid = nt_handler.current_tid;
                                nt_handler.pi = 1;
                                nt_handler.current_tid =
                                    hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                                let status = nt_handler
                                    .nt_allocate_virtual_memory_with_user_memory(
                                        &alloc_args,
                                        SyscallUserMemory::CsrThreadStack { sb: false },
                                    );
                                nt_handler.pi = saved_pi;
                                nt_handler.current_tid = saved_tid;
                                print_str(
                                    b"[csr-api] serviced worker NtAllocateVirtualMemory status=0x",
                                );
                                print_hex(status);
                                print_str(b"\n");
                                status as u64
                            }
                            _ => 0xC000_0005,
                        };
                    }
                    SSN_NT_PROTECT_VM => {
                        let stack_arg4 = sp
                            .checked_add(0x28)
                            .and_then(|address| csr_stack_read(address));
                        result = match stack_arg4 {
                            Some(old_protect) => {
                                let protect_args = [
                                    get_recv_mr(9),
                                    rdx,
                                    get_recv_mr(7),
                                    get_recv_mr(8),
                                    old_protect,
                                ];
                                let saved_pi = nt_handler.pi;
                                let saved_tid = nt_handler.current_tid;
                                nt_handler.pi = 1;
                                nt_handler.current_tid =
                                    hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                                let status = nt_handler.nt_protect_virtual_memory_with_user_memory(
                                    &protect_args,
                                    SyscallUserMemory::CsrThreadStack { sb: false },
                                );
                                nt_handler.pi = saved_pi;
                                nt_handler.current_tid = saved_tid;
                                print_str(
                                    b"[csr-api] serviced worker NtProtectVirtualMemory status=0x",
                                );
                                print_hex(status);
                                print_str(b"\n");
                                status as u64
                            }
                            None => 0xC000_0005,
                        };
                    }
                    SSN_NT_CREATE_THREAD => {
                        result = csr_api_worker_create_thread(
                            nt_handler,
                            main_fault_ep,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(8),
                            sp,
                        ) as u64;
                        print_str(b"[csr-api] serviced worker NtCreateThread status=0x");
                        print_hex(result as u32);
                        print_str(b"\n");
                    }
                    SSN_SET_EVENT => {
                        let event_handle = get_recv_mr(9);
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 1;
                        result = match nt_handler
                            .event_index_for_handle(event_handle, EVENT_MODIFY_STATE)
                        {
                            Ok(index) => match nt_handler.events.set_existing(index as u64) {
                                Some(previous) => {
                                    if rdx != 0 {
                                        let _ = csr_stack_write32(rdx, previous as u32);
                                    }
                                    if !previous {
                                        wait_wake_dispatcher_set(nt_handler);
                                    }
                                    0
                                }
                                None => 0xC000_0008,
                            },
                            Err(status) => status as u64,
                        };
                        nt_handler.pi = saved_pi;
                    }
                    SSN_NT_SET_INFO_THREAD => {
                        result = csr_set_thread_information_call(
                            nt_handler,
                            false,
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi),
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8) as u32,
                        );
                    }
                    SSN_NT_QUERY_INFORMATION_THREAD => {
                        result = match sp
                            .checked_add(0x28)
                            .and_then(|address| csr_stack_read(address))
                        {
                            Some(return_length) => csr_query_thread_call(
                                nt_handler,
                                get_recv_mr(9),
                                rdx as u32,
                                get_recv_mr(7),
                                get_recv_mr(8) as u32,
                                return_length,
                            ),
                            None => 0xC000_0005,
                        };
                    }
                    SSN_QUERY_OBJECT => {
                        result = match sp
                            .checked_add(0x28)
                            .and_then(|address| csr_stack_read(address))
                        {
                            Some(return_length) => {
                                let query_args = [
                                    get_recv_mr(9),
                                    rdx,
                                    get_recv_mr(7),
                                    get_recv_mr(8),
                                    return_length,
                                ];
                                let saved_pi = nt_handler.pi;
                                let saved_tid = nt_handler.current_tid;
                                nt_handler.pi = 1;
                                nt_handler.current_tid =
                                    hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                                let status = nt_handler.nt_query_object_with_user_memory(
                                    &query_args,
                                    SyscallUserMemory::CsrThreadStack { sb: false },
                                );
                                nt_handler.pi = saved_pi;
                                nt_handler.current_tid = saved_tid;
                                print_str(b"[csr-api] serviced worker NtQueryObject status=0x");
                                print_hex(status);
                                print_str(b"\n");
                                status as u64
                            }
                            None => 0xC000_0005,
                        };
                    }
                    SSN_SET_INFO_OBJECT => {
                        let set_args = [get_recv_mr(9), rdx, get_recv_mr(7), get_recv_mr(8)];
                        let saved_pi = nt_handler.pi;
                        let saved_tid = nt_handler.current_tid;
                        nt_handler.pi = 1;
                        nt_handler.current_tid =
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                        let status = nt_handler.nt_set_information_object_with_user_memory(
                            &set_args,
                            SyscallUserMemory::CsrThreadStack { sb: false },
                        );
                        nt_handler.pi = saved_pi;
                        nt_handler.current_tid = saved_tid;
                        print_str(b"[csr-api] serviced worker NtSetInformationObject status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        result = status as u64;
                    }
                    SSN_RESUME_THREAD => {
                        let resume_args = [get_recv_mr(9), rdx];
                        let saved_pi = nt_handler.pi;
                        let saved_tid = nt_handler.current_tid;
                        nt_handler.pi = 1;
                        nt_handler.current_tid =
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                        let status = nt_handler.nt_resume_thread_with_user_memory(
                            &resume_args,
                            SyscallUserMemory::CsrThreadStack { sb: false },
                        );
                        nt_handler.pi = saved_pi;
                        nt_handler.current_tid = saved_tid;
                        print_str(b"[csr-api] serviced worker NtResumeThread status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        result = status as u64;
                    }
                    SSN_DUPLICATE_OBJECT => {
                        let source_process = get_recv_mr(9);
                        let source_handle = rdx;
                        let target_process = get_recv_mr(7);
                        let target_out = get_recv_mr(8);
                        let desired_access = sp
                            .checked_add(0x28)
                            .and_then(|address| csr_stack_read(address));
                        let options = sp
                            .checked_add(0x38)
                            .and_then(|address| csr_stack_read(address))
                            .unwrap_or(0) as u32;
                        let saved_pi = nt_handler.pi;
                        let saved_tid = nt_handler.current_tid;
                        nt_handler.pi = 1;
                        nt_handler.current_tid =
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                        let source_pid = nt_handler.resolve_process_handle(source_process);
                        let target_pid = nt_handler.resolve_process_handle(target_process);
                        let mut close_source_pid = source_pid;
                        let mut recovered_from_client = false;
                        result = match target_pid {
                            Some(target_pid) => {
                                if options & DUPLICATE_SAME_ACCESS == 0 && desired_access.is_none()
                                {
                                    0xC000_0005
                                } else {
                                    let desired_access = (options & DUPLICATE_SAME_ACCESS == 0)
                                        .then_some(desired_access.unwrap_or(0) as u32);
                                    let mut duplicate_result: Option<
                                        Result<nt_process::Handle, u32>,
                                    > = None;
                                    if let Some(source_pid) = source_pid {
                                        duplicate_result =
                                            Some(nt_handler.duplicate_process_handle_with_access(
                                                source_pid,
                                                source_handle as nt_process::Handle,
                                                target_pid,
                                                desired_access,
                                            ));
                                    }
                                    if matches!(
                                        duplicate_result,
                                        None | Some(Err(nt_process::STATUS_INVALID_HANDLE))
                                    ) {
                                        let client_source_pid = client_pid as nt_process::ProcessId;
                                        if client_source_pid != 0
                                            && Some(client_source_pid) != source_pid
                                            && nt_handler
                                                .pm
                                                .lookup_handle(
                                                    client_source_pid,
                                                    source_handle as nt_process::Handle,
                                                )
                                                .is_some()
                                        {
                                            duplicate_result = Some(
                                                nt_handler.duplicate_process_handle_with_access(
                                                    client_source_pid,
                                                    source_handle as nt_process::Handle,
                                                    target_pid,
                                                    desired_access,
                                                ),
                                            );
                                            close_source_pid = Some(client_source_pid);
                                            recovered_from_client = true;
                                        }
                                    }
                                    match duplicate_result
                                        .unwrap_or(Err(nt_process::STATUS_INVALID_HANDLE))
                                    {
                                        Ok(handle) if csr_stack_has_range(target_out, 8) => {
                                            let _ = csr_stack_copyout(
                                                target_out,
                                                &(handle as u64).to_le_bytes(),
                                            );
                                            let count =
                                                nt_handler.pm.handle_count(target_pid) as u64;
                                            if count > PM_HANDLE_PEAK.load(Ordering::Relaxed) {
                                                PM_HANDLE_PEAK.store(count, Ordering::Relaxed);
                                            }
                                            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
                                            0
                                        }
                                        Ok(handle) => {
                                            let _ = nt_handler
                                                .close_process_handle(target_pid, handle as u64);
                                            0xC000_0005
                                        }
                                        Err(status) => status as u64,
                                    }
                                }
                            }
                            None => nt_process::STATUS_INVALID_HANDLE as u64,
                        };
                        if options & DUPLICATE_CLOSE_SOURCE != 0 {
                            if let Some(source_pid) = close_source_pid {
                                let _ = nt_handler.close_process_handle(source_pid, source_handle);
                            }
                        }
                        nt_handler.pi = saved_pi;
                        nt_handler.current_tid = saved_tid;
                        print_str(b"[csr-api] serviced worker NtDuplicateObject status=0x");
                        print_hex(result as u32);
                        if recovered_from_client {
                            print_str(b" source=client");
                        }
                        print_str(b"\n");
                    }
                    SSN_MAP_VIEW => {}
                    SSN_CLOSE => {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 1;
                        nt_handler.close_current_handle(get_recv_mr(9));
                        nt_handler.pi = saved_pi;
                    }
                    SSN_REPLY_WAIT_RECV => {
                        let reply_msg = get_recv_mr(7);
                        let recv_msg = get_recv_mr(8);
                        let mut reply_bytes = [0u8; CSR_API_MSG_MAX];
                        let reply_source = if reply_msg != 0 {
                            reply_msg
                        } else {
                            // Hosted clients are not CSR-registered yet, so requests are delivered as
                            // LPC_DATAGRAM to avoid CsrLocateThreadByClientId rejecting them. ReactOS'
                            // datagram branch runs the real dispatch but leaves ReplyMsg=NULL. Return
                            // the worker-mutated ReceiveMsg frame so the parked client observes the real
                            // csrsrv/basesrv side effects instead of the old blind success fallback.
                            delivered_recvmsg
                        };
                        let reply_len = if reply_source != 0 {
                            let Some(header_word) = csr_stack_read(reply_source) else {
                                return false;
                            };
                            let total = ((header_word >> 16) as u16) as usize;
                            if !(0x28..=CSR_API_MSG_MAX).contains(&total)
                                || !csr_stack_copyin(reply_source, &mut reply_bytes[..total])
                            {
                                return false;
                            }
                            reply_bytes[4..6]
                                .copy_from_slice(&nt_lpc_abi::msg_type::LPC_REPLY.to_le_bytes());
                            total
                        } else {
                            0
                        };
                        if reply_msg == 0 {
                            print_str(b"[csr-api] worker returned datagram ReplyMsg=NULL; using executed ReceiveMsg ApiNumber=0x");
                            print_hex(api_number);
                            print_str(b" bytes=");
                            print_u64(reply_len as u64);
                            print_str(b"\n");
                        }
                        let _ = lpc_client().and_then(|client| {
                            client
                                .reply_wait_receive_with_reply(
                                    listen_port,
                                    &reply_bytes[..reply_len],
                                )
                                .ok()
                        });
                        let response = lpc_client()
                            .and_then(|client| client.reply_wait_receive(client_port).ok());
                        CSR_API_RECVMSG.store(recv_msg, Ordering::Relaxed);
                        CSR_API_RECVPORT.store(get_recv_mr(9), Ordering::Relaxed);
                        CSR_API_RECV_SP.store(sp, Ordering::Relaxed);
                        CSR_API_RECV_FLAGS.store(flags, Ordering::Relaxed);
                        CSR_API_RECV_RDX.store(rdx, Ordering::Relaxed);
                        CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                        let Some(response) = response else {
                            print_str(b"[csr-api] worker produced no reply for ApiNumber=0x");
                            print_hex(api_number);
                            print_str(b"\n");
                            return false;
                        };
                        if response.connection_info.is_empty()
                            || !nt_handler.xas_try_write_buf(reply_va, &response.connection_info)
                        {
                            return false;
                        }
                        CSR_MSGS.fetch_add(1, Ordering::Relaxed);
                        CSR_API_REAL_REPLIES.fetch_add(1, Ordering::Relaxed);
                        print_str(
                            b"[csr-api] real CsrApiRequestThread reply completed ApiNumber=0x",
                        );
                        print_hex(api_number);
                        print_str(b" bytes=");
                        print_u64(response.connection_info.len() as u64);
                        print_str(b"\n");
                        return true;
                    }
                    _ => {
                        print_str(b"[csr-api] unexpected worker SSN=");
                        print_u64(ssn);
                        print_str(b"\n");
                        return false;
                    }
                }
                set_reply_mr(15, resume_ip);
                set_reply_mr(16, sp);
                set_reply_mr(17, flags);
                client_reply_on(reply, 18, result, 0, 0, rdx);
            }
            _ => return false,
        }
        let (_badge, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    false
}

/// Number of committed stack frames for the CSR API thread (deeper than SM: CsrApiRequestThread →
/// CsrConnectToUser [loader walk] → CsrApiHandleConnectionRequest).
pub const CSR_STACK_FRAMES: u64 = 8;

/// Spawn csrss's REAL `CsrApiRequestThread` as a 2nd thread in csrss's VSpace (mirrors
/// `spawn_sm_loop_thread`). It faults to `CSR_FAULT_EP` (no standing receiver) so it PARKS on its
/// first fault/syscall until `csr_rendezvous` drains it for winlogon's CSR connect. `param` is the
/// hRequestEvent handle (CsrApiRequestThread's PVOID Parameter). The TEB carries the self-connect
/// ClientId so the thread's own bookkeeping is consistent.
pub(crate) unsafe fn spawn_csr_loop_thread(
    csrss_pml4: u64,
    entry_rip: u64,
    param: u64,
    pid: u64,
    tid: u64,
) -> u64 {
    spawn_hosted_thread(&HostedThread {
        pml4: csrss_pml4,
        client_pi: 1,
        entry_rip,
        arg0: param,
        arg1: 0,
        loader_context: None,
        scr: CSR_ENV_SCRATCH_VA,
        teb_va: CSR_TEB_VA,
        stack_base: CSR_STACK_BASE,
        stack_frames: CSR_STACK_FRAMES,
        ipcbuf_va: CSR_IPCBUF_VA,
        tramp_va: CSR_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: CSR_STACK_MIRROR_VA,
        fault_ep: CSR_FAULT_EP.load(Ordering::Relaxed),
        cid_proc: pid,
        cid_thread: tid,
        resume: false,
        prio: 0,
        // BATCH 6: csrss (pi 1, badge 2) also runs on OUR native ntdll, so the CSR API
        // thread uses the native transport and its TEB-derived private IPC buffer.
        native: true,
        diag: false,
    })
}

/// Spawn the real CSRSS session-manager API worker. ReactOS creates it suspended and performs the
/// first resume itself, so construction deliberately leaves the TCB stopped.
pub(crate) unsafe fn spawn_csr_sb_loop_thread(
    csrss_pml4: u64,
    entry_rip: u64,
    param: u64,
    pid: u64,
    tid: u64,
) -> u64 {
    spawn_hosted_thread(&HostedThread {
        pml4: csrss_pml4,
        client_pi: 1,
        entry_rip,
        arg0: param,
        arg1: 0,
        loader_context: None,
        scr: CSR_SB_ENV_SCRATCH_VA,
        teb_va: CSR_SB_TEB_VA,
        stack_base: CSR_SB_STACK_BASE,
        stack_frames: CSR_SB_STACK_FRAMES,
        ipcbuf_va: CSR_SB_IPCBUF_VA,
        tramp_va: CSR_SB_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: CSR_SB_STACK_MIRROR_VA,
        fault_ep: CSR_SB_FAULT_EP.load(Ordering::Relaxed),
        cid_proc: pid,
        cid_thread: tid,
        resume: false,
        prio: 0,
        native: true,
        diag: false,
    })
}

/// Run the real SB worker from its initial resume through demand faults to its first blocking
/// NtReplyWaitReceivePort. The retained reply object is the durable parked receive for later SM
/// session messages; no synthetic status is returned to the worker.
pub(crate) unsafe fn csr_sb_startup(
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) -> bool {
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    let ep = CSR_SB_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSR_SB_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return false;
    }
    let mut fill_idx = 0;
    let (_badge, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    for _ in 0..8000 {
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0;
            let rsp = m1;
            let arg1 = m2;
            let arg3 = get_recv_mr(4);
            let arg4 = get_recv_mr(5);
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn;
            m2 = 0;
            mi = (2u64 << 12) | (mi & 0x7f);
        }
        match mi >> 12 {
            6 => {
                let page = m1 & !0xfff;
                if m1 < 0x10000
                    || !csr_fill_page(
                        page,
                        csrss_pml4,
                        csrss_pe,
                        img_end,
                        nt_base,
                        nt_end,
                        ntdll_pe,
                        reg,
                        dll_pes,
                        &mut fill_idx,
                    )
                {
                    print_str(b"[csr-sb] unresolved startup fault\n");
                    return false;
                }
                client_reply_on(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                client_reply_on(reply, 3, m0 + 3, m1, m2, 0);
            }
            2 if m0 == SSN_REPLY_WAIT_RECV => {
                CSR_SB_RECVMSG.store(get_recv_mr(8), Ordering::Relaxed);
                CSR_SB_RECVPORT.store(get_recv_mr(9), Ordering::Relaxed);
                CSR_SB_RECV_SP.store(get_recv_mr(16), Ordering::Relaxed);
                CSR_SB_RECV_FLAGS.store(get_recv_mr(17), Ordering::Relaxed);
                CSR_SB_RECV_RDX.store(m3, Ordering::Relaxed);
                CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                print_str(b"[csr-sb] real worker parked on NtReplyWaitReceivePort\n");
                return true;
            }
            2 => {
                print_str(b"[csr-sb] unexpected startup SSN=");
                print_u64(m0);
                print_str(b"\n");
                return false;
            }
            label => {
                print_str(b"[csr-sb] unexpected startup label=");
                print_u64(label);
                print_str(b"\n");
                return false;
            }
        }
        let (_badge, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    false
}

/// Spawn winlogon's rpcrt4 server WORKER thread (its first NtCreateThread = RPCRT4_server_thread) in
/// winlogon's VSpace (pi 2) and RESUME it into the main service-loop multiplex — the SERVICE-9 C-c
/// N-threads pattern applied to winlogon. Faults to a cap minted at [`WINLOGON_WORKER_BADGE`] off the
/// MAIN service `fault_ep`; the loop sub-selects it as (pi 2, worker) via its OWN stack mirror. This
/// makes the worker actually RUN its wait array (get_wait_array → NtWaitForMultipleObjects), so the
/// rpcrt4 two-thread handshake completes: the worker parks on [mgr_event, …], the main thread's
/// signal_state_changed SetEvents mgr_event → the worker wakes → SetEvents server_ready_event → the
/// main thread's WaitForSingleObject(server_ready_event) wakes. `entry_rip`/`param` come from the
/// caller's CONTEXT; `cid_*` is the real ClientId {caller pid, fresh tid}. Returns the TCB.
pub(crate) unsafe fn spawn_wl_listener_thread(
    slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let (scr, teb_va, stack_base, stack_frames, ipcbuf_va, tramp_va, stack_mirror_va, badge) =
        match slot {
            0 => (
                WL_LISTENER_ENV_SCRATCH_VA,
                WL_LISTENER_TEB_VA,
                WL_LISTENER_STACK_BASE,
                WL_LISTENER_STACK_FRAMES,
                WL_LISTENER_IPCBUF_VA,
                WL_LISTENER_TRAMP_VA,
                WINLOGON_WORKER_STACK_MIRROR_VA,
                WINLOGON_WORKER_BADGE,
            ),
            1 => (
                WL_WORKER2_ENV_SCRATCH_VA,
                WL_WORKER2_TEB_VA,
                WL_WORKER2_STACK_BASE,
                WL_WORKER2_STACK_FRAMES,
                WL_WORKER2_IPCBUF_VA,
                WL_WORKER2_TRAMP_VA,
                WINLOGON_WORKER2_STACK_MIRROR_VA,
                WINLOGON_WORKER2_BADGE,
            ),
            2 => (
                WL_WORKER3_ENV_SCRATCH_VA,
                WL_WORKER3_TEB_VA,
                WL_WORKER3_STACK_BASE,
                WL_WORKER3_STACK_FRAMES,
                WL_WORKER3_IPCBUF_VA,
                WL_WORKER3_TRAMP_VA,
                WINLOGON_WORKER3_STACK_MIRROR_VA,
                WINLOGON_WORKER3_BADGE,
            ),
            _ => return 0,
        };
    let worker_ep = mint_badged(main_fault_ep, badge);
    spawn_hosted_thread(&HostedThread {
        pml4,
        client_pi: 2,
        entry_rip: start.rip,
        arg0: start.rcx,
        arg1: start.rdx,
        loader_context: (slot == 0)
            .then(|| img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed))
            .filter(|&rva| rva != 0)
            .map(|rva| LoaderThreadContext {
                loader_va: NTDLL_BASE + rva,
                start,
                initial_teb,
            }),
        scr,
        teb_va,
        stack_base,
        stack_frames,
        ipcbuf_va,
        tramp_va,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va,
        fault_ep: worker_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 106, // above winlogon-main(102) so it runs when winlogon's main parks/blocks
        // BATCH 19: winlogon (pi 2) runs on OUR ntdll's NATIVE seL4-Call transport, so its rpcrt4
        // server WORKER thread must too. All three worker slots run in winlogon's VSpace (pi 2) with
        // distinct TEB-derived IPC buffers. Their faults still arrive on the badged MAIN fault-EP (the
        // loop's NT_NATIVE_SYSCALL_LABEL NORMALIZE arm re-labels them into the shared servicing body),
        // so the worker actually RUNS its rpcrt4 RPC-server init + NtSetEvent(s) the event winlogon's
        // main parks on.
        native: true,
        diag: false,
    })
}

/// Spawn the one bounded generic ntdll thread-pool worker assigned to `pi`. The caller-supplied
/// stack allocation is not mapped into this userspace kernel, so normalize both INITIAL_TEB and
/// CONTEXT.Rsp to the fixed 16-page worker stack before entering LdrInitializeThunk. The original
/// RIP/RCX/RDX remain intact and are restored by the loader trampoline.
pub(crate) unsafe fn spawn_tp_worker_thread(
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    if pi >= TP_WORKER_PI_COUNT || worker_slot >= TP_WORKER_SLOT_COUNT {
        return 0;
    }
    if img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed) == 0 {
        return 0;
    }
    let worker_ep = mint_badged(main_fault_ep, tp_worker_badge(pi, worker_slot));
    spawn_slot_thread(&RemoteThreadSpawn {
        target_pi: pi,
        slot: worker_slot,
        pml4,
        start,
        cid_proc,
        cid_thread,
        fault_ep: worker_ep,
        use_loader: true,
        native: true,
        resume,
    })
}

/// Everything the general cross-VSpace thread spawn needs. See [`spawn_slot_thread`].
#[derive(Clone, Copy)]
pub(crate) struct RemoteThreadSpawn {
    /// Hosted-process index the new thread BELONGS TO (selects its executive-side mirror/scratch).
    pub target_pi: usize,
    /// Which bounded per-process thread window to build it in.
    pub slot: usize,
    /// The TARGET's VSpace (PML4) cap — the address space the stack/TEB/IPC/trampoline land in.
    pub pml4: u64,
    /// Caller-supplied start context: `rip` = the start routine, `rcx` = its parameter.
    pub start: nt_thread_start::Amd64ThreadContext,
    /// The `ClientId` stamped into the new thread's TEB.
    pub cid_proc: u64,
    pub cid_thread: u64,
    /// Endpoint the thread's faults/syscalls are delivered to.
    pub fault_ep: u64,
    /// Enter `LdrInitializeThunk` first (a real hosted process) or the start routine directly.
    pub use_loader: bool,
    /// NATIVE seL4-Call transport (our ntdll). Hosted threads still get rust-micro's hybrid
    /// hosted-syscalls flag; this tells the executive-side spawn which ntdll entry path to use.
    pub native: bool,
    /// Resume immediately, or leave suspended (`CreateSuspended`).
    pub resume: bool,
}

/// ★ THE GENERAL CROSS-VSPACE THREAD SPAWN — `PspCreateThread`'s mechanism half.
///
/// Build a REAL hosted Windows thread inside an **arbitrary target process's address space**: its
/// own stack, its own TEB (→ GS base, `ClientId`, the process's shared PEB pointer, an
/// ACTIVATION_CONTEXT_STACK), its own IPC buffer and entry trampoline — all mapped in `pml4`, the
/// TARGET's VSpace — starting at a **caller-supplied entry point with a caller-supplied
/// parameter**. Nothing here is specific to the caller: `target_pi` names the process the thread
/// belongs to (selecting its executive-side mirror/scratch windows) and `pml4` its address space,
/// so `RtlCreateUserThread(ProcessHandle != NtCurrentProcess)` — `DbgUiIssueRemoteBreakin`'s
/// break-in thread, `CreateRemoteThread`, an injected worker — lands correctly.
///
/// `slot` picks one of the bounded per-process thread windows (`TP_WORKER_SLOT_COUNT` of them,
/// shared with the ntdll thread-pool workers: they are the same resource — a process's Nth extra
/// thread). `use_loader` routes the new thread through `LdrInitializeThunk` first, which is what a
/// real hosted process needs (TLS + `DLL_THREAD_ATTACH` before the start routine runs); `false`
/// enters the start routine directly, for a target with no ntdll mapped. `fault_ep` is the endpoint
/// the thread's faults and syscalls are delivered to (the badged main service EP for a live
/// process; a private endpoint when the caller services the thread itself).
pub(crate) unsafe fn spawn_slot_thread(spawn: &RemoteThreadSpawn) -> u64 {
    let RemoteThreadSpawn {
        target_pi,
        slot,
        pml4,
        mut start,
        cid_proc,
        cid_thread,
        fault_ep,
        use_loader,
        native,
        resume,
    } = *spawn;
    if target_pi >= MAX_PI || slot >= TP_WORKER_SLOT_COUNT || pml4 == 0 || fault_ep == 0 {
        return 0;
    }
    let loader_context = if use_loader {
        let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
        if loader_rva == 0 {
            return 0;
        }
        // The caller-supplied stack allocation is not mapped into this userspace kernel, so
        // normalize both INITIAL_TEB and CONTEXT.Rsp to the fixed 16-page slot stack before entering
        // LdrInitializeThunk. The original RIP/RCX/RDX remain intact and are restored by the loader
        // trampoline. ReactOS amd64 RtlInitializeContext: (StackBase - 6 pointers), align 16, -8.
        start.rsp = tp_worker_context_rsp(slot);
        Some(LoaderThreadContext {
            loader_va: NTDLL_BASE + loader_rva,
            start,
            initial_teb: nt_thread_start::InitialTeb64 {
                stack_base: tp_worker_stack_top(slot),
                stack_limit: tp_worker_stack_base(slot),
                allocated_stack_base: tp_worker_stack_base(slot),
            },
        })
    } else {
        None
    };
    spawn_hosted_thread(&HostedThread {
        pml4,
        client_pi: target_pi as u64,
        entry_rip: start.rip,
        arg0: start.rcx,
        arg1: start.rdx,
        loader_context,
        scr: tp_worker_env_scratch_va(target_pi, slot),
        teb_va: tp_worker_teb_va(slot),
        stack_base: tp_worker_stack_base(slot),
        stack_frames: TP_WORKER_STACK_FRAMES,
        ipcbuf_va: tp_worker_ipcbuf_va(slot),
        tramp_va: tp_worker_tramp_va(slot),
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: tp_worker_stack_mirror_va(target_pi, slot),
        fault_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 106,
        native,
        diag: false,
    })
}

/// Spawn services' REAL RPC listener thread (ScmStartRpcServer's rpcrt4 io_thread) in services'
/// VSpace (pi 3) and RESUME it into the main service-loop multiplex. Unlike `spawn_wl_listener_thread`
/// (suspended, no-receiver EP), this one faults to a cap minted at [`SVC_LISTENER_BADGE`] off the MAIN
/// service `fault_ep`, so the loop receives + sub-selects it as (pi 3, listener) via its own stack
/// mirror. `svc_pml4` = services' PML4; `entry_rip`/`param` from the caller's CONTEXT; `main_fault_ep`
/// = the shared service-loop endpoint (this fn mints the badged cap). Returns the TCB.
pub(crate) unsafe fn spawn_svc_listener_thread(
    svc_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let listener_ep = mint_badged(main_fault_ep, SVC_LISTENER_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: svc_pml4,
        client_pi: 3,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: SVC_LISTENER_ENV_SCRATCH_VA,
        teb_va: SVC_LISTENER_TEB_VA,
        stack_base: SVC_LISTENER_STACK_BASE,
        stack_frames: SVC_LISTENER_STACK_FRAMES,
        ipcbuf_va: SVC_LISTENER_IPCBUF_VA,
        tramp_va: SVC_LISTENER_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: SVC_LISTENER_STACK_MIRROR_VA,
        fault_ep: listener_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 104, // above winlogon(102)/services(103) so it runs when services' main parks
        // BATCH 33: services (pi 3) runs on OUR ntdll's NATIVE seL4-Call transport, so its SCM RPC
        // listener thread must too. native:true plus its TEB-derived private IPC buffer makes its
        // Call dispatch (MR0=SSN), so it runs its rpcrt4 ncacn_np receive loop
        // (FSCTL_PIPE_LISTEN + NtReadFile on the server pipe) — the reads the pipe-pending
        // park/re-drive edge then completes.
        native: true,
        diag: false,
    })
}

/// BATCH 35 — spawn services' SCM per-connection RPC WORKER thread (rpcrt4 `RPCRT4_new_client`,
/// created by the SCM listener via its SECOND NtCreateThread on an accepted connection) in services'
/// VSpace (pi 3) and RESUME it into the main service-loop multiplex. Faults to a cap minted at
/// [`SCM_WORKER_BADGE`] off the MAIN service `fault_ep`; the loop sub-selects it as (pi 3, scm-worker)
/// via its OWN stack mirror/TEB (distinct from services' main thread AND its listener). This is the
/// thread that reads winlogon's bind PDU off `\pipe\ntsvcs` and writes bind_ack — its blocking pipe
/// reads park via `pipe_wait_park` and re-drive on winlogon's write via `pipe_redrive_all` (which is
/// already badge-general through `mirror_ctx_for`). A clone of `spawn_svc_listener_thread` with the
/// SCM_WORKER VA window, native transport (services runs on OUR ntdll), and a private IPC buffer
/// derived from its TEB.
pub(crate) unsafe fn spawn_scm_worker_thread(
    svc_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let worker_ep = mint_badged(main_fault_ep, SCM_WORKER_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: svc_pml4,
        client_pi: 3,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: SCM_WORKER_ENV_SCRATCH_VA,
        teb_va: SCM_WORKER_TEB_VA,
        stack_base: SCM_WORKER_STACK_BASE,
        stack_frames: SCM_WORKER_STACK_FRAMES,
        ipcbuf_va: SCM_WORKER_IPCBUF_VA,
        tramp_va: SCM_WORKER_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: SCM_WORKER_STACK_MIRROR_VA,
        fault_ep: worker_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 104, // same band as the listener (above winlogon/services main threads)
        native: true,
        diag: true, // BATCH 36 DIAG: surface silent SYS_SEND spawn errors for the 3rd hosted thread
    })
}

/// Spawn lsass' `\pipe\lsarpc` PER-CONNECTION RPC WORKER thread (rpcrt4 `RPCRT4_new_client` →
/// `CreateThread(RPCRT4_io_thread)`, `rpc_server.c:626`) in lsass' VSpace (pi 4) and RESUME it into
/// the main service-loop multiplex at [`LSA_WORKER_BADGE`]. The exact analogue of
/// [`spawn_scm_worker_thread`] for lsass, on its OWN target-VSpace window (the three lsass listener
/// blocks and the generic TP slot-0 block are all taken) and its own executive mirror/scratch.
///
/// **This is the self-RPC server half.** lsass' main thread is simultaneously the CLIENT
/// (samsrv `SampGetAccountDomainInfo` → `LsaOpenPolicy` → advapi32 `ncacn_np:\pipe\lsarpc`), parked
/// on its overlapped read; this worker is a genuinely separate seL4 thread with its own
/// TEB/GS/stack/IPC buffer, so the two never share a stack mirror and the client's park is woken by
/// the worker's write through the ordinary pipe re-drive edge.
pub(crate) unsafe fn spawn_lsa_worker_thread(
    lsass_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let worker_ep = mint_badged(main_fault_ep, LSA_WORKER_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: lsass_pml4,
        client_pi: 4,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: LSA_WORKER_ENV_SCRATCH_VA,
        teb_va: LSA_WORKER_TEB_VA,
        stack_base: LSA_WORKER_STACK_BASE,
        stack_frames: LSA_WORKER_STACK_FRAMES,
        ipcbuf_va: LSA_WORKER_IPCBUF_VA,
        tramp_va: LSA_WORKER_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: LSA_WORKER_STACK_MIRROR_VA,
        fault_ep: worker_ep,
        cid_proc,
        cid_thread,
        resume,
        // Above lsass' main thread and its three listeners so the worker runs as soon as the main
        // thread parks on its own RPC read — the whole point of the self-RPC.
        prio: 106,
        // lsass runs on OUR ntdll's native seL4-Call transport, so its worker must too.
        native: true,
        // Surface a silent SYS_SEND alias-map failure for this fresh VA window (the BATCH-36 lesson:
        // a colliding executive scratch VA leaves the trampoline frame zero-filled → cr2=0 at entry).
        diag: true,
    })
}

/// Spawn lsass' LSA server thread (StartAuthenticationPort / LsapRmServerThread, created by lsass'
/// LsapInitDatabase via NtCreateThread) in lsass' VSpace (pi 4) and RESUME it into the main service-loop
/// multiplex — the SERVICE-9 C-c pattern replicated for lsass. Faults to a cap minted at
/// [`LSASS_LISTENER_BADGE`] off the MAIN service `fault_ep`; the loop sub-selects it as (pi 4, listener)
/// via its own stack mirror. `lsass_pml4` = lsass' PML4; `entry_rip`/`param` from the caller's CONTEXT.
/// Returns the TCB.
pub(crate) unsafe fn spawn_lsass_listener_thread(
    lsass_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: lsass_pml4,
        client_pi: 4,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: LSASS_LISTENER_ENV_SCRATCH_VA,
        teb_va: LSASS_LISTENER_TEB_VA,
        stack_base: LSASS_LISTENER_STACK_BASE,
        stack_frames: LSASS_LISTENER_STACK_FRAMES,
        ipcbuf_va: LSASS_LISTENER_IPCBUF_VA,
        tramp_va: LSASS_LISTENER_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: LSASS_LISTENER_STACK_MIRROR_VA,
        fault_ep: listener_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 105, // above winlogon(102)/services(103)/svc-listener(104) so it runs once lsass' main parks/blocks
        // BATCH 24: lsass (pi 4) runs on OUR ntdll's NATIVE seL4-Call transport, so its LSA server
        // thread must too. native:true makes its Call dispatch (MR0=SSN) through its TEB-derived
        // private IPC buffer.
        // Its faults still arrive on the badged MAIN fault-EP (the loop's NT_NATIVE_SYSCALL_LABEL
        // NORMALIZE arm re-labels them), so it actually RUNS LsarStartRpcServer →
        // SetEvent(LSA_RPC_SERVER_ACTIVE).
        native: true,
        diag: false,
    })
}

/// Spawn lsass' SECOND LSA server thread (LsapRmServerThread) — same multiplex, its own target-VSpace
/// VAs (distinct TEB/stack/tramp) + badge (LSASS_LISTENER2_BADGE).
pub(crate) unsafe fn spawn_lsass_listener2_thread(
    lsass_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER2_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: lsass_pml4,
        client_pi: 4,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: LSASS_LISTENER2_ENV_SCRATCH_VA,
        teb_va: LSASS_LISTENER2_TEB_VA,
        stack_base: LSASS_LISTENER2_STACK_BASE,
        stack_frames: LSASS_LISTENER2_STACK_FRAMES,
        ipcbuf_va: LSASS_LISTENER2_IPCBUF_VA,
        tramp_va: LSASS_LISTENER2_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: LSASS_LISTENER2_STACK_MIRROR_VA,
        fault_ep: listener_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 105,
        // BATCH 24: native transport (mirror listener1) — lsass runs on our native ntdll.
        native: true,
        diag: false,
    })
}

pub(crate) unsafe fn spawn_lsass_listener3_thread(
    lsass_pml4: u64,
    entry_rip: u64,
    arg0: u64,
    arg1: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER3_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: lsass_pml4,
        client_pi: 4,
        entry_rip,
        arg0,
        arg1,
        loader_context: None,
        scr: LSASS_LISTENER3_ENV_SCRATCH_VA,
        teb_va: LSASS_LISTENER3_TEB_VA,
        stack_base: LSASS_LISTENER3_STACK_BASE,
        stack_frames: LSASS_LISTENER3_STACK_FRAMES,
        ipcbuf_va: LSASS_LISTENER3_IPCBUF_VA,
        tramp_va: LSASS_LISTENER3_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: LSASS_LISTENER3_STACK_MIRROR_VA,
        fault_ep: listener_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 105,
        // BATCH 24: native transport (mirror listener1) — lsass runs on our native ntdll.
        native: true,
        diag: false,
    })
}

/// Write a u64 to the CSR thread's stack (via the executive's CSR_STACK_MIRROR alias).
fn csr_heap_has_range(va: u64, len: usize) -> bool {
    va >= SMSS_ALLOC_VA
        && va
            .checked_add(len as u64)
            .is_some_and(|end| end <= SMSS_ALLOC_VA + SMSS_HEAP_MIRROR_WINDOW)
}
fn csr_stack_has_range(va: u64, len: usize) -> bool {
    (va >= CSR_STACK_BASE
        && va
            .checked_add(len as u64)
            .is_some_and(|end| end <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000))
        || csr_heap_has_range(va, len)
}
unsafe fn csr_stack_copyout(va: u64, bytes: &[u8]) -> bool {
    if !csr_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= CSR_STACK_BASE {
        CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)
    } else {
        CSRSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), mirror as *mut u8, bytes.len());
    true
}
unsafe fn csr_stack_copyin(va: u64, bytes: &mut [u8]) -> bool {
    if !csr_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= CSR_STACK_BASE {
        CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)
    } else {
        CSRSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(mirror as *const u8, bytes.as_mut_ptr(), bytes.len());
    true
}
unsafe fn csr_stack_read(va: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    csr_stack_copyin(va, &mut bytes).then(|| u64::from_le_bytes(bytes))
}
pub(crate) unsafe fn csr_stack_write(va: u64, v: u64) {
    let _ = csr_stack_copyout(va, &v.to_le_bytes());
}
/// Write a u32 to the CSR thread's stack, returning false for an invalid output pointer.
pub(crate) unsafe fn csr_stack_write32(va: u64, v: u32) -> bool {
    csr_stack_copyout(va, &v.to_le_bytes())
}
/// Write a u16 to the CSR thread's stack (for PORT_MESSAGE.Type@0x04).
pub(crate) unsafe fn csr_stack_write16(va: u64, v: u16) {
    let _ = csr_stack_copyout(va, &v.to_le_bytes());
}
unsafe fn csr_sb_stack_write(va: u64, v: u64) {
    if va >= CSR_SB_STACK_BASE && va + 8 <= CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile(
            (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *mut u64,
            v,
        );
    }
}
unsafe fn csr_sb_stack_write16(va: u64, v: u16) {
    if va >= CSR_SB_STACK_BASE && va + 2 <= CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile(
            (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *mut u16,
            v,
        );
    }
}
unsafe fn csr_sb_stack_read(va: u64) -> u64 {
    csr_sb_stack_read_checked(va).unwrap_or(0)
}
unsafe fn csr_sb_stack_read_checked(va: u64) -> Option<u64> {
    let end = va.checked_add(8)?;
    if va < CSR_SB_STACK_BASE || end > CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000 {
        return None;
    }
    Some(core::ptr::read_volatile(
        (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *const u64,
    ))
}
fn csr_sb_stack_has_range(va: u64, len: usize) -> bool {
    (va >= CSR_SB_STACK_BASE
        && va
            .checked_add(len as u64)
            .is_some_and(|end| end <= CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000))
        || csr_heap_has_range(va, len)
}
unsafe fn csr_sb_stack_copyout(va: u64, bytes: &[u8]) -> bool {
    if !csr_sb_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= CSR_SB_STACK_BASE {
        CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)
    } else {
        CSRSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), mirror as *mut u8, bytes.len());
    true
}
unsafe fn csr_sb_stack_copyin(va: u64, bytes: &mut [u8]) -> bool {
    if !csr_sb_stack_has_range(va, bytes.len()) {
        return false;
    }
    let mirror = if va >= CSR_SB_STACK_BASE {
        CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)
    } else {
        CSRSS_HEAP_MIRROR_VA + (va - SMSS_ALLOC_VA)
    };
    core::ptr::copy_nonoverlapping(mirror as *const u8, bytes.as_mut_ptr(), bytes.len());
    true
}

pub(crate) fn csr_thread_stack_has_range(sb: bool, va: u64, len: usize) -> bool {
    if sb {
        csr_sb_stack_has_range(va, len)
    } else {
        csr_stack_has_range(va, len)
    }
}

pub(crate) unsafe fn csr_thread_stack_copyin(sb: bool, va: u64, bytes: &mut [u8]) -> bool {
    if sb {
        csr_sb_stack_copyin(va, bytes)
    } else {
        csr_stack_copyin(va, bytes)
    }
}

pub(crate) unsafe fn csr_thread_stack_copyout(sb: bool, va: u64, bytes: &[u8]) -> bool {
    if sb {
        csr_sb_stack_copyout(va, bytes)
    } else {
        csr_stack_copyout(va, bytes)
    }
}

unsafe fn csr_set_thread_information_call(
    nt_handler: &mut ExecNtHandler,
    sb: bool,
    tid: u64,
    handle: u64,
    information_class: u32,
    information: u64,
    information_length: u32,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    let expected = match ExecNtHandler::thread_set_length(information_class) {
        Ok(length) => length,
        Err(status) => return status as u64,
    };
    if information_length as usize != expected {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as u64;
    }
    let mut value = [0u8; 0x10];
    if expected != 0 {
        let alignment_mask = if information_class == 38 { 7 } else { 3 };
        if information & alignment_mask != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !csr_thread_stack_copyin(sb, information, &mut value[..expected]) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = tid;
    let status = if information_class == 38 {
        match nt_handler.resolve_thread_for_set(handle) {
            Err(status) => status,
            Ok(target) => {
                let raw_byte_length = u16::from_le_bytes(value[..2].try_into().unwrap()) as usize;
                let buffer = u64::from_le_bytes(value[8..16].try_into().unwrap());
                let byte_length = if buffer == 0 { 0 } else { raw_byte_length & !1 };
                let source_valid = if buffer == 0 || raw_byte_length == 0 {
                    true
                } else if buffer & 1 != 0 {
                    false
                } else {
                    let mut last = [0u8; 1];
                    buffer
                        .checked_add(raw_byte_length as u64 - 1)
                        .is_some_and(|address| csr_thread_stack_copyin(sb, address, &mut last))
                };
                if buffer != 0 && raw_byte_length != 0 && buffer & 1 != 0 {
                    STATUS_DATATYPE_MISALIGNMENT as u32
                } else if !source_valid {
                    STATUS_ACCESS_VIOLATION as u32
                } else if byte_length > nt_process::THREAD_NAME_MAX_UNITS * 2 {
                    0xC000_009A
                } else {
                    let mut bytes = [0u8; nt_process::THREAD_NAME_MAX_UNITS * 2];
                    if byte_length != 0
                        && !csr_thread_stack_copyin(sb, buffer, &mut bytes[..byte_length])
                    {
                        STATUS_ACCESS_VIOLATION as u32
                    } else {
                        let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
                        for (index, chunk) in bytes[..byte_length].chunks_exact(2).enumerate() {
                            name[index] = u16::from_le_bytes([chunk[0], chunk[1]]);
                        }
                        nt_handler.set_thread_name_resolved(target, &name[..byte_length / 2])
                    }
                }
            }
        }
    } else {
        nt_handler.set_thread_information_captured(
            handle,
            information_class,
            u64::from_le_bytes(value[..8].try_into().unwrap()),
        )
    };
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    status as u64
}

unsafe fn csr_sb_query_thread_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information_class: u32,
    information: u64,
    information_length: u32,
    return_length: u64,
) -> u64 {
    if information_class == 38 {
        return csr_sb_query_thread_name_call(
            nt_handler,
            handle,
            information,
            information_length,
            return_length,
        );
    }
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    let expected = match ExecNtHandler::thread_query_length(information_class) {
        Ok(length) => length,
        Err(status) => return status as u64,
    };
    if information_length as usize != expected {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as u64;
    }
    if information != 0 {
        if information & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let mut probe = [0u8; 0x30];
        if !csr_sb_stack_copyin(information, &mut probe[..expected]) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if return_length != 0 && !csr_sb_stack_has_range(return_length, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
    let mut status = match nt_handler.query_thread_information_captured(handle, information_class) {
        Ok((output, length)) => {
            if csr_sb_stack_copyout(information, &output[..length]) {
                if information_class == 0 {
                    WL_LISTENER_TEB_QUERIED.fetch_add(1, Ordering::Relaxed);
                }
                0
            } else {
                STATUS_ACCESS_VIOLATION
            }
        }
        Err(status) => status as u64,
    };
    if return_length != 0 && !csr_sb_stack_copyout(return_length, &(expected as u32).to_le_bytes())
    {
        status = STATUS_ACCESS_VIOLATION;
    }
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    status
}

unsafe fn csr_sb_query_thread_name_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information: u64,
    information_length: u32,
    return_length: u64,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
    if information != 0 {
        if information & 7 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !csr_sb_stack_has_range(information, information_length as usize) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if return_length != 0 && !csr_sb_stack_has_range(return_length, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
    let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
    let query = nt_handler.query_thread_name_captured(handle, &mut name);
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;

    let mut required = 0u32;
    let mut status = match query {
        Ok(units) => {
            required = (0x10 + units * 2) as u32;
            if information_length < required {
                STATUS_BUFFER_TOO_SMALL
            } else {
                let mut output = [0u8; 0x10 + nt_process::THREAD_NAME_MAX_UNITS * 2];
                if units != 0 {
                    let bytes = (units * 2) as u16;
                    output[..2].copy_from_slice(&bytes.to_le_bytes());
                    output[2..4].copy_from_slice(&bytes.to_le_bytes());
                    output[8..16].copy_from_slice(&(information + 0x10).to_le_bytes());
                    for (index, unit) in name[..units].iter().enumerate() {
                        output[0x10 + index * 2..0x12 + index * 2]
                            .copy_from_slice(&unit.to_le_bytes());
                    }
                }
                if csr_sb_stack_copyout(information, &output[..required as usize]) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
        }
        Err(status) => status as u64,
    };
    if return_length != 0 && !csr_sb_stack_copyout(return_length, &required.to_le_bytes()) {
        status = STATUS_ACCESS_VIOLATION;
    }
    status
}

unsafe fn csr_query_thread_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information_class: u32,
    information: u64,
    information_length: u32,
    return_length: u64,
) -> u64 {
    if information_class == 38 {
        return csr_query_thread_name_call(
            nt_handler,
            handle,
            information,
            information_length,
            return_length,
        );
    }
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    let expected = match ExecNtHandler::thread_query_length(information_class) {
        Ok(length) => length,
        Err(status) => return status as u64,
    };
    if information_length as usize != expected {
        return nt_process::STATUS_INFO_LENGTH_MISMATCH as u64;
    }
    if information != 0 {
        if information & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        let mut probe = [0u8; 0x30];
        if !csr_stack_copyin(information, &mut probe[..expected]) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if return_length != 0 && !csr_stack_has_range(return_length, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
    let mut status = match nt_handler.query_thread_information_captured(handle, information_class) {
        Ok((output, length)) => {
            if csr_stack_copyout(information, &output[..length]) {
                if information_class == 0 {
                    WL_LISTENER_TEB_QUERIED.fetch_add(1, Ordering::Relaxed);
                }
                0
            } else {
                STATUS_ACCESS_VIOLATION
            }
        }
        Err(status) => status as u64,
    };
    if return_length != 0 && !csr_stack_copyout(return_length, &(expected as u32).to_le_bytes()) {
        status = STATUS_ACCESS_VIOLATION;
    }
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;
    status
}

unsafe fn csr_query_thread_name_call(
    nt_handler: &mut ExecNtHandler,
    handle: u64,
    information: u64,
    information_length: u32,
    return_length: u64,
) -> u64 {
    const STATUS_ACCESS_VIOLATION: u64 = 0xC000_0005;
    const STATUS_DATATYPE_MISALIGNMENT: u64 = 0x8000_0002;
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
    if information != 0 {
        if information & 7 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !csr_stack_has_range(information, information_length as usize) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if return_length != 0 && !csr_stack_has_range(return_length, 4) {
        return STATUS_ACCESS_VIOLATION;
    }
    let saved_pi = nt_handler.pi;
    let saved_tid = nt_handler.current_tid;
    nt_handler.pi = 1;
    nt_handler.current_tid = hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
    let mut name = [0u16; nt_process::THREAD_NAME_MAX_UNITS];
    let query = nt_handler.query_thread_name_captured(handle, &mut name);
    nt_handler.pi = saved_pi;
    nt_handler.current_tid = saved_tid;

    let mut required = 0u32;
    let mut status = match query {
        Ok(units) => {
            required = (0x10 + units * 2) as u32;
            if information_length < required {
                STATUS_BUFFER_TOO_SMALL
            } else {
                let mut output = [0u8; 0x10 + nt_process::THREAD_NAME_MAX_UNITS * 2];
                if units != 0 {
                    let bytes = (units * 2) as u16;
                    output[..2].copy_from_slice(&bytes.to_le_bytes());
                    output[2..4].copy_from_slice(&bytes.to_le_bytes());
                    output[8..16].copy_from_slice(&(information + 0x10).to_le_bytes());
                    for (index, unit) in name[..units].iter().enumerate() {
                        output[0x10 + index * 2..0x12 + index * 2]
                            .copy_from_slice(&unit.to_le_bytes());
                    }
                }
                if csr_stack_copyout(information, &output[..required as usize]) {
                    0
                } else {
                    STATUS_ACCESS_VIOLATION
                }
            }
        }
        Err(status) => status as u64,
    };
    if return_length != 0 && !csr_stack_copyout(return_length, &required.to_le_bytes()) {
        status = STATUS_ACCESS_VIOLATION;
    }
    status
}

/// Demand-fill one code/data page for the CSR API thread during the rendezvous. The page is in
/// csrss's own image (PE_LOAD_BASE..img_end), ntdll, or a mapped registry DLL (csrsrv/user32/…, via
/// `dll_for_page`). Filled through an isolated executive scratch (CSR_FILL_SCRATCH_BASE, own PT) then
/// mapped into csrss's VSpace. Returns false if the page belongs to none (a genuine fault).
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn csr_fill_page(
    page: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    fill_idx: &mut u64,
) -> bool {
    let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
        (PE_LOAD_BASE, csrss_pe)
    } else if nt_base != 0 && page >= nt_base && page < nt_end {
        match ntdll_pe {
            Some(p) => (nt_base, p),
            None => return false,
        }
    } else if let Some((i, _)) = reg.dll_for_page(page) {
        match dll_pes[i].as_ref() {
            Some(p) => (reg.base(i), p),
            None => return false,
        }
    } else {
        return false;
    };
    if CSR_FILL_PT_DONE.swap(1, Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(
            spt,
            LBL_X86_PAGE_TABLE_MAP,
            CSR_FILL_SCRATCH_BASE,
            CAP_INIT_THREAD_VSPACE,
        );
    }
    let scratch_index = CSR_FILL_NEXT.fetch_add(1, Ordering::Relaxed);
    if scratch_index >= 512 {
        return false;
    }
    let scratch = CSR_FILL_SCRATCH_BASE + scratch_index * 0x1000;
    *fill_idx += 1;
    let f = alloc_frame();
    let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    let rights = fill_image_page(tpe, (page - base) as u32, scratch);
    let _ = page_map(copy_cap(f), page, rights, csrss_pml4);
    true
}

/// Deliver SMSS's reverse connection to the already-parked real CsrSbApiRequestThread and drive
/// its real accept/complete calls. Returns the client-side communication handle used by SMSS.
#[allow(clippy::too_many_arguments)]
unsafe fn csr_sb_accept_connection(
    conn_id: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &ExecNtHandler,
) -> u64 {
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    let ep = CSR_SB_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSR_SB_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 || CSR_SB_RECEIVE_PARKED.swap(0, Ordering::Relaxed) == 0 {
        return 0;
    }
    let recvmsg = CSR_SB_RECVMSG.load(Ordering::Relaxed);
    let port = CSR_SB_RECVPORT.load(Ordering::Relaxed);
    let (smss_pid, smss_tid) = live_hosted_cid_for_pi(nt_handler, 0);
    let delivered = lpc_client()
        .and_then(|c| c.reply_wait_receive(port).ok())
        .is_some_and(|r| r.connection_id == conn_id);
    if !delivered {
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return 0;
    }
    csr_sb_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
    csr_sb_stack_write(recvmsg + 0x08, smss_pid);
    csr_sb_stack_write(recvmsg + 0x10, smss_tid);
    set_reply_mr(15, 0);
    set_reply_mr(16, CSR_SB_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, CSR_SB_RECV_FLAGS.load(Ordering::Relaxed));
    client_reply_on(reply, 18, 0, 0, 0, CSR_SB_RECV_RDX.load(Ordering::Relaxed));

    let mut client_handle = 0;
    let mut fill_idx = 0;
    let (_badge, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    for _ in 0..8000 {
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0;
            let rsp = m1;
            let arg1 = m2;
            let arg3 = get_recv_mr(4);
            let arg4 = get_recv_mr(5);
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn;
            m2 = 0;
            mi = (2u64 << 12) | (mi & 0x7f);
        }
        match mi >> 12 {
            6 => {
                let page = m1 & !0xfff;
                if m1 < 0x10000
                    || !csr_fill_page(
                        page,
                        csrss_pml4,
                        csrss_pe,
                        img_end,
                        nt_base,
                        nt_end,
                        ntdll_pe,
                        reg,
                        dll_pes,
                        &mut fill_idx,
                    )
                {
                    return 0;
                }
                client_reply_on(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return 0 };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return 0;
                }
                client_reply_on(reply, 3, m0 + 3, m1, m2, 0);
            }
            2 => {
                let ssn = m0;
                let sp = get_recv_mr(16);
                let flags = get_recv_mr(17);
                let rdx = m3;
                match ssn {
                    SSN_ACCEPT_CONNECT => {
                        let out = get_recv_mr(9);
                        let accept = get_recv_mr(8) != 0;
                        let server_handle = lpc_client()
                            .and_then(|c| c.accept_connect(conn_id, accept, rdx).ok())
                            .unwrap_or(0);
                        csr_sb_stack_write(out, server_handle);
                    }
                    SSN_COMPLETE_CONNECT => {
                        if let Some((handle, _)) =
                            lpc_client().and_then(|c| c.complete_connect(conn_id).ok())
                        {
                            client_handle = handle;
                        }
                    }
                    SSN_REPLY_WAIT_RECV => {
                        CSR_SB_RECVMSG.store(get_recv_mr(8), Ordering::Relaxed);
                        CSR_SB_RECVPORT.store(get_recv_mr(9), Ordering::Relaxed);
                        CSR_SB_RECV_SP.store(sp, Ordering::Relaxed);
                        CSR_SB_RECV_FLAGS.store(flags, Ordering::Relaxed);
                        CSR_SB_RECV_RDX.store(rdx, Ordering::Relaxed);
                        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                        print_str(
                            b"[csr-sb] authentic reverse connection accepted; worker re-parked\n",
                        );
                        return client_handle;
                    }
                    _ => {
                        print_str(b"[csr-sb] unexpected reverse-connect SSN=");
                        print_u64(ssn);
                        print_str(b"\n");
                        return 0;
                    }
                }
                set_reply_mr(15, 0);
                set_reply_mr(16, sp);
                set_reply_mr(17, flags);
                client_reply_on(reply, 18, 0, 0, 0, rdx);
            }
            _ => return 0,
        }
        let (_badge, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    0
}

/// Drive one ordinary SB request through the real `CsrSbApiRequestThread`. The worker receives the
/// brokered bytes on its named listen port, executes csrsrv's dispatcher, sends the reply from its
/// next `NtReplyWaitReceivePort`, and remains parked for the following session-manager request.
#[allow(clippy::too_many_arguments)]
unsafe fn csr_sb_api_request_rendezvous(
    client_port: u64,
    request_va: u64,
    reply_va: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &mut ExecNtHandler,
) -> bool {
    const SSN_SET_INFO_PROCESS: u64 = 237;
    const SSN_QUERY_OBJECT: u64 = 170;
    const SSN_SET_INFO_OBJECT: u64 = 236;
    const SSN_RESUME_THREAD: u64 = 214;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_CLOSE: u64 = 27;

    let ep = CSR_SB_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSR_SB_SLOT.load(Ordering::Relaxed);
    let was_parked = CSR_SB_RECEIVE_PARKED.swap(0, Ordering::Relaxed);
    print_str(b"[csr-sb-api] enter client=0x");
    print_hex_u64(client_port);
    print_str(b" request=0x");
    print_hex_u64(request_va);
    print_str(b" parked=");
    print_u64(was_parked);
    print_str(b"\n");
    if ep == 0 || reply == 0 || was_parked == 0 {
        print_str(b"[csr-sb-api] missing endpoint/reply/parked receive\n");
        return false;
    }
    let request_len = ((sm_stack_read(request_va) >> 16) as u16) as usize;
    print_str(b"[csr-sb-api] request length=");
    print_u64(request_len as u64);
    print_str(b" listen=0x");
    print_hex_u64(CSR_SB_RECVPORT.load(Ordering::Relaxed));
    print_str(b"\n");
    if !(0x28..=0x120).contains(&request_len) {
        print_str(b"[csr-sb-api] invalid request length\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let mut request = [0u8; 0x120];
    if !sm_stack_copyin(request_va, &mut request[..request_len]) {
        print_str(b"[csr-sb-api] request is outside SM worker stack\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let smss_pid = live_hosted_pid_for_leaf(nt_handler, b"smss.exe").unwrap_or(0) as u64;
    let smss_tid = live_hosted_main_tid_for_leaf(nt_handler, b"smss.exe").unwrap_or(0) as u64;
    request[4..6].copy_from_slice(&nt_lpc_abi::msg_type::LPC_REQUEST.to_le_bytes());
    request[8..16].copy_from_slice(&smss_pid.to_le_bytes());
    request[16..24].copy_from_slice(&smss_tid.to_le_bytes());
    if lpc_client()
        .and_then(|client| {
            client
                .request_wait_reply(client_port, &request[..request_len])
                .ok()
        })
        .is_none()
    {
        print_str(b"[csr-sb-api] broker request send failed\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let listen_port = CSR_SB_RECVPORT.load(Ordering::Relaxed);
    let Some(received) =
        lpc_client().and_then(|client| client.reply_wait_receive(listen_port).ok())
    else {
        print_str(b"[csr-sb-api] broker listen receive failed\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    };
    let recvmsg = CSR_SB_RECVMSG.load(Ordering::Relaxed);
    if received.connection_info.len() != request_len
        || !csr_sb_stack_copyout(recvmsg, &received.connection_info)
    {
        print_str(b"[csr-sb-api] received length/copyout mismatch got=");
        print_u64(received.connection_info.len() as u64);
        print_str(b"\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    csr_sb_stack_write16(recvmsg + 4, nt_lpc_abi::msg_type::LPC_REQUEST);
    csr_sb_stack_write(recvmsg + 8, smss_pid);
    csr_sb_stack_write(recvmsg + 16, smss_tid);
    let context_out = CSR_SB_RECV_RDX.load(Ordering::Relaxed);
    if context_out != 0 {
        csr_sb_stack_write(context_out, received.port_context);
    }
    set_reply_mr(15, 0);
    set_reply_mr(16, CSR_SB_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, CSR_SB_RECV_FLAGS.load(Ordering::Relaxed));
    client_reply_on(reply, 18, 0, 0, 0, 0);

    let mut fill_idx = 0;
    let (_badge, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    for _ in 0..8000 {
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0;
            let rsp = m1;
            let arg1 = m2;
            let arg3 = get_recv_mr(4);
            let arg4 = get_recv_mr(5);
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn;
            m2 = 0;
            mi = (2u64 << 12) | (mi & 0x7f);
        }
        match mi >> 12 {
            6 => {
                let page = m1 & !0xfff;
                if m1 < 0x10000
                    || !csr_fill_page(
                        page,
                        csrss_pml4,
                        csrss_pe,
                        img_end,
                        nt_base,
                        nt_end,
                        ntdll_pe,
                        reg,
                        dll_pes,
                        &mut fill_idx,
                    )
                {
                    print_str(b"[csr-sb-api] unresolved worker fault\n");
                    return false;
                }
                client_reply_on(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                client_reply_on(reply, 3, m0 + 3, m1, m2, 0);
            }
            2 => {
                let ssn = m0;
                let sp = get_recv_mr(16);
                let flags = get_recv_mr(17);
                let rdx = m3;
                let mut result = 0u64;
                print_str(b"[csr-sb-api] worker SSN=");
                print_u64(ssn);
                print_str(b"\n");
                match ssn {
                    SSN_SET_INFO_PROCESS => {}
                    SSN_NT_PROTECT_VM => {
                        let stack_arg4 = sp
                            .checked_add(0x28)
                            .and_then(|address| csr_sb_stack_read_checked(address));
                        result = match stack_arg4 {
                            Some(old_protect) => {
                                let protect_args = [
                                    get_recv_mr(9),
                                    rdx,
                                    get_recv_mr(7),
                                    get_recv_mr(8),
                                    old_protect,
                                ];
                                let saved_pi = nt_handler.pi;
                                let saved_tid = nt_handler.current_tid;
                                nt_handler.pi = 1;
                                nt_handler.current_tid =
                                    hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
                                let status = nt_handler.nt_protect_virtual_memory_with_user_memory(
                                    &protect_args,
                                    SyscallUserMemory::CsrThreadStack { sb: true },
                                );
                                nt_handler.pi = saved_pi;
                                nt_handler.current_tid = saved_tid;
                                print_str(
                                    b"[csr-sb-api] serviced worker NtProtectVirtualMemory status=0x",
                                );
                                print_hex(status);
                                print_str(b"\n");
                                status as u64
                            }
                            None => 0xC000_0005,
                        };
                    }
                    SSN_NT_SET_INFO_THREAD => {
                        result = csr_set_thread_information_call(
                            nt_handler,
                            true,
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi),
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8) as u32,
                        );
                    }
                    SSN_NT_QUERY_INFORMATION_THREAD => {
                        result = match sp
                            .checked_add(0x28)
                            .and_then(|address| csr_sb_stack_read_checked(address))
                        {
                            Some(return_length) => csr_sb_query_thread_call(
                                nt_handler,
                                get_recv_mr(9),
                                rdx as u32,
                                get_recv_mr(7),
                                get_recv_mr(8) as u32,
                                return_length,
                            ),
                            None => 0xC000_0005,
                        };
                    }
                    SSN_QUERY_OBJECT => {
                        result = match sp
                            .checked_add(0x28)
                            .and_then(|address| csr_sb_stack_read_checked(address))
                        {
                            Some(return_length) => {
                                let query_args = [
                                    get_recv_mr(9),
                                    rdx,
                                    get_recv_mr(7),
                                    get_recv_mr(8),
                                    return_length,
                                ];
                                let saved_pi = nt_handler.pi;
                                let saved_tid = nt_handler.current_tid;
                                nt_handler.pi = 1;
                                nt_handler.current_tid =
                                    hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
                                let status = nt_handler.nt_query_object_with_user_memory(
                                    &query_args,
                                    SyscallUserMemory::CsrThreadStack { sb: true },
                                );
                                nt_handler.pi = saved_pi;
                                nt_handler.current_tid = saved_tid;
                                print_str(b"[csr-sb-api] serviced worker NtQueryObject status=0x");
                                print_hex(status);
                                print_str(b"\n");
                                status as u64
                            }
                            None => 0xC000_0005,
                        };
                    }
                    SSN_SET_INFO_OBJECT => {
                        let set_args = [get_recv_mr(9), rdx, get_recv_mr(7), get_recv_mr(8)];
                        let saved_pi = nt_handler.pi;
                        let saved_tid = nt_handler.current_tid;
                        nt_handler.pi = 1;
                        nt_handler.current_tid =
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
                        let status = nt_handler.nt_set_information_object_with_user_memory(
                            &set_args,
                            SyscallUserMemory::CsrThreadStack { sb: true },
                        );
                        nt_handler.pi = saved_pi;
                        nt_handler.current_tid = saved_tid;
                        print_str(b"[csr-sb-api] serviced worker NtSetInformationObject status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        result = status as u64;
                    }
                    SSN_RESUME_THREAD => {
                        let resume_args = [get_recv_mr(9), rdx];
                        let saved_pi = nt_handler.pi;
                        let saved_tid = nt_handler.current_tid;
                        nt_handler.pi = 1;
                        nt_handler.current_tid =
                            hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrSbApi);
                        let status = nt_handler.nt_resume_thread_with_user_memory(
                            &resume_args,
                            SyscallUserMemory::CsrThreadStack { sb: true },
                        );
                        nt_handler.pi = saved_pi;
                        nt_handler.current_tid = saved_tid;
                        print_str(b"[csr-sb-api] serviced worker NtResumeThread status=0x");
                        print_hex(status);
                        print_str(b"\n");
                        result = status as u64;
                    }
                    SSN_CLOSE => {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 1;
                        nt_handler.close_current_handle(get_recv_mr(9));
                        nt_handler.pi = saved_pi;
                    }
                    SSN_REPLY_WAIT_RECV => {
                        let reply_msg = get_recv_mr(7);
                        let mut reply_bytes = [0u8; 0x120];
                        let reply_len = if reply_msg != 0 {
                            let total = ((csr_sb_stack_read(reply_msg) >> 16) as u16) as usize;
                            if !(0x28..=0x120).contains(&total)
                                || !csr_sb_stack_copyin(reply_msg, &mut reply_bytes[..total])
                            {
                                return false;
                            }
                            total
                        } else {
                            0
                        };
                        let _ = lpc_client().and_then(|client| {
                            client
                                .reply_wait_receive_with_reply(
                                    listen_port,
                                    &reply_bytes[..reply_len],
                                )
                                .ok()
                        });
                        let Some(response) = lpc_client()
                            .and_then(|client| client.reply_wait_receive(client_port).ok())
                        else {
                            return false;
                        };
                        if response.connection_info.is_empty()
                            || !sm_stack_copyout(reply_va, &response.connection_info)
                        {
                            return false;
                        }
                        CSR_SB_RECVMSG.store(get_recv_mr(8), Ordering::Relaxed);
                        CSR_SB_RECVPORT.store(get_recv_mr(9), Ordering::Relaxed);
                        CSR_SB_RECV_SP.store(sp, Ordering::Relaxed);
                        CSR_SB_RECV_FLAGS.store(flags, Ordering::Relaxed);
                        CSR_SB_RECV_RDX.store(rdx, Ordering::Relaxed);
                        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                        print_str(b"[csr-sb-api] real SbpCreateSession reply completed\n");
                        return true;
                    }
                    _ => {
                        print_str(b"[csr-sb-api] unexpected worker SSN=");
                        print_u64(ssn);
                        print_str(b"\n");
                        return false;
                    }
                }
                set_reply_mr(15, 0);
                set_reply_mr(16, sp);
                set_reply_mr(17, flags);
                client_reply_on(reply, 18, result, 0, 0, rdx);
            }
            _ => return false,
        }
        let (_badge, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
        mi = nmi;
        m0 = nm0;
        m1 = nm1;
        m2 = nm2;
        m3 = nm3;
    }
    false
}

/// AUTHENTIC CSR accept: drive csrss's REAL `CsrApiRequestThread` through one pending client
/// `NtSecureConnectPort(\Windows\ApiPort)`. Mirrors `sm_rendezvous`: a nested loop on
/// `CSR_FAULT_EP`/`REPLY_CSRLOOP` services the thread's real syscalls until `NtCompleteConnectPort`.
/// The thread's pre-loop `CsrConnectToUser` is in-process (no syscalls; ClientThreadSetup is a stub
/// returning TRUE, and CsrLocateThreadInProcess returns non-NULL since csrss registered its static
/// threads at init → no spin). On the connection: NtSetEvent (signal the real hRequestEvent) →
/// NtReplyWaitReceivePort (drain the broker's pending connection + marshal the PORT_MESSAGE:
/// Type=LPC_CONNECTION_REQUEST, ClientId = the CSR worker CID so CsrLocateThreadByClientId matches a
/// registered CSR_THREAD → CsrProcess=CsrRootProcess → AllowConnection=TRUE) → [NtMapViewOfSection of
/// the CSR shared section — no-op success] → NtAcceptConnectPort (broker accept) → NtCompleteConnectPort
/// (broker complete). Returns the client comm-port handle (0 on wall). After the accept reply, the
/// worker is left to run into its next receive and the next rendezvous drains that state if needed.
///
/// ★ FLAGGED RESIDUALS (host limitations, NOT the accept mechanism — the real thread runs + issues the
/// real receive/accept syscalls): (a) THE ACCEPT DECISION — CsrApiHandleConnectionRequest's
/// CsrLocateThreadByClientId (hash table, exact CID) finds no registered CSR_PROCESS for hosted
/// clients yet (that needs the SM→SB→CsrSrvCreateProcess *session-registration* plane, a separate
/// fork), so the real thread can compute AllowConnection=FALSE and pass Accept=FALSE. The
/// executive OVERRIDES the broker to accept+complete at the NtAcceptConnectPort syscall so the client
/// connects; (b) the CSR_API_CONNECTINFO reply payload + shared-section mapping into clients are still
/// executive-modeled (in `csr_client_connect`) because the isolated LPC broker carries no message
/// payload across the connect. (The marshaled connection-request ClientId is now cosmetic for hosted
/// clients until CSR process registration lands.)
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn csr_rendezvous(
    conn_id: u64,
    csrss_pml4: u64,
    csrss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
    nt_handler: &mut ExecNtHandler,
) -> u64 {
    const SSN_SET_EVENT: u64 = 228;
    const SSN_MAP_VIEW: u64 = 113;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    let ep = CSR_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_CSRLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return 0;
    }
    let mut client_handle = 0u64;
    let mut fill_idx = 0u64;
    let mut guard = 0u64;
    let csrss_pid = live_hosted_pid_for_leaf(nt_handler, b"csrss.exe").unwrap_or(0) as u64;
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) =
        if CSR_API_RECEIVE_PARKED.swap(0, Ordering::Relaxed) != 0 {
            let recvmsg = CSR_API_RECVMSG.load(Ordering::Relaxed);
            let port = CSR_API_RECVPORT.load(Ordering::Relaxed);
            let Some(r) = lpc_client().and_then(|c| c.reply_wait_receive(port).ok()) else {
                CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                return 0;
            };
            if r.connection_id == 0 {
                CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                return 0;
            }
            CSR_MSGS.fetch_add(1, Ordering::Relaxed);
            csr_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
            csr_stack_write(recvmsg + 0x08, csrss_pid);
            csr_stack_write(
                recvmsg + 0x10,
                hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi),
            );
            set_reply_mr(15, 0);
            set_reply_mr(16, CSR_API_RECV_SP.load(Ordering::Relaxed));
            set_reply_mr(17, CSR_API_RECV_FLAGS.load(Ordering::Relaxed));
            client_reply_on(reply, 18, 0, 0, 0, CSR_API_RECV_RDX.load(Ordering::Relaxed));
            recv_full_r12(ep, reply)
        } else {
            recv_full_r12(ep, reply)
        };
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[csr-rdv] WALL: guard exhausted\n");
            break;
        }
        // BATCH 7: the CSR-API thread (CsrApiRequestThread) runs on OUR ntdll's NATIVE seL4-Call
        // transport (spawn_csr_loop_thread sets native: true), so its Nt* syscalls arrive as a native
        // `Call` (label NT_NATIVE_SYSCALL_LABEL), NOT an UnknownSyscall fault (label 2). NORMALIZE it
        // into the label-2 register-slot layout the accept body below reads — mirroring sm_rendezvous:
        // MR0=SSN, MR1=rsp, MR2/MR3=arg1/arg2, MR4/MR5=arg3/arg4 (from the executive's recv IPC buffer)
        // → the fault frame slots R10@9=arg1, R8@7=arg3, R9@8=arg4, SP@16=rsp, FLAGS@17=0; re-label 2.
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0; // MR0
            let rsp = m1; // MR1 = caller rsp
            let arg1 = m2; // MR2
            let arg3 = get_recv_mr(4); // MR4 (IPC buffer)
            let arg4 = get_recv_mr(5); // MR5 (IPC buffer)
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            m0 = ssn; // the accept body reads ssn = m0
            m2 = 0; // resume_ip unused for a native reply (no fault restart)
            mi = (2u64 << 12) | (mi & 0x7F);
        }
        let label = mi >> 12;
        if label == 6 {
            let page = m1 & !0xFFFu64;
            if m1 < 0x10000
                || !csr_fill_page(
                    page,
                    csrss_pml4,
                    csrss_pe,
                    img_end,
                    nt_base,
                    nt_end,
                    ntdll_pe,
                    reg,
                    dll_pes,
                    &mut fill_idx,
                )
            {
                print_str(b"[csr-rdv] WALL: unresolved fault ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((m1 >> 32) as u32);
                print_hex(m1 as u32);
                print_str(b"\n");
                break;
            }
            client_reply_on(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        if label == 3 {
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base
                    && fip < nt_end
                    && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD)
                {
                    client_reply_on(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
            }
            print_str(b"[csr-rdv] WALL: exception fip=0x");
            print_hex((fip >> 32) as u32);
            print_hex(fip as u32);
            print_str(b" num=");
            print_u64(m3);
            print_str(b"\n");
            break;
        }
        if label == 2 {
            let ssn = m0;
            let resume_ip = m2;
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let rdx = m3;
            let mut result = 0u64;
            match ssn {
                SSN_SET_EVENT => {
                    let event_handle = get_recv_mr(9); // R10
                    print_str(b"[csr-rdv] real NtSetEvent handle=0x");
                    print_hex(event_handle as u32);
                    print_str(b"\n");
                    if rdx != 0
                        && (rdx & 3 != 0
                            || rdx < CSR_STACK_BASE
                            || rdx > CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 - 4)
                    {
                        result = if rdx & 3 != 0 {
                            0x8000_0002
                        } else {
                            0xC000_0005
                        };
                    } else {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 1;
                        result = match nt_handler
                            .event_index_for_handle(event_handle, EVENT_MODIFY_STATE)
                        {
                            Ok(index) => match nt_handler.events.set_existing(index as u64) {
                                Some(previous) => {
                                    if rdx != 0 {
                                        let _ = csr_stack_write32(rdx, previous as u32);
                                    }
                                    if !previous {
                                        wait_wake_dispatcher_set(nt_handler);
                                    }
                                    0
                                }
                                None => 0xC000_0008, // STATUS_INVALID_HANDLE
                            },
                            Err(status) => status as u64,
                        };
                        nt_handler.pi = saved_pi;
                    }
                }
                SSN_NT_PROTECT_VM => {
                    let stack_arg4 = sp
                        .checked_add(0x28)
                        .and_then(|address| csr_stack_read(address));
                    result = match stack_arg4 {
                        Some(old_protect) => {
                            let protect_args = [
                                get_recv_mr(9),
                                rdx,
                                get_recv_mr(7),
                                get_recv_mr(8),
                                old_protect,
                            ];
                            let saved_pi = nt_handler.pi;
                            let saved_tid = nt_handler.current_tid;
                            nt_handler.pi = 1;
                            nt_handler.current_tid =
                                hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi);
                            let status = nt_handler.nt_protect_virtual_memory_with_user_memory(
                                &protect_args,
                                SyscallUserMemory::CsrThreadStack { sb: false },
                            );
                            nt_handler.pi = saved_pi;
                            nt_handler.current_tid = saved_tid;
                            print_str(
                                b"[csr-rdv] serviced worker NtProtectVirtualMemory status=0x",
                            );
                            print_hex(status);
                            print_str(b"\n");
                            status as u64
                        }
                        None => 0xC000_0005,
                    };
                }
                SSN_NT_SET_INFO_THREAD => {
                    result = csr_set_thread_information_call(
                        nt_handler,
                        false,
                        hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi),
                        get_recv_mr(9),
                        rdx as u32,
                        get_recv_mr(7),
                        get_recv_mr(8) as u32,
                    );
                }
                SSN_NT_QUERY_INFORMATION_THREAD => {
                    result = match sp
                        .checked_add(0x28)
                        .and_then(|address| csr_stack_read(address))
                    {
                        Some(return_length) => csr_query_thread_call(
                            nt_handler,
                            get_recv_mr(9),
                            rdx as u32,
                            get_recv_mr(7),
                            get_recv_mr(8) as u32,
                            return_length,
                        ),
                        None => 0xC000_0005,
                    };
                }
                SSN_MAP_VIEW => {} // NtMapViewOfSection (CSR shared section into CsrRootProcess) — success
                SSN_REPLY_WAIT_RECV => {
                    let recvmsg = get_recv_mr(8); // R9 = &ReceiveMsg.Header
                    let port = get_recv_mr(9); // R10 = CsrApiPort handle
                    let got = lpc_client().and_then(|c| c.reply_wait_receive(port).ok());
                    match got {
                        Some(r) if r.connection_id != 0 => {
                            // The REAL CsrApiRequestThread received a live CSR API message off
                            // \Windows\ApiPort (an LPC_CONNECTION_REQUEST from winlogon's kernel32 CSR
                            // client). This is genuine winlogon↔csrss CSR message-plane traffic on the
                            // real path (NtReplyWaitReceivePort returning a real connection) — count it.
                            CSR_MSGS.fetch_add(1, Ordering::Relaxed);
                            csr_stack_write16(
                                recvmsg + 0x04,
                                nt_lpc_client::LPC_CONNECTION_REQUEST,
                            );
                            csr_stack_write(recvmsg + 0x08, csrss_pid);
                            csr_stack_write(
                                recvmsg + 0x10,
                                hosted_role_tid(nt_handler, 1, HostedThreadRole::CsrApi),
                            );
                        }
                        _ => {
                            // No pending connection (the re-park receive): leave the thread PARKED.
                            CSR_API_RECVMSG.store(recvmsg, Ordering::Relaxed);
                            CSR_API_RECVPORT.store(port, Ordering::Relaxed);
                            CSR_API_RECV_SP.store(sp, Ordering::Relaxed);
                            CSR_API_RECV_FLAGS.store(flags, Ordering::Relaxed);
                            CSR_API_RECV_RDX.store(rdx, Ordering::Relaxed);
                            CSR_API_RECEIVE_PARKED.store(1, Ordering::Relaxed);
                            print_str(b"[csr-rdv] real API worker parked on NtReplyWaitReceivePort port=0x");
                            print_hex(port as u32);
                            print_str(b"\n");
                            break;
                        }
                    }
                }
                SSN_ACCEPT_CONNECT => {
                    // The REAL CsrApiHandleConnectionRequest reached NtAcceptConnectPort. Hosted
                    // clients are not registered CSR_PROCESSes yet, so ReactOS may pass Accept=FALSE
                    // and skip NtCompleteConnectPort. Force the broker accept+complete here and return
                    // the completed client comm-port handle to the blocked client.
                    let porthandle_out = get_recv_mr(9); // R10 = *ServerPort
                    let sh = lpc_client()
                        .and_then(|c| c.accept_connect(conn_id, true, rdx).ok())
                        .unwrap_or(0);
                    csr_stack_write(porthandle_out, sh);
                    if client_handle == 0 {
                        if let Some((ch, _)) =
                            lpc_client().and_then(|c| c.complete_connect(conn_id).ok())
                        {
                            client_handle = ch;
                        }
                    }
                }
                SSN_COMPLETE_CONNECT => {
                    if client_handle == 0 {
                        if let Some((ch, _)) =
                            lpc_client().and_then(|c| c.complete_connect(conn_id).ok())
                        {
                            client_handle = ch;
                        }
                    }
                }
                _ => {
                    // An incidental syscall on the accept path (NtDelayExecution retry,
                    // NtSetInformationThread, …) — no-op success + keep going (bounded by `guard`).
                    print_str(b"[csr-rdv] incidental SSN=");
                    print_u64(ssn);
                    print_str(b" -> no-op success\n");
                }
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            client_reply_on(reply, 18, result, 0, 0, rdx);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        print_str(b"[csr-rdv] WALL: unexpected label=");
        print_u64(label);
        print_str(b"\n");
        break;
    }
    client_handle
}
