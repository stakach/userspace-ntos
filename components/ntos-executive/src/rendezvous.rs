//! `rendezvous` — the SM/CSR loop-thread spawn + authentic SM/CSR rendezvous glue
//! (sm_fill_page/csr_fill_page + sm_rendezvous/csr_rendezvous + the loop-thread
//! spawners). Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

/// Spawn the AUTHENTIC SM-loop thread (path B): the general hosted thread running smss's real
/// `SmpApiLoop` (`entry_rip`) with RCX = the `\SmApiPort` handle (`port_handle`). Its stack is
/// MIRRORED into the executive so `sm_rendezvous` can write its syscall out-params. It faults to
/// `SM_FAULT_EP` (no standing receiver) and is resumed at spawn → PARKS on its first fault.
pub(crate) unsafe fn spawn_sm_loop_thread(smss_pml4: u64, entry_rip: u64, port_handle: u64) -> u64 {
    // BATCH 6: smss (pi 0) runs on OUR ntdll's NATIVE seL4-Call transport, so its SmpApiLoop 2nd
    // thread must too — DON'T set TCBSetHostedSyscalls (native Call → MR0=SSN). Its private IPC
    // frame lives at the VA ntdll derives from the active TEB; otherwise the Call faults as an
    // UnknownSyscall with m0=RAX garbage → `[sm-rdv] WALL: unexpected SSN`.
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
        cid_proc: 0,
        cid_thread: 0,
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

unsafe fn sm_capture_object_attributes(
    address: u64,
) -> Option<nt_ntdll_layout::ObjectAttributes> {
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
    let result = match nt_handler.open_process_captured(
        object_attributes,
        client_id,
        desired_access,
    ) {
        Ok((owner, handle)) => {
            if sm_stack_copyout(process_handle, &(handle as u64).to_le_bytes()) {
                nt_handler.account_published_process_handle(owner);
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
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, SM_FILL_SCRATCH_BASE, CAP_INIT_THREAD_VSPACE);
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
            sm_stack_write(recvmsg + 0x08, PM_PIDS[connector_pi].load(Ordering::Relaxed));
            sm_stack_write(recvmsg + 0x10, PM_TIDS[connector_pi].load(Ordering::Relaxed));
            sm_stack_write32(recvmsg + 0x28, received.subsystem_type);
            for (i, chunk) in received.connection_info.chunks_exact(2).take(120).enumerate() {
                sm_stack_write16(
                    recvmsg + 0x2c + i as u64 * 2,
                    u16::from_le_bytes([chunk[0], chunk[1]]),
                );
            }
            print_str(b"[sm-rdv] resumed parked receive for pi=");
            print_u64(connector_pi as u64);
            print_str(b" cid=");
            print_u64(PM_PIDS[connector_pi].load(Ordering::Relaxed));
            print_str(b"/");
            print_u64(PM_TIDS[connector_pi].load(Ordering::Relaxed));
            print_str(b"\n");
            set_reply_mr(15, 0);
            set_reply_mr(16, SM_RECV_SP.load(Ordering::Relaxed));
            set_reply_mr(17, SM_RECV_FLAGS.load(Ordering::Relaxed));
            send_on_reply(reply, 18, 0, 0, 0, SM_RECV_RDX.load(Ordering::Relaxed));
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
            if m1 < 0x10000 || !sm_fill_page(page, smss_pml4, smss_pe, img_end, nt_base, nt_end, ntdll_pe, &mut fill_idx) {
                print_str(b"[sm-rdv] WALL: unresolved fault ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((m1 >> 32) as u32);
                print_hex(m1 as u32);
                print_str(b"\n");
                break;
            }
            send_on_reply(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        if label == 3 {
            // Debug ntdll int-0x2d (DbgPrint from a DPRINT1) — skip the `int 0x2d; int3` (3 bytes),
            // like the main loop. m0 = FaultIP.
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base && fip < nt_end && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD) {
                    send_on_reply(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
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
                SSN_SET_INFO_THREAD => {} // RtlSetThreadIsCritical → no-op success
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
                SSN_QUERY_INFO_PROCESS => {
                    // ProcessBasicInformation initializes SmUniqueProcessId from the real SMSS
                    // EPROCESS identity; the later SMSS connection request carries the same CID.
                    let class = rdx;
                    let buf = get_recv_mr(7); // R8 = buffer
                    if class == 0 {
                        sm_stack_write(buf + 0x20, PM_PIDS[0].load(Ordering::Relaxed));
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
                            sm_stack_write(
                                recvmsg + 0x08,
                                PM_PIDS[connector_pi].load(Ordering::Relaxed),
                            );
                            sm_stack_write(
                                recvmsg + 0x10,
                                PM_TIDS[connector_pi].load(Ordering::Relaxed),
                            );
                            sm_stack_write32(recvmsg + 0x28, r.subsystem_type);
                            for (i, chunk) in r.connection_info.chunks_exact(2).take(120).enumerate() {
                                sm_stack_write16(
                                    recvmsg + 0x2c + i as u64 * 2,
                                    u16::from_le_bytes([chunk[0], chunk[1]]),
                                );
                            }
                            print_str(b"[sm-rdv] delivered connection cid=");
                            print_u64(PM_PIDS[connector_pi].load(Ordering::Relaxed));
                            print_str(b"/");
                            print_u64(PM_TIDS[connector_pi].load(Ordering::Relaxed));
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
                    if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                        client_handle = ch;
                    }
                    print_str(b"[sm-rdv] forward NtCompleteConnectPort replied; awaiting reverse connect\n");
                    // Continue into SmpHandleConnectionRequest's reverse connection and real event set.
                }
                SSN_CONNECT_PORT => {
                    let out = get_recv_mr(9);
                    let sb_name: alloc::vec::Vec<u16> = "\\Windows\\SbApiPort".encode_utf16().collect();
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
                    result = match nt_handler.event_index_for_handle(event_handle, EVENT_MODIFY_STATE) {
                        Ok(index) => match nt_handler.events.set_existing(index as u64) {
                            Some(previous) => {
                                if !previous {
                                    wait_wake_dispatcher_set(nt_handler);
                                }
                                print_str(b"[sm-rdv] real NtSetEvent completed subsystem readiness\n");
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
            send_on_reply(reply, 18, result, 0, 0, rdx);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
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
    request[4..6].copy_from_slice(&nt_lpc_abi::msg_type::LPC_REQUEST.to_le_bytes());
    request[8..16].copy_from_slice(&PM_PIDS[0].load(Ordering::Relaxed).to_le_bytes());
    request[16..24].copy_from_slice(&PM_TIDS[0].load(Ordering::Relaxed).to_le_bytes());
    if request_len >= 0x7c {
        print_str(b"[sm-api] SmExecPgm wire subsystem=");
        print_u64(u32::from_le_bytes(request[0x78..0x7c].try_into().unwrap()) as u64);
        print_str(b"\n");
    }
    let sent = lpc_client()
        .and_then(|client| client.request_wait_reply(client_port, &request[..request_len]).ok())
        .is_some();
    if !sent {
        SM_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }

    let listen_port = SM_RECVPORT.load(Ordering::Relaxed);
    let Some(received) = lpc_client().and_then(|client| client.reply_wait_receive(listen_port).ok())
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
    sm_stack_write(recvmsg + 8, PM_PIDS[0].load(Ordering::Relaxed));
    sm_stack_write(recvmsg + 16, PM_TIDS[0].load(Ordering::Relaxed));
    let context_out = SM_RECV_RDX.load(Ordering::Relaxed);
    if context_out != 0 {
        sm_stack_write(context_out, received.port_context);
    }
    set_reply_mr(15, 0);
    set_reply_mr(16, SM_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, SM_RECV_FLAGS.load(Ordering::Relaxed));
    send_on_reply(reply, 18, 0, 0, 0, 0);

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
                        page, smss_pml4, smss_pe, img_end, nt_base, nt_end, ntdll_pe,
                        &mut fill_idx,
                    )
                {
                    print_str(b"[sm-api] unresolved worker fault\n");
                    return false;
                }
                send_on_reply(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                send_on_reply(reply, 3, m0 + 3, m1, m2, 0);
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
                    SSN_SET_INFO_THREAD => {}
                    SSN_NT_OPEN_PROCESS => {
                        result = sm_open_process_call(
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
                            sm_stack_write(buffer + 0x20, PM_PIDS[0].load(Ordering::Relaxed));
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
                                .reply_wait_receive_with_reply(listen_port, &reply_bytes[..reply_len])
                                .ok()
                        });
                        let Some(response) =
                            lpc_client().and_then(|client| client.reply_wait_receive(client_port).ok())
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
                send_on_reply(reply, 18, result, 0, 0, rdx);
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
                        page, csrss_pml4, csrss_pe, img_end, nt_base, nt_end, ntdll_pe,
                        reg, dll_pes, &mut fill_idx,
                    )
                {
                    print_str(b"[csr-sb] unresolved startup fault\n");
                    return false;
                }
                send_on_reply(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                send_on_reply(reply, 3, m0 + 3, m1, m2, 0);
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
        // server WORKER thread must too — mirror the BATCH-6 SM/CSR pattern: DON'T set
        // TCBSetHostedSyscalls (native Call → MR0=SSN, not an UnknownSyscall trap whose m0=RAX is
        // garbage). All three worker slots run in winlogon's VSpace (pi 2) with distinct TEB-derived
        // IPC buffers. Their faults still arrive on the badged MAIN fault-EP (the loop's
        // NT_NATIVE_SYSCALL_LABEL NORMALIZE arm re-labels them into the shared servicing body), so the
        // worker actually RUNS its rpcrt4 RPC-server init + NtSetEvent(s) the event winlogon's main
        // parks on. Without native:true the worker's first native Call faulted as UnknownSyscall with
        // SSN=garbage → `[wl-worker] PARK` (never ran its RPC init) → winlogon main stuck on the SAS wait.
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
    mut start: nt_thread_start::Amd64ThreadContext,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
    resume: bool,
) -> u64 {
    if pi >= TP_WORKER_PI_COUNT || worker_slot >= TP_WORKER_SLOT_COUNT {
        return 0;
    }
    let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
    if loader_rva == 0 {
        return 0;
    }

    // ReactOS amd64 RtlInitializeContext: (StackBase - 6 pointers), align down to 16, then -8.
    start.rsp = tp_worker_context_rsp(worker_slot);
    let initial_teb = nt_thread_start::InitialTeb64 {
        stack_base: tp_worker_stack_top(worker_slot),
        stack_limit: tp_worker_stack_base(worker_slot),
        allocated_stack_base: tp_worker_stack_base(worker_slot),
    };
    let worker_ep = mint_badged(main_fault_ep, tp_worker_badge(pi, worker_slot));
    spawn_hosted_thread(&HostedThread {
        pml4,
        client_pi: pi as u64,
        entry_rip: start.rip,
        arg0: start.rcx,
        arg1: start.rdx,
        loader_context: Some(LoaderThreadContext {
            loader_va: NTDLL_BASE + loader_rva,
            start,
            initial_teb,
        }),
        scr: tp_worker_env_scratch_va(pi, worker_slot),
        teb_va: tp_worker_teb_va(worker_slot),
        stack_base: tp_worker_stack_base(worker_slot),
        stack_frames: TP_WORKER_STACK_FRAMES,
        ipcbuf_va: tp_worker_ipcbuf_va(worker_slot),
        tramp_va: tp_worker_tramp_va(worker_slot),
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: tp_worker_stack_mirror_va(pi, worker_slot),
        fault_ep: worker_ep,
        cid_proc,
        cid_thread,
        resume,
        prio: 106,
        native: true,
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
        // listener thread must too — mirror the BATCH 24 lsass-listener fix (was BATCH-6 native:false,
        // whose first native Call faulted as UnknownSyscall with SSN=garbage 0x100_105f_b000 →
        // `[svc-listener] blocking server syscall -> PARK (drop)` before it ever created/read its
        // \pipe\ntsvcs server end). native:true plus its TEB-derived private IPC buffer makes its
        // Call dispatch (MR0=r10=SSN), so it runs its rpcrt4 ncacn_np receive loop
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
        // thread must too — mirror BATCH 6/19 (winlogon's RPC listener). Without native:true the thread's
        // first native Call faulted as UnknownSyscall with SSN=garbage (0x100_0080_0000 = RAX at trap) →
        // `[lsass-listener] PARK (unserviced)` → then a stray fault at a garbage stack RIP. Set
        // native → its Call dispatches (MR0=r10=SSN) through its TEB-derived private IPC buffer.
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
pub(crate) unsafe fn csr_stack_write(va: u64, v: u64) {
    if va >= CSR_STACK_BASE && va + 8 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u64, v);
    }
}
/// Write a u32 to the CSR thread's stack, returning false for an invalid output pointer.
pub(crate) unsafe fn csr_stack_write32(va: u64, v: u32) -> bool {
    if va >= CSR_STACK_BASE && va + 4 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u32, v);
        true
    } else {
        false
    }
}
/// Write a u16 to the CSR thread's stack (for PORT_MESSAGE.Type@0x04).
pub(crate) unsafe fn csr_stack_write16(va: u64, v: u16) {
    if va >= CSR_STACK_BASE && va + 2 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u16, v);
    }
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
unsafe fn csr_sb_stack_write32(va: u64, v: u32) {
    if va >= CSR_SB_STACK_BASE && va + 4 <= CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile(
            (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *mut u32,
            v,
        );
    }
}
unsafe fn csr_sb_stack_read(va: u64) -> u64 {
    if va >= CSR_SB_STACK_BASE && va + 8 <= CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000 {
        core::ptr::read_volatile(
            (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *const u64,
        )
    } else {
        0
    }
}
unsafe fn csr_sb_stack_copyout(va: u64, bytes: &[u8]) -> bool {
    if va < CSR_SB_STACK_BASE
        || va + bytes.len() as u64 > CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000
    {
        return false;
    }
    core::ptr::copy_nonoverlapping(
        bytes.as_ptr(),
        (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *mut u8,
        bytes.len(),
    );
    true
}
unsafe fn csr_sb_stack_copyin(va: u64, bytes: &mut [u8]) -> bool {
    if va < CSR_SB_STACK_BASE
        || va + bytes.len() as u64 > CSR_SB_STACK_BASE + CSR_SB_STACK_FRAMES * 0x1000
    {
        return false;
    }
    core::ptr::copy_nonoverlapping(
        (CSR_SB_STACK_MIRROR_VA + (va - CSR_SB_STACK_BASE)) as *const u8,
        bytes.as_mut_ptr(),
        bytes.len(),
    );
    true
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
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, CSR_FILL_SCRATCH_BASE, CAP_INIT_THREAD_VSPACE);
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
    let delivered = lpc_client()
        .and_then(|c| c.reply_wait_receive(port).ok())
        .is_some_and(|r| r.connection_id == conn_id);
    if !delivered {
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return 0;
    }
    csr_sb_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
    csr_sb_stack_write(recvmsg + 0x08, PM_PIDS[0].load(Ordering::Relaxed));
    csr_sb_stack_write(recvmsg + 0x10, PM_TIDS[0].load(Ordering::Relaxed));
    set_reply_mr(15, 0);
    set_reply_mr(16, CSR_SB_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, CSR_SB_RECV_FLAGS.load(Ordering::Relaxed));
    send_on_reply(
        reply,
        18,
        0,
        0,
        0,
        CSR_SB_RECV_RDX.load(Ordering::Relaxed),
    );

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
                        page, csrss_pml4, csrss_pe, img_end, nt_base, nt_end, ntdll_pe,
                        reg, dll_pes, &mut fill_idx,
                    )
                {
                    return 0;
                }
                send_on_reply(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return 0 };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return 0;
                }
                send_on_reply(reply, 3, m0 + 3, m1, m2, 0);
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
                        print_str(b"[csr-sb] authentic reverse connection accepted; worker re-parked\n");
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
                send_on_reply(reply, 18, 0, 0, 0, rdx);
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
    const SSN_QUERY_INFO_THREAD: u64 = 162;
    const SSN_QUERY_OBJECT: u64 = 170;
    const SSN_SET_INFO_OBJECT: u64 = 236;
    const SSN_RESUME_THREAD: u64 = 214;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_CLOSE: u64 = 27;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;

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
    request[4..6].copy_from_slice(&nt_lpc_abi::msg_type::LPC_REQUEST.to_le_bytes());
    request[8..16].copy_from_slice(&PM_PIDS[0].load(Ordering::Relaxed).to_le_bytes());
    request[16..24].copy_from_slice(&PM_TIDS[0].load(Ordering::Relaxed).to_le_bytes());
    if lpc_client()
        .and_then(|client| client.request_wait_reply(client_port, &request[..request_len]).ok())
        .is_none()
    {
        print_str(b"[csr-sb-api] broker request send failed\n");
        CSR_SB_RECEIVE_PARKED.store(1, Ordering::Relaxed);
        return false;
    }
    let listen_port = CSR_SB_RECVPORT.load(Ordering::Relaxed);
    let Some(received) = lpc_client().and_then(|client| client.reply_wait_receive(listen_port).ok())
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
    csr_sb_stack_write(recvmsg + 8, PM_PIDS[0].load(Ordering::Relaxed));
    csr_sb_stack_write(recvmsg + 16, PM_TIDS[0].load(Ordering::Relaxed));
    let context_out = CSR_SB_RECV_RDX.load(Ordering::Relaxed);
    if context_out != 0 {
        csr_sb_stack_write(context_out, received.port_context);
    }
    set_reply_mr(15, 0);
    set_reply_mr(16, CSR_SB_RECV_SP.load(Ordering::Relaxed));
    set_reply_mr(17, CSR_SB_RECV_FLAGS.load(Ordering::Relaxed));
    send_on_reply(reply, 18, 0, 0, 0, 0);

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
                        page, csrss_pml4, csrss_pe, img_end, nt_base, nt_end, ntdll_pe,
                        reg, dll_pes, &mut fill_idx,
                    )
                {
                    print_str(b"[csr-sb-api] unresolved worker fault\n");
                    return false;
                }
                send_on_reply(reply, 0, 0, 0, 0, 0);
            }
            3 => {
                let Some(pe) = ntdll_pe else { return false };
                if m0 < nt_base
                    || m0 >= nt_end
                    || pe_byte_at_rva(pe, (m0 - nt_base) as u32) != Some(0xcd)
                {
                    return false;
                }
                send_on_reply(reply, 3, m0 + 3, m1, m2, 0);
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
                    SSN_SET_INFO_PROCESS | SSN_SET_INFO_OBJECT => {}
                    SSN_QUERY_INFO_THREAD => {
                        let caller_pid = PM_PIDS[1].load(Ordering::Relaxed) as nt_process::ProcessId;
                        if nt_handler
                            .pm
                            .resolve_thread_handle(
                                caller_pid,
                                CSR_SB_TID.load(Ordering::Relaxed) as nt_process::ThreadId,
                                get_recv_mr(9),
                                0,
                            )
                            .is_err()
                        {
                            result = nt_process::STATUS_INVALID_HANDLE as u64;
                        } else if rdx == 1 {
                            let buffer = get_recv_mr(7);
                            for offset in (0..0x20).step_by(8) {
                                csr_sb_stack_write(buffer + offset, 0);
                            }
                        }
                    }
                    SSN_QUERY_OBJECT => {
                        let buffer = get_recv_mr(7);
                        csr_sb_stack_write16(buffer, 0);
                        let result_len = csr_sb_stack_read(sp + 0x28);
                        if result_len != 0 {
                            csr_sb_stack_write32(result_len, 2);
                        }
                    }
                    SSN_RESUME_THREAD => {
                        let caller_pid = PM_PIDS[1].load(Ordering::Relaxed) as nt_process::ProcessId;
                        let tid = match nt_handler.pm.resolve_thread_handle(
                            caller_pid,
                            CSR_SB_TID.load(Ordering::Relaxed) as nt_process::ThreadId,
                            get_recv_mr(9),
                            THREAD_SUSPEND_RESUME,
                        ) {
                            Ok(tid) => tid,
                            Err(status) => {
                                result = status as u64;
                                0
                            }
                        };
                        if tid != 0 {
                            let previous = nt_handler
                                .pm
                                .thread(tid)
                                .map(|thread| thread.suspend_count)
                                .unwrap_or(0);
                            let main_pi = (0..MAX_PI)
                                .find(|&index| PM_TIDS[index].load(Ordering::Relaxed) == tid as u64);
                            if previous == 1 {
                                let tcb = main_pi
                                    .map(|index| PM_MAIN_TCBS[index].load(Ordering::Relaxed))
                                    .unwrap_or(0);
                                if tcb <= 1 || tcb_resume(tcb) != 0 {
                                    result = 0xC0000001;
                                }
                            }
                            if result == 0 {
                                match nt_handler.pm.resume_thread(tid) {
                                    Ok(previous) => {
                                        if rdx != 0 {
                                            csr_sb_stack_write32(rdx, previous);
                                        }
                                        print_str(b"[csr-sb-api] resumed main tid=");
                                        print_u64(tid as u64);
                                        print_str(b" previous=");
                                        print_u64(previous as u64);
                                        print_str(b"\n");
                                    }
                                    Err(status) => result = status as u64,
                                }
                            }
                        }
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
                                .reply_wait_receive_with_reply(listen_port, &reply_bytes[..reply_len])
                                .ok()
                        });
                        let Some(response) =
                            lpc_client().and_then(|client| client.reply_wait_receive(client_port).ok())
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
                send_on_reply(reply, 18, result, 0, 0, rdx);
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

/// AUTHENTIC CSR accept: drive csrss's REAL `CsrApiRequestThread` through one connection accept for
/// winlogon's `NtSecureConnectPort(\Windows\ApiPort)`. Mirrors `sm_rendezvous`: a nested loop on
/// `CSR_FAULT_EP`/`REPLY_CSRLOOP` services the thread's real syscalls until `NtCompleteConnectPort`.
/// The thread's pre-loop `CsrConnectToUser` is in-process (no syscalls; ClientThreadSetup is a stub
/// returning TRUE, and CsrLocateThreadInProcess returns non-NULL since csrss registered its static
/// threads at init → no spin). On the connection: NtSetEvent (signal the real hRequestEvent) →
/// NtReplyWaitReceivePort (drain the broker's pending connection + marshal the PORT_MESSAGE:
/// Type=LPC_CONNECTION_REQUEST, ClientId = the self-connect CID so CsrLocateThreadByClientId matches a
/// registered CSR_THREAD → CsrProcess=CsrRootProcess → AllowConnection=TRUE) → [NtMapViewOfSection of
/// the CSR shared section — no-op success] → NtAcceptConnectPort (broker accept) → NtCompleteConnectPort
/// (broker complete). Returns the client comm-port handle (0 on wall). Leaves the thread re-parked on
/// its next NtReplyWaitReceivePort (break-after-complete, like SM).
///
/// ★ FLAGGED RESIDUALS (host limitations, NOT the accept mechanism — the real thread runs + issues the
/// real receive/accept syscalls): (a) THE ACCEPT DECISION — CsrApiHandleConnectionRequest's
/// CsrLocateThreadByClientId (hash table, exact CID) finds NO thread for winlogon because winlogon is
/// not a registered CSR_PROCESS (that needs the SM→SB→CsrSrvCreateProcess *session-registration* plane,
/// a separate fork), so the real thread computes AllowConnection=FALSE and passes Accept=FALSE. The
/// executive OVERRIDES the broker to accept+complete at the NtAcceptConnectPort syscall so winlogon
/// connects; (b) the CSR_API_CONNECTINFO reply payload + shared-section mapping into winlogon are still
/// executive-modeled (in `csr_client_connect`) because the isolated LPC broker carries no message
/// payload across the connect. (The marshaled connection-request ClientId is now cosmetic — no hashed
/// CSR_THREAD can match it either way.)
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
            csr_stack_write(recvmsg + 0x08, PM_PIDS[1].load(Ordering::Relaxed));
            csr_stack_write(recvmsg + 0x10, CSR_API_TID.load(Ordering::Relaxed));
            set_reply_mr(15, 0);
            set_reply_mr(16, CSR_API_RECV_SP.load(Ordering::Relaxed));
            set_reply_mr(17, CSR_API_RECV_FLAGS.load(Ordering::Relaxed));
            send_on_reply(
                reply,
                18,
                0,
                0,
                0,
                CSR_API_RECV_RDX.load(Ordering::Relaxed),
            );
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
                || !csr_fill_page(page, csrss_pml4, csrss_pe, img_end, nt_base, nt_end, ntdll_pe, reg, dll_pes, &mut fill_idx)
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
            send_on_reply(reply, 0, 0, 0, 0, 0);
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        if label == 3 {
            let fip = m0;
            if let Some(p) = ntdll_pe {
                if fip >= nt_base && fip < nt_end && pe_byte_at_rva(p, (fip - nt_base) as u32) == Some(0xCD) {
                    send_on_reply(reply, 3, fip + 3, m1, m2, 0);
                    let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
                    mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
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
            let mut done = false;
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
                        result = if rdx & 3 != 0 { 0x8000_0002 } else { 0xC000_0005 };
                    } else {
                        let saved_pi = nt_handler.pi;
                        nt_handler.pi = 1;
                        result = match nt_handler.event_index_for_handle(event_handle, EVENT_MODIFY_STATE) {
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
                            csr_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
                            csr_stack_write(recvmsg + 0x08, PM_PIDS[1].load(Ordering::Relaxed));
                            csr_stack_write(recvmsg + 0x10, CSR_API_TID.load(Ordering::Relaxed));
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
                    // The REAL CsrApiHandleConnectionRequest reached NtAcceptConnectPort. ★ FLAGGED
                    // OVERRIDE: in our host winlogon is NOT a registered CSR_PROCESS (that needs the
                    // SM→SB→CsrSrvCreateProcess session plane we don't model), so CsrLocateThreadByClientId
                    // returned NULL → the thread passes Accept=FALSE (R9) and will SKIP NtCompleteConnectPort.
                    // Force the broker to ACCEPT + COMPLETE here so winlogon's connect succeeds — the real
                    // thread issued the accept syscall; only the accept DECISION is executive-supplied.
                    let porthandle_out = get_recv_mr(9); // R10 = *ServerPort
                    let sh = lpc_client()
                        .and_then(|c| c.accept_connect(conn_id, true, rdx).ok())
                        .unwrap_or(0);
                    csr_stack_write(porthandle_out, sh);
                    if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                        client_handle = ch;
                    }
                    // Reply the accept, then break: the thread resumes into its (rejecting) tail +
                    // re-parks on its next NtReplyWaitReceivePort. Single winlogon connect → done.
                    done = true;
                }
                SSN_COMPLETE_CONNECT => {
                    // Defensive: if the accept were ever ALLOWED (a future registered CSR process),
                    // the thread would call this — complete through the broker.
                    if client_handle == 0 {
                        if let Some((ch, _)) = lpc_client().and_then(|c| c.complete_connect(conn_id).ok()) {
                            client_handle = ch;
                        }
                    }
                    done = true;
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
            send_on_reply(reply, 18, result, 0, 0, rdx);
            if done {
                break;
            }
            let (_b, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(ep, reply);
            mi = nmi; m0 = nm0; m1 = nm1; m2 = nm2; m3 = nm3;
            continue;
        }
        print_str(b"[csr-rdv] WALL: unexpected label=");
        print_u64(label);
        print_str(b"\n");
        break;
    }
    client_handle
}
