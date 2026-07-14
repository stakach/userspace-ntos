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
    spawn_hosted_thread(&HostedThread {
        pml4: smss_pml4,
        entry_rip,
        param: port_handle,
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
    })
}

/// Write a u64 to the SM-loop thread's stack (via the executive's SM_STACK_MIRROR alias), for a
/// syscall out-param that lives on its stack (RequestMsg / PortHandle / PROCESS_BASIC_INFORMATION).
pub(crate) unsafe fn sm_stack_write(va: u64, v: u64) {
    if va >= SM_STACK_BASE && va + 8 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u64, v);
    }
}
/// Write a u16 to the SM-loop thread's stack (for PORT_MESSAGE.Type@0x04).
pub(crate) unsafe fn sm_stack_write16(va: u64, v: u16) {
    if va >= SM_STACK_BASE && va + 2 <= SM_STACK_BASE + SM_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((SM_STACK_MIRROR_VA + (va - SM_STACK_BASE)) as *mut u16, v);
    }
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
    smss_pml4: u64,
    smss_pe: &nt_pe_loader::PeFile,
    img_end: u64,
    nt_base: u64,
    nt_end: u64,
    ntdll_pe: Option<&nt_pe_loader::PeFile>,
) -> u64 {
    const PID_SMSS: u64 = 4; // any nonzero value; must match on both sides (self-connect ClientId)
    const SSN_SET_INFO_THREAD: u64 = 238;
    const SSN_QUERY_INFO_PROCESS: u64 = 161;
    const SSN_REPLY_WAIT_RECV: u64 = 203;
    const SSN_ACCEPT_CONNECT: u64 = 0;
    const SSN_COMPLETE_CONNECT: u64 = 31;
    let ep = SM_FAULT_EP.load(Ordering::Relaxed);
    let reply = REPLY_SMLOOP_SLOT.load(Ordering::Relaxed);
    if ep == 0 || reply == 0 {
        return 0;
    }
    let mut client_handle = 0u64;
    let mut fill_idx = 0u64;
    let mut guard = 0u64;
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[sm-rdv] WALL: guard exhausted\n");
            break;
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
            let mut done = false;
            match ssn {
                SSN_SET_INFO_THREAD => {} // RtlSetThreadIsCritical → no-op success
                SSN_QUERY_INFO_PROCESS => {
                    // ProcessBasicInformation (class 0): write UniqueProcessId@+0x20 = PID_SMSS so
                    // SmUniqueProcessId is set → the connection request's ClientId matches (self-connect).
                    let class = rdx;
                    let buf = get_recv_mr(7); // R8 = buffer
                    if class == 0 {
                        sm_stack_write(buf + 0x20, PID_SMSS);
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
                            sm_stack_write(recvmsg + 0x08, PID_SMSS); // ClientId.UniqueProcess
                            sm_stack_write(recvmsg + 0x10, PID_SMSS + 4); // ClientId.UniqueThread
                        }
                        _ => {
                            // No pending connection (the 2nd receive): leave the thread PARKED — do NOT
                            // reply. It re-blocks on this NtReplyWaitReceivePort until the next connect.
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
                    // Reply (below), then BREAK: the connection is done. SmpApiLoop loops back to its
                    // next NtReplyWaitReceivePort, which faults FRESH to sm_fault_ep (no receiver) and
                    // re-parks — so a LATER connect's rendezvous can recv that fresh fault (rather than
                    // this rendezvous draining an empty receive, which would leave the thread blocked
                    // on a reply and deadlock the next connect).
                    done = true;
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
            if done {
                break;
            }
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

/// Number of committed stack frames for the CSR API thread (deeper than SM: CsrApiRequestThread →
/// CsrConnectToUser [loader walk] → CsrApiHandleConnectionRequest).
pub const CSR_STACK_FRAMES: u64 = 8;

/// Spawn csrss's REAL `CsrApiRequestThread` as a 2nd thread in csrss's VSpace (mirrors
/// `spawn_sm_loop_thread`). It faults to `CSR_FAULT_EP` (no standing receiver) so it PARKS on its
/// first fault/syscall until `csr_rendezvous` drains it for winlogon's CSR connect. `param` is the
/// hRequestEvent handle (CsrApiRequestThread's PVOID Parameter). The TEB carries the self-connect
/// ClientId so the thread's own bookkeeping is consistent.
pub(crate) unsafe fn spawn_csr_loop_thread(csrss_pml4: u64, entry_rip: u64, param: u64) -> u64 {
    // NOT resumed here: CsrApiRequestThread's pre-loop CsrConnectToUser touches CsrRootProcess's
    // thread list under csrss's process lock, which csrss's MAIN thread is still mutating during init
    // (CsrAddStaticServerThread). Resuming now would race. Instead `csr_rendezvous` resumes it lazily,
    // by which time csrss main has finished init + parked → the CSR thread runs alone in csrss's VSpace.
    // The TEB carries the self-connect ClientId (0x40/0x48) so the thread's own bookkeeping is consistent.
    spawn_hosted_thread(&HostedThread {
        pml4: csrss_pml4,
        entry_rip,
        param,
        scr: CSR_ENV_SCRATCH_VA,
        teb_va: CSR_TEB_VA,
        stack_base: CSR_STACK_BASE,
        stack_frames: CSR_STACK_FRAMES,
        ipcbuf_va: CSR_IPCBUF_VA,
        tramp_va: CSR_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: CSR_STACK_MIRROR_VA,
        fault_ep: CSR_FAULT_EP.load(Ordering::Relaxed),
        cid_proc: CSR_STATIC_CID_PROC,
        cid_thread: CSR_STATIC_CID_THREAD,
        resume: false,
        prio: 0,
    })
}

/// Spawn a REAL thread through the GENERAL NtCreateThread path for a hosted process `pml4` (first
/// live user: winlogon's RPC listener). `entry_rip`/`param` come from the caller's CONTEXT; `cid_*`
/// is the real ClientId {caller pid, fresh tid} the ETHREAD carries. Returns the TCB. The thread
/// faults to the dedicated `WL_LISTENER_FAULT_EP` (no receiver). It is left SUSPENDED (`resume:
/// false`): its real TEB is mapped + queryable, but it is not scheduled — a "parked before first
/// instruction" listener. Resuming it into the service loop (so it runs to `FSCTL_PIPE_LISTEN`)
/// requires a per-thread stack-mirror switch in the main multiplex (the flagged follow-up).
pub(crate) unsafe fn spawn_wl_listener_thread(pml4: u64, entry_rip: u64, param: u64, cid_proc: u64, cid_thread: u64) -> u64 {
    spawn_hosted_thread(&HostedThread {
        pml4,
        entry_rip,
        param,
        scr: WL_LISTENER_ENV_SCRATCH_VA,
        teb_va: WL_LISTENER_TEB_VA,
        stack_base: WL_LISTENER_STACK_BASE,
        stack_frames: WL_LISTENER_STACK_FRAMES,
        ipcbuf_va: WL_LISTENER_IPCBUF_VA,
        tramp_va: WL_LISTENER_TRAMP_VA,
        peb_va: SMSS_PEB_VA,
        stack_mirror_va: 0, // park-only: no rendezvous writes its stack
        fault_ep: WL_LISTENER_FAULT_EP.load(Ordering::Relaxed),
        cid_proc,
        cid_thread,
        resume: false,
        prio: 0,
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
    param: u64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> u64 {
    let listener_ep = mint_badged(main_fault_ep, SVC_LISTENER_BADGE);
    spawn_hosted_thread(&HostedThread {
        pml4: svc_pml4,
        entry_rip,
        param,
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
        resume: true, // run it into the multiplex (the N-threads mechanism)
        prio: 104, // above winlogon(102)/services(103) so it runs when services' main parks
    })
}

/// Write a u64 to the CSR thread's stack (via the executive's CSR_STACK_MIRROR alias).
pub(crate) unsafe fn csr_stack_write(va: u64, v: u64) {
    if va >= CSR_STACK_BASE && va + 8 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u64, v);
    }
}
/// Write a u16 to the CSR thread's stack (for PORT_MESSAGE.Type@0x04).
pub(crate) unsafe fn csr_stack_write16(va: u64, v: u16) {
    if va >= CSR_STACK_BASE && va + 2 <= CSR_STACK_BASE + CSR_STACK_FRAMES * 0x1000 {
        core::ptr::write_volatile((CSR_STACK_MIRROR_VA + (va - CSR_STACK_BASE)) as *mut u16, v);
    }
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
    dll_pes: &[&Option<nt_pe_loader::PeFile>; DLL_REG_COUNT],
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
    let scratch = CSR_FILL_SCRATCH_BASE + (*fill_idx).min(511) * 0x1000;
    *fill_idx += 1;
    let f = alloc_frame();
    let _ = page_map(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
    let rights = fill_image_page(tpe, (page - base) as u32, scratch);
    let _ = page_map(copy_cap(f), page, rights, csrss_pml4);
    true
}

/// AUTHENTIC CSR accept: drive csrss's REAL `CsrApiRequestThread` through one connection accept for
/// winlogon's `NtSecureConnectPort(\Windows\ApiPort)`. Mirrors `sm_rendezvous`: a nested loop on
/// `CSR_FAULT_EP`/`REPLY_CSRLOOP` services the thread's real syscalls until `NtCompleteConnectPort`.
/// The thread's pre-loop `CsrConnectToUser` is in-process (no syscalls; ClientThreadSetup is a stub
/// returning TRUE, and CsrLocateThreadInProcess returns non-NULL since csrss registered its static
/// threads at init → no spin). On the connection: NtSetEvent (signal hRequestEvent, no-op) →
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
    dll_pes: &[&Option<nt_pe_loader::PeFile>; DLL_REG_COUNT],
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
    // Lazily resume the CSR thread on the FIRST rendezvous (csrss main has finished init + parked, so
    // the thread runs alone in csrss's VSpace — no race on the CSR process/thread lists). Subsequent
    // rendezvous re-recv the thread already re-parked on its next NtReplyWaitReceivePort.
    if CSR_RESUMED.swap(1, Ordering::Relaxed) == 0 {
        let tcb = CSR_LOOP_TCB.load(Ordering::Relaxed);
        if tcb != 0 && tcb != 1 {
            let _ = tcb_resume(tcb);
        }
    }
    let (_b, mut mi, mut m0, mut m1, mut m2, mut m3) = recv_full_r12(ep, reply);
    loop {
        guard += 1;
        if guard > 8000 {
            print_str(b"[csr-rdv] WALL: guard exhausted\n");
            break;
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
                SSN_SET_EVENT => {} // NtSetEvent(hRequestEvent) — no-op success
                SSN_MAP_VIEW => {} // NtMapViewOfSection (CSR shared section into CsrRootProcess) — success
                SSN_REPLY_WAIT_RECV => {
                    let recvmsg = get_recv_mr(8); // R9 = &ReceiveMsg.Header
                    let port = get_recv_mr(9); // R10 = CsrApiPort handle
                    let got = lpc_client().and_then(|c| c.reply_wait_receive(port).ok());
                    match got {
                        Some(r) if r.connection_id != 0 => {
                            csr_stack_write16(recvmsg + 0x04, nt_lpc_client::LPC_CONNECTION_REQUEST);
                            csr_stack_write(recvmsg + 0x08, CSR_STATIC_CID_PROC); // ClientId.UniqueProcess
                            csr_stack_write(recvmsg + 0x10, CSR_STATIC_CID_THREAD); // ClientId.UniqueThread
                        }
                        _ => {
                            // No pending connection (the re-park receive): leave the thread PARKED.
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
