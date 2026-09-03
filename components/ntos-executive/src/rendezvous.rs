//! Hosted-thread spawn helpers.
#![allow(clippy::all)]
use crate::*;

pub(crate) unsafe fn spawn_wl_listener_thread(
    handler: &mut ExecNtHandler,
    slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
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
            _ => return HostedThreadSpawnResult::failed(),
        };
    let worker_ep = mint_badged(main_fault_ep, badge);
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return HostedThreadSpawnResult::failed();
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4,
            client_pi: 2,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            loader_context: Some(loader_context),
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 19: winlogon (pi 2) runs on OUR ntdll's NATIVE seL4-Call transport, so its rpcrt4
            // server WORKER thread must too. All three worker slots run in winlogon's VSpace (pi 2) with
            // distinct TEB-derived IPC buffers. Their faults still arrive on the badged MAIN fault-EP (the
            // loop's NT_NATIVE_SYSCALL_LABEL NORMALIZE arm re-labels them into the shared servicing body),
            // so the worker actually RUNS its rpcrt4 RPC-server init + NtSetEvent(s) the event winlogon's
            // main parks on.
            native: true,
            diag: false,
        },
    )
}

fn hosted_loader_thread_context(
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
) -> Option<LoaderThreadContext> {
    let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
    (loader_rva != 0).then_some(LoaderThreadContext {
        loader_va: NTDLL_BASE + loader_rva,
        start,
        initial_teb,
    })
}

/// Spawn the one bounded generic ntdll thread-pool worker assigned to `pi`. The caller-supplied
/// stack allocation is not mapped into this userspace kernel, so normalize both INITIAL_TEB and
/// CONTEXT.Rsp to the fixed 16-page worker stack before entering LdrInitializeThunk. The original
/// RIP/RCX/RDX remain intact and are restored by the loader trampoline.
pub(crate) unsafe fn spawn_tp_worker_thread(
    handler: &mut ExecNtHandler,
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    if pi >= MAX_PI || worker_slot >= TP_WORKER_SLOT_COUNT {
        return HostedThreadSpawnResult::failed();
    }
    if img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed) == 0 {
        return HostedThreadSpawnResult::failed();
    }
    let worker_ep = mint_badged(main_fault_ep, tp_worker_badge(pi, worker_slot));
    spawn_slot_thread(
        handler,
        &RemoteThreadSpawn {
            target_pi: pi,
            slot: worker_slot,
            pml4,
            start,
            cid_proc,
            cid_thread,
            fault_ep: worker_ep,
            use_loader: true,
            native: true,
        },
    )
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
pub(crate) unsafe fn spawn_slot_thread(
    handler: &mut ExecNtHandler,
    spawn: &RemoteThreadSpawn,
) -> HostedThreadSpawnResult {
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
    } = *spawn;
    if target_pi >= MAX_PI || slot >= TP_WORKER_SLOT_COUNT || pml4 == 0 || fault_ep == 0 {
        return HostedThreadSpawnResult::failed();
    }
    let loader_context = if use_loader {
        let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
        if loader_rva == 0 {
            return HostedThreadSpawnResult::failed();
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
    spawn_hosted_thread(
        handler,
        &HostedThread {
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            native,
            diag: false,
        },
    )
}

/// Spawn services' REAL RPC listener thread (ScmStartRpcServer's rpcrt4 io_thread) in services'
/// VSpace (pi 3) and RESUME it into the main service-loop multiplex. Unlike `spawn_wl_listener_thread`
/// (suspended, no-receiver EP), this one faults to a cap minted at [`SVC_LISTENER_BADGE`] off the MAIN
/// service `fault_ep`, so the loop receives + sub-selects it as (pi 3, listener) via its own stack
/// mirror. `svc_pml4` = services' PML4; `entry_rip`/`param` from the caller's CONTEXT; `main_fault_ep`
/// = the shared service-loop endpoint (this fn mints the badged cap). Returns the TCB.
pub(crate) unsafe fn spawn_svc_listener_thread(
    handler: &mut ExecNtHandler,
    svc_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let listener_ep = mint_badged(main_fault_ep, SVC_LISTENER_BADGE);
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return HostedThreadSpawnResult::failed();
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: svc_pml4,
            client_pi: 3,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            loader_context: Some(loader_context),
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 33: services (pi 3) runs on OUR ntdll's NATIVE seL4-Call transport, so its SCM RPC
            // listener thread must too. native:true plus its TEB-derived private IPC buffer makes its
            // Call dispatch (MR0=SSN), so it runs its rpcrt4 ncacn_np receive loop
            // (FSCTL_PIPE_LISTEN + NtReadFile on the server pipe) — the reads the pipe-pending
            // park/re-drive edge then completes.
            native: true,
            diag: false,
        },
    )
}

/// Spawn lsass' LSA server thread (StartAuthenticationPort / LsapRmServerThread, created by lsass'
/// LsapInitDatabase via NtCreateThread) in lsass' VSpace (pi 4) and RESUME it into the main service-loop
/// multiplex — the SERVICE-9 C-c pattern replicated for lsass. Faults to a cap minted at
/// [`LSASS_LISTENER_BADGE`] off the MAIN service `fault_ep`; the loop sub-selects it as (pi 4, listener)
/// via its own stack mirror. `lsass_pml4` = lsass' PML4; `entry_rip`/`param` from the caller's CONTEXT.
/// Returns the TCB.
pub(crate) unsafe fn spawn_lsass_listener_thread(
    handler: &mut ExecNtHandler,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER_BADGE);
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return HostedThreadSpawnResult::failed();
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: 4,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            loader_context: Some(loader_context),
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 24: lsass (pi 4) runs on OUR ntdll's NATIVE seL4-Call transport, so its LSA server
            // thread must too. native:true makes its Call dispatch (MR0=SSN) through its TEB-derived
            // private IPC buffer.
            // Its faults still arrive on the badged MAIN fault-EP (the loop's NT_NATIVE_SYSCALL_LABEL
            // NORMALIZE arm re-labels them), so it actually RUNS LsarStartRpcServer →
            // SetEvent(LSA_RPC_SERVER_ACTIVE).
            native: true,
            diag: false,
        },
    )
}

/// Spawn lsass' SECOND LSA server thread (LsapRmServerThread) — same multiplex, its own target-VSpace
/// VAs (distinct TEB/stack/tramp) + badge (LSASS_LISTENER2_BADGE).
pub(crate) unsafe fn spawn_lsass_listener2_thread(
    handler: &mut ExecNtHandler,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER2_BADGE);
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return HostedThreadSpawnResult::failed();
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: 4,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            loader_context: Some(loader_context),
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 24: native transport (mirror listener1) — lsass runs on our native ntdll.
            native: true,
            diag: false,
        },
    )
}

pub(crate) unsafe fn spawn_lsass_listener3_thread(
    handler: &mut ExecNtHandler,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let listener_ep = mint_badged(main_fault_ep, LSASS_LISTENER3_BADGE);
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return HostedThreadSpawnResult::failed();
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: 4,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            loader_context: Some(loader_context),
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
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 24: native transport (mirror listener1) — lsass runs on our native ntdll.
            native: true,
            diag: false,
        },
    )
}
