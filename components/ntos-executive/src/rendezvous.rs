//! Hosted-thread spawn helpers.
#![allow(clippy::all)]
use crate::*;

pub(crate) unsafe fn spawn_wl_listener_thread(
    handler: &mut ExecNtHandler,
    owner_pi: usize,
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
            _ => return Err(HostedThreadSpawnFailure::Unstarted),
        };
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return Err(HostedThreadSpawnFailure::Unstarted);
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4,
            client_pi: owner_pi as u64,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            user_context: Some(loader_context),
            scr,
            teb_va,
            stack_base,
            stack_frames,
            ipcbuf_va,
            tramp_va,
            peb_va: SMSS_PEB_VA,
            stack_mirror_va,
            fault_ep: ThreadFaultEndpoint::Badged { source: main_fault_ep, badge },
            cid_proc,
            cid_thread,
            prio: HOSTED_USER_THREAD_PRIORITY,
            // The worker shares its owner's native transport, with a private TEB-derived IPC buffer.
            native: true,
            diag: false,
        },
    )
}

fn hosted_loader_thread_context(
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
) -> Option<HostedUserThreadContext> {
    let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
    (loader_rva != 0).then_some(HostedUserThreadContext {
        loader_va: Some(NTDLL_BASE + loader_rva),
        start,
        initial_teb,
        stack_origin: ThreadStackOrigin::Caller(initial_teb),
    })
}

/// Spawn a generic worker with the stack ownership selected at syscall admission.
pub(crate) unsafe fn spawn_tp_worker_thread(
    handler: &mut ExecNtHandler,
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    stack_origin: ThreadStackOrigin,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    if pi >= MAX_PI || worker_slot >= TP_WORKER_SLOT_COUNT {
        return Err(HostedThreadSpawnFailure::Unstarted);
    }
    if img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed) == 0 {
        return Err(HostedThreadSpawnFailure::Unstarted);
    }
    spawn_slot_thread(
        handler,
        &RemoteThreadSpawn {
            target_pi: pi,
            slot: worker_slot,
            pml4,
            start,
            stack_origin,
            cid_proc,
            cid_thread,
            fault_ep: ThreadFaultEndpoint::Badged {
                source: main_fault_ep,
                badge: tp_worker_badge(pi, worker_slot),
            },
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
    pub stack_origin: ThreadStackOrigin,
    /// The `ClientId` stamped into the new thread's TEB.
    pub cid_proc: u64,
    pub cid_thread: u64,
    /// Borrowed endpoint source, copied as-is or badged directly into the thread's CNode.
    pub fault_ep: ThreadFaultEndpoint,
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
        stack_origin,
        cid_proc,
        cid_thread,
        fault_ep,
        use_loader,
        native,
    } = *spawn;
    if target_pi >= MAX_PI || slot >= TP_WORKER_SLOT_COUNT || pml4 == 0 || !fault_ep.is_valid() {
        return Err(HostedThreadSpawnFailure::Unstarted);
    }
    let loader_va = if use_loader {
        let loader_rva = img_spawn::OUR_LDR_INITIALIZE_THUNK_RVA.load(Ordering::Relaxed);
        if loader_rva == 0 {
            return Err(HostedThreadSpawnFailure::Unstarted);
        }
        Some(NTDLL_BASE + loader_rva)
    } else {
        None
    };
    let user_context = if use_loader || matches!(stack_origin, ThreadStackOrigin::Caller(_)) {
        let initial_teb = match stack_origin {
            ThreadStackOrigin::Caller(initial_teb) => initial_teb,
            ThreadStackOrigin::ConstructorStack => {
                start.rsp = tp_worker_context_rsp(slot);
                nt_thread_start::InitialTeb64 {
                    stack_base: tp_worker_stack_top(slot),
                    stack_limit: tp_worker_stack_base(slot),
                    allocated_stack_base: tp_worker_stack_base(slot),
                }
            }
        };
        Some(HostedUserThreadContext {
            loader_va,
            start,
            initial_teb,
            stack_origin,
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
            user_context,
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

/// Construct the SCM RPC listener in the caller-resolved owner VSpace. Runtime publication and
/// first resume belong to the caller; faults use the listener's badged service endpoint.
pub(crate) unsafe fn spawn_svc_listener_thread(
    handler: &mut ExecNtHandler,
    owner_pi: usize,
    svc_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return Err(HostedThreadSpawnFailure::Unstarted);
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: svc_pml4,
            client_pi: owner_pi as u64,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            user_context: Some(loader_context),
            scr: SVC_LISTENER_ENV_SCRATCH_VA,
            teb_va: SVC_LISTENER_TEB_VA,
            stack_base: SVC_LISTENER_STACK_BASE,
            stack_frames: SVC_LISTENER_STACK_FRAMES,
            ipcbuf_va: SVC_LISTENER_IPCBUF_VA,
            tramp_va: SVC_LISTENER_TRAMP_VA,
            peb_va: SMSS_PEB_VA,
            stack_mirror_va: SVC_LISTENER_STACK_MIRROR_VA,
            fault_ep: ThreadFaultEndpoint::Badged {
                source: main_fault_ep,
                badge: SVC_LISTENER_BADGE,
            },
            cid_proc,
            cid_thread,
            prio: HOSTED_USER_THREAD_PRIORITY,
            native: true,
            diag: false,
        },
    )
}

/// Construct the LSA listener using the dynamically resolved process owner. The caller publishes
/// and resumes the returned mechanism.
pub(crate) unsafe fn spawn_lsass_listener_thread(
    handler: &mut ExecNtHandler,
    owner_pi: usize,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return Err(HostedThreadSpawnFailure::Unstarted);
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: owner_pi as u64,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            user_context: Some(loader_context),
            scr: LSASS_LISTENER_ENV_SCRATCH_VA,
            teb_va: LSASS_LISTENER_TEB_VA,
            stack_base: LSASS_LISTENER_STACK_BASE,
            stack_frames: LSASS_LISTENER_STACK_FRAMES,
            ipcbuf_va: LSASS_LISTENER_IPCBUF_VA,
            tramp_va: LSASS_LISTENER_TRAMP_VA,
            peb_va: SMSS_PEB_VA,
            stack_mirror_va: LSASS_LISTENER_STACK_MIRROR_VA,
            fault_ep: ThreadFaultEndpoint::Badged {
                source: main_fault_ep,
                badge: LSASS_LISTENER_BADGE,
            },
            cid_proc,
            cid_thread,
            prio: HOSTED_USER_THREAD_PRIORITY,
            native: true,
            diag: false,
        },
    )
}

/// Spawn lsass' SECOND LSA server thread (LsapRmServerThread) — same multiplex, its own target-VSpace
/// VAs (distinct TEB/stack/tramp) + badge (LSASS_LISTENER2_BADGE).
pub(crate) unsafe fn spawn_lsass_listener2_thread(
    handler: &mut ExecNtHandler,
    owner_pi: usize,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return Err(HostedThreadSpawnFailure::Unstarted);
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: owner_pi as u64,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            user_context: Some(loader_context),
            scr: LSASS_LISTENER2_ENV_SCRATCH_VA,
            teb_va: LSASS_LISTENER2_TEB_VA,
            stack_base: LSASS_LISTENER2_STACK_BASE,
            stack_frames: LSASS_LISTENER2_STACK_FRAMES,
            ipcbuf_va: LSASS_LISTENER2_IPCBUF_VA,
            tramp_va: LSASS_LISTENER2_TRAMP_VA,
            peb_va: SMSS_PEB_VA,
            stack_mirror_va: LSASS_LISTENER2_STACK_MIRROR_VA,
            fault_ep: ThreadFaultEndpoint::Badged {
                source: main_fault_ep,
                badge: LSASS_LISTENER2_BADGE,
            },
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
    owner_pi: usize,
    lsass_pml4: u64,
    start: nt_thread_start::Amd64ThreadContext,
    initial_teb: nt_thread_start::InitialTeb64,
    cid_proc: u64,
    cid_thread: u64,
    main_fault_ep: u64,
) -> HostedThreadSpawnResult {
    let Some(loader_context) = hosted_loader_thread_context(start, initial_teb) else {
        return Err(HostedThreadSpawnFailure::Unstarted);
    };
    spawn_hosted_thread(
        handler,
        &HostedThread {
            pml4: lsass_pml4,
            client_pi: owner_pi as u64,
            entry_rip: start.rip,
            arg0: start.rcx,
            arg1: start.rdx,
            user_context: Some(loader_context),
            scr: LSASS_LISTENER3_ENV_SCRATCH_VA,
            teb_va: LSASS_LISTENER3_TEB_VA,
            stack_base: LSASS_LISTENER3_STACK_BASE,
            stack_frames: LSASS_LISTENER3_STACK_FRAMES,
            ipcbuf_va: LSASS_LISTENER3_IPCBUF_VA,
            tramp_va: LSASS_LISTENER3_TRAMP_VA,
            peb_va: SMSS_PEB_VA,
            stack_mirror_va: LSASS_LISTENER3_STACK_MIRROR_VA,
            fault_ep: ThreadFaultEndpoint::Badged {
                source: main_fault_ep,
                badge: LSASS_LISTENER3_BADGE,
            },
            cid_proc,
            cid_thread,
            prio: HOSTED_USER_THREAD_PRIORITY,
            // BATCH 24: native transport (mirror listener1) — lsass runs on our native ntdll.
            native: true,
            diag: false,
        },
    )
}
