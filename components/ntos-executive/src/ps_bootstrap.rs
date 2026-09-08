//! Early ownership of the canonical Ps and token stores, transferred once to the live handler.

use super::*;

pub(crate) struct PsBootstrapSeed {
    pub ps: nt_user_host::ps_bootstrap::PsBootstrapState,
    pub pids: [nt_process::ProcessId; HOSTED_PROCESS_MANAGER_SEED_COUNT],
    pub main_tids: [nt_process::ThreadId; HOSTED_PROCESS_MANAGER_SEED_COUNT],
    pub pool_tids:
        [[nt_process::ThreadId; PM_RUNTIME_THREAD_SLOTS]; HOSTED_PROCESS_MANAGER_SEED_COUNT],
}

enum BootstrapPhase {
    Uninitialized,
    Owned(PsBootstrapSeed),
    Transferred,
}

static mut BOOTSTRAP: BootstrapPhase = BootstrapPhase::Uninitialized;

// These two initial objects live as long as the executive image. Providers alias its retained
// image frames; using the executive's private heap here would expose unrelated provider memory.
#[repr(C, align(4096))]
struct InitialObjectPage([u8; 4096]);

static mut INITIAL_PROCESS: InitialObjectPage = InitialObjectPage([0; 4096]);
static mut INITIAL_THREAD: InitialObjectPage = InitialObjectPage([0; 4096]);
static INITIAL_PROCESS_BODY: AtomicU64 = AtomicU64::new(0);
static mut INITIAL_SYSTEM_PROJECTION: Option<InitialSystemProjection> = None;

#[derive(Clone, Copy)]
pub(crate) struct InitialSystemProjection {
    pub identity: nt_process::InitialSystemIdentity,
    pub process_body: u64,
    pub thread_body: u64,
}

/// Immutable projection metadata, published before any provider can execute. It is not a grant
/// to impersonate System: root-issued call channels separately authenticate the logical caller.
pub(crate) fn initial_system_projection() -> Option<InitialSystemProjection> {
    if INITIAL_PROCESS_BODY.load(Ordering::Acquire) == 0 {
        return None;
    }
    unsafe { core::ptr::addr_of!(INITIAL_SYSTEM_PROJECTION).read() }
}

pub(crate) fn is_initial_system_process(body: u64) -> bool {
    body != 0 && INITIAL_PROCESS_BODY.load(Ordering::Acquire) == body
}

unsafe fn publish_initial_objects(
    ps: &mut nt_user_host::ps_bootstrap::PsBootstrapState,
) -> Result<(), u32> {
    use nt_kernel_abi::{ps_reactos_x64 as abi, GuestAddr};

    let (pm, _) = ps.managers_mut();
    let identity = pm.initial_system_identity().ok_or(0xc000_000du32)?;
    let process = core::ptr::addr_of_mut!(INITIAL_PROCESS);
    let thread = core::ptr::addr_of_mut!(INITIAL_THREAD);
    abi::initialize_process(
        &mut (*process).0,
        abi::ProcessInitialization {
            body: GuestAddr(process as u64),
            process_id: u64::from(identity.process_id()),
            peb: GuestAddr(0),
        },
    )
    .map_err(|_| 0xc000_000du32)?;
    abi::initialize_thread(
        &mut (*thread).0,
        abi::ThreadInitialization {
            body: GuestAddr(thread as u64),
            process_body: GuestAddr(process as u64),
            process_id: u64::from(identity.process_id()),
            thread_id: u64::from(identity.thread_id()),
            teb: GuestAddr(0),
            system_thread: true,
        },
    )
    .map_err(|_| 0xc000_000du32)?;
    // Both fresh identities and storage belong to this unpublished seed. Publication cannot
    // collide with a hosted object; a failed invariant is fatal, never a partial live bootstrap.
    assert!(pm.publish_process_kernel_object(identity.process_id(), process as u64));
    assert!(pm.publish_thread_kernel_object(identity.thread_id(), thread as u64));
    ps_object_backing::initialize(identity)?;
    core::ptr::addr_of_mut!(INITIAL_SYSTEM_PROJECTION).write(Some(InitialSystemProjection {
        identity,
        process_body: process as u64,
        thread_body: thread as u64,
    }));
    INITIAL_PROCESS_BODY.store(process as u64, Ordering::Release);
    Ok(())
}

/// Root bootstrap is serialized. No borrowed store reference may escape into provider IPC.
pub(crate) unsafe fn initialize(entry: u64, parameter: u64) -> Result<(), u32> {
    if !matches!(
        &*core::ptr::addr_of!(BOOTSTRAP),
        BootstrapPhase::Uninitialized
    ) {
        return Err(0xc000_000d);
    }
    let mut seed = seed_processes(entry, parameter)?;
    publish_initial_objects(&mut seed.ps)?;
    core::ptr::addr_of_mut!(BOOTSTRAP).write(BootstrapPhase::Owned(seed));
    Ok(())
}

pub(crate) unsafe fn take() -> PsBootstrapSeed {
    match core::mem::replace(
        &mut *core::ptr::addr_of_mut!(BOOTSTRAP),
        BootstrapPhase::Transferred,
    ) {
        BootstrapPhase::Owned(seed) => seed,
        BootstrapPhase::Uninitialized => panic!("Ps bootstrap must precede handler initialization"),
        BootstrapPhase::Transferred => panic!("Ps bootstrap stores were already transferred"),
    }
}

pub(crate) unsafe fn hosted_main_client_id(pi: usize) -> Option<nt_process::ClientId> {
    let BootstrapPhase::Owned(seed) = &*core::ptr::addr_of!(BOOTSTRAP) else {
        return None;
    };
    let &pid = seed.pids.get(pi)?;
    let &tid = seed.main_tids.get(pi)?;
    let client_id = seed.ps.process_manager().client_id(tid)?;
    (client_id.unique_process == pid).then_some(client_id)
}

pub(crate) unsafe fn service_initial_system_request(
    caller: nt_process::InitialSystemIdentity,
    op: u64,
    object: u64,
    value: u64,
) -> (i32, u64, u64, u64) {
    let BootstrapPhase::Owned(seed) = &mut *core::ptr::addr_of_mut!(BOOTSTRAP) else {
        return (0xc000_00a3u32 as i32, 0, 0, 0);
    };
    let (pm, _) = seed.ps.managers_mut();
    if !pm.validate_initial_system_caller(caller) {
        return (0xc000_00a3u32 as i32, 0, 0, 0);
    }
    provider_ps::dispatch(pm, op, object, value)
}

#[inline(never)]
fn seed_processes(entry: u64, parameter: u64) -> Result<PsBootstrapSeed, u32> {
    let mut ps = nt_user_host::ps_bootstrap::PsBootstrapState::try_new(entry, parameter)?;
    let (pm, tokens) = ps.managers_mut();
    let system = pm
        .initial_system_identity()
        .expect("bootstrap owns initial System identity");
    let mut pids = [0; HOSTED_PROCESS_MANAGER_SEED_COUNT];
    let mut main_tids = [0; HOSTED_PROCESS_MANAGER_SEED_COUNT];
    let mut pool_tids = [[0; PM_RUNTIME_THREAD_SLOTS]; HOSTED_PROCESS_MANAGER_SEED_COUNT];

    pm.reserve_modules(64);
    pm.reserve_process_capacity(MAX_PI + 1);
    pm.reserve_thread_capacity(MAX_PI * (1 + PM_RUNTIME_THREAD_SLOTS) + 1);
    pm.reserve_debug_objects(PM_DEBUG_OBJECT_SLOTS, PM_DEBUG_EVENTS_PER_OBJECT)?;
    PM_PROC_COUNT.store(0, Ordering::Relaxed);
    PM_OBJECT_COUNT.store(0, Ordering::Relaxed);
    PM_INITIAL_SYSTEM_OBJECT_PRESENT.store(0, Ordering::Relaxed);
    PM_DYNAMIC_PROCESS_ALLOCATIONS.store(0, Ordering::Relaxed);
    PM_PROCESS_SPAWNED_OK.store(0, Ordering::Relaxed);
    PM_IDENTITY_OK.store(0, Ordering::Relaxed);
    PM_VSPACE_PUBLISHED_OK.store(0, Ordering::Relaxed);
    reset_hosted_gate_metadata();
    PM_RUNNING_PROCESS_MASK.store(0, Ordering::Relaxed);
    PM_MAIN_THREADS_OK.store(0, Ordering::Relaxed);
    HOSTED_THREAD_RUNTIME_OK.store(0, Ordering::Relaxed);
    PM_HANDLE_CAP_BOOT.store(0, Ordering::Relaxed);
    PM_HANDLE_CAP_MAX.store(0, Ordering::Relaxed);
    PM_HANDLE_CAP_GROWTHS.store(0, Ordering::Relaxed);

    for pi in 0..HOSTED_PROCESS_MANAGER_SEED_COUNT {
        let image = hosted_process_manager_seed_image(pi).expect("bootstrap seed index is bounded");
        let parent = if pi == 0 {
            system.process_id()
        } else {
            pids[0]
        };
        let pid = pm.create_process(image.process_name, Some(parent), None);
        let token = tokens.insert(nt_security::AccessToken::system());
        assert_eq!(pm.replace_process_primary_token(pid, Some(token)), Ok(None));
        pids[pi] = pid;
    }
    for &pid in &pids {
        pm.reserve_process_threads(pid, 1 + PM_RUNTIME_THREAD_SLOTS);
        assert!(pm.set_peb_base(pid, SMSS_PEB_VA));
    }
    for (pi, &pid) in pids.iter().enumerate() {
        main_tids[pi] = pm.create_thread(pid, 0, 0, false)?;
    }
    for (pi, &pid) in pids.iter().enumerate() {
        for slot in 0..PM_RUNTIME_THREAD_SLOTS {
            pool_tids[pi][slot] = pm.create_dormant_thread(pid)?;
        }
        pm.reserve_handles(pid, PM_HANDLE_RESERVE);
    }
    Ok(PsBootstrapSeed {
        ps,
        pids,
        main_tids,
        pool_tids,
    })
}
