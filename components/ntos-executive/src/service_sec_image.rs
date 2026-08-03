//! `service_sec_image` — the per-process SEC_IMAGE demand-fault service loop.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;
use nt_io_abi::major;

const SEC_IMAGE_FAULT_CAP: u64 = 15000;
static SEC_IMAGE_PREFETCH_THROTTLE_LOGGED: AtomicU64 = AtomicU64::new(0);
static GUI_CLIENTINFO_SEED_LOGGED: AtomicU64 = AtomicU64::new(0);
static EXPLORER_FRONTIER_QUIESCE_DEFERS: AtomicU64 = AtomicU64::new(0);
static EXPLORER_GETMESSAGE_DIAG_N: AtomicU64 = AtomicU64::new(0);
static EXPLORER_FLUSH_ICACHE_TRACE: AtomicU64 = AtomicU64::new(0);
static EXPLORER_CALLBACK_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
static USERCONNECT_COPY_FAILURES: AtomicU64 = AtomicU64::new(0);
static WIN32K_MSG_COPY_FAILURES: AtomicU64 = AtomicU64::new(0);
static WINLOGON_DESKTOP_PAINT_PENDING: AtomicU64 = AtomicU64::new(0);
static BUILD_HWND_LIST_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static CREATE_BITMAP_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);
static TEXT_EXTENT_MARSHAL_TRACE: AtomicU64 = AtomicU64::new(0);

const WIN32K_MSG_BYTES: usize = 48;
const WIN32K_BUILD_HWND_LIST_STAGE_BYTES: usize = 0x1000;
const WIN32K_BUILD_HWND_LIST_COUNT_OFFSET: u64 = 0x0ff0;
const WIN32K_BUILD_HWND_LIST_MAX_HANDLES: u64 = WIN32K_BUILD_HWND_LIST_COUNT_OFFSET / 8;
const WIN32K_CREATE_BITMAP_STAGE_BYTES: usize = 0x4000;
const WIN32K_TEXT_EXTENT_STAGE_BYTES: usize = 0x4000;
const WM_QUIT: u32 = 0x0012;

fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    value.checked_add(align - 1).map(|v| v & !(align - 1))
}

fn win32k_client_label<'a>(nt_handler: &'a ExecNtHandler, pi: usize) -> &'a [u8] {
    nt_handler.hosted_process_leaf(pi).unwrap_or(b"client")
}

fn hosted_process_uses_client_gdi(nt_handler: &ExecNtHandler, pi: usize) -> bool {
    match nt_handler.hosted_process_role(pi) {
        Some(
            nt_exe_image::HostedProcessRole::InteractiveLogon
            | nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
            | nt_exe_image::HostedProcessRole::InteractiveShell,
        ) => true,
        _ => false,
    }
}

fn record_hosted_client_gdi_mapping(nt_handler: &ExecNtHandler, pi: usize, gdi_va: u64) {
    let Some(image) = nt_handler.hosted_process_image(pi) else {
        return;
    };
    let first = match image.role {
        nt_exe_image::HostedProcessRole::InteractiveLogon => {
            WINLOGON_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap => {
            USERINIT_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        nt_exe_image::HostedProcessRole::InteractiveShell => {
            EXPLORER_GDI_MAPPED.swap(1, Ordering::Relaxed) == 0
        }
        _ => false,
    };
    if first {
        print_str(b"[client-gdi] ");
        print_str(image.leaf);
        print_str(b" handle table mapped @0x");
        print_hex((gdi_va >> 32) as u32);
        print_hex(gdi_va as u32);
        print_str(b" with live user attributes (PEB->GdiSharedHandleTable seeded pre-loader)\n");
    }
}

fn hosted_process_is_noninteractive_service_gui_client(
    nt_handler: &ExecNtHandler,
    pi: usize,
) -> bool {
    nt_handler.hosted_process_role(pi)
        == Some(nt_exe_image::HostedProcessRole::NonInteractiveService)
}

fn hosted_process_is_interactive_shell_gui_client(nt_handler: &ExecNtHandler, pi: usize) -> bool {
    matches!(
        nt_handler.hosted_process_role(pi),
        Some(
            nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
                | nt_exe_image::HostedProcessRole::InteractiveShell
        )
    )
}

fn ntgdi_bitmap_format_rgb(bits: u32) -> u32 {
    if bits <= 1 {
        1
    } else if bits <= 4 {
        2
    } else if bits <= 8 {
        3
    } else if bits <= 16 {
        4
    } else if bits <= 24 {
        5
    } else if bits <= 32 {
        6
    } else {
        0
    }
}

fn ntgdi_bits_per_format(format: u32) -> Option<u64> {
    match format {
        1 => Some(1),
        2 => Some(4),
        3 => Some(8),
        4 => Some(16),
        5 => Some(24),
        6 => Some(32),
        _ => None,
    }
}

fn ntgdi_create_bitmap_bits_size(
    width: u64,
    height: u64,
    planes: u64,
    bits_pixel: u64,
) -> Option<usize> {
    let width = (width as u32) as i32;
    let height = (height as u32) as i32;
    let planes = planes as u32;
    let bits_pixel = bits_pixel as u32;
    let c_bits = planes.checked_mul(bits_pixel)?;
    let format = ntgdi_bitmap_format_rgb(c_bits);
    let real_bpp = ntgdi_bits_per_format(format)?;
    if width <= 0 || width >= 0x0800_0000 || height <= 0 || bits_pixel > 32 || planes > 32 {
        return None;
    }
    let row_bits = (width as u64).checked_mul(real_bpp)?;
    let row_bytes = row_bits.checked_add(15).map(|bits| (bits & !15) >> 3)?;
    let size = row_bytes.checked_mul(height as u64)?;
    if size >= 0x1_0000_0000 || size > usize::MAX as u64 {
        return None;
    }
    Some(size as usize)
}

fn sec_image_forward_run() -> u64 {
    let slots_cap =
        ROOT_CSPACE_END.load(Ordering::Relaxed) - ROOT_CSPACE_START.load(Ordering::Relaxed);
    let slots_used = NEXT_SLOT.load(Ordering::Relaxed) - ROOT_CSPACE_START.load(Ordering::Relaxed);
    let slot_pressure = slots_cap != 0 && slots_used * 5 >= slots_cap * 4;
    let frame_pressure = CSRSS_FRAME_HW.load(Ordering::Relaxed) * 10 >= CSRSS_FRAME_CAP as u64 * 7;
    if slot_pressure || frame_pressure {
        if SEC_IMAGE_PREFETCH_THROTTLE_LOGGED.swap(1, Ordering::Relaxed) == 0 {
            print_str(b"[sec-image] forward prefetch throttled under pool pressure: cslots=");
            print_u64(slots_used);
            print_str(b"/");
            print_u64(slots_cap);
            print_str(b" frame-reg=");
            print_u64(CSRSS_FRAME_HW.load(Ordering::Relaxed));
            print_str(b"/");
            print_u64(CSRSS_FRAME_CAP as u64);
            print_str(b"\n");
        }
        4
    } else {
        32
    }
}

fn hosted_thread_tcb_or_zero(nt_handler: &ExecNtHandler, tid: u64) -> u64 {
    nt_handler.hosted_thread_tcb(tid).unwrap_or(0)
}

unsafe fn load_hosted_bootstrap_image(
    catalog: &mut nt_exe_image::OwnedHostedImageCatalog<8>,
    enabled: bool,
    spec: HostedBootstrapLoadSpec,
) -> (Option<nt_pe_loader::PeFile<'static>>, u64) {
    let (pe, va) = if enabled {
        load_dll_from_fs(spec.disk_path, spec.stem)
    } else {
        (None, 0)
    };
    if let Some(ref image_pe) = pe {
        apply_relocations_to_buf(image_pe, va, PE_LOAD_BASE);
        let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
        core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, PE_LOAD_BASE);
    }
    register_loaded_hosted_image(catalog, spec.image, spec.runtime, pe.is_some())
        .expect("hosted bootstrap image metadata must register once when loaded");
    (pe, va)
}

fn register_loaded_hosted_bootstrap_pe(
    loaded_images: &mut HostedLoadedImageTable,
    spec: HostedBootstrapLoadSpec,
    pe: &Option<nt_pe_loader::PeFile<'static>>,
    pool_va: u64,
) {
    loaded_images
        .register_if_loaded(spec.image.as_ref(), pe, pool_va)
        .expect("loaded hosted executable PE metadata must register once");
}

fn loaded_hosted_pe_by_pi<'a>(
    loaded_images: &'a HostedLoadedImageTable,
    pi: usize,
) -> Option<&'a nt_pe_loader::PeFile<'static>> {
    unsafe { loaded_images.pe_by_pi(pi) }
}

fn win32k_client_context_for_thread(
    nt_handler: &ExecNtHandler,
    pi: usize,
    badge: u64,
    tid: u64,
    tcb: u64,
    role: Option<HostedThreadRole>,
    teb: u64,
    peb_mirror: u64,
    scratch_base: u64,
) -> win32k_glue::Win32kClientContext {
    let pid = nt_handler.pm_pid_for_pi(pi).unwrap_or(0);
    win32k_glue::Win32kClientContext {
        pi: pi as u32,
        pid: pid as u64,
        badge,
        tid,
        tcb,
        eprocess: nt_handler.pm.process_kernel_object(pid).unwrap_or(0),
        ethread: nt_handler
            .pm
            .thread_kernel_object(tid as nt_process::ThreadId)
            .unwrap_or(0),
        role,
        process_role: nt_handler.hosted_process_role(pi),
        top_badge: nt_handler.hosted_process_top_badge(pi).unwrap_or(0),
        teb,
        peb_mirror,
        scratch_base,
    }
}

unsafe fn sync_win32k_context_to_process_manager(
    nt_handler: &mut ExecNtHandler,
    expected: win32k_glue::Win32kClientContext,
) {
    let published = win32k_glue::published_win32k_context();
    let pid = if published.pid != 0 {
        published.pid
    } else {
        expected.pid
    };
    let tid = if published.tid != 0 {
        published.tid
    } else {
        expected.tid
    };
    if expected.pid != 0 && pid != expected.pid {
        print_str(b"[win32k-context] ERROR: published PID mismatch expected=");
        print_u64(expected.pid);
        print_str(b" actual=");
        print_u64(pid);
        print_str(b"\n");
        return;
    }
    if expected.tid != 0 && tid != expected.tid {
        print_str(b"[win32k-context] ERROR: published TID mismatch expected=");
        print_u64(expected.tid);
        print_str(b" actual=");
        print_u64(tid);
        print_str(b"\n");
        return;
    }
    if pid != 0 && pid <= nt_process::ProcessId::MAX as u64 {
        let pid = pid as nt_process::ProcessId;
        if published.eprocess != 0 {
            let _ = nt_handler.pm.set_process_kernel_object(pid, published.eprocess);
        }
        if published.w32process != 0 {
            let _ = nt_handler.pm.set_process_win32(pid, published.w32process);
        }
    }
    if tid != 0 && tid <= nt_process::ThreadId::MAX as u64 {
        let tid = tid as nt_process::ThreadId;
        if published.ethread != 0 {
            let _ = nt_handler.pm.set_thread_kernel_object(tid, published.ethread);
        }
        if published.w32thread != 0 {
            let _ = nt_handler.pm.set_thread_win32(tid, published.w32thread);
        }
    }
}

unsafe fn dispatch_win32k_for_client(
    nt_handler: &mut ExecNtHandler,
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    client: win32k_glue::Win32kClientContext,
) -> (u64, bool) {
    let result =
        win32k_glue::win32k_dispatch_wide(ssn, a0, a1, a2, a3, caller_sp, stack_args, client);
    sync_win32k_context_to_process_manager(nt_handler, client);
    result
}

unsafe fn post_winlogon_second_sas_after_welcome_drain(
    pi: usize,
    badge: u64,
    current_tid: u64,
    current_tcb: u64,
    current_role: Option<HostedThreadRole>,
    process_role: Option<nt_exe_image::HostedProcessRole>,
    top_badge: u64,
    main_tid: u64,
    pid: u64,
    client_teb: u64,
    peb_mirror: u64,
    scratch_base: u64,
) -> bool {
    let sas1 = WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed);
    let sas2 = WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed);
    let paint_now = win32k_glue::real_wm_paint_callback_returns();
    let paint_at_sas1 = WINLOGON_PAINT_RETURNS_AT_SAS1.load(Ordering::Relaxed);
    let paint_hwnd = win32k_glue::last_real_wm_paint_hwnd();
    let paint_pwnd = if paint_hwnd != 0 {
        winlogon_pwnd_for_hwnd(paint_hwnd)
    } else {
        0
    };
    if process_role != Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
        || badge != top_badge
        || current_tid == 0
        || main_tid != current_tid
        || sas1 == 0
        || sas2 != 0
    {
        return false;
    }
    if paint_now <= paint_at_sas1 {
        return false;
    }
    if paint_pwnd == 0 {
        return false;
    }

    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let mut logon_state = 0u32;
    if session != 0 {
        const WLSESSION_LOGONSTATE_OFF: u64 = 0x118;
        let mut bytes = [0u8; 4];
        if img_spawn::smss_copyin(session + WLSESSION_LOGONSTATE_OFF, &mut bytes) {
            logon_state = u32::from_le_bytes(bytes);
        }
    }
    print_str(b"[wl-main] welcome queue drained after real paint; Session->LogonState=0x");
    print_hex(logon_state);
    print_str(b"\n");
    if logon_state != nt_user_callback::WINLOGON_STATE_LOGGED_OFF {
        return false;
    }

    WINLOGON_SAS_LOGONSTATE.store(logon_state as u64, Ordering::Relaxed);
    let _ = winlogon_dialog_observe_logged_off(session, logon_state);
    let hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    if hwnd == 0 {
        return false;
    }
    WINLOGON_KEY_OPENED_AT_INJECT.store(
        WINLOGON_KEY_OPENED.load(Ordering::Relaxed),
        Ordering::Relaxed,
    );
    print_str(b"[wl-main] posting simulated Ctrl-Alt-Del through real NtUserPostMessage hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b"\n");
    let post = win32k_glue::win32k_dispatch_wide(
        0x100e,
        hwnd,
        nt_user_callback::WLX_WM_SAS as u64,
        nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL,
        0,
        0,
        &[],
        win32k_glue::Win32kClientContext {
            pi: pi as u32,
            pid,
            badge,
            tid: current_tid,
            tcb: current_tcb,
            eprocess: 0,
            ethread: 0,
            role: current_role,
            process_role,
            top_badge,
            teb: client_teb,
            peb_mirror,
            scratch_base,
        },
    );
    print_str(b"[wl-main] NtUserPostMessage(WLX_WM_SAS) -> ret=0x");
    print_hex(post.0 as u32);
    print_str(b"\n");
    if post.1 && post.0 != 0 {
        WINLOGON_SAS2_INJECTED.store(1, Ordering::Relaxed);
        true
    } else {
        false
    }
}

fn hosted_top_badge_for_pi(nt_handler: &ExecNtHandler, pi: usize) -> u64 {
    nt_handler.hosted_process_top_badge(pi).unwrap_or(0)
}

fn hosted_top_badge_for_role(
    nt_handler: &ExecNtHandler,
    role: nt_exe_image::HostedProcessRole,
) -> Option<u64> {
    (0..MAX_PI).find_map(|pi| {
        (nt_handler.hosted_process_role(pi) == Some(role))
            .then(|| nt_handler.hosted_process_top_badge(pi))
            .flatten()
    })
}

fn hosted_pi_for_top_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<usize> {
    (0..MAX_PI).find(|&pi| {
        hosted_process_runtime_for_pi(pi).is_some()
            && nt_handler.hosted_process_top_badge(pi) == Some(badge)
    })
}

fn hosted_non_native_top_level_badge(nt_handler: &ExecNtHandler, badge: u64) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge)
        .and_then(|pi| nt_handler.hosted_process_role(pi))
        .is_some_and(|role| role != nt_exe_image::HostedProcessRole::NativeSession)
}

fn hosted_pi_has_role(
    nt_handler: &ExecNtHandler,
    pi: usize,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    nt_handler.hosted_process_role(pi) == Some(role)
}

fn hosted_pi_has_leaf(nt_handler: &ExecNtHandler, pi: usize, leaf: &[u8]) -> bool {
    nt_handler
        .hosted_process_leaf(pi)
        .is_some_and(|process_leaf| process_leaf.eq_ignore_ascii_case(leaf))
}

fn hosted_main_badge_has_role(
    nt_handler: &ExecNtHandler,
    badge: u64,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge)
        .is_some_and(|pi| hosted_pi_has_role(nt_handler, pi, role))
}

fn hosted_owner_has_role(
    nt_handler: &ExecNtHandler,
    badge: u64,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    let owner = owner_top_badge_for(nt_handler, badge);
    hosted_main_badge_has_role(nt_handler, owner, role)
}

fn hosted_main_badge_has_leaf(nt_handler: &ExecNtHandler, badge: u64, leaf: &[u8]) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge)
        .is_some_and(|pi| hosted_pi_has_leaf(nt_handler, pi, leaf))
}

fn hosted_pi_for_mechanism_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<usize> {
    if let Some((pi, _)) = tp_worker_identity_from_badge(badge) {
        return Some(pi);
    }
    hosted_pi_for_top_badge(nt_handler, badge)
}

fn live_hosted_pi_for_leaf(nt_handler: &ExecNtHandler, leaf: &[u8]) -> Option<usize> {
    let target_leaf = nt_exe_image::canonical_exe_leaf(leaf)?;
    for pi in 0..MAX_PI {
        let Some(pid) = nt_handler.pm_pid_for_pi(pi) else {
            continue;
        };
        let Some(process) = nt_handler.pm.process(pid) else {
            continue;
        };
        let Some(process_leaf) =
            nt_exe_image::canonical_exe_leaf(process.image_file_name.as_bytes())
        else {
            continue;
        };
        if process_leaf.eq_ignore_ascii_case(target_leaf) {
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

fn live_hosted_pi_for_thread_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<usize> {
    nt_handler
        .hosted_thread_pi_for_badge(badge)
        .filter(|&pi| nt_handler.pm_pid_for_pi(pi).is_some())
}

fn live_hosted_pi_for_fault_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<usize> {
    live_hosted_pi_for_thread_badge(nt_handler, badge)
        .or_else(|| hosted_pi_for_mechanism_badge(nt_handler, badge))
}

fn hosted_leaf_for_fault_badge(nt_handler: &ExecNtHandler, badge: u64) -> Option<&[u8]> {
    let pi = live_hosted_pi_for_fault_badge(nt_handler, badge)?;
    nt_handler.hosted_process_leaf(pi)
}

unsafe fn defer_explorer_startup_quiesce(nt_handler: &ExecNtHandler) -> bool {
    const MAX_DEFERS: u64 = 4;

    if EXPLORER_SPAWNED.load(Ordering::Relaxed) != 1
        || EXPLORER_CREATE_WINDOW_STRING_CAPTURES.load(Ordering::Relaxed) != 0
    {
        return false;
    }

    let process_connects = EXPLORER_SSN_HIST[ssn_bucket(win32k_subsystem::SSN_NT_USER_INITIALIZE)]
        .load(Ordering::Relaxed);
    let create_window_calls = EXPLORER_SSN_HIST[ssn_bucket(0x1077)].load(Ordering::Relaxed);
    if process_connects == 0 || create_window_calls != 0 {
        return false;
    }

    let tcb = nt_handler.hosted_main_thread_tcb_for_pi(6).unwrap_or(0);
    if tcb <= 1 {
        return false;
    }

    let n = EXPLORER_FRONTIER_QUIESCE_DEFERS.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_DEFERS {
        return false;
    }

    let resume = tcb_resume(tcb);
    print_str(b"[explorer-frontier] deferred quiesce after NtUserProcessConnect; kick=");
    print_u64(n + 1);
    print_str(b"/");
    print_u64(MAX_DEFERS);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b" resume=0x");
    print_hex(resume as u32);
    print_str(b"\n");
    resume == 0
}

struct HostedExeSpawn<'a> {
    image: nt_exe_image::HostedProcessImageRef<'a>,
    runtime: HostedProcessRuntime,
    pe: &'a nt_pe_loader::PeFile<'static>,
    spawned: &'static AtomicU64,
}

#[derive(Clone, Copy)]
enum HostedMultiplexedThreadSpawner {
    ServicesListener,
    ScmWorker,
    LsassListener,
    LsassListener2,
    LsassListener3,
    LsaWorker,
}

#[derive(Clone, Copy)]
enum HostedThreadResumeMode {
    PoolState,
    Always,
}

#[derive(Clone, Copy)]
struct HostedThreadSpawnSpec {
    owner_leaf: &'static [u8],
    teb: u64,
    badge: u64,
    role: HostedThreadRole,
    spawner: HostedMultiplexedThreadSpawner,
    resume: HostedThreadResumeMode,
    spawn_prefix: &'static [u8],
    spawned_prefix: &'static [u8],
    spawned_suffix: &'static [u8],
}

fn hosted_multiplexed_thread_spawn_for(
    request: HostedThreadSpawnRequest,
) -> Option<HostedThreadSpawnSpec> {
    match request {
        HostedThreadSpawnRequest::ServicesListener => Some(HostedThreadSpawnSpec {
            owner_leaf: b"services.exe",
            teb: SVC_LISTENER_TEB_VA,
            badge: SVC_LISTENER_BADGE,
            role: HostedThreadRole::ServicesListener,
            spawner: HostedMultiplexedThreadSpawner::ServicesListener,
            resume: HostedThreadResumeMode::PoolState,
            spawn_prefix: b"[svc-thread] spawning + RESUMING REAL RPC listener thread: entry=0x",
            spawned_prefix: b"[svc-thread] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 7)\n",
        }),
        HostedThreadSpawnRequest::ScmWorker => Some(HostedThreadSpawnSpec {
            owner_leaf: b"services.exe",
            teb: SCM_WORKER_TEB_VA,
            badge: SCM_WORKER_BADGE,
            role: HostedThreadRole::ScmWorker,
            spawner: HostedMultiplexedThreadSpawner::ScmWorker,
            resume: HostedThreadResumeMode::Always,
            spawn_prefix:
                b"[scm-worker] spawning + RESUMING REAL per-connection RPC worker: entry=0x",
            spawned_prefix: b"[scm-worker] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 15)\n",
        }),
        HostedThreadSpawnRequest::LsassListener { slot: 0 } => Some(HostedThreadSpawnSpec {
            owner_leaf: b"lsass.exe",
            teb: LSASS_LISTENER_TEB_VA,
            badge: LSASS_LISTENER_BADGE,
            role: HostedThreadRole::LsassListener,
            spawner: HostedMultiplexedThreadSpawner::LsassListener,
            resume: HostedThreadResumeMode::PoolState,
            spawn_prefix: b"[lsass-thread] spawning + RESUMING REAL LSA server thread: entry=0x",
            spawned_prefix: b"[lsass-thread] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 9)\n",
        }),
        HostedThreadSpawnRequest::LsassListener { slot: 1 } => Some(HostedThreadSpawnSpec {
            owner_leaf: b"lsass.exe",
            teb: LSASS_LISTENER2_TEB_VA,
            badge: LSASS_LISTENER2_BADGE,
            role: HostedThreadRole::LsassListener2,
            spawner: HostedMultiplexedThreadSpawner::LsassListener2,
            resume: HostedThreadResumeMode::PoolState,
            spawn_prefix: b"[lsass-thread2] spawning + RESUMING 2nd LSA server thread: entry=0x",
            spawned_prefix: b"[lsass-thread2] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 10)\n",
        }),
        HostedThreadSpawnRequest::LsassListener { slot: 2 } => Some(HostedThreadSpawnSpec {
            owner_leaf: b"lsass.exe",
            teb: LSASS_LISTENER3_TEB_VA,
            badge: LSASS_LISTENER3_BADGE,
            role: HostedThreadRole::LsassListener3,
            spawner: HostedMultiplexedThreadSpawner::LsassListener3,
            resume: HostedThreadResumeMode::PoolState,
            spawn_prefix: b"[lsass-thread3] spawning + RESUMING 3rd LSA worker: entry=0x",
            spawned_prefix: b"[lsass-thread3] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 14)\n",
        }),
        HostedThreadSpawnRequest::LsaWorker => Some(HostedThreadSpawnSpec {
            owner_leaf: b"lsass.exe",
            teb: LSA_WORKER_TEB_VA,
            badge: LSA_WORKER_BADGE,
            role: HostedThreadRole::LsaWorker,
            spawner: HostedMultiplexedThreadSpawner::LsaWorker,
            resume: HostedThreadResumeMode::Always,
            spawn_prefix:
                b"[lsa-worker] spawning + RESUMING REAL per-connection LSA RPC worker: entry=0x",
            spawned_prefix: b"[lsa-worker] spawned + resumed tcb=0x",
            spawned_suffix: b" (runs into the main multiplex, badge 26)\n",
        }),
        _ => None,
    }
}

fn hosted_exe_spawn_for<'a>(
    request: nt_exe_image::SpawnRequest,
    catalog: &'a nt_exe_image::OwnedHostedImageCatalog<8>,
    loaded_images: &'a HostedLoadedImageTable,
) -> Option<HostedExeSpawn<'a>> {
    let target = request.target?;
    let image = catalog.get_by_leaf(request.leaf())?;
    if nt_exe_image::SpawnTarget::from_image(image) != target {
        return None;
    }
    let runtime = hosted_process_runtime_for_pi(target.pi)?;
    let spawned = runtime.spawned?;
    let pe = unsafe { loaded_images.pe_by_pi(target.pi)? };
    Some(HostedExeSpawn {
        image,
        runtime,
        pe,
        spawned,
    })
}

unsafe fn spawn_requested_hosted_exe(
    request: nt_exe_image::SpawnRequest,
    spec: HostedExeSpawn<'_>,
    fault_ep: u64,
    procs: &mut [ProcExec; MAX_PI],
    nt_handler: &mut ExecNtHandler,
    exe_images: &mut nt_exe_image::ImageTable<8>,
) -> Result<u64, u32> {
    let pi = spec.image.pi;
    let child_pid = nt_handler
        .pm_pid_for_pi(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let child_tid = nt_handler
        .pm_main_tid_for_pi(pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let creator_pid = nt_handler
        .pm_pid_for_pi(request.creator_pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let child_spawn = spawn_hosted_sec_image_for_image(
        spec.image,
        spec.pe,
        mint_badged(fault_ep, spec.image.top_badge),
        NTDLL_BASE,
        true,
        0,
        child_pid as u64,
        child_tid as u64,
    );
    nt_handler.register_main_thread_tcb(pi, child_spawn.main_tcb);
    procs[pi].pid = child_pid as u64;
    procs[pi].pml4 = child_spawn.pml4;
    nt_handler.publish_hosted_process_vspace(pi, child_spawn.pml4)?;
    procs[pi].img_end = PE_LOAD_BASE + image_extent(spec.pe);
    procs[pi].scratch_base = spec.runtime.scratch_base;
    map_demand_scratch_pts(spec.runtime.scratch_base);
    nt_handler.bind_main_thread_entry(pi, PE_LOAD_BASE + spec.pe.entry_point_rva() as u64);
    let _ = nt_handler.pm.set_peb_base(child_pid, SMSS_PEB_VA);

    let process_handle = match nt_handler.pm.insert_handle(
        creator_pid,
        nt_process::HandleObject::Process(child_pid),
        nt_process::map_process_access(request.desired_access),
    ) {
        Ok(handle) => {
            PM_HANDLES_TRACKED.fetch_add(1, Ordering::Relaxed);
            handle as u64
        }
        Err(status) => {
            let _ = exe_images.rollback_spawn(request);
            return Err(status);
        }
    };

    if !nt_handler.publish_created_process(request.process_handle_out, process_handle, SMSS_PEB_VA)
    {
        let _ = exe_images.rollback_spawn(request);
        return Err(0xC000_0005);
    }
    if exe_images.publish(request, process_handle).is_err() {
        return Err(0xC000_000D);
    }
    spec.spawned.store(1, Ordering::Relaxed);

    print_str(b"[ntos-exec] NtCreateProcessEx: spawned ");
    print_str(spec.image.leaf);
    print_str(b" (badge ");
    print_u64(spec.image.top_badge);
    print_str(b") -> handle 0x");
    print_hex((process_handle >> 32) as u32);
    print_hex(process_handle as u32);
    if pi >= 5 {
        print_str(b"; initial thread awaits NtCreateThread\n");
    } else {
        print_str(b"; its ntdll loader now multiplexed into this loop\n");
    }
    Ok(process_handle)
}

/// Populate one GUI thread's client-side win32 state from the desktop facts published by the live
/// win32k dispatch thread. `Win32ThreadInfo` is an opaque server THREADINFO identity; the inline
/// CLIENTINFO stores the client mapping of DESKTOPINFO and the USER-heap pointer delta.
unsafe fn seed_gui_thread_client_info(
    pi: usize,
    teb_alias: u64,
    pml4: u64,
) -> Option<(u64, u64, u64)> {
    let server_deskinfo = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_DESKINFO) as *const u64,
    );
    let pti = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_PTI) as *const u64,
    );
    if server_deskinfo == 0 || pti == 0 {
        return None;
    }

    let pool_delta = win32k_glue::map_win32k_pool_into_csrss(pml4, pi);
    let user_delta = win32k_subsystem::WIN32K_HEAP_VADDR - win32k_subsystem::CSRSS_W32_SHARED_VA;
    let client_deskinfo = server_deskinfo.checked_sub(pool_delta)?;
    core::ptr::write_volatile((teb_alias + 0x78) as *mut u64, pti);
    core::ptr::write_volatile((teb_alias + 0x820) as *mut u64, client_deskinfo);
    core::ptr::write_volatile((teb_alias + 0x828) as *mut u64, user_delta);
    Some((client_deskinfo, pti, user_delta))
}

unsafe fn seed_winlogon_thread_client_info(teb_alias: u64, pml4: u64) -> Option<(u64, u64, u64)> {
    seed_gui_thread_client_info(2, teb_alias, pml4)
}

fn winlogon_thread_teb_alias_for(
    badge: u64,
    tp_worker_identity: Option<(usize, usize)>,
    is_wl_worker: bool,
) -> Option<u64> {
    if let Some((2, tp_slot)) = tp_worker_identity {
        return Some(tp_worker_stack_mirror_va(2, tp_slot) + TP_WORKER_STACK_FRAMES * 0x1000);
    }
    if is_wl_worker {
        return Some(match badge {
            WINLOGON_WORKER2_BADGE => {
                WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000
            }
            WINLOGON_WORKER3_BADGE => {
                WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000
            }
            _ => WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000,
        });
    }
    Some(WINLOGON_MAIN_TEB_MIRROR_VA)
}

fn hosted_gui_thread_teb_alias_for(
    nt_handler: &ExecNtHandler,
    pi: usize,
    badge: u64,
    current_tid: u64,
    tp_worker_identity: Option<(usize, usize)>,
    is_wl_worker: bool,
) -> Option<u64> {
    if pi == 2 {
        return winlogon_thread_teb_alias_for(badge, tp_worker_identity, is_wl_worker);
    }
    let Some(main_tid) = nt_handler.pm_main_tid_for_pi(pi) else {
        return None;
    };
    if current_tid == 0
        || current_tid != u64::from(main_tid)
        || badge != hosted_top_badge_for_pi(nt_handler, pi)
    {
        return None;
    }
    let teb_alias = hosted_env_scratch_base_for_pi(pi);
    (teb_alias != 0).then_some(teb_alias)
}

unsafe fn observe_winlogon_completed_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    filled_pages: &mut [u64; 512],
    faults: usize,
    scratch_base: u64,
) {
    if dispatch.ssn == 0x1288 {
        observe_winlogon_natural_switch_desktop(dispatch.status);
        return;
    }
    if dispatch.ssn != 0x1077 || dispatch.status == 0 {
        return;
    }
    let hwnd = dispatch.status as u32 as u64;
    let class = dispatch.args[1];
    let name = dispatch.args[3];
    let sas_hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    if sas_hwnd != 0 && hwnd == sas_hwnd {
        if WINLOGON_SAS_MILESTONE.swap(1, Ordering::Relaxed) == 0 {
            print_str(
                b"[wl-main] winlogon created SAS window (completed NtUserCreateWindowEx -> HWND 0x",
            );
            print_hex(hwnd as u32);
            print_str(b")\n");
        }
        return;
    }
    if WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0 {
        return;
    }

    if class != nt_user_callback::WC_DIALOG_ATOM {
        return;
    }
    WINLOGON_DIALOG_WINDOWS.fetch_add(1, Ordering::Relaxed);
    if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
        || WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
            <= WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
        || name == 0
    {
        return;
    }

    let mut raw = [0u8; 16];
    let descriptor_read =
        img_spawn::client_copyin_mapped(2, name, &mut raw, filled_pages, faults, scratch_base);
    let descriptor = descriptor_read
        .then(|| nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw))
        .and_then(Result::ok);
    let raw_length = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let raw_maximum_and_ansi = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let raw_buffer = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    let source = if descriptor.is_some()
        && img_spawn::smss_mirror(raw_buffer, raw_length as u64).is_some()
    {
        1
    } else if descriptor.is_some()
        && img_spawn::scratch_for(raw_buffer, filled_pages, faults, scratch_base).is_some()
    {
        2
    } else if descriptor.is_some() && csrss_frame_get(2, raw_buffer & !0xfff) != 0 {
        3
    } else if descriptor.is_some() && client_copyin_frame_get(2, raw_buffer & !0xfff) != 0 {
        4
    } else {
        0
    };
    let mut bytes = [0u8; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS * 2];
    let mut units = [0u16; nt_user_callback::MAX_DIALOG_CAPTION_CODE_UNITS];
    let mut count = 0usize;
    let mut caption_read = false;
    if let Some(descriptor) = descriptor {
        let length = descriptor.length_bytes as usize;
        caption_read = img_spawn::client_copyin_mapped(
            2,
            descriptor.buffer,
            &mut bytes[..length],
            filled_pages,
            faults,
            scratch_base,
        );
        if caption_read {
            count =
                nt_user_callback::decode_utf16le_bounded(&bytes[..length], &mut units).unwrap_or(0);
        }
    }
    let style = smss_stack_read(dispatch.caller_sp + 0x28) as u32;
    let top_level = style & 0x8000_0000 != 0 && style & 0x4000_0000 == 0;
    let caption_match = caption_read && units[..count] == nt_user_callback::IDD_LOGON_CAPTION;
    let session = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let correlated = if caption_read {
        winlogon_dialog_capture_idd_logon(session, hwnd, class, &units[..count], top_level, true)
    } else {
        false
    };
    print_str(b"[dialog-caption] hwnd=0x");
    print_hex(hwnd as u32);
    print_str(b" descriptor-read=");
    print_u64(descriptor_read as u64);
    print_str(b" parse=");
    print_u64(descriptor.is_some() as u64);
    print_str(b" len=");
    print_u64(raw_length as u64);
    print_str(b" maxansi=0x");
    print_hex(raw_maximum_and_ansi);
    print_str(b" buf=0x");
    print_hex((raw_buffer >> 32) as u32);
    print_hex(raw_buffer as u32);
    print_str(b" source=");
    print_u64(source);
    print_str(b" caption-read=");
    print_u64(caption_read as u64);
    print_str(b" units=");
    print_u64(count as u64);
    print_str(b" Logon=");
    print_u64(caption_match as u64);
    print_str(b" top-level=");
    print_u64(top_level as u64);
    print_str(b" correlated=");
    print_u64(correlated as u64);
    print_str(b"\n");
}

unsafe fn observe_winlogon_natural_switch_desktop(status: u64) {
    if status == 0 {
        return;
    }
    if WINLOGON_PAINT_DONE.load(Ordering::Relaxed) != 0 {
        return;
    }

    // Read back the 768-px sampled grid; count how many winlogon's OWN SwitchDesktop flow
    // painted to the WC_DESKTOP background. This can run either immediately after a
    // non-callback switch or after NtCallbackReturn resumes the suspended switch.
    let fb = FB_VADDR as *const u32;
    let mut matched = 0u32;
    let mut changed = 0u32;
    let mut non_bg_count = 0u32;
    let mut non_bg_index = 0u64;
    let mut non_bg_value = 0u32;
    let mut sample0 = 0u32;
    for r in 0..24u64 {
        for c in 0..32u64 {
            let idx = r * 32 * 1024 + c * 32;
            let px = core::ptr::read_volatile(fb.add(idx as usize));
            if r == 0 && c == 0 {
                sample0 = px;
            }
            if px != 0x00FF_00FF {
                changed += 1;
            }
            if px == FB_DESKTOP_BG {
                matched += 1;
            } else {
                non_bg_count += 1;
                non_bg_index = idx;
                non_bg_value = px;
            }
        }
    }
    WINLOGON_NATURAL_PAINT.store(matched as u64, Ordering::Relaxed);
    FB_PIXELS_DREW.store(if changed > 0 { 2 } else { 1 }, Ordering::Relaxed);
    FB_PIXELS_MATCH.store(matched as u64, Ordering::Relaxed);
    FB_PIXELS_CHANGED.store(changed as u64, Ordering::Relaxed);
    FB_NON_BG_COUNT.store(non_bg_count as u64, Ordering::Relaxed);
    FB_NON_BG_INDEX.store(non_bg_index, Ordering::Relaxed);
    FB_NON_BG_VALUE.store(non_bg_value as u64, Ordering::Relaxed);
    FB_PIXELS_SAMPLE0.store(sample0 as u64, Ordering::Relaxed);
    let cursor_overlay = matched as u64 + 1 == FB_SAMPLE_COUNT
        && non_bg_count == 1
        && non_bg_index == FB_CURSOR_SAMPLE_INDEX
        && non_bg_value != 0x00FF_00FF;
    let full_desktop = changed as u64 == FB_SAMPLE_COUNT
        && sample0 == FB_DESKTOP_BG
        && (matched as u64 == FB_SAMPLE_COUNT || cursor_overlay);
    if full_desktop {
        WINLOGON_PAINT_DONE.store(1, Ordering::Relaxed);
        WINLOGON_DESKTOP_PAINT_PENDING.store(0, Ordering::Relaxed);
    }
    print_str(b"[win32k-svc] winlogon NtUserSwitchDesktop ret=0x");
    print_hex(status as u32);
    print_str(b" -> NATURAL fb readback: changed ");
    print_u64(changed as u64);
    print_str(b"/768, desktop-bg ");
    print_u64(matched as u64);
    print_str(b"/768 (px0=0x");
    print_hex(sample0);
    print_str(b", non-bg ");
    print_u64(non_bg_count as u64);
    print_str(b" at 0x");
    print_hex(non_bg_index as u32);
    print_str(b" value=0x");
    print_hex(non_bg_value);
    print_str(b")\n");
}

unsafe fn observe_completed_dialog_modal_dispatch(
    dispatch: win32k_glue::CompletedWin32kDispatch,
    badge: u64,
    tid: u64,
) {
    if winlogon_dialog_modal_expected_ssn() != dispatch.ssn
        || !winlogon_dialog_modal_thread_matches(badge, tid, dispatch.args[0])
    {
        return;
    }
    let hwnd = smss_stack_read(dispatch.args[0]);
    let message = smss_stack_read(dispatch.args[0] + 8) as u32;
    let _ = winlogon_dialog_modal_observe(dispatch.ssn, dispatch.status, hwnd, message);
}

/// Service a SEC_IMAGE process: on each VMFault, fault the faulting image page in BY RVA from
/// the PE file (scratch frames rotate from `scratch_base`); on SSN_DONE, capture the verdict.
/// Capture region inside the shared win32k ARG frame (4 pages, mapped in BOTH the executive and
/// win32k). SSN 0x10FA (`NtUserProcessConnect`) uses the frame from offset 0, so captures live in the
/// upper pages. Slots are handed out ROUND-ROBIN: window creation re-enters win32k through user-mode
/// callbacks (WM_NCCREATE/WM_CREATE ...), so a nested dispatch must not clobber an outer capture.
const RC_ARG_CAPTURE_BASE: u64 = 0x1000;
const RC_ARG_CAPTURE_SLOT: u64 = 0x0220;
const RC_ARG_CAPTURE_SLOTS: u64 = 0x0010;
const RC_CLASS_MENU_DESC_OFF: u64 = 0x0080;
const RC_CLASS_MENU_BUF_OFF: u64 = 0x00A0;
const DEVMODEW_DMSIZE_OFF: usize = 0x44;
const DEVMODEW_DMDRIVEREXTRA_OFF: usize = 0x46;
const DEVMODEW_MIN_BYTES: usize = 0x48;
/// Maximum bytes captured per string. `RTL_MAXIMUM_ATOM_LENGTH` is 255 chars, so 0x200 bytes covers
/// every legal class/window name; anything longer is passed through untouched.
const RC_ARG_BUF_CAP: u64 = 0x0200;
static RC_ARG_CAPTURE_NEXT: AtomicU64 = AtomicU64::new(0);

fn le_u64_at(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

/// Is `va` inside the client's MAIN IMAGE window? Every hosted process is loaded at the SAME
/// `PE_LOAD_BASE`, so these VAs COLLIDE across clients: win32k's per-client demand window can observe
/// an empty/other-client page at such a VA WITHOUT faulting, so the demand-fault client-frame sharing
/// never runs and win32k reads zeros. Client stack/heap VAs do not have this problem (they are
/// recorded per-process and resolve correctly), so only this range needs legacy create-window capture.
fn client_image_range(va: u64) -> bool {
    va >= PE_LOAD_BASE && va < PE_LOAD_BASE + IMAGE_MIRROR_WINDOW
}

/// Capture a client counted-string argument (`UNICODE_STRING` when `large` is false, `LARGE_STRING`
/// when true) into the shared win32k ARG frame — the NT "probe and capture" contract applied at the
/// executive's cross-VSpace boundary. Both layouts put `Buffer` at +8; they differ only in the width
/// of the leading `Length` field and in `LARGE_STRING`'s `MaximumLength:31 | bAnsi:1` word.
///
/// Returns the ARG-frame VA of the captured descriptor, or `sp_va` UNCHANGED when capture is
/// impossible. Even `Length == 0` atom/resource forms are staged: win32k still probes the descriptor
/// before interpreting `Buffer` as the atom. For nonzero strings, both descriptor and bytes are copied
/// unconditionally when readable. Falling back to the original pointer keeps this strictly fail-safe.
unsafe fn capture_client_string_arg(
    pi: u64,
    sp_va: u64,
    large: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> u64 {
    if sp_va == 0 {
        return sp_va;
    }
    let mut sd = [0u8; 16];
    if !img_spawn::client_copyin_mapped(pi, sp_va, &mut sd, filled_pages, nfilled, scratch_base) {
        return sp_va;
    }
    let length = if large {
        u32::from_le_bytes(sd[0..4].try_into().unwrap()) as u64
    } else {
        u16::from_le_bytes([sd[0], sd[1]]) as u64
    };
    let buffer = u64::from_le_bytes(sd[8..16].try_into().unwrap());
    if length + 2 > RC_ARG_BUF_CAP || (length != 0 && buffer == 0) {
        return sp_va;
    }
    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc =
        win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT;
    let buf = desc + 0x20;
    let captured_buffer = if length == 0 {
        buffer
    } else {
        let mut chars = [0u8; RC_ARG_BUF_CAP as usize];
        if !img_spawn::client_copyin_mapped(
            pi,
            buffer,
            &mut chars[..length as usize],
            filled_pages,
            nfilled,
            scratch_base,
        ) {
            return sp_va;
        }
        core::ptr::copy_nonoverlapping(chars.as_ptr(), buf as *mut u8, length as usize);
        core::ptr::write_volatile((buf + length) as *mut u16, 0); // UNICODE_NULL terminate
        buf
    };
    if large {
        // LARGE_STRING: Length(u32), MaximumLength:31|bAnsi:1 (u32), Buffer(u64). Preserve bAnsi.
        let ansi_bit = u32::from_le_bytes(sd[4..8].try_into().unwrap()) & 0x8000_0000;
        core::ptr::write_volatile(desc as *mut u32, length as u32);
        let maximum = if length == 0 {
            u32::from_le_bytes(sd[4..8].try_into().unwrap()) & 0x7fff_ffff
        } else {
            length as u32 + 2
        };
        core::ptr::write_volatile((desc + 4) as *mut u32, maximum | ansi_bit);
    } else {
        core::ptr::write_volatile(desc as *mut u16, length as u16);
        let maximum = if length == 0 {
            u16::from_le_bytes([sd[2], sd[3]])
        } else {
            (length + 2) as u16
        };
        core::ptr::write_volatile((desc + 2) as *mut u16, maximum);
        core::ptr::write_volatile((desc + 4) as *mut u32, 0); // explicit x64 padding
    }
    core::ptr::write_volatile((desc + 8) as *mut u64, captured_buffer);
    desc
}

unsafe fn capture_client_devmodew_arg(
    pi: u64,
    devmode: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> u64 {
    if devmode == 0 {
        return 0;
    }
    let mut header = [0u8; DEVMODEW_MIN_BYTES];
    if !img_spawn::client_copyin_mapped(
        pi,
        devmode,
        &mut header,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return devmode;
    }
    let dm_size = u16::from_le_bytes(
        header[DEVMODEW_DMSIZE_OFF..DEVMODEW_DMSIZE_OFF + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let dm_driver_extra = u16::from_le_bytes(
        header[DEVMODEW_DMDRIVEREXTRA_OFF..DEVMODEW_DMDRIVEREXTRA_OFF + 2]
            .try_into()
            .unwrap(),
    ) as usize;
    let Some(size) = dm_size.checked_add(dm_driver_extra) else {
        return devmode;
    };
    if !(DEVMODEW_MIN_BYTES..=RC_ARG_CAPTURE_SLOT as usize).contains(&size) {
        return devmode;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let staged = rc_arg_slot_base(slot);
    core::ptr::write_bytes(staged as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    let mut bytes = [0u8; RC_ARG_CAPTURE_SLOT as usize];
    if !img_spawn::client_copyin_mapped(
        pi,
        devmode,
        &mut bytes[..size],
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return devmode;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), staged as *mut u8, size);
    staged
}

/// Legacy `NtUserCreateWindowEx` capture: only rebase counted strings whose buffers live in the
/// colliding main-image range. Completed-dispatch observers inspect the argument vector that was sent
/// to win32k, so non-explorer stack/heap/DLL strings must remain untouched until those observers carry
/// their own saved original argument copy.
unsafe fn capture_client_string_arg_if_main_image(
    pi: u64,
    sp_va: u64,
    large: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> u64 {
    if sp_va == 0 {
        return sp_va;
    }
    let mut sd = [0u8; 16];
    if !img_spawn::client_copyin_mapped(pi, sp_va, &mut sd, filled_pages, nfilled, scratch_base) {
        return sp_va;
    }
    let length = if large {
        u32::from_le_bytes(sd[0..4].try_into().unwrap()) as u64
    } else {
        u16::from_le_bytes([sd[0], sd[1]]) as u64
    };
    let buffer = le_u64_at(&sd, 8);
    if length == 0 || buffer == 0 || length + 2 > RC_ARG_BUF_CAP || !client_image_range(buffer) {
        return sp_va;
    }
    let mut chars = [0u8; RC_ARG_BUF_CAP as usize];
    if !img_spawn::client_copyin_mapped(
        pi,
        buffer,
        &mut chars[..length as usize],
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return sp_va;
    }
    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc =
        win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT;
    let buf = desc + 0x20;
    core::ptr::copy_nonoverlapping(chars.as_ptr(), buf as *mut u8, length as usize);
    core::ptr::write_volatile((buf + length) as *mut u16, 0); // UNICODE_NULL terminate
    if large {
        // LARGE_STRING: Length(u32), MaximumLength:31|bAnsi:1 (u32). Preserve bAnsi.
        let ansi_bit = u32::from_le_bytes(sd[4..8].try_into().unwrap()) & 0x8000_0000;
        core::ptr::write_volatile(desc as *mut u32, length as u32);
        core::ptr::write_volatile((desc + 4) as *mut u32, (length as u32 + 2) | ansi_bit);
    } else {
        core::ptr::write_volatile(desc as *mut u16, length as u16);
        core::ptr::write_volatile((desc + 2) as *mut u16, (length + 2) as u16);
        core::ptr::write_volatile((desc + 4) as *mut u32, 0); // explicit x64 padding
    }
    core::ptr::write_volatile((desc + 8) as *mut u64, buf);
    desc
}

unsafe fn stage_unicode_string_descriptor_for_win32k(
    pi: u64,
    descriptor: u64,
    desc_out: u64,
    buf_out: u64,
    buf_cap: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> bool {
    core::ptr::write_bytes(desc_out as *mut u8, 0, 16);
    if descriptor == 0 {
        return true;
    }
    let mut sd = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        descriptor,
        &mut sd,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return false;
    }
    let length = u16::from_le_bytes([sd[0], sd[1]]) as u64;
    let maximum = u16::from_le_bytes([sd[2], sd[3]]) as u64;
    let buffer = u64::from_le_bytes(sd[8..16].try_into().unwrap());
    if length & 1 != 0 {
        return false;
    }
    if length != 0 && (buffer == 0 || length > maximum || length + 2 > buf_cap) {
        return false;
    }
    core::ptr::copy_nonoverlapping(sd.as_ptr(), desc_out as *mut u8, sd.len());
    if length != 0 {
        let out = core::slice::from_raw_parts_mut(buf_out as *mut u8, length as usize);
        if !img_spawn::client_copyin_mapped(pi, buffer, out, filled_pages, nfilled, scratch_base) {
            return false;
        }
        core::ptr::write_volatile((buf_out + length) as *mut u16, 0);
        core::ptr::write_volatile((desc_out + 2) as *mut u16, (length + 2) as u16);
        core::ptr::write_volatile((desc_out + 8) as *mut u64, buf_out);
    }
    true
}

#[derive(Clone, Copy)]
struct CapturedGetClassInfo {
    wnd_client: u64,
    menu_client: u64,
    class_desc: u64,
    wnd_out: u64,
    menu_out: u64,
    scrollbar: bool,
    ansi: bool,
}

#[derive(Clone, Copy)]
struct CapturedGetClassName {
    desc_client: u64,
    buffer_client: u64,
    desc_out: u64,
    buffer_out: u64,
    maximum: u16,
}

fn rc_arg_slot_base(slot: u64) -> u64 {
    win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT
}

unsafe fn staged_unicode_string_is_scrollbar(desc: u64) -> bool {
    let length = core::ptr::read_unaligned(desc as *const u16) as usize;
    if length != nt_kernel_exec::user_class::SCROLLBAR_CLASS_NAME.len() * 2 {
        return false;
    }
    let buffer = core::ptr::read_unaligned((desc + 8) as *const u64);
    if buffer == 0 {
        return false;
    }
    let mut units = [0u16; nt_kernel_exec::user_class::SCROLLBAR_CLASS_NAME.len()];
    for (index, unit) in units.iter_mut().enumerate() {
        *unit = core::ptr::read_unaligned((buffer + index as u64 * 2) as *const u16);
    }
    nt_kernel_exec::user_class::is_scrollbar_class_name(&units)
}

unsafe fn capture_get_class_info_graph(
    pi: u64,
    class_name: u64,
    wnd_class: u64,
    menu_name_ptr: u64,
    ansi: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedGetClassInfo> {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    if class_name == 0 || wnd_class == 0 {
        return None;
    }
    let class_slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let out_slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let class_base = rc_arg_slot_base(class_slot);
    let out_base = rc_arg_slot_base(out_slot);
    core::ptr::write_bytes(class_base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::write_bytes(out_base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    if !stage_unicode_string_descriptor_for_win32k(
        pi,
        class_name,
        class_base,
        class_base + 0x20,
        RC_ARG_CAPTURE_SLOT - 0x20,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return None;
    }

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    if !img_spawn::client_copyin_mapped(
        pi,
        wnd_class,
        &mut wnd,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return None;
    }
    let wnd_out = out_base;
    let menu_out = out_base + WNDCLASSEXW_SIZE as u64;
    core::ptr::copy_nonoverlapping(wnd.as_ptr(), wnd_out as *mut u8, wnd.len());
    core::ptr::write_unaligned(menu_out as *mut u64, 0);
    let scrollbar = staged_unicode_string_is_scrollbar(class_base);
    Some(CapturedGetClassInfo {
        wnd_client: wnd_class,
        menu_client: menu_name_ptr,
        class_desc: class_base,
        wnd_out,
        menu_out,
        scrollbar,
        ansi,
    })
}

unsafe fn copy_back_get_class_info(
    pi: u64,
    capture: CapturedGetClassInfo,
    atom: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> bool {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    let wnd_bytes = core::slice::from_raw_parts(capture.wnd_out as *const u8, WNDCLASSEXW_SIZE);
    let wnd_ok = img_spawn::client_write_mapped(
        pi,
        capture.wnd_client,
        wnd_bytes,
        filled_pages,
        nfilled,
        scratch_base,
    );
    let menu_value = core::ptr::read_unaligned(capture.menu_out as *const u64);
    let menu_ok = capture.menu_client == 0
        || img_spawn::client_write_mapped(
            pi,
            capture.menu_client,
            &menu_value.to_le_bytes(),
            filled_pages,
            nfilled,
            scratch_base,
        );
    let copyout_ok = wnd_ok && menu_ok;
    if capture.scrollbar && atom != 0 {
        let hcursor = core::ptr::read_unaligned((capture.wnd_out + 0x28) as *const u64);
        GLOBAL_SCROLLBAR_CLASS_ATOM.store(atom, Ordering::Relaxed);
        if hcursor != 0 {
            GLOBAL_SCROLLBAR_CLASS_CURSOR.store(hcursor, Ordering::Relaxed);
        }
    }
    if pi == 5 && capture.scrollbar {
        let style = core::ptr::read_unaligned((capture.wnd_out + 0x04) as *const u32);
        let proc = core::ptr::read_unaligned((capture.wnd_out + 0x08) as *const u64);
        let cb_wnd_extra = core::ptr::read_unaligned((capture.wnd_out + 0x14) as *const u32);
        let hcursor = core::ptr::read_unaligned((capture.wnd_out + 0x28) as *const u64);
        USERINIT_SCROLLBAR_CLASSINFO_ATOM.store(atom, Ordering::Relaxed);
        USERINIT_SCROLLBAR_CLASSINFO_STYLE.store(style as u64, Ordering::Relaxed);
        USERINIT_SCROLLBAR_CLASSINFO_EXTRA.store(cb_wnd_extra as u64, Ordering::Relaxed);
        USERINIT_SCROLLBAR_CLASSINFO_PROC.store((proc != 0) as u64, Ordering::Relaxed);
        if copyout_ok {
            USERINIT_SCROLLBAR_CLASSINFO_COPYOUTS.fetch_add(1, Ordering::Relaxed);
        } else {
            USERINIT_SCROLLBAR_CLASSINFO_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        print_str(b"[win32k-class] pi=5 ScrollBar capture=1 atom=0x");
        print_hex(atom as u32);
        print_str(b" copyout=");
        print_u64(copyout_ok as u64);
        print_str(b" style=0x");
        print_hex(style);
        print_str(b" cbWndExtra=0x");
        print_hex(cb_wnd_extra);
        print_str(b" proc=");
        print_u64((proc != 0) as u64);
        print_str(b" hcursor=0x");
        print_hex_u64(hcursor);
        print_str(b"\n");
    }
    copyout_ok
}

fn remember_global_scrollbar_cursor(handle: u32) {
    if handle != 0 {
        let _ = GLOBAL_SCROLLBAR_CLASS_CURSOR.compare_exchange(
            0,
            handle as u64,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

unsafe fn capture_service_client_pfn_arrays(
    pi: usize,
    pfn_client_a: u64,
    pfn_client_w: u64,
    hmod_user: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> bool {
    use nt_kernel_exec::user_class::{pfn_client_proc, FNID_SCROLLBAR, PFNCLIENT_SIZE};

    if pi >= MAX_PI {
        return false;
    }

    let mut captured = false;
    let mut raw = [0u8; PFNCLIENT_SIZE];
    if pfn_client_a != 0
        && img_spawn::client_copyin_mapped(
            pi as u64,
            pfn_client_a,
            &mut raw,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        if let Some(proc) = pfn_client_proc(&raw, FNID_SCROLLBAR).filter(|proc| *proc != 0) {
            SVC_CLIENT_PFNA_SCROLLBAR[pi].store(proc, Ordering::Relaxed);
            captured = true;
        }
    }

    raw.fill(0);
    if pfn_client_w != 0
        && img_spawn::client_copyin_mapped(
            pi as u64,
            pfn_client_w,
            &mut raw,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        if let Some(proc) = pfn_client_proc(&raw, FNID_SCROLLBAR).filter(|proc| *proc != 0) {
            SVC_CLIENT_PFNW_SCROLLBAR[pi].store(proc, Ordering::Relaxed);
            captured = true;
        }
    }

    if hmod_user != 0 {
        SVC_CLIENT_HMOD_USER32[pi].store(hmod_user, Ordering::Relaxed);
    }
    if captured {
        SVC_CLIENT_PFN_ARRAYS_CAPTURED.fetch_add(1, Ordering::Relaxed);
    }
    captured
}

unsafe fn copy_service_scrollbar_class_info(
    pi: usize,
    capture: CapturedGetClassInfo,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<u64> {
    use nt_kernel_exec::user_class::{scrollbar_class_info, WNDCLASSEXW_SIZE};

    if pi >= MAX_PI || !capture.scrollbar {
        return None;
    }
    let proc = if capture.ansi {
        SVC_CLIENT_PFNA_SCROLLBAR[pi].load(Ordering::Relaxed)
    } else {
        SVC_CLIENT_PFNW_SCROLLBAR[pi].load(Ordering::Relaxed)
    };
    if proc == 0 {
        return None;
    }
    let mut atom = SVC_SCROLLBAR_CLASS_ATOM[pi].load(Ordering::Relaxed) as u16;
    if atom == 0 {
        let observed = GLOBAL_SCROLLBAR_CLASS_ATOM.load(Ordering::Relaxed) as u16;
        if observed == 0 {
            return None;
        }
        atom = match SVC_SCROLLBAR_CLASS_ATOM[pi].compare_exchange(
            0,
            observed as u64,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => observed,
            Err(existing) => existing as u16,
        };
    }
    let hcursor = GLOBAL_SCROLLBAR_CLASS_CURSOR.load(Ordering::Relaxed);
    if hcursor == 0 {
        return None;
    }
    let mut initial = [0u8; WNDCLASSEXW_SIZE];
    core::ptr::copy_nonoverlapping(
        capture.wnd_out as *const u8,
        initial.as_mut_ptr(),
        initial.len(),
    );
    let payload = scrollbar_class_info(&initial, atom, proc, hcursor)?;
    core::ptr::copy_nonoverlapping(
        payload.wnd_class().as_ptr(),
        capture.wnd_out as *mut u8,
        WNDCLASSEXW_SIZE,
    );
    core::ptr::write_unaligned(capture.menu_out as *mut u64, payload.menu_name());
    if copy_back_get_class_info(
        pi as u64,
        capture,
        payload.atom() as u64,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        Some(payload.atom() as u64)
    } else {
        SVC_SCROLLBAR_CLASSINFO_COPYOUT_ERRORS.fetch_add(1, Ordering::Relaxed);
        None
    }
}

unsafe fn capture_get_class_name_out(
    pi: u64,
    class_name: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedGetClassName> {
    if class_name == 0 {
        return None;
    }
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        class_name,
        &mut raw,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return None;
    }
    let length = u16::from_le_bytes([raw[0], raw[1]]);
    let maximum = u16::from_le_bytes([raw[2], raw[3]]);
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length & 1 != 0 || maximum < length || maximum == 0 || buffer == 0 {
        return None;
    }
    let staged_max = (maximum as u64).min(RC_ARG_BUF_CAP) as u16;
    if staged_max < 2 {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let desc_out = rc_arg_slot_base(slot);
    let buffer_out = desc_out + 0x20;
    core::ptr::write_bytes(desc_out as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    raw[2..4].copy_from_slice(&staged_max.to_le_bytes());
    raw[8..16].copy_from_slice(&buffer_out.to_le_bytes());
    core::ptr::copy_nonoverlapping(raw.as_ptr(), desc_out as *mut u8, raw.len());
    Some(CapturedGetClassName {
        desc_client: class_name,
        buffer_client: buffer,
        desc_out,
        buffer_out,
        maximum,
    })
}

unsafe fn copy_back_get_class_name(
    pi: u64,
    capture: CapturedGetClassName,
    chars_returned: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> bool {
    let byte_len = chars_returned.saturating_mul(2).min(RC_ARG_BUF_CAP);
    let copy_len = (byte_len + 2)
        .min(capture.maximum as u64)
        .min(RC_ARG_BUF_CAP) as usize;
    let text = core::slice::from_raw_parts(capture.buffer_out as *const u8, copy_len);
    let text_ok = img_spawn::client_write_mapped(
        pi,
        capture.buffer_client,
        text,
        filled_pages,
        nfilled,
        scratch_base,
    );

    let mut desc = [0u8; 16];
    core::ptr::copy_nonoverlapping(capture.desc_out as *const u8, desc.as_mut_ptr(), desc.len());
    desc[2..4].copy_from_slice(&capture.maximum.to_le_bytes());
    desc[8..16].copy_from_slice(&capture.buffer_client.to_le_bytes());
    let desc_ok = img_spawn::client_write_mapped(
        pi,
        capture.desc_client,
        &desc,
        filled_pages,
        nfilled,
        scratch_base,
    );
    text_ok && desc_ok
}

unsafe fn capture_register_class_graph(
    pi: u64,
    wnd_class: u64,
    class_menu: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<(u64, u64)> {
    use nt_kernel_exec::user_class::WNDCLASSEXW_SIZE;

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    if wnd_class == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            wnd_class,
            &mut wnd,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let mut menu = [0u8; 24];
    if class_menu == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            class_menu,
            &mut menu,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }

    let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed) % RC_ARG_CAPTURE_SLOTS;
    let base =
        win32k_subsystem::WIN32K_ARG_VADDR + RC_ARG_CAPTURE_BASE + slot * RC_ARG_CAPTURE_SLOT;
    let wnd_out = base;
    let menu_out = base + WNDCLASSEXW_SIZE as u64 + 0x10;
    let menu_desc_out = base + RC_CLASS_MENU_DESC_OFF;
    let menu_buf_out = base + RC_CLASS_MENU_BUF_OFF;
    let menu_buf_cap = RC_ARG_CAPTURE_SLOT - RC_CLASS_MENU_BUF_OFF;
    core::ptr::write_bytes(base as *mut u8, 0, RC_ARG_CAPTURE_SLOT as usize);
    core::ptr::copy_nonoverlapping(wnd.as_ptr(), wnd_out as *mut u8, wnd.len());

    let menu_descriptor = u64::from_le_bytes(menu[16..24].try_into().unwrap());
    if !stage_unicode_string_descriptor_for_win32k(
        pi,
        menu_descriptor,
        menu_desc_out,
        menu_buf_out,
        menu_buf_cap,
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return None;
    }
    menu[16..24].copy_from_slice(&menu_desc_out.to_le_bytes());
    core::ptr::copy_nonoverlapping(menu.as_ptr(), menu_out as *mut u8, menu.len());
    Some((wnd_out, menu_out))
}

enum CapturedCursorString {
    Atom(u16),
    Text(usize),
}

#[derive(Clone, Copy)]
struct CapturedClassAtomName {
    len: usize,
    units: [u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP],
}

impl CapturedClassAtomName {
    fn as_slice(&self) -> &[u16] {
        &self.units[..self.len]
    }
}

/// Capture one `UNICODE_STRING` used by `NtUserFindExistingCursorIcon`. A zero-length resource is
/// the MAKEINTRESOURCE form: its Buffer field is the integer identity and is never dereferenced.
unsafe fn capture_cursor_counted_string(
    pi: u64,
    descriptor: u64,
    allow_atom: bool,
    units: &mut [u16; nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP],
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedCursorString> {
    use nt_kernel_exec::user_cursor::{
        decode_utf16, parse_string_descriptor, CursorStringDescriptor,
    };

    let mut raw = [0u8; 16];
    if descriptor == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            descriptor,
            &mut raw,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let (length, buffer) = match parse_string_descriptor(&raw, allow_atom)? {
        CursorStringDescriptor::Atom(atom) => return Some(CapturedCursorString::Atom(atom)),
        CursorStringDescriptor::Text { byte_len, buffer } => (byte_len, buffer),
    };
    let mut bytes = [0u8; nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP * 2];
    if !img_spawn::client_copyin_mapped(
        pi,
        buffer,
        &mut bytes[..length],
        filled_pages,
        nfilled,
        scratch_base,
    ) {
        return None;
    }
    decode_utf16(&bytes[..length], units).map(CapturedCursorString::Text)
}

unsafe fn capture_registered_class_atom_name(
    pi: u64,
    class_name_descriptor: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<CapturedClassAtomName> {
    let mut captured = [0u16; nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP];
    let len = match capture_cursor_counted_string(
        pi,
        class_name_descriptor,
        true,
        &mut captured,
        filled_pages,
        nfilled,
        scratch_base,
    )? {
        CapturedCursorString::Text(len) => len,
        CapturedCursorString::Atom(_) => return None,
    };
    if len > nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP {
        return None;
    }
    let mut units = [0u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP];
    units[..len].copy_from_slice(&captured[..len]);
    Some(CapturedClassAtomName { len, units })
}

unsafe fn copy_class_atom_name_from_mirror(
    pi: u64,
    atom: u16,
    unicode_string: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<u64> {
    let mut name = [0u16; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP];
    let Some(name_len) = GLOBAL_CLASS_ATOM_NAME_MIRROR
        .copy_name(atom, &mut name)
        .or_else(|| nt_kernel_exec::user_class::integer_atom_name(atom, &mut name))
    else {
        GLOBAL_CLASS_ATOM_NAME_MIRROR_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let mut raw = [0u8; 16];
    if unicode_string == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            unicode_string,
            &mut raw,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        GLOBAL_CLASS_ATOM_NAME_MIRROR_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    if maximum < 2 {
        return Some(0);
    }
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if buffer == 0 {
        GLOBAL_CLASS_ATOM_NAME_MIRROR_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let chars = name_len.min((maximum - 2) / 2);
    let mut bytes = [0u8; nt_kernel_exec::user_class::CLASS_ATOM_NAME_CAP * 2];
    for (index, unit) in name[..chars].iter().copied().enumerate() {
        bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let text_ok = chars == 0
        || img_spawn::client_write_mapped(
            pi,
            buffer,
            &bytes[..chars * 2],
            filled_pages,
            nfilled,
            scratch_base,
        );
    let terminator_ok = img_spawn::client_write_mapped(
        pi,
        buffer + chars as u64 * 2,
        &0u16.to_le_bytes(),
        filled_pages,
        nfilled,
        scratch_base,
    );
    if !text_ok || !terminator_ok {
        GLOBAL_CLASS_ATOM_NAME_MIRROR_FAILURES.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    GLOBAL_CLASS_ATOM_NAME_MIRROR_SERVES.fetch_add(1, Ordering::Relaxed);
    Some((chars * 2) as u64)
}

unsafe fn capture_cursor_identity_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    icon_kind: u32,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    use nt_kernel_exec::user_cursor::{CursorLookupKey, CursorResource, CURSOR_TEXT_CAP};

    let mut module = [0u16; CURSOR_TEXT_CAP];
    let module_len = match capture_cursor_counted_string(
        pi,
        module_descriptor,
        false,
        &mut module,
        filled_pages,
        nfilled,
        scratch_base,
    )? {
        CapturedCursorString::Text(len) => len,
        CapturedCursorString::Atom(_) => return None,
    };
    let mut resource_name = [0u16; CURSOR_TEXT_CAP];
    let resource = match capture_cursor_counted_string(
        pi,
        resource_descriptor,
        true,
        &mut resource_name,
        filled_pages,
        nfilled,
        scratch_base,
    )? {
        CapturedCursorString::Atom(atom) => CursorResource::atom(atom),
        CapturedCursorString::Text(len) => CursorResource::name(&resource_name[..len])?,
    };
    CursorLookupKey::new(&module[..module_len], resource, icon_kind)
}

/// Probe and capture the complete three-argument lookup key before crossing into win32k. The size
/// fields are intentionally ignored because ReactOS uses only module, resource, and bIcon when it
/// searches the per-process and global cursor lists. Preserve the raw BOOL because win32k compares
/// it directly with its canonical 0/1 object type.
unsafe fn capture_cursor_lookup_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    parameter: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    let mut params = [0u8; 12];
    if parameter == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            parameter,
            &mut params,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let icon_kind = u32::from_le_bytes(params[0..4].try_into().unwrap());
    capture_cursor_identity_key(
        pi,
        module_descriptor,
        resource_descriptor,
        icon_kind,
        filled_pages,
        nfilled,
        scratch_base,
    )
}

/// Capture the identity assigned by a real `NtUserSetCursorIconData`. `CURSORDATA.rt` is RT_CURSOR
/// (1) or RT_ICON (3); normalize it to the canonical BOOL stored by a later lookup key.
unsafe fn capture_cursor_set_data_key(
    pi: u64,
    module_descriptor: u64,
    resource_descriptor: u64,
    cursor_data: u64,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_cursor::CursorLookupKey> {
    let mut data_prefix = [0u8; 18];
    if cursor_data == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            cursor_data,
            &mut data_prefix,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let icon_kind = match u16::from_le_bytes([data_prefix[16], data_prefix[17]]) {
        1 => 0,
        3 => 1,
        _ => return None,
    };
    capture_cursor_identity_key(
        pi,
        module_descriptor,
        resource_descriptor,
        icon_kind,
        filled_pages,
        nfilled,
        scratch_base,
    )
}

unsafe fn capture_class_name_identity(
    pi: u64,
    descriptor: u64,
    allow_none: bool,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_class::ClassNameIdentity> {
    use nt_kernel_exec::user_class::ClassNameIdentity;
    use nt_kernel_exec::user_cursor::CURSOR_TEXT_CAP;

    if descriptor == 0 && allow_none {
        return Some(ClassNameIdentity::none());
    }
    let mut descriptor_bytes = [0u8; 16];
    if descriptor == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            descriptor,
            &mut descriptor_bytes,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let length = u16::from_le_bytes([descriptor_bytes[0], descriptor_bytes[1]]);
    let buffer = u64::from_le_bytes(descriptor_bytes[8..16].try_into().unwrap());
    if allow_none && length == 0 && buffer == 0 {
        return Some(ClassNameIdentity::none());
    }
    let mut name = [0u16; CURSOR_TEXT_CAP];
    match capture_cursor_counted_string(
        pi,
        descriptor,
        true,
        &mut name,
        filled_pages,
        nfilled,
        scratch_base,
    )? {
        CapturedCursorString::Atom(atom) => Some(ClassNameIdentity::atom(atom)),
        CapturedCursorString::Text(len) => ClassNameIdentity::name(&name[..len]),
    }
}

unsafe fn capture_builtin_class_key(
    pi: u64,
    wnd_class: u64,
    class_name: u64,
    class_version: u64,
    class_menu: u64,
    fn_id: u32,
    flags: u32,
    filled_pages: &[u64],
    nfilled: usize,
    scratch_base: u64,
) -> Option<nt_kernel_exec::user_class::BuiltinClassKey> {
    use nt_kernel_exec::user_class::{BuiltinClassKey, WNDCLASSEXW_SIZE};

    let mut wnd = [0u8; WNDCLASSEXW_SIZE];
    if wnd_class == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            wnd_class,
            &mut wnd,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let class_name =
        capture_class_name_identity(pi, class_name, false, filled_pages, nfilled, scratch_base)?;
    let class_version = capture_class_name_identity(
        pi,
        class_version,
        false,
        filled_pages,
        nfilled,
        scratch_base,
    )?;
    let mut menu_graph = [0u8; 24];
    if class_menu == 0
        || !img_spawn::client_copyin_mapped(
            pi,
            class_menu,
            &mut menu_graph,
            filled_pages,
            nfilled,
            scratch_base,
        )
    {
        return None;
    }
    let menu_descriptor = u64::from_le_bytes(menu_graph[16..24].try_into().unwrap());
    let menu_name = capture_class_name_identity(
        pi,
        menu_descriptor,
        true,
        filled_pages,
        nfilled,
        scratch_base,
    )?;
    BuiltinClassKey::decode(&wnd, class_name, class_version, menu_name, fn_id, flags)
}

/// Faults are routed to the main image (at PE_LOAD_BASE) or, if present, a second image `ntdll`
/// at `(base, pe)` — so smss's resolved ntdll calls fault ntdll's pages in and EXECUTE. SAFE
/// STOP: halt (don't loop) on a fault outside BOTH images (a null deref / bad address), a
/// non-VMFault (#GP), or a fault cap. Returns (verdict, faults, first, stop, ntdll_faults).
pub(crate) unsafe fn service_sec_image(
    fault_ep: u64,
    pml4: u64,
    main_tcb: u64,
    pe: &nt_pe_loader::PeFile,
    scratch_base: u64,
    ntdll: Option<(u64, &nt_pe_loader::PeFile)>,
) -> (u64, u64, u64, u64, u64, u64) {
    loader_trace_clear();
    let img_end = PE_LOAD_BASE + image_extent(pe);
    let (nt_base, nt_end) = match ntdll {
        Some((b, npe)) => (b, b + image_extent(npe)),
        None => (0, 0),
    };
    let mut verdict = 0u64;
    let mut faults = 0u64;
    // Per-process demand-fault backstop (see the use sites). BATCH-22: raised from 2000 now that the
    // persistent scratch VA is decoupled from this count (bounded ≤256 slots) — it's a frame-budget /
    // runaway guard only, sized to let lsass's full LSA-init DLL tree page in within the frame pool.
    // Per-process fresh-fill ceiling. Each fresh fill consumes a UNIQUE monotonic scratch slot
    // (`scratch_base + faults*0x1000`), so this must stay under the per-process scratch window
    // (now 64 MiB = 16384 slots, see map_demand_scratch_pts). (A) EAGER IMAGE-MAP front-loads a
    // process's whole DLL tree, so raised 6000→15000 (headroom under 16384) to let lsass's full
    // LSA-init tree page in eagerly without hitting the cap. Runaway/frame-pool guard only.
    let mut first = 0u64;
    let mut stop = 0u64;
    let mut ntfaults = 0u64;
    let mut stop_ssn = 0u64;
    let mut iters = 0u64;
    let mut dbgsvc = 0u64;
    // page VA filled at each fault index → its persistent executive scratch is
    // scratch_base + index*0x1000. Lets a syscall handler copy OUT to any already-mapped image
    // page (e.g. an ntdll .data global), not just the stack (which has its own mirror).
    // Working buffer for the current pi's demand-filled page VAs — a STATIC (not a 4 KiB stack local)
    // so the 5th hosted process doesn't pressure the rootserver stack on the deep FS-walk call
    // chain (see FILLED_WORK). Loaded from / saved to `pfilled[pi]` around each dispatch below.
    let filled_pages: &mut [u64; 512] = &mut *core::ptr::addr_of_mut!(FILLED_WORK);
    // DIAG ring buffer of the last serviced SSNs, to locate the silent 0x80000005.
    let mut ssn_ring = [0u16; 32];
    let mut ssn_ring_badge = [0u8; 32];
    // winlogon-main-only ring (badge==WINLOGON_BADGE) — isolate winlogon's sequence from the
    // services (badge 6) noise that dominates the shared ring, to diagnose the StartLsass wall.
    let mut wl_ring = [0u16; 48];
    let mut wl_ri = 0usize;
    let mut ssn_ri = 0usize;
    // Distinct fake handles for objects we don't model yet (ports/threads/events/sections) now live
    // on `nt_handler.next_handle` (Workstream A group A) — a single monotonic source shared by the
    // migrated create-handle handlers and the remaining ladder cases (NtCreateSection/Process/File).
    let mut csrss_process_handle = 0u64;
    // Generic owner-local file/section/spawn state for hosted executable images.
    let mut exe_images = nt_exe_image::ImageTable::<8>::new();
    let mut exe_image_catalog = nt_exe_image::OwnedHostedImageCatalog::<8>::new();
    reset_hosted_process_runtimes();
    register_loaded_hosted_image(
        &mut exe_image_catalog,
        smss_bootstrap_image(),
        smss_process_runtime(),
        !pe.bytes().is_empty(),
    )
    .expect("SMSS hosted image metadata must register once");
    // csrss's loadable DLLs (csrsrv + the ServerDlls basesrv/winsrv) are tracked by the generic
    // nt-dll-registry, built below once their PEs are parsed. The shared page-directory covering the
    // 0x8000_0000 1 GiB range (the compact DLL arena lives in it) is created on the first map.
    // Per-process (indexed by pi: 0=smss, 1=csrss, 2=winlogon): the DLL page-directory once-flag +
    // a bitset of which arena PT windows are reserved in that process's VSpace. Compact DLLs may
    // share a PT and large DLLs may span several.
    let mut dll_pd_created = [false; MAX_PI];
    let mut dll_pt_bits = [[0u64; DLL_ARENA_PT_WORDS]; MAX_PI];
    // csrss's ANONYMOUS section (no file backing) — its CSR SharedSection shared memory. Tracked by
    // handle + requested size; NtMapViewOfSection reserves a VA range and the fault router
    // demand-pages ZERO frames into it (commit-on-touch).
    let mut csrss_anon_section_handle = 0u64;
    let mut csrss_anon_base = 0u64;
    let mut csrss_anon_size = 0u64;
    // The named NLS section \Nls\NlsSectionCP20127 (US-ASCII code-page table) csrss's Win32 client
    // stack maps during a DllMain. NtOpenSection records the handle; NtMapViewOfSection maps the
    // staged c_20127.nls frames into csrss.
    let mut nls_section_handle = 0u64;
    // Only the LIVE smss run (ntdll present) launches hosted child EXEs; the earlier demo SEC_IMAGE
    // call has no FS/pool, so skip the reads there. The bootstrap manifest supplies disk paths,
    // image identity, and runtime layout; each loaded PE is relocated to PE_LOAD_BASE and published
    // into the loaded-image registry below.
    let bootstrap_load_specs = hosted_bootstrap_load_specs();
    let csrss_pi = bootstrap_load_specs
        .iter()
        .find(|spec| spec.image.role == nt_exe_image::HostedProcessRole::Win32Subsystem)
        .map(|spec| spec.image.pi)
        .expect("bootstrap manifest must include CSRSS");
    let mut hosted_bootstrap_pes: [Option<nt_pe_loader::PeFile<'static>>;
        HOSTED_BOOTSTRAP_LOAD_COUNT] = core::array::from_fn(|_| None);
    let mut hosted_bootstrap_pool_vas = [0u64; HOSTED_BOOTSTRAP_LOAD_COUNT];
    for (index, spec) in bootstrap_load_specs.iter().copied().enumerate() {
        let (loaded_pe, pool_va) =
            load_hosted_bootstrap_image(&mut exe_image_catalog, ntdll.is_some(), spec);
        hosted_bootstrap_pes[index] = loaded_pe;
        hosted_bootstrap_pool_vas[index] = pool_va;
    }
    let mut hosted_loaded_images = HostedLoadedImageTable::new();
    for (index, spec) in bootstrap_load_specs.iter().copied().enumerate() {
        register_loaded_hosted_bootstrap_pe(
            &mut hosted_loaded_images,
            spec,
            &hosted_bootstrap_pes[index],
            hosted_bootstrap_pool_vas[index],
        );
    }
    // Generic DLL registry: the loadable DLLs each hosted process's ntdll loader resolves +
    // demand-pages — csrss's static import csrsrv.dll + its CsrLoadServerDll ServerDlls
    // basesrv/winsrv, the shared Win32 client stack (kernel32/user32/gdi32/rpcrt4/…), winlogon's
    // userenv/mpr, and lsass's lsasrv/samsrv/msv1_0. ALL are sourced BY PATH from the real \reactos
    // FS into the demand-load pool — NO hardcoded per-DLL block, NO fixed staging buffer, NO
    // STORAGE_SHARED offset: a single DATA-DRIVEN table (seed stem, System32 leaf) drives the load.
    // Adding a served DLL = one row here. ORDER IS LOAD-BEARING: it is the registration order, which
    // is the base-assignment order — csrsrv MUST stay first so it keeps registry base 0x8000_0000 =
    // its preferred ImageBase (relocation delta 0, text byte-identical + shared read-only across
    // processes); the rest are loader-relocated to their fixed slots. All slots share the 1 GiB
    // 0x8000_0000 PDPT range. Load-flow DECISIONS (name/handle/VA lookups + SECTION_IMAGE_INFORMATION)
    // run through host-tested nt-dll-registry; the executive keeps the parsed PEs parallel (same
    // index) for the effectful demand-fill. (winsrv is ~100 pages — the root CNode is an XL page under
    // extern-rootserver, so the caps fit.) These load at BOOT (below the service_sec_image heap mark)
    // rather than on the fly during a syscall because the per-syscall bump-heap reset would rewind any
    // registry Vec growth / pool alloc made ABOVE the mark; loading them here keeps every DLL's parsed
    // PE + registry slot persistent (see project_full_fs Part 2 for the demand-load-during-syscall
    // rework this still awaits).
    // Part 3 — TRUE syscall-time demand-load. The eager per-DLL `DLL_TABLE` is GONE: DLLs load PURELY
    // ON-DEMAND from the real \reactos FS when a hosted process's loader first requests one (a
    // `reg.resolve_name` MISS in NtOpenFile → `fs_loader::demand_load_dll`). At boot we only:
    //   (1) PIN csrsrv at slot 0 (base 0x8000_0000 = its preferred ImageBase, relocation delta 0 →
    //       byte-identical shared text, loader never relocates it). Demand-load assigns slots in
    //       loader-request order, which can't guarantee csrsrv lands at slot 0, so this ONE entry is a
    //       documented pin (DLL_PIN_COUNT). No other DLL cares about its base (all get relocated).
    //   (2) RESERVE the remaining metadata slots empty (per-pi handle stores pre-allocated below
    //       the heap_mark → the on-demand `activate` at syscall time needs NO heap growth, surviving
    //       the per-syscall bump-heap reset). `dll_pe_store` is pre-sized below the mark, so an
    //       on-demand `dll_pe_store[slot] = Some(pe)` is likewise reset-safe. The pool bytes live
    //       in the cap-mapped POOL arena (atomic POOL_NEXT), reset-safe too.
    // Adding a new DLL (userinit/explorer/shell32/…) now needs NO edit here — it demand-loads into a
    // free reserved slot. NO maintained DLL list remains (only the 1-entry csrsrv base pin).
    // csrsrv (base pin) + the three `_vista` forwarder DLLs (loaded via LdrpSnapThunk's forwarder
    // path, which the NtOpenFile-based demand-load hook can't catch — see DLL_PIN_COUNT). ws2help is
    // demand-loadable (ws2_32 loads it as a normal import, not a forwarder), so it's NOT pinned.
    const DLL_PINS: [(&[u8], &[u8]); DLL_PIN_COUNT] = [
        (b"csrsrv", b"reactos\\system32\\csrsrv.dll"),
        (b"kernel32_vista", b"reactos\\system32\\kernel32_vista.dll"),
        (b"advapi32_vista", b"reactos\\system32\\advapi32_vista.dll"),
        (b"ntdll_vista", b"reactos\\system32\\ntdll_vista.dll"),
    ];
    // Heap-backed parsed-PE storage (lives for the whole loop without consuming the 16 KiB stack).
    // `dll_pes[i]` holds `&dll_pe_store[i]`
    // — a stable ref into this array — so the erased `*const [&Option<PeFile>; N]` handed to the
    // handler stays valid when a demand-load later writes `dll_pe_store[slot] = Some(pe)` (the ref
    // points AT the slot, so it observes the new value). Only the LIVE run (ntdll present) mounts the
    // pool/FS + demand-loads; the demo SEC_IMAGE call leaves every slot None.
    let mut dll_pe_store: Vec<Option<nt_pe_loader::PeFile<'static>>> =
        Vec::with_capacity(DLL_REG_COUNT);
    dll_pe_store.resize_with(DLL_REG_COUNT, || None);
    let mut reg = nt_dll_registry::Registry::new(DLL_ARENA_START, DLL_ARENA_END);
    if ntdll.is_some() {
        // (1) Load + register + relocate the pinned csrsrv at slot 0 (base 0x8000_0000, delta 0).
        for (i, &(stem, path)) in DLL_PINS.iter().enumerate() {
            let (pe, va) = load_dll_from_fs(path, stem);
            let (sz, ent) = pe
                .as_ref()
                .map(|p| (image_extent(p), p.entry_point_rva()))
                .unwrap_or((0, 0));
            reg.register(stem, sz, ent);
            if let Some(ref p) = pe {
                let base = reg.base(i);
                apply_relocations_to_buf(p, va, base);
                let e_lfanew = core::ptr::read_volatile((va + 0x3c) as *const u32) as u64;
                core::ptr::write_volatile((va + e_lfanew + 0x30) as *mut u64, base);
            }
            dll_pe_store[i] = pe;
        }
    }
    // (2) Reserve remaining metadata slots. VA is consumed only when a real image activates one.
    for _ in DLL_PIN_COUNT..DLL_REG_COUNT {
        reg.reserve();
    }
    // Raw mut ptr to the PE store for the on-demand fill (the handler activates a reserved slot then
    // writes its parsed PE here via this ptr; `dll_pes[slot]` — a ref AT the slot — observes it).
    // Taken BEFORE `dll_pes` borrows the array immutably (a raw ptr holds no borrow). The demand-load
    // writes through this ptr are single-threaded + never alias a live `dll_pes[i]` read (the router
    // reads a slot only after it's mapped, which is after it's written).
    let dll_pe_store_ptr = dll_pe_store.as_mut_ptr();
    let dll_pes: Vec<&Option<nt_pe_loader::PeFile>> =
        (0..DLL_REG_COUNT).map(|i| &dll_pe_store[i]).collect();
    // The real NT syscall path (seam): dispatch SSNs the handler implements; the rest fall back
    // to the broker match below.
    let nt_dispatcher = NativeSyscallDispatcher::new(build_nt_table());
    let mut nt_handler = reset_exec_nt_handler(
        &exe_image_catalog as *const nt_exe_image::OwnedHostedImageCatalog<8>,
    );
    nt_handler.register_main_thread_tcb(0, main_tcb);
    let mut delay_queue = nt_delay_execution::Queue::<DELAY_WAITER_N>::new();
    if ntdll.is_some() {
        publish_kuser_clocks();
        let alias = kuser_page_alias_get(0);
        if alias != 0 {
            KUSER_CLOCK_INITIAL_TICK.store(
                u64::from(nt_ntdll_layout::kuser::read_tick_count(alias as *const u8)),
                Ordering::Release,
            );
        }
        KUSER_CLOCK_INIT_OK.store(true, Ordering::Release);
    }
    // Heap high-water mark taken AFTER all persistent state (the service table + the
    // pre-reserved process handle tables) is allocated. Each smss syscall we service allocates
    // transient Vec/String (copyin buffers, registry value info) on the no-free bump heap; without
    // reclamation a few hundred registry syscalls exhaust the 128 KiB heap and the executive
    // panics. Rewinding to this mark each iteration reclaims all per-syscall transients while
    // leaving the persistent state (below the mark) intact.
    // `mut` because the CM write overlay's runtime `String`/`Vec` growth (NtCreateKey/NtSetValueKey)
    // must survive the per-syscall reset: after a mutating syscall the loop advances this mark past
    // the overlay's new allocations (see the `overlay_dirty` consume below the dispatch).
    let mut heap_mark = allocator::mark();
    // Per-hosted-process state, indexed by fault badge (0 = smss, 1 = csrss). The SINGLE service
    // loop multiplexes both: each thread faults through a fault-EP cap minted with its badge, so the
    // recv badge selects whose VSpace / image / scratch / fault-bookkeeping to use. Slot 1 (csrss)
    // is filled in when NtCreateProcess spawns it; until then only slot 0 (smss) is live. The `mut`
    // working locals (pml4/scratch_base/img_end/pe via shadowing, faults/first/ntfaults/filled_pages)
    // are LOADED from these at the top of each iteration and SAVED back before each recv, so the
    // ~30 body references stay unchanged.
    // smss's PE (the function param `pe` is shadowed per-iteration to the active process's image; the
    // SM-loop rendezvous always demand-fills SMSS's image, so capture it here before the shadow).
    let smss_pe: &nt_pe_loader::PeFile = pe;
    // Bind smss's pre-created main ETHREAD to its real image entry (smss is already running from the
    // initial recv, not a loop spawn — so bind here). Only on the LIVE run (ntdll present).
    if ntdll.is_some() {
        nt_handler.bind_main_thread_entry(0, PE_LOAD_BASE + smss_pe.entry_point_rva() as u64);
    }
    // Slots are EPROCESS-linked via the handler-owned process mechanism lookup. smss is live from
    // the initial recv; later hosted processes claim their pid on the native create-process path and
    // fill pml4/scratch/img_end when the service loop constructs their seL4 mechanism.
    let mut procs = [ProcExec::empty(); MAX_PI];
    for (i, p) in procs.iter_mut().enumerate() {
        p.pid = nt_handler
            .pm_pid_for_pi(i)
            .map(|pid| pid as u64)
            .unwrap_or(0);
    }
    procs[0].pml4 = pml4;
    nt_handler
        .publish_hosted_process_vspace(0, pml4)
        .expect("smss VSpace publication requires a registered bootstrap process");
    procs[0].scratch_base = scratch_base;
    procs[0].img_end = img_end;
    // Per-process demand-fill bookkeeping is kept in static storage rather than on the bounded
    // rootserver stack (a local copy plus the loop's other arrays would risk the guard
    // page — the recurring stack-array-overflow hazard). service_sec_image runs once for the live
    // run; zero it at entry so the demo call (ntdll=None) starts clean too.
    let pfilled: &mut [[u64; 512]; MAX_PI] = &mut *core::ptr::addr_of_mut!(PFILLED);
    for p in pfilled.iter_mut() {
        for e in p.iter_mut() {
            *e = 0;
        }
    }
    let vm_maps = core::ptr::addr_of_mut!(PROCESS_VM_REGIONS)
        as *mut nt_address_space::VmRegionMap<VM_REGION_CAPACITY>;
    for index in 0..MAX_PI {
        core::ptr::write(
            vm_maps.add(index),
            nt_address_space::VmRegionMap::new(SMSS_ALLOC_VA, PRIVATE_VM_LIMIT),
        );
    }
    VM_FREE_FRAME_N = 0;
    // Fix (B): the INITIAL recv also binds REPLY_MAIN (r12) so the first caller's Call is captured
    // as a reply cap, matching every reply_recv_badge recv in the loop body.
    let (mut badge, mut mi, mut m0, mut m1, mut m2, mut m3) =
        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
    // ★★ PARK + QUIESCE CONTRACT — see docs/n-threads-multiplex.md §1a for the authoritative catalog
    // of every park site + the quiesce predicate. Load-bearing: moving a park's location/condition or
    // changing the quiesce logic can hang the boot (never quiesce) or quiesce EARLY (miss specs / skip
    // the desktop paint). The two helpers below (`park_and_log!` crash parks, `mark_wait_parked!`
    // wakeable waits) + the `crash_parked`/`wait_parked` bitmasks ARE the unified park mechanism; the
    // remaining direct-`break` sites are per-process steady-state predicates (notably the
    // LSA_RPC_SERVER_ACTIVE_SIGNALLED paint-ordering guard) intentionally kept distinct.
    // ★ FAULT ISOLATION (generalized park-and-log). An UNHANDLED / UNRECOVERABLE fault in ONE hosted
    // process must PARK THAT PROCESS (with a clear one-line log) and let the shared loop CONTINUE
    // servicing the others — a process crash does not halt the kernel (fundamental OS fault isolation).
    // This replaces the recurring whack-a-mole of adding a bespoke park arm per new terminal wall
    // (smss-190, the listener-parks, the lsass-post-signal park, …). `crash_parked` is a bitmask of
    // top-level process badges (0/2/4/6/8, all < 64) that have hit an unrecoverable crash; a parked
    // process's further faults are re-parked WITHOUT re-logging (the `already` guard). QUIESCE
    // (break → gate) only when no live top-level process can make forward progress — every live one
    // is crash-parked (so `recv` would block forever). Cooperative parks (wait/delay/listener) are a
    // DIFFERENT, wakeable state and are left as-is; only a real crash sets a `crash_parked` bit.
    let mut crash_parked: u64 = 0;
    // Which THREAD badges have already logged a `[parked]` fault line (see `park_and_log!`).
    let mut crash_logged: u64 = 0;
    // Cooperative-wait bitmask: top-level process badges currently parked in a WAKEABLE wait
    // (NtWaitForSingleObject/MultipleObjects on an unsignalled event, or a lsass-post-signal
    // containment park). A wait-parked process CAN still be woken by a RUNNING process's NtSetEvent,
    // so it stays in the live set — UNLESS every live process is now parked (crash OR wait), in which
    // case no signaler remains → deadlock → quiesce. Cleared at loop-top when the process produces an
    // event (it's running again). This closes the quiesce gap: winlogon WaitForLsass-parked + lsass
    // server-thread-parked + services crash-parked would otherwise block `recv` forever (boot timeout,
    // gate never runs). See the `maybe_quiesce_all_parked!` uses at the wait-park sites.
    let mut wait_parked: u64 = 0;
    // park_and_log!(label, ip, cr2): the generalized UNRECOVERABLE-fault handler. Logs once per
    // top-level process (`[parked] pi=.. badge=.. fault=.. ip=.. cr2=..`), marks its crash bit,
    // flushes this pi's fault bookkeeping, then QUIESCE-checks (if every live top-level process is
    // now crash-parked, break → the gate runs + qemu_exit) else recv-next WITHOUT replying (the
    // faulting thread stays blocked in-kernel, exactly like the cooperative listener-park) and
    // continue the loop for another badge. Uses the surrounding loop locals directly (single call
    // site style), so it must be invoked where they are all in scope.
    macro_rules! park_and_log {
        ($pi:expr, $label:expr, $ip:expr, $cr2:expr) => {{
            let __pi: usize = $pi;
            let __owner = owner_top_badge_for(&nt_handler, badge);
            let __bit = 1u64 << __owner;
            // ★ THE LOG LINE IS PER *THREAD* BADGE, the crash BIT is per process. A hosted process
            // has several threads and one of them can already have milestone-parked (which sets the
            // process's crash bit) — suppressing the print on the process bit then SILENCED a
            // genuinely NEW fault on a different thread, and the boot quiesced with no fault line at
            // all. Measured in batch 59: winlogon's worker parked on an empty GetMessage, then its
            // main thread faulted post-profile-copy and printed NOTHING.
            let __log_bit = 1u64 << (badge & 63);
            let __already = (crash_logged & __log_bit) != 0;
            crash_logged |= __log_bit;
            crash_parked |= __bit;
            if !__already {
                print_str(b"[parked] pi=");
                print_u64(__pi as u64);
                print_str(b" badge=");
                print_u64(badge);
                print_str(b" fault=");
                print_str($label);
                print_str(b" ip=0x");
                print_hex((($ip as u64) >> 32) as u32);
                print_hex($ip as u32);
                print_str(b" cr2=0x");
                print_hex((($cr2 as u64) >> 32) as u32);
                print_hex($cr2 as u32);
                print_str(b" -> PARK process (unrecoverable); loop continues\n");
            }
            procs[__pi].faults = faults;
            procs[__pi].first = first;
            procs[__pi].ntfaults = ntfaults;
            pfilled[__pi] = *filled_pages;
            // ★ DEAD-CLIENT CALLBACK UNWIND. If this process died while it was running a win32k
            // user-mode callback, win32k's dispatch is SUSPENDED inside `KeUserModeCallback` waiting
            // for a reply this thread can no longer send. Unwind those continuations now and resume
            // win32k with a failure NTSTATUS, so the isolated component returns to its idle dispatch
            // receive loop instead of being stranded (which would block the shared loop's next `recv`
            // forever = boot wedge, no gate, no measurement). No-op when the process held no
            // callbacks. See win32k_glue::unwind_dead_client_user_callbacks.
            let _ = win32k_glue::unwind_dead_client_user_callbacks(__pi as u32);
            // QUIESCE: no live top-level process can still make forward progress → nothing left to
            // serve. `wait_parked` counts too (matching every other quiesce site): a crash-park plus
            // all-others-cooperatively-waiting leaves NO runnable signaler, so the next `recv` would
            // block forever. Additionally, winlogon dying at its post-OpenSCManager GUI/login
            // frontier (LSA already signalled → services/lsass are just idle RPC servers with no live
            // client left) is terminal for the boot by the same rule the null-deref arm already
            // applies — generalized here so it holds for ANY unrecoverable winlogon fault.
            if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0
                || (__pi == 2 && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0)
            {
                print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                stop = $ip as u64;
                break;
            }
            let (nb, nmi, nm0, nm1, nm2, nm3) =
                recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            // Diverges: park_and_log! always exits the current loop iteration (never yields a value).
            continue
        }};
    }
    // ★ dbgk_forward_exception!(pi, record) — `DbgkForwardException` on the REAL fault path.
    //
    // Invoked at each site where this loop has CLASSIFIED an unrecoverable USER exception
    // (`#PF`/`#GP`/`#UD`/int3/single-step), immediately BEFORE that site's existing handling.
    // `ExecNtHandler::dbgk_forward_exception` consults `EPROCESS.DebugPort`: a process with no
    // debugger attached returns `false` having done NOTHING (two lookups, no log, no state change),
    // so the whole fault path — `park_and_log!`, `crash_parked`, the dead-client callback unwind,
    // the win32k arms — behaves byte-identically to before this existed. That is the case for every
    // process on the current boot (nothing calls `NtDebugActiveProcess`), so the live serial output
    // is unchanged. When a debugger IS attached, a real `DbgKmExceptionApi` event carrying the
    // faithful `EXCEPTION_RECORD` (code / flags / address / parameters + FirstChance) is queued on
    // its `DEBUG_OBJECT` and any thread parked in `NtWaitForDebugEvent` is woken.
    //
    // ★ TARGET-SIDE BLOCKING (`DbgkpQueueMessage`'s wait on `DebugEvent->ContinueEvent`). After a
    // successful forward the FAULTING THREAD IS PARKED on the event — its reply capability is stolen
    // into the `DEBUG_EVENT` — and the site must recv the next event WITHOUT replying
    // (`dbgk_block_and_park!` below does exactly that). `NtDebugContinue` then applies the continue
    // status: `DBG_CONTINUE` resumes it with the FAULT-flavoured reply (a `#PF` retries the faulting
    // instruction, an int3 resumes past it), `DBG_EXCEPTION_NOT_HANDLED` leaves the site's own
    // handling standing, and `DBG_TERMINATE_THREAD`/`DBG_TERMINATE_PROCESS` are ENFORCED.
    // See `ntdll_plan.md` §D.
    macro_rules! dbgk_forward_exception {
        ($pi:expr, $record:expr) => {{
            let __record: nt_process::dbgk::ExceptionRecord = $record;
            let __forwarded = nt_handler.dbgk_forward_exception($pi, 0, __record, true);
            if __forwarded {
                print_str(b"[dbgk] exception forwarded to debugger pi=");
                print_u64($pi as u64);
                print_str(b" code=0x");
                print_hex(__record.exception_code);
                print_str(b" addr=0x");
                print_hex((__record.exception_address >> 32) as u32);
                print_hex(__record.exception_address as u32);
                print_str(b"\n");
            }
            __forwarded
        }};
    }
    // dbgk_block_and_park!(pi, kind, ip, sp, flags): BLOCK the faulting thread on the debug event it
    // just reported, then recv the next event WITHOUT replying (the thread stays blocked in-kernel,
    // exactly like `park_and_log!`'s park, but WAKEABLE — the debugger's continue resumes it).
    //
    // ★ SAFETY. Reached only when `dbgk_forward_exception!` returned true, i.e. the process really
    // has an `EPROCESS.DebugPort` — never on the live boot. If the park cannot be taken (no reply
    // object, pool exhausted) it yields `false` and the site's ordinary handling runs unchanged.
    // A blocked reporter counts toward the all-parked QUIESCE (it is a cooperative wait), so a
    // debugger that never continues still lets the boot reach the gate.
    macro_rules! dbgk_block_and_park {
        ($pi:expr, $kind:expr, $ip:expr, $sp:expr, $flags:expr) => {{
            let __blocked =
                nt_handler.dbgk_block_reporter($pi, 0, badge, $kind, 0, $ip, $sp, $flags, 0);
            if __blocked {
                print_str(b"[dbgk] reporter BLOCKED on continue (fault kind=");
                print_u64($kind as u64);
                print_str(b") pi=");
                print_u64($pi as u64);
                print_str(b" ip=0x");
                print_hex((($ip as u64) >> 32) as u32);
                print_hex($ip as u32);
                print_str(b"\n");
                procs[$pi].faults = faults;
                procs[$pi].first = first;
                procs[$pi].ntfaults = ntfaults;
                pfilled[$pi] = *filled_pages;
                mark_wait_parked!($pi, $ip);
                let (nb, nmi, nm0, nm1, nm2, nm3) =
                    recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
            }
            __blocked
        }};
    }
    // mark_wait_parked!(pi): record that this top-level process is now cooperatively wait-parked, and
    // if EVERY live top-level process is now parked (crash OR wait) — i.e. no runnable thread remains
    // to signal any waiter — QUIESCE (break → the gate runs). Called right before a wait-park's
    // recv-without-reply. Non-diverging in the common case (just sets the bit); breaks only at true
    // all-parked deadlock. `$ip` is used as the reported stop value.
    macro_rules! mark_wait_parked {
        ($pi:expr, $ip:expr) => {{
            let __owner = owner_top_badge_for(&nt_handler, badge);
            wait_parked |= 1u64 << __owner;
            if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0 {
                print_str(
                    b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n",
                );
                stop = $ip as u64;
                let _ = $pi;
                break;
            }
        }};
    }
    // (B) GLOBAL PROGRESS-STALL WATCHDOG state — WALL-CLOCK based (iteration counts are useless here:
    // each win32k dispatch is a whole-component TCG round-trip taking SECONDS, so the loop does only
    // ~1-2 iterations/sec and an iter-count stall never trips within the boot budget). `last_progress_t`
    // is the monotonic time (100ns units) at the last epoch bump (a NEW demand-load / fresh page fill /
    // event / paint = real forward progress). If NO progress happens for STALL_BUDGET_100NS of
    // WALL-CLOCK time, forward progress is impossible (every live process cooperatively parked with no
    // signaler, or a slow win32k live-lock that WALLs without loading/filling anything new) → QUIESCE
    // (break → run the gate + qemu_exit). Generous enough that a genuinely-advancing (even if slow)
    // boot phase — which keeps filling pages / loading DLLs — never trips; only a true stall does.
    const STALL_BUDGET_100NS: u64 = 45 * 10_000_000; // 45 s of NO forward progress
    let mut last_progress_epoch = PROGRESS_EPOCH.load(Ordering::Relaxed);
    let mut last_progress_t = monotonic_time_100ns();
    // FORWARD-PROGRESS CENSUS (see `print_progress_census`): attribute the wall-clock between two
    // consecutive loop tops to the badge that was serviced in between, and count the iterations.
    let mut census_prev_t = last_progress_t;
    let mut census_prev_badge = usize::MAX;
    // …and dump that census every `CENSUS_PERIOD_100NS`, so a boot that never quiesces (killed by
    // the harness at RUNEXIT=124, before the gate/final census ever runs) STILL says where its
    // wall-clock went. Successive dumps turn a runaway into a measurable RATE. The clock is a
    // STATIC because the win32k dispatch arm's nested pump ticks it too (see `w32_census_enter`).
    CENSUS_LAST_DUMP.store(last_progress_t, Ordering::Relaxed);
    loop {
        if ntdll.is_some() {
            publish_kuser_clocks();
        }
        // Progress-stall accounting: reset the wall-clock window on any epoch bump (real forward
        // progress); quiesce if no progress for STALL_BUDGET_100NS.
        {
            let ep = PROGRESS_EPOCH.load(Ordering::Relaxed);
            let now = monotonic_time_100ns();
            {
                let slot = census_slot(badge);
                if census_prev_badge != usize::MAX {
                    BADGE_TIME_100NS[census_prev_badge]
                        .fetch_add(now.wrapping_sub(census_prev_t), Ordering::Relaxed);
                }
                BADGE_EVENTS[slot].fetch_add(1, Ordering::Relaxed);
                BADGE_LAST_T[slot].store(now, Ordering::Relaxed);
                census_prev_badge = slot;
                census_prev_t = now;
                census_tick_static(now);
            }
            if ep != last_progress_epoch {
                last_progress_epoch = ep;
                last_progress_t = now;
            } else if now.wrapping_sub(last_progress_t) >= STALL_BUDGET_100NS {
                if defer_explorer_startup_quiesce(&nt_handler) {
                    last_progress_t = now;
                } else {
                    print_str(b"[quiesce] no forward progress for ~45s wall-clock (no new load/fill/event/paint) -> run gate\n");
                    stop = m1;
                    break;
                }
            }
        }
        // TAIL WATCH — sample every hosted process' TEB tail on EVERY service-loop event, so the
        // good→bad transition is attributed to the event that preceded it rather than to whichever
        // observer happened to look next.
        for watch_pi in 1..5usize {
            crate::teb_tail_watch(watch_pi, 0, m0, badge);
        }
        // ★ ARM THE IN-`recv` DEADMAN at the POST-LOGON milestone — the frontier this batch works
        // on, and safely past every SM/CSR/LSA rendezvous whose nested receive loops do not screen a
        // bound-notification badge. From here on a boot that stops receiving IPC entirely reports
        // itself (`[deadman]`) and quiesces to the gate instead of hanging out the run's timeout.
        if crate::EXEC_DEADMAN_WATCHDOG
            && crate::WATCHDOG_ARMED.load(Ordering::Relaxed) == 0
            && WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0
        {
            crate::watchdog_arm(&delay_queue);
        }
        // Keep the client-side TEB-tail watch armed from winlogon's SPAWN on (bounded by
        // WL_TEB2_MAX_CYCLES). Arming it at the post-logon milestone was measured to be TOO LATE —
        // the descriptor was already corrupt one second before the first arm.
        if crate::WL_TEB_TAIL_WRITE_WATCH {
            crate::wl_teb2_protect();
        }
        // ★ DRAIN timer ticks a COMPONENT PUMP absorbed. The HPET notification is bound to the root
        // TCB, so it can cancel ANY blocking recv the executive makes — including `pump_recv`'s,
        // which cannot service it (the delay queue lives here). The pump latches it instead; this
        // runs the same `delay_timer_interrupt` the badge arm below would have, one dispatch later.
        // Multiple pump receives can absorb ticks before this loop top; service the coalesced timer
        // state once, but account for every delivery the pump deferred.
        let pump_ticks = DELAY_TIMER_TICKS_PENDING.swap(0, Ordering::Relaxed);
        if pump_ticks != 0 {
            PUMP_TIMER_TICKS_DRAINED.fetch_add(pump_ticks, Ordering::Relaxed);
            delay_timer_interrupt(&mut delay_queue, &mut nt_handler);
        }
        if badge == DELAY_TIMER_BADGE {
            if delay_queue.len() != 0 && delay_queue.has_badge_other_than(badge) {
                let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
                if progress < 8 {
                    print_str(
                        b"[delay] timer badge progressed while client waiter parked: queued=",
                    );
                    print_u64(delay_queue.len() as u64);
                    print_str(b"\n");
                }
            }
            let timer_trace = DELAY_TIMER_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
            if timer_trace < 8 {
                print_str(b"[delay] TIMER-NOTIFICATION msginfo_label=");
                print_u64(mi >> 12);
                print_str(b" raw_m0=0x");
                print_hex_u64(m0);
                print_str(b"\n");
            }
            delay_timer_interrupt(&mut delay_queue, &mut nt_handler);
            // ★ THE DEADMAN'S TEETH. `watchdog_on_tick` (inside `recv_full_r12`) has already
            // REPORTED the deadlock; this is where the boot acts on it — quiesce and run the gate,
            // so a deadlock ends as a gate line with a diagnosis instead of `RUNEXIT=124`.
            if crate::WATCHDOG_TRIPPED.load(Ordering::Relaxed) != 0 {
                print_str(b"[deadman] tripped -> QUIESCE; run the gate\n");
                stop = m1;
                break;
            }
            let received = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
            badge = received.0;
            mi = received.1;
            m0 = received.2;
            m1 = received.3;
            m2 = received.4;
            m3 = received.5;
            continue;
        }
        if delay_queue.len() != 0 && delay_queue.has_badge_other_than(badge) {
            let progress = DELAY_OTHER_BADGE_PROGRESS.fetch_add(1, Ordering::Relaxed);
            if progress < 8 {
                print_str(b"[delay] unrelated badge progressed while waiter parked: badge=");
                print_u64(badge);
                print_str(b" queued=");
                print_u64(delay_queue.len() as u64);
                print_str(b"\n");
            }
        }
        // SAFETY: every allocation made past `heap_mark` belongs to the previous iteration's
        // syscall service and is dead now (its Vec/String were dropped at the loop-body's end).
        unsafe { allocator::reset_to(heap_mark) };
        iters += 1;
        // With the per-syscall heap reset above, smss now runs all the way through the ntdll
        // loader + Session Manager SmpInit — enumerating its real registry (NtOpenKey/
        // NtEnumerateValueKey/NtClose) — to a NATURAL stop: SmpInit fails at the missing \??
        // DosDevices object namespace and smss winds down into an unserviced syscall (stop_ssn),
        // ~290 iters, a few seconds. This ceiling is only a safety backstop against a future
        // genuine infinite loop; the run stops well before it. NOTE: with FOUR hosted processes
        // (smss/csrss/winlogon/services) multiplexing through this ONE service loop, the shared
        // budget now covers services' full DllMain/CRT bring-up too — raised 3000→5000 so services
        // reaches its real SCM entry (ScmMain) rather than starving at the old ceiling. Verified
        // each process still PROGRESSES (new SSNs / advancing demand-faults), not spinning.
        // BATCH 20: services.exe now SPAWNS (winlogon's CreateProcessInternalW no longer bails — the
        // relative-path fix) and runs its FULL ntdll loader — but it pulls in an ENORMOUS dependency
        // tree (57 modules: crypt32/dbghelp/libtiff/wintrust/…), each snapping+relocating hundreds of
        // pages via demand faults. Under TCG (~4 faults/s) fully loading services would take >2000s.
        // The gate-relevant work (winlogon → SwitchDesktop → paint + services SPAWNING + its loader
        // STARTING) is complete well before that. Cap at 5000 iters so the boot TERMINATES in-budget
        // and the specs (incl. exec_services_spawned) run; services' full SCM bring-up is the next
        // batch's frontier. Backstop only — each process still PROGRESSES (advancing faults), not
        // spinning (verified: cr2 sweeps the whole DLL space at the loader's snap RIP, never repeats).
        // BATCH 22: the demand-fault BATCH bulk-fill (fill a run of consecutive same-image pages per
        // fault-EP round-trip) + the scratch-VA decoupling cut the per-page round-trip cost ~3× (boot
        // 106s→~35s @5000 iters). With the per-process fault cost now bounded (FAULT_CAP + batching),
        // the iters backstop is lifted so lsass's full LSA-init DLL tree (lsasrv/samsrv/msv1_0 + deps)
        // can grind to LSA_RPC_SERVER_ACTIVE inside the 500s TCG budget → winlogon WaitForLsass wake →
        // InitializeSAS → SwitchDesktop → the 0x003a6ea5 paint. Still a runaway backstop, not the
        // functional terminus.
        if iters > 60000 {
            stop = m1;
            break;
        }
        // Select the hosted process this fault/syscall came from (0 = smss, CSRSS_BADGE = csrss) and
        // LOAD its state into the working locals. pml4/scratch_base/img_end/pe are immutable per
        // process (shadow the params); faults/first/ntfaults/filled_pages are mutable (SAVED back
        // before every recv below).
        // The N-threads-per-process multiplex: SVC_LISTENER_BADGE is services' (pi 3) RPC listener
        // thread — same VSpace/image/pml4 as services' main thread, but a DIFFERENT stack + TEB. It's
        // resolved to pi 3 here; the per-thread stack mirror is switched below (is_svc_listener).
        let is_svc_listener = badge == SVC_LISTENER_BADGE;
        // BATCH 35: services' SCM per-connection RPC worker (pi 3, its OWN stack mirror/TEB) — the
        // N-threads multiplex generalized to a DYNAMICALLY-spawned worker (not a pre-created pool
        // listener). It reads winlogon's bind PDU + writes bind_ack; resolved to pi 3 like the listener.
        let is_scm_worker = badge == SCM_WORKER_BADGE;
        let is_lsass_listener = badge == LSASS_LISTENER_BADGE;
        let is_lsass_listener2 = badge == LSASS_LISTENER2_BADGE;
        let is_lsass_listener3 = badge == LSASS_LISTENER3_BADGE;
        // lsass' `\pipe\lsarpc` PER-CONNECTION RPC worker (pi 4, its OWN stack mirror/TEB) — the
        // N-threads multiplex generalized to lsass' dynamically-spawned rpcrt4 io_thread. It reads the
        // LSA RPC bind PDU and answers `LsarOpenPolicy` for lsass' own self-RPC.
        let is_lsa_worker = badge == LSA_WORKER_BADGE;
        // Generic ntdll workers have one badge per process and role (slot 0: 16..20, slot 1: 21..25).
        // role orthogonal to the listener recognizers: it shares process state and mirrors, but not
        // RPC-listener-specific parking or quiesce policy.
        let tp_worker_identity = tp_worker_identity_from_badge(badge);
        let tp_worker_slot = tp_worker_identity.map(|(_, slot)| slot);
        let is_tp_worker = tp_worker_identity.is_some();
        // winlogon's rpcrt4 server WORKER thread (pi 2, its own stack mirror/TEB) — same N-threads
        // multiplex. It runs the wait array (NtWaitForMultipleObjects → parks) that the main thread's
        // signal_state_changed wakes, completing the rpcrt4 server-thread handshake.
        let is_wl_worker = matches!(
            badge,
            WINLOGON_WORKER_BADGE | WINLOGON_WORKER2_BADGE | WINLOGON_WORKER3_BADGE
        );
        if is_wl_worker {
            let n = WL_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(b"[wl-worker] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 2 rpcrt4 worker)\n");
            }
        }
        if is_svc_listener {
            let n = SVC_LISTENER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 4 {
                print_str(b"[svc-listener] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 3 listener)\n");
            }
        }
        if is_scm_worker {
            let n = SCM_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(b"[scm-worker] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 3 per-connection worker)\n");
            }
        }
        if is_lsa_worker {
            let n = LSA_WORKER_FAULTS.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(b"[lsa-worker] multiplex event #");
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 4 per-connection worker)\n");
            }
        }
        if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
            let ctr = if is_lsass_listener3 {
                &LSASS_LISTENER3_FAULTS
            } else if is_lsass_listener2 {
                &LSASS_LISTENER2_FAULTS
            } else {
                &LSASS_LISTENER_FAULTS
            };
            let n = ctr.fetch_add(1, Ordering::Relaxed);
            if n < 8 {
                print_str(if is_lsass_listener3 {
                    b"[lsass-listener3] multiplex event #"
                } else if is_lsass_listener2 {
                    b"[lsass-listener2] multiplex event #"
                } else {
                    b"[lsass-listener] multiplex event #"
                });
                print_u64(n);
                print_str(b" label=0x");
                print_hex((mi >> 12) as u32);
                print_str(b" m1=0x");
                print_hex(m1 as u32);
                print_str(b" (N-threads sub-select: pi 4 listener)\n");
            }
        }
        let pi = live_hosted_pi_for_fault_badge(&nt_handler, badge).unwrap_or(0);
        // This process is producing an event → it's running, not wait-parked. Clear its cooperative
        // wait bit so the all-parked quiesce test reflects reality (a woken waiter re-enters here).
        wait_parked &= !(1u64 << owner_top_badge_for(&nt_handler, badge));
        if hosted_main_badge_has_role(
            &nt_handler,
            badge,
            nt_exe_image::HostedProcessRole::InteractiveLogon,
        ) {
            WINLOGON_MAIN_EVENT_WAIT_PARKED.store(0, Ordering::Relaxed);
        }
        if PM_TERMINATE_THREAD_NO_REPLY.load(Ordering::Relaxed) != 0 && badge < 64 {
            PM_POST_TERM_CONTINUED_BADGES.fetch_or(1u64 << badge, Ordering::Relaxed);
        }
        // LOUD overflow guard: `pi` indexes the fixed-size per-process arrays (procs / pfilled /
        // dll_pd_created / dll_pt_bits, all sized to MAX_PI). A future 6th/7th hosted process
        // adds a badge→pi arm above; if one ever exceeds MAX_PI this panics with a clear message
        // (the panic handler prints file:line) instead of silently corrupting an adjacent array /
        // spinning. Bump MAX_PI (a scalar .bss cost) to admit more processes.
        assert!(
            pi < MAX_PI,
            "hosted process pi exceeds MAX_PI — bump MAX_PI"
        );
        // Resolve this fault badge to its real EPROCESS via the handler-owned ProcessManager lookup.
        // Read-only (no alloc under the reset), it proves the live badge-multiplex is backed by real
        // nt-process objects. The per-pi arrays below still carry the load-bearing mechanism state;
        // the bulk migrates that onto the EPROCESS next (see the convergence report).
        if let Some(pid) = nt_handler.pm_pid_for_pi(pi) {
            if nt_handler.pm.process(pid).is_some() {
                PM_BADGE_LOOKUPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Route the shared stack helpers (smss_stack_read/write) to THIS process's stack mirror, so
        // its syscall out-params (e.g. NtAllocateVirtualMemory's base for RtlCreateHeap) land on its
        // own stack, not the other process's.
        let (active_stack_base, active_stack_frames) = if let Some(slot) = tp_worker_slot {
            (tp_worker_stack_base(slot), TP_WORKER_STACK_FRAMES)
        } else if is_svc_listener {
            (SVC_LISTENER_STACK_BASE, SVC_LISTENER_STACK_FRAMES)
        } else if is_scm_worker {
            (SCM_WORKER_STACK_BASE, SCM_WORKER_STACK_FRAMES)
        } else if is_lsass_listener {
            (LSASS_LISTENER_STACK_BASE, LSASS_LISTENER_STACK_FRAMES)
        } else if is_lsass_listener2 {
            (LSASS_LISTENER2_STACK_BASE, LSASS_LISTENER2_STACK_FRAMES)
        } else if is_lsass_listener3 {
            (LSASS_LISTENER3_STACK_BASE, LSASS_LISTENER3_STACK_FRAMES)
        } else if is_lsa_worker {
            (LSA_WORKER_STACK_BASE, LSA_WORKER_STACK_FRAMES)
        } else if is_wl_worker {
            match badge {
                WINLOGON_WORKER2_BADGE => (WL_WORKER2_STACK_BASE, WL_WORKER2_STACK_FRAMES),
                WINLOGON_WORKER3_BADGE => (WL_WORKER3_STACK_BASE, WL_WORKER3_STACK_FRAMES),
                _ => (WL_LISTENER_STACK_BASE, WL_LISTENER_STACK_FRAMES),
            }
        } else {
            (STACK_BASE, STACK_FRAMES)
        };
        ACTIVE_STACK_BASE.store(active_stack_base, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(active_stack_frames * 0x1000, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(
            if let Some((tp_pi, tp_slot)) = tp_worker_identity {
                tp_worker_stack_mirror_va(tp_pi, tp_slot)
            } else if is_svc_listener {
                // Per-thread sub-selection: the listener's OWN stack mirror (its syscall out-params /
                // stack-arg reads land on its own stack, not services' main-thread stack).
                SVC_LISTENER_STACK_MIRROR_VA
            } else if is_scm_worker {
                // BATCH 35: the SCM worker's OWN stack mirror (its bind-PDU read buffer / out-params).
                SCM_WORKER_STACK_MIRROR_VA
            } else if is_lsass_listener {
                // Per-thread sub-selection: lsass' LSA server thread's OWN stack mirror (distinct from
                // lsass' main-thread stack).
                LSASS_LISTENER_STACK_MIRROR_VA
            } else if is_lsass_listener2 {
                LSASS_LISTENER2_STACK_MIRROR_VA
            } else if is_lsass_listener3 {
                LSASS_LISTENER3_STACK_MIRROR_VA
            } else if is_lsa_worker {
                // The LSA per-connection worker's OWN mirror (its RPC-PDU read buffers / out-params).
                LSA_WORKER_STACK_MIRROR_VA
            } else if is_wl_worker {
                match badge {
                    WINLOGON_WORKER2_BADGE => WINLOGON_WORKER2_STACK_MIRROR_VA,
                    WINLOGON_WORKER3_BADGE => WINLOGON_WORKER3_STACK_MIRROR_VA,
                    _ => WINLOGON_WORKER_STACK_MIRROR_VA,
                }
            } else {
                hosted_main_stack_mirror_for_pi(pi)
            },
            Ordering::Relaxed,
        );
        ACTIVE_IMAGE_MIRROR.store(hosted_active_image_mirror_for_pi(pi), Ordering::Relaxed);
        ACTIVE_HEAP_MIRROR.store(hosted_heap_mirror_for_pi(pi), Ordering::Relaxed);
        let pml4 = procs[pi].pml4;
        let scratch_base = procs[pi].scratch_base;
        ACTIVE_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
        ACTIVE_SCRATCH_BASE.store(scratch_base, Ordering::Relaxed);
        let img_end = procs[pi].img_end;
        let pe: &nt_pe_loader::PeFile = if pi == 0 {
            pe
        } else {
            unsafe { hosted_loaded_images.pe_by_pi(pi) }
                .expect("faulting hosted process must have a registered loaded executable PE")
        };
        faults = procs[pi].faults;
        first = procs[pi].first;
        ntfaults = procs[pi].ntfaults;
        *filled_pages = pfilled[pi];
        if pi == 2 {
            let watch = KERNEL32_TABLE_WATCH_SCRATCH.load(Ordering::Relaxed);
            if watch != 0 {
                // BaseHeapHandleTable+8 is zero after the kernel32 BSS page is materialized. The
                // value below is the first eight bytes of the msgina dialog-resource signature
                // observed in the corrupt page. Catch the first client event after it changes.
                let value = core::ptr::read_volatile((watch + 0x648) as *const u64);
                if value == 0x0039_003c_5081_0080
                    && KERNEL32_TABLE_WATCH_CORRUPT.swap(1, Ordering::Relaxed) == 0
                {
                    print_str(b"[alias-corrupt] badge=");
                    print_u64(badge);
                    print_str(b" label=0x");
                    print_hex((mi >> 12) as u32);
                    print_str(b" m0=0x");
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" m1=0x");
                    print_hex((m1 >> 32) as u32);
                    print_hex(m1 as u32);
                    print_str(b" faults=");
                    print_u64(faults);
                    print_str(b" scratch=0x");
                    print_hex((watch >> 32) as u32);
                    print_hex(watch as u32);
                    print_str(b"\n");
                }
            }
        }
        // A CPU exception (label 3). The DEBUG ntdll emits `int 0x2d` (DebugService/DPRINT),
        // which #GPs with no kernel debugger; emulate it as a no-op by skipping past the
        // `int 0x2d; int3` pair (echo the registers, advance the fault IP by 3, restart).
        if (mi >> 12) == 3 {
            // UserException delivery: m0=FaultIP, m1=SP, m2=FLAGS, m3=Number, mr4=Code. The
            // reply sets IP/SP/FLAGS (length 3); the general registers are preserved.
            let fip = m0;
            let mut skipped = false;
            if let Some((nb, npe)) = ntdll {
                if fip >= nb && fip < nb + image_extent(npe) {
                    if pe_byte_at_rva(npe, (fip - nb) as u32) == Some(0xCD) {
                        // Skip `int 0x2d; int3` (3 bytes) — the no-op DebugService.
                        procs[pi].faults = faults;
                        procs[pi].first = first;
                        procs[pi].ntfaults = ntfaults;
                        pfilled[pi] = *filled_pages;
                        let (nb, nmi, nm0, nm1, nm2, nm3) =
                            reply_recv_badge(fault_ep, 3, fip + 3, m1, m2, 0);
                        badge = nb;
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        skipped = true;
                        dbgsvc += 1;
                    }
                }
            }
            if skipped {
                continue;
            }
            // DbgkForwardException: a debugged process's debugger sees the trap first (m3 is the
            // delivered exception NUMBER — the x86 vector — which maps to the NTSTATUS
            // `KiDispatchException` would report). No-op when nothing debugs this process.
            if dbgk_forward_exception!(
                pi,
                nt_process::dbgk::ExceptionRecord::new(
                    nt_process::dbgk::exception_code_for_trap(m3 as u32),
                    fip,
                )
            ) && dbgk_block_and_park!(
                pi,
                nt_process::dbgk::DBGK_BLOCK_USER_EXCEPTION,
                fip,
                m1,
                m2
            ) {
                // The faulting thread is BLOCKED on the debugger's continue; its reply capability is
                // held by the DEBUG_EVENT. The next event has already been received.
                continue;
            }
            // ★ POST-LOGON CPU-EXCEPTION DIAGNOSTIC (bounded to the first 4). A label-3 fault
            // reports only IP/SP/FLAGS/vector/code, which is not enough to tell a bad POINTER from a
            // bad TARGET. Recover the faulting thread's GPRs, the stack's return-address chain and —
            // when the fault IP is inside our `RtlEnterCriticalSection` — the 40-byte
            // `RTL_CRITICAL_SECTION` the caller handed us, so the wall is MEASURED, not attributed.
            if hosted_pi_has_role(
                &nt_handler,
                pi,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            ) && hosted_owner_has_role(
                &nt_handler,
                badge,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            ) && crate::WL_CPUEXC_DIAG_N.fetch_add(1, Ordering::Relaxed) < 4
            {
                let tcb = if hosted_main_badge_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) {
                    nt_handler.hosted_main_thread_tcb_for_pi(pi).unwrap_or(0)
                } else {
                    0
                };
                let mut regs = [0u64; 20];
                if tcb != 0 {
                    crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
                }
                let (rip, rsp, rax, rcx, rdx) = (regs[0], regs[1], regs[3], regs[5], regs[6]);
                let ntdll_base = ntdll.map(|(nb, _)| nb).unwrap_or(0);
                print_str(b"[cs-diag] label=3 exc#=");
                print_u64(m3);
                print_str(b" code=0x");
                print_hex(get_recv_mr(4) as u32);
                print_str(b" fip=n+0x");
                print_hex(fip.wrapping_sub(ntdll_base) as u32);
                print_str(b" rip=n+0x");
                print_hex(rip.wrapping_sub(ntdll_base) as u32);
                print_str(b" rsp=0x");
                print_hex((rsp >> 32) as u32);
                print_hex(rsp as u32);
                print_str(b" rax=0x");
                print_hex((rax >> 32) as u32);
                print_hex(rax as u32);
                print_str(b" rcx=0x");
                print_hex((rcx >> 32) as u32);
                print_hex(rcx as u32);
                print_str(b" rdx=0x");
                print_hex((rdx >> 32) as u32);
                print_hex(rdx as u32);
                // Canonical-address test: a #GP(0) on a memory operand in long mode is what a
                // NON-canonical effective address produces (a merely unmapped/RO page is a #PF).
                let canonical = {
                    let top = rcx >> 47;
                    top == 0 || top == 0x1FFFF
                };
                print_str(b" rcx-canonical=");
                print_u64(canonical as u64);
                print_str(b"\n");
                let stk_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
                let stk_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
                let stk_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
                let read_wl = |va: u64| -> Option<u64> {
                    unsafe {
                        if va >= stk_base && va + 8 <= stk_base + stk_size {
                            return Some(core::ptr::read_volatile(
                                (stk_mirror + (va - stk_base)) as *const u64,
                            ));
                        }
                        img_spawn::client_read_u64_mapped(
                            pi as u64,
                            va,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                    }
                };
                // The RTL_CRITICAL_SECTION itself: DebugInfo/LockCount/RecursionCount/OwningThread/
                // LockSemaphore/SpinCount at +0x00/08/0c/10/18/20.
                if canonical {
                    print_str(b"[cs-diag] CS@0x");
                    print_hex((rcx >> 32) as u32);
                    print_hex(rcx as u32);
                    let mut ok = true;
                    for off in (0..0x28u64).step_by(8) {
                        match read_wl(rcx + off) {
                            Some(v) => {
                                print_str(b" +0x");
                                print_u64(off);
                                print_str(b"=0x");
                                print_hex((v >> 32) as u32);
                                print_hex(v as u32);
                            }
                            None => {
                                ok = false;
                                break;
                            }
                        }
                    }
                    if !ok {
                        print_str(b" <unreadable: not backed by any mapped frame>");
                    }
                    print_str(b"\n");
                }
                // The live TEB tail through the executive's persistent alias: TEB+0x1698 is
                // `ReservedForNtRpc`, rpcrt4's per-thread `threaddata` cache.
                if crate::TEB_TAIL_ALIAS_LIVE.load(Ordering::Relaxed) & (1u64 << 2) != 0 {
                    print_str(b"[cs-diag] live TEB+0x1680..0x16b0:");
                    let mut off = 0u64;
                    while off < 0x30 {
                        print_str(b" ");
                        print_hex(
                            (core::ptr::read_volatile(
                                (crate::WINLOGON_MAIN_TEB_MIRROR_VA + 0x5000 + 0x680 + off)
                                    as *const u64,
                            ) >> 32) as u32,
                        );
                        print_hex(core::ptr::read_volatile(
                            (crate::WINLOGON_MAIN_TEB_MIRROR_VA + 0x5000 + 0x680 + off)
                                as *const u64,
                        ) as u32);
                        off += 8;
                    }
                    print_str(b"\n");
                }
                // The return-address chain. RtlEnterCriticalSection's frame is push/push/sub 0x28,
                // so its own return address sits at SP+0x38 at the faulting instruction.
                print_str(b"[cs-diag] ret@sp+0x38=0x");
                match read_wl(rsp + 0x38) {
                    Some(v) => {
                        print_hex((v >> 32) as u32);
                        print_hex(v as u32);
                        if ntdll_base != 0 && v >= ntdll_base {
                            print_str(b" (n+0x");
                            print_hex(v.wrapping_sub(ntdll_base) as u32);
                            print_str(b")");
                        }
                    }
                    None => print_str(b"?"),
                }
                print_str(b" callers:");
                let mut shown = 0;
                for i in 0..96u64 {
                    if let Some(v) = read_wl(rsp + i * 8) {
                        if let Some((nb, npe)) = ntdll {
                            if v >= nb && v < nb + image_extent(npe) {
                                print_str(b" n+0x");
                                print_hex((v - nb) as u32);
                                shown += 1;
                            }
                        }
                        if v >= 0x8000_0000 && v < 0x8080_0000 {
                            print_str(b" d+0x");
                            print_hex(v as u32);
                            shown += 1;
                        }
                        if shown >= 24 {
                            break;
                        }
                    }
                }
                print_str(b"\n");
            }
            // ★ WINLOGON POST-LOGON MILESTONE PARK — the same rule the #PF arm applies, and for the
            // same reason. Once the interactive logon has really completed, a fault on winlogon's
            // post-logon path is a FRONTIER, not a crash: `park_and_log!` would latch the whole
            // process as a dead win32k callback client, which disarms the post-quiesce callback
            // injections (`exec_user_callback_dead_client_unwind` /
            // `exec_win32k_transport_call_nested`) even though winlogon's other threads are alive and
            // hold no callback frames. Batch 59 measured exactly that: with `CopyDirectory` really
            // running, winlogon reaches kernel32's `ASSERT(StaticUnicodeString.MaximumLength == …)`
            // in `fileutils.c:26`, whose `int 3` lands HERE.
            if hosted_pi_has_role(
                &nt_handler,
                pi,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            ) && hosted_owner_has_role(
                &nt_handler,
                badge,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            ) && WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0
                && !win32k_glue::client_has_active_callback_frames(pi as u32)
            {
                print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON; its POST-LOGON path raises an unhandled CPU exception at ip=0x");
                print_hex((fip >> 32) as u32);
                print_hex(fip as u32);
                print_str(b" -> MILESTONE park (holds no win32k callback frame; boot continues)\n");
                crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                procs[pi].faults = faults;
                procs[pi].first = first;
                procs[pi].ntfaults = ntfaults;
                pfilled[pi] = *filled_pages;
                WINLOGON_POST_LOGON_MILESTONE_PARK.store(fip, Ordering::Relaxed);
                WINLOGON_POST_LOGON_MILESTONE_CR2.store(fip, Ordering::Relaxed);
                if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0
                    || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                {
                    print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                    stop = fip;
                    break;
                }
                let (nb, nmi, nm0, nm1, nm2, nm3) =
                    recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // Unhandled CPU exception (label 3) at a non-skippable site — a real crash. Park+log.
            park_and_log!(pi, b"cpu-exception(3)", fip, fip);
        }
        // DebugException (label 4 = int3 / #BP). OUR ntdll's `RtlRaiseException` / `RtlRaiseStatus`
        // seams issue int3. Decode WHAT exception the caller is raising: recover winlogon's full GPRs
        // (RCX = PEXCEPTION_RECORD arg, RSP), read the EXCEPTION_RECORD from its demand-faulted memory,
        // and walk the stack for the raise site. m1 = fault_ip for a DebugException fault.
        if (mi >> 12) == 4 {
            let bp_ip = m1;
            let tcb = nt_handler.hosted_main_thread_tcb_for_pi(pi).unwrap_or(0);
            if tcb != 0 && ntdll.is_some() {
                let mut regs = [0u64; 20];
                crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
                let rip = regs[0];
                let rcx = regs[5];
                let rsp = regs[1];
                let raise_rva = if let Some((nb, _)) = ntdll {
                    rip.wrapping_sub(nb)
                } else {
                    rip
                };
                print_str(b"[bp-diag] int3 rva=0x");
                print_hex(raise_rva as u32);
                print_str(b" rcx(record*)=0x");
                print_hex((rcx >> 32) as u32);
                print_hex(rcx as u32);
                print_str(b" rsp=0x");
                print_hex((rsp >> 32) as u32);
                print_hex(rsp as u32);
                print_str(b"\n");
                // Read the EXCEPTION_RECORD (first 0x30 bytes) from winlogon's memory. The record lives
                // on the raiser's stack → read via the stack mirror (`smss_stack_read`), falling back to
                // the demand-faulted-page scratch alias for a non-stack record ptr.
                let stk_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
                let stk_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
                let stk_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
                let read_wl = |va: u64| -> Option<u64> {
                    unsafe {
                        if va >= stk_base && va + 8 <= stk_base + stk_size {
                            return Some(core::ptr::read_volatile(
                                (stk_mirror + (va - stk_base)) as *const u64,
                            ));
                        }
                        scratch_for(va, filled_pages, faults as usize, scratch_base)
                            .map(|m| core::ptr::read_volatile(m as *const u64))
                    }
                };
                let mut rec = [0u8; 0x30];
                let mut got = true;
                for off in (0..0x30u64).step_by(8) {
                    if let Some(v) = read_wl(rcx + off) {
                        rec[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
                    } else {
                        got = false;
                        break;
                    }
                }
                if got {
                    let code = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
                    let flags = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
                    let addr = u64::from_le_bytes([
                        rec[16], rec[17], rec[18], rec[19], rec[20], rec[21], rec[22], rec[23],
                    ]);
                    // NumberParameters @ +0x18 (byte 24); ExceptionInformation[] @ +0x20 (byte 32).
                    let nparm = u32::from_le_bytes([rec[24], rec[25], rec[26], rec[27]]);
                    let info0 = u64::from_le_bytes([
                        rec[32], rec[33], rec[34], rec[35], rec[36], rec[37], rec[38], rec[39],
                    ]);
                    let info1 = u64::from_le_bytes([
                        rec[40], rec[41], rec[42], rec[43], rec[44], rec[45], rec[46], rec[47],
                    ]);
                    print_str(b"[bp-diag] EXCEPTION_RECORD code=0x");
                    print_hex(code);
                    print_str(b" flags=0x");
                    print_hex(flags);
                    print_str(b" addr=0x");
                    print_hex((addr >> 32) as u32);
                    print_hex(addr as u32);
                    print_str(b" nparams=");
                    print_u64(nparm as u64);
                    print_str(b" info0=0x");
                    print_hex((info0 >> 32) as u32);
                    print_hex(info0 as u32);
                    print_str(b" info1=0x");
                    print_hex((info1 >> 32) as u32);
                    print_hex(info1 as u32);
                    print_str(b"\n");
                    // 0xC06D007E = VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND) — a VC++
                    // delay-load failure. ExceptionInformation[0] points at a DelayLoadInfo whose
                    // +0x08 (szDll, LPCSTR) names the missing DLL. Dump it.
                    if code == 0xC06D_007E && info0 != 0 {
                        // DelayLoadInfo: cb@0, pidd@0x08, ppfn@0x10, szDll(LPCSTR)@0x18.
                        if let Some(szdll) = read_wl(info0 + 0x18) {
                            print_str(b"[bp-diag] delayload szDll ptr=0x");
                            print_hex((szdll >> 32) as u32);
                            print_hex(szdll as u32);
                            print_str(b" name=\"");
                            // Read up to 40 ASCII bytes of the DLL name into a buffer.
                            let mut name = [0u8; 41];
                            let mut n = 0usize;
                            for j in 0..40u64 {
                                if let Some(w) = read_wl((szdll + j) & !7) {
                                    let b = ((w >> (8 * ((szdll + j) & 7))) & 0xff) as u8;
                                    if b == 0 {
                                        break;
                                    }
                                    name[n] = if b.is_ascii_graphic() || b == b' ' {
                                        b
                                    } else {
                                        b'?'
                                    };
                                    n += 1;
                                } else {
                                    break;
                                }
                            }
                            print_str(&name[..n]);
                            print_str(b"\"\n");
                        }
                    }
                } else {
                    print_str(b"[bp-diag] EXCEPTION_RECORD not in a faulted page (rcx unmapped)\n");
                }
                // Walk the caller's stack for return addresses in ntdll / DLLs to identify the raise
                // site (who called RtlRaiseException / RtlRaiseStatus).
                print_str(b"[bp-diag] callers:");
                let mut shown = 0;
                for i in 0..96u64 {
                    if let Some(v) = read_wl(rsp + i * 8) {
                        if let Some((nb, npe)) = ntdll {
                            if v >= nb && v < nb + image_extent(npe) {
                                print_str(b" n+0x");
                                print_hex((v - nb) as u32);
                                shown += 1;
                            }
                        }
                        if v >= 0x8000_0000 && v < 0x8080_0000 {
                            print_str(b" d+0x");
                            print_hex(v as u32);
                            shown += 1;
                        }
                        if shown >= 24 {
                            break;
                        }
                    }
                }
                print_str(b"\n");
            }
            // DbgkForwardException: an int3 is THE event a debugger exists for — it reports as
            // `DbgBreakpointStateChange` (`DbgUiRemoteBreakin`'s break-in lands here). No-op when
            // nothing debugs this process.
            if dbgk_forward_exception!(
                pi,
                nt_process::dbgk::ExceptionRecord::new(nt_process::dbgk::STATUS_BREAKPOINT, bp_ip)
            ) && dbgk_block_and_park!(
                pi,
                nt_process::dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                bp_ip,
                m2,
                m3
            ) {
                continue;
            }
            // Unhandled int3/#BP (a RtlRaiseException the loader/process can't recover) — a crash. Park+log.
            park_and_log!(pi, b"debug-exception(4)", bp_ip, bp_ip);
        }
        if (mi >> 12) == 6 {
            let addr = m1;
            if faults == 0 {
                first = addr;
            }
            let page = addr & !0xFFFu64;
            // ★ CLIENT-SIDE TEB-TAIL WRITE WATCH — a WRITE fault on winlogon's own (present,
            // read-only) second TEB page. This is the measurement that names the code corrupting
            // `StaticUnicodeString`: win32k is exonerated (it is never handed this page, and the
            // good→bad transition never straddles a dispatch), so the writer runs in the client.
            if crate::WL_TEB_TAIL_WRITE_WATCH
                && hosted_pi_has_role(
                    &nt_handler,
                    pi,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                )
                && page == SMSS_TEB_VA + 0x1000
                && (m3 & 0x2) != 0
                && crate::WL_TEB2_PROTECTED.load(Ordering::Relaxed) != 0
            {
                let tcb = if hosted_owner_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && hosted_main_badge_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) {
                    nt_handler.hosted_main_thread_tcb_for_pi(pi).unwrap_or(0)
                } else {
                    0
                };
                crate::wl_teb2_report_write(m0, addr, tcb);
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            if pi == 2
                && (m3 & 0x7) == 0x7
                && WINLOGON_HANDLE_FAULT_DIAG_N.fetch_add(1, Ordering::Relaxed) == 0
            {
                const KERNEL32_BASE_HEAP_HANDLE_TABLE: u64 = 0x8045_1640;
                let mut table = [0u8; 0x30];
                let table_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    KERNEL32_BASE_HEAP_HANDLE_TABLE,
                    &mut table,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b"[handle-fault] table-ok=");
                print_u64(table_ok as u64);
                if table_ok {
                    for off in (0..table.len()).step_by(8) {
                        let value = u64::from_le_bytes(table[off..off + 8].try_into().unwrap());
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                const KERNEL32_RTL_ALLOCATE_HANDLE_IAT: u64 = 0x8041_74a8;
                let mut iat = [0u8; 8];
                let iat_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    KERNEL32_RTL_ALLOCATE_HANDLE_IAT,
                    &mut iat,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" iat-ok=");
                print_u64(iat_ok as u64);
                if iat_ok {
                    let target = u64::from_le_bytes(iat);
                    print_str(b" iat=0x");
                    print_hex((target >> 32) as u32);
                    print_hex(target as u32);
                }
                for (name, (frame, index)) in [
                    (b" table".as_slice(), csrss_frame_get_exact(2, 0x8045_1000)),
                    (b" msgina".as_slice(), csrss_frame_get_exact(2, 0x8230_e000)),
                    (
                        b" entry".as_slice(),
                        csrss_frame_get_exact(2, 0x0000_0100_0057_9000),
                    ),
                ] {
                    print_str(name);
                    print_str(b"-cap=0x");
                    print_hex(frame as u32);
                    print_str(b"-pa=0x");
                    let paddr = if frame != 0 {
                        get_frame_paddr(frame)
                    } else {
                        0
                    };
                    print_hex((paddr >> 32) as u32);
                    print_hex(paddr as u32);
                    print_str(b"-idx=");
                    print_u64(if index == usize::MAX {
                        u64::MAX
                    } else {
                        index as u64
                    });
                }
                print_str(b" frame-n=");
                print_u64(core::ptr::read(core::ptr::addr_of!(CSRSS_FRAME_N)) as u64);
                let (heap_frame, heap_index) = csrss_frame_get_exact(2, NTDLL_BASE + 0x99_000);
                print_str(b" heap-cap=0x");
                print_hex(heap_frame as u32);
                print_str(b"-pa=0x");
                let heap_pa = if heap_frame != 0 {
                    get_frame_paddr(heap_frame)
                } else {
                    0
                };
                print_hex((heap_pa >> 32) as u32);
                print_hex(heap_pa as u32);
                print_str(b"-idx=");
                print_u64(if heap_index == usize::MAX {
                    u64::MAX
                } else {
                    heap_index as u64
                });
                let mut heap_state = [0u8; 0x30];
                let heap_ok = img_spawn::client_copyin_mapped(
                    2,
                    NTDLL_BASE + 0x99_000,
                    &mut heap_state,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" heap-ok=");
                print_u64(heap_ok as u64);
                if heap_ok {
                    for off in (0..heap_state.len()).step_by(8) {
                        let value =
                            u64::from_le_bytes(heap_state[off..off + 8].try_into().unwrap());
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                let callback_frame = (win32k_subsystem::WIN32K_SHARED_VADDR
                    + win32k_subsystem::SH_USER_CALLBACK)
                    as *const nt_user_callback::CallbackFrame;
                let callback_proc = core::ptr::read_volatile(core::ptr::addr_of!(
                    (*callback_frame).payload[0]
                ) as *const u64);
                print_str(b" callback-proc=0x");
                print_hex((callback_proc >> 32) as u32);
                print_hex(callback_proc as u32);
                let entry_va = addr.saturating_sub(8);
                let mut entry = [0u8; 0x20];
                let entry_ok = img_spawn::client_copyin_mapped(
                    pi as u64,
                    entry_va,
                    &mut entry,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                );
                print_str(b" entry=0x");
                print_hex((entry_va >> 32) as u32);
                print_hex(entry_va as u32);
                print_str(b" entry-ok=");
                print_u64(entry_ok as u64);
                if entry_ok {
                    for off in (0..entry.len()).step_by(8) {
                        let value = u64::from_le_bytes(entry[off..off + 8].try_into().unwrap());
                        print_str(b" +");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                let tcb = tp_worker_identity
                    .and_then(|(tp_pi, tp_slot)| nt_handler.hosted_tp_worker_tcb(tp_pi, tp_slot))
                    .or_else(|| nt_handler.hosted_main_thread_tcb_for_pi(pi))
                    .unwrap_or(0);
                if tcb != 0 {
                    let mut regs = [0u64; 20];
                    win32k_glue::tcb_read_regs20(tcb, &mut regs);
                    print_str(b" rip=0x");
                    print_hex((regs[0] >> 32) as u32);
                    print_hex(regs[0] as u32);
                    print_str(b" rsp=0x");
                    print_hex((regs[1] >> 32) as u32);
                    print_hex(regs[1] as u32);
                    print_str(b" rcx=0x");
                    print_hex((regs[5] >> 32) as u32);
                    print_hex(regs[5] as u32);
                    for off in (0..=0x80u64).step_by(8) {
                        let value = smss_stack_read(regs[1] + off);
                        print_str(b" sp+");
                        print_hex(off as u32);
                        print_str(b"=0x");
                        print_hex((value >> 32) as u32);
                        print_hex(value as u32);
                    }
                }
                print_str(b"\n");
            }
            // ROBUSTNESS (gate-safety): a genuine NULL/low deref (addr < 64 KiB) is never a
            // demand-fillable region (image/DLL/scratch/stack/anon all live far above) — it's an
            // unrecoverable client fault (e.g. user32's UserClientDllInitialize deref of a still-null
            // gSharedInfo). Map it and we hand the faulter a zero page → it silently spins on the bad
            // value and the loop never makes progress (deterministic hang). So STOP the loop cleanly
            // with a diagnostic instead — exactly like the win32k `[vmf-out]` stop path.
            if addr < 0x10000 {
                let tcb = tp_worker_identity
                    .and_then(|(tp_pi, tp_slot)| nt_handler.hosted_tp_worker_tcb(tp_pi, tp_slot))
                    .or_else(|| nt_handler.hosted_main_thread_tcb_for_pi(pi))
                    .unwrap_or(0);
                if tcb != 0 {
                    let mut regs = [0u64; 20];
                    win32k_glue::tcb_read_regs20(tcb, &mut regs);
                    print_str(b"[vmf-low] rcx=0x");
                    print_hex((regs[5] >> 32) as u32);
                    print_hex(regs[5] as u32);
                    print_str(b" rsi=0x");
                    print_hex((regs[7] >> 32) as u32);
                    print_hex(regs[7] as u32);
                    print_str(b" rdi=0x");
                    print_hex((regs[8] >> 32) as u32);
                    print_hex(regs[8] as u32);
                    print_str(b" rsp=0x");
                    print_hex((regs[1] >> 32) as u32);
                    print_hex(regs[1] as u32);
                    print_str(b" ret=0x");
                    let ret = smss_stack_read(regs[1] + 0x10);
                    print_hex((ret >> 32) as u32);
                    print_hex(ret as u32);
                    print_str(b"\n");
                }
                // user32 GetThreadDesktopWnd (RVA 0x50009) dereferences
                // `GetThreadDesktopInfo()->spwnd`. IntSetThreadDesktop can clear the client fields
                // while the hosted per-thread desktop-heap view is being established. Repair the
                // exact fault in the TEB that owns it (main or one of winlogon's worker TEBs), then
                // retry the instruction. This must precede the generic worker-wall park below.
                if pi == 2 && m0 == 0x801a_0009 && addr == 0x10 {
                    let teb_alias = if let Some((2, tp_slot)) = tp_worker_identity {
                        tp_worker_stack_mirror_va(2, tp_slot) + TP_WORKER_STACK_FRAMES * 0x1000
                    } else if is_wl_worker {
                        match badge {
                            WINLOGON_WORKER2_BADGE => {
                                WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000
                            }
                            WINLOGON_WORKER3_BADGE => {
                                WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000
                            }
                            _ => {
                                WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000
                            }
                        }
                    } else {
                        0x0000_0100_107C_0000
                    };
                    let tcb = match badge {
                        _ if tp_worker_identity.is_some() => {
                            let (tp_pi, tp_slot) = tp_worker_identity.unwrap();
                            nt_handler.hosted_tp_worker_tcb(tp_pi, tp_slot).unwrap_or(0)
                        }
                        WINLOGON_WORKER_BADGE => nt_handler
                            .hosted_thread_tcb_for_role(2, HostedThreadRole::WinlogonListener)
                            .unwrap_or(0),
                        WINLOGON_WORKER2_BADGE => nt_handler
                            .hosted_thread_tcb_for_role(
                                2,
                                HostedThreadRole::WinlogonWorker { slot: 1 },
                            )
                            .unwrap_or(0),
                        WINLOGON_WORKER3_BADGE => nt_handler
                            .hosted_thread_tcb_for_role(
                                2,
                                HostedThreadRole::WinlogonWorker { slot: 2 },
                            )
                            .unwrap_or(0),
                        _ => nt_handler.hosted_main_thread_tcb_for_pi(2).unwrap_or(0),
                    };
                    if let Some((client_deskinfo, pti, _)) =
                        seed_winlogon_thread_client_info(teb_alias, pml4)
                    {
                        // The faulting instruction already has RAX=NULL. Re-run the helper call at
                        // 0x801a0004 so it reloads the repaired TEB fields before dereferencing.
                        if tcb != 0 && win32k_glue::rewind_fault_ip(tcb, 0x801a_0004) {
                            print_str(b"[wl-deskinfo-fixup] badge=");
                            print_u64(badge);
                            print_str(b" real pti=0x");
                            print_hex((pti >> 32) as u32);
                            print_hex(pti as u32);
                            print_str(b" pDeskInfo=0x");
                            print_hex((client_deskinfo >> 32) as u32);
                            print_hex(client_deskinfo as u32);
                            print_str(b" -> rewind helper call; RESUME\n");
                            procs[pi].faults = faults;
                            procs[pi].first = first;
                            procs[pi].ntfaults = ntfaults;
                            pfilled[pi] = *filled_pages;
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                            badge = nb;
                            mi = nmi;
                            m0 = nm0;
                            m1 = nm1;
                            m2 = nm2;
                            m3 = nm3;
                            continue;
                        }
                    }
                    print_str(b"[wl-deskinfo-fixup] real client state unavailable; PARK worker\n");
                }
                if is_tp_worker {
                    print_str(b"[tp-worker] wall badge=");
                    print_u64(badge);
                    print_str(b" ip=0x");
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" addr=0x");
                    print_hex(addr as u32);
                    print_str(b" -> PARK generic worker; owner continues\n");
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // N-threads multiplex: the services RPC listener (badge 7) walls on its OWN
                // unrecoverable fault (rpcrt4 io_thread derefs a connection field that needs a real
                // client connect — the listener's next frontier). PARK it (don't reply → it stays
                // blocked, its ETHREAD/TEB stay mapped) and CONTINUE the loop so services' main thread
                // + winlogon keep advancing (winlogon → StartLsass). Contained per-thread, not a boot
                // stop — the whole point of the per-thread multiplex.
                if is_svc_listener
                    || is_scm_worker
                    || is_lsass_listener
                    || is_lsass_listener2
                    || is_lsass_listener3
                    || is_lsa_worker
                    || is_wl_worker
                {
                    print_str(if is_wl_worker {
                        b"[wl-worker] wall ip=0x"
                    } else if is_scm_worker {
                        b"[scm-worker] wall ip=0x"
                    } else if is_lsa_worker {
                        b"[lsa-worker] wall ip=0x"
                    } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
                        b"[lsass-listener] wall ip=0x"
                    } else {
                        b"[svc-listener] wall ip=0x"
                    });
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" addr=0x");
                    print_hex(addr as u32);
                    print_str(b" -> PARK thread (its own unrecoverable fault); boot continues\n");
                    if is_wl_worker && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[wl-worker] terminal wall while winlogon main waits for this worker -> run gate\n");
                        stop = m0;
                        break;
                    }
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    // Recv the next event WITHOUT replying to the listener (it stays blocked).
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                print_str(match pi {
                    1 => b"[csrss vmf] NULL/low deref ip=0x",
                    2 => b"[winlogon vmf] NULL/low deref ip=0x",
                    3 => b"[services vmf] NULL/low deref ip=0x",
                    4 => b"[lsass vmf] NULL/low deref ip=0x",
                    5 => b"[userinit vmf] NULL/low deref ip=0x",
                    _ => b"[smss vmf] NULL/low deref ip=0x",
                });
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" (dll_rva = ip - dll_base; user32@0x84000000, gdi32@0x85000000)\n");
                // DIAG (BATCH 7): dump the fault frame RSP + the caller return addresses so we can
                // identify who passed NULL (e.g. strlen(NULL) during msvcrt CRT init). At strlen+0x16
                // the frame is `sub rsp,0x18` deep so the return addr is at [rsp+0x18]; also dump a
                // small window of the stack to see the call chain.
                {
                    let sp = get_recv_mr(16);
                    print_str(b"[winlogon vmf] rsp=0x");
                    print_hex((sp >> 32) as u32);
                    print_hex(sp as u32);
                    print_str(b" retaddrs[");
                    // Scan up the stack for the first plausible RETURN ADDRESSES (msvcrt 0x806xxxxx,
                    // our ntdll 0x100_00xxxxxx, or another mapped DLL 0x80xxxxxx) so we see the caller
                    // chain that reached strlen(NULL).
                    let mut k: u64 = 0;
                    let mut printed: u64 = 0;
                    while k < 96 && printed < 10 {
                        let v = smss_stack_read(sp + k * 8);
                        let is_ntdll = v >= 0x0000_0100_0000_0000 && v < 0x0000_0100_0100_0000;
                        let is_dll = v >= 0x8000_0000 && v < 0x8100_0000;
                        if is_ntdll || is_dll {
                            print_str(b" +0x");
                            print_hex((k * 8) as u32);
                            print_str(b":0x");
                            print_hex((v >> 32) as u32);
                            print_hex(v as u32);
                            printed += 1;
                        }
                        k += 1;
                    }
                    print_str(b" ]\n");
                }
                // BATCH 39 — winlogon (pi 2) is the process the whole boot drives toward; once it has
                // crossed OpenSCManager (the SCM RPC round-trip) and reached its GUI/login init, the
                // remaining "live" top-level processes (services / lsass) are just the SCM + LSA RPC
                // SERVERS with no live client left. So when winlogon hits an unrecoverable crash AT its
                // GUI/login frontier (its next wall past OpenSCManager — currently msgina.dll's login
                // flow, RVA 0x95f8), with LSA already signalled (steady state), QUIESCE to the gate
                // instead of blocking the loop's recv forever (the servers can't advance without
                // winlogon). This makes the route-ON boot reach the gate cleanly (BATCH 38 flagged this
                // as the "break-on-winlogon-crash quiesce"). Mark winlogon crash-parked first so the
                // gate's crash state is honest.
                // DbgkForwardException: an unrecoverable page fault is `STATUS_ACCESS_VIOLATION`
                // with `MmAccessFault`'s two arguments — the access type (from the x86 page-fault
                // error code in m3: bit 1 = write, bit 4 = instruction fetch) and the faulting
                // address. Forwarded BEFORE either terminal branch below so a debugger sees the
                // crash whichever one this process takes. No-op when nothing debugs it.
                if dbgk_forward_exception!(
                    pi,
                    nt_process::dbgk::ExceptionRecord::access_violation(
                        m0,
                        if m3 & 0x10 != 0 {
                            8
                        } else if m3 & 0x2 != 0 {
                            1
                        } else {
                            0
                        },
                        addr,
                    )
                ) && dbgk_block_and_park!(pi, nt_process::dbgk::DBGK_BLOCK_VM_FAULT, m0, 0, 0)
                {
                    // BLOCKED on the debugger's continue; the next event is already received. A
                    // `DBG_CONTINUE` replies length-0 → the faulting instruction is RETRIED.
                    continue;
                }
                if pi == 2 && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0 {
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    print_str(b"[wl-main] winlogon crashed at its post-OpenSCManager GUI/login frontier (LSA signalled, SCM servers idle) -> QUIESCE; run gate\n");
                    stop = m0;
                    break;
                }
                // Unrecoverable NULL/low deref on a top-level process thread — a crash. Park+log
                // (the per-process detail above already printed; park_and_log adds the [parked] line).
                park_and_log!(pi, b"null-deref", m0, addr);
            }
            // Slot 0 returns from its fixed loader bootstrap stack into the reservation created by
            // kernel32!BaseCreateStack. Grow only the next contiguous page in that reservation and
            // advance the live TEB limit before retrying the fault.
            if badge == WINLOGON_WORKER_BADGE {
                let allocation_base = WL_LISTENER_STACK_ALLOCATION_BASE.load(Ordering::Acquire);
                let stack_base = WL_LISTENER_STACK_BASE_REAL.load(Ordering::Acquire);
                let mapped_low = WL_LISTENER_STACK_MAPPED_LOW.load(Ordering::Acquire);
                if m3 & 1 == 0
                    && page < stack_base
                    && csrss_frame_get_exact(2, page).0 == 0
                    && nt_thread_start::next_stack_growth_page(allocation_base, mapped_low, addr)
                        == Some(page)
                {
                    let (frame, retype_error) = alloc_frame_r();
                    let map_error = if retype_error == 0 {
                        page_map_r(frame, page, RW_NX, pml4)
                    } else {
                        retype_error
                    };
                    if retype_error == 0 && map_error == 0 {
                        csrss_frame_put(2, page, frame);
                        if csrss_frame_get_exact(2, page).0 == frame {
                            let teb_alias =
                                WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000;
                            core::ptr::write_volatile(
                                (teb_alias + 0x10) as *mut u64,
                                page + nt_thread_start::USER_PAGE_SIZE,
                            );
                            WL_LISTENER_STACK_MAPPED_LOW.store(page, Ordering::Release);
                            print_str(b"[wl-worker] grew real stack page=0x");
                            print_hex((page >> 32) as u32);
                            print_hex(page as u32);
                            print_str(b" allocation=0x");
                            print_hex((allocation_base >> 32) as u32);
                            print_hex(allocation_base as u32);
                            print_str(b"\n");
                            procs[pi].faults = faults;
                            procs[pi].first = first;
                            procs[pi].ntfaults = ntfaults;
                            pfilled[pi] = *filled_pages;
                            let (nb, nmi, nm0, nm1, nm2, nm3) =
                                reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                            badge = nb;
                            mi = nmi;
                            m0 = nm0;
                            m1 = nm1;
                            m2 = nm2;
                            m3 = nm3;
                            continue;
                        }
                    }
                    if frame != 0 {
                        let _ = cnode_delete_recycle_r(frame);
                    }
                    print_str(b"[wl-worker] real stack growth failed page=0x");
                    print_hex((page >> 32) as u32);
                    print_hex(page as u32);
                    print_str(b" retype=");
                    print_u64(retype_error);
                    print_str(b" map=");
                    print_u64(map_error);
                    print_str(b"\n");
                    park_and_log!(pi, b"wl-stack-growth", m0, addr);
                }
            }
            // Dynamic stack growth (Windows guard-page style): a fault just below the committed
            // stack commits a fresh zeroed page and restarts, so smss's stack grows on demand
            // instead of crashing at the 16 KiB initial commit. Bounded by STACK_GROWTH_FLOOR so it
            // never runs into the env mappings below.
            if page >= STACK_GROWTH_FLOOR && page < STACK_BASE {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                // Preserve the mapped frame cap so stack-based syscall arguments remain reachable
                // after the stack grows below its fixed executive mirror. GUI clients also reuse
                // this record for win32k's per-client attachment.
                csrss_frame_put(pi as u64, page, f);
                faults += 1;
                procs[pi].faults = faults;
                procs[pi].first = first;
                procs[pi].ntfaults = ntfaults;
                pfilled[pi] = *filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // csrss's anonymous section (CSR shared memory): commit a ZERO frame on touch.
            if pi == 1
                && csrss_anon_base != 0
                && page >= csrss_anon_base
                && page < csrss_anon_base + ((csrss_anon_size + 0xFFF) & !0xFFFu64)
            {
                let f = alloc_frame();
                let _ = page_map(f, page, RW_NX, pml4);
                csrss_frame_put(pi as u64, page, f); // CSR shared section (pi 1) — shareable into win32k
                faults += 1;
                procs[pi].faults = faults;
                procs[pi].first = first;
                procs[pi].ntfaults = ntfaults;
                pfilled[pi] = *filled_pages;
                let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
                badge = nb;
                mi = nmi;
                m0 = nm0;
                m1 = nm1;
                m2 = nm2;
                m3 = nm3;
                continue;
            }
            // Route to whichever image contains the faulting page.
            let (base, tpe) = if page >= PE_LOAD_BASE && page < img_end {
                (PE_LOAD_BASE, pe)
            } else if nt_base != 0 && page >= nt_base && page < nt_end {
                ntfaults += 1;
                (nt_base, ntdll.unwrap().1)
            } else if let Some((i, _)) = if pi >= 1 {
                reg.dll_for_page(page)
            } else {
                None
            } {
                // A mapped registry DLL (csrsrv/basesrv/winsrv/Win32 stack) in a DLL-loading
                // process's VSpace (csrss pi==1 OR winlogon pi==2) — demand-page it from that DLL's
                // parsed PE. csrsrv sits at its preferred ImageBase (no relocation); the others are
                // loader-relocated to their fixed bases. The registry resolves which one owns the page.
                (reg.base(i), dll_pes[i].as_ref().unwrap())
            } else {
                // DIAG: dump the fault so we can tell a stack-growth fault (addr just below the
                // stack) from a real null deref. m0=IP, m1=addr(cr2), m2=prefetch, m3=fsr.
                print_str(b"[vmf-out] ip=0x");
                print_hex((m0 >> 32) as u32);
                print_hex(m0 as u32);
                print_str(b" addr=0x");
                print_hex((addr >> 32) as u32);
                print_hex(addr as u32);
                print_str(b" pf=");
                print_u64(m2);
                print_str(b" fsr=");
                print_u64(m3);
                print_str(b" img_end=0x");
                print_hex((img_end >> 32) as u32);
                print_hex(img_end as u32);
                print_str(b" stack=[0x");
                print_hex(STACK_BASE as u32);
                print_str(b"..0x");
                print_hex((STACK_BASE + STACK_FRAMES * 0x1000) as u32);
                print_str(b")\n");
                // On an INSTRUCTION-FETCH fault (ip==addr, both a bare low RVA) execution CALLed/JMPed
                // through a bad/truncated code pointer. Read the faulting thread's real GPRs + walk its
                // stack (TCB rsp) for return addresses in any mapped module — this identifies the CALLER
                // (module + RVA) whose indirect transfer landed on the bare RVA. General class-of-wall
                // diagnostic (BATCH 24/25: lsass rpcrt4 `0x3a288`); applies to any process at quiescence.
                if m0 == addr && addr < 0x8000_0000 {
                    let tcb = nt_handler.hosted_main_thread_tcb_for_pi(pi).unwrap_or(0);
                    if tcb != 0 {
                        let mut regs = [0u64; 20];
                        crate::win32k_glue::tcb_read_regs20(tcb, &mut regs);
                        // seL4 x86_64 UserContext order: [0]rip [1]rsp [2]rflags [3]rax [4]rbx [5]rcx
                        // [6]rdx [7]rsi [8]rdi [9]rbp [10]r8..[17]r15.
                        print_str(b"[vmf-out] regs: rip=0x");
                        print_hex(regs[0] as u32);
                        print_str(b" rsp=0x");
                        print_hex((regs[1] >> 32) as u32);
                        print_hex(regs[1] as u32);
                        print_str(b" rax=0x");
                        print_hex((regs[3] >> 32) as u32);
                        print_hex(regs[3] as u32);
                        print_str(b" rcx=0x");
                        print_hex((regs[5] >> 32) as u32);
                        print_hex(regs[5] as u32);
                        print_str(b"\n");
                        // Walk the REAL stack (TCB rsp) for return addresses (ntdll 0x100_00xxxxxx / a
                        // mapped DLL 0x80xxxxxx). The nearest one identifies the faulting caller.
                        let rsp = regs[1];
                        // ★ TRUNC PROBE: [rsp] is the return address the CALLER pushed with its
                        // `call [mem]` that jumped to the bare RVA. Print [rsp+0..0x20] unconditionally
                        // so the immediate caller (module+RVA) is visible.
                        print_str(b"[trunc] top-of-stack:");
                        {
                            let mut j: u64 = 0;
                            while j < 4 {
                                let v = smss_stack_read(rsp + j * 8);
                                print_str(b" [rsp+0x");
                                print_hex((j * 8) as u32);
                                print_str(b"]=0x");
                                print_hex((v >> 32) as u32);
                                print_hex(v as u32);
                                j += 1;
                            }
                            print_str(b"\n");
                        }
                        print_str(b"[vmf-out] instr-fetch [rsp..]:");
                        let mut k: u64 = 0;
                        let mut printed: u64 = 0;
                        while k < 64 && printed < 12 {
                            let v = smss_stack_read(rsp + k * 8);
                            let is_ntdll = v >= 0x0000_0100_0000_0000 && v < 0x0000_0100_0100_0000;
                            // Widen to ALL mapped DLLs (0x8000_0000..0x8300_0000 covers rpcrt4/lsasrv/…)
                            // + lsass.exe/heap (0x100_0056_0000..0x100_00d0_0000) so the immediate
                            // rpcrt4/lsasrv caller + the heap dispatch object are captured.
                            let is_dll = v >= 0x8000_0000 && v < 0x8300_0000;
                            let is_lsass = v >= 0x0000_0100_0055_0000 && v < 0x0000_0100_00d0_0000;
                            if is_ntdll || is_dll || is_lsass {
                                print_str(b" +0x");
                                print_hex((k * 8) as u32);
                                print_str(b":0x");
                                print_hex((v >> 32) as u32);
                                print_hex(v as u32);
                                printed += 1;
                            }
                            k += 1;
                        }
                        print_str(b"\n");
                    }
                }
                // A client that faults while a win32k user-mode callback is in flight: dump the exact
                // client-side state user32 used to derive the PWND it dereferenced (see
                // `dump_client_callback_crash_state`). Callback-scoped, so it costs nothing on any
                // other wall.
                win32k_glue::dump_client_callback_crash_state(
                    pi,
                    nt_handler.hosted_main_thread_tcb_for_pi(pi).unwrap_or(0),
                );
                // ★ Checkpoint B containment: once lsass has signaled LSA_RPC_SERVER_ACTIVE (its
                // essential init is done), an unrecoverable fault on lsass' MAIN thread (badge 8) —
                // e.g. rpcrt4 NdrSimpleTypeUnmarshall dereferencing a bogus RPC request buffer
                // (cr2 ~0xe000002d6) while its RPC server services a self-directed call — is CONTAINED:
                // PARK that thread (recv the next event without replying, leaving it blocked) so the
                // boot advances to winlogon's WaitForLsass/login instead of stopping. Same philosophy
                // as the N-threads listener-park; scoped so it can't mask a pre-signal lsass fault or
                // any other process's fault.
                // DbgkForwardException (same shape as the null-deref site above): report the
                // unmapped-address access violation to a debugger BEFORE either terminal branch.
                if dbgk_forward_exception!(
                    pi,
                    nt_process::dbgk::ExceptionRecord::access_violation(
                        m0,
                        if m3 & 0x10 != 0 {
                            8
                        } else if m3 & 0x2 != 0 {
                            1
                        } else {
                            0
                        },
                        addr,
                    )
                ) && dbgk_block_and_park!(pi, nt_process::dbgk::DBGK_BLOCK_VM_FAULT, m0, 0, 0)
                {
                    // BLOCKED on the debugger's continue; the next event is already received. A
                    // `DBG_CONTINUE` replies length-0 → the faulting instruction is RETRIED.
                    continue;
                }
                if hosted_main_badge_has_leaf(&nt_handler, badge, b"lsass.exe")
                    && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                {
                    print_str(b"[wait] lsass main unrecoverable fault POST-LSA-signal -> PARK (boot continues)\n");
                    // Terminal for lsass main — count toward quiesce (lsass has done its signalling job).
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0 {
                        print_str(b"[quiesce] every live process parked/waiting (no signaler left) -> run gate\n");
                        stop = addr;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // ★ WINLOGON POST-LOGON MILESTONE PARK. winlogon's main thread has, by this point,
                // COMPLETED the interactive logon for real: `LsaLogonUser` returned SUCCESS, lsass
                // duplicated the `NtCreateToken` token into winlogon's handle table and winlogon
                // queried it (`WINLOGON_LOGON_TOKEN_QUERIES`). Its post-logon path (profile load →
                // `userinit.exe`) is the NEXT frontier and it faults there — measured: our own
                // ntdll's `RtlQueryInformationActivationContext` reads
                // `TEB.ActivationContextStackPointer->ActiveFrame` and finds a NON-POINTER value.
                //
                // Park at the achieved milestone instead of crash-parking. The difference is not
                // cosmetic: `park_and_log!` calls `unwind_dead_client_user_callbacks(pi)`, which
                // latches the WHOLE process as a dead win32k callback client — wrong here, because
                // this is ONE thread and winlogon's worker threads are alive, hold no callback
                // frames (asserted, not assumed) and are still valid callback clients. The faulting
                // thread is left blocked at its fault exactly as any other park leaves its thread.
                //
                // ★ ANY winlogon THREAD, not just badge 4. The post-logon profile/`userinit` work is
                // driven from whichever winlogon thread `WlxActivateUserShell` runs on, and once the
                // profile copy really advanced (batch 59) the fault landed on a WORKER badge — which
                // fell through to `park_and_log!` and latched the whole process as a dead win32k
                // callback client, disarming both post-quiesce callback injections. The guard that
                // makes this safe is the callback-frame assertion below, which is per-PROCESS, so it
                // holds for any of its threads.
                if hosted_pi_has_role(
                    &nt_handler,
                    pi,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && hosted_owner_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0
                    && !win32k_glue::client_has_active_callback_frames(pi as u32)
                {
                    print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON (LsaLogonUser SUCCESS + logon token received/queried); its POST-LOGON path faults at ip=0x");
                    print_hex((m0 >> 32) as u32);
                    print_hex(m0 as u32);
                    print_str(b" cr2=0x");
                    print_hex((addr >> 32) as u32);
                    print_hex(addr as u32);
                    print_str(
                        b" -> MILESTONE park (holds no win32k callback frame; boot continues)\n",
                    );
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    WINLOGON_POST_LOGON_MILESTONE_PARK.store(m0, Ordering::Relaxed);
                    WINLOGON_POST_LOGON_MILESTONE_CR2.store(addr, Ordering::Relaxed);
                    // Same terminal rule `park_and_log!` applies to a parked winlogon: once the LSA
                    // server has signalled, services/lsass are idle RPC servers with no live client
                    // left, so a parked winlogon leaves NO runnable signaler and the next `recv`
                    // would block forever (measured: RUNEXIT=124 without this clause).
                    if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0
                        || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                        stop = m0;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // Unrecoverable fault outside every mapped image/DLL/scratch/stack (a truncated code
                // pointer / bad address the diagnostics above symbolized) — a real crash. Park+log.
                // park_and_log! diverges (type `!`) so this arm yields no value — match type is satisfied.
                park_and_log!(pi, b"vmf-out", m0, addr)
            };
            // Per-process demand-fault backstop. With the BATCH-22 scratch-VA decoupling (persistent
            // scratch bounded to ≤256 slots regardless of this count) this is now purely a
            // frame-budget / runaway guard, not a scratch limit — raised so lsass's full LSA-init DLL
            // tree (lsasrv/samsrv/msv1_0 + deps, thousands of pages) fits.
            if faults >= SEC_IMAGE_FAULT_CAP {
                // This process exhausted its per-process demand-fault budget (runaway / frame-pool
                // guard) — treat as unrecoverable for THIS process: park+log, let the others proceed.
                park_and_log!(pi, b"fault-cap", m0, addr);
            }
            // ★ BATCH BULK-FILL (BATCH 22 perf fix): under QEMU TCG each demand fault is a full
            // fault-EP round-trip (~4/s), so a big DLL image page-by-page dominates the boot budget
            // (lsass' LSA-init DLL tree ran past the 500s timeout). Instead of filling ONLY the
            // faulting page, fill+map a forward RUN of consecutive same-image pages in this one
            // round-trip. Every extra page is filled EXACTLY as its own demand fault would (same
            // fill_image_page/rights/cache/mirror/filled_pages bookkeeping) — pure correctness
            // preservation — so when the process resumes it finds the next pages already present and
            // does NOT re-fault them. This cuts the per-process round-trip count by ~BATCH×.
            //
            // The `end` bound is the containing image's extent (main image → img_end; a registered
            // DLL → base + image_size; ntdll → nt_end). Extra pages are only PRE-filled when they are
            // genuinely unmapped in THIS process — a per-process page not yet in `filled_pages`, and a
            // shared-text page not yet in the global `dll_cache` — so we never double-map. The
            // FAULTING page (batch index 0) keeps the full original logic incl. the shared-cache HIT
            // path; extra pages take the fresh-fill path (a shared page already cached is left to a
            // normal later fault — correct, just unbatched).
            let img_hi = if base == PE_LOAD_BASE {
                img_end
            } else if base == nt_base {
                nt_end
            } else if let Some((di, _)) = reg.dll_for_page(page) {
                reg.base(di) + reg.get(di).map(|d| d.image_size).unwrap_or(0)
            } else {
                base
            };
            // Prefetch a bounded forward window from the page the process actually touched. Whole-image
            // eager mapping made every untouched section resident and retained one root-CNode cap for
            // each scratch mapping plus one for each process mapping. A broad LSASS dependency scan
            // therefore exhausted the finite root CSpace before those pages were ever referenced.
            // Thirty-two pages amortize the QEMU fault round-trip while preserving genuine demand
            // paging; once root-slot or frame-registry pressure approaches the gate, shrink the
            // speculative run so late userinit DLL loads stop pre-residenting mostly untouched pages.
            let (batch_start, batch_pages) = (page, sec_image_forward_run());
            let mut allocation_failed = false;
            let mut bi: u64 = 0;
            while bi < batch_pages {
                let bpage = batch_start + bi * 0x1000;
                if bpage >= img_hi || bpage < base {
                    break;
                }
                // The single page that actually FAULTED (present in every window). Only this page is
                // guaranteed unmapped; every other page must be checked before (re)mapping.
                let is_fault_page = bpage == page;
                if faults >= SEC_IMAGE_FAULT_CAP {
                    break;
                }
                let rva = (bpage - base) as u32;
                // SHAREABLE = a registered DLL's executable text (not the per-process main image at
                // PE_LOAD_BASE, and an RX page). Byte-identical across processes (each DLL loaded at a
                // fixed base + pre-relocated) → filled ONCE into a frame, mapped READ-ONLY (RX) into
                // every process that faults it — real image sharing.
                let shareable = base != PE_LOAD_BASE && page_rights(tpe, rva) == 2;
                let cached = if shareable { dll_cache_get(bpage) } else { 0 };
                // A forward run may overlap pages filled by an earlier run. The faulting page must
                // still be handled, but speculative neighbours that are already resident must not
                // be filled into a new frame and mapped over the live page (seL4 DeleteFirst).
                if !is_fault_page && !shareable && filled_pages.contains(&bpage) {
                    bi += 1;
                    continue;
                }
                // ★ BATCH 25 — FIXUP-SURVIVAL (the general correctness fix). A per-process image page
                // (a DLL's headers/.rdata/.idata/IAT or the main image) is filled ONCE from the raw
                // on-disk PE, then the ON-TARGET ntdll loader applies base RELOCATIONS + snaps the IAT
                // by WRITING into that mapped frame (in-process). Those fixups live ONLY in the frame,
                // NOT in the on-disk PE. If such a page is later RE-FAULTED at runtime (its mapping was
                // dropped / never landed / the demand loader re-touches it) and we naively re-FILL it
                // from the raw PE, we DISCARD the loader's fixups — a snapped IAT slot reverts to its
                // raw ILT thunk (a bare IMAGE_IMPORT_BY_NAME RVA), a relocated pointer loses its base.
                // OBSERVED (lsass, BATCH 24): kernel32's ntdll-IAT page (RVA 0x77000, in .rdata → RW)
                // reverted → CloseHandle's `call *[IAT]` jumped to the bare RVA 0x3a288 (should be
                // NTDLL_BASE+0x3a288) → instr-fetch fault, before SetEvent(LSA_RPC_SERVER_ACTIVE).
                // FIX: for a per-process page THIS process already has a frame recorded for
                // (`csrss_frame_get(pi,page)` — populated at the FIRST fill for every pi>=1 process),
                // RE-MAP that SAME frame (which holds the loader's in-memory fixups) instead of filling a
                // fresh raw frame. `csrss_frame_get` falls back to the shared DLL cache, so restrict to
                // `!shareable` (a genuine per-process frame the caller recorded). Applies to ANY page in
                // the window (not just the faulting one) so an eager whole-image pass re-maps, never
                // re-fills, a page whose fixups already landed.
                if !shareable && pi >= 1 {
                    let existing = csrss_frame_get(pi as u64, bpage);
                    if existing != 0 && existing != dll_cache_get(bpage) {
                        if is_fault_page {
                            // A previously-filled per-process frame for THE FAULTING page → re-map it
                            // (preserving fixups). rights: per-process image pages are RW_NX here.
                            let (cc, ce) = copy_cap_r(existing);
                            let me = page_map_r(cc, bpage, RW_NX, pml4);
                            if ce != 0 || me != 0 {
                                let _ = cnode_delete_recycle_r(cc);
                            }
                            let n = FIXUP_REMAP_N.fetch_add(1, Ordering::Relaxed);
                            if n < 16 {
                                print_str(b"[fixup-remap] pi=");
                                print_u64(pi as u64);
                                print_str(b" page=0x");
                                print_hex(bpage as u32);
                                print_str(b" frame preserved (copy=");
                                print_u64(ce);
                                print_str(b" map=");
                                print_u64(me);
                                print_str(b")\n");
                            }
                        }
                        // Already backed by a recorded per-process frame → it is (or was) mapped; do NOT
                        // re-fill/double-map a non-faulting page. Advance. (No `faults` bump — no fill.)
                        bi += 1;
                        continue;
                    }
                }
                // A non-faulting page must only be (pre)filled if it is genuinely UNMAPPED in this
                // process. The faulting page always proceeds (it faulted → it is NOT mapped). For a
                // shared page, `cached != 0` means a frame exists.
                //  - In the small FORWARD-RUN (non-eager) path, THIS process may already have the
                //    cached shared page mapped (it's a re-entry) → skip pre-mapping to avoid a
                //    double-map; let it fault normally if unmapped.
                // A cached shared neighbour may already be mapped by an overlapping prior window.
                // Without a mapping query, leave it for its own cheap cache-hit fault rather than
                // risking DeleteFirst and consuming another destination cap.
                if !is_fault_page && shareable && cached != 0 {
                    bi += 1;
                    continue;
                }
                let (frame, rights) = if cached != 0 {
                    DLL_SHARED_HITS.fetch_add(1, Ordering::Relaxed);
                    (cached, 2u64) // shared text → RX, no fill, no fresh frame
                } else {
                    // MISS (shared, first process) or a per-process page: fill a fresh frame `f`,
                    // mapped at a UNIQUE monotonic scratch slot (seL4 records the mapping on the frame
                    // object, so a slot must not be reused without an unmap — unique slots are the
                    // proven model; a COPY of `f` is what gets mapped into the process). The BATCH does
                    // not change the TOTAL distinct pages a process fills (only WHEN, in fewer
                    // round-trips), so scratch consumption matches the pre-batch baseline; the widened
                    // + re-spaced per-process scratch windows (see *_SCRATCH_BASE) give room for the
                    // higher counts lsass's LSA-init tree reaches.
                    let scratch = scratch_base + faults * 0x1000;
                    let (f, fe) = alloc_frame_r();
                    let se = page_map_r(f, scratch, RW_NX, CAP_INIT_THREAD_VSPACE);
                    if pi == 2 && bpage == 0x8230_e000 {
                        let (old, old_index) = csrss_frame_get_exact(2, 0x8045_1000);
                        print_str(b"[alias-diag] msgina-before faults=");
                        print_u64(faults);
                        print_str(b" scratch=0x");
                        print_hex((scratch >> 32) as u32);
                        print_hex(scratch as u32);
                        print_str(b" new-cap=0x");
                        print_hex(f as u32);
                        print_str(b" new-pa=0x");
                        let new_pa = if fe == 0 { get_frame_paddr(f) } else { 0 };
                        print_hex((new_pa >> 32) as u32);
                        print_hex(new_pa as u32);
                        print_str(b" old-cap=0x");
                        print_hex(old as u32);
                        print_str(b" old-pa=0x");
                        let old_pa = if old != 0 { get_frame_paddr(old) } else { 0 };
                        print_hex((old_pa >> 32) as u32);
                        print_hex(old_pa as u32);
                        print_str(b" old-idx=");
                        print_u64(if old_index == usize::MAX {
                            u64::MAX
                        } else {
                            old_index as u64
                        });
                        print_str(b" retype=");
                        print_u64(fe);
                        print_str(b" smap=");
                        print_u64(se);
                        print_str(b"\n");
                    }
                    // ★ ROBUSTNESS (must precede the fill): fill_image_page WRITES the PE bytes THROUGH
                    // the scratch alias. If alloc_frame_r / page_map_r failed (untyped pool or CNode
                    // slots exhausted — the frame pressure eager-map front-loads), the scratch VA is
                    // NOT mapped, and an unconditional write here faults the EXECUTIVE ITSELF (tcb=3,
                    // no fault handler → the whole boot dies). Guard the fill on a successful map, and
                    // break out of this image's batch so the faulting thread is handled below (it will
                    // re-fault or park) instead of taking the executive down.
                    if fe != 0 || se != 0 {
                        print_str(b"[map-fail] rva=0x");
                        print_hex(rva);
                        print_str(b" retype=");
                        print_u64(fe);
                        print_str(b" smap=");
                        print_u64(se);
                        print_str(b" faults=");
                        print_u64(faults);
                        print_str(b" (alloc/map FAILED - skip fill, resource pressure)\n");
                        allocation_failed = true;
                        break;
                    }
                    let r = fill_image_page(tpe, rva, scratch);
                    if pi == 2 && bpage == 0x8045_1000 {
                        KERNEL32_TABLE_WATCH_SCRATCH.store(scratch, Ordering::Relaxed);
                        print_str(b"[alias-watch] kernel32 table faults=");
                        print_u64(faults);
                        print_str(b" scratch=0x");
                        print_hex((scratch >> 32) as u32);
                        print_hex(scratch as u32);
                        print_str(b" cap=0x");
                        print_hex(f as u32);
                        print_str(b" pa=0x");
                        let pa = get_frame_paddr(f);
                        print_hex((pa >> 32) as u32);
                        print_hex(pa as u32);
                        print_str(b"\n");
                    }
                    if shareable {
                        dll_cache_put(bpage, f); // this frame becomes the shared copy for all processes
                    } else {
                        // Per-process page (main image, or DLL headers/rdata/data/IAT): record it for
                        // copy-out via its scratch alias, and mirror the main image so smss_copyin can
                        // read static-string args from .rdata.
                        if (faults as usize) < filled_pages.len() {
                            filled_pages[faults as usize] = bpage;
                        }
                        if pi >= 1 {
                            // Record every process's private image page so a later overlapping forward
                            // prefetch can reuse it instead of allocating and attempting a second map.
                            // For GUI clients the same record also lets win32k identity-map live client
                            // data such as PFNCLIENT arrays and stack-built OBJECT_ATTRIBUTES.
                            csrss_frame_put_at(pi as u64, bpage, f, scratch);
                        }
                        if base == PE_LOAD_BASE {
                            let off = bpage - PE_LOAD_BASE;
                            if off < IMAGE_MIRROR_WINDOW {
                                let mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
                                let _ = page_map(
                                    copy_cap(f),
                                    mirror + off,
                                    RW_NX,
                                    CAP_INIT_THREAD_VSPACE,
                                );
                            }
                        }
                    }
                    faults += 1; // a fill consumed a scratch slot; shared HITs do not
                    bump_progress(); // (B) a fresh page filled = real memory progress (resets stall)
                    (f, if shareable { 2 } else { r })
                };
                // Map the frame into the faulting process (RX for shared text, its fill rights otherwise).
                let (cc, ce) = copy_cap_r(frame);
                let me = page_map_r(cc, bpage, rights, pml4);
                if ce != 0 || me != 0 {
                    let _ = cnode_delete_recycle_r(cc);
                    print_str(b"[map-fail] va=0x");
                    print_hex(bpage as u32);
                    print_str(b" copy=");
                    print_u64(ce);
                    print_str(b" map=");
                    print_u64(me);
                    print_str(b" shared=");
                    print_u64(shareable as u64);
                    print_str(b"\n");
                    if ce != 0 || me != 8 || is_fault_page {
                        allocation_failed = true;
                        break;
                    }
                }
                bi += 1;
            }
            if allocation_failed {
                park_and_log!(pi, b"image-map-resource", m0, addr);
            }
            procs[pi].faults = faults;
            procs[pi].first = first;
            procs[pi].ntfaults = ntfaults;
            pfilled[pi] = *filled_pages;
            let (nb, nmi, nm0, nm1, nm2, nm3) = reply_recv_badge(fault_ep, 0, 0, 0, 0, 0);
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        // ntdll_plan Step 6.A — NATIVE seL4-Call transport. OUR ntdll (native-transport smss) does a
        // real seL4 `Call(CT_FAULT)` instead of a Windows-`syscall` UnknownSyscall trap. The request
        // carries: MR0=SSN(m0), MR1=caller-rsp(m1), MR2=arg1(m2), MR3=arg2(m3), MR4=arg3(recv_mr[4]),
        // MR5=arg4(recv_mr[5]); args5+ stay on the caller's stack (read via the mirror using rsp). We
        // NORMALIZE it into the fault-frame register slots the `(mi>>12)==2` arm reads, then re-label
        // the message as UnknownSyscall (2) so it flows through that arm's FULL servicing body
        // unchanged (dispatch + out-writes + spawn/park/delay post-actions). The reply is a NORMAL IPC
        // reply (the native caller has NO pending fault): `reply_recv_badge(..,result,..)` fans
        // result→MR0→the caller's r10, which our native stub reads as NTSTATUS.
        if (mi >> 12) == nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL {
            let ssn = m0; // MR0
            let rsp = m1; // MR1 = caller rsp (for stack args + stack out-param mirror writes)
            let arg1 = m2; // MR2
            let arg2 = m3; // MR3
            let arg3 = get_recv_mr(4); // MR4 (IPC buffer)
            let arg4 = get_recv_mr(5); // MR5 (IPC buffer)
                                       // Stage the fault-frame register slots the `==2` arm reads: R10@9=arg1, R8@7=arg3,
                                       // R9@8=arg4, SP@16=rsp, FLAGS@17=0. (arg2 is read directly from `m3`.)
            set_recv_mr(9, arg1);
            set_recv_mr(7, arg3);
            set_recv_mr(8, arg4);
            set_recv_mr(16, rsp);
            set_recv_mr(17, 0);
            // m0 stays = SSN; m2 becomes resume_ip (unused for a native reply — no fault restart).
            m0 = ssn;
            m2 = 0;
            // Re-label as UnknownSyscall so the shared servicing arm below runs.
            mi = (2u64 << 12) | (mi & 0x7F);
            // BATCH 34 DIAG: trace every SERVER listener SSN so the boot log reveals the exact
            // rpcrt4 ncacn_np server-side wait model (NtCreateNamedPipeFile / FSCTL_PIPE_LISTEN /
            // overlapped NtReadFile / NtWaitForMultipleObjects). Bounded so it never floods.
            if is_svc_listener {
                let dn = SVC_LISTENER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 24 {
                    print_str(b"[svc-listener-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
            // BATCH 37 DIAG: trace the SCM per-connection worker's native SSNs to reveal exactly why it
            // exits before reading the bind (the self-inspection syscalls + which handle it reads/exits on).
            if is_scm_worker {
                let dn = SCM_WORKER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 32 {
                    print_str(b"[scm-worker-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
            // LSA-RPC DIAG: trace lsass' `\pipe\lsarpc` rpcrt4 SERVER thread's native SSNs so the
            // boot log shows exactly what it does when a client connect completes its listen
            // (re-listen instance create → `RPCRT4_new_client` → `CreateThread`) and where it walls.
            // SPIN DIAGNOSTIC: a hosted thread that loops on an un-traced syscall makes the boot look
            // hung (the executive is just servicing it as fast as it can, with no log line). Print a
            // heartbeat every 8192 native syscalls with the badge + current SSN so any such loop is
            // immediately visible and attributable. Costs one increment per syscall.
            {
                let n = NATIVE_SYSCALL_HEARTBEAT.fetch_add(1, Ordering::Relaxed);
                if n % 8192 == 8191 {
                    print_str(b"[ssn-heartbeat] total=");
                    print_u64(n + 1);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b"\n");
                }
            }
            // lsass' generic ntdll thread-pool worker is where rpcrt4 runs `RPCRT4_worker_thread`
            // (`QueueUserWorkItem`, rpc_server.c:591) — i.e. the actual `LsarOpenPolicy` server-stub
            // dispatch. Trace it so the RPC dispatch is visible, not a black box.
            if is_tp_worker && pi == 4 {
                let dn = LSA_TP_WORKER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 64 {
                    print_str(b"[lsa-tp-ssn] #");
                    print_u64(dn);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
            // FORWARD-PROGRESS CENSUS: per-SSN histogram for the two processes that matter to the
            // starvation question — lsass (whose self-RPC is suspected of churning) and winlogon
            // (whose SAS window the paint depends on). A poll/retry livelock is unmistakable here.
            if pi == 4 || pi == 2 || pi == 1 || pi == 6 {
                let bucket = ssn_bucket(ssn);
                match pi {
                    4 => LSASS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                    2 => WINLOGON_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                    1 => CSRSS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                    _ => EXPLORER_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                };
            }
            if is_lsa_worker {
                LSA_WORKER_SYSCALLS.fetch_add(1, Ordering::Relaxed);
                let dn = LSA_WORKER_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 48 {
                    print_str(b"[lsa-worker-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
            if is_lsass_listener3 {
                let dn = LSA_LISTENER3_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if dn < 40 {
                    print_str(b"[lsa-srv-ssn] #");
                    print_u64(dn);
                    print_str(b" ssn=");
                    print_u64(ssn);
                    print_str(b" arg1=0x");
                    print_hex(arg1 as u32);
                    print_str(b" arg2=0x");
                    print_hex(arg2 as u32);
                    print_str(b"\n");
                }
            }
        }
        if (mi >> 12) == 2 {
            // A native `syscall` from the process (via ntdll's Nt* stub). SSN_DONE is our test
            // sentinel; otherwise it's a REAL Nt* system call to service.
            if m0 == SSN_DONE {
                verdict = get_recv_mr(9); // R10 = arg1
                break;
            }
            ssn_ring[ssn_ri % 32] = m0 as u16;
            ssn_ring_badge[ssn_ri % 32] = badge as u8;
            ssn_ri += 1;
            if hosted_main_badge_has_role(
                &nt_handler,
                badge,
                nt_exe_image::HostedProcessRole::InteractiveLogon,
            ) {
                wl_ring[wl_ri % 48] = m0 as u16;
                wl_ri += 1;
            }
            let resume_ip = m2; // RCX = syscall return address
            let sp = get_recv_mr(16);
            let flags = get_recv_mr(17);
            let current_tid = nt_handler
                .hosted_thread_tid_for_badge(badge)
                .unwrap_or_else(|| {
                    print_str(b"[hosted-thread] missing runtime TID for syscall badge=");
                    print_u64(badge);
                    print_str(b" pi=");
                    print_u64(pi as u64);
                    print_str(b"\n");
                    0
                });
            if pi == 6 {
                let (active_depth, continuation_depth) = win32k_glue::user_callback_stack_depths();
                if active_depth != 0 {
                    let n = EXPLORER_CALLBACK_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                    if n < 96 {
                        print_str(b"[explorer-cb-ssn] #");
                        print_u64(n);
                        print_str(b" badge=");
                        print_u64(badge);
                        print_str(b" tid=");
                        print_u64(current_tid);
                        print_str(b" ssn=0x");
                        print_hex_u64(m0);
                        print_str(b" depth=");
                        print_u64(active_depth as u64);
                        print_str(b"/");
                        print_u64(continuation_depth as u64);
                        print_str(b" rdx=0x");
                        print_hex_u64(m3);
                        print_str(b" r8=0x");
                        print_hex_u64(get_recv_mr(7));
                        print_str(b" r9=0x");
                        print_hex_u64(get_recv_mr(8));
                        print_str(b" r10=0x");
                        print_hex_u64(get_recv_mr(9));
                        print_str(b" r15=0x");
                        print_hex_u64(get_recv_mr(14));
                        print_str(b" resume-ip=0x");
                        print_hex_u64(resume_ip);
                        print_str(b"\n");
                    }
                }
            }
            if pi == 6 && m0 == SSN_NT_FLUSH_INSTRUCTION_CACHE {
                let n = EXPLORER_FLUSH_ICACHE_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 32 {
                    let (active_depth, continuation_depth) =
                        win32k_glue::user_callback_stack_depths();
                    print_str(b"[explorer-flush-icache] #");
                    print_u64(n);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" tid=");
                    print_u64(current_tid);
                    print_str(b" callback-depth=");
                    print_u64(active_depth as u64);
                    print_str(b" continuation-depth=");
                    print_u64(continuation_depth as u64);
                    print_str(b" process=0x");
                    print_hex_u64(get_recv_mr(9));
                    print_str(b" base=0x");
                    print_hex_u64(m3);
                    print_str(b" size=0x");
                    print_hex_u64(get_recv_mr(7));
                    print_str(b" resume-ip=0x");
                    print_hex_u64(resume_ip);
                    print_str(b"\n");
                }
            }
            if m0 == 22 {
                if let Some(completion) = win32k_glue::complete_controlled_user_callback(
                    pi as u32,
                    badge,
                    current_tid,
                    get_recv_mr(9),
                    m3,
                    get_recv_mr(7),
                ) {
                    if pi == 2 {
                        if let Some(dispatch) = completion.outer_dispatch {
                            observe_winlogon_completed_dispatch(
                                dispatch,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            );
                            observe_completed_dialog_modal_dispatch(dispatch, badge, current_tid);
                        }
                    }
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    client_reply_on(reply_main, 0, 0, 0, 0, 0);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, reply_main);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
            }
            let mut result = 0u64; // STATUS_SUCCESS unless a handler overrides
                                   // DIAG (credential frontier): once the injected VK_RETURN has been delivered, trace
                                   // winlogon's NATIVE (non-win32k) syscalls — that is the WM_COMMAND(IDOK) ->
                                   // LogonDialogProc -> DoLogon -> DoLoginTasks -> ConnectToLsa/LsaLogonUser tail.
            if pi == 2 && m0 < 0x1000 && WINLOGON_CRED_RETRIEVED_RETURN.load(Ordering::Relaxed) != 0
            {
                let n = WINLOGON_CRED_POST_RETURN_SSNS.fetch_add(1, Ordering::Relaxed);
                if n < 192 {
                    print_str(b"[cred-tail] winlogon native SSN=");
                    print_u64(m0);
                    print_str(b"\n");
                }
            }
            // DIAG: trace the real LSA server thread's native SSNs while it handles a client exchange
            // (bounded) — this is the ground truth for how far `LsapHandlePortConnection` /
            // `LsapLookupAuthenticationPackage` / `LsapLogonUser` get on our host.
            if badge == LSA_SRV_LIVE_BADGE.load(Ordering::Relaxed) {
                // lsasrv's `LsapCopyFromClient` reading the caller's `MSV1_0_INTERACTIVE_LOGON` out of
                // its VSpace while it services `LSASS_REQUEST_LOGON_USER` — the credentials genuinely
                // crossing into the authentication package.
                if m0 == SSN_NT_READ_VM
                    && LSA_LAST_API_NUMBER.load(Ordering::Relaxed) == 2
                    && LSA_CLI_REPLY_CAP.load(Ordering::Relaxed) != 0
                {
                    LSA_LOGON_CLIENT_READS.fetch_add(1, Ordering::Relaxed);
                }
                let n = LSA_SRV_SSN_TRACE.fetch_add(1, Ordering::Relaxed);
                if n < 96 {
                    print_str(b"[lsa-srv-ssn] #");
                    print_u64(n);
                    print_str(b" ssn=");
                    print_u64(m0);
                    print_str(b" arg1=0x");
                    print_hex(get_recv_mr(9) as u32);
                    print_str(b" arg2=0x");
                    print_hex(m3 as u32);
                    print_str(b"\n");
                }
            }
            // ═══ `\LsaAuthenticationPort` RENDEZVOUS — server side ═══════════════════════════════
            // lsass' REAL `AuthPortThreadRoutine` reached `NtReplyWaitReceivePort(AuthPortHandle, …)`
            // (`references/reactos/dll/win32/lsasrv/authport.c:245`). Unlike the generic listener park
            // below (which DROPS the reply capability and strands the thread forever) this parks it
            // WAKEABLY: the reply object stays owned by the rendezvous, so a later client connect or
            // request genuinely resumes this thread inside its own receive loop. If the syscall also
            // carried a `ReplyMessage` (the server answering the request it just handled), that reply
            // is copied straight out of the server's buffer into the waiting client's.
            if LSA_RENDEZVOUS_ENABLED
                && m0 == SSN_NT_REPLY_WAIT_RECEIVE_PORT
                && (is_lsass_listener || is_lsass_listener2 || is_lsass_listener3)
                && LSA_AUTH_PORT_HANDLE.load(Ordering::Relaxed) != 0
                && get_recv_mr(9) == LSA_AUTH_PORT_HANDLE.load(Ordering::Relaxed)
            {
                nt_handler.pi = pi;
                nt_handler.current_badge = badge;
                nt_handler.current_tid = current_tid;
                let replymsg = get_recv_mr(7); // R8 = ReplyMessage (NULL on the first receive)
                let recvmsg = get_recv_mr(8); // R9 = &RequestMsg
                let ctx_out = m3; // RDX = PVOID *PortContext
                if replymsg != 0 {
                    let _ = lsa_deliver_reply(&mut nt_handler, replymsg);
                }
                if lsa_server_park(badge, pi, recvmsg, ctx_out, resume_ip, sp, flags) {
                    if LSA_SERVER_PARKS.load(Ordering::Relaxed) <= 4 {
                        print_str(b"[lsa-rdv] real LSA server thread (badge ");
                        print_u64(badge);
                        print_str(
                            b") BLOCKED in NtReplyWaitReceivePort(\\LsaAuthenticationPort) msg=0x",
                        );
                        print_hex(recvmsg as u32);
                        print_str(b" -> wakeable park (reply cap retained)\n");
                    }
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    mark_wait_parked!(pi, m0);
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
            }
            // ═══ `\LsaAuthenticationPort` RENDEZVOUS — client DATA plane ═════════════════════════
            // winlogon's `LsaLookupAuthenticationPackage` / `LsaLogonUser` / … marshal an `LSA_API_MSG`
            // and issue `NtRequestWaitReplyPort(LsaHandle, &ApiMessage, &ApiMessage)`
            // (`references/reactos/sdk/lib/lsalib/lsa.c`). Relay the message VERBATIM into the parked
            // real server's `RequestMsg` and BLOCK this caller until the server replies.
            if LSA_RENDEZVOUS_ENABLED
                && m0 == SSN_NT_REQUEST_WAIT_REPLY_PORT
                && lsa_server_parked()
                && LSA_CLI_REPLY_CAP.load(Ordering::Relaxed) == 0
                && WINLOGON_LSA_PORT_HANDLE.load(Ordering::Relaxed) != 0
                && get_recv_mr(9) == WINLOGON_LSA_PORT_HANDLE.load(Ordering::Relaxed)
            {
                nt_handler.pi = pi;
                nt_handler.current_badge = badge;
                nt_handler.current_tid = current_tid;
                let reqmsg = m3; // RDX = RequestMessage
                let replymsg = get_recv_mr(7); // R8 = ReplyMessage
                let mut message = [0u8; LSA_API_MSG_MAX];
                let mut length = 0usize;
                let mut header = [0u8; LSA_PORT_MESSAGE_HEADER as usize];
                if reqmsg != 0 && nt_handler.xas_read(reqmsg, &mut header) {
                    let total = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
                    let want = total
                        .max(LSA_PORT_MESSAGE_HEADER as usize + 8)
                        .min(LSA_API_MSG_MAX);
                    if nt_handler.xas_read(reqmsg, &mut message[..want]) {
                        length = want;
                    }
                }
                if length > LSA_PORT_MESSAGE_HEADER as usize {
                    let api_number = u32::from_le_bytes(
                        message[LSA_PORT_MESSAGE_HEADER as usize
                            ..LSA_PORT_MESSAGE_HEADER as usize + 4]
                            .try_into()
                            .unwrap(),
                    ) as u64;
                    let client_pid = nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64;
                    if lsa_client_park(2, badge, pi, replymsg, 0, 0, resume_ip, sp, flags) {
                        let delivered = lsa_server_deliver(
                            &mut nt_handler,
                            LSA_MSG_TYPE_REQUEST,
                            client_pid,
                            current_tid,
                            &message[LSA_PORT_MESSAGE_HEADER as usize..length],
                            LSA_PORT_CONTEXT.load(Ordering::Relaxed),
                        );
                        if delivered {
                            LSA_REQUESTS_DELIVERED.fetch_add(1, Ordering::Relaxed);
                            LSA_LAST_API_NUMBER.store(api_number, Ordering::Relaxed);
                            // ApiNumber 2 = LsaLogonUser: mark the credential validation IN FLIGHT
                            // so registry reads the real MSV1_0/lsasrv code makes while servicing it
                            // (notably `GetAccountDomainSid`'s `PolAcDm*` reads) are attributable to
                            // the logon rather than to LSA init.
                            LSA_LOGON_IN_FLIGHT
                                .store(u64::from(api_number == 2), Ordering::Relaxed);
                            if api_number < 64 {
                                LSA_API_MASK.fetch_or(1u64 << api_number, Ordering::Relaxed);
                            }
                            print_str(
                                b"[lsa-rdv] REQUEST relayed to the real LSA server: ApiNumber=",
                            );
                            print_u64(api_number);
                            print_str(b" bytes=");
                            print_u64(length as u64);
                            print_str(b" -> connector BLOCKED on the reply\n");
                            bump_progress();
                        } else {
                            // Nothing was woken on the server side — release the connector with a
                            // real failure rather than leaving it blocked forever.
                            let cap = LSA_CLI_REPLY_CAP.swap(0, Ordering::Relaxed);
                            LSA_CLI_KIND.store(0, Ordering::Relaxed);
                            lsa_wake(cap, 0xC000_0001, resume_ip, sp, flags);
                        }
                        procs[pi].faults = faults;
                        procs[pi].first = first;
                        procs[pi].ntfaults = ntfaults;
                        pfilled[pi] = *filled_pages;
                        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                        let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                        badge = nb;
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        continue;
                    }
                }
            }
            let mut handled = true;
            // BATCH 43: set when winlogon reaches its win32k SAS-window creation milestone (0x1077 OK) →
            // park it (recv-next-without-reply) so the boot quiesces + the gate runs (see the !handled block).
            let mut wl_milestone_park = false;
            // Set alongside `wl_milestone_park` when the park must NOT end the boot (see the
            // blocking-GetMessage guard): the thread parks, the service loop keeps running.
            let mut wl_park_defer_quiesce = false;
            // (Phase 3: the `routed_win32k` / `routed_lpc` / `routed_csr` flags that used to live
            // here are GONE. They existed solely to steer this syscall's reply away from the legacy
            // `reply_to` — which a nested win32k / SM-loop / CSR-thread fault had clobbered — and
            // onto the caller's bound `REPLY_MAIN`. Every reply takes the bound object now, so there
            // is nothing left to steer. See the reply tail at the bottom of the syscall arm.)
            let mut redirected_user_callback = false;
            // Broker-only terminal waits (currently smss waiting forever for csrss/winlogon) park
            // by withholding a reply. Self-termination does not use this flag: its explicit post
            // action deletes the bound Reply cap and caller TCB before receiving again.
            let mut park_caller = false;
            // Checkpoint B: -1 = no wait-park; >=0 = NtWaitForSingleObject asked to park this caller on
            // the given obj_ns event index (set from nt_handler.wait_park_event after dispatch).
            let mut park_wait_event: i64 = -1;
            // Array-wait park (NtWaitForMultipleObjects): the resolved obj_ns event set + WaitAll flag.
            // count 0 = no array-park. Consumed next to park_wait_event in the reply block.
            let park_wait_set = &mut *core::ptr::addr_of_mut!(PARK_WAIT_SET_WORK);
            let park_wait_indices = &mut *core::ptr::addr_of_mut!(PARK_WAIT_INDEX_WORK);
            let mut park_wait_set_n: usize = 0;
            let mut park_wait_set_all = false;
            let mut park_wait_deadline: Option<u64> = None;
            let mut park_keyed_wait_key: u64 = u64::MAX;
            let mut park_keyed_wait_deadline: Option<u64> = None;
            let mut park_delay_deadline: Option<u64> = None;
            let mut park_io_completion_port: i64 = -1;
            let mut park_io_completion_key_out: u64 = 0;
            let mut park_io_completion_apc_out: u64 = 0;
            let mut park_io_completion_iosb_out: u64 = 0;
            let mut park_io_completion_deadline: Option<u64> = None;
            // BATCH 33 — pipe-pending park request latched from the handler (0 = none). Consumed at the
            // reply site (the reply-cap steal needs resume_ip/sp/flags, known there).
            let mut park_pipe_fid: u64 = 0;
            let mut park_pipe_buffer_va: u64 = 0;
            let mut park_pipe_buffer_len: u32 = 0;
            let mut park_pipe_iosb_va: u64 = 0;
            let mut park_pipe_apc_context: u64 = 0;
            let mut park_pipe_event_obj_idx: u64 = u64::MAX;
            let mut park_pipe_transceive = false;
            let mut park_pipe_is_write = false;
            // ★ Dbgk TARGET-SIDE BLOCK request (syscall flavour) latched out of the handler:
            // a debug event was posted from THIS syscall arm and NT blocks the reporting thread on
            // the debugger's continue. Consumed at the reply site (the reply-cap steal needs
            // resume_ip/sp/flags, known only there). Always false with no debugger attached.
            let mut park_dbgk_reporter = false;
            // Every syscall path, including the still hand-wired ladder below, resolves process-local
            // handles through ExecNtHandler. Refresh caller identity before choosing table vs ladder;
            // doing this only inside table dispatch left a runtime worker using whichever process ran
            // the previous registered syscall.
            nt_handler.pi = pi;
            nt_handler.current_badge = badge;
            nt_handler.current_tid = current_tid;
            // SEAM: if this SSN is in the real service table, dispatch it through the NT syscall
            // dispatcher -> real handler; otherwise fall through to the broker match. The x64 native
            // ABI passes args in r10(=rcx),rdx,r8,r9 then the stack; here we forward the register
            // args (sized to the service's max) — pointer/stack args come with the copyin layer.
            if let Some(entry) = nt_dispatcher.table().lookup(m0 as u32) {
                let origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
                // x64 native syscall args: arg1=R10 (the stub's `mov r10,rcx`; RCX itself is the
                // syscall return address), arg2=RDX, arg3=R8, arg4=R9, then arg5+ on the caller's
                // stack at [rsp+0x28], [rsp+0x30], … RDX rides in m3; R8/R9/R10 + the stack come
                // from the IPC buffer / stack mirror.
                let mut argv = [0u64; 16];
                argv[0] = get_recv_mr(9); // R10
                argv[1] = m3; // RDX
                argv[2] = get_recv_mr(7); // R8
                argv[3] = get_recv_mr(8); // R9
                let n = (entry.max_args as usize).min(16);
                let mut stack_args_valid = true;
                for i in 4..n {
                    let Some(argument_va) = sp.checked_add(0x28 + (i as u64 - 4) * 8) else {
                        stack_args_valid = false;
                        break;
                    };
                    let mut bytes = [0u8; 8];
                    if client_copyin_mapped(
                        pi as u64,
                        argument_va,
                        &mut bytes,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    ) {
                        argv[i] = u64::from_le_bytes(bytes);
                    } else {
                        stack_args_valid = false;
                        break;
                    }
                }
                // Refresh the handler's per-call executive context, then clear the stop side-signal
                // + out-write queue so a migrated handler can raise them (group A/B signals).
                nt_handler.post_action = ExecPostAction::None;
                nt_handler.stop = false;
                nt_handler.overlay_dirty = false;
                nt_handler.dll_loaded_dirty = false;
                nt_handler.token_dirty = false;
                nt_handler.process_dirty = false;
                nt_handler.hive_mounts_dirty = false;
                nt_handler.out_writes_n = 0;
                nt_handler.exe_spawn_request = None;
                nt_handler.thread_spawn_request = None;
                nt_handler.wait_park_event = -1;
                nt_handler.wait_deadline_100ns = u64::MAX;
                nt_handler.keyed_wait_key = u64::MAX;
                nt_handler.keyed_wait_deadline_100ns = u64::MAX;
                nt_handler.delay_requested = false;
                nt_handler.delay_interval_100ns = 0;
                nt_handler.delay_alertable = false;
                nt_handler.io_completion_park_port = -1;
                nt_handler.io_completion_key_out = 0;
                nt_handler.io_completion_apc_out = 0;
                nt_handler.io_completion_iosb_out = 0;
                nt_handler.io_completion_deadline_100ns = u64::MAX;
                nt_handler.io_completion_wake = None;
                nt_handler.io_signal_event = -1;
                nt_handler.pipe_park_fid = 0;
                nt_handler.pipe_park_buffer_va = 0;
                nt_handler.pipe_park_buffer_len = 0;
                nt_handler.pipe_park_iosb_va = 0;
                nt_handler.pipe_park_apc_context = 0;
                nt_handler.pipe_park_event_obj_idx = u64::MAX;
                nt_handler.pipe_park_transceive = false;
                nt_handler.pipe_park_is_write = false;
                nt_handler.dbgk_block_request = false;
                nt_handler.pipe_write_redrive = false;
                nt_handler.pipe_listen_fid = 0;
                nt_handler.pipe_listen_event_handle = 0;
                nt_handler.pipe_listen_iosb_va = 0;
                nt_handler.pipe_connect_redrive = 0;
                nt_handler.lpc_rendezvous_conn = 0;
                nt_handler.sm_request_port = 0;
                nt_handler.sm_request_message = 0;
                nt_handler.sm_reply_message = 0;
                nt_handler.csr_request_port = 0;
                nt_handler.csr_request_message = 0;
                nt_handler.csr_reply_message = 0;
                nt_handler.csr_start_request = 0;
                nt_handler.csr_rendezvous_conn = 0;
                // Group-C handlers reach the loop's section/registry/demand-fill state through this
                // ctx of raw refs (rebuilt each iteration at the current loop locals).
                nt_handler.loop_ctx = Some(ExecLoopCtx {
                    pml4,
                    procs: &mut procs,
                    pfilled,
                    nls_section_handle: &mut nls_section_handle as *mut u64,
                    reg: &mut reg as *mut nt_dll_registry::Registry,
                    hosted_loaded_images: &hosted_loaded_images as *const HostedLoadedImageTable,
                    exe_images: &mut exe_images as *mut nt_exe_image::ImageTable<8>,
                    exe_image_catalog: &mut exe_image_catalog
                        as *mut nt_exe_image::OwnedHostedImageCatalog<8>,
                    filled_pages: filled_pages as *mut [u64; 512],
                    faults: &mut faults as *mut u64,
                    scratch_base,
                    // Erase the non-'static lifetime through a thin `*const ()` (the image bytes are
                    // executive-lifetime; the loop outlives every `dispatch`).
                    pe: pe as *const nt_pe_loader::PeFile as *const ()
                        as *const nt_pe_loader::PeFile<'static>,
                    ntdll_pe: match ntdll {
                        Some((_, npe)) => {
                            npe as *const nt_pe_loader::PeFile as *const ()
                                as *const nt_pe_loader::PeFile<'static>
                        }
                        None => core::ptr::null(),
                    },
                    img_end,
                    nt_base,
                    nt_end,
                    dll_pes: dll_pes.as_ptr()
                        as *const &'static Option<nt_pe_loader::PeFile<'static>>,
                    dll_pes_len: dll_pes.len(),
                    dll_pe_store: dll_pe_store_ptr as *mut ()
                        as *mut Option<nt_pe_loader::PeFile<'static>>,
                    csrss_anon_section_handle: &mut csrss_anon_section_handle as *mut u64,
                    csrss_anon_size: &mut csrss_anon_size as *mut u64,
                    csrss_anon_base: &mut csrss_anon_base as *mut u64,
                    dll_pd_created: &mut dll_pd_created as *mut [bool; MAX_PI],
                    dll_pt_bits: &mut dll_pt_bits as *mut [[u64; DLL_ARENA_PT_WORDS]; MAX_PI],
                });
                // ALPC last-mile item (a): NtAlpc* SSNs are registered in the dispatcher via this
                // recognizer. DORMANT — `ALPC_HOST_PRESENT` is never set at boot (no ALPC binary
                // yet), and the Win7 ALPC SSNs collide with the live ReactOS SSN space, so it can
                // never fire for the 3 live ReactOS processes → byte-identical boot. When active it
                // routes a real ALPC process's NtAlpc* syscall to the unified port-service ALPC
                // adapter (skipping the native ReactOS dispatch).
                if !stack_args_valid {
                    result = 0xC000_0005;
                } else if let Some(st) = try_route_alpc_ssn(m0, &[], &mut [0u8; 8]) {
                    result = st;
                    handled = true;
                } else {
                    let res =
                        nt_dispatcher.dispatch(m0 as u32, &argv[..n], &origin, &mut nt_handler);
                    result = res.status as u64;
                    if nt_handler.stop {
                        handled = false; // handler couldn't service → stop with the SSN recorded
                    }
                }
                // NtResumeThread for a CSRSS server worker is a serialized run-to-receive action.
                // Execute it immediately after dispatch, while the main CSRSS Call is still bound to
                // REPLY_MAIN and therefore cannot race this worker on the shared native IPC frame.
                if nt_handler.csr_start_request != 0 {
                    print_str(b"[csr-thread] outer start role=");
                    print_u64(nt_handler.csr_start_request as u64);
                    print_str(b"\n");
                    if nt_handler.csr_start_request == 1 {
                        let tcb = nt_handler
                            .hosted_thread_tcb_for_role(csrss_pi, HostedThreadRole::CsrApi)
                            .unwrap_or(0);
                        if tcb > 1 {
                            let _ = tcb_resume(tcb);
                            let _ = csr_rendezvous(
                                0,
                                procs[csrss_pi].pml4,
                                loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                                    .expect("CSRSS PE must be registered before CSR API start"),
                                procs[csrss_pi].img_end,
                                nt_base,
                                nt_end,
                                ntdll.map(|(_, p)| p),
                                &reg,
                                &dll_pes,
                                &mut nt_handler,
                            );
                            if CSR_API_RECEIVE_PARKED.load(Ordering::Relaxed) == 0 {
                                result = 0xC000_0001;
                            } else {
                                if let Some(tid) = nt_handler
                                    .hosted_thread_tid_for_role(csrss_pi, HostedThreadRole::CsrApi)
                                {
                                    let _ = nt_handler.pm.set_thread_state(
                                        tid as nt_process::ThreadId,
                                        nt_process::ThreadState::Running,
                                    );
                                } else {
                                    result = 0xC000_0001;
                                }
                            }
                        } else {
                            result = 0xC000_0001;
                        }
                    } else if nt_handler.csr_start_request == 2 {
                        let tcb = nt_handler
                            .hosted_thread_tcb_for_role(csrss_pi, HostedThreadRole::CsrSbApi)
                            .unwrap_or(0);
                        if tcb > 1 {
                            let _ = tcb_resume(tcb);
                            if !csr_sb_startup(
                                procs[csrss_pi].pml4,
                                loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                                    .expect("CSRSS PE must be registered before CSR SB startup"),
                                procs[csrss_pi].img_end,
                                nt_base,
                                nt_end,
                                ntdll.map(|(_, p)| p),
                                &reg,
                                &dll_pes,
                            ) {
                                result = 0xC000_0001;
                            } else {
                                if let Some(tid) = nt_handler.hosted_thread_tid_for_role(
                                    csrss_pi,
                                    HostedThreadRole::CsrSbApi,
                                ) {
                                    let _ = nt_handler.pm.set_thread_state(
                                        tid as nt_process::ThreadId,
                                        nt_process::ThreadState::Running,
                                    );
                                } else {
                                    result = 0xC000_0001;
                                }
                            }
                        } else {
                            result = 0xC000_0001;
                        }
                    }
                }
                // A successful self-termination is a control-flow action, not a status-returning
                // syscall. First delete/replace the Reply object bound to this fault (so no send can
                // resume it), then suspend/delete the exact badge-selected TCB, and receive the next
                // caller immediately. Remote termination tears down its target but still replies to
                // the caller through the normal tail below.
                match nt_handler.post_action {
                    ExecPostAction::TerminateCurrentThread { tid } => {
                        // BATCH 34: if the SCM RPC listener (svc-listener, badge 7) terminates, mark the
                        // SCM server no-longer-live so winlogon's SCM read-park becomes terminal (quiesce)
                        // instead of hanging the loop's recv (no signaler left until the per-connection
                        // worker is routed — the flagged N-threads follow-up).
                        if is_svc_listener {
                            SVC_LISTENER_TERMINATED.store(1, Ordering::Relaxed);
                        }
                        let reply_dropped = drop_current_syscall_reply();
                        let mechanism_deleted = terminate_hosted_thread_mechanism(
                            tid,
                            &mut delay_queue,
                            &mut nt_handler,
                        );
                        if reply_dropped && mechanism_deleted {
                            PM_TERMINATE_THREAD_NO_REPLY.fetch_add(1, Ordering::Relaxed);
                        }
                        print_str(b"[thread-term] self-post tid=");
                        print_u64(tid);
                        print_str(b" reply-dropped=");
                        print_u64(reply_dropped as u64);
                        print_str(b" mechanism-deleted=");
                        print_u64(mechanism_deleted as u64);
                        print_str(b" -> recv without reply\n");
                        procs[pi].faults = faults;
                        procs[pi].first = first;
                        procs[pi].ntfaults = ntfaults;
                        pfilled[pi] = *filled_pages;
                        // BATCH 34: the SCM listener just exited AND winlogon is already SCM-read-parked
                        // (waiting for bind_ack). No live signaler remains (BATCH 35 routes the
                        // per-connection worker but it PARKS on a trampoline-entry fault — see the frontier
                        // note; it does not yet write bind_ack), so QUIESCE now → run the gate + clean
                        // qemu_exit instead of blocking to timeout.
                        if is_svc_listener && WINLOGON_SCM_PARKED.load(Ordering::Relaxed) != 0 {
                            print_str(b"[wl-main] SCM listener exited while winlogon SCM-read-parked (no worker routed yet) -> QUIESCE; run gate\n");
                            stop = m1;
                            break;
                        }
                        let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                        let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                        badge = nb;
                        mi = nmi;
                        m0 = nm0;
                        m1 = nm1;
                        m2 = nm2;
                        m3 = nm3;
                        continue;
                    }
                    ExecPostAction::TerminateRemoteThread { tid } => {
                        let _ = terminate_hosted_thread_mechanism(
                            tid,
                            &mut delay_queue,
                            &mut nt_handler,
                        );
                    }
                    ExecPostAction::TerminateProcess {
                        process_index,
                        current_tid,
                        drop_reply,
                    } => {
                        let preserve_tid = if current_tid != 0 {
                            Some(current_tid)
                        } else {
                            None
                        };
                        let reply_dropped = if drop_reply {
                            drop_current_syscall_reply()
                        } else {
                            false
                        };
                        let reclaimed = terminate_hosted_process_mechanisms(
                            process_index,
                            preserve_tid,
                            &mut delay_queue,
                            &mut nt_handler,
                        );
                        let current_deleted = if drop_reply && current_tid != 0 {
                            terminate_hosted_thread_mechanism(
                                current_tid,
                                &mut delay_queue,
                                &mut nt_handler,
                            )
                        } else {
                            false
                        };
                        if drop_reply || current_tid == 0 {
                            let _ = win32k_glue::unwind_dead_client_user_callbacks(
                                process_index as u32,
                            );
                        }
                        if drop_reply && reply_dropped && current_deleted {
                            PM_TERMINATE_PROCESS_NO_REPLY.fetch_add(1, Ordering::Relaxed);
                            if process_index < 64 {
                                PM_TERMINATE_PROCESS_NO_REPLY_PIS
                                    .fetch_or(1u64 << process_index, Ordering::Relaxed);
                            }
                        }
                        print_str(b"[process-term] pi=");
                        print_u64(process_index as u64);
                        print_str(b" current_tid=");
                        print_u64(current_tid);
                        print_str(b" drop_reply=");
                        print_u64(drop_reply as u64);
                        print_str(b" reply-dropped=");
                        print_u64(reply_dropped as u64);
                        print_str(b" reclaimed=");
                        print_u64(reclaimed as u64);
                        print_str(b" current-deleted=");
                        print_u64(current_deleted as u64);
                        print_str(b"\n");
                        if drop_reply {
                            procs[pi].faults = faults;
                            procs[pi].first = first;
                            procs[pi].ntfaults = ntfaults;
                            pfilled[pi] = *filled_pages;
                            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                            badge = nb;
                            mi = nmi;
                            m0 = nm0;
                            m1 = nm1;
                            m2 = nm2;
                            m3 = nm3;
                            continue;
                        }
                    }
                    ExecPostAction::CriticalTermination { code, object } => {
                        let reply_dropped = drop_current_syscall_reply();
                        // A critical process can bugcheck while it is running a win32k user-mode
                        // callback; unwind those continuations so win32k is idle (not stranded in its
                        // callback receive loop) for the gate. No-op when it held none.
                        let _ = win32k_glue::unwind_dead_client_user_callbacks(pi as u32);
                        print_str(b"[critical-termination] bugcheck=0x");
                        print_hex(code);
                        print_str(b" object=0x");
                        print_hex((object >> 32) as u32);
                        print_hex(object as u32);
                        print_str(b" reply-dropped=");
                        print_u64(reply_dropped as u64);
                        print_str(b" -> fatal stop\n");
                        stop = code as u64;
                        break;
                    }
                    ExecPostAction::None => {}
                }
                // CM write plane: a handler that mutated the registry overlay (NtCreateKey/
                // NtSetValueKey) allocated `String`/`Vec` on the bump heap ABOVE `heap_mark`. Pin the
                // mark PAST them now so the next iteration's `reset_to(heap_mark)` keeps them (real
                // NT: created keys/values persist). The mark also swallows this iteration's transient
                // allocations — a bounded leak (only a handful of overlay mutations per boot), well
                // within the 2 MiB heap; non-mutating iterations still reset fully.
                if nt_handler.overlay_dirty {
                    nt_handler.overlay_dirty = false;
                    heap_mark = allocator::mark();
                }
                // Demand-load plane: a handler that demand-loaded a DLL (NtOpenFile resolve-miss →
                // fs_loader::demand_load_dll → registry `activate`d a reserved slot + wrote its parsed
                // PE into dll_pe_store) pins the heap mark PAST the load's allocations so the activated
                // registry slot survives the next `reset_to(heap_mark)`. Mirrors `overlay_dirty` — the
                // pool bytes + dll_pe_store write are already reset-safe; this covers the registry fill.
                if nt_handler.dll_loaded_dirty {
                    nt_handler.dll_loaded_dirty = false;
                    heap_mark = allocator::mark();
                }
                if nt_handler.token_dirty {
                    nt_handler.token_dirty = false;
                    heap_mark = allocator::mark();
                }
                if nt_handler.process_dirty {
                    nt_handler.process_dirty = false;
                    heap_mark = allocator::mark();
                }
                // HIVE MOUNT plane: `NtLoadKey`/`NtUnloadKey` grew the `\Registry\User` mount
                // table's path `String`s above `heap_mark`. Same contract as `overlay_dirty` — a
                // mounted hive must outlive the syscall that mounted it. (The hive BYTES live in a
                // static slot, so only the paths need pinning.)
                if nt_handler.hive_mounts_dirty {
                    nt_handler.hive_mounts_dirty = false;
                    heap_mark = allocator::mark();
                }
                // WRITABLE FILESYSTEM plane: a handler that touched the writable overlay
                // (`writable_fs`) — its lazy mount, or a create/write/set-information/close — grew
                // the volume's `Vec`/`String` state ABOVE `heap_mark`. Pin the mark PAST it so the
                // directories and files a hosted process created SURVIVE the next per-syscall
                // reset. Exactly the `overlay_dirty` contract, for the file system instead of the
                // registry; bounded (the profile tree is a handful of nodes) and only on the
                // iterations that actually touched the volume.
                if nt_handler.writable_fs_dirty {
                    nt_handler.writable_fs_dirty = false;
                    heap_mark = allocator::mark();
                }
                // PROFILE FRONTIER (batch 58): once winlogon has resolved the profiles root, trace
                // every NATIVE syscall of its that FAILS, with the SSN and the NTSTATUS. `userenv`
                // only ever prints `GetLastError()`, and several distinct NTSTATUSes collapse onto
                // the same DOS error, so the frontier is unmeasurable without this.
                if pi == 2
                    && m0 < 0x1000
                    && result != 0
                    // STATUS_NO_MORE_FILES ends every legitimate `FindNextFileW` loop and
                    // STATUS_INVALID_INFO_CLASS is a probe kernel32 makes and ignores; both flood
                    // the window without being frontier information.
                    && result != 0x8000_0006
                    && result != 0xC000_0003
                    && crate::writable_fs::PROFILE_USER_DIR_CREATED.load(Ordering::Relaxed) != 0
                    // A SECOND budget opens once the user hive is loaded: the profile-copy phase
                    // exhausts the first one long before winlogon's remaining `HandleLogon` steps
                    // run, and those steps fail through `WARN`, which the binary does not print.
                    && (PROFILE_FRONTIER_TRACED.fetch_add(1, Ordering::Relaxed) < 32
                        || (post_profile_phase()
                            && POST_PROFILE_FRONTIER_TRACED.fetch_add(1, Ordering::Relaxed) < 96))
                {
                    print_str(b"[profile-frontier] winlogon SSN=");
                    print_u64(m0);
                    print_str(b" arg4=");
                    print_u64(get_recv_mr(8));
                    print_str(b" stack5=");
                    print_u64(smss_stack_read(get_recv_mr(16) + 0x28));
                    print_str(b" -> status=0x");
                    print_hex(result as u32);
                    print_str(b"\n");
                }
                // Bump-heap PRESSURE tripwire. Every pin above moves the permanent floor; when it
                // climbs, say so. A silent approach to the cap is what an exhausted no-free heap
                // looks like from the outside (allocations start returning null and callers take
                // their error paths), so this makes the boot's real occupancy visible in the log.
                if heap_mark >= HEAP_WATERMARK_REPORTED.load(Ordering::Relaxed) as usize + 0x2_0000
                {
                    HEAP_WATERMARK_REPORTED.store(heap_mark as u64, Ordering::Relaxed);
                    print_str(b"[heap] executive bump high-water=");
                    print_u64(heap_mark as u64);
                    print_str(b" cap=");
                    print_u64(allocator::HEAP_FRAMES * 0x1000);
                    print_str(b"\n");
                }
                // Drain queued out-param writes (group B2): csrss out-ptrs may be arbitrary VAs that
                // need a persistent image-page alias; other hosted processes can also return values
                // to DLL globals. Use the handler's common cross-address-space writer for both.
                for k in 0..nt_handler.out_writes_n {
                    let (ptr, val) = nt_handler.out_writes[k];
                    if !nt_handler.xas_write_u64(ptr, val) {
                        print_str(b"[copyout] failed pi=");
                        print_u64(pi as u64);
                        print_str(b" ptr=0x");
                        print_hex((ptr >> 32) as u32);
                        print_hex(ptr as u32);
                        print_str(b"\n");
                    }
                }
                // Checkpoint B: NtWaitForSingleObject on an unsignaled real event asked to PARK this
                // caller. Latch it for the reply site (the actual reply-cap steal happens there where
                // resume_ip/sp/flags are known).
                if nt_handler.wait_park_event >= 0 {
                    park_wait_event = nt_handler.wait_park_event;
                    if nt_handler.wait_deadline_100ns != u64::MAX {
                        park_wait_deadline = Some(nt_handler.wait_deadline_100ns);
                    }
                }
                if nt_handler.keyed_wait_key != u64::MAX {
                    park_keyed_wait_key = nt_handler.keyed_wait_key;
                    if nt_handler.keyed_wait_deadline_100ns != u64::MAX {
                        park_keyed_wait_deadline = Some(nt_handler.keyed_wait_deadline_100ns);
                    }
                }
                if nt_handler.delay_requested {
                    let monotonic_now = monotonic_time_100ns();
                    let system_now = nt_system_time_100ns();
                    match nt_delay_execution::due_time(
                        nt_handler.delay_interval_100ns,
                        monotonic_now,
                        system_now,
                    ) {
                        nt_delay_execution::Due::Immediate => {
                            if DELAY_TRACE_COUNT.load(Ordering::Relaxed) <= 16 {
                                print_str(b"[delay] COMPLETE-IMMEDIATE badge=");
                                print_u64(badge);
                                print_str(b" tid=");
                                print_u64(nt_handler.current_tid);
                                print_str(b" callsite=0x");
                                print_hex_u64(resume_ip);
                                print_str(b" interval_100ns=");
                                if nt_handler.delay_interval_100ns < 0 {
                                    print_str(b"-");
                                    print_u64(nt_handler.delay_interval_100ns.unsigned_abs());
                                } else {
                                    print_u64(nt_handler.delay_interval_100ns as u64);
                                }
                                print_str(b"\n");
                            }
                        }
                        nt_delay_execution::Due::Monotonic100ns(deadline) => {
                            park_delay_deadline = Some(deadline);
                            if DELAY_TRACE_COUNT.load(Ordering::Relaxed) <= 16 {
                                print_str(b"[delay] PARK-REQUEST badge=");
                                print_u64(badge);
                                print_str(b" tid=");
                                print_u64(nt_handler.current_tid);
                                print_str(b" callsite=0x");
                                print_hex_u64(resume_ip);
                                print_str(b" deadline_100ns=");
                                print_u64(deadline);
                                print_str(b" now_100ns=");
                                print_u64(monotonic_now);
                                print_str(if nt_handler.delay_alertable {
                                    b" alertable=1 queued_apc=0\n"
                                } else {
                                    b" alertable=0 queued_apc=0\n"
                                });
                            }
                        }
                    }
                }
                if nt_handler.io_completion_park_port >= 0 {
                    park_io_completion_port = nt_handler.io_completion_park_port;
                    park_io_completion_key_out = nt_handler.io_completion_key_out;
                    park_io_completion_apc_out = nt_handler.io_completion_apc_out;
                    park_io_completion_iosb_out = nt_handler.io_completion_iosb_out;
                    if nt_handler.io_completion_deadline_100ns != u64::MAX {
                        park_io_completion_deadline = Some(nt_handler.io_completion_deadline_100ns);
                    }
                }
                if nt_handler.io_completion_wake.is_some() {
                    let _ = unsafe { io_completion_deliver(&mut nt_handler) };
                }
                if nt_handler.io_signal_event >= 0 {
                    let _ = wait_wake_dispatcher_set(&mut nt_handler);
                }
                // BATCH 33: latch a pipe-pending park request (the reply-cap steal happens at the reply
                // site where resume_ip/sp/flags are known). Re-drive any parked pipe reads on a peer
                // write (done HERE, before the writer's own reply — npfs already queued the bytes).
                if nt_handler.dbgk_block_request {
                    park_dbgk_reporter = true;
                }
                if nt_handler.pipe_park_fid != 0 {
                    park_pipe_fid = nt_handler.pipe_park_fid;
                    park_pipe_buffer_va = nt_handler.pipe_park_buffer_va;
                    park_pipe_buffer_len = nt_handler.pipe_park_buffer_len;
                    park_pipe_iosb_va = nt_handler.pipe_park_iosb_va;
                    park_pipe_apc_context = nt_handler.pipe_park_apc_context;
                    park_pipe_event_obj_idx = nt_handler.pipe_park_event_obj_idx;
                    park_pipe_transceive = nt_handler.pipe_park_transceive;
                    park_pipe_is_write = nt_handler.pipe_park_is_write;
                }
                // ★ BATCH 34: a client CONNECT to a pipe with a pending async server FSCTL_PIPE_LISTEN
                // for the SAME pipe name completes that listen — signal its completion event so the
                // server's NtWaitForMultipleObjects wakes and reads the client's first PDU (the bind).
                // Name-scoped (pipe_connect_redrive carries the connected pipe's leaf name-hash) so a
                // connect to \ntsvcs never spuriously wakes the \lsarpc/\samr servers. Only a CONNECT
                // (not a write) completes a listen — a write re-drives parked reads (below), which is
                // the correct edge once the connection is established.
                if nt_handler.pipe_connect_redrive != 0 {
                    let connect_name_hash = nt_handler.pipe_connect_redrive;
                    let listens = pipe_listen_complete_named(&mut nt_handler, connect_name_hash);
                    if listens != 0 {
                        print_str(b"[pipe-listen] completed ");
                        print_u64(listens);
                        print_str(b" pending server listen(s) on client connect\n");
                    }
                }
                if nt_handler.pipe_write_redrive {
                    let woken = pipe_redrive_all(&mut nt_handler);
                    if woken != 0 && PIPE_REDRIVE_TRACE_COUNT.load(Ordering::Relaxed) <= 20 {
                        print_str(b"[pipe-redrive] peer write woke ");
                        print_u64(woken);
                        print_str(b" parked reader(s)\n");
                    }
                }
                // The hosted-exe lane reserved a spawn after validating the owner-local file ->
                // section -> process transition in `exe_images`. The remaining per-image policy is
                // the address-space descriptor; handle publication and ProcessManager wiring are
                // common for csrss/winlogon and later Win32 children.
                if let Some(request) = nt_handler.exe_spawn_request {
                    let is_csrss_spawn = request.leaf().eq_ignore_ascii_case(b"csrss.exe");
                    if let Some(spec) =
                        hosted_exe_spawn_for(request, &exe_image_catalog, &hosted_loaded_images)
                    {
                        if spec.spawned.load(Ordering::Relaxed) == 0 {
                            match spawn_requested_hosted_exe(
                                request,
                                spec,
                                fault_ep,
                                &mut procs,
                                &mut nt_handler,
                                &mut exe_images,
                            ) {
                                Ok(process_handle) if is_csrss_spawn => {
                                    csrss_process_handle = process_handle;
                                }
                                Ok(_) => {}
                                Err(status) => {
                                    result = u64::from(status);
                                }
                            }
                        }
                    } else {
                        let _ = exe_images.rollback_spawn(request);
                        result = u64::from(nt_process::STATUS_INVALID_PARAMETER);
                    }
                }
                if let Some(request) = nt_handler.thread_spawn_request.take() {
                    spawn_requested_local_thread(
                        &mut nt_handler,
                        request,
                        &procs,
                        pml4,
                        sp,
                        fault_ep,
                    );
                }
                // ★ CROSS-VSPACE NtCreateThread: the handler decided the policy; build the REAL
                // thread inside the TARGET's address space here, where the main fault endpoint the
                // new thread must be badged onto is in scope. `None` on every boot today.
                if let Some(request) = nt_handler.remote_thread_request.take() {
                    spawn_requested_remote_thread(&mut nt_handler, &request, fault_ep);
                }
                // ═══ `\LsaAuthenticationPort` RENDEZVOUS — the accept landed ════════════════════
                // lsass' real `LsapHandlePortConnection` just ran `NtAcceptConnectPort` (+
                // `NtCompleteConnectPort` when it accepted). Publish the broker's client comm-port
                // handle plus the server's OWN `ConnectInfo` (`Status`, `OperationalMode`) into the
                // blocked connector and resume it — `LsaRegisterLogonProcess` returns from there.
                {
                    let outcome = LSA_COMPLETE_PENDING.swap(0, Ordering::Relaxed);
                    if outcome != 0 {
                        let _ = lsa_complete_connect(&mut nt_handler, outcome);
                        bump_progress();
                    }
                }
                // ═══ `\LsaAuthenticationPort` RENDEZVOUS — client CONNECT ════════════════════════
                // The pending connection names lsass' LSA authentication port, so its acceptor is
                // lsass' REAL `AuthPortThreadRoutine` (blocked in `NtReplyWaitReceivePort`), NOT smss'
                // `SmpApiLoop`. Deliver the connection request — carrying the connector's OWN
                // `LSA_CONNECTION_INFO` (`LogonProcessNameBuffer` = "MSGINA", `CreateContext`,
                // `TrustedCaller`) and its real `CLIENT_ID` — into the server's `RequestMsg` and BLOCK
                // the connector until the server's `NtAcceptConnectPort`/`NtCompleteConnectPort` runs
                // (`references/reactos/dll/win32/lsasrv/authport.c:163`).
                if LSA_RENDEZVOUS_ENABLED
                    && nt_handler.lpc_rendezvous_conn != 0
                    && lsa_server_parked()
                    && LSA_CLI_REPLY_CAP.load(Ordering::Relaxed) == 0
                    && LSA_PENDING_CONN.load(Ordering::Relaxed) == 0
                {
                    let name16 = nt_handler.read_lpc_name(m3);
                    if lpc_name_is(&name16, b"\\LsaAuthenticationPort") {
                        let conn_id = nt_handler.lpc_rendezvous_conn;
                        let out_ptr = nt_handler.lpc_rendezvous_out;
                        nt_handler.lpc_rendezvous_conn = 0;
                        // NtConnectPort arg7 = *ConnectionInformation, arg8 = *ConnectionInformationLength.
                        let conn_info_ptr = smss_stack_read(sp + 0x38);
                        let conn_info_len_ptr = smss_stack_read(sp + 0x40);
                        let mut conn_info = [0u8; LSA_CONNECTION_INFO_SIZE];
                        let mut conn_info_len = 0usize;
                        if conn_info_ptr != 0 && conn_info_len_ptr != 0 {
                            let mut raw = [0u8; 4];
                            if nt_handler.xas_read(conn_info_len_ptr, &mut raw) {
                                conn_info_len = (u32::from_le_bytes(raw) as usize)
                                    .min(LSA_CONNECTION_INFO_SIZE);
                                if conn_info_len != 0
                                    && !nt_handler
                                        .xas_read(conn_info_ptr, &mut conn_info[..conn_info_len])
                                {
                                    conn_info_len = 0;
                                }
                            }
                        }
                        let client_pid = nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64;
                        let client_tid = nt_handler.current_tid;
                        LSA_PENDING_CONN.store(conn_id, Ordering::Relaxed);
                        LSA_ACCEPT_DECISION.store(0, Ordering::Relaxed);
                        LSA_COMPLETE_PENDING.store(0, Ordering::Relaxed);
                        if lsa_client_park(
                            1,
                            badge,
                            pi,
                            out_ptr,
                            conn_info_ptr,
                            conn_info_len as u64,
                            resume_ip,
                            sp,
                            flags,
                        ) {
                            let delivered = lsa_server_deliver(
                                &mut nt_handler,
                                LSA_MSG_TYPE_CONNECTION_REQUEST,
                                client_pid,
                                client_tid,
                                &conn_info[..conn_info_len],
                                0,
                            );
                            if delivered {
                                LSA_CONNECT_DELIVERED.fetch_add(1, Ordering::Relaxed);
                                if pi == 2 {
                                    WINLOGON_CRED_LSA_CONNECT.store(1, Ordering::Relaxed);
                                }
                                print_str(b"[lsa-rdv] pi=");
                                print_u64(pi as u64);
                                print_str(b" NtConnectPort(\\LsaAuthenticationPort) conn=");
                                print_u64(conn_id);
                                print_str(b" info=");
                                print_u64(conn_info_len as u64);
                                print_str(b"B -> delivered to the REAL LSA server; connector BLOCKED on the accept\n");
                                bump_progress();
                            } else {
                                let cap = LSA_CLI_REPLY_CAP.swap(0, Ordering::Relaxed);
                                LSA_CLI_KIND.store(0, Ordering::Relaxed);
                                LSA_PENDING_CONN.store(0, Ordering::Relaxed);
                                lsa_wake(cap, 0xC000_0001, resume_ip, sp, flags);
                            }
                            procs[pi].faults = faults;
                            procs[pi].first = first;
                            procs[pi].ntfaults = ntfaults;
                            pfilled[pi] = *filled_pages;
                            let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                            let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                            badge = nb;
                            mi = nmi;
                            m0 = nm0;
                            m1 = nm1;
                            m2 = nm2;
                            m3 = nm3;
                            continue;
                        }
                        // The reply pool is exhausted — restore the pending connect so the legacy
                        // path below reports the wall instead of losing the connection silently.
                        LSA_PENDING_CONN.store(0, Ordering::Relaxed);
                        nt_handler.lpc_rendezvous_conn = conn_id;
                    }
                }
                // Path B (authentic accept): csrss's NtConnectPort left the broker connection Pending
                // (Manual). Drive the REAL SmpApiLoop thread through the connection rendezvous (it runs
                // in smss's VSpace = procs[0].pml4, demand-filling from smss's image + ntdll), then write the
                // completed client comm-port handle to csrss's *PortHandle + reply csrss via REPLY_MAIN.
                if nt_handler.lpc_rendezvous_conn != 0 {
                    let conn_id = nt_handler.lpc_rendezvous_conn;
                    let out_ptr = nt_handler.lpc_rendezvous_out;
                    print_str(b"[sm-rdv] caller pi=");
                    print_u64(pi as u64);
                    print_str(b" NtConnectPort pending (conn=");
                    print_u64(conn_id);
                    print_str(b") -> driving the real SmpApiLoop accept\n");
                    let client_handle = sm_rendezvous(
                        conn_id,
                        pi,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                        procs[csrss_pi].pml4,
                        loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                            .expect("CSRSS PE must be registered before SM rendezvous"),
                        procs[csrss_pi].img_end,
                        &reg,
                        &dll_pes,
                        &mut nt_handler,
                    );
                    if client_handle != 0 {
                        if nt_handler.xas_write_u64(out_ptr, client_handle) {
                            let name16 = nt_handler.read_lpc_name(m3); // RDX = PortName
                            nt_handler.cache_lpc_connection(conn_id, client_handle, &name16);
                            result = 0; // STATUS_SUCCESS
                            print_str(b"[sm-rdv] AUTHENTIC accept complete: client handle=0x");
                            print_hex((client_handle >> 32) as u32);
                            print_hex(client_handle as u32);
                            print_str(b" -> caller NtConnectPort SUCCESS\n");
                        } else {
                            print_str(b"[sm-rdv] WALL: failed client handle copyout\n");
                            handled = false;
                            result = 0xC0000005;
                        }
                    } else {
                        // The rendezvous walled — stop cleanly with a diagnostic (don't hand csrss junk).
                        print_str(b"[sm-rdv] WALL: rendezvous produced no client handle\n");
                        handled = false;
                        result = 0xC0000001;
                        // ★ CREDENTIAL FRONTIER MILESTONE PARK. winlogon arriving here after the
                        // logon dialog took the injected credentials is msgina's
                        // `DoLogon → DoLoginTasks → ConnectToLsa → LsaRegisterLogonProcess`
                        // connecting to `\LsaAuthenticationPort`. Nothing on this boot ACCEPTS that
                        // port (lsass never publishes it), so winlogon would block forever waiting
                        // for the LSA server — a COOPERATIVE wait, not a crash. Park it as a
                        // milestone so its TCB stays live (a crash-park marks the process a dead
                        // win32k callback client and strands the callback plane) and the boot
                        // quiesces at the furthest proven point of the logon.
                        if pi == 2 && winlogon_credential_return_delivered() {
                            let name16 = nt_handler.read_lpc_name(m3);
                            if lpc_name_is(&name16, b"\\LsaAuthenticationPort") {
                                print_str(b"[cred-frontier] msgina DoLogon reached ConnectToLsa(\\LsaAuthenticationPort) with the typed credentials -> MILESTONE park\n");
                                WINLOGON_CRED_LSA_CONNECT.store(1, Ordering::Relaxed);
                                wl_milestone_park = true;
                            }
                        }
                    }
                }
                if nt_handler.sm_request_port != 0 {
                    let completed = sm_api_request_rendezvous(
                        nt_handler.sm_request_port,
                        nt_handler.sm_request_message,
                        nt_handler.sm_reply_message,
                        procs[0].pml4,
                        smss_pe,
                        procs[0].img_end,
                        nt_base,
                        nt_end,
                        ntdll.map(|(_, p)| p),
                        procs[csrss_pi].pml4,
                        loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                            .expect("CSRSS PE must be registered before SM API rendezvous"),
                        procs[csrss_pi].img_end,
                        &reg,
                        &dll_pes,
                        &mut nt_handler,
                    );
                    if completed {
                        result = 0;
                    } else {
                        print_str(b"[sm-api] WALL: synchronous SM request did not complete\n");
                        result = 0xC0000001;
                        handled = false;
                    }
                }
                if nt_handler.csr_request_port != 0 {
                    let csr_request_port = nt_handler.csr_request_port;
                    let csr_request_message = nt_handler.csr_request_message;
                    let csr_reply_message = nt_handler.csr_reply_message;
                    let completed = loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                        .is_some_and(|pe| {
                            csr_api_request_rendezvous(
                                csr_request_port,
                                csr_request_message,
                                csr_reply_message,
                                procs[csrss_pi].pml4,
                                fault_ep,
                                pe,
                                procs[csrss_pi].img_end,
                                nt_base,
                                nt_end,
                                ntdll.map(|(_, p)| p),
                                &reg,
                                &dll_pes,
                                &mut nt_handler,
                            )
                        });
                    if completed {
                        result = 0;
                    } else if CSR_API_RECEIVE_PARKED.load(Ordering::Relaxed) != 0 {
                        print_str(b"[csr-api] real request path unavailable before worker resume -> modeled fallback\n");
                        result = nt_handler.model_csr_request_reply(csr_request_message) as u64;
                    } else {
                        CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[csr-api] real request path failed after worker resume -> failing request\n");
                        result = 0xC0000001;
                        handled = false;
                    }
                }
                // Authentic CSR accept: this client's NtSecureConnectPort left the broker connection
                // Pending (Manual). Drive the REAL CsrApiRequestThread through the connection accept (it
                // runs in csrss's VSpace, demand-filling from csrss's image + the mapped DLLs +
                // ntdll), then write the completed client comm-port handle to this process'
                // *PortHandle. `pml4` is the client; csr_rendezvous takes csrss's PML4 explicitly.
                if nt_handler.csr_rendezvous_conn != 0 {
                    let conn_id = nt_handler.csr_rendezvous_conn;
                    let out_ptr = nt_handler.csr_rendezvous_out;
                    // Only drive the real accept if csrss actually spawned its CsrApiRequestThread
                    // (the CSR runtime TCB record is a real cap > 1). Otherwise recv_full_r12(CSR_FAULT_EP) would block
                    // forever with no faulter. Do not synthesize a handle here: pending
                    // \Windows\ApiPort connects are now required to complete through the real CSR worker.
                    let have_thread = nt_handler
                        .hosted_thread_tcb_for_role(csrss_pi, HostedThreadRole::CsrApi)
                        .is_some()
                        && loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi).is_some();
                    if !have_thread {
                        CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[csr-rdv] no real CSR thread -> failing pending connect\n");
                        result = 0xC0000001;
                        handled = false;
                    } else {
                        print_str(b"[csr-rdv] pi=");
                        print_u64(pi as u64);
                        print_str(b" NtSecureConnectPort pending (conn=");
                        print_u64(conn_id);
                        print_str(b") -> driving the real CsrApiRequestThread accept\n");
                        let client_handle = csr_rendezvous(
                            conn_id,
                            procs[csrss_pi].pml4,
                            loaded_hosted_pe_by_pi(&hosted_loaded_images, csrss_pi)
                                .expect("CSRSS PE must be registered before CSR rendezvous"),
                            procs[csrss_pi].img_end,
                            nt_base,
                            nt_end,
                            ntdll.map(|(_, p)| p),
                            &reg,
                            &dll_pes,
                            &mut nt_handler,
                        );
                        if client_handle == 0 {
                            CSR_RENDEZVOUS_FAILURES.fetch_add(1, Ordering::Relaxed);
                            print_str(b"[csr-rdv] WALL: rendezvous produced no handle -> failing pending connect\n");
                            result = 0xC0000001;
                            handled = false;
                        } else {
                            // AUTHENTIC: the real CSR thread accepted + completed the connection.
                            CSR_AUTHENTIC_ACCEPTS.fetch_add(1, Ordering::Relaxed);
                            CSR_AUTHENTIC_ACCEPT_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
                            nt_handler.cache_lpc_connection(
                                conn_id,
                                client_handle,
                                b"\\Windows\\ApiPort"
                                    .iter()
                                    .map(|&b| b as u16)
                                    .collect::<alloc::vec::Vec<u16>>()
                                    .as_slice(),
                            );
                            print_str(b"[csr-rdv] AUTHENTIC accept complete: client handle=0x");
                            print_hex((client_handle >> 32) as u32);
                            print_hex(client_handle as u32);
                            print_str(b" -> client NtSecureConnectPort SUCCESS\n");
                            if out_ptr != 0 {
                                // Client *PortHandle (&CsrApiPort, an ntdll .data global) — demand-fill window.
                                csrss_out_write(
                                    out_ptr,
                                    client_handle,
                                    &mut *filled_pages,
                                    &mut faults,
                                    scratch_base,
                                    &reg,
                                    &dll_pes,
                                    pml4,
                                );
                            }
                            result = 0; // STATUS_SUCCESS
                        }
                    }
                }
            } else if m0 == 223 {
                // NtSetDefaultHardErrorPort(PortHandle=R10). csrsrv's CsrServerInitialization registers
                // its API port as the hard-error port right after SmConnectToSm succeeds
                // (init.c:1119). No kernel state to model in the host — accept it so CsrServerInit
                // returns and csrss.exe's main continues. (One-time; NtRaiseHardError already routes to
                // our diagnostic path.)
                result = 0; // STATUS_SUCCESS
            } else if m0 == 45 {
                // NtCreateMutant(MutantHandle=R10, DesiredAccess=RDX, ObjectAttributes=R8,
                // InitialOwner=R9). rpcrt4's ncacn_np server init (StartRpcServer) creates sync
                // mutants. Mint a fake handle so the caller can later wait/release it; no real mutant
                // is modeled (the wait/release paths below are no-ops). Additive.
                let out = get_recv_mr(9); // R10 = *MutantHandle
                if out != 0 {
                    let value = FAKE_SYNC_HANDLE.fetch_add(4, Ordering::Relaxed);
                    let _ = client_write_u64_mapped(
                        pi as u64,
                        out,
                        value,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                }
                result = 0;
            } else if m0 == 196 {
                // NtReleaseMutant(196) — legacy modeled object.
                result = 0;
            } else if m0 == 280 && badge != 0 {
                // ★ NtWaitForMultipleObjects(ObjectCount=R10, HandleArray=RDX, WaitType=R8,
                // Alertable=R9, *TimeOut=[sp+0x28]) — REAL array-wait with reply-cap parking (Part 1 of
                // the winlogon rpcrt4 handshake). WaitType 1 = WaitAny, 0 = WaitAll. This is the
                // worker-thread half of the rpcrt4 two-thread handshake: the server WORKER thread
                // (multiplexed via WINLOGON_WORKER_BADGE / SVC/LSASS listeners) runs
                // rpcrt4_protseq_np_wait_for_new_connection = WaitForMultipleObjects([mgr_event,
                // listen_events…]). We resolve the handle array to dispatcher objects:
                //   • WaitAny + any already signalled → immediate WAIT_0+index.
                //   • WaitAll + all signalled → immediate WAIT_0.
                //   • otherwise, if the set contains at least one real waitable object —
                //     the main thread's signal_state_changed SetEvents mgr_event) → PARK on the set
                //     (steal the reply cap, recv next, wake on NtSetEvent). ★ NO-DEADLOCK: only park
                //     when a real event is present; a set of only fake handles → immediate WAIT_0.
                let count = get_recv_mr(9) as usize; // R10 = ObjectCount
                let harr = m3; // RDX = HandleArray
                let wait_type = get_recv_mr(7); // R8 = WaitType (1=Any, 0=All)
                let wait_all = wait_type == 0;
                let mut nev = 0usize;
                let mut any_signalled_idx: i64 = -1; // handle-array index (k) of the first signalled
                let mut any_signalled_obj: usize = 0; // obj_ns idx of that event (for auto-reset)
                let mut any_signalled_real = false;
                let mut all_signalled = true;
                let mut has_real_event = false;
                let mut wait_identities = [u64::MAX; WAITER_MAX_EVENTS];
                let mut wait_error: Option<u32> =
                    if harr == 0 || count == 0 || count > WAITER_MAX_EVENTS || wait_type > 1 {
                        Some(0xC000_000D) // STATUS_INVALID_PARAMETER
                    } else {
                        None
                    };
                let trace = EVENT_TRACE_N.fetch_add(1, Ordering::Relaxed);
                if wait_error.is_none() {
                    for k in 0..count {
                        let h = client_read_u64_mapped(
                            pi as u64,
                            harr + (k as u64) * 8,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                        .unwrap_or(0);
                        match nt_handler.waitable_index_for_handle(h, SYNCHRONIZE_ACCESS) {
                            Ok(idx) => {
                                if trace < 32 {
                                    print_str(b"[event] wait-item k=");
                                    print_u64(k as u64);
                                    print_str(b" h=0x");
                                    print_hex_u64(h);
                                    print_str(b" -> obj=");
                                    print_u64(idx as u64);
                                    print_str(b"\n");
                                }
                                has_real_event = true;
                                park_wait_set[nev] = idx;
                                park_wait_indices[nev] = k as u8;
                                wait_identities[k] = idx as u64;
                                nev += 1;
                                if nt_handler.dispatcher_ready(idx) {
                                    if any_signalled_idx < 0 {
                                        any_signalled_idx = k as i64;
                                        any_signalled_obj = idx;
                                        any_signalled_real = true;
                                    }
                                } else {
                                    all_signalled = false;
                                }
                                continue;
                            }
                            Err(_) if nt_handler.is_legacy_opaque_handle(h) => {
                                if trace < 32 {
                                    print_str(b"[event] wait-item k=");
                                    print_u64(k as u64);
                                    print_str(b" h=0x");
                                    print_hex_u64(h);
                                    print_str(b" -> legacy\n");
                                }
                                // Compatibility sync handles are modeled as permanently signaled.
                                // Preserve their original array position for WaitAny.
                                if any_signalled_idx < 0 {
                                    any_signalled_idx = k as i64;
                                }
                                wait_identities[k] = 0x8000_0000_0000_0000 | h;
                            }
                            Err(status) => {
                                if trace < 32 {
                                    print_str(b"[event] wait-item k=");
                                    print_u64(k as u64);
                                    print_str(b" h=0x");
                                    print_hex_u64(h);
                                    print_str(b" -> status=0x");
                                    print_hex(status);
                                    print_str(b"\n");
                                }
                                wait_error = Some(status);
                                break;
                            }
                        }
                    }
                    if wait_all && wait_error.is_none() {
                        'duplicates: for left in 0..count {
                            for right in left + 1..count {
                                if wait_identities[left] == wait_identities[right] {
                                    wait_error = Some(0xC000_0030); // STATUS_INVALID_PARAMETER_MIX
                                    break 'duplicates;
                                }
                            }
                        }
                    }
                }
                // Consume dispatcher state only after the complete immediate condition is satisfied.
                let timeout_ptr = client_read_u64_mapped(
                    pi as u64,
                    sp + 0x28,
                    filled_pages,
                    faults as usize,
                    scratch_base,
                )
                .unwrap_or(0);
                let wait_due = if timeout_ptr == 0 {
                    None
                } else {
                    Some(nt_delay_execution::due_time(
                        client_read_u64_mapped(
                            pi as u64,
                            timeout_ptr,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                        .unwrap_or(0) as i64,
                        monotonic_time_100ns(),
                        nt_system_time_100ns(),
                    ))
                };
                let zero_timeout = matches!(wait_due, Some(nt_delay_execution::Due::Immediate));
                let finite_deadline = match wait_due {
                    Some(nt_delay_execution::Due::Monotonic100ns(deadline)) => Some(deadline),
                    _ => None,
                };
                if trace < 32 {
                    print_str(b"[event] wait-multi pi=");
                    print_u64(pi as u64);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b" count=");
                    print_u64(count as u64);
                    print_str(if wait_all { b" all" } else { b" any" });
                    print_str(b" real=");
                    print_u64(nev as u64);
                    print_str(if zero_timeout {
                        b" timeout=zero\n"
                    } else if timeout_ptr == 0 {
                        b" timeout=infinite\n"
                    } else {
                        b" timeout=finite\n"
                    });
                }
                if let Some(status) = wait_error {
                    result = status as u64;
                } else if wait_all {
                    if has_real_event && all_signalled {
                        for k in 0..nev {
                            nt_handler.dispatcher_consume(park_wait_set[k]);
                        }
                        result = 0; // WAIT_0 (all satisfied)
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event {
                        park_wait_set_n = nev;
                        park_wait_set_all = true;
                        park_wait_deadline = finite_deadline;
                        result = 0;
                    } else {
                        result = 0; // no real event → immediate WAIT_0 (no live signaler; documented)
                    }
                } else {
                    // WaitAny
                    if any_signalled_idx >= 0 {
                        if any_signalled_real {
                            nt_handler.dispatcher_consume(any_signalled_obj);
                        }
                        result = any_signalled_idx as u64; // WAIT_OBJECT_0 + index
                    } else if zero_timeout {
                        result = 0x102;
                    } else if has_real_event {
                        park_wait_set_n = nev;
                        park_wait_set_all = false;
                        park_wait_deadline = finite_deadline;
                        result = 0;
                    } else {
                        result = 0; // no real event to park on → immediate WAIT_0 (documented)
                    }
                }
            } else if m0 == 19 {
                // NtApphelpCacheControl(Command=R10, Data=RDX). kernel32's CreateProcessInternalW →
                // BasepCheckBadapp → BaseCheckAppcompatCache → BasepShimCacheSearch does
                // NtApphelpCacheControl(ApphelpCacheServiceLookup). Returning SUCCESS means "the image
                // is in the shim cache, known-good" → BaseCheckAppcompatCache returns TRUE → the app is
                // allowed WITHOUT loading apphelp.dll or running the shim engine. No app-compat state is
                // modeled; SUCCESS is the "no shim needed" answer. (BasepShimCacheCheckBypass is a
                // hardcoded FALSE in ReactOS, so this single SUCCESS short-circuits the whole path.)
                result = 0;
            } else if m0 == 195 {
                // NtRegisterThreadTerminatePort(PortHandle=R10). kernel32's CsrNewThread() — the LAST
                // step of BaseDllInitialize after the CSR connect — registers the thread's LPC
                // terminate port (so CSR is told when the thread dies). No terminate-port model in the
                // host → accept it (STATUS_SUCCESS) so winlogon's kernel32 DllMain completes + the
                // loader runs the remaining DllMains toward winlogon's entry.
                result = 0;
            } else if m0 == 280 && badge == 0 {
                // NtWaitForMultipleObjects — smss's main thread waits (WaitAny) on {csrss, winlogon}
                // to die (smss.c:518). In our boot NEITHER dies, so smss's correct terminal state is to
                // block here FOREVER. PARK it (never reply, recv the next event) so the higher-priority
                // winlogon keeps running forward. Returning STATUS_WAIT_0 instead would make smss think
                // csrss/winlogon terminated -> its hard-error teardown path (wrong). This is the
                // designed end of smss's lifetime; the loop now terminates on winlogon's next wall.
                park_caller = true;
                result = 0;
            } else if m0 >= win32k_subsystem::WIN32K_SERVICE_BASE
                && (hosted_non_native_top_level_badge(&nt_handler, badge)
                    || is_wl_worker
                    || (is_tp_worker && pi != 0))
            {
                let dialog_modal_expected_ssn = if pi == 2 {
                    winlogon_dialog_modal_expected_ssn()
                } else {
                    0
                };
                let modal_message_buffer = get_recv_mr(9);
                let dialog_modal_dispatch = dialog_modal_expected_ssn != 0
                    && dialog_modal_expected_ssn == m0
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    );
                if dialog_modal_dispatch {
                    print_str(b"[dialog-pump] routing real modal SSN=");
                    print_hex(m0 as u32);
                    print_str(b"\n");
                    if WINLOGON_KEY_OPENED.load(Ordering::Relaxed)
                        > WINLOGON_KEY_OPENED_AT_INJECT.load(Ordering::Relaxed)
                    {
                        WINLOGON_LOGGED_OUT_SAS_RAN.store(1, Ordering::Relaxed);
                    }
                }
                let sas_hwnd = if pi == 2 {
                    core::ptr::read_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND)
                            as *const u64,
                    )
                } else {
                    0
                };
                if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0
                    && !winlogon_dialog_modal_target_alive()
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    )
                {
                    // A destroyed IDD_LOGON is only an ERROR while nobody has typed into it. Once
                    // the credential keystrokes went in, `EndDialog` destroying it is the dialog
                    // reaching its DECISION — the intended outcome, not a fault.
                    if !winlogon_credential_started() {
                        WINLOGON_DIALOG_MODAL_ERRORS.fetch_add(1, Ordering::Relaxed);
                    }
                    print_str(b"[dialog-pump] correlated IDD_LOGON was destroyed; parking modal GetMessage\n");
                    handled = false;
                    wl_milestone_park = true;
                } else if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && WINLOGON_DIALOG_MODAL_DRAINED.load(Ordering::Relaxed) != 0
                    && winlogon_dialog_modal_thread_matches(
                        badge,
                        current_tid,
                        modal_message_buffer,
                    )
                {
                    // ★ HEADLESS CREDENTIAL INPUT. The dialog is painted and its pump is about to
                    // block for a keystroke nobody can type. Post real WM_CHARs / VK_RETURN into
                    // its real edit control through the REAL NtUserPostMessage (exactly the shim
                    // that stands in for Ctrl-Alt-Del), then let this GetMessage run — the queue is
                    // non-empty, so it returns instead of blocking win32k. When there is nothing
                    // left to type the blocking GetMessage is parked as before.
                    let peb_mirror = hosted_peb_mirror_for_pi(2);
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    let route =
                        winlogon_credential_injection_route(win32k_client_context_for_thread(
                            &nt_handler,
                            pi,
                            badge,
                            nt_handler.current_tid,
                            hosted_thread_tcb_or_zero(&nt_handler, nt_handler.current_tid),
                            nt_handler.hosted_thread_role(nt_handler.current_tid),
                            client_teb,
                            peb_mirror,
                            scratch_base,
                        ));
                    if !route {
                        print_str(b"[dialog-pump] real IDD_LOGON queue drained; parking its blocking GetMessage\n");
                        handled = false;
                        wl_milestone_park = true;
                    }
                } else if pi == 2
                    && m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && sas_hwnd != 0
                    && m3 == sas_hwnd
                    && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0
                {
                    let n = WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
                    if n == 0 {
                        print_str(b"[wl-main] winlogon entered its SAS message loop; routing real GetMessage for posted WLX_WM_SAS\n");
                    } else {
                        wl_park_defer_quiesce =
                            userinit_shell_frontier_pending(&nt_handler, crash_parked, wait_parked);
                        print_str(if wl_park_defer_quiesce {
                            b"[wl-main] SAS queue empty at main-loop GetMessage -> parking while userinit advances to shell frontier\n"
                        } else {
                            b"[wl-main] SAS queue empty at main-loop GetMessage -> parking\n"
                        });
                        handled = false;
                        wl_milestone_park = true;
                    }
                } else if m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                    && GET_MESSAGE_EMPTY_QUEUE_GUARD
                {
                    // ★ BATCH 58 — THE GENERAL RULE: A BLOCKING `NtUserGetMessage` MUST NEVER BE
                    // DISPATCHED INTO win32k ON AN EMPTY QUEUE.
                    //
                    // The executive's service loop is SINGLE-THREADED and win32k is a component it
                    // drives synchronously, so `co_IntGetPeekMessage`'s wait does not block one
                    // thread — it blocks THE WHOLE SYSTEM, permanently. And because the loop is then
                    // stuck inside `win32k_dispatch`'s recv, the wall-clock stall watchdog at the
                    // loop top never runs either, so the boot can never even quiesce to the gate.
                    // MEASURED (batch 58, `PROVISION_DEFAULT_USER_PROFILE = true`): the profile
                    // flow's `Error: 87` puts up a real userenv MessageBox whose modal pump calls
                    // GetMessage on a window no existing special case covers; the boot went
                    // COMPLETELY SILENT at t=310 s and was killed at 555 s (`RUNEXIT=124`). It was
                    // never "more UI work costing more time" — the log's last line is a `0x1006`
                    // dispatch with no reply, and host-side timestamps show ZERO output for the
                    // remaining 245 s.
                    //
                    // The rule is NT's own definition of GetMessage — *peek, and only then wait* —
                    // so ask win32k the non-blocking half FIRST, with the caller's real arguments
                    // and `PM_NOREMOVE` (the message stays queued for the GetMessage that follows).
                    // A non-empty queue dispatches exactly as before (byte-identical behaviour); an
                    // EMPTY queue — the only case that could hang — takes the established milestone
                    // park, so the boot quiesces and the gate runs. This subsumes the special-cased
                    // parks above rather than competing with them: it is the LAST arm of the chain.
                    let sp = get_recv_mr(16);
                    let peb_mirror = hosted_peb_mirror_for_pi(pi);
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    // The caller's own NtUserGetMessage(MSG* [R10], HWND [RDX], min [R8], max [R9]);
                    // NtUserPeekMessage takes the same four plus wRemoveMsg on the stack.
                    W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
                    let client = win32k_client_context_for_thread(
                        &nt_handler,
                        pi,
                        badge,
                        nt_handler.current_tid,
                        hosted_thread_tcb_or_zero(&nt_handler, nt_handler.current_tid),
                        nt_handler.hosted_thread_role(nt_handler.current_tid),
                        client_teb,
                        peb_mirror,
                        scratch_base,
                    );
                    let peek = dispatch_win32k_for_client(
                        &mut nt_handler,
                        nt_user_callback::NTUSER_PEEK_MESSAGE_SSN,
                        get_recv_mr(9),
                        m3,
                        get_recv_mr(7),
                        get_recv_mr(8),
                        sp,
                        &[0u64], // wRemoveMsg = PM_NOREMOVE: look, do not consume
                        client,
                    );
                    GET_MESSAGE_PREFLIGHT_PEEKS.fetch_add(1, Ordering::Relaxed);
                    if peek.0 == 0 {
                        let main_tid = nt_handler
                            .pm_main_tid_for_pi(pi)
                            .map(u64::from)
                            .unwrap_or(0);
                        if !post_winlogon_second_sas_after_welcome_drain(
                            pi,
                            badge,
                            current_tid,
                            hosted_thread_tcb_or_zero(&nt_handler, current_tid),
                            nt_handler.hosted_thread_role(current_tid),
                            nt_handler.hosted_process_role(pi),
                            nt_handler.hosted_process_top_badge(pi).unwrap_or(0),
                            main_tid,
                            nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                            client_teb,
                            peb_mirror,
                            scratch_base,
                        ) {
                            let n = GET_MESSAGE_EMPTY_QUEUE_PARKS.fetch_add(1, Ordering::Relaxed);
                            // ★ WHOSE park ends the boot. winlogon's MAIN thread (badge 4) running out
                            // of messages is the established terminal condition — it is the thread that
                            // drives the logon, so its empty SAS loop means winlogon has nothing left.
                            // A WORKER thread's pump running dry does NOT: measured, the profile copy
                            // runs on the MAIN thread while worker badge 13 pumps the desktop, so
                            // quiescing on the worker's park CUT THE `CopyDirectory` OFF MID-TREE.
                            // Park the worker and keep the loop running so the main thread advances;
                            // the grace is BOUNDED so a boot where nothing else can run still reaches
                            // the gate rather than blocking in the loop's recv forever.
                            const EMPTY_QUEUE_PARK_GRACE: u64 = 3;
                            let winlogon_top_badge = hosted_top_badge_for_role(
                                &nt_handler,
                                nt_exe_image::HostedProcessRole::InteractiveLogon,
                            )
                            .expect("winlogon hosted metadata must be registered before GUI pump");
                            let userinit_top_badge = hosted_top_badge_for_role(
                                &nt_handler,
                                nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
                            )
                            .expect("userinit hosted metadata must be registered before GUI pump");
                            let defer = (badge != winlogon_top_badge
                                && badge != userinit_top_badge
                                && n < EMPTY_QUEUE_PARK_GRACE)
                                || (owner_top_badge_for(&nt_handler, badge) != userinit_top_badge
                                    && userinit_shell_frontier_pending(
                                        &nt_handler,
                                        crash_parked,
                                        wait_parked,
                                    ));
                            if n < 8 {
                                print_str(b"[wl-main] blocking GetMessage on an EMPTY queue (pi=");
                                print_u64(pi as u64);
                                print_str(b" badge=");
                                print_u64(badge);
                                print_str(b" hwnd-filter=0x");
                                print_hex(m3 as u32);
                                print_str(if defer {
                                    b") -> parking this thread, loop continues\n"
                                } else {
                                    b") -> parking instead of hanging win32k\n"
                                });
                            }
                            handled = false;
                            wl_milestone_park = true;
                            wl_park_defer_quiesce = defer;
                        }
                    }
                }
                // Tell win32k_dispatch WHICH client this call belongs to (csrss pi 1 / winlogon pi 2 /
                // services pi 3 / lsass pi 4) so it attaches win32k's client window to this client's frames
                // (per-client cross-AS client memory — services' OBJECT_ATTRIBUTES / USERCONNECT
                // resolve to SERVICES' frames, not the stale csrss/winlogon frame at the same VA).
                // The w32_client_attach / csrss_frame_get / map_win32k_heap_into_csrss machinery is
                // fully pi-keyed (bit `1<<pi`), so a 3rd GUI client needs no new state — same recipe
                // that made winlogon the 2nd client. The reply is caller-agnostic: REPLY_MAIN is
                // bound to THIS caller at its recv, so it resumes exactly services (no reply-spin).
                W32_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
                // ★ (B) SPIN WATCHDOG. A GUI client can live-lock a run of win32k calls that never
                // terminates — either all WALLing (csrss's user32 RegisterSystemClasses hammering
                // NtUserFindExistingCursorIcon 0x103d / NtUserRegisterClassExWOW 0x10b4 when win32k
                // asserts) OR each returning STATUS_SUCCESS yet never satisfying the loop condition (the
                // assert-skips leave win32k's class table inconsistent so the same cursor/class is
                // re-registered forever). It keeps issuing syscalls so it is neither crash- nor
                // wait-parked → without this it spins the shared loop to the TCG timeout and the boot
                // never reaches the gate. A TOTAL per-client win32k-dispatch budget catches BOTH cases:
                // a client's real win32k init is bounded (a few hundred calls), so past a generous
                // ceiling it is a live-lock → PARK the client (like a crash) so the loop quiesces + the
                // gate runs. General: applies to any client (winlogon's paint fires well under the cap).
                {
                    // Real cursor/icon/OBM callbacks run bounded resource-load bursts before SAS;
                    // dispatching the first real SAS then starts welcome-dialog construction, whose child
                    // creation and layout legitimately cross the historical 500-call ceiling before
                    // IDD_LOGON can be correlated. Grant only a bounded bridge after both the dequeued
                    // SAS and a real post-SAS dialog creation; reserve the larger burst for the exact
                    // correlated credential dialog.
                    const W32_TOTAL_LIMIT: u64 = 500;
                    const W32_RESOURCE_CALLBACK_LIMIT: u64 = 1536;
                    const W32_POST_SAS_DIALOG_LIMIT: u64 = 2048;
                    const W32_IDD_LOGON_LIMIT: u64 = 4096;
                    // Explorer's first real shell window startup legitimately crosses the generic
                    // 500-dispatch budget now that userinit launches the real process and user32/ATL
                    // run callbacks instead of the old synthetic create path. Keep it bounded, but
                    // do not kill the shell midway through its WM_NCCREATE/WM_CREATE burst.
                    const W32_EXPLORER_STARTUP_LIMIT: u64 = 2048;
                    // Typing credentials into the painted dialog is a second bounded burst: every
                    // character runs the real edit control's caret/invalidate/repaint cycle on top
                    // of the dialog's own pump. Grant the headroom only once keystrokes are in.
                    const W32_CREDENTIAL_LIMIT: u64 = 12288;
                    let limit = if pi == 2 && winlogon_credential_started() {
                        W32_CREDENTIAL_LIMIT
                    } else if pi == 2 && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0 {
                        W32_IDD_LOGON_LIMIT
                    } else if pi == 2
                        && WINLOGON_SAS1_RETRIEVED.load(Ordering::Relaxed) != 0
                        && WINLOGON_DIALOG_WINDOWS.load(Ordering::Relaxed) != 0
                    {
                        W32_POST_SAS_DIALOG_LIMIT
                    } else if pi == 2 && win32k_glue::real_resource_callback_started() {
                        W32_RESOURCE_CALLBACK_LIMIT
                    } else if pi == 6 && EXPLORER_SPAWNED.load(Ordering::Relaxed) != 0 {
                        W32_EXPLORER_STARTUP_LIMIT
                    } else {
                        W32_TOTAL_LIMIT
                    };
                    let total = W32_TOTAL_DISPATCH[pi].fetch_add(1, Ordering::Relaxed) + 1;
                    // FORWARD-PROGRESS CENSUS: the win32k SHADOW table lands in the same per-process
                    // histogram as the native table (high half). Without this the census could see
                    // only the native syscalls, and every "the UI work grew" claim about a win32k
                    // frontier was unmeasured by construction.
                    {
                        let bucket = ssn_bucket(m0);
                        match pi {
                            4 => LSASS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                            2 => WINLOGON_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                            1 => CSRSS_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                            6 => EXPLORER_SSN_HIST[bucket].fetch_add(1, Ordering::Relaxed),
                            _ => 0,
                        };
                        // …and the WALL-CLOCK, which is the whole point: this arm runs a nested
                        // pump, so the main loop's badge census cannot see any of the time spent
                        // here. It also ticks the periodic dump, so a non-quiescing boot reports.
                        w32_census_enter(m0);
                    }
                    if total >= limit {
                        print_str(b"[w32-spin] pi=");
                        print_u64(pi as u64);
                        print_str(b" badge=");
                        print_u64(badge);
                        print_str(b" last SSN=0x");
                        print_hex(m0 as u32);
                        print_str(b" exceeded ");
                        print_u64(total);
                        print_str(b" total win32k dispatches (live-lock) -> PARK\n");
                        park_and_log!(pi, b"win32k-spin", m0, m0);
                    }
                }
                // Phase 2c Milestone C: a win32k NtUser/NtGdi system call (SSN >= 0x1000) issued by
                // csrss (winsrv's UserServerDllInitialization) OR by winlogon (its user32 DllMain's
                // NtUserProcessConnect + WinMain's window-station/desktop calls) — the SECOND hosted
                // GUI client. Forward it to the parked win32k component through the persistent dispatch
                // loop; the handler runs in win32k's OWN context (GS=KPCR / session heap). Both clients
                // are serviced ONE AT A TIME by the main loop (FIFO recv), each bound to REPLY_MAIN at
                // its recv, so the reply (client_reply_on(REPLY_MAIN)) resumes exactly this caller
                // — csrss and winlogon never orphan each other. Scalar + handle args ride the registers
                // exactly as the native x64 syscall passed them (arg1=R10, arg2=RDX, arg3=R8, arg4=R9);
                // pointer/buffer args are marshaled per SSN as needed. Per-process stack/heap/image
                // mirrors are already selected by `pi` above (smss_stack_read reaches winlogon's stack).
                let a0 = get_recv_mr(9); // R10 = arg1
                let a1 = m3; // RDX = arg2
                let a2 = get_recv_mr(7); // R8 = arg3
                let a3 = get_recv_mr(8); // R9 = arg4
                let sp = get_recv_mr(16); // real syscall-entry RSP for win32k stack args
                                          // NtUserInitialize(dwWinVersion=a0, hPowerRequestEvent=a1, hMediaRequestEvent=a2):
                                          // winsrv created these events via NtCreateEvent into its own image globals. Forward
                                          // exactly what the caller supplied; no executive-side substitution is permitted.
                if m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE_REAL {
                    print_str(b"[ntuser-init] raw power=0x");
                    print_hex((a1 >> 32) as u32);
                    print_hex(a1 as u32);
                    print_str(b" media=0x");
                    print_hex((a2 >> 32) as u32);
                    print_hex(a2 as u32);
                    print_str(b"\n");
                }
                // CROSS-AS ARG MARSHALING. NtUserProcessConnect(handle, USERCONNECT* buf, size): the
                // buffer is a client user pointer (usually its stack) NOT mapped in win32k's VSpace.
                // Passing it raw makes win32k's handler fault/spin on an address win32k_dispatch can't
                // resolve. Copy the caller's input buffer into the shared ARG frame (mapped in BOTH),
                // dispatch with the ARG-frame pointer, then copy win32k's out-params back to the same
                // caller process.
                let has_buf = m0 == win32k_subsystem::SSN_NT_USER_INITIALIZE; // 0x10FA = NtUserProcessConnect
                let current_pid = nt_handler.pm_pid_for_pi(pi);
                let mut d_a0 = if has_buf
                    && (a0 == 0xFFFF_FFFF_FFFF_FFFF
                        || (current_pid.is_some()
                            && nt_handler.resolve_process_handle(a0) == current_pid))
                {
                    // The component's Ob layer accepts only this narrow connect handle for the
                    // current process. Real handles must be resolved by ProcessManager before they are
                    // translated, so arbitrary process-typed values cannot alias to the current EPROCESS.
                    win32k_subsystem::FAKE_PROCESS_HANDLE
                } else {
                    a0
                };
                let (mut d_a1, blen) = if has_buf {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    let n = a2.min(win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000);
                    core::ptr::write_bytes(
                        arg as *mut u8,
                        0,
                        (win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000) as usize,
                    );
                    let input = core::slice::from_raw_parts_mut(arg as *mut u8, n as usize);
                    if !img_spawn::client_copyin_mapped(
                        pi as u64,
                        a1,
                        input,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    ) {
                        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                        if failures < 8 {
                            print_str(
                                b"[win32k-svc] NtUserProcessConnect USERCONNECT copy-in failed pi=",
                            );
                            print_u64(pi as u64);
                            print_str(b" buffer=0x");
                            print_hex((a1 >> 32) as u32);
                            print_hex(a1 as u32);
                            print_str(b" bytes=");
                            print_u64(n);
                            print_str(b"\n");
                        }
                    }
                    (arg, n)
                } else {
                    (a1, 0)
                };
                let msg_syscall = pi == 6
                    && a0 != 0
                    && (m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                        || m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
                        || m0 == nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN);
                let msg_returns_to_client = msg_syscall
                    && (m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                        || m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN);
                if msg_syscall {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    if msg_returns_to_client {
                        core::ptr::write_bytes(arg as *mut u8, 0, WIN32K_MSG_BYTES);
                        d_a0 = arg;
                    } else {
                        let input =
                            core::slice::from_raw_parts_mut(arg as *mut u8, WIN32K_MSG_BYTES);
                        if img_spawn::client_copyin_process_mapped(
                            pi as u64,
                            a0,
                            input,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                            false,
                        ) {
                            d_a0 = arg;
                        } else {
                            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                            if failures < 8 {
                                print_str(b"[win32k-svc] explorer MSG copy-in failed ssn=0x");
                                print_hex(m0 as u32);
                                print_str(b" buffer=0x");
                                print_hex_u64(a0);
                                print_str(b"\n");
                            }
                        }
                    }
                }
                // BATCH 43: throttle the per-dispatch header for the HIGH-FREQUENCY class-registration
                // loop SSNs (0x103d NtUserFindExistingCursorIcon / 0x10b4 NtUserRegisterClassExWOW), which
                // each fire dozens of times during user32 RegisterSystemClasses. Serial writes dominate the
                // TCG per-round-trip cost and the boot budget is tight now that winlogon crosses its win32k
                // wall (BATCH 43). Print the first 6 of each, then suppress; all OTHER SSNs always print.
                let w32_hot = m0 == 0x103d || m0 == 0x10b4;
                let w32_log = !w32_hot || W32_HOT_LOG.fetch_add(1, Ordering::Relaxed) < 12;
                if w32_log {
                    print_str(b"[win32k-svc] ");
                    print_str(win32k_client_label(&nt_handler, pi));
                    print_str(b" -> SSN 0x");
                    print_hex(m0 as u32);
                    print_str(b" (dispatch)\n");
                }
                // ── NT ARGUMENT CAPTURE for `NtUserRegisterClassExWOW` (SSN 0x10b4).
                // a1 = ClassName and a2 = ClsVersion are client `PUNICODE_STRING`s whose descriptor
                // and `Buffer` both belong to the caller's address space. Real NT probes and captures
                // them before win32k consumes them. Do the same at the executive's cross-VSpace boundary:
                // stage a bounded descriptor for atoms/resources too, and stage readable nonzero buffers
                // regardless of whether they live in the main image, a DLL, stack, or heap.
                //
                // The shared ARG frame is mapped in both VSpaces (already the proven mechanism for
                // `NtUserProcessConnect`). If a string graph is unreadable or oversized, the original
                // pointer is forwarded and win32k's normal probe/error path decides the result.
                let mut d_a2 = a2;
                let mut d_a3 = a3;
                let mut register_class_stack_args = [0u64; 3];
                let mut register_class_stack_arg_count = 0usize;
                let mut create_window_stack_args = [0u64; 11];
                let mut create_window_stack_arg_count = 0usize;
                let mut create_window_probe_failed = false;
                let mut open_dcw_stack_args = [0u64; 3];
                let mut open_dcw_stack_arg_count = 0usize;
                let mut open_dcw_dhpdev_copyout = (0u64, 0u64);
                let mut build_hwnd_list_stack_args = [0u64; 3];
                let mut build_hwnd_list_stack_arg_count = 0usize;
                let mut build_hwnd_list_copyout = (0u64, 0u64, 0u64, 0u64);
                let mut create_bitmap_stack_args = [0u64; 1];
                let mut create_bitmap_stack_arg_count = 0usize;
                let mut create_bitmap_probe_failed = false;
                let mut text_extent_stack_args = [0u64; 4];
                let mut text_extent_stack_arg_count = 0usize;
                let mut text_extent_copyout = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0usize);
                let mut text_extent_probe_failed = false;
                if m0 == 0x10b4 {
                    d_a1 = capture_client_string_arg(
                        pi as u64,
                        d_a1,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    d_a2 = capture_client_string_arg(
                        pi as u64,
                        d_a2,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if sp != 0 {
                        let fn_id = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x28,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let class_flags = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x30,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let p_wow = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x38,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        if let (Some(fn_id), Some(class_flags), Some(p_wow)) =
                            (fn_id, class_flags, p_wow)
                        {
                            register_class_stack_args = [fn_id, class_flags, p_wow];
                            register_class_stack_arg_count = register_class_stack_args.len();
                        }
                    }
                } else if m0 == 0x1036 {
                    // NtUserRegisterWindowMessage takes one client PUNICODE_STRING. ReactOS probes and
                    // captures it before adding the atom; isolated win32k needs the same cross-VSpace
                    // capture or shell message registration can fault on a foreign user pointer while
                    // inside an explorer callback.
                    let captured = capture_client_string_arg(
                        pi as u64,
                        d_a0,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if captured != d_a0 {
                        d_a0 = captured;
                        if pi == 6 {
                            EXPLORER_REGISTER_WINDOW_MESSAGE_CAPTURES
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else if m0 == 0x101b && sp != 0 {
                    // NtUserBuildHwndList writes both the needed count and the HWND array through
                    // caller-owned user pointers. Isolated win32k cannot safely probe those VAs
                    // directly, so stage the outputs in the shared ARG page and copy the real
                    // win32k result back after dispatch. ReactOS' win32k table exposes seven
                    // service arguments, while the Vista/Wine user32 path calls an eight-argument
                    // wrapper with an extra TRUE before dwThreadId; normalize that shape here.
                    let tail0 = client_read_u64_mapped(
                        pi as u64,
                        sp + 0x28,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    let tail1 = client_read_u64_mapped(
                        pi as u64,
                        sp + 0x30,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    let tail2 = client_read_u64_mapped(
                        pi as u64,
                        sp + 0x38,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    let tail3 = client_read_u64_mapped(
                        pi as u64,
                        sp + 0x40,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if let (Some(tail0), Some(tail1), Some(tail2)) = (tail0, tail1, tail2) {
                        let eight_arg_shape = tail3.is_some_and(|needed| {
                            a3 <= 1
                                && tail1 != 0
                                && tail1 <= 0x0001_0000
                                && tail2 >= 0x0001_0000
                                && needed >= 0x0001_0000
                        });
                        let (thread_id, c_hwnd, client_list, client_needed, shape) =
                            if eight_arg_shape {
                                (tail0, tail1, tail2, tail3.unwrap_or(0), 8u64)
                            } else {
                                (a3, tail0, tail1, tail2, 7u64)
                            };
                        if client_needed != 0 {
                            let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                            let staged_list = arg;
                            let staged_needed = arg + WIN32K_BUILD_HWND_LIST_COUNT_OFFSET;
                            let c_hwnd_forwarded = c_hwnd.min(WIN32K_BUILD_HWND_LIST_MAX_HANDLES);
                            core::ptr::write_bytes(
                                staged_list as *mut u8,
                                0,
                                WIN32K_BUILD_HWND_LIST_STAGE_BYTES,
                            );
                            d_a3 = thread_id;
                            build_hwnd_list_stack_args = [
                                c_hwnd_forwarded,
                                if client_list != 0 && c_hwnd_forwarded != 0 {
                                    staged_list
                                } else {
                                    0
                                },
                                staged_needed,
                            ];
                            build_hwnd_list_stack_arg_count = build_hwnd_list_stack_args.len();
                            build_hwnd_list_copyout =
                                (client_list, staged_list, client_needed, c_hwnd_forwarded);

                            let n = BUILD_HWND_LIST_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                            if n < 8 {
                                print_str(b"[w32marshal] NtUserBuildHwndList pi=");
                                print_u64(pi as u64);
                                print_str(b" shape=");
                                print_u64(shape);
                                print_str(b" tid=");
                                print_u64(thread_id);
                                print_str(b" c=");
                                print_u64(c_hwnd);
                                print_str(b" forwarded=");
                                print_u64(c_hwnd_forwarded);
                                print_str(b" list=0x");
                                print_hex_u64(client_list);
                                print_str(b" needed=0x");
                                print_hex_u64(client_needed);
                                print_str(b"\n");
                            }
                        }
                    }
                } else if m0 == 0x106c && sp != 0 && hosted_process_uses_client_gdi(&nt_handler, pi)
                {
                    // NtGdiCreateBitmap's fifth argument is an optional client pointer to
                    // initialized bitmap bits. ReactOS probes and copies that range before
                    // UnsafeSetBitmapBits; isolated win32k must receive a pointer in its own address
                    // space, not a raw hosted-client VA that may later collapse inside EngCopyBits.
                    let bits = client_read_u64_mapped(
                        pi as u64,
                        sp + 0x28,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if let Some(bits) = bits {
                        create_bitmap_stack_args = [0];
                        create_bitmap_stack_arg_count = create_bitmap_stack_args.len();
                        let size = ntgdi_create_bitmap_bits_size(a0, a1, a2, a3);
                        if bits != 0 {
                            if let Some(bytes) = size {
                                if bytes <= WIN32K_CREATE_BITMAP_STAGE_BYTES {
                                    prefill_client_copyin_dll_range_pages(
                                        pi as u64,
                                        bits,
                                        bytes,
                                        scratch_base,
                                        &reg,
                                        &dll_pes,
                                    );
                                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                                    core::ptr::write_bytes(
                                        arg as *mut u8,
                                        0,
                                        WIN32K_CREATE_BITMAP_STAGE_BYTES,
                                    );
                                    let input =
                                        core::slice::from_raw_parts_mut(arg as *mut u8, bytes);
                                    if img_spawn::client_copyin_mapped(
                                        pi as u64,
                                        bits,
                                        input,
                                        filled_pages,
                                        faults as usize,
                                        scratch_base,
                                    ) {
                                        create_bitmap_stack_args = [arg];
                                        let n = CREATE_BITMAP_MARSHAL_TRACE
                                            .fetch_add(1, Ordering::Relaxed);
                                        if n < 24 {
                                            print_str(b"[w32marshal] NtGdiCreateBitmap pi=");
                                            print_u64(pi as u64);
                                            print_str(b" ");
                                            print_u64(a0 as u32 as u64);
                                            print_str(b"x");
                                            print_u64(a1 as u32 as u64);
                                            print_str(b" planes=");
                                            print_u64(a2 as u32 as u64);
                                            print_str(b" bpp=");
                                            print_u64(a3 as u32 as u64);
                                            print_str(b" bits=0x");
                                            print_hex_u64(bits);
                                            print_str(b" bytes=");
                                            print_u64(bytes as u64);
                                            print_str(b"\n");
                                        }
                                    } else {
                                        create_bitmap_probe_failed = true;
                                    }
                                } else {
                                    create_bitmap_probe_failed = true;
                                }
                            }
                        } else {
                            let n = CREATE_BITMAP_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                            if n < 24 {
                                print_str(b"[w32marshal] NtGdiCreateBitmap explicit-null pi=");
                                print_u64(pi as u64);
                                print_str(b" ");
                                print_u64(a0 as u32 as u64);
                                print_str(b"x");
                                print_u64(a1 as u32 as u64);
                                print_str(b" planes=");
                                print_u64(a2 as u32 as u64);
                                print_str(b" bpp=");
                                print_u64(a3 as u32 as u64);
                                print_str(b"\n");
                            }
                        }
                    } else {
                        create_bitmap_probe_failed = true;
                    }
                } else if m0 == 0x11d9 && hosted_process_uses_client_gdi(&nt_handler, pi) {
                    // NtGdiGetTextExtentExW has one client input buffer and three possible output
                    // buffers in its stack tail. Isolated win32k must see only win32k-owned VAs; the
                    // executive copies results back to the hosted client after a TRUE service return.
                    let fit = if sp != 0 {
                        client_read_u64_mapped(
                            pi as u64,
                            sp + 0x28,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                    } else {
                        None
                    };
                    let dx = if sp != 0 {
                        client_read_u64_mapped(
                            pi as u64,
                            sp + 0x30,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                    } else {
                        None
                    };
                    let size = if sp != 0 {
                        client_read_u64_mapped(
                            pi as u64,
                            sp + 0x38,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                    } else {
                        None
                    };
                    let fl = if sp != 0 {
                        client_read_u64_mapped(
                            pi as u64,
                            sp + 0x40,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        )
                    } else {
                        None
                    };
                    if let (Some(fit), Some(dx), Some(size), Some(fl)) = (fit, dx, size, fl) {
                        let count = a2 as u32;
                        let count_negative = (count as i32) < 0;
                        let wants_fit = fit != 0 && count != 0;
                        let wants_dx = dx != 0 && count != 0;
                        let string_bytes = (count as usize).checked_mul(2);
                        let dx_bytes = if wants_dx {
                            (count as usize).checked_mul(4)
                        } else {
                            Some(0)
                        };
                        if count_negative || size == 0 || (count != 0 && d_a1 == 0) {
                            text_extent_probe_failed = true;
                        } else if let (Some(string_bytes), Some(dx_bytes)) =
                            (string_bytes, dx_bytes)
                        {
                            let base = win32k_subsystem::WIN32K_ARG_VADDR;
                            let cap = WIN32K_TEXT_EXTENT_STAGE_BYTES as u64;
                            let staged_string = if count != 0 { base } else { 0 };
                            let mut offset = string_bytes as u64;
                            let mut layout_ok = true;
                            if let Some(next) = align_up_u64(offset, 8) {
                                offset = next;
                            } else {
                                layout_ok = false;
                            }
                            let staged_fit = if layout_ok && wants_fit {
                                let out = base + offset;
                                if let Some(next) = align_up_u64(offset + 4, 8) {
                                    offset = next;
                                } else {
                                    layout_ok = false;
                                }
                                out
                            } else {
                                0
                            };
                            let staged_dx = if layout_ok && wants_dx {
                                let out = base + offset;
                                if let Some(next) = align_up_u64(offset + dx_bytes as u64, 8) {
                                    offset = next;
                                } else {
                                    layout_ok = false;
                                }
                                out
                            } else {
                                0
                            };
                            let staged_size = if layout_ok {
                                let out = base + offset;
                                offset += 8;
                                out
                            } else {
                                0
                            };
                            if !layout_ok || offset > cap {
                                text_extent_probe_failed = true;
                            } else {
                                core::ptr::write_bytes(
                                    base as *mut u8,
                                    0,
                                    WIN32K_TEXT_EXTENT_STAGE_BYTES,
                                );
                                let copied_string = if count == 0 {
                                    true
                                } else {
                                    prefill_client_copyin_dll_range_pages(
                                        pi as u64,
                                        d_a1,
                                        string_bytes,
                                        scratch_base,
                                        &reg,
                                        &dll_pes,
                                    );
                                    let input = core::slice::from_raw_parts_mut(
                                        staged_string as *mut u8,
                                        string_bytes,
                                    );
                                    img_spawn::client_copyin_mapped(
                                        pi as u64,
                                        d_a1,
                                        input,
                                        filled_pages,
                                        faults as usize,
                                        scratch_base,
                                    )
                                };
                                if copied_string {
                                    d_a1 = staged_string;
                                    text_extent_stack_args =
                                        [staged_fit, staged_dx, staged_size, fl];
                                    text_extent_stack_arg_count = text_extent_stack_args.len();
                                    text_extent_copyout = (
                                        if wants_fit { fit } else { 0 },
                                        staged_fit,
                                        if wants_dx { dx } else { 0 },
                                        staged_dx,
                                        size,
                                        staged_size,
                                        dx_bytes,
                                    );
                                    let n =
                                        TEXT_EXTENT_MARSHAL_TRACE.fetch_add(1, Ordering::Relaxed);
                                    if n < 24 {
                                        print_str(b"[w32marshal] NtGdiGetTextExtentExW pi=");
                                        print_u64(pi as u64);
                                        print_str(b" count=");
                                        print_u64(count as u64);
                                        print_str(b" str=0x");
                                        print_hex_u64(a1);
                                        print_str(b" fit=0x");
                                        print_hex_u64(fit);
                                        print_str(b" dx=0x");
                                        print_hex_u64(dx);
                                        print_str(b" size=0x");
                                        print_hex_u64(size);
                                        print_str(b" bytes=");
                                        print_u64(offset);
                                        print_str(b"\n");
                                    }
                                } else {
                                    text_extent_probe_failed = true;
                                }
                            }
                        } else {
                            text_extent_probe_failed = true;
                        }
                    } else {
                        text_extent_probe_failed = true;
                    }
                } else if m0 == 0x10de && pi != 3 && pi != 4 {
                    // NtGdiOpenDCW probes/copies the caller's optional device name before opening
                    // the DC. Capture interactive clients' counted strings at the executive boundary
                    // so nested GDI calls from user callbacks do not hand isolated win32k a foreign
                    // user VA. Non-interactive services take the light path below.
                    d_a0 = capture_client_string_arg(
                        pi as u64,
                        d_a0,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    d_a2 = capture_client_string_arg(
                        pi as u64,
                        d_a2,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    d_a1 = capture_client_devmodew_arg(
                        pi as u64,
                        d_a1,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if sp != 0 {
                        let b_display = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x28,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let hspool = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x30,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let dhpdev_out = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x38,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        if let (Some(b_display), Some(hspool), Some(dhpdev_out)) =
                            (b_display, hspool, dhpdev_out)
                        {
                            if dhpdev_out != 0 {
                                let slot = RC_ARG_CAPTURE_NEXT.fetch_add(1, Ordering::Relaxed)
                                    % RC_ARG_CAPTURE_SLOTS;
                                let staged_out = rc_arg_slot_base(slot);
                                core::ptr::write_bytes(
                                    staged_out as *mut u8,
                                    0,
                                    RC_ARG_CAPTURE_SLOT as usize,
                                );
                                open_dcw_stack_args = [b_display, hspool, staged_out];
                                open_dcw_stack_arg_count = open_dcw_stack_args.len();
                                open_dcw_dhpdev_copyout = (dhpdev_out, staged_out);
                            }
                        }
                    }
                } else if m0 == 0x1077 {
                    // `NtUserCreateWindowEx` takes LARGE_STRING ClassName/ClsVersion/WindowName.
                    if sp == 0 {
                        create_window_probe_failed = true;
                    } else {
                        let mut tail_ok = true;
                        let mut i = 0usize;
                        while i < create_window_stack_args.len() {
                            match client_read_u64_mapped(
                                pi as u64,
                                sp + 0x28 + i as u64 * 8,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            ) {
                                Some(value) => create_window_stack_args[i] = value,
                                None => {
                                    tail_ok = false;
                                    break;
                                }
                            }
                            i += 1;
                        }
                        if tail_ok {
                            create_window_stack_arg_count = create_window_stack_args.len();
                        } else {
                            create_window_probe_failed = true;
                        }
                    }
                    if pi == 6 {
                        // Explorer reaches this path with create-window strings outside the main image
                        // window. Capture them generically so isolated win32k never sees foreign VAs.
                        prefill_client_large_string_pages(
                            pi as u64,
                            d_a1,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                        prefill_client_large_string_pages(
                            pi as u64,
                            d_a2,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                        prefill_client_large_string_pages(
                            pi as u64,
                            d_a3,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                        let original_a1 = d_a1;
                        let original_a2 = d_a2;
                        let original_a3 = d_a3;
                        d_a1 = capture_client_string_arg(
                            pi as u64,
                            d_a1,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        d_a2 = capture_client_string_arg(
                            pi as u64,
                            d_a2,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        d_a3 = capture_client_string_arg(
                            pi as u64,
                            d_a3,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        if d_a1 != original_a1 || d_a2 != original_a2 || d_a3 != original_a3 {
                            EXPLORER_CREATE_WINDOW_STRING_CAPTURES.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        d_a1 = capture_client_string_arg_if_main_image(
                            pi as u64,
                            d_a1,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        d_a2 = capture_client_string_arg_if_main_image(
                            pi as u64,
                            d_a2,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        d_a3 = capture_client_string_arg_if_main_image(
                            pi as u64,
                            d_a3,
                            true,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    }
                } else if m0 == 0x1080
                    && hosted_process_is_interactive_shell_gui_client(&nt_handler, pi)
                {
                    // NtUserDefSetText takes HWND plus a client PLARGE_STRING. It often runs from
                    // DefWindowProc while win32k is parked in a user callback; capture the counted
                    // string before isolated win32k probes the client's raw pointer graph.
                    if nt_handler.hosted_process_role(pi)
                        == Some(nt_exe_image::HostedProcessRole::InteractiveShell)
                    {
                        prefill_client_large_string_pages(
                            pi as u64,
                            d_a1,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                    }
                    d_a1 = capture_client_string_arg(
                        pi as u64,
                        d_a1,
                        true,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                } else if m0 == 0x1041 && a0 == 0x14 {
                    // SystemParametersInfoW(SPI_SETDESKWALLPAPER) passes a user-mode UNICODE_STRING
                    // descriptor, and that descriptor's Buffer is another user pointer. Capture the graph
                    // at the executive boundary before isolated win32k's SpiSetWallpaper probes it.
                    let captured = capture_client_string_arg(
                        pi as u64,
                        d_a2,
                        false,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if captured != d_a2 {
                        d_a2 = captured;
                        if pi == 5 {
                            let n = USERINIT_WALLPAPER_SPI_CAPTURES.fetch_add(1, Ordering::Relaxed);
                            if n < 4 {
                                print_str(b"[w32marshal] userinit captured SPI_SETDESKWALLPAPER UNICODE_STRING arg=0x");
                                print_hex((a2 >> 32) as u32);
                                print_hex(a2 as u32);
                                print_str(b" -> 0x");
                                print_hex((captured >> 32) as u32);
                                print_hex(captured as u32);
                                print_str(b"\n");
                            }
                        }
                    }
                }
                if m0 == 0x10b4 {
                    if let Some((class_arg, menu_arg)) = capture_register_class_graph(
                        pi as u64,
                        a0,
                        a3,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    ) {
                        d_a0 = class_arg;
                        d_a3 = menu_arg;
                    }
                }
                let cursor_identity_key = if m0 == 0x103d {
                    capture_cursor_lookup_key(
                        pi as u64,
                        a0,
                        a1,
                        a2,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    )
                } else if m0 == 0x10a8 {
                    capture_cursor_set_data_key(
                        pi as u64,
                        a1,
                        a2,
                        a3,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    )
                } else {
                    None
                };
                let builtin_class_args = if m0 == 0x10b4 {
                    if register_class_stack_arg_count == register_class_stack_args.len() {
                        Some((
                            register_class_stack_args[0] as u32,
                            register_class_stack_args[1] as u32,
                        ))
                    } else {
                        let sp = get_recv_mr(16);
                        match (
                            client_read_u64_mapped(
                                pi as u64,
                                sp + 0x28,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            ),
                            client_read_u64_mapped(
                                pi as u64,
                                sp + 0x30,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            ),
                        ) {
                            (Some(fn_id), Some(flags)) => Some((fn_id as u32, flags as u32)),
                            _ => None,
                        }
                    }
                } else {
                    None
                };
                let builtin_class_attempt = builtin_class_args.is_some_and(|(fn_id, flags)| {
                    (nt_kernel_exec::user_class::FNID_BUILTIN_FIRST
                        ..=nt_kernel_exec::user_class::FNID_BUILTIN_LAST)
                        .contains(&fn_id)
                        && flags == 0
                });
                let register_class_fn_id = builtin_class_args.map(|(fn_id, _)| fn_id).unwrap_or(0);
                let builtin_class_key = builtin_class_args.and_then(|(fn_id, flags)| {
                    capture_builtin_class_key(
                        pi as u64,
                        a0,
                        a1,
                        a2,
                        a3,
                        fn_id,
                        flags,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    )
                });
                let registered_class_atom_name = if m0 == 0x10b4 {
                    capture_registered_class_atom_name(
                        pi as u64,
                        a1,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    )
                } else {
                    None
                };
                let get_class_info_ansi = if m0 == 0x10bd {
                    client_read_u64_mapped(
                        pi as u64,
                        sp + 0x28,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    )
                    .is_some_and(|value| value != 0)
                } else {
                    false
                };
                let get_class_info_capture = if m0 == 0x10bd {
                    let capture = capture_get_class_info_graph(
                        pi as u64,
                        a1,
                        a2,
                        a3,
                        get_class_info_ansi,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if let Some(capture) = capture {
                        d_a1 = capture.class_desc;
                        d_a2 = capture.wnd_out;
                        d_a3 = if a3 == 0 { 0 } else { capture.menu_out };
                        if pi == 5 && capture.scrollbar {
                            USERINIT_SCROLLBAR_CLASSINFO_QUERIES.fetch_add(1, Ordering::Relaxed);
                        }
                        Some(capture)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let get_class_name_capture = if m0 == 0x107c {
                    let capture = capture_get_class_name_out(
                        pi as u64,
                        a2,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if let Some(capture) = capture {
                        d_a2 = capture.desc_out;
                        Some(capture)
                    } else {
                        None
                    }
                } else {
                    None
                };
                // DIAG: NtUserCreateWindowStation(0x122f) OA-pointer probe — read the client's REAL
                // OBJECT_ATTRIBUTES.Length via its stack mirror (pi-selected) so we can tell a stale
                // (wrong-client) frame in win32k from a genuinely-bad OA the client built.
                if m0 == 0x122f {
                    let mut oa = [0u8; 0x30];
                    let oa_ok = img_spawn::client_copyin_mapped(
                        pi as u64,
                        a0,
                        &mut oa,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    let object_name = if oa_ok {
                        u64::from_le_bytes(oa[0x10..0x18].try_into().unwrap())
                    } else {
                        0
                    };
                    let mut name = [0u8; 0x10];
                    let name_ok = object_name != 0
                        && img_spawn::client_copyin_mapped(
                            pi as u64,
                            object_name,
                            &mut name,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    let name_lengths = if name_ok {
                        u32::from_le_bytes(name[0..4].try_into().unwrap())
                    } else {
                        0
                    };
                    let name_buffer = if name_ok {
                        u64::from_le_bytes(name[8..16].try_into().unwrap())
                    } else {
                        0
                    };
                    let mut prefix = [0u8; 8];
                    let prefix_ok = name_buffer != 0
                        && img_spawn::client_copyin_mapped(
                            pi as u64,
                            name_buffer,
                            &mut prefix,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    print_str(b"[w32diag] 0x122f OA=0x");
                    print_hex((a0 >> 32) as u32);
                    print_hex(a0 as u32);
                    print_str(b" real-Length=0x");
                    print_hex(smss_stack_read(a0) as u32);
                    print_str(b" pi=");
                    print_u64(pi as u64);
                    print_str(b" graph=");
                    print_u64(oa_ok as u64);
                    print_str(b"/");
                    print_u64(name_ok as u64);
                    print_str(b"/");
                    print_u64(prefix_ok as u64);
                    print_str(b" ObjectName=0x");
                    print_hex((object_name >> 32) as u32);
                    print_hex(object_name as u32);
                    print_str(b" LenMax=0x");
                    print_hex(name_lengths);
                    print_str(b" Buffer=0x");
                    print_hex((name_buffer >> 32) as u32);
                    print_hex(name_buffer as u32);
                    print_str(b" text4=0x");
                    print_hex(u64::from_le_bytes(prefix) as u32);
                    print_str(b"\n");

                    // win32k is an isolated component, so capture the nested user pointer graph at
                    // the executive boundary just as NtUserCreateWindowStation's ProbeForRead block
                    // does in a monolithic kernel. Preserve scalar handles/flags and the caller's
                    // security descriptor pointer; only the OA, counted-string descriptor, and its
                    // bounded UTF-16 buffer need rebasing into the shared argument window.
                    let name_len = (name_lengths & 0xffff) as usize;
                    let name_max = (name_lengths >> 16) as usize;
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    let arg_bytes = (win32k_subsystem::WIN32K_ARG_FRAMES * 0x1000) as usize;
                    let graph_valid = oa_ok
                        && name_ok
                        && prefix_ok
                        && name_len != 0
                        && name_len & 1 == 0
                        && name_len <= name_max
                        && name_max <= arg_bytes - 0x40;
                    if graph_valid {
                        core::ptr::write_bytes(arg as *mut u8, 0, arg_bytes);
                        core::ptr::copy_nonoverlapping(oa.as_ptr(), arg as *mut u8, oa.len());
                        core::ptr::copy_nonoverlapping(
                            name.as_ptr(),
                            (arg + 0x30) as *mut u8,
                            name.len(),
                        );
                        let name_out =
                            core::slice::from_raw_parts_mut((arg + 0x40) as *mut u8, name_max);
                        if img_spawn::client_copyin_mapped(
                            pi as u64,
                            name_buffer,
                            name_out,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        ) {
                            core::ptr::write_unaligned((arg + 0x10) as *mut u64, arg + 0x30);
                            core::ptr::write_unaligned((arg + 0x38) as *mut u64, arg + 0x40);
                            d_a0 = arg;
                            print_str(
                                b"[w32marshal] captured named window-station OA graph bytes=",
                            );
                            print_u64(0x40 + name_max as u64);
                            print_str(b"\n");
                        }
                    }
                }
                // ★ THE COUNTED DESKTOP PAINT — winlogon's OWN natural NtUserSwitchDesktop paints the
                // framebuffer, and THIS is the source of the `exec_win32k_desktop_painted` gate spec
                // (scaffold RETIRED — see the m0==0x125a arm, which now runs ONLY the InitVideo/surface
                // bringup, not the paint). Right BEFORE winlogon's SSN 0x1288 we clear the WHOLE fb to
                // magenta — now LOAD-BEARING: it wipes any earlier pixels so the counted spec genuinely
                // proves winlogon's co_IntShowDesktop -> co_UserRedrawWindow -> DesktopWindowProc
                // WM_ERASEBKGND -> IntPaintDesktop re-painted 0x003a6ea5 by the AUTHENTIC boot flow
                // (BOOTBOOT -> kernel -> smss -> csrss -> winlogon -> win32k), not a stale scaffold paint.
                // ★ BATCH 46 — only the FIRST winlogon switch is the real (painting) transition; the second
                // is win32k's `pdesk == gpdeskInputDesktop` already-current no-op (zero paint work). The
                // first switch can park in user callbacks before the paint completes, so the readback is
                // latched either here for a non-callback dispatch or later from NtCallbackReturn's completed
                // outer-dispatch observer. Once latched, the already-current second switch must not clear the fb.
                let winlogon_switch_requested = m0 == 0x1288
                    && hosted_main_badge_has_role(
                        &nt_handler,
                        badge,
                        nt_exe_image::HostedProcessRole::InteractiveLogon,
                    )
                    && WINLOGON_PAINT_DONE.load(Ordering::Relaxed) == 0;
                let winlogon_switch_transitions = winlogon_switch_requested
                    && win32k_subsystem::switch_desktop_would_change_input_desktop(a0);
                let winlogon_switch_observe_after = winlogon_switch_requested
                    && (winlogon_switch_transitions
                        || WINLOGON_DESKTOP_PAINT_PENDING.load(Ordering::Relaxed) != 0);
                if winlogon_switch_transitions {
                    WINLOGON_DESKTOP_PAINT_PENDING.store(1, Ordering::Relaxed);
                    let fb = FB_VADDR as *mut u32;
                    for i in 0..(1024u64 * 768) {
                        core::ptr::write_volatile(fb.add(i as usize), 0x00FF_00FF);
                    }
                    print_str(
                        b"[win32k-svc] fb cleared to magenta before winlogon NtUserSwitchDesktop\n",
                    );
                }
                // Non-interactive services run user32 RegisterSystemClasses during GUI-DLL
                // process attach, but they do not own the interactive window station path that loads
                // and registers system cursors. Route only the real interactive win32k state that is
                // safe to share across the session: exact promoted cursor identities, exact built-in
                // class registrations, and captured per-process client PFNs. A miss remains a visible
                // NULL/FALSE result instead of minting an atom or handle.
                //
                // The gate is driven by the live EPROCESS image role, not the launch slot:
                // services.exe and lsass.exe are non-interactive service hosts on a WSS_NOIO window
                // station, and neither should enter win32k's interactive cursor/class/stock-object
                // EngCopyBits path while initializing service DLLs.
                let svc_noninteractive =
                    hosted_process_is_noninteractive_service_gui_client(&nt_handler, pi);
                let shell_gui_client =
                    hosted_process_is_interactive_shell_gui_client(&nt_handler, pi);
                let userinit_gui_client = nt_handler.hosted_process_role(pi)
                    == Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap);
                // Shell GUI clients ask win32k for class atom names from inside nested user
                // callbacks. The hosted win32k still has one shared PROCESSINFO, so exact
                // mirror-backed names are served before dispatch; misses stay visible.
                let class_atom_name_mirror_result = if m0 == 0x10ad && shell_gui_client {
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    crate::ke_gdi_flush_user_batch(pi, client_teb);
                    let mirrored = copy_class_atom_name_from_mirror(
                        pi as u64,
                        a0 as u16,
                        a1,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    if mirrored.is_none() {
                        print_str(b"[win32k-svc] shell NtUserGetAtomName(0x10ad) MIRROR MISS pi=");
                        print_u64(pi as u64);
                        print_str(b" atom=0x");
                        print_hex(a0 as u32);
                        print_str(b" -> bytes=0\n");
                    }
                    Some(mirrored.unwrap_or(0))
                } else {
                    None
                };
                let (mut st, mut ok): (u64, bool) = if wl_milestone_park {
                    // winlogon reached its SAS message-loop milestone (0x1006/0x1001) — do NOT dispatch to
                    // win32k (its GetMessage would block the executive); the !handled block parks winlogon.
                    (0, false)
                } else if let Some(mirror_bytes) = class_atom_name_mirror_result {
                    print_str(b"[win32k-svc] shell NtUserGetAtomName(0x10ad) MIRROR pi=");
                    print_u64(pi as u64);
                    print_str(b" atom=0x");
                    print_hex(a0 as u32);
                    print_str(b" -> bytes=");
                    print_u64(mirror_bytes);
                    print_str(b"\n");
                    (mirror_bytes, true)
                } else if m0 == 0x103d && shell_gui_client {
                    // userinit/explorer are distinct interactive child processes, but the current
                    // win32k host still has one shared PROCESSINFO. Entering the real handler with
                    // that mismatched state reaches an unbounded EngCopyBits path. Reuse only a
                    // handle learned from a real winlogon lookup and a successful real
                    // NtUserSetSystemCursor promotion; an exact miss remains NULL.
                    let hit = cursor_identity_key
                        .as_ref()
                        .and_then(|key| GLOBAL_CURSOR_MIRROR.lookup_global(key));
                    if let Some(handle) = hit {
                        remember_global_scrollbar_cursor(handle);
                        if userinit_gui_client {
                            USERINIT_GLOBAL_CURSOR_HITS.fetch_add(1, Ordering::Relaxed);
                            USERINIT_GLOBAL_CURSOR_HANDLE.store(handle as u64, Ordering::Relaxed);
                        }
                        print_str(b"[win32k-svc] shell global cursor mirror HIT pi=");
                        print_u64(pi as u64);
                        print_str(b" -> real HCURSOR 0x");
                        print_hex(handle);
                        print_str(b"\n");
                    } else {
                        print_str(b"[win32k-svc] shell global cursor mirror MISS pi=");
                        print_u64(pi as u64);
                        print_str(b" -> NULL\n");
                    }
                    (hit.unwrap_or(0) as u64, true)
                } else if m0 == 0x10b4 && shell_gui_client && builtin_class_attempt {
                    // The hosted win32k currently has one shared PROCESSINFO, whose built-in class
                    // list was populated by winlogon. A second real registration from userinit or
                    // explorer would mutate that same list and report duplicate-class semantics.
                    // Reuse only an exact real atom learned from winlogon's successful registration
                    // of the same complete class.
                    let hit = builtin_class_key
                        .as_ref()
                        .and_then(|key| GLOBAL_BUILTIN_CLASS_MIRROR.lookup(key));
                    if let (Some(key), Some(atom)) = (builtin_class_key.as_ref(), hit) {
                        if userinit_gui_client {
                            let bit = 1u64 << (key.fn_id() - 0x02a1);
                            USERINIT_BUILTIN_CLASS_HITS.fetch_add(1, Ordering::Relaxed);
                            USERINIT_BUILTIN_CLASS_MASK.fetch_or(bit, Ordering::Relaxed);
                            if key.fn_id() == 0x02a4 {
                                USERINIT_DIALOG_CLASS_ATOM.store(atom as u64, Ordering::Relaxed);
                            }
                        }
                        print_str(b"[win32k-svc] shell builtin class mirror HIT pi=");
                        print_u64(pi as u64);
                        print_str(b" fnid=0x");
                        print_hex(key.fn_id());
                        print_str(b" -> real atom 0x");
                        print_hex(atom as u32);
                        print_str(b"\n");
                    } else {
                        if userinit_gui_client {
                            USERINIT_BUILTIN_CLASS_MISSES.fetch_add(1, Ordering::Relaxed);
                        }
                        print_str(b"[win32k-svc] shell builtin class mirror MISS pi=");
                        print_u64(pi as u64);
                        print_str(b" -> atom 0\n");
                    }
                    (hit.unwrap_or(0) as u64, true)
                } else if create_bitmap_probe_failed {
                    let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    if failures < 8 {
                        print_str(b"[win32k-svc] NtGdiCreateBitmap input probe failed pi=");
                        print_u64(pi as u64);
                        print_str(b" ");
                        print_u64(a0 as u32 as u64);
                        print_str(b"x");
                        print_u64(a1 as u32 as u64);
                        print_str(b" planes=");
                        print_u64(a2 as u32 as u64);
                        print_str(b" bpp=");
                        print_u64(a3 as u32 as u64);
                        print_str(b" -> NULL\n");
                    }
                    (0, true)
                } else if text_extent_probe_failed {
                    let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    if failures < 8 {
                        print_str(b"[win32k-svc] NtGdiGetTextExtentExW input probe failed pi=");
                        print_u64(pi as u64);
                        print_str(b" count=");
                        print_u64(a2 as u32 as u64);
                        print_str(b" str=0x");
                        print_hex_u64(a1);
                        print_str(b" -> FALSE\n");
                    }
                    (0, true)
                } else if create_window_probe_failed {
                    let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                    if failures < 8 {
                        print_str(b"[win32k-svc] NtUserCreateWindowEx stack probe failed pi=");
                        print_u64(pi as u64);
                        print_str(b" sp=0x");
                        print_hex_u64(sp);
                        print_str(b" -> NULL\n");
                    }
                    (0, true)
                } else if m0 == 0x103d && svc_noninteractive {
                    // Reuse only an exact cursor handle learned from the real interactive win32k path.
                    let hit = cursor_identity_key
                        .as_ref()
                        .and_then(|key| GLOBAL_CURSOR_MIRROR.lookup_global(key));
                    if let Some(handle) = hit {
                        remember_global_scrollbar_cursor(handle);
                        print_str(
                            b"[win32k-svc] svc NtUserFindExistingCursorIcon(0x103d) MIRROR pi=",
                        );
                        print_u64(pi as u64);
                        print_str(b" -> real HCURSOR 0x");
                        print_hex(handle);
                        print_str(b"\n");
                    } else {
                        print_str(b"[win32k-svc] svc NtUserFindExistingCursorIcon(0x103d) MIRROR MISS pi=");
                        print_u64(pi as u64);
                        print_str(b" -> NULL\n");
                    }
                    (hit.unwrap_or(0) as u64, true)
                } else if m0 == 0x10b4 && svc_noninteractive {
                    // Non-interactive services reuse only class atoms already observed from real
                    // win32k registration/query paths. A miss stays visible instead of minting an atom.
                    let hit = if register_class_fn_id == nt_kernel_exec::user_class::FNID_SCROLLBAR
                    {
                        let atom = GLOBAL_SCROLLBAR_CLASS_ATOM.load(Ordering::Relaxed) as u16;
                        if atom != 0 && pi < MAX_PI {
                            SVC_SCROLLBAR_CLASS_ATOM[pi].store(atom as u64, Ordering::Relaxed);
                            Some(atom)
                        } else {
                            None
                        }
                    } else if builtin_class_attempt {
                        builtin_class_key
                            .as_ref()
                            .and_then(|key| GLOBAL_BUILTIN_CLASS_MIRROR.lookup(key))
                    } else {
                        None
                    };
                    if let Some(atom) = hit {
                        print_str(b"[win32k-svc] svc NtUserRegisterClassExWOW(0x10b4) MIRROR pi=");
                        print_u64(pi as u64);
                        print_str(b" fnid=0x");
                        print_hex(register_class_fn_id);
                        print_str(b" -> real atom 0x");
                        print_hex(atom as u32);
                        print_str(b"\n");
                    } else {
                        print_str(
                            b"[win32k-svc] svc NtUserRegisterClassExWOW(0x10b4) MIRROR MISS pi=",
                        );
                        print_u64(pi as u64);
                        print_str(b" fnid=0x");
                        print_hex(register_class_fn_id);
                        print_str(b" -> atom 0\n");
                    }
                    (hit.unwrap_or(0) as u64, true)
                } else if m0 == 0x125b && svc_noninteractive {
                    // ReactOS NtUserInitializeClientPfnArrays returns STATUS_SUCCESS once the
                    // session-global client PFN arrays have already been initialized. Winlogon's
                    // interactive setup does that first; WSS_NOIO service processes only need their
                    // client PFNs captured for later service-owned classinfo mirrors.
                    let captured = capture_service_client_pfn_arrays(
                        pi,
                        a0,
                        a1,
                        a3,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    );
                    print_str(b"[win32k-svc] svc NtUserInitializeClientPfnArrays(0x125b) SERVICE-PFN captured-pfns=");
                    print_u64(captured as u64);
                    print_str(b" -> STATUS_SUCCESS\n");
                    (0, true)
                } else if m0 == 0x11e0 && svc_noninteractive {
                    // ReactOS NtGdiInit is a BOOL leaf that returns TRUE. Keep WSS_NOIO services on
                    // that leaf result until win32k has separate per-service GDI process ownership.
                    print_str(b"[win32k-svc] svc NtGdiInit(0x11e0) SERVICE-LEAF -> TRUE\n");
                    (1, true)
                } else if m0 == 0x10de && svc_noninteractive {
                    // WSS_NOIO services have no display DC. Return the real failure value for a DC
                    // open instead of constructing an HDC backed by the interactive process state.
                    print_str(b"[win32k-svc] svc NtGdiOpenDCW(0x10de) NO DISPLAY DC -> NULL\n");
                    (0, true)
                } else if m0 == 0x10d4 && svc_noninteractive {
                    // NtGdiGetStockObject returns session-global stock handles. Reuse only handles
                    // learned from real win32k calls, so service-side gdi32 validates them through
                    // the live shared GDI table instead of receiving an invented handle index.
                    let object_id = a0 as u32;
                    let hit = GLOBAL_GDI_STOCK_OBJECT_MIRROR.lookup(object_id);
                    if let Some(handle) = hit {
                        SVC_GDI_STOCK_OBJECT_HITS.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[win32k-svc] svc NtGdiGetStockObject(0x10d4) MIRROR object=");
                        print_u64(object_id as u64);
                        print_str(b" -> real handle 0x");
                        print_hex(handle);
                        print_str(b"\n");
                    } else {
                        SVC_GDI_STOCK_OBJECT_MISSES.fetch_add(1, Ordering::Relaxed);
                        print_str(
                            b"[win32k-svc] svc NtGdiGetStockObject(0x10d4) MIRROR MISS object=",
                        );
                        print_u64(object_id as u64);
                        print_str(b" -> NULL\n");
                    }
                    (hit.unwrap_or(0) as u64, true)
                } else if m0 == 0x106c && svc_noninteractive {
                    // Non-interactive services may ask gdi32 for cached process-attach bitmaps even
                    // though they never own an interactive display target. Reuse the real session
                    // DEFAULT_BITMAP only for the zero-sized stock-object case; all other service
                    // bitmap allocation requests fail visibly until service GDI object ownership is
                    // wired through the provider.
                    let zero_size_default_bitmap = if a0 == 0 || a1 == 0 {
                        GLOBAL_GDI_STOCK_OBJECT_MIRROR
                            .lookup(nt_kernel_exec::user_gdi::DEFAULT_BITMAP)
                    } else {
                        None
                    };
                    if let Some(handle) = zero_size_default_bitmap {
                        SVC_GDI_STOCK_OBJECT_HITS.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[win32k-svc] svc NtGdiCreateBitmap(0x106c) MIRROR zero-size -> DEFAULT_BITMAP 0x");
                        print_hex(handle);
                        print_str(b"\n");
                        (handle as u64, true)
                    } else {
                        print_str(b"[win32k-svc] svc NtGdiCreateBitmap(0x106c) MIRROR MISS ");
                        print_u64(a0 as u32 as u64);
                        print_str(b"x");
                        print_u64(a1 as u32 as u64);
                        print_str(b" planes=");
                        print_u64(a2 as u32 as u64);
                        print_str(b" bpp=");
                        print_u64(a3 as u32 as u64);
                        print_str(b" -> NULL\n");
                        (0, true)
                    }
                } else if m0 == 0x10b5 && svc_noninteractive {
                    // Pattern brushes are process-owned GDI objects, not stock handles. A
                    // non-interactive service cannot receive an invented brush handle; fail visibly
                    // until real provider-owned service GDI object allocation is available.
                    print_str(b"[win32k-svc] svc NtGdiCreatePatternBrushInternal(0x10b5) MIRROR MISS hbm=0x");
                    print_hex(a0 as u32);
                    print_str(b" -> NULL\n");
                    (0, true)
                } else if m0 == 0x10bd && svc_noninteractive {
                    // Non-interactive services have already supplied their real user32 client PFN
                    // arrays and registered the system classes through the bounded service path above.
                    // Return ScrollBar class info from that per-process state instead of reporting the
                    // class absent, while still avoiding win32k's interactive UserRegisterSystemClasses
                    // blit path for WSS_NOIO services.
                    if let Some(capture) = get_class_info_capture {
                        if let Some(atom) = copy_service_scrollbar_class_info(
                            pi,
                            capture,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        ) {
                            SVC_SCROLLBAR_CLASSINFO_HITS.fetch_add(1, Ordering::Relaxed);
                            print_str(b"[win32k-svc] svc NtUserGetClassInfo(0x10bd) MIRROR ScrollBar atom=0x");
                            print_hex(atom as u32);
                            print_str(b" ansi=");
                            print_u64(capture.ansi as u64);
                            print_str(b" -> TRUE\n");
                            (atom, true)
                        } else {
                            SVC_SCROLLBAR_CLASSINFO_MISSES.fetch_add(1, Ordering::Relaxed);
                            print_str(b"[win32k-svc] svc NtUserGetClassInfo(0x10bd) MIRROR MISS scrollbar=");
                            print_u64(capture.scrollbar as u64);
                            print_str(b" atom=0x");
                            print_hex(SVC_SCROLLBAR_CLASS_ATOM[pi].load(Ordering::Relaxed) as u32);
                            print_str(b" hcursor=0x");
                            print_hex_u64(GLOBAL_SCROLLBAR_CLASS_CURSOR.load(Ordering::Relaxed));
                            print_str(b" procA=");
                            print_u64(
                                (SVC_CLIENT_PFNA_SCROLLBAR[pi].load(Ordering::Relaxed) != 0) as u64,
                            );
                            print_str(b" procW=");
                            print_u64(
                                (SVC_CLIENT_PFNW_SCROLLBAR[pi].load(Ordering::Relaxed) != 0) as u64,
                            );
                            print_str(b" ansi=");
                            print_u64(capture.ansi as u64);
                            print_str(b" -> FALSE\n");
                            (0, true)
                        }
                    } else {
                        SVC_SCROLLBAR_CLASSINFO_MISSES.fetch_add(1, Ordering::Relaxed);
                        print_str(b"[win32k-svc] svc NtUserGetClassInfo(0x10bd) MIRROR MISS capture=0 -> FALSE\n");
                        (0, true)
                    }
                } else {
                    // Forward the real syscall-entry stack pointer to win32k. The component derives
                    // exact arity from win32k's SSPT and reads only the required tail args through
                    // the attached client-memory path.
                    let peb_mirror = hosted_peb_mirror_for_pi(pi);
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    if pi >= 1 && m0 == 0x1077 && a3 != 0 {
                        prefill_client_large_string_pages(
                            pi as u64,
                            a3,
                            scratch_base,
                            &mut faults,
                            filled_pages,
                            &reg,
                            &dll_pes,
                        );
                    }
                    crate::teb_tail_watch(pi, 1, m0, 0);
                    // ★ `KiSystemCallHandler`'s win32k arm (ntoskrnl/ke/amd64/traphandler.c:180):
                    // BEFORE dispatching any win32k system call, if the caller's
                    // `TEB.GdiBatchCount != 0`, run `KeGdiFlushUserBatch`. Without this step
                    // `gdi32!GdiAllocBatchCommand`'s `GdiTebBatch.Offset` never resets and the
                    // deferred-GDI records march straight through the caller's TEB — the single root
                    // cause of the whole TEB-clobber family (batches 53/59/60) and of winlogon's
                    // `#GP` in `RtlEnterCriticalSection` on rpcrt4's `TEB.ReservedForNtRpc`.
                    crate::ke_gdi_flush_user_batch(pi, client_teb);
                    let open_dcw_staged_stack =
                        m0 == 0x10de && open_dcw_stack_arg_count == open_dcw_stack_args.len();
                    let build_hwnd_list_staged_stack = m0 == 0x101b
                        && build_hwnd_list_stack_arg_count == build_hwnd_list_stack_args.len();
                    let create_bitmap_staged_stack = m0 == 0x106c
                        && create_bitmap_stack_arg_count == create_bitmap_stack_args.len();
                    let text_extent_staged_stack =
                        m0 == 0x11d9 && text_extent_stack_arg_count == text_extent_stack_args.len();
                    let register_class_staged_stack = m0 == 0x10b4
                        && register_class_stack_arg_count == register_class_stack_args.len();
                    let create_window_staged_stack = m0 == 0x1077
                        && create_window_stack_arg_count == create_window_stack_args.len();
                    // Keep the original SP in the dispatch context for callback/completion
                    // observers. win32k_dispatch_wide still sends SH_REQ_CALLER_SP=0 when
                    // stack_args is non-empty, so the component consumes only the staged tail.
                    let (dispatch_sp, dispatch_stack_args): (u64, &[u64]) = if open_dcw_staged_stack
                    {
                        (sp, &open_dcw_stack_args)
                    } else if build_hwnd_list_staged_stack {
                        (sp, &build_hwnd_list_stack_args)
                    } else if create_bitmap_staged_stack {
                        (sp, &create_bitmap_stack_args)
                    } else if text_extent_staged_stack {
                        (sp, &text_extent_stack_args)
                    } else if register_class_staged_stack {
                        (sp, &register_class_stack_args)
                    } else if create_window_staged_stack {
                        (sp, &create_window_stack_args)
                    } else {
                        (sp, &[])
                    };
                    let client = win32k_client_context_for_thread(
                        &nt_handler,
                        pi,
                        badge,
                        nt_handler.current_tid,
                        hosted_thread_tcb_or_zero(&nt_handler, nt_handler.current_tid),
                        nt_handler.hosted_thread_role(nt_handler.current_tid),
                        client_teb,
                        peb_mirror,
                        scratch_base,
                    );
                    let mut r = dispatch_win32k_for_client(
                        &mut nt_handler,
                        m0,
                        d_a0,
                        d_a1,
                        d_a2,
                        d_a3,
                        dispatch_sp,
                        dispatch_stack_args,
                        client,
                    );
                    // ★ win32k just ran KeStackAttachProcess'd to this client and may have written
                    // SERVER data through its TEB pages — OBSERVE (do not yet repair) the TEB-tail
                    // invariants the client's own CRT depends on, so the frontier has a number.
                    crate::teb_tail_watch(pi, 2, m0, 0);
                    crate::observe_client_teb_tail(pi);
                    // The credential READ-BACK. A single-line edit control renders itself with
                    // `EDIT_PaintText -> TextOutW -> NtGdiExtTextOutW(hdc, x, y, opts, lprc,
                    // es->text + col, count, …)` (args 5..9 ride the win64 stack tail). The string
                    // it hands GDI IS the control's live text buffer, so matching our injected user
                    // name there proves the real edit control holds what was typed into it.
                    if pi == 2 && m0 == nt_user_callback::NTGDI_EXT_TEXT_OUT_W_SSN && sp != 0 {
                        let string = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x30,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let count = client_read_u64_mapped(
                            pi as u64,
                            sp + 0x38,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        if let (Some(string), Some(count)) = (string, count) {
                            winlogon_credential_observe_text_out(string, count);
                        }
                    }
                    if open_dcw_staged_stack && r.1 && r.0 != 0 {
                        let (client_out, staged_out) = open_dcw_dhpdev_copyout;
                        let dhpdev = core::ptr::read_unaligned(staged_out as *const u64);
                        if client_out != 0
                            && !img_spawn::client_write_u64_mapped(
                                pi as u64,
                                client_out,
                                dhpdev,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            )
                        {
                            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                            if failures < 8 {
                                print_str(
                                    b"[win32k-svc] NtGdiOpenDCW pUMDHPDEV copy-out failed pi=",
                                );
                                print_u64(pi as u64);
                                print_str(b" buffer=0x");
                                print_hex_u64(client_out);
                                print_str(b"\n");
                            }
                            r = (0xC000_0001, false);
                        }
                    }
                    if build_hwnd_list_staged_stack && r.1 {
                        let (client_list, staged_list, client_needed, c_hwnd_forwarded) =
                            build_hwnd_list_copyout;
                        let needed = core::ptr::read_unaligned(
                            (staged_list + WIN32K_BUILD_HWND_LIST_COUNT_OFFSET) as *const u32,
                        );
                        let needed_ok = img_spawn::client_write_mapped(
                            pi as u64,
                            client_needed,
                            &needed.to_le_bytes(),
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let handles_to_copy = (needed as u64).min(c_hwnd_forwarded) as usize;
                        let handles_ok = client_list == 0
                            || handles_to_copy == 0
                            || img_spawn::client_copyout_mapped(
                                pi as u64,
                                client_list,
                                core::slice::from_raw_parts(
                                    staged_list as *const u8,
                                    handles_to_copy * 8,
                                ),
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            );
                        if !needed_ok || !handles_ok {
                            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                            if failures < 8 {
                                print_str(b"[win32k-svc] NtUserBuildHwndList copy-out failed pi=");
                                print_u64(pi as u64);
                                print_str(b" list=0x");
                                print_hex_u64(client_list);
                                print_str(b" needed=0x");
                                print_hex_u64(client_needed);
                                print_str(b" handles=");
                                print_u64(handles_to_copy as u64);
                                print_str(b"\n");
                            }
                            r = (0xC000_0005, false);
                        }
                    }
                    if text_extent_staged_stack && r.1 && r.0 != 0 {
                        let (
                            client_fit,
                            staged_fit,
                            client_dx,
                            staged_dx,
                            client_size,
                            staged_size,
                            dx_bytes,
                        ) = text_extent_copyout;
                        let size_ok = img_spawn::client_write_mapped(
                            pi as u64,
                            client_size,
                            core::slice::from_raw_parts(staged_size as *const u8, 8),
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                        let fit_ok = client_fit == 0
                            || img_spawn::client_write_mapped(
                                pi as u64,
                                client_fit,
                                core::slice::from_raw_parts(staged_fit as *const u8, 4),
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            );
                        let dx_ok = client_dx == 0
                            || dx_bytes == 0
                            || img_spawn::client_copyout_mapped(
                                pi as u64,
                                client_dx,
                                core::slice::from_raw_parts(staged_dx as *const u8, dx_bytes),
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            );
                        if !size_ok || !fit_ok || !dx_ok {
                            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                            if failures < 8 {
                                print_str(
                                    b"[win32k-svc] NtGdiGetTextExtentExW copy-out failed pi=",
                                );
                                print_u64(pi as u64);
                                print_str(b" fit=0x");
                                print_hex_u64(client_fit);
                                print_str(b" dx=0x");
                                print_hex_u64(client_dx);
                                print_str(b" size=0x");
                                print_hex_u64(client_size);
                                print_str(b" dx-bytes=");
                                print_u64(dx_bytes as u64);
                                print_str(b"\n");
                            }
                            r = (0, true);
                        }
                    }
                    // DIAG: dump the retrieved MSG for winlogon's SAS GetMessage (a0=R10=&Msg). MSG =
                    // {hwnd@0, message@8, wParam@0x10, lParam@0x18}. Confirms whether the injected
                    // WLX_WM_SAS (0x659) reaches winlogon so DispatchMessageW runs SASWindowProc.
                    if pi == 2 && (m0 == 0x1006 || m0 == 0x1001) && a0 != 0 {
                        let hwnd = smss_stack_read(a0);
                        let message = smss_stack_read(a0 + 8);
                        let wparam = smss_stack_read(a0 + 0x10);
                        print_str(b"[wl-diag] GetMessage retrieved MSG hwnd=0x");
                        print_hex(hwnd as u32);
                        print_str(b" message=0x");
                        print_hex(message as u32);
                        print_str(b" wParam=0x");
                        print_hex(wparam as u32);
                        print_str(b" (ret=0x");
                        print_hex(r.0 as u32);
                        print_str(b")\n");
                        if r.0 == 1 {
                            // Count the injected credential keystrokes that genuinely came back
                            // out of win32k's real message queue into the dialog's real pump.
                            winlogon_credential_observe_retrieved(hwnd, message as u32, wparam);
                        }
                        if r.0 == 1
                            && message as u32 == nt_user_callback::WLX_WM_SAS
                            && wparam == nt_user_callback::WLX_SAS_TYPE_CTRL_ALT_DEL
                        {
                            if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) == 0
                                && WINLOGON_SAS1_RETRIEVED.swap(1, Ordering::Relaxed) == 0
                            {
                                WINLOGON_PAINT_RETURNS_AT_SAS1.store(
                                    win32k_glue::real_wm_paint_callback_returns(),
                                    Ordering::Relaxed,
                                );
                            } else if WINLOGON_SAS2_INJECTED.load(Ordering::Relaxed) != 0 {
                                WINLOGON_MSGLOOP_MILESTONE.fetch_add(1, Ordering::Relaxed);
                            }
                            let session = core::ptr::read_volatile(
                                (win32k_subsystem::WIN32K_SHARED_VADDR
                                    + win32k_subsystem::SH_SAS_SESSION)
                                    as *const u64,
                            );
                            let _ = winlogon_dialog_observe_sas_message(
                                session,
                                hwnd,
                                message as u32,
                                wparam,
                            );
                        }
                    }
                    if nt_handler.hosted_process_role(pi)
                        == Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
                        && m0 == nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
                        && r.0 == 0
                    {
                        let main_tid = nt_handler
                            .pm_main_tid_for_pi(pi)
                            .map(u64::from)
                            .unwrap_or(0);
                        let _ = post_winlogon_second_sas_after_welcome_drain(
                            pi,
                            badge,
                            current_tid,
                            hosted_thread_tcb_or_zero(&nt_handler, current_tid),
                            nt_handler.hosted_thread_role(current_tid),
                            nt_handler.hosted_process_role(pi),
                            nt_handler.hosted_process_top_badge(pi).unwrap_or(0),
                            main_tid,
                            nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
                            client_teb,
                            peb_mirror,
                            scratch_base,
                        );
                    }
                    r
                };
                let callback_suspended = win32k_glue::take_user_callback_pump_suspended();
                if dialog_modal_dispatch && !callback_suspended {
                    let hwnd = if a0 != 0 { smss_stack_read(a0) } else { 0 };
                    let message = if a0 != 0 {
                        smss_stack_read(a0 + 8) as u32
                    } else {
                        0
                    };
                    if !winlogon_dialog_modal_observe(m0, st, hwnd, message) {
                        handled = false;
                        wl_milestone_park = true;
                    }
                }
                if callback_suspended {
                    let peb_mirror = hosted_peb_mirror_for_pi(pi);
                    let client_teb = nt_handler
                        .pm
                        .thread_teb(nt_handler.current_tid as nt_process::ThreadId)
                        .filter(|teb| *teb != 0)
                        .unwrap_or(SMSS_TEB_VA);
                    redirected_user_callback = win32k_glue::begin_controlled_user_callback_redirect(
                        win32k_client_context_for_thread(
                            &nt_handler,
                            pi,
                            badge,
                            nt_handler.current_tid,
                            hosted_thread_tcb_or_zero(&nt_handler, nt_handler.current_tid),
                            nt_handler.hosted_thread_role(nt_handler.current_tid),
                            client_teb,
                            peb_mirror,
                            scratch_base,
                        ),
                        resume_ip,
                        sp,
                        flags,
                    );
                    if !redirected_user_callback {
                        let resumed = win32k_glue::cancel_suspended_user_callback();
                        st = resumed.0 as u32 as u64;
                        ok = resumed.1;
                    }
                }
                if ok && !redirected_user_callback && msg_returns_to_client {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    let staged_message = core::ptr::read_unaligned((arg + 8) as *const u32);
                    let should_copy_msg = st != 0
                        || (m0 == nt_user_callback::NTUSER_GET_MESSAGE_SSN
                            && staged_message == WM_QUIT);
                    if should_copy_msg {
                        let output =
                            core::slice::from_raw_parts(arg as *const u8, WIN32K_MSG_BYTES);
                        if !img_spawn::client_copyout_mapped(
                            pi as u64,
                            a0,
                            output,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        ) {
                            let failures = WIN32K_MSG_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                            if failures < 8 {
                                print_str(b"[win32k-svc] explorer MSG copy-out failed ssn=0x");
                                print_hex(m0 as u32);
                                print_str(b" buffer=0x");
                                print_hex_u64(a0);
                                print_str(b"\n");
                            }
                            st = 0;
                        }
                    }
                }
                if msg_syscall && ok && !redirected_user_callback {
                    let n = EXPLORER_GETMESSAGE_DIAG_N.fetch_add(1, Ordering::Relaxed);
                    if n < 128 || n.is_power_of_two() {
                        let mut msg = [0u8; WIN32K_MSG_BYTES];
                        let copy_ok = img_spawn::client_copyin_process_mapped(
                            pi as u64,
                            a0,
                            &mut msg,
                            filled_pages,
                            faults as usize,
                            scratch_base,
                            false,
                        );
                        let hwnd = u64::from_le_bytes(msg[0..8].try_into().unwrap_or([0; 8]));
                        let message = u32::from_le_bytes(msg[8..12].try_into().unwrap_or([0; 4]));
                        let wparam =
                            u64::from_le_bytes(msg[0x10..0x18].try_into().unwrap_or([0; 8]));
                        let lparam =
                            u64::from_le_bytes(msg[0x18..0x20].try_into().unwrap_or([0; 8]));
                        let time = u32::from_le_bytes(msg[0x20..0x24].try_into().unwrap_or([0; 4]));
                        print_str(b"[explorer-msg] ssn=0x");
                        print_hex(m0 as u32);
                        print_str(b" ret=0x");
                        print_hex(st as u32);
                        print_str(b" msgptr=0x");
                        print_hex_u64(a0);
                        print_str(b" hfilter=0x");
                        print_hex_u64(a1);
                        print_str(b" min=0x");
                        print_hex(a2 as u32);
                        print_str(b" max=0x");
                        print_hex(a3 as u32);
                        print_str(b" copy=");
                        print_u64(if copy_ok { 1 } else { 0 });
                        print_str(b" hwnd=0x");
                        print_hex_u64(hwnd);
                        print_str(b" message=0x");
                        print_hex(message);
                        print_str(b" wParam=0x");
                        print_hex_u64(wparam);
                        print_str(b" lParam=0x");
                        print_hex_u64(lparam);
                        print_str(b" time=");
                        print_u64(time as u64);
                        print_str(b"\n");
                    }
                }
                if ok && !redirected_user_callback {
                    if let Some(capture) = get_class_info_capture {
                        if st != 0 {
                            if !copy_back_get_class_info(
                                pi as u64,
                                capture,
                                st as u32 as u64,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            ) {
                                st = 0;
                            }
                        } else if pi == 5 && capture.scrollbar {
                            USERINIT_SCROLLBAR_CLASSINFO_ERRORS.fetch_add(1, Ordering::Relaxed);
                            print_str(b"[win32k-class] pi=5 ScrollBar capture=1 atom=0x00000000 copyout=0 style=0x00000000 cbWndExtra=0x00000000 proc=0\n");
                        }
                    }
                    if let Some(capture) = get_class_name_capture {
                        if st != 0
                            && !copy_back_get_class_name(
                                pi as u64,
                                capture,
                                st,
                                filled_pages,
                                faults as usize,
                                scratch_base,
                            )
                        {
                            st = 0;
                        }
                    }
                }
                if ok && !redirected_user_callback && m0 == 0x10b4 && st != 0 && !svc_noninteractive
                {
                    if let Some(name) = registered_class_atom_name.as_ref() {
                        if GLOBAL_CLASS_ATOM_NAME_MIRROR.observe(st as u16, name.as_slice()) {
                            GLOBAL_CLASS_ATOM_NAMES_OBSERVED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if ok
                    && !redirected_user_callback
                    && m0 == 0x10d4
                    && st != 0
                    && !svc_noninteractive
                    && GLOBAL_GDI_STOCK_OBJECT_MIRROR.observe(a0 as u32, st as u32)
                {
                    GLOBAL_GDI_STOCK_OBJECTS_OBSERVED.fetch_add(1, Ordering::Relaxed);
                    print_str(b"[win32k-svc] NtGdiGetStockObject(0x10d4) OBSERVED object=");
                    print_u64(a0 as u32 as u64);
                    print_str(b" -> real handle 0x");
                    print_hex(st as u32);
                    print_str(b"\n");
                }
                if pi == 2 && ok && !redirected_user_callback {
                    if m0 == 0x10a8 && st != 0 {
                        if let Some(key) = cursor_identity_key.as_ref() {
                            GLOBAL_CURSOR_MIRROR.observe_identity(key, a0 as u32);
                            GLOBAL_CURSOR_IDENTITIES_OBSERVED.fetch_add(1, Ordering::Relaxed);
                        }
                    } else if m0 == 0x1283 && st != 0 {
                        GLOBAL_CURSOR_MIRROR.promote(a0 as u32);
                        GLOBAL_CURSOR_PROMOTIONS.fetch_add(1, Ordering::Relaxed);
                    }
                    if m0 == 0x10b4 && st != 0 {
                        if let Some(key) = builtin_class_key.as_ref() {
                            GLOBAL_BUILTIN_CLASS_MIRROR.observe(key, st as u16);
                            GLOBAL_BUILTIN_CLASSES_OBSERVED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if winlogon_switch_observe_after && !redirected_user_callback {
                    observe_winlogon_natural_switch_desktop(st);
                }
                if has_buf && ok && st == 0 && !redirected_user_callback {
                    // NtUserProcessConnect (0x10FA) returned STATUS_SUCCESS for this GUI client —
                    // record the per-pi "win32k client connected" bit (csrss=1, winlogon=2, services=3).
                    W32_CONNECTED_MASK.fetch_or(1u64 << pi, Ordering::Relaxed);
                }
                if has_buf && ok && !redirected_user_callback {
                    let arg = win32k_subsystem::WIN32K_ARG_VADDR;
                    // gSharedInfo CLIENT-MAPPING. win32k's NtUserProcessConnect handler filled the
                    // USERCONNECT's siClient with pointers into its OWN session-space USER heap
                    // (gpsi / gHandleTable / the handle-entry array — all `UserHeapAlloc`ed), which
                    // is NOT mapped in csrss → user32's DllMain `Init` faults dereferencing
                    // gSharedInfo.aheList->handles. RO-map that heap arena into csrss and rewrite the
                    // siClient pointers (+ ulSharedDelta) to the csrss-relative client addresses so
                    // the client reads valid memory. delta = server(win32k) − client(csrss).
                    let delta = map_win32k_heap_into_csrss(pml4, pi);
                    let heap_lo = win32k_subsystem::WIN32K_HEAP_VADDR;
                    let heap_hi = heap_lo + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000;
                    // The handler's own shift (0 in this single-AS host; be robust anyway): recover
                    // the raw server VA before applying our delta.
                    let hd = core::ptr::read_volatile(
                        (arg + win32k_subsystem::UC_SI_DELTA) as *const u64,
                    );
                    // Publish the RAW server-VA aheList (USER handle table) so win32k's WM_CREATE callback
                    // bridge can resolve a HWND → its PWND to persist WND.dwUserData (the Session), for the
                    // client-side SASWindowProc. Capture it before the delta rewrite below.
                    {
                        let ahe_client = core::ptr::read_volatile(
                            (arg + win32k_subsystem::UC_SI_AHELIST) as *const u64,
                        );
                        if ahe_client != 0 {
                            let ahe_server = ahe_client.wrapping_add(hd);
                            if ahe_server >= heap_lo && ahe_server < heap_hi {
                                core::ptr::write_volatile(
                                    (win32k_subsystem::WIN32K_SHARED_VADDR
                                        + win32k_subsystem::SH_SAS_AHELIST)
                                        as *mut u64,
                                    ahe_server,
                                );
                            }
                        }
                    }
                    for off in [win32k_subsystem::UC_SI_PSI, win32k_subsystem::UC_SI_AHELIST] {
                        let client = core::ptr::read_volatile((arg + off) as *const u64);
                        if client != 0 {
                            let server = client.wrapping_add(hd);
                            if server >= heap_lo && server < heap_hi {
                                core::ptr::write_volatile(
                                    (arg + off) as *mut u64,
                                    server.wrapping_sub(delta),
                                );
                            }
                        }
                    }
                    core::ptr::write_volatile(
                        (arg + win32k_subsystem::UC_SI_DELTA) as *mut u64,
                        delta,
                    );
                    core::ptr::write_volatile(
                        (arg + win32k_subsystem::UC_SI_PDISPINFO) as *mut u64,
                        0,
                    );
                    // Copy the fixed-up USERCONNECT back to the original caller, not a fixed bootstrap
                    // mirror. Explorer and userinit use the same VA ranges as earlier clients in their
                    // own VSpaces, so this must stay pi-keyed.
                    let output = core::slice::from_raw_parts(arg as *const u8, blen as usize);
                    if !img_spawn::client_write_mapped(
                        pi as u64,
                        a1,
                        output,
                        filled_pages,
                        faults as usize,
                        scratch_base,
                    ) {
                        let failures = USERCONNECT_COPY_FAILURES.fetch_add(1, Ordering::Relaxed);
                        if failures < 8 {
                            print_str(b"[win32k-svc] NtUserProcessConnect USERCONNECT copy-out failed pi=");
                            print_u64(pi as u64);
                            print_str(b" buffer=0x");
                            print_hex((a1 >> 32) as u32);
                            print_hex(a1 as u32);
                            print_str(b" bytes=");
                            print_u64(blen);
                            print_str(b"\n");
                        }
                        ok = false;
                        st = 0xC000_0001;
                    }
                }
                // BATCH 43: throttle the status line for the same hot class-loop SSNs (WALL statuses ALWAYS
                // print — a wall is never suppressed).
                if !redirected_user_callback && (!ok || w32_log) {
                    print_str(b"[win32k-svc] ");
                    print_str(win32k_client_label(&nt_handler, pi));
                    print_str(b" SSN 0x");
                    print_hex(m0 as u32);
                    print_str(if ok {
                        b" -> status=0x"
                    } else {
                        b" -> WALL status=0x"
                    });
                    print_hex(st as u32);
                    print_str(b"\n");
                }
                // ★ DESKTOP-HEAP CLIENT-WINDOW MAPPING. Once win32k has bound the Default desktop it
                // publishes (per dispatch, via the coherent shared page) the DESKTOPINFO server VA
                // (SH_SAS_DESKINFO) + the dispatch THREADINFO server VA (SH_SAS_PTI == every window's
                // head.pti). Seed the interactive GUI client's TEB.Win32ClientInfo so user32's
                // client-side ValidateHwnd/DesktopPtrToUser/IntCallMessageProc resolve real heap-
                // resident PWNDs in the process' RO-mapped heap view without a syscall:
                //   - Win32ThreadInfo (TEB+0x78) = pti (server VA), matching Wnd->head.pti.
                //   - CLIENTINFO.pDeskInfo (TEB+0x820) = DESKTOPINFO minus the pool-map delta.
                //   - CLIENTINFO.ulClientDelta (TEB+0x828) = USER heap server->client delta.
                // This used to be winlogon-only for the SAS path; explorer's real shell/ATL path uses
                // the same ReactOS client-side `IsWindow` and subclass validation, so every hosted
                // GUI main thread must be restated after win32k can clear the fields.
                if let Some(teb_alias) = hosted_gui_thread_teb_alias_for(
                    &nt_handler,
                    pi,
                    badge,
                    current_tid,
                    tp_worker_identity,
                    is_wl_worker,
                ) {
                    if let Some((client_deskinfo, pti, delta)) =
                        seed_gui_thread_client_info(pi, teb_alias, pml4)
                    {
                        if pi == 2 {
                            if WINLOGON_DESKHEAP_MAPPED.swap(1, Ordering::Relaxed) == 0 {
                                print_str(b"[wl-main] winlogon CLIENTINFO seeded for client-side ValidateHwnd: pDeskInfo=0x");
                                print_hex((client_deskinfo >> 32) as u32);
                                print_hex(client_deskinfo as u32);
                                print_str(b" pti=0x");
                                print_hex((pti >> 32) as u32);
                                print_hex(pti as u32);
                                print_str(b" ulClientDelta=0x");
                                print_hex((delta >> 32) as u32);
                                print_hex(delta as u32);
                                print_str(b"\n");
                            }
                        } else {
                            let bit = 1u64 << pi;
                            if GUI_CLIENTINFO_SEED_LOGGED.fetch_or(bit, Ordering::Relaxed) & bit
                                == 0
                            {
                                print_str(b"[gui-clientinfo] pi=");
                                print_u64(pi as u64);
                                print_str(b" CLIENTINFO seeded for client-side ValidateHwnd: pDeskInfo=0x");
                                print_hex((client_deskinfo >> 32) as u32);
                                print_hex(client_deskinfo as u32);
                                print_str(b" pti=0x");
                                print_hex((pti >> 32) as u32);
                                print_hex(pti as u32);
                                print_str(b" ulClientDelta=0x");
                                print_hex((delta >> 32) as u32);
                                print_hex(delta as u32);
                                print_str(b"\n");
                            }
                        }
                    }
                }
                // ★ CLIENT-GDI HANDLE-TABLE MAPPING. GUI clients whose PEB+0xf8 was seeded before
                // gdi32's GdiProcessSetup must also have the live win32k GDI table projected into
                // their VSpace before client-side GdiValidateHandle runs. Winlogon needs this for the
                // msgina dialog DC/font setup; later interactive shell clients use the same cataloged
                // role path instead of fixed pi checks.
                if hosted_process_uses_client_gdi(&nt_handler, pi) {
                    let gdi_va = win32k_glue::map_gdi_shared_handle_table_into_client(pml4, pi);
                    let gdi_attributes = win32k_glue::map_gdi_user_attributes_into_client(pml4, pi);
                    if gdi_va != 0 && gdi_attributes {
                        record_hosted_client_gdi_mapping(&nt_handler, pi, gdi_va);
                    }
                }
                // ★ EAGER DESKTOP-GFX HOOK FULLY RETIRED. There is no longer any m0==0x125a
                // SSN_INIT_DESKTOP_GFX scaffold here: win32k's own NtUserInitialize (0x125a) dispatch
                // seeds the host prerequisites the display init depends on (the system font +
                // WinSta0/Default Ob objects — see win32k_subsystem::dispatch_loop's post-0x125a step). The
                // actual InitVideo/framebuf-surface bringup AND the paint now happen FULLY LAZILY from
                // winlogon's OWN first GUI DC-op: NtUserSwitchDesktop → co_IntShowDesktop →
                // co_UserRedrawWindow → WM_ERASEBKGND → UserGetDCEx(DCX_CACHE) → DceAllocDCE →
                // DceCreateDisplayDC → co_IntGraphicsCheck(TRUE) → co_AddGuiApp →
                // co_IntInitializeDesktopGraphics (InitVideo/surface :278/:286 + the atomic paint :340).
                // The counted exec_win32k_desktop_painted spec is fed by the m0==0x1288 arm above.
                if redirected_user_callback {
                    result = nt_user_callback::STATUS_PENDING as u32 as u64;
                } else if ok {
                    result = st; // pointer-width NtUser/NtGdi return value back to the caller
                    if pi == 2 && m0 == 0x1077 && st != 0 {
                        observe_winlogon_completed_dispatch(
                            win32k_glue::CompletedWin32kDispatch {
                                ssn: m0,
                                args: [a0, a1, a2, a3],
                                caller_sp: sp,
                                status: st,
                            },
                            filled_pages,
                            faults as usize,
                            scratch_base,
                        );
                    }
                    // ★ BATCH 45 — QUIESCE at the InitializeSAS-complete milestone. `UserSetLogonNotifyWindow`
                    // (0x127c) is winlogon's DEFINING final interactive step: it registers its logon-notify
                    // window, which happens exactly once after the SAS window exists. Past this, winlogon
                    // enters its SAS message loop (an infinite NtUserGetMessage wait we don't service) and
                    // never returns to the executive → the boot would never quiesce and the gate never runs
                    // (the BATCH-44 620s timeout). This is the win32k analogue of the listener milestone
                    // parks below: winlogon's TCB stays blocked at this proven-advanced steady state, the boot
                    // quiesces, and the gate runs cleanly. Gated on the SAS HWND milestone so we only park
                    // once winlogon actually created its window (never on the old NULL-HWND failure path).
                    if pi == 2
                        && m0 == 0x127c
                        && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) != 0
                    {
                        // UserSetLogonNotifyWindow success = the SAS window + logon-notify registration is
                        // done. winlogon now runs the InitializeSAS tail (SetDefaultLanguage) + WinMain's
                        // post-SAS setup (RemoveStatusMessage, GetSetupType, PostMessage(WLX_WM_SAS),
                        // NtInitializeRegistry) then enters its GetMessage loop. Do NOT park here — let it
                        // advance; the message-loop milestone park (0x1006/0x1001 above) is its real steady
                        // state. (Reaching 0x127c-success now requires the PsLookup/gpidLogon fix, else the
                        // logon-process access check would fail SetLogonNotifyWindow → InitializeSAS FALSE.)
                        print_str(b"[wl-main] winlogon registered logon-notify window (0x127c) = SAS window ready -> advancing to post-SAS setup\n");
                    }
                } else {
                    handled = false; // dispatch wall — stop with the SSN recorded
                    result = 0xC0000001;
                }
            } else {
                handled = false;
                result = 0xC0000002; // STATUS_NOT_IMPLEMENTED
            }
            if !handled {
                // ★ BATCH 43 — winlogon SAS-window MILESTONE park (recv-next-without-reply). winlogon has
                // CROSSED its win32k class-call-proc wall and created its SAS window; its further
                // window-show→paint flow exceeds the 620s TCG budget. Park it here (its TCB stays blocked
                // at the proven-advanced state) and QUIESCE to the gate — provided the boot is otherwise at
                // steady state (winlogon crossed msgina + LSA signalled). This is the win32k analogue of the
                // listener milestone parks below.
                if wl_milestone_park {
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    let userinit_shell_pending =
                        userinit_shell_frontier_pending(&nt_handler, crash_parked, wait_parked);
                    if !wl_park_defer_quiesce
                        && !userinit_shell_pending
                        && WINLOGON_KEY_OPENED.load(Ordering::Relaxed) != 0
                        && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[quiesce] winlogon reached its win32k SAS-window milestone + steady state -> run gate\n");
                        stop = m0;
                        break;
                    } else if userinit_shell_pending {
                        print_str(b"[quiesce] winlogon milestone parked; deferring gate until userinit attempts its shell image\n");
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // After logon has succeeded, an unimplemented win32k syscall from winlogon's main
                // thread is the same kind of frontier as the post-logon VM/#BP milestone parks
                // above. Do not route this through `park_and_log!`: that helper intentionally
                // latches the whole process as a dead callback client, which is wrong here because
                // the expendable worker threads remain alive and hold no callback frames. The
                // post-quiesce callback-injection gates depend on that distinction.
                if hosted_pi_has_role(
                    &nt_handler,
                    pi,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && hosted_owner_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && WINLOGON_LOGON_TOKEN_QUERIES.load(Ordering::Relaxed) != 0
                    && !win32k_glue::client_has_active_callback_frames(pi as u32)
                {
                    print_str(b"[wl-main] winlogon COMPLETED THE INTERACTIVE LOGON; its POST-LOGON path hit unimplemented win32k SSN=0x");
                    print_hex(m0 as u32);
                    print_str(
                        b" -> MILESTONE park (holds no win32k callback frame; boot continues)\n",
                    );
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    WINLOGON_POST_LOGON_MILESTONE_PARK.store(m0, Ordering::Relaxed);
                    WINLOGON_POST_LOGON_MILESTONE_CR2.store(m0, Ordering::Relaxed);
                    if (live_top_badges(&nt_handler) & !(crash_parked | wait_parked)) == 0
                        || LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[quiesce] all live processes parked/waiting -> run gate\n");
                        stop = m0;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                if is_tp_worker {
                    print_str(b"[tp-worker] blocking/unserviced syscall badge=");
                    print_u64(badge);
                    print_str(b" SSN=");
                    print_u64(m0);
                    print_str(b" -> PARK generic worker; owner continues\n");
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // N-threads multiplex: a SERVER thread (svc/lsass listener) that walls on an unserviced
                // BLOCKING server-loop syscall (e.g. NtListenPort / NtReplyWaitReceivePort — it reached
                // its LPC/RPC receive loop and would block forever waiting for a client) PARKS instead of
                // stopping the whole boot. Recv the next event WITHOUT replying → the listener's seL4
                // thread stays blocked (its ETHREAD/TEB/stack stay mapped), and lsass' main thread + the
                // rest of the boot keep advancing. Contained per-thread — the point of the multiplex.
                if is_svc_listener
                    || is_scm_worker
                    || is_lsass_listener
                    || is_lsass_listener2
                    || is_lsass_listener3
                    || is_lsa_worker
                    || is_wl_worker
                {
                    print_str(if is_wl_worker {
                        b"[wl-worker] blocking/unserviced server syscall SSN="
                    } else if is_scm_worker {
                        b"[scm-worker] blocking/unserviced server syscall SSN="
                    } else if is_lsa_worker {
                        b"[lsa-worker] blocking/unserviced server syscall SSN="
                    } else if is_lsass_listener || is_lsass_listener2 || is_lsass_listener3 {
                        b"[lsass-listener] blocking server syscall SSN="
                    } else {
                        b"[svc-listener] blocking server syscall SSN="
                    });
                    print_u64(m0);
                    print_str(b" -> PARK thread (reached its RPC receive loop / unserviced); boot continues\n");
                    // ★ LSA rendezvous safety: never leave the LSA client blocked on a server that
                    // just walled — release it with the real failure so its own error path runs.
                    if LSA_SRV_LIVE_BADGE.load(Ordering::Relaxed) == badge {
                        let _ = lsa_release_client_on_server_wall(m0);
                    }
                    if is_wl_worker && WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed) != 0
                    {
                        print_str(b"[wl-worker] parked before signalling the waiting winlogon main thread -> run gate\n");
                        stop = m0;
                        break;
                    }
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    // BATCH 40: a PURE-SERVER listener (services pi3 / lsass pi4) reaching its RPC
                    // receive loop is a terminal cooperative park (it blocks forever waiting for a
                    // client, and by now its process' main thread is done its bring-up). Count its
                    // OWNER process toward the all-parked quiesce so the boot reaches the gate once
                    // every live process is parked — otherwise (now that winlogon crosses msgina and no
                    // longer CRASHES to trigger a quiesce) the main loop blocks in recv forever after
                    // the last listener parks. EXCLUDE is_wl_worker: it shares winlogon's badge whose
                    // MAIN thread has its own SCM-RPC-read quiesce path — marking winlogon here while its
                    // main is still active would quiesce prematurely. mark_wait_parked! only breaks at
                    // true all-parked deadlock; otherwise it just records the bit and recv proceeds.
                    if is_svc_listener {
                        // The SCM listener parking → no live signaler for winlogon's SCM read.
                        SVC_LISTENER_PARKED.store(1, Ordering::Relaxed);
                    }
                    if !is_wl_worker {
                        mark_wait_parked!(pi, m0);
                    }
                    // BATCH 40 terminal backstop: once winlogon has CROSSED its msgina GINA init
                    // (WINLOGON_KEY_OPENED > 0 — WlxInitialize got a non-NULL context, no
                    // WlxShutdown(NULL) crash) AND lsass has signalled LSA_RPC_SERVER_ACTIVE, the boot
                    // has reached steady state: the only remaining live top-level processes are the
                    // persistent SCM/LSA/CSR RPC SERVERS with no live terminating client. A server
                    // listener parking here (SSN=24 = its blocking receive) means it will block forever
                    // waiting for a client the (crashed/parked) clients will never send — so the main
                    // loop's next recv would hang forever (winlogon no longer CRASHES to trigger the
                    // old msgina-wall quiesce). QUIESCE to the gate. Gated on the msgina-crossed +
                    // LSA-signalled steady state so it never fires during live bring-up.
                    // Gate the terminal quiesce on winlogon having reached its SAS MESSAGE-LOOP milestone
                    // (WINLOGON_MSGLOOP_MILESTONE) in addition to the msgina + LSA steady state. Without
                    // this, a server listener parking races winlogon's post-InitializeSAS flow: it fires
                    // right after SetDefaultLanguage (SSN 224) and stops the loop before winlogon issues
                    // PostMessage(WLX_WM_SAS) / enters GetMessage. Requiring the message-loop milestone makes
                    // the quiesce deterministic — winlogon is parked at its genuine steady state first.
                    if WINLOGON_KEY_OPENED.load(Ordering::Relaxed) != 0
                        && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                        && WINLOGON_MSGLOOP_MILESTONE.load(Ordering::Relaxed) >= 2
                    {
                        print_str(b"[quiesce] server listener parked + winlogon parked at empty SAS message loop + LSA signalled -> steady state -> run gate\n");
                        stop = m0;
                        break;
                    }
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // ★ N-processes multiplex (BATCH 17): smss' (badge 0) main thread terminating must NOT
                // stop the whole boot while a HIGHER hosted process (winlogon) still has pending work.
                // smss reaches NtRaiseHardError (SSN 190) via SmpTerminate (smss.c:SmpTerminate ->
                // NtRaiseHardError(STATUS_SYSTEM_PROCESS_TERMINATED) -> NtTerminateProcess) — its death
                // cry after it has finished spawning csrss + winlogon. In real NT smss then WAITS on the
                // subsystem handles; here its main thread is done its bring-up job. PARK it (recv next
                // WITHOUT replying, exactly like a server listener) so winlogon's user32 window-class /
                // cursor init keeps being serviced instead of freezing at its 0x103d fetch. Behavior-
                // preserving for smss (it was terminating regardless); unblocks the higher process. This
                // is the same class of fix as BATCH 10 (a terminal syscall from one process killed the
                // shared loop), generalized to smss' hard-error path.
                if badge == 0 && m0 == 190 {
                    print_str(b"[smss] NtRaiseHardError(190) = SmpTerminate -> PARK smss main; winlogon continues\n");
                    // Terminal for smss (its bring-up job is done) — count it toward quiesce so the
                    // loop can cleanly exit once every other live process is parked too.
                    crash_parked |= 1u64 << owner_top_badge_for(&nt_handler, badge);
                    procs[pi].faults = faults;
                    procs[pi].first = first;
                    procs[pi].ntfaults = ntfaults;
                    pfilled[pi] = *filled_pages;
                    let (nb, nmi, nm0, nm1, nm2, nm3) =
                        recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                if hosted_main_badge_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                ) && m0 == 190
                {
                    // DIAG (BATCH 21): winlogon's hard-error site — dump raw args while its mirror
                    // is active (ErrorStatus=R10, param0=[stack], caller=[rsp]).
                    print_str(b"[wl-190] R10=0x");
                    print_hex((get_recv_mr(9) >> 32) as u32);
                    print_hex(get_recv_mr(9) as u32);
                    print_str(b" RDX=0x");
                    print_hex(m3 as u32);
                    print_str(b" R8=0x");
                    print_hex(get_recv_mr(7) as u32);
                    print_str(b" sp=0x");
                    print_hex(get_recv_mr(16) as u32);
                    print_str(b" [sp]=0x");
                    print_hex(smss_stack_read(get_recv_mr(16)) as u32);
                    print_str(b"\n");
                }
                // An Nt* syscall we don't service yet AND can't safely fake a result for — the process
                // can't make progress. Record the SSN for the report line, then park+log this process
                // (unrecoverable for it) and let the shared loop keep servicing the others.
                stop_ssn = m0;
                park_and_log!(pi, b"unhandled-syscall", m0, m0);
            }
            set_reply_mr(15, resume_ip);
            set_reply_mr(16, sp);
            set_reply_mr(17, flags);
            procs[pi].faults = faults;
            procs[pi].first = first;
            procs[pi].ntfaults = ntfaults;
            pfilled[pi] = *filled_pages;
            let reply_main = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
            if park_io_completion_port >= 0 && reply_main != 0 {
                if park_io_completion_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if io_completion_park(
                    &mut nt_handler,
                    park_io_completion_port as u32,
                    park_io_completion_key_out,
                    park_io_completion_apc_out,
                    park_io_completion_iosb_out,
                    park_io_completion_deadline.unwrap_or(u64::MAX),
                    resume_ip,
                    sp,
                    flags,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[io-completion] pi=");
                    print_u64(pi as u64);
                    print_str(b" port=");
                    print_u64(park_io_completion_port as u64);
                    print_str(b" -> PARK remover\n");
                    let received = recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                } else {
                    print_str(
                        b"[io-completion] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n",
                    );
                    result = 0xC000_009A;
                }
            }
            if let Some(deadline) = park_delay_deadline {
                if delay_park(
                    &mut delay_queue,
                    deadline,
                    reply_main,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    badge,
                ) {
                    if DELAY_PARKED_COUNT.load(Ordering::Relaxed) <= 16 {
                        print_str(b"[delay] PARKED badge=");
                        print_u64(badge);
                        print_str(b" tid=");
                        print_u64(nt_handler.current_tid);
                        print_str(b" queued=");
                        print_u64(delay_queue.len() as u64);
                        print_str(b" -> receive continues\n");
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let received = recv_full_r12(fault_ep, new_reply);
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                }
                print_str(b"[delay] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                result = 0xC000_009A;
            }
            // Keyed-event wait park (`NtWaitForKeyedEvent`): used by ReactOS condition variables and
            // run-once state. The matching `NtReleaseKeyedEvent` wakes via keyed_wait_wake_one.
            if park_keyed_wait_key != u64::MAX && reply_main != 0 {
                if park_keyed_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if keyed_wait_park(
                    park_keyed_wait_key,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_keyed_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[keyed] NtWaitForKeyedEvent key=0x");
                    print_hex_u64(park_keyed_wait_key);
                    print_str(b" -> PARK caller\n");
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let received = recv_full_r12(fault_ep, new_reply);
                    badge = received.0;
                    mi = received.1;
                    m0 = received.2;
                    m1 = received.3;
                    m2 = received.4;
                    m3 = received.5;
                    continue;
                } else {
                    print_str(b"[keyed] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // Checkpoint B: PARK this caller on an unsignaled event (steal its reply cap into the waiter
            // queue keyed by the event, rotate REPLY_MAIN to a fresh pool object, recv the next event
            // WITHOUT replying). The matching NtSetEvent wakes it. If the pool/queue is exhausted,
            // wait_park returns false → fall through to a normal (immediate WAIT_0) reply, never a hang.
            // A winlogon worker that has started but has not yet created the SAS/status window is a
            // live signaler for the main thread's anonymous server-ready event. The historical
            // `WL_WORKER_FAULTS > 0` shortcut treated any serviced worker syscall as a terminal park
            // and stopped immediately after RegisterClassExWOW, before the runnable worker's next
            // timeslice. Park the main thread normally and keep servicing the worker instead.
            let winlogon_worker_can_signal = park_wait_event >= 0
                && hosted_pi_has_role(
                    &nt_handler,
                    pi,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                )
                && hosted_main_badge_has_role(
                    &nt_handler,
                    badge,
                    nt_exe_image::HostedProcessRole::InteractiveLogon,
                )
                && nt_handler
                    .hosted_thread_tcb_for_role(pi, HostedThreadRole::WinlogonWorker { slot: 1 })
                    .is_some()
                && WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed) == 0;
            if park_wait_event >= 0 && reply_main != 0 {
                if park_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if wait_park(
                    park_wait_event as usize,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    // An INDEFINITE (no-deadline) wait by a top-level process is quiesce-relevant: if
                    // every live process is now parked, no signaler remains → run the gate. A
                    // deadline-bounded wait is timer-woken, so it never deadlocks — don't count it.
                    if winlogon_worker_can_signal {
                        WINLOGON_MAIN_EVENT_WAIT_PARKED.store(1, Ordering::Relaxed);
                        print_str(b"[wl-main] parked on worker-ready event; runnable worker remains a signaler\n");
                    } else if park_wait_deadline.is_none() {
                        trace_indefinite_wait_park(
                            &nt_handler,
                            badge,
                            live_top_badges(&nt_handler),
                            crash_parked,
                            wait_parked,
                        );
                        if pi_is_top_level(&nt_handler, badge) {
                            mark_wait_parked!(pi, resume_ip);
                        }
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                } else {
                    print_str(b"[wait] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // Array-wait park (NtWaitForMultipleObjects): PARK on the resolved event SET (WaitAny/All).
            // The matching NtSetEvent (signal_state_changed → SetEvent(mgr_event)) wakes it via
            // dispatcher wake path, returning WAIT_0+index. Pool/queue exhaustion → immediate fallback.
            if park_wait_set_n > 0 && reply_main != 0 {
                if park_wait_deadline.is_some() && !delay_timer_init() {
                    result = 0xC000_009A;
                } else if wait_park_multi(
                    &park_wait_set[..park_wait_set_n],
                    &park_wait_indices[..park_wait_set_n],
                    park_wait_set_all,
                    resume_ip,
                    sp,
                    flags,
                    nt_handler.current_tid,
                    park_wait_deadline,
                ) {
                    delay_timer_rearm(&delay_queue);
                    print_str(b"[wait] pi=");
                    print_u64(pi as u64);
                    print_str(b" NtWaitForMultipleObjects(");
                    print_u64(park_wait_set_n as u64);
                    print_str(if park_wait_set_all {
                        b" events, WaitAll) UNSIGNALLED -> PARK caller\n"
                    } else {
                        b" events, WaitAny) UNSIGNALLED -> PARK caller\n"
                    });
                    if park_wait_deadline.is_none() {
                        trace_indefinite_wait_park(
                            &nt_handler,
                            badge,
                            live_top_badges(&nt_handler),
                            crash_parked,
                            wait_parked,
                        );
                        if pi_is_top_level(&nt_handler, badge) {
                            mark_wait_parked!(pi, resume_ip);
                        }
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                } else {
                    print_str(b"[wait] array park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    result = 0xC000_009A;
                }
            }
            // BATCH 33 — PIPE-PENDING PARK: a real npfs pipe read / TRANSCEIVE returned STATUS_PENDING
            // (no data yet). Steal this caller's reply cap into the PipeWaiterTable keyed by the reading
            // end fid (rotate REPLY_MAIN to a fresh pool object), recv the next event WITHOUT replying —
            // the caller stays blocked in-kernel. A later peer write re-drives it (pipe_redrive_all).
            // Pool/table exhaustion returns STATUS_INSUFFICIENT_RESOURCES; returning PENDING without
            // retaining an owned IRP would leave both completion and ThreadIsIoPending inconsistent.
            if park_pipe_fid != 0 && reply_main != 0 {
                if pipe_wait_park(
                    park_pipe_fid,
                    pi as u32,
                    nt_handler.current_tid,
                    badge,
                    park_pipe_buffer_va,
                    park_pipe_buffer_len,
                    park_pipe_iosb_va,
                    park_pipe_apc_context,
                    park_pipe_event_obj_idx,
                    park_pipe_transceive,
                    park_pipe_is_write,
                    resume_ip,
                    sp,
                    flags,
                ) {
                    print_str(b"[pipe-park] badge=");
                    print_u64(badge);
                    print_str(b" fid=0x");
                    print_hex(park_pipe_fid as u32);
                    print_str(b" -> PARK reader (re-driven on peer write)\n");
                    // Quiesce accounting: a top-level process (winlogon) parked on a pipe read whose
                    // peer may never write is quiesce-relevant — if every live process is now parked
                    // (crash OR wait OR pipe) with no runnable signaler, break to the gate rather than
                    // block the loop's recv forever. A listener/worker sub-thread parking is NOT
                    // quiesce-relevant (its parent process may still run + write).
                    if pi_is_top_level(&nt_handler, badge) {
                        // ★ BATCH 34 — the SCM server round-trip is now LIVE. winlogon's SCM-RPC read
                        // parking (recoverable, re-drivable) is NO LONGER terminal once its ncacn_np
                        // SERVER peer (services' SCM listener) has been connected: a client connect
                        // completed the server's async FSCTL_PIPE_LISTEN + signalled its event, so the
                        // svc-listener is a RUNNABLE (non-top-level, badge 7) signaler that will read the
                        // bind PDU and write bind_ack — which re-drives THIS parked read (batch-33 edge).
                        // The all-top-level-parked quiesce test does NOT see the runnable svc-listener, so
                        // marking winlogon parked here would falsely quiesce. So while the server is live
                        // (a listen was signalled), DON'T mark_wait_parked! (skip the immediate quiesce)
                        // — just continue the loop's recv: the runnable server produces events, and the
                        // 45s wall-clock progress watchdog still stops the loop cleanly if it truly stalls.
                        // The SCM server is LIVE only while its listener is signalled AND still running
                        // (not terminated). BATCH 35 routes the per-connection RPC worker into the
                        // multiplex, but until the worker's trampoline-entry fault is resolved (it PARKS
                        // unrecoverably — see the BATCH 35 frontier note) it is NOT a live signaler, so we
                        // do NOT treat a spawned-but-faulted worker as keeping the server live (that would
                        // hang the loop's recv with no signaler → boot timeout). Once the listener exits
                        // there is no signaler for winlogon's SCM read, so parking is terminal → quiesce.
                        let scm_server_live = pi == 2
                            && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                            && PIPE_LISTEN_SIGNALLED_COUNT.load(Ordering::Relaxed) != 0
                            && SVC_LISTENER_TERMINATED.load(Ordering::Relaxed) == 0
                            // BATCH 40: a PARKED listener (persistent-server world) is no longer a live
                            // signaler either — treat it like TERMINATED so winlogon's read-park becomes
                            // terminal and the boot quiesces (else the loop's recv hangs forever).
                            && SVC_LISTENER_PARKED.load(Ordering::Relaxed) == 0;
                        if !scm_server_live {
                            mark_wait_parked!(pi, resume_ip);
                            // Terminal backstop: winlogon's SCM read parking with NO live server signaler
                            // (no listen ever signalled, or the listener has exited) after LSA is signalled
                            // is its steady state — run the gate rather than block recv forever.
                            if pi == 2
                                && LSA_RPC_SERVER_ACTIVE_SIGNALLED.load(Ordering::Relaxed) != 0
                            {
                                print_str(b"[wl-main] winlogon SCM-RPC read parked (no live server signaler) + LSA signalled -> QUIESCE; run gate\n");
                                stop = resume_ip;
                                break;
                            }
                        } else {
                            // BATCH 43: only log on the FIRST 0→1 transition (this fires on every SCM read
                            // retry; serial writes dominate the TCG per-round-trip cost, and the boot budget
                            // is now tight with winlogon's heavier post-win32k-wall flow).
                            let first = WINLOGON_SCM_PARKED.swap(1, Ordering::Relaxed) == 0;
                            // BATCH 39 — defense-in-depth REASSERT of winlogon's client CLIENTINFO on the
                            // SCM-RPC read-park path (winlogon's LAST activity before its post-OpenSCManager
                            // GUI init calls user32 GetThreadDesktopWnd). win32k's IntSetThreadDesktop ELSE
                            // branch clears TEB.Win32ThreadInfo(+0x78)/pDeskInfo(+0x820); re-seed via the
                            // executive's persistent alias of winlogon's TEB frame. (The primary guarantee
                            // is the spawn seed + the fault-time repair; this keeps the window minimal.)
                            let _ = seed_winlogon_thread_client_info(
                                WINLOGON_MAIN_TEB_MIRROR_VA,
                                procs[2].pml4,
                            );
                            if first {
                                print_str(b"[wl-main] winlogon SCM-RPC read parked; SCM server LIVE (listener signalled + running) -> continue recv (server may write bind_ack)\n");
                            }
                        }
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                } else {
                    print_str(b"[pipe-park] park unavailable -> STATUS_INSUFFICIENT_RESOURCES\n");
                    nt_handler.release_file_reference(park_pipe_fid);
                    result = 0xC000_009A;
                }
            }
            // ★ Dbgk TARGET-SIDE BLOCK, SYSCALL flavour (`DbgkpQueueMessage`'s wait on
            // `DebugEvent->ContinueEvent`). This syscall posted a debug event for a process whose
            // debugger is attached, and NT blocks the REPORTING thread until `NtDebugContinue`.
            // Park it with the SYSCALL reply shape (status in MR0 + resume context in MR15/16/17 —
            // the shape `dbgk_reporter_resume` replays) and recv the next event WITHOUT replying.
            // The block rides on the `DEBUG_EVENT`; a debug-object teardown / the post-loop drain
            // releases it, so it can never wedge the boot. `park_dbgk_reporter` is false on every
            // boot today (nothing attaches a debugger), so this whole block is skipped.
            if park_dbgk_reporter && reply_main != 0 {
                if nt_handler.dbgk_block_reporter(
                    pi,
                    nt_handler.current_tid,
                    badge,
                    nt_process::dbgk::DBGK_BLOCK_SYSCALL,
                    0,
                    resume_ip,
                    sp,
                    flags,
                    result,
                ) {
                    print_str(b"[dbgk] reporter BLOCKED on continue (syscall) pi=");
                    print_u64(pi as u64);
                    print_str(b" badge=");
                    print_u64(badge);
                    print_str(b"\n");
                    // A blocked reporter is a COOPERATIVE wait (the debugger's continue wakes it),
                    // so it counts toward the all-parked quiesce exactly like every other wait —
                    // the boot still reaches the gate if the debugger never continues.
                    if pi_is_top_level(&nt_handler, badge) {
                        mark_wait_parked!(pi, resume_ip);
                    }
                    let new_reply = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
                    let (nb, nmi, nm0, nm1, nm2, nm3) = recv_full_r12(fault_ep, new_reply);
                    badge = nb;
                    mi = nmi;
                    m0 = nm0;
                    m1 = nm1;
                    m2 = nm2;
                    m3 = nm3;
                    continue;
                }
                // Could not park (no reply object / pool exhausted / nothing eligible took the
                // block) — fall through to the ordinary reply: post-and-continue, never a hang.
                print_str(b"[dbgk] reporter block unavailable -> post-and-continue\n");
            }
            // ★ PHASE 3 — ONE reply shape for every serviced client syscall: resume the caller
            // through the reply object the KERNEL bound to it at its recv (`decode_reply` →
            // `replies[idx].bound_tcb`), then recv the next event re-registering that same object.
            //
            // What used to be here was a four-way fork whose only purpose was deciding whether the
            // executive's single legacy `reply_to` slot could still be trusted: it is written on the
            // RECEIVER by every incoming `Call`, so a component dispatch (or one of its demand-page
            // faults) serviced during this syscall silently re-pointed it at the COMPONENT, and the
            // "fast path" would then resume npfs with a length-18 syscall result while the real
            // client slept forever (the hang that ended the first Phase-1 boot). `routed_win32k`,
            // `routed_lpc`, `routed_csr` and `COMPONENT_CALL_CLOBBERED_REPLY_TO` were four ways of
            // asking "did anything clobber it?". With the legacy reply retired the question is moot:
            // nothing can re-point a bound reply object, so the answer is always the same reply.
            // TAIL WATCH tag 3: the executive has FINISHED servicing this native syscall and has not
            // yet resumed the caller. A transition seen here is the executive's own handler; a
            // transition that only ever shows at tag 0 happened while the CLIENT was running.
            crate::teb_tail_watch(pi, 3, m0, badge);
            let (nb, nmi, nm0, nm1, nm2, nm3) = if reply_main == 0 {
                // Pre-retype (demo path): no reply objects exist yet, legacy `reply_to` it is.
                reply_recv_badge(fault_ep, 18, result, m1, 0, m3)
            } else if park_caller {
                // The caller's binding was STOLEN into a park slot — do not reply, just recv.
                recv_full_r12(fault_ep, reply_main)
            } else {
                // A client redirected into a win32k user-mode callback resumes with the length-0
                // fault reply the redirect staged, not with a syscall result.
                let len = if redirected_user_callback { 0 } else { 18 };
                let (r0, r1, r3) = if redirected_user_callback {
                    (0, 0, 0)
                } else {
                    (result, m1, m3)
                };
                client_reply_on(reply_main, len, r0, r1, 0, r3);
                recv_full_r12(fault_ep, reply_main)
            };
            badge = nb;
            mi = nmi;
            m0 = nm0;
            m1 = nm1;
            m2 = nm2;
            m3 = nm3;
            continue;
        }
        // A non-VMFault, non-syscall fault (e.g. #GP) the loop can't service — unrecoverable. Park+log.
        park_and_log!(pi, b"other-fault", m1, m1);
    }
    // ★ THE ESCAPE HATCH (unconditional, bounded). The service loop is done: release every reporter
    // still blocked on a debug event, so a debugger that attached, took an event and never continued
    // (or died holding one) can NEVER leave a target parked with its reply capability stranded. With
    // no debug object alive — every boot today — this returns on its first line and costs nothing.
    {
        let released = nt_handler.dbgk_release_all_blocked_reporters();
        if released != 0 {
            print_str(b"[dbgk] post-loop drain released ");
            print_u64(released as u64);
            print_str(b" blocked reporter(s)\n");
        }
    }
    // === DEAD-CLIENT CALLBACK-UNWIND FAULT INJECTION (POST-QUIESCE). The boot's whole load-bearing
    // flow is finished here — winlogon's SAS → msgina dialog → the authentic desktop/dialog paints
    // have completed and their counters are latched — and win32k is idle in its dispatch receive
    // loop. That makes this the one point where a client can be deliberately killed MID-CALLBACK
    // without perturbing anything: the injection drives an expendable winlogon RPC worker thread into
    // a REAL win32k user-mode callback (WM_NULL, so nothing can change), terminates it there, and
    // asserts `unwind_dead_client_user_callbacks` recovers win32k. Without that unwind this is the
    // shape that WEDGED the boot (RUNEXIT=124, no gate at all). See `exec_user_callback_dead_client_unwind`. ===
    // === PRIVATE-VM COMMIT/DECOMMIT/RE-COMMIT SELF-TEST (POST-QUIESCE). Runs on the real
    // `vm_map_private_page` path in a real hosted VSpace, at a VA above every placement the boot
    // makes, so it perturbs nothing. See `private_vm_unmap_selftest`. ===
    crate::private_vm_unmap_selftest(2, procs[2].pml4, procs[2].scratch_base);
    if ntdll.is_some() && WIN32K_TCB.load(Ordering::Relaxed) != 0 {
        let client_pid = nt_handler.pm_pid_for_pi(2).unwrap_or(0) as u64;
        let scratch_base = procs[2].scratch_base;
        if let Some(callback_thread) = winlogon_callback_thread_candidate(&nt_handler) {
            // ★ FIRST: the NESTED request↔reply BINDING injection (`exec_win32k_transport_call_nested`).
            // It runs on the SAME expendable worker but leaves it ALIVE and latches nothing, so the
            // dead-client injection below still finds a live, redirectable thread. Order matters: the
            // dead-client injection latches winlogon's pi as DEAD, after which no further callback can
            // park and this injection could not arm.
            let nested_proof = win32k_glue::inject_win32k_nested_dispatch_slip(
                client_pid,
                scratch_base,
                callback_thread,
            );
            WIN32K_NESTED_SLIP_INJECTION.store(nested_proof, Ordering::Relaxed);
            let mut terminate_victim = |victim_tid: u64| {
                let terminated = terminate_hosted_thread_mechanism(
                    victim_tid,
                    &mut delay_queue,
                    &mut nt_handler,
                );
                win32k_glue::DeadClientVictimTermination {
                    terminated,
                    tcb_reclaimed: nt_handler.hosted_thread_tcb(victim_tid).is_none(),
                }
            };
            let proof = win32k_glue::inject_dead_client_callback_unwind(
                client_pid,
                scratch_base,
                callback_thread,
                &mut terminate_victim,
            );
            DEAD_CLIENT_UNWIND_INJECTION.store(proof, Ordering::Relaxed);
        } else {
            print_str(b"[cb-inject] no runtime-registered winlogon callback worker -> skipped\n");
        }
    }
    // === Path 2 lifecycle self-test (POST-LOOP: no more per-syscall heap reset follows, so these
    // durable pm allocations are safe). Proves NtOpenProcess + NtTerminateProcess route through pm.
    // The 3 HOSTED EPROCESSes are left untouched — terminate runs on a THROWAWAY process. ===
    if ntdll.is_some() {
        // NtOpenProcess: smss (pi 0) opens csrss by pid → a real Process(csrss_pid) handle in smss's
        // EPROCESS table.
        nt_handler.pi = 0;
        let mut open_ok = 0u64;
        if let (Some(smss_pid), Some(csrss_pid)) =
            (nt_handler.pm_pid_for_pi(0), nt_handler.pm_pid_for_pi(1))
        {
            let object_attributes = nt_ntdll_layout::ObjectAttributes::default();
            let client_id = nt_ntdll_layout::ClientId {
                unique_process: csrss_pid as u64,
                unique_thread: 0,
            };
            if let Ok((owner, _)) = nt_handler.open_process_captured(
                object_attributes,
                Some(client_id),
                0x0400, // PROCESS_QUERY_INFORMATION
            ) {
                nt_handler.account_published_pm_handle(owner);
                open_ok |= 1;
            }
            if nt_handler
                .pm
                .close_handle_by_object(smss_pid, nt_process::HandleObject::Process(csrss_pid))
            {
                open_ok |= 2; // the opened handle really is in smss's table
            }
        }
        PM_NTOPENPROCESS_OK.store(open_ok, Ordering::Relaxed);

        // NtTerminateProcess: build a throwaway EPROCESS + thread + handle, then run the same policy
        // teardown the handler drives, and verify the process/thread are signalled + wait-able + the
        // handle table closes. Also verify the handler's ProcessHandle resolve (NtCurrentProcess→self).
        let mut life_ok = 0u64;
        let parent = nt_handler.pm_pid_for_pi(0);
        let tpid = nt_handler
            .pm
            .create_process("lifecycle-test.exe", parent, None);
        if let Ok(ttid) = nt_handler.pm.create_thread(tpid, 0x1000, 0, false) {
            let th = nt_handler
                .pm
                .insert_handle(tpid, nt_process::HandleObject::Opaque(0xDEAD), 0)
                .ok();
            nt_handler.pi = 0;
            if nt_handler.resolve_process_handle(0xFFFF_FFFF_FFFF_FFFF)
                == nt_handler.pm_pid_for_pi(0)
            {
                life_ok |= 1; // NtCurrentProcess() resolves to the caller
            }
            if nt_handler.pm.terminate_process(tpid, 0x1234).is_ok() {
                life_ok |= 2;
            }
            if nt_handler.pm.is_process_signaled(tpid) {
                life_ok |= 4;
            }
            if nt_handler.pm.is_thread_signaled(ttid) {
                life_ok |= 8; // teardown signalled the process's threads
            }
            if nt_handler.pm.wait_process(tpid) == Some(0x1234) {
                life_ok |= 16; // exit status readable via wait
            }
            if th.is_some_and(|h| nt_handler.pm.close_handle(tpid, h).is_ok()) {
                life_ok |= 32; // handle-table teardown
            }
        }
        PM_LIFECYCLE_OK.store(life_ok, Ordering::Relaxed);

        // BATCH 39 — direct NtTerminateThread MECHANISM self-test (throwaway EPROCESS + threads).
        // Drives the exact terminate path the handler uses (`resolve_terminate_thread_handle` +
        // `terminate_thread`/`exit_thread` + `can_reclaim_thread`) WITHOUT depending on any live
        // hosted-thread self-exit. This replaces the batch-38 live-lifecycle terminate specs: with
        // the SCM RPC succeeding (route ON), the SCM worker/listener PERSIST as servers instead of
        // self-exiting, so a live self-exit COUNT is no longer a stable invariant. Runs post-loop on
        // throwaway processes/threads only -> the 6 hosted processes are untouched.
        {
            use nt_process::{HandleObject, ProcessState, ThreadState};
            const THREAD_TERMINATE: u32 = 0x0001;
            let mut term_ok = 0u64;
            let parent = nt_handler.pm_pid_for_pi(0);
            // Process A: two threads. `victim` is terminated via a typed Thread handle; `bystander`
            // must keep running (proves per-thread, not per-process, termination).
            let pa = nt_handler
                .pm
                .create_process("term-selftest-a.exe", parent, None);
            if let (Ok(victim), Ok(bystander)) = (
                nt_handler.pm.create_thread(pa, 0x2000, 0, false),
                nt_handler.pm.create_thread(pa, 0x3000, 0, false),
            ) {
                // A typed Thread handle with THREAD_TERMINATE resolves to the target tid.
                let hv = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), THREAD_TERMINATE)
                    .ok();
                if let Some(hv) = hv {
                    if nt_handler.pm.resolve_terminate_thread_handle(
                        pa,
                        bystander,
                        hv as u64,
                        THREAD_TERMINATE,
                    ) == Ok(victim)
                    {
                        term_ok |= 0x01;
                    }
                }
                // A Thread handle WITHOUT THREAD_TERMINATE is rejected (access check enforced).
                if let Ok(hna) = nt_handler
                    .pm
                    .insert_handle(pa, HandleObject::Thread(victim), 0)
                {
                    if nt_handler
                        .pm
                        .resolve_terminate_thread_handle(
                            pa,
                            bystander,
                            hna as u64,
                            THREAD_TERMINATE,
                        )
                        .is_err()
                    {
                        term_ok |= 0x02;
                    }
                    let _ = nt_handler.pm.close_handle(pa, hna);
                }
                // The NULL/current pseudo-handle form (kernel32!ExitThread) resolves to the caller.
                if nt_handler
                    .pm
                    .resolve_terminate_thread_handle(pa, victim, 0, THREAD_TERMINATE)
                    == Ok(victim)
                {
                    term_ok |= 0x04;
                }
                // Terminate the victim: it becomes Terminated (signalled) with the exit status; the
                // bystander stays Ready and the EPROCESS is NOT cascaded (a live thread remains).
                if nt_handler.pm.terminate_thread(victim, 0xDEAD).is_ok()
                    && nt_handler.pm.thread(victim).is_some_and(|t| {
                        t.state == ThreadState::Terminated && t.exit_status == Some(0xDEAD)
                    })
                    && nt_handler.pm.is_thread_signaled(victim)
                    && nt_handler
                        .pm
                        .thread(bystander)
                        .is_some_and(|t| t.state != ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pa)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x08;
                    term_ok |= 0x40; // the unrelated bystander thread continued
                }
                // TCB-reclaim gating: while a process handle still refers to the terminated victim it
                // must NOT be reclaimable (TID/slot aliasing hazard); after every such handle closes
                // it becomes reclaimable. Mirrors the handler's live TCB-reclaim guard.
                if let Some(hv) = hv {
                    let blocked = !nt_handler.pm.can_reclaim_thread(victim);
                    let _ = nt_handler.pm.close_handle(pa, hv);
                    if blocked && nt_handler.pm.can_reclaim_thread(victim) {
                        term_ok |= 0x10;
                    }
                }
            }
            // Process B: exercise the NO-CASCADE exit_thread path the handler uses for a process
            // whose OTHER threads keep it alive (the csrss "CSRSRV keeps us going" shape). The init
            // thread exits but a worker thread remains → the EPROCESS stays Running.
            let pb = nt_handler
                .pm
                .create_process("term-selftest-b.exe", parent, None);
            if let (Ok(init), Ok(_worker)) = (
                nt_handler.pm.create_thread(pb, 0x4000, 0, false),
                nt_handler.pm.create_thread(pb, 0x5000, 0, false),
            ) {
                if nt_handler.pm.exit_thread(init, 0x1).is_ok()
                    && nt_handler
                        .pm
                        .thread(init)
                        .is_some_and(|t| t.state == ThreadState::Terminated)
                    && nt_handler
                        .pm
                        .process(pb)
                        .is_some_and(|p| p.state == ProcessState::Running)
                {
                    term_ok |= 0x20;
                }
            }
            PM_TERMINATE_THREAD_SELFTEST.store(term_ok, Ordering::Relaxed);
        }

        // === Dbgk END-TO-END SELF-TEST (POST-LOOP) =================================================
        // Drives the REAL user-mode debugging plane the five native handlers dispatch into:
        // create a DEBUG_OBJECT, mint a TYPED handle for it in smss's REAL EPROCESS handle table and
        // resolve it through the handler's own `debug_object_for_handle` (access checks included),
        // attach it to a THROWAWAY debuggee, retrieve the fake create-process message with
        // NtWaitForDebugEvent's core (handles opened in the debugger's table + a rendered
        // DBGUI_WAIT_STATE_CHANGE), resolve it with NtDebugContinue, observe the thread-create /
        // thread-exit / process-exit EVENT SOURCES, then detach and prove the plane goes inert.
        // The 3 hosted EPROCESSes are otherwise untouched (only smss gains + loses handles).
        {
            use nt_process::dbgk;
            nt_handler.pi = 0;
            let mut dbg_ok = 0u64;
            let debugger_pid = nt_handler.pm_pid_for_pi(0);
            if let Some(debugger_pid) = debugger_pid {
                let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
                let bad_flags_rejected = nt_handler.pm.create_debug_object(0x8000)
                    == Err(nt_process::STATUS_INVALID_PARAMETER);
                if let Ok(object) = nt_handler
                    .pm
                    .create_debug_object(dbgk::DBGK_KILL_PROCESS_ON_EXIT)
                {
                    if bad_flags_rejected
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.kill_process_on_exit())
                    {
                        dbg_ok |= 0x0001;
                    }
                    // 0x1000 — the handler's typed-handle resolution + access enforcement, driven
                    // against smss's REAL per-process handle table.
                    let full = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .ok();
                    let no_access = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .ok();
                    let wrong_type = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Opaque(0xDB6), 0)
                        .ok();
                    if full.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Ok(object)
                    }) && no_access.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(
                            h as u64,
                            dbgk::DEBUG_OBJECT_ADD_REMOVE_PROCESS,
                        ) == Err(0xC000_0022)
                    }) && wrong_type.is_some_and(|h| {
                        nt_handler.debug_object_for_handle(h as u64, 0) == Err(0xC000_0024)
                    }) {
                        dbg_ok |= 0x1000;
                    }
                    for handle in [full, no_access, wrong_type].into_iter().flatten() {
                        let _ = nt_handler.pm.close_handle(debugger_pid, handle);
                    }

                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-selftest.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_4000_0000);
                    if let Ok(main) = nt_handler.pm.create_thread(target, 0x2000, 0, false) {
                        let debugger = nt_process::ClientId {
                            unique_process: debugger_pid,
                            unique_thread: debugger_tid,
                        };
                        // 0x0002 — attach installs the port + PEB.BeingDebugged and posts + activates
                        // the fake DbgKmCreateProcessApi message.
                        if nt_handler.pm.debug_active_process(target, object, debugger) == Ok(1)
                            && nt_handler.pm.process_debug_port(target) == Some(object)
                            && nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.len() == 1 && o.events_present())
                        {
                            dbg_ok |= 0x0002;
                        }
                        // 0x0004 — a self-attach is denied and a second attach is PORT_ALREADY_SET.
                        if let Ok(second) = nt_handler.pm.create_debug_object(0) {
                            if nt_handler
                                .pm
                                .debug_active_process(debugger_pid, second, debugger)
                                == Err(nt_process::STATUS_ACCESS_DENIED)
                                && nt_handler.pm.debug_active_process(target, second, debugger)
                                    == Err(dbgk::STATUS_PORT_ALREADY_SET)
                            {
                                dbg_ok |= 0x0004;
                            }
                            nt_handler.pm.destroy_debug_object(second);
                        }
                        // 0x0008 / 0x0010 — the wait retrieves it, with REAL handles opened in the
                        // debugger's table and the state change rendered around them.
                        if let Ok(Some(result)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            let sc = &result.state_change;
                            let u64_at = |o: usize| {
                                u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]))
                            };
                            if result.state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                                && result.client_id.unique_process == target
                                && result.client_id.unique_thread == main
                                && u64_at(0x08) == target as u64
                                && u64_at(0x38) == 0x0000_0001_4000_0000
                                && u64_at(0x50) == 0x2000
                            {
                                dbg_ok |= 0x0008;
                            }
                            if result.handle_to_process != 0
                                && result.handle_to_thread != 0
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_process)
                                    == Some(nt_process::HandleObject::Process(target))
                                && nt_handler
                                    .pm
                                    .lookup_handle(debugger_pid, result.handle_to_thread)
                                    == Some(nt_process::HandleObject::Thread(main))
                                && u64_at(0x18) == result.handle_to_process as u64
                                && u64_at(0x20) == result.handle_to_thread as u64
                            {
                                dbg_ok |= 0x0010;
                            }
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_process);
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, result.handle_to_thread);
                            // 0x0020 — one outstanding event per debuggee process.
                            if matches!(
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                Ok(None)
                            ) {
                                dbg_ok |= 0x0020;
                            }
                            // 0x0040 — continue validates its status and resolves the read event.
                            if nt_handler
                                .pm
                                .debug_continue(object, result.client_id, 0x1234)
                                == Err(nt_process::STATUS_INVALID_PARAMETER)
                                && nt_handler
                                    .pm
                                    .debug_continue(object, result.client_id, dbgk::DBG_CONTINUE)
                                    .is_ok()
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                            {
                                dbg_ok |= 0x0040;
                            }
                        }
                        // 0x0080 — EVENT SOURCE: thread create.
                        if let Ok(worker) = nt_handler.pm.create_thread(target, 0x3000, 0, false) {
                            if let Ok(Some(created)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if created.state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE
                                    && created.client_id.unique_thread == worker
                                    && u64::from_le_bytes(
                                        created.state_change[0x28..0x30]
                                            .try_into()
                                            .unwrap_or([0; 8]),
                                    ) == 0x3000
                                {
                                    dbg_ok |= 0x0080;
                                }
                                let _ = nt_handler
                                    .pm
                                    .close_handle(debugger_pid, created.handle_to_thread);
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    created.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                            // 0x0100 — EVENT SOURCE: thread exit (no cascade: main still lives).
                            let _ = nt_handler.pm.exit_thread(worker, 0x1234);
                            if let Ok(Some(exited)) =
                                nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                            {
                                if exited.state == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                                    && exited.client_id.unique_thread == worker
                                    && u32::from_le_bytes(
                                        exited.state_change[0x18..0x1c]
                                            .try_into()
                                            .unwrap_or([0; 4]),
                                    ) == 0x1234
                                {
                                    dbg_ok |= 0x0100;
                                }
                                let _ = nt_handler.pm.debug_continue(
                                    object,
                                    exited.client_id,
                                    dbgk::DBG_CONTINUE,
                                );
                            }
                        }
                        // 0x0200 — EVENT SOURCE: process exit.
                        let _ = nt_handler.pm.terminate_process(target, 0x99);
                        if let Ok(Some(dead)) =
                            nt_handler.pm.wait_for_debug_event(object, debugger_pid)
                        {
                            if dead.state == dbgk::DBG_EXIT_PROCESS_STATE_CHANGE
                                && u32::from_le_bytes(
                                    dead.state_change[0x18..0x1c].try_into().unwrap_or([0; 4]),
                                ) == 0x99
                            {
                                dbg_ok |= 0x0200;
                            }
                        }
                        // 0x0400 — detach clears the port + flushes; a second detach is PORT_NOT_SET.
                        let flushed = nt_handler.pm.remove_process_debug(target, object);
                        if flushed.is_ok()
                            && nt_handler.pm.process_debug_port(target).is_none()
                            && !nt_handler.pm.is_process_being_debugged(target)
                            && nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty())
                            && nt_handler.pm.remove_process_debug(target, object)
                                == Err(dbgk::STATUS_PORT_NOT_SET)
                        {
                            dbg_ok |= 0x0400;
                        }
                        // 0x0800 — a LIVE process that was attached then detached reports nothing
                        // further: attach a second throwaway debuggee, detach it, then create a
                        // thread in it and prove the plane stays inert.
                        let target2 =
                            nt_handler
                                .pm
                                .create_process("dbgk-selftest-b.exe", None, None);
                        if nt_handler
                            .pm
                            .create_thread(target2, 0x6000, 0, false)
                            .is_ok()
                        {
                            let attached = nt_handler
                                .pm
                                .debug_active_process(target2, object, debugger)
                                == Ok(1);
                            let detached =
                                nt_handler.pm.remove_process_debug(target2, object) == Ok(1);
                            let drained = nt_handler
                                .pm
                                .debug_object(object)
                                .is_some_and(|o| o.is_empty());
                            let _ = nt_handler.pm.create_thread(target2, 0x7000, 0, false);
                            if attached
                                && detached
                                && drained
                                && nt_handler
                                    .pm
                                    .debug_object(object)
                                    .is_some_and(|o| o.is_empty())
                                && matches!(
                                    nt_handler.pm.wait_for_debug_event(object, debugger_pid),
                                    Ok(None)
                                )
                            {
                                dbg_ok |= 0x0800;
                            }
                        }
                    }
                    nt_handler.pm.destroy_debug_object(object);
                }
            }
            DBGK_SELFTEST.store(dbg_ok, Ordering::Relaxed);
        }

        // === Dbgk SYSCALL-DISPATCH SELF-TEST (POST-LOOP) ===========================================
        // The block above drives the PLANE (ProcessManager + the pure `nt_process::dbgk` state
        // machine) directly; it proves nothing about the five NATIVE HANDLER ARMS. This block drives
        // those arms through the REAL dispatch route a hosted process uses —
        // `nt_dispatcher.dispatch(SSN, argv, origin, &mut nt_handler)`, the exact call the service
        // loop makes for every syscall — with REAL MARSHALLED ARGUMENTS living in CLIENT memory
        // (smss's mirrored stack). So the handler's own SSN→service resolution, typed-handle lookup,
        // `DbgkDebugObjectMapping` access checks, ProbeForWrite/copyin/copyout of the `*DebugHandle`,
        // `*Timeout`, `*CLIENT_ID` and `DBGUI_WAIT_STATE_CHANGE`, its counters and its wait-park
        // request all execute for real. Verified by the DBGK_* counters, which read 0 without it.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_ACCESS_VIOLATION: u32 = 0xC000_0005;
            const ST_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
            const ST_INVALID_HANDLE: u32 = 0xC000_0008;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const ST_ACCESS_DENIED: u32 = 0xC000_0022;
            const ST_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
            // The client-side argument block: the DEEPEST (unused) end of smss's 16 KiB stack, which
            // is inside its mirrored range so the handler's copyin/copyout reach it exactly as they
            // reach a live caller's stack. smss is parked in its final syscall and the boot exits
            // right after the specs, so nothing ever reads these bytes back.
            const A_HANDLE: u64 = STACK_BASE + 0x80; // *DebugHandle out (8)
            const A_CLIENT_ID: u64 = STACK_BASE + 0x88; // CLIENT_ID in (16)
            const A_TIMEOUT: u64 = STACK_BASE + 0x98; // LARGE_INTEGER *Timeout in (8)
                                                      // DBGUI_WAIT_STATE_CHANGE out (0xB8).
            const A_STATE: u64 = STACK_BASE + 0xA0;
            // Handler-owned temporary slots let the specs exercise pid -> pi routing without
            // publishing throwaway processes as hosted launch topology.
            const DBGK_TEST_PI: usize = MAX_PI - 1;
            const DBGK_TEST_PI2: usize = MAX_PI - 2;

            let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
            let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
            let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
            let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
            let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
            let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
            let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            // Take the loop context so every client access goes through smss's mirrors (the same
            // idiom the post-loop pipe / io-completion re-drive helpers use).
            let saved_ctx = nt_handler.loop_ctx.take();
            ACTIVE_STACK_BASE.store(STACK_BASE, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(STACK_FRAMES * 0x1000, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(SMSS_STACK_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(SMSS_HEAP_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(IMAGE_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(0, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut sc_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every service below goes through THIS — the dispatcher, by SSN. An unregistered number
            // returns STATUS_INVALID_SYSTEM_SERVICE and never reaches a handler; a wrong argument
            // count returns STATUS_INVALID_PARAMETER before the handler.
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }

            // 0x0001 — the five services really are registered at the sysfuncs.lst-derived SSNs, with
            // their documented argument counts.
            if [
                (NativeService::NtCreateDebugObject, 35u32, 4u8),
                (NativeService::NtDebugActiveProcess, 59, 2),
                (NativeService::NtDebugContinue, 60, 3),
                (NativeService::NtRemoveProcessDebug, 199, 2),
                (NativeService::NtWaitForDebugEvent, 279, 4),
            ]
            .iter()
            .all(|&(service, ssn, argc)| {
                nt_dispatcher.table().number_of(service) == Some(ssn)
                    && nt_dispatcher.table().lookup(ssn).is_some_and(|entry| {
                        entry.service == service && entry.min_args == argc && entry.max_args == argc
                    })
            }) {
                sc_ok |= 0x0001;
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            // Zero the client argument block through the mirror; if that fails the mirrors are not
            // usable and the whole test would be meaningless, so it stays 0 (=> FAIL) rather than
            // silently "passing".
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100]);
            if debugger_pid != 0 && client_args_ready {
                // --- NtCreateDebugObject (SSN 35): [*DebugHandle, DesiredAccess, *OA, Flags] ------
                let create = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                // Read the handle back out of CLIENT memory the way the caller would — proof the
                // out-parameter was really marshalled, not just returned.
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                let create_negatives = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[0, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                ) == ST_ACCESS_VIOLATION
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE + 1, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0]
                    ) == ST_DATATYPE_MISALIGNMENT
                    && sysc!(
                        SSN_NT_CREATE_DEBUG_OBJECT,
                        &[A_HANDLE, dbgk::DEBUG_OBJECT_ALL_ACCESS as u64, 0, 0x8000]
                    ) == ST_INVALID_PARAMETER;
                // 0x0002 — the handler created a real object, bound its EventsPresent dispatcher
                // event, minted a TYPED per-process handle and copied it out; its counter moved.
                if create == 0
                    && dbg_handle != 0
                    && object.is_some()
                    && host_event != 0
                    && DBGK_OBJECTS_CREATED.load(Ordering::Relaxed) >= 1
                    && create_negatives
                {
                    sc_ok |= 0x0002;
                }

                if let Some(object) = object {
                    // A throwaway debuggee with a real image base + main thread.
                    let target = nt_handler.pm.create_process("dbgk-syscall.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_5000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x2100, 0, false).ok();
                    let target_registered = nt_handler
                        .register_temporary_process_slot(DBGK_TEST_PI, target, 0)
                        .is_ok();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_target_noaccess = nt_handler
                        .pm
                        .insert_handle(debugger_pid, nt_process::HandleObject::Process(target), 0)
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_dbg_noaccess = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::DebugObject(object),
                            0,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_wrong_type = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Opaque(0xDB65),
                            dbgk::DEBUG_OBJECT_ALL_ACCESS,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // 0x0080 — the DEBUG-handle checks, all through the dispatch route: a handle
                    // without the required DbgkDebugObjectMapping access is ACCESS_DENIED on every
                    // service, a non-debug handle is OBJECT_TYPE_MISMATCH, and a NULL out/in pointer
                    // is ACCESS_VIOLATION.
                    if sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_dbg_noaccess])
                        == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_dbg_noaccess, 0, A_TIMEOUT, A_STATE]
                        ) == ST_ACCESS_DENIED
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[h_dbg_noaccess, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, h_dbg_noaccess])
                            == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, h_wrong_type])
                            == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[h_wrong_type, 0, A_TIMEOUT, A_STATE]
                        ) == ST_OBJECT_TYPE_MISMATCH
                        && sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, A_TIMEOUT, 0])
                            == ST_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, 0, dbgk::DBG_CONTINUE as u64]
                        ) == ST_ACCESS_VIOLATION
                    {
                        sc_ok |= 0x0080;
                    }
                    // 0x0200 — the PROCESS-handle side: a process handle lacking
                    // PROCESS_SUSPEND_RESUME is ACCESS_DENIED, an unknown one is INVALID_HANDLE, and
                    // detaching a process that was never attached is STATUS_PORT_NOT_SET.
                    if sysc!(
                        SSN_NT_DEBUG_ACTIVE_PROCESS,
                        &[h_target_noaccess, dbg_handle]
                    ) == ST_ACCESS_DENIED
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[0xDEAD_BEEF, dbg_handle])
                            == ST_INVALID_HANDLE
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0200;
                    }

                    // --- NtDebugActiveProcess (SSN 59): [ProcessHandle, DebugHandle] -------------
                    let attaches_before = DBGK_ATTACHES.load(Ordering::Relaxed);
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach = if target_registered {
                        sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                    } else {
                        ST_INVALID_PARAMETER
                    };
                    // 0x0004 — the attach ran IN THE HANDLER (its counter moved), installed the port
                    // + PEB.BeingDebugged and posted the fake create message; a second one is
                    // STATUS_PORT_ALREADY_SET.
                    if attach == 0
                        && DBGK_ATTACHES.load(Ordering::Relaxed) == attaches_before + 1
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) >= fake_before + 1
                        && nt_handler.pm.process_debug_port(target) == Some(object)
                        && nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_ALREADY_SET
                    {
                        sc_ok |= 0x0004;
                    }

                    // --- NtWaitForDebugEvent (SSN 279): [DebugHandle, Alertable, *Timeout,
                    //     *StateChange] — a REAL immediate timeout in client memory + a REAL
                    //     DBGUI_WAIT_STATE_CHANGE copied back out to client memory.
                    let timeout_written = img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let sc_u32 =
                        |o: usize| u32::from_le_bytes(sc[o..o + 4].try_into().unwrap_or([0; 4]));
                    let sc_u64 =
                        |o: usize| u64::from_le_bytes(sc[o..o + 8].try_into().unwrap_or([0; 8]));
                    let handle_to_process = sc_u64(0x18);
                    let handle_to_thread = sc_u64(0x20);
                    // 0x0008 — the handler served the wait and the OUT-PARAM LANDED IN CLIENT MEMORY:
                    // DbgCreateProcessStateChange for the right CLIENT_ID, carrying REAL process /
                    // thread handles opened in the debugger's own table, the image base and the
                    // initial thread's start address.
                    if wait == 0
                        && timeout_written
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sc_u64(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64(0x10) == main as u64)
                        && sc_u64(0x38) == 0x0000_0001_5000_0000
                        && sc_u64(0x50) == 0x2100
                        && handle_to_process != 0
                        && handle_to_thread != 0
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, handle_to_process as nt_process::Handle)
                            == Some(nt_process::HandleObject::Process(target))
                        && main.is_some_and(|main| {
                            nt_handler
                                .pm
                                .lookup_handle(debugger_pid, handle_to_thread as nt_process::Handle)
                                == Some(nt_process::HandleObject::Thread(main))
                        })
                    {
                        sc_ok |= 0x0008;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_process as nt_process::Handle);
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, handle_to_thread as nt_process::Handle);
                    // 0x0010 — nothing further is reportable for this debuggee (one outstanding event
                    // per process) and the *Timeout the handler READ from client memory is immediate
                    // ⇒ STATUS_TIMEOUT, with no park requested.
                    if sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == ST_TIMEOUT
                        && nt_handler.wait_park_event < 0
                    {
                        sc_ok |= 0x0010;
                    }

                    // --- NtDebugContinue (SSN 60): [DebugHandle, *AppClientId, ContinueStatus] ---
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    // 0x0020 — the handler read the CLIENT_ID out of client memory, rejected an
                    // illegal continue status and resolved the read event; its counter moved.
                    if client_id_written
                        && sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x1234])
                            == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        sc_ok |= 0x0020;
                    }

                    // 0x0100 — WAIT-PARK / WAKE-SIGNAL. With the queue drained and a NULL (=
                    // infinite) *Timeout the handler must PARK: it binds `wait_park_event` to the
                    // debug object's EventsPresent dispatcher event — the same field the service loop
                    // consumes to steal the caller's reply cap — and that event is NOT ready. A later
                    // queue-side post through the same dispatch route (attaching a second debuggee)
                    // SETS that very dispatcher event, which is exactly what the loop's wake path
                    // consumes, and the re-issued wait then returns the new event.
                    // HONEST SCOPE: the reply-cap steal + thread resume itself is NOT exercised —
                    // post-loop there is no live client blocked inside the syscall.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_deadline_100ns = u64::MAX;
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize)
                        && nt_handler.wait_deadline_100ns == u64::MAX;
                    nt_handler.wait_park_event = -1;
                    let target2 = nt_handler
                        .pm
                        .create_process("dbgk-syscall-b.exe", None, None);
                    nt_handler.pm.set_image_base(target2, 0x0000_0001_6000_0000);
                    let _ = nt_handler.pm.create_thread(target2, 0x2200, 0, false);
                    let target2_registered = nt_handler
                        .register_temporary_process_slot(DBGK_TEST_PI2, target2, 0)
                        .is_ok();
                    let h_target2 = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target2),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let woke = target2_registered
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target2, dbg_handle]) == 0
                        && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    let redriven = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0;
                    let mut sc2 = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
                    let redriven_payload = img_spawn::smss_copyin(A_STATE, &mut sc2)
                        && u32::from_le_bytes(sc2[0..4].try_into().unwrap_or([0; 4]))
                            == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && u64::from_le_bytes(sc2[8..16].try_into().unwrap_or([0; 8]))
                            == target2 as u64;
                    if parked && woke && redriven && redriven_payload {
                        sc_ok |= 0x0100;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_deadline_100ns = u64::MAX;

                    // --- NtRemoveProcessDebug (SSN 199): [ProcessHandle, DebugHandle] ------------
                    let detaches_before = DBGK_DETACHES.load(Ordering::Relaxed);
                    // 0x0040 — the detach ran IN THE HANDLER (its counter moved), cleared the port +
                    // BeingDebugged, and a second detach is STATUS_PORT_NOT_SET.
                    if sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0
                        && DBGK_DETACHES.load(Ordering::Relaxed) == detaches_before + 1
                        && nt_handler.pm.process_debug_port(target).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                        && sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle])
                            == dbgk::STATUS_PORT_NOT_SET
                    {
                        sc_ok |= 0x0040;
                    }
                    // 0x0400 — NtClose (SSN 27) on the last debug-object handle, through the same
                    // dispatch route, runs DbgkpCloseObject: the object is destroyed and the
                    // STILL-ATTACHED second debuggee is detached.
                    let aux_closed = h_dbg_noaccess == 0
                        || (sysc!(SSN_NT_CLOSE, &[h_dbg_noaccess]) == 0
                            && nt_handler.pm.debug_object(object).is_some());
                    if nt_handler.pm.process_debug_port(target2) == Some(object)
                        && aux_closed
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && nt_handler.pm.debug_object(object).is_none()
                        && nt_handler.pm.process_debug_port(target2).is_none()
                    {
                        sc_ok |= 0x0400;
                    }

                    nt_handler.clear_temporary_process_slot(DBGK_TEST_PI);
                    nt_handler.clear_temporary_process_slot(DBGK_TEST_PI2);
                    for handle in [
                        h_target,
                        h_target2,
                        h_target_noaccess,
                        h_dbg_noaccess,
                        h_wrong_type,
                    ] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                }
            }

            ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_deadline_100ns = u64::MAX;
            DBGK_SYSCALL_SELFTEST.store(sc_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk EXCEPTION-FORWARDING self-test (post-loop) ═══════════════════════════════════
        // `DbgkForwardException` — the debug-event source the previous batch left DEFERRED and the
        // load-bearing one (without it a debugger cannot see a crash or an `int3`).
        //
        // WHAT IS DRIVEN FOR REAL: the debugger side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)`, arguments marshalled in CLIENT memory) exactly as a
        // hosted process's syscalls do, and the DEBUGGEE side goes through
        // `ExecNtHandler::dbgk_forward_exception` — *the very entry the live fault path calls* at
        // its `#PF` / `#GP` / int3 classification sites (`dbgk_forward_exception!`). Nothing here
        // reimplements the forward: the throwaway debuggee is registered in a handler-owned
        // temporary slot, so the pi -> pid -> `EPROCESS.DebugPort` resolution the fault path
        // performs is the same resolution performed here.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const THREAD_TERMINATE: u32 = 0x0001;
            const ST_TIMEOUT: u32 = 0x0000_0102;
            const ST_INVALID_PARAMETER: u32 = 0xC000_000D;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            // Temporary slots for the throwaway debuggees (cleared again below). Slots 0..=4 are
            // the live hosted set and remain untouched.
            const EXC_TEST_PI: usize = MAX_PI - 1;
            const EXC_TEST_PI2: usize = MAX_PI - 2;

            let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
            let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
            let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
            let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
            let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
            let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
            let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx.take();
            ACTIVE_STACK_BASE.store(STACK_BASE, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(STACK_FRAMES * 0x1000, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(SMSS_STACK_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(SMSS_HEAP_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(IMAGE_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(0, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut ex_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            // Read a field back out of the DBGUI_WAIT_STATE_CHANGE the handler copied to CLIENT
            // memory — the bytes ntdll's `DbgUiWaitStateChange` would receive.
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                // --- setup: a real debug object + an attached throwaway debuggee, all by SSN ----
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                let host_event = object
                    .and_then(|object| nt_handler.pm.debug_object(object))
                    .map(|o| o.host_event)
                    .unwrap_or(0);
                if let (0, Some(object)) = (created, object) {
                    let target = nt_handler
                        .pm
                        .create_process("dbgk-exception.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_7000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x3100, 0, false).ok();
                    // A second thread so terminating one (the lifecycle poster below) does not
                    // signal the process and tear its handles down.
                    let worker = nt_handler.pm.create_thread(target, 0x3200, 0, false).ok();
                    let target_registered = nt_handler
                        .register_temporary_process_slot(EXC_TEST_PI, target, 0)
                        .is_ok();
                    // A NEVER-attached process in the OTHER free slot: the live-boot shape, the
                    // control for the no-debugger gate.
                    let plain = nt_handler.pm.create_process("dbgk-plain.exe", None, None);
                    let _ = nt_handler.pm.create_thread(plain, 0x3300, 0, false);
                    let plain_registered = nt_handler
                        .register_temporary_process_slot(EXC_TEST_PI2, plain, 0)
                        .is_ok();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_worker = worker
                        .and_then(|worker| {
                            nt_handler
                                .pm
                                .insert_handle(
                                    debugger_pid,
                                    nt_process::HandleObject::Thread(worker),
                                    THREAD_TERMINATE,
                                )
                                .ok()
                        })
                        .map(u64::from)
                        .unwrap_or(0);
                    // Attach, then DRAIN every attach-time fake create message (one
                    // DbgKmCreateProcessApi for the first thread + a DbgKmCreateThreadApi for each
                    // other one) so the queue is empty and the exception below is unambiguously the
                    // outstanding event. Each drain step reads the reported CLIENT_ID straight back
                    // out of the state change in CLIENT memory and continues that exact thread.
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut drained = 0u64;
                    while drained < 8
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                    {
                        let mut reported = [0u8; 16];
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        reported[0..8].copy_from_slice(&sc[0x08..0x10]);
                        reported[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &reported)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // From here on the CLIENT_ID in client memory is the debuggee's MAIN thread —
                    // the thread every forwarded exception below reports for.
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    // 0x0001 — attached through the REAL dispatch route, with both fake create
                    // messages (two live threads) retrieved and continued by SSN, leaving the queue
                    // empty.
                    if attached
                        && client_id_written
                        && drained == 2
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0001;
                    }

                    // --- THE FORWARD: the exact entry the live fault path calls ----------------
                    // A REAL page fault's record: STATUS_ACCESS_VIOLATION at RIP 0x0000_0001_7000_4321
                    // writing 0x0000_0000_0000_0018 — the shape `dbgk_forward_exception!` builds at
                    // the loop's null-deref / vmf-out sites from (m0, m3, addr).
                    const EXC_IP: u64 = 0x0000_0001_7000_4321;
                    const EXC_ADDR: u64 = 0x18;
                    let forwarded_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let forwarded = nt_handler.dbgk_forward_exception(
                        EXC_TEST_PI,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(EXC_IP, 1, EXC_ADDR),
                        true,
                    );
                    // 0x0002 — the forward ran: it resolved pi → pid → DebugPort, queued exactly one
                    // DbgKmExceptionApi event and moved the counter.
                    if forwarded
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == forwarded_before + 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_EXCEPTION_API
                        })
                    {
                        ex_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE record lands in CLIENT memory: DbgExceptionStateChange for the
                    // faulting CLIENT_ID, exception code / address / both MmAccessFault parameters
                    // / FirstChance.
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    // Macros, not closures: the state-change buffer is re-filled by each later
                    // `smss_copyin`, so nothing may hold a borrow of it across the checks.
                    macro_rules! sc_u32 {
                        ($o:expr) => {
                            u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                        };
                    }
                    macro_rules! sc_u64 {
                        ($o:expr) => {
                            u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                        };
                    }
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u32!(0x18) == dbgk::STATUS_ACCESS_VIOLATION
                        && sc_u64!(0x28) == EXC_IP
                        && sc_u32!(0x30) == 2
                        && sc_u64!(0x38) == 1
                        && sc_u64!(0x40) == EXC_ADDR
                        && sc_u32!(0xb0) == 1
                    {
                        ex_ok |= 0x0004;
                    }

                    // 0x0008 — NtDebugContinue resolves the EXCEPTION event: an illegal continue
                    // status is rejected, DBG_CONTINUE (read from the CLIENT_ID in client memory)
                    // succeeds, the handler counter moves and the queue drains.
                    let continues_before = DBGK_CONTINUES.load(Ordering::Relaxed);
                    if sysc!(SSN_NT_DEBUG_CONTINUE, &[dbg_handle, A_CLIENT_ID, 0x4321])
                        == ST_INVALID_PARAMETER
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && DBGK_CONTINUES.load(Ordering::Relaxed) == continues_before + 1
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        ex_ok |= 0x0008;
                    }

                    // 0x0010 — BREAKPOINT/trap refinement. An `int3` forwarded exactly as the
                    // label-4 fault site forwards it reports as DbgBreakpointStateChange (not a
                    // plain exception), and the trap-vector → NTSTATUS map the label-3 site uses is
                    // the one `KiDispatchException` reports.
                    const BP_IP: u64 = 0x0000_0001_7000_1005;
                    if nt_handler.dbgk_forward_exception(
                        EXC_TEST_PI,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, BP_IP),
                        true,
                    ) && sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                        && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT
                        && sc_u64!(0x28) == BP_IP
                        && dbgk::exception_code_for_trap(3) == dbgk::STATUS_BREAKPOINT
                        && dbgk::exception_code_for_trap(6) == dbgk::STATUS_ILLEGAL_INSTRUCTION
                        && dbgk::exception_code_for_trap(14) == dbgk::STATUS_ACCESS_VIOLATION
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole fault-path
                    // integration rests on: forwarding for a process with NO EPROCESS.DebugPort
                    // returns false, moves no counter and queues nothing. This is what EVERY fault
                    // on the live boot takes, which is why the fault path is byte-identical.
                    let quiet_before = DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    if plain_registered
                        && !nt_handler.dbgk_forward_exception(
                            EXC_TEST_PI2,
                            0,
                            dbgk::ExceptionRecord::access_violation(0x1000, 0, 0x40),
                            true,
                        )
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_EXCEPTIONS_FORWARDED.load(Ordering::Relaxed) == quiet_before
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        ex_ok |= 0x0020;
                    }

                    // 0x0040 — ★ THE SIGNAL FIX, fault-path poster. Park the debugger on the
                    // object's EventsPresent dispatcher event (empty queue + NULL = infinite
                    // *Timeout), then forward an exception through the FAULT-PATH entry — which is
                    // not a syscall at all. Before this batch only the five dbgk syscall arms
                    // mirrored the modelled signal, so this post would have left the dispatcher
                    // event CLEAR and never woken the parked debugger.
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_deadline_100ns = u64::MAX;
                    let park_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let parked = park_status == ST_TIMEOUT
                        && park_index >= 0
                        && park_index as u64 + 1 == host_event
                        && !nt_handler.dispatcher_ready(park_index as usize);
                    nt_handler.wait_park_event = -1;
                    const FAULT_IP: u64 = 0x0000_0001_7000_9999;
                    let woke = nt_handler.dbgk_forward_exception(
                        EXC_TEST_PI,
                        main.unwrap_or(0) as u64,
                        dbgk::ExceptionRecord::access_violation(FAULT_IP, 0, 0x88),
                        false,
                    ) && park_index >= 0
                        && nt_handler.dispatcher_ready(park_index as usize);
                    if parked
                        && woke
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                        && sc_u64!(0x28) == FAULT_IP
                        // SecondChance ⇒ FirstChance == 0, carried through faithfully.
                        && sc_u32!(0xb0) == 0
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_EXCEPTION_NOT_HANDLED as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0040;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_deadline_100ns = u64::MAX;

                    // 0x0080 — ★ THE SIGNAL FIX, NON-DBGK SYSCALL poster. The same park, then
                    // NtTerminateThread (SSN 267) on one of the debuggee's threads: a LIFECYCLE
                    // event source whose handler arm never mirrored the debug signal before this
                    // batch (it is now covered because the mirror runs at the ONE chokepoint every
                    // service passes through). The dispatcher event must be SET and the re-issued
                    // wait must return that thread's DbgExitThreadStateChange.
                    let park2_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park2_index = nt_handler.wait_park_event;
                    let parked2 = park2_status == ST_TIMEOUT
                        && park2_index >= 0
                        && !nt_handler.dispatcher_ready(park2_index as usize);
                    nt_handler.wait_park_event = -1;
                    let mut worker_client = [0u8; 16];
                    worker_client[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    worker_client[8..16]
                        .copy_from_slice(&(worker.unwrap_or(0) as u64).to_le_bytes());
                    if parked2
                        && h_worker != 0
                        && img_spawn::smss_copyout(A_CLIENT_ID, &worker_client)
                        && sysc!(SSN_NT_TERMINATE_THREAD, &[h_worker, 0x1234]) == 0
                        && park2_index >= 0
                        && nt_handler.dispatcher_ready(park2_index as usize)
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_EXIT_THREAD_STATE_CHANGE
                        && worker.is_some_and(|worker| sc_u64!(0x10) == worker as u64)
                        && sc_u32!(0x18) == 0x1234
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        ex_ok |= 0x0080;
                    }
                    nt_handler.wait_park_event = -1;
                    nt_handler.wait_deadline_100ns = u64::MAX;

                    nt_handler.clear_temporary_process_slot(EXC_TEST_PI);
                    nt_handler.clear_temporary_process_slot(EXC_TEST_PI2);
                    for handle in [h_target, h_worker] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — leaves no debug object alive,
                    // so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_deadline_100ns = u64::MAX;
            DBGK_EXCEPTION_SELFTEST.store(ex_ok, Ordering::Relaxed);
        }

        // ═══ Dbgk MODULE LOAD/UNLOAD self-test (post-loop) ═════════════════════════════════════
        // `DbgkMapViewOfSection` / `DbgkUnMapViewOfSection` + `DbgkpPostFakeModuleMessages` — the
        // last of the deferred debug-event sources.
        //
        // WHAT IS DRIVEN FOR REAL: the DEBUGGER side goes through the REAL dispatch route
        // (`nt_dispatcher.dispatch(SSN, …)` with the arguments marshalled in CLIENT memory), and the
        // DEBUGGEE side goes through `ExecNtHandler::dbgk_module_load` / `dbgk_module_unload` —
        // *the very entries the live `NtMapViewOfSection` SEC_IMAGE branch and the
        // `NtUnmapViewOfSection` arm call*. Nothing is reimplemented for the test: each throwaway
        // process sits in a handler-owned temporary slot, so the pi -> pid ->
        // `EPROCESS.DebugPort` resolution is the same one the mapping path performs.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const FILE_GENERIC_READ: u32 = 0x0012_0089;
            // Client argument block — past the exception self-test's 0x180..0x280 window.
            const A_HANDLE: u64 = STACK_BASE + 0x280;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x288;
            const A_TIMEOUT: u64 = STACK_BASE + 0x298;
            const A_STATE: u64 = STACK_BASE + 0x2A0;
            // Temporary slots are cleared again below; slots 0..=4 are the live hosted set.
            const MOD_TEST_PI: usize = MAX_PI - 1;
            const MOD_TEST_PI2: usize = MAX_PI - 2;
            // The debuggee's own image base + the IMAGE views this test maps into it.
            const TARGET_IMAGE_BASE: u64 = 0x0000_0001_8000_0000;
            const DLL_BASE: u64 = 0x0000_0000_7100_0000;
            const NOT_AN_IMAGE_BASE: u64 = 0x0000_0000_7200_0000;
            const PLAIN_IMAGE_BASE: u64 = 0x0000_0001_9000_0000;
            const PLAIN_PROBE_BASE: u64 = 0x0000_0000_7300_0000;
            const PLAIN_DLL_A: u64 = 0x0000_0000_7400_0000;
            const PLAIN_DLL_B: u64 = 0x0000_0000_7500_0000;
            const NAME_POINTER: u64 = SMSS_TEB_VA + 0x28; // NtTib.ArbitraryUserPointer
            const DBG_INFO: (u32, u32) = (0x0000_1234, 0x0000_0056);

            let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
            let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
            let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
            let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
            let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
            let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
            let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx.take();
            ACTIVE_STACK_BASE.store(STACK_BASE, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(STACK_FRAMES * 0x1000, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(SMSS_STACK_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(SMSS_HEAP_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(IMAGE_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(0, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut md_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap_or([0; 4]))
                };
            }
            macro_rules! sc_u64 {
                ($o:expr) => {
                    u64::from_le_bytes(sc[$o..$o + 8].try_into().unwrap_or([0; 8]))
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            if debugger_pid != 0 && client_args_ready {
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The DEBUGGED throwaway debuggee.
                    let target = nt_handler.pm.create_process("dbgk-module.exe", None, None);
                    nt_handler.pm.set_image_base(target, TARGET_IMAGE_BASE);
                    let main = nt_handler.pm.create_thread(target, 0x4100, 0, false).ok();
                    let target_registered = nt_handler
                        .register_temporary_process_slot(MOD_TEST_PI, target, 0)
                        .is_ok();
                    // The NEVER-attached control — the live-boot shape, and later the subject of the
                    // attach-time fake-module proof.
                    let plain = nt_handler
                        .pm
                        .create_process("dbgk-modplain.exe", None, None);
                    nt_handler.pm.set_image_base(plain, PLAIN_IMAGE_BASE);
                    let plain_main = nt_handler.pm.create_thread(plain, 0x4200, 0, false).ok();
                    let plain_registered = nt_handler
                        .register_temporary_process_slot(MOD_TEST_PI2, plain, 0)
                        .is_ok();
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let h_plain = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(plain),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    // The DEBUGGEE's own handle to the image file — the thing `DbgkpOpenHandles`
                    // duplicates. A real per-process handle in the debuggee's own table.
                    let debuggee_file = nt_handler
                        .pm
                        .insert_handle(
                            target,
                            nt_process::HandleObject::File(0xF11E_0001),
                            FILE_GENERIC_READ,
                        )
                        .map(u64::from)
                        .unwrap_or(0);

                    // --- 0x0001 setup: attach + drain the fake create message, all by SSN --------
                    let attached = target_registered
                        && h_target != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main.unwrap_or(0) as u64).to_le_bytes());
                    let client_id_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    if attached
                        && client_id_written
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0001;
                    }

                    // --- THE LOAD: the exact entry the live SEC_IMAGE map branch calls -----------
                    // On the live path the mapping thread is the caller, so report as the debuggee's
                    // thread (what `self.current_tid` holds inside a serviced syscall).
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let loads_before = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let loaded = nt_handler.dbgk_module_load(
                        MOD_TEST_PI,
                        DLL_BASE,
                        debuggee_file,
                        DBG_INFO,
                        NAME_POINTER,
                    );
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0002 — the map-path entry queued exactly one DbgKmLoadDllApi, moved the
                    // counter, and tracked the view as a module of the debuggee.
                    if loaded
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == loads_before + 1
                        && nt_handler.pm.module_count(target) == 1
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 1
                                && o.events()[0].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                        })
                    {
                        md_ok |= 0x0002;
                    }

                    // 0x0004 — the debugger retrieves it through the REAL NtWaitForDebugEvent arm
                    // and the WHOLE payload lands in CLIENT memory, with the image FILE handle
                    // DUPLICATED into the debugger's own table (`DbgkpOpenHandles`).
                    let waits_before = DBGK_WAITS_SERVED.load(Ordering::Relaxed);
                    let wait = sysc!(
                        SSN_NT_WAIT_FOR_DEBUG_EVENT,
                        &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                    );
                    let sc_read = img_spawn::smss_copyin(A_STATE, &mut sc);
                    let reported_file = sc_u64!(0x18);
                    if wait == 0
                        && sc_read
                        && DBGK_WAITS_SERVED.load(Ordering::Relaxed) == waits_before + 1
                        && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x08) == target as u64
                        && main.is_some_and(|main| sc_u64!(0x10) == main as u64)
                        && sc_u64!(0x20) == DLL_BASE
                        && sc_u32!(0x28) == DBG_INFO.0
                        && sc_u32!(0x2c) == DBG_INFO.1
                        && sc_u64!(0x30) == NAME_POINTER
                        // The duplicate is a DIFFERENT handle value in the DEBUGGER's table naming
                        // the SAME file object, with DUPLICATE_SAME_ACCESS.
                        && debuggee_file != 0
                        && reported_file != 0
                        && reported_file != debuggee_file
                        && nt_handler
                            .pm
                            .lookup_handle(debugger_pid, reported_file as nt_process::Handle)
                            == Some(nt_process::HandleObject::File(0xF11E_0001))
                        && nt_handler
                            .pm
                            .handle_access(debugger_pid, reported_file as nt_process::Handle)
                            == Some(FILE_GENERIC_READ)
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0004;
                    }
                    let _ = nt_handler
                        .pm
                        .close_handle(debugger_pid, reported_file as nt_process::Handle);

                    // --- THE UNLOAD: the exact entry the live NtUnmapViewOfSection arm calls -----
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let unloads_before = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let unloaded = nt_handler.dbgk_module_unload(MOD_TEST_PI, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    // 0x0008 — DbgKmUnloadDllApi posted, retrieved as DbgUnloadDllStateChange with
                    // the right base, and the view is no longer tracked.
                    if unloaded
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == unloads_before + 1
                        && nt_handler.pm.module_count(target) == 0
                        && sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) == 0
                        && img_spawn::smss_copyin(A_STATE, &mut sc)
                        && sc_u32!(0x00) == dbgk::DBG_UNLOAD_DLL_STATE_CHANGE
                        && sc_u64!(0x18) == DLL_BASE
                        && sysc!(
                            SSN_NT_DEBUG_CONTINUE,
                            &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                        ) == 0
                    {
                        md_ok |= 0x0008;
                    }

                    // 0x0010 — IMAGE-ONLY. Unmapping a base that was never an IMAGE view (a data or
                    // anonymous mapping — the CSR shared section and the NLS section on the live
                    // boot) posts nothing: `MmUnmapViewOfSection` only calls
                    // `DbgkUnMapViewOfSection` when the VAD it tore down was an image VAD. Same for
                    // re-unmapping the view already unmapped above.
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    nt_handler.current_tid = main.unwrap_or(0) as u64;
                    let image_only = !nt_handler.dbgk_module_unload(MOD_TEST_PI, NOT_AN_IMAGE_BASE)
                        && !nt_handler.dbgk_module_unload(MOD_TEST_PI, DLL_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if image_only
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0010;
                    }

                    // 0x0020 — ★ THE NO-DEBUGGER GATE, the safety property the whole mapping-path
                    // integration rests on: a map AND an unmap in a process with NO
                    // `EPROCESS.DebugPort` both return false, move no counter and queue nothing.
                    // This is the path EVERY DLL map on the live boot takes (and with no debug
                    // object alive at all, `dbgk_module_load` returns on its FIRST line, before any
                    // lookup — which is the state of every boot today).
                    let quiet_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    let quiet_unloads = DBGK_MODULE_UNLOADS.load(Ordering::Relaxed);
                    let queued_before = nt_handler
                        .pm
                        .debug_object(object)
                        .map(|o| o.len())
                        .unwrap_or(0);
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let gated = plain_registered
                        && !nt_handler.dbgk_module_load(
                            MOD_TEST_PI2,
                            PLAIN_PROBE_BASE,
                            0,
                            DBG_INFO,
                            NAME_POINTER,
                        )
                        && !nt_handler.dbgk_module_unload(MOD_TEST_PI2, PLAIN_PROBE_BASE);
                    nt_handler.current_tid = debugger_tid as u64;
                    if gated
                        && !nt_handler.pm.is_process_being_debugged(plain)
                        && DBGK_MODULE_LOADS.load(Ordering::Relaxed) == quiet_loads
                        && DBGK_MODULE_UNLOADS.load(Ordering::Relaxed) == quiet_unloads
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .map(|o| o.len())
                            .unwrap_or(0)
                            == queued_before
                    {
                        md_ok |= 0x0020;
                    }

                    // --- 0x0040 — ATTACH-TIME FAKE MODULE MESSAGES -------------------------------
                    // Two DLLs + the process's OWN image map into the still-UNDEBUGGED control
                    // process (nothing posts — proven by the counter staying put), and only THEN is
                    // a debugger attached. `DbgkpPostFakeModuleMessages` must report the two DLLs as
                    // fake `DbgKmLoadDllApi` messages AFTER the create-process message, attributed
                    // to the first thread, with the EXE's own view NOT re-reported.
                    nt_handler.current_tid = plain_main.unwrap_or(0) as u64;
                    let premapped_loads = DBGK_MODULE_LOADS.load(Ordering::Relaxed);
                    for base in [PLAIN_DLL_A, PLAIN_DLL_B, PLAIN_IMAGE_BASE] {
                        nt_handler.dbgk_module_load(MOD_TEST_PI2, base, 0, DBG_INFO, NAME_POINTER);
                    }
                    nt_handler.current_tid = debugger_tid as u64;
                    let premapped = DBGK_MODULE_LOADS.load(Ordering::Relaxed) == premapped_loads
                        && nt_handler.pm.module_count(plain) == 3;
                    let fake_before = DBGK_FAKE_MESSAGES.load(Ordering::Relaxed);
                    let attach_plain = plain_registered
                        && h_plain != 0
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_plain, dbg_handle]) == 0;
                    if premapped
                        && attach_plain
                        // 1 create-process + 2 load-dll fake messages (the EXE view is skipped).
                        && DBGK_FAKE_MESSAGES.load(Ordering::Relaxed) == fake_before + 3
                        && nt_handler.pm.debug_object(object).is_some_and(|o| {
                            o.len() == 3
                                && o.events()[0].message.api_number()
                                    == dbgk::DBGKM_CREATE_PROCESS_API
                                && o.events()[1].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                && o.events()[2].message.api_number() == dbgk::DBGKM_LOAD_DLL_API
                                // The module messages ride the FIRST reported thread's CLIENT_ID …
                                && plain_main.is_some_and(|first| {
                                    o.events()[1].client_id.unique_thread == first
                                        && o.events()[2].client_id.unique_thread == first
                                })
                                // … are NOWAIT backout events, and only the create-process one was
                                // activated by DbgkpSetProcessDebugObject.
                                && o.events()[1].flags & dbgk::DEBUG_EVENT_NOWAIT != 0
                                && !o.events()[0].is_inactive()
                                && o.events()[1].is_inactive()
                                && o.events()[2].is_inactive()
                        })
                    {
                        md_ok |= 0x0040;
                    }

                    // 0x0080 — each of the three is retrieved through the REAL NtWaitForDebugEvent
                    // arm, in order, and continued by SSN: create-process, then the two
                    // DbgLoadDllStateChanges carrying the bases that were mapped before the attach.
                    let mut plain_client = [0u8; 16];
                    plain_client[0..8].copy_from_slice(&(plain as u64).to_le_bytes());
                    plain_client[8..16]
                        .copy_from_slice(&(plain_main.unwrap_or(0) as u64).to_le_bytes());
                    let mut drained_ok = img_spawn::smss_copyout(A_CLIENT_ID, &plain_client);
                    for (state, base) in [
                        (dbgk::DBG_CREATE_PROCESS_STATE_CHANGE, PLAIN_IMAGE_BASE),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_A),
                        (dbgk::DBG_LOAD_DLL_STATE_CHANGE, PLAIN_DLL_B),
                    ] {
                        let reported_base_offset = if state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        {
                            0x38 // CreateProcessInfo.NewProcess.BaseOfImage
                        } else {
                            0x20 // LoadDll.BaseOfDll
                        };
                        drained_ok = drained_ok
                            && sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            ) == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == state
                            && sc_u64!(0x08) == plain as u64
                            && sc_u64!(reported_base_offset) == base
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) == 0;
                    }
                    if drained_ok
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        md_ok |= 0x0080;
                    }

                    nt_handler.clear_temporary_process_slot(MOD_TEST_PI);
                    nt_handler.clear_temporary_process_slot(MOD_TEST_PI2);
                    for handle in [h_target, h_plain] {
                        if handle != 0 {
                            let _ = nt_handler
                                .pm
                                .close_handle(debugger_pid, handle as nt_process::Handle);
                        }
                    }
                    // DbgkpCloseObject through the real NtClose arm — no debug object survives the
                    // spec, so the gate's post-spec state matches a plain boot.
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle]);
                }
            }

            ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_deadline_100ns = u64::MAX;
            DBGK_MODULE_SELFTEST.store(md_ok, Ordering::Relaxed);
        }

        // The hosted receive loop is finished and has no delay waiter outstanding. Disable timer 0
        // and unbind its notification so a stale HPET signal cannot intercept later self-test recvs.
        delay_timer_shutdown(&delay_queue);

        // === Dbgk TARGET-SIDE BLOCKING SELF-TEST (POST-LOOP) — the keystone deferred item ==========
        //
        // NT blocks the REPORTING thread inside `DbgkpQueueMessage` until `NtDebugContinue` runs
        // `DbgkpWakeTarget`, then applies the continue status to it. Proving that needs something no
        // model call can give: a LIVE thread genuinely blocked in-kernel on the Call that delivered
        // its fault, whose reply capability the executive holds. So this test stands up a REAL
        // throwaway CLIENT THREAD (`selftests::dbgk_client_spawn` — a fresh VSpace + code page +
        // hosted-syscalls TCB + SC, the same machinery as the ALPC cross-VSpace proof) that takes ONE
        // FAULT OF EACH FLAVOUR in order, writing a progress MARKER between them. The executive reads
        // that marker through its own window on the client's shared frame, so "the reporter blocked"
        // and "the continue resumed it" are OBSERVED, not inferred.
        //
        // The DEBUGGER side runs through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory, the established idiom); the TARGET
        // side runs through `dbgk_forward_exception` / `dbgk_module_load` / `dbgk_block_reporter` -
        // the very entries the live fault loop and the live `NtMapViewOfSection` arm call.
        // Throwaway-only: a temporary handler slot, fresh caps, all reclaimed afterwards.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const A_HANDLE: u64 = STACK_BASE + 0x180;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x188;
            const A_TIMEOUT: u64 = STACK_BASE + 0x198;
            const A_STATE: u64 = STACK_BASE + 0x1A0;
            const BLK_TEST_PI: usize = MAX_PI - 1;
            // Executive scratch VAs inside the SAME proven-resident 2 MiB page table the ALPC
            // cross-VSpace self-test uses (see its comment): base + 3000*0x1000, PT index 5.
            let write_scratch_t = SMSS_SCRATCH_BASE + 3010 * 0x1000;
            let write_scratch_d = SMSS_SCRATCH_BASE + 3011 * 0x1000;
            let marker_win_t = SMSS_SCRATCH_BASE + 3012 * 0x1000;
            let marker_win_d = SMSS_SCRATCH_BASE + 3013 * 0x1000;

            let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
            let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
            let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
            let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
            let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
            let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
            let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx.take();
            ACTIVE_STACK_BASE.store(STACK_BASE, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(STACK_FRAMES * 0x1000, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(SMSS_STACK_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(SMSS_HEAP_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(IMAGE_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(0, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut bk_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {
                    nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status
                };
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;
            let client_args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());

            // Throwaway caps: the client's shared marker frame, the `#PF` fixup frame, the reply
            // objects each fault is received on, and a spare reply object for the escape-hatch probe.
            let mut slots = [0u64; 96];
            let mut nslots = 0usize;
            let mut make = |kind: u64, bits: u32| -> u64 {
                let s = alloc_slot();
                slots[nslots] = s;
                nslots += 1;
                let made = untyped_retype_r(CAP_INIT_UNTYPED, kind, bits, 1, s);
                if made != 0 {
                    print_str(b"[dbgk-blk] retype FAILED kind=");
                    print_u64(kind);
                    print_str(b" status=");
                    print_u64(made);
                    print_str(b"\n");
                }
                s
            };
            let shared_t = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let shared_d = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let fixup_frame = make(OBJ_X86_4K_PAGE, PAGING_BITS);
            let reply_a = make(OBJ_REPLY, 0);
            let reply_b = make(OBJ_REPLY, 0);
            let reply_c = make(OBJ_REPLY, 0);
            let reply_d = make(OBJ_REPLY, 0);
            let reply_spare = make(OBJ_REPLY, 0);
            // NOTE the ORDER below: each marker frame is mapped into its CLIENT'S VSpace FIRST (by
            // `dbgk_client_spawn`) and only then windowed into the executive through a `copy_cap`.
            // A frame capability carries its own mapping, and mapping a COPY first leaves the
            // ORIGINAL's map attempt failing with `seL4_DeleteFirst` — which is exactly how the
            // ALPC cross-VSpace self-test orders its shared frames too.
            if debugger_pid != 0 && client_args_ready {
                // --- a real DEBUG_OBJECT, by SSN ---------------------------------------------
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    // The debuggee EPROCESS standing for the throwaway CLIENT THREAD, in a free
                    // temporary slot so pi -> pid -> DebugPort resolution is the real one. A second
                    // thread keeps the process alive when the first is terminated by DBG_TERMINATE.
                    let target = nt_handler.pm.create_process("dbgk-block.exe", None, None);
                    nt_handler.pm.set_image_base(target, 0x0000_0001_9000_0000);
                    let main = nt_handler.pm.create_thread(target, 0x5100, 0, false).ok();
                    let _keepalive = nt_handler.pm.create_thread(target, 0x5200, 0, false).ok();
                    let target_registered = nt_handler
                        .register_temporary_process_slot(BLK_TEST_PI, target, 0)
                        .is_ok();
                    let main_tid = main.unwrap_or(0);
                    let h_target = nt_handler
                        .pm
                        .insert_handle(
                            debugger_pid,
                            nt_process::HandleObject::Process(target),
                            PROCESS_SUSPEND_RESUME,
                        )
                        .map(u64::from)
                        .unwrap_or(0);
                    let mut client_id = [0u8; 16];
                    client_id[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                    client_id[8..16].copy_from_slice(&(main_tid as u64).to_le_bytes());
                    let cid_written = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);

                    // --- THE LIVE CLIENT THREAD ---------------------------------------------
                    let code = selftests::dbgk_target_client_code();
                    let (client_pml4, client_tcb, client_ep) = selftests::dbgk_client_spawn(
                        &code,
                        shared_t,
                        write_scratch_t,
                        0,
                        &mut slots,
                        &mut nslots,
                    );
                    // 0x0001 — setup: attach BY SSN + drain the fake create message BY SSN. The
                    // FIRST recv also proves the client thread really ran (marker 1) and really
                    // faulted (its `#PF` on the deliberately-unmapped page).
                    let attach_ok = target_registered
                        && h_target != 0
                        && cid_written
                        && sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // `DbgkpPostFakeProcessCreateMessages` posts one message per live thread — a
                    // `DbgKmCreateProcessApi` for the first and a `DbgKmCreateThreadApi` for the
                    // keep-alive one — so drain BOTH (each continued with ITS OWN CLIENT_ID) and
                    // leave the queue genuinely empty before the client's first fault is reported.
                    let mut drained = 0u64;
                    let mut first_state = 0u32;
                    while attach_ok && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        if drained == 0 {
                            first_state = sc_u32!(0x00);
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    // Restore the reporting thread's CLIENT_ID for the blocking continues below.
                    let cid_restored = img_spawn::smss_copyout(A_CLIENT_ID, &client_id);
                    let attached = attach_ok
                        && cid_restored
                        && drained == 2
                        && first_state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty());
                    // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══════
                    // The executive's own window on the client's marker page (a copy_cap of the
                    // SAME physical frame the client writes — mapped only now that the client's own
                    // mapping is in place).
                    let win_t = {
                        let s = copy_cap(shared_t);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    };
                    let win_t_ok =
                        page_map_r(win_t, marker_win_t, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_t = || {
                        if win_t_ok {
                            core::ptr::read_volatile(marker_win_t as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // ★ Every stage below is GUARDED. A blocking `recv` on the client's endpoint is
                    // only ever issued once the previous continue is KNOWN to have resumed it, and
                    // any failure breaks out with the bits collected so far — a self-test that could
                    // block forever would be a boot wedge, which is exactly what this batch must not
                    // introduce. `loop { … break }` gives the early exits.
                    loop {
                        // ═══ FAULT 1 — VMFault (`#PF`), the flavour every page fault takes ═══
                        let (_fb, f1_mi, f1_m0, f1_m1, _f1m2, _f1m3) =
                            recv_full_r12(client_ep, reply_a);
                        dbgk_blk_trace(b"f1", f1_mi, f1_m0, f1_m1, marker_t());
                        if attached
                            && client_pml4 != 0
                            && (f1_mi >> 12) == 6
                            && f1_m1 == selftests::DBGK_CLIENT_FIXUP
                            && marker_t() == 1
                        {
                            bk_ok |= 0x0001;
                        }
                        // 0x0002 — ★ THE BLOCK. Forward the fault through the entry the live loop
                        // uses, then PARK the reporting thread on the event it just queued.
                        // Observable: the block rides on the DEBUG_EVENT, the counter moves, and the
                        // client has NOT progressed (marker still 1) while the debugger holds it.
                        let blocked_before = DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed);
                        let forwarded = nt_handler.dbgk_forward_exception(
                            BLK_TEST_PI,
                            main_tid as u64,
                            dbgk::ExceptionRecord::access_violation(f1_m0, 1, f1_m1),
                            true,
                        );
                        let parked = nt_handler.dbgk_block_reporter(
                            BLK_TEST_PI,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_VM_FAULT,
                            reply_a,
                            f1_m0,
                            0,
                            0,
                            0,
                        );
                        dbgk_blk_trace(
                            b"blk1",
                            0,
                            forwarded as u64,
                            parked as u64,
                            nt_handler.pm.blocked_reporter_count(object) as u64,
                        );
                        if forwarded
                            && parked
                            && DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed) == blocked_before + 1
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 1
                        {
                            bk_ok |= 0x0002;
                        }
                        if !parked {
                            break; // nothing holds the client's reply cap — never recv again
                        }
                        // 0x0004 — ★ THE CONTINUE RESUMES IT. The debugger retrieves the exception,
                        // maps the page the client faulted on (a real debugger's fixup), and
                        // continues: `DbgkpWakeTarget` replies with the VMFault shape (length 0, no
                        // register transfer) so the faulting instruction is RETRIED — and now
                        // succeeds. Proof it resumed AND continued: its NEXT fault arrives with
                        // marker 2, i.e. the instruction after the `#PF` really executed.
                        let mapped = page_map_r(
                            fixup_frame,
                            selftests::DBGK_CLIENT_FIXUP,
                            RW_NX,
                            client_pml4,
                        ) == 0;
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait1 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read1 = wait1 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE;
                        let cont1 = if read1 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke1 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(b"c1", 0, wait1 as u64, cont1 as u64, woke1 as u64);
                        if !woke1 {
                            // The reporter was never resumed — release it so nothing is stranded,
                            // and do NOT recv (the client can no longer produce an event).
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 2 — DebugException (int3) ══════════════════════════════
                        let (_fb, f2_mi, f2_m0, _f2m1, _f2m2, _f2m3) =
                            recv_full_r12(client_ep, reply_b);
                        dbgk_blk_trace(b"f2", f2_mi, f2_m0, 0, marker_t());
                        if mapped
                            && read1
                            && cont1 == 0
                            && nt_handler.pm.blocked_reporter_count(object) == 0
                            && (f2_mi >> 12) == 4
                            && marker_t() == 2
                        {
                            bk_ok |= 0x0004;
                        }
                        // 0x0008 — the DebugException flavour: forward the int3, BLOCK its reporter,
                        // prove no progress, continue — the client resumes PAST the int3 and its
                        // next fault carries marker 3.
                        let forwarded2 = nt_handler.dbgk_forward_exception(
                            BLK_TEST_PI,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f2_m0),
                            true,
                        );
                        let blocked2 = nt_handler.dbgk_block_reporter(
                            BLK_TEST_PI,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                            reply_b,
                            f2_m0,
                            0,
                            0,
                            0,
                        );
                        let no_progress2 = forwarded2
                            && blocked2
                            && nt_handler.pm.blocked_reporter_count(object) == 1
                            && marker_t() == 2;
                        if !blocked2 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait2 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read2 = wait2 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE;
                        let cont2 = if read2 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke2 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c2",
                            no_progress2 as u64,
                            wait2 as u64,
                            cont2 as u64,
                            woke2 as u64,
                        );
                        if !woke2 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 3 — UnknownSyscall: the SYSCALL flavour ═══════════════
                        let (_fb, f3_mi, f3_m0, _f3m1, f3_m2, _f3m3) =
                            recv_full_r12(client_ep, reply_c);
                        // The service loop's own derivation: for an UnknownSyscall the resume IP is
                        // RCX (MR2) — the address `syscall` pushed — NOT the message's FaultIP slot.
                        let f3_ip = f3_m2;
                        let f3_sp = get_recv_mr(16);
                        let f3_flags = get_recv_mr(17);
                        dbgk_blk_trace(b"f3", f3_mi, f3_m0, 0, marker_t());
                        if no_progress2
                            && cont2 == 0
                            && (f3_mi >> 12) == 2
                            && f3_m0 == 0xDB
                            && marker_t() == 3
                        {
                            bk_ok |= 0x0008;
                        }
                        // 0x0010 — the SYSCALL flavour. A real `DbgkMapViewOfSection` load-dll event
                        // posted from a SYSCALL blocks its reporter (NT queues it with flags 0), and
                        // DBG_CONTINUE resumes it with the SYSCALL reply shape — status in MR0,
                        // resume context in MR15/16/17 — so the syscall returns and the client runs
                        // on.
                        nt_handler.current_tid = main_tid as u64;
                        let module_posted = nt_handler.dbgk_module_load(
                            BLK_TEST_PI,
                            0x0000_0001_9100_0000,
                            0,
                            (0, 0),
                            0,
                        );
                        nt_handler.current_tid = debugger_tid as u64;
                        nt_handler.dbgk_block_request = false;
                        let blocked3 = nt_handler.dbgk_block_reporter(
                            BLK_TEST_PI,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_SYSCALL,
                            reply_c,
                            f3_ip,
                            f3_sp,
                            f3_flags,
                            0,
                        );
                        let no_progress3 = module_posted && blocked3 && marker_t() == 3;
                        if !blocked3 {
                            break;
                        }
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait3 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let read3 = wait3 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_LOAD_DLL_STATE_CHANGE;
                        let cont3 = if read3 {
                            sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            )
                        } else {
                            u32::MAX
                        };
                        let woke3 =
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        dbgk_blk_trace(
                            b"c3",
                            no_progress3 as u64,
                            wait3 as u64,
                            cont3 as u64,
                            woke3 as u64,
                        );
                        if !woke3 {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                            break;
                        }
                        // ═══ FAULT 4 — UserException (`ud2`) ════════════════════════════
                        let (_fb, f4_mi, f4_m0, f4_m1, f4_m2, _f4m3) =
                            recv_full_r12(client_ep, reply_d);
                        dbgk_blk_trace(b"f4", f4_mi, f4_m0, 0, marker_t());
                        if no_progress3 && cont3 == 0 && (f4_mi >> 12) == 3 && marker_t() == 4 {
                            bk_ok |= 0x0010;
                        }
                        // 0x0020 — ★ DBG_TERMINATE_THREAD **ENFORCED**. Block the `ud2` reporter,
                        // then continue with DBG_TERMINATE_THREAD: the reporting ETHREAD is really
                        // terminated and it is NEVER resumed — the marker stays 4, i.e. the
                        // instruction after the `ud2` never executed. (Before this batch the status
                        // was recorded, not enforced.)
                        let forwarded4 = nt_handler.dbgk_forward_exception(
                            BLK_TEST_PI,
                            main_tid as u64,
                            dbgk::ExceptionRecord::new(0xC000_001D, f4_m0),
                            true,
                        );
                        let blocked4 = nt_handler.dbgk_block_reporter(
                            BLK_TEST_PI,
                            main_tid as u64,
                            0,
                            dbgk::DBGK_BLOCK_USER_EXCEPTION,
                            reply_d,
                            f4_m0,
                            f4_m1,
                            f4_m2,
                            0,
                        );
                        let terms_before = DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed);
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let wait4 = sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        );
                        let terminated = forwarded4
                            && blocked4
                            && wait4 == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc)
                            && sc_u32!(0x00) == dbgk::DBG_EXCEPTION_STATE_CHANGE
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_TERMINATE_THREAD as u64]
                            ) == 0;
                        dbgk_blk_trace(
                            b"term",
                            terminated as u64,
                            DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed),
                            DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed),
                            marker_t(),
                        );
                        if terminated
                            && DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed) == terms_before + 1
                            && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before
                            && nt_handler
                                .pm
                                .thread(main_tid)
                                .is_some_and(|t| t.state == nt_process::ThreadState::Terminated)
                            && marker_t() == 4
                        {
                            bk_ok |= 0x0020;
                        }
                        break;
                    }

                    // ═══ 0x0080 — ★ THE DEBUGGER-SIDE BLOCKING WAIT, with a LIVE CLIENT ═══════
                    // A second real client thread issues a syscall the test services as
                    // `NtWaitForDebugEvent` with an EMPTY queue. Its fault is received on the
                    // executive's REAL fault endpoint bound to REPLY_MAIN, so the PRODUCTION
                    // `wait_park` steals its reply capability exactly as the service loop does. The
                    // client cannot progress until a queue-side post runs `wait_wake_dispatcher_set`.
                    let dcode = selftests::dbgk_debugger_client_code();
                    let (dbg_pml4, dbg_tcb, _dbg_ep) = selftests::dbgk_client_spawn(
                        &dcode,
                        shared_d,
                        write_scratch_d,
                        fault_ep,
                        &mut slots,
                        &mut nslots,
                    );
                    let win_d = {
                        let s = copy_cap(shared_d);
                        slots[nslots] = s;
                        nslots += 1;
                        s
                    };
                    let win_d_ok =
                        page_map_r(win_d, marker_win_d, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
                    let marker_d = || {
                        if win_d_ok {
                            core::ptr::read_volatile(marker_win_d as *const u64)
                        } else {
                            u64::MAX
                        }
                    };
                    // Drain anything still queued so the wait genuinely finds nothing to report.
                    let mut drain_guard = 0;
                    while drain_guard < 16 {
                        drain_guard += 1;
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                        {
                            break;
                        }
                        if !img_spawn::smss_copyin(A_STATE, &mut sc) {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                    }
                    // ★ SELECT this test's client, don't just take whatever arrives. `fault_ep` is
                    // the executive's SHARED endpoint: a hosted thread that was still runnable when
                    // the loop quiesced can land here first, and a bare `recv` would then read ITS
                    // message as the client's (observed: a win32k `m0 = 0x101b` from a still-live
                    // winlogon worker, which made this step read a foreign syscall and silently skip
                    // the whole assertion). Any foreign message is simply LEFT UNANSWERED — the boot
                    // has already quiesced, so an un-replied caller is exactly as parked as every
                    // other thread on the `[parked]` list. The selection is on the client's own
                    // distinctive SSN, so the assertion below is unchanged in strength.
                    let mut w_mi = 0u64;
                    let mut w_m0 = 0u64;
                    let mut w_m2 = 0u64;
                    let mut select_guard = 0;
                    while select_guard < 8 {
                        select_guard += 1;
                        let (_wb, mi_r, m0_r, _w1, m2_r, _w3) =
                            recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                        w_mi = mi_r;
                        w_m0 = m0_r;
                        w_m2 = m2_r;
                        if (mi_r >> 12) == 2 && m0_r == 0xD1 {
                            break;
                        }
                        dbgk_blk_trace(b"dw1-foreign", mi_r, m0_r, 0, marker_d());
                    }
                    let w_ip = w_m2; // RCX = the syscall return address (the loop's `resume_ip`)
                    let w_sp = get_recv_mr(16);
                    let w_flags = get_recv_mr(17);
                    dbgk_blk_trace(b"dw1", w_mi, w_m0, 0, marker_d());
                    // The handler's own park REQUEST (NULL *Timeout, empty queue) — the exact arm a
                    // hosted debugger would take.
                    nt_handler.wait_park_event = -1;
                    let wait_status =
                        sysc!(SSN_NT_WAIT_FOR_DEBUG_EVENT, &[dbg_handle, 0, 0, A_STATE]);
                    let park_index = nt_handler.wait_park_event;
                    let live_parked = dbg_pml4 != 0
                        && (w_mi >> 12) == 2
                        && w_m0 == 0xD1
                        && wait_status == 0x102
                        && park_index >= 0
                        && wait_park(park_index as usize, w_ip, w_sp, w_flags, 0xD1D1_0001, None)
                        && marker_d() == 0;
                    // A queue-side post through the very entry the fault path uses SETS the
                    // object's EventsPresent dispatcher event and wakes the parked client.
                    let _ = nt_handler.dbgk_forward_exception(
                        BLK_TEST_PI,
                        main_tid as u64,
                        dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, 0x9999),
                        true,
                    );
                    // GUARD: only recv again when the client was really parked (else nothing
                    // could ever resume it and the recv would block forever).
                    if live_parked {
                        let (_wb2, w2_mi, w2_m0, _x1, _x2, _x3) =
                            recv_full_r12(fault_ep, REPLY_MAIN_SLOT.load(Ordering::Relaxed));
                        dbgk_blk_trace(b"dw2", w2_mi, w2_m0, 0, marker_d());
                        if (w2_mi >> 12) == 2 && w2_m0 == 0xD2 && marker_d() == 1 {
                            bk_ok |= 0x0080;
                        }
                    }

                    // 0x0040 — ★ THE ESCAPE HATCH. Leave a reporter blocked and destroy the debug
                    // object (`NtClose` → `DbgkpCloseObject`, i.e. the debugger died holding the
                    // event): every blocked target is RELEASED, so nothing can stay parked forever.
                    let released_before = DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed);
                    let stranded = nt_handler.dbgk_block_reporter(
                        BLK_TEST_PI,
                        main_tid as u64,
                        0,
                        dbgk::DBGK_BLOCK_VM_FAULT,
                        reply_spare,
                        0x1000,
                        0,
                        0,
                        0,
                    );
                    if stranded
                        && nt_handler.pm.blocked_reporter_count(object) == 1
                        && sysc!(SSN_NT_CLOSE, &[dbg_handle]) == 0
                        && DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed) == released_before + 1
                        && nt_handler.pm.debug_object(object).is_none()
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        bk_ok |= 0x0040;
                    }

                    // Reclaim: suspend both throwaway client threads, then delete every cap this
                    // test made (child-first), leaving the TCBs + PML4s last. The executive's own
                    // `fault_ep` is NOT in `slots` (it was passed in, not minted). These caps are
                    // selftest-private, so their root slots can be returned to the allocator before
                    // the next post-loop selftest starts.
                    let _ = tcb_suspend_r(client_tcb);
                    let _ = tcb_suspend_r(dbg_tcb);
                    for index in (0..nslots).rev() {
                        let s = slots[index];
                        if s == 0
                            || s == client_tcb
                            || s == dbg_tcb
                            || s == client_pml4
                            || s == dbg_pml4
                        {
                            continue;
                        }
                        let _ = cnode_delete_recycle_r(s);
                    }
                    let _ = cnode_delete_recycle_r(client_tcb);
                    let _ = cnode_delete_recycle_r(dbg_tcb);
                    let _ = cnode_delete_recycle_r(client_pml4);
                    let _ = cnode_delete_recycle_r(dbg_pml4);
                    nt_handler.clear_temporary_process_slot(BLK_TEST_PI);
                }
            }

            print_str(b"[ntos-exec] dbgk target-block selftest bits=0x");
            print_hex(bk_ok as u32);
            print_str(b" blocked=");
            print_u64(DBGK_REPORTERS_BLOCKED.load(Ordering::Relaxed));
            print_str(b" resumed=");
            print_u64(DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed));
            print_str(b" terminated=");
            print_u64(DBGK_TERMINATES_ENFORCED.load(Ordering::Relaxed));
            print_str(b" released=");
            print_u64(DBGK_REPORTERS_RELEASED.load(Ordering::Relaxed));
            print_str(b"\n");

            ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_deadline_100ns = u64::MAX;
            DBGK_BLOCK_SELFTEST.store(bk_ok, Ordering::Relaxed);
        }

        // === Dbgk REMOTE BREAK-IN SELF-TEST (POST-LOOP) — `DbgUiIssueRemoteBreakin`, end to end ===
        //
        // Three things had to become real together, because each is inert without the others:
        //   (1) CROSS-VSPACE THREAD CREATION — `NtCreateThread` with a FOREIGN `ProcessHandle` that
        //       really builds a thread (own stack + TEB + IPC buffer, caller-supplied entry AND
        //       parameter) inside the TARGET's address space (`create_remote_thread` →
        //       `rendezvous::spawn_slot_thread`).
        //   (2) `PEB->BeingDebugged` WRITE-THROUGH into the target's LIVE PEB page
        //       (`DbgkpMarkProcessPeb`) — without it `DbgUiRemoteBreakin` reads a zero byte, skips
        //       `DbgBreakPoint()` and exits silently, so the whole feature would be a no-op.
        //   (3) the `int3` → `DbgkForwardException` → `NtWaitForDebugEvent` → `NtDebugContinue`
        //       chain that batches 52 and 54 already built.
        //
        // The DEBUGGER side goes through the REAL dispatch route (`nt_dispatcher.dispatch(SSN, …)`
        // with the arguments marshalled in smss's CLIENT memory — the established idiom); the
        // TARGET side goes through `dbgk_forward_exception` / `dbgk_block_reporter`, the very
        // entries the live fault loop calls. The MECHANISM spawn calls `rendezvous::spawn_slot_thread`
        // — exactly what the loop's `spawn_requested_remote_thread` calls with the request the
        // handler produced — differing only in the two transport switches a target with no ntdll
        // mapped requires (direct entry instead of `LdrInitializeThunk`, hosted-syscalls instead of
        // the native Call) and a private endpoint, so the post-loop test can service it itself.
        {
            use nt_process::dbgk;
            const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
            const PROCESS_CREATE_THREAD: u32 = 0x0002;
            const THREAD_ALL_ACCESS: u64 = 0x001F_03FF;
            const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
            const BRK_TEST_PI: usize = MAX_PI - 3;
            // Argument scratch in smss's CLIENT memory (its stack mirror), clear of the block
            // self-test's window and of the live stack (which grows DOWN from the top).
            const A_HANDLE: u64 = STACK_BASE + 0x300;
            const A_CLIENT_ID: u64 = STACK_BASE + 0x308;
            const A_TIMEOUT: u64 = STACK_BASE + 0x318;
            const A_STATE: u64 = STACK_BASE + 0x320;
            // A_STATE holds a whole DBGUI_WAIT_STATE_CHANGE (0xB8) → 0x320..0x3D8; keep the
            // NtCreateThread argument block clear of it.
            const A_THREAD_HANDLE: u64 = STACK_BASE + 0x400;
            const A_CID_OUT: u64 = STACK_BASE + 0x408;
            const A_CALLER_SP: u64 = STACK_BASE + 0x420; // the "client stack" NtCreateThread reads
            const A_CONTEXT: u64 = STACK_BASE + 0x500; // the caller's CONTEXT record
                                                       // Executive scratch inside the SAME proven-resident 2 MiB page table the other post-loop
                                                       // self-tests use (SMSS_SCRATCH_BASE + 3000*0x1000, PT index 5).
            let write_scratch = SMSS_SCRATCH_BASE + 3020 * 0x1000;
            let mark_win = SMSS_SCRATCH_BASE + 3021 * 0x1000;
            let peb_win = SMSS_SCRATCH_BASE + 3022 * 0x1000;

            let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
            let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
            let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
            let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
            let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
            let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
            let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
            let saved_pi = nt_handler.pi;
            let saved_tid = nt_handler.current_tid;
            let saved_ctx = nt_handler.loop_ctx.take();
            ACTIVE_STACK_BASE.store(STACK_BASE, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(STACK_FRAMES * 0x1000, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(SMSS_STACK_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(SMSS_HEAP_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(IMAGE_MIRROR_VA, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(0, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(SMSS_SCRATCH_BASE, Ordering::Relaxed);
            nt_handler.pi = 0;

            let mut br_ok = 0u64;
            let dbg_origin = SyscallOrigin::new(1, 1, ProcessorMode::UserMode);
            // Every dispatch through the real route, with the out-param write queue drained exactly
            // as the service loop drains it (`xas_write_u64` per queued write).
            macro_rules! sysc {
                ($ssn:expr, $args:expr) => {{
                    nt_handler.out_writes_n = 0;
                    let status = nt_dispatcher
                        .dispatch($ssn as u32, $args, &dbg_origin, &mut nt_handler)
                        .status;
                    for k in 0..nt_handler.out_writes_n {
                        let (ptr, val) = nt_handler.out_writes[k];
                        let _ = nt_handler.xas_write_u64(ptr, val);
                    }
                    nt_handler.out_writes_n = 0;
                    status
                }};
            }
            let mut sc = [0u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE];
            macro_rules! sc_u32 {
                ($o:expr) => {
                    u32::from_le_bytes(sc[$o..$o + 4].try_into().unwrap())
                };
            }

            let debugger_pid = nt_handler.pm_pid_for_pi(0).unwrap_or(0);
            let debugger_tid = nt_handler.pm.main_thread(debugger_pid).unwrap_or(0);
            nt_handler.current_tid = debugger_tid as u64;

            let mut slots = [0u64; 64];
            let mut nslots = 0usize;
            // Macros (not closures) so the slot list stays freely usable alongside them.
            macro_rules! push_slot {
                ($cap:expr) => {{
                    let s = $cap;
                    slots[nslots] = s;
                    nslots += 1;
                    s
                }};
            }
            macro_rules! make {
                ($kind:expr, $bits:expr) => {{
                    let s = push_slot!(alloc_slot());
                    let made = untyped_retype_r(CAP_INIT_UNTYPED, $kind, $bits, 1, s);
                    if made != 0 {
                        print_str(b"[dbgk-brk] retype FAILED kind=");
                        print_u64($kind);
                        print_str(b" status=");
                        print_u64(made);
                        print_str(b"\n");
                    }
                    s
                }};
            }

            // ── The throwaway TARGET's address space ────────────────────────────────────────
            // A real hosted-process paging skeleton: the image PT (which covers the env block —
            // PEB @0x53, DESKINFO @0x54 and PE_LOAD_BASE @0x56) plus the WORK_CLUSTER PT that holds
            // the bounded thread-slot windows the remote thread's stack/TEB/IPC/trampoline land in.
            let target_pml4 = make!(OBJ_X86_PML4, PAGING_BITS);
            map_image_skeleton(target_pml4, 1);
            // The target's PEB page: mapped in ITS VSpace first, then windowed into the executive
            // (a frame capability carries its own mapping — map the original before any copy), and
            // registered with that window as its permanent alias, exactly as `spawn_sec_image`
            // registers a hosted process's PEB. That registration is what lets the general
            // client-memory writer reach it — `dbgk_mark_process_peb` invents no new mechanism.
            let peb_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let peb_mapped = page_map_r(peb_frame, SMSS_PEB_VA, RW_NX, target_pml4) == 0;
            let peb_alias = push_slot!(copy_cap(peb_frame));
            let peb_win_ok =
                peb_mapped && page_map_r(peb_alias, peb_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            if peb_win_ok {
                csrss_frame_put_at(BRK_TEST_PI as u64, SMSS_PEB_VA, peb_frame, peb_win);
            }
            // The marker page (target-only) + the executive's window on the same frame.
            let mark_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let mark_mapped = page_map_r(
                mark_frame,
                selftests::DBGK_BREAKIN_MARK_VA,
                RW_NX,
                target_pml4,
            ) == 0;
            let mark_alias = push_slot!(copy_cap(mark_frame));
            let mark_win_ok =
                mark_mapped && page_map_r(mark_alias, mark_win, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            let marker = |offset: u64| -> u64 {
                if mark_win_ok {
                    core::ptr::read_volatile((mark_win + offset) as *const u64)
                } else {
                    u64::MAX
                }
            };
            let peb_being_debugged = || -> u64 {
                if peb_win_ok {
                    core::ptr::read_volatile(
                        (peb_win + nt_ntdll_layout::PEB_BEING_DEBUGGED_OFFSET as u64) as *const u8,
                    ) as u64
                } else {
                    u64::MAX
                }
            };
            // `DbgUiRemoteBreakin`'s code page: written through an executive alias, mapped RX (W^X).
            let code = selftests::dbgk_breakin_thread_code();
            let code_frame = make!(OBJ_X86_4K_PAGE, PAGING_BITS);
            let code_written =
                page_map_r(code_frame, write_scratch, RW_NX, CAP_INIT_THREAD_VSPACE) == 0;
            if code_written {
                for (i, b) in code.iter().enumerate() {
                    core::ptr::write_volatile((write_scratch + i as u64) as *mut u8, *b);
                }
            }
            let code_copy = push_slot!(copy_cap(code_frame));
            let code_mapped = code_written
                && page_map_r(
                    code_copy,
                    selftests::DBGK_BREAKIN_CODE_VA,
                    /* RX */ 2,
                    target_pml4,
                ) == 0;

            let brk_ep = make!(OBJ_ENDPOINT, 0);
            let reply_a = make!(OBJ_REPLY, 0);
            let reply_b = make!(OBJ_REPLY, 0);

            // ── The throwaway TARGET process object ────────────────────────────────────────
            let target = nt_handler.pm.create_process("dbgk-breakin.exe", None, None);
            nt_handler.pm.set_image_base(target, 0x0000_0001_A000_0000);
            let target_main = nt_handler
                .pm
                .create_thread(target, selftests::DBGK_BREAKIN_CODE_VA, 0, false)
                .unwrap_or(0);
            // The target's pre-created spare ETHREAD pool — the same reset-safe pool every hosted
            // process gets at boot, and what a runtime thread create draws from.
            let pool_tid = nt_handler
                .pm
                .create_thread(target, 0, 0, false)
                .unwrap_or(0);
            let target_registered = nt_handler
                .register_temporary_process_slot(BRK_TEST_PI, target, target_pml4)
                .is_ok();
            let pool_registered = nt_handler
                .register_temporary_pool_thread_slot(BRK_TEST_PI, 0, pool_tid)
                .is_ok();
            // This process HAS its initial thread, so a foreign-handle create is a genuine
            // ADDITIONAL thread — the real cross-VSpace path (exactly the live rule).
            PM_INITIAL_THREAD_DONE.fetch_or(1u64 << BRK_TEST_PI, Ordering::Relaxed);

            let h_target = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD,
                )
                .map(u64::from)
                .unwrap_or(0);
            // The SAME process, through a handle that lacks PROCESS_CREATE_THREAD.
            let h_target_no_create = nt_handler
                .pm
                .insert_handle(
                    debugger_pid,
                    nt_process::HandleObject::Process(target),
                    PROCESS_SUSPEND_RESUME,
                )
                .map(u64::from)
                .unwrap_or(0);

            let args_ready = img_spawn::smss_copyout(A_HANDLE, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_CONTEXT, &[0u8; 0x100])
                && img_spawn::smss_copyout(A_TIMEOUT, &0i64.to_le_bytes());
            let setup_ok = peb_win_ok
                && mark_win_ok
                && code_mapped
                && target_main != 0
                && pool_tid != 0
                && target_registered
                && pool_registered
                && h_target != 0
                && h_target_no_create != 0
                && args_ready
                && debugger_pid != 0;

            let mut spawned_breakin_tid = 0u64;
            let mut breakin_runtime_tid = 0u64;
            if setup_ok {
                // ── 0x0001 — a real DEBUG_OBJECT + attach BY SSN, fake create messages drained ──
                let created = sysc!(
                    SSN_NT_CREATE_DEBUG_OBJECT,
                    &[
                        A_HANDLE,
                        dbgk::DEBUG_OBJECT_ALL_ACCESS as u64,
                        0,
                        dbgk::DBGK_KILL_PROCESS_ON_EXIT as u64,
                    ]
                );
                let dbg_handle = smss_stack_read(A_HANDLE);
                let object = match nt_handler
                    .pm
                    .lookup_handle(debugger_pid, dbg_handle as nt_process::Handle)
                {
                    Some(nt_process::HandleObject::DebugObject(object)) => Some(object),
                    _ => None,
                };
                if let (0, Some(object)) = (created, object) {
                    let peb_before = peb_being_debugged();
                    let marks_before = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let attached = sysc!(SSN_NT_DEBUG_ACTIVE_PROCESS, &[h_target, dbg_handle]) == 0
                        && nt_handler.pm.process_debug_port(target) == Some(object);
                    // `DbgkpPostFakeProcessCreateMessages` posts one message per live thread.
                    let mut drained = 0u64;
                    while attached && drained < 8 {
                        if sysc!(
                            SSN_NT_WAIT_FOR_DEBUG_EVENT,
                            &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                        ) != 0
                            || !img_spawn::smss_copyin(A_STATE, &mut sc)
                        {
                            break;
                        }
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&sc[0x08..0x10]);
                        cid[8..16].copy_from_slice(&sc[0x10..0x18]);
                        if !img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            || sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) != 0
                        {
                            break;
                        }
                        drained += 1;
                    }
                    if attached
                        && drained == 2
                        && nt_handler
                            .pm
                            .debug_object(object)
                            .is_some_and(|o| o.is_empty())
                    {
                        br_ok |= 0x0001;
                    }
                    // ── 0x0002 — ★ `PEB->BeingDebugged` WRITTEN THROUGH, read back out of the
                    // TARGET's own PEB page (the very frame its VSpace maps at SMSS_PEB_VA).
                    if peb_before == 0
                        && peb_being_debugged() == 1
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before + 1
                        && nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0002;
                    }

                    // ── 0x0008 — ★ THE CROSS-VSPACE CREATE, BY SSN. Marshal NtCreateThread's
                    // stack-resident arguments (ClientId / ThreadContext / InitialTeb /
                    // CreateSuspended) in CLIENT memory and stage the caller stack pointer the
                    // handler reads them through, then issue SSN 55 with the TARGET's handle.
                    let ctx_ok =
                        img_spawn::smss_copyout(
                            A_CONTEXT + nt_thread_start::CONTEXT_RIP_OFFSET,
                            &selftests::DBGK_BREAKIN_CODE_VA.to_le_bytes(),
                        ) && img_spawn::smss_copyout(
                            A_CONTEXT + nt_thread_start::CONTEXT_RCX_OFFSET,
                            &selftests::DBGK_BREAKIN_PARAM.to_le_bytes(),
                        ) && img_spawn::smss_copyout(A_CALLER_SP + 0x28, &A_CID_OUT.to_le_bytes())
                            && img_spawn::smss_copyout(
                                A_CALLER_SP + 0x30,
                                &A_CONTEXT.to_le_bytes(),
                            )
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x38, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_CALLER_SP + 0x40, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_THREAD_HANDLE, &0u64.to_le_bytes())
                            && img_spawn::smss_copyout(A_CID_OUT, &[0u8; 16]);
                    set_recv_mr(16, A_CALLER_SP);
                    // ★ The security negative FIRST (it must change nothing): the same target
                    // through a handle without PROCESS_CREATE_THREAD.
                    // NtCreateThread's full 8-argument shape (the dispatcher enforces argc):
                    // ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,
                    // ThreadContext, InitialTeb, CreateSuspended — the last four also readable
                    // through the caller's stack, which is where the handler takes them from.
                    let denied = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target_no_create,
                            A_CID_OUT,
                            A_CONTEXT,
                            0,
                            0,
                        ]
                    );
                    let created_before = PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed);
                    set_recv_mr(16, A_CALLER_SP);
                    let create_status = sysc!(
                        SSN_NT_CREATE_THREAD,
                        &[
                            A_THREAD_HANDLE,
                            THREAD_ALL_ACCESS,
                            0,
                            h_target,
                            A_CID_OUT,
                            A_CONTEXT,
                            0,
                            0,
                        ]
                    );
                    let thread_handle = smss_stack_read(A_THREAD_HANDLE);
                    let cid_proc = smss_stack_read(A_CID_OUT);
                    let breakin_tid = smss_stack_read(A_CID_OUT + 8);
                    breakin_runtime_tid = breakin_tid;
                    let request = nt_handler.remote_thread_request.take();
                    print_str(b"[dbgk-brk] denied=0x");
                    print_hex(denied);
                    print_str(b" create=0x");
                    print_hex(create_status);
                    print_str(b" ctx_ok=");
                    print_u64(ctx_ok as u64);
                    print_str(b" h=0x");
                    print_hex(thread_handle as u32);
                    print_str(b" tid=");
                    print_u64(breakin_tid);
                    print_str(b" req=");
                    print_u64(request.is_some() as u64);
                    print_str(b"\n");
                    let handle_ok = matches!(
                        nt_handler
                            .pm
                            .lookup_handle(debugger_pid, thread_handle as nt_process::Handle),
                        Some(nt_process::HandleObject::Thread(t)) if t as u64 == breakin_tid
                    );
                    if ctx_ok
                        && denied == STATUS_ACCESS_DENIED
                        && create_status == 0
                        && PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed) == created_before + 1
                        && thread_handle != 0
                        && handle_ok
                        && cid_proc == target as u64
                        && breakin_tid != 0
                        && breakin_tid != target_main as u64
                        && request.is_some_and(|r| {
                            r.target_pi == BRK_TEST_PI
                                && r.pml4 == target_pml4
                                && r.start.rip == selftests::DBGK_BREAKIN_CODE_VA
                                && r.start.rcx == selftests::DBGK_BREAKIN_PARAM
                                && r.cid_thread == breakin_tid
                        })
                    {
                        br_ok |= 0x0008;
                    }

                    // ── 0x0010 — ★ THE REMOTE THREAD REALLY RUNS IN THE TARGET'S VSPACE.
                    // Build the mechanism through the same entry the loop uses; the thread's own
                    // stack/TEB/IPC buffer are mapped in the TARGET's pml4, and the marker it writes
                    // lands in a page that exists ONLY there.
                    let mut tcb = 0u64;
                    let mut breakin_runtime_slot = 0usize;
                    if let Some(request) = request {
                        breakin_runtime_slot = request.slot;
                        tcb = rendezvous::spawn_slot_thread(&rendezvous::RemoteThreadSpawn {
                            target_pi: request.target_pi,
                            slot: request.slot,
                            pml4: request.pml4,
                            start: request.start,
                            cid_proc: request.cid_proc,
                            cid_thread: request.cid_thread,
                            fault_ep: brk_ep,
                            // The throwaway target has no ntdll mapped, so enter the start routine
                            // directly and keep the hosted-syscalls trap (its exit `syscall` is
                            // delivered here as an UnknownSyscall fault).
                            use_loader: false,
                            native: false,
                            resume: request.resume,
                        });
                        if tcb != 0 {
                            nt_handler.register_hosted_thread_tcb(
                                BRK_TEST_PI,
                                request.cid_thread,
                                tcb,
                                tp_worker_badge(BRK_TEST_PI, request.slot),
                                HostedThreadRole::TpWorker { slot: request.slot },
                            );
                            spawned_breakin_tid = request.cid_thread;
                            PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if tcb != 0 {
                        // Its first fault: the `int3` if it read BeingDebugged = 1, else its exit
                        // syscall. Either way it must have RUN — the marker proves the thread
                        // executed in the target's address space with a correct TEB/PEB.
                        let (_fb, f1_mi, f1_m0, _f1m1, _f1m2, _f1m3) =
                            recv_full_r12(brk_ep, reply_a);
                        if marker(0x00) == 0x11
                            && marker(0x08) == SMSS_PEB_VA
                            && marker(0x18) == selftests::DBGK_BREAKIN_PARAM
                        {
                            br_ok |= 0x0010;
                        }
                        // ── 0x0020 — ★ IT HIT THE BREAKPOINT, and the debugger sees it.
                        // The byte it read is the write-through; the `int3` (DebugException,
                        // label 4) is forwarded through the live fault-loop entry and its reporter
                        // parked, then retrieved BY SSN as DbgBreakpointStateChange carrying the
                        // BREAK-IN THREAD's CLIENT_ID.
                        let is_breakpoint = (f1_mi >> 12) == 4 && marker(0x10) == 1;
                        let forwarded = is_breakpoint
                            && nt_handler.dbgk_forward_exception(
                                BRK_TEST_PI,
                                breakin_tid,
                                dbgk::ExceptionRecord::new(dbgk::STATUS_BREAKPOINT, f1_m0),
                                true,
                            );
                        let parked = forwarded
                            && nt_handler.dbgk_block_reporter(
                                BRK_TEST_PI,
                                breakin_tid,
                                0,
                                dbgk::DBGK_BLOCK_DEBUG_EXCEPTION,
                                reply_a,
                                f1_m0,
                                0,
                                0,
                                0,
                            );
                        let waited = parked
                            && sysc!(
                                SSN_NT_WAIT_FOR_DEBUG_EVENT,
                                &[dbg_handle, 0, A_TIMEOUT, A_STATE]
                            ) == 0
                            && img_spawn::smss_copyin(A_STATE, &mut sc);
                        let reported = waited
                            && sc_u32!(0x00) == dbgk::DBG_BREAKPOINT_STATE_CHANGE
                            && u64::from_le_bytes(sc[0x08..0x10].try_into().unwrap())
                                == target as u64
                            && u64::from_le_bytes(sc[0x10..0x18].try_into().unwrap())
                                == breakin_tid
                            && sc_u32!(0x18) == dbgk::STATUS_BREAKPOINT;
                        if reported {
                            br_ok |= 0x0020;
                        }
                        // ── 0x0040 — ★ CONTINUE RESUMES IT PAST THE int3 AND IT EXITS CLEANLY.
                        let resumed_before = DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed);
                        let mut cid = [0u8; 16];
                        cid[0..8].copy_from_slice(&(target as u64).to_le_bytes());
                        cid[8..16].copy_from_slice(&breakin_tid.to_le_bytes());
                        let continued = reported
                            && img_spawn::smss_copyout(A_CLIENT_ID, &cid)
                            && sysc!(
                                SSN_NT_DEBUG_CONTINUE,
                                &[dbg_handle, A_CLIENT_ID, dbgk::DBG_CONTINUE as u64]
                            ) == 0
                            && DBGK_REPORTERS_RESUMED.load(Ordering::Relaxed) == resumed_before + 1;
                        if continued {
                            // Its exit path: marker 0x12 (it really resumed past the breakpoint)
                            // then the `RtlExitUserThread` stand-in syscall arrives here.
                            let (_eb, e_mi, e_m0, _em1, _em2, _em3) =
                                recv_full_r12(brk_ep, reply_b);
                            if (e_mi >> 12) == 2
                                && e_m0 == selftests::DBGK_BREAKIN_EXIT_SSN
                                && marker(0x00) == 0x12
                            {
                                br_ok |= 0x0040;
                            }
                        } else if parked {
                            let _ = nt_handler.dbgk_release_all_blocked_reporters();
                        }
                    }

                    // ── 0x0004 — ★ DETACH CLEARS `PEB->BeingDebugged` in the LIVE PEB page.
                    let marks_before_detach = DBGK_PEB_MARKS.load(Ordering::Relaxed);
                    let detached = sysc!(SSN_NT_REMOVE_PROCESS_DEBUG, &[h_target, dbg_handle]) == 0;
                    if detached
                        && peb_being_debugged() == 0
                        && DBGK_PEB_MARKS.load(Ordering::Relaxed) == marks_before_detach + 1
                        && !nt_handler.pm.is_process_being_debugged(target)
                    {
                        br_ok |= 0x0004;
                    }
                    let _ = sysc!(SSN_NT_CLOSE, &[dbg_handle, 0, 0, 0]);
                    // Reclaim: suspend the remote thread, then drop every throwaway cap. Keep
                    // `target_pml4` out of the recycle path for now because its skeleton mappings are
                    // not tracked in this local slot list; all other slots here are local aliases,
                    // replies, endpoints, or throwaway frames.
                    let brk_tcb = nt_handler
                        .hosted_thread_tcb_for_role(
                            BRK_TEST_PI,
                            HostedThreadRole::TpWorker {
                                slot: breakin_runtime_slot,
                            },
                        )
                        .unwrap_or(0);
                    if brk_tcb > 1 {
                        let _ = tcb_suspend_r(brk_tcb);
                    }
                }
            }
            print_str(b"[ntos-exec] dbgk remote-breakin selftest bits=0x");
            print_hex(br_ok as u32);
            print_str(b" peb-marks=");
            print_u64(DBGK_PEB_MARKS.load(Ordering::Relaxed));
            print_str(b" remote-created=");
            print_u64(PM_REMOTE_THREADS_CREATED.load(Ordering::Relaxed));
            print_str(b" remote-spawned=");
            print_u64(PM_REMOTE_THREADS_SPAWNED.load(Ordering::Relaxed));
            print_str(b" marker=0x");
            print_hex(if mark_win_ok {
                core::ptr::read_volatile(mark_win as *const u64) as u32
            } else {
                0xFFFF_FFFF
            });
            print_str(b"\n");
            for i in (0..nslots).rev() {
                let s = slots[i];
                if s != 0 && s != target_pml4 {
                    let _ = cnode_delete_recycle_r(s);
                }
            }
            if spawned_breakin_tid != 0 {
                breakin_runtime_tid = spawned_breakin_tid;
            }
            if breakin_runtime_tid != 0 {
                let _ = nt_handler.release_hosted_thread_runtime(breakin_runtime_tid);
            }
            nt_handler.clear_temporary_pool_thread_slot(BRK_TEST_PI, 0);
            nt_handler.clear_temporary_process_slot(BRK_TEST_PI);
            PM_INITIAL_THREAD_DONE.fetch_and(!(1u64 << BRK_TEST_PI), Ordering::Relaxed);
            nt_handler.remote_thread_request = None;

            ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
            ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
            ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
            ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
            ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
            ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
            ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
            nt_handler.pi = saved_pi;
            nt_handler.current_tid = saved_tid;
            nt_handler.loop_ctx = saved_ctx;
            nt_handler.wait_park_event = -1;
            nt_handler.wait_deadline_100ns = u64::MAX;
            DBGK_BREAKIN_SELFTEST.store(br_ok, Ordering::Relaxed);
        }

        // Path 1b COUNTED SPEC — process-local dense handle VALUES. Two DISTINCT live EPROCESSes each
        // allocate their first handle and BOTH get the SAME dense value (0x4), yet it refers to a
        // DIFFERENT object in each: proof of per-process handle namespaces (a global value scheme
        // could not hand out 0x4 twice). Runs post-loop on throwaway EPROCESSes (durable allocs are
        // safe — no reset follows), leaving the 3 hosted processes untouched.
        let pa = nt_handler.pm.create_process("hlocal-a.exe", None, None);
        let pb = nt_handler.pm.create_process("hlocal-b.exe", None, None);
        let ha = nt_handler
            .pm
            .insert_handle(pa, nt_process::HandleObject::Opaque(0xA11CE), 0);
        let hb = nt_handler
            .pm
            .insert_handle(pb, nt_process::HandleObject::Opaque(0xB0B), 0);
        let mut hl_ok = 0u64;
        if ha == Ok(4) && hb == Ok(4) {
            hl_ok |= 1; // both processes' FIRST handle is the same dense value 0x4
        }
        if nt_handler.pm.lookup_handle(pa, 4) == Some(nt_process::HandleObject::Opaque(0xA11CE))
            && nt_handler.pm.lookup_handle(pb, 4) == Some(nt_process::HandleObject::Opaque(0xB0B))
        {
            hl_ok |= 2; // the SAME value 0x4 resolves to a DIFFERENT object in each namespace
        }
        if nt_handler.pm.lookup_handle(pa, 4) != nt_handler.pm.lookup_handle(pb, 4) {
            hl_ok |= 4; // no cross-process aliasing
        }
        PM_HANDLE_LOCAL_OK.store(hl_ok, Ordering::Relaxed);

        // ITEM 2b — prove the seL4 MECHANISM-teardown (reclamation) on a THROWAWAY untyped/caps.
        // Runs here (post-loop, live boot only) alongside the other lifecycle self-tests; it touches
        // ONLY freshly-retyped throwaway caps + an unused scratch page, deletes everything it makes,
        // and never touches the 3 hosted processes' resources → byte-identical boot.
        PM_RECLAIM_OK.store(reclaim_mechanism_selftest(), Ordering::Relaxed);
        // ALPC last-mile item (b) — prove a REAL cross-address-space ALPC section view: two SEPARATE
        // throwaway endpoint VSpaces map the same port-section backing frames (copy_cap + page_map,
        // the CSRSS_ANON_BASE machinery), a hosted thread in one writes big data, a hosted thread in
        // the other reads it back through ITS OWN view mapping. Throwaway-only + reclaimed after →
        // the 3 live hosted processes are untouched (byte-identical boot).
        ALPC_XVIEW_OK.store(alpc_cross_vspace_selftest(), Ordering::Relaxed);
    }
    if csrss_process_handle != 0 {
        print_str(b"[sec-stop] csrss (badge 2) spawned, handle 0x");
        print_hex(csrss_process_handle as u32);
        print_str(b"; demand-paged ");
        print_u64(procs[csrss_pi].faults);
        print_str(b" page(s) (");
        print_u64(procs[csrss_pi].ntfaults);
        print_str(b" in ntdll), first fault=0x");
        print_hex((procs[csrss_pi].first >> 32) as u32);
        print_hex(procs[csrss_pi].first as u32);
        print_str(b"\n");
    }
    print_str(b"[sec-stop] NEXT_SLOT=");
    print_u64(NEXT_SLOT.load(Ordering::Relaxed));
    print_str(b" shared_frames=");
    print_u64(core::ptr::read(core::ptr::addr_of!(DLL_CACHE_N)) as u64);
    print_str(b" shared_hits=");
    print_u64(DLL_SHARED_HITS.load(Ordering::Relaxed));
    print_str(b"\n[sec-stop] badge=");
    print_u64(badge);
    print_str(b" (");
    print_str(hosted_leaf_for_fault_badge(&nt_handler, badge).unwrap_or(b"unknown"));
    print_str(b") label=");
    print_u64(mi >> 12);
    print_str(b" m0=0x");
    print_hex((m0 >> 32) as u32);
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex((m1 >> 32) as u32);
    print_hex(m1 as u32);
    print_str(b" exc#=");
    print_u64(m3);
    print_str(b" code=0x");
    print_hex(get_recv_mr(4) as u32);
    print_str(b" iters=");
    print_u64(iters);
    print_str(b" dbgsvc=");
    print_u64(dbgsvc);
    print_str(b" stop_ssn=");
    print_u64(stop_ssn);
    // Dump the last serviced SSNs in chronological order (oldest first).
    print_str(b" ssns:");
    let ring_n = if ssn_ri < 32 { 0 } else { ssn_ri - 32 };
    for k in ring_n..ssn_ri {
        print_str(b" ");
        print_u64(ssn_ring_badge[k % 32] as u64);
        print_str(b":");
        print_u64(ssn_ring[k % 32] as u64);
    }
    // winlogon-main-only SSN sequence (badge 4), oldest first — isolates the StartLsass wall.
    print_str(b"\n[wl-ring]");
    let wl_n = if wl_ri < 48 { 0 } else { wl_ri - 48 };
    for k in wl_n..wl_ri {
        print_str(b" ");
        print_u64(wl_ring[k % 48] as u64);
    }
    // NtWriteVirtualMemory(287) diagnostic: dump the args + scan the caller's stack for smss/ntdll
    // return addresses to identify which routine issued it (RtlCreateUserProcess param-inject?).
    if stop_ssn == 287 {
        let sp = get_recv_mr(16);
        print_str(b"\n[287] proc=0x");
        print_hex(get_recv_mr(9) as u32); // R10 ProcessHandle
        print_str(b" base=0x");
        print_hex((m3 >> 32) as u32);
        print_hex(m3 as u32); // RDX BaseAddress
        print_str(b" buf=0x");
        print_hex((get_recv_mr(7) >> 32) as u32);
        print_hex(get_recv_mr(7) as u32); // R8 Buffer
        print_str(b" size=0x");
        print_hex(get_recv_mr(8) as u32); // R9 Size
        print_str(b" written*=0x");
        print_hex(smss_stack_read(sp + 0x28) as u32);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= PE_LOAD_BASE && v < PE_LOAD_BASE + 0x40000 {
                // smss image
                print_str(b" s+0x");
                print_hex((v - PE_LOAD_BASE) as u32);
                shown += 1;
            }
            if shown >= 16 {
                break;
            }
        }
    }
    // NtRaiseHardError(190): decode the status (R10), Parameters[0], and the caller ([rsp]).
    // Guarded to this case — get_recv_mr(16)/(8) only hold a valid smss stack ptr here.
    if stop_ssn == 190 {
        print_str(b" r10=0x");
        print_hex((get_recv_mr(9) >> 32) as u32);
        print_hex(get_recv_mr(9) as u32);
        print_str(b" param0=0x");
        print_hex(smss_stack_read(get_recv_mr(8)) as u32);
        print_str(b" caller=0x");
        print_hex(smss_stack_read(get_recv_mr(16)) as u32);
        // Scan the stack for ntdll AND kernel32 return addresses to reconstruct the call chain that
        // produced the failure status (winlogon's CreateProcessW hard-error path is kernel32 code).
        let sp = get_recv_mr(16);
        print_str(b" chain:");
        let mut shown = 0;
        for i in 0..160u64 {
            let v = smss_stack_read(sp + i * 8);
            if v >= NTDLL_BASE && v < NTDLL_BASE + 0xf4000 {
                print_str(b" n+0x");
                print_hex((v - NTDLL_BASE) as u32);
                shown += 1;
            } else if v >= 0x803a0000 && v < 0x803a0000 + 0x2b0000 {
                print_str(b" k32+0x");
                print_hex((v - 0x803a0000) as u32);
                shown += 1;
            }
            if shown >= 20 {
                break;
            }
        }
    }
    print_str(b"\n");
    if ntdll.is_some() {
        loader_trace_dump(&reg);
    }
    if let Some(winlogon_pi) = live_hosted_pi_for_leaf(&nt_handler, b"winlogon.exe") {
        WINLOGON_FAULTS.store(procs[winlogon_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] winlogon (pi ");
        print_u64(winlogon_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[winlogon_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[winlogon_pi].first >> 32) as u32);
        print_hex(procs[winlogon_pi].first as u32);
        print_str(b"\n");
    } else {
        WINLOGON_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(services_pi) = live_hosted_pi_for_leaf(&nt_handler, b"services.exe") {
        SERVICES_FAULTS.store(procs[services_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] services (pi ");
        print_u64(services_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[services_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[services_pi].first >> 32) as u32);
        print_hex(procs[services_pi].first as u32);
        print_str(b"\n");
    } else {
        SERVICES_FAULTS.store(0, Ordering::Relaxed);
    }
    if let Some(lsass_pi) = live_hosted_pi_for_leaf(&nt_handler, b"lsass.exe") {
        LSASS_FAULTS.store(procs[lsass_pi].faults, Ordering::Relaxed);
        print_str(b"[ntos-exec] lsass (pi ");
        print_u64(lsass_pi as u64);
        print_str(b") demand-faulted ");
        print_u64(procs[lsass_pi].faults);
        print_str(b" page(s), first=0x");
        print_hex((procs[lsass_pi].first >> 32) as u32);
        print_hex(procs[lsass_pi].first as u32);
        print_str(b"\n");
    } else {
        LSASS_FAULTS.store(0, Ordering::Relaxed);
    }
    // Path 3: record that each folded per-process ProcExec is EPROCESS-linked (live pml4 + its pid
    // matches the ProcessManager's pid for that pi). Read by `exec_eprocess_linked_mechanism`.
    let mut link_ok = 0u64;
    for (i, p) in procs.iter().enumerate() {
        if p.pml4 != 0
            && p.pid != 0
            && nt_handler.pm_pid_for_pi(i).map(|pid| pid as u64) == Some(p.pid)
        {
            link_ok |= 1 << i;
        }
    }
    PM_EXEC_LINK_OK.store(link_ok, Ordering::Relaxed);
    // Report smss's (slot 0) own fault stats regardless of which process stopped the loop — csrss
    // (slot 1) commonly halts it now that it runs, and the caller's "smss faulted N" line + the
    // exec_reactos_smss_* checks are about smss specifically. csrss's counts are in the sec-stop line.
    (
        verdict,
        procs[0].faults,
        procs[0].first,
        stop,
        procs[0].ntfaults,
        stop_ssn,
    )
}

#[inline(never)]
unsafe fn spawn_requested_multiplexed_thread(
    nt_handler: &mut ExecNtHandler,
    spec: HostedThreadSpawnSpec,
    procs: &[ProcExec; MAX_PI],
    caller_sp: u64,
    fault_ep: u64,
) {
    let (owner_pi, cid_proc, pml4) = live_process_context(nt_handler, procs, spec.owner_leaf)
        .expect("hosted EPROCESS missing before multiplexed thread spawn");
    let Some(tid) = nt_handler.hosted_thread_tid_for_role(owner_pi, spec.role) else {
        print_str(b"[thread-life] missing reserved runtime role before spawn\n");
        return;
    };

    let (_ctx_va, start) = requested_thread_start(caller_sp);
    let suspended = hosted_thread_suspended(nt_handler, tid);
    let resume = match spec.resume {
        HostedThreadResumeMode::PoolState => !suspended,
        HostedThreadResumeMode::Always => true,
    };

    print_str(spec.spawn_prefix);
    print_hex((start.rip >> 32) as u32);
    print_hex(start.rip as u32);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b"\n");

    let tcb = match spec.spawner {
        HostedMultiplexedThreadSpawner::ServicesListener => spawn_svc_listener_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
        HostedMultiplexedThreadSpawner::ScmWorker => spawn_scm_worker_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
        HostedMultiplexedThreadSpawner::LsassListener => spawn_lsass_listener_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
        HostedMultiplexedThreadSpawner::LsassListener2 => spawn_lsass_listener2_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
        HostedMultiplexedThreadSpawner::LsassListener3 => spawn_lsass_listener3_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
        HostedMultiplexedThreadSpawner::LsaWorker => spawn_lsa_worker_thread(
            pml4, start.rip, start.rcx, start.rdx, cid_proc, tid, fault_ep, resume,
        ),
    };

    nt_handler.register_hosted_thread_tcb(owner_pi, tid, tcb, spec.badge, spec.role);
    nt_handler
        .pm
        .set_thread_teb(tid as nt_process::ThreadId, spec.teb);

    print_str(spec.spawned_prefix);
    print_hex(tcb as u32);
    print_str(spec.spawned_suffix);
}

#[inline(never)]
unsafe fn requested_thread_start(caller_sp: u64) -> (u64, nt_thread_start::Amd64ThreadContext) {
    let context_va = smss_stack_read(caller_sp + 0x30);
    (
        context_va,
        nt_thread_start::Amd64ThreadContext::read(
            |address| unsafe { smss_stack_read(address) },
            context_va,
        ),
    )
}

#[inline]
fn hosted_thread_suspended(nt_handler: &ExecNtHandler, tid: u64) -> bool {
    nt_handler
        .pm_pool_slot_for_tid(tid)
        .is_some_and(|(pi, slot)| nt_handler.is_pool_thread_suspended(pi, slot))
}

#[inline]
fn winlogon_callback_thread_candidate(
    nt_handler: &ExecNtHandler,
) -> Option<win32k_glue::WinlogonCallbackThread> {
    let candidates = [
        (
            HostedThreadRole::WinlogonWorker { slot: 1 },
            WL_WORKER2_TEB_VA,
            WL_WORKER2_STACK_BASE + WL_WORKER2_STACK_FRAMES * 0x1000,
        ),
        (
            HostedThreadRole::WinlogonListener,
            WL_LISTENER_TEB_VA,
            WL_LISTENER_STACK_BASE + WL_LISTENER_STACK_FRAMES * 0x1000,
        ),
    ];
    for (role, teb, stack_top) in candidates {
        if let Some((tid, tcb, badge)) = nt_handler.hosted_thread_identity_for_role(2, role) {
            return Some(win32k_glue::WinlogonCallbackThread {
                badge,
                tid,
                tcb,
                role,
                teb,
                stack_top,
            });
        }
    }
    None
}

#[inline]
fn live_process_context(
    nt_handler: &ExecNtHandler,
    procs: &[ProcExec; MAX_PI],
    leaf: &[u8],
) -> Option<(usize, u64, u64)> {
    let pi = live_hosted_pi_for_leaf(nt_handler, leaf)?;
    Some((
        pi,
        nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64,
        procs[pi].pml4,
    ))
}

#[inline(never)]
unsafe fn spawn_requested_local_thread(
    nt_handler: &mut ExecNtHandler,
    request: HostedThreadSpawnRequest,
    procs: &[ProcExec; MAX_PI],
    current_pml4: u64,
    caller_sp: u64,
    fault_ep: u64,
) {
    if let Some(spec) = hosted_multiplexed_thread_spawn_for(request) {
        spawn_requested_multiplexed_thread(nt_handler, spec, procs, caller_sp, fault_ep);
        return;
    }

    match request {
        HostedThreadSpawnRequest::SmLoop => {
            let Some(tid) = nt_handler.hosted_thread_tid_for_role(0, HostedThreadRole::SmLoop)
            else {
                print_str(b"[sm-loop] missing reserved runtime role before spawn\n");
                return;
            };
            let (ctx_va, start) = requested_thread_start(caller_sp);
            print_str(b"[sm-loop] spawning REAL SmpApiLoop thread: ctx=0x");
            print_hex((ctx_va >> 32) as u32);
            print_hex(ctx_va as u32);
            print_str(b" entry=0x");
            print_hex((start.rip >> 32) as u32);
            print_hex(start.rip as u32);
            print_str(b" port=0x");
            print_hex((start.rcx >> 32) as u32);
            print_hex(start.rcx as u32);
            print_str(b"\n");
            let cid_proc = nt_handler.pm_pid_for_pi(0).unwrap_or(0) as u64;
            let pml4 = if procs[0].pml4 != 0 {
                procs[0].pml4
            } else {
                current_pml4
            };
            let tcb = spawn_sm_loop_thread(pml4, start.rip, start.rcx, cid_proc, tid);
            nt_handler.register_hosted_thread_tcb(
                0,
                tid,
                tcb,
                hosted_top_badge_for_pi(nt_handler, 0),
                HostedThreadRole::SmLoop,
            );
            print_str(b"[sm-loop] spawned tcb=0x");
            print_hex(tcb as u32);
            print_str(b" (parks on its first fault to sm_fault_ep)\n");
        }
        HostedThreadSpawnRequest::Csr { slot } => {
            let role = match slot {
                0 => HostedThreadRole::CsrApi,
                1 => HostedThreadRole::CsrSbApi,
                _ => return,
            };
            let (csrss_pi, pid, pml4) = live_process_context(nt_handler, procs, b"csrss.exe")
                .expect("csrss.exe EPROCESS missing before CSR thread spawn");
            let Some(tid) = nt_handler.hosted_thread_tid_for_role(csrss_pi, role) else {
                print_str(b"[csr-thread] missing reserved runtime role before spawn\n");
                return;
            };
            let (_ctx_va, start) = requested_thread_start(caller_sp);
            if slot == 0 {
                print_str(b"[csr-loop] spawning REAL CsrApiRequestThread: entry=0x");
            } else {
                print_str(b"[csr-sb] spawning REAL CsrSbApiRequestThread: entry=0x");
            }
            print_hex((start.rip >> 32) as u32);
            print_hex(start.rip as u32);
            if slot == 0 {
                print_str(b" param=0x");
                print_hex(start.rcx as u32);
            } else {
                print_str(b" tid=");
                print_u64(tid);
            }
            print_str(b"\n");
            let tcb = if slot == 0 {
                spawn_csr_loop_thread(pml4, start.rip, start.rcx, pid, tid)
            } else {
                spawn_csr_sb_loop_thread(pml4, start.rip, start.rcx, pid, tid)
            };
            nt_handler.register_hosted_thread_tcb(
                csrss_pi,
                tid,
                tcb,
                hosted_top_badge_for_pi(nt_handler, csrss_pi),
                role,
            );
            if slot == 0 {
                print_str(b"[csr-loop] spawned tcb=0x");
                print_hex(tcb as u32);
                print_str(b" (parks on its first fault to csr_fault_ep)\n");
            }
        }
        HostedThreadSpawnRequest::Winlogon { slot } => {
            let (role, badge, teb) = match slot {
                0 => (
                    HostedThreadRole::WinlogonListener,
                    WINLOGON_WORKER_BADGE,
                    WL_LISTENER_TEB_VA,
                ),
                1 => (
                    HostedThreadRole::WinlogonWorker { slot },
                    WINLOGON_WORKER2_BADGE,
                    WL_WORKER2_TEB_VA,
                ),
                2 => (
                    HostedThreadRole::WinlogonWorker { slot },
                    WINLOGON_WORKER3_BADGE,
                    WL_WORKER3_TEB_VA,
                ),
                _ => return,
            };
            let (wl_pi, cid_proc, pml4) = live_process_context(nt_handler, procs, b"winlogon.exe")
                .expect("winlogon.exe EPROCESS missing before worker spawn");
            let Some(tid) = nt_handler.hosted_thread_tid_for_role(wl_pi, role) else {
                print_str(b"[wl-thread] missing reserved runtime role before spawn\n");
                return;
            };
            let (_ctx_va, start) = requested_thread_start(caller_sp);
            let initial_teb_va = smss_stack_read(caller_sp + 0x38);
            let initial_teb = nt_thread_start::InitialTeb64::read(
                |address| unsafe { smss_stack_read(address) },
                initial_teb_va,
            );
            print_str(b"[wl-thread] spawning REAL worker slot=");
            print_u64(slot as u64);
            print_str(b" (multiplexed): entry=0x");
            print_hex((start.rip >> 32) as u32);
            print_hex(start.rip as u32);
            print_str(b" arg0=0x");
            print_hex((start.rcx >> 32) as u32);
            print_hex(start.rcx as u32);
            print_str(b" arg1=0x");
            print_hex((start.rdx >> 32) as u32);
            print_hex(start.rdx as u32);
            print_str(b" tid=");
            print_u64(tid);
            print_str(b"\n");
            let suspended = nt_handler.is_pool_thread_suspended(wl_pi, slot);
            let tcb = spawn_wl_listener_thread(
                slot,
                pml4,
                start,
                initial_teb,
                cid_proc,
                tid,
                fault_ep,
                false,
            );
            let teb_alias = match slot {
                0 => WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000,
                1 => WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000,
                2 => WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000,
                _ => 0,
            };
            if seed_winlogon_thread_client_info(teb_alias, pml4).is_none() {
                print_str(b"[wl-thread] win32 client state not published before worker spawn\n");
            }
            if slot == 0 {
                let mapped_low = initial_teb
                    .stack_limit
                    .checked_sub(nt_thread_start::USER_PAGE_SIZE)
                    .filter(|&low| {
                        initial_teb.allocated_stack_base & 0xfff == 0
                            && initial_teb.stack_base & 0xfff == 0
                            && initial_teb.allocated_stack_base <= low
                            && low < initial_teb.stack_base
                            && csrss_frame_get_exact(wl_pi as u64, low).0 != 0
                    })
                    .unwrap_or(0);
                if mapped_low != 0 {
                    WL_LISTENER_STACK_ALLOCATION_BASE
                        .store(initial_teb.allocated_stack_base, Ordering::Release);
                    WL_LISTENER_STACK_BASE_REAL.store(initial_teb.stack_base, Ordering::Release);
                    WL_LISTENER_STACK_MAPPED_LOW.store(mapped_low, Ordering::Release);
                } else {
                    WL_LISTENER_STACK_ALLOCATION_BASE.store(0, Ordering::Release);
                    WL_LISTENER_STACK_BASE_REAL.store(0, Ordering::Release);
                    WL_LISTENER_STACK_MAPPED_LOW.store(0, Ordering::Release);
                    print_str(b"[wl-thread] real stack reservation could not be armed\n");
                }
            }
            nt_handler.register_hosted_thread_tcb(wl_pi, tid, tcb, badge, role);
            if slot == 0 {
                WL_LISTENER_THREAD_MINTED.store(1, Ordering::Relaxed);
            }
            nt_handler
                .pm
                .set_thread_teb(tid as nt_process::ThreadId, teb);
            if !suspended {
                let _ = tcb_resume(tcb);
            }
            print_str(b"[wl-thread] spawned tcb=0x");
            print_hex(tcb as u32);
            print_str(b" TEB=0x");
            print_hex((teb >> 32) as u32);
            print_hex(teb as u32);
            print_str(if suspended {
                b" (SUSPENDED; NtResumeThread owns first run; real ETHREAD + TEB)\n"
            } else {
                b" (RESUMED into multiplex; real ETHREAD + TEB)\n"
            });
        }
        HostedThreadSpawnRequest::TpWorker { pi, slot } => {
            if pi < TP_WORKER_PI_COUNT && slot < TP_WORKER_SLOT_COUNT {
                spawn_requested_tp_worker(
                    nt_handler,
                    pi,
                    slot,
                    procs[pi].pml4,
                    caller_sp,
                    fault_ep,
                );
            }
        }
        _ => {}
    }
}

#[inline(never)]
unsafe fn spawn_requested_tp_worker(
    nt_handler: &mut ExecNtHandler,
    pi: usize,
    worker_slot: usize,
    pml4: u64,
    caller_sp: u64,
    fault_ep: u64,
) {
    let role = HostedThreadRole::TpWorker { slot: worker_slot };
    if nt_handler.hosted_thread_tcb_for_role(pi, role).is_some() {
        return;
    }

    let context_va = smss_stack_read(caller_sp + 0x30);
    let start = nt_thread_start::Amd64ThreadContext::read(
        |address| unsafe { smss_stack_read(address) },
        context_va,
    );
    let Some(tid) = nt_handler.hosted_thread_tid_for_role(pi, role) else {
        return;
    };
    let cid_proc = nt_handler.pm_pid_for_pi(pi).unwrap_or(0) as u64;
    let suspended = nt_handler
        .pm_pool_slot_for_tid(tid)
        .is_some_and(|(pool_pi, slot)| {
            pool_pi == pi && nt_handler.is_pool_thread_suspended(pool_pi, slot)
        });
    let tcb = spawn_tp_worker_thread(
        pi,
        worker_slot,
        pml4,
        start,
        cid_proc,
        tid,
        fault_ep,
        !suspended,
    );
    nt_handler.register_hosted_thread_tcb(pi, tid, tcb, tp_worker_badge(pi, worker_slot), role);
    nt_handler
        .pm
        .set_thread_teb(tid as nt_process::ThreadId, tp_worker_teb_va(worker_slot));

    print_str(b"[tp-worker] spawned pi=");
    print_u64(pi as u64);
    print_str(b" badge=");
    print_u64(tp_worker_badge(pi, worker_slot));
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    if worker_slot != 0 {
        print_str(b" slot=");
        print_u64(worker_slot as u64);
    }
    print_str(if suspended {
        b" suspended; NtResumeThread owns first run\n"
    } else {
        b" resumed into generic multiplex\n"
    });
}

/// ★ Build the seL4 thread for a pending cross-VSpace `NtCreateThread`: the MECHANISM half of
/// `create_remote_thread`. The new thread's faults/syscalls arrive on the MAIN service endpoint
/// badged with its `(target pi, slot)` identity, so the loop's existing N-threads multiplex
/// (`tp_worker_identity_from_badge` → `mirror_ctx_for`) sub-selects it exactly like any other extra
/// thread of that process — a remote thread is not a special kind of thread once it exists.
///
/// A target index outside the live range has no place in that multiplex; such a request only comes
/// from a post-loop self-test, which supplies its own endpoint and services the thread itself.
pub(crate) unsafe fn spawn_requested_remote_thread(
    nt_handler: &mut ExecNtHandler,
    request: &RemoteThreadRequest,
    fault_ep: u64,
) -> u64 {
    if request.target_pi >= TP_WORKER_PI_COUNT {
        return 0;
    }
    let badged = mint_badged(fault_ep, tp_worker_badge(request.target_pi, request.slot));
    let tcb = rendezvous::spawn_slot_thread(&rendezvous::RemoteThreadSpawn {
        target_pi: request.target_pi,
        slot: request.slot,
        pml4: request.pml4,
        start: request.start,
        cid_proc: request.cid_proc,
        cid_thread: request.cid_thread,
        fault_ep: badged,
        use_loader: true,
        native: true,
        resume: request.resume,
    });
    if tcb != 0 {
        nt_handler.register_hosted_thread_tcb(
            request.target_pi,
            request.cid_thread,
            tcb,
            tp_worker_badge(request.target_pi, request.slot),
            HostedThreadRole::TpWorker { slot: request.slot },
        );
        PM_REMOTE_THREADS_SPAWNED.fetch_add(1, Ordering::Relaxed);
    }
    print_str(b"[remote-thread] spawned target_pi=");
    print_u64(request.target_pi as u64);
    print_str(b" slot=");
    print_u64(request.slot as u64);
    print_str(b" tid=");
    print_u64(request.cid_thread);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b"\n");
    tcb
}

/// The active memory context for the thread identified by `badge`: stack base/size/mirror, process
/// heap/image mirrors, and its demand scratch window. This is the same selection the main service
/// loop makes. Parked-I/O delivery temporarily switches to the parked thread's context.
#[inline]
fn mirror_ctx_for(badge: u64, pi: usize) -> (u64, u64, u64, u64, u64, u64) {
    let (stack_base, stack_frames, stack_mirror) =
        if let Some((tp_pi, tp_slot)) = tp_worker_identity_from_badge(badge) {
            debug_assert_eq!(tp_pi, pi);
            (
                tp_worker_stack_base(tp_slot),
                TP_WORKER_STACK_FRAMES,
                tp_worker_stack_mirror_va(tp_pi, tp_slot),
            )
        } else {
            match badge {
                SVC_LISTENER_BADGE => (
                    SVC_LISTENER_STACK_BASE,
                    SVC_LISTENER_STACK_FRAMES,
                    SVC_LISTENER_STACK_MIRROR_VA,
                ),
                SCM_WORKER_BADGE => (
                    SCM_WORKER_STACK_BASE,
                    SCM_WORKER_STACK_FRAMES,
                    SCM_WORKER_STACK_MIRROR_VA,
                ),
                LSASS_LISTENER_BADGE => (
                    LSASS_LISTENER_STACK_BASE,
                    LSASS_LISTENER_STACK_FRAMES,
                    LSASS_LISTENER_STACK_MIRROR_VA,
                ),
                LSASS_LISTENER2_BADGE => (
                    LSASS_LISTENER2_STACK_BASE,
                    LSASS_LISTENER2_STACK_FRAMES,
                    LSASS_LISTENER2_STACK_MIRROR_VA,
                ),
                LSASS_LISTENER3_BADGE => (
                    LSASS_LISTENER3_STACK_BASE,
                    LSASS_LISTENER3_STACK_FRAMES,
                    LSASS_LISTENER3_STACK_MIRROR_VA,
                ),
                LSA_WORKER_BADGE => (
                    LSA_WORKER_STACK_BASE,
                    LSA_WORKER_STACK_FRAMES,
                    LSA_WORKER_STACK_MIRROR_VA,
                ),
                WINLOGON_WORKER2_BADGE => (
                    WL_WORKER2_STACK_BASE,
                    WL_WORKER2_STACK_FRAMES,
                    WINLOGON_WORKER2_STACK_MIRROR_VA,
                ),
                WINLOGON_WORKER3_BADGE => (
                    WL_WORKER3_STACK_BASE,
                    WL_WORKER3_STACK_FRAMES,
                    WINLOGON_WORKER3_STACK_MIRROR_VA,
                ),
                WINLOGON_WORKER_BADGE => (
                    WL_LISTENER_STACK_BASE,
                    WL_LISTENER_STACK_FRAMES,
                    WINLOGON_WORKER_STACK_MIRROR_VA,
                ),
                _ => {
                    // A top-level process MAIN thread — keyed by pi like the loop's default arm.
                    (
                        STACK_BASE,
                        STACK_FRAMES,
                        hosted_main_stack_mirror_for_pi(pi),
                    )
                }
            }
        };
    let heap_mirror = hosted_heap_mirror_for_pi(pi);
    let image_mirror = hosted_active_image_mirror_for_pi(pi);
    let scratch_base = hosted_scratch_base_for_pi(pi);
    (
        stack_base,
        stack_frames * 0x1000,
        stack_mirror,
        heap_mirror,
        image_mirror,
        scratch_base,
    )
}

unsafe fn io_completion_park(
    nt_handler: &mut ExecNtHandler,
    port_id: u32,
    key_context_out: u64,
    apc_context_out: u64,
    io_status_block_out: u64,
    deadline_100ns: u64,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let Some((fresh_index, fresh)) = (0..WAIT_REPLY_POOL_N).find_map(|index| {
        let cap = WAIT_REPLY_POOL[index].load(Ordering::Relaxed);
        (used & (1u64 << index) == 0 && cap != 0).then_some((index, cap))
    }) else {
        return false;
    };
    if nt_handler.io_completion_ports.retain(port_id).is_err() {
        return false;
    }
    let mut waiter = nt_io_completion::CompletionWaiter::default();
    waiter.port_id = port_id;
    waiter.process_index = nt_handler.pi as u8;
    waiter.reply_cap = stolen;
    waiter.resume_ip = resume_ip;
    waiter.resume_sp = sp;
    waiter.resume_flags = flags;
    waiter.thread_id = nt_handler.current_tid;
    waiter.badge = nt_handler.current_badge;
    waiter.key_context_out = key_context_out;
    waiter.apc_context_out = apc_context_out;
    waiter.io_status_block_out = io_status_block_out;
    waiter.deadline_100ns = deadline_100ns;
    if unsafe { (&mut *core::ptr::addr_of_mut!(IO_COMPLETION_WAITERS)).insert(waiter) }.is_err() {
        let _ = nt_handler.io_completion_ports.release(port_id);
        return false;
    }
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_index, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    IO_COMPLETION_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

unsafe fn io_completion_deliver(nt_handler: &mut ExecNtHandler) -> bool {
    let Some((waiter, packet)) = nt_handler.io_completion_wake.take() else {
        return false;
    };
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
    let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take();

    let (stack_base, stack_size, stack_mirror, heap_mirror, image_mirror, scratch_base) =
        mirror_ctx_for(waiter.badge, waiter.process_index as usize);
    ACTIVE_STACK_BASE.store(stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(image_mirror, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(waiter.process_index as u64, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(scratch_base, Ordering::Relaxed);
    nt_handler.pi = waiter.process_index as usize;

    let copied = nt_handler
        .xas_try_write_buf(waiter.apc_context_out, &packet.apc_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.key_context_out, &packet.key_context.to_le_bytes())
        && nt_handler.xas_try_write_buf(waiter.io_status_block_out, &packet.status.to_le_bytes())
        && nt_handler.xas_try_write_buf(
            waiter.io_status_block_out + 8,
            &packet.information.to_le_bytes(),
        );

    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;

    set_reply_mr(15, waiter.resume_ip);
    set_reply_mr(16, waiter.resume_sp);
    set_reply_mr(17, waiter.resume_flags);
    client_reply_on(
        waiter.reply_cap,
        18,
        if copied { 0 } else { 0xC000_0005 },
        0,
        0,
        0,
    );
    release_reply_pool_cap(waiter.reply_cap);
    let _ = nt_handler.io_completion_ports.release(waiter.port_id);
    IO_COMPLETION_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

// ═══ `\LsaAuthenticationPort` RENDEZVOUS — loop-side machinery ═══════════════════════════════════
//
// The x64 `PORT_MESSAGE` header lsass' `LSA_API_MSG` starts with:
//   +0x00 u1.s1.DataLength (u16) / u1.s1.TotalLength (u16)
//   +0x04 u2.s2.Type (u16) / u2.s2.DataInfoOffset (u16)
//   +0x08 ClientId.UniqueProcess (u64)   +0x10 ClientId.UniqueThread (u64)
//   +0x18 MessageId (u32)                +0x20 ClientViewSize (u64)
//   +0x28 the payload union (`LSA_CONNECTION_INFO` on a connect, `ApiNumber`/`Status`/… otherwise)
const LSA_PORT_MESSAGE_HEADER: u64 = 0x28;
/// `sizeof(LSA_CONNECTION_INFO)` on x64: Status(4) + OperationalMode(4) + Length(4) +
/// LogonProcessNameBuffer[128] + CreateContext(4) + TrustedCaller(4)
/// (`references/reactos/sdk/include/reactos/subsys/lsass/lsass.h:37`).
const LSA_CONNECTION_INFO_SIZE: usize = 4 + 4 + 4 + 128 + 4 + 4;
/// Upper bound on the bytes we relay for one `LSA_API_MSG` (header + the largest payload union). The
/// actual count always comes from the message's own `TotalLength`, clamped to this.
const LSA_API_MSG_MAX: usize = 0x200;
/// `LPC_CONNECTION_REQUEST` (10) / `LPC_REQUEST` (1) — the NT `LPC_TYPE` values `AuthPortThreadRoutine`
/// switches on (`references/reactos/sdk/include/ndk/lpctypes.h`); `nt_lpc_abi::msg_type` mirrors them.
const LSA_MSG_TYPE_CONNECTION_REQUEST: u16 = nt_lpc_abi::msg_type::LPC_CONNECTION_REQUEST;
const LSA_MSG_TYPE_REQUEST: u16 = nt_lpc_abi::msg_type::LPC_REQUEST;

/// lsass' REAL `AuthPortThreadRoutine` blocked in `NtReplyWaitReceivePort(AuthPortHandle, …)`.
/// `reply_cap != 0` ⇒ parked; the thread is genuinely blocked in-kernel on the Call that delivered
/// that syscall, exactly like every other executive wait-park.
static LSA_SRV_REPLY_CAP: AtomicU64 = AtomicU64::new(0);
static LSA_SRV_BADGE: AtomicU64 = AtomicU64::new(0);
/// The multiplex badge of the LSA server thread, latched at its FIRST park and never cleared — used
/// to recognise its syscalls while it is RUNNING (diagnostics + the wall-release below).
static LSA_SRV_LIVE_BADGE: AtomicU64 = AtomicU64::new(u64::MAX);
/// Bounded SSN trace for the real LSA server thread.
static LSA_SRV_SSN_TRACE: AtomicU64 = AtomicU64::new(0);
/// The SSN the real LSA server walled on while a client was blocked (u64::MAX = never).
pub(crate) static LSA_SERVER_WALL_SSN: AtomicU64 = AtomicU64::new(u64::MAX);
static LSA_SRV_PI: AtomicU64 = AtomicU64::new(4);
/// `R9` — `&RequestMsg` (the server's stack-local `LSA_API_MSG` it receives into).
static LSA_SRV_RECVMSG: AtomicU64 = AtomicU64::new(0);
/// `RDX` — `PVOID *PortContext` (the server reads back the `LSAP_LOGON_CONTEXT` here).
static LSA_SRV_CTXOUT: AtomicU64 = AtomicU64::new(0);
static LSA_SRV_IP: AtomicU64 = AtomicU64::new(0);
static LSA_SRV_SP: AtomicU64 = AtomicU64::new(0);
static LSA_SRV_FLAGS: AtomicU64 = AtomicU64::new(0);

/// The LSA client (winlogon) blocked in `NtConnectPort` (kind 1) or `NtRequestWaitReplyPort` (kind 2)
/// while the real server runs its half of the exchange.
static LSA_CLI_REPLY_CAP: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_KIND: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_BADGE: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_PI: AtomicU64 = AtomicU64::new(2);
/// connect: `*PortHandle` (R10). request: the client's reply `PORT_MESSAGE` buffer (R8).
static LSA_CLI_OUT: AtomicU64 = AtomicU64::new(0);
/// connect only: the client's `ConnectionInformation` buffer + its length (copied back after accept).
static LSA_CLI_CONNINFO: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_CONNINFO_LEN: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_IP: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_SP: AtomicU64 = AtomicU64::new(0);
static LSA_CLI_FLAGS: AtomicU64 = AtomicU64::new(0);

/// Steal the Reply object bound to the caller the loop is currently servicing and rotate a fresh pool
/// object into `REPLY_MAIN_SLOT` — the SAME mechanism `wait_park_multi` / `pipe_wait_park` /
/// `dbgk_reporter_park` use. `None` ⇒ the pool is exhausted (caller must not park).
unsafe fn lsa_steal_main_reply() -> Option<u64> {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return None;
    }
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    for index in 0..WAIT_REPLY_POOL_N {
        if used & (1u64 << index) != 0 {
            continue;
        }
        let cap = WAIT_REPLY_POOL[index].load(Ordering::Relaxed);
        if cap != 0 {
            WAIT_REPLY_POOL_USED.fetch_or(1u64 << index, Ordering::Relaxed);
            REPLY_MAIN_SLOT.store(cap, Ordering::Relaxed);
            return Some(stolen);
        }
    }
    None
}

/// Resume a thread blocked on a stolen reply cap: restore its native-syscall resume context
/// (RCX/RSP/RFLAGS in MR15/16/17) and return `status` in MR0 — the identical shape `pipe_redrive_all`
/// and the event wake use.
unsafe fn lsa_wake(cap: u64, status: u64, ip: u64, sp: u64, flags: u64) {
    set_reply_mr(15, ip);
    set_reply_mr(16, sp);
    set_reply_mr(17, flags);
    client_reply_on(cap, 18, status, 0, 0, 0);
    release_reply_pool_cap(cap);
}

/// Run `body` with the executive's cross-address-space copy context pointed at `badge`/`pi`'s VSpace
/// mirrors, then restore. Mirrors `pipe_redrive_all`'s context switch exactly (including dropping
/// `loop_ctx` so the copy is mirror-only — the target thread's stack/heap are already mapped).
unsafe fn lsa_with_peer<R>(
    nt_handler: &mut ExecNtHandler,
    badge: u64,
    pi: usize,
    body: impl FnOnce(&mut ExecNtHandler) -> R,
) -> R {
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
    let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take();
    let (sb, ss, smv, hmv, imv, scratch_base) = mirror_ctx_for(badge, pi);
    ACTIVE_STACK_BASE.store(sb, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(ss, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(smv, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(hmv, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(imv, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(pi as u64, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(scratch_base, Ordering::Relaxed);
    nt_handler.pi = pi;
    let out = body(nt_handler);
    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    out
}

/// Is lsass' real LSA server thread currently blocked in its `NtReplyWaitReceivePort`?
fn lsa_server_parked() -> bool {
    LSA_SRV_REPLY_CAP.load(Ordering::Relaxed) != 0
}

/// PARK the real LSA server thread on its `NtReplyWaitReceivePort` — the reply capability is RETAINED
/// (not dropped like the generic listener park), so a later client connect/request can genuinely
/// resume it. Returns false if the reply pool is exhausted (caller falls back to the generic park).
#[allow(clippy::too_many_arguments)]
unsafe fn lsa_server_park(
    badge: u64,
    pi: usize,
    recvmsg: u64,
    ctx_out: u64,
    ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let Some(cap) = lsa_steal_main_reply() else {
        return false;
    };
    LSA_SRV_BADGE.store(badge, Ordering::Relaxed);
    LSA_SRV_PI.store(pi as u64, Ordering::Relaxed);
    LSA_SRV_RECVMSG.store(recvmsg, Ordering::Relaxed);
    LSA_SRV_CTXOUT.store(ctx_out, Ordering::Relaxed);
    LSA_SRV_IP.store(ip, Ordering::Relaxed);
    LSA_SRV_SP.store(sp, Ordering::Relaxed);
    LSA_SRV_FLAGS.store(flags, Ordering::Relaxed);
    LSA_SRV_REPLY_CAP.store(cap, Ordering::Relaxed);
    LSA_SRV_LIVE_BADGE.store(badge, Ordering::Relaxed);
    LSA_SERVER_PARKS.fetch_add(1, Ordering::Relaxed);
    true
}

/// The real LSA server thread hit a syscall this executive does not service while a client was
/// blocked on its half of the exchange. Release the client with a real failure (its own error path
/// then runs) instead of leaving it blocked forever, and record the wall for the report.
unsafe fn lsa_release_client_on_server_wall(ssn: u64) -> bool {
    let cap = LSA_CLI_REPLY_CAP.swap(0, Ordering::Relaxed);
    if cap == 0 {
        return false;
    }
    LSA_CLI_KIND.store(0, Ordering::Relaxed);
    LSA_PENDING_CONN.store(0, Ordering::Relaxed);
    LSA_SERVER_WALL_SSN.store(ssn, Ordering::Relaxed);
    print_str(b"[lsa-rdv] WALL: the real LSA server walled on SSN=");
    print_u64(ssn);
    print_str(b" with a client blocked -> releasing the client with STATUS_UNSUCCESSFUL\n");
    lsa_wake(
        cap,
        0xC000_0001,
        LSA_CLI_IP.load(Ordering::Relaxed),
        LSA_CLI_SP.load(Ordering::Relaxed),
        LSA_CLI_FLAGS.load(Ordering::Relaxed),
    );
    true
}

/// Deliver a message into the parked server's `RequestMsg` and RESUME it. `payload` lands at
/// `+0x28`; the `PORT_MESSAGE` header is built here exactly as the NT LPC port would. Returns false
/// if the server is not parked or the marshalling failed (nothing is woken, nothing is faked).
unsafe fn lsa_server_deliver(
    nt_handler: &mut ExecNtHandler,
    msg_type: u16,
    client_pid: u64,
    client_tid: u64,
    payload: &[u8],
    port_context: u64,
) -> bool {
    let cap = LSA_SRV_REPLY_CAP.load(Ordering::Relaxed);
    let recvmsg = LSA_SRV_RECVMSG.load(Ordering::Relaxed);
    if cap == 0 || recvmsg == 0 {
        return false;
    }
    let badge = LSA_SRV_BADGE.load(Ordering::Relaxed);
    let pi = LSA_SRV_PI.load(Ordering::Relaxed) as usize;
    let ctx_out = LSA_SRV_CTXOUT.load(Ordering::Relaxed);
    let mut header = [0u8; LSA_PORT_MESSAGE_HEADER as usize];
    let data_length = payload.len() as u16;
    let total_length = (LSA_PORT_MESSAGE_HEADER as u16).saturating_add(data_length);
    header[0..2].copy_from_slice(&data_length.to_le_bytes());
    header[2..4].copy_from_slice(&total_length.to_le_bytes());
    header[4..6].copy_from_slice(&msg_type.to_le_bytes());
    header[8..16].copy_from_slice(&client_pid.to_le_bytes());
    header[16..24].copy_from_slice(&client_tid.to_le_bytes());
    let ok = lsa_with_peer(nt_handler, badge, pi, |handler| {
        let mut ok = handler.xas_try_write_buf(recvmsg, &header);
        if ok && !payload.is_empty() {
            ok = handler.xas_try_write_buf(recvmsg + LSA_PORT_MESSAGE_HEADER, payload);
        }
        if ok && ctx_out != 0 {
            ok = handler.xas_write_u64(ctx_out, port_context);
        }
        ok
    });
    if !ok {
        print_str(b"[lsa-rdv] WALL: could not marshal the message into the server's RequestMsg\n");
        return false;
    }
    LSA_SRV_REPLY_CAP.store(0, Ordering::Relaxed);
    lsa_wake(
        cap,
        0, // STATUS_SUCCESS from NtReplyWaitReceivePort
        LSA_SRV_IP.load(Ordering::Relaxed),
        LSA_SRV_SP.load(Ordering::Relaxed),
        LSA_SRV_FLAGS.load(Ordering::Relaxed),
    );
    true
}

/// PARK the LSA client (winlogon) blocked on the real server's half of the exchange.
#[allow(clippy::too_many_arguments)]
unsafe fn lsa_client_park(
    kind: u64,
    badge: u64,
    pi: usize,
    out: u64,
    conninfo: u64,
    conninfo_len: u64,
    ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let Some(cap) = lsa_steal_main_reply() else {
        return false;
    };
    LSA_CLI_KIND.store(kind, Ordering::Relaxed);
    LSA_CLI_BADGE.store(badge, Ordering::Relaxed);
    LSA_CLI_PI.store(pi as u64, Ordering::Relaxed);
    LSA_CLI_OUT.store(out, Ordering::Relaxed);
    LSA_CLI_CONNINFO.store(conninfo, Ordering::Relaxed);
    LSA_CLI_CONNINFO_LEN.store(conninfo_len, Ordering::Relaxed);
    LSA_CLI_IP.store(ip, Ordering::Relaxed);
    LSA_CLI_SP.store(sp, Ordering::Relaxed);
    LSA_CLI_FLAGS.store(flags, Ordering::Relaxed);
    LSA_CLI_REPLY_CAP.store(cap, Ordering::Relaxed);
    true
}

/// Finish the CONNECT half: the real server completed (or refused) the connection. Copy the
/// `ConnectInfo` the server itself wrote (`OperationalMode = 0x43218765`, `Status`) back into the
/// connector's buffer, publish the broker's client comm-port handle into its `*PortHandle`, and
/// resume it. Returns true if a client was woken.
unsafe fn lsa_complete_connect(nt_handler: &mut ExecNtHandler, outcome: u64) -> bool {
    let cap = LSA_CLI_REPLY_CAP.load(Ordering::Relaxed);
    if cap == 0 || LSA_CLI_KIND.load(Ordering::Relaxed) != 1 {
        return false;
    }
    let srv_badge = LSA_SRV_BADGE.load(Ordering::Relaxed);
    let srv_pi = LSA_SRV_PI.load(Ordering::Relaxed) as usize;
    let recvmsg = LSA_SRV_RECVMSG.load(Ordering::Relaxed);
    // Read the server's OWN ConnectInfo back out of its message buffer — these are the bytes
    // `LsapHandlePortConnection` wrote, not a fabrication.
    let mut connect_info = [0u8; LSA_CONNECTION_INFO_SIZE];
    let have_info = recvmsg != 0
        && lsa_with_peer(nt_handler, srv_badge, srv_pi, |handler| {
            handler.xas_read(recvmsg + LSA_PORT_MESSAGE_HEADER, &mut connect_info)
        });
    let status = if outcome == 1 {
        u32::from_le_bytes(connect_info[0..4].try_into().unwrap()) as u64
    } else {
        0xC000_0022 // STATUS_ACCESS_DENIED — the real server passed Accept = FALSE
    };
    let operational_mode = u32::from_le_bytes(connect_info[4..8].try_into().unwrap()) as u64;
    let client_handle = LSA_CLIENT_HANDLE.load(Ordering::Relaxed);
    let cli_badge = LSA_CLI_BADGE.load(Ordering::Relaxed);
    let cli_pi = LSA_CLI_PI.load(Ordering::Relaxed) as usize;
    let out = LSA_CLI_OUT.load(Ordering::Relaxed);
    let conninfo = LSA_CLI_CONNINFO.load(Ordering::Relaxed);
    let conninfo_len =
        (LSA_CLI_CONNINFO_LEN.load(Ordering::Relaxed) as usize).min(LSA_CONNECTION_INFO_SIZE);
    lsa_with_peer(nt_handler, cli_badge, cli_pi, |handler| {
        if outcome == 1 && out != 0 && client_handle != 0 {
            let _ = handler.xas_write_u64(out, client_handle);
        }
        if have_info && conninfo != 0 && conninfo_len != 0 {
            handler.xas_write_buf(conninfo, &connect_info[..conninfo_len]);
        }
    });
    if outcome == 1 {
        LSA_CONNECT_COMPLETED.fetch_add(1, Ordering::Relaxed);
        LSA_OPERATIONAL_MODE.store(operational_mode, Ordering::Relaxed);
        if cli_pi == 2 {
            WINLOGON_LSA_PORT_HANDLE.store(client_handle, Ordering::Relaxed);
            WINLOGON_LSA_CONNECTED.store(1, Ordering::Relaxed);
        }
        print_str(b"[lsa-rdv] CONNECT COMPLETE: real LSA server accepted; client port handle=0x");
        print_hex((client_handle >> 32) as u32);
        print_hex(client_handle as u32);
        print_str(b" ConnectInfo.Status=0x");
        print_hex(status as u32);
        print_str(b" OperationalMode=0x");
        print_hex(operational_mode as u32);
        print_str(b"\n");
    } else {
        print_str(b"[lsa-rdv] CONNECT REFUSED by the real LSA server\n");
    }
    LSA_CLI_REPLY_CAP.store(0, Ordering::Relaxed);
    LSA_CLI_KIND.store(0, Ordering::Relaxed);
    LSA_PENDING_CONN.store(0, Ordering::Relaxed);
    lsa_wake(
        cap,
        status,
        LSA_CLI_IP.load(Ordering::Relaxed),
        LSA_CLI_SP.load(Ordering::Relaxed),
        LSA_CLI_FLAGS.load(Ordering::Relaxed),
    );
    true
}

/// Finish the REQUEST half: the server's `NtReplyWaitReceivePort` carried a `ReplyMessage`, so copy
/// that reply out of the server's buffer into the parked client's reply buffer and resume it.
unsafe fn lsa_deliver_reply(nt_handler: &mut ExecNtHandler, replymsg: u64) -> bool {
    let cap = LSA_CLI_REPLY_CAP.load(Ordering::Relaxed);
    if cap == 0 || LSA_CLI_KIND.load(Ordering::Relaxed) != 2 || replymsg == 0 {
        return false;
    }
    let srv_badge = LSA_SRV_BADGE.load(Ordering::Relaxed);
    let srv_pi = LSA_SRV_PI.load(Ordering::Relaxed) as usize;
    let mut buffer = [0u8; LSA_API_MSG_MAX];
    let mut length = 0usize;
    lsa_with_peer(nt_handler, srv_badge, srv_pi, |handler| {
        let mut header = [0u8; LSA_PORT_MESSAGE_HEADER as usize];
        if !handler.xas_read(replymsg, &mut header) {
            return;
        }
        let total = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
        let want = total
            .max(LSA_PORT_MESSAGE_HEADER as usize)
            .min(LSA_API_MSG_MAX);
        if handler.xas_read(replymsg, &mut buffer[..want]) {
            length = want;
        }
    });
    if length == 0 {
        print_str(b"[lsa-rdv] WALL: could not read the server's reply message\n");
        return false;
    }
    let cli_badge = LSA_CLI_BADGE.load(Ordering::Relaxed);
    let cli_pi = LSA_CLI_PI.load(Ordering::Relaxed) as usize;
    let out = LSA_CLI_OUT.load(Ordering::Relaxed);
    lsa_with_peer(nt_handler, cli_badge, cli_pi, |handler| {
        if out != 0 {
            handler.xas_write_buf(out, &buffer[..length]);
        }
    });
    LSA_REPLIES_DELIVERED.fetch_add(1, Ordering::Relaxed);
    // LSA_API_MSG.Status is the u32 right after ApiNumber (payload +0x04).
    let api_status = if length >= LSA_PORT_MESSAGE_HEADER as usize + 8 {
        u32::from_le_bytes(
            buffer[LSA_PORT_MESSAGE_HEADER as usize + 4..LSA_PORT_MESSAGE_HEADER as usize + 8]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };
    match LSA_LAST_API_NUMBER.load(Ordering::Relaxed) {
        2 => LSA_LOGON_REPLY_STATUS.store(api_status as u64, Ordering::Relaxed),
        3 => LSA_LOOKUP_REPLY_STATUS.store(api_status as u64, Ordering::Relaxed),
        _ => {}
    }
    LSA_LOGON_IN_FLIGHT.store(0, Ordering::Relaxed);
    // ★ LAST INSTANT THE LOGON DIALOG IS GUARANTEED ALIVE. A SUCCESSFUL `LsaLogonUser` makes msgina
    // return `WLX_SAS_ACTION_LOGON`, and `EndDialog` then legitimately DESTROYS the IDD_LOGON dialog
    // and its controls — after which the gate can no longer resolve their HWNDs or sample their
    // framebuffer rectangle. Latch those three measurements here, unchanged, so the gate asserts the
    // same properties measured while they hold. (Before the token service existed the reply was a
    // failure and the dialog stayed up, which is the only reason a gate-time sample ever worked.)
    if LSA_LAST_API_NUMBER.load(Ordering::Relaxed) == 2 {
        unsafe { crate::latch_logon_dialog_evidence() };
    }
    print_str(b"[lsa-rdv] REPLY delivered: api=");
    print_u64(LSA_LAST_API_NUMBER.load(Ordering::Relaxed));
    print_str(b" LSA_API_MSG.Status=0x");
    print_hex(api_status);
    print_str(b" bytes=");
    print_u64(length as u64);
    print_str(b"\n");
    LSA_CLI_REPLY_CAP.store(0, Ordering::Relaxed);
    LSA_CLI_KIND.store(0, Ordering::Relaxed);
    lsa_wake(
        cap,
        0, // NtRequestWaitReplyPort itself succeeded; the API status rides in the message
        LSA_CLI_IP.load(Ordering::Relaxed),
        LSA_CLI_SP.load(Ordering::Relaxed),
        LSA_CLI_FLAGS.load(Ordering::Relaxed),
    );
    true
}

/// BATCH 33 — PARK a caller whose npfs pipe read returned STATUS_PENDING. Mirrors the event
/// `wait_park_multi` reply-cap steal EXACTLY (steal the active REPLY_MAIN, rotate a fresh pool object
/// into REPLY_MAIN so the next recv binds a new object), but records the wait in the PipeWaiterTable
/// keyed by the reading end's npfs file-id instead of an obj_ns event index. Returns true on success;
/// false if the pool or the waiter table is exhausted (caller then returns PENDING directly — degraded
/// but never a hang). The stolen cap resumes the blocked thread when the peer writes (`pipe_redrive_all`).
unsafe fn pipe_wait_park(
    file_id: u64,
    pi: u32,
    tid: u64,
    badge: u64,
    buffer_va: u64,
    buffer_len: u32,
    iosb_va: u64,
    apc_context: u64,
    event_obj_idx: u64,
    is_transceive: bool,
    is_write: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> bool {
    let stolen = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    if stolen == 0 {
        return false;
    }
    // Find a FREE pool object to become the new active REPLY_MAIN (same rotation as wait_park_multi).
    let used = WAIT_REPLY_POOL_USED.load(Ordering::Relaxed);
    let mut fresh = 0u64;
    let mut fresh_bit = 0usize;
    for i in 0..WAIT_REPLY_POOL_N {
        if used & (1u64 << i) == 0 {
            let cp = WAIT_REPLY_POOL[i].load(Ordering::Relaxed);
            if cp != 0 {
                fresh = cp;
                fresh_bit = i;
                break;
            }
        }
    }
    if fresh == 0 {
        return false; // pool exhausted → caller returns PENDING directly
    }
    let table = &mut *core::ptr::addr_of_mut!(PIPE_WAITERS);
    let parked = table.park(nt_io_manager::PipeWaiter {
        file_id,
        pi,
        tid,
        badge,
        buffer_va,
        buffer_len,
        iosb_va,
        apc_context,
        event_obj_idx,
        reply_cap: stolen,
        resume_ip,
        resume_sp: sp,
        resume_flags: flags,
        is_transceive,
        is_write,
    });
    if parked.is_none() {
        return false; // table exhausted → caller returns PENDING directly
    }
    // Commit the reply-cap rotation only after the waiter is recorded.
    WAIT_REPLY_POOL_USED.fetch_or(1u64 << fresh_bit, Ordering::Relaxed);
    REPLY_MAIN_SLOT.store(fresh, Ordering::Relaxed);
    PIPE_WAIT_PARKED_COUNT.fetch_add(1, Ordering::Relaxed);
    true
}

/// BATCH 33 — RE-DRIVE every parked pipe read after a peer write. The executive has no peer→reader
/// map (npfs pairs the two ends internally by name), so on ANY completed pipe write we re-issue EVERY
/// parked read against npfs: npfs's own FCB pairing makes the reader whose peer just wrote return data
/// (non-PENDING) while the others stay PENDING. For each reader that now has bytes we copy them into
/// its buffer + fill its IOSB (through ITS OWN VSpace mirrors — switched in for the copyout, since the
/// active process is the WRITER, then restored) and reply to its stolen reply cap (restoring its
/// native-syscall resume context, exactly like the event wake), then free the slot. Idempotent: a read
/// still PENDING leaves the waiter parked (re-armable for the next PDU / write). Returns woken count.
unsafe fn pipe_redrive_all(nt_handler: &mut ExecNtHandler) -> u64 {
    let transport_capacity = (driver_launch::FSD_ARG_FRAMES * 0x1000) as usize;
    // Snapshot the active-mirror context + handler identity so we can restore after each re-drive.
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
    let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take(); // copyout via mirrors only during the re-drive
    let mut woken = 0u64;
    let table = &*core::ptr::addr_of!(PIPE_WAITERS);
    let snapshot: alloc::vec::Vec<(usize, nt_io_manager::PipeWaiter)> = table.drain_all().collect();
    for (slot, w) in snapshot {
        // Re-issue this reader's read against npfs; if still PENDING, leave it parked.
        let want = (w.buffer_len as usize).min(transport_capacity).max(1);
        let mut output = alloc::vec![0u8; want];
        // BATCH 37: FIRST check for a completed-pending-read stash for this fid. When this reader's
        // original read went PENDING, npfs retained the read IRP; the peer WRITE already completed it
        // (copying the payload into THAT IRP) — so a fresh re-drive read would find the queue drained
        // and return garbage/PENDING. `take_completed_read` hands back the exact bytes npfs delivered
        // to the pending read IRP (this is how the rpcrt4 worker gets winlogon's bind PDU).
        let (status, completed) = if w.is_write {
            match driver_launch::take_completed_write(w.file_id) {
                Some(completion) => completion,
                None => continue,
            }
        } else if let Some((st, info, bytes)) = driver_launch::take_completed_read(w.file_id) {
            let n = (bytes.len()).min(output.len());
            output[..n].copy_from_slice(&bytes[..n]);
            (st, info)
        } else if w.is_transceive {
            match nt_handler.npfs_route_raw(
                major::IRP_MJ_READ as u64,
                0,
                w.file_id,
                &[],
                &mut output,
            ) {
                Some((st, info, _)) => (st as u32, info),
                None => continue,
            }
        } else {
            continue;
        };
        if status == 0x0000_0103 {
            continue; // still PENDING → stays parked (re-armable)
        }
        // Data (or a terminal status) available. Point the copyout at the READER's VSpace mirrors.
        let (sb, ss, smv, hmv, imv, scratch_base) = mirror_ctx_for(w.badge, w.pi as usize);
        ACTIVE_STACK_BASE.store(sb, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(ss, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(smv, Ordering::Relaxed);
        ACTIVE_HEAP_MIRROR.store(hmv, Ordering::Relaxed);
        ACTIVE_IMAGE_MIRROR.store(imv, Ordering::Relaxed);
        ACTIVE_CLIENT_PI.store(w.pi as u64, Ordering::Relaxed);
        ACTIVE_SCRATCH_BASE.store(scratch_base, Ordering::Relaxed);
        nt_handler.pi = w.pi as usize;
        let copy_len = (completed as usize).min(output.len());
        // BATCH 37: copy the delivered bytes for SUCCESS *and* STATUS_BUFFER_OVERFLOW (0x80000005) —
        // a message-mode read of a message larger than the buffer returns the partial bytes WITH
        // overflow (rpcrt4 reads the 16-byte common header of a 72-byte bind PDU this way, then reads
        // the remainder). Gating the copyout on `status == 0` left the reader's buffer zeroed on
        // overflow, so rpcrt4's RPCRT4_ValidateCommonHeader saw an all-zero header and failed. Only a
        // hard error / PENDING leaves the buffer untouched.
        if !w.is_write
            && (status == 0 || status == 0x8000_0005)
            && copy_len != 0
            && w.buffer_va != 0
        {
            nt_handler.xas_write_buf(w.buffer_va, &output[..copy_len]);
            // ★ LSA SELF-RPC instrumentation: an MS-RPC PDU actually DELIVERED off lsass' own
            // `\lsarpc` to a parked reader, attributed by badge to the per-connection WORKER (the
            // bind / request it must service) or to lsass' main thread as the CLIENT (the bind_ack /
            // response that unblocks `LsaOpenPolicy`). Name-scoped via the fid->pipe-name map.
            let lsass_pi = live_hosted_pi_for_leaf(nt_handler, b"lsass.exe");
            if lsass_pi == Some(w.pi as usize)
                && output.first() == Some(&5)
                && pipe_fid_name_hash(w.file_id) == lsarpc_pipe_name_hash()
            {
                let pdu_type = output.get(2).copied().unwrap_or(0xFF) as u64;
                if w.badge == LSA_WORKER_BADGE {
                    LSA_WORKER_PDU_READS.fetch_add(1, Ordering::Relaxed);
                    let _ = LSA_WORKER_FIRST_PDU_TYPE.compare_exchange(
                        0xFF,
                        pdu_type,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    );
                } else {
                    LSA_SELF_RPC_CLIENT_READS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if w.iosb_va != 0 {
            nt_handler.xas_write_buf(w.iosb_va, &status.to_le_bytes());
            nt_handler.xas_write_buf(w.iosb_va + 8, &(completed as u64).to_le_bytes());
        }
        if w.event_obj_idx != u64::MAX {
            let _ = nt_handler.events.set_existing(w.event_obj_idx);
            let _ = wait_wake_dispatcher_set(nt_handler);
        }
        nt_handler.post_file_completion(w.file_id, w.apc_context, status, completed);
        if nt_handler.io_completion_wake.is_some() {
            let _ = io_completion_deliver(nt_handler);
        }
        // Wake the blocked thread on its stolen reply cap — restore RCX/RSP/RFLAGS (MR15/16/17) and
        // return `status` in MR0 (→ RAX/r10), exactly like the event wake.
        let cap = w.reply_cap;
        if cap != 0 {
            set_reply_mr(15, w.resume_ip);
            set_reply_mr(16, w.resume_sp);
            set_reply_mr(17, w.resume_flags);
            client_reply_on(cap, 18, status as u64, 0, 0, 0);
            release_reply_pool_cap(cap);
        }
        nt_handler.release_file_reference(w.file_id);
        // Free the slot (re-armable for the next PDU).
        let table_mut = &mut *core::ptr::addr_of_mut!(PIPE_WAITERS);
        table_mut.complete(slot);
        woken += 1;
        PIPE_WAIT_WOKEN_COUNT.fetch_add(1, Ordering::Relaxed);
        if PIPE_REDRIVE_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16 {
            print_str(b"[pipe-redrive] WOKE reader fid=0x");
            print_hex(w.file_id as u32);
            print_str(b" pi=");
            print_u64(w.pi as u64);
            print_str(b" badge=");
            print_u64(w.badge);
            print_str(b" status=0x");
            print_hex(status);
            print_str(b" bytes=");
            print_u64(completed);
            print_str(b"\n");
        }
    }
    // Restore the writer's active-mirror context + handler identity.
    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    woken
}

/// BATCH 34 — complete the pending async server `FSCTL_PIPE_LISTEN` matching `name_hash` after a
/// client CONNECT to that same pipe name. The ncacn_np rpcrt4 SERVER posted an OVERLAPPED
/// FSCTL_PIPE_LISTEN (STATUS_PENDING, no client) with a completion EVENT, then parked on
/// `NtWaitForMultipleObjects([mgr_event, listen_event])`. The client just connected (npfs paired the
/// ends by name), so ONE matching pending listen is now satisfied: fill its listen IOSB
/// `{Status=SUCCESS, Information=0}` in the SERVER's VSpace (switch in the listener's mirror context
/// for the copyout, then restore) and signal its completion event via the shared dispatcher wake path
/// NtSetEvent wake path — waking the server's wait-array so it reads the client's first PDU (the bind).
/// Name-scoped so a `\ntsvcs` connect never wakes `\lsarpc`/`\samr` (which would spin their rpcrt4
/// accept loop). Returns 1 if a listen was completed, else 0. Re-armable: rpcrt4 re-posts a fresh
/// FSCTL_PIPE_LISTEN for the next client (a NEW record). Completes ONE listen per connect (one client).
unsafe fn pipe_listen_complete_named(nt_handler: &mut ExecNtHandler, name_hash: u64) -> u64 {
    // Find the matching pending listen (name-scoped); take it (consumed once per client connect).
    let l = {
        let table_mut = &mut *core::ptr::addr_of_mut!(PIPE_ASYNC_LISTENS);
        match table_mut.complete_by_name(name_hash) {
            Some(l) => l,
            None => return 0,
        }
    };
    let saved_stack_base = ACTIVE_STACK_BASE.load(Ordering::Relaxed);
    let saved_stack_size = ACTIVE_STACK_SIZE.load(Ordering::Relaxed);
    let saved_stack_mirror = ACTIVE_STACK_MIRROR.load(Ordering::Relaxed);
    let saved_heap_mirror = ACTIVE_HEAP_MIRROR.load(Ordering::Relaxed);
    let saved_image_mirror = ACTIVE_IMAGE_MIRROR.load(Ordering::Relaxed);
    let saved_client_pi = ACTIVE_CLIENT_PI.load(Ordering::Relaxed);
    let saved_scratch_base = ACTIVE_SCRATCH_BASE.load(Ordering::Relaxed);
    let saved_pi = nt_handler.pi;
    let saved_ctx = nt_handler.loop_ctx.take();
    let mut completed = 0u64;
    {
        // Point the IOSB copyout at the SERVER listener's VSpace mirrors.
        let badge = l.badge;
        let (sb, ss, smv, hmv, imv, scratch_base) = mirror_ctx_for(badge, l.pi as usize);
        ACTIVE_STACK_BASE.store(sb, Ordering::Relaxed);
        ACTIVE_STACK_SIZE.store(ss, Ordering::Relaxed);
        ACTIVE_STACK_MIRROR.store(smv, Ordering::Relaxed);
        ACTIVE_HEAP_MIRROR.store(hmv, Ordering::Relaxed);
        ACTIVE_IMAGE_MIRROR.store(imv, Ordering::Relaxed);
        ACTIVE_CLIENT_PI.store(l.pi as u64, Ordering::Relaxed);
        ACTIVE_SCRATCH_BASE.store(scratch_base, Ordering::Relaxed);
        nt_handler.pi = l.pi as usize;
        // Fill the listen IO_STATUS_BLOCK: {Status=STATUS_SUCCESS, Information=0}.
        if l.iosb_va != 0 {
            nt_handler.xas_write_buf(l.iosb_va, &0u32.to_le_bytes());
            nt_handler.xas_write_buf(l.iosb_va + 8, &0u64.to_le_bytes());
        }
        // SIGNAL the overlapped completion event → wakes the server's NtWaitForMultipleObjects. Reuse
        // the exact NtSetEvent wake path: set the event's `signalled` flag then reevaluate waiters.
        if l.event_obj_idx != u64::MAX {
            let idx = l.event_obj_idx as usize;
            let _ = nt_handler.events.set_existing(idx as u64);
            let woken = wait_wake_dispatcher_set(nt_handler);
            if PIPE_LISTEN_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < 16 {
                print_str(b"[pipe-listen] COMPLETE server fid=0x");
                print_hex(l.server_file_id as u32);
                print_str(b" signalled event_obj=0x");
                print_hex(idx as u32);
                print_str(b" -> woke ");
                print_u64(woken);
                print_str(b" server wait(s)\n");
            }
        }
        completed += 1;
        PIPE_LISTEN_SIGNALLED_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    ACTIVE_STACK_BASE.store(saved_stack_base, Ordering::Relaxed);
    ACTIVE_STACK_SIZE.store(saved_stack_size, Ordering::Relaxed);
    ACTIVE_STACK_MIRROR.store(saved_stack_mirror, Ordering::Relaxed);
    ACTIVE_HEAP_MIRROR.store(saved_heap_mirror, Ordering::Relaxed);
    ACTIVE_IMAGE_MIRROR.store(saved_image_mirror, Ordering::Relaxed);
    ACTIVE_CLIENT_PI.store(saved_client_pi, Ordering::Relaxed);
    ACTIVE_SCRATCH_BASE.store(saved_scratch_base, Ordering::Relaxed);
    nt_handler.pi = saved_pi;
    nt_handler.loop_ctx = saved_ctx;
    completed
}

unsafe fn ensure_client_copyin_dll_page(
    pi: u64,
    page: u64,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) -> bool {
    if csrss_frame_get(pi, page) != 0 || client_copyin_frame_get(pi, page) != 0 {
        return true;
    }
    let Some((i, rva)) = reg.dll_for_page(page) else {
        return false;
    };
    let Some(slot) = dll_pes.get(i) else {
        return false;
    };
    let Some(tpe) = (*slot).as_ref() else {
        return false;
    };
    let prefetch_index =
        core::ptr::read(core::ptr::addr_of!(CLIENT_COPYIN_FRAME_N)).min(CLIENT_COPYIN_FRAME_CAP);
    if prefetch_index == CLIENT_COPYIN_FRAME_CAP {
        return false;
    }
    // Reserve the high end of each process scratch window for bounded copy-in prefetches. Demand
    // fills are capped below this range, so every prefetched page keeps a distinct live alias.
    let alias = scratch_base + DEMAND_SCRATCH_WINDOW - (prefetch_index as u64 + 3) * 0x1000;
    let (frame, fe) = alloc_frame_r();
    let se = page_map_r(frame, alias, RW_NX, CAP_INIT_THREAD_VSPACE);
    if fe != 0 || se != 0 {
        return false;
    }
    let _ = fill_image_page(tpe, rva, alias);
    client_copyin_frame_put(pi, page, frame, alias);
    true
}

unsafe fn prefill_client_copyin_dll_range_pages(
    pi: u64,
    va: u64,
    len: usize,
    scratch_base: u64,
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) {
    if len == 0 {
        return;
    }
    let Some(last) = va.checked_add(len as u64 - 1) else {
        return;
    };
    let mut page = va & !0xfffu64;
    let last_page = last & !0xfffu64;
    loop {
        let _ = ensure_client_copyin_dll_page(pi, page, scratch_base, reg, dll_pes);
        if page == last_page {
            break;
        }
        page += 0x1000;
    }
}

unsafe fn prefill_client_large_string_pages(
    pi: u64,
    descriptor_va: u64,
    scratch_base: u64,
    faults: &mut u64,
    filled_pages: &mut [u64; 512],
    reg: &nt_dll_registry::Registry,
    dll_pes: &[&Option<nt_pe_loader::PeFile>],
) {
    let mut raw = [0u8; 16];
    if !img_spawn::client_copyin_mapped(
        pi,
        descriptor_va,
        &mut raw,
        filled_pages,
        *faults as usize,
        scratch_base,
    ) {
        return;
    }
    let Ok(descriptor) = nt_user_callback::LargeUnicodeStringDescriptor::parse(&raw) else {
        return;
    };
    let mut offset = 0usize;
    let length = descriptor.length_bytes as usize;
    let mut last_page = u64::MAX;
    while offset < length {
        let current = descriptor.buffer + offset as u64;
        let page = current & !0xfffu64;
        if page != last_page {
            let _ = ensure_client_copyin_dll_page(pi, page, scratch_base, reg, dll_pes);
            last_page = page;
        }
        let page_remaining = 0x1000usize - (current as usize & 0xfff);
        offset += page_remaining.min(length - offset);
    }
}

/// Map any fault badge to the TOP-LEVEL process badge that owns it. Named listener/worker
/// ownership is runtime metadata; top-level and generic TP-worker badges are mechanism-level decodes.
#[inline]
fn owner_top_badge_for(nt_handler: &ExecNtHandler, badge: u64) -> u64 {
    nt_handler
        .hosted_thread_pi_for_badge(badge)
        .or_else(|| hosted_pi_for_mechanism_badge(nt_handler, badge))
        .map(|pi| hosted_top_badge_for_pi(nt_handler, pi))
        .unwrap_or(0)
}

/// A top-level process badge (its MAIN thread), not a listener/worker sub-thread. Only a top-level
/// process's indefinite wait is quiesce-relevant (a sub-thread listener parks cooperatively but its
/// parent process may still run).
#[inline]
/// A DEADLINE-LESS wait park is the one park that can wedge the boot: the parked thread can only be
/// woken by another RUNNABLE thread, and if none is left the loop's next `recv` blocks forever —
/// past even the wall-clock stall watchdog, which lives at the loop top and therefore never runs.
/// Only a TOP-LEVEL badge's park is counted toward quiesce (a worker parking says nothing about its
/// process's main thread), so trace every one of them with the three masks the quiesce test reads.
fn trace_indefinite_wait_park(
    nt_handler: &ExecNtHandler,
    badge: u64,
    live: u64,
    crash_parked: u64,
    wait_parked: u64,
) {
    static N: AtomicU64 = AtomicU64::new(0);
    if N.fetch_add(1, Ordering::Relaxed) >= 24 {
        return;
    }
    print_str(b"[wait-park] badge=");
    print_u64(badge);
    print_str(b" owner=");
    print_u64(owner_top_badge_for(nt_handler, badge));
    print_str(b" top-level=");
    print_u64(pi_is_top_level(nt_handler, badge) as u64);
    print_str(b" live=0x");
    print_hex(live as u32);
    print_str(b" crash=0x");
    print_hex(crash_parked as u32);
    print_str(b" wait=0x");
    print_hex(wait_parked as u32);
    print_str(b"\n");
}

#[inline]
fn userinit_shell_frontier_pending(
    nt_handler: &ExecNtHandler,
    crash_parked: u64,
    wait_parked: u64,
) -> bool {
    if USERINIT_SPAWNED.load(Ordering::Relaxed) != 1
        || USERINIT_SHELL_IMAGE_ATTEMPTS.load(Ordering::Relaxed) != 0
    {
        return false;
    }
    let userinit_badge = hosted_top_badge_for_role(
        nt_handler,
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap,
    )
    .expect("userinit hosted metadata must be registered once userinit is spawned");
    let userinit_bit = 1u64 << userinit_badge;
    (crash_parked | wait_parked) & userinit_bit == 0
}

fn pi_is_top_level(nt_handler: &ExecNtHandler, badge: u64) -> bool {
    hosted_pi_for_top_badge(nt_handler, badge).is_some()
}

/// The bitmask of LIVE top-level process badges (smss is always live; the rest once SPAWNED).
/// Used by the quiesce test: the boot has no forward progress possible once every live top-level
/// process is crash-parked (so the loop's next `recv` would block on the fault-EP forever).
#[inline]
unsafe fn live_top_badges(nt_handler: &ExecNtHandler) -> u64 {
    (0..MAX_PI)
        .filter_map(|pi| {
            hosted_process_pi_is_live(pi).then_some(hosted_top_badge_for_pi(nt_handler, pi))
        })
        .fold(0u64, |mask, badge| mask | (1u64 << badge))
}

/// One-line progress trace for the dbgk target-blocking self-test: which fault the throwaway client
/// took and what its progress MARKER read at that moment. Six lines per boot — they are the
/// human-readable record of "parked, not progressed" / "resumed, and continued".
unsafe fn dbgk_blk_trace(tag: &[u8], msginfo: u64, m0: u64, m1: u64, marker: u64) {
    print_str(b"[dbgk-blk] ");
    print_str(tag);
    print_str(b" label=");
    print_u64(msginfo >> 12);
    print_str(b" m0=0x");
    print_hex(m0 as u32);
    print_str(b" m1=0x");
    print_hex(m1 as u32);
    print_str(b" marker=");
    print_u64(marker);
    print_str(b"\n");
}
