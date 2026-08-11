//! Hosted-process runtime placement and SEC_IMAGE spawn helpers.
//!
//! Runtime placement is allocated when an image is admitted into the hosted-image catalog. The
//! address bands below preserve the current boot layout, but callers no longer pass image-specific
//! `HostedProcessRuntime` constants around as identity.
#![allow(clippy::all)]
use crate::*;
use nt_hosted_runtime::{DynamicRuntimeArena, ProcessRuntimeLayout};

#[derive(Clone, Copy)]
pub(crate) struct HostedProcessRuntime {
    pub(crate) pi: usize,
    pub(crate) priority: u64,
    pub(crate) env_scratch_va: u64,
    pub(crate) stack_mirror_va: u64,
    pub(crate) heap_mirror_va: u64,
    pub(crate) active_image_mirror_va: u64,
    pub(crate) spawn_image_mirror_va: u64,
    pub(crate) scratch_base: u64,
    pub(crate) spawned: Option<&'static AtomicU64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedProcessRuntimeRegistrationError {
    InvalidPi,
    DuplicatePi,
    MissingLayout,
}

#[derive(Clone, Copy)]
struct HostedProcessRuntimeTable {
    entries: [Option<HostedProcessRuntime>; MAX_PI],
}

impl HostedProcessRuntimeTable {
    const fn new() -> Self {
        Self {
            entries: [None; MAX_PI],
        }
    }

    fn reset(&mut self) {
        self.entries = [None; MAX_PI];
    }

    fn register(
        &mut self,
        runtime: HostedProcessRuntime,
    ) -> Result<(), HostedProcessRuntimeRegistrationError> {
        if runtime.pi >= MAX_PI {
            return Err(HostedProcessRuntimeRegistrationError::InvalidPi);
        }
        if self.entries[runtime.pi].is_some() {
            return Err(HostedProcessRuntimeRegistrationError::DuplicatePi);
        }
        self.entries[runtime.pi] = Some(runtime);
        Ok(())
    }

    fn get_by_pi(&self, pi: usize) -> Option<HostedProcessRuntime> {
        self.entries.get(pi).and_then(|entry| *entry)
    }
}

static mut HOSTED_PROCESS_RUNTIMES: HostedProcessRuntimeTable = HostedProcessRuntimeTable::new();

pub(crate) fn reset_hosted_process_runtimes() {
    unsafe { (&mut *core::ptr::addr_of_mut!(HOSTED_PROCESS_RUNTIMES)).reset() };
    reset_dynamic_spawned_signals();
}

pub(crate) fn register_hosted_process_runtime(
    runtime: HostedProcessRuntime,
) -> Result<(), HostedProcessRuntimeRegistrationError> {
    unsafe { (&mut *core::ptr::addr_of_mut!(HOSTED_PROCESS_RUNTIMES)).register(runtime) }
}

pub(crate) fn hosted_process_runtime_for_pi(pi: usize) -> Option<HostedProcessRuntime> {
    unsafe { (&*core::ptr::addr_of!(HOSTED_PROCESS_RUNTIMES)).get_by_pi(pi) }
}

#[derive(Clone, Copy)]
struct HostedProcessAddressLayout {
    scratch_base: u64,
    env_scratch_va: u64,
    stack_mirror_va: u64,
    heap_mirror_va: u64,
    image_mirror_va: u64,
}

const HOSTED_PROCESS_DEFAULT_PRIORITY: u64 = 100;
const SMSS_ENV_SCRATCH_VA: u64 = 0x0000_0100_1074_0000;
const CSRSS_ENV_SCRATCH_VA: u64 = 0x0000_0100_1078_0000;
const HOSTED_DYNAMIC_FIRST_PI: usize = 7;
const HOSTED_DYNAMIC_RUNTIME_BASE: u64 = 0x0000_0101_6000_0000;
const HOSTED_DYNAMIC_RUNTIME_STRIDE: u64 = 0x0800_0000;
const HOSTED_DYNAMIC_RUNTIME_LIMIT: u64 = HOSTED_DYNAMIC_RUNTIME_BASE
    + (MAX_PI - HOSTED_DYNAMIC_FIRST_PI) as u64 * HOSTED_DYNAMIC_RUNTIME_STRIDE;
const HOSTED_ENV_SCRATCH_WINDOW: u64 = 0x9000;
const HOSTED_MIRROR_WINDOW: u64 = 0x20_0000;
const HOSTED_DYNAMIC_RUNTIME_ARENA: DynamicRuntimeArena = DynamicRuntimeArena {
    first_pi: HOSTED_DYNAMIC_FIRST_PI,
    max_pi: MAX_PI,
    base: HOSTED_DYNAMIC_RUNTIME_BASE,
    limit: HOSTED_DYNAMIC_RUNTIME_LIMIT,
    stride: HOSTED_DYNAMIC_RUNTIME_STRIDE,
    scratch_offset: 0,
    stack_offset: DEMAND_SCRATCH_WINDOW,
    env_offset: DEMAND_SCRATCH_WINDOW + 0x10_0000,
    heap_offset: DEMAND_SCRATCH_WINDOW + 0x20_0000,
    image_offset: DEMAND_SCRATCH_WINDOW + 0x40_0000,
    scratch_len: DEMAND_SCRATCH_WINDOW,
    stack_len: STACK_FRAMES * 0x1000,
    env_len: HOSTED_ENV_SCRATCH_WINDOW,
    heap_len: HOSTED_MIRROR_WINDOW,
    image_len: HOSTED_MIRROR_WINDOW,
};
const _: () = {
    assert!(HOSTED_DYNAMIC_RUNTIME_BASE >= driver_launch::FSD_EXEC_LIMIT);
    assert!(HOSTED_DYNAMIC_RUNTIME_BASE & 0x1f_ffff == 0);
    assert!(HOSTED_DYNAMIC_RUNTIME_STRIDE & 0x1f_ffff == 0);
    assert!(HOSTED_DYNAMIC_RUNTIME_LIMIT >= HOSTED_DYNAMIC_RUNTIME_BASE);
};

static HOSTED_DYNAMIC_SPAWNED: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];

fn reset_dynamic_spawned_signals() {
    for spawned in HOSTED_DYNAMIC_SPAWNED.iter() {
        spawned.store(0, Ordering::Relaxed);
    }
}

fn spawned_signal_for_pi(pi: usize) -> Option<&'static AtomicU64> {
    match pi {
        1 => Some(&CSRSS_SPAWNED),
        2 => Some(&WINLOGON_SPAWNED),
        3 => Some(&SERVICES_SPAWNED),
        4 => Some(&LSASS_SPAWNED),
        5 => Some(&USERINIT_SPAWNED),
        6 => Some(&EXPLORER_SPAWNED),
        HOSTED_DYNAMIC_FIRST_PI..MAX_PI => HOSTED_DYNAMIC_SPAWNED.get(pi),
        _ => None,
    }
}

fn core_service_layout(pi: usize) -> Option<HostedProcessAddressLayout> {
    if !(2..=4).contains(&pi) {
        return None;
    }
    let service_index = (pi - 2) as u64;
    let stack_mirror_va = match pi {
        2 => WINLOGON_STACK_MIRROR_VA,
        3 => SERVICES_STACK_MIRROR_VA,
        4 => LSASS_STACK_MIRROR_VA,
        _ => return None,
    };
    let env_scratch_va = match pi {
        2 => WINLOGON_MAIN_TEB_MIRROR_VA,
        3 => SERVICES_ENV_SCRATCH_VA,
        4 => LSASS_ENV_SCRATCH_VA,
        _ => return None,
    };
    let heap_mirror_va = WINLOGON_HEAP_MIRROR_VA + service_index * 0x40_0000;
    Some(HostedProcessAddressLayout {
        scratch_base: SMSS_SCRATCH_BASE + pi as u64 * DEMAND_SCRATCH_WINDOW,
        env_scratch_va,
        stack_mirror_va,
        heap_mirror_va,
        image_mirror_va: heap_mirror_va + 0x20_0000,
    })
}

fn shell_layout(pi: usize) -> Option<HostedProcessAddressLayout> {
    let stack_mirror_va = match pi {
        5 => USERINIT_STACK_MIRROR_VA,
        6 => EXPLORER_STACK_MIRROR_VA,
        _ => return None,
    };
    let scratch_base = match pi {
        5 => USERINIT_SCRATCH_BASE,
        6 => EXPLORER_SCRATCH_BASE,
        _ => return None,
    };
    Some(HostedProcessAddressLayout {
        scratch_base,
        env_scratch_va: stack_mirror_va + 0x10_0000,
        stack_mirror_va,
        heap_mirror_va: stack_mirror_va + 0x20_0000,
        image_mirror_va: stack_mirror_va + 0x40_0000,
    })
}

fn dynamic_layout(pi: usize) -> Option<HostedProcessAddressLayout> {
    let layout = HOSTED_DYNAMIC_RUNTIME_ARENA.layout_for_pi(pi).ok()?;
    Some(address_layout_from_runtime_layout(layout))
}

fn address_layout_from_runtime_layout(layout: ProcessRuntimeLayout) -> HostedProcessAddressLayout {
    HostedProcessAddressLayout {
        scratch_base: layout.scratch_base,
        env_scratch_va: layout.env_scratch_va,
        stack_mirror_va: layout.stack_mirror_va,
        heap_mirror_va: layout.heap_mirror_va,
        image_mirror_va: layout.image_mirror_va,
    }
}

fn address_layout_for_image(
    image: nt_exe_image::HostedProcessImageRef<'_>,
) -> Option<HostedProcessAddressLayout> {
    match image.role {
        nt_exe_image::HostedProcessRole::NativeSession if image.pi == 0 => {
            Some(HostedProcessAddressLayout {
                scratch_base: SMSS_SCRATCH_BASE,
                env_scratch_va: SMSS_ENV_SCRATCH_VA,
                stack_mirror_va: SMSS_STACK_MIRROR_VA,
                heap_mirror_va: SMSS_HEAP_MIRROR_VA,
                image_mirror_va: IMAGE_MIRROR_VA,
            })
        }
        nt_exe_image::HostedProcessRole::Win32Subsystem if image.pi == 1 => {
            Some(HostedProcessAddressLayout {
                scratch_base: CSRSS_SCRATCH_BASE,
                env_scratch_va: CSRSS_ENV_SCRATCH_VA,
                stack_mirror_va: CSRSS_STACK_MIRROR_VA,
                heap_mirror_va: CSRSS_HEAP_MIRROR_VA,
                image_mirror_va: CSRSS_IMAGE_MIRROR_VA,
            })
        }
        nt_exe_image::HostedProcessRole::InteractiveLogon
        | nt_exe_image::HostedProcessRole::NonInteractiveService => {
            core_service_layout(image.pi).or_else(|| dynamic_layout(image.pi))
        }
        nt_exe_image::HostedProcessRole::InteractiveShellBootstrap
        | nt_exe_image::HostedProcessRole::InteractiveShell => {
            shell_layout(image.pi).or_else(|| dynamic_layout(image.pi))
        }
        nt_exe_image::HostedProcessRole::NativeSession
        | nt_exe_image::HostedProcessRole::Win32Subsystem => None,
    }
}

fn runtime_for_image(
    image: nt_exe_image::HostedProcessImageRef<'_>,
) -> Result<HostedProcessRuntime, HostedProcessRuntimeRegistrationError> {
    if image.pi >= MAX_PI {
        return Err(HostedProcessRuntimeRegistrationError::InvalidPi);
    }
    let layout = address_layout_for_image(image)
        .ok_or(HostedProcessRuntimeRegistrationError::MissingLayout)?;
    let spawned = spawned_signal_for_pi(image.pi);
    let spawn_image_mirror_va = match image.role {
        nt_exe_image::HostedProcessRole::NativeSession
        | nt_exe_image::HostedProcessRole::Win32Subsystem => 0,
        _ => layout.image_mirror_va,
    };
    Ok(HostedProcessRuntime {
        pi: image.pi,
        priority: HOSTED_PROCESS_DEFAULT_PRIORITY,
        env_scratch_va: layout.env_scratch_va,
        stack_mirror_va: layout.stack_mirror_va,
        heap_mirror_va: layout.heap_mirror_va,
        active_image_mirror_va: layout.image_mirror_va,
        spawn_image_mirror_va,
        scratch_base: layout.scratch_base,
        spawned,
    })
}

pub(crate) fn register_hosted_process_runtime_for_image(
    image: nt_exe_image::HostedProcessImageRef<'_>,
) -> Result<(), HostedProcessRuntimeRegistrationError> {
    register_hosted_process_runtime(runtime_for_image(image)?)
}

fn expect_hosted_process_runtime(pi: usize) -> HostedProcessRuntime {
    hosted_process_runtime_for_pi(pi).expect("hosted process runtime layout must be registered")
}

pub(crate) fn hosted_main_stack_mirror_for_pi(pi: usize) -> u64 {
    expect_hosted_process_runtime(pi).stack_mirror_va
}

pub(crate) fn hosted_env_scratch_base_for_pi(pi: usize) -> u64 {
    expect_hosted_process_runtime(pi).env_scratch_va
}

pub(crate) fn hosted_peb_mirror_for_pi(pi: usize) -> u64 {
    let env_scratch = hosted_env_scratch_base_for_pi(pi);
    if env_scratch == 0 {
        0
    } else {
        env_scratch + 0x1000
    }
}

pub(crate) fn hosted_heap_mirror_for_pi(pi: usize) -> u64 {
    expect_hosted_process_runtime(pi).heap_mirror_va
}

pub(crate) unsafe fn spawn_hosted_sec_image_for_image(
    image: nt_exe_image::HostedProcessImageRef<'_>,
    pe: &nt_pe_loader::PeFile,
    fault_ep_c: u64,
    ntdll: Option<(u64, &nt_pe_loader::PeFile)>,
    setup_env: bool,
    ldrpinit_rva: u64,
    client_process_id: u64,
    client_thread_id: u64,
) -> img_spawn::SecImageSpawn {
    let runtime = expect_hosted_process_runtime(image.pi);
    spawn_sec_image(
        image.pi as u64,
        pe,
        fault_ep_c,
        ntdll,
        setup_env,
        runtime.priority,
        runtime.env_scratch_va,
        runtime.stack_mirror_va,
        runtime.heap_mirror_va,
        runtime.spawn_image_mirror_va,
        client_process_id,
        client_thread_id,
        image.nt_image_path,
        image.command_line,
        image.role.uses_win32_client_gdi(),
        ldrpinit_rva,
    )
}

pub(crate) fn hosted_active_image_mirror_for_pi(pi: usize) -> u64 {
    expect_hosted_process_runtime(pi).active_image_mirror_va
}

pub(crate) fn hosted_scratch_base_for_pi(pi: usize) -> u64 {
    expect_hosted_process_runtime(pi).scratch_base
}

pub(crate) fn hosted_process_pi_is_live(pi: usize) -> bool {
    match hosted_process_runtime_for_pi(pi) {
        Some(runtime) => runtime
            .spawned
            .map(|spawned| spawned.load(Ordering::Relaxed) == 1)
            .unwrap_or(pi == 0),
        None => false,
    }
}
