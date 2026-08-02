//! Hosted-process runtime placement and SEC_IMAGE spawn helpers.
//!
//! This module contains the fixed per-process mechanism layout that still needs to become a real
//! allocator. Keeping it out of the syscall service loop makes the remaining tech debt explicit.
#![allow(clippy::all)]
use crate::*;

#[derive(Clone, Copy)]
pub(crate) struct HostedProcessRuntime {
    pub(crate) priority: u64,
    pub(crate) env_scratch_va: u64,
    pub(crate) stack_mirror_va: u64,
    pub(crate) heap_mirror_va: u64,
    pub(crate) active_image_mirror_va: u64,
    pub(crate) spawn_image_mirror_va: u64,
    pub(crate) scratch_base: u64,
    pub(crate) spawned: Option<&'static AtomicU64>,
}

pub(crate) fn hosted_process_runtime_for_pi(pi: usize) -> Option<HostedProcessRuntime> {
    match pi {
        0 => Some(HostedProcessRuntime {
            priority: 100,
            env_scratch_va: 0x0000_0100_1074_0000,
            stack_mirror_va: SMSS_STACK_MIRROR_VA,
            heap_mirror_va: SMSS_HEAP_MIRROR_VA,
            active_image_mirror_va: IMAGE_MIRROR_VA,
            spawn_image_mirror_va: 0,
            scratch_base: SMSS_SCRATCH_BASE,
            spawned: None,
        }),
        1 => Some(HostedProcessRuntime {
            priority: 101,
            env_scratch_va: 0x0000_0100_1078_0000,
            stack_mirror_va: CSRSS_STACK_MIRROR_VA,
            heap_mirror_va: CSRSS_HEAP_MIRROR_VA,
            active_image_mirror_va: CSRSS_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: 0,
            scratch_base: CSRSS_SCRATCH_BASE,
            spawned: Some(&CSRSS_SPAWNED),
        }),
        2 => Some(HostedProcessRuntime {
            priority: 102,
            env_scratch_va: WINLOGON_MAIN_TEB_MIRROR_VA,
            stack_mirror_va: WINLOGON_STACK_MIRROR_VA,
            heap_mirror_va: WINLOGON_HEAP_MIRROR_VA,
            active_image_mirror_va: WINLOGON_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: WINLOGON_IMAGE_MIRROR_VA,
            scratch_base: WINLOGON_SCRATCH_BASE,
            spawned: Some(&WINLOGON_SPAWNED),
        }),
        3 => Some(HostedProcessRuntime {
            priority: 103,
            env_scratch_va: SERVICES_ENV_SCRATCH_VA,
            stack_mirror_va: SERVICES_STACK_MIRROR_VA,
            heap_mirror_va: SERVICES_HEAP_MIRROR_VA,
            active_image_mirror_va: SERVICES_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: SERVICES_IMAGE_MIRROR_VA,
            scratch_base: SERVICES_SCRATCH_BASE,
            spawned: Some(&SERVICES_SPAWNED),
        }),
        4 => Some(HostedProcessRuntime {
            priority: 104,
            env_scratch_va: LSASS_ENV_SCRATCH_VA,
            stack_mirror_va: LSASS_STACK_MIRROR_VA,
            heap_mirror_va: LSASS_HEAP_MIRROR_VA,
            active_image_mirror_va: LSASS_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: LSASS_IMAGE_MIRROR_VA,
            scratch_base: LSASS_SCRATCH_BASE,
            spawned: Some(&LSASS_SPAWNED),
        }),
        5 => Some(HostedProcessRuntime {
            priority: 105,
            env_scratch_va: USERINIT_ENV_SCRATCH_VA,
            stack_mirror_va: USERINIT_STACK_MIRROR_VA,
            heap_mirror_va: USERINIT_HEAP_MIRROR_VA,
            active_image_mirror_va: USERINIT_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: USERINIT_IMAGE_MIRROR_VA,
            scratch_base: USERINIT_SCRATCH_BASE,
            spawned: Some(&USERINIT_SPAWNED),
        }),
        6 => Some(HostedProcessRuntime {
            priority: 106,
            env_scratch_va: EXPLORER_ENV_SCRATCH_VA,
            stack_mirror_va: EXPLORER_STACK_MIRROR_VA,
            heap_mirror_va: EXPLORER_HEAP_MIRROR_VA,
            active_image_mirror_va: EXPLORER_IMAGE_MIRROR_VA,
            spawn_image_mirror_va: EXPLORER_IMAGE_MIRROR_VA,
            scratch_base: EXPLORER_SCRATCH_BASE,
            spawned: Some(&EXPLORER_SPAWNED),
        }),
        _ => None,
    }
}

pub(crate) fn hosted_main_stack_mirror_for_pi(pi: usize) -> u64 {
    hosted_process_runtime_for_pi(pi)
        .map(|runtime| runtime.stack_mirror_va)
        .unwrap_or(SMSS_STACK_MIRROR_VA)
}

pub(crate) fn hosted_env_scratch_base_for_pi(pi: usize) -> u64 {
    hosted_process_runtime_for_pi(pi)
        .map(|runtime| runtime.env_scratch_va)
        .unwrap_or(0)
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
    hosted_process_runtime_for_pi(pi)
        .map(|runtime| runtime.heap_mirror_va)
        .unwrap_or(SMSS_HEAP_MIRROR_VA)
}

pub(crate) unsafe fn spawn_hosted_sec_image_for_image(
    image: nt_exe_image::HostedProcessImageRef<'_>,
    pe: &nt_pe_loader::PeFile,
    fault_ep_c: u64,
    ntdll_base: u64,
    setup_env: bool,
    ldrpinit_rva: u64,
    client_process_id: u64,
    client_thread_id: u64,
) -> img_spawn::SecImageSpawn {
    let runtime = hosted_process_runtime_for_pi(image.pi).unwrap();
    spawn_sec_image(
        image.pi as u64,
        pe,
        fault_ep_c,
        ntdll_base,
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
        ldrpinit_rva,
    )
}

pub(crate) fn hosted_active_image_mirror_for_pi(pi: usize) -> u64 {
    hosted_process_runtime_for_pi(pi)
        .map(|runtime| runtime.active_image_mirror_va)
        .unwrap_or(IMAGE_MIRROR_VA)
}

pub(crate) fn hosted_scratch_base_for_pi(pi: usize) -> u64 {
    hosted_process_runtime_for_pi(pi)
        .map(|runtime| runtime.scratch_base)
        .unwrap_or(SMSS_SCRATCH_BASE)
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
