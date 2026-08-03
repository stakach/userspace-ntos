//! Hosted-process runtime placement and SEC_IMAGE spawn helpers.
//!
//! This module contains the fixed per-process mechanism layout that still needs to become a real
//! allocator. Keeping it out of the syscall service loop makes the remaining tech debt explicit.
#![allow(clippy::all)]
use crate::*;

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
}

pub(crate) fn register_hosted_process_runtime(
    runtime: HostedProcessRuntime,
) -> Result<(), HostedProcessRuntimeRegistrationError> {
    unsafe { (&mut *core::ptr::addr_of_mut!(HOSTED_PROCESS_RUNTIMES)).register(runtime) }
}

pub(crate) fn hosted_process_runtime_for_pi(pi: usize) -> Option<HostedProcessRuntime> {
    unsafe { (&*core::ptr::addr_of!(HOSTED_PROCESS_RUNTIMES)).get_by_pi(pi) }
}

pub(crate) const SMSS_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 0,
    priority: 100,
    env_scratch_va: 0x0000_0100_1074_0000,
    stack_mirror_va: SMSS_STACK_MIRROR_VA,
    heap_mirror_va: SMSS_HEAP_MIRROR_VA,
    active_image_mirror_va: IMAGE_MIRROR_VA,
    spawn_image_mirror_va: 0,
    scratch_base: SMSS_SCRATCH_BASE,
    spawned: None,
};

pub(crate) const CSRSS_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 1,
    priority: 101,
    env_scratch_va: 0x0000_0100_1078_0000,
    stack_mirror_va: CSRSS_STACK_MIRROR_VA,
    heap_mirror_va: CSRSS_HEAP_MIRROR_VA,
    active_image_mirror_va: CSRSS_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: 0,
    scratch_base: CSRSS_SCRATCH_BASE,
    spawned: Some(&CSRSS_SPAWNED),
};

pub(crate) const WINLOGON_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 2,
    priority: 102,
    env_scratch_va: WINLOGON_MAIN_TEB_MIRROR_VA,
    stack_mirror_va: WINLOGON_STACK_MIRROR_VA,
    heap_mirror_va: WINLOGON_HEAP_MIRROR_VA,
    active_image_mirror_va: WINLOGON_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: WINLOGON_IMAGE_MIRROR_VA,
    scratch_base: WINLOGON_SCRATCH_BASE,
    spawned: Some(&WINLOGON_SPAWNED),
};

pub(crate) const SERVICES_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 3,
    priority: 103,
    env_scratch_va: SERVICES_ENV_SCRATCH_VA,
    stack_mirror_va: SERVICES_STACK_MIRROR_VA,
    heap_mirror_va: SERVICES_HEAP_MIRROR_VA,
    active_image_mirror_va: SERVICES_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: SERVICES_IMAGE_MIRROR_VA,
    scratch_base: SERVICES_SCRATCH_BASE,
    spawned: Some(&SERVICES_SPAWNED),
};

pub(crate) const LSASS_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 4,
    priority: 104,
    env_scratch_va: LSASS_ENV_SCRATCH_VA,
    stack_mirror_va: LSASS_STACK_MIRROR_VA,
    heap_mirror_va: LSASS_HEAP_MIRROR_VA,
    active_image_mirror_va: LSASS_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: LSASS_IMAGE_MIRROR_VA,
    scratch_base: LSASS_SCRATCH_BASE,
    spawned: Some(&LSASS_SPAWNED),
};

pub(crate) const USERINIT_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 5,
    priority: 105,
    env_scratch_va: USERINIT_ENV_SCRATCH_VA,
    stack_mirror_va: USERINIT_STACK_MIRROR_VA,
    heap_mirror_va: USERINIT_HEAP_MIRROR_VA,
    active_image_mirror_va: USERINIT_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: USERINIT_IMAGE_MIRROR_VA,
    scratch_base: USERINIT_SCRATCH_BASE,
    spawned: Some(&USERINIT_SPAWNED),
};

pub(crate) const EXPLORER_PROCESS_RUNTIME: HostedProcessRuntime = HostedProcessRuntime {
    pi: 6,
    priority: 106,
    env_scratch_va: EXPLORER_ENV_SCRATCH_VA,
    stack_mirror_va: EXPLORER_STACK_MIRROR_VA,
    heap_mirror_va: EXPLORER_HEAP_MIRROR_VA,
    active_image_mirror_va: EXPLORER_IMAGE_MIRROR_VA,
    spawn_image_mirror_va: EXPLORER_IMAGE_MIRROR_VA,
    scratch_base: EXPLORER_SCRATCH_BASE,
    spawned: Some(&EXPLORER_SPAWNED),
};

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
    ntdll_base: u64,
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
