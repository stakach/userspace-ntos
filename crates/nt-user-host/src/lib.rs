//! # `nt-user-host` — User Process Host + official ntdll bootstrap
//!
//! The seL4-hosted user-mode side (spec: NT User Process Host + Official ntdll Bootstrap): the
//! [`WindowsProfile`], PEB/TEB/`KUSER_SHARED_DATA` byte-layout builders, a [`UserProcessHost`] that
//! owns a process ([`nt_process`]) + its PEB/TEB/KUSER user VAs, and [`KernelServices`] — the
//! [`nt_syscall::NativeSyscallHandler`] that wires the native syscall dispatcher to the real
//! subsystems (registry / filesystem / address space / process manager / KUSER time). `no_std` + `alloc`.

#![no_std]

extern crate alloc;

mod profile;
mod services;

use alloc::vec::Vec;

pub use profile::{
    build_kuser_shared_data, build_peb, build_teb, kuser_off, peb_off, read_u32, read_u64, teb_off,
    WindowsProfile, KUSER_SHARED_DATA_VA,
};
pub use services::KernelServices;

// A deterministic user-VA layout for the first hosted process (spec §14).
const PEB_VA: u64 = 0x0000_0001_0000_0000;
const TEB_VA: u64 = 0x0000_0001_0001_0000;
const IMAGE_BASE_VA: u64 = 0x0000_0001_4000_0000;
const STACK_BASE: u64 = 0x0000_0001_0010_0000;
const STACK_LIMIT: u64 = 0x0000_0001_000F_0000; // 64 KiB stack

/// A hosted user process: the [`nt_process`] process + its PEB/TEB/KUSER user-mode structures
/// (spec §8.2). v0.1 builds the structures eagerly at fixed VAs.
pub struct UserProcessHost {
    profile: WindowsProfile,
    process_id: u32,
    main_thread_id: u32,
    peb: Vec<u8>,
    teb: Vec<u8>,
    kuser: Vec<u8>,
}

impl UserProcessHost {
    /// Launch a hosted process from a [`KernelServices`] (spec §8.1, §14): create the process +
    /// its main thread, and build the PEB/TEB/`KUSER_SHARED_DATA` for the profile.
    pub fn launch(services: &mut KernelServices, image_file_name: &str, entry_point: u64) -> Self {
        let profile = services.profile;
        let pid = services.pm.create_process(image_file_name, None, None);
        let tid = services
            .pm
            .create_thread(pid, entry_point, 0, false)
            .unwrap();

        let peb = build_peb(&profile, IMAGE_BASE_VA, 0, 0, 0);
        let teb = build_teb(TEB_VA, PEB_VA, STACK_BASE, STACK_LIMIT, pid, tid);
        let kuser = build_kuser_shared_data(&profile, services.system_time_100ns, 1);

        UserProcessHost {
            profile,
            process_id: pid,
            main_thread_id: tid,
            peb,
            teb,
            kuser,
        }
    }

    pub fn process_id(&self) -> u32 {
        self.process_id
    }
    pub fn main_thread_id(&self) -> u32 {
        self.main_thread_id
    }
    pub fn profile(&self) -> WindowsProfile {
        self.profile
    }
    pub fn peb(&self) -> &[u8] {
        &self.peb
    }
    pub fn teb(&self) -> &[u8] {
        &self.teb
    }
    pub fn kuser_shared_data(&self) -> &[u8] {
        &self.kuser
    }
    pub fn peb_va(&self) -> u64 {
        PEB_VA
    }
    pub fn teb_va(&self) -> u64 {
        TEB_VA
    }
}

#[cfg(test)]
mod tests;
