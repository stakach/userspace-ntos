//! The Windows version profile (spec §3) + PEB/TEB/KUSER_SHARED_DATA byte-layout builders
//! (spec §10-§12). v0.1 sets required fields at their real x64 offsets; the rest are zero but the
//! offsets exist (spec §11.2).

use alloc::vec;
use alloc::vec::Vec;

/// A pinned Windows version profile (spec §3.1) — the ABI shape official `ntdll` expects.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WindowsProfile {
    pub os_major: u32,
    pub os_minor: u32,
    pub os_build: u16,
    pub platform_id: u32,  // VER_PLATFORM_WIN32_NT = 2
    pub product_type: u32, // NtProductWinNt = 1
    pub number_of_processors: u32,
}

impl WindowsProfile {
    /// Windows 7 SP1 (NT 6.1, build 7601) — the v0.1 pinned target profile (avoids the NT 6.3+
    /// ABI complexity; matches `references/ntdll.dll`).
    pub fn windows7_sp1() -> Self {
        WindowsProfile {
            os_major: 6,
            os_minor: 1,
            os_build: 7601,
            platform_id: 2,  // VER_PLATFORM_WIN32_NT
            product_type: 1, // NtProductWinNt
            number_of_processors: 1,
        }
    }

    /// Windows 11 23H2 (build 22631) — a later profile, not the v0.1 target.
    pub fn windows11_23h2() -> Self {
        WindowsProfile {
            os_major: 10,
            os_minor: 0,
            os_build: 22631,
            platform_id: 2,
            product_type: 1,
            number_of_processors: 1,
        }
    }
}

/// The Windows-compatible fixed user VA of `KUSER_SHARED_DATA` on x64 (spec §12.1).
pub const KUSER_SHARED_DATA_VA: u64 = 0x0000_0000_7FFE_0000;

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
/// Read a `u64` at `off` (for tests + the host verifying its own layout).
pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

// x64 PEB field offsets (spec §10.2).
pub mod peb_off {
    pub const BEING_DEBUGGED: usize = 0x02;
    pub const IMAGE_BASE_ADDRESS: usize = 0x10;
    pub const LDR: usize = 0x18;
    pub const PROCESS_PARAMETERS: usize = 0x20;
    pub const PROCESS_HEAP: usize = 0x30;
    pub const NUMBER_OF_PROCESSORS: usize = 0xB8;
    pub const NT_GLOBAL_FLAG: usize = 0xBC;
    pub const OS_MAJOR_VERSION: usize = 0x118;
    pub const OS_MINOR_VERSION: usize = 0x11C;
    pub const OS_BUILD_NUMBER: usize = 0x120;
    pub const OS_PLATFORM_ID: usize = 0x124;
    pub const SESSION_ID: usize = 0x2C0;
    pub const SIZE: usize = 0x380;
}

/// Build a v0.1 PEB (spec §10.2): version fields + the loader/params/heap/image-base pointers.
pub fn build_peb(
    profile: &WindowsProfile,
    image_base: u64,
    ldr: u64,
    process_parameters: u64,
    process_heap: u64,
) -> Vec<u8> {
    let mut peb = vec![0u8; peb_off::SIZE];
    peb[peb_off::BEING_DEBUGGED] = 0;
    put_u64(&mut peb, peb_off::IMAGE_BASE_ADDRESS, image_base);
    put_u64(&mut peb, peb_off::LDR, ldr);
    put_u64(&mut peb, peb_off::PROCESS_PARAMETERS, process_parameters);
    put_u64(&mut peb, peb_off::PROCESS_HEAP, process_heap);
    put_u32(
        &mut peb,
        peb_off::NUMBER_OF_PROCESSORS,
        profile.number_of_processors,
    );
    put_u32(&mut peb, peb_off::OS_MAJOR_VERSION, profile.os_major);
    put_u32(&mut peb, peb_off::OS_MINOR_VERSION, profile.os_minor);
    put_u16(&mut peb, peb_off::OS_BUILD_NUMBER, profile.os_build);
    put_u32(&mut peb, peb_off::OS_PLATFORM_ID, profile.platform_id);
    put_u32(&mut peb, peb_off::SESSION_ID, 1);
    peb
}

// x64 TEB field offsets (spec §11.2). NT_TIB is at the top.
pub mod teb_off {
    pub const STACK_BASE: usize = 0x08; // NT_TIB.StackBase
    pub const STACK_LIMIT: usize = 0x10; // NT_TIB.StackLimit
    pub const SELF: usize = 0x30; // NT_TIB.Self
    pub const CLIENT_ID_PROCESS: usize = 0x40;
    pub const CLIENT_ID_THREAD: usize = 0x48;
    pub const PEB: usize = 0x60; // ProcessEnvironmentBlock
    pub const LAST_ERROR: usize = 0x68; // LastErrorValue
    pub const TLS_SLOTS: usize = 0x1480; // 64 * u64
    pub const SIZE: usize = 0x1800;
}

/// Build a v0.1 TEB (spec §11.2): NT_TIB (StackBase/Limit/Self), ClientId, the PEB pointer.
pub fn build_teb(
    teb_va: u64,
    peb_va: u64,
    stack_base: u64,
    stack_limit: u64,
    process_id: u32,
    thread_id: u32,
) -> Vec<u8> {
    let mut teb = vec![0u8; teb_off::SIZE];
    put_u64(&mut teb, teb_off::STACK_BASE, stack_base);
    put_u64(&mut teb, teb_off::STACK_LIMIT, stack_limit);
    put_u64(&mut teb, teb_off::SELF, teb_va); // NT_TIB.Self points at the TEB
    put_u64(&mut teb, teb_off::CLIENT_ID_PROCESS, process_id as u64);
    put_u64(&mut teb, teb_off::CLIENT_ID_THREAD, thread_id as u64);
    put_u64(&mut teb, teb_off::PEB, peb_va);
    put_u32(&mut teb, teb_off::LAST_ERROR, 0);
    teb
}

// KUSER_SHARED_DATA field offsets (spec §12.2).
pub mod kuser_off {
    pub const TICK_COUNT_LOW: usize = 0x00;
    pub const TICK_COUNT_MULTIPLIER: usize = 0x04;
    pub const SYSTEM_TIME_LOW: usize = 0x14; // KSYSTEM_TIME { LowPart, High1Time, High2Time }
    pub const NT_PRODUCT_TYPE: usize = 0x264;
    pub const PRODUCT_TYPE_IS_VALID: usize = 0x268;
    pub const NT_MAJOR_VERSION: usize = 0x26C;
    pub const NT_MINOR_VERSION: usize = 0x270;
    pub const PROCESSOR_FEATURES: usize = 0x274; // u8[64]
    pub const SIZE: usize = 0x1000; // one page
}

/// Build the read-only `KUSER_SHARED_DATA` page (spec §12.2): version + a plausible system time.
pub fn build_kuser_shared_data(
    profile: &WindowsProfile,
    system_time_100ns: u64,
    tick_count: u32,
) -> Vec<u8> {
    let mut k = vec![0u8; kuser_off::SIZE];
    put_u32(&mut k, kuser_off::TICK_COUNT_LOW, tick_count);
    put_u32(&mut k, kuser_off::TICK_COUNT_MULTIPLIER, 0x0FA0_0000);
    // SystemTime as a KSYSTEM_TIME (High1 == High2 for a stable read).
    put_u32(&mut k, kuser_off::SYSTEM_TIME_LOW, system_time_100ns as u32);
    put_u32(
        &mut k,
        kuser_off::SYSTEM_TIME_LOW + 4,
        (system_time_100ns >> 32) as u32,
    );
    put_u32(
        &mut k,
        kuser_off::SYSTEM_TIME_LOW + 8,
        (system_time_100ns >> 32) as u32,
    );
    put_u32(&mut k, kuser_off::NT_PRODUCT_TYPE, profile.product_type);
    k[kuser_off::PRODUCT_TYPE_IS_VALID] = 1;
    put_u32(&mut k, kuser_off::NT_MAJOR_VERSION, profile.os_major);
    put_u32(&mut k, kuser_off::NT_MINOR_VERSION, profile.os_minor);
    k[kuser_off::PROCESSOR_FEATURES] = 1; // at least one feature bit plausible
    k
}
