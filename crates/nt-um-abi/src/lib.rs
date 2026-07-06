//! Shared ABI for the out-of-process (isolated) driver model.
//!
//! The driver-host root task (the "NT kernel") and each isolated `driver-host-um`
//! driver component compile against these same constants so their SURT reflector
//! ring, shared data frames, protocol, and capability layout line up across the
//! address-space boundary. `no_std`, no dependencies — the single source of truth.

#![no_std]

// --- Shared-frame vaddrs (identical in both address spaces) ------------------
// All live in one 2 MiB page table [0x1_0080_0000, 0x1_009F_FFFF]; the isolated
// driver's own image is linked at UM_IMAGE_BASE within the same table.
/// Submission ring (`SurtSqe`): the driver produces requests, the kernel consumes.
pub const SUB_RING_VADDR: u64 = 0x0000_0100_0080_0000;
/// Completion ring (`SurtCqe`): the kernel produces replies, the driver consumes.
pub const COMP_RING_VADDR: u64 = 0x0000_0100_0080_1000;
/// Request payload frame (the driver writes; the kernel reads `[..len]`).
pub const REQ_DATA_VADDR: u64 = 0x0000_0100_0080_2000;
/// Reply payload frame (the kernel writes; the driver reads `[..information]`).
pub const REP_DATA_VADDR: u64 = 0x0000_0100_0080_3000;
/// Base of the isolated driver's 16 KiB stack.
pub const STACK_BASE: u64 = 0x0000_0100_0080_8000;
/// Stack size in 4 KiB frames.
pub const STACK_FRAMES: u64 = 4;
/// The isolated driver's IPC buffer.
pub const IPCBUF_VADDR: u64 = 0x0000_0100_0080_F000;
/// Link base of the isolated driver's own ELF image (private frames, its own code+data).
pub const UM_IMAGE_BASE: u64 = 0x0000_0100_0090_0000;

/// SURT ring frame length (one 4 KiB frame per ring).
pub const RING_LEN: usize = 4096;
/// SURT ring queue depth.
pub const QLEN: u32 = 8;

// --- The driver's own CNode cptr slots (radix-5, guard-59 → direct indexing) -
pub const CT_PML4: u64 = 2;
pub const CT_N_SUB: u64 = 3;
pub const CT_N_COMP: u64 = 4;
pub const CT_RESULT: u64 = 5;
pub const CT_FAULT: u64 = 6;
pub const CN_RADIX: u32 = 5;
pub const CN_GUARD_BADGE: u64 = 59;

// --- Reflector protocol ------------------------------------------------------
/// Open the device interface named by the GUID (req = GUID utf8) → `detail0` = device
/// handle, reply frame = symbolic link.
pub const OP_OPEN: u16 = 1;
/// Issue an IOCTL (`user_data` = device handle, req = `[ioctl:u32]`) → reply frame = output.
pub const OP_IOCTL: u16 = 2;
/// The driver reached a healthy uptime checkpoint (no payload). The supervisor uses this to
/// distinguish a rapid startup crash from a transient fault after the driver stabilized.
pub const OP_HEALTHY: u16 = 3;

// --- Behavior profile the supervisor passes to the driver (arg0 / rdi) -------
/// `arg0` layout: low 8 bits = profile, next 8 bits = attempt number.
pub const fn arg_profile(arg0: u64) -> u8 {
    (arg0 & 0xFF) as u8
}
pub const fn arg_attempt(arg0: u64) -> u8 {
    ((arg0 >> 8) & 0xFF) as u8
}
pub const fn make_arg(profile: u8, attempt: u8) -> u64 {
    (profile as u64) | ((attempt as u64) << 8)
}
/// Profile: crash rapidly on every spawn (a genuinely broken driver → crash loop → disable).
pub const PROFILE_ALWAYS_CRASH: u8 = 0;
/// Profile: crash once (attempt 0), then run healthy (proves restart recovery + counter reset).
pub const PROFILE_RECOVER: u8 = 1;
/// Profile: host a REAL UMDF v2 driver's full lifecycle inside this isolated process
/// (DriverEntry + EvtDeviceAdd + device create + IOCTLs), then report health. The driver
/// runs entirely in the isolated VSpace; a crash is caught by the supervisor.
pub const PROFILE_HOST_UMDF: u8 = 2;

/// Where the parent maps a read/write/EXECUTE window for the isolated host to load the
/// UMDF v2 driver image into (the isolated host has no untyped, so it can't make memory
/// executable itself — the parent provides the RWX window). Inside the host's own PT,
/// past its image.
pub const UMDF_DLL_VADDR: u64 = 0x0000_0100_0098_0000;
/// Frames of the RWX driver-image window (covers the DLL's SizeOfImage 0xd000 + slack).
pub const UMDF_DLL_FRAMES: u64 = 16;

// --- KMDF device-interface identifiers (the device the driver reaches) -------
pub const KMDF_IFACE_GUID: &str = "{9a7b0b24-6e57-4c51-ad3c-6d9f5f0e0001}";
pub const KMDF_IOCTL_PING: u32 = 0x0022_2200;
pub const KMDF_PING_MAGIC: u32 = 0x4946_4B4D; // "MKFI"

/// `NTSTATUS` success, carried in `SurtCqe.status`.
pub const STATUS_SUCCESS: i32 = 0;
