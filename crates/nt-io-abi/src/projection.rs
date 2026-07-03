//! Driver Host projection records (spec §4.3, §9 M9).
//!
//! When the I/O Manager hands work to an isolated Driver Host peer it sends
//! **local projections** — never canonical pointers (spec §4.2). These are the
//! stable, fixed-layout compatibility structures a peer's runtime projects for a
//! loaded driver: a `DRIVER_OBJECT` / `DEVICE_OBJECT` / `FILE_OBJECT` /
//! `IO_STACK_LOCATION` view carrying only ids + scalars. The IRP projection
//! itself is [`crate::IrpDispatchRequest`].

use bytemuck::{Pod, Zeroable};

/// Driver-peer completion flags carried in the dispatch CQE (spec §16.5).
pub mod cqe_flags {
    /// The peer completed the IRP synchronously; this is the final status.
    pub const IODRV_CQE_FINAL: u32 = 0x0000_0001;
    /// The peer accepted the IRP as pending; a final completion follows on the
    /// reverse ring (`IODRV_OP_COMPLETE_IRP`).
    pub const IODRV_CQE_PENDING_ACCEPTED: u32 = 0x0000_0002;
}

/// A peer's view of its `DRIVER_OBJECT` (spec §4.3). Ids + scalars only.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DriverObjectProjection {
    pub driver_id: u64,
    pub flags: u32,
    pub device_count: u32,
}

/// A peer's view of a `DEVICE_OBJECT` (spec §4.3).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DeviceObjectProjection {
    pub device_id: u64,
    pub driver_id: u64,
    pub device_type: u32,
    pub characteristics: u32,
    pub flags: u32,
    pub extension_size: u32,
    pub alignment_requirement: u32,
    pub stack_size: u32,
}

/// A peer's view of a `FILE_OBJECT` (spec §4.3).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct FileObjectProjection {
    pub file_id: u64,
    pub device_id: u64,
    pub flags: u32,
    pub _reserved: u32,
}

/// A peer's view of an `IO_STACK_LOCATION` (spec §4.3, §13.3). The `parameters`
/// array is the raw per-major parameter words (interpreted by major function).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoStackLocationProjection {
    pub major: u8,
    pub minor: u8,
    pub flags: u16,
    pub control: u16,
    pub _reserved: u16,
    pub device_id: u64,
    pub file_id: u64,
    pub parameters: [u64; 3],
}

// ---------------------------------------------------------------------------
// Compile-time layout guarantees (gap-free, so Pod holds).
// ---------------------------------------------------------------------------
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<DriverObjectProjection>() == 16);
    assert!(size_of::<DeviceObjectProjection>() == 40);
    assert!(size_of::<FileObjectProjection>() == 24);
    assert!(size_of::<IoStackLocationProjection>() == 48);
    assert!(align_of::<DeviceObjectProjection>() == 8);
    assert!(align_of::<IoStackLocationProjection>() == 8);
};
