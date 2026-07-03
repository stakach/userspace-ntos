//! Fixed-layout request/reply payloads (spec §16.4, §17.2–17.5).
//!
//! Every struct is `#[repr(C)]` + `bytemuck::Pod` (safe byte<->struct with no
//! `unsafe` in our code). `Pod` forbids implicit padding, so fields are ordered
//! (and explicit `_reserved` added) to be gap-free; this is our own client/server
//! wire, not a Windows binary layout, so the field order may differ from the
//! spec's illustrative structs. All variable payloads (paths, buffers) live in
//! separate SURT registered buffers, referenced by id + offset + len — never
//! inline pointers. Path payloads are UTF-16LE code units.

use bytemuck::{Pod, Zeroable};

/// `IO_OP_OPEN` — open/create a device path (spec §17.2). The UTF-16 path is at
/// `path_offset`/`path_len_bytes` in the request buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoOpenRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub desired_access: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub path_offset: u32,
    pub path_len_bytes: u32,
}

/// `IO_OP_READ` / `IO_OP_WRITE` — transfer to/from a registered buffer (§17.3).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoReadWriteRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub len: u32,
    pub file_handle: u64,
    pub buffer_id: u64,
    pub offset: u64,
    pub key: u32,
    pub _reserved: u32,
}

/// `IO_OP_DEVICE_CONTROL` / `IO_OP_INTERNAL_CONTROL` — buffered IOCTL (§17.4).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoDeviceControlRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub ioctl_code: u32,
    pub file_handle: u64,
    pub input_buffer_id: u64,
    pub input_offset: u64,
    pub output_buffer_id: u64,
    pub output_offset: u64,
    pub input_len: u32,
    pub output_len: u32,
}

/// `IO_OP_CLEANUP` / `IO_OP_CLOSE` / `IO_OP_FLUSH` — operate on a file handle.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoFileRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub _reserved: u32,
    pub file_handle: u64,
}

/// `IO_OP_CANCEL` — cancel an in-flight request by its id (§17.5).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoCancelRequest {
    pub abi_size: u16,
    pub flags: u16,
    pub _reserved: u32,
    pub request_id: u64,
}

/// `IODRV_OP_DISPATCH_IRP` payload — an IRP projection for a driver peer (§16.4).
/// Variable parameters live after this header in the registered payload buffer.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IrpDispatchRequest {
    pub abi_size: u16,
    pub major: u8,
    pub minor: u8,
    pub flags: u32,
    pub irp_id: u64,
    pub device_id: u64,
    pub file_id: u64,
    pub buffer_id: u64,
    pub buffer_offset: u64,
    pub buffer_len: u32,
    pub parameter_offset: u32,
    pub parameter_len: u32,
    pub _reserved: u32,
}

/// A generic I/O completion (spec §19). Mirrors the SURT CQE fields: `status` is
/// an `NTSTATUS` as `i32`, `information` is `IoStatus.Information` (bytes / result
/// value), `detail0`/`detail1` carry a handle or id per opcode.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoReply {
    pub status: i32,
    pub flags: u32,
    pub information: u64,
    pub detail0: u64,
    pub detail1: u64,
}

// ---------------------------------------------------------------------------
// Compile-time layout guarantees (gap-free, so Pod holds).
// ---------------------------------------------------------------------------
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<IoOpenRequest>() == 28);
    assert!(size_of::<IoReadWriteRequest>() == 40);
    assert!(size_of::<IoDeviceControlRequest>() == 56);
    assert!(size_of::<IoFileRequest>() == 16);
    assert!(size_of::<IoCancelRequest>() == 16);
    assert!(size_of::<IrpDispatchRequest>() == 64);
    assert!(size_of::<IoReply>() == 32);
    assert!(align_of::<IoReadWriteRequest>() == 8);
    assert!(align_of::<IrpDispatchRequest>() == 8);
};
