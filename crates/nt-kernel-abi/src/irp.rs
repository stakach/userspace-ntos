//! `IRP` + `IO_STACK_LOCATION` + `IO_STATUS_BLOCK` projections (spec §7.1).

use bytemuck::{Pod, Zeroable};

use crate::GuestAddr;

/// `LIST_ENTRY` (x64, 16 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ListEntry {
    pub flink: GuestAddr,
    pub blink: GuestAddr,
}

/// `IO_STATUS_BLOCK` (x64, 16 bytes). `status` is an `NTSTATUS`; `information` is
/// the completion byte count / result value.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct IoStatusBlock {
    pub status: i32,
    pub _reserved: u32,
    pub information: u64,
}

/// `IRP` (x64, 208 bytes, 16-byte aligned). The driver reads/writes `io_status`,
/// `associated_irp_system_buffer` (`AssociatedIrp.SystemBuffer` for buffered I/O),
/// `user_buffer`, and the current stack location; the runtime owns the rest.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct Irp {
    pub type_: i16,
    pub size: u16,
    pub _pad0: u32,
    pub mdl_address: GuestAddr,
    pub flags: u32,
    pub _pad1: u32,
    /// `AssociatedIrp` union — the `SystemBuffer` pointer (buffered I/O).
    pub associated_irp_system_buffer: GuestAddr,
    pub thread_list_entry: ListEntry,
    pub io_status: IoStatusBlock,
    pub requestor_mode: i8,
    pub pending_returned: u8,
    pub stack_count: i8,
    pub current_location: i8,
    pub cancel: u8,
    pub cancel_irql: u8,
    pub apc_environment: i8,
    pub allocation_flags: u8,
    pub user_iosb: GuestAddr,
    pub user_event: GuestAddr,
    /// `Overlay` union (async params / allocation size).
    pub _overlay: [u8; 16],
    pub cancel_routine: GuestAddr,
    pub user_buffer: GuestAddr,
    /// `Tail` union up to `Tail.Overlay.CurrentStackLocation` (offset 184).
    pub _tail_pre: [u8; 64],
    /// `Tail.Overlay.CurrentStackLocation` — the driver's current stack location.
    pub current_stack_location: GuestAddr,
    /// Remainder of the `Tail` union.
    pub _tail_post: [u8; 16],
}

/// The `Parameters.DeviceIoControl` view of an `IO_STACK_LOCATION` (x64, 32 bytes).
/// The `POINTER_ALIGNMENT` on the lengths pads them to 8-byte slots.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct DeviceIoControlParams {
    pub output_buffer_length: u32,
    pub _pad0: u32,
    pub input_buffer_length: u32,
    pub _pad1: u32,
    pub io_control_code: u32,
    pub _pad2: u32,
    pub type3_input_buffer: GuestAddr,
}

/// The `Parameters.Read` / `Parameters.Write` view (x64, first 32 bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ReadWriteParams {
    pub length: u32,
    pub _pad0: u32,
    pub key: u32,
    pub _pad1: u32,
    pub byte_offset: u64,
    pub _reserved: u64,
}

/// `IO_STACK_LOCATION` (x64, 72 bytes). `parameters` is the 32-byte per-major
/// union — view it via [`device_io_control`](Self::device_io_control) etc.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Pod, Zeroable)]
pub struct IoStackLocation {
    pub major_function: u8,
    pub minor_function: u8,
    pub flags: u8,
    pub control: u8,
    pub _pad: u32,
    pub parameters: [u64; 4],
    pub device_object: GuestAddr,
    pub file_object: GuestAddr,
    pub completion_routine: GuestAddr,
    pub context: GuestAddr,
}

impl IoStackLocation {
    /// Read the `Parameters` union as `DeviceIoControl`.
    pub fn device_io_control(&self) -> DeviceIoControlParams {
        bytemuck::cast(self.parameters)
    }
    /// Write `DeviceIoControl` parameters.
    pub fn set_device_io_control(&mut self, p: DeviceIoControlParams) {
        self.parameters = bytemuck::cast(p);
    }
    /// Read the `Parameters` union as `Read`/`Write`.
    pub fn read_write(&self) -> ReadWriteParams {
        bytemuck::cast(self.parameters)
    }
    /// Write `Read`/`Write` parameters.
    pub fn set_read_write(&mut self, p: ReadWriteParams) {
        self.parameters = bytemuck::cast(p);
    }
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<IoStatusBlock>() == 16);
    assert!(size_of::<ListEntry>() == 16);
    assert!(size_of::<DeviceIoControlParams>() == 32);
    assert!(size_of::<ReadWriteParams>() == 32);

    assert!(size_of::<Irp>() == 208);
    assert!(align_of::<Irp>() == 16);
    assert!(offset_of!(Irp, associated_irp_system_buffer) == 24);
    assert!(offset_of!(Irp, io_status) == 48);
    assert!(offset_of!(Irp, cancel_routine) == 104);
    assert!(offset_of!(Irp, user_buffer) == 112);
    assert!(offset_of!(Irp, current_stack_location) == 184);

    assert!(size_of::<IoStackLocation>() == 72);
    assert!(offset_of!(IoStackLocation, parameters) == 8);
    assert!(offset_of!(IoStackLocation, device_object) == 40);
    assert!(offset_of!(IoStackLocation, completion_routine) == 56);
};
