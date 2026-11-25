//! Driver-local Win64 `IoConnectInterruptEx` adapter for the existing IRQ grant broker.

use super::*;

const CONNECT_FULLY_SPECIFIED: u32 = 1;
const CONNECT_LINE_BASED: u32 = 2;
const CONNECT_FULLY_SPECIFIED_GROUP: u32 = 4;

// ReactOS/WDK IO_CONNECT_INTERRUPT_PARAMETERS: Version at 0, union at 8.
// The full variant also defines the size of the union on x64.
#[repr(C)]
struct FullySpecified {
    pdo: u64,
    interrupt_object_out: u64,
    service_routine: u64,
    service_context: u64,
    spin_lock: u64,
    synchronize_irql: u8,
    floating_save: u8,
    share_vector: u8,
    vector: u32,
    irql: u8,
    mode: u32,
    affinity: u64,
    group: u16,
}

#[repr(C)]
struct ConnectParameters {
    version: u32,
    fields: FullySpecified,
}

const _: () = assert!(core::mem::size_of::<FullySpecified>() == 72);
const _: () = assert!(core::mem::size_of::<ConnectParameters>() == 80);
const _: () = assert!(core::mem::offset_of!(ConnectParameters, fields) == 8);
const _: () = assert!(core::mem::offset_of!(FullySpecified, synchronize_irql) == 40);
const _: () = assert!(core::mem::offset_of!(FullySpecified, vector) == 44);
const _: () = assert!(core::mem::offset_of!(FullySpecified, mode) == 52);
const _: () = assert!(core::mem::offset_of!(FullySpecified, group) == 64);

// Read only fields defined by the selected union variant. C callers need not initialize
// padding or the trailing full-specific fields of a line-based request.
unsafe fn field<T: Copy>(address: u64, offset: usize) -> T {
    read_unaligned((address + offset as u64) as *const T)
}

macro_rules! full_field {
    ($base:expr, $name:ident, $ty:ty) => {
        unsafe { field::<$ty>($base, core::mem::offset_of!(FullySpecified, $name)) }
    };
}

/// `NTSTATUS IoConnectInterruptEx(PIO_CONNECT_INTERRUPT_PARAMETERS)`.
/// The parameter buffer and returned PKINTERRUPT remain in the driver's VSpace.
pub(super) extern "win64" fn s_io_connect_interrupt_ex(parameters: u64) -> i32 {
    if parameters == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(fields) = parameters
        .checked_add(core::mem::offset_of!(ConnectParameters, fields) as u64)
        .filter(|base| {
            base.checked_add(core::mem::size_of::<FullySpecified>() as u64)
                .is_some()
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let version: u32 = unsafe { field(parameters, 0) };
    let pdo: u64 = full_field!(fields, pdo, u64);
    match version {
        CONNECT_FULLY_SPECIFIED | CONNECT_FULLY_SPECIFIED_GROUP => {
            let group: u16 = if version == CONNECT_FULLY_SPECIFIED_GROUP {
                full_field!(fields, group, u16)
            } else {
                0
            };
            if group != 0 {
                // The hosted grant exposes one 64-bit processor group only.
                return STATUS_NOT_SUPPORTED;
            }
            s_io_connect_interrupt_selected(
                full_field!(fields, interrupt_object_out, u64) as *mut u64,
                full_field!(fields, service_routine, u64),
                full_field!(fields, service_context, u64),
                full_field!(fields, spin_lock, u64),
                full_field!(fields, vector, u32),
                full_field!(fields, irql, u8),
                full_field!(fields, synchronize_irql, u8),
                full_field!(fields, mode, u32),
                full_field!(fields, share_vector, u8),
                full_field!(fields, affinity, u64),
                full_field!(fields, floating_save, u8),
                pdo,
                false,
            )
        }
        CONNECT_LINE_BASED => {
            if pdo == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            // The line-based union ends after FloatingSave; it has no ShareVector
            // field. Root supplies sharing policy from the selected PDO grant.
            let requested_sync_irql: u8 = full_field!(fields, synchronize_irql, u8);
            s_io_connect_interrupt_selected(
                full_field!(fields, interrupt_object_out, u64) as *mut u64,
                full_field!(fields, service_routine, u64),
                full_field!(fields, service_context, u64),
                full_field!(fields, spin_lock, u64),
                0,
                0,
                requested_sync_irql,
                0,
                0,
                0,
                full_field!(fields, floating_save, u8),
                pdo,
                true,
            )
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

/// `VOID IoDisconnectInterruptEx(PIO_DISCONNECT_INTERRUPT_PARAMETERS)`.
/// Only the object returned by the active grant-owned connection may be retired.
pub(super) extern "win64" fn s_io_disconnect_interrupt_ex(parameters: u64) {
    if parameters == 0 || parameters.checked_add(16).is_none() {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x49524458, parameters, 0, 0]) }
    }
    let version: u32 = unsafe { field(parameters, 0) };
    if !matches!(version, CONNECT_FULLY_SPECIFIED | CONNECT_LINE_BASED | CONNECT_FULLY_SPECIFIED_GROUP) {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x49524458, parameters, version as u64, 1]) }
    }
    let connection: u64 = unsafe { field(parameters, 8) };
    if connection == 0 {
        return;
    }
    if !disconnect_hosted_interrupt(connection) {
        unsafe { crate::provider_bugcheck::report(0xc4, [0x49524458, connection, version as u64, 3]) }
    }
}
