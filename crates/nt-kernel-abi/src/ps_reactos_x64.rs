//! Neutral Ps projections for the ReactOS Win2003 AMD64 profile.
//!
//! These local provider bytes are not canonical process/thread authority. Initialize fresh,
//! unpublished storage only; never reinitialize a live projection to select a GUI caller.
//! Offsets follow `sdk/include/ndk/{ke,ps}types.h` and `ndk/tests/win2003_x64.c`.
//! ReactOS adds `KTHREAD.StateSaveArea` at 0x320, shifting ETHREAD fields by eight
//! bytes relative to Windows 2003. Its final `ThreadName` is at 0x430.

use crate::GuestAddr;

/// Conservative projection capacity, not a claim about sizeof(EPROCESS).
pub const EPROCESS_BODY_BYTES: usize = 0x1000;
/// Includes ReactOS's final ThreadName pointer; 0x400 truncates the real flags.
pub const ETHREAD_BODY_BYTES: usize = 0x438;
pub const KPROCESS_BYTES: usize = 0xb0;
pub const KTHREAD_BYTES: usize = 0x328;

pub const EPROCESS_UNIQUE_PROCESS_ID: usize = 0xd0;
pub const EPROCESS_WIN32_PROCESS: usize = 0x1d8;
pub const EPROCESS_THREAD_LIST_HEAD: usize = 0x288;
pub const EPROCESS_PEB: usize = 0x2b8;
pub const KTHREAD_APC_STATE: usize = 0x48;
pub const KTHREAD_APC_STATE_PROCESS: usize = 0x68;
pub const KTHREAD_TEB: usize = 0xb0;
pub const KTHREAD_PREVIOUS_MODE: usize = 0x153;
pub const KTHREAD_PROCESS: usize = 0x200;
pub const KTHREAD_APC_STATE_POINTERS: usize = 0x210;
pub const KTHREAD_SAVED_APC_STATE: usize = 0x220;
pub const KTHREAD_WIN32_THREAD: usize = 0x250;
pub const ETHREAD_CLIENT_ID_PROCESS: usize = 0x378;
pub const ETHREAD_CLIENT_ID_THREAD: usize = 0x380;
pub const ETHREAD_THREADS_PROCESS: usize = 0x3d8;
pub const ETHREAD_CROSS_THREAD_FLAGS: usize = 0x41c;
pub const ETHREAD_THREAD_NAME: usize = 0x430;
pub const ETHREAD_SYSTEM_THREAD: u32 = 1 << 4;

const DISPATCHER_WAIT_LIST: usize = 8;
const PROCESS_LIST_HEADS: &[usize] = &[
    DISPATCHER_WAIT_LIST,
    0x18, // KPROCESS.ProfileListHead
    0x50, // KPROCESS.ReadyListHead
    0x70, // KPROCESS.ThreadListHead
    EPROCESS_THREAD_LIST_HEAD,
];
const THREAD_LIST_HEADS: &[usize] = &[
    DISPATCHER_WAIT_LIST,
    0x18, // KTHREAD.MutantListHead
    KTHREAD_APC_STATE,
    KTHREAD_APC_STATE + 0x10,
    0x330, // ETHREAD.LpcReplyChain
    0x348, // ETHREAD.PostBlockList
    0x368, // ETHREAD.ActiveTimerListHead
    0x3b8, // ETHREAD.IrpList
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    BufferTooSmall,
    NullBody,
    UnalignedAddress,
    AddressOverflow,
    InvalidProcessId,
    InvalidThreadId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessInitialization {
    pub body: GuestAddr,
    pub process_id: u64,
    /// An actual PEB address, or NULL for processes such as System.
    pub peb: GuestAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadInitialization {
    pub body: GuestAddr,
    pub process_body: GuestAddr,
    pub process_id: u64,
    pub thread_id: u64,
    /// An actual TEB address, or NULL for kernel threads.
    pub teb: GuestAddr,
    pub system_thread: bool,
}

fn aligned(address: GuestAddr) -> Result<(), ProjectionError> {
    if address.0 & 7 != 0 {
        return Err(ProjectionError::UnalignedAddress);
    }
    Ok(())
}

fn body_range(address: GuestAddr, bytes: usize) -> Result<(), ProjectionError> {
    if address.is_null() {
        return Err(ProjectionError::NullBody);
    }
    aligned(address)?;
    address
        .0
        .checked_add(bytes as u64)
        .ok_or(ProjectionError::AddressOverflow)?;
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn empty_lists(bytes: &mut [u8], body: GuestAddr, offsets: &[usize]) {
    for &offset in offsets {
        let address = body.0 + offset as u64;
        write_u64(bytes, offset, address);
        write_u64(bytes, offset + 8, address);
    }
}

/// Initialize the identity and empty-list fields established by KeInitializeProcess and
/// PspCreateProcess. All validation precedes writes. Trailing caller storage is untouched.
/// This does not install a token, address space, scheduler state, PEB substitute, or GUI data.
pub fn initialize_process(
    output: &mut [u8],
    init: ProcessInitialization,
) -> Result<(), ProjectionError> {
    if output.len() < EPROCESS_BODY_BYTES {
        return Err(ProjectionError::BufferTooSmall);
    }
    body_range(init.body, EPROCESS_BODY_BYTES)?;
    aligned(init.peb)?;
    if init.process_id == 0 {
        return Err(ProjectionError::InvalidProcessId);
    }
    let output = &mut output[..EPROCESS_BODY_BYTES];
    output.fill(0);
    output[0] = 3; // ProcessObject
    output[2] = (KPROCESS_BYTES / 4) as u8;
    empty_lists(output, init.body, PROCESS_LIST_HEADS);
    write_u64(output, EPROCESS_UNIQUE_PROCESS_ID, init.process_id);
    write_u64(output, EPROCESS_PEB, init.peb.0);
    Ok(())
}

/// Initialize the neutral fields established by KeInitThread and PspCreateThread. Stack,
/// scheduler, token/impersonation, service-table and GUI fields remain zero until their actual
/// owners publish them. PreviousMode starts as KernelMode, not an inferred user-mode value.
pub fn initialize_thread(
    output: &mut [u8],
    init: ThreadInitialization,
) -> Result<(), ProjectionError> {
    if output.len() < ETHREAD_BODY_BYTES {
        return Err(ProjectionError::BufferTooSmall);
    }
    body_range(init.body, ETHREAD_BODY_BYTES)?;
    body_range(init.process_body, EPROCESS_BODY_BYTES)?;
    aligned(init.teb)?;
    if init.process_id == 0 {
        return Err(ProjectionError::InvalidProcessId);
    }
    if init.thread_id == 0 {
        return Err(ProjectionError::InvalidThreadId);
    }
    let output = &mut output[..ETHREAD_BODY_BYTES];
    output.fill(0);
    output[0] = 6; // ThreadObject; the remaining dispatcher union bytes are flags, not Size.
    empty_lists(output, init.body, THREAD_LIST_HEADS);
    write_u64(output, KTHREAD_APC_STATE_PROCESS, init.process_body.0);
    write_u64(
        output,
        KTHREAD_APC_STATE_POINTERS,
        init.body.0 + KTHREAD_APC_STATE as u64,
    );
    write_u64(
        output,
        KTHREAD_APC_STATE_POINTERS + 8,
        init.body.0 + KTHREAD_SAVED_APC_STATE as u64,
    );
    write_u64(output, KTHREAD_TEB, init.teb.0);
    write_u64(output, KTHREAD_PROCESS, init.process_body.0);
    write_u64(output, ETHREAD_CLIENT_ID_PROCESS, init.process_id);
    write_u64(output, ETHREAD_CLIENT_ID_THREAD, init.thread_id);
    write_u64(output, ETHREAD_THREADS_PROCESS, init.process_body.0);
    let flags = if init.system_thread {
        ETHREAD_SYSTEM_THREAD
    } else {
        0
    };
    output[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

#[cfg(test)]
#[path = "ps_reactos_x64_tests.rs"]
mod tests;
