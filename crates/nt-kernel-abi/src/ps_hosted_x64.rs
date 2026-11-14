//! Neutral Ps projections for the hosted x64 driver and Win32k images.
//!
//! These local provider bytes are not canonical process/thread authority. Initialize fresh,
//! unpublished storage only; never reinitialize a live projection to select a GUI caller.
//!
//! The layout is the pinned LiberNT release's (commit 8e478a22): the AMD64 `KTHREAD` and
//! `KPROCESS` of `sdk/include/ndk/ketypes.h` (Windows 11 26100 offsets, with the ReactOS
//! scheduler fields in spare slots) and the `ETHREAD` and `EPROCESS` of
//! `sdk/include/ndk/pstypes.h` built on them. Every hosted kernel-mode image of the release is
//! compiled against those headers, and win32k.sys reads several fields itself instead of
//! calling the kernel, so a field published anywhere else is simply absent for it.
//! [`PINNED_LAYOUT`] ties each offset to its declaration; the release's ntoskrnl.exe accessors
//! and win32k.sys instructions are checked against the same table when the image is cached.

use crate::GuestAddr;

/// Conservative projection capacity; the pinned `sizeof(EPROCESS)` is [`EPROCESS_BYTES`].
pub const EPROCESS_BODY_BYTES: usize = 0x1000;
/// `sizeof(EPROCESS)`: the body size the pinned `PspCreateProcess` asks the object manager for.
pub const EPROCESS_BYTES: usize = 0x840;
/// `sizeof(ETHREAD)`: the body size the pinned `PspCreateThread` asks the object manager for.
pub const ETHREAD_BODY_BYTES: usize = 0x6c0;
pub const KPROCESS_BYTES: usize = 0x1c8;
pub const KTHREAD_BYTES: usize = 0x4c0;

pub const EPROCESS_UNIQUE_PROCESS_ID: usize = 0x1d0;
pub const EPROCESS_WIN32_PROCESS: usize = 0x298;
/// The base of the process image section, as `PsGetProcessSectionBaseAddress` returns it.
pub const EPROCESS_SECTION_BASE_ADDRESS: usize = 0x2b0;
/// The handle `PsSetProcessWindowStation` stores and `PsGetProcessWin32WindowStation` returns.
pub const EPROCESS_WIN32_WINDOW_STATION: usize = 0x2c8;
pub const EPROCESS_PEB: usize = 0x2e0;
/// Address returned by PsGetProcessImageFileName; fifteen bytes, then `PriorityClass`.
pub const EPROCESS_IMAGE_FILE_NAME: usize = 0x338;
pub const EPROCESS_IMAGE_FILE_NAME_BYTES: usize = 15;
pub const EPROCESS_THREAD_LIST_HEAD: usize = 0x370;
const KPROCESS_PROFILE_LIST_HEAD: usize = 0x18;
const KPROCESS_THREAD_LIST_HEAD: usize = 0x30;
const KPROCESS_READY_LIST_HEAD: usize = 0x68;

/// `KTHREAD.ThreadFlags`; `EnableStackSwap` is the bit `KeSetKernelStackSwapEnable` exchanges.
pub const KTHREAD_THREAD_FLAGS: usize = 0x78;
pub const KTHREAD_ENABLE_STACK_SWAP: u32 = 1 << 6;
pub const KTHREAD_APC_STATE: usize = 0x98;
pub const KTHREAD_APC_STATE_PROCESS: usize = 0xb8;
pub const KTHREAD_TEB: usize = 0xf0;
/// The per-thread win32k state. win32k.sys loads `[ETHREAD + 0x1c8]` itself in `IntSetTimer`,
/// `NtUserPostThreadMessage`, `NtUserBuildHwndList` and the inlined current-thread form.
pub const KTHREAD_WIN32_THREAD: usize = 0x1c8;
/// The owning process. The pinned `ETHREAD` has no separate `ThreadsProcess`.
pub const KTHREAD_PROCESS: usize = 0x220;
pub const KTHREAD_PREVIOUS_MODE: usize = 0x232;
pub const KTHREAD_APC_STATE_INDEX: usize = 0x24a;
pub const KTHREAD_SAVED_APC_STATE: usize = 0x258;
/// The thread's suspend count, a `CHAR`. win32k.sys reads it for its hung-window test.
pub const KTHREAD_SUSPEND_COUNT: usize = 0x284;
const KTHREAD_MUTANT_LIST_HEAD: usize = 0x308;
pub const KTHREAD_APC_STATE_POINTERS: usize = 0x4a0;
const ETHREAD_LPC_REPLY_CHAIN: usize = 0x4c8;
const ETHREAD_POST_BLOCK_LIST: usize = 0x4d8;
const ETHREAD_ACTIVE_TIMER_LIST_HEAD: usize = 0x4f8;
/// The thread's client id. win32k.sys reads both halves from `pti->pEThread` directly.
pub const ETHREAD_CLIENT_ID_PROCESS: usize = 0x508;
pub const ETHREAD_CLIENT_ID_THREAD: usize = 0x510;
const ETHREAD_IRP_LIST: usize = 0x540;
pub const ETHREAD_DEVICE_TO_VERIFY: usize = 0x558;
pub const ETHREAD_CROSS_THREAD_FLAGS: usize = 0x5a0;
pub const ETHREAD_SYSTEM_THREAD: u32 = 1 << 4;
/// `MAXIMUM_SUSPEND_COUNT`: the largest value the `CHAR` suspend count holds.
pub const MAXIMUM_SUSPEND_COUNT: u32 = 127;

/// One projected field against the pinned LiberNT release.
#[derive(Clone, Copy, Debug)]
pub struct PinnedField {
    pub object: &'static str,
    pub name: &'static str,
    /// Where this crate writes the field.
    pub projected: usize,
    /// Where the pinned release keeps it.
    pub pinned: usize,
    pub bytes: usize,
    /// Declaration in the pinned AMD64 headers (`sdk/include/ndk`, commit 8e478a22).
    pub header: &'static str,
}

const fn pinned(
    object: &'static str,
    name: &'static str,
    projected: usize,
    pinned: usize,
    bytes: usize,
    header: &'static str,
) -> PinnedField {
    PinnedField { object, name, projected, pinned, bytes, header }
}

/// The pinned release's layout for every field this projection writes.
pub const PINNED_LAYOUT: &[PinnedField] = &[
    pinned("KPROCESS", "ProfileListHead", KPROCESS_PROFILE_LIST_HEAD, 0x18, 16, "ketypes.h:3716"),
    pinned("KPROCESS", "ThreadListHead", KPROCESS_THREAD_LIST_HEAD, 0x30, 16, "ketypes.h:3718"),
    pinned("KPROCESS", "ReadyListHead", KPROCESS_READY_LIST_HEAD, 0x68, 16, "ketypes.h:3723"),
    pinned("EPROCESS", "UniqueProcessId", EPROCESS_UNIQUE_PROCESS_ID, 0x1d0, 8, "pstypes.h:2002"),
    pinned("EPROCESS", "Win32Process", EPROCESS_WIN32_PROCESS, 0x298, 8, "pstypes.h:2097"),
    pinned("EPROCESS", "SectionBaseAddress", EPROCESS_SECTION_BASE_ADDRESS, 0x2b0, 8, "pstypes.h:2100"),
    pinned("EPROCESS", "Win32WindowStation", EPROCESS_WIN32_WINDOW_STATION, 0x2c8, 8, "pstypes.h:2103"),
    pinned("EPROCESS", "Peb", EPROCESS_PEB, 0x2e0, 8, "pstypes.h:2106"),
    pinned("EPROCESS", "ImageFileName", EPROCESS_IMAGE_FILE_NAME, 0x338, 15, "pstypes.h:2117"),
    pinned("EPROCESS", "ThreadListHead", EPROCESS_THREAD_LIST_HEAD, 0x370, 16, "pstypes.h:2123"),
    pinned("KTHREAD", "ThreadFlags", KTHREAD_THREAD_FLAGS, 0x78, 4, "ketypes.h:2220"),
    pinned("KTHREAD", "ApcState.ApcListHead", KTHREAD_APC_STATE, 0x98, 0x20, "ketypes.h:2249"),
    pinned("KTHREAD", "ApcState.Process", KTHREAD_APC_STATE_PROCESS, 0xb8, 8, "ketypes.h:2249"),
    pinned("KTHREAD", "Teb", KTHREAD_TEB, 0xf0, 8, "ketypes.h:2265"),
    pinned("KTHREAD", "Win32Thread", KTHREAD_WIN32_THREAD, 0x1c8, 8, "ketypes.h:2315"),
    pinned("KTHREAD", "Process", KTHREAD_PROCESS, 0x220, 8, "ketypes.h:2357"),
    pinned("KTHREAD", "PreviousMode", KTHREAD_PREVIOUS_MODE, 0x232, 1, "ketypes.h:2360"),
    pinned("KTHREAD", "ApcStateIndex", KTHREAD_APC_STATE_INDEX, 0x24a, 1, "ketypes.h:2369"),
    pinned("KTHREAD", "SavedApcState", KTHREAD_SAVED_APC_STATE, 0x258, 0x2b, "ketypes.h:2375"),
    pinned("KTHREAD", "SuspendCount", KTHREAD_SUSPEND_COUNT, 0x284, 1, "ketypes.h:2380"),
    pinned("KTHREAD", "MutantListHead", KTHREAD_MUTANT_LIST_HEAD, 0x308, 16, "ketypes.h:2422"),
    pinned("KTHREAD", "ApcStatePointer", KTHREAD_APC_STATE_POINTERS, 0x4a0, 16, "ketypes.h:2520"),
    pinned("ETHREAD", "LpcReplyChain", ETHREAD_LPC_REPLY_CHAIN, 0x4c8, 16, "pstypes.h:1616"),
    pinned("ETHREAD", "PostBlockList", ETHREAD_POST_BLOCK_LIST, 0x4d8, 16, "pstypes.h:1622"),
    pinned("ETHREAD", "ActiveTimerListHead", ETHREAD_ACTIVE_TIMER_LIST_HEAD, 0x4f8, 16, "pstypes.h:1647"),
    pinned("ETHREAD", "Cid.UniqueProcess", ETHREAD_CLIENT_ID_PROCESS, 0x508, 8, "pstypes.h:1648"),
    pinned("ETHREAD", "Cid.UniqueThread", ETHREAD_CLIENT_ID_THREAD, 0x510, 8, "pstypes.h:1648"),
    pinned("ETHREAD", "IrpList", ETHREAD_IRP_LIST, 0x540, 16, "pstypes.h:1670"),
    pinned("ETHREAD", "DeviceToVerify", ETHREAD_DEVICE_TO_VERIFY, 0x558, 8, "pstypes.h:1672"),
    pinned("ETHREAD", "CrossThreadFlags", ETHREAD_CROSS_THREAD_FLAGS, 0x5a0, 4, "pstypes.h:1736"),
];

const DISPATCHER_WAIT_LIST: usize = 8;
const PROCESS_LIST_HEADS: &[usize] = &[
    DISPATCHER_WAIT_LIST,
    KPROCESS_PROFILE_LIST_HEAD,
    KPROCESS_THREAD_LIST_HEAD,
    KPROCESS_READY_LIST_HEAD,
    EPROCESS_THREAD_LIST_HEAD,
];
const THREAD_LIST_HEADS: &[usize] = &[
    DISPATCHER_WAIT_LIST,
    KTHREAD_APC_STATE,
    KTHREAD_APC_STATE + 0x10,
    KTHREAD_MUTANT_LIST_HEAD,
    ETHREAD_LPC_REPLY_CHAIN,
    ETHREAD_POST_BLOCK_LIST,
    ETHREAD_ACTIVE_TIMER_LIST_HEAD,
    ETHREAD_IRP_LIST,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionError {
    BufferTooSmall,
    NullBody,
    UnalignedAddress,
    AddressOverflow,
    InvalidProcessId,
    InvalidThreadId,
    IdentityMismatch,
    InvalidPreviousMode,
    InvalidSuspendCount,
    UnterminatedImageFileName,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreadPreviousMode {
    KernelMode = 0,
    UserMode = 1,
}

pub fn thread_previous_mode(body: &[u8]) -> Result<ThreadPreviousMode, ProjectionError> {
    match body.get(KTHREAD_PREVIOUS_MODE).ok_or(ProjectionError::BufferTooSmall)? {
        0 => Ok(ThreadPreviousMode::KernelMode),
        1 => Ok(ThreadPreviousMode::UserMode),
        _ => Err(ProjectionError::InvalidPreviousMode),
    }
}

pub fn exchange_thread_previous_mode(
    body: &mut [u8], mode: ThreadPreviousMode,
) -> Result<ThreadPreviousMode, ProjectionError> {
    let previous = thread_previous_mode(body)?;
    body[KTHREAD_PREVIOUS_MODE] = mode as u8;
    Ok(previous)
}

/// `KeSetKernelStackSwapEnable`: exchange the `EnableStackSwap` bit, leaving the other flags.
pub fn exchange_thread_stack_swap_enable(
    body: &mut [u8], enable: bool,
) -> Result<bool, ProjectionError> {
    let flags = body
        .get_mut(KTHREAD_THREAD_FLAGS..KTHREAD_THREAD_FLAGS + 4)
        .ok_or(ProjectionError::BufferTooSmall)?;
    let old = u32::from_le_bytes(flags.try_into().unwrap());
    let new = (old & !KTHREAD_ENABLE_STACK_SWAP)
        | if enable { KTHREAD_ENABLE_STACK_SWAP } else { 0 };
    flags.copy_from_slice(&new.to_le_bytes());
    Ok(old & KTHREAD_ENABLE_STACK_SWAP != 0)
}

/// Publish the Process Manager's suspend count where the release keeps `Tcb.SuspendCount`.
pub fn set_thread_suspend_count(
    output: &mut [u8],
    thread: ThreadInitialization,
    count: u32,
) -> Result<(), ProjectionError> {
    if count > MAXIMUM_SUSPEND_COUNT {
        return Err(ProjectionError::InvalidSuspendCount);
    }
    validate_thread_activation(output, thread)?;
    output[KTHREAD_SUSPEND_COUNT] = count as u8;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessInitialization {
    pub body: GuestAddr,
    pub process_id: u64,
    /// An actual PEB address, or NULL for processes such as System.
    pub peb: GuestAddr,
    /// Exact process basename, bounded and NUL-terminated by the Ps owner.
    pub image_file_name: [u8; 16],
    /// Base of the mapped process image, or NULL for a process without one such as System.
    pub section_base_address: GuestAddr,
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
    /// The Process Manager's suspend count for this activation.
    pub suspend_count: u32,
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
    if init.image_file_name[EPROCESS_IMAGE_FILE_NAME_BYTES] != 0 {
        return Err(ProjectionError::UnterminatedImageFileName);
    }
    let output = &mut output[..EPROCESS_BODY_BYTES];
    output.fill(0);
    output[0] = 3; // ProcessObject
    output[2] = (KPROCESS_BYTES / 4) as u8;
    empty_lists(output, init.body, PROCESS_LIST_HEADS);
    write_u64(output, EPROCESS_UNIQUE_PROCESS_ID, init.process_id);
    write_u64(output, EPROCESS_SECTION_BASE_ADDRESS, init.section_base_address.0);
    write_u64(output, EPROCESS_PEB, init.peb.0);
    output[EPROCESS_IMAGE_FILE_NAME..EPROCESS_IMAGE_FILE_NAME + EPROCESS_IMAGE_FILE_NAME_BYTES]
        .copy_from_slice(&init.image_file_name[..EPROCESS_IMAGE_FILE_NAME_BYTES]);
    Ok(())
}

/// Initialize the neutral fields established by KeInitThread and PspCreateThread. Stack,
/// scheduler, token/impersonation, service-table and GUI fields remain zero until their actual
/// owners publish them; later suspend-count changes are published by [`set_thread_suspend_count`]. PreviousMode starts as KernelMode, not an inferred user-mode value.
pub fn initialize_thread(
    output: &mut [u8],
    init: ThreadInitialization,
) -> Result<(), ProjectionError> {
    validate_thread_fields(output, init)?;
    let output = &mut output[..ETHREAD_BODY_BYTES];
    output.fill(0);
    output[0] = 6; // ThreadObject; the remaining dispatcher union bytes are flags, not Size.
    output[KTHREAD_THREAD_FLAGS..KTHREAD_THREAD_FLAGS + 4]
        .copy_from_slice(&KTHREAD_ENABLE_STACK_SWAP.to_le_bytes());
    output[KTHREAD_SUSPEND_COUNT] = init.suspend_count as u8;
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
    let flags = if init.system_thread {
        ETHREAD_SYSTEM_THREAD
    } else {
        0
    };
    output[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

fn validate_thread_fields(
    output: &[u8],
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
    if init.suspend_count > MAXIMUM_SUSPEND_COUNT {
        return Err(ProjectionError::InvalidSuspendCount);
    }
    Ok(())
}

/// Refresh activation-specific fields on an existing, unattached ETHREAD projection. The
/// caller must first drain old execution, pointer references and provider aliases, and serialize
/// this update with its authoritative activation-generation commit. Byte identity checks do not
/// establish that lifetime authority or prove the supplied body is actually mapped here.
///
/// Only TEB, the SystemThread bit and the suspend count change. PreviousMode is execution-context state, not a
/// property inferred from a nonzero TEB. Lists, APC state, GUI pointers, other cross-thread flags
/// and all trailing storage remain untouched. No successful or failed call initializes storage.
pub fn refresh_thread_activation(
    output: &mut [u8],
    fields: ThreadInitialization,
) -> Result<(), ProjectionError> {
    validate_thread_activation(output, fields)?;
    let old_flags = u32::from_le_bytes(
        output[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
            .try_into()
            .unwrap(),
    );
    let flags = (old_flags & !ETHREAD_SYSTEM_THREAD)
        | if fields.system_thread {
            ETHREAD_SYSTEM_THREAD
        } else {
            0
        };
    write_u64(output, KTHREAD_TEB, fields.teb.0);
    output[KTHREAD_SUSPEND_COUNT] = fields.suspend_count as u8;
    output[ETHREAD_CROSS_THREAD_FLAGS..ETHREAD_CROSS_THREAD_FLAGS + 4]
        .copy_from_slice(&flags.to_le_bytes());
    Ok(())
}

/// Read-only preflight for [`refresh_thread_activation`]. To rely on success across an
/// authoritative PM commit, the caller must retain the same mapping, bytes and supplied fields
/// under its exclusive, nonreentrant owner until the subsequent refresh has completed.
pub fn validate_thread_activation(
    output: &[u8],
    fields: ThreadInitialization,
) -> Result<(), ProjectionError> {
    validate_thread_fields(output, fields)?;
    let read_u64 =
        |offset: usize| u64::from_le_bytes(output[offset..offset + 8].try_into().unwrap());
    if output[0] != 6
        || read_u64(ETHREAD_CLIENT_ID_PROCESS) != fields.process_id
        || read_u64(ETHREAD_CLIENT_ID_THREAD) != fields.thread_id
        || read_u64(KTHREAD_PROCESS) != fields.process_body.0
        || read_u64(KTHREAD_APC_STATE_PROCESS) != fields.process_body.0
        || read_u64(KTHREAD_APC_STATE_POINTERS) != fields.body.0 + KTHREAD_APC_STATE as u64
        || read_u64(KTHREAD_APC_STATE_POINTERS + 8)
            != fields.body.0 + KTHREAD_SAVED_APC_STATE as u64
    {
        return Err(ProjectionError::IdentityMismatch);
    }
    Ok(())
}

/// Project a verified device into the requestor's exact live ETHREAD body.
///
/// The caller must have already authenticated the IRP, its requestor thread, and the canonical
/// device under their owning locks. This function validates the projected ETHREAD identity again
/// before touching its one field; a stale or truncated body is never partially modified. A null
/// device is permitted because the native field may be cleared.
pub fn set_thread_device_to_verify(
    output: &mut [u8],
    thread: ThreadInitialization,
    device: GuestAddr,
) -> Result<(), ProjectionError> {
    validate_thread_activation(output, thread)?;
    aligned(device)?;
    write_u64(output, ETHREAD_DEVICE_TO_VERIFY, device.0);
    Ok(())
}

#[cfg(test)]
#[path = "ps_hosted_x64_tests.rs"]
mod tests;
