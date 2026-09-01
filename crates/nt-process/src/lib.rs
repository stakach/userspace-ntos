//! # `nt-process` — Process Manager (processes, threads, image sections)
//!
//! The NT Process Manager (spec: NT Process, Thread, Image Section, and User-Mode Bootstrap):
//! [`NtProcess`] + [`NtThread`] objects with scheduling states + a [`ClientId`], per-process
//! [handle tables](ProcessManager::insert_handle), the process/thread **lifecycle** (create →
//! ready/running → terminate, with dispatcher signalling + [`ProcessManager::wait`]), and
//! `SEC_IMAGE` [image sections](ProcessManager::create_image_section) — a PE parsed + laid out +
//! relocated through `nt-pe-loader`, with read-only image data **shared** across processes that
//! map the same file. `no_std` + `alloc`.

#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use nt_pe_loader::{MappedImage, PeError, PeFile};
use nt_security::TokenId;

pub mod dbgk;
pub mod job;
pub mod job_abi;

use dbgk::{DbgKmMessage, DebugEvent, DebugObjectId, DebugObjectStore};

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const THREAD_NAME_MAX_UNITS: usize = 256;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_CID: u32 = 0xC000_000B;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_PORT_ALREADY_SET: u32 = 0xC000_0048;
pub const STATUS_SUSPEND_COUNT_EXCEEDED: u32 = 0xC000_004A;
pub const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
pub const STATUS_HANDLE_NOT_CLOSABLE: u32 = 0xC000_0235;
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_00E9;
pub const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
pub const SEM_FAILCRITICALERRORS: u32 = 0x0001;
/// Durable registrations preallocated with each ETHREAD. The executive uses a rewindable syscall
/// heap, so registration consumes this kernel-owned reserve instead of reallocating during a call.
pub const THREAD_TERMINATION_PORT_RESERVE: usize = 4;

pub const PROCESS_GENERIC_READ: u32 = 0x0002_0410;
pub const PROCESS_GENERIC_WRITE: u32 = 0x0002_0BEB;
pub const PROCESS_GENERIC_EXECUTE: u32 = 0x0012_0000;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const THREAD_GENERIC_READ: u32 = 0x0002_0048;
pub const THREAD_GENERIC_WRITE: u32 = 0x0002_0037;
pub const THREAD_GENERIC_EXECUTE: u32 = 0x0012_0000;
pub const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const PROCESS_PRIORITY_CLASS_INVALID: u8 = 0;
pub const PROCESS_PRIORITY_CLASS_IDLE: u8 = 1;
pub const PROCESS_PRIORITY_CLASS_NORMAL: u8 = 2;
pub const PROCESS_PRIORITY_CLASS_HIGH: u8 = 3;
pub const PROCESS_PRIORITY_CLASS_REALTIME: u8 = 4;
pub const PROCESS_PRIORITY_CLASS_BELOW_NORMAL: u8 = 5;
pub const PROCESS_PRIORITY_CLASS_ABOVE_NORMAL: u8 = 6;
pub const DEFAULT_PROCESS_BASE_PRIORITY: i32 = 13;
pub const LOW_PRIORITY: i32 = 0;
pub const LOW_REALTIME_PRIORITY: i32 = 16;
pub const HIGH_PRIORITY: i32 = 31;
pub const THREAD_BASE_PRIORITY_LOWRT: i32 = 15;
pub const THREAD_BASE_PRIORITY_MAX: i32 = 2;
pub const THREAD_BASE_PRIORITY_MIN: i32 = -2;
pub const THREAD_BASE_PRIORITY_IDLE: i32 = -15;
pub const MAXIMUM_PROCESSORS: u64 = 64;

pub const PROCESS_CREATE_FLAGS_BREAKAWAY: u32 = 0x0000_0001;
pub const PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT: u32 = 0x0000_0002;
pub const PROCESS_CREATE_FLAGS_INHERIT_HANDLES: u32 = 0x0000_0004;
pub const PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE: u32 = 0x0000_0008;
pub const PROCESS_CREATE_FLAGS_LARGE_PAGES: u32 = 0x0000_0010;
pub const PROCESS_CREATE_FLAGS_LEGAL_MASK: u32 = PROCESS_CREATE_FLAGS_BREAKAWAY
    | PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT
    | PROCESS_CREATE_FLAGS_INHERIT_HANDLES
    | PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE
    | PROCESS_CREATE_FLAGS_LARGE_PAGES;

/// The process-creation arguments after the legacy `NtCreateProcess` ABI has been translated to
/// the `NtCreateProcessEx` contract used by `PspCreateProcess`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcessCreateInput {
    pub flags: u32,
    pub section_handle: u64,
    pub debug_port: u64,
    pub exception_port: u64,
    pub job_member_level: u32,
}

/// Decode the two native process-creation ABIs without reading beyond the registered service
/// contract. Legacy NT encodes BREAKAWAY and NO_DEBUG_INHERIT in the low handle bits and supplies
/// an `InheritObjectTable` BOOLEAN in argument five.
pub fn decode_process_create_input(
    args: &[u64],
    extended: bool,
) -> Result<ProcessCreateInput, u32> {
    let required = if extended { 9 } else { 8 };
    if args.len() < required {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if extended {
        let flags = args[4] as u32;
        if flags & !PROCESS_CREATE_FLAGS_LEGAL_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        return Ok(ProcessCreateInput {
            flags,
            section_handle: args[5],
            debug_port: args[6],
            exception_port: args[7],
            // ReactOS/NT5 declares the final NtCreateProcessEx argument as BOOLEAN. The Win64
            // caller is only required to define the low byte of a stack argument this narrow, so
            // the remaining seven bytes must never participate in process or job policy.
            job_member_level: args[8] as u8 as u32,
        });
    }

    let mut flags = 0;
    if args[5] & 1 != 0 {
        flags |= PROCESS_CREATE_FLAGS_BREAKAWAY;
    }
    if args[6] & 1 != 0 {
        flags |= PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT;
    }
    if args[4] != 0 {
        flags |= PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
    }
    Ok(ProcessCreateInput {
        flags,
        section_handle: args[5] & !3,
        debug_port: args[6] & !3,
        exception_port: args[7],
        job_member_level: 0,
    })
}

/// Expand generic process access bits using the NT process-object generic mapping. Until process
/// security descriptors are modelled, `MAXIMUM_ALLOWED` grants the full process mask.
pub fn map_process_access(desired: u32) -> u32 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    let mut mapped =
        desired & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
    if desired & GENERIC_READ != 0 {
        mapped |= PROCESS_GENERIC_READ;
    }
    if desired & GENERIC_WRITE != 0 {
        mapped |= PROCESS_GENERIC_WRITE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        mapped |= PROCESS_GENERIC_EXECUTE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        mapped |= PROCESS_ALL_ACCESS;
    }
    mapped
}

/// Expand generic thread access bits using the NT thread-object generic mapping. Until thread
/// security descriptors are modelled, `MAXIMUM_ALLOWED` grants the full thread mask.
pub fn map_thread_access(desired: u32) -> u32 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    let mut mapped =
        desired & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
    if desired & GENERIC_READ != 0 {
        mapped |= THREAD_GENERIC_READ;
    }
    if desired & GENERIC_WRITE != 0 {
        mapped |= THREAD_GENERIC_WRITE;
    }
    if desired & GENERIC_EXECUTE != 0 {
        mapped |= THREAD_GENERIC_EXECUTE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        mapped |= THREAD_ALL_ACCESS;
    }
    mapped
}

pub type ProcessId = u32;
pub type ThreadId = u32;
pub type Handle = u32;
pub type SectionId = u32;
pub type AddressSpaceId = u32;

/// Broker-owned reference to one exact LPC port object. This is deliberately distinct from a
/// process-local user handle: it remains valid after that handle table entry is closed and must be
/// returned to the broker during process teardown.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExceptionPortEndpoint(u64);

impl ExceptionPortEndpoint {
    pub fn new(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

/// Opaque ownership token for one exact, process-local handle slot that is not yet visible.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HandleReservation {
    pub process_id: ProcessId,
    pub handle: Handle,
    pub generation: u64,
}

/// NT client ids are handle-shaped values: non-zero multiples of four. ReactOS GDI also stores
/// low-bit metadata in owner fields and masks it before comparing against `PsGetCurrentProcessId`.
pub const CLIENT_ID_GRANULARITY: u32 = 4;
const FIRST_CLIENT_ID: u32 = CLIENT_ID_GRANULARITY;

#[inline]
fn allocate_client_id(next: &mut u32) -> u32 {
    let id = *next;
    debug_assert!(id != 0);
    debug_assert_eq!(id % CLIENT_ID_GRANULARITY, 0);
    *next = id
        .checked_add(CLIENT_ID_GRANULARITY)
        .expect("nt-process ClientId space exhausted");
    id
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserApc {
    pub routine: u64,
    pub normal_context: u64,
    pub system_argument1: u64,
    pub system_argument2: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KernelUserApcSource {
    Timer(u64),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct QueuedUserApc {
    apc: UserApc,
    source: Option<KernelUserApcSource>,
}

struct IdTable<T> {
    entries: Vec<(u32, T)>,
}

impl<T> Default for IdTable<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> IdTable<T> {
    fn reserve_capacity(&mut self, capacity: usize) {
        if capacity > self.entries.capacity() {
            self.entries
                .reserve_exact(capacity - self.entries.capacity());
        }
    }

    fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    fn position(&self, key: u32) -> Result<usize, usize> {
        self.entries
            .binary_search_by_key(&key, |(candidate, _)| *candidate)
    }

    fn insert(&mut self, key: u32, value: T) -> Option<T> {
        match self.position(key) {
            Ok(index) => Some(core::mem::replace(&mut self.entries[index].1, value)),
            Err(index) => {
                self.entries.insert(index, (key, value));
                None
            }
        }
    }

    fn get(&self, key: &u32) -> Option<&T> {
        self.position(*key).ok().map(|index| &self.entries[index].1)
    }

    fn get_mut(&mut self, key: &u32) -> Option<&mut T> {
        self.position(*key)
            .ok()
            .map(|index| &mut self.entries[index].1)
    }

    fn contains_key(&self, key: &u32) -> bool {
        self.position(*key).is_ok()
    }

    fn remove(&mut self, key: &u32) -> Option<T> {
        self.position(*key)
            .ok()
            .map(|index| self.entries.remove(index).1)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn iter(&self) -> impl Iterator<Item = (&u32, &T)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }

    fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.iter().map(|(_, value)| value)
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.entries.iter_mut().map(|(_, value)| value)
    }
}

pub struct ThreadIdSet {
    entries: Vec<ThreadId>,
}

impl Default for ThreadIdSet {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl ThreadIdSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reserve_capacity(&mut self, capacity: usize) {
        if capacity > self.entries.capacity() {
            self.entries
                .reserve_exact(capacity - self.entries.capacity());
        }
    }

    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, index: usize) -> Option<&ThreadId> {
        self.entries.get(index)
    }

    pub fn insert(&mut self, tid: ThreadId) -> bool {
        match self.entries.binary_search(&tid) {
            Ok(_) => false,
            Err(index) => {
                self.entries.insert(index, tid);
                true
            }
        }
    }

    pub fn iter(&self) -> core::slice::Iter<'_, ThreadId> {
        self.entries.iter()
    }
}

impl<'a> IntoIterator for &'a ThreadIdSet {
    type Item = &'a ThreadId;
    type IntoIter = core::slice::Iter<'a, ThreadId>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// A `CLIENT_ID` (spec §7.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClientId {
    pub unique_process: ProcessId,
    pub unique_thread: ThreadId,
}

/// Capture the handle-width native `CLIENT_ID` values for `NtOpenProcess` without truncation.
pub fn process_client_id_from_native(
    unique_process: u64,
    unique_thread: u64,
) -> Result<ClientId, u32> {
    let unique_process = match u32::try_from(unique_process) {
        Ok(pid) => pid,
        Err(_) if unique_thread != 0 => return Err(STATUS_INVALID_CID),
        Err(_) => return Err(STATUS_INVALID_PARAMETER),
    };
    let unique_thread = u32::try_from(unique_thread).map_err(|_| STATUS_INVALID_CID)?;
    Ok(ClientId {
        unique_process,
        unique_thread,
    })
}

/// Capture the handle-width native `CLIENT_ID` values for `NtOpenThread` without truncation.
pub fn thread_client_id_from_native(
    unique_process: u64,
    unique_thread: u64,
) -> Result<ClientId, u32> {
    let missing_status = if unique_process == 0 {
        STATUS_INVALID_PARAMETER
    } else {
        STATUS_INVALID_CID
    };
    let unique_process = u32::try_from(unique_process).map_err(|_| STATUS_INVALID_CID)?;
    let unique_thread = u32::try_from(unique_thread).map_err(|_| missing_status)?;
    if unique_thread == 0 {
        return Err(missing_status);
    }
    Ok(ClientId {
        unique_process,
        unique_thread,
    })
}

/// The architecture-neutral fields returned for `ThreadBasicInformation`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThreadBasicInformation {
    pub exit_status: u32,
    pub teb_base_address: u64,
    pub client_id: ClientId,
    pub affinity_mask: u64,
    pub priority: i32,
    pub base_priority: i32,
}

/// The architecture-neutral fields returned for `ProcessBasicInformation`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcessBasicInformation {
    pub exit_status: u32,
    pub peb_base_address: u64,
    pub affinity_mask: u64,
    pub base_priority: i32,
    pub unique_process_id: ProcessId,
    pub inherited_from_unique_process_id: ProcessId,
}

/// What a successful [`ProcessManager::wait_for_debug_event`] hands back: the rendered
/// `DBGUI_WAIT_STATE_CHANGE` plus the handles/`CLIENT_ID` the host needs to finish the call.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DebugWaitResult {
    /// The `DBG_STATE` reported (`DbgCreateProcessStateChange`, …).
    pub state: u32,
    /// The debuggee `CLIENT_ID` the debugger passes back to `NtDebugContinue`.
    pub client_id: ClientId,
    /// Handle to the reported process opened in the debugger's handle table (`0` when the state
    /// carries none).
    pub handle_to_process: Handle,
    /// Handle to the reported thread opened in the debugger's handle table (`0` when none).
    pub handle_to_thread: Handle,
    /// The image FILE handle duplicated into the debugger's handle table for the two states that
    /// carry one — `DbgCreateProcessStateChange` and `DbgLoadDllStateChange` (`DbgkpOpenHandles`'s
    /// `ObDuplicateObject`). `0` when the state carries none, or when the debuggee's own handle
    /// could not be duplicated (exactly what the kernel leaves behind on failure).
    pub handle_to_file: Handle,
    /// The x64 `DBGUI_WAIT_STATE_CHANGE` image to copy out to the debugger.
    pub state_change: [u8; dbgk::DBGUI_WAIT_STATE_CHANGE_SIZE],
}

/// A module — an **IMAGE** view mapped into a process. The modelled equivalent of the
/// `LDR_DATA_TABLE_ENTRY`s on `PEB->Ldr->InLoadOrderModuleList`, which is the list
/// `DbgkpPostFakeModuleMessages` walks to tell an attaching debugger what is already loaded, and
/// the "is this base an image view?" test `MmUnmapViewOfSection` performs before calling
/// `DbgkUnMapViewOfSection`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessModule {
    /// The owning process. `0` marks a free slot in the tracking table.
    pub pid: ProcessId,
    /// `LDR_DATA_TABLE_ENTRY.DllBase` = `DBGKM_LOAD_DLL.BaseOfDll`.
    pub base: u64,
    /// The **debuggee's own** handle to the image file. Duplicated into the debugger's handle table
    /// when the message is reported (`DbgkpOpenHandles`); `0` = none.
    pub file_handle: u64,
    /// `IMAGE_FILE_HEADER.PointerToSymbolTable` → `DBGKM_LOAD_DLL.DebugInfoFileOffset`.
    pub debug_info_file_offset: u32,
    /// `IMAGE_FILE_HEADER.NumberOfSymbols` → `DBGKM_LOAD_DLL.DebugInfoSize`.
    pub debug_info_size: u32,
    /// `DBGKM_LOAD_DLL.NamePointer` — a pointer **in the debuggee** to the module's name
    /// (`&NtCurrentTeb()->NtTib.ArbitraryUserPointer` in `DbgkMapViewOfSection`). `0` = none, which
    /// is what `DbgkpPostFakeModuleMessages` reports for its fake messages.
    pub name_pointer: u64,
}

/// Default cap on tracked modules across all processes. `DbgkpPostFakeModuleMessages` likewise
/// stops walking `InLoadOrderModuleList` after 500 entries.
pub const DEFAULT_TRACKED_MODULES: usize = 64;

/// Architecture-neutral fields returned for `ThreadTimes` (`KERNEL_USER_TIMES`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThreadTimes {
    pub create_time: i64,
    pub exit_time: i64,
    pub kernel_time: i64,
    pub user_time: i64,
}

/// Architecture-neutral fields returned for process `KERNEL_USER_TIMES`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProcessTimes {
    pub create_time: i64,
    pub exit_time: i64,
    pub kernel_time: i64,
    pub user_time: i64,
}

/// Process states (spec §7.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Created,
    LoadingImage,
    Ready,
    Running,
    Exiting,
    Terminated,
}

/// Thread states (spec §7.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Initialized,
    Ready,
    Running,
    Waiting,
    Suspended,
    Terminated,
}

/// A loaded `SEC_IMAGE` image section (spec §13). The laid-out + relocated image bytes are
/// immutable and shared read-only across every process that maps this file.
pub struct ImageSection {
    image_file_name: String,
    image: MappedImage,
    size_of_image: u32,
    entry_point: u64,
    /// Number of processes currently mapping this image (read-only sharing, spec §13.7).
    map_refs: u32,
}

impl ImageSection {
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }
    pub fn load_base(&self) -> u64 {
        self.image.load_base
    }
    pub fn map_refs(&self) -> u32 {
        self.map_refs
    }
    pub fn image_file_name(&self) -> &str {
        &self.image_file_name
    }
    /// The immutable image bytes (shared read-only, spec §13.7).
    pub fn image_bytes(&self) -> &[u8] {
        &self.image.bytes
    }
    /// Resolve an IAT slot to an address (spec §13.5) — the loader writing an import.
    pub fn patch_iat(&mut self, slot_rva: u32, addr: u64) -> Result<(), PeError> {
        self.image.patch_iat(slot_rva, addr)
    }
}

/// The `NtProcess` object (spec §7.1).
pub struct NtProcess {
    pub process_id: ProcessId,
    pub parent: Option<ProcessId>,
    /// Terminal Services session identity reported by
    /// `NtQueryInformationProcess(ProcessSessionInformation)`.
    pub session_id: u32,
    pub image_file_name: String,
    pub address_space_id: AddressSpaceId,
    pub image_section: Option<SectionId>,
    pub threads: ThreadIdSet,
    pub main_thread: Option<ThreadId>,
    pub state: ProcessState,
    pub exit_status: Option<u32>,
    /// Dispatcher references held by parked waits independently of user handles.
    wait_references: u32,
    /// Stable primary-token identity. The external token store owns the object bytes and reference
    /// count; the process holds one reference while this slot is populated.
    primary_token: Option<TokenId>,
    /// Opaque `W32PROCESS` pointer parked by win32k via `PsSetProcessWin32Process`
    /// (read back with `PsGetProcessWin32Process`). `None` until win32k attaches.
    pub win32_process: Option<u64>,
    /// Opaque executive-owned `EPROCESS` body pointer used by kernel-mode providers that need a
    /// stable process object address. The object bytes live outside this crate; ProcessManager owns
    /// the NT identity and stores the pointer verbatim.
    pub kernel_process_object: Option<u64>,
    /// Opaque `WINDOWSTATION` pointer (`PsSetProcessWindowStation` /
    /// `PsGetProcessWin32WindowStation`).
    pub win32_window_station: Option<u64>,
    /// Lazy, stable `ProcessCookie` returned by `NtQueryInformationProcess` class 36.
    process_cookie: u32,
    /// `EPROCESS.DefaultHardErrorProcessing`, queried/set by
    /// `ProcessDefaultHardErrorMode`.
    default_hard_error_processing: u32,
    /// `ProcessBreakOnTermination`, initially clear and mutable through the native info class.
    break_on_termination: bool,
    /// `EPROCESS.SectionBaseAddress` — the mapped base of the process image. Reported to a
    /// debugger in the `DbgKmCreateProcessApi` message. `0` until the host records it.
    pub image_base: u64,
    /// `PEB` base reported by `NtQueryInformationProcess(ProcessBasicInformation)`. The kernel host
    /// sets this when it maps the process environment.
    peb_base_address: u64,
    /// `KPROCESS.Affinity`; single-processor hosts expose bit 0 by default.
    affinity_mask: u64,
    /// `KPROCESS.BasePriority`, surfaced through `ProcessBasicInformation`.
    base_priority: i32,
    /// `EPROCESS.PriorityClass`. ReactOS initializes new processes to NORMAL (2).
    priority_class: u8,
    /// Foreground/background priority mode carried by `PROCESS_PRIORITY_CLASS.Foreground` and
    /// `ProcessForegroundInformation`.
    foreground: bool,
    /// `EPROCESS.ExceptionPort`, represented by an exact broker-owned LPC object reference.
    exception_port_endpoint: Option<ExceptionPortEndpoint>,
    /// Sticky one-shot state: teardown may release the reference but can never make the process
    /// eligible to install another exception port.
    exception_port_was_set: bool,
    /// `EPROCESS.DebugPort` — the `DEBUG_OBJECT` a debugger attached to this process, if any.
    debug_port: Option<DebugObjectId>,
    /// `PEB.BeingDebugged` — mirrors `DebugPort != NULL` (`DbgkpMarkProcessPeb`).
    being_debugged: bool,
    /// `PSF_CREATE_REPORTED_BIT` — the `DbgKmCreateProcessApi` message has already been reported,
    /// so a later thread create reports `DbgKmCreateThreadApi` instead.
    create_reported: bool,
    /// Self-relative security descriptor applied through `NtQuerySecurityObject` /
    /// `NtSetSecurityObject` on process handles. Access checks still use handle grants; this stores
    /// the object descriptor CSRSS and debuggers can query or replace.
    security_descriptor: Vec<u8>,
    /// Per-process handle table (spec §8.1). A dense **array of entries** indexed by handle slot —
    /// the real NT `HANDLE_TABLE` shape — rather than a `BTreeMap`. Slot `i` ↔ handle value
    /// `(i + 1) * 4` (NT handles are non-zero multiples of 4). Freed slots are reused. A reserved
    /// slot fixes one future handle value before an external CREATE begins while remaining
    /// invisible to lookup and ordinary insertion. Capacity can still be reserved up front for
    /// allocation-free ordinary inserts.
    handles: Vec<HandleSlot>,
    next_handle_reservation_generation: u64,
}

/// References returned by the Process Manager's EPROCESS delete procedure. Their backing stores
/// live outside this crate, so the executive releases them after the policy object is no longer
/// reachable. Job membership is released internally because Ps owns both sides of that relation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessObjectDeletion {
    pub primary_token: Option<TokenId>,
    pub exception_port: Option<ExceptionPortEndpoint>,
    pub job: Option<job::JobId>,
    pub deleted_threads: usize,
}

/// Exact reasons the Process object type's delete procedure cannot yet run.
///
/// Termination signals EPROCESS/ETHREAD dispatcher objects; it does not delete them. This snapshot
/// exposes the Object Manager references that must drain before deletion without leaking the
/// process manager's private handle-table representation into the executive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessObjectDeleteBlockers {
    pub state: Option<ProcessState>,
    pub process_wait_references: u32,
    pub debug_port_present: bool,
    pub own_handle_slots: usize,
    pub external_process_handles: usize,
    pub first_external_process_handle_owner: Option<ProcessId>,
    pub missing_threads: usize,
    pub live_threads: usize,
    pub thread_wait_references: u32,
    pub thread_termination_ports: usize,
    pub thread_impersonations: usize,
    pub external_thread_handles: usize,
    pub first_external_thread_handle_owner: Option<ProcessId>,
    pub first_external_thread_handle_target: Option<ThreadId>,
}

impl ProcessObjectDeleteBlockers {
    pub const fn delete_ready(self) -> bool {
        matches!(self.state, Some(ProcessState::Terminated))
            && self.process_wait_references == 0
            && !self.debug_port_present
            && self.own_handle_slots == 0
            && self.external_process_handles == 0
            && self.missing_threads == 0
            && self.live_threads == 0
            && self.thread_wait_references == 0
            && self.thread_termination_ports == 0
            && self.thread_impersonations == 0
            && self.external_thread_handles == 0
    }
}

impl NtProcess {
    /// `EPROCESS.DebugPort`.
    pub fn debug_port(&self) -> Option<DebugObjectId> {
        self.debug_port
    }
    /// `PEB.BeingDebugged`.
    pub fn being_debugged(&self) -> bool {
        self.being_debugged
    }
    /// `PSF_CREATE_REPORTED_BIT`.
    pub fn create_reported(&self) -> bool {
        self.create_reported
    }
    /// `EPROCESS.PriorityClass`.
    pub fn priority_class(&self) -> u8 {
        self.priority_class
    }
    /// `KPROCESS.BasePriority`.
    pub fn base_priority(&self) -> i32 {
        self.base_priority
    }
    /// Foreground/background priority mode.
    pub fn foreground(&self) -> bool {
        self.foreground
    }
    /// `EPROCESS.ExceptionPort`.
    pub fn exception_port_endpoint(&self) -> Option<ExceptionPortEndpoint> {
        self.exception_port_endpoint
    }
}

/// What a handle refers to (spec §8.1). v0.1 covers the object kinds the loader needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandleObject {
    Process(ProcessId),
    Thread(ThreadId),
    Section(SectionId),
    /// An I/O Manager `FILE_OBJECT`. The identifier belongs to the backing filesystem service.
    File(u64),
    /// An I/O Manager `FILE_OBJECT` plus the device route that owned it at create/open time.
    RoutedFile {
        file_id: u64,
        device_id: u64,
    },
    /// A read-only file on the executive's mounted FAT volume.
    DiskFile {
        first_cluster: u32,
        size: u32,
        object_id: u32,
    },
    /// A directory on the executive's mounted FAT volume.
    Directory {
        first_cluster: u32,
        object_id: u32,
    },
    /// A file OR directory on the executive's WRITABLE overlay volume (`nt-fs` `MemFs`, mounted
    /// over the writable namespace prefixes). The `u64` is that volume's own file-object id.
    OverlayFile(u64),
    /// An executive I/O completion-port object, indexed in the executive's fixed object table.
    IoCompletion(u32),
    /// A Configuration Manager key target. The executive owns the read-only hive and mutable
    /// overlay for the process lifetime; each handle independently owns only this typed reference.
    RegistryKey(u32),
    /// A process primary access token. The id is the owning process id.
    Token(ProcessId),
    /// A stable, independently owned token object.
    TokenObject(TokenId),
    /// A `DEBUG_OBJECT` (the user-mode debugging plane's event port).
    DebugObject(DebugObjectId),
    /// A Process Manager job object.
    Job(job::JobId),
    /// An object the executive still models ad-hoc (port/event/file/token/key/…) during the
    /// process-hosting convergence — the handle-table entry is real (per-process, closable) even
    /// though the target isn't yet an `nt-process` object. The `u64` is the executive's opaque tag.
    Opaque(u64),
}

/// Per-handle attributes controlled by `NtSetInformationObject(ObjectHandleFlagInformation)`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HandleFlags {
    pub inherit: bool,
    pub protect_from_close: bool,
}

/// One parent handle selected by `ObInitProcess` for inheritance into a new child. NT preserves
/// the handle value and granted access while copying only entries carrying `OBJ_INHERIT`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InheritedHandle {
    pub handle: Handle,
    pub object: HandleObject,
    pub granted_access: u32,
    pub flags: HandleFlags,
}

struct HandleEntry {
    object: HandleObject,
    granted_access: u32,
    flags: HandleFlags,
}

enum HandleSlot {
    Free,
    Reserved(u64),
    Bound { generation: u64, entry: HandleEntry },
    Occupied(HandleEntry),
}

impl HandleSlot {
    fn is_free(&self) -> bool {
        matches!(self, Self::Free)
    }

    fn entry(&self) -> Option<&HandleEntry> {
        match self {
            Self::Occupied(entry) => Some(entry),
            Self::Free | Self::Reserved(_) | Self::Bound { .. } => None,
        }
    }

    /// Any object reference already bound to this slot. A Bound entry is intentionally invisible
    /// to user-mode lookup until publication, but it owns the target object just as an Occupied
    /// handle does.
    fn reference_entry(&self) -> Option<&HandleEntry> {
        match self {
            Self::Bound { entry, .. } | Self::Occupied(entry) => Some(entry),
            Self::Free | Self::Reserved(_) => None,
        }
    }

    fn entry_mut(&mut self) -> Option<&mut HandleEntry> {
        match self {
            Self::Occupied(entry) => Some(entry),
            Self::Free | Self::Reserved(_) | Self::Bound { .. } => None,
        }
    }

    fn take_entry(&mut self) -> Option<HandleEntry> {
        if !matches!(self, Self::Occupied(_)) {
            return None;
        }
        let Self::Occupied(entry) = core::mem::replace(self, Self::Free) else {
            unreachable!();
        };
        Some(entry)
    }
}

/// The NT handle-value ↔ table-slot mapping: handle `h` (a non-zero multiple of 4) indexes slot
/// `h/4 - 1`. Returns `None` for a malformed handle (zero or not a multiple of 4).
#[inline]
fn handle_to_slot(handle: Handle) -> Option<usize> {
    if handle == 0 || handle % 4 != 0 {
        return None;
    }
    Some((handle / 4 - 1) as usize)
}

/// The inverse of [`handle_to_slot`]: table slot `i` → handle value `(i + 1) * 4`.
#[inline]
fn slot_to_handle(slot: usize) -> Handle {
    ((slot + 1) * 4) as Handle
}

/// The `NtThread` object (spec §7.2).
pub struct NtThread {
    pub thread_id: ThreadId,
    pub process_id: ProcessId,
    pub start_address: u64,
    pub win32_start_address: u64,
    pub parameter: u64,
    pub state: ThreadState,
    pub is_system_thread: bool,
    pub exit_status: Option<u32>,
    /// Dispatcher references held by parked waits independently of user handles.
    wait_references: u32,
    pub create_time_100ns: i64,
    pub exit_time_100ns: i64,
    pub kernel_time_100ns: i64,
    pub user_time_100ns: i64,
    /// Generation of the dormant/reclaimed-thread activation boundary.
    activation_generation: u64,
    /// LPC port objects referenced by `NtRegisterThreadTerminatePort`, in registration order.
    /// `PspExitThread` drains this as a stack, so duplicates intentionally remain distinct.
    termination_ports: Vec<u64>,
    /// Active impersonation context. The thread owns a token reference independently of the user
    /// handle that assigned it.
    impersonation: Option<ImpersonationContext>,
    /// Self-relative security descriptor applied through `NtQuerySecurityObject` /
    /// `NtSetSecurityObject` on thread handles. Access checks use handle grants; this stores the
    /// object descriptor that user-mode security setup can query or replace.
    security_descriptor: Vec<u8>,
    pub suspend_count: u32,
    /// Opaque `W32THREAD` pointer parked by win32k via `PsSetThreadWin32Thread`
    /// (read back with `PsGetThreadWin32Thread`). `None` until win32k attaches.
    pub win32_thread: Option<u64>,
    /// Opaque executive-owned `ETHREAD` body pointer used by kernel-mode providers that need a
    /// stable thread object address. The object bytes live outside this crate; ProcessManager owns
    /// the NT identity and stores the pointer verbatim.
    pub kernel_thread_object: Option<u64>,
    /// The thread's TEB base VA (its `NtCurrentTeb()` / `KTHREAD.Teb`). Set when the host actually
    /// spawns the backing thread (its TEB is a per-thread page); read back by
    /// `NtQueryInformationThread(ThreadBasicInformation).TebBaseAddress`. `0` until the TEB is mapped.
    pub teb_base: u64,
    /// `KTHREAD.Affinity`; constrained by the owning process affinity mask.
    affinity_mask: u64,
    /// `KTHREAD.Priority`.
    priority: i32,
    /// `KTHREAD.BasePriority`.
    base_priority: i32,
    /// `KTHREAD.IdealProcessor`.
    ideal_processor: u64,
    /// `ThreadBreakOnTermination`, initially clear and not inherited from the process.
    break_on_termination: bool,
    /// `ThreadPriorityBoost`: true when dynamic priority boosts are disabled.
    disable_boost: bool,
    /// `ThreadHideFromDebugger`, set-only-to-true through the native API.
    hide_from_debugger: bool,
    thread_name_len: u16,
    thread_name: Vec<u16>,
    user_apc_queue: VecDeque<QueuedUserApc>,
}

/// Allocation-free, invisible activation of a dormant hosted ETHREAD. The host prepares this
/// before constructing its scheduler mechanism and commits it only after mechanism admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadActivationPlan {
    tid: ThreadId,
    process_id: ProcessId,
    generation: u64,
    expected_state: ThreadState,
    start_address: u64,
    parameter: u64,
    create_suspended: bool,
    teb_base: u64,
    create_time_100ns: i64,
    hide_from_debugger: bool,
}

impl ThreadActivationPlan {
    pub const fn thread_id(self) -> ThreadId {
        self.tid
    }

    pub const fn process_id(self) -> ProcessId {
        self.process_id
    }

    pub const fn create_suspended(self) -> bool {
        self.create_suspended
    }
}

/// Per-thread state installed through `ThreadImpersonationToken`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImpersonationContext {
    pub token: TokenId,
    pub copy_on_open: bool,
    pub effective_only: bool,
    pub level: nt_security::SecurityImpersonationLevel,
}

/// The win32k per-system callout function pointers registered via
/// `PsEstablishWin32Callouts` (spec §7.4). win32k passes a `WIN32_CALLOUTS_FPNS`
/// structure at init; the executive parks its address (and the couple of
/// callouts it drives synchronously on process/thread create) so Phase 2 can
/// invoke them. All fields are raw kernel pointers (`0` = not supplied).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Win32Callouts {
    /// Address of the `WIN32_CALLOUTS_FPNS` structure win32k supplied.
    pub table: u64,
    /// `ProcessCallout` — run on process create/destroy.
    pub process_callout: u64,
    /// `ThreadCallout` — run on thread create/destroy.
    pub thread_callout: u64,
    /// `GlobalAtomTableCallout` — returns the per-session atom table.
    pub global_atom_callout: u64,
    /// `JobCallout` — publishes job UI policy and W32PROCESS membership to win32k.
    pub job_callout: u64,
    /// `BatchFlushRoutine` — drains the current thread's GDI user batch.
    pub batch_flush_callout: u64,
}

/// The Process Manager: processes, threads, and image sections (spec §5, §9-§13).
#[derive(Default)]
pub struct ProcessManager {
    processes: IdTable<NtProcess>,
    threads: IdTable<NtThread>,
    sections: Vec<Option<ImageSection>>,
    next_cid: u32,
    next_asid: u32,
    /// win32k's registered callouts (`PsEstablishWin32Callouts`), once attached.
    win32_callouts: Option<Win32Callouts>,
    /// The live `DEBUG_OBJECT` table (the user-mode debugging plane). See [`dbgk`].
    dbgk: DebugObjectStore,
    /// Ps job objects and their exact process membership, accounting, and limit policy.
    jobs: job::JobStore,
    /// The IMAGE views mapped into each process — the modelled `PEB->Ldr` module list. A `pid` of
    /// `0` marks a free slot, so an unmap never shifts the table (and never reallocates).
    ///
    /// ★ Maintained **only while at least one `DEBUG_OBJECT` exists** ([`record_module`] /
    /// [`forget_module`] return immediately otherwise): with no debugger in the system nothing can
    /// ever observe the list, so the host's — extremely load-bearing — section-mapping path stays
    /// literally untouched. See `ntdll_plan.md` §D for what that does and does not cover.
    modules: Vec<ProcessModule>,
    /// Cap on [`modules`](Self::modules); a host [`reserve_modules`](Self::reserve_modules)s it up
    /// front so recording never reallocates.
    module_limit: usize,
}

impl ProcessManager {
    pub fn new() -> Self {
        ProcessManager {
            next_cid: FIRST_CLIENT_ID, // cid 0 is reserved; 4 is System by convention.
            next_asid: 1,
            module_limit: DEFAULT_TRACKED_MODULES,
            ..Default::default()
        }
    }

    /// Pre-allocate the module-tracking table for `capacity` IMAGE views and cap it there, so a
    /// later [`report_module_load`](Self::report_module_load) never reallocates (the same
    /// reserve-up-front discipline a bump-allocating host needs for every durable table).
    pub fn reserve_modules(&mut self, capacity: usize) {
        self.modules
            .reserve_exact(capacity.saturating_sub(self.modules.len()));
        self.module_limit = capacity;
    }

    /// Pre-allocate the process table for a host that knows its bounded hosted-process envelope.
    /// This keeps later `NtCreateProcess[Ex]` object insertion from reallocating on reset-sensitive
    /// allocators; it does not create any synthetic process identities.
    pub fn reserve_process_capacity(&mut self, capacity: usize) {
        self.processes.reserve_capacity(capacity);
    }

    /// Pre-allocate the global thread table for a host that pre-creates or dynamically creates a
    /// bounded ETHREAD pool. Later [`create_thread`](Self::create_thread) calls can then insert
    /// real thread objects without growing the durable table mid-syscall.
    pub fn reserve_thread_capacity(&mut self, capacity: usize) {
        self.threads.reserve_capacity(capacity);
    }

    /// Pre-allocate and cap the debug-object table for a bounded host.
    ///
    /// `object_slots` is the maximum live `DEBUG_OBJECT` count; `events_per_object` is the
    /// precharged queue size for each object. Pure host tests can leave this uncalled and use the
    /// default growable model.
    pub fn reserve_debug_objects(
        &mut self,
        object_slots: usize,
        events_per_object: usize,
    ) -> Result<(), u32> {
        self.dbgk.reserve_capacity(object_slots, events_per_object)
    }

    pub fn process_capacity(&self) -> usize {
        self.processes.capacity()
    }

    pub fn thread_capacity(&self) -> usize {
        self.threads.capacity()
    }

    // --- image sections (spec §13) -------------------------------------------

    /// `ZwCreateSection(SEC_IMAGE)` (spec §13.1): validate the PE, lay it out + relocate it to
    /// `load_base` via `nt-pe-loader`, and register the image section. If an image section for the
    /// same file already exists, share it (bump the map ref, spec §13.7).
    pub fn create_image_section(
        &mut self,
        image_file_name: &str,
        pe_bytes: &[u8],
        load_base: u64,
    ) -> Result<SectionId, u32> {
        if let Some(id) = self.find_image_section(image_file_name) {
            self.sections[id as usize].as_mut().unwrap().map_refs += 1;
            return Ok(id);
        }
        let pe = PeFile::parse(pe_bytes).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?;
        let image = pe.map(load_base).map_err(|_| STATUS_INVALID_IMAGE_FORMAT)?; // layout + relocations
        let section = ImageSection {
            image_file_name: image_file_name.into(),
            size_of_image: pe.size_of_image(),
            entry_point: image.entry_point(),
            image,
            map_refs: 1,
        };
        let id = self.sections.len() as SectionId;
        self.sections.push(Some(section));
        Ok(id)
    }

    fn find_image_section(&self, name: &str) -> Option<SectionId> {
        self.sections
            .iter()
            .position(|s| {
                s.as_ref()
                    .is_some_and(|s| s.image_file_name.eq_ignore_ascii_case(name))
            })
            .map(|i| i as SectionId)
    }

    pub fn image_section(&self, id: SectionId) -> Option<&ImageSection> {
        self.sections.get(id as usize)?.as_ref()
    }
    pub fn image_section_mut(&mut self, id: SectionId) -> Option<&mut ImageSection> {
        self.sections.get_mut(id as usize)?.as_mut()
    }

    // --- process creation (spec §9) ------------------------------------------

    /// `NtCreateProcess` (spec §9.2): create a process with its own address space, optionally
    /// backed by an image section. State starts `Created` → `LoadingImage` (image) / `Ready`.
    pub fn create_process(
        &mut self,
        image_file_name: &str,
        parent: Option<ProcessId>,
        image_section: Option<SectionId>,
    ) -> ProcessId {
        let pid = allocate_client_id(&mut self.next_cid);
        let asid = self.next_asid;
        self.next_asid += 1;
        let state = if image_section.is_some() {
            ProcessState::Ready // image already laid out
        } else {
            ProcessState::Created
        };
        let default_hard_error_processing = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.default_hard_error_processing)
            .unwrap_or(SEM_FAILCRITICALERRORS);
        let session_id = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.session_id)
            .unwrap_or(0);
        let affinity_mask = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.affinity_mask)
            .unwrap_or(1);
        let base_priority = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.base_priority)
            .unwrap_or(DEFAULT_PROCESS_BASE_PRIORITY);
        let priority_class = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.priority_class)
            .unwrap_or(PROCESS_PRIORITY_CLASS_NORMAL);
        let foreground = parent
            .and_then(|pid| self.processes.get(&pid))
            .map(|process| process.foreground)
            .unwrap_or(false);
        self.processes.insert(
            pid,
            NtProcess {
                process_id: pid,
                parent,
                session_id,
                image_file_name: image_file_name.into(),
                address_space_id: asid,
                image_section,
                threads: ThreadIdSet::new(),
                main_thread: None,
                state,
                exit_status: None,
                wait_references: 0,
                primary_token: None,
                win32_process: None,
                kernel_process_object: None,
                win32_window_station: None,
                process_cookie: 0,
                default_hard_error_processing,
                break_on_termination: false,
                image_base: 0,
                peb_base_address: 0,
                affinity_mask,
                base_priority,
                priority_class,
                foreground,
                exception_port_endpoint: None,
                exception_port_was_set: false,
                debug_port: None,
                being_debugged: false,
                create_reported: false,
                security_descriptor: Vec::from(&nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]),
                handles: Vec::new(),
                next_handle_reservation_generation: 1,
            },
        );
        pid
    }

    /// `PspCreateProcess` job admission. The child is inserted only for the duration of this
    /// transaction until its inherited job accepts it; a failed assignment runs the process delete
    /// side of the transaction before returning the failure, so no PID or membership is published.
    ///
    /// Other creation-flag semantics (handle/debug inheritance and address-space policy) belong to
    /// their respective owners. This method validates the NT5 legal mask and consumes only the job
    /// policy bits.
    pub fn create_process_with_job_policy(
        &mut self,
        image_file_name: &str,
        parent: Option<ProcessId>,
        image_section: Option<SectionId>,
        flags: u32,
        job_member_level: u32,
    ) -> Result<ProcessId, u32> {
        if flags & !PROCESS_CREATE_FLAGS_LEGAL_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }

        let inherited_job = self.select_child_job(parent, flags, job_member_level)?;

        let pid = self.create_process(image_file_name, parent, image_section);
        let Some(job_id) = inherited_job else {
            return Ok(pid);
        };
        let session_id = self
            .process(pid)
            .expect("new process remains private during job admission")
            .session_id;
        let assignment = match self.jobs.assign(job_id, pid, session_id, 0) {
            Ok(assignment) => assignment,
            Err(status) => {
                self.rollback_unpublished_process(pid);
                return Err(status);
            }
        };
        self.jobs.queue_notification(assignment.notification);
        if assignment.status != STATUS_SUCCESS {
            self.rollback_unpublished_process(pid);
            return Err(assignment.status);
        }
        if let Err(status) = self.apply_job_limits_to_process(job_id, pid) {
            self.rollback_unpublished_process(pid);
            return Err(status);
        }
        Ok(pid)
    }

    /// Resolve the job a new child would inherit without changing process or job state. Hosts use
    /// this to validate an idempotent in-flight create before reusing its reserved mechanism slot.
    pub fn select_child_job(
        &self,
        parent: Option<ProcessId>,
        flags: u32,
        job_member_level: u32,
    ) -> Result<Option<job::JobId>, u32> {
        if flags & !PROCESS_CREATE_FLAGS_LEGAL_MASK != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let parent_job = match parent {
            Some(parent) => {
                self.process(parent).ok_or(STATUS_INVALID_HANDLE)?;
                self.jobs.job_for_process(parent)
            }
            None => None,
        };
        if parent_job.is_none() && job_member_level != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        match parent_job {
            None => Ok(None),
            Some(job_id) => {
                let limits = self.jobs.basic_limits(job_id)?;
                if limits.limit_flags & job::JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK != 0 {
                    Ok(None)
                } else if flags & PROCESS_CREATE_FLAGS_BREAKAWAY != 0 {
                    if limits.limit_flags & job::JOB_OBJECT_LIMIT_BREAKAWAY_OK == 0 {
                        Err(STATUS_ACCESS_DENIED)
                    } else {
                        Ok(None)
                    }
                } else {
                    self.jobs
                        .select_from_set(job_id, job_member_level)
                        .map(Some)
                }
            }
        }
    }

    fn rollback_unpublished_process(&mut self, pid: ProcessId) {
        let _ = self.jobs.remove_process_reference(pid);
        let Some(process) = self.processes.remove(&pid) else {
            return;
        };
        if let Some(section) = process.image_section {
            if let Some(section) = self
                .sections
                .get_mut(section as usize)
                .and_then(Option::as_mut)
            {
                section.map_refs = section.map_refs.saturating_sub(1);
            }
        }
    }

    /// Abort a process-creation transaction before its PID or handles have been returned to a
    /// caller. External handle owners must release their references and empty the new handle table
    /// first; Ps then removes job membership and the private process record.
    pub fn abort_process_creation(&mut self, pid: ProcessId) -> Option<ProcessObjectDeletion> {
        let Some(process) = self.processes.get(&pid) else {
            return None;
        };
        if process.handles.iter().any(|slot| !slot.is_free()) {
            return None;
        }
        for tid in &process.threads {
            let thread = self.threads.get(tid)?;
            if thread.wait_references != 0
                || !thread.termination_ports.is_empty()
                || thread.impersonation.is_some()
            {
                return None;
            }
        }
        let process = self.processes.remove(&pid)?;
        let deleted_threads = process.threads.len();
        for tid in &process.threads {
            let removed = self.threads.remove(tid);
            debug_assert!(removed.is_some());
        }
        self.modules.retain(|module| module.pid != pid);
        let job = self.jobs.remove_process_reference(pid);
        if let Some(section) = process.image_section {
            if let Some(section) = self
                .sections
                .get_mut(section as usize)
                .and_then(Option::as_mut)
            {
                section.map_refs = section.map_refs.saturating_sub(1);
            }
        }
        Some(ProcessObjectDeletion {
            primary_token: process.primary_token,
            exception_port: process.exception_port_endpoint,
            job,
            deleted_threads,
        })
    }

    /// Pre-reserve `pid`'s handle-table capacity so subsequent [`insert_handle`](Self::insert_handle)
    /// calls write into already-allocated storage and never reallocate (spec §8.1). A host on a
    /// bump/reset allocator reserves the durable table at boot (below its per-call reset mark), so
    /// handle inserts during a serviced call don't leak into the transient region. No-op for an
    /// unknown pid.
    pub fn reserve_handles(&mut self, pid: ProcessId, capacity: usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            if capacity > proc.handles.capacity() {
                proc.handles.reserve(capacity - proc.handles.capacity());
            }
        }
    }

    /// Claim one exact, invisible handle slot before an external operation begins. Ordinary handle
    /// insertion skips it until commit or cancellation consumes the reservation.
    pub fn try_reserve_handle_slot(&mut self, pid: ProcessId) -> Result<HandleReservation, u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let generation = proc.next_handle_reservation_generation;
        proc.next_handle_reservation_generation = generation.wrapping_add(1).max(1);
        let slot = if let Some(slot) = proc.handles.iter().position(HandleSlot::is_free) {
            proc.handles[slot] = HandleSlot::Reserved(generation);
            slot
        } else {
            if proc.handles.len() == proc.handles.capacity() {
                proc.handles
                    .try_reserve(1)
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            }
            let slot = proc.handles.len();
            proc.handles.push(HandleSlot::Reserved(generation));
            slot
        };
        Ok(HandleReservation {
            process_id: pid,
            handle: slot_to_handle(slot),
            generation,
        })
    }

    /// Bind an object into its exact reservation while keeping the handle invisible. This is the
    /// first leg of a cross-subsystem publication transaction.
    pub fn bind_reserved_handle(
        &mut self,
        reservation: HandleReservation,
        object: HandleObject,
        granted_access: u32,
    ) -> Result<(), u32> {
        match object {
            HandleObject::Process(target) if !self.processes.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            HandleObject::Thread(target) if !self.threads.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            _ => {}
        }
        let proc = self
            .processes
            .get_mut(&reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = proc.handles.get_mut(slot).ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(entry, HandleSlot::Reserved(generation) if *generation == reservation.generation)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        *entry = HandleSlot::Bound {
            generation: reservation.generation,
            entry: HandleEntry {
                object,
                granted_access,
                flags: HandleFlags::default(),
            },
        };
        Ok(())
    }

    /// Make one bound handle visible. No allocation or object validation remains at this point.
    pub fn publish_reserved_handle(
        &mut self,
        reservation: HandleReservation,
    ) -> Result<Handle, u32> {
        let proc = self
            .processes
            .get_mut(&reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = proc.handles.get_mut(slot).ok_or(STATUS_INVALID_HANDLE)?;
        let HandleSlot::Bound {
            generation,
            entry: _,
        } = entry
        else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if *generation != reservation.generation {
            return Err(STATUS_INVALID_HANDLE);
        }
        let HandleSlot::Bound { entry: bound, .. } = core::mem::replace(entry, HandleSlot::Free)
        else {
            unreachable!();
        };
        let debug_object = match bound.object {
            HandleObject::DebugObject(object) => Some(object),
            _ => None,
        };
        *entry = HandleSlot::Occupied(bound);
        if let Some(object) = debug_object {
            if let Some(debug_object) = self.dbgk.get_mut(object) {
                debug_object.add_handle();
            }
        }
        Ok(reservation.handle)
    }

    /// Release an exact reservation that has not been bound.
    pub fn cancel_reserved_handle(&mut self, reservation: HandleReservation) -> Result<(), u32> {
        let proc = self
            .processes
            .get_mut(&reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = proc.handles.get_mut(slot).ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(entry, HandleSlot::Reserved(generation) if *generation == reservation.generation)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        *entry = HandleSlot::Free;
        Ok(())
    }

    /// Roll back a bound but still-invisible handle and return its object to the external owner.
    pub fn cancel_bound_handle(
        &mut self,
        reservation: HandleReservation,
    ) -> Result<HandleObject, u32> {
        let proc = self
            .processes
            .get_mut(&reservation.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(reservation.handle).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = proc.handles.get_mut(slot).ok_or(STATUS_INVALID_HANDLE)?;
        if !matches!(entry, HandleSlot::Bound { generation, .. } if *generation == reservation.generation)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let HandleSlot::Bound { entry: bound, .. } = core::mem::replace(entry, HandleSlot::Free)
        else {
            unreachable!();
        };
        Ok(bound.object)
    }

    pub fn handle_reservation_count(&self, pid: ProcessId) -> usize {
        self.processes
            .get(&pid)
            .map(|process| {
                process
                    .handles
                    .iter()
                    .filter(|slot| {
                        matches!(slot, HandleSlot::Reserved(_) | HandleSlot::Bound { .. })
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Pre-reserve the per-process TID link set. This is separate from
    /// [`reserve_thread_capacity`](Self::reserve_thread_capacity): the global ETHREAD table stores
    /// objects, while each EPROCESS also owns the ordered set of TIDs belonging to it.
    pub fn reserve_process_threads(&mut self, pid: ProcessId, capacity: usize) {
        if let Some(proc) = self.processes.get_mut(&pid) {
            proc.threads.reserve_capacity(capacity);
        }
    }

    pub fn process_thread_capacity(&self, pid: ProcessId) -> usize {
        self.processes
            .get(&pid)
            .map(|p| p.threads.capacity())
            .unwrap_or(0)
    }

    /// `pid`'s current handle-table capacity (reserved slots) — for a host to check headroom.
    pub fn handle_capacity(&self, pid: ProcessId) -> usize {
        self.processes
            .get(&pid)
            .map(|p| p.handles.capacity())
            .unwrap_or(0)
    }

    pub fn process(&self, pid: ProcessId) -> Option<&NtProcess> {
        self.processes.get(&pid)
    }
    /// Return the initialized per-process pointer cookie, or zero before its first query.
    pub fn process_cookie(&self, pid: ProcessId) -> Option<u32> {
        self.processes
            .get(&pid)
            .map(|process| process.process_cookie)
    }

    /// Initialize a process cookie once. Zero is rejected because it is the process object's
    /// uninitialized sentinel.
    pub fn get_or_initialize_process_cookie(
        &mut self,
        pid: ProcessId,
        candidate: u32,
    ) -> Option<u32> {
        let process = self.processes.get_mut(&pid)?;
        if process.process_cookie == 0 && candidate != 0 {
            process.process_cookie = candidate;
        }
        (process.process_cookie != 0).then_some(process.process_cookie)
    }

    /// Resolve a caller-local process handle (or `NtCurrentProcess`) and return the policy fields
    /// used by `NtQueryInformationProcess(ProcessBasicInformation)`.
    pub fn query_process_basic(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<ProcessBasicInformation, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(ProcessBasicInformation {
            exit_status: if process.state == ProcessState::Terminated {
                process.exit_status.unwrap_or(STATUS_SUCCESS)
            } else {
                STATUS_PENDING
            },
            peb_base_address: process.peb_base_address,
            affinity_mask: process.affinity_mask,
            base_priority: process.base_priority,
            unique_process_id: pid,
            inherited_from_unique_process_id: process.parent.unwrap_or(0),
        })
    }

    /// Return process-level timing by aggregating the ETHREAD accounting already tracked for the
    /// process. This mirrors the kernel's process counters without introducing a second clock model.
    pub fn query_process_times(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<ProcessTimes, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        self.process_times(pid).ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn process_times(&self, pid: ProcessId) -> Option<ProcessTimes> {
        let process = self.process(pid)?;
        let mut create_time = 0;
        let mut exit_time = 0;
        let mut kernel_time = 0i64;
        let mut user_time = 0i64;
        for tid in &process.threads {
            let Some(thread) = self.threads.get(tid) else {
                continue;
            };
            if thread.create_time_100ns != 0
                && (create_time == 0 || thread.create_time_100ns < create_time)
            {
                create_time = thread.create_time_100ns;
            }
            if process.state == ProcessState::Terminated && thread.exit_time_100ns > exit_time {
                exit_time = thread.exit_time_100ns;
            }
            kernel_time = kernel_time.saturating_add(thread.kernel_time_100ns);
            user_time = user_time.saturating_add(thread.user_time_100ns);
        }
        Some(ProcessTimes {
            create_time,
            exit_time,
            kernel_time,
            user_time,
        })
    }

    pub fn query_process_handle_count(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<u32, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        Ok(self.handle_count(pid) as u32)
    }

    pub fn query_process_debug_port(&self, caller_pid: ProcessId, handle: u64) -> Result<u64, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        Ok(if self.process_debug_port(pid).is_some() {
            u64::MAX
        } else {
            0
        })
    }

    pub fn query_process_debug_flags(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<u32, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok((process.state != ProcessState::Terminated && process.debug_port.is_none()) as u32)
    }

    pub fn query_process_priority_class(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<u8, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        self.process(pid)
            .map(|process| process.priority_class)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn query_process_foreground(
        &self,
        caller_pid: ProcessId,
        handle: u64,
    ) -> Result<bool, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        self.process(pid)
            .map(|process| process.foreground)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn query_process_session_id(&self, caller_pid: ProcessId, handle: u64) -> Result<u32, u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, PROCESS_QUERY_INFORMATION)?;
        self.process(pid)
            .map(|process| process.session_id)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn set_process_session_id(&mut self, pid: ProcessId, session_id: u32) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.session_id = session_id;
        Ok(())
    }

    pub fn set_process_priority_class(
        &mut self,
        pid: ProcessId,
        priority_class: u8,
    ) -> Result<(), u32> {
        if !(PROCESS_PRIORITY_CLASS_INVALID..=PROCESS_PRIORITY_CLASS_ABOVE_NORMAL)
            .contains(&priority_class)
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.priority_class = priority_class;
        Ok(())
    }

    pub fn set_process_base_priority(
        &mut self,
        pid: ProcessId,
        base_priority: i32,
    ) -> Result<(), u32> {
        if !((LOW_PRIORITY + 1)..=HIGH_PRIORITY).contains(&base_priority) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.base_priority = base_priority;
        Ok(())
    }

    pub fn set_process_foreground(&mut self, pid: ProcessId, foreground: bool) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.foreground = foreground;
        Ok(())
    }

    /// Install the one permitted `EPROCESS.ExceptionPort` object reference.
    pub fn install_process_exception_port_endpoint(
        &mut self,
        pid: ProcessId,
        endpoint: ExceptionPortEndpoint,
    ) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.exception_port_was_set {
            return Err(STATUS_PORT_ALREADY_SET);
        }
        process.exception_port_endpoint = Some(endpoint);
        process.exception_port_was_set = true;
        Ok(())
    }

    pub fn process_exception_port_endpoint(&self, pid: ProcessId) -> Option<ExceptionPortEndpoint> {
        self.process(pid)
            .and_then(|process| process.exception_port_endpoint)
    }

    /// Remove the broker reference only as part of common process teardown. Runtime callers cannot
    /// replace an installed exception port; the native one-shot invariant remains intact.
    pub fn take_process_exception_port_endpoint(
        &mut self,
        pid: ProcessId,
    ) -> Result<Option<ExceptionPortEndpoint>, u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(process.exception_port_endpoint.take())
    }
    pub fn thread(&self, tid: ThreadId) -> Option<&NtThread> {
        self.threads.get(&tid)
    }

    /// Replace a process primary-token reference and return the prior identity to its owner.
    pub fn replace_process_primary_token(
        &mut self,
        pid: ProcessId,
        token: Option<TokenId>,
    ) -> Result<Option<TokenId>, u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(core::mem::replace(&mut process.primary_token, token))
    }

    pub fn process_primary_token(&self, pid: ProcessId) -> Option<TokenId> {
        self.processes.get(&pid)?.primary_token
    }

    /// Return the process object's self-relative security descriptor after resolving a caller-local
    /// process handle. `NtCurrentProcess()` is the caller and carries maximum pseudo-handle access.
    pub fn process_security_descriptor(
        &self,
        caller_pid: ProcessId,
        handle: u64,
        required_access: u32,
    ) -> Result<&[u8], u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, required_access)?;
        self.processes
            .get(&pid)
            .map(|process| process.security_descriptor.as_slice())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Replace the process object's self-relative security descriptor after the same process-handle
    /// access checks used by other process syscalls.
    pub fn set_process_security_descriptor(
        &mut self,
        caller_pid: ProcessId,
        handle: u64,
        required_access: u32,
        descriptor: Vec<u8>,
    ) -> Result<(), u32> {
        let pid = self.resolve_process_handle(caller_pid, handle, required_access)?;
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.security_descriptor = descriptor;
        Ok(())
    }

    /// Return the thread object's self-relative security descriptor after resolving a caller-local
    /// thread handle. `NtCurrentThread()` resolves through `current_tid` and carries maximum
    /// pseudo-handle access.
    pub fn thread_security_descriptor(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        required_access: u32,
    ) -> Result<&[u8], u32> {
        let tid = self.resolve_thread_handle(caller_pid, current_tid, handle, required_access)?;
        self.threads
            .get(&tid)
            .map(|thread| thread.security_descriptor.as_slice())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// Replace the thread object's self-relative security descriptor after the same thread-handle
    /// access checks used by other thread syscalls.
    pub fn set_thread_security_descriptor(
        &mut self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        required_access: u32,
        descriptor: Vec<u8>,
    ) -> Result<(), u32> {
        let tid = self.resolve_thread_handle(caller_pid, current_tid, handle, required_access)?;
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.security_descriptor = descriptor;
        Ok(())
    }

    /// Replace or clear a thread impersonation context. The returned context lets the caller
    /// release the old token reference after retaining the replacement.
    pub fn replace_thread_impersonation(
        &mut self,
        tid: ThreadId,
        context: Option<ImpersonationContext>,
    ) -> Result<Option<ImpersonationContext>, u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(core::mem::replace(&mut thread.impersonation, context))
    }

    pub fn thread_impersonation(&self, tid: ThreadId) -> Option<ImpersonationContext> {
        self.threads.get(&tid)?.impersonation
    }

    /// Select the thread impersonation token when present, otherwise its process primary token.
    pub fn effective_token(&self, tid: ThreadId) -> Option<TokenId> {
        let thread = self.threads.get(&tid)?;
        thread
            .impersonation
            .map(|context| context.token)
            .or_else(|| self.process_primary_token(thread.process_id))
    }
    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    // --- thread creation (spec §10) ------------------------------------------

    /// `NtCreateThread` / `PsCreateSystemThread` (spec §10): create a thread in `pid`. The first
    /// thread becomes the process's main thread + moves the process `Running`.
    pub fn create_thread(
        &mut self,
        pid: ProcessId,
        start_address: u64,
        parameter: u64,
        is_system_thread: bool,
    ) -> Result<ThreadId, u32> {
        let tid = self.insert_thread_object(
            pid,
            start_address,
            parameter,
            is_system_thread,
            ThreadState::Ready,
            true,
        )?;
        let _ = self.report_existing_thread_create(tid);
        Ok(tid)
    }

    /// Pre-create one dormant ETHREAD identity for a bounded hosted mechanism pool. A dormant
    /// identity is neither runnable nor debugger-reportable and cannot become a process's main
    /// thread; [`prepare_thread_activation`](Self::prepare_thread_activation) is its only route into
    /// the live thread state machine.
    pub fn create_dormant_thread(&mut self, pid: ProcessId) -> Result<ThreadId, u32> {
        if self
            .processes
            .get(&pid)
            .ok_or(STATUS_INVALID_HANDLE)?
            .main_thread
            .is_none()
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.insert_thread_object(pid, 0, 0, false, ThreadState::Initialized, false)
    }

    fn insert_thread_object(
        &mut self,
        pid: ProcessId,
        start_address: u64,
        parameter: u64,
        is_system_thread: bool,
        state: ThreadState,
        may_become_main: bool,
    ) -> Result<ThreadId, u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(proc.state, ProcessState::Exiting | ProcessState::Terminated) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if proc.main_thread.is_none() && !may_become_main {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let affinity_mask = proc.affinity_mask;
        let base_priority = proc.base_priority;
        let mut termination_ports = Vec::new();
        termination_ports
            .try_reserve_exact(THREAD_TERMINATION_PORT_RESERVE)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let tid = allocate_client_id(&mut self.next_cid);
        proc.threads.insert(tid);
        if proc.main_thread.is_none() {
            proc.main_thread = Some(tid);
            proc.state = ProcessState::Running;
        }
        self.threads.insert(
            tid,
            NtThread {
                thread_id: tid,
                process_id: pid,
                start_address,
                win32_start_address: start_address,
                parameter,
                state,
                is_system_thread,
                exit_status: None,
                wait_references: 0,
                create_time_100ns: 0,
                exit_time_100ns: 0,
                kernel_time_100ns: 0,
                user_time_100ns: 0,
                activation_generation: 1,
                termination_ports,
                impersonation: None,
                security_descriptor: Vec::from(&nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..]),
                suspend_count: 0,
                win32_thread: None,
                kernel_thread_object: None,
                teb_base: 0,
                affinity_mask,
                priority: base_priority,
                base_priority,
                ideal_processor: 0,
                break_on_termination: false,
                disable_boost: false,
                hide_from_debugger: false,
                thread_name_len: 0,
                thread_name: Vec::new(),
                user_apc_queue: VecDeque::new(),
            },
        );
        Ok(tid)
    }

    /// A preallocated ETHREAD has transitioned into a real user thread. This is the Dbgk-visible
    /// half of hosted runtime/remote thread activation; dormant `Initialized` pool slots are not NT
    /// threads yet for debugger purposes.
    pub fn report_existing_thread_create(&mut self, tid: ThreadId) -> Option<DebugObjectId> {
        let (pid, start_address) = self.threads.get(&tid).and_then(|thread| {
            Self::thread_is_debug_reportable(thread)
                .then_some((thread.process_id, thread.start_address))
        })?;
        self.report_thread_create_message(pid, tid, start_address)
    }

    fn report_thread_create_message(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        start_address: u64,
    ) -> Option<DebugObjectId> {
        if !self
            .processes
            .get(&pid)
            .is_some_and(|p| p.debug_port.is_some())
        {
            return None;
        }
        let (reported, image_base) = self
            .processes
            .get(&pid)
            .map(|p| (p.create_reported, p.image_base))
            .unwrap_or((true, 0));
        let message = if reported {
            DbgKmMessage::CreateThread {
                sub_system_key: 0,
                start_address,
            }
        } else {
            if let Some(p) = self.processes.get_mut(&pid) {
                p.create_reported = true;
            }
            DbgKmMessage::CreateProcess {
                sub_system_key: 0,
                file_handle: 0,
                base_of_image: image_base,
                debug_info_file_offset: 0,
                debug_info_size: 0,
                initial_thread_sub_system_key: 0,
                initial_thread_start_address: start_address,
            }
        };
        self.report_debug_message(pid, tid, message)
    }

    // --- kernel/win32k per-process/thread context slots (spec §7.4) ----------
    //
    // Kernel-mode providers need stable process/thread object bodies
    // (`EPROCESS`/`ETHREAD`) while win32k parks opaque `W32PROCESS`/`W32THREAD`
    // pointers on those objects. These are pointer slots — the executive stores
    // what the owning boundary hands it and returns it verbatim.

    /// Park the executive-owned `EPROCESS` body pointer on `pid`.
    /// Returns `false` for an unknown process.
    pub fn set_process_kernel_object(&mut self, pid: ProcessId, eprocess: u64) -> bool {
        match self.processes.get_mut(&pid) {
            Some(p) => {
                p.kernel_process_object = (eprocess != 0).then_some(eprocess);
                true
            }
            None => false,
        }
    }

    /// Read back the parked `EPROCESS` body pointer.
    pub fn process_kernel_object(&self, pid: ProcessId) -> Option<u64> {
        self.processes
            .get(&pid)
            .and_then(|p| p.kernel_process_object)
    }

    /// Reverse-map an `EPROCESS` body pointer to the owning PID.
    pub fn pid_for_kernel_process_object(&self, eprocess: u64) -> Option<ProcessId> {
        if eprocess == 0 {
            return None;
        }
        self.processes.iter().find_map(|(&pid, process)| {
            (process.kernel_process_object == Some(eprocess)).then_some(pid)
        })
    }

    /// `PsSetProcessWin32Process`: park win32k's `W32PROCESS` pointer on `pid`.
    /// Returns `false` for an unknown process.
    pub fn set_process_win32(&mut self, pid: ProcessId, win32process: u64) -> bool {
        match self.processes.get_mut(&pid) {
            Some(p) => {
                p.win32_process = (win32process != 0).then_some(win32process);
                true
            }
            None => false,
        }
    }

    /// Clear the parked W32PROCESS only when it still names the provider object whose delete
    /// callout just completed. A stale completion must not detach a newer provider generation.
    pub fn clear_process_win32_exact(&mut self, pid: ProcessId, expected: u64) -> bool {
        if expected == 0 {
            return false;
        }
        match self.processes.get_mut(&pid) {
            Some(process) if process.win32_process == Some(expected) => {
                process.win32_process = None;
                true
            }
            _ => false,
        }
    }

    /// `PsGetProcessWin32Process`: read back the parked `W32PROCESS` pointer
    /// (`0`/`None` if win32k has not attached to `pid`).
    pub fn process_win32(&self, pid: ProcessId) -> Option<u64> {
        self.processes.get(&pid).and_then(|p| p.win32_process)
    }

    /// `PsSetThreadWin32Thread`: park win32k's `W32THREAD` pointer on `tid`.
    pub fn set_thread_win32(&mut self, tid: ThreadId, win32thread: u64) -> bool {
        match self.threads.get_mut(&tid) {
            Some(t) => {
                t.win32_thread = (win32thread != 0).then_some(win32thread);
                true
            }
            None => false,
        }
    }

    /// Clear the parked W32THREAD only after an exact provider ThreadCallout(Exit) completion.
    pub fn clear_thread_win32_exact(&mut self, tid: ThreadId, expected: u64) -> bool {
        if expected == 0 {
            return false;
        }
        match self.threads.get_mut(&tid) {
            Some(thread) if thread.win32_thread == Some(expected) => {
                thread.win32_thread = None;
                true
            }
            _ => false,
        }
    }

    /// `PsGetThreadWin32Thread`: read back the parked `W32THREAD` pointer.
    pub fn thread_win32(&self, tid: ThreadId) -> Option<u64> {
        self.threads.get(&tid).and_then(|t| t.win32_thread)
    }

    /// Park the executive-owned `ETHREAD` body pointer on `tid`.
    /// Returns `false` for an unknown thread.
    pub fn set_thread_kernel_object(&mut self, tid: ThreadId, ethread: u64) -> bool {
        match self.threads.get_mut(&tid) {
            Some(t) => {
                t.kernel_thread_object = (ethread != 0).then_some(ethread);
                true
            }
            None => false,
        }
    }

    /// Read back the parked `ETHREAD` body pointer.
    pub fn thread_kernel_object(&self, tid: ThreadId) -> Option<u64> {
        self.threads.get(&tid).and_then(|t| t.kernel_thread_object)
    }

    /// Reverse-map an `ETHREAD` body pointer to the owning TID.
    pub fn tid_for_kernel_thread_object(&self, ethread: u64) -> Option<ThreadId> {
        if ethread == 0 {
            return None;
        }
        self.threads.iter().find_map(|(&tid, thread)| {
            (thread.kernel_thread_object == Some(ethread)).then_some(tid)
        })
    }

    /// `PsSetProcessWindowStation`: bind a `WINDOWSTATION` to `pid`.
    pub fn set_process_window_station(&mut self, pid: ProcessId, window_station: u64) -> bool {
        match self.processes.get_mut(&pid) {
            Some(p) => {
                p.win32_window_station = (window_station != 0).then_some(window_station);
                true
            }
            None => false,
        }
    }

    /// `PsGetProcessWin32WindowStation`: read back the bound `WINDOWSTATION`.
    pub fn process_window_station(&self, pid: ProcessId) -> Option<u64> {
        self.processes
            .get(&pid)
            .and_then(|p| p.win32_window_station)
    }

    /// `PsEstablishWin32Callouts`: record win32k's callout table. win32k calls
    /// this exactly once at `win32k!DriverEntry`. Returns the previous
    /// registration (`None` on the first, expected, call).
    pub fn establish_win32_callouts(&mut self, callouts: Win32Callouts) -> Option<Win32Callouts> {
        self.win32_callouts.replace(callouts)
    }

    /// The registered win32k callouts, if `PsEstablishWin32Callouts` has run.
    pub fn win32_callouts(&self) -> Option<Win32Callouts> {
        self.win32_callouts
    }

    pub fn client_id(&self, tid: ThreadId) -> Option<ClientId> {
        self.threads.get(&tid).map(|t| ClientId {
            unique_process: t.process_id,
            unique_thread: tid,
        })
    }

    /// Resolve a caller-local thread handle (or `NtCurrentThread`) and return the policy fields used
    /// by `NtQueryInformationThread(ThreadBasicInformation)`. Buffer validation and wire-format
    /// copyout remain the syscall host's responsibility.
    pub fn query_thread_basic(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
    ) -> Result<ThreadBasicInformation, u32> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, handle, THREAD_QUERY_INFORMATION)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(ThreadBasicInformation {
            exit_status: thread.exit_status.unwrap_or(STATUS_PENDING),
            teb_base_address: thread.teb_base,
            client_id: ClientId {
                unique_process: thread.process_id,
                unique_thread: tid,
            },
            affinity_mask: thread.affinity_mask,
            priority: thread.priority,
            base_priority: thread.base_priority,
        })
    }

    /// Return real thread accounting fields after enforcing `THREAD_QUERY_INFORMATION`.
    pub fn query_thread_times(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
    ) -> Result<ThreadTimes, u32> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, handle, THREAD_QUERY_INFORMATION)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(ThreadTimes {
            create_time: thread.create_time_100ns,
            exit_time: if thread.state == ThreadState::Terminated {
                thread.exit_time_100ns
            } else {
                0
            },
            kernel_time: thread.kernel_time_100ns,
            user_time: thread.user_time_100ns,
        })
    }

    /// Query one of the ULONG thread state classes supported by the native API.
    pub fn query_thread_u32(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        information_class: u32,
    ) -> Result<u32, u32> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, handle, THREAD_QUERY_INFORMATION)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        match information_class {
            12 => Ok((self
                .threads
                .values()
                .filter(|candidate| {
                    candidate.process_id == thread.process_id
                        && !matches!(
                            candidate.state,
                            ThreadState::Initialized | ThreadState::Terminated
                        )
                })
                .count()
                == 1) as u32),
            14 => Ok(thread.disable_boost as u32),
            17 => Ok(thread.hide_from_debugger as u32),
            18 => Ok(thread.break_on_termination as u32),
            20 => Ok((thread.state == ThreadState::Terminated) as u32),
            _ => Err(STATUS_INVALID_INFO_CLASS),
        }
    }

    /// Publish host clock/accounting values used by `ThreadTimes`.
    pub fn set_thread_times(
        &mut self,
        tid: ThreadId,
        create_time_100ns: i64,
        exit_time_100ns: i64,
        kernel_time_100ns: i64,
        user_time_100ns: i64,
    ) -> bool {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return false;
        };
        thread.create_time_100ns = create_time_100ns;
        thread.exit_time_100ns = exit_time_100ns;
        thread.kernel_time_100ns = kernel_time_100ns;
        thread.user_time_100ns = user_time_100ns;
        true
    }

    /// Publish monotonic scheduler-owned CPU counters for one ETHREAD. The
    /// values are absolute 100 ns counts, not executive wall-clock deltas.
    pub fn update_thread_cpu_times(
        &mut self,
        tid: ThreadId,
        kernel_time_100ns: i64,
        user_time_100ns: i64,
    ) -> Result<ProcessId, u32> {
        if kernel_time_100ns < 0 || user_time_100ns < 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if kernel_time_100ns < thread.kernel_time_100ns || user_time_100ns < thread.user_time_100ns
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        thread.kernel_time_100ns = kernel_time_100ns;
        thread.user_time_100ns = user_time_100ns;
        Ok(thread.process_id)
    }

    /// Publish scheduler-owned CPU counters and evaluate any job time limits
    /// affected by the new sample.
    pub fn publish_thread_cpu_times(
        &mut self,
        tid: ThreadId,
        kernel_time_100ns: i64,
        user_time_100ns: i64,
    ) -> Result<job::JobTimeLimitActions, u32> {
        let pid = self.update_thread_cpu_times(tid, kernel_time_100ns, user_time_100ns)?;
        let Some(job_id) = self.jobs.job_for_process(pid) else {
            return Ok(job::JobTimeLimitActions::default());
        };
        let process_user_time = self
            .process_times(pid)
            .ok_or(STATUS_INVALID_HANDLE)?
            .user_time;
        let this_period_job_user_time = self.job_accounting(job_id)?.this_period_total_user_time;
        self.jobs
            .evaluate_time_limits(job_id, pid, process_user_time, this_period_job_user_time)
    }

    pub fn set_thread_create_time(&mut self, tid: ThreadId, create_time_100ns: i64) -> bool {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return false;
        };
        thread.create_time_100ns = create_time_100ns;
        true
    }

    pub fn thread_start_address(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
    ) -> Result<u64, u32> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, handle, THREAD_QUERY_INFORMATION)?;
        self.thread(tid)
            .map(|thread| thread.win32_start_address)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    pub fn set_thread_disable_boost(&mut self, tid: ThreadId, disabled: bool) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.disable_boost = disabled;
        Ok(())
    }

    pub fn set_thread_priority(&mut self, tid: ThreadId, priority: i32) -> Result<(), u32> {
        if !((LOW_PRIORITY + 1)..=HIGH_PRIORITY).contains(&priority) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.priority = priority;
        Ok(())
    }

    pub fn set_thread_base_priority(
        &mut self,
        tid: ThreadId,
        base_priority: i32,
    ) -> Result<(), u32> {
        let process_id = self
            .threads
            .get(&tid)
            .map(|thread| thread.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self
            .processes
            .get(&process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let normal_delta =
            (THREAD_BASE_PRIORITY_MIN..=THREAD_BASE_PRIORITY_MAX).contains(&base_priority);
        let special = base_priority == THREAD_BASE_PRIORITY_LOWRT + 1
            || base_priority == THREAD_BASE_PRIORITY_IDLE - 1;
        let realtime_absolute = process.priority_class == PROCESS_PRIORITY_CLASS_REALTIME
            && ((THREAD_BASE_PRIORITY_IDLE - 1)..=HIGH_PRIORITY).contains(&base_priority);
        if !(normal_delta || special || realtime_absolute) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.base_priority = base_priority;
        Ok(())
    }

    pub fn set_thread_affinity_mask(&mut self, tid: ThreadId, affinity: u64) -> Result<(), u32> {
        if affinity == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process_id = self
            .threads
            .get(&tid)
            .map(|thread| thread.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process_affinity = self
            .processes
            .get(&process_id)
            .map(|process| process.affinity_mask)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if affinity & !process_affinity != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.affinity_mask = affinity;
        Ok(())
    }

    pub fn set_thread_ideal_processor(
        &mut self,
        tid: ThreadId,
        ideal_processor: u64,
    ) -> Result<(), u32> {
        if ideal_processor > MAXIMUM_PROCESSORS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.ideal_processor = ideal_processor;
        Ok(())
    }

    pub fn thread_ideal_processor(&self, tid: ThreadId) -> Option<u64> {
        self.thread(tid).map(|thread| thread.ideal_processor)
    }

    pub fn set_thread_hide_from_debugger(&mut self, tid: ThreadId) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.hide_from_debugger = true;
        Ok(())
    }

    /// `ETHREAD.HideFromDebugger` suppresses Dbgk notifications generated by that reporting thread.
    fn thread_hides_from_debugger(&self, pid: ProcessId, tid: ThreadId) -> bool {
        self.threads
            .get(&tid)
            .is_some_and(|thread| thread.process_id == pid && thread.hide_from_debugger)
    }

    fn thread_is_debug_reportable(thread: &NtThread) -> bool {
        !matches!(
            thread.state,
            ThreadState::Initialized | ThreadState::Terminated
        )
    }

    pub fn set_thread_name(&mut self, tid: ThreadId, name: &[u16]) -> Result<(), u32> {
        if name.len() > THREAD_NAME_MAX_UNITS {
            return Err(0xC000_009A);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.thread_name.clear();
        thread.thread_name.extend_from_slice(name);
        thread.thread_name_len = name.len() as u16;
        Ok(())
    }

    pub fn query_thread_name(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        output: &mut [u16; THREAD_NAME_MAX_UNITS],
    ) -> Result<usize, u32> {
        const THREAD_QUERY_INFORMATION: u32 = 0x0040;
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, handle, THREAD_QUERY_INFORMATION)?;
        let thread = self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        let length = thread.thread_name_len as usize;
        output[..length].copy_from_slice(&thread.thread_name[..length]);
        Ok(length)
    }

    pub fn queue_user_apc(
        &mut self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        thread_handle: u64,
        apc: UserApc,
    ) -> Result<ThreadId, u32> {
        let tid =
            self.resolve_thread_handle(caller_pid, current_tid, thread_handle, THREAD_SET_CONTEXT)?;
        self.queue_user_apc_to_thread(tid, apc, None)?;
        Ok(tid)
    }

    /// Queue a user APC from kernel-owned completion machinery that already resolved the issuing
    /// thread. This bypasses user handle access checks, but still applies the same lifetime,
    /// system-thread, and bounded-queue rules as `NtQueueApcThread`.
    pub fn queue_kernel_user_apc(&mut self, tid: ThreadId, apc: UserApc) -> Result<ThreadId, u32> {
        self.queue_user_apc_to_thread(tid, apc, None)?;
        Ok(tid)
    }

    /// Queue one kernel APC for a stable owner. A queued owner cannot be inserted twice; after the
    /// APC is delivered or removed, the same owner may queue its next completion.
    pub fn queue_kernel_user_apc_once(
        &mut self,
        tid: ThreadId,
        source: KernelUserApcSource,
        apc: UserApc,
    ) -> Result<bool, u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.is_system_thread {
            return Err(STATUS_INVALID_HANDLE);
        }
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_UNSUCCESSFUL);
        }
        if thread
            .user_apc_queue
            .iter()
            .any(|queued| queued.source == Some(source))
        {
            return Ok(false);
        }
        thread
            .user_apc_queue
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        thread.user_apc_queue.push_back(QueuedUserApc {
            apc,
            source: Some(source),
        });
        Ok(true)
    }

    pub fn remove_kernel_user_apc(&mut self, tid: ThreadId, source: KernelUserApcSource) -> bool {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return false;
        };
        let Some(position) = thread
            .user_apc_queue
            .iter()
            .position(|queued| queued.source == Some(source))
        else {
            return false;
        };
        thread.user_apc_queue.remove(position).is_some()
    }

    fn queue_user_apc_to_thread(
        &mut self,
        tid: ThreadId,
        apc: UserApc,
        source: Option<KernelUserApcSource>,
    ) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.is_system_thread {
            return Err(STATUS_INVALID_HANDLE);
        }
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_UNSUCCESSFUL);
        }
        thread
            .user_apc_queue
            .try_reserve(1)
            .map_err(|_| STATUS_NO_MEMORY)?;
        thread
            .user_apc_queue
            .push_back(QueuedUserApc { apc, source });
        Ok(())
    }

    pub fn has_user_apc(&self, tid: ThreadId) -> bool {
        self.threads
            .get(&tid)
            .is_some_and(|thread| !thread.user_apc_queue.is_empty())
    }

    pub fn peek_user_apc(&self, tid: ThreadId) -> Option<UserApc> {
        let thread = self.threads.get(&tid)?;
        thread.user_apc_queue.front().map(|queued| queued.apc)
    }

    pub fn take_user_apc(&mut self, tid: ThreadId) -> Option<UserApc> {
        self.threads
            .get_mut(&tid)?
            .user_apc_queue
            .pop_front()
            .map(|queued| queued.apc)
    }

    pub fn clear_user_apcs(&mut self, tid: ThreadId) -> bool {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return false;
        };
        thread.user_apc_queue.clear();
        true
    }

    /// Resolve a caller-local thread handle for an operation requiring `required_access`.
    /// `NtCurrentThread` resolves to the supplied scheduling identity rather than assuming the
    /// process main thread, which is essential once multiple user threads share one process.
    pub fn resolve_thread_handle(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        required_access: u32,
    ) -> Result<ThreadId, u32> {
        let tid = if handle == u64::MAX - 1 {
            let current = self.thread(current_tid).ok_or(STATUS_INVALID_HANDLE)?;
            if current.process_id != caller_pid {
                return Err(STATUS_INVALID_HANDLE);
            }
            current_tid
        } else {
            let handle = handle as Handle;
            let tid = match self.lookup_handle(caller_pid, handle) {
                Some(HandleObject::Thread(tid)) => tid,
                _ => return Err(STATUS_INVALID_HANDLE),
            };
            let granted = self
                .handle_access(caller_pid, handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            if granted & required_access != required_access {
                return Err(STATUS_ACCESS_DENIED);
            }
            tid
        };
        self.thread(tid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(tid)
    }

    /// Resolve a caller-local process handle (or `NtCurrentProcess`) with an access check.
    pub fn resolve_process_handle(
        &self,
        caller_pid: ProcessId,
        handle: u64,
        required_access: u32,
    ) -> Result<ProcessId, u32> {
        let pid = if handle == u64::MAX {
            caller_pid
        } else {
            let handle = handle as Handle;
            let pid = match self.lookup_handle(caller_pid, handle) {
                Some(HandleObject::Process(pid)) => pid,
                _ => return Err(STATUS_INVALID_HANDLE),
            };
            let granted = self
                .handle_access(caller_pid, handle)
                .ok_or(STATUS_INVALID_HANDLE)?;
            if granted & required_access != required_access {
                return Err(STATUS_ACCESS_DENIED);
            }
            pid
        };
        self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        Ok(pid)
    }

    /// Open a process selected by a captured native `CLIENT_ID` and place the new
    /// typed handle in the caller's table.
    ///
    /// A nonzero thread id must belong to the requested process; native process
    /// lookup distinguishes an invalid PID from an invalid PID/TID pair.
    pub fn open_process_by_client_id(
        &mut self,
        caller_pid: ProcessId,
        client_id: ClientId,
        granted_access: u32,
    ) -> Result<Handle, u32> {
        if self.process(caller_pid).is_none() {
            return Err(STATUS_INVALID_HANDLE);
        }
        let target_pid = if client_id.unique_thread != 0 {
            let thread = self
                .thread(client_id.unique_thread)
                .ok_or(STATUS_INVALID_CID)?;
            if thread.process_id != client_id.unique_process {
                return Err(STATUS_INVALID_CID);
            }
            thread.process_id
        } else {
            self.process(client_id.unique_process)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            client_id.unique_process
        };
        self.insert_handle(
            caller_pid,
            HandleObject::Process(target_pid),
            granted_access,
        )
    }

    /// Open a thread selected by a captured native `CLIENT_ID` and place the typed handle in the
    /// caller's table. A zero process id is permitted; otherwise it must own the selected thread.
    pub fn open_thread_by_client_id(
        &mut self,
        caller_pid: ProcessId,
        client_id: ClientId,
        granted_access: u32,
    ) -> Result<Handle, u32> {
        if self.process(caller_pid).is_none() {
            return Err(STATUS_INVALID_HANDLE);
        }
        let missing_status = if client_id.unique_process == 0 {
            STATUS_INVALID_PARAMETER
        } else {
            STATUS_INVALID_CID
        };
        let thread = self.thread(client_id.unique_thread).ok_or(missing_status)?;
        if client_id.unique_process != 0 && thread.process_id != client_id.unique_process {
            return Err(STATUS_INVALID_CID);
        }
        self.insert_handle(
            caller_pid,
            HandleObject::Thread(client_id.unique_thread),
            granted_access,
        )
    }

    pub fn process_break_on_termination(&self, pid: ProcessId) -> Option<bool> {
        self.process(pid)
            .map(|process| process.break_on_termination)
    }

    pub fn process_default_hard_error_processing(&self, pid: ProcessId) -> Option<u32> {
        self.process(pid)
            .map(|process| process.default_hard_error_processing)
    }

    pub fn set_process_default_hard_error_processing(
        &mut self,
        pid: ProcessId,
        mode: u32,
    ) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.default_hard_error_processing = mode;
        Ok(())
    }

    pub fn set_process_break_on_termination(
        &mut self,
        pid: ProcessId,
        enabled: bool,
    ) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.break_on_termination = enabled;
        Ok(())
    }

    pub fn thread_break_on_termination(&self, tid: ThreadId) -> Option<bool> {
        self.thread(tid).map(|thread| thread.break_on_termination)
    }

    pub fn set_thread_break_on_termination(
        &mut self,
        tid: ThreadId,
        enabled: bool,
    ) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.break_on_termination = enabled;
        Ok(())
    }

    /// Bugcheck code required before a direct process termination, if the process is critical.
    pub fn critical_process_termination_code(&self, pid: ProcessId) -> Option<u32> {
        self.process(pid)
            .filter(|process| process.break_on_termination)
            .map(|_| 0x0000_00F4) // CRITICAL_OBJECT_TERMINATION
    }

    /// Bugcheck code required before terminating `tid`. A critical ETHREAD uses
    /// CRITICAL_OBJECT_TERMINATION; terminating the last active thread of a critical EPROCESS uses
    /// CRITICAL_PROCESS_DIED.
    pub fn critical_thread_termination_code(&self, tid: ThreadId) -> Option<u32> {
        let thread = self.thread(tid)?;
        if thread.break_on_termination {
            return Some(0x0000_00F4);
        }
        let process = self.process(thread.process_id)?;
        if !process.break_on_termination || thread.is_system_thread {
            return None;
        }
        let other_active = self.threads.values().any(|candidate| {
            candidate.thread_id != tid
                && candidate.process_id == thread.process_id
                && !candidate.is_system_thread
                && !matches!(
                    candidate.state,
                    ThreadState::Initialized | ThreadState::Terminated
                )
        });
        (!other_active).then_some(0x0000_00EF) // CRITICAL_PROCESS_DIED
    }

    /// Resolve the target of `NtTerminateThread`. In addition to the ordinary typed thread handle
    /// and `NtCurrentThread` pseudo-handle forms, NT defines a NULL handle as the current thread for
    /// this service (the form used by ReactOS kernel32!ExitThread).
    pub fn resolve_terminate_thread_handle(
        &self,
        caller_pid: ProcessId,
        current_tid: ThreadId,
        handle: u64,
        required_access: u32,
    ) -> Result<ThreadId, u32> {
        self.resolve_thread_handle(
            caller_pid,
            current_tid,
            if handle == 0 { u64::MAX - 1 } else { handle },
            required_access,
        )
    }

    /// A terminated ETHREAD may only be recycled after every process handle referring to it has
    /// closed. Hosts can use this predicate to avoid TID/slot aliasing while reclaiming mechanism
    /// resources independently of the policy object.
    pub fn can_reclaim_thread(&self, tid: ThreadId) -> bool {
        self.thread(tid).is_some_and(|thread| {
            thread.state == ThreadState::Terminated && thread.wait_references == 0
        }) && !self.processes.values().any(|process| {
            process.handles.iter().any(|entry| {
                entry
                    .entry()
                    .is_some_and(|entry| entry.object == HandleObject::Thread(tid))
            })
        })
    }

    /// Validate an activation without changing the ETHREAD or making it debugger-reportable.
    pub fn prepare_thread_activation(
        &self,
        tid: ThreadId,
        start_address: u64,
        parameter: u64,
        create_suspended: bool,
        teb_base: u64,
        create_time_100ns: i64,
        hide_from_debugger: bool,
    ) -> Result<ThreadActivationPlan, u32> {
        if start_address == 0 || teb_base == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let thread = self.threads.get(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        let process = self
            .processes
            .get(&thread.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let reusable = match thread.state {
            ThreadState::Initialized => {
                thread.wait_references == 0
                    && thread.termination_ports.is_empty()
                    && thread.impersonation.is_none()
                    && thread.user_apc_queue.is_empty()
                    && !self.processes.values().any(|process| {
                        process.handles.iter().any(|entry| {
                            entry
                                .entry()
                                .is_some_and(|entry| entry.object == HandleObject::Thread(tid))
                        })
                    })
            }
            ThreadState::Terminated => self.can_reclaim_thread(tid),
            _ => false,
        };
        if !reusable {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if thread.security_descriptor.capacity()
            < nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR.len()
        {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(ThreadActivationPlan {
            tid,
            process_id: thread.process_id,
            generation: thread.activation_generation,
            expected_state: thread.state,
            start_address,
            parameter,
            create_suspended,
            teb_base,
            create_time_100ns,
            hide_from_debugger,
        })
    }

    /// Publish a prepared hosted ETHREAD activation. Debug notification remains a separate final
    /// step so the host can make the already-bound user handle visible first.
    pub fn commit_thread_activation(&mut self, plan: ThreadActivationPlan) -> Result<(), u32> {
        let current = self.threads.get(&plan.tid).ok_or(STATUS_INVALID_HANDLE)?;
        if current.process_id != plan.process_id
            || current.activation_generation != plan.generation
            || current.state != plan.expected_state
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process = self
            .processes
            .get(&plan.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let affinity_mask = process.affinity_mask;
        let base_priority = process.base_priority;
        let reusable = match current.state {
            ThreadState::Initialized => {
                current.wait_references == 0
                    && current.termination_ports.is_empty()
                    && current.impersonation.is_none()
                    && current.user_apc_queue.is_empty()
                    && !self.processes.values().any(|process| {
                        process.handles.iter().any(|entry| {
                            entry
                                .entry()
                                .is_some_and(|entry| entry.object == HandleObject::Thread(plan.tid))
                        })
                    })
            }
            ThreadState::Terminated => self.can_reclaim_thread(plan.tid),
            _ => false,
        };
        if !reusable {
            return Err(STATUS_INVALID_PARAMETER);
        }

        let default_security = &nt_security::DEFAULT_KEY_SECURITY_DESCRIPTOR[..];
        let thread = self
            .threads
            .get_mut(&plan.tid)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if thread.security_descriptor.capacity() < default_security.len() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        thread.start_address = plan.start_address;
        thread.win32_start_address = plan.start_address;
        thread.parameter = plan.parameter;
        thread.state = if plan.create_suspended {
            ThreadState::Suspended
        } else {
            ThreadState::Running
        };
        thread.exit_status = None;
        thread.create_time_100ns = plan.create_time_100ns;
        thread.exit_time_100ns = 0;
        thread.kernel_time_100ns = 0;
        thread.user_time_100ns = 0;
        thread.termination_ports.clear();
        thread.suspend_count = plan.create_suspended as u32;
        thread.win32_thread = None;
        thread.teb_base = plan.teb_base;
        thread.affinity_mask = affinity_mask;
        thread.priority = base_priority;
        thread.base_priority = base_priority;
        thread.ideal_processor = 0;
        thread.security_descriptor.clear();
        thread
            .security_descriptor
            .extend_from_slice(default_security);
        thread.break_on_termination = false;
        thread.disable_boost = false;
        thread.hide_from_debugger = plan.hide_from_debugger;
        thread.thread_name_len = 0;
        thread.thread_name.clear();
        thread.user_apc_queue.clear();
        thread.activation_generation = thread.activation_generation.wrapping_add(1).max(1);
        Ok(())
    }

    /// Bind a thread's start address (spec §10) — a host that pre-creates the main thread as an
    /// identity (before its image entry point is known) sets it once the entry is resolved at the
    /// real spawn. Returns `false` for an unknown thread. Alloc-free (a field write) so it is safe
    /// to call during a serviced call on a reset bump allocator.
    pub fn set_thread_start_address(&mut self, tid: ThreadId, start_address: u64) -> bool {
        match self.threads.get_mut(&tid) {
            Some(t) => {
                t.start_address = start_address;
                t.win32_start_address = start_address;
                true
            }
            None => false,
        }
    }

    /// Set the user-visible Win32 entry point without altering the scheduler's execution entry.
    pub fn set_thread_win32_start_address(
        &mut self,
        tid: ThreadId,
        start_address: u64,
    ) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.win32_start_address = start_address;
        Ok(())
    }

    /// Bind a thread's TEB base VA (spec §7.2) — the host sets it once it maps the thread's TEB page
    /// at the real spawn. Returns `false` for an unknown thread. Alloc-free (a field write), so it is
    /// safe to call during a serviced call on a reset bump allocator.
    pub fn set_thread_teb(&mut self, tid: ThreadId, teb_base: u64) -> bool {
        match self.threads.get_mut(&tid) {
            Some(t) => {
                t.teb_base = teb_base;
                true
            }
            None => false,
        }
    }

    /// Read back a thread's TEB base VA (`0` until the host maps it) — for
    /// `NtQueryInformationThread(ThreadBasicInformation).TebBaseAddress`.
    pub fn thread_teb(&self, tid: ThreadId) -> Option<u64> {
        self.threads.get(&tid).map(|t| t.teb_base)
    }

    /// Visit every mapped TEB belonging to `pid` without allocating. Unknown processes are rejected;
    /// threads whose TEB has not been mapped yet are skipped.
    pub fn for_each_process_thread_teb<F>(&self, pid: ProcessId, mut f: F) -> Result<(), u32>
    where
        F: FnMut(ThreadId, u64),
    {
        let process = self.processes.get(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        for tid in &process.threads {
            if let Some(teb) = self.thread_teb(*tid).filter(|teb| *teb != 0) {
                f(*tid, teb);
            }
        }
        Ok(())
    }

    /// The `pid`'s main (first) thread id, if any (spec §7.1) — the identity a host binds/queries.
    pub fn main_thread(&self, pid: ProcessId) -> Option<ThreadId> {
        self.processes.get(&pid).and_then(|p| p.main_thread)
    }

    /// Return whether `current_tid` has another runnable thread. This is the NT scheduler's
    /// ready-summary predicate in process-manager terms: initialized/suspended/waiting/terminated
    /// threads are not candidates, while ready and already-running peers are.
    pub fn has_yield_candidate(&self, current_tid: ThreadId) -> bool {
        self.threads.iter().any(|(&tid, thread)| {
            tid != current_tid && matches!(thread.state, ThreadState::Ready | ThreadState::Running)
        })
    }

    /// A scheduling-state transition (spec §11.2), e.g. `Ready` → `Running` → `Waiting`.
    pub fn set_thread_state(&mut self, tid: ThreadId, state: ThreadState) -> Result<(), u32> {
        let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if t.state == ThreadState::Terminated {
            return Err(STATUS_INVALID_PARAMETER);
        }
        t.state = state;
        if state == ThreadState::Initialized {
            t.suspend_count = 0;
        }
        if state == ThreadState::Terminated {
            t.user_apc_queue.clear();
        }
        Ok(())
    }

    /// Increment a thread's suspend count and return its previous value. The first suspension
    /// removes the thread from the runnable set; nested suspensions retain that state until the
    /// matching final resume.
    pub fn suspend_thread(&mut self, tid: ThreadId) -> Result<u32, u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let previous = thread.suspend_count;
        thread.suspend_count = thread
            .suspend_count
            .checked_add(1)
            .ok_or(STATUS_SUSPEND_COUNT_EXCEEDED)?;
        thread.state = ThreadState::Suspended;
        Ok(previous)
    }

    /// Decrement a thread's suspend count and return its previous value. A zero-count resume is a
    /// successful no-op, matching `NtResumeThread`; the final resume makes the thread ready.
    pub fn resume_thread(&mut self, tid: ThreadId) -> Result<u32, u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let previous = thread.suspend_count;
        if previous != 0 {
            thread.suspend_count -= 1;
            if thread.suspend_count == 0 {
                thread.state = ThreadState::Ready;
            }
        }
        Ok(previous)
    }

    // --- termination + signalling (spec §12.3, §21) --------------------------

    /// Attach a referenced LPC port object to the current ETHREAD. Registrations are intentionally
    /// not deduplicated: NT allocates one termination record per call and later delivers them LIFO.
    /// Capacity is reserved when the thread object is created so this mutation is safe under a
    /// rewindable syscall allocator.
    pub fn register_thread_termination_port(
        &mut self,
        tid: ThreadId,
        port: u64,
    ) -> Result<(), u32> {
        if port == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.state == ThreadState::Terminated {
            return Err(STATUS_THREAD_IS_TERMINATING);
        }
        if thread.termination_ports.len() == thread.termination_ports.capacity() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        thread.termination_ports.push(port);
        Ok(())
    }

    /// Remove the most recently registered termination port. Teardown calls this until `None`,
    /// which both enforces native LIFO delivery and releases every retained registration exactly
    /// once even when delivery itself fails.
    pub fn pop_thread_termination_port(&mut self, tid: ThreadId) -> Result<Option<u64>, u32> {
        self.threads
            .get_mut(&tid)
            .map(|thread| thread.termination_ports.pop())
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// `NtTerminateThread` (spec §21.1): set the exit status, mark terminated (signalled), and if
    /// this was the last non-system thread, initiate process exit.
    pub fn terminate_thread(&mut self, tid: ThreadId, exit_status: u32) -> Result<(), u32> {
        self.terminate_thread_at(tid, exit_status, 0)
    }

    /// Terminate a thread and stamp every ETHREAD transitioned by the last-thread cascade.
    pub fn terminate_thread_at(
        &mut self,
        tid: ThreadId,
        exit_status: u32,
        exit_time_100ns: i64,
    ) -> Result<(), u32> {
        let (pid, was_system, transitioned) = {
            let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
            let transitioned = t.state != ThreadState::Terminated;
            if transitioned {
                t.state = ThreadState::Terminated;
                t.exit_status = Some(exit_status);
                t.user_apc_queue.clear();
                if exit_time_100ns != 0 || t.exit_time_100ns == 0 {
                    t.exit_time_100ns = exit_time_100ns;
                }
            }
            (t.process_id, t.is_system_thread, transitioned)
        };
        if !transitioned {
            return Ok(());
        }
        // Dbgk event source: a thread exit in a debugged process reports DbgKmExitThreadApi.
        let _ = self.report_debug_message(pid, tid, DbgKmMessage::ExitThread { exit_status });
        if !was_system {
            let remaining = self
                .threads
                .values()
                .filter(|t| {
                    t.process_id == pid
                        && !t.is_system_thread
                        && !matches!(t.state, ThreadState::Initialized | ThreadState::Terminated)
                })
                .count();
            if remaining == 0 {
                self.terminate_process_at(pid, exit_status, exit_time_100ns)?;
            }
        }
        Ok(())
    }

    /// Terminate a SINGLE thread WITHOUT the last-thread process-exit cascade (unlike
    /// [`terminate_thread`](Self::terminate_thread)). For a hosted process whose OTHER threads keep
    /// it alive even though this (main/init) thread exits — e.g. csrss.exe's init thread calls
    /// `NtTerminateThread(NtCurrentThread())` and CSRSRV's API worker threads keep the process
    /// running ("CSRSRV keeps us going"). Marks the ETHREAD Terminated (signalled) + records the
    /// exit status; the EPROCESS stays whatever it was (Running). Alloc-free (in-place field writes
    /// on an already-allocated node) — safe to call under the executive's per-syscall heap reset.
    pub fn exit_thread(&mut self, tid: ThreadId, exit_status: u32) -> Result<(), u32> {
        self.exit_thread_at(tid, exit_status, 0)
    }

    /// Terminate one thread without process-exit cascading and retain its first exit timestamp.
    pub fn exit_thread_at(
        &mut self,
        tid: ThreadId,
        exit_status: u32,
        exit_time_100ns: i64,
    ) -> Result<(), u32> {
        let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        let transitioned = t.state != ThreadState::Terminated;
        let pid = t.process_id;
        if transitioned {
            t.state = ThreadState::Terminated;
            t.exit_status = Some(exit_status);
            t.user_apc_queue.clear();
            if exit_time_100ns != 0 || t.exit_time_100ns == 0 {
                t.exit_time_100ns = exit_time_100ns;
            }
        }
        if transitioned {
            // Dbgk event source: DbgKmExitThreadApi (the no-cascade self-exit path).
            let _ = self.report_debug_message(pid, tid, DbgKmMessage::ExitThread { exit_status });
        }
        Ok(())
    }

    /// `NtTerminateProcess` (spec §21.2): terminate all threads, set the exit status, and mark the
    /// process terminated (signalled). Releases the image-section map ref (spec §13.7).
    pub fn terminate_process(&mut self, pid: ProcessId, exit_status: u32) -> Result<(), u32> {
        self.terminate_process_at(pid, exit_status, 0)
    }

    /// Terminate a process and stamp only threads that transition during this call.
    pub fn terminate_process_at(
        &mut self,
        pid: ProcessId,
        exit_status: u32,
        exit_time_100ns: i64,
    ) -> Result<(), u32> {
        let (thread_count, section) = {
            let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
            if proc.state == ProcessState::Terminated {
                return Ok(());
            }
            proc.state = ProcessState::Terminated;
            proc.exit_status = Some(exit_status);
            (proc.threads.len(), proc.image_section)
        };
        for index in 0..thread_count {
            let Some(tid) = self
                .processes
                .get(&pid)
                .and_then(|proc| proc.threads.get(index).copied())
            else {
                continue;
            };
            if let Some(t) = self.threads.get_mut(&tid) {
                if t.state != ThreadState::Terminated {
                    t.state = ThreadState::Terminated;
                    t.exit_status = Some(exit_status);
                    t.user_apc_queue.clear();
                    if exit_time_100ns != 0 || t.exit_time_100ns == 0 {
                        t.exit_time_100ns = exit_time_100ns;
                    }
                }
            }
        }
        if let Some(times) = self.process_times(pid) {
            let notifications = self.jobs.exit_process(pid, times, exit_status);
            self.jobs.queue_notifications(notifications);
        }
        if let Some(sid) = section {
            if let Some(s) = self.sections.get_mut(sid as usize).and_then(|s| s.as_mut()) {
                s.map_refs = s.map_refs.saturating_sub(1);
            }
        }
        // Dbgk event source (`DbgkExitProcess`): report the process exit against its main thread's
        // CLIENT_ID. The debug port itself stays set — the debugger still has to retrieve and
        // continue this last event; it is dropped by an explicit detach or by the debug object's
        // destruction.
        let main = self
            .processes
            .get(&pid)
            .and_then(|p| p.main_thread)
            .unwrap_or(0);
        let _ = self.report_debug_message(pid, main, DbgKmMessage::ExitProcess { exit_status });
        Ok(())
    }

    /// ReactOS/NT `NtTerminateProcess(NULL, status)` suicide phase: terminate every other thread in
    /// the current process, but leave the caller running so user-mode shutdown can unload DLLs and
    /// notify CSRSS before the final handle-form self-termination.
    pub fn terminate_process_other_threads_at(
        &mut self,
        pid: ProcessId,
        current_tid: ThreadId,
        exit_status: u32,
        exit_time_100ns: i64,
    ) -> Result<(), u32> {
        let thread_count = {
            let proc = self.processes.get(&pid).ok_or(STATUS_INVALID_HANDLE)?;
            if proc.state == ProcessState::Terminated {
                return Ok(());
            }
            proc.threads.len()
        };
        for index in 0..thread_count {
            let Some(tid) = self
                .processes
                .get(&pid)
                .and_then(|proc| proc.threads.get(index).copied())
            else {
                continue;
            };
            if tid != current_tid {
                let _ = self.exit_thread_at(tid, exit_status, exit_time_100ns);
            }
        }
        Ok(())
    }

    /// A process/thread is a waitable dispatcher object, signalled once terminated (spec §12.1).
    pub fn retain_process_wait_reference(&mut self, pid: ProcessId) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.wait_references = process
            .wait_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn release_process_wait_reference(&mut self, pid: ProcessId) -> Result<(), u32> {
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        process.wait_references = process
            .wait_references
            .checked_sub(1)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(())
    }

    pub fn retain_thread_wait_reference(&mut self, tid: ThreadId) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.wait_references = thread
            .wait_references
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    pub fn release_thread_wait_reference(&mut self, tid: ThreadId) -> Result<(), u32> {
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        thread.wait_references = thread
            .wait_references
            .checked_sub(1)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        Ok(())
    }

    pub fn process_wait_references(&self, pid: ProcessId) -> Option<u32> {
        self.processes
            .get(&pid)
            .map(|process| process.wait_references)
    }

    pub fn thread_wait_references(&self, tid: ThreadId) -> Option<u32> {
        self.threads.get(&tid).map(|thread| thread.wait_references)
    }

    pub fn is_process_signaled(&self, pid: ProcessId) -> bool {
        self.processes
            .get(&pid)
            .map(|p| p.state == ProcessState::Terminated)
            .unwrap_or(false)
    }
    pub fn is_thread_signaled(&self, tid: ThreadId) -> bool {
        self.threads
            .get(&tid)
            .map(|t| t.state == ThreadState::Terminated)
            .unwrap_or(false)
    }
    /// `NtWaitForSingleObject` on a process (spec §12.2): returns the exit status if terminated.
    pub fn wait_process(&self, pid: ProcessId) -> Option<u32> {
        let p = self.processes.get(&pid)?;
        (p.state == ProcessState::Terminated).then_some(p.exit_status.unwrap_or(0))
    }

    // --- Ps job objects ------------------------------------------------------

    pub fn create_job(&mut self, session_id: u32) -> Result<job::JobId, u32> {
        self.jobs.create(session_id)
    }

    pub fn discard_unreferenced_job(&mut self, id: job::JobId) -> bool {
        self.jobs.discard_unreferenced(id)
    }

    pub fn job_exists(&self, id: job::JobId) -> bool {
        self.jobs.contains(id)
    }

    pub fn release_job_handle(&mut self, id: job::JobId) -> Result<job::JobCloseAction, u32> {
        self.jobs.release_handle(id)
    }

    pub fn take_job_destruction(&mut self) -> Option<job::JobDestruction> {
        self.jobs.take_destruction()
    }

    pub fn restore_job_destruction(&mut self, destruction: job::JobDestruction) -> bool {
        self.jobs.restore_destruction(destruction)
    }

    pub fn assign_process_to_job(&mut self, id: job::JobId, pid: ProcessId) -> Result<u32, u32> {
        self.assign_process_to_job_with_commit(id, pid, 0)
    }

    pub fn assign_process_to_job_with_commit(
        &mut self,
        id: job::JobId,
        pid: ProcessId,
        initial_commit_bytes: u64,
    ) -> Result<u32, u32> {
        let plan = self.prepare_process_job_assignment(id, pid, initial_commit_bytes)?;
        self.commit_process_job_assignment(plan)
    }

    pub fn prepare_process_job_assignment(
        &mut self,
        id: job::JobId,
        pid: ProcessId,
        initial_commit_bytes: u64,
    ) -> Result<job::JobAssignmentPlan, u32> {
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let session_id = process.session_id;
        self.jobs
            .prepare_assignment(id, pid, session_id, initial_commit_bytes)
    }

    pub fn commit_process_job_assignment(
        &mut self,
        plan: job::JobAssignmentPlan,
    ) -> Result<u32, u32> {
        let id = plan.job_id();
        let pid = plan.process_id();
        let process = self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        if process.state == ProcessState::Terminated {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let assignment = self.jobs.commit_assignment(plan)?;
        self.jobs.queue_notification(assignment.notification);
        if assignment.status == STATUS_SUCCESS {
            self.apply_job_limits_to_process(id, pid)?;
        }
        Ok(assignment.status)
    }

    fn apply_job_limits_to_process(&mut self, id: job::JobId, pid: ProcessId) -> Result<(), u32> {
        let limits = self.jobs.basic_limits(id)?;
        let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if limits.limit_flags & job::JOB_OBJECT_LIMIT_PRIORITY_CLASS != 0 {
            process.priority_class = limits.priority_class as u8;
        }
        if limits.limit_flags & job::JOB_OBJECT_LIMIT_AFFINITY != 0 {
            process.affinity_mask = limits.affinity;
            for tid in &process.threads {
                if let Some(thread) = self.threads.get_mut(tid) {
                    thread.affinity_mask = limits.affinity;
                }
            }
        }
        Ok(())
    }

    pub fn process_job(&self, pid: ProcessId) -> Option<job::JobId> {
        self.jobs.job_for_process(pid)
    }

    pub fn mark_job_process_forced_termination(&mut self, pid: ProcessId) -> Result<(), u32> {
        self.jobs.mark_process_forced_termination(pid)
    }

    pub fn is_process_in_job(&self, pid: ProcessId, id: Option<job::JobId>) -> Result<u32, u32> {
        self.process(pid).ok_or(STATUS_INVALID_HANDLE)?;
        let process_job = self.jobs.job_for_process(pid);
        Ok(
            if process_job.is_some() && id.is_none_or(|id| process_job == Some(id)) {
                job::STATUS_PROCESS_IN_JOB
            } else {
                job::STATUS_PROCESS_NOT_IN_JOB
            },
        )
    }

    pub fn remove_process_job_reference(&mut self, pid: ProcessId) -> Option<job::JobId> {
        self.jobs.remove_process_reference(pid)
    }

    /// Run the Process object type's delete procedure once no Object Manager or dispatcher
    /// reference can still expose this EPROCESS or one of its ETHREADs. Termination only signals the
    /// objects; deletion is deliberately later. Thread impersonation and termination-port references
    /// must already have been returned by thread rundown.
    pub fn delete_process_object_if_unreferenced(
        &mut self,
        pid: ProcessId,
    ) -> Option<ProcessObjectDeletion> {
        if !self.process_object_delete_ready(pid) {
            return None;
        }
        let process = self.processes.get(&pid)?;
        for tid in &process.threads {
            let thread = self.threads.get(tid)?;
            if thread.impersonation.is_some() {
                return None;
            }
        }

        let process = self
            .processes
            .remove(&pid)
            .expect("validated process remains present until deletion");
        let deleted_threads = process.threads.len();
        for tid in &process.threads {
            let removed = self.threads.remove(tid);
            debug_assert!(removed.is_some());
        }
        self.modules.retain(|module| module.pid != pid);
        let job = self.jobs.remove_process_reference(pid);
        Some(ProcessObjectDeletion {
            primary_token: process.primary_token,
            exception_port: process.exception_port_endpoint,
            job,
            deleted_threads,
        })
    }

    /// Whether only Ps-owned token/port references remain before the process delete procedure can
    /// run. The debug port is detached here once its final event has been continued.
    pub fn process_object_delete_ready(&mut self, pid: ProcessId) -> bool {
        let _ = self.clear_deleted_process_debug_object_if_unreferenced(pid);
        self.process_object_delete_blockers(pid)
            .is_some_and(ProcessObjectDeleteBlockers::delete_ready)
    }

    /// Snapshot every predicate used by [`Self::process_object_delete_ready`]. The scan is
    /// allocation-free and reports the first external owner for process/thread handles so the host
    /// can diagnose a reference leak without reaching into private Object Manager tables.
    pub fn process_object_delete_blockers(
        &self,
        pid: ProcessId,
    ) -> Option<ProcessObjectDeleteBlockers> {
        let process = self.processes.get(&pid)?;
        let mut blockers = ProcessObjectDeleteBlockers {
            state: Some(process.state),
            process_wait_references: process.wait_references,
            debug_port_present: process.debug_port.is_some(),
            own_handle_slots: process
                .handles
                .iter()
                .filter(|slot| !slot.is_free())
                .count(),
            ..ProcessObjectDeleteBlockers::default()
        };

        for (&owner_pid, owner) in self.processes.iter() {
            for slot in &owner.handles {
                let Some(entry) = slot.reference_entry() else {
                    continue;
                };
                match entry.object {
                    HandleObject::Process(target) if target == pid => {
                        blockers.external_process_handles += 1;
                        blockers
                            .first_external_process_handle_owner
                            .get_or_insert(owner_pid);
                    }
                    HandleObject::Thread(target)
                        if process.threads.iter().any(|tid| *tid == target) =>
                    {
                        blockers.external_thread_handles += 1;
                        if blockers.first_external_thread_handle_owner.is_none() {
                            blockers.first_external_thread_handle_owner = Some(owner_pid);
                            blockers.first_external_thread_handle_target = Some(target);
                        }
                    }
                    _ => {}
                }
            }
        }

        for tid in &process.threads {
            let Some(thread) = self.threads.get(tid) else {
                blockers.missing_threads += 1;
                continue;
            };
            blockers.live_threads += usize::from(thread.state != ThreadState::Terminated);
            blockers.thread_wait_references = blockers
                .thread_wait_references
                .saturating_add(thread.wait_references);
            blockers.thread_termination_ports = blockers
                .thread_termination_ports
                .saturating_add(thread.termination_ports.len());
            blockers.thread_impersonations += usize::from(thread.impersonation.is_some());
        }
        Some(blockers)
    }

    pub fn job_active_process_ids_owned(&self, id: job::JobId) -> Result<Vec<ProcessId>, u32> {
        self.jobs.active_process_ids_owned(id)
    }

    pub fn job_process_ids_owned(&self, id: job::JobId) -> Result<(u32, Vec<ProcessId>), u32> {
        self.jobs.process_ids_owned(id)
    }

    pub fn job_accounting(&self, id: job::JobId) -> Result<job::JobAccounting, u32> {
        let mut accounting = self.jobs.accounting(id)?;
        for (pid, process) in self.processes.iter() {
            if process.state == ProcessState::Terminated
                || self.jobs.job_for_process(*pid) != Some(id)
            {
                continue;
            }
            if let Some(times) = self.process_times(*pid) {
                accounting.total_user_time =
                    accounting.total_user_time.saturating_add(times.user_time);
                accounting.total_kernel_time = accounting
                    .total_kernel_time
                    .saturating_add(times.kernel_time);
                accounting.this_period_total_user_time = accounting
                    .this_period_total_user_time
                    .saturating_add(times.user_time);
                accounting.this_period_total_kernel_time = accounting
                    .this_period_total_kernel_time
                    .saturating_add(times.kernel_time);
            }
        }
        let (period_start_user, period_start_kernel) = self.jobs.time_period_start(id)?;
        accounting.this_period_total_user_time = accounting
            .total_user_time
            .saturating_sub(period_start_user)
            .max(0);
        accounting.this_period_total_kernel_time = accounting
            .total_kernel_time
            .saturating_sub(period_start_kernel)
            .max(0);
        Ok(accounting)
    }

    pub fn job_basic_limits(&self, id: job::JobId) -> Result<job::JobBasicLimits, u32> {
        self.jobs.basic_limits(id)
    }

    pub fn job_extended_limits(&self, id: job::JobId) -> Result<job::JobExtendedLimits, u32> {
        self.jobs.extended_limits(id)
    }

    pub fn set_job_basic_limits(
        &mut self,
        id: job::JobId,
        limits: job::JobBasicLimits,
    ) -> Result<(), u32> {
        let accounting = self.job_accounting(id)?;
        self.jobs.set_basic_limits_at(
            id,
            limits,
            accounting.total_user_time,
            accounting.total_kernel_time,
        )
    }

    pub fn set_job_extended_limits(
        &mut self,
        id: job::JobId,
        limits: job::JobExtendedLimits,
    ) -> Result<(), u32> {
        let plan = self.prepare_job_extended_limits(id, limits)?;
        self.commit_job_extended_limits(plan)
    }

    pub fn prepare_job_extended_limits(
        &self,
        id: job::JobId,
        limits: job::JobExtendedLimits,
    ) -> Result<job::JobExtendedLimitPlan, u32> {
        let accounting = self.job_accounting(id)?;
        self.jobs.prepare_extended_limits_at(
            id,
            limits,
            accounting.total_user_time,
            accounting.total_kernel_time,
        )
    }

    pub fn commit_job_extended_limits(
        &mut self,
        plan: job::JobExtendedLimitPlan,
    ) -> Result<(), u32> {
        self.jobs.commit_extended_limits(plan)
    }

    pub fn has_active_job_time_limits(&self) -> bool {
        self.jobs.has_time_limits()
    }

    pub fn job_ui_restrictions(&self, id: job::JobId) -> Result<u32, u32> {
        self.jobs.ui_restrictions(id)
    }

    pub fn set_job_ui_restrictions(
        &mut self,
        id: job::JobId,
        restrictions: u32,
    ) -> Result<(), u32> {
        self.jobs.set_ui_restrictions(id, restrictions)
    }

    pub fn prepare_job_ui_restrictions(
        &self,
        id: job::JobId,
        restrictions: u32,
    ) -> Result<job::JobUiRestrictionPlan, u32> {
        self.jobs.prepare_ui_restrictions(id, restrictions)
    }

    pub fn commit_job_ui_restrictions(
        &mut self,
        plan: job::JobUiRestrictionPlan,
    ) -> Result<(), u32> {
        self.jobs.commit_ui_restrictions(plan)
    }

    pub fn job_security_limits(&self, id: job::JobId) -> Result<u32, u32> {
        self.jobs.security_limits(id)
    }

    pub fn set_job_security_limits(&mut self, id: job::JobId, limits: u32) -> Result<(), u32> {
        self.jobs.set_security_limits(id, limits)
    }

    pub fn prepare_job_security_limits(
        &self,
        id: job::JobId,
        requested: u32,
    ) -> Result<job::JobSecurityLimitPlan, u32> {
        self.jobs.prepare_security_limits(id, requested)
    }

    pub fn commit_job_security_limits(
        &mut self,
        plan: job::JobSecurityLimitPlan,
    ) -> Result<(), u32> {
        self.jobs.commit_security_limits(plan)
    }

    pub fn job_end_of_job_time_action(&self, id: job::JobId) -> Result<u32, u32> {
        self.jobs.end_of_job_time_action(id)
    }

    pub fn set_job_end_of_job_time_action(
        &mut self,
        id: job::JobId,
        action: u32,
    ) -> Result<(), u32> {
        self.jobs.set_end_of_job_time_action(id, action)
    }

    pub fn complete_job_time_notification(
        &mut self,
        id: job::JobId,
        delivered: bool,
    ) -> Result<bool, u32> {
        self.jobs.complete_job_time_notification(id, delivered)
    }

    pub fn prepare_job_memory_charge(
        &mut self,
        pid: ProcessId,
        bytes: u64,
    ) -> Result<Option<job::JobMemoryChargePlan>, u32> {
        if !self.processes.contains_key(&pid) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.jobs.prepare_memory_charge(pid, bytes)
    }

    pub fn report_process_memory_limit_violation(&mut self, pid: ProcessId) -> Result<(), u32> {
        if !self.processes.contains_key(&pid) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.jobs.report_process_memory_limit(pid)
    }

    pub fn commit_job_memory_charge(&mut self, plan: job::JobMemoryChargePlan) -> Result<(), u32> {
        self.jobs.commit_memory_charge(plan)
    }

    pub fn release_job_memory(&mut self, pid: ProcessId, bytes: u64) -> Result<(), u32> {
        if !self.processes.contains_key(&pid) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.jobs.release_memory(pid, bytes)
    }

    pub fn job_memory_usage(&self, pid: ProcessId) -> Result<(u64, u64), u32> {
        self.jobs.memory_usage(pid)
    }

    pub fn job_completion_port(
        &self,
        id: job::JobId,
    ) -> Result<Option<job::CompletionPortAssociation>, u32> {
        self.jobs.completion_port(id)
    }

    pub fn associate_job_completion_port(
        &mut self,
        id: job::JobId,
        association: job::CompletionPortAssociation,
    ) -> Result<(), u32> {
        self.jobs.associate_completion_port(id, association)
    }

    pub fn job_member_level(&self, id: job::JobId) -> Result<u32, u32> {
        self.jobs.member_level(id)
    }

    pub fn create_job_set(&mut self, members: &[(job::JobId, u32)]) -> Result<(), u32> {
        self.jobs.create_set(members)
    }

    pub fn select_job_from_set(
        &self,
        parent: job::JobId,
        requested_level: u32,
    ) -> Result<job::JobId, u32> {
        self.jobs.select_from_set(parent, requested_level)
    }

    pub fn take_job_notification(&mut self) -> Option<job::JobNotification> {
        self.jobs.take_notification()
    }

    pub fn retain_job_wait_reference(&mut self, id: job::JobId) -> Result<(), u32> {
        self.jobs.retain_wait(id)
    }

    pub fn release_job_wait_reference(&mut self, id: job::JobId) -> Result<bool, u32> {
        self.jobs.release_wait(id)
    }

    pub fn is_job_signaled(&self, id: job::JobId) -> bool {
        self.jobs.is_signaled(id)
    }

    // --- Dbgk: the user-mode debugging plane (ntoskrnl/dbgk) -----------------
    //
    // The DEBUG_OBJECT itself (queue + waiter + continue) is the pure state machine in [`dbgk`];
    // what lives here is the half that needs the process/thread tables: which EPROCESS owns which
    // debug port, the fake create messages an attach posts, and the create/exit event sources.

    /// `NtCreateDebugObject` — create a `DEBUG_OBJECT` with the given `DBGK_*` flags.
    pub fn create_debug_object(&mut self, create_flags: u32) -> Result<DebugObjectId, u32> {
        self.dbgk.create(create_flags)
    }

    /// Borrow a live debug object.
    pub fn debug_object(&self, object: DebugObjectId) -> Option<&dbgk::DebugObject> {
        self.dbgk.get(object)
    }

    /// Mutably borrow a live debug object (`NtSetInformationDebugObject`).
    pub fn debug_object_mut(&mut self, object: DebugObjectId) -> Option<&mut dbgk::DebugObject> {
        self.dbgk.get_mut(object)
    }

    /// Number of live debug objects.
    pub fn debug_object_count(&self) -> usize {
        self.dbgk.len()
    }

    /// Account a removed debug-object handle-table entry. Returns whether that was the last handle.
    pub fn release_debug_object_handle(&mut self, object: DebugObjectId) -> Option<bool> {
        self.dbgk
            .get_mut(object)
            .map(|debug_object| debug_object.release_handle() == 0)
    }

    /// Record `EPROCESS.SectionBaseAddress` for `pid` (reported to a debugger in the
    /// `DbgKmCreateProcessApi` message). Returns `false` for an unknown process.
    pub fn set_image_base(&mut self, pid: ProcessId, base: u64) -> bool {
        match self.processes.get_mut(&pid) {
            Some(p) => {
                p.image_base = base;
                true
            }
            None => false,
        }
    }

    /// Record the user-mode PEB base for `pid` (reported by
    /// `NtQueryInformationProcess(ProcessBasicInformation)`). Returns `false` for an unknown process.
    pub fn set_peb_base(&mut self, pid: ProcessId, base: u64) -> bool {
        match self.processes.get_mut(&pid) {
            Some(p) => {
                p.peb_base_address = base;
                true
            }
            None => false,
        }
    }

    // --- the modelled module list (`PEB->Ldr->InLoadOrderModuleList`) -----------------------------

    /// Record `module` as an IMAGE view mapped into `pid`, replacing any earlier record for the
    /// same base. Returns whether it is now tracked.
    ///
    /// ★ No-ops (returning `false`) while **no** `DEBUG_OBJECT` exists: nothing could ever observe
    /// the list then, and the host's section-mapping path must stay untouched on a boot with no
    /// debugger. Also no-ops once the table is full, exactly as `DbgkpPostFakeModuleMessages`
    /// stops walking after 500 modules.
    fn record_module(&mut self, pid: ProcessId, mut module: ProcessModule) -> bool {
        if self.dbgk.is_empty() || pid == 0 {
            return false;
        }
        module.pid = pid;
        if let Some(slot) = self
            .modules
            .iter_mut()
            .find(|m| m.pid == pid && m.base == module.base)
        {
            *slot = module;
            return true;
        }
        if let Some(slot) = self.modules.iter_mut().find(|m| m.pid == 0) {
            *slot = module;
            return true;
        }
        if self.modules.len() >= self.module_limit {
            return false;
        }
        self.modules.push(module);
        true
    }

    /// Drop the record for the IMAGE view at `base` in `pid`. Returns whether one existed — the
    /// modelled equivalent of `MmUnmapViewOfSection`'s "was this an image VAD?" test, which is what
    /// decides whether `DbgkUnMapViewOfSection` runs at all.
    fn forget_module(&mut self, pid: ProcessId, base: u64) -> bool {
        match self
            .modules
            .iter_mut()
            .find(|m| m.pid == pid && m.base == base)
        {
            Some(slot) => {
                *slot = ProcessModule::default();
                true
            }
            None => false,
        }
    }

    /// The IMAGE views currently mapped into `pid`, in load order, written into `out`; returns how
    /// many were written. This is the list `DbgkpPostFakeModuleMessages` walks.
    pub fn process_modules_into(&self, pid: ProcessId, out: &mut [ProcessModule]) -> usize {
        let mut n = 0;
        for module in self.modules.iter().filter(|m| m.pid == pid) {
            if n == out.len() {
                break;
            }
            out[n] = *module;
            n += 1;
        }
        n
    }

    /// How many IMAGE views are tracked for `pid`.
    pub fn module_count(&self, pid: ProcessId) -> usize {
        self.modules.iter().filter(|m| m.pid == pid).count()
    }

    /// `DbgkMapViewOfSection` — an **IMAGE** view became mapped in `pid` (the caller enforces
    /// image-only, exactly as `MmMapViewOfSection`'s `Section->u.Flags.Image` test does). Records it
    /// in the process's modelled module list and, when the process is being debugged, posts
    /// `DbgKmLoadDllApi` to its `EPROCESS.DebugPort`.
    ///
    /// Returns the debug object the message landed on (`None` = not debugged, so nothing was
    /// posted — the path every map on a boot with no debugger takes).
    pub fn report_module_load(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        module: ProcessModule,
    ) -> Option<DebugObjectId> {
        self.record_module(pid, module);
        self.report_debug_message(
            pid,
            tid,
            DbgKmMessage::LoadDll {
                file_handle: module.file_handle,
                base_of_dll: module.base,
                debug_info_file_offset: module.debug_info_file_offset,
                debug_info_size: module.debug_info_size,
                name_pointer: module.name_pointer,
            },
        )
    }

    /// `DbgkUnMapViewOfSection` — the view at `base` was unmapped from `pid`. Reports
    /// `DbgKmUnloadDllApi` **only when `base` names a tracked IMAGE view**, which is the modelled
    /// form of `MmUnmapViewOfSection`'s `if (DbgBase)` guard: a data / anonymous view was never
    /// recorded, so unmapping one reports nothing.
    pub fn report_module_unload(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        base: u64,
    ) -> Option<DebugObjectId> {
        if !self.forget_module(pid, base) {
            return None;
        }
        self.report_debug_message(pid, tid, DbgKmMessage::UnloadDll { base_address: base })
    }

    /// `EPROCESS.DebugPort` for `pid`.
    pub fn process_debug_port(&self, pid: ProcessId) -> Option<DebugObjectId> {
        self.processes.get(&pid).and_then(|p| p.debug_port)
    }

    /// `PEB.BeingDebugged` for `pid` (`DbgkpMarkProcessPeb`'s modelled state).
    pub fn is_process_being_debugged(&self, pid: ProcessId) -> bool {
        self.processes.get(&pid).is_some_and(|p| p.being_debugged)
    }

    /// `NtDebugActiveProcess` — attach `object` to `pid` on behalf of the `debugger` client.
    ///
    /// Faithful to `DbgkpPostFakeProcessCreateMessages` + `DbgkpSetProcessDebugObject`: a
    /// `DbgKmCreateProcessApi` message is posted for the process's first live thread and a
    /// `DbgKmCreateThreadApi` message for each remaining one, **then** — exactly the order
    /// `DbgkpPostFakeProcessCreateMessages` uses (`DbgkpPostFakeThreadMessages` first, then
    /// `DbgkpPostFakeModuleMessages(Process, FirstThread, …)`) — a `DbgKmLoadDllApi` message for
    /// every IMAGE view already mapped in the target, attributed to that FIRST thread. All are
    /// `NOWAIT|INACTIVE` with the attaching thread as their backout thread; then the debug port is
    /// installed and the first backout event is activated (which signals the debugger). Returns the
    /// number of fake messages posted.
    ///
    /// The process's own image (`EPROCESS.SectionBaseAddress`) is skipped: the
    /// `DbgKmCreateProcessApi` message already carries it, which is why
    /// `DbgkpPostFakeModuleMessages` skips `InLoadOrderModuleList`'s first entry (the executable).
    ///
    /// Errors: `STATUS_ACCESS_DENIED` for a self-attach, `STATUS_PROCESS_IS_TERMINATING` for a dying
    /// target, `STATUS_UNSUCCESSFUL` when the target has no live thread to report,
    /// `STATUS_PORT_ALREADY_SET` when another debugger already owns the process.
    pub fn debug_active_process(
        &mut self,
        pid: ProcessId,
        object: DebugObjectId,
        debugger: ClientId,
    ) -> Result<usize, u32> {
        if self.dbgk.get(object).is_none() {
            return Err(STATUS_INVALID_HANDLE);
        }
        if pid == debugger.unique_process {
            return Err(STATUS_ACCESS_DENIED);
        }
        let Some(proc) = self.processes.get(&pid) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if matches!(proc.state, ProcessState::Exiting | ProcessState::Terminated) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        if proc.debug_port.is_some() {
            return Err(dbgk::STATUS_PORT_ALREADY_SET);
        }
        let image_base = proc.image_base;
        let thread_count = proc.threads.len();
        let first_thread = proc
            .threads
            .iter()
            .copied()
            .find(|tid| {
                self.threads
                    .get(tid)
                    .is_some_and(Self::thread_is_debug_reportable)
            })
            .ok_or(STATUS_UNSUCCESSFUL)?;

        let mut posted = 0usize;
        let mut live_index = 0usize;
        for index in 0..thread_count {
            let Some(tid) = self
                .processes
                .get(&pid)
                .and_then(|proc| proc.threads.get(index).copied())
            else {
                continue;
            };
            let Some(start_address) = self.threads.get(&tid).and_then(|thread| {
                Self::thread_is_debug_reportable(thread).then_some(thread.start_address)
            }) else {
                continue;
            };
            let message = if live_index == 0 {
                DbgKmMessage::CreateProcess {
                    sub_system_key: 0,
                    file_handle: 0,
                    base_of_image: image_base,
                    debug_info_file_offset: 0,
                    debug_info_size: 0,
                    initial_thread_sub_system_key: 0,
                    initial_thread_start_address: start_address,
                }
            } else {
                DbgKmMessage::CreateThread {
                    sub_system_key: 0,
                    start_address,
                }
            };
            let mut event = DebugEvent::new(
                ClientId {
                    unique_process: pid,
                    unique_thread: tid,
                },
                message,
                dbgk::DEBUG_EVENT_NOWAIT | dbgk::DEBUG_EVENT_INACTIVE,
            );
            event.backout_thread = Some(debugger.unique_thread);
            let queued = self
                .dbgk
                .get_mut(object)
                .map(|o| o.queue(event))
                .unwrap_or(Err(STATUS_INVALID_HANDLE));
            if let Err(status) = queued {
                // Back out every message this attach posted, exactly as the failure path does.
                if let Some(o) = self.dbgk.get_mut(object) {
                    let _ = o.flush_process_count(pid);
                }
                return Err(status);
            }
            live_index += 1;
            posted += 1;
        }

        // `DbgkpPostFakeModuleMessages`: after the thread messages, one fake `DbgKmLoadDllApi` per
        // module already mapped in the target, all attributed to the FIRST reported thread (NT
        // passes `FirstThread` in). The executable's own view is skipped — the create-process
        // message above already reported `base_of_image`.
        let mut modules = [ProcessModule::default(); DEFAULT_TRACKED_MODULES];
        let module_count = self.process_modules_into(pid, &mut modules);
        for module in &modules[..module_count] {
            if module.base == image_base {
                continue;
            }
            let mut event = DebugEvent::new(
                ClientId {
                    unique_process: pid,
                    unique_thread: first_thread,
                },
                DbgKmMessage::LoadDll {
                    file_handle: module.file_handle,
                    base_of_dll: module.base,
                    debug_info_file_offset: module.debug_info_file_offset,
                    debug_info_size: module.debug_info_size,
                    // `DbgkpPostFakeModuleMessages` clears NamePointer for a fake message (the name
                    // it does have is a kernel-side UNICODE_STRING, not a debuggee pointer).
                    name_pointer: 0,
                },
                dbgk::DEBUG_EVENT_NOWAIT | dbgk::DEBUG_EVENT_INACTIVE,
            );
            event.backout_thread = Some(debugger.unique_thread);
            let queued = self
                .dbgk
                .get_mut(object)
                .map(|o| o.queue(event))
                .unwrap_or(Err(STATUS_INVALID_HANDLE));
            if let Err(status) = queued {
                if let Some(o) = self.dbgk.get_mut(object) {
                    let _ = o.flush_process_count(pid);
                }
                return Err(status);
            }
            posted += 1;
        }

        if let Some(p) = self.processes.get_mut(&pid) {
            p.debug_port = Some(object);
            p.being_debugged = true;
            p.create_reported = true;
        }
        if let Some(o) = self.dbgk.get_mut(object) {
            o.activate_backout_events(debugger.unique_thread);
        }
        Ok(posted)
    }

    /// `NtRemoveProcessDebug` / `DbgkClearProcessDebugObject` — detach `object` from `pid`, clear
    /// `PEB.BeingDebugged`, and flush the process's queued events. Returns the number flushed.
    pub fn remove_process_debug(
        &mut self,
        pid: ProcessId,
        object: DebugObjectId,
    ) -> Result<usize, u32> {
        let Some(proc) = self.processes.get_mut(&pid) else {
            return Err(STATUS_INVALID_HANDLE);
        };
        if proc.debug_port != Some(object) {
            return Err(dbgk::STATUS_PORT_NOT_SET);
        }
        proc.debug_port = None;
        proc.being_debugged = false;
        let flushed = self
            .dbgk
            .get_mut(object)
            .map(|o| o.flush_process_count(pid))
            .unwrap_or(0);
        Ok(flushed)
    }

    /// `DbgkpCloseObject` — the debugger's last handle went away: mark the object inactive, detach
    /// every process still pointing at it, and drop it. Returns the number of processes detached.
    pub fn destroy_debug_object(&mut self, object: DebugObjectId) -> usize {
        if let Some(o) = self.dbgk.get_mut(object) {
            o.mark_debugger_inactive();
        }
        let mut detached = 0usize;
        for process in self.processes.values_mut() {
            if process.debug_port == Some(object) {
                process.debug_port = None;
                process.being_debugged = false;
                detached += 1;
            }
        }
        self.dbgk.destroy(object);
        detached
    }

    /// `NtWaitForDebugEvent`'s non-blocking core: dequeue the next reportable event from `object`,
    /// open the debugger-process handles the state change carries (`DbgkpOpenHandles`), and render
    /// the `DBGUI_WAIT_STATE_CHANGE`. `Ok(None)` = nothing to report (the caller blocks or times
    /// out); `Err(STATUS_DEBUGGER_INACTIVE)` = the object is dead.
    pub fn wait_for_debug_event(
        &mut self,
        object: DebugObjectId,
        debugger_pid: ProcessId,
    ) -> Result<Option<DebugWaitResult>, u32> {
        let index = match self.dbgk.get_mut(object) {
            Some(o) => o.dequeue_for_wait()?,
            None => return Err(STATUS_INVALID_HANDLE),
        };
        let Some(index) = index else {
            return Ok(None);
        };
        let event = match self.dbgk.get(object).and_then(|o| o.events().get(index)) {
            Some(event) => *event,
            None => return Ok(None),
        };
        let state = event.message.state();
        let want_process = state == dbgk::DBG_CREATE_PROCESS_STATE_CHANGE;
        let want_thread = want_process || state == dbgk::DBG_CREATE_THREAD_STATE_CHANGE;
        let handle_to_process = if want_process && self.processes.contains_key(&debugger_pid) {
            self.insert_handle(
                debugger_pid,
                HandleObject::Process(event.client_id.unique_process),
                PROCESS_ALL_ACCESS,
            )
            .unwrap_or(0)
        } else {
            0
        };
        let handle_to_thread = if want_thread && self.processes.contains_key(&debugger_pid) {
            self.insert_handle(
                debugger_pid,
                HandleObject::Thread(event.client_id.unique_thread),
                THREAD_ALL_ACCESS,
            )
            .unwrap_or(0)
        } else {
            0
        };
        // `DbgkpOpenHandles`'s tail: the two states that carry an image FILE handle
        // (`DbgCreateProcessStateChange` and `DbgLoadDllStateChange`) have it `ObDuplicateObject`ed
        // — `DUPLICATE_SAME_ACCESS` — from the reporting process into the DEBUGGER's table, and
        // left NULL if that fails. The queued message holds the DEBUGGEE's own handle, which is
        // meaningless in the debugger's namespace until it is duplicated.
        let queued_file_handle = match event.message {
            DbgKmMessage::LoadDll { file_handle, .. }
            | DbgKmMessage::CreateProcess { file_handle, .. } => file_handle,
            _ => 0,
        };
        let handle_to_file = if queued_file_handle != 0 {
            self.duplicate_handle(
                event.client_id.unique_process,
                queued_file_handle as Handle,
                debugger_pid,
            )
            .unwrap_or(0)
        } else {
            0
        };
        // Report the DUPLICATED handle, not the debuggee's.
        let mut reported = event;
        match &mut reported.message {
            DbgKmMessage::LoadDll { file_handle, .. }
            | DbgKmMessage::CreateProcess { file_handle, .. } => {
                *file_handle = handle_to_file as u64
            }
            _ => {}
        }
        Ok(Some(DebugWaitResult {
            state,
            client_id: event.client_id,
            handle_to_process,
            handle_to_thread,
            handle_to_file,
            state_change: dbgk::encode_wait_state_change(
                &reported,
                handle_to_process as u64,
                handle_to_thread as u64,
            ),
        }))
    }

    /// `DbgkpQueueMessage`'s blocking half — record `block` as the **blocked reporting thread** of
    /// the event just queued for `client_id` on `object`.
    ///
    /// The reporting thread does not return from its fault/syscall until `NtDebugContinue` resolves
    /// that event; the host owns the actual park (it holds the thread's reply capability) and this
    /// carries the association on the `DEBUG_EVENT`, exactly where NT keeps it. Returns `false` if
    /// no eligible event is queued (the reporter must then NOT be parked).
    pub fn block_reporter(
        &mut self,
        object: DebugObjectId,
        client_id: ClientId,
        block: dbgk::ReporterBlock,
    ) -> bool {
        self.dbgk
            .get_mut(object)
            .is_some_and(|o| o.attach_reporter(client_id, block))
    }

    /// Update the resume context attached to a blocked Dbgk reporter after a debugger changes the
    /// thread context with `NtSetContextThread`.
    pub fn update_blocked_reporter_context(
        &mut self,
        client_id: ClientId,
        resume_ip: Option<u64>,
        resume_sp: Option<u64>,
        resume_flags: Option<u64>,
    ) -> bool {
        let Some(object) = self
            .process(client_id.unique_process)
            .and_then(|process| process.debug_port())
        else {
            return false;
        };
        self.dbgk.get_mut(object).is_some_and(|o| {
            o.update_reporter_context(client_id, resume_ip, resume_sp, resume_flags)
        })
    }

    /// Release every blocked reporter on `object` (optionally only those of `pid`) — the escape
    /// hatch a debug-object teardown / debuggee detach runs so no target stays parked forever.
    pub fn drain_blocked_reporters(
        &mut self,
        object: DebugObjectId,
        pid: Option<ProcessId>,
    ) -> Vec<(ClientId, dbgk::ReporterBlock)> {
        match self.dbgk.get_mut(object) {
            Some(o) => o.drain_reporters(pid),
            None => Vec::new(),
        }
    }

    /// Allocation-free [`drain_blocked_reporters`](Self::drain_blocked_reporters) variant for
    /// bounded hosts. Returns how many entries were written to `out`.
    pub fn drain_blocked_reporters_into(
        &mut self,
        object: DebugObjectId,
        pid: Option<ProcessId>,
        out: &mut [(ClientId, dbgk::ReporterBlock)],
    ) -> usize {
        match self.dbgk.get_mut(object) {
            Some(o) => o.drain_reporters_into(pid, out),
            None => 0,
        }
    }

    /// How many events on `object` currently carry a blocked reporter.
    pub fn blocked_reporter_count(&self, object: DebugObjectId) -> usize {
        self.dbgk
            .get(object)
            .map(|o| o.blocked_reporters())
            .unwrap_or(0)
    }

    /// `NtDebugContinue` — resolve the read event for `client_id` with `continue_status`. Returns
    /// the removed event (whose `returned_status` is the continue status the target would see).
    ///
    /// The removed event carries the **blocked reporting thread** (`DebugEvent::reporter_block`) if
    /// one was parked on it; [`dbgk::wake_action`] turns the continue status into what
    /// `DbgkpWakeTarget` must do with it (resume / leave blocked / terminate).
    pub fn debug_continue(
        &mut self,
        object: DebugObjectId,
        client_id: ClientId,
        continue_status: u32,
    ) -> Result<DebugEvent, u32> {
        let event = match self.dbgk.get_mut(object) {
            Some(o) => o.continue_event(client_id, continue_status),
            None => Err(STATUS_INVALID_HANDLE),
        }?;
        let _ =
            self.clear_deleted_process_debug_object_if_unreferenced(event.client_id.unique_process);
        Ok(event)
    }

    /// Queue a `DBGKM_MSG` against `pid`'s debug port, if it has one. Returns the debug object the
    /// event landed on (`None` = not debugged, or the debugger has gone).
    ///
    /// ★ Every caller is a POSTING SITE: the host mirrors the object's `EventsPresent` onto its
    /// dispatcher object after any post, so a thread parked in `NtWaitForDebugEvent` is woken no
    /// matter which path queued the event.
    fn report_debug_message(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        message: DbgKmMessage,
    ) -> Option<DebugObjectId> {
        let suppress_for_hidden_thread = matches!(
            message,
            DbgKmMessage::Exception { .. }
                | DbgKmMessage::CreateThread { .. }
                | DbgKmMessage::ExitThread { .. }
                | DbgKmMessage::LoadDll { .. }
                | DbgKmMessage::UnloadDll { .. }
        );
        if suppress_for_hidden_thread && self.thread_hides_from_debugger(pid, tid) {
            return None;
        }
        let object = self.processes.get(&pid).and_then(|p| p.debug_port)?;
        let event = DebugEvent::new(
            ClientId {
                unique_process: pid,
                unique_thread: tid,
            },
            message,
            0,
        );
        self.dbgk
            .get_mut(object)
            .is_some_and(|o| o.queue(event).is_ok())
            .then_some(object)
    }

    /// `DbgkClearProcessDebugObject` from process-object deletion: once a terminated process has no
    /// process handles and no queued debug events keeping it visible, clear `EPROCESS.DebugPort` and
    /// `PEB.BeingDebugged`. Termination itself deliberately does not call this, so the debugger can
    /// still retrieve and continue the final `DbgKmExitProcessApi` event.
    pub fn clear_deleted_process_debug_object_if_unreferenced(
        &mut self,
        pid: ProcessId,
    ) -> Option<usize> {
        let object = {
            let process = self.processes.get(&pid)?;
            if process.state != ProcessState::Terminated
                || self.handle_object_reference_count(HandleObject::Process(pid)) != 0
            {
                return None;
            }
            process.debug_port?
        };
        if self
            .dbgk
            .get(object)
            .is_some_and(|debug| debug.events().iter().any(|event| event.process_id() == pid))
        {
            return None;
        }
        let process = self.processes.get_mut(&pid)?;
        if process.debug_port != Some(object) {
            return None;
        }
        process.debug_port = None;
        process.being_debugged = false;
        Some(0)
    }

    /// `DbgkForwardException` — report a user-mode exception taken by `tid` in `pid` to that
    /// process's `EPROCESS.DebugPort`.
    ///
    /// Faithful to `ntoskrnl/dbgk/dbgkobj.c::DbgkForwardException`: nothing happens (and `None` is
    /// returned) when the process has no debug port, so the caller's ordinary
    /// SEH / unhandled-exception path proceeds untouched. `first_chance` is
    /// `DbgkForwardException`'s `!SecondChance` — the debugger sees a first-chance report before
    /// the exception is offered to the process, and a second-chance one after nothing handled it.
    ///
    /// Returns the debug object the `DbgKmExceptionApi` message was queued on. The reporting thread
    /// is NOT blocked on the continue (see the module docs) — the continue status the debugger
    /// supplies is recorded by [`debug_continue`](Self::debug_continue), not applied to a thread.
    pub fn report_exception(
        &mut self,
        pid: ProcessId,
        tid: ThreadId,
        record: dbgk::ExceptionRecord,
        first_chance: bool,
    ) -> Option<DebugObjectId> {
        self.report_debug_message(
            pid,
            tid,
            DbgKmMessage::Exception {
                record,
                first_chance: u32::from(first_chance),
            },
        )
    }

    /// Every live debug object's id, written into `out` (stable slot order); returns how many were
    /// written. A host uses this to mirror each object's modelled `EventsPresent` onto its
    /// dispatcher object without allocating.
    pub fn debug_object_ids_into(&self, out: &mut [DebugObjectId]) -> usize {
        let mut n = 0;
        for id in self.dbgk.ids() {
            if n == out.len() {
                break;
            }
            out[n] = id;
            n += 1;
        }
        n
    }

    // --- handle tables (spec §8) ---------------------------------------------

    /// Insert an object into `pid`'s handle table (spec §8.1), returning the handle. Reuses the
    /// first free slot (as the real NT handle table does), else appends. With capacity reserved via
    /// [`reserve_handles`](Self::reserve_handles), appending stays within pre-allocated storage (no
    /// reallocation).
    pub fn insert_handle(
        &mut self,
        pid: ProcessId,
        object: HandleObject,
        granted_access: u32,
    ) -> Result<Handle, u32> {
        if !self.processes.contains_key(&pid) {
            return Err(STATUS_INVALID_HANDLE);
        }
        match object {
            HandleObject::Process(target) if !self.processes.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            HandleObject::Thread(target) if !self.threads.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            HandleObject::Job(target) if !self.jobs.contains(target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            _ => {}
        }
        if let HandleObject::Job(object) = object {
            self.jobs.retain_handle(object)?;
        }
        let slot = {
            let proc = self
                .processes
                .get_mut(&pid)
                .expect("validated handle-table owner");
            let entry = HandleEntry {
                object,
                granted_access,
                flags: HandleFlags::default(),
            };
            let free = proc.handles.iter().position(HandleSlot::is_free);
            match free {
                Some(i) => {
                    proc.handles[i] = HandleSlot::Occupied(entry);
                    i
                }
                None => {
                    proc.handles.push(HandleSlot::Occupied(entry));
                    proc.handles.len() - 1
                }
            }
        };
        if let HandleObject::DebugObject(object) = object {
            if let Some(debug_object) = self.dbgk.get_mut(object) {
                debug_object.add_handle();
            }
        }
        Ok(slot_to_handle(slot))
    }

    /// Snapshot the inheritable portion of a process handle table in handle-value order. The
    /// returned records own no references; a process-creation transaction must either install each
    /// record into the child or discard the snapshot.
    pub fn inheritable_handles(&self, pid: ProcessId) -> Result<Vec<InheritedHandle>, u32> {
        let process = self.processes.get(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let count = process
            .handles
            .iter()
            .filter(|slot| slot.entry().is_some_and(|entry| entry.flags.inherit))
            .count();
        let mut inherited = Vec::new();
        inherited
            .try_reserve(count)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for (slot, entry) in process
            .handles
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.entry().map(|entry| (slot, entry)))
        {
            if entry.flags.inherit {
                inherited.push(InheritedHandle {
                    handle: slot_to_handle(slot),
                    object: entry.object,
                    granted_access: entry.granted_access,
                    flags: entry.flags,
                });
            }
        }
        Ok(inherited)
    }

    /// Install one inherited handle at its exact parent-table value. Object kinds owned by Ps
    /// acquire their handle reference here; backing stores owned by another executive subsystem
    /// must be retained by the caller before this publication step.
    pub fn insert_inherited_handle(
        &mut self,
        pid: ProcessId,
        inherited: InheritedHandle,
    ) -> Result<Handle, u32> {
        match inherited.object {
            HandleObject::Process(target) if !self.processes.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            HandleObject::Thread(target) if !self.threads.contains_key(&target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            HandleObject::Job(target) if !self.jobs.contains(target) => {
                return Err(STATUS_INVALID_HANDLE);
            }
            _ => {}
        }
        let slot = handle_to_slot(inherited.handle).ok_or(STATUS_INVALID_HANDLE)?;
        {
            let process = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
            if process.handles.len() <= slot {
                process
                    .handles
                    .try_reserve(slot + 1 - process.handles.len())
                    .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
                process.handles.resize_with(slot + 1, || HandleSlot::Free);
            }
            if !process.handles[slot].is_free() {
                return Err(STATUS_INVALID_HANDLE);
            }
        }
        if let HandleObject::Job(job) = inherited.object {
            self.jobs.retain_handle(job)?;
        }
        self.processes
            .get_mut(&pid)
            .expect("validated inherited handle-table owner")
            .handles[slot] = HandleSlot::Occupied(HandleEntry {
            object: inherited.object,
            granted_access: inherited.granted_access,
            flags: inherited.flags,
        });
        if let HandleObject::DebugObject(object) = inherited.object {
            if let Some(debug_object) = self.dbgk.get_mut(object) {
                debug_object.add_handle();
            }
        }
        Ok(inherited.handle)
    }
    /// Resolve a handle in `pid`'s table (spec §8.1).
    pub fn lookup_handle(&self, pid: ProcessId, handle: Handle) -> Option<HandleObject> {
        let proc = self.processes.get(&pid)?;
        proc.handles
            .get(handle_to_slot(handle)?)?
            .entry()
            .map(|e| e.object)
    }
    pub fn handle_access(&self, pid: ProcessId, handle: Handle) -> Option<u32> {
        let proc = self.processes.get(&pid)?;
        proc.handles
            .get(handle_to_slot(handle)?)?
            .entry()
            .map(|e| e.granted_access)
    }
    /// Return the mutable per-handle attributes for `handle`.
    pub fn handle_flags(&self, pid: ProcessId, handle: Handle) -> Option<HandleFlags> {
        let proc = self.processes.get(&pid)?;
        proc.handles
            .get(handle_to_slot(handle)?)?
            .entry()
            .map(|e| e.flags)
    }
    /// Update the mutable per-handle attributes for `handle`.
    pub fn set_handle_flags(
        &mut self,
        pid: ProcessId,
        handle: Handle,
        flags: HandleFlags,
    ) -> Result<(), u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(handle).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = proc
            .handles
            .get_mut(slot)
            .and_then(HandleSlot::entry_mut)
            .ok_or(STATUS_INVALID_HANDLE)?;
        entry.flags = flags;
        Ok(())
    }
    /// Remove a handle and return its object identity so the owning subsystem can release object
    /// references after the table entry is gone.
    pub fn take_handle(&mut self, pid: ProcessId, handle: Handle) -> Result<HandleObject, u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(handle).ok_or(STATUS_INVALID_HANDLE)?;
        proc.handles
            .get_mut(slot)
            .and_then(HandleSlot::take_entry)
            .map(|entry| entry.object)
            .ok_or(STATUS_INVALID_HANDLE)
    }
    /// User-mode `NtClose`: remove a handle unless it is protected from close.
    pub fn take_handle_for_close(
        &mut self,
        pid: ProcessId,
        handle: Handle,
    ) -> Result<HandleObject, u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(handle).ok_or(STATUS_INVALID_HANDLE)?;
        if proc
            .handles
            .get(slot)
            .and_then(HandleSlot::entry)
            .ok_or(STATUS_INVALID_HANDLE)?
            .flags
            .protect_from_close
        {
            return Err(STATUS_HANDLE_NOT_CLOSABLE);
        }
        proc.handles
            .get_mut(slot)
            .and_then(HandleSlot::take_entry)
            .map(|entry| entry.object)
            .ok_or(STATUS_INVALID_HANDLE)
    }
    /// `NtClose` (spec §8.1): remove a handle from `pid`'s table (frees the slot for reuse).
    pub fn close_handle(&mut self, pid: ProcessId, handle: Handle) -> Result<(), u32> {
        let object = self.take_handle_for_close(pid, handle)?;
        match object {
            HandleObject::Process(target) => {
                let _ = self.clear_deleted_process_debug_object_if_unreferenced(target);
            }
            HandleObject::Job(target) => {
                let _ = self.jobs.release_handle(target);
            }
            _ => {}
        }
        Ok(())
    }
    /// Remove one arbitrary handle from `pid`. Hosts use this during process teardown to release
    /// backing-object references owned outside the process manager.
    pub fn take_any_handle(&mut self, pid: ProcessId) -> Option<HandleObject> {
        let proc = self.processes.get_mut(&pid)?;
        proc.handles
            .iter_mut()
            .find_map(|entry| entry.take_entry().map(|entry| entry.object))
    }
    /// Close the first handle in `pid`'s table whose entry refers to `object` (spec §8.1), freeing
    /// the slot; returns whether one was found. A host that assigns its own handle VALUES (outside
    /// this table's `(slot+1)*4` scheme) records each with the value in a [`HandleObject::Opaque`]
    /// tag and closes by that tag on `NtClose` — so the per-process table is the ownership record
    /// even while the value allocator stays host-side (the process-hosting convergence hybrid).
    pub fn close_handle_by_object(&mut self, pid: ProcessId, object: HandleObject) -> bool {
        let Some(proc) = self.processes.get_mut(&pid) else {
            return false;
        };
        if let Some(slot) = proc
            .handles
            .iter()
            .position(|e| e.entry().is_some_and(|h| h.object == object))
        {
            proc.handles[slot] = HandleSlot::Free;
            match object {
                HandleObject::Process(target) => {
                    let _ = self.clear_deleted_process_debug_object_if_unreferenced(target);
                }
                HandleObject::Job(target) => {
                    let _ = self.jobs.release_handle(target);
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }
    /// `NtDuplicateObject` into another process's table (spec §8) — the target gets its own handle.
    pub fn duplicate_handle(
        &mut self,
        src_pid: ProcessId,
        handle: Handle,
        dst_pid: ProcessId,
    ) -> Result<Handle, u32> {
        self.duplicate_handle_with_access(src_pid, handle, dst_pid, None)
    }
    /// Duplicate a handle while optionally replacing its granted access mask. `None` implements
    /// `DUPLICATE_SAME_ACCESS`; `Some(mask)` implements the ordinary `DesiredAccess` path.
    pub fn duplicate_handle_with_access(
        &mut self,
        src_pid: ProcessId,
        handle: Handle,
        dst_pid: ProcessId,
        desired_access: Option<u32>,
    ) -> Result<Handle, u32> {
        let (object, access, flags) = {
            let e = self
                .processes
                .get(&src_pid)
                .and_then(|p| p.handles.get(handle_to_slot(handle)?))
                .and_then(HandleSlot::entry)
                .ok_or(STATUS_INVALID_HANDLE)?;
            (e.object, e.granted_access, e.flags)
        };
        let new_handle = self.insert_handle(dst_pid, object, desired_access.unwrap_or(access))?;
        self.set_handle_flags(dst_pid, new_handle, flags)?;
        Ok(new_handle)
    }
    pub fn handle_count(&self, pid: ProcessId) -> usize {
        self.processes
            .get(&pid)
            .map(|p| p.handles.iter().filter_map(HandleSlot::entry).count())
            .unwrap_or(0)
    }

    /// Count live handle-table entries across all processes that reference `object`. Hosts use this
    /// after removing a handle entry to decide whether the backing NT object has reached its last
    /// handle without depending on the private table layout.
    pub fn handle_object_count(&self, object: HandleObject) -> usize {
        self.processes
            .values()
            .map(|process| {
                process
                    .handles
                    .iter()
                    .filter(|entry| entry.entry().is_some_and(|entry| entry.object == object))
                    .count()
            })
            .sum()
    }

    /// Count every committed Object Manager reference, including handles bound into an invisible
    /// publication transaction. Bare reservations do not yet name an object and are excluded.
    pub fn handle_object_reference_count(&self, object: HandleObject) -> usize {
        self.processes
            .values()
            .map(|process| {
                process
                    .handles
                    .iter()
                    .filter(|slot| {
                        slot.reference_entry()
                            .is_some_and(|entry| entry.object == object)
                    })
                    .count()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests;
