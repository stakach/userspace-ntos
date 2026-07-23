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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use nt_pe_loader::{MappedImage, PeError, PeFile};
use nt_security::TokenId;

// NTSTATUS
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_CID: u32 = 0xC000_000B;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_SUSPEND_COUNT_EXCEEDED: u32 = 0xC000_004A;
pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_00E9;
pub const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

pub const PROCESS_GENERIC_READ: u32 = 0x0002_0410;
pub const PROCESS_GENERIC_WRITE: u32 = 0x0002_0BEB;
pub const PROCESS_GENERIC_EXECUTE: u32 = 0x0012_0000;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;
pub const THREAD_GENERIC_READ: u32 = 0x0002_0048;
pub const THREAD_GENERIC_WRITE: u32 = 0x0002_0037;
pub const THREAD_GENERIC_EXECUTE: u32 = 0x0012_0000;
pub const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

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
    pub image_file_name: String,
    pub address_space_id: AddressSpaceId,
    pub image_section: Option<SectionId>,
    pub threads: BTreeSet<ThreadId>,
    pub main_thread: Option<ThreadId>,
    pub state: ProcessState,
    pub exit_status: Option<u32>,
    /// Stable primary-token identity. The external token store owns the object bytes and reference
    /// count; the process holds one reference while this slot is populated.
    primary_token: Option<TokenId>,
    /// Opaque `W32PROCESS` pointer parked by win32k via `PsSetProcessWin32Process`
    /// (read back with `PsGetProcessWin32Process`). `None` until win32k attaches.
    pub win32_process: Option<u64>,
    /// Opaque `WINDOWSTATION` pointer (`PsSetProcessWindowStation` /
    /// `PsGetProcessWin32WindowStation`).
    pub win32_window_station: Option<u64>,
    /// Lazy, stable `ProcessCookie` returned by `NtQueryInformationProcess` class 36.
    process_cookie: u32,
    /// `ProcessBreakOnTermination`, initially clear and mutable through the native info class.
    break_on_termination: bool,
    /// Per-process handle table (spec §8.1). A dense **array of entries** indexed by handle slot —
    /// the real NT `HANDLE_TABLE` shape — rather than a `BTreeMap`. Slot `i` ↔ handle value
    /// `(i + 1) * 4` (NT handles are non-zero multiples of 4). Freed slots (`None`) are reused (as
    /// the real handle table does). This representation is **pre-reservable**: a host that reserves
    /// capacity up front ([`ProcessManager::reserve_handles`]) gets `insert_handle` writing into
    /// pre-allocated storage with **no reallocation**, so it can run on a bump allocator whose
    /// transient region is reset per call without corrupting the durable table.
    handles: Vec<Option<HandleEntry>>,
}

/// What a handle refers to (spec §8.1). v0.1 covers the object kinds the loader needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandleObject {
    Process(ProcessId),
    Thread(ThreadId),
    Section(SectionId),
    /// An I/O Manager `FILE_OBJECT`. The identifier belongs to the backing filesystem service.
    File(u64),
    /// A read-only file on the executive's mounted FAT volume.
    DiskFile {
        first_cluster: u32,
        size: u32,
    },
    /// A directory on the executive's mounted FAT volume.
    Directory {
        first_cluster: u32,
        object_id: u32,
    },
    /// The executive-reserved `\SystemRoot\bootstat.dat` file used by RTL boot-status APIs.
    BootStatusFile,
    /// An executive I/O completion-port object, indexed in the executive's fixed object table.
    IoCompletion(u32),
    /// A Configuration Manager key target. The executive owns the read-only hive and mutable
    /// overlay for the process lifetime; each handle independently owns only this typed reference.
    RegistryKey(u32),
    /// A process primary access token. The id is the owning process id.
    Token(ProcessId),
    /// A stable, independently owned token object.
    TokenObject(TokenId),
    /// An object the executive still models ad-hoc (port/event/file/token/key/…) during the
    /// process-hosting convergence — the handle-table entry is real (per-process, closable) even
    /// though the target isn't yet an `nt-process` object. The `u64` is the executive's opaque tag.
    Opaque(u64),
}

struct HandleEntry {
    object: HandleObject,
    granted_access: u32,
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
    pub parameter: u64,
    pub state: ThreadState,
    pub is_system_thread: bool,
    pub exit_status: Option<u32>,
    /// Active impersonation context. The thread owns a token reference independently of the user
    /// handle that assigned it.
    impersonation: Option<ImpersonationContext>,
    pub suspend_count: u32,
    /// Opaque `W32THREAD` pointer parked by win32k via `PsSetThreadWin32Thread`
    /// (read back with `PsGetThreadWin32Thread`). `None` until win32k attaches.
    pub win32_thread: Option<u64>,
    /// The thread's TEB base VA (its `NtCurrentTeb()` / `KTHREAD.Teb`). Set when the host actually
    /// spawns the backing thread (its TEB is a per-thread page); read back by
    /// `NtQueryInformationThread(ThreadBasicInformation).TebBaseAddress`. `0` until the TEB is mapped.
    pub teb_base: u64,
    /// `ThreadBreakOnTermination`, initially clear and not inherited from the process.
    break_on_termination: bool,
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
}

/// The Process Manager: processes, threads, and image sections (spec §5, §9-§13).
#[derive(Default)]
pub struct ProcessManager {
    processes: BTreeMap<ProcessId, NtProcess>,
    threads: BTreeMap<ThreadId, NtThread>,
    sections: Vec<Option<ImageSection>>,
    next_pid: u32,
    next_tid: u32,
    next_asid: u32,
    /// win32k's registered callouts (`PsEstablishWin32Callouts`), once attached.
    win32_callouts: Option<Win32Callouts>,
    /// When set, [`insert_handle`](Self::insert_handle) never reuses a freed (`None`) slot — it
    /// always appends, so a process's handle VALUES stay **monotonic** for the lifetime of the run
    /// (a closed value is never handed out again). A host that hands its returned dense values back
    /// to a foreign process AND indexes external state by those values (e.g. the ntos executive's
    /// per-process DLL registry) needs this: NT-style slot reuse would recycle a value while stale
    /// external bindings to the old value still exist, mis-routing the next open. Default `false`
    /// (real NT reuses freed handle slots). Path 1b of the nt-process convergence.
    no_reuse: bool,
}

impl ProcessManager {
    pub fn new() -> Self {
        ProcessManager {
            next_pid: 4, // pid 0=idle, 4=System by convention
            next_tid: 4,
            next_asid: 1,
            ..Default::default()
        }
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
        let pid = self.next_pid;
        self.next_pid += 1;
        let asid = self.next_asid;
        self.next_asid += 1;
        let state = if image_section.is_some() {
            ProcessState::Ready // image already laid out
        } else {
            ProcessState::Created
        };
        self.processes.insert(
            pid,
            NtProcess {
                process_id: pid,
                parent,
                image_file_name: image_file_name.into(),
                address_space_id: asid,
                image_section,
                threads: BTreeSet::new(),
                main_thread: None,
                state,
                exit_status: None,
                primary_token: None,
                win32_process: None,
                win32_window_station: None,
                process_cookie: 0,
                break_on_termination: false,
                handles: Vec::new(),
            },
        );
        pid
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

    /// Set append-only handle allocation (see the [`no_reuse`](ProcessManager) field): when `true`,
    /// [`insert_handle`](Self::insert_handle) never reuses a freed slot, so per-process handle
    /// VALUES stay monotonic (a closed value is never handed out again).
    pub fn set_handle_no_reuse(&mut self, no_reuse: bool) {
        self.no_reuse = no_reuse;
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
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(proc.state, ProcessState::Exiting | ProcessState::Terminated) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let tid = self.next_tid;
        self.next_tid += 1;
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
                parameter,
                state: ThreadState::Ready,
                is_system_thread,
                exit_status: None,
                impersonation: None,
                suspend_count: 0,
                win32_thread: None,
                teb_base: 0,
                break_on_termination: false,
            },
        );
        Ok(tid)
    }

    // --- win32k per-process/thread context slots (spec §7.4) -----------------
    //
    // win32k parks an opaque `W32PROCESS`/`W32THREAD` pointer on each hosted
    // process/thread and reads it back on every NtUser/NtGdi call. These are
    // pure pointer slots — the executive stores what win32k hands it and returns
    // it verbatim; it never dereferences the value.

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

    /// `PsGetThreadWin32Thread`: read back the parked `W32THREAD` pointer.
    pub fn thread_win32(&self, tid: ThreadId) -> Option<u64> {
        self.threads.get(&tid).and_then(|t| t.win32_thread)
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
            exit_status: thread.exit_status.unwrap_or(STATUS_SUCCESS),
            teb_base_address: thread.teb_base,
            client_id: ClientId {
                unique_process: thread.process_id,
                unique_thread: tid,
            },
            affinity_mask: 1,
            priority: 0,
            base_priority: 0,
        })
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
        self.thread(tid)
            .is_some_and(|thread| thread.state == ThreadState::Terminated)
            && !self.processes.values().any(|process| {
                process.handles.iter().any(|entry| {
                    entry
                        .as_ref()
                        .is_some_and(|entry| entry.object == HandleObject::Thread(tid))
                })
            })
    }

    /// Reset a preallocated runtime-thread identity after its terminated object is no longer
    /// reachable through any handle. This is intentionally narrower than creating a new NT thread:
    /// hosts use it to recycle bounded, allocation-free worker slots after deleting the old backing
    /// mechanism.
    pub fn reuse_reclaimed_thread(
        &mut self,
        tid: ThreadId,
        start_address: u64,
        create_suspended: bool,
    ) -> Result<(), u32> {
        if !self.can_reclaim_thread(tid) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process_id = self
            .threads
            .get(&tid)
            .map(|thread| thread.process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let process = self
            .processes
            .get(&process_id)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if matches!(
            process.state,
            ProcessState::Exiting | ProcessState::Terminated
        ) {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let thread = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if thread.impersonation.is_some() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        thread.start_address = start_address;
        thread.parameter = 0;
        thread.state = if create_suspended {
            ThreadState::Initialized
        } else {
            ThreadState::Running
        };
        thread.exit_status = None;
        thread.suspend_count = 0;
        thread.win32_thread = None;
        thread.teb_base = 0;
        thread.break_on_termination = false;
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
                true
            }
            None => false,
        }
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

    /// The `pid`'s main (first) thread id, if any (spec §7.1) — the identity a host binds/queries.
    pub fn main_thread(&self, pid: ProcessId) -> Option<ThreadId> {
        self.processes.get(&pid).and_then(|p| p.main_thread)
    }

    /// A scheduling-state transition (spec §11.2), e.g. `Ready` → `Running` → `Waiting`.
    pub fn set_thread_state(&mut self, tid: ThreadId, state: ThreadState) -> Result<(), u32> {
        let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        if t.state == ThreadState::Terminated {
            return Err(STATUS_INVALID_PARAMETER);
        }
        t.state = state;
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

    /// `NtTerminateThread` (spec §21.1): set the exit status, mark terminated (signalled), and if
    /// this was the last non-system thread, initiate process exit.
    pub fn terminate_thread(&mut self, tid: ThreadId, exit_status: u32) -> Result<(), u32> {
        let (pid, was_system) = {
            let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
            t.state = ThreadState::Terminated;
            t.exit_status = Some(exit_status);
            (t.process_id, t.is_system_thread)
        };
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
                self.terminate_process(pid, exit_status)?;
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
        let t = self.threads.get_mut(&tid).ok_or(STATUS_INVALID_HANDLE)?;
        t.state = ThreadState::Terminated;
        t.exit_status = Some(exit_status);
        Ok(())
    }

    /// `NtTerminateProcess` (spec §21.2): terminate all threads, set the exit status, and mark the
    /// process terminated (signalled). Releases the image-section map ref (spec §13.7).
    pub fn terminate_process(&mut self, pid: ProcessId, exit_status: u32) -> Result<(), u32> {
        let (tids, section) = {
            let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
            if proc.state == ProcessState::Terminated {
                return Ok(());
            }
            proc.state = ProcessState::Terminated;
            proc.exit_status = Some(exit_status);
            (
                proc.threads.iter().copied().collect::<Vec<_>>(),
                proc.image_section,
            )
        };
        for tid in tids {
            if let Some(t) = self.threads.get_mut(&tid) {
                if t.state != ThreadState::Terminated {
                    t.state = ThreadState::Terminated;
                    t.exit_status = Some(exit_status);
                }
            }
        }
        if let Some(sid) = section {
            if let Some(s) = self.sections.get_mut(sid as usize).and_then(|s| s.as_mut()) {
                s.map_refs = s.map_refs.saturating_sub(1);
            }
        }
        Ok(())
    }

    /// A process/thread is a waitable dispatcher object, signalled once terminated (spec §12.1).
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
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let entry = HandleEntry {
            object,
            granted_access,
        };
        let free = if self.no_reuse {
            None // append-only: never recycle a freed value (see `no_reuse`)
        } else {
            proc.handles.iter().position(|e| e.is_none())
        };
        let slot = match free {
            Some(i) => {
                proc.handles[i] = Some(entry);
                i
            }
            None => {
                proc.handles.push(Some(entry));
                proc.handles.len() - 1
            }
        };
        Ok(slot_to_handle(slot))
    }
    /// Resolve a handle in `pid`'s table (spec §8.1).
    pub fn lookup_handle(&self, pid: ProcessId, handle: Handle) -> Option<HandleObject> {
        let proc = self.processes.get(&pid)?;
        proc.handles
            .get(handle_to_slot(handle)?)?
            .as_ref()
            .map(|e| e.object)
    }
    pub fn handle_access(&self, pid: ProcessId, handle: Handle) -> Option<u32> {
        let proc = self.processes.get(&pid)?;
        proc.handles
            .get(handle_to_slot(handle)?)?
            .as_ref()
            .map(|e| e.granted_access)
    }
    /// Remove a handle and return its object identity so the owning subsystem can release object
    /// references after the table entry is gone.
    pub fn take_handle(&mut self, pid: ProcessId, handle: Handle) -> Result<HandleObject, u32> {
        let proc = self.processes.get_mut(&pid).ok_or(STATUS_INVALID_HANDLE)?;
        let slot = handle_to_slot(handle).ok_or(STATUS_INVALID_HANDLE)?;
        proc.handles
            .get_mut(slot)
            .and_then(Option::take)
            .map(|entry| entry.object)
            .ok_or(STATUS_INVALID_HANDLE)
    }
    /// `NtClose` (spec §8.1): remove a handle from `pid`'s table (frees the slot for reuse).
    pub fn close_handle(&mut self, pid: ProcessId, handle: Handle) -> Result<(), u32> {
        self.take_handle(pid, handle).map(|_| ())
    }
    /// Remove one arbitrary handle from `pid`. Hosts use this during process teardown to release
    /// backing-object references owned outside the process manager.
    pub fn take_any_handle(&mut self, pid: ProcessId) -> Option<HandleObject> {
        let proc = self.processes.get_mut(&pid)?;
        proc.handles
            .iter_mut()
            .find_map(|entry| entry.take().map(|entry| entry.object))
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
            .position(|e| e.as_ref().is_some_and(|h| h.object == object))
        {
            proc.handles[slot] = None;
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
        let (object, access) = {
            let e = self
                .processes
                .get(&src_pid)
                .and_then(|p| p.handles.get(handle_to_slot(handle)?))
                .and_then(|e| e.as_ref())
                .ok_or(STATUS_INVALID_HANDLE)?;
            (e.object, e.granted_access)
        };
        self.insert_handle(dst_pid, object, desired_access.unwrap_or(access))
    }
    pub fn handle_count(&self, pid: ProcessId) -> usize {
        self.processes
            .get(&pid)
            .map(|p| p.handles.iter().filter(|e| e.is_some()).count())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests;
