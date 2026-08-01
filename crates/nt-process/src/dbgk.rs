//! # `dbgk` — the user-mode debugging plane (`DEBUG_OBJECT` + its event queue)
//!
//! A faithful port of the **pure** half of ReactOS `ntoskrnl/dbgk/dbgkobj.c`: the `DEBUG_OBJECT`
//! (an event list + the `EventsPresent` signal + the `DebuggerInactive`/`KillProcessOnExit` flag
//! bits) and the three state-machine operations that move events through it —
//!
//! * **queue** (`DbgkpQueueMessage`) — append a [`DebugEvent`] carrying a [`DbgKmMessage`];
//! * **wait** (`NtWaitForDebugEvent`'s scan) — hand out the first event that is neither
//!   `DEBUG_EVENT_INACTIVE` nor already `DEBUG_EVENT_READ` **and** whose `UniqueProcess` no
//!   earlier queued event already claims (NT reports **one event per debuggee process at a
//!   time**), marking it `READ`; when nothing qualifies the `EventsPresent` signal is cleared;
//! * **continue** (`NtDebugContinue`) — find the `READ` event matching a `CLIENT_ID`, remove it,
//!   and **activate** the next queued event for that same process (clearing its `INACTIVE` bit and
//!   re-signalling `EventsPresent`), returning the removed event so the caller can wake the target.
//!
//! Plus the attach/detach halves that belong to the object rather than the process:
//! [`DebugObject::activate_backout_events`] (`DbgkpSetProcessDebugObject`'s activation pass over
//! the fake create messages posted at attach) and [`DebugObject::flush_process`]
//! (`DbgkClearProcessDebugObject`'s temp-list drain on detach).
//!
//! The process-side of the lifecycle (which `EPROCESS` owns which debug port, posting the fake
//! create messages for an attach, and the create/exit event sources) lives on
//! [`ProcessManager`](crate::ProcessManager) — it needs the process/thread tables. Everything in
//! *this* module is pure data + logic, so the queue/waiter/continue semantics are host-tested.
//!
//! [`encode_wait_state_change`] renders a dequeued event into the x64
//! `DBGUI_WAIT_STATE_CHANGE` byte image ntdll's `DbgUiWaitStateChange` receives — the exact input
//! `nt_ntdll::dbg::convert_state_change` turns into a Win32 `DEBUG_EVENT`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{ClientId, ProcessId, ThreadId};

/// Identity of a `DEBUG_OBJECT` inside a [`DebugObjectStore`].
pub type DebugObjectId = u32;

// --- NTSTATUS values this plane returns -------------------------------------------------------

/// `STATUS_PORT_ALREADY_SET` — the target process already has a debug port.
pub const STATUS_PORT_ALREADY_SET: u32 = 0xC000_0048;
/// `STATUS_PORT_NOT_SET` — the target process has no (matching) debug port.
pub const STATUS_PORT_NOT_SET: u32 = 0xC000_0353;
/// `STATUS_DEBUGGER_INACTIVE` — the debug object's debugger has gone away.
pub const STATUS_DEBUGGER_INACTIVE: u32 = 0xC000_0354;

// --- DEBUG_OBJECT access rights (`ndk/dbgktypes.h`) -------------------------------------------

/// `DEBUG_OBJECT_WAIT_STATE_CHANGE` — required by `NtWaitForDebugEvent`/`NtDebugContinue`.
pub const DEBUG_OBJECT_WAIT_STATE_CHANGE: u32 = 0x0001;
/// `DEBUG_OBJECT_ADD_REMOVE_PROCESS` — required by `NtDebugActiveProcess`/`NtRemoveProcessDebug`.
pub const DEBUG_OBJECT_ADD_REMOVE_PROCESS: u32 = 0x0002;
/// `DEBUG_OBJECT_SET_INFORMATION` — required by `NtSetInformationDebugObject`.
pub const DEBUG_OBJECT_SET_INFORMATION: u32 = 0x0004;
/// `DEBUG_OBJECT_ALL_ACCESS` = `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xF`.
pub const DEBUG_OBJECT_ALL_ACCESS: u32 = 0x001F_000F;

/// Expand generic access bits with the `DbgkDebugObjectMapping` generic mapping.
pub fn map_debug_object_access(desired: u32) -> u32 {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const STANDARD_RIGHTS_READ: u32 = 0x0002_0000;
    const STANDARD_RIGHTS_WRITE: u32 = 0x0002_0000;
    const STANDARD_RIGHTS_EXECUTE: u32 = 0x0002_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    let mut mapped =
        desired & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL | MAXIMUM_ALLOWED);
    if desired & GENERIC_READ != 0 {
        mapped |= STANDARD_RIGHTS_READ | DEBUG_OBJECT_WAIT_STATE_CHANGE;
    }
    if desired & GENERIC_WRITE != 0 {
        mapped |= STANDARD_RIGHTS_WRITE | DEBUG_OBJECT_ADD_REMOVE_PROCESS;
    }
    if desired & GENERIC_EXECUTE != 0 {
        mapped |= STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    }
    if desired & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        mapped |= DEBUG_OBJECT_ALL_ACCESS;
    }
    mapped
}

// --- DEBUG_EVENT flags --------------------------------------------------------------------------

/// `DEBUG_EVENT_READ` — already handed to the debugger by a wait; awaiting a continue.
pub const DEBUG_EVENT_READ: u32 = 0x01;
/// `DEBUG_EVENT_NOWAIT` — the reporting thread does NOT block on the continue event.
pub const DEBUG_EVENT_NOWAIT: u32 = 0x02;
/// `DEBUG_EVENT_INACTIVE` — queued but not yet eligible for a wait.
pub const DEBUG_EVENT_INACTIVE: u32 = 0x04;
/// `DEBUG_EVENT_RELEASE` — the queuer holds the target thread's rundown protection.
pub const DEBUG_EVENT_RELEASE: u32 = 0x08;
/// `DEBUG_EVENT_PROTECT_FAILED` — rundown protection could not be acquired for the target.
pub const DEBUG_EVENT_PROTECT_FAILED: u32 = 0x10;
/// `DEBUG_EVENT_SUSPEND` — the target was suspended for this event.
pub const DEBUG_EVENT_SUSPEND: u32 = 0x20;

// --- NtCreateDebugObject flags ------------------------------------------------------------------

/// `DBGK_KILL_PROCESS_ON_EXIT` — kill the debuggees when the debug object is destroyed.
pub const DBGK_KILL_PROCESS_ON_EXIT: u32 = 0x1;
/// `DBGK_ALL_FLAGS` — every legal `NtCreateDebugObject` flag.
pub const DBGK_ALL_FLAGS: u32 = DBGK_KILL_PROCESS_ON_EXIT;

// --- DEBUG_OBJECT flag bits (the `Flags` union bitfield) ---------------------------------------

/// `DebuggerInactive:1`.
pub const DEBUG_OBJECT_DEBUGGER_INACTIVE: u32 = 0x1;
/// `KillProcessOnExit:1`.
pub const DEBUG_OBJECT_KILL_PROCESS_ON_EXIT: u32 = 0x2;

// --- DBG_STATE (the DBGUI_WAIT_STATE_CHANGE `NewState`) ----------------------------------------

/// `DbgIdle`.
pub const DBG_IDLE: u32 = 0;
/// `DbgReplyPending`.
pub const DBG_REPLY_PENDING: u32 = 1;
/// `DbgCreateThreadStateChange`.
pub const DBG_CREATE_THREAD_STATE_CHANGE: u32 = 2;
/// `DbgCreateProcessStateChange`.
pub const DBG_CREATE_PROCESS_STATE_CHANGE: u32 = 3;
/// `DbgExitThreadStateChange`.
pub const DBG_EXIT_THREAD_STATE_CHANGE: u32 = 4;
/// `DbgExitProcessStateChange`.
pub const DBG_EXIT_PROCESS_STATE_CHANGE: u32 = 5;
/// `DbgExceptionStateChange`.
pub const DBG_EXCEPTION_STATE_CHANGE: u32 = 6;
/// `DbgBreakpointStateChange`.
pub const DBG_BREAKPOINT_STATE_CHANGE: u32 = 7;
/// `DbgSingleStepStateChange`.
pub const DBG_SINGLE_STEP_STATE_CHANGE: u32 = 8;
/// `DbgLoadDllStateChange`.
pub const DBG_LOAD_DLL_STATE_CHANGE: u32 = 9;
/// `DbgUnloadDllStateChange`.
pub const DBG_UNLOAD_DLL_STATE_CHANGE: u32 = 10;

// --- DBGKM_APINUMBER ----------------------------------------------------------------------------

/// `DbgKmExceptionApi`.
pub const DBGKM_EXCEPTION_API: u32 = 0;
/// `DbgKmCreateThreadApi`.
pub const DBGKM_CREATE_THREAD_API: u32 = 1;
/// `DbgKmCreateProcessApi`.
pub const DBGKM_CREATE_PROCESS_API: u32 = 2;
/// `DbgKmExitThreadApi`.
pub const DBGKM_EXIT_THREAD_API: u32 = 3;
/// `DbgKmExitProcessApi`.
pub const DBGKM_EXIT_PROCESS_API: u32 = 4;
/// `DbgKmLoadDllApi`.
pub const DBGKM_LOAD_DLL_API: u32 = 5;
/// `DbgKmUnloadDllApi`.
pub const DBGKM_UNLOAD_DLL_API: u32 = 6;

// --- Continue statuses accepted by NtDebugContinue ----------------------------------------------

/// `DBG_EXCEPTION_HANDLED`.
pub const DBG_EXCEPTION_HANDLED: u32 = 0x0001_0001;
/// `DBG_CONTINUE`.
pub const DBG_CONTINUE: u32 = 0x0001_0002;
/// `DBG_TERMINATE_THREAD`.
pub const DBG_TERMINATE_THREAD: u32 = 0x4001_0003;
/// `DBG_TERMINATE_PROCESS`.
pub const DBG_TERMINATE_PROCESS: u32 = 0x4001_0004;
/// `DBG_EXCEPTION_NOT_HANDLED`.
pub const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x8001_0001;

/// Whether `status` is one of the five continue statuses `NtDebugContinue` accepts.
pub fn is_valid_continue_status(status: u32) -> bool {
    matches!(
        status,
        DBG_CONTINUE
            | DBG_EXCEPTION_HANDLED
            | DBG_EXCEPTION_NOT_HANDLED
            | DBG_TERMINATE_THREAD
            | DBG_TERMINATE_PROCESS
    )
}

/// `STATUS_BREAKPOINT` — an exception message with this code reports as `DbgBreakpointStateChange`.
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
/// `STATUS_SINGLE_STEP` — reports as `DbgSingleStepStateChange`.
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

// --- Trap-vector → NTSTATUS (the exception code a fault reports to a debugger) -------------------

/// `STATUS_DATATYPE_MISALIGNMENT`.
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// `STATUS_ACCESS_VIOLATION`.
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// `STATUS_ILLEGAL_INSTRUCTION`.
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
/// `STATUS_ARRAY_BOUNDS_EXCEEDED`.
pub const STATUS_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000_008C;
/// `STATUS_FLOAT_DIVIDE_BY_ZERO`.
pub const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000_008E;
/// `STATUS_INTEGER_DIVIDE_BY_ZERO`.
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
/// `STATUS_INTEGER_OVERFLOW`.
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
/// `STATUS_PRIVILEGED_INSTRUCTION`.
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;
/// `STATUS_STACK_OVERFLOW`.
pub const STATUS_STACK_OVERFLOW: u32 = 0xC000_00FD;

/// The NTSTATUS exception code an x86/x64 trap `vector` reports, matching what ReactOS's
/// `KiTrapXXHandler`s hand to `KiDispatchException` (`ntoskrnl/ke/i386/traphdlr.c`).
///
/// `#GP` (13) reports `STATUS_ACCESS_VIOLATION` — the fall-through `KiTrap0D` takes for a
/// non-privileged-instruction general protection fault; a privileged-instruction `#GP` is a
/// decode-time refinement the caller applies itself. Anything unrecognised reports
/// `STATUS_ACCESS_VIOLATION`, the code `KiDispatchException` uses for an unclassified user fault.
pub fn exception_code_for_trap(vector: u32) -> u32 {
    match vector {
        0 => STATUS_INTEGER_DIVIDE_BY_ZERO, // #DE
        1 => STATUS_SINGLE_STEP,            // #DB
        3 => STATUS_BREAKPOINT,             // #BP
        4 => STATUS_INTEGER_OVERFLOW,       // #OF
        5 => STATUS_ARRAY_BOUNDS_EXCEEDED,  // #BR
        6 => STATUS_ILLEGAL_INSTRUCTION,    // #UD
        7 => STATUS_ILLEGAL_INSTRUCTION,    // #NM (no math coprocessor)
        12 => STATUS_STACK_OVERFLOW,        // #SS
        13 => STATUS_ACCESS_VIOLATION,      // #GP
        14 => STATUS_ACCESS_VIOLATION,      // #PF
        16 => STATUS_FLOAT_DIVIDE_BY_ZERO,  // #MF (the reported x87 status refines this)
        17 => STATUS_DATATYPE_MISALIGNMENT, // #AC
        19 => STATUS_FLOAT_DIVIDE_BY_ZERO,  // #XM (the reported MXCSR status refines this)
        _ => STATUS_ACCESS_VIOLATION,
    }
}

/// The x64 `EXCEPTION_RECORD` carried by a `DbgKmExceptionApi` message.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub exception_code: u32,
    pub exception_flags: u32,
    pub exception_record: u64,
    pub exception_address: u64,
    pub number_parameters: u32,
    pub exception_information: [u64; 15],
}

impl Default for ExceptionRecord {
    fn default() -> Self {
        ExceptionRecord {
            exception_code: 0,
            exception_flags: 0,
            exception_record: 0,
            exception_address: 0,
            number_parameters: 0,
            exception_information: [0; 15],
        }
    }
}

impl ExceptionRecord {
    /// A parameter-less record for `code` raised at `address` (`KiDispatchException0Args`).
    pub fn new(code: u32, address: u64) -> Self {
        ExceptionRecord {
            exception_code: code,
            exception_address: address,
            ..ExceptionRecord::default()
        }
    }

    /// Attach `parameters` (`ExceptionInformation`, at most 15 — `EXCEPTION_MAXIMUM_PARAMETERS`)
    /// and set `NumberParameters` accordingly. Extra entries beyond 15 are dropped, exactly as
    /// `KiDispatchException` clamps.
    pub fn with_parameters(mut self, parameters: &[u64]) -> Self {
        let n = parameters.len().min(self.exception_information.len());
        self.exception_information[..n].copy_from_slice(&parameters[..n]);
        self.number_parameters = n as u32;
        self
    }

    /// The `STATUS_ACCESS_VIOLATION` record a page fault reports: `ExceptionInformation[0]` = the
    /// access type (0 read / 1 write / 8 execute) and `[1]` = the faulting virtual address, the
    /// two arguments `MmAccessFault` hands `KiDispatchException2Args`.
    pub fn access_violation(address: u64, access_type: u64, fault_address: u64) -> Self {
        ExceptionRecord::new(STATUS_ACCESS_VIOLATION, address)
            .with_parameters(&[access_type, fault_address])
    }
}

/// A `DBGKM_MSG` payload — the kernel-side debug message the debuggee reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DbgKmMessage {
    /// `DBGKM_EXCEPTION`.
    Exception {
        record: ExceptionRecord,
        first_chance: u32,
    },
    /// `DBGKM_CREATE_THREAD`.
    CreateThread {
        sub_system_key: u32,
        start_address: u64,
    },
    /// `DBGKM_CREATE_PROCESS`.
    CreateProcess {
        sub_system_key: u32,
        file_handle: u64,
        base_of_image: u64,
        debug_info_file_offset: u32,
        debug_info_size: u32,
        initial_thread_sub_system_key: u32,
        initial_thread_start_address: u64,
    },
    /// `DBGKM_EXIT_THREAD`.
    ExitThread { exit_status: u32 },
    /// `DBGKM_EXIT_PROCESS`.
    ExitProcess { exit_status: u32 },
    /// `DBGKM_LOAD_DLL`.
    LoadDll {
        file_handle: u64,
        base_of_dll: u64,
        debug_info_file_offset: u32,
        debug_info_size: u32,
        name_pointer: u64,
    },
    /// `DBGKM_UNLOAD_DLL`.
    UnloadDll { base_address: u64 },
}

impl DbgKmMessage {
    /// The `DBGKM_APINUMBER` this payload rides under.
    pub fn api_number(&self) -> u32 {
        match self {
            DbgKmMessage::Exception { .. } => DBGKM_EXCEPTION_API,
            DbgKmMessage::CreateThread { .. } => DBGKM_CREATE_THREAD_API,
            DbgKmMessage::CreateProcess { .. } => DBGKM_CREATE_PROCESS_API,
            DbgKmMessage::ExitThread { .. } => DBGKM_EXIT_THREAD_API,
            DbgKmMessage::ExitProcess { .. } => DBGKM_EXIT_PROCESS_API,
            DbgKmMessage::LoadDll { .. } => DBGKM_LOAD_DLL_API,
            DbgKmMessage::UnloadDll { .. } => DBGKM_UNLOAD_DLL_API,
        }
    }

    /// The `DBG_STATE` a wait reports for this payload — `DbgkpConvertKernelToUserStateChange`'s
    /// api-number → state mapping, including the breakpoint/single-step refinement of an exception.
    pub fn state(&self) -> u32 {
        match self {
            DbgKmMessage::Exception { record, .. } => match record.exception_code {
                STATUS_BREAKPOINT => DBG_BREAKPOINT_STATE_CHANGE,
                STATUS_SINGLE_STEP => DBG_SINGLE_STEP_STATE_CHANGE,
                _ => DBG_EXCEPTION_STATE_CHANGE,
            },
            DbgKmMessage::CreateThread { .. } => DBG_CREATE_THREAD_STATE_CHANGE,
            DbgKmMessage::CreateProcess { .. } => DBG_CREATE_PROCESS_STATE_CHANGE,
            DbgKmMessage::ExitThread { .. } => DBG_EXIT_THREAD_STATE_CHANGE,
            DbgKmMessage::ExitProcess { .. } => DBG_EXIT_PROCESS_STATE_CHANGE,
            DbgKmMessage::LoadDll { .. } => DBG_LOAD_DLL_STATE_CHANGE,
            DbgKmMessage::UnloadDll { .. } => DBG_UNLOAD_DLL_STATE_CHANGE,
        }
    }
}

// --- the BLOCKED REPORTING THREAD (`DbgkpQueueMessage`'s `ContinueEvent` wait) ------------------

/// No reporter is blocked on this event (`DEBUG_EVENT_NOWAIT` — the attach-time fake messages and
/// the lifecycle posts, which NT also queues without a waiting reporter).
pub const DBGK_BLOCK_NONE: u8 = 0;
/// The reporter blocked inside a **syscall** (seL4 `UnknownSyscall` fault). Resuming it replies with
/// the syscall reply shape: the return status in MR0 (RAX) plus MR15/16/17 = FaultIP/SP/FLAGS.
pub const DBGK_BLOCK_SYSCALL: u8 = 1;
/// The reporter blocked at a **UserException** fault (`#UD`/`#GP`/a CPU exception the executive's
/// fault loop classified at label 3). Resuming it replies with the UserException shape — length 3,
/// MR0/1/2 = FaultIP/SP/FLAGS.
pub const DBGK_BLOCK_USER_EXCEPTION: u8 = 2;
/// The reporter blocked at a **VMFault** (`#PF`, the fault loop's label 6). Resuming it replies
/// length 0: no register transfer, the faulting instruction is retried (NT's "exception dismissed,
/// resume at the faulting context").
pub const DBGK_BLOCK_VM_FAULT: u8 = 3;
/// The reporter blocked at a **DebugException** (int3 / `#BP`, the fault loop's label 4). Resuming
/// it replies length 0; the recorded resume IP already points past the trapping instruction.
pub const DBGK_BLOCK_DEBUG_EXCEPTION: u8 = 4;

/// The **blocked reporting thread** carried by a [`DebugEvent`].
///
/// `DbgkpQueueMessage` keeps the reporting thread parked on the event's `ContinueEvent` until
/// `NtDebugContinue` runs `DbgkpWakeTarget`. We have no in-kernel thread to park, so the host
/// records everything needed to RESUME that thread here — the seL4 Reply capability its blocked
/// Call is bound to, the fault flavour that says which reply shape resumes it, and the resume
/// context. The whole struct is opaque, plain data to this module: the pure state machine only
/// carries it from the queue site to the continue site (exactly the role `DebugEvent->ContinueEvent`
/// plays in the kernel), and the host performs the actual wake.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReporterBlock {
    /// `DBGK_BLOCK_*` — which reply shape resumes this reporter.
    pub kind: u8,
    /// The host's Reply capability bound to the blocked reporter's Call (0 = none).
    pub reply_cap: u64,
    /// Hosted-process index the reporter belongs to (the host's `pi`).
    pub pi: u32,
    /// The reporter's thread id (the `CLIENT_ID.UniqueThread` of the event).
    pub tid: u64,
    /// The reporter's fault-endpoint badge (its identity in the host's service multiplex).
    pub badge: u64,
    /// Resume `FaultIP` — for a syscall block, the instruction after the `syscall`.
    pub resume_ip: u64,
    /// Resume stack pointer.
    pub resume_sp: u64,
    /// Resume RFLAGS.
    pub resume_flags: u64,
    /// The status a **syscall**-flavoured reporter returns when it is resumed (what the syscall
    /// would have returned had it never blocked). Ignored for the fault flavours.
    pub resume_status: u64,
}

impl ReporterBlock {
    /// Whether this block names a resumable reporter.
    pub fn is_blocked(&self) -> bool {
        self.kind != DBGK_BLOCK_NONE && self.reply_cap != 0
    }

    /// Whether the reporter blocked at a FAULT (as opposed to inside a syscall). A fault reporter
    /// resumes only on `DBG_CONTINUE`; a syscall reporter resumes on any non-terminating continue.
    pub fn is_fault(&self) -> bool {
        matches!(
            self.kind,
            DBGK_BLOCK_USER_EXCEPTION | DBGK_BLOCK_VM_FAULT | DBGK_BLOCK_DEBUG_EXCEPTION
        )
    }
}

/// What `DbgkpWakeTarget` must do to a blocked reporter for a given continue status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeAction {
    /// Nothing was blocked (or nothing to do) — `NtDebugContinue` just resolves the event.
    None,
    /// Resume the reporter so it CONTINUES EXECUTION (`DBG_CONTINUE` / `DBG_EXCEPTION_HANDLED`,
    /// and — for a syscall reporter — `DBG_EXCEPTION_NOT_HANDLED` too, since a syscall-reported
    /// event is not an exception the debugger can decline).
    Resume,
    /// Leave the reporter blocked: the fault site's own handling stands (`DBG_EXCEPTION_NOT_HANDLED`
    /// at a fault — the second-chance / park outcome).
    LeaveBlocked,
    /// `DBG_TERMINATE_THREAD` — terminate the reporting thread; it is never resumed.
    TerminateThread,
    /// `DBG_TERMINATE_PROCESS` — terminate the reporting thread's whole process.
    TerminateProcess,
}

/// `DbgkpWakeTarget`'s decision table: what a continue status does to the reporter blocked on the
/// event being continued. Pure — the host performs the action.
pub fn wake_action(block: &ReporterBlock, continue_status: u32) -> WakeAction {
    if !block.is_blocked() {
        // NT still terminates on a DBG_TERMINATE_* continue even when the event carried no waiting
        // reporter (`DbgkpWakeTarget` calls PspTerminateThreadByPointer regardless); with nothing
        // parked there is no thread of ours to resume, so only the terminations survive.
        return match continue_status {
            DBG_TERMINATE_THREAD => WakeAction::TerminateThread,
            DBG_TERMINATE_PROCESS => WakeAction::TerminateProcess,
            _ => WakeAction::None,
        };
    }
    match continue_status {
        DBG_TERMINATE_THREAD => WakeAction::TerminateThread,
        DBG_TERMINATE_PROCESS => WakeAction::TerminateProcess,
        DBG_CONTINUE | DBG_EXCEPTION_HANDLED => WakeAction::Resume,
        // `DBG_EXCEPTION_NOT_HANDLED`: the debugger declined the exception, so the normal path
        // proceeds. For a FAULT that means the fault site's own unrecoverable handling stands (the
        // thread stays blocked, exactly as `park_and_log!` leaves it); for a SYSCALL-reported event
        // (a module load) there is no exception to decline, so the syscall simply completes.
        _ => {
            if block.is_fault() {
                WakeAction::LeaveBlocked
            } else {
                WakeAction::Resume
            }
        }
    }
}

/// A queued `DEBUG_EVENT`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DebugEvent {
    /// `DEBUG_EVENT_*` flag bits.
    pub flags: u32,
    /// The reporting thread's `CLIENT_ID` (the debuggee pid/tid this event is about).
    pub client_id: ClientId,
    /// The `DBGKM_MSG` payload.
    pub message: DbgKmMessage,
    /// `DebugEvent->Status` — the status handed back to the (blocked) reporting thread.
    pub status: u32,
    /// `DebugEvent->ApiMsg.ReturnedStatus` — the continue status the debugger resolved it with.
    pub returned_status: u32,
    /// `DebugEvent->BackoutThread` — the thread that queued an inactive (attach-time) event.
    pub backout_thread: Option<ThreadId>,
    /// The **blocked reporting thread** NT parks on `DebugEvent->ContinueEvent` until
    /// `NtDebugContinue` runs `DbgkpWakeTarget`. `None` = post-and-continue (a `NOWAIT` event or a
    /// lifecycle post) — the reporter was never blocked.
    pub reporter: Option<ReporterBlock>,
}

impl DebugEvent {
    /// Build an event for `client_id` carrying `message`, with the given `DEBUG_EVENT_*` flags.
    pub fn new(client_id: ClientId, message: DbgKmMessage, flags: u32) -> Self {
        DebugEvent {
            flags,
            client_id,
            message,
            status: crate::STATUS_SUCCESS,
            returned_status: crate::STATUS_SUCCESS,
            backout_thread: None,
            reporter: None,
        }
    }

    /// The blocked reporter this event carries, if any (`DebugEvent->ContinueEvent`'s waiter).
    pub fn reporter_block(&self) -> Option<ReporterBlock> {
        self.reporter.filter(|block| block.is_blocked())
    }

    /// The debuggee process this event belongs to.
    pub fn process_id(&self) -> ProcessId {
        self.client_id.unique_process
    }

    /// Whether the event has been handed to a debugger and awaits a continue.
    pub fn is_read(&self) -> bool {
        self.flags & DEBUG_EVENT_READ != 0
    }

    /// Whether the event is queued-but-not-yet-eligible.
    pub fn is_inactive(&self) -> bool {
        self.flags & DEBUG_EVENT_INACTIVE != 0
    }
}

/// A `DEBUG_OBJECT`: the debugger's event port.
#[derive(Clone, Debug, Default)]
pub struct DebugObject {
    /// The `Flags` union: `DebuggerInactive:1 | KillProcessOnExit:1`.
    pub flags: u32,
    /// `DebugObject->EventsPresent` (a notification `KEVENT`) — set while a readable event exists.
    events_present: bool,
    /// `DebugObject->EventList`, head-to-tail.
    events: Vec<DebugEvent>,
    /// Opaque host key for the dispatcher object backing `EventsPresent` (the executive parks a
    /// `NtWaitForDebugEvent` caller on a REAL notification event, so the existing wait-park/wake
    /// machinery serves the debugger's block). `0` = no host object bound; the pure model's
    /// [`events_present`](Self::events_present) remains authoritative either way.
    pub host_event: u64,
}

impl DebugObject {
    /// `NtCreateDebugObject`'s object initialisation for the given `DBGK_*` creation flags.
    pub fn new(create_flags: u32) -> Self {
        DebugObject {
            flags: if create_flags & DBGK_KILL_PROCESS_ON_EXIT != 0 {
                DEBUG_OBJECT_KILL_PROCESS_ON_EXIT
            } else {
                0
            },
            events_present: false,
            events: Vec::new(),
            host_event: 0,
        }
    }

    /// `DebugObject->DebuggerInactive`.
    pub fn debugger_inactive(&self) -> bool {
        self.flags & DEBUG_OBJECT_DEBUGGER_INACTIVE != 0
    }

    /// `DebugObject->KillProcessOnExit`.
    pub fn kill_process_on_exit(&self) -> bool {
        self.flags & DEBUG_OBJECT_KILL_PROCESS_ON_EXIT != 0
    }

    /// `NtSetInformationDebugObject(DebugObjectKillProcessOnExitInformation)`.
    pub fn set_kill_process_on_exit(&mut self, kill: bool) {
        if kill {
            self.flags |= DEBUG_OBJECT_KILL_PROCESS_ON_EXIT;
        } else {
            self.flags &= !DEBUG_OBJECT_KILL_PROCESS_ON_EXIT;
        }
    }

    /// `DbgkpCloseObject` — the debugger handle went away; no further events may be queued.
    pub fn mark_debugger_inactive(&mut self) {
        self.flags |= DEBUG_OBJECT_DEBUGGER_INACTIVE;
        self.events_present = false;
    }

    /// The `EventsPresent` notification-event state a host mirrors onto a real dispatcher object.
    pub fn events_present(&self) -> bool {
        self.events_present
    }

    /// The queued events, head-to-tail.
    pub fn events(&self) -> &[DebugEvent] {
        &self.events
    }

    /// Number of queued events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the event list is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// `DbgkpQueueMessage` — append `event` to the object's list.
    ///
    /// A `DEBUG_EVENT_NOWAIT` event is queued **without** signalling `EventsPresent` (it is an
    /// attach-time backout event that [`activate_backout_events`](Self::activate_backout_events)
    /// later makes eligible); any other event signals the debugger awake. Fails with
    /// `STATUS_DEBUGGER_INACTIVE` once the debugger has gone.
    pub fn queue(&mut self, event: DebugEvent) -> Result<(), u32> {
        if self.debugger_inactive() {
            return Err(STATUS_DEBUGGER_INACTIVE);
        }
        let nowait = event.flags & DEBUG_EVENT_NOWAIT != 0;
        self.events.push(event);
        if !nowait {
            self.events_present = true;
        }
        Ok(())
    }

    /// `DbgkpQueueMessage`'s **blocking** half: record `block` as the reporting thread parked on the
    /// most recently queued event for `client_id` that is not already `NOWAIT` and has no reporter.
    ///
    /// NT queues the `DEBUG_EVENT` on the reporter's own stack and then waits on its `ContinueEvent`;
    /// we queue first and attach the (host-owned) block second, which is the same association. The
    /// event stops being a post-and-continue one, so `NtDebugContinue` will run `DbgkpWakeTarget`
    /// against it. Returns `false` when no such event exists (nothing was blocked).
    pub fn attach_reporter(&mut self, client_id: ClientId, block: ReporterBlock) -> bool {
        if !block.is_blocked() {
            return false;
        }
        for event in self.events.iter_mut().rev() {
            if event.client_id == client_id
                && event.reporter.is_none()
                && event.flags & DEBUG_EVENT_NOWAIT == 0
            {
                event.reporter = Some(block);
                return true;
            }
        }
        false
    }

    /// Take the blocked reporter off every event of this object (optionally only those belonging to
    /// `pid`), returning them.
    ///
    /// The debugger-death escape hatch: `DbgkpCloseObject` marks the object inactive, and
    /// `DbgkClearProcessDebugObject` detaches one debuggee — in both cases every blocked target must
    /// be released rather than left parked forever (a boot that cannot quiesce is a failure). The
    /// events themselves are left in place; the caller decides what to do with each reporter.
    pub fn drain_reporters(&mut self, pid: Option<ProcessId>) -> Vec<(ClientId, ReporterBlock)> {
        let mut out = Vec::new();
        for event in self.events.iter_mut() {
            if pid.is_some_and(|pid| event.process_id() != pid) {
                continue;
            }
            if let Some(block) = event.reporter.take() {
                if block.is_blocked() {
                    out.push((event.client_id, block));
                }
            }
        }
        out
    }

    /// How many events currently carry a blocked reporter.
    pub fn blocked_reporters(&self) -> usize {
        self.events
            .iter()
            .filter(|event| event.reporter_block().is_some())
            .count()
    }

    /// `DbgkpSetProcessDebugObject`'s activation pass: the fake create messages queued for
    /// `backout_thread` during an attach become eligible. The FIRST one is un-`INACTIVE`d and
    /// signals `EventsPresent` (`DoSetEvent`); the rest stay inactive but lose their backout thread,
    /// exactly as the kernel leaves them for `NtDebugContinue` to activate one at a time.
    ///
    /// Returns the number of events whose backout thread was cleared.
    pub fn activate_backout_events(&mut self, backout_thread: ThreadId) -> usize {
        let mut cleared = 0;
        let mut do_set_event = true;
        for event in &mut self.events {
            if event.is_inactive() && event.backout_thread == Some(backout_thread) {
                if do_set_event {
                    event.flags &= !DEBUG_EVENT_INACTIVE;
                    do_set_event = false;
                }
                event.backout_thread = None;
                cleared += 1;
            }
        }
        if !do_set_event {
            self.events_present = true;
        }
        cleared
    }

    /// `NtWaitForDebugEvent`'s scan: pick the next event to report.
    ///
    /// Returns the index of the event now flagged `DEBUG_EVENT_READ`, or `None` when nothing is
    /// eligible (in which case `EventsPresent` is cleared, so a waiter blocks again). An event
    /// whose process already has an earlier queued event is marked `INACTIVE` and skipped — the
    /// **one-outstanding-event-per-debuggee-process** rule.
    pub fn dequeue_for_wait(&mut self) -> Result<Option<usize>, u32> {
        if self.debugger_inactive() {
            return Err(STATUS_DEBUGGER_INACTIVE);
        }
        let mut chosen = None;
        for index in 0..self.events.len() {
            if self.events[index].flags & (DEBUG_EVENT_INACTIVE | DEBUG_EVENT_READ) != 0 {
                continue;
            }
            let pid = self.events[index].process_id();
            let shadowed = self.events[..index]
                .iter()
                .any(|earlier| earlier.process_id() == pid);
            if shadowed {
                self.events[index].flags |= DEBUG_EVENT_INACTIVE;
                self.events[index].backout_thread = None;
                continue;
            }
            chosen = Some(index);
            break;
        }
        match chosen {
            Some(index) => {
                self.events[index].flags |= DEBUG_EVENT_READ;
                Ok(Some(index))
            }
            None => {
                self.events_present = false;
                Ok(None)
            }
        }
    }

    /// `NtDebugContinue` — resolve the `READ` event matching `client_id` with `continue_status`.
    ///
    /// Removes and returns it (the caller wakes the reporting thread with
    /// `DebugEvent->ApiMsg.ReturnedStatus`), and activates the next queued event for the SAME
    /// process (clearing `INACTIVE` + re-signalling `EventsPresent`). `Err(STATUS_INVALID_PARAMETER)`
    /// when no such read event exists, or when `continue_status` is not a legal continue status.
    pub fn continue_event(
        &mut self,
        client_id: ClientId,
        continue_status: u32,
    ) -> Result<DebugEvent, u32> {
        if !is_valid_continue_status(continue_status) {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        let mut to_wake = None;
        for index in 0..self.events.len() {
            let event = &self.events[index];
            if event.process_id() != client_id.unique_process {
                continue;
            }
            match to_wake {
                // We already removed this process's read event; the next same-process event in the
                // list becomes eligible and re-signals the debugger.
                Some(_) => {
                    self.events[index].flags &= !DEBUG_EVENT_INACTIVE;
                    self.events_present = true;
                    break;
                }
                None => {
                    if event.client_id.unique_thread == client_id.unique_thread && event.is_read() {
                        to_wake = Some(index);
                    }
                }
            }
        }
        let Some(index) = to_wake else {
            return Err(crate::STATUS_INVALID_PARAMETER);
        };
        let mut event = self.events.remove(index);
        event.returned_status = continue_status;
        event.status = crate::STATUS_SUCCESS;
        Ok(event)
    }

    /// `DbgkClearProcessDebugObject`'s temp-list drain: remove and return every event belonging to
    /// `pid`, each marked `STATUS_DEBUGGER_INACTIVE` so its (blocked) reporting thread is released.
    pub fn flush_process(&mut self, pid: ProcessId) -> Vec<DebugEvent> {
        let mut flushed = Vec::new();
        let mut remaining = Vec::with_capacity(self.events.len());
        for mut event in self.events.drain(..) {
            if event.process_id() == pid {
                event.status = STATUS_DEBUGGER_INACTIVE;
                flushed.push(event);
            } else {
                remaining.push(event);
            }
        }
        self.events = remaining;
        if !self
            .events
            .iter()
            .any(|e| e.flags & (DEBUG_EVENT_INACTIVE | DEBUG_EVENT_READ) == 0)
        {
            self.events_present = false;
        }
        flushed
    }
}

/// The executive's table of live `DEBUG_OBJECT`s.
#[derive(Clone, Debug, Default)]
pub struct DebugObjectStore {
    objects: BTreeMap<DebugObjectId, DebugObject>,
    next_id: DebugObjectId,
}

impl DebugObjectStore {
    /// A fresh, empty store. Ids start at 1 so `0` is never a valid object.
    pub fn new() -> Self {
        DebugObjectStore {
            objects: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// `NtCreateDebugObject` — validate `create_flags` and insert a new object.
    pub fn create(&mut self, create_flags: u32) -> Result<DebugObjectId, u32> {
        if create_flags & !DBGK_ALL_FLAGS != 0 {
            return Err(crate::STATUS_INVALID_PARAMETER);
        }
        if self.next_id == 0 {
            self.next_id = 1;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.objects.insert(id, DebugObject::new(create_flags));
        Ok(id)
    }

    /// Borrow an object.
    pub fn get(&self, id: DebugObjectId) -> Option<&DebugObject> {
        self.objects.get(&id)
    }

    /// Mutably borrow an object.
    pub fn get_mut(&mut self, id: DebugObjectId) -> Option<&mut DebugObject> {
        self.objects.get_mut(&id)
    }

    /// `DbgkpDeleteObject` — drop the object (its last handle closed).
    pub fn destroy(&mut self, id: DebugObjectId) -> Option<DebugObject> {
        self.objects.remove(&id)
    }

    /// Number of live debug objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether no debug object is live.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// The id of every live object, in creation order.
    pub fn ids(&self) -> impl Iterator<Item = DebugObjectId> + '_ {
        self.objects.keys().copied()
    }
}

/// Size of the x64 `DBGUI_WAIT_STATE_CHANGE` structure.
pub const DBGUI_WAIT_STATE_CHANGE_SIZE: usize = 0xb8;

fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// `DbgkpConvertKernelToUserStateChange` + `DbgkpOpenHandles`: render `event` into the x64
/// `DBGUI_WAIT_STATE_CHANGE` byte image, with the debugger-process handles the kernel opened for
/// the reported process/thread (`0` when the state has no such handle).
///
/// Layout (x64): `NewState` u32 @0x00 · `AppClientId` @0x08/0x10 · `StateInfo` @0x18.
pub fn encode_wait_state_change(
    event: &DebugEvent,
    handle_to_process: u64,
    handle_to_thread: u64,
) -> [u8; DBGUI_WAIT_STATE_CHANGE_SIZE] {
    let mut buf = [0u8; DBGUI_WAIT_STATE_CHANGE_SIZE];
    put_u32(&mut buf, 0x00, event.message.state());
    put_u64(&mut buf, 0x08, event.client_id.unique_process as u64);
    put_u64(&mut buf, 0x10, event.client_id.unique_thread as u64);
    match event.message {
        DbgKmMessage::CreateThread {
            sub_system_key,
            start_address,
        } => {
            put_u64(&mut buf, 0x18, handle_to_thread);
            put_u32(&mut buf, 0x20, sub_system_key);
            put_u64(&mut buf, 0x28, start_address);
        }
        DbgKmMessage::CreateProcess {
            sub_system_key,
            file_handle,
            base_of_image,
            debug_info_file_offset,
            debug_info_size,
            initial_thread_sub_system_key,
            initial_thread_start_address,
        } => {
            put_u64(&mut buf, 0x18, handle_to_process);
            put_u64(&mut buf, 0x20, handle_to_thread);
            put_u32(&mut buf, 0x28, sub_system_key);
            put_u64(&mut buf, 0x30, file_handle);
            put_u64(&mut buf, 0x38, base_of_image);
            put_u32(&mut buf, 0x40, debug_info_file_offset);
            put_u32(&mut buf, 0x44, debug_info_size);
            put_u32(&mut buf, 0x48, initial_thread_sub_system_key);
            put_u64(&mut buf, 0x50, initial_thread_start_address);
        }
        DbgKmMessage::ExitThread { exit_status } | DbgKmMessage::ExitProcess { exit_status } => {
            put_u32(&mut buf, 0x18, exit_status);
        }
        DbgKmMessage::Exception {
            record,
            first_chance,
        } => {
            put_u32(&mut buf, 0x18, record.exception_code);
            put_u32(&mut buf, 0x1c, record.exception_flags);
            put_u64(&mut buf, 0x20, record.exception_record);
            put_u64(&mut buf, 0x28, record.exception_address);
            put_u32(&mut buf, 0x30, record.number_parameters);
            for (i, value) in record.exception_information.iter().enumerate() {
                put_u64(&mut buf, 0x38 + i * 8, *value);
            }
            put_u32(&mut buf, 0xb0, first_chance);
        }
        DbgKmMessage::LoadDll {
            file_handle,
            base_of_dll,
            debug_info_file_offset,
            debug_info_size,
            name_pointer,
        } => {
            put_u64(&mut buf, 0x18, file_handle);
            put_u64(&mut buf, 0x20, base_of_dll);
            put_u32(&mut buf, 0x28, debug_info_file_offset);
            put_u32(&mut buf, 0x2c, debug_info_size);
            put_u64(&mut buf, 0x30, name_pointer);
        }
        DbgKmMessage::UnloadDll { base_address } => {
            put_u64(&mut buf, 0x18, base_address);
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn cid(pid: ProcessId, tid: ThreadId) -> ClientId {
        ClientId {
            unique_process: pid,
            unique_thread: tid,
        }
    }

    fn create_thread_msg(start: u64) -> DbgKmMessage {
        DbgKmMessage::CreateThread {
            sub_system_key: 0,
            start_address: start,
        }
    }

    #[test]
    fn create_rejects_unknown_flags_and_honours_kill_on_exit() {
        let mut store = DebugObjectStore::new();
        assert_eq!(store.create(0x8000), Err(crate::STATUS_INVALID_PARAMETER));
        let plain = store.create(0).unwrap();
        assert!(!store.get(plain).unwrap().kill_process_on_exit());
        let killer = store.create(DBGK_KILL_PROCESS_ON_EXIT).unwrap();
        assert!(store.get(killer).unwrap().kill_process_on_exit());
        assert_ne!(plain, killer);
        assert_eq!(store.len(), 2);
        // Ids are never zero, so a host can use 0 as "no object".
        assert!(plain != 0 && killer != 0);
    }

    #[test]
    fn queue_signals_events_present_only_for_immediate_events() {
        let mut object = DebugObject::new(0);
        assert!(!object.events_present());
        let mut backout = DebugEvent::new(
            cid(8, 12),
            create_thread_msg(0x1000),
            DEBUG_EVENT_NOWAIT | DEBUG_EVENT_INACTIVE,
        );
        backout.backout_thread = Some(4);
        object.queue(backout).unwrap();
        assert!(!object.events_present(), "a NOWAIT event must not signal");
        object
            .queue(DebugEvent::new(cid(9, 13), create_thread_msg(0x2000), 0))
            .unwrap();
        assert!(object.events_present());
        assert_eq!(object.len(), 2);
    }

    #[test]
    fn queue_fails_once_the_debugger_is_inactive() {
        let mut object = DebugObject::new(0);
        object.mark_debugger_inactive();
        assert_eq!(
            object.queue(DebugEvent::new(cid(8, 12), create_thread_msg(1), 0)),
            Err(STATUS_DEBUGGER_INACTIVE)
        );
        assert_eq!(
            object.dequeue_for_wait(),
            Err(STATUS_DEBUGGER_INACTIVE),
            "a wait on a dead debug object reports DEBUGGER_INACTIVE"
        );
    }

    #[test]
    fn activate_backout_events_makes_only_the_first_eligible() {
        let mut object = DebugObject::new(0);
        for tid in [12u32, 13, 14] {
            let mut event = DebugEvent::new(
                cid(8, tid),
                create_thread_msg(tid as u64),
                DEBUG_EVENT_NOWAIT | DEBUG_EVENT_INACTIVE,
            );
            event.backout_thread = Some(4);
            object.queue(event).unwrap();
        }
        assert!(!object.events_present());
        assert_eq!(object.activate_backout_events(4), 3);
        assert!(object.events_present());
        assert!(!object.events()[0].is_inactive());
        assert!(object.events()[1].is_inactive());
        assert!(object.events()[2].is_inactive());
        assert!(object.events().iter().all(|e| e.backout_thread.is_none()));
    }

    #[test]
    fn wait_reports_one_event_per_process_then_clears_the_signal() {
        let mut object = DebugObject::new(0);
        object
            .queue(DebugEvent::new(cid(8, 12), create_thread_msg(1), 0))
            .unwrap();
        object
            .queue(DebugEvent::new(cid(8, 13), create_thread_msg(2), 0))
            .unwrap();
        object
            .queue(DebugEvent::new(cid(9, 20), create_thread_msg(3), 0))
            .unwrap();

        // First wait: pid 8's head event.
        let first = object.dequeue_for_wait().unwrap().unwrap();
        assert_eq!(first, 0);
        assert!(object.events()[0].is_read());

        // Second wait: pid 8 already has an outstanding event, so its second is skipped (and
        // marked INACTIVE); pid 9's event is reported instead.
        let second = object.dequeue_for_wait().unwrap().unwrap();
        assert_eq!(second, 2);
        assert_eq!(object.events()[2].client_id, cid(9, 20));
        assert!(object.events()[1].is_inactive());

        // Third wait: nothing eligible → no event, and the signal is cleared.
        assert_eq!(object.dequeue_for_wait().unwrap(), None);
        assert!(!object.events_present());
    }

    #[test]
    fn continue_removes_the_read_event_and_activates_the_next_for_that_process() {
        let mut object = DebugObject::new(0);
        object
            .queue(DebugEvent::new(cid(8, 12), create_thread_msg(1), 0))
            .unwrap();
        object
            .queue(DebugEvent::new(cid(8, 13), create_thread_msg(2), 0))
            .unwrap();
        object.dequeue_for_wait().unwrap().unwrap();
        object.dequeue_for_wait().unwrap(); // shadows + inactivates the second, clears the signal
        assert!(!object.events_present());

        // A bad continue status is rejected before anything is touched.
        assert_eq!(
            object.continue_event(cid(8, 12), 0x1234),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(object.len(), 2);

        let woken = object.continue_event(cid(8, 12), DBG_CONTINUE).unwrap();
        assert_eq!(woken.client_id, cid(8, 12));
        assert_eq!(woken.returned_status, DBG_CONTINUE);
        assert_eq!(object.len(), 1);
        // The next same-process event became eligible and re-signalled the debugger.
        assert!(!object.events()[0].is_inactive());
        assert!(object.events_present());
        let next = object.dequeue_for_wait().unwrap().unwrap();
        assert_eq!(object.events()[next].client_id, cid(8, 13));
    }

    #[test]
    fn continue_requires_a_matching_read_event() {
        let mut object = DebugObject::new(0);
        object
            .queue(DebugEvent::new(cid(8, 12), create_thread_msg(1), 0))
            .unwrap();
        // Not read yet.
        assert_eq!(
            object.continue_event(cid(8, 12), DBG_CONTINUE),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        object.dequeue_for_wait().unwrap().unwrap();
        // Wrong thread.
        assert_eq!(
            object.continue_event(cid(8, 99), DBG_CONTINUE),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        // Wrong process.
        assert_eq!(
            object.continue_event(cid(9, 12), DBG_CONTINUE),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert!(object
            .continue_event(cid(8, 12), DBG_EXCEPTION_NOT_HANDLED)
            .is_ok());
    }

    #[test]
    fn flush_process_drains_only_that_process_and_marks_it_inactive() {
        let mut object = DebugObject::new(0);
        object
            .queue(DebugEvent::new(cid(8, 12), create_thread_msg(1), 0))
            .unwrap();
        object
            .queue(DebugEvent::new(cid(9, 20), create_thread_msg(2), 0))
            .unwrap();
        let flushed = object.flush_process(8);
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].status, STATUS_DEBUGGER_INACTIVE);
        assert_eq!(object.len(), 1);
        assert_eq!(object.events()[0].client_id, cid(9, 20));
        assert!(object.events_present());
        // Flushing the remainder clears the signal.
        assert_eq!(object.flush_process(9).len(), 1);
        assert!(!object.events_present());
    }

    #[test]
    fn message_api_numbers_and_states_match_the_ndk_enums() {
        assert_eq!(create_thread_msg(0).api_number(), DBGKM_CREATE_THREAD_API);
        assert_eq!(create_thread_msg(0).state(), DBG_CREATE_THREAD_STATE_CHANGE);
        let exit = DbgKmMessage::ExitProcess { exit_status: 1 };
        assert_eq!(exit.api_number(), DBGKM_EXIT_PROCESS_API);
        assert_eq!(exit.state(), DBG_EXIT_PROCESS_STATE_CHANGE);
        let mut record = ExceptionRecord::default();
        record.exception_code = STATUS_BREAKPOINT;
        let bp = DbgKmMessage::Exception {
            record,
            first_chance: 1,
        };
        assert_eq!(bp.api_number(), DBGKM_EXCEPTION_API);
        assert_eq!(bp.state(), DBG_BREAKPOINT_STATE_CHANGE);
        record.exception_code = STATUS_SINGLE_STEP;
        assert_eq!(
            DbgKmMessage::Exception {
                record,
                first_chance: 1
            }
            .state(),
            DBG_SINGLE_STEP_STATE_CHANGE
        );
        record.exception_code = 0xC000_0005;
        assert_eq!(
            DbgKmMessage::Exception {
                record,
                first_chance: 1
            }
            .state(),
            DBG_EXCEPTION_STATE_CHANGE
        );
    }

    #[test]
    fn encode_create_process_state_change_matches_the_x64_layout() {
        let event = DebugEvent::new(
            cid(0x20, 0x24),
            DbgKmMessage::CreateProcess {
                sub_system_key: 7,
                file_handle: 0x1122_3344,
                base_of_image: 0x0000_0001_4000_0000,
                debug_info_file_offset: 0xAABB,
                debug_info_size: 0xCCDD,
                initial_thread_sub_system_key: 9,
                initial_thread_start_address: 0x0000_0001_4000_1000,
            },
            0,
        );
        let buf = encode_wait_state_change(&event, 0x40, 0x44);
        let u32_at = |o: usize| u32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
        assert_eq!(u32_at(0x00), DBG_CREATE_PROCESS_STATE_CHANGE);
        assert_eq!(u64_at(0x08), 0x20);
        assert_eq!(u64_at(0x10), 0x24);
        assert_eq!(u64_at(0x18), 0x40); // HandleToProcess
        assert_eq!(u64_at(0x20), 0x44); // HandleToThread
        assert_eq!(u32_at(0x28), 7);
        assert_eq!(u64_at(0x30), 0x1122_3344);
        assert_eq!(u64_at(0x38), 0x0000_0001_4000_0000);
        assert_eq!(u32_at(0x40), 0xAABB);
        assert_eq!(u32_at(0x44), 0xCCDD);
        assert_eq!(u32_at(0x48), 9);
        assert_eq!(u64_at(0x50), 0x0000_0001_4000_1000);
    }

    #[test]
    fn encode_covers_thread_exit_dll_and_exception_states() {
        let thread = DebugEvent::new(cid(8, 12), create_thread_msg(0xDEAD_BEEF), 0);
        let buf = encode_wait_state_change(&thread, 0, 0x44);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            DBG_CREATE_THREAD_STATE_CHANGE
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x18..0x20].try_into().unwrap()),
            0x44
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap()),
            0xDEAD_BEEF
        );

        let exit = DebugEvent::new(cid(8, 12), DbgKmMessage::ExitThread { exit_status: 7 }, 0);
        let buf = encode_wait_state_change(&exit, 0, 0);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            DBG_EXIT_THREAD_STATE_CHANGE
        );
        assert_eq!(u32::from_le_bytes(buf[0x18..0x1c].try_into().unwrap()), 7);

        let dll = DebugEvent::new(
            cid(8, 12),
            DbgKmMessage::LoadDll {
                file_handle: 0x10,
                base_of_dll: 0x8000_0000,
                debug_info_file_offset: 1,
                debug_info_size: 2,
                name_pointer: 0x9000,
            },
            0,
        );
        let buf = encode_wait_state_change(&dll, 0, 0);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            DBG_LOAD_DLL_STATE_CHANGE
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x20..0x28].try_into().unwrap()),
            0x8000_0000
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x30..0x38].try_into().unwrap()),
            0x9000
        );

        let mut record = ExceptionRecord::default();
        record.exception_code = STATUS_BREAKPOINT;
        record.exception_address = 0x7FFE_0000;
        record.number_parameters = 2;
        record.exception_information[0] = 11;
        record.exception_information[1] = 22;
        let exception = DebugEvent::new(
            cid(8, 12),
            DbgKmMessage::Exception {
                record,
                first_chance: 1,
            },
            0,
        );
        let buf = encode_wait_state_change(&exception, 0, 0);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            DBG_BREAKPOINT_STATE_CHANGE
        );
        assert_eq!(
            u32::from_le_bytes(buf[0x18..0x1c].try_into().unwrap()),
            STATUS_BREAKPOINT
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap()),
            0x7FFE_0000
        );
        assert_eq!(u64::from_le_bytes(buf[0x38..0x40].try_into().unwrap()), 11);
        assert_eq!(u64::from_le_bytes(buf[0x40..0x48].try_into().unwrap()), 22);
        assert_eq!(u32::from_le_bytes(buf[0xb0..0xb4].try_into().unwrap()), 1);
    }

    #[test]
    fn access_mapping_expands_generics() {
        assert_eq!(
            map_debug_object_access(0x1000_0000),
            DEBUG_OBJECT_ALL_ACCESS
        );
        assert_eq!(
            map_debug_object_access(0x0200_0000),
            DEBUG_OBJECT_ALL_ACCESS
        );
        assert!(map_debug_object_access(0x8000_0000) & DEBUG_OBJECT_WAIT_STATE_CHANGE != 0);
        assert!(map_debug_object_access(0x4000_0000) & DEBUG_OBJECT_ADD_REMOVE_PROCESS != 0);
        // A specific mask passes through untouched.
        assert_eq!(
            map_debug_object_access(DEBUG_OBJECT_SET_INFORMATION),
            DEBUG_OBJECT_SET_INFORMATION
        );
    }

    #[test]
    fn continue_status_validation_matches_the_five_legal_values() {
        for status in [
            DBG_CONTINUE,
            DBG_EXCEPTION_HANDLED,
            DBG_EXCEPTION_NOT_HANDLED,
            DBG_TERMINATE_THREAD,
            DBG_TERMINATE_PROCESS,
        ] {
            assert!(is_valid_continue_status(status));
        }
        assert!(!is_valid_continue_status(0));
        assert!(!is_valid_continue_status(0x0001_0003));
    }

    #[test]
    fn destroy_removes_the_object() {
        let mut store = DebugObjectStore::new();
        let id = store.create(0).unwrap();
        assert!(store.get_mut(id).is_some());
        assert!(store.destroy(id).is_some());
        assert!(store.get(id).is_none());
        assert!(store.is_empty());
    }
}
