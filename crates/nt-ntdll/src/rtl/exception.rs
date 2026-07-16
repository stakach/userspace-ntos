//! The x64 structured-exception-handling (SEH) machinery: `RtlDispatchException`, `RtlUnwind`,
//! `RtlRaiseException`/`RtlRaiseStatus`, and the function-table registry
//! (`RtlAddFunctionTable`/`RtlLookupFunctionEntry`).
//!
//! x64 SEH is **table-based** (not the x86 `fs:[0]` handler chain): each function's unwind + handler
//! info lives in a `RUNTIME_FUNCTION` entry (a `.pdata` row) registered for the image; on an
//! exception the dispatcher walks up the call stack, for each frame looks up the covering
//! `RUNTIME_FUNCTION`, and if it has a language handler, calls it. This module implements the
//! **dispatch + unwind LOGIC** over a host-testable model (a mock function-table + a mock handler
//! set); the actual machine-context capture (`RtlCaptureContext`) + the resume (`NtContinue`) are
//! target-gated and live with [`crate::ki`].
//!
//! Pairs with [`crate::ki::exception_dispatcher`] (the `KiUserExceptionDispatcher` the kernel jumps
//! to): the kernel delivers a `CONTEXT` + `EXCEPTION_RECORD`, the dispatcher calls
//! [`dispatch_exception`], and on unhandled the process defaults to the unhandled-exception filter.

use alloc::vec::Vec;

/// `EXCEPTION_DISPOSITION` — a language handler's verdict on an exception.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// `ExceptionContinueExecution` — the handler fixed it; resume at the faulting point.
    ContinueExecution,
    /// `ExceptionContinueSearch` — not mine; keep walking up the frames.
    ContinueSearch,
    /// `ExceptionNestedException` — an exception occurred within this handler.
    NestedException,
    /// `ExceptionCollidedUnwind` — an unwind collided with another.
    CollidedUnwind,
}

/// `EXCEPTION_RECORD` (the load-bearing fields): the code, flags, and faulting address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    /// `ExceptionCode` (an `NTSTATUS`, e.g. `STATUS_ACCESS_VIOLATION`).
    pub code: u32,
    /// `ExceptionFlags` (bit 1 = `EXCEPTION_NONCONTINUABLE`, bit 2 = `EXCEPTION_UNWINDING`).
    pub flags: u32,
    /// `ExceptionAddress` — the faulting instruction pointer.
    pub address: u64,
    /// `ExceptionInformation` (up to 15 parameters; e.g. AV read/write + address).
    pub information: Vec<u64>,
}

/// `EXCEPTION_NONCONTINUABLE`.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x0000_0001;
/// `EXCEPTION_UNWINDING`.
pub const EXCEPTION_UNWINDING: u32 = 0x0000_0002;
/// `EXCEPTION_EXIT_UNWIND`.
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x0000_0004;
/// `EXCEPTION_TARGET_UNWIND`.
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x0000_0020;
/// `EXCEPTION_COLLIDED_UNWIND`.
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x0000_0040;

/// `STATUS_NONCONTINUABLE_EXCEPTION` — raised if a handler tries to continue a noncontinuable
/// exception.
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;

/// A `RUNTIME_FUNCTION` (`.pdata` row): the `[begin, end)` RVA range a function covers + the RVA of
/// its `UNWIND_INFO` (which, if it has the `UNW_FLAG_EHANDLER` bit, names a language handler).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// `BeginAddress` (RVA of the function's first instruction).
    pub begin: u32,
    /// `EndAddress` (RVA one past the function's last instruction).
    pub end: u32,
    /// `UnwindInfoAddress` (RVA of the `UNWIND_INFO`).
    pub unwind_info: u32,
}

impl RuntimeFunction {
    /// Whether this entry covers the given function-relative RVA.
    pub fn covers(&self, rva: u32) -> bool {
        rva >= self.begin && rva < self.end
    }
}

/// A registered function table for an image (`RtlAddFunctionTable`): the image base + its
/// `RUNTIME_FUNCTION` rows, kept sorted by `begin` for a binary-search lookup.
#[derive(Clone, Debug, Default)]
pub struct FunctionTable {
    /// The image base the entry RVAs are relative to.
    pub image_base: u64,
    /// The `.pdata` rows, sorted by `begin`.
    pub functions: Vec<RuntimeFunction>,
}

impl FunctionTable {
    /// `RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)` — register a function table.
    /// Sorts the rows by `begin` for lookup.
    pub fn add(image_base: u64, mut functions: Vec<RuntimeFunction>) -> Self {
        functions.sort_by_key(|f| f.begin);
        FunctionTable { image_base, functions }
    }

    /// `RtlLookupFunctionEntry(ControlPc, ImageBase*, HistoryTable)` — find the `RUNTIME_FUNCTION`
    /// covering an absolute control PC. Returns `None` for a leaf function (no `.pdata` entry) — the
    /// dispatcher then treats it as a leaf (RIP-relative unwind).
    pub fn lookup(&self, control_pc: u64) -> Option<RuntimeFunction> {
        if control_pc < self.image_base {
            return None;
        }
        let rva = (control_pc - self.image_base) as u32;
        // Binary search: the last entry whose begin <= rva, then range-check.
        let idx = self.functions.partition_point(|f| f.begin <= rva);
        if idx == 0 {
            return None;
        }
        let cand = self.functions[idx - 1];
        if cand.covers(rva) {
            Some(cand)
        } else {
            None
        }
    }
}

/// A stack frame for the host-testable dispatch model: a control PC + whether its covering function
/// has a language handler and what that handler returns.
#[derive(Copy, Clone, Debug)]
pub struct FrameModel {
    /// The frame's control PC (return address into the caller).
    pub control_pc: u64,
    /// The handler's verdict when called (if the frame has a language handler).
    pub handler: Option<Disposition>,
}

/// The result of [`dispatch_exception`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    /// A handler returned `ContinueExecution` at the given frame index — resume the thread.
    Handled { frame: usize },
    /// No handler claimed the exception — it is unhandled (→ unhandled-exception filter → terminate).
    Unhandled,
    /// The exception was noncontinuable and a handler tried to continue it.
    Noncontinuable,
}

/// `RtlDispatchException(ExceptionRecord, Context)` — walk the frames top-down, calling each frame's
/// language handler until one returns `ContinueExecution` (handled) or the frames are exhausted
/// (unhandled). This is the pure dispatch LOGIC; the real dispatcher captures the machine `CONTEXT`
/// and, on `Handled`, resumes via `NtContinue` ([`crate::ki`]).
pub fn dispatch_exception(record: &ExceptionRecord, frames: &[FrameModel]) -> DispatchResult {
    for (i, f) in frames.iter().enumerate() {
        if let Some(disp) = f.handler {
            match disp {
                Disposition::ContinueExecution => {
                    // A handler can't continue a noncontinuable exception.
                    if record.flags & EXCEPTION_NONCONTINUABLE != 0 {
                        return DispatchResult::Noncontinuable;
                    }
                    return DispatchResult::Handled { frame: i };
                }
                Disposition::ContinueSearch => continue,
                // Nested/collided: the real dispatcher raises a new exception; for the model we treat
                // it as continuing the search (the collision handling is target-context work).
                Disposition::NestedException | Disposition::CollidedUnwind => continue,
            }
        }
    }
    DispatchResult::Unhandled
}

/// `RtlUnwind` / `RtlUnwindEx` — the second SEH pass: from the current frame down to `target_frame`,
/// call each intervening frame's handler with `EXCEPTION_UNWINDING` set (so termination handlers /
/// `__finally` blocks run), then transfer control to the target. Returns the indices of the frames
/// whose unwind handler was invoked (for host verification). The actual control transfer to the
/// target frame is target-gated.
pub fn unwind(frames: &[FrameModel], target_frame: usize) -> Vec<usize> {
    let mut unwound = Vec::new();
    let end = target_frame.min(frames.len());
    for (i, f) in frames.iter().enumerate().take(end) {
        if f.handler.is_some() {
            // In the real unwind the handler is called with EXCEPTION_UNWINDING; we record that it
            // participates. (`__finally` blocks execute here.)
            unwound.push(i);
        }
    }
    unwound
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    fn rec(code: u32, flags: u32) -> ExceptionRecord {
        ExceptionRecord { code, flags, address: 0x1000, information: Vec::new() }
    }

    #[test]
    fn function_table_lookup() {
        let t = FunctionTable::add(
            0x1_0000,
            vec![
                RuntimeFunction { begin: 0x100, end: 0x200, unwind_info: 0x900 },
                RuntimeFunction { begin: 0x200, end: 0x350, unwind_info: 0x910 },
            ],
        );
        // PC in the second function.
        let f = t.lookup(0x1_0000 + 0x250).unwrap();
        assert_eq!(f.begin, 0x200);
        // PC before any function (leaf / no entry).
        assert!(t.lookup(0x1_0000 + 0x050).is_none());
        // PC past the last function.
        assert!(t.lookup(0x1_0000 + 0x400).is_none());
        // PC below the image base.
        assert!(t.lookup(0x0FFF).is_none());
    }

    #[test]
    fn dispatch_finds_handler() {
        let frames = [
            FrameModel { control_pc: 0x100, handler: Some(Disposition::ContinueSearch) },
            FrameModel { control_pc: 0x200, handler: Some(Disposition::ContinueExecution) },
            FrameModel { control_pc: 0x300, handler: None },
        ];
        assert_eq!(
            dispatch_exception(&rec(0xC000_0005, 0), &frames),
            DispatchResult::Handled { frame: 1 }
        );
    }

    #[test]
    fn dispatch_unhandled_when_all_search() {
        let frames = [
            FrameModel { control_pc: 0x100, handler: Some(Disposition::ContinueSearch) },
            FrameModel { control_pc: 0x200, handler: None },
        ];
        assert_eq!(dispatch_exception(&rec(0xC000_0005, 0), &frames), DispatchResult::Unhandled);
    }

    #[test]
    fn noncontinuable_rejected() {
        let frames = [FrameModel { control_pc: 0x100, handler: Some(Disposition::ContinueExecution) }];
        assert_eq!(
            dispatch_exception(&rec(0xC000_0025, EXCEPTION_NONCONTINUABLE), &frames),
            DispatchResult::Noncontinuable
        );
    }

    #[test]
    fn unwind_runs_intervening_finally_blocks() {
        let frames = [
            FrameModel { control_pc: 0x100, handler: Some(Disposition::ContinueSearch) },
            FrameModel { control_pc: 0x200, handler: None },
            FrameModel { control_pc: 0x300, handler: Some(Disposition::ContinueSearch) },
            FrameModel { control_pc: 0x400, handler: Some(Disposition::ContinueExecution) },
        ];
        // Unwind down to frame 3 (the target); frames 0 and 2 have handlers (finally blocks).
        assert_eq!(unwind(&frames, 3), vec![0, 2]);
    }
}
