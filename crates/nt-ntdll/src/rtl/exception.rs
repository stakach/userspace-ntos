//! The x64 structured-exception-handling (SEH) machinery: the **table-based** unwind + dispatch
//! model. On x64 there is no `fs:[0]` handler chain — each function's prologue-unwind + language
//! handler live in a `RUNTIME_FUNCTION` (`.pdata` row) whose `UnwindInfoAddress` points at an
//! `UNWIND_INFO` blob (`.xdata`). On an exception the dispatcher walks the call stack; for each
//! frame it `RtlLookupFunctionEntry`'s the covering `RUNTIME_FUNCTION`, `RtlVirtualUnwind`'s that
//! one frame (restoring the caller's registers into the `CONTEXT`), and — if the function has a
//! language handler — calls it to decide `ContinueSearch` vs `ExecuteHandler`.
//!
//! This module is the **pure, host-testable core**: it operates over an [`ImageReader`] abstraction
//! (read a `u8`/`u16`/`u32` at an RVA in a module, and enumerate a module's `.pdata`) so the exact
//! same code runs against hand-crafted `UNWIND_INFO` byte blobs in host tests and against live
//! mapped images on target. The C-ABI export wrappers + the live `ImageReader` over the loader's
//! `MODULE_TABLE` live in `nt-ntdll-dll` (`exports.rs` / `on_target.rs`).
//!
//! References: the documented x64 exception model (MS "x64 exception handling"), cross-checked
//! against `references/reactos/sdk/lib/rtl/amd64/unwind.c` (`RtlVirtualUnwind`,
//! `RtlLookupFunctionEntry`, `RtlpUnwindOpSlots`) and `references/reactos/sdk/lib/rtl/` for
//! `__C_specific_handler`'s `SCOPE_TABLE` walk.

use alloc::vec::Vec;
use core::mem::size_of;

// =================================================================================================
// EXCEPTION_RECORD / dispositions
// =================================================================================================

/// `EXCEPTION_DISPOSITION` — a language handler's verdict on an exception.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// `ExceptionContinueExecution` (0) — the handler fixed it; resume at the faulting point.
    ContinueExecution,
    /// `ExceptionContinueSearch` (1) — not mine; keep walking up the frames.
    ContinueSearch,
    /// `ExceptionNestedException` (2) — an exception occurred within this handler.
    NestedException,
    /// `ExceptionCollidedUnwind` (3) — an unwind collided with another.
    CollidedUnwind,
}

impl Disposition {
    /// The raw `EXCEPTION_DISPOSITION` integer a language handler returns.
    pub fn from_raw(v: i32) -> Disposition {
        match v {
            0 => Disposition::ContinueExecution,
            2 => Disposition::NestedException,
            3 => Disposition::CollidedUnwind,
            _ => Disposition::ContinueSearch, // 1 and anything else → search (the safe default)
        }
    }
}

/// `EXCEPTION_RECORD` (the load-bearing fields): the code, flags, and faulting address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    /// `ExceptionCode` (an `NTSTATUS`, e.g. `STATUS_ACCESS_VIOLATION`).
    pub code: u32,
    /// `ExceptionFlags` (bit 0 = `EXCEPTION_NONCONTINUABLE`, bit 1 = `EXCEPTION_UNWINDING`).
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

/// `STATUS_NONCONTINUABLE_EXCEPTION`.
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC000_0025;
/// `STATUS_UNWIND` (raised to abandon a first-pass search when an unwind is required).
pub const STATUS_UNWIND: u32 = 0xC000_0027;

// =================================================================================================
// x64 CONTEXT — the integer register file we unwind through
// =================================================================================================

/// Register indices as used by `UNWIND_CODE.OpInfo` and by the x64 ABI (`0=RAX .. 15=R15`). We keep
/// the general-purpose registers we actually unwind (nonvols + RSP/RIP); XMM is modelled as a
/// separate array indexed 0..15.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// General registers `[RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15]` (index == ABI reg
    /// number, so `OpInfo` indexes directly).
    pub gpr: [u64; 16],
    /// `Rip` (the instruction pointer).
    pub rip: u64,
    /// XMM0..XMM15 low 128 bits modelled as 2×u64 each (we track them so `UWOP_SAVE_XMM128` restores
    /// are faithful; only the low/high halves are needed for the unwind bookkeeping).
    pub xmm: [[u64; 2]; 16],
}

/// ABI register numbers (index into [`Context::gpr`]).
pub const REG_RAX: usize = 0;
/// `RCX`.
pub const REG_RCX: usize = 1;
/// `RDX`.
pub const REG_RDX: usize = 2;
/// `RBX`.
pub const REG_RBX: usize = 3;
/// `RSP`.
pub const REG_RSP: usize = 4;
/// `RBP`.
pub const REG_RBP: usize = 5;
/// `RSI`.
pub const REG_RSI: usize = 6;
/// `RDI`.
pub const REG_RDI: usize = 7;

impl Context {
    /// `RSP`.
    pub fn rsp(&self) -> u64 {
        self.gpr[REG_RSP]
    }
    /// Set `RSP`.
    pub fn set_rsp(&mut self, v: u64) {
        self.gpr[REG_RSP] = v;
    }
}

// =================================================================================================
// RUNTIME_FUNCTION (.pdata) + UNWIND_INFO (.xdata)
// =================================================================================================

/// `IMAGE_DIRECTORY_ENTRY_EXCEPTION` — the `.pdata` data-directory index.
pub const DIRECTORY_ENTRY_EXCEPTION: usize = 3;

/// A `RUNTIME_FUNCTION` (`.pdata` row, 12 bytes on x64): `[BeginAddress, EndAddress,
/// UnwindInfoAddress]` — all RVAs relative to the image base.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    /// `BeginAddress` (RVA of the function's first instruction).
    pub begin: u32,
    /// `EndAddress` (RVA one past the function's last instruction).
    pub end: u32,
    /// `UnwindInfoAddress` (RVA of the `UNWIND_INFO`; if bit 0 is set it is a chained pointer to
    /// another `RUNTIME_FUNCTION` — see [`Self::is_chained_ptr`]).
    pub unwind_info: u32,
}

impl RuntimeFunction {
    /// Whether this entry covers the given image-relative RVA.
    pub fn covers(&self, rva: u32) -> bool {
        rva >= self.begin && rva < self.end
    }

    /// In a *chained* `RUNTIME_FUNCTION` the low bit of `UnwindInfoAddress` is set and the rest is
    /// the RVA of the parent `RUNTIME_FUNCTION`. (This is the "sequence of contiguous code" chaining
    /// form some compilers emit for `.pdata` — distinct from the `UNW_FLAG_CHAININFO` in `xdata`.)
    pub fn is_chained_ptr(&self) -> bool {
        self.unwind_info & 1 == 1
    }
}

/// `UNW_FLAG_*` (the `Flags` nibble of `UNWIND_INFO`).
pub mod unw_flag {
    /// `UNW_FLAG_NHANDLER` — no language handler.
    pub const NHANDLER: u8 = 0x0;
    /// `UNW_FLAG_EHANDLER` — an exception (filter) handler is present.
    pub const EHANDLER: u8 = 0x1;
    /// `UNW_FLAG_UHANDLER` — a termination (unwind) handler is present.
    pub const UHANDLER: u8 = 0x2;
    /// `UNW_FLAG_CHAININFO` — this `UNWIND_INFO` chains to another `RUNTIME_FUNCTION` (shared
    /// prologue). The chained entry follows the (padded) unwind-code array.
    pub const CHAININFO: u8 = 0x4;
}

/// The x64 unwind opcodes (`UNWIND_CODE.UnwindOp`, the low nibble of the op byte).
pub mod uwop {
    /// `UWOP_PUSH_NONVOL` — `push` of a nonvol register (OpInfo = reg). 1 slot.
    pub const PUSH_NONVOL: u8 = 0;
    /// `UWOP_ALLOC_LARGE` — a large stack alloc. 2 slots (OpInfo 0 → next u16 * 8) or 3 slots
    /// (OpInfo 1 → next u32).
    pub const ALLOC_LARGE: u8 = 1;
    /// `UWOP_ALLOC_SMALL` — `sub rsp, (OpInfo*8)+8`. 1 slot.
    pub const ALLOC_SMALL: u8 = 2;
    /// `UWOP_SET_FPREG` — establish the frame pointer (`FrameRegister`). 1 slot.
    pub const SET_FPREG: u8 = 3;
    /// `UWOP_SAVE_NONVOL` — a nonvol saved at `[frame + next_u16*8]`. 2 slots.
    pub const SAVE_NONVOL: u8 = 4;
    /// `UWOP_SAVE_NONVOL_FAR` — a nonvol saved at `[frame + next_u32]`. 3 slots.
    pub const SAVE_NONVOL_FAR: u8 = 5;
    /// `UWOP_SAVE_XMM128` — an XMM reg saved at `[frame + next_u16*16]`. 2 slots.
    pub const SAVE_XMM128: u8 = 8;
    /// `UWOP_SAVE_XMM128_FAR` — an XMM reg saved at `[frame + next_u32]`. 3 slots.
    pub const SAVE_XMM128_FAR: u8 = 9;
    /// `UWOP_PUSH_MACHFRAME` — a hardware-interrupt machine frame was pushed. 1 slot.
    pub const PUSH_MACHFRAME: u8 = 10;
}

/// The parsed fixed header of an `UNWIND_INFO` (`.xdata`). Byte layout:
/// - `[0]`: `Version:3` (low) | `Flags:5` (high)
/// - `[1]`: `SizeOfProlog`
/// - `[2]`: `CountOfCodes`
/// - `[3]`: `FrameRegister:4` (low) | `FrameOffset:4` (high)
/// - `[4..]`: `CountOfCodes` × 2-byte `UNWIND_CODE` slots (padded to an even count)
///
/// After the (padded) code array, if a handler flag is set, a `u32` handler RVA + language-specific
/// handler data follow; if `CHAININFO`, a chained `RUNTIME_FUNCTION` (12 bytes) follows instead.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UnwindInfoHeader {
    /// `Version` (should be 1 or 2).
    pub version: u8,
    /// `Flags` (`UNW_FLAG_*`).
    pub flags: u8,
    /// `SizeOfProlog` — the byte length of the prologue.
    pub size_of_prolog: u8,
    /// `CountOfCodes` — the number of 2-byte unwind-code slots.
    pub count_of_codes: u8,
    /// `FrameRegister` — the ABI reg number of the frame pointer (0 = none).
    pub frame_register: u8,
    /// `FrameOffset` — the frame-pointer offset (in 16-byte units; `RSP = frame_reg - FrameOffset*16`
    /// at frame-pointer establishment).
    pub frame_offset: u8,
}

impl UnwindInfoHeader {
    /// Parse the 4-byte fixed header.
    pub fn parse(b: &[u8; 4]) -> UnwindInfoHeader {
        UnwindInfoHeader {
            version: b[0] & 0x07,
            flags: (b[0] >> 3) & 0x1F,
            size_of_prolog: b[1],
            count_of_codes: b[2],
            frame_register: b[3] & 0x0F,
            frame_offset: (b[3] >> 4) & 0x0F,
        }
    }

    /// The byte offset (from the `UNWIND_INFO` start) of the data following the unwind-code array
    /// (handler RVA / chained entry): `4 + align_up(CountOfCodes, 2) * 2`.
    pub fn tail_offset(&self) -> usize {
        let padded = (self.count_of_codes as usize).div_ceil(2) * 2;
        4 + padded * 2
    }

    /// True if this `UNWIND_INFO` names a language handler (`EHANDLER` or `UHANDLER`).
    pub fn has_handler(&self) -> bool {
        self.flags & (unw_flag::EHANDLER | unw_flag::UHANDLER) != 0
    }

    /// True if this `UNWIND_INFO` chains to a parent `RUNTIME_FUNCTION`.
    pub fn is_chained(&self) -> bool {
        self.flags & unw_flag::CHAININFO != 0
    }
}

// =================================================================================================
// ImageReader — the abstraction over "a set of loaded modules"
// =================================================================================================

/// The read-only view the unwinder needs of the process's loaded images: read raw bytes at an
/// image-relative RVA, and locate the module + `.pdata` entry covering an absolute PC.
///
/// On the host this is a mock over hand-crafted byte blobs; on target it is a walk of the loader's
/// `MODULE_TABLE` + reads through the live mapped images.
pub trait ImageReader {
    /// Given an absolute control PC, return `(image_base, RuntimeFunction)` for the covering
    /// function, or `None` if the PC is not in any known module's `.pdata` (a leaf / unknown frame).
    /// This is `RtlLookupFunctionEntry`.
    fn lookup_function(&self, control_pc: u64) -> Option<(u64, RuntimeFunction)>;

    /// Read a `u8` at `image_base + rva`.
    fn read_u8(&self, image_base: u64, rva: u32) -> Option<u8>;

    /// Read a `u16` at `image_base + rva` (little-endian).
    fn read_u16(&self, image_base: u64, rva: u32) -> Option<u16> {
        let lo = self.read_u8(image_base, rva)? as u16;
        let hi = self.read_u8(image_base, rva + 1)? as u16;
        Some(lo | (hi << 8))
    }

    /// Read a `u32` at `image_base + rva` (little-endian).
    fn read_u32(&self, image_base: u64, rva: u32) -> Option<u32> {
        let lo = self.read_u16(image_base, rva)? as u32;
        let hi = self.read_u16(image_base, rva + 2)? as u32;
        Some(lo | (hi << 16))
    }
}

/// Read a value at an absolute VA (for the stack reads the unwinder does — popping saved nonvols /
/// the return address off the establisher frame). Split from [`ImageReader`] because on the host the
/// "stack" is a separate mock array, and on target it is a raw memory read.
pub trait StackReader {
    /// Read a `u64` at absolute address `addr`, or `None` if not readable.
    fn read_u64(&self, addr: u64) -> Option<u64>;
}

/// Lowest valid user-mode instruction address accepted by `RtlWalkFrameChain`.
pub const USER_ADDRESS_LOW: u64 = 0x0000_0000_0001_0000;
/// Highest valid user-mode instruction address accepted by ReactOS on x64.
pub const USER_ADDRESS_HIGH: u64 = 0x0000_07ff_fffe_ffff;

/// A hard failure while walking an x64 frame chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameWalkError {
    /// The supplied TEB stack range is empty or inverted.
    InvalidStackBounds,
    /// The requested skipped/output frame count overflowed.
    CountOverflow,
    /// A leaf or unwind-code stack read fell outside the bounded stack or was unavailable.
    StackRead,
    /// A covering runtime function had unreadable or invalid unwind metadata.
    UnwindData,
}

struct BoundedStack<'a> {
    inner: &'a dyn StackReader,
    low: u64,
    high: u64,
}

impl StackReader for BoundedStack<'_> {
    fn read_u64(&self, addr: u64) -> Option<u64> {
        let end = addr.checked_add(size_of::<u64>() as u64)?;
        if addr < self.low || end > self.high || addr & 7 != 0 {
            return None;
        }
        self.inner.read_u64(addr)
    }
}

/// Walk user-mode x64 frames from an already captured context. Leaf functions pop a return address;
/// nonleaf functions use their `.pdata`/`.xdata` through [`virtual_unwind`]. Stack reads are bounded
/// by the current TEB limits before being delegated to `stack`.
///
/// The returned count follows ReactOS: when `frames_to_skip` is nonzero it includes successfully
/// skipped frames, while only `callers.len()` post-skip addresses are written.
pub fn walk_frame_chain(
    mut context: Context,
    callers: &mut [u64],
    frames_to_skip: usize,
    stack_low: u64,
    stack_high: u64,
    image: &dyn ImageReader,
    stack: &dyn StackReader,
) -> Result<usize, FrameWalkError> {
    if stack_low >= stack_high {
        return Err(FrameWalkError::InvalidStackBounds);
    }
    let total = frames_to_skip
        .checked_add(callers.len())
        .ok_or(FrameWalkError::CountOverflow)?;
    let bounded = BoundedStack {
        inner: stack,
        low: stack_low,
        high: stack_high,
    };
    let mut control_pc = context.rip;

    for index in 0..total {
        if let Some((image_base, function)) = image.lookup_function(control_pc) {
            virtual_unwind(
                unw_flag::NHANDLER,
                image_base,
                control_pc,
                function,
                &mut context,
                image,
                &bounded,
            )
            .ok_or(FrameWalkError::UnwindData)?;
        } else {
            let rsp = context.rsp();
            context.rip = bounded.read_u64(rsp).ok_or(FrameWalkError::StackRead)?;
            context.set_rsp(
                rsp.checked_add(size_of::<u64>() as u64)
                    .ok_or(FrameWalkError::StackRead)?,
            );
        }

        if !(USER_ADDRESS_LOW..=USER_ADDRESS_HIGH).contains(&context.rip)
            || context.rsp() <= stack_low
            || context.rsp() >= stack_high
        {
            return Ok(index);
        }

        control_pc = context.rip;
        if index >= frames_to_skip {
            callers[index - frames_to_skip] = control_pc;
        }
    }
    Ok(total)
}

/// Validate the bounded request used by `RtlCaptureStackBackTrace`. The native routine adds one
/// skipped frame for itself and rejects a total of 128 or more.
pub fn stack_back_trace_request(
    frames_to_skip: u32,
    frames_to_capture: u32,
) -> Option<(usize, usize)> {
    let skip = frames_to_skip.checked_add(1)? as usize;
    let total = skip.checked_add(frames_to_capture as usize)?;
    (total < 128).then_some((skip, total))
}

/// Copy the requested post-skip frames and compute the native wrapping low-32-bit address hash.
/// `None` means the walk did not get past all skipped frames, in which case the caller must leave
/// its optional hash output untouched.
pub fn project_stack_back_trace(
    frames: &[u64],
    frames_to_skip: usize,
    back_trace: &mut [u64],
) -> Option<(usize, u32)> {
    if frames.len() <= frames_to_skip {
        return None;
    }
    let count = back_trace.len().min(frames.len() - frames_to_skip);
    let mut hash = 0u32;
    for index in 0..count {
        let address = frames[frames_to_skip + index];
        back_trace[index] = address;
        hash = hash.wrapping_add(address as u32);
    }
    Some((count, hash))
}

/// Select the two outputs used by `RtlGetCallersAddress` from its four-frame walk.
pub fn callers_addresses(frames: &[u64; 4], frame_count: usize) -> (u64, u64) {
    (
        if frame_count >= 3 { frames[2] } else { 0 },
        if frame_count == 4 { frames[3] } else { 0 },
    )
}

// =================================================================================================
// RtlLookupFunctionEntry — resolve a control PC through a (possibly chained) RUNTIME_FUNCTION
// =================================================================================================

/// The static `.pdata` of one image (its `RUNTIME_FUNCTION` rows sorted by `begin`), used to build a
/// concrete [`ImageReader::lookup_function`] over a byte blob. Kept sorted for a binary search.
#[derive(Clone, Debug, Default)]
pub struct FunctionTable {
    /// The image base the entry RVAs are relative to.
    pub image_base: u64,
    /// The `.pdata` rows, sorted by `begin`.
    pub functions: Vec<RuntimeFunction>,
}

impl FunctionTable {
    /// `RtlAddFunctionTable` — register + sort a function table.
    pub fn add(image_base: u64, mut functions: Vec<RuntimeFunction>) -> Self {
        functions.sort_by_key(|f| f.begin);
        FunctionTable {
            image_base,
            functions,
        }
    }

    /// Find the `RUNTIME_FUNCTION` covering an absolute control PC (binary search). Returns `None`
    /// for a leaf (no covering `.pdata` entry).
    pub fn lookup(&self, control_pc: u64) -> Option<RuntimeFunction> {
        if control_pc < self.image_base {
            return None;
        }
        let rva = (control_pc - self.image_base) as u32;
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

// =================================================================================================
// The unwind-code interpreter — RtlVirtualUnwind's core
// =================================================================================================

/// The outcome of unwinding one frame ([`virtual_unwind`]): the (possibly still-null) language
/// handler RVA + the RVA of the language-specific handler data (the `SCOPE_TABLE` for
/// `__C_specific_handler`). The [`Context`] passed to `virtual_unwind` is updated in place to the
/// caller's register state.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct UnwindResult {
    /// The image base the handler/data RVAs are relative to (the module that owned the frame).
    pub image_base: u64,
    /// The language handler's RVA (0 = none for this unwind type).
    pub handler_rva: u32,
    /// The RVA of the language-specific handler data (0 = none).
    pub handler_data_rva: u32,
    /// The establisher frame (the frame base that the handler-data offsets are relative to). For a
    /// frame-pointer function this is `FrameRegister - FrameOffset*16` computed during the prologue;
    /// otherwise it is the incoming `RSP` after the prologue.
    pub establisher_frame: u64,
}

/// `HandlerType` for [`virtual_unwind`] — which handler flag we want returned (matches the
/// `UNW_FLAG_*` value): `EHANDLER` during the first (search) pass, `UHANDLER` during the unwind
/// (second) pass. `NHANDLER` (0) means "unwind only, don't return a handler".
pub type HandlerType = u8;

/// `RtlVirtualUnwind` — unwind exactly one frame. Parse the function's `UNWIND_INFO`, apply the
/// unwind codes whose prologue offset has already executed (i.e. `CodeOffset <= prologue_offset`,
/// where `prologue_offset = pc - func.begin`), restoring nonvols + `RSP` into `ctx`, then pop the
/// return address to set `ctx.rip`. Follows `UNW_FLAG_CHAININFO` to unwind the shared prologue.
///
/// Returns the language handler (of the requested `handler_type`) + its data RVA, or an
/// all-zero [`UnwindResult`] if this function has no such handler. On a hard read failure returns
/// `None` (a corrupt / unmapped unwind table — the caller treats it as unhandleable).
///
/// `image_base` + `func` come from [`ImageReader::lookup_function`]; `control_pc` is the absolute PC
/// in this frame; `img` reads the `.xdata`; `stack` reads saved values off the frame.
pub fn virtual_unwind(
    handler_type: HandlerType,
    image_base: u64,
    control_pc: u64,
    func: RuntimeFunction,
    ctx: &mut Context,
    img: &dyn ImageReader,
    stack: &dyn StackReader,
) -> Option<UnwindResult> {
    let covering_func = func;
    let control_rva = u32::try_from(control_pc.checked_sub(image_base)?).ok()?;
    if !covering_func.covers(control_rva) {
        return None;
    }

    // Resolve a chained-pointer RUNTIME_FUNCTION (low bit of UnwindInfoAddress set → the RVA points
    // at the parent RUNTIME_FUNCTION, not an UNWIND_INFO). Follow the chain to the real xdata.
    let mut func = func;
    let mut guard = 0;
    while func.is_chained_ptr() {
        let parent_rva = func.unwind_info & !1;
        let begin = img.read_u32(image_base, parent_rva)?;
        let end = img.read_u32(image_base, parent_rva + 4)?;
        let uw = img.read_u32(image_base, parent_rva + 8)?;
        func = RuntimeFunction {
            begin,
            end,
            unwind_info: uw,
        };
        guard += 1;
        if guard > 32 {
            return None; // pathological chain
        }
    }

    // The image-relative offset of the control PC within the function's prologue. If the PC is at the
    // function's very first byte (== begin) this is 0 → the prologue has not executed at all.
    let prologue_offset = (control_pc.wrapping_sub(image_base) as u32).wrapping_sub(func.begin);

    unwind_one(
        handler_type,
        image_base,
        func.unwind_info,
        prologue_offset,
        ctx,
        img,
        stack,
        0,
        control_rva,
        covering_func.end,
    )
}

/// The inner recursive worker (recursion depth `depth` bounds `CHAININFO`). `unwind_rva` is the RVA
/// of this level's `UNWIND_INFO`; `prologue_offset` is how far into *this* function's prologue the PC
/// is (chained levels use 0 — the shared prologue is fully executed by the time we chain to it).
#[allow(clippy::too_many_arguments)]
fn unwind_one(
    handler_type: HandlerType,
    image_base: u64,
    unwind_rva: u32,
    prologue_offset: u32,
    ctx: &mut Context,
    img: &dyn ImageReader,
    stack: &dyn StackReader,
    depth: u32,
    control_rva: u32,
    function_end_rva: u32,
) -> Option<UnwindResult> {
    if depth > 32 {
        return None; // pathological CHAININFO chain
    }
    let hdr = UnwindInfoHeader::parse(&[
        img.read_u8(image_base, unwind_rva)?,
        img.read_u8(image_base, unwind_rva + 1)?,
        img.read_u8(image_base, unwind_rva + 2)?,
        img.read_u8(image_base, unwind_rva + 3)?,
    ]);

    // GetEstablisherFrame (ref RtlVirtualUnwind): the frame the handler's data offsets are relative
    // to. If there is no frame register it is the incoming RSP. Otherwise, if the PC is past the
    // prologue (or we are on a chained level, prologue_offset == u32::MAX), it is
    // FrameReg - FrameOffset*16. If still inside the prologue, it is that only once the SET_FPREG
    // code (with CodeOffset <= prologue_offset) has executed; else the incoming RSP. Computed BEFORE
    // any register restores so the frame-register value is the live one.
    let establisher_frame =
        compute_establisher_frame(&hdr, image_base, unwind_rva, prologue_offset, ctx, img)?;

    // A PC in an AMD64 epilogue must execute the remaining epilogue instructions, not reverse the
    // entire prologue again. ReactOS recognizes the ABI's optional stack adjustment, nonvolatile
    // pops, and final `ret` sequence.
    if prologue_offset > hdr.size_of_prolog as u32
        && hdr.count_of_codes != 0
        && try_unwind_epilogue(image_base, control_rva, function_end_rva, ctx, img, stack)
    {
        return Some(UnwindResult {
            image_base,
            establisher_frame,
            ..Default::default()
        });
    }

    // Walk the unwind codes. Each slot is (CodeOffset, op_byte) little-endian pairs; a code may
    // consume additional slots for its operand. We only APPLY a code if its CodeOffset has already
    // been executed by the PC (CodeOffset <= prologue_offset) — codes for prologue instructions that
    // have not run yet are skipped (their register was not saved yet). Per the reference, ALL
    // SAVE_*/PUSH ops read relative to the CURRENT unwinding RSP (not the frame base).
    let count = hdr.count_of_codes as usize;
    let mut i = 0usize;
    let mut machframe = false;
    while i < count {
        let code_off = img.read_u8(image_base, unwind_rva + 4 + (i as u32) * 2)?;
        let op_byte = img.read_u8(image_base, unwind_rva + 4 + (i as u32) * 2 + 1)?;
        let op = op_byte & 0x0F;
        let op_info = (op_byte >> 4) & 0x0F;
        let slots = op_slots(op, op_info)?;

        if (code_off as u32) <= prologue_offset {
            if apply_code(
                op,
                op_info,
                image_base,
                unwind_rva,
                i,
                hdr.frame_register,
                hdr.frame_offset,
                ctx,
                img,
                stack,
            )? && op == uwop::PUSH_MACHFRAME
            {
                machframe = true;
            }
        }
        i += slots;
    }

    // Handle CHAININFO: the chained RUNTIME_FUNCTION sits at the (padded) tail; reload UnwindInfo
    // from its UnwindData and apply IT in full (all its prologue codes have executed by here). The
    // language handler + establisher frame come from THIS (last-applied) level in the reference; we
    // apply the chained codes then fall through to collect this level's handler.
    if hdr.is_chained() {
        let tail = unwind_rva + hdr.tail_offset() as u32;
        // tail: RUNTIME_FUNCTION { begin:u32, end:u32, unwind_info:u32 }
        let chained_uw = img.read_u32(image_base, tail + 8)?;
        // Apply the chained prologue in full WITHOUT its own return-address pop (that belongs to the
        // outermost frame). We recurse with a "codes only" flag by using prologue_offset u32::MAX and
        // a sentinel that suppresses the ret pop — handled by unwind_codes_only below.
        apply_chained_codes(image_base, chained_uw & !1, ctx, img, stack, depth + 1)?;
    }

    // A machine-frame op already set RIP+RSP from the trap frame → do NOT pop a return address.
    if !machframe {
        let ret_addr_slot = ctx.rsp();
        let ret = stack.read_u64(ret_addr_slot)?;
        ctx.rip = ret;
        ctx.set_rsp(ret_addr_slot.wrapping_add(8));
    }

    Some(collect_handler(
        handler_type,
        image_base,
        &hdr,
        unwind_rva,
        establisher_frame,
        img,
    ))
}

/// Recognize and execute the remaining instructions of a canonical AMD64 epilogue. The scan uses a
/// local context and commits it only after reaching the function's final `ret`, so ordinary body
/// instructions fall back to unwind-code interpretation without partially changing the context.
fn try_unwind_epilogue(
    image_base: u64,
    control_rva: u32,
    function_end_rva: u32,
    ctx: &mut Context,
    img: &dyn ImageReader,
    stack: &dyn StackReader,
) -> bool {
    let Some(end_rva) = function_end_rva.checked_sub(1) else {
        return false;
    };
    if control_rva > end_rva {
        return false;
    }

    let read_u8 = |rva| img.read_u8(image_base, rva);
    let read_u32 = |rva| img.read_u32(image_base, rva);
    let mut local = *ctx;
    let mut cursor = control_rva;

    if let Some(instr) = read_u32(cursor) {
        // 48 83 c4 ib / 48 81 c4 id: add rsp, immediate.
        if instr & 0x00ff_fdff == 0x00c4_8148 {
            if instr & 0x0000_ff00 == 0x0000_8300 {
                local.set_rsp(local.rsp().wrapping_add((instr >> 24) as u64));
                cursor = match cursor.checked_add(4) {
                    Some(next) => next,
                    None => return false,
                };
            } else {
                let Some(imm) = read_u32(cursor.wrapping_add(3)) else {
                    return false;
                };
                local.set_rsp(local.rsp().wrapping_add(imm as u64));
                cursor = match cursor.checked_add(7) {
                    Some(next) => next,
                    None => return false,
                };
            }
        // 48/49 8d 60..a7 [disp]: lea rsp, [nonvolatile + displacement].
        } else if instr & 0x0038_fffe == 0x0020_8d48 {
            let reg = (((instr >> 16) & 7) + ((instr & 1) * 8)) as usize;
            let mode = (instr >> 22) & 3;
            let (displacement, length) = match mode {
                0 => (0i64, 3u32),
                1 => (((instr >> 24) as u8 as i8) as i64, 4),
                2 => {
                    let Some(raw) = read_u32(cursor.wrapping_add(3)) else {
                        return false;
                    };
                    (raw as i32 as i64, 7)
                }
                _ => return false,
            };
            local.set_rsp(local.gpr[reg].wrapping_add_signed(displacement));
            cursor = match cursor.checked_add(length) {
                Some(next) => next,
                None => return false,
            };
        }
    }

    while cursor < end_rva {
        let Some(opcode) = read_u8(cursor) else {
            return false;
        };
        let (reg, length) = if opcode & 0xf8 == 0x58 {
            ((opcode & 7) as usize, 1u32)
        } else if (opcode == 0x41 || opcode == 0x49)
            && read_u8(cursor.wrapping_add(1)).is_some_and(|next| next & 0xf8 == 0x58)
        {
            let next = read_u8(cursor.wrapping_add(1)).unwrap_or(0);
            (((next & 7) + 8) as usize, 2)
        } else {
            return false;
        };
        let Some(value) = stack.read_u64(local.rsp()) else {
            return false;
        };
        local.gpr[reg] = value;
        local.set_rsp(local.rsp().wrapping_add(8));
        cursor = match cursor.checked_add(length) {
            Some(next) => next,
            None => return false,
        };
    }

    if cursor != end_rva || read_u8(cursor) != Some(0xc3) {
        return false;
    }
    let Some(return_address) = stack.read_u64(local.rsp()) else {
        return false;
    };
    local.rip = return_address;
    local.set_rsp(local.rsp().wrapping_add(8));
    *ctx = local;
    true
}

/// Apply ONLY the unwind codes of a chained `UNWIND_INFO` (no return-address pop, no handler
/// collection) — the shared-prologue register/stack restores. Recurses for nested CHAININFO.
fn apply_chained_codes(
    image_base: u64,
    unwind_rva: u32,
    ctx: &mut Context,
    img: &dyn ImageReader,
    stack: &dyn StackReader,
    depth: u32,
) -> Option<()> {
    if depth > 32 {
        return None;
    }
    let hdr = UnwindInfoHeader::parse(&[
        img.read_u8(image_base, unwind_rva)?,
        img.read_u8(image_base, unwind_rva + 1)?,
        img.read_u8(image_base, unwind_rva + 2)?,
        img.read_u8(image_base, unwind_rva + 3)?,
    ]);
    let count = hdr.count_of_codes as usize;
    let mut i = 0usize;
    while i < count {
        let op_byte = img.read_u8(image_base, unwind_rva + 4 + (i as u32) * 2 + 1)?;
        let op = op_byte & 0x0F;
        let op_info = (op_byte >> 4) & 0x0F;
        let slots = op_slots(op, op_info)?;
        // Chained prologue: every code has executed → apply unconditionally.
        apply_code(
            op,
            op_info,
            image_base,
            unwind_rva,
            i,
            hdr.frame_register,
            hdr.frame_offset,
            ctx,
            img,
            stack,
        )?;
        i += slots;
    }
    if hdr.is_chained() {
        let tail = unwind_rva + hdr.tail_offset() as u32;
        let chained_uw = img.read_u32(image_base, tail + 8)?;
        apply_chained_codes(image_base, chained_uw & !1, ctx, img, stack, depth + 1)?;
    }
    Some(())
}

/// `GetEstablisherFrame` (ref `unwind.c:431`).
fn compute_establisher_frame(
    hdr: &UnwindInfoHeader,
    image_base: u64,
    unwind_rva: u32,
    prologue_offset: u32,
    ctx: &Context,
    img: &dyn ImageReader,
) -> Option<u64> {
    if hdr.frame_register == 0 {
        return Some(ctx.rsp());
    }
    let fp_value =
        ctx.gpr[hdr.frame_register as usize].wrapping_sub((hdr.frame_offset as u64) * 16);
    // Past the prologue (or a chained level, prologue_offset == u32::MAX) → the FP is established.
    if prologue_offset >= hdr.size_of_prolog as u32 {
        return Some(fp_value);
    }
    // Still inside the prologue: the FP is the frame register only if the SET_FPREG code has run.
    let count = hdr.count_of_codes as usize;
    let mut i = 0usize;
    while i < count {
        let off = img.read_u8(image_base, unwind_rva + 4 + (i as u32) * 2)?;
        let op_byte = img.read_u8(image_base, unwind_rva + 4 + (i as u32) * 2 + 1)?;
        let op = op_byte & 0x0F;
        let op_info = (op_byte >> 4) & 0x0F;
        if op == uwop::SET_FPREG && (off as u32) <= prologue_offset {
            return Some(fp_value);
        }
        i += op_slots(op, op_info)?;
    }
    Some(ctx.rsp())
}

/// Collect the language handler (+ data RVA) from a non-chained `UNWIND_INFO` if it matches the
/// requested `handler_type`.
fn collect_handler(
    handler_type: HandlerType,
    image_base: u64,
    hdr: &UnwindInfoHeader,
    unwind_rva: u32,
    establisher_frame: u64,
    img: &dyn ImageReader,
) -> UnwindResult {
    let mut res = UnwindResult {
        image_base,
        establisher_frame,
        ..Default::default()
    };
    // A handler is returned only when its flag is requested (EHANDLER for the search pass, UHANDLER
    // for the unwind pass). handler_type == 0 → don't return a handler.
    if handler_type != 0 && hdr.has_handler() && (hdr.flags & handler_type) != 0 {
        let tail = unwind_rva + hdr.tail_offset() as u32;
        if let Some(hrva) = img.read_u32(image_base, tail) {
            res.handler_rva = hrva;
            // The language-specific handler data (e.g. the SCOPE_TABLE) immediately follows the
            // handler RVA.
            res.handler_data_rva = tail + 4;
        }
    }
    res
}

/// How many 2-byte slots an unwind code consumes (including its own slot). Some depend on `OpInfo`.
/// Mirrors `UnwindOpSlots` (ref `unwind.c:174`).
fn op_slots(op: u8, op_info: u8) -> Option<usize> {
    Some(match op {
        uwop::PUSH_NONVOL => 1,
        uwop::ALLOC_LARGE => {
            if op_info == 0 {
                2
            } else {
                3
            }
        }
        uwop::ALLOC_SMALL => 1,
        uwop::SET_FPREG => 1,
        uwop::SAVE_NONVOL => 2,
        uwop::SAVE_NONVOL_FAR => 3,
        6 => 2, // UWOP_EPILOG (v2) — no-op, 2 slots
        7 => 3, // UWOP_SPARE_CODE — 3 slots
        uwop::SAVE_XMM128 => 2,
        uwop::SAVE_XMM128_FAR => 3,
        uwop::PUSH_MACHFRAME => 1,
        _ => return None, // unknown op → corrupt xdata
    })
}

/// Apply one unwind code to `ctx` (undo the corresponding prologue instruction), faithful to
/// `RtlVirtualUnwind`'s op table. Per the reference, ALL `SAVE_*` offsets are relative to the CURRENT
/// unwinding RSP (`Context->Rsp`), and register indices are ABI numbers (into [`Context::gpr`]).
/// `frame_offset` is the header's `FrameOffset` (for `SET_FPREG`). Returns `true` if the op was
/// `UWOP_PUSH_MACHFRAME` (which terminates the unwind — the caller must not pop a return address).
/// `idx` is the code's slot index (its operand slots follow at `idx+1`, `idx+2`).
#[allow(clippy::too_many_arguments)]
fn apply_code(
    op: u8,
    op_info: u8,
    image_base: u64,
    unwind_rva: u32,
    idx: usize,
    frame_register: u8,
    frame_offset: u8,
    ctx: &mut Context,
    img: &dyn ImageReader,
    stack: &dyn StackReader,
) -> Option<bool> {
    let slot = |n: usize| unwind_rva + 4 + ((idx + n) as u32) * 2;
    match op {
        uwop::PUSH_NONVOL => {
            // A `push reg` was executed: the register's saved value sits at [RSP]; pop it, RSP += 8.
            let v = stack.read_u64(ctx.rsp())?;
            ctx.gpr[op_info as usize] = v;
            ctx.set_rsp(ctx.rsp().wrapping_add(8));
        }
        uwop::ALLOC_LARGE => {
            let size = if op_info == 0 {
                (img.read_u16(image_base, slot(1))? as u64) * 8
            } else {
                img.read_u32(image_base, slot(1))? as u64
            };
            ctx.set_rsp(ctx.rsp().wrapping_add(size));
        }
        uwop::ALLOC_SMALL => {
            let size = (op_info as u64) * 8 + 8;
            ctx.set_rsp(ctx.rsp().wrapping_add(size));
        }
        uwop::SET_FPREG => {
            // Undo the frame-pointer establishment: RSP = FrameReg - FrameOffset*16 (ref:
            // `Rsp = GetReg(FrameRegister) - FrameOffset*16`). The frame register is in the header,
            // NOT this code's OpInfo (which is 0/unused for SET_FPREG).
            ctx.set_rsp(ctx.gpr[frame_register as usize].wrapping_sub((frame_offset as u64) * 16));
        }
        uwop::SAVE_NONVOL => {
            // reg = *((u64*)Rsp + FrameOffset); the stored u16 is a count of 8-byte slots.
            let off = (img.read_u16(image_base, slot(1))? as u64) * 8;
            let v = stack.read_u64(ctx.rsp().wrapping_add(off))?;
            ctx.gpr[op_info as usize] = v;
        }
        uwop::SAVE_NONVOL_FAR => {
            // reg = *(u64*)(Rsp + u32) — raw byte offset.
            let off = img.read_u32(image_base, slot(1))? as u64;
            let v = stack.read_u64(ctx.rsp().wrapping_add(off))?;
            ctx.gpr[op_info as usize] = v;
        }
        uwop::SAVE_XMM128 => {
            // xmm[OpInfo] = *((M128A*)Rsp + FrameOffset); stored u16 is a count of 16-byte slots.
            let off = (img.read_u16(image_base, slot(1))? as u64) * 16;
            let lo = stack.read_u64(ctx.rsp().wrapping_add(off))?;
            let hi = stack.read_u64(ctx.rsp().wrapping_add(off + 8))?;
            ctx.xmm[op_info as usize] = [lo, hi];
        }
        uwop::SAVE_XMM128_FAR => {
            let off = img.read_u32(image_base, slot(1))? as u64;
            let lo = stack.read_u64(ctx.rsp().wrapping_add(off))?;
            let hi = stack.read_u64(ctx.rsp().wrapping_add(off + 8))?;
            ctx.xmm[op_info as usize] = [lo, hi];
        }
        6 | 7 => {
            // UWOP_EPILOG / UWOP_SPARE_CODE — no register effect during a virtual unwind.
        }
        uwop::PUSH_MACHFRAME => {
            // A trap/interrupt machine frame (ref: `Rsp += OpInfo*8; Rip=[Rsp+0]; Rsp=[Rsp+0x18]`).
            ctx.set_rsp(ctx.rsp().wrapping_add((op_info as u64) * 8));
            let rip = stack.read_u64(ctx.rsp())?;
            let new_rsp = stack.read_u64(ctx.rsp().wrapping_add(0x18))?;
            ctx.rip = rip;
            ctx.set_rsp(new_rsp);
            return Some(true); // machine frame terminates the unwind
        }
        _ => return None,
    }
    Some(false)
}

// =================================================================================================
// __C_specific_handler — the SCOPE_TABLE walk for C __try/__except/__finally
// =================================================================================================

/// One `SCOPE_TABLE` record (4 RVAs). For a `__try/__except`: `[BeginAddress, EndAddress) ` is the
/// guarded region, `HandlerAddress` is the FILTER RVA (or the sentinel `1` = "execute handler
/// unconditionally"), `JumpTarget` is the `__except` body RVA. For a `__try/__finally`,
/// `HandlerAddress` is the `__finally` routine and `JumpTarget` is 0.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ScopeRecord {
    /// `BeginAddress` (RVA of the guarded region start).
    pub begin: u32,
    /// `EndAddress` (RVA one past the guarded region).
    pub end: u32,
    /// `HandlerAddress` — the filter RVA, or `1` (`EXCEPTION_EXECUTE_HANDLER`), or (finally) the
    /// `__finally` routine RVA.
    pub handler: u32,
    /// `JumpTarget` — the `__except` body RVA (0 ⇒ this is a `__finally` record).
    pub target: u32,
}

/// The `EXCEPTION_EXECUTE_HANDLER` sentinel a `HandlerAddress` can carry (no filter to run — always
/// execute).
pub const SCOPE_HANDLER_EXECUTE: u32 = 1;

/// A filter's verdict (the `int` a `__except` filter expression returns).
pub const EXCEPTION_EXECUTE_HANDLER: i32 = 1;
/// `EXCEPTION_CONTINUE_SEARCH`.
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
/// `EXCEPTION_CONTINUE_EXECUTION`.
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;

/// The decision `__C_specific_handler` reaches for one scope-table walk (the pure part; running the
/// filter + performing the unwind are seams the caller drives).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CHandlerAction {
    /// No scope in this frame matched the fault PC → `ExceptionContinueSearch`.
    ContinueSearch,
    /// A `__try/__except` scope matched and its filter returned EXECUTE_HANDLER: unwind to
    /// `target_rva` (the `__except` body) in the frame at `establisher_frame`.
    ExecuteHandler {
        /// The `__except` body RVA to transfer to (relative to the image base).
        target_rva: u32,
        /// The `__except` body's filter that fired (the scope index, for verification).
        scope_index: usize,
    },
    /// A filter returned EXCEPTION_CONTINUE_EXECUTION → `ExceptionContinueExecution` (resume the
    /// faulting instruction).
    ContinueExecution,
}

/// `__C_specific_handler`'s scope-table walk — the *search-pass* decision. For each scope record
/// whose `[begin,end)` covers `pc_rva`, decide via the filter: a `HandlerAddress == 1` sentinel is
/// EXECUTE unconditionally; a `target == 0` record is a `__finally` (skipped in the search pass);
/// otherwise the filter at `HandlerAddress` is evaluated by `run_filter` (the caller runs the real
/// filter; the host test supplies a closure). The first matching `__except` whose filter returns
/// EXECUTE wins.
///
/// `pc_rva` is the fault PC relative to the image base; `scopes` is the parsed scope table. Returns
/// the [`CHandlerAction`]. This is pure: the only impurity (the filter call) is injected.
pub fn c_specific_handler_search(
    pc_rva: u32,
    scopes: &[ScopeRecord],
    mut run_filter: impl FnMut(u32) -> i32,
) -> CHandlerAction {
    for (i, s) in scopes.iter().enumerate() {
        if pc_rva < s.begin || pc_rva >= s.end {
            continue;
        }
        if s.target == 0 {
            // A __finally record — no filter; it runs during the UNWIND pass, not the search.
            continue;
        }
        let verdict = if s.handler == SCOPE_HANDLER_EXECUTE {
            EXCEPTION_EXECUTE_HANDLER
        } else {
            run_filter(s.handler)
        };
        match verdict {
            EXCEPTION_EXECUTE_HANDLER => {
                return CHandlerAction::ExecuteHandler {
                    target_rva: s.target,
                    scope_index: i,
                }
            }
            EXCEPTION_CONTINUE_EXECUTION => return CHandlerAction::ContinueExecution,
            _ => continue, // EXCEPTION_CONTINUE_SEARCH → try the next scope
        }
    }
    CHandlerAction::ContinueSearch
}

/// `__C_specific_handler`'s *unwind-pass* work: the `__finally` blocks (and any target-terminated
/// `__except` scopes) between the current PC and the unwind target that must run. Returns the RVAs
/// of the `__finally` handlers to invoke, in order. A scope is a `__finally` when `target == 0`; it
/// runs if its `[begin,end)` covers the fault PC and it is being unwound out of.
pub fn c_specific_handler_unwind(pc_rva: u32, scopes: &[ScopeRecord]) -> Vec<u32> {
    let mut finallies = Vec::new();
    for s in scopes {
        if pc_rva >= s.begin && pc_rva < s.end && s.target == 0 {
            finallies.push(s.handler); // the __finally routine RVA
        }
    }
    finallies
}

// =================================================================================================
// RtlDispatchException / RtlUnwindEx — the frame-walk model
// =================================================================================================

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

/// `RtlDispatchException(ExceptionRecord, Context)` — the first (search) pass modelled over an
/// abstract frame list: walk top-down, call each frame's language handler until one returns
/// `ContinueExecution` (handled) or the frames are exhausted (unhandled). The live dispatcher builds
/// the frame list by iterating [`virtual_unwind`] and, per frame, calling the real language handler.
pub fn dispatch_exception(record: &ExceptionRecord, frames: &[FrameModel]) -> DispatchResult {
    for (i, f) in frames.iter().enumerate() {
        if let Some(disp) = f.handler {
            match disp {
                Disposition::ContinueExecution => {
                    if record.flags & EXCEPTION_NONCONTINUABLE != 0 {
                        return DispatchResult::Noncontinuable;
                    }
                    return DispatchResult::Handled { frame: i };
                }
                Disposition::ContinueSearch => continue,
                Disposition::NestedException | Disposition::CollidedUnwind => continue,
            }
        }
    }
    DispatchResult::Unhandled
}

/// `RtlUnwindEx` — the second pass: from the current frame down to `target_frame`, call each
/// intervening frame's termination handler (with `EXCEPTION_UNWINDING` set) so `__finally` blocks
/// run, then transfer control to the target. Returns the indices of the frames whose unwind handler
/// participated (host verification). The control transfer to the target is target-gated.
pub fn unwind(frames: &[FrameModel], target_frame: usize) -> Vec<usize> {
    let mut unwound = Vec::new();
    let end = target_frame.min(frames.len());
    for (i, f) in frames.iter().enumerate().take(end) {
        if f.handler.is_some() {
            unwound.push(i);
        }
    }
    unwound
}

/// `STATUS_POSSIBLE_DEADLOCK` — the exception the critical-section deadlock detector raises; the
/// top-level filter special-cases it (resume execution rather than let it terminate).
pub const STATUS_POSSIBLE_DEADLOCK: u32 = 0xC000_0194;

/// `RtlUnhandledExceptionFilter(ExceptionInfo)` — the top-level exception filter. Faithful to
/// `references/reactos/sdk/lib/rtl/exception.c:RtlUnhandledExceptionFilter2` (which
/// `RtlUnhandledExceptionFilter` tail-calls): a `STATUS_POSSIBLE_DEADLOCK` is dismissed
/// (`EXCEPTION_CONTINUE_EXECUTION`), everything else declines (`EXCEPTION_CONTINUE_SEARCH`) so the
/// exception keeps propagating to the real fatal-error path. This is the pure decision core; the
/// export reads `ExceptionInfo->ExceptionRecord->ExceptionCode` and forwards it here.
pub fn unhandled_exception_filter(exception_code: u32) -> i32 {
    if exception_code == STATUS_POSSIBLE_DEADLOCK {
        EXCEPTION_CONTINUE_EXECUTION
    } else {
        EXCEPTION_CONTINUE_SEARCH
    }
}

// =================================================================================================
// Tests
// =================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::collections::BTreeMap;
    use std::vec;

    // ---- A concrete host ImageReader over a byte blob at a fixed base + a .pdata table ----------

    struct MockImage {
        base: u64,
        // rva -> byte
        bytes: BTreeMap<u32, u8>,
        pdata: FunctionTable,
    }

    impl MockImage {
        fn new(base: u64) -> Self {
            MockImage {
                base,
                bytes: BTreeMap::new(),
                pdata: FunctionTable::add(base, vec![]),
            }
        }
        fn write(&mut self, rva: u32, data: &[u8]) {
            for (k, b) in data.iter().enumerate() {
                self.bytes.insert(rva + k as u32, *b);
            }
        }
        fn set_pdata(&mut self, funcs: Vec<RuntimeFunction>) {
            self.pdata = FunctionTable::add(self.base, funcs);
        }
    }

    impl ImageReader for MockImage {
        fn lookup_function(&self, control_pc: u64) -> Option<(u64, RuntimeFunction)> {
            self.pdata.lookup(control_pc).map(|f| (self.base, f))
        }
        fn read_u8(&self, image_base: u64, rva: u32) -> Option<u8> {
            if image_base != self.base {
                return None;
            }
            self.bytes.get(&rva).copied()
        }
    }

    // A mock stack: absolute addr -> u64.
    struct MockStack {
        cells: BTreeMap<u64, u64>,
    }
    impl MockStack {
        fn new() -> Self {
            MockStack {
                cells: BTreeMap::new(),
            }
        }
        fn put(&mut self, addr: u64, v: u64) {
            self.cells.insert(addr, v);
        }
    }
    impl StackReader for MockStack {
        fn read_u64(&self, addr: u64) -> Option<u64> {
            self.cells.get(&addr).copied()
        }
    }

    fn rec(code: u32, flags: u32) -> ExceptionRecord {
        ExceptionRecord {
            code,
            flags,
            address: 0x1000,
            information: Vec::new(),
        }
    }

    // ------------------------------------------------------------------------------------------
    // RtlWalkFrameChain / RtlCaptureStackBackTrace
    // ------------------------------------------------------------------------------------------

    #[test]
    fn frame_walk_leaf_frames_and_skip_prefix() {
        let image = MockImage::new(0x1400_0000);
        let mut stack = MockStack::new();
        stack.put(0x2000, 0x1400_1111);
        stack.put(0x2008, 0x1400_2222);
        stack.put(0x2010, 0x1400_3333);
        let mut context = Context::default();
        context.rip = 0x1400_0100;
        context.set_rsp(0x2000);
        let mut callers = [0u64; 2];

        let count =
            walk_frame_chain(context, &mut callers, 1, 0x1000, 0x3000, &image, &stack).unwrap();

        assert_eq!(count, 3);
        assert_eq!(callers, [0x1400_2222, 0x1400_3333]);
    }

    #[test]
    fn frame_walk_uses_runtime_unwind_for_nonleaf_frame() {
        let mut image = MockImage::new(0x1_4000_0000);
        image.set_pdata(vec![RuntimeFunction {
            begin: 0x1000,
            end: 0x1100,
            unwind_info: 0x2000,
        }]);
        image.write(0x2000, &[0x01, 0, 0, 0]);
        let mut stack = MockStack::new();
        stack.put(0x2000, 0x1_4000_3000);
        let mut context = Context::default();
        context.rip = 0x1_4000_1050;
        context.set_rsp(0x2000);
        let mut callers = [0u64; 1];

        let count =
            walk_frame_chain(context, &mut callers, 0, 0x1000, 0x3000, &image, &stack).unwrap();

        assert_eq!(count, 1);
        assert_eq!(callers, [0x1_4000_3000]);
    }

    #[test]
    fn frame_walk_stops_before_recording_invalid_frame() {
        let image = MockImage::new(0x1400_0000);
        let mut stack = MockStack::new();
        stack.put(0x2000, USER_ADDRESS_LOW - 1);
        let mut context = Context::default();
        context.rip = 0x1400_0100;
        context.set_rsp(0x2000);
        let mut callers = [0xAAAA_AAAAu64; 1];

        let count =
            walk_frame_chain(context, &mut callers, 0, 0x1000, 0x3000, &image, &stack).unwrap();

        assert_eq!(count, 0);
        assert_eq!(callers, [0xAAAA_AAAA]);
    }

    #[test]
    fn frame_walk_rejects_missing_or_out_of_bounds_stack_reads() {
        let image = MockImage::new(0x1400_0000);
        let stack = MockStack::new();
        let mut context = Context::default();
        context.rip = 0x1400_0100;
        context.set_rsp(0x1000);
        let mut callers = [0u64; 1];

        assert_eq!(
            walk_frame_chain(context, &mut callers, 0, 0x1000, 0x3000, &image, &stack,),
            Err(FrameWalkError::StackRead)
        );
        assert_eq!(
            walk_frame_chain(context, &mut callers, 0, 0x3000, 0x3000, &image, &stack,),
            Err(FrameWalkError::InvalidStackBounds)
        );
    }

    #[test]
    fn frame_walk_preserves_prior_output_at_stack_boundary() {
        let image = MockImage::new(0x1400_0000);
        let mut stack = MockStack::new();
        stack.put(0x2ff0, 0x1400_1111);
        stack.put(0x2ff8, 0x1400_2222);
        let mut context = Context::default();
        context.rip = 0x1400_0100;
        context.set_rsp(0x2ff0);
        let mut callers = [0xAAAA_AAAAu64; 2];

        let count =
            walk_frame_chain(context, &mut callers, 0, 0x1000, 0x3000, &image, &stack).unwrap();

        assert_eq!(count, 1);
        assert_eq!(callers, [0x1400_1111, 0xAAAA_AAAA]);
    }

    #[test]
    fn stack_back_trace_request_enforces_native_limit() {
        assert_eq!(stack_back_trace_request(0, 126), Some((1, 127)));
        assert_eq!(stack_back_trace_request(0, 127), None);
        assert_eq!(stack_back_trace_request(u32::MAX, 0), None);
    }

    #[test]
    fn stack_back_trace_projection_copies_and_wraps_hash() {
        let frames = [0x1000_0000_FFFF_FFF0, 0x20, 0x30, 0x40];
        let mut trace = [0u64; 3];
        let projected = project_stack_back_trace(&frames, 1, &mut trace);
        assert_eq!(projected, Some((3, 0x90)));
        assert_eq!(trace, [0x20, 0x30, 0x40]);

        let mut untouched = [0xABCDu64; 1];
        assert_eq!(
            project_stack_back_trace(&frames[..1], 1, &mut untouched),
            None
        );
        assert_eq!(untouched, [0xABCD]);
    }

    #[test]
    fn callers_address_selection_matches_native_count_rules() {
        let frames = [1, 2, 3, 4];
        assert_eq!(callers_addresses(&frames, 2), (0, 0));
        assert_eq!(callers_addresses(&frames, 3), (3, 0));
        assert_eq!(callers_addresses(&frames, 4), (3, 4));
        assert_eq!(callers_addresses(&frames, 5), (3, 0));
    }

    #[test]
    fn virtual_unwind_executes_remaining_epilogue() {
        let mut image = MockImage::new(0x1_4000_0000);
        image.set_pdata(vec![RuntimeFunction {
            begin: 0x1000,
            end: 0x1100,
            unwind_info: 0x2000,
        }]);
        // One ALLOC_SMALL(0x20) unwind code makes this a non-leaf function. At 0x10f8 the compiled
        // epilogue is: add rsp,20h; pop rbx; pop rsi; pop rdi; ret.
        image.write(0x2000, &[0x01, 4, 1, 0, 4, 0x32]);
        image.write(0x10f8, &[0x48, 0x83, 0xc4, 0x20, 0x5b, 0x5e, 0x5f, 0xc3]);
        let mut stack = MockStack::new();
        stack.put(0x8020, 0xBBBB_BBBB);
        stack.put(0x8028, 0x6666_6666);
        stack.put(0x8030, 0x7777_7777);
        stack.put(0x8038, 0x1_4000_3000);
        let mut context = Context::default();
        context.rip = 0x1_4000_10f8;
        context.set_rsp(0x8000);

        let result = virtual_unwind(
            unw_flag::NHANDLER,
            image.base,
            context.rip,
            image.pdata.functions[0],
            &mut context,
            &image,
            &stack,
        )
        .unwrap();

        assert_eq!(result.handler_rva, 0);
        assert_eq!(context.gpr[REG_RBX], 0xBBBB_BBBB);
        assert_eq!(context.gpr[REG_RSI], 0x6666_6666);
        assert_eq!(context.gpr[REG_RDI], 0x7777_7777);
        assert_eq!(context.rip, 0x1_4000_3000);
        assert_eq!(context.rsp(), 0x8040);
    }

    // ------------------------------------------------------------------------------------------
    // UNWIND_INFO header parsing
    // ------------------------------------------------------------------------------------------

    #[test]
    fn unwind_header_parse() {
        // version=1, flags=EHANDLER(1) -> byte0 = 1 | (1<<3) = 0x09
        // size_of_prolog=0x0C, count=3, framereg=5(RBP), frameoffset=2 -> byte3 = 5 | (2<<4)=0x25
        let h = UnwindInfoHeader::parse(&[0x09, 0x0C, 0x03, 0x25]);
        assert_eq!(h.version, 1);
        assert_eq!(h.flags, unw_flag::EHANDLER);
        assert_eq!(h.size_of_prolog, 0x0C);
        assert_eq!(h.count_of_codes, 3);
        assert_eq!(h.frame_register, REG_RBP as u8);
        assert_eq!(h.frame_offset, 2);
        assert!(h.has_handler());
        // 3 codes -> padded to 4 -> tail at 4 + 4*2 = 12
        assert_eq!(h.tail_offset(), 12);
    }

    #[test]
    fn unwind_header_flags() {
        let h = UnwindInfoHeader::parse(&[(unw_flag::CHAININFO << 3) | 1, 0, 0, 0]);
        assert!(h.is_chained());
        assert!(!h.has_handler());
        let h2 = UnwindInfoHeader::parse(&[(unw_flag::UHANDLER << 3) | 1, 0, 2, 0]);
        assert!(h2.has_handler());
        assert_eq!(h2.tail_offset(), 4 + 2 * 2);
    }

    // ------------------------------------------------------------------------------------------
    // RtlLookupFunctionEntry
    // ------------------------------------------------------------------------------------------

    #[test]
    fn function_table_lookup() {
        let t = FunctionTable::add(
            0x1_0000,
            vec![
                RuntimeFunction {
                    begin: 0x100,
                    end: 0x200,
                    unwind_info: 0x900,
                },
                RuntimeFunction {
                    begin: 0x200,
                    end: 0x350,
                    unwind_info: 0x910,
                },
            ],
        );
        let f = t.lookup(0x1_0000 + 0x250).unwrap();
        assert_eq!(f.begin, 0x200);
        assert!(t.lookup(0x1_0000 + 0x050).is_none());
        assert!(t.lookup(0x1_0000 + 0x400).is_none());
        assert!(t.lookup(0x0FFF).is_none());
    }

    #[test]
    fn lookup_at_exact_begin_and_end_boundaries() {
        let t = FunctionTable::add(
            0x400000,
            vec![RuntimeFunction {
                begin: 0x1000,
                end: 0x1100,
                unwind_info: 0x5000,
            }],
        );
        assert!(t.lookup(0x400000 + 0x1000).is_some()); // first byte covered
        assert!(t.lookup(0x400000 + 0x10FF).is_some()); // last byte covered
        assert!(t.lookup(0x400000 + 0x1100).is_none()); // end is exclusive
    }

    // ------------------------------------------------------------------------------------------
    // virtual_unwind: individual unwind codes
    // ------------------------------------------------------------------------------------------

    // Build a function at base+0x1000..0x1100 with UNWIND_INFO at 0x2000; return the image + a
    // helper to run virtual_unwind at a given (already-past-prologue) PC.
    fn img_with_unwind(
        codes: &[u8],
        flags_byte: u8,
        size_of_prolog: u8,
        count: u8,
        framereg: u8,
    ) -> MockImage {
        let mut img = MockImage::new(0x14000000);
        img.set_pdata(vec![RuntimeFunction {
            begin: 0x1000,
            end: 0x1100,
            unwind_info: 0x2000,
        }]);
        let hdr = [flags_byte, size_of_prolog, count, framereg];
        img.write(0x2000, &hdr);
        img.write(0x2004, codes);
        img
    }

    #[test]
    fn unwind_push_nonvol_restores_reg_and_pops() {
        // A single `push rbx` (UWOP_PUSH_NONVOL, OpInfo=RBX=3) at prologue offset 1.
        // op byte = op(0) | (opinfo(3) << 4) = 0x30, code_off = 1.
        let img = img_with_unwind(&[0x01, 0x30], 0x01 /*ver1,nhandler*/, 0x08, 1, 0);
        let mut stack = MockStack::new();
        // RSP starts at 0x9000. The pushed RBX value sits at [RSP] = 0x9000.
        stack.put(0x9000, 0xDEAD_BEEF); // saved RBX
        stack.put(0x9008, 0x1400_2222); // return address (after popping RBX, RSP=0x9008)
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        let r = virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RBX], 0xDEAD_BEEF); // RBX restored
        assert_eq!(ctx.rip, 0x1400_2222); // return address popped into RIP
        assert_eq!(ctx.rsp(), 0x9010); // RSP: 0x9000 +8 (pop RBX) +8 (pop retaddr)
        assert_eq!(r.handler_rva, 0); // no handler requested / present
    }

    #[test]
    fn unwind_alloc_small() {
        // `sub rsp, 0x28` == UWOP_ALLOC_SMALL, size=(OpInfo*8)+8 => OpInfo=4 => 0x28.
        // op byte = 2 | (4<<4) = 0x42, code_off = 4.
        let img = img_with_unwind(&[0x04, 0x42], 0x01, 0x08, 1, 0);
        let mut stack = MockStack::new();
        // After undoing the 0x28 alloc, RSP = 0x8000 + 0x28 = 0x8028; return addr there.
        stack.put(0x8028, 0x1400_3333);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_3333);
        assert_eq!(ctx.rsp(), 0x8028 + 8);
    }

    #[test]
    fn unwind_alloc_large_op0() {
        // UWOP_ALLOC_LARGE OpInfo=0: next u16 * 8 bytes. size 0x200 => u16 = 0x40.
        // op byte = 1 | (0<<4) = 0x01, code_off = 8, then u16 operand 0x0040.
        let img = img_with_unwind(&[0x08, 0x01, 0x40, 0x00], 0x01, 0x10, 2, 0);
        let mut stack = MockStack::new();
        stack.put(0x8000 + 0x200, 0x1400_4444);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_4444);
        assert_eq!(ctx.rsp(), 0x8000 + 0x200 + 8);
    }

    #[test]
    fn unwind_alloc_large_op1() {
        // UWOP_ALLOC_LARGE OpInfo=1: next u32 bytes. size 0x1_2340.
        // op byte = 1 | (1<<4) = 0x11, code_off = 8, then u32 0x0001_2340.
        let img = img_with_unwind(&[0x08, 0x11, 0x40, 0x23, 0x01, 0x00], 0x01, 0x10, 3, 0);
        let mut stack = MockStack::new();
        stack.put(0x8000 + 0x1_2340, 0x1400_5555);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_5555);
        assert_eq!(ctx.rsp(), 0x8000 + 0x1_2340 + 8);
    }

    #[test]
    fn unwind_save_nonvol() {
        // UWOP_SAVE_NONVOL OpInfo=RSI(6): value at [RSP + u16*8]. offset units=3 => +0x18.
        // op byte = 4 | (6<<4) = 0x64, code_off = 0x0A, then u16 = 0x0003.
        let img = img_with_unwind(&[0x0A, 0x64, 0x03, 0x00], 0x01, 0x10, 2, 0);
        let mut stack = MockStack::new();
        stack.put(0x7000 + 0x18, 0xCAFE_F00D); // saved RSI
        stack.put(0x7000, 0x1400_6666); // return address (RSP unchanged; no alloc undone)
        let mut ctx = Context::default();
        ctx.set_rsp(0x7000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RSI], 0xCAFE_F00D);
        assert_eq!(ctx.rip, 0x1400_6666);
        assert_eq!(ctx.rsp(), 0x7008);
    }

    #[test]
    fn unwind_respects_prologue_offset() {
        // A `push rbx` at code_off=4: if the PC is at prologue offset 2 (before the push executed),
        // the code must NOT be applied (RBX not restored, RSP not popped for it).
        let img = img_with_unwind(&[0x04, 0x30], 0x01, 0x08, 1, 0);
        let mut stack = MockStack::new();
        // If the push were WRONGLY applied it'd pop [0x9000] first; instead RSP should stay and the
        // return address is directly at [0x9000].
        stack.put(0x9000, 0x1400_7777);
        let mut ctx = Context::default();
        ctx.set_rsp(0x9000);
        // PC at func begin + 2 (prologue offset 2 < code_off 4).
        let pc = 0x14000000 + 0x1002;
        let (base, f) = img.lookup_function(pc).unwrap();
        virtual_unwind(0, base, pc, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RBX], 0); // NOT restored — push hadn't executed
        assert_eq!(ctx.rip, 0x1400_7777);
        assert_eq!(ctx.rsp(), 0x9008); // only the return-address pop
    }

    #[test]
    fn unwind_returns_handler_when_requested() {
        // UWOP_ALLOC_SMALL 0x08 (OpInfo=0), flags=EHANDLER. Tail after 2 codes(1 slot padded to 2):
        // count=1 -> padded 2 -> tail at 4 + 2*2 = 8. handler RVA there = 0xABCD.
        let flags_byte = 0x01 | (unw_flag::EHANDLER << 3); // ver1, EHANDLER
        let mut img = img_with_unwind(&[0x02, 0x12], flags_byte, 0x08, 1, 0);
        img.write(0x2000 + 8, &0x0000_ABCDu32.to_le_bytes()); // handler RVA
        img.write(0x2000 + 12, &0x0000_1111u32.to_le_bytes()); // handler data (scope table RVA)
        let mut stack = MockStack::new();
        stack.put(0x8010, 0x1400_8888); // after undoing 0x10 alloc: 0x8000+0x10
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        // Request the EHANDLER (search pass).
        let r = virtual_unwind(
            unw_flag::EHANDLER,
            base,
            0x14000000 + 0x1050,
            f,
            &mut ctx,
            &img,
            &stack,
        )
        .unwrap();
        assert_eq!(r.handler_rva, 0xABCD);
        assert_eq!(r.handler_data_rva, 0x2000 + 12); // points at the handler-data (RVA in xdata)
        assert_eq!(ctx.rip, 0x1400_8888);
    }

    #[test]
    fn unwind_no_handler_when_type_zero() {
        let flags_byte = 0x01 | (unw_flag::EHANDLER << 3);
        let mut img = img_with_unwind(&[0x02, 0x12], flags_byte, 0x08, 1, 0);
        img.write(0x2000 + 8, &0x0000_ABCDu32.to_le_bytes());
        let mut stack = MockStack::new();
        stack.put(0x8010, 0x1400_8888);
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        // handler_type 0 => don't return a handler even though one exists.
        let r = virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(r.handler_rva, 0);
    }

    #[test]
    fn unwind_frame_pointer_function() {
        // Prologue: push rbp; mov rbp,rsp (via lea + SET_FPREG). Codes (reverse order, highest
        // code_off first as the linker emits):
        //   [code_off=5, SET_FPREG]   op=3|(0<<4)=0x03
        //   [code_off=1, PUSH_NONVOL RBP(5)] op=0|(5<<4)=0x50
        // framereg=RBP(5), frameoffset=0.
        let framereg_byte = REG_RBP as u8; // frameoffset 0
        let img = img_with_unwind(&[0x05, 0x03, 0x01, 0x50], 0x01, 0x08, 2, framereg_byte);
        let mut stack = MockStack::new();
        // At the fault PC (past prologue), RBP holds the frame base. We model: RBP = 0xA000.
        // push rbp saved the caller's RBP at [frame]. After SET_FPREG restore, RSP := frame base
        // (0xA000). Then PUSH_NONVOL RBP pops caller RBP from [0xA000], RSP -> 0xA008; return addr
        // at [0xA008].
        stack.put(0xA000, 0xBBBB_0000); // caller's saved RBP
        stack.put(0xA008, 0x1400_9999); // return address
        let mut ctx = Context::default();
        ctx.gpr[REG_RBP] = 0xA000; // current frame register value
        ctx.set_rsp(0x1000); // arbitrary current RSP (frame-pointer func → RSP restored from RBP)
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RBP], 0xBBBB_0000); // caller RBP restored
        assert_eq!(ctx.rip, 0x1400_9999);
        assert_eq!(ctx.rsp(), 0xA010);
    }

    // ------------------------------------------------------------------------------------------
    // __C_specific_handler scope-table walk
    // ------------------------------------------------------------------------------------------

    #[test]
    fn c_handler_executes_matching_except() {
        // One __try/__except covering [0x100,0x200); filter at 0x900 returns EXECUTE; body at 0x250.
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: 0x900,
            target: 0x250,
        }];
        let action = c_specific_handler_search(0x150, &scopes, |filt| {
            assert_eq!(filt, 0x900);
            EXCEPTION_EXECUTE_HANDLER
        });
        assert_eq!(
            action,
            CHandlerAction::ExecuteHandler {
                target_rva: 0x250,
                scope_index: 0
            }
        );
    }

    #[test]
    fn c_handler_continue_search_when_filter_declines() {
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: 0x900,
            target: 0x250,
        }];
        let action = c_specific_handler_search(0x150, &scopes, |_| EXCEPTION_CONTINUE_SEARCH);
        assert_eq!(action, CHandlerAction::ContinueSearch);
    }

    #[test]
    fn c_handler_pc_outside_all_scopes() {
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: 0x900,
            target: 0x250,
        }];
        let action = c_specific_handler_search(0x500, &scopes, |_| EXCEPTION_EXECUTE_HANDLER);
        assert_eq!(action, CHandlerAction::ContinueSearch);
    }

    #[test]
    fn c_handler_execute_sentinel_skips_filter() {
        // HandlerAddress == 1 (EXCEPTION_EXECUTE_HANDLER sentinel) → no filter call, always execute.
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: SCOPE_HANDLER_EXECUTE,
            target: 0x300,
        }];
        let mut called = false;
        let action = c_specific_handler_search(0x150, &scopes, |_| {
            called = true;
            EXCEPTION_CONTINUE_SEARCH
        });
        assert!(!called);
        assert_eq!(
            action,
            CHandlerAction::ExecuteHandler {
                target_rva: 0x300,
                scope_index: 0
            }
        );
    }

    #[test]
    fn c_handler_continue_execution() {
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: 0x900,
            target: 0x250,
        }];
        let action = c_specific_handler_search(0x150, &scopes, |_| EXCEPTION_CONTINUE_EXECUTION);
        assert_eq!(action, CHandlerAction::ContinueExecution);
    }

    #[test]
    fn c_handler_first_matching_except_wins() {
        // Two nested scopes both cover 0x150; the first (inner) declines, the second executes.
        let scopes = [
            ScopeRecord {
                begin: 0x140,
                end: 0x160,
                handler: 0x900,
                target: 0x250,
            },
            ScopeRecord {
                begin: 0x100,
                end: 0x200,
                handler: 0x910,
                target: 0x260,
            },
        ];
        let action = c_specific_handler_search(0x150, &scopes, |filt| {
            if filt == 0x900 {
                EXCEPTION_CONTINUE_SEARCH
            } else {
                EXCEPTION_EXECUTE_HANDLER
            }
        });
        assert_eq!(
            action,
            CHandlerAction::ExecuteHandler {
                target_rva: 0x260,
                scope_index: 1
            }
        );
    }

    #[test]
    fn c_handler_unwind_collects_finally() {
        // Two __finally scopes (target==0) covering the PC, plus a __except that should be ignored.
        let scopes = [
            ScopeRecord {
                begin: 0x100,
                end: 0x200,
                handler: 0xAAA,
                target: 0,
            }, // __finally
            ScopeRecord {
                begin: 0x140,
                end: 0x160,
                handler: 0xBBB,
                target: 0,
            }, // __finally
            ScopeRecord {
                begin: 0x100,
                end: 0x200,
                handler: 0x900,
                target: 0x250,
            }, // __except
        ];
        let f = c_specific_handler_unwind(0x150, &scopes);
        assert_eq!(f, vec![0xAAA, 0xBBB]);
    }

    #[test]
    fn c_handler_search_skips_finally() {
        // A __finally (target==0) covering the PC must be skipped in the SEARCH pass.
        let scopes = [ScopeRecord {
            begin: 0x100,
            end: 0x200,
            handler: 0xAAA,
            target: 0,
        }];
        let action = c_specific_handler_search(0x150, &scopes, |_| EXCEPTION_EXECUTE_HANDLER);
        assert_eq!(action, CHandlerAction::ContinueSearch);
    }

    // ------------------------------------------------------------------------------------------
    // dispatch + unwind frame-walk model
    // ------------------------------------------------------------------------------------------

    #[test]
    fn dispatch_finds_handler() {
        let frames = [
            FrameModel {
                control_pc: 0x100,
                handler: Some(Disposition::ContinueSearch),
            },
            FrameModel {
                control_pc: 0x200,
                handler: Some(Disposition::ContinueExecution),
            },
            FrameModel {
                control_pc: 0x300,
                handler: None,
            },
        ];
        assert_eq!(
            dispatch_exception(&rec(0xC000_0005, 0), &frames),
            DispatchResult::Handled { frame: 1 }
        );
    }

    #[test]
    fn dispatch_unhandled_when_all_search() {
        let frames = [
            FrameModel {
                control_pc: 0x100,
                handler: Some(Disposition::ContinueSearch),
            },
            FrameModel {
                control_pc: 0x200,
                handler: None,
            },
        ];
        assert_eq!(
            dispatch_exception(&rec(0xC000_0005, 0), &frames),
            DispatchResult::Unhandled
        );
    }

    #[test]
    fn noncontinuable_rejected() {
        let frames = [FrameModel {
            control_pc: 0x100,
            handler: Some(Disposition::ContinueExecution),
        }];
        assert_eq!(
            dispatch_exception(&rec(0xC000_0025, EXCEPTION_NONCONTINUABLE), &frames),
            DispatchResult::Noncontinuable
        );
    }

    #[test]
    fn unwind_runs_intervening_finally_blocks() {
        let frames = [
            FrameModel {
                control_pc: 0x100,
                handler: Some(Disposition::ContinueSearch),
            },
            FrameModel {
                control_pc: 0x200,
                handler: None,
            },
            FrameModel {
                control_pc: 0x300,
                handler: Some(Disposition::ContinueSearch),
            },
            FrameModel {
                control_pc: 0x400,
                handler: Some(Disposition::ContinueExecution),
            },
        ];
        assert_eq!(unwind(&frames, 3), vec![0, 2]);
    }

    #[test]
    fn disposition_from_raw() {
        assert_eq!(Disposition::from_raw(0), Disposition::ContinueExecution);
        assert_eq!(Disposition::from_raw(1), Disposition::ContinueSearch);
        assert_eq!(Disposition::from_raw(2), Disposition::NestedException);
        assert_eq!(Disposition::from_raw(3), Disposition::CollidedUnwind);
        assert_eq!(Disposition::from_raw(99), Disposition::ContinueSearch);
    }

    // ------------------------------------------------------------------------------------------
    // A multi-frame end-to-end unwind: two stacked frames, unwind through both.
    // ------------------------------------------------------------------------------------------

    #[test]
    fn unwind_two_stacked_frames() {
        // Frame A (inner): func at 0x1000, `push rbx; sub rsp,0x20`.
        //   codes: [code_off=5, ALLOC_SMALL(0x20 => OpInfo=3)] op=2|(3<<4)=0x32
        //          [code_off=1, PUSH_NONVOL RBX(3)]           op=0|(3<<4)=0x30
        // Frame B (outer): func at 0x1200, `push rbx`.
        let mut img = MockImage::new(0x14000000);
        img.set_pdata(vec![
            RuntimeFunction {
                begin: 0x1000,
                end: 0x1100,
                unwind_info: 0x2000,
            },
            RuntimeFunction {
                begin: 0x1200,
                end: 0x1300,
                unwind_info: 0x2100,
            },
        ]);
        img.write(0x2000, &[0x01, 0x08, 0x02, 0x00]); // ver1, size 8, 2 codes
        img.write(0x2004, &[0x05, 0x32, 0x01, 0x30]);
        img.write(0x2100, &[0x01, 0x04, 0x01, 0x00]); // ver1, size 4, 1 code
        img.write(0x2104, &[0x01, 0x30]);

        let mut stack = MockStack::new();
        // Frame A: RSP=0x8000. Undo sub 0x20 -> 0x8020. Pop RBX from 0x8020 -> RBX_A, RSP 0x8028.
        // Return address at 0x8028 points into frame B (0x14000000+0x1250).
        stack.put(0x8020, 0xAAAA_AAAA); // saved RBX in A
        stack.put(0x8028, 0x14000000 + 0x1250); // return into B
                                                // Frame B: RSP now 0x8030. Pop RBX from 0x8030 -> RBX_B, RSP 0x8038. Return addr = caller.
        stack.put(0x8030, 0xBBBB_BBBB); // saved RBX in B
        stack.put(0x8038, 0xDEAD_C0DE); // final caller return

        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);

        // Unwind frame A.
        let pc_a = 0x14000000 + 0x1050;
        let (base, fa) = img.lookup_function(pc_a).unwrap();
        virtual_unwind(0, base, pc_a, fa, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RBX], 0xAAAA_AAAA);
        assert_eq!(ctx.rip, 0x14000000 + 0x1250);
        assert_eq!(ctx.rsp(), 0x8030);

        // Unwind frame B (PC now = ctx.rip).
        let (base2, fb) = img.lookup_function(ctx.rip).unwrap();
        virtual_unwind(0, base2, ctx.rip, fb, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RBX], 0xBBBB_BBBB);
        assert_eq!(ctx.rip, 0xDEAD_C0DE);
        assert_eq!(ctx.rsp(), 0x8040);
    }

    #[test]
    fn lookup_returns_none_for_leaf_frame() {
        let img = MockImage::new(0x14000000);
        // No pdata rows.
        assert!(img.lookup_function(0x14000000 + 0x50).is_none());
    }

    #[test]
    fn corrupt_unwind_op_returns_none() {
        // An unknown unwind op (0x0F) should make virtual_unwind return None (corrupt xdata), not
        // panic or fabricate.
        let img = img_with_unwind(&[0x01, 0x0F], 0x01, 0x08, 1, 0);
        let stack = MockStack::new();
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        assert!(virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).is_none());
    }

    #[test]
    fn unwind_save_nonvol_far() {
        // UWOP_SAVE_NONVOL_FAR OpInfo=RDI(7): value at [RSP + u32] (raw byte offset, 3 slots).
        // op byte = 5 | (7<<4) = 0x75, code_off = 0x0C, then u32 = 0x0000_1000.
        let img = img_with_unwind(&[0x0C, 0x75, 0x00, 0x10, 0x00, 0x00], 0x01, 0x10, 3, 0);
        let mut stack = MockStack::new();
        stack.put(0x7000 + 0x1000, 0xFEED_FACE); // saved RDI at raw byte offset 0x1000
        stack.put(0x7000, 0x1400_ABAB); // return address (RSP unchanged; SAVE_* doesn't move RSP)
        let mut ctx = Context::default();
        ctx.set_rsp(0x7000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.gpr[REG_RDI], 0xFEED_FACE);
        assert_eq!(ctx.rip, 0x1400_ABAB);
        assert_eq!(ctx.rsp(), 0x7008);
    }

    #[test]
    fn unwind_save_xmm128() {
        // UWOP_SAVE_XMM128 OpInfo=XMM6(6): 128-bit value at [RSP + u16*16] (2 slots).
        // op byte = 8 | (6<<4) = 0x68, code_off = 0x0A, then u16 = 0x0002 => byte offset 0x20.
        let img = img_with_unwind(&[0x0A, 0x68, 0x02, 0x00], 0x01, 0x10, 2, 0);
        let mut stack = MockStack::new();
        stack.put(0x7000 + 0x20, 0x1111_2222_3333_4444); // XMM6 low
        stack.put(0x7000 + 0x28, 0x5555_6666_7777_8888); // XMM6 high
        stack.put(0x7000, 0x1400_CDCD); // return address
        let mut ctx = Context::default();
        ctx.set_rsp(0x7000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.xmm[6], [0x1111_2222_3333_4444, 0x5555_6666_7777_8888]);
        assert_eq!(ctx.rip, 0x1400_CDCD);
        assert_eq!(ctx.rsp(), 0x7008);
    }

    #[test]
    fn unwind_save_xmm128_far() {
        // UWOP_SAVE_XMM128_FAR OpInfo=XMM10(10): 128-bit value at [RSP + u32] raw offset (3 slots).
        // op byte = 9 | (10<<4) = 0xA9, code_off = 0x10, then u32 = 0x0000_0200.
        let img = img_with_unwind(&[0x10, 0xA9, 0x00, 0x02, 0x00, 0x00], 0x01, 0x18, 3, 0);
        let mut stack = MockStack::new();
        stack.put(0x7000 + 0x200, 0xAAAA_BBBB_CCCC_DDDD); // XMM10 low
        stack.put(0x7000 + 0x208, 0xEEEE_FFFF_0000_1111); // XMM10 high
        stack.put(0x7000, 0x1400_EFEF); // return address
        let mut ctx = Context::default();
        ctx.set_rsp(0x7000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.xmm[10], [0xAAAA_BBBB_CCCC_DDDD, 0xEEEE_FFFF_0000_1111]);
        assert_eq!(ctx.rip, 0x1400_EFEF);
        assert_eq!(ctx.rsp(), 0x7008);
    }

    #[test]
    fn unwind_push_machframe_terminates_without_retaddr_pop() {
        // UWOP_PUSH_MACHFRAME (op 10) OpInfo=0 (no error code): RSP += 0; RIP=[RSP]; RSP=[RSP+0x18].
        // This op TERMINATES the unwind — no return-address pop happens after it (it IS the trap
        // frame). op byte = 10 | (0<<4) = 0x0A, code_off = 1.
        let img = img_with_unwind(&[0x01, 0x0A], 0x01, 0x08, 1, 0);
        let mut stack = MockStack::new();
        stack.put(0x6000, 0x1400_1234); // trap-frame RIP at [RSP]
        stack.put(0x6000 + 0x18, 0x9999_0000); // trap-frame RSP at [RSP+0x18]
                                               // A poisoned cell where a spurious return-address pop WOULD read from (must NOT be used).
        stack.put(0x9999_0000, 0xDEAD_DEAD);
        let mut ctx = Context::default();
        ctx.set_rsp(0x6000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(
            ctx.rip, 0x1400_1234,
            "RIP comes straight from the trap frame, not a ret pop"
        );
        assert_eq!(
            ctx.rsp(),
            0x9999_0000,
            "RSP restored from [orig+0x18], not orig+8"
        );
    }

    #[test]
    fn unwind_push_machframe_with_error_code_adjusts_rsp() {
        // UWOP_PUSH_MACHFRAME OpInfo=1 (an error-code was pushed): RSP += 1*8 first, THEN the frame.
        // op byte = 10 | (1<<4) = 0x1A, code_off = 1.
        let img = img_with_unwind(&[0x01, 0x1A], 0x01, 0x08, 1, 0);
        let mut stack = MockStack::new();
        // RSP starts 0x6000; +8 for error code → machine frame based at 0x6008.
        stack.put(0x6008, 0x1400_5678); // RIP
        stack.put(0x6008 + 0x18, 0x8888_0000); // caller RSP
        let mut ctx = Context::default();
        ctx.set_rsp(0x6000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(ctx.rip, 0x1400_5678);
        assert_eq!(ctx.rsp(), 0x8888_0000);
    }

    #[test]
    fn unwind_epilog_and_spare_codes_are_noops() {
        // UWOP_EPILOG (op 6, 2 slots) and UWOP_SPARE_CODE (op 7, 3 slots) have NO register effect
        // during a virtual unwind, but their slots must be consumed so a following real code (a
        // PUSH_NONVOL RBX here) is decoded at the correct offset. Layout (all past prologue):
        //   [off=1, EPILOG]     op=6|(0<<4)=0x06  + 1 operand slot (u16)
        //   [off=1, SPARE]      op=7|(0<<4)=0x07  + 2 operand slots (u32)
        //   [off=1, PUSH RBX]   op=0|(3<<4)=0x30
        // count = 2(epilog) + 3(spare) + 1(push) = 6 codes worth of slots.
        let codes = [
            0x01, 0x06, 0x00, 0x00, // EPILOG + u16 operand
            0x01, 0x07, 0x00, 0x00, 0x00, 0x00, // SPARE + u32 operand
            0x01, 0x30, // PUSH_NONVOL RBX
        ];
        let img = img_with_unwind(&codes, 0x01, 0x08, 6, 0);
        let mut stack = MockStack::new();
        stack.put(0x8000, 0xC0DE_C0DE); // saved RBX popped by the PUSH_NONVOL
        stack.put(0x8008, 0x1400_7A7A); // return address after the pop
        let mut ctx = Context::default();
        ctx.set_rsp(0x8000);
        let (base, f) = img.lookup_function(0x14000000 + 0x1050).unwrap();
        virtual_unwind(0, base, 0x14000000 + 0x1050, f, &mut ctx, &img, &stack).unwrap();
        assert_eq!(
            ctx.gpr[REG_RBX], 0xC0DE_C0DE,
            "the PUSH after the no-op codes decoded correctly"
        );
        assert_eq!(ctx.rip, 0x1400_7A7A);
        assert_eq!(ctx.rsp(), 0x8010);
    }

    #[test]
    fn unhandled_filter_dismisses_possible_deadlock() {
        // The deadlock detector's exception is dismissed → resume execution.
        assert_eq!(
            unhandled_exception_filter(STATUS_POSSIBLE_DEADLOCK),
            EXCEPTION_CONTINUE_EXECUTION
        );
    }

    #[test]
    fn unhandled_filter_declines_ordinary_exceptions() {
        // STATUS_ACCESS_VIOLATION and friends keep propagating (continue search).
        assert_eq!(
            unhandled_exception_filter(0xC000_0005),
            EXCEPTION_CONTINUE_SEARCH
        );
        assert_eq!(
            unhandled_exception_filter(0x8000_0003),
            EXCEPTION_CONTINUE_SEARCH
        ); // breakpoint
        assert_eq!(unhandled_exception_filter(0), EXCEPTION_CONTINUE_SEARCH);
    }
}
