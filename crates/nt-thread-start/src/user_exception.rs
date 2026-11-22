//! Hardware exceptions delivered to a user thread, as x64 NT delivers them.
//!
//! [`classify`] turns a processor fault into the `EXCEPTION_RECORD` the dispatcher sees
//! (ReactOS `ntoskrnl/ke/amd64/trap.S` and `except.c`). [`plan_user_exception_stack`] lays out
//! the `KUSER_EXCEPTION_STACK` that `KiDispatchExceptionToUser` writes below the faulting
//! thread's stack pointer, and the register state that resumes the thread at
//! `ntdll!KiUserExceptionDispatcher`:
//!
//! ```text
//!   new RSP -> CONTEXT          (0x4d0, 16-byte aligned)
//!              EXCEPTION_RECORD (0x98)
//!              ULONG64 Alignment
//!              MACHINE_FRAME    (Rip, SegCs, EFlags, Rsp, SegSs: 5 qwords)
//! ```

use crate::{AMD64_CONTEXT_SIZE, CONTEXT_RIP_OFFSET, CONTEXT_RSP_OFFSET};

mod floating_point;
mod privileged_instruction;
pub use floating_point::{
    FloatingPointState, STATUS_FLOAT_DIVIDE_BY_ZERO, STATUS_FLOAT_INEXACT_RESULT,
    STATUS_FLOAT_INVALID_OPERATION, STATUS_FLOAT_OVERFLOW, STATUS_FLOAT_STACK_CHECK,
    STATUS_FLOAT_UNDERFLOW,
};
pub use privileged_instruction::{is_privileged_instruction, PRIVILEGED_INSTRUCTION_WINDOW};

pub const EXCEPTION_RECORD_SIZE: usize = 0x98;
pub const MACHINE_FRAME_SIZE: usize = 0x28;
/// `sizeof(KUSER_EXCEPTION_STACK)`: its members, padded to the CONTEXT's 16-byte alignment.
pub const KUSER_EXCEPTION_STACK_SIZE: usize =
    (AMD64_CONTEXT_SIZE + EXCEPTION_RECORD_SIZE + 8 + MACHINE_FRAME_SIZE + 15) & !15;
const _: () = assert!(KUSER_EXCEPTION_STACK_SIZE == 0x5a0);
const RECORD_OFFSET: usize = AMD64_CONTEXT_SIZE;
const MACHINE_FRAME_OFFSET: usize = RECORD_OFFSET + EXCEPTION_RECORD_SIZE + 8;
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;
pub const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
pub const STATUS_IN_PAGE_ERROR: u32 = 0xc000_0006;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;
pub const STATUS_ARRAY_BOUNDS_EXCEEDED: u32 = 0xc000_008c;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xc000_0094;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xc000_0095;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xc000_0096;
pub const STATUS_STACK_OVERFLOW: u32 = 0xc000_00fd;
/// `BREAKPOINT_BREAK`, the first parameter of an `int 3` breakpoint.
const BREAKPOINT_BREAK: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub parameter_count: u32,
    pub parameters: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

impl ExceptionRecord {
    fn new(code: u32, address: u64, parameters: &[u64]) -> Self {
        let mut record = Self {
            code,
            flags: 0,
            address,
            parameter_count: parameters.len() as u32,
            parameters: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        };
        record.parameters[..parameters.len()].copy_from_slice(parameters);
        record
    }

    pub fn encode(&self) -> [u8; EXCEPTION_RECORD_SIZE] {
        let mut out = [0u8; EXCEPTION_RECORD_SIZE];
        out[0..4].copy_from_slice(&self.code.to_le_bytes());
        out[4..8].copy_from_slice(&self.flags.to_le_bytes());
        // ExceptionRecord (chained) @8 stays NULL.
        out[0x10..0x18].copy_from_slice(&self.address.to_le_bytes());
        out[0x18..0x1c].copy_from_slice(&self.parameter_count.to_le_bytes());
        for (index, parameter) in self.parameters.iter().enumerate() {
            let offset = 0x20 + index * 8;
            out[offset..offset + 8].copy_from_slice(&parameter.to_le_bytes());
        }
        out
    }
}

/// What the memory manager decided about a user page fault it could not satisfy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageFaultOutcome {
    AccessViolation,
    /// A guard page was touched; the guard was removed (stack growth or a program's guard).
    GuardPage,
    /// The stack's last guard page was touched and no further page can be committed.
    StackOverflow,
    /// The backing data could not be read; `status` is the I/O failure.
    InPageError(u32),
}

impl PageFaultOutcome {
    /// trap.S PageFaultError: the exception a failed MmAccessFault `status` raises. Anything
    /// other than an access, guard page or stack overflow failure is an in-page error.
    pub fn from_access_fault_status(status: u32) -> Self {
        match status {
            STATUS_ACCESS_VIOLATION => Self::AccessViolation,
            STATUS_GUARD_PAGE_VIOLATION => Self::GuardPage,
            STATUS_STACK_OVERFLOW => Self::StackOverflow,
            status => Self::InPageError(status),
        }
    }
}

/// A processor exception raised in user mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareFault {
    /// #DE.
    DivideError,
    /// #DB.
    Debug,
    /// #BP (`int 3`); the reported RIP is after the instruction.
    Breakpoint,
    /// #OF (`into`).
    Overflow,
    /// #BR.
    BoundRange,
    /// #UD.
    InvalidOpcode,
    /// #GP raised by a privileged instruction.
    PrivilegedInstruction,
    /// Any other #GP from user mode (for example a non-canonical address).
    GeneralProtection,
    /// #PF the memory manager refused: `error_code` is the processor's, `address` CR2.
    PageFault { error_code: u32, address: u64, outcome: PageFaultOutcome },
    /// #AC.
    AlignmentCheck,
    /// #MF: `status` is the pending, unmasked x87 exception; `instruction` and `data` are the
    /// x87 instruction and operand pointers (FIP/FDP).
    X87FloatingPoint { status: u32, stack_fault: bool, instruction: u64, data: u64 },
    /// #XM: `status` is the pending, unmasked SIMD exception of `mxcsr`.
    SimdFloatingPoint { status: u32, mxcsr: u32 },
}

impl HardwareFault {
    /// The fault an AMD64 processor vector raised in user mode reports, for the vectors that
    /// carry no further state. #PF (14) needs the memory manager's outcome, and a #GP that
    /// is a privileged instruction needs the instruction bytes, so neither is produced here.
    pub fn from_vector(vector: u64) -> Option<Self> {
        Some(match vector {
            0 => Self::DivideError,
            1 => Self::Debug,
            3 => Self::Breakpoint,
            4 => Self::Overflow,
            5 => Self::BoundRange,
            6 => Self::InvalidOpcode,
            13 => Self::GeneralProtection,
            17 => Self::AlignmentCheck,
            _ => return None,
        })
    }

    /// A user #MF (16) or #XM (19), given the faulting thread's floating-point state. `None`
    /// for other vectors, and when no unmasked exception is pending (ReactOS bugchecks then).
    pub fn floating_point(vector: u64, state: &FloatingPointState) -> Option<Self> {
        match vector {
            16 => state.x87_status().map(|(status, stack_fault)| Self::X87FloatingPoint {
                status,
                stack_fault,
                instruction: state.instruction_pointer,
                data: state.data_pointer,
            }),
            19 => state.simd_status().map(|status| Self::SimdFloatingPoint { status, mxcsr: state.mxcsr }),
            _ => None,
        }
    }

    /// A user #GP, given the instruction bytes readable at the faulting RIP
    /// (KiGeneralProtectionFaultUserMode).
    pub fn general_protection(instruction: &[u8]) -> Self {
        if is_privileged_instruction(instruction) {
            Self::PrivilegedInstruction
        } else {
            Self::GeneralProtection
        }
    }
}

/// The exception record for `fault` at `rip`, and the RIP the delivered CONTEXT must carry.
pub fn classify(fault: HardwareFault, rip: u64) -> (ExceptionRecord, u64) {
    use HardwareFault::*;
    match fault {
        DivideError => (ExceptionRecord::new(STATUS_INTEGER_DIVIDE_BY_ZERO, rip, &[]), rip),
        Debug => (ExceptionRecord::new(STATUS_SINGLE_STEP, rip, &[]), rip),
        Breakpoint => {
            // except.c: a breakpoint is reported at the int 3 itself (Rip - 1).
            let at = rip.wrapping_sub(1);
            (ExceptionRecord::new(STATUS_BREAKPOINT, at, &[BREAKPOINT_BREAK, 0, 0]), at)
        }
        Overflow => (ExceptionRecord::new(STATUS_INTEGER_OVERFLOW, rip, &[0, 0, 0]), rip),
        BoundRange => (ExceptionRecord::new(STATUS_ARRAY_BOUNDS_EXCEEDED, rip, &[]), rip),
        InvalidOpcode => (ExceptionRecord::new(STATUS_ILLEGAL_INSTRUCTION, rip, &[]), rip),
        PrivilegedInstruction => (ExceptionRecord::new(STATUS_PRIVILEGED_INSTRUCTION, rip, &[]), rip),
        // trap.S: a user #GP that is not a privileged instruction is an access violation at an
        // unknown address (-1).
        GeneralProtection => (ExceptionRecord::new(STATUS_ACCESS_VIOLATION, rip, &[0, u64::MAX]), rip),
        PageFault { error_code, address, outcome } => {
            // trap.S PageFaultError: Param1 = (ErrorCode >> 1) & 9 (write = 1, execute = 8).
            let access = u64::from((error_code >> 1) & 9);
            let record = match outcome {
                PageFaultOutcome::AccessViolation => {
                    ExceptionRecord::new(STATUS_ACCESS_VIOLATION, rip, &[access, address])
                }
                PageFaultOutcome::GuardPage => {
                    ExceptionRecord::new(STATUS_GUARD_PAGE_VIOLATION, rip, &[access, address])
                }
                PageFaultOutcome::StackOverflow => {
                    ExceptionRecord::new(STATUS_STACK_OVERFLOW, rip, &[access, address])
                }
                PageFaultOutcome::InPageError(status) => ExceptionRecord::new(
                    STATUS_IN_PAGE_ERROR,
                    rip,
                    &[access, address, u64::from(status)],
                ),
            };
            (record, rip)
        }
        AlignmentCheck => (ExceptionRecord::new(STATUS_DATATYPE_MISALIGNMENT, rip, &[]), rip),
        // KiNpxHandler: reported at the x87 instruction; a stack fault adds its operand.
        X87FloatingPoint { status, stack_fault: true, instruction, data } => {
            (ExceptionRecord::new(status, instruction, &[0, data]), rip)
        }
        X87FloatingPoint { status, stack_fault: false, instruction, .. } => {
            (ExceptionRecord::new(status, instruction, &[0]), rip)
        }
        // trap.S KiXmmException: two parameters, 0 and MXCSR.
        SimdFloatingPoint { status, mxcsr } => {
            (ExceptionRecord::new(status, rip, &[0, u64::from(mxcsr)]), rip)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePlanError {
    /// The frame would wrap below address 0 or leave the thread's stack reservation.
    OutsideStack,
    /// The delivered CONTEXT has no user RSP.
    MissingStackPointer,
}

/// The `KUSER_EXCEPTION_STACK` and the state that resumes at `KiUserExceptionDispatcher`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserExceptionFrame {
    /// Address of the frame: the new RSP, which is also the CONTEXT.
    pub rsp: u64,
    pub bytes: [u8; KUSER_EXCEPTION_STACK_SIZE],
    /// `RCX` = the EXCEPTION_RECORD, `RDX` = the CONTEXT (ReactOS `KiDispatchExceptionToUser`).
    pub rcx: u64,
    pub rdx: u64,
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

/// Lay out the frame below the faulting `context`'s RSP. `stack_limit` is the lowest address of
/// the thread's stack reservation.
pub fn plan_user_exception_stack(
    context: &[u8; AMD64_CONTEXT_SIZE],
    record: &ExceptionRecord,
    stack_limit: u64,
) -> Result<UserExceptionFrame, FramePlanError> {
    let rsp = read_u64(context, CONTEXT_RSP_OFFSET as usize);
    if rsp == 0 {
        return Err(FramePlanError::MissingStackPointer);
    }
    let frame = rsp
        .checked_sub(KUSER_EXCEPTION_STACK_SIZE as u64)
        .map(|frame| frame & !15)
        .filter(|&frame| frame >= stack_limit)
        .ok_or(FramePlanError::OutsideStack)?;
    let mut bytes = [0u8; KUSER_EXCEPTION_STACK_SIZE];
    bytes[..AMD64_CONTEXT_SIZE].copy_from_slice(context);
    bytes[RECORD_OFFSET..RECORD_OFFSET + EXCEPTION_RECORD_SIZE].copy_from_slice(&record.encode());
    // MACHINE_FRAME { Rip, SegCs, EFlags, Rsp, SegSs } from the delivered CONTEXT.
    let rip = read_u64(context, CONTEXT_RIP_OFFSET as usize);
    let seg_cs = u64::from(u16::from_le_bytes([context[0x38], context[0x39]]));
    let eflags = u64::from(u32::from_le_bytes(context[0x44..0x48].try_into().unwrap()));
    let seg_ss = u64::from(u16::from_le_bytes([context[0x42], context[0x43]]));
    for (index, value) in [rip, seg_cs, eflags, rsp, seg_ss].into_iter().enumerate() {
        let offset = MACHINE_FRAME_OFFSET + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    Ok(UserExceptionFrame {
        rsp: frame,
        bytes,
        rcx: frame + RECORD_OFFSET as u64,
        rdx: frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_access_faults_raise_what_trap_s_raises() {
        let record = |status| {
            classify(
                HardwareFault::PageFault {
                    error_code: 0x4, // user read, not present
                    address: 0x5000,
                    outcome: PageFaultOutcome::from_access_fault_status(status),
                },
                0x1000,
            )
            .0
        };
        assert_eq!(record(STATUS_ACCESS_VIOLATION).code, STATUS_ACCESS_VIOLATION);
        assert_eq!(record(STATUS_GUARD_PAGE_VIOLATION).code, STATUS_GUARD_PAGE_VIOLATION);
        assert_eq!(record(STATUS_STACK_OVERFLOW).code, STATUS_STACK_OVERFLOW);
        // Any other status is STATUS_IN_PAGE_ERROR with the status as ExceptionInformation[2].
        let device_error = record(0xc000_0185);
        assert_eq!(device_error.code, STATUS_IN_PAGE_ERROR);
        assert_eq!(device_error.parameter_count, 3);
        assert_eq!(device_error.parameters[..3], [0, 0x5000, 0xc000_0185]);
    }

    #[test]
    fn a_general_protection_fault_decodes_its_instruction() {
        let code = |bytes: &[u8]| classify(HardwareFault::general_protection(bytes), 0x1000).0.code;
        assert_eq!(code(&[0xfa]), STATUS_PRIVILEGED_INSTRUCTION); // cli
        assert_eq!(code(&[0x0f, 0x30]), STATUS_PRIVILEGED_INSTRUCTION); // wrmsr
        assert_eq!(code(&[0x48, 0x8b, 0x04, 0x25]), STATUS_ACCESS_VIOLATION); // mov rax, [abs]
        assert_eq!(code(&[]), STATUS_ACCESS_VIOLATION); // unreadable RIP
    }

    #[test]
    fn vectors_map_to_the_exceptions_ki_trap_handlers_raise() {
        let code = |vector| HardwareFault::from_vector(vector).map(|fault| classify(fault, 0x1000).0.code);
        assert_eq!(code(0), Some(STATUS_INTEGER_DIVIDE_BY_ZERO));
        assert_eq!(code(1), Some(STATUS_SINGLE_STEP));
        assert_eq!(code(3), Some(STATUS_BREAKPOINT));
        assert_eq!(code(4), Some(STATUS_INTEGER_OVERFLOW));
        assert_eq!(code(5), Some(STATUS_ARRAY_BOUNDS_EXCEEDED));
        assert_eq!(code(6), Some(STATUS_ILLEGAL_INSTRUCTION));
        assert_eq!(code(13), Some(STATUS_ACCESS_VIOLATION));
        assert_eq!(code(17), Some(STATUS_DATATYPE_MISALIGNMENT));
        for vector in [2, 7, 8, 14, 16, 18, 19, 255] {
            assert_eq!(HardwareFault::from_vector(vector), None, "vector {vector}");
        }
    }

    #[test]
    fn floating_point_faults_report_the_pending_unmasked_exception() {
        let state = |control_word, status_word, mxcsr| FloatingPointState {
            control_word,
            status_word,
            instruction_pointer: 0x1_4000_2000,
            data_pointer: 0x3000,
            mxcsr,
        };
        // #XM: divide-by-zero unmasked (MXCSR.ZM clear) and flagged.
        let mxcsr = (0x1f80 & !(1 << 9)) | (1 << 2);
        let simd = HardwareFault::floating_point(19, &state(0x037f, 0, mxcsr)).unwrap();
        let (record, delivered_rip) = classify(simd, 0x1000);
        assert_eq!((record.code, record.address, delivered_rip), (STATUS_FLOAT_DIVIDE_BY_ZERO, 0x1000, 0x1000));
        assert_eq!(record.parameters[..record.parameter_count as usize], [0, u64::from(mxcsr)]);
        // #MF: an unmasked x87 overflow, reported at the x87 instruction.
        let x87 = HardwareFault::floating_point(16, &state(0x0377, 1 << 3, 0x1f80)).unwrap();
        let (record, delivered_rip) = classify(x87, 0x1000);
        assert_eq!((record.code, record.address, delivered_rip), (STATUS_FLOAT_OVERFLOW, 0x1_4000_2000, 0x1000));
        assert_eq!(record.parameters[..record.parameter_count as usize], [0]);
        // An x87 stack fault also reports its operand.
        let stack = HardwareFault::floating_point(16, &state(0x037e, (1 << 6) | 1, 0x1f80)).unwrap();
        let record = classify(stack, 0x1000).0;
        assert_eq!((record.code, record.parameter_count, record.parameters[1]), (STATUS_FLOAT_STACK_CHECK, 2, 0x3000));
        // Nothing pending and unmasked, or another vector: not a floating-point exception.
        assert_eq!(HardwareFault::floating_point(19, &state(0x037f, 0, 0x1f80 | 0x3f)), None);
        assert_eq!(HardwareFault::floating_point(16, &state(0x037f, 0x3f, 0x1f80)), None);
        assert_eq!(HardwareFault::floating_point(0, &state(0, 0x3f, 0x3f)), None);
    }

    fn context(rsp: u64, rip: u64) -> [u8; AMD64_CONTEXT_SIZE] {
        let mut context = [0u8; AMD64_CONTEXT_SIZE];
        context[CONTEXT_RSP_OFFSET as usize..][..8].copy_from_slice(&rsp.to_le_bytes());
        context[CONTEXT_RIP_OFFSET as usize..][..8].copy_from_slice(&rip.to_le_bytes());
        context[0x38..0x3a].copy_from_slice(&0x33u16.to_le_bytes());
        context[0x42..0x44].copy_from_slice(&0x2bu16.to_le_bytes());
        context[0x44..0x48].copy_from_slice(&0x246u32.to_le_bytes());
        context
    }

    #[test]
    fn the_frame_matches_kuser_exception_stack() {
        let rsp = 0x7_0000_8f38;
        let (record, rip) = classify(
            HardwareFault::PageFault {
                error_code: 0x6, // user write, not present
                address: 0x10,
                outcome: PageFaultOutcome::AccessViolation,
            },
            0x1_4000_1234,
        );
        let mut delivered = context(rsp, rip);
        delivered[0x78..0x80].copy_from_slice(&0x1111u64.to_le_bytes()); // Rax
        let frame = plan_user_exception_stack(&delivered, &record, 0x7_0000_0000).unwrap();
        assert_eq!(frame.rsp, (rsp - 0x5a0) & !15);
        assert_eq!(frame.rsp % 16, 0);
        assert_eq!(frame.rdx, frame.rsp);
        assert_eq!(frame.rcx, frame.rsp + 0x4d0);
        // The CONTEXT is the first 0x4d0 bytes, unchanged.
        assert_eq!(&frame.bytes[..AMD64_CONTEXT_SIZE], &delivered[..]);
        // The EXCEPTION_RECORD follows it.
        let record_bytes = &frame.bytes[0x4d0..0x4d0 + 0x98];
        assert_eq!(u32::from_le_bytes(record_bytes[0..4].try_into().unwrap()), STATUS_ACCESS_VIOLATION);
        assert_eq!(read_u64(record_bytes, 0x10), 0x1_4000_1234);
        assert_eq!(u32::from_le_bytes(record_bytes[0x18..0x1c].try_into().unwrap()), 2);
        assert_eq!((read_u64(record_bytes, 0x20), read_u64(record_bytes, 0x28)), (1, 0x10));
        // Then 8 bytes of alignment and the MACHINE_FRAME.
        let machine = &frame.bytes[0x570..0x598];
        assert_eq!(
            [0, 8, 16, 24, 32].map(|offset| read_u64(machine, offset)),
            [0x1_4000_1234, 0x33, 0x246, rsp, 0x2b]
        );
    }

    #[test]
    fn classification_follows_the_amd64_trap_handlers() {
        let rip = 0x1000;
        assert_eq!(classify(HardwareFault::DivideError, rip).0.code, STATUS_INTEGER_DIVIDE_BY_ZERO);
        assert_eq!(classify(HardwareFault::Debug, rip).0.code, STATUS_SINGLE_STEP);
        assert_eq!(classify(HardwareFault::InvalidOpcode, rip).0.code, STATUS_ILLEGAL_INSTRUCTION);
        assert_eq!(classify(HardwareFault::AlignmentCheck, rip).0.code, STATUS_DATATYPE_MISALIGNMENT);
        let (breakpoint, delivered_rip) = classify(HardwareFault::Breakpoint, rip);
        assert_eq!((breakpoint.code, breakpoint.address, delivered_rip), (STATUS_BREAKPOINT, 0xfff, 0xfff));
        assert_eq!(breakpoint.parameter_count, 3);
        let gp = classify(HardwareFault::GeneralProtection, rip).0;
        assert_eq!((gp.code, gp.parameters[0], gp.parameters[1]), (STATUS_ACCESS_VIOLATION, 0, u64::MAX));
        for (error_code, access) in [(0x4, 0), (0x6, 1), (0x14, 8)] {
            let record = classify(
                HardwareFault::PageFault { error_code, address: 0x20, outcome: PageFaultOutcome::AccessViolation },
                rip,
            )
            .0;
            assert_eq!(record.parameters[0], access, "error code {error_code:#x}");
        }
        let guard = classify(
            HardwareFault::PageFault { error_code: 0x6, address: 0x5000, outcome: PageFaultOutcome::GuardPage },
            rip,
        )
        .0;
        assert_eq!((guard.code, guard.parameters[1]), (STATUS_GUARD_PAGE_VIOLATION, 0x5000));
        let overflow = classify(
            HardwareFault::PageFault { error_code: 0x6, address: 0x5000, outcome: PageFaultOutcome::StackOverflow },
            rip,
        )
        .0;
        assert_eq!(overflow.code, STATUS_STACK_OVERFLOW);
        let in_page = classify(
            HardwareFault::PageFault {
                error_code: 0x4,
                address: 0x5000,
                outcome: PageFaultOutcome::InPageError(0xc000_000e),
            },
            rip,
        )
        .0;
        assert_eq!((in_page.code, in_page.parameter_count, in_page.parameters[2]), (STATUS_IN_PAGE_ERROR, 3, 0xc000_000e));
    }

    #[test]
    fn a_frame_that_leaves_the_stack_is_refused() {
        let record = classify(HardwareFault::DivideError, 0x1000).0;
        assert_eq!(
            plan_user_exception_stack(&context(0x7_0000_0400, 0x1000), &record, 0x7_0000_0000),
            Err(FramePlanError::OutsideStack)
        );
        assert_eq!(
            plan_user_exception_stack(&context(0x100, 0x1000), &record, 0),
            Err(FramePlanError::OutsideStack)
        );
        assert_eq!(
            plan_user_exception_stack(&context(0, 0x1000), &record, 0),
            Err(FramePlanError::MissingStackPointer)
        );
    }
}
