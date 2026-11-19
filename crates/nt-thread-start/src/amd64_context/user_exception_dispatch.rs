//! Prepare `KiDispatchExceptionToUser`: the CONTEXT of the faulting thread, the
//! `KUSER_EXCEPTION_STACK` below its stack pointer and the register install that resumes it at
//! `ntdll!KiUserExceptionDispatcher`. Pure: nothing is written and no thread is changed.

use super::{CapturedAmd64Context, CodecError, LegacyContextRestore, CONTEXT_AMD64, LEGACY_FLOATING_POINT_BYTES};
use crate::user_exception::{
    plan_user_exception_stack, ExceptionRecord, FramePlanError, KUSER_EXCEPTION_STACK_SIZE,
};
use crate::AMD64_CONTEXT_SIZE;

/// `CONTEXT_ALL`: control, integer, segments, floating point and debug registers.
const CONTEXT_ALL: u32 = CONTEXT_AMD64 | 0x1f;

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedUserException {
    pub frame_va: u64,
    pub frame: [u8; KUSER_EXCEPTION_STACK_SIZE],
    pub install: LegacyContextRestore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserExceptionError {
    Codec(CodecError),
    Frame(FramePlanError),
    /// No dispatcher address in user space.
    InvalidDispatcher,
}

/// `live` is the faulting thread's registers in UserContext order, with RIP/RSP/RFLAGS as the
/// fault reported them and RIP already adjusted by the classification (breakpoint).
pub fn prepare_user_exception(
    live: &[u64; 20],
    floating_point: &[u8; LEGACY_FLOATING_POINT_BYTES],
    debug: &[u64; 6],
    record: &ExceptionRecord,
    dispatcher: u64,
    stack_limit: u64,
    highest_user_address: u64,
) -> Result<PreparedUserException, UserExceptionError> {
    if dispatcher == 0 || dispatcher > highest_user_address {
        return Err(UserExceptionError::InvalidDispatcher);
    }
    let mut context = CapturedAmd64Context { bytes: [0; AMD64_CONTEXT_SIZE] };
    context.bytes[0x30..0x34].copy_from_slice(&CONTEXT_ALL.to_le_bytes());
    context.publish_legacy_registers(live).map_err(UserExceptionError::Codec)?;
    context.publish_legacy_floating_point(floating_point).map_err(UserExceptionError::Codec)?;
    context.publish_legacy_debug_registers(debug).map_err(UserExceptionError::Codec)?;
    // The handler may NtContinue this CONTEXT; refuse one NtContinue would refuse.
    context
        .prepare_continue(live[0], live[1], live[2], highest_user_address, false)
        .map_err(UserExceptionError::Codec)?;
    let planned = plan_user_exception_stack(&context.bytes, record, stack_limit)
        .map_err(UserExceptionError::Frame)?;
    if planned.rsp > highest_user_address {
        return Err(UserExceptionError::Frame(FramePlanError::OutsideStack));
    }
    let mut registers = *live;
    registers[0] = dispatcher;
    registers[1] = planned.rsp;
    registers[5] = planned.rcx;
    registers[6] = planned.rdx;
    Ok(PreparedUserException {
        frame_va: planned.rsp,
        frame: planned.bytes,
        install: LegacyContextRestore {
            registers,
            register_mask: (1 << 0) | (1 << 1) | (1 << 5) | (1 << 6),
            floating_point: None,
            debug: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user_exception::{classify, HardwareFault, PageFaultOutcome, STATUS_ACCESS_VIOLATION};

    const HIGHEST_USER: u64 = 0x7fff_ffff_ffff;

    fn live() -> [u64; 20] {
        let mut registers = [0u64; 20];
        registers[0] = 0x1_4000_2000; // rip
        registers[1] = 0x100_1000_8f48; // rsp
        registers[2] = 0x246; // rflags
        registers[3] = 0xaaaa; // rax
        registers[5] = 0xcccc; // rcx
        registers[6] = 0xdddd; // rdx
        registers
    }

    fn fpu() -> [u8; LEGACY_FLOATING_POINT_BYTES] {
        let mut state = [0u8; LEGACY_FLOATING_POINT_BYTES];
        state[0..2].copy_from_slice(&0x027fu16.to_le_bytes()); // FCW
        state[24..28].copy_from_slice(&0x1f80u32.to_le_bytes()); // MXCSR
        state[28..32].copy_from_slice(&0xffffu32.to_le_bytes()); // MXCSR_MASK
        state
    }

    #[test]
    fn resumes_at_the_dispatcher_with_the_faulting_context_on_the_stack() {
        let registers = live();
        let (record, _) = classify(
            HardwareFault::PageFault { error_code: 0x4, address: 0, outcome: PageFaultOutcome::AccessViolation },
            registers[0],
        );
        let prepared = prepare_user_exception(
            &registers,
            &fpu(),
            &[0; 6],
            &record,
            0x7ffb_7000_4000,
            0x100_1000_0000,
            HIGHEST_USER,
        )
        .unwrap();
        assert_eq!(prepared.frame_va % 16, 0);
        assert_eq!(prepared.install.registers[0], 0x7ffb_7000_4000);
        assert_eq!(prepared.install.registers[1], prepared.frame_va);
        assert_eq!(prepared.install.registers[5], prepared.frame_va + 0x4d0);
        assert_eq!(prepared.install.registers[6], prepared.frame_va);
        // Other registers keep their fault-time values (they are not selected).
        assert_eq!(prepared.install.registers[3], 0xaaaa);
        // The stacked CONTEXT carries the faulting RIP, RSP and RAX and is CONTEXT_ALL.
        let context = &prepared.frame[..0x4d0];
        let u64_at = |offset: usize| u64::from_le_bytes(context[offset..offset + 8].try_into().unwrap());
        assert_eq!(u32::from_le_bytes(context[0x30..0x34].try_into().unwrap()), CONTEXT_ALL);
        assert_eq!((u64_at(0xf8), u64_at(0x98), u64_at(0x78)), (0x1_4000_2000, 0x100_1000_8f48, 0xaaaa));
        assert_eq!(u32::from_le_bytes(prepared.frame[0x4d0..0x4d4].try_into().unwrap()), STATUS_ACCESS_VIOLATION);
    }

    #[test]
    fn refuses_a_kernel_dispatcher_or_a_stack_without_room() {
        let registers = live();
        let (record, _) = classify(HardwareFault::DivideError, registers[0]);
        assert_eq!(
            prepare_user_exception(&registers, &fpu(), &[0; 6], &record, 0, 0, HIGHEST_USER),
            Err(UserExceptionError::InvalidDispatcher)
        );
        assert_eq!(
            prepare_user_exception(
                &registers,
                &fpu(),
                &[0; 6],
                &record,
                0x7ffb_7000_4000,
                registers[1] - 0x100,
                HIGHEST_USER
            ),
            Err(UserExceptionError::Frame(FramePlanError::OutsideStack))
        );
    }
}
