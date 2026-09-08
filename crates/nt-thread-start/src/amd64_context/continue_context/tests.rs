use super::*;
use crate::amd64_context::debug_context::DEBUG_REGISTERS;
use crate::amd64_context::{
    CONTEXT_FLOATING_POINT, CONTEXT_MXCSR_OFFSET, FLOAT_SAVE_OFFSET, FX_MXCSR_OFFSET, NT5_FCW_MASK,
    NT5_MXCSR_MASK,
};

const HIGHEST: u64 = 0x7fff_ffff_ffff;

fn context(flags: u32) -> CapturedAmd64Context {
    CapturedAmd64Context::capture(
        |_, bytes| {
            bytes.fill(0xa5);
            bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
            bytes[CS_OFFSET..CS_OFFSET + 2].copy_from_slice(&0x33u16.to_le_bytes());
            bytes[EFLAGS_OFFSET..EFLAGS_OFFSET + 4].copy_from_slice(&0x202u32.to_le_bytes());
            crate::put_u64(bytes, CONTEXT_RIP_OFFSET as usize, 0x1234);
            crate::put_u64(bytes, CONTEXT_RSP_OFFSET as usize, 0x5679);
            Ok(())
        },
        0x1000,
    )
    .unwrap()
}

fn prepare(context: &CapturedAmd64Context) -> Result<LegacyContextRestore, CodecError> {
    context.prepare_continue(0x4321, 0x9877, 0x202, HIGHEST, false)
}

#[test]
fn all_fifteen_integer_registers_have_exact_usercontext_slots() {
    fn assert_copy<T: Copy>() {}
    assert_copy::<LegacyContextRestore>();
    let mut context = context(CONTROL | INTEGER);
    let offsets = [
        0x78, 0x90, 0x80, 0x88, 0xa8, 0xb0, 0xa0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0,
    ];
    for (index, offset) in offsets.into_iter().enumerate() {
        crate::put_u64(
            &mut context.bytes,
            offset,
            0xfeed_0000_0000_0000 | index as u64,
        );
    }
    let original = context.bytes;
    let restore = prepare(&context).unwrap();
    assert_eq!(&restore.registers[..3], &[0x1234, 0x5679, 0x202]);
    for index in 0..15 {
        assert_eq!(
            restore.registers[index + 3],
            0xfeed_0000_0000_0000 | index as u64
        );
    }
    assert_eq!(restore.register_mask, (1 << 18) - 1);
    assert_eq!(&restore.registers[18..], &[0, 0]);
    assert_eq!(restore.register_mask & ((1 << 18) | (1 << 19)), 0);
    assert_eq!(restore.floating_point, None);
    assert_eq!(context.bytes, original);
}

#[test]
fn absent_control_uses_canonical_return_tuple_not_reported_syscall_pc() {
    let mut context = context(INTEGER);
    crate::put_u64(&mut context.bytes, CONTEXT_RIP_OFFSET as usize, 0);
    crate::put_u64(&mut context.bytes, CONTEXT_RSP_OFFSET as usize, u64::MAX);
    context.bytes[EFLAGS_OFFSET..EFLAGS_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let restore = prepare(&context).unwrap();
    assert_eq!(&restore.registers[..3], &[0x4321, 0x9877, 0x202]);
    assert_eq!(restore.register_mask, (1 << 18) - 1);
}

#[test]
fn requested_control_does_not_use_or_validate_unselected_resume_tuple() {
    let context = context(CONTROL);
    let restore = context
        .prepare_continue(0, u64::MAX, EFLAGS_AC, HIGHEST, false)
        .unwrap();
    assert_eq!(&restore.registers[..3], &[0x1234, 0x5679, 0x202]);
    assert_eq!(restore.register_mask, 7);
    assert_eq!(&restore.registers[3..], &[0; 17]);
}

#[test]
fn unrequested_integer_and_fp_groups_cannot_overwrite_live_registers_or_tls() {
    for flags in [CONTEXT_AMD64, CONTROL, CONTEXT_AMD64 | 4] {
        let context = context(flags);
        let original = context.bytes;
        let restore = prepare(&context).unwrap();
        assert_eq!(restore.register_mask, 7);
        assert_eq!(&restore.registers[3..], &[0; 17]);
        assert_eq!(restore.floating_point, None);
        assert_eq!(context.bytes, original);
    }
}

#[test]
fn fp_continue_uses_nt5_set_masks_and_authoritative_top_level_mxcsr() {
    let mut context = context(CONTEXT_FLOATING_POINT);
    context.bytes[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + 2]
        .copy_from_slice(&u16::MAX.to_le_bytes());
    context.bytes[CONTEXT_MXCSR_OFFSET..CONTEXT_MXCSR_OFFSET + 4]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    context.bytes[FLOAT_SAVE_OFFSET + FX_MXCSR_OFFSET..FLOAT_SAVE_OFFSET + FX_MXCSR_OFFSET + 4]
        .fill(0);
    let original = context.bytes;
    let restore = prepare(&context).unwrap();
    assert_eq!(restore.register_mask, 7);
    assert_eq!(&restore.registers[..3], &[0x4321, 0x9877, 0x202]);
    let fp = restore.floating_point.unwrap();
    assert_eq!(
        u16::from_le_bytes(fp[..2].try_into().unwrap()),
        NT5_FCW_MASK
    );
    assert_eq!(read_u32(&fp, FX_MXCSR_OFFSET), NT5_MXCSR_MASK);
    assert_eq!(
        &fp[32..416],
        &original[FLOAT_SAVE_OFFSET + 32..FLOAT_SAVE_OFFSET + 416]
    );
    assert_eq!(context.bytes, original);
}

#[test]
fn user_eflags_are_sanitized_without_rewriting_stack_pointer() {
    let mut context = context(CONTROL);
    context.bytes[EFLAGS_OFFSET..EFLAGS_OFFSET + 4]
        .copy_from_slice(&(u32::MAX & !(EFLAGS_AC as u32)).to_le_bytes());
    let restore = prepare(&context).unwrap();
    assert_eq!(restore.registers[2], (0x40dd5 & !EFLAGS_AC) | 0x202);
    assert_eq!(restore.registers[1], 0x5679);
    let context = context_without_control();
    let restore = context
        .prepare_continue(1, 3, u64::MAX & !EFLAGS_AC, HIGHEST, false)
        .unwrap();
    assert_eq!(restore.registers[2], (0x40dd5 & !EFLAGS_AC) | 0x202);
    assert_eq!(restore.registers[1], 3);
}

fn context_without_control() -> CapturedAmd64Context {
    context(CONTEXT_AMD64)
}

#[test]
fn zero_and_above_limit_selected_pointers_are_rejected() {
    for control in [false, true] {
        for (ip, sp, error) in [
            (0, 1, CodecError::InvalidInstructionPointer),
            (HIGHEST + 1, 1, CodecError::InvalidInstructionPointer),
            (1, 0, CodecError::InvalidStackPointer),
            (1, HIGHEST + 1, CodecError::InvalidStackPointer),
        ] {
            let mut context = context(if control { CONTROL } else { CONTEXT_AMD64 });
            crate::put_u64(&mut context.bytes, CONTEXT_RIP_OFFSET as usize, ip);
            crate::put_u64(&mut context.bytes, CONTEXT_RSP_OFFSET as usize, sp);
            assert_eq!(
                context.prepare_continue(ip, sp, 0x202, HIGHEST, false),
                Err(error)
            );
        }
    }
    let context = context_without_control();
    assert!(context
        .prepare_continue(HIGHEST, HIGHEST, 0x202, HIGHEST, false)
        .is_ok());
    assert_eq!(
        context.prepare_continue(1, 1, 0x202, 0, false),
        Err(CodecError::InvalidInstructionPointer)
    );
}

#[test]
fn architecture_and_extended_state_rejections_are_explicit() {
    for flags in [0, 0x8, 0x0001_000b] {
        assert_eq!(
            prepare(&context(flags)),
            Err(CodecError::InvalidArchitecture)
        );
    }
    for flags in [CONTEXT_AMD64 | 0x40, CONTEXT_FLOATING_POINT | 0x80] {
        assert_eq!(
            prepare(&context(flags)),
            Err(CodecError::UnsupportedExtendedState)
        );
    }
}

#[test]
fn nt_logical_and_platform_physical_native_selectors_are_both_explicitly_admitted() {
    assert_eq!(NT_NATIVE_CODE_SELECTOR, 0x33);
    assert_eq!(PLATFORM_NATIVE_CODE_SELECTOR, 0x2b);
    for cs in [NT_NATIVE_CODE_SELECTOR, PLATFORM_NATIVE_CODE_SELECTOR] {
        let mut context = context(CONTROL);
        context.bytes[CS_OFFSET..CS_OFFSET + 2].copy_from_slice(&cs.to_le_bytes());
        assert!(prepare(&context).is_ok());
    }
}

#[test]
fn compatibility_cs_is_rejected_even_when_control_is_not_requested() {
    for flags in [CONTEXT_AMD64, CONTROL] {
        for cs in [0u16, 0x23, 0x10, 0xffff] {
            let mut context = context(flags);
            context.bytes[CS_OFFSET..CS_OFFSET + 2].copy_from_slice(&cs.to_le_bytes());
            assert_eq!(
                prepare(&context),
                Err(CodecError::UnsupportedCompatibilityMode)
            );
        }
    }
}

#[test]
fn debug_test_alert_and_selected_ac_are_not_silently_dropped() {
    let mut unsupported = context(DEBUG_REGISTERS);
    crate::put_u64(&mut unsupported.bytes, 0x70, 2 << 16);
    assert_eq!(
        prepare(&unsupported),
        Err(CodecError::UnsupportedDebugRegisters)
    );
    let partial = context_without_control();
    assert_eq!(
        partial.prepare_continue(1, 2, 0x202, HIGHEST, true),
        Err(CodecError::UnsupportedTestAlert)
    );
    assert_eq!(
        partial.prepare_continue(1, 2, EFLAGS_AC, HIGHEST, false),
        Err(CodecError::UnsupportedAlignmentCheck)
    );
    let mut context = context(CONTROL);
    context.bytes[EFLAGS_OFFSET..EFLAGS_OFFSET + 4]
        .copy_from_slice(&(EFLAGS_AC as u32).to_le_bytes());
    assert_eq!(
        prepare(&context),
        Err(CodecError::UnsupportedAlignmentCheck)
    );
}

#[test]
fn rejection_statuses_and_input_bytes_are_preserved() {
    for error in [
        CodecError::InvalidArchitecture,
        CodecError::InvalidInstructionPointer,
        CodecError::InvalidStackPointer,
        CodecError::InvalidDebugRegisters,
    ] {
        assert_eq!(error.status(), 0xc000_000d);
    }
    for error in [
        CodecError::UnsupportedCompatibilityMode,
        CodecError::UnsupportedDebugRegisters,
        CodecError::UnsupportedTestAlert,
        CodecError::UnsupportedAlignmentCheck,
    ] {
        assert_eq!(error.status(), 0xc000_00bb);
    }
    let mut context = context(CONTROL | DEBUG_REGISTERS);
    crate::put_u64(&mut context.bytes, 0x70, 2 << 16);
    let original = context.bytes;
    assert_eq!(
        prepare(&context),
        Err(CodecError::UnsupportedDebugRegisters)
    );
    assert_eq!(context.bytes, original);
}

#[test]
fn self_set_preserves_requested_control_but_returns_success_in_rax() {
    let mut context = context(CONTROL | INTEGER);
    crate::put_u64(&mut context.bytes, CONTEXT_RAX_OFFSET as usize, 0xdead);
    crate::put_u64(&mut context.bytes, CONTEXT_RBX_OFFSET as usize, 0xbeef);
    let before = context.bytes;
    let plan = context
        .prepare_self_set(0, u64::MAX, EFLAGS_AC, HIGHEST)
        .unwrap();
    assert_eq!(&plan.registers[..5], &[0x1234, 0x5679, 0x202, 0, 0xbeef]);
    assert_eq!(plan.register_mask, (1 << 18) - 1);
    assert_eq!(plan.debug, None);
    assert_eq!(context.bytes, before);
}

#[test]
fn self_set_without_control_uses_canonical_service_return_not_fault_pc() {
    let mut context = context(INTEGER);
    crate::put_u64(&mut context.bytes, CONTEXT_RIP_OFFSET as usize, 0x1000);
    crate::put_u64(&mut context.bytes, CONTEXT_RSP_OFFSET as usize, 0);
    context.bytes[EFLAGS_OFFSET..EFLAGS_OFFSET + 4].fill(0xff);
    let plan = context
        .prepare_self_set(0x1002, 0x5678, 0x246, HIGHEST)
        .unwrap();
    assert_eq!(&plan.registers[..4], &[0x1002, 0x5678, 0x246, 0]);
    assert_eq!(plan.register_mask, (1 << 18) - 1);
}

#[test]
fn self_set_only_adds_status_and_continuation_to_unrequested_gpr_groups() {
    for flags in [
        CONTEXT_AMD64,
        CONTROL,
        CONTEXT_AMD64 | 4,
        CONTEXT_FLOATING_POINT,
    ] {
        let context = context(flags);
        let base = context.prepare_set(HIGHEST).unwrap();
        let plan = context
            .prepare_self_set(0x4321, 0x8765, 0x202, HIGHEST)
            .unwrap();
        assert_eq!(plan.register_mask, 0xf);
        assert_eq!(&plan.registers[3..], &[0; 17]);
        assert_eq!(plan.floating_point, base.floating_point);
        assert_eq!(plan.debug, base.debug);
    }
}

#[test]
fn self_set_rejects_invalid_fallback_without_mutating_capture() {
    let context = context(INTEGER);
    let before = context.bytes;
    for (ip, sp, flags, error) in [
        (0, 1, 0x202, CodecError::InvalidInstructionPointer),
        (HIGHEST + 1, 1, 0x202, CodecError::InvalidInstructionPointer),
        (1, 0, 0x202, CodecError::InvalidStackPointer),
        (1, HIGHEST + 1, 0x202, CodecError::InvalidStackPointer),
        (1, 1, EFLAGS_AC, CodecError::UnsupportedAlignmentCheck),
    ] {
        assert_eq!(context.prepare_self_set(ip, sp, flags, HIGHEST), Err(error));
        assert_eq!(context.bytes, before);
    }
}

#[test]
fn self_set_keeps_selected_debug_and_fp_in_the_same_restore() {
    let mut context = context(CONTEXT_FLOATING_POINT | DEBUG_REGISTERS);
    context.bytes[0x48..0x78].fill(0);
    crate::put_u64(&mut context.bytes, 0x48, 0x4000);
    crate::put_u64(&mut context.bytes, 0x70, 1);
    let plan = context.prepare_self_set(1, 2, 0x202, HIGHEST).unwrap();
    assert_eq!(plan.register_mask, 0xf);
    assert_eq!(plan.debug, Some([0x4000, 0, 0, 0, 0, 1]));
    assert!(plan.floating_point.is_some());
}
