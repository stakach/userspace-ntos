use super::*;
use crate::amd64_context::{CONTEXT_AMD64, CONTEXT_FLOATING_POINT};
use crate::{AMD64_CONTEXT_SIZE, CONTEXT_RIP_OFFSET, CONTEXT_RSP_OFFSET};

const HIGHEST: u64 = 0x0000_7fff_ffff_ffff;

fn capture(flags: u32) -> CapturedAmd64Context {
    let mut bytes = [0x5a; AMD64_CONTEXT_SIZE];
    bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&0x33u16.to_le_bytes());
    bytes[0x44..0x48].copy_from_slice(&0x246u32.to_le_bytes());
    let ip = CONTEXT_RIP_OFFSET as usize;
    let sp = CONTEXT_RSP_OFFSET as usize;
    bytes[ip..ip + 8].copy_from_slice(&0x500000u64.to_le_bytes());
    bytes[sp..sp + 8].copy_from_slice(&0x900000u64.to_le_bytes());
    CapturedAmd64Context::capture(
        |_, output| {
            output.copy_from_slice(&bytes);
            Ok(())
        },
        0x1000,
    )
    .unwrap()
}

fn application() -> [u64; 18] {
    let mut words = core::array::from_fn(|index| 0x100000 + index as u64 * 0x1111);
    words[..3].copy_from_slice(&[0x400000, 0x800000, 0x202]);
    words
}

#[test]
fn unrequested_registers_come_from_application_without_tls_or_fp_fabrication() {
    let context = capture(CONTEXT_AMD64);
    let saved = *context.as_bytes();
    let original = application();
    let plan = context
        .prepare_native_continue(&original, HIGHEST, false)
        .unwrap();
    assert_eq!(&plan.registers[..18], &original);
    assert_eq!(&plan.registers[18..], &[0, 0]);
    assert_eq!(plan.register_mask, (1 << 18) - 1);
    assert_eq!(plan.floating_point, None);
    assert_eq!(plan.debug, None);
    assert_eq!(context.as_bytes(), &saved);
}

#[test]
fn selected_control_replaces_only_application_control() {
    let context = capture(CONTEXT_AMD64 | 1);
    let original = application();
    let plan = context
        .prepare_native_continue(&original, HIGHEST, false)
        .unwrap();
    assert_eq!(&plan.registers[..3], &[0x500000, 0x900000, 0x246]);
    assert_eq!(&plan.registers[3..18], &original[3..]);
}

#[test]
fn selected_integer_replaces_every_gpr_but_preserves_application_control() {
    let context = capture(CONTEXT_AMD64 | 2);
    let original = application();
    let selected = context.prepare_set(HIGHEST).unwrap();
    let plan = context
        .prepare_native_continue(&original, HIGHEST, false)
        .unwrap();
    assert_eq!(&plan.registers[..3], &original[..3]);
    assert_eq!(&plan.registers[3..18], &selected.registers[3..18]);
}

#[test]
fn self_set_forces_only_terminal_rax_over_selected_and_unselected_integer() {
    for flags in [
        CONTEXT_AMD64,
        CONTEXT_AMD64 | 1,
        CONTEXT_AMD64 | 2,
        CONTEXT_AMD64 | 3,
    ] {
        let context = capture(flags);
        let original = application();
        let mut expected = context
            .prepare_native_continue(&original, HIGHEST, false)
            .unwrap();
        expected.registers[3] = 0;
        assert_eq!(
            context.prepare_native_self_set(&original, HIGHEST),
            Ok(expected)
        );
    }
}

#[test]
fn selected_fp_payload_survives_application_register_completion() {
    let context = capture(CONTEXT_FLOATING_POINT);
    let selected = context.prepare_set(HIGHEST).unwrap();
    let plan = context
        .prepare_native_continue(&application(), HIGHEST, false)
        .unwrap();
    assert_eq!(plan.floating_point, selected.floating_point);
    assert!(plan.floating_point.is_some());
    assert_eq!(plan.debug, None);
}

#[test]
fn selected_debug_payload_survives_without_selecting_floating_point() {
    let mut context = capture(CONTEXT_AMD64 | 0x10);
    context.bytes[0x48..0x78].fill(0);
    context.bytes[0x48..0x50].copy_from_slice(&0x401234u64.to_le_bytes());
    context.bytes[0x70..0x78].copy_from_slice(&1u64.to_le_bytes());
    let plan = context
        .prepare_native_continue(&application(), HIGHEST, false)
        .unwrap();
    assert_eq!(plan.debug, Some([0x401234, 0, 0, 0, 0, 1]));
    assert_eq!(plan.floating_point, None);
}

#[test]
fn absent_control_still_validates_captured_continuation_and_alert_policy() {
    let context = capture(CONTEXT_AMD64);
    for index in [0, 1] {
        let mut original = application();
        original[index] = HIGHEST + 1;
        let expected = if index == 0 {
            CodecError::InvalidInstructionPointer
        } else {
            CodecError::InvalidStackPointer
        };
        assert_eq!(
            context.prepare_native_continue(&original, HIGHEST, false),
            Err(expected)
        );
        assert_eq!(
            context.prepare_native_self_set(&original, HIGHEST),
            Err(expected)
        );
    }
    let mut original = application();
    original[2] |= 1 << 18;
    assert_eq!(
        context.prepare_native_continue(&original, HIGHEST, false),
        Err(CodecError::UnsupportedAlignmentCheck)
    );
    assert_eq!(
        context.prepare_native_continue(&application(), HIGHEST, true),
        Err(CodecError::UnsupportedTestAlert)
    );
}
