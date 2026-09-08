use super::*;

fn captured(flags: u32) -> CapturedAmd64Context {
    let mut bytes = [0; AMD64_CONTEXT_SIZE];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(13).wrapping_add(7);
    }
    bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
    crate::put_u64(&mut bytes, CONTEXT_RIP_OFFSET as usize, 0x1234);
    crate::put_u64(&mut bytes, CONTEXT_RSP_OFFSET as usize, 0x8765);
    CapturedAmd64Context { bytes }
}

#[test]
fn normalization_retains_requested_gprs_and_exact_rsp_but_installs_native_control() {
    let captured = captured(CONTEXT_AMD64 | 0x1f);
    let original = captured.bytes;
    let initial = captured.normalize_initial(0xffff).unwrap();
    assert_eq!(initial.context.flags(), CONTEXT_AMD64 | 0xf);
    assert_eq!(&initial.as_bytes()[0x38..0x3a], &0x33u16.to_le_bytes());
    assert_eq!(&initial.as_bytes()[0x42..0x44], &0x2bu16.to_le_bytes());
    assert_eq!(initial.startup_projection().rsp, 0x8765);
    for offset in INTEGER_OFFSETS {
        assert_eq!(
            &initial.as_bytes()[offset as usize..offset as usize + 8],
            &original[offset as usize..offset as usize + 8]
        );
    }
    assert_eq!(
        super::super::read_u32(initial.as_bytes(), 0x44) & (1 << 18),
        0
    );
    for index in 0..AMD64_CONTEXT_SIZE {
        if (0x30..0x3a).contains(&index)
            || (0x42..0x48).contains(&index)
            || (FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES).contains(&index)
        {
            continue;
        }
        assert_eq!(initial.as_bytes()[index], original[index]);
    }
}

#[test]
fn requested_fp_payload_survives_but_initial_controls_are_fresh() {
    let captured = captured(CONTEXT_FLOATING_POINT);
    let original = captured.bytes;
    let initial = captured.normalize_initial(0xffff).unwrap();
    let fp =
        &initial.as_bytes()[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES];
    assert_eq!(u16::from_le_bytes(fp[..2].try_into().unwrap()), 0x23f);
    assert!(fp[2..24].iter().all(|byte| *byte == 0));
    assert_eq!(super::super::read_u32(fp, FX_MXCSR_OFFSET), 0x1f80);
    assert_eq!(
        super::super::read_u32(initial.as_bytes(), CONTEXT_MXCSR_OFFSET),
        0x1f80
    );
    assert!(fp[28..32].iter().all(|byte| *byte == 0));
    assert_eq!(
        &fp[32..416],
        &original[FLOAT_SAVE_OFFSET + 32..FLOAT_SAVE_OFFSET + 416]
    );
    assert!(fp[416..].iter().all(|byte| *byte == 0));
}

#[test]
fn unrequested_groups_become_explicit_fresh_zero_state_not_loader_garbage() {
    let initial = captured(0).normalize_initial(0xffff).unwrap();
    assert_eq!(initial.context.flags(), CONTEXT_AMD64 | 0xb);
    let plan = initial.prepare_direct_install();
    assert_eq!(plan.register_mask, (1 << 18) - 1);
    assert_eq!(&plan.registers[3..], &[0; 17]);
    let fp = plan.floating_point.unwrap();
    assert_eq!(u16::from_le_bytes(fp[..2].try_into().unwrap()), 0x23f);
    assert_eq!(super::super::read_u32(&fp, FX_MXCSR_OFFSET), 0x1f80);
    assert!(fp[32..].iter().all(|byte| *byte == 0));
}

#[test]
fn direct_initial_install_and_loader_continue_have_explicitly_distinct_fcw_policies() {
    let initial = captured(CONTEXT_AMD64 | 3)
        .normalize_initial(0xffff)
        .unwrap();
    let direct = initial.prepare_direct_install();
    let continued = initial
        .context
        .prepare_continue(0, 0, 0, 0xffff, false)
        .unwrap();
    assert_eq!(direct.registers, continued.registers);
    assert_eq!(direct.register_mask, continued.register_mask);
    assert_eq!(
        u16::from_le_bytes(direct.floating_point.unwrap()[..2].try_into().unwrap()),
        0x23f
    );
    assert_eq!(
        u16::from_le_bytes(continued.floating_point.unwrap()[..2].try_into().unwrap()),
        0x237
    );
}

#[test]
fn constructor_is_explicit_and_preserves_supplied_start_and_stack_pointer() {
    let start = Amd64ThreadContext {
        rip: 0x1234,
        rsp: 0x8765,
        rcx: 0x1122,
        rdx: 0x3344,
    };
    let initial = InitialAmd64Context::constructor(start, 0xffff).unwrap();
    assert_eq!(initial.startup_projection(), start);
    let plan = initial.prepare_direct_install();
    assert_eq!(&plan.registers[..3], &[start.rip, start.rsp, 0x202]);
    assert_eq!(plan.registers[5], start.rcx);
    assert_eq!(plan.registers[6], start.rdx);
    for index in [3, 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19] {
        assert_eq!(plan.registers[index], 0);
    }
}

#[test]
fn unsupported_extended_state_is_not_erased_by_initialization() {
    for flags in [CONTEXT_AMD64 | 0x40, CONTEXT_AMD64 | 0x80] {
        assert!(matches!(
            captured(flags).normalize_initial(0xffff),
            Err(CodecError::UnsupportedExtendedState)
        ));
    }
}

#[test]
fn bad_initial_control_is_rejected_without_creator_continuation_fallback() {
    for (rip, rsp, error) in [
        (0, 1, CodecError::InvalidInstructionPointer),
        (0x10000, 1, CodecError::InvalidInstructionPointer),
        (1, 0, CodecError::InvalidStackPointer),
        (1, 0x10000, CodecError::InvalidStackPointer),
    ] {
        let mut capture = captured(0);
        crate::put_u64(&mut capture.bytes, CONTEXT_RIP_OFFSET as usize, rip);
        crate::put_u64(&mut capture.bytes, CONTEXT_RSP_OFFSET as usize, rsp);
        assert!(matches!(capture.normalize_initial(0xffff), Err(actual) if actual == error));
    }
}
