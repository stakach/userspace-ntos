use super::*;

const HIGHEST: u64 = 0x0000_7fff_ffff_ffff;
const SSN: u64 = 27; // NtClose

fn message(ssn: u64) -> u64 {
    (NT_NATIVE_CONTEXT_SYSCALL_LABEL << 12)
        | (NATIVE_CONTEXT_PREFIX_WORDS + u64::from(exact_native_context_argc(ssn).unwrap()))
}

fn continuation() -> NativeCallContinuation {
    let mut registers = [0; NATIVE_CONTEXT_REGISTER_COUNT];
    for (index, value) in registers.iter_mut().enumerate() {
        *value = 0xfeed_0000_0000_0000 | index as u64;
    }
    registers[0] = 0x401234;
    registers[1] = 0x801008;
    NativeCallContinuation::new(SSN as u32, 0x801000, registers, HIGHEST).unwrap()
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn exact_wire_layout_and_all_eighteen_words_roundtrip() {
    let original = continuation();
    let bytes = original.encode();
    assert_eq!(bytes.len(), 176);
    assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
    assert_eq!(&bytes[4..8], &176u32.to_le_bytes());
    assert_eq!(&bytes[8..12], &27u32.to_le_bytes());
    assert_eq!(&bytes[12..16], &[0; 4]);
    assert_eq!(&bytes[16..24], &0x801000u64.to_le_bytes());
    for index in 0..18 {
        assert_eq!(
            &bytes[24 + index * 8..32 + index * 8],
            &original.registers()[index].to_le_bytes()
        );
    }
    assert_eq!(&bytes[168..176], &[0; 8]);
    assert_eq!(
        NativeCallContinuation::decode(&bytes, SSN, HIGHEST),
        Ok(original)
    );
    assert_eq!(original.service_number(), 27);
    assert_eq!(original.entry_rsp(), 0x801000);
    assert_eq!(
        original.registers()[2],
        0xfeed_0000_0000_0002,
        "raw flags are captured, not silently sanitized"
    );
}

#[test]
fn framing_is_exact_for_zero_one_and_widest_current_services() {
    for (name, argc) in [
        ("NtYieldExecution", 0),
        ("NtClose", 1),
        ("NtCreateNamedPipeFile", 14),
    ] {
        let ssn = u64::from(crate::ssn_of(name).unwrap());
        assert_eq!(exact_native_context_argc(ssn), Ok(argc));
        assert_eq!(validate_native_context_request(message(ssn), ssn), Ok(argc));
        for malformed in [
            message(ssn) - 1,
            message(ssn) + 1,
            message(ssn) | (1 << 7),
            message(ssn) | (1 << 9),
            crate::native_syscall_message_info(argc),
            0,
            u64::MAX,
        ] {
            assert_eq!(
                validate_native_context_request(malformed, ssn),
                Err(NativeContextError::InvalidEnvelope)
            );
        }
    }
    assert_ne!(
        NT_NATIVE_CONTEXT_SYSCALL_LABEL,
        crate::NT_NATIVE_SYSCALL_LABEL
    );
}

#[test]
fn exact_arity_lookup_never_truncates_unknown_or_large_ssn() {
    for ssn in [
        u64::MAX,
        u64::from(u32::MAX),
        (1 << 32) | SSN,
        u64::from(crate::ALPC_SSN_BASE),
    ] {
        assert_eq!(
            exact_native_context_argc(ssn),
            Err(NativeContextError::UnknownService)
        );
        assert_eq!(
            validate_native_context_request(message(SSN), ssn),
            Err(NativeContextError::UnknownService)
        );
    }
    for entry in crate::NT_SYSCALLS {
        if let Some(argc) = crate::exact_argc_of(entry.name) {
            assert_eq!(exact_native_context_argc(u64::from(entry.ssn)), Ok(argc));
            assert!(argc <= NATIVE_CONTEXT_MAX_ARGS);
        }
    }
}

#[test]
fn version_size_reserved_and_service_mismatch_fail_exactly() {
    let original = continuation().encode();
    for length in 0..NATIVE_CONTEXT_BYTES {
        assert_eq!(
            NativeCallContinuation::decode(&original[..length], SSN, HIGHEST),
            Err(NativeContextError::InvalidSize)
        );
    }
    let long = [0u8; NATIVE_CONTEXT_BYTES + 1];
    assert_eq!(
        NativeCallContinuation::decode(&long, SSN, HIGHEST),
        Err(NativeContextError::InvalidSize)
    );
    for (offset, value, error) in [
        (VERSION_OFFSET, 0, NativeContextError::UnsupportedVersion),
        (VERSION_OFFSET, 2, NativeContextError::UnsupportedVersion),
        (SIZE_OFFSET, 175, NativeContextError::InvalidSize),
        (SIZE_OFFSET, 177, NativeContextError::InvalidSize),
        (RESERVED_HEADER_OFFSET, 1, NativeContextError::ReservedBits),
        (SERVICE_OFFSET, 34, NativeContextError::ServiceMismatch),
    ] {
        let mut bytes = original;
        put32(&mut bytes, offset, value);
        assert_eq!(
            NativeCallContinuation::decode(&bytes, SSN, HIGHEST),
            Err(error)
        );
    }
    for bit in 0..64 {
        let mut bytes = original;
        put64(&mut bytes, RESERVED_TAIL_OFFSET, 1 << bit);
        assert_eq!(
            NativeCallContinuation::decode(&bytes, SSN, HIGHEST),
            Err(NativeContextError::ReservedBits)
        );
    }
}

#[test]
fn control_addresses_and_post_ret_relationship_are_checked() {
    let original = continuation().encode();
    for bad in [0, HIGHEST + 1, 0xffff_8000_0000_0000, u64::MAX] {
        let mut bytes = original;
        put64(&mut bytes, REGISTERS_OFFSET, bad);
        assert_eq!(
            NativeCallContinuation::decode(&bytes, SSN, u64::MAX),
            Err(NativeContextError::InvalidInstructionPointer)
        );
        let mut bytes = original;
        put64(&mut bytes, REGISTERS_OFFSET + 8, bad);
        assert_eq!(
            NativeCallContinuation::decode(&bytes, SSN, u64::MAX),
            Err(NativeContextError::InvalidStackPointer)
        );
        let mut bytes = original;
        put64(&mut bytes, ENTRY_RSP_OFFSET, bad);
        assert_eq!(
            NativeCallContinuation::decode(&bytes, SSN, u64::MAX),
            Err(NativeContextError::InvalidStackPointer)
        );
    }
    let mut bytes = original;
    put64(&mut bytes, REGISTERS_OFFSET + 8, 0x801000);
    assert_eq!(
        NativeCallContinuation::decode(&bytes, SSN, HIGHEST),
        Err(NativeContextError::InvalidStackRelation)
    );
    put64(&mut bytes, REGISTERS_OFFSET + 8, HIGHEST);
    put64(&mut bytes, ENTRY_RSP_OFFSET, HIGHEST - 8);
    assert!(NativeCallContinuation::decode(&bytes, SSN, HIGHEST).is_ok());
    assert_eq!(
        NativeCallContinuation::decode(&original, SSN, 0x400000),
        Err(NativeContextError::InvalidInstructionPointer)
    );
}

#[test]
fn malformed_envelope_and_pointer_never_invoke_reader() {
    for (info, ssn, address, highest, error) in [
        (
            message(SSN) + 1,
            SSN,
            0x1000,
            HIGHEST,
            NativeContextError::InvalidEnvelope,
        ),
        (
            message(SSN),
            1 << 32,
            0x1000,
            HIGHEST,
            NativeContextError::UnknownService,
        ),
        (
            message(SSN),
            SSN,
            0,
            HIGHEST,
            NativeContextError::InvalidAddress,
        ),
        (
            message(SSN),
            SSN,
            0x1001,
            HIGHEST,
            NativeContextError::Misaligned,
        ),
        (
            message(SSN),
            SSN,
            0x1000,
            0x10ae,
            NativeContextError::InvalidAddress,
        ),
        (
            message(SSN),
            SSN,
            u64::MAX - 15,
            u64::MAX,
            NativeContextError::InvalidAddress,
        ),
        (
            message(SSN),
            SSN,
            HIGHEST + 1,
            u64::MAX,
            NativeContextError::InvalidAddress,
        ),
        (
            message(SSN),
            SSN,
            0xffff_8000_0000_0000,
            u64::MAX,
            NativeContextError::InvalidAddress,
        ),
    ] {
        assert_eq!(
            NativeCallContinuation::capture(info, ssn, address, highest, |_, _| panic!(
                "invalid request reached reader"
            )),
            Err(error)
        );
    }
}

#[test]
fn single_full_capture_accepts_last_aligned_user_span() {
    let original = continuation();
    let bytes = original.encode();
    let address = HIGHEST + 1 - NATIVE_CONTEXT_BYTES as u64;
    assert_eq!(address % NATIVE_CONTEXT_ALIGNMENT, 0);
    let mut calls = 0;
    let captured = NativeCallContinuation::capture(
        message(SSN),
        SSN,
        address,
        HIGHEST,
        |actual_address, output| {
            calls += 1;
            assert_eq!(actual_address, address);
            assert_eq!(output.len(), 176);
            output.copy_from_slice(&bytes);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(captured, original);
}

#[test]
fn capture_preserves_exact_reader_error_even_after_partial_write() {
    for status in [0xc000_0005, 0x8000_0001, 0xc000_012d] {
        let mut calls = 0;
        assert_eq!(
            NativeCallContinuation::capture(message(SSN), SSN, 0x1000, HIGHEST, |_, output| {
                calls += 1;
                output[..100].copy_from_slice(&continuation().encode()[..100]);
                Err(status)
            }),
            Err(NativeContextError::ReadFailed(status))
        );
        assert_eq!(calls, 1);
    }
}

#[test]
fn generated_and_bridge_frame_gaps_do_not_change_owned_continuation() {
    for gap in [184, 312, 440] {
        let address = 0x800000;
        let entry = address + gap;
        let mut registers = *continuation().registers();
        registers[1] = entry + 8;
        let original = NativeCallContinuation::new(SSN as u32, entry, registers, HIGHEST).unwrap();
        let mut bytes = original.encode();
        let captured =
            NativeCallContinuation::capture(message(SSN), SSN, address, HIGHEST, |_, output| {
                output.copy_from_slice(&bytes);
                Ok(())
            })
            .unwrap();
        bytes.fill(0);
        assert_eq!(
            captured, original,
            "no user buffer reference survives capture"
        );
    }
}
