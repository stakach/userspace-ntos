//! Exact native-producer instruction contract, independent of export retention metadata.
//!
//! Matching starts at the export RVA and consumes every byte through RET. Branch displacements
//! are part of the contract: opcode fragments elsewhere in a function cannot satisfy this gate.
//! The actual-PE execution oracle separately checks semantics under transport clobber.

const BODY_BYTES: usize = 239;

// Version 1, no handler/frame register, six codes in descending instruction-end order.
// See https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
const UNWIND_BYTES: [u8; 16] = [
    1, 15, 6, 0, 15, 0xf2, // ALLOC_SMALL 128
    8, 0xd0, // PUSH_NONVOL R13
    6, 0xc0, // PUSH_NONVOL R12
    4, 0xf0, // PUSH_NONVOL R15
    2, 0x60, // PUSH_NONVOL RSI
    1, 0x70, // PUSH_NONVOL RDI
];

/// Require one exact, non-overlapping RUNTIME_FUNCTION and the matching prologue description.
/// The caller obtains the exception directory through the PE parser, not a section-name guess.
pub(super) fn unwind_matches(pdata: &[u8], image: &[u8], export_rva: u32) -> bool {
    if pdata.is_empty() || pdata.len() % 12 != 0 {
        return false;
    }
    let Some(expected_end) = export_rva.checked_add(BODY_BYTES as u32) else {
        return false;
    };
    let mut previous_end = 0;
    let mut found = false;
    for row in pdata.chunks_exact(12) {
        let begin = u32::from_le_bytes(row[..4].try_into().unwrap());
        let end = u32::from_le_bytes(row[4..8].try_into().unwrap());
        let unwind = u32::from_le_bytes(row[8..12].try_into().unwrap());
        if begin < previous_end || begin >= end || end as usize > image.len() {
            return false;
        }
        previous_end = end;
        if begin <= export_rva && export_rva < end {
            if begin != export_rva || end != expected_end || unwind % 4 != 0 {
                return false;
            }
            if !image
                .get(unwind as usize..)
                .is_some_and(|bytes| bytes.starts_with(&UNWIND_BYTES))
            {
                return false;
            }
            found = true;
        }
    }
    found
}

pub(super) fn matches(bytes: &[u8], ssn: u32, argc: u8) -> bool {
    argc <= 16 && bytes.starts_with(&expected_body(ssn, argc))
}

fn expected_body(ssn: u32, argc: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(BODY_BYTES);
    bytes.extend_from_slice(&[
        0x57, 0x56, 0x41, 0x57, 0x41, 0x54, 0x41, 0x55, // save RDI/RSI/R15/R12/R13
        0x48, 0x81, 0xec, 0x80, 0, 0, 0, // reserve immutable argument vector
        0x48, 0x89, 0x0c, 0x24, // [rsp] = RCX
        0x48, 0x89, 0x54, 0x24, 0x08, // [rsp+8] = RDX
        0x4c, 0x89, 0x44, 0x24, 0x10, // [rsp+16] = R8
        0x4c, 0x89, 0x4c, 0x24, 0x18, // [rsp+24] = R9
        0x48, 0x8d, 0xb4, 0x24, 0xd0, 0, 0, 0, // RSI = entry RSP + 40
        0x48, 0x8d, 0x7c, 0x24, 0x20, // RDI = retained argument five
        0xb9,
    ]);
    bytes.extend_from_slice(&u32::from(argc).to_le_bytes());
    bytes.extend_from_slice(&[
        0x83, 0xe9, 4, 0x7e, 3, 0xf3, 0x48, 0xa5, // copy argc-4; JLE skips only REP
        // Retry targets exactly this GS load, after immutable capture and before all restaging.
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0, 0x49, 0xbb,
    ]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA.to_le_bytes());
    bytes.extend_from_slice(&[0x4c, 0x39, 0xd8, 0x74, 0x0f, 0x49, 0xbb]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_PE_MAIN_TEB_VA.to_le_bytes());
    bytes.extend_from_slice(&[0x4c, 0x39, 0xd8, 0x75, 0x0c, 0x48, 0xb8]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_MAIN_IPC_BUFFER_VA.to_le_bytes());
    bytes.extend_from_slice(&[0xeb, 6, 0x48, 0x2d]); // main skips worker subtraction
    bytes.extend_from_slice(
        &(nt_syscall_abi::NT_NATIVE_WORKER_IPC_BUFFER_DELTA as u32).to_le_bytes(),
    );
    bytes.extend_from_slice(&[
        0x48, 0x8d, 0x74, 0x24, 0x10, // RSI = retained argument three
        0x48, 0x8d, 0x78, 0x28, // RDI = current thread IPC MR4
        0xb9,
    ]);
    bytes.extend_from_slice(&u32::from(argc).to_le_bytes());
    bytes.extend_from_slice(&[
        0x83, 0xe9, 2, 0x7e, 3, 0xf3, 0x48, 0xa5, // copy argc-2 on every attempt
        0x4c, 0x8b, 0x0c, 0x24, // R9 = retained argument one
        0x4c, 0x8b, 0x7c, 0x24, 8, // R15 = retained argument two
        0x4c, 0x8d, 0x84, 0x24, 0xa8, 0, 0, 0, // R8 = exact entry RSP
        0x41, 0xba,
    ]);
    bytes.extend_from_slice(&ssn.to_le_bytes());
    bytes.extend_from_slice(&[0xbf, 6, 0, 0, 0, 0xbe]);
    bytes.extend_from_slice(
        &(nt_syscall_abi::native_syscall_message_info(argc) as u32).to_le_bytes(),
    );
    bytes.extend_from_slice(&[
        0x45, 0x31, 0xe4, 0x45, 0x31, 0xed, // clear composed destinations R12/R13
        0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // SysCall
        0x0f, 0x05, 0x48, 0x83, 0xfe, 1, 0x74,
        0x1b, // exact one-word reply -> terminal epilogue
        0x48, 0x83, 0xfe, 6, 0x75, 0x13, // anything except exact six words -> UD2
        0x48, 0xb8,
    ]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_RETRY_REPLY.to_le_bytes());
    bytes.extend_from_slice(&[
        0x49, 0x39, 0xc2, // retry requires exact MR0 sentinel
        0x0f, 0x84, 0x62, 0xff, 0xff, 0xff, // retry -> GS load at offset 60
        0x0f, 0x0b, // invalid envelope never replays a service
        0x4c, 0x89, 0xd0, // terminal RAX = MR0
        0x48, 0x81, 0xc4, 0x80, 0, 0, 0, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5f, 0x5e, 0x5f, 0xc3,
    ]);
    assert_eq!(bytes.len(), BODY_BYTES);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_body_covers_every_shared_service() {
        for service in nt_syscall_abi::NT_SYSCALLS {
            let argc = nt_syscall_abi::exact_argc_of(service.name).unwrap();
            let bytes = expected_body(service.ssn, argc);
            assert!(matches(&bytes, service.ssn, argc));
            assert!(!matches(&bytes, service.ssn ^ 1, argc));
            assert!(!matches(&bytes, service.ssn, argc + 1));
        }
    }

    #[test]
    fn every_instruction_immediate_and_branch_byte_is_required() {
        let original = expected_body(39, 11);
        for index in 0..original.len() {
            for bit in 0..8 {
                let mut changed = original.clone();
                changed[index] ^= 1 << bit;
                assert!(
                    !matches(&changed, 39, 11),
                    "accepted mutation at {index}/{bit}"
                );
            }
            assert!(
                !matches(&original[..index], 39, 11),
                "accepted truncation at {index}"
            );
        }
    }

    #[test]
    fn template_must_start_at_export_and_preserve_ret_boundary() {
        let body = expected_body(46, 14);
        let mut prefixed = vec![0xc3];
        prefixed.extend_from_slice(&body);
        assert!(!matches(&prefixed, 46, 14));
        let mut old_prologue = vec![0x57, 0x56, 0x41, 0x57];
        old_prologue.extend_from_slice(&body);
        assert!(!matches(&old_prologue, 46, 14));
        let mut padded = body;
        padded.extend_from_slice(&[0xcc; 16]);
        assert!(matches(&padded, 46, 14));
        assert!(!matches(&padded, 46, 17));
    }

    fn unwind_fixture() -> (Vec<u8>, Vec<u8>) {
        let mut image = vec![0; 1024];
        image[512..528].copy_from_slice(&UNWIND_BYTES);
        let pdata = [64u32, 64 + BODY_BYTES as u32, 512]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        (pdata, image)
    }

    #[test]
    fn every_unwind_header_and_operation_bit_is_required() {
        let (pdata, image) = unwind_fixture();
        assert!(unwind_matches(&pdata, &image, 64));
        for index in 512..528 {
            for bit in 0..8 {
                let mut changed = image.clone();
                changed[index] ^= 1 << bit;
                assert!(
                    !unwind_matches(&pdata, &changed, 64),
                    "accepted {index}/{bit}"
                );
            }
            assert!(!unwind_matches(&pdata, &image[..index], 64));
        }
    }

    #[test]
    fn runtime_function_requires_exact_bounds_and_unique_sorted_coverage() {
        let (pdata, image) = unwind_fixture();
        for index in 0..pdata.len() {
            assert!(!unwind_matches(&pdata[..index], &image, 64));
        }
        assert!(!unwind_matches(&pdata, &image, 63));
        assert!(!unwind_matches(&pdata, &image, 65));
        assert!(!unwind_matches(&pdata, &image, u32::MAX));
        for column in 0..3 {
            for value in [0, 1, 63, 65, 302, 304, 513, u32::MAX] {
                let mut changed = pdata.clone();
                changed[column * 4..column * 4 + 4].copy_from_slice(&value.to_le_bytes());
                assert!(!unwind_matches(&changed, &image, 64));
            }
        }
        let mut duplicate = pdata.clone();
        duplicate.extend_from_slice(&pdata);
        assert!(!unwind_matches(&duplicate, &image, 64));
        let mut overlap = pdata;
        overlap.extend([300u32, 400, 512].into_iter().flat_map(u32::to_le_bytes));
        assert!(!unwind_matches(&overlap, &image, 64));
    }

    #[test]
    fn neighboring_functions_preserve_coverage_but_unsorted_tables_fail() {
        let (target, image) = unwind_fixture();
        let before: Vec<u8> = [1u32, 32, 512]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let after: Vec<u8> = [400u32, 450, 512]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let sorted = [before.as_slice(), &target, &after].concat();
        assert!(unwind_matches(&sorted, &image, 64));
        let unsorted = [after.as_slice(), &target, &before].concat();
        assert!(!unwind_matches(&unsorted, &image, 64));
        assert!(!unwind_matches(&[before, after].concat(), &image, 64));
    }
}
