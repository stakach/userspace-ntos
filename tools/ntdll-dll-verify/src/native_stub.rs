//! Exact native-producer instruction contract, independent of export retention metadata.
//!
//! Matching starts at the export RVA and consumes every byte through RET. Branch displacements
//! are part of the contract: opcode fragments elsewhere in a function cannot satisfy this gate.
//! The actual-PE execution oracle separately checks semantics under transport clobber.

const BODY_BYTES: usize = 239;

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
        0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0,
        0x49, 0xbb,
    ]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_SEC_IMAGE_MAIN_TEB_VA.to_le_bytes());
    bytes.extend_from_slice(&[0x4c, 0x39, 0xd8, 0x74, 0x0f, 0x49, 0xbb]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_PE_MAIN_TEB_VA.to_le_bytes());
    bytes.extend_from_slice(&[0x4c, 0x39, 0xd8, 0x75, 0x0c, 0x48, 0xb8]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_MAIN_IPC_BUFFER_VA.to_le_bytes());
    bytes.extend_from_slice(&[0xeb, 6, 0x48, 0x2d]); // main skips worker subtraction
    bytes.extend_from_slice(&(nt_syscall_abi::NT_NATIVE_WORKER_IPC_BUFFER_DELTA as u32).to_le_bytes());
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
    bytes.extend_from_slice(&(nt_syscall_abi::native_syscall_message_info(argc) as u32).to_le_bytes());
    bytes.extend_from_slice(&[
        0x45, 0x31, 0xe4, 0x45, 0x31, 0xed, // clear composed destinations R12/R13
        0x48, 0xc7, 0xc2, 0xff, 0xff, 0xff, 0xff, // SysCall
        0x0f, 0x05,
        0x48, 0x83, 0xfe, 1, 0x74, 0x1b, // exact one-word reply -> terminal epilogue
        0x48, 0x83, 0xfe, 6, 0x75, 0x13, // anything except exact six words -> UD2
        0x48, 0xb8,
    ]);
    bytes.extend_from_slice(&nt_syscall_abi::NT_NATIVE_RETRY_REPLY.to_le_bytes());
    bytes.extend_from_slice(&[
        0x49, 0x39, 0xc2, // retry requires exact MR0 sentinel
        0x0f, 0x84, 0x62, 0xff, 0xff, 0xff, // retry -> GS load at offset 60
        0x0f, 0x0b, // invalid envelope never replays a service
        0x4c, 0x89, 0xd0, // terminal RAX = MR0
        0x48, 0x81, 0xc4, 0x80, 0, 0, 0,
        0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5f, 0x5e, 0x5f, 0xc3,
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
                assert!(!matches(&changed, 39, 11), "accepted mutation at {index}/{bit}");
            }
            assert!(!matches(&original[..index], 39, 11), "accepted truncation at {index}");
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
}
