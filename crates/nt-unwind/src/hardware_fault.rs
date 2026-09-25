//! Translation of architecturally identified x86-64 provider faults into NT records.
//!
//! This intentionally does not guess a status for #GP: ReactOS decodes the instruction before
//! deciding between privileged-instruction and access-violation status.

use alloc::vec;

use crate::ExceptionRecord;

pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xc000_001d;

/// The exception represented by a delivered seL4 VMFault, if the wire fields are consistent.
pub fn page_fault(
    instruction_pointer: u64,
    fault_address: u64,
    error_code: u64,
    instruction: bool,
) -> Option<ExceptionRecord> {
    // Bits 3 and 2 respectively indicate a reserved page-table bit and user-mode origin.
    // A reserved-bit failure is an invalid address-space installation, not a provider exception.
    if error_code & 0x8 != 0 || error_code & 0x4 == 0 || (error_code & 0x10 != 0) != instruction {
        return None;
    }
    let operation = if instruction {
        8
    } else if error_code & 2 != 0 {
        1
    } else {
        0
    };
    Some(ExceptionRecord {
        code: STATUS_ACCESS_VIOLATION,
        flags: 0,
        address: instruction_pointer,
        information: vec![operation, fault_address],
    })
}

/// Translate only unambiguous delivered seL4 UserException vectors. The error code is the
/// architecture's vector-specific code, not an NTSTATUS.
pub fn user_exception(
    instruction_pointer: u64,
    vector: u64,
    error_code: u64,
) -> Option<ExceptionRecord> {
    match (vector, error_code) {
        (6, 0) => Some(ExceptionRecord {
            code: STATUS_ILLEGAL_INSTRUCTION,
            flags: 0,
            address: instruction_pointer,
            information: vec![],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_fault_reports_nt_access_kind_and_exact_address() {
        for (error, instruction, expected_kind) in [
            (0x4, false, 0),
            (0x5, false, 0),
            (0x6, false, 1),
            (0x7, false, 1),
            (0x15, true, 8),
        ] {
            let record = page_fault(0x1234, 0x5678, error, instruction).unwrap();
            assert_eq!(record.code, STATUS_ACCESS_VIOLATION);
            assert_eq!(record.flags, 0);
            assert_eq!(record.address, 0x1234);
            assert_eq!(record.information, vec![expected_kind, 0x5678]);
        }
    }

    #[test]
    fn malformed_or_kernel_page_faults_do_not_claim_nt_provider_semantics() {
        for (error, instruction) in [(0, false), (0xc, false), (0x4, true), (0x14, false)] {
            assert!(page_fault(1, 2, error, instruction).is_none());
        }
    }

    #[test]
    fn only_identified_invalid_opcode_maps_without_decoding() {
        let record = user_exception(0x1234, 6, 0).unwrap();
        assert_eq!(record.code, STATUS_ILLEGAL_INSTRUCTION);
        assert_eq!(record.address, 0x1234);
        assert!(record.information.is_empty());
        for (vector, code) in [(6, 1), (7, 0), (13, 0), (13, 2)] {
            assert!(user_exception(0x1234, vector, code).is_none());
        }
    }
}
