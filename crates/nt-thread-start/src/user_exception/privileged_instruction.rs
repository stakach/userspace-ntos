//! ReactOS `KiIsPrivilegedInstruction` (ke/amd64/except.c) for native 64-bit code: a user #GP
//! on one of these instructions is STATUS_PRIVILEGED_INSTRUCTION, any other an access
//! violation.

/// The most bytes the decoder looks at: 14 prefixes and a three-byte opcode.
pub const PRIVILEGED_INSTRUCTION_WINDOW: usize = 18;

/// Whether `bytes`, read at the faulting RIP, start with a privileged instruction. Bytes the
/// caller could not read are absent; an instruction that runs past them is not privileged,
/// as ReactOS's probe failure is not.
pub fn is_privileged_instruction(bytes: &[u8]) -> bool {
    let at = |index: usize| bytes.get(index).copied();
    let mut ip = 0;
    let mut prefixes = 0;
    while prefixes < 15 {
        match at(ip) {
            // REX, then segment, operand/address size, LOCK and REP prefixes.
            Some(0x40..=0x4f | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0
                | 0xf2 | 0xf3) => {
                ip += 1;
                prefixes += 1;
            }
            _ => break,
        }
    }
    if prefixes == 15 {
        // Too many prefixes: only concurrently modified code gets here.
        return false;
    }
    let reg = |modrm: Option<u8>| modrm.map(|modrm| (modrm >> 3) & 7);
    match at(ip) {
        Some(0xf4 | 0xfa | 0xfb) => true, // HLT, CLI, STI
        Some(0x0f) => match at(ip + 1) {
            // CLTS, SYSRET, INVD, WBINVD, MOV to/from CR/DR, WRMSR, RDMSR, RDPMC, SYSEXIT,
            // VMREAD, VMWRITE.
            Some(0x06 | 0x07 | 0x08 | 0x09 | 0x20 | 0x21 | 0x22 | 0x23 | 0x30 | 0x32 | 0x33
                | 0x35 | 0x78 | 0x79) => true,
            Some(0x00) => matches!(reg(at(ip + 2)), Some(2 | 3)), // LLDT, LTR
            Some(0x01) => {
                // VMCALL, VMLAUNCH, VMRESUME, VMXOFF, MONITOR, MWAIT, XSETBV, SWAPGS; then
                // LGDT, LIDT, LMSW and INVLPG by ModRM.reg.
                matches!(at(ip + 2), Some(0xc1 | 0xc2 | 0xc3 | 0xc4 | 0xc8 | 0xc9 | 0xd1 | 0xf8))
                    || matches!(reg(at(ip + 2)), Some(2 | 3 | 6 | 7))
            }
            Some(0x38) => matches!(at(ip + 2), Some(0x80 | 0x81)), // INVEPT, INVVPID
            Some(0xc7) => matches!(reg(at(ip + 2)), Some(6 | 7)), // VMPTRLD/VMCLEAR/VMXON, VMPTRST
            _ => false,
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_instructions_are_privileged() {
        for bytes in [
            &[0xf4][..],             // hlt
            &[0xfa],                 // cli
            &[0x0f, 0x22, 0xd8],     // mov cr3, rax
            &[0x0f, 0x30],           // wrmsr
            &[0x0f, 0x00, 0xd8],     // ltr ax
            &[0x0f, 0x01, 0xf8],     // swapgs
            &[0x0f, 0x01, 0x38],     // invlpg [rax]
            &[0x0f, 0x01, 0x10],     // lgdt [rax]
            &[0x66, 0x0f, 0x38, 0x80, 0x00], // invept
            &[0x0f, 0xc7, 0x30],     // vmptrld [rax]
            &[0x48, 0x0f, 0x20, 0xc0], // REX.W mov rax, cr0
            &[0xf3, 0x2e, 0x64, 0xf4], // prefixed hlt
        ] {
            assert!(is_privileged_instruction(bytes), "{bytes:02x?}");
        }
    }

    #[test]
    fn ordinary_and_unreadable_instructions_are_not() {
        assert!(!is_privileged_instruction(&[])); // nothing readable
        assert!(!is_privileged_instruction(&[0x0f])); // opcode runs past the readable bytes
        assert!(!is_privileged_instruction(&[0x0f, 0x01]));
        assert!(!is_privileged_instruction(&[0x48, 0x8b, 0x00]));
        assert!(!is_privileged_instruction(&[0x0f, 0x00, 0x00])); // sldt [rax]
        assert!(!is_privileged_instruction(&[0x0f, 0xa2])); // cpuid
        assert!(!is_privileged_instruction(&[0x0f, 0x31])); // rdtsc
        assert!(!is_privileged_instruction(&[0xcd, 0x2d])); // int 0x2d
        // Fifteen prefixes: ReactOS gives up.
        assert!(!is_privileged_instruction(&[0x66; 16]));
    }
}
