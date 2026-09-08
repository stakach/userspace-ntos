use super::{
    read_u32, CapturedAmd64Context, CodecError, CONTEXT_AMD64, LEGACY_FLOATING_POINT_BYTES,
};
use crate::{
    captured_u64, CONTEXT_R10_OFFSET, CONTEXT_R11_OFFSET, CONTEXT_R12_OFFSET, CONTEXT_R13_OFFSET,
    CONTEXT_R14_OFFSET, CONTEXT_R15_OFFSET, CONTEXT_R8_OFFSET, CONTEXT_R9_OFFSET,
    CONTEXT_RAX_OFFSET, CONTEXT_RBP_OFFSET, CONTEXT_RBX_OFFSET, CONTEXT_RCX_OFFSET,
    CONTEXT_RDI_OFFSET, CONTEXT_RDX_OFFSET, CONTEXT_RIP_OFFSET, CONTEXT_RSI_OFFSET,
    CONTEXT_RSP_OFFSET,
};

const CONTROL: u32 = CONTEXT_AMD64 | 1;
const INTEGER: u32 = CONTEXT_AMD64 | 2;
const DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
const CS_OFFSET: usize = 0x38;
const EFLAGS_OFFSET: usize = 0x44;
const EFLAGS_AC: u64 = 1 << 18;
const NT5_USER_EFLAGS_MASK: u64 = 0x40dd5;

/// NT's logical native selector and this platform's actual native64 GDT selector are separate
/// ABI namespaces. Neither selector denotes NT compatibility mode (0x23).
pub const NT_NATIVE_CODE_SELECTOR: u16 = 0x33;
pub const PLATFORM_NATIVE_CODE_SELECTOR: u16 = 0x2b;

/// Validated native legacy CONTEXT restore payload, with seL4 UserContext register ordering.
///
/// Only selected register bits may be written. Floating point is a separate optional group;
/// bits 18/19 (FS/GS bases) are never selected. The consumer must perform the complete selected
/// update and restart atomically; this pure plan does not own a target TCB or authorize it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyContextRestore {
    pub registers: [u64; 20],
    pub register_mask: u64,
    pub floating_point: Option<[u8; LEGACY_FLOATING_POINT_BYTES]>,
}

impl CapturedAmd64Context {
    /// Prepare NtContinue without changing the captured bytes or any target state.
    ///
    /// The resume tuple must be the caller's canonical syscall-return continuation, not the
    /// raw faulting SYSCALL instruction reported by a fault transport. It is used whenever
    /// CONTROL is absent, so a partial-group continue cannot accidentally reissue that syscall.
    /// Segment bases are preserved, as NT5 does; compatibility CS, debug updates, TestAlert,
    /// alignment-check exceptions and extended state require implementations beyond this codec.
    pub fn prepare_continue(
        &self,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        highest_user_address: u64,
        test_alert: bool,
    ) -> Result<LegacyContextRestore, CodecError> {
        if self.flags() & CONTEXT_AMD64 == 0 {
            return Err(CodecError::InvalidArchitecture);
        }
        self.validate_legacy_state()?;
        if test_alert {
            return Err(CodecError::UnsupportedTestAlert);
        }
        if self.flags() & DEBUG_REGISTERS == DEBUG_REGISTERS {
            return Err(CodecError::UnsupportedDebugRegisters);
        }
        // NT5 KeContextToKframes chooses native versus compatibility CS independently of the
        // CONTROL group. This native-only path must not silently choose a compatibility frame.
        if !matches!(
            u16::from_le_bytes(self.bytes[CS_OFFSET..CS_OFFSET + 2].try_into().unwrap()),
            NT_NATIVE_CODE_SELECTOR | PLATFORM_NATIVE_CODE_SELECTOR
        ) {
            return Err(CodecError::UnsupportedCompatibilityMode);
        }
        let (ip, sp, flags) = if self.flags() & CONTROL == CONTROL {
            (
                captured_u64(&self.bytes, CONTEXT_RIP_OFFSET),
                captured_u64(&self.bytes, CONTEXT_RSP_OFFSET),
                read_u32(&self.bytes, EFLAGS_OFFSET) as u64,
            )
        } else {
            (resume_ip, resume_sp, resume_flags)
        };
        if ip == 0 || ip > highest_user_address {
            return Err(CodecError::InvalidInstructionPointer);
        }
        if sp == 0 || sp > highest_user_address {
            return Err(CodecError::InvalidStackPointer);
        }
        if flags & EFLAGS_AC != 0 {
            return Err(CodecError::UnsupportedAlignmentCheck);
        }
        let mut registers = [0; 20];
        registers[0] = ip;
        registers[1] = sp;
        registers[2] = (flags & NT5_USER_EFLAGS_MASK) | 0x202;
        let mut register_mask = 0x7;
        if self.flags() & INTEGER == INTEGER {
            for (index, offset) in [
                CONTEXT_RAX_OFFSET,
                CONTEXT_RBX_OFFSET,
                CONTEXT_RCX_OFFSET,
                CONTEXT_RDX_OFFSET,
                CONTEXT_RSI_OFFSET,
                CONTEXT_RDI_OFFSET,
                CONTEXT_RBP_OFFSET,
                CONTEXT_R8_OFFSET,
                CONTEXT_R9_OFFSET,
                CONTEXT_R10_OFFSET,
                CONTEXT_R11_OFFSET,
                CONTEXT_R12_OFFSET,
                CONTEXT_R13_OFFSET,
                CONTEXT_R14_OFFSET,
                CONTEXT_R15_OFFSET,
            ]
            .into_iter()
            .enumerate()
            {
                registers[index + 3] = captured_u64(&self.bytes, offset);
            }
            register_mask |= ((1 << 15) - 1) << 3;
        }
        Ok(LegacyContextRestore {
            registers,
            register_mask,
            floating_point: self.extract_legacy_floating_point()?,
        })
    }
}

#[cfg(test)]
mod tests;
