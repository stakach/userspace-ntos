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

pub(super) const CONTROL: u32 = CONTEXT_AMD64 | 1;
pub(super) const INTEGER: u32 = CONTEXT_AMD64 | 2;
pub(super) const INTEGER_OFFSETS: [u64; 15] = [
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
];
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
    /// DR0, DR1, DR2, DR3, DR6, DR7, selected and installed as one group.
    pub debug: Option<[u64; 6]>,
}

impl CapturedAmd64Context {
    /// Prepare NtContinue without changing the captured bytes or any target state.
    ///
    /// The resume tuple must be the caller's canonical syscall-return continuation, not the
    /// raw faulting SYSCALL instruction reported by a fault transport. It is used whenever
    /// CONTROL is absent, so a partial-group continue cannot accidentally reissue that syscall.
    /// Segment bases are preserved, as NT5 does; compatibility CS, TestAlert,
    /// alignment-check exceptions and extended state require implementations beyond this codec.
    pub fn prepare_continue(
        &self,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        highest_user_address: u64,
        test_alert: bool,
    ) -> Result<LegacyContextRestore, CodecError> {
        self.validate_native_restore()?;
        if test_alert {
            return Err(CodecError::UnsupportedTestAlert);
        }
        self.prepare_selected(
            highest_user_address,
            Some((resume_ip, resume_sp, resume_flags)),
        )
    }

    /// Prepare NtSetContextThread without reading or merging the target's live context.
    /// Absent CONTROL selects no control registers. Segment bases are never selected.
    /// NT5 selects user CS independently of CONTROL, so even partial requests must supply a
    /// supported native CS; compatibility mode is not silently inferred from missing bytes.
    pub fn prepare_set(
        &self,
        highest_user_address: u64,
    ) -> Result<LegacyContextRestore, CodecError> {
        self.validate_native_restore()?;
        self.prepare_selected(highest_user_address, None)
    }

    /// Prepare fault-transport self NtSetContextThread for atomic service-exit restart.
    /// The fallback tuple is the canonical service return, never its faulting SYSCALL PC.
    /// The service's STATUS_SUCCESS replaces RAX even when INTEGER supplied a different value.
    /// This does not authorize a native-call transport to invent a missing continuation.
    pub fn prepare_self_set(
        &self,
        resume_ip: u64,
        resume_sp: u64,
        resume_flags: u64,
        highest_user_address: u64,
    ) -> Result<LegacyContextRestore, CodecError> {
        self.validate_native_restore()?;
        let mut plan = self.prepare_selected(
            highest_user_address,
            Some((resume_ip, resume_sp, resume_flags)),
        )?;
        plan.registers[3] = 0;
        plan.register_mask |= 1 << 3;
        Ok(plan)
    }

    fn validate_native_restore(&self) -> Result<(), CodecError> {
        self.validate_native_groups()?;
        // NT5 KeContextToKframes chooses native versus compatibility CS independently of the
        // CONTROL group. This native-only path must not silently choose a compatibility frame.
        if !matches!(
            u16::from_le_bytes(self.bytes[CS_OFFSET..CS_OFFSET + 2].try_into().unwrap()),
            NT_NATIVE_CODE_SELECTOR | PLATFORM_NATIVE_CODE_SELECTOR
        ) {
            return Err(CodecError::UnsupportedCompatibilityMode);
        }
        Ok(())
    }

    fn prepare_selected(
        &self,
        highest_user_address: u64,
        continuation: Option<(u64, u64, u64)>,
    ) -> Result<LegacyContextRestore, CodecError> {
        let control = if self.flags() & CONTROL == CONTROL {
            Some((
                captured_u64(&self.bytes, CONTEXT_RIP_OFFSET),
                captured_u64(&self.bytes, CONTEXT_RSP_OFFSET),
                read_u32(&self.bytes, EFLAGS_OFFSET) as u64,
            ))
        } else {
            continuation
        };
        let mut registers = [0; 20];
        let mut register_mask = 0;
        if let Some((ip, sp, flags)) = control {
            if ip == 0 || ip > highest_user_address {
                return Err(CodecError::InvalidInstructionPointer);
            }
            if sp == 0 || sp > highest_user_address {
                return Err(CodecError::InvalidStackPointer);
            }
            if flags & EFLAGS_AC != 0 {
                return Err(CodecError::UnsupportedAlignmentCheck);
            }
            registers[0] = ip;
            registers[1] = sp;
            registers[2] = (flags & NT5_USER_EFLAGS_MASK) | 0x202;
            register_mask = 0x7;
        }
        if self.flags() & INTEGER == INTEGER {
            for (index, offset) in INTEGER_OFFSETS.into_iter().enumerate() {
                registers[index + 3] = captured_u64(&self.bytes, offset);
            }
            register_mask |= ((1 << 15) - 1) << 3;
        }
        Ok(LegacyContextRestore {
            registers,
            register_mask,
            floating_point: self.extract_legacy_floating_point()?,
            debug: self.extract_legacy_debug_registers(highest_user_address)?,
        })
    }
}

#[cfg(test)]
mod tests;
