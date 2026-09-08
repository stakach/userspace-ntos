use super::{
    CapturedAmd64Context, CodecError, LegacyContextRestore, CONTEXT_AMD64, CONTEXT_FLOATING_POINT,
    CONTEXT_MXCSR_OFFSET, FLOAT_SAVE_OFFSET, FX_MXCSR_OFFSET, LEGACY_FLOATING_POINT_BYTES,
    NT_NATIVE_CODE_SELECTOR,
};
use crate::{
    Amd64ThreadContext, AMD64_CONTEXT_SIZE, CONTEXT_R10_OFFSET, CONTEXT_R11_OFFSET,
    CONTEXT_R12_OFFSET, CONTEXT_R13_OFFSET, CONTEXT_R14_OFFSET, CONTEXT_R15_OFFSET,
    CONTEXT_R8_OFFSET, CONTEXT_R9_OFFSET, CONTEXT_RAX_OFFSET, CONTEXT_RBP_OFFSET,
    CONTEXT_RBX_OFFSET, CONTEXT_RCX_OFFSET, CONTEXT_RDI_OFFSET, CONTEXT_RDX_OFFSET,
    CONTEXT_RIP_OFFSET, CONTEXT_RSI_OFFSET, CONTEXT_RSP_OFFSET,
};

pub const INITIAL_THREAD_FCW: u16 = 0x023f;
pub const INITIAL_THREAD_MXCSR: u32 = 0x1f80;
const INTEGER_OFFSETS: [u64; 15] = [
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

/// Owned fresh-thread context, distinct from a partial continuation request.
///
/// Normalization reflects zeroed initial trap/exception frames, followed by requested groups
/// and NT5's explicit fresh FP controls. INTEGER/FP/CONTROL are then all represented so a loader
/// cannot leave unrequested groups clobbered. This owner is deliberately not Copy or Clone.
///
/// ```compile_fail
/// fn requires_copy<T: Copy>() {}
/// requires_copy::<nt_thread_start::amd64_context::InitialAmd64Context>();
/// ```
#[derive(Debug)]
pub struct InitialAmd64Context {
    context: CapturedAmd64Context,
}

impl CapturedAmd64Context {
    /// Consume a capture into fresh native64 state with automatic alignment handling (AC clear).
    ///
    /// NT5 thredini.c forces CONTROL, strips DEBUG, selects native CS/SS and initializes FP
    /// control state after copying requested groups. RSP sizing/alignment policy belongs to the
    /// stack creator in this system: its exact supplied RSP is preserved, not rounded again.
    pub fn normalize_initial(
        mut self,
        highest_user_address: u64,
    ) -> Result<InitialAmd64Context, CodecError> {
        self.validate_legacy_state()?;
        let original_flags = self.flags();
        if original_flags & 2 == 0 {
            for offset in INTEGER_OFFSETS {
                crate::put_u64(&mut self.bytes, offset as usize, 0);
            }
        }
        let fp =
            &mut self.bytes[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES];
        if original_flags & 8 == 0 {
            fp.fill(0);
        }
        // Native and FXSAVE32 pointer formats are not interchangeable. thredini resets these
        // pointers/opcode/status regardless of requested FP, so the initial image has no pointer
        // translation ambiguity. Only x87 slots and XMM0-15 retain requested payloads.
        fp[..32].fill(0);
        fp[416..].fill(0);
        fp[..2].copy_from_slice(&INITIAL_THREAD_FCW.to_le_bytes());
        // Abridged FXSAVE FTW=0 means all x87 registers empty (legacy full tag word=0xffff).
        fp[FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4]
            .copy_from_slice(&INITIAL_THREAD_MXCSR.to_le_bytes());
        self.bytes[CONTEXT_MXCSR_OFFSET..CONTEXT_MXCSR_OFFSET + 4]
            .copy_from_slice(&INITIAL_THREAD_MXCSR.to_le_bytes());
        let flags = (original_flags | CONTEXT_AMD64 | 0xb) & !0x10;
        self.bytes[0x30..0x34].copy_from_slice(&flags.to_le_bytes());
        self.bytes[0x38..0x3a].copy_from_slice(&NT_NATIVE_CODE_SELECTOR.to_le_bytes());
        self.bytes[0x42..0x44].copy_from_slice(&0x2bu16.to_le_bytes());
        let eflags = super::read_u32(&self.bytes, 0x44) & !(1 << 18);
        self.bytes[0x44..0x48].copy_from_slice(&eflags.to_le_bytes());
        let validated = self.prepare_continue(0, 0, 0, highest_user_address, false)?;
        self.bytes[0x44..0x48].copy_from_slice(&(validated.registers[2] as u32).to_le_bytes());
        Ok(InitialAmd64Context { context: self })
    }
}

impl InitialAmd64Context {
    /// Explicit kernel-generated constructor entry, not a fabricated caller capture.
    pub fn constructor(
        start: Amd64ThreadContext,
        highest_user_address: u64,
    ) -> Result<Self, CodecError> {
        let mut bytes = [0; AMD64_CONTEXT_SIZE];
        bytes[0x30..0x34].copy_from_slice(&(CONTEXT_AMD64 | 3).to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&0x202u32.to_le_bytes());
        crate::put_u64(&mut bytes, CONTEXT_RIP_OFFSET as usize, start.rip);
        crate::put_u64(&mut bytes, CONTEXT_RSP_OFFSET as usize, start.rsp);
        crate::put_u64(&mut bytes, CONTEXT_RCX_OFFSET as usize, start.rcx);
        crate::put_u64(&mut bytes, CONTEXT_RDX_OFFSET as usize, start.rdx);
        CapturedAmd64Context { bytes }.normalize_initial(highest_user_address)
    }

    pub fn as_bytes(&self) -> &[u8; AMD64_CONTEXT_SIZE] {
        self.context.as_bytes()
    }

    pub fn startup_projection(&self) -> Amd64ThreadContext {
        self.context.startup_projection()
    }

    /// Initial frame installation, without creator continuation values or a restart decision.
    ///
    /// Direct installation uses thredini's fresh FCW=0x023f. The loader path passes these bytes
    /// to NtContinue, whose separate SET mask produces FCW=0x0237. These are deliberately not
    /// claimed to be identical policies. The consumer must install all selected groups atomically.
    pub fn prepare_direct_install(&self) -> LegacyContextRestore {
        let mut restore = self
            .context
            .prepare_continue(0, 0, 0, u64::MAX, false)
            .expect("normalized initial context remains validated");
        debug_assert_eq!(
            self.context.flags() & CONTEXT_FLOATING_POINT,
            CONTEXT_FLOATING_POINT
        );
        restore
            .floating_point
            .as_mut()
            .expect("initial FP group is explicit")
            .copy_from_slice(
                &self.context.bytes
                    [FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES],
            );
        super::floating_point::wire_to_hardware(
            restore
                .floating_point
                .as_mut()
                .expect("initial FP group is explicit"),
        );
        restore
    }
}

#[cfg(test)]
mod tests;
