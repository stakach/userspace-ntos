//! Captured ReactOS/current AMD64 CONTEXT bytes and native legacy floating-point conversion.
//!
//! This wire layout has a 512-byte FXSAVE-shaped FloatSave at 0x100. The local NT5 tree uses
//! separate XMM registers and an older LEGACY_SAVE_AREA; its `ke/amd64/exceptn.c` supplies the
//! restore ordering and FCW/MXCSR masks used here, not this wire layout. Extended state is not
//! representable by this codec and must never be silently accepted as legacy floating point.

use crate::{
    capture_bytes, captured_u64, Amd64ThreadContext, CaptureError, AMD64_CONTEXT_ALIGNMENT,
    AMD64_CONTEXT_SIZE, CONTEXT_RCX_OFFSET, CONTEXT_RDX_OFFSET, CONTEXT_RIP_OFFSET,
    CONTEXT_RSP_OFFSET,
};

pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
pub const CONTEXT_XSTATE: u32 = CONTEXT_AMD64 | 0x40;
pub const FLOAT_SAVE_OFFSET: usize = 0x100;
pub const LEGACY_FLOATING_POINT_BYTES: usize = 512;
pub const CONTEXT_MXCSR_OFFSET: usize = 0x34;
pub const FX_MXCSR_OFFSET: usize = 24;
pub const NT5_FCW_MASK: u16 = 0x1f37;
pub const NT5_MXCSR_MASK: u32 = 0xffbf;

const CONTEXT_FLAGS_OFFSET: usize = 0x30;
const EXTENDED_STATE_GROUPS: u32 = 0x40 | 0x80; // XSTATE and CET

mod continue_context;
mod debug_context;
mod floating_point;
mod register_publication;
mod native_continuation;
pub use continue_context::{
    LegacyContextRestore, NT_NATIVE_CODE_SELECTOR, PLATFORM_NATIVE_CODE_SELECTOR,
};
mod initial_trampoline;
pub use initial_trampoline::{
    initial_context_trampoline, InitialContextTrampoline, INITIAL_CONTEXT_TRAMPOLINE_CAPACITY,
};
mod initial_context;
pub use initial_context::{InitialAmd64Context, INITIAL_THREAD_FCW, INITIAL_THREAD_MXCSR};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    UnsupportedExtendedState,
    InvalidArchitecture,
    InvalidInstructionPointer,
    InvalidContextAddress,
    InvalidStackPointer,
    InvalidDebugRegisters,
    UnsupportedCompatibilityMode,
    UnsupportedDebugRegisters,
    UnsupportedTestAlert,
    UnsupportedAlignmentCheck,
}

impl CodecError {
    pub const fn status(self) -> u32 {
        match self {
            Self::InvalidArchitecture
            | Self::InvalidInstructionPointer
            | Self::InvalidContextAddress
            | Self::InvalidStackPointer
            | Self::InvalidDebugRegisters => 0xc000_000d,
            Self::UnsupportedExtendedState
            | Self::UnsupportedCompatibilityMode
            | Self::UnsupportedDebugRegisters
            | Self::UnsupportedTestAlert
            | Self::UnsupportedAlignmentCheck => 0xc000_00bb,
        }
    }
}

/// Complete captured bytes. No alignment-sensitive typed casts or external memory borrows.
/// Capture itself preserves all requested flags; a codec must admit the groups it implements.
#[derive(Debug, Eq, PartialEq)]
pub struct CapturedAmd64Context {
    bytes: [u8; AMD64_CONTEXT_SIZE],
}

impl CapturedAmd64Context {
    pub fn capture(
        read: impl FnMut(u64, &mut [u8]) -> Result<(), u32>,
        address: u64,
    ) -> Result<Self, CaptureError> {
        Ok(Self {
            bytes: capture_bytes(read, address, AMD64_CONTEXT_ALIGNMENT)?,
        })
    }

    pub fn as_bytes(&self) -> &[u8; AMD64_CONTEXT_SIZE] {
        &self.bytes
    }

    pub fn flags(&self) -> u32 {
        read_u32(&self.bytes, CONTEXT_FLAGS_OFFSET)
    }

    /// The existing four-register projection only; it does not apply unrequested native groups.
    pub fn startup_projection(&self) -> Amd64ThreadContext {
        Amd64ThreadContext {
            rip: captured_u64(&self.bytes, CONTEXT_RIP_OFFSET),
            rsp: captured_u64(&self.bytes, CONTEXT_RSP_OFFSET),
            rcx: captured_u64(&self.bytes, CONTEXT_RCX_OFFSET),
            rdx: captured_u64(&self.bytes, CONTEXT_RDX_OFFSET),
        }
    }

    fn floating_point_requested(&self) -> Result<bool, CodecError> {
        self.validate_legacy_state()?;
        Ok(self.flags() & CONTEXT_FLOATING_POINT == CONTEXT_FLOATING_POINT)
    }

    /// Refuse extended state without allocating or transforming a legacy floating-point image.
    pub fn validate_legacy_state(&self) -> Result<(), CodecError> {
        if self.flags() & EXTENDED_STATE_GROUPS != 0 {
            return Err(CodecError::UnsupportedExtendedState);
        }
        Ok(())
    }

    fn validate_native_groups(&self) -> Result<(), CodecError> {
        if self.flags() & CONTEXT_AMD64 == 0 {
            return Err(CodecError::InvalidArchitecture);
        }
        self.validate_legacy_state()
    }

    /// Extract a legacy hardware image only when the AMD64 floating-point group was requested.
    /// NT5 restores top-level MxCsr, not a conflicting value inside FloatSave. Preserve the x87
    /// and XMM0-15 payloads while sanitizing FCW and that authoritative MXCSR value.
    pub fn extract_legacy_floating_point(
        &self,
    ) -> Result<Option<[u8; LEGACY_FLOATING_POINT_BYTES]>, CodecError> {
        if !self.floating_point_requested()? {
            return Ok(None);
        }
        let mut image = [0; LEGACY_FLOATING_POINT_BYTES];
        image.copy_from_slice(
            &self.bytes[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES],
        );
        let mxcsr = read_u32(&self.bytes, CONTEXT_MXCSR_OFFSET);
        sanitize(&mut image, mxcsr);
        floating_point::wire_to_hardware(&mut image);
        Ok(Some(image))
    }

    /// Publish the requested native legacy FP group, preserving flags and all unrelated bytes.
    /// Like NT5 KeContextFromKframes, observation preserves the raw saved hardware FCW/MXCSR;
    /// the SET/restore masks are not applied here. The hardware MXCSR is mirrored into the
    /// top-level field. FXSAVE64 pointer fields are converted to XMM_SAVE_AREA32 offsets;
    /// all remaining supplied hardware bytes are copied unchanged into FloatSave.
    /// Returns false without mutation for an unrequested group; unsupported extended state is
    /// rejected before any field is written.
    pub fn publish_legacy_floating_point(
        &mut self,
        image: &[u8; LEGACY_FLOATING_POINT_BYTES],
    ) -> Result<bool, CodecError> {
        if !self.floating_point_requested()? {
            return Ok(false);
        }
        let mxcsr = read_u32(image, FX_MXCSR_OFFSET);
        let mut wire = *image;
        floating_point::hardware_to_wire(&mut wire);
        self.bytes[FLOAT_SAVE_OFFSET..FLOAT_SAVE_OFFSET + LEGACY_FLOATING_POINT_BYTES]
            .copy_from_slice(&wire);
        self.bytes[CONTEXT_MXCSR_OFFSET..CONTEXT_MXCSR_OFFSET + 4]
            .copy_from_slice(&mxcsr.to_le_bytes());
        Ok(true)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn sanitize(image: &mut [u8; LEGACY_FLOATING_POINT_BYTES], mxcsr: u32) {
    let fcw = u16::from_le_bytes(image[..2].try_into().unwrap()) & NT5_FCW_MASK;
    image[..2].copy_from_slice(&fcw.to_le_bytes());
    image[FX_MXCSR_OFFSET..FX_MXCSR_OFFSET + 4]
        .copy_from_slice(&(mxcsr & NT5_MXCSR_MASK).to_le_bytes());
}

#[cfg(test)]
mod tests;
