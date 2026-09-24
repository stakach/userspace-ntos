//! Byte-exact AMD64 NT `CONTEXT` boundary for native capture and handler calls.
//!
//! The pure [`Context`](crate::Context) intentionally models only GPRs, RIP, and XMM registers.
//! Native adapters must retain this raw record across a walk so unmodelled home slots, segment and
//! debug registers, FPU legacy state, vector state, and branch records survive unchanged.
//! Offsets follow NT5/ReactOS `CONTEXT` (`references/reactos/sdk/include/xdk/amd64/ke.h`).

use crate::{Context, REG_RSP};
use core::mem::{align_of, offset_of, size_of};

pub const RAW_CONTEXT_SIZE: usize = 0x4d0;
const FLAGS_OFFSET: usize = 0x30;
const MXCSR_OFFSET: usize = 0x34;
const EFLAGS_OFFSET: usize = 0x44;
const GPR_OFFSET: usize = 0x78;
const RIP_OFFSET: usize = 0xf8;
const FXSAVE_MXCSR_OFFSET: usize = 0x118;
const XMM_OFFSET: usize = 0x1a0;

/// Control, integer, and floating-point state in the NT AMD64 `ContextFlags` field.
pub const CONTEXT_AMD64_FULL: u32 = 0x0010_000b;

/// Opaque native record. No Rust reference to a typed register field is formed from raw bytes.
#[repr(C, align(16))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawContext {
    bytes: [u8; RAW_CONTEXT_SIZE],
}

// This layout is used only for independent compile-time checks of the published NT5 offsets.
#[repr(C, align(16))]
#[allow(dead_code)]
struct Nt5ContextLayout {
    home: [u64; 6],
    flags: u32,
    mxcsr: u32,
    segments: [u16; 6],
    eflags: u32,
    debug: [u64; 6],
    gpr: [u64; 16],
    rip: u64,
    fxsave: [u8; 0x200],
    vector: [u8; 0x1a0],
    tail: [u64; 6],
}

const _: () = {
    assert!(size_of::<RawContext>() == RAW_CONTEXT_SIZE);
    assert!(align_of::<RawContext>() == 16);
    assert!(size_of::<Nt5ContextLayout>() == RAW_CONTEXT_SIZE);
    assert!(align_of::<Nt5ContextLayout>() == 16);
    assert!(offset_of!(Nt5ContextLayout, flags) == FLAGS_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, mxcsr) == MXCSR_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, eflags) == EFLAGS_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, gpr) == GPR_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, rip) == RIP_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, fxsave) + 0x18 == FXSAVE_MXCSR_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, fxsave) + 0xa0 == XMM_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, vector) == 0x300);
    assert!(offset_of!(Nt5ContextLayout, tail) == 0x4a0);
};

impl RawContext {
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0; RAW_CONTEXT_SIZE],
        }
    }

    pub const fn from_bytes(bytes: [u8; RAW_CONTEXT_SIZE]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; RAW_CONTEXT_SIZE] {
        &self.bytes
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; RAW_CONTEXT_SIZE] {
        &mut self.bytes
    }

    pub fn context_flags(&self) -> u32 {
        self.read_u32(FLAGS_OFFSET)
    }

    pub fn set_context_flags(&mut self, flags: u32) {
        self.write_u32(FLAGS_OFFSET, flags);
    }

    pub fn mxcsr(&self) -> u32 {
        self.read_u32(MXCSR_OFFSET)
    }

    /// Update both the top-level field and its copy in the embedded FXSAVE area.
    pub fn set_mxcsr(&mut self, value: u32) {
        self.write_u32(MXCSR_OFFSET, value);
        self.write_u32(FXSAVE_MXCSR_OFFSET, value);
    }

    pub fn eflags(&self) -> u32 {
        self.read_u32(EFLAGS_OFFSET)
    }

    pub fn set_eflags(&mut self, value: u32) {
        self.write_u32(EFLAGS_OFFSET, value);
    }

    /// ABI register index `0=RAX .. 15=R15`.
    pub fn gpr(&self, index: usize) -> Option<u64> {
        (index < 16).then(|| self.read_u64(GPR_OFFSET + index * 8))
    }

    pub fn set_gpr(&mut self, index: usize, value: u64) -> bool {
        if index >= 16 {
            return false;
        }
        self.write_u64(GPR_OFFSET + index * 8, value);
        true
    }

    pub fn rsp(&self) -> u64 {
        self.gpr(REG_RSP).expect("RSP is an ABI register")
    }

    pub fn set_rsp(&mut self, value: u64) {
        self.set_gpr(REG_RSP, value);
    }

    pub fn rip(&self) -> u64 {
        self.read_u64(RIP_OFFSET)
    }

    pub fn set_rip(&mut self, value: u64) {
        self.write_u64(RIP_OFFSET, value);
    }

    pub fn xmm(&self, index: usize) -> Option<[u64; 2]> {
        (index < 16).then(|| {
            let offset = XMM_OFFSET + index * 16;
            [self.read_u64(offset), self.read_u64(offset + 8)]
        })
    }

    pub fn set_xmm(&mut self, index: usize, value: [u64; 2]) -> bool {
        if index >= 16 {
            return false;
        }
        let offset = XMM_OFFSET + index * 16;
        self.write_u64(offset, value[0]);
        self.write_u64(offset + 8, value[1]);
        true
    }

    pub fn to_context(&self) -> Context {
        let mut context = Context::default();
        for index in 0..16 {
            context.gpr[index] = self.gpr(index).expect("valid ABI register");
            context.xmm[index] = self.xmm(index).expect("valid XMM register");
        }
        context.rip = self.rip();
        context
    }

    /// Write modeled registers back into this record, retaining every other native field.
    pub fn update_from_context(&mut self, context: &Context) {
        for index in 0..16 {
            self.set_gpr(index, context.gpr[index]);
            self.set_xmm(index, context.xmm[index]);
        }
        self.set_rip(context.rip);
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut value = [0; 4];
        value.copy_from_slice(&self.bytes[offset..offset + 4]);
        u32::from_le_bytes(value)
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u64(&self, offset: usize) -> u64 {
        let mut value = [0; 8];
        value.copy_from_slice(&self.bytes[offset..offset + 8]);
        u64::from_le_bytes(value)
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_offsets_and_out_of_range_indices() {
        let mut raw = RawContext::zeroed();
        raw.set_context_flags(CONTEXT_AMD64_FULL);
        raw.set_mxcsr(0x1f80);
        raw.set_eflags(0x202);
        raw.set_gpr(0, 0x1122_3344_5566_7788);
        raw.set_rsp(0x1234_5678);
        raw.set_rip(0x8765_4321);
        raw.set_xmm(15, [0xaabb_ccdd, 0xeeff_0011]);
        assert_eq!(raw.context_flags(), CONTEXT_AMD64_FULL);
        assert_eq!(raw.mxcsr(), 0x1f80);
        assert_eq!(raw.eflags(), 0x202);
        assert_eq!(raw.gpr(0), Some(0x1122_3344_5566_7788));
        assert_eq!(raw.rsp(), 0x1234_5678);
        assert_eq!(raw.rip(), 0x8765_4321);
        assert_eq!(raw.xmm(15), Some([0xaabb_ccdd, 0xeeff_0011]));
        assert_eq!(
            &raw.as_bytes()[GPR_OFFSET..GPR_OFFSET + 8],
            &0x1122_3344_5566_7788u64.to_le_bytes()
        );
        assert_eq!(
            &raw.as_bytes()[FXSAVE_MXCSR_OFFSET..FXSAVE_MXCSR_OFFSET + 4],
            &0x1f80u32.to_le_bytes()
        );
        assert_eq!(raw.gpr(16), None);
        assert_eq!(raw.xmm(16), None);
        assert!(!raw.set_gpr(16, 1));
        assert!(!raw.set_xmm(16, [1, 2]));
    }

    #[test]
    fn pure_context_roundtrip_preserves_every_unmodelled_byte() {
        let mut raw = RawContext::from_bytes([0xa5; RAW_CONTEXT_SIZE]);
        let mut context = Context::default();
        for index in 0..16 {
            context.gpr[index] = 0x1000 + index as u64;
            context.xmm[index] = [0x2000 + index as u64, 0x3000 + index as u64];
        }
        context.rip = 0x4000;
        raw.update_from_context(&context);
        assert_eq!(raw.to_context(), context);
        for (offset, byte) in raw.as_bytes().iter().enumerate() {
            let modeled = (GPR_OFFSET..RIP_OFFSET + 8).contains(&offset)
                || (XMM_OFFSET..XMM_OFFSET + 16 * 16).contains(&offset);
            if !modeled {
                assert_eq!(*byte, 0xa5, "unmodelled byte at {offset:#x}");
            }
        }
    }
}
