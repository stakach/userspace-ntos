//! Byte-exact AMD64 NT `CONTEXT` boundary for native capture and handler calls.
//!
//! The pure [`Context`](crate::Context) intentionally models only GPRs, RIP, and XMM registers.
//! Native adapters must retain this raw record across a walk so unmodelled home slots, segment and
//! debug registers, FPU legacy state, vector state, and branch records survive unchanged.
//! Offsets follow NT5/ReactOS `CONTEXT` (`references/reactos/sdk/include/xdk/amd64/ke.h`).

use crate::{Context, StackReader, REG_RSP};
use core::mem::{align_of, offset_of, size_of};

pub const RAW_CONTEXT_SIZE: usize = 0x4d0;
const FLAGS_OFFSET: usize = 0x30;
const MXCSR_OFFSET: usize = 0x34;
const SEGMENTS_OFFSET: usize = 0x38;
const EFLAGS_OFFSET: usize = 0x44;
const GPR_OFFSET: usize = 0x78;
const RIP_OFFSET: usize = 0xf8;
const FXSAVE_MXCSR_OFFSET: usize = 0x118;
const FXSAVE_MXCSR_MASK_OFFSET: usize = 0x11c;
const XMM_OFFSET: usize = 0x1a0;
const FXSAVE_OFFSET: usize = 0x100;
const DEBUG_OFFSET: usize = 0x48;

/// Control, integer, and floating-point state in the NT AMD64 `ContextFlags` field.
pub const CONTEXT_AMD64_FULL: u32 = 0x0010_000b;
pub const CONTEXT_AMD64_FULL_SEGMENTS: u32 = CONTEXT_AMD64_FULL | 0x4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RawContextCaptureError {
    Unaligned,
    OutOfBounds,
    Unreadable,
    InvalidFlags,
}

/// An invalid atomic x86-64 legacy-context snapshot from the microkernel.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LegacyContextError {
    ReservedRegisters,
    Eflags,
    Mxcsr,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RawContextRestoreError {
    InvalidFlags,
    Stack,
    InstructionAddress,
    Segments,
    Eflags,
    Mxcsr,
}

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
    assert!(offset_of!(Nt5ContextLayout, segments) == SEGMENTS_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, eflags) == EFLAGS_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, gpr) == GPR_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, rip) == RIP_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, fxsave) + 0x18 == FXSAVE_MXCSR_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, fxsave) + 0xa0 == XMM_OFFSET);
    assert!(offset_of!(Nt5ContextLayout, vector) == 0x300);
    assert!(offset_of!(Nt5ContextLayout, tail) == 0x4a0);
};

impl RawContext {
    /// Copy one complete native record from an authenticated stack reader before the caller
    /// releases its physical dispatch lease. No partial record escapes on a failed word read.
    pub fn capture_bounded(
        reader: &dyn StackReader,
        address: u64,
        stack_low: u64,
        stack_high: u64,
    ) -> Result<Self, RawContextCaptureError> {
        if address & 15 != 0 {
            return Err(RawContextCaptureError::Unaligned);
        }
        let end = address
            .checked_add(RAW_CONTEXT_SIZE as u64)
            .ok_or(RawContextCaptureError::OutOfBounds)?;
        if stack_low >= stack_high || address < stack_low || end > stack_high {
            return Err(RawContextCaptureError::OutOfBounds);
        }
        let mut context = Self::zeroed();
        for (index, word) in context.bytes.chunks_exact_mut(8).enumerate() {
            let location = address + (index * 8) as u64;
            let value = reader
                .read_u64(location)
                .ok_or(RawContextCaptureError::Unreadable)?;
            word.copy_from_slice(&value.to_le_bytes());
        }
        if context.context_flags() & CONTEXT_AMD64_FULL != CONTEXT_AMD64_FULL {
            return Err(RawContextCaptureError::InvalidFlags);
        }
        Ok(context)
    }

    /// Convert one atomic seL4 x86-64 legacy-context read to an NT CONTEXT. The kernel reports
    /// public registers in seL4 order, an exact FXSAVE64 image, and DR0-3/DR6/DR7. It does not
    /// report segment selectors, so this record advertises FULL, not SEGMENTS; no selector is
    /// guessed from the executive's own thread.
    pub fn from_legacy_snapshot(
        registers: &[u64; 20],
        floating_point: &[u8; 0x200],
        debug: &[u64; 6],
    ) -> Result<Self, LegacyContextError> {
        if registers[18] != 0 || registers[19] != 0 {
            return Err(LegacyContextError::ReservedRegisters);
        }
        if registers[2] >> 32 != 0 || registers[2] & 2 == 0 {
            return Err(LegacyContextError::Eflags);
        }
        let mxcsr = u32::from_le_bytes(floating_point[24..28].try_into().unwrap());
        let reported_mask = u32::from_le_bytes(floating_point[28..32].try_into().unwrap());
        let mask = if reported_mask == 0 {
            0xffbf
        } else {
            reported_mask
        };
        if mxcsr & !mask != 0 {
            return Err(LegacyContextError::Mxcsr);
        }
        let mut raw = Self::zeroed();
        raw.set_context_flags(CONTEXT_AMD64_FULL);
        raw.set_eflags(registers[2] as u32);
        raw.bytes[FXSAVE_OFFSET..FXSAVE_OFFSET + floating_point.len()]
            .copy_from_slice(floating_point);
        raw.write_u32(MXCSR_OFFSET, mxcsr);
        for (index, value) in debug.iter().enumerate() {
            raw.write_u64(DEBUG_OFFSET + index * 8, *value);
        }
        // seL4 UserContext order: RIP, RSP, RFLAGS, RAX, RBX, RCX, RDX, RSI, RDI, RBP,
        // R8..R15. NT's ABI register indices instead follow the AMD64 unwind numbering.
        let abi_to_legacy = [3, 5, 6, 4, 1, 9, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17];
        for (abi_index, legacy_index) in abi_to_legacy.into_iter().enumerate() {
            raw.set_gpr(abi_index, registers[legacy_index]);
        }
        raw.set_rip(registers[0]);
        Ok(raw)
    }

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

    /// Segment index `0=CS, 1=DS, 2=ES, 3=FS, 4=GS, 5=SS`.
    pub fn segment(&self, index: usize) -> Option<u16> {
        (index < 6).then(|| self.read_u16(SEGMENTS_OFFSET + index * 2))
    }

    pub fn set_segment(&mut self, index: usize, value: u16) -> bool {
        if index >= 6 {
            return false;
        }
        self.write_u16(SEGMENTS_OFFSET + index * 2, value);
        true
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

    /// Validate a handler-modified record against its owned capture before native restore.
    /// The caller must additionally authenticate the lane and writable stack mapping under its
    /// physical dispatch lease; `admitted_pc` must consult that same instance's executable map.
    pub fn validate_restore(
        &self,
        captured: &Self,
        stack_low: u64,
        stack_high: u64,
        admitted_pc: impl FnOnce(u64) -> bool,
    ) -> Result<(), RawContextRestoreError> {
        if self.context_flags() & CONTEXT_AMD64_FULL != CONTEXT_AMD64_FULL
            || self.context_flags() != captured.context_flags()
        {
            return Err(RawContextRestoreError::InvalidFlags);
        }
        let rsp = self.rsp();
        if rsp & 7 != 0
            || stack_low >= stack_high
            || rsp
                .checked_sub(32)
                .is_none_or(|scratch| scratch < stack_low)
            || rsp > stack_high
        {
            return Err(RawContextRestoreError::Stack);
        }
        let rip = self.rip();
        let sign_extension = if rip & (1 << 47) != 0 { 0xffff } else { 0 };
        if rip >> 48 != sign_extension || !admitted_pc(rip) {
            return Err(RawContextRestoreError::InstructionAddress);
        }
        if captured.context_flags() & 0x4 != 0
            && (0..6).any(|index| self.segment(index) != captured.segment(index))
        {
            return Err(RawContextRestoreError::Segments);
        }
        // POPFQ may update arithmetic status flags. Keep direction, interrupt, trap, IOPL,
        // and all reserved bits exactly as they were in the authenticated capture.
        const ARITHMETIC_FLAGS: u32 = 0x8d5;
        if captured.eflags() & 2 == 0
            || (self.eflags() ^ captured.eflags()) & !ARITHMETIC_FLAGS != 0
        {
            return Err(RawContextRestoreError::Eflags);
        }
        let mask = match captured.read_u32(FXSAVE_MXCSR_MASK_OFFSET) {
            0 => 0xffbf,
            value => value,
        };
        let mxcsr = self.mxcsr();
        if mxcsr != self.read_u32(FXSAVE_MXCSR_OFFSET) || mxcsr & !mask != 0 {
            return Err(RawContextRestoreError::Mxcsr);
        }
        Ok(())
    }

    fn read_u32(&self, offset: usize) -> u32 {
        let mut value = [0; 4];
        value.copy_from_slice(&self.bytes[offset..offset + 4]);
        u32::from_le_bytes(value)
    }

    fn read_u16(&self, offset: usize) -> u16 {
        let mut value = [0; 2];
        value.copy_from_slice(&self.bytes[offset..offset + 2]);
        u16::from_le_bytes(value)
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
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
    use core::cell::Cell;

    struct MockStack {
        base: u64,
        bytes: [u8; RAW_CONTEXT_SIZE],
        fail_word: Option<usize>,
        reads: Cell<usize>,
    }

    impl StackReader for MockStack {
        fn read_u64(&self, address: u64) -> Option<u64> {
            self.reads.set(self.reads.get() + 1);
            let offset = address.checked_sub(self.base)? as usize;
            if offset & 7 != 0 || self.fail_word == Some(offset / 8) {
                return None;
            }
            let word: [u8; 8] = self.bytes.get(offset..offset + 8)?.try_into().ok()?;
            Some(u64::from_le_bytes(word))
        }
    }

    fn mock_stack() -> MockStack {
        let mut raw = RawContext::from_bytes([0xa5; RAW_CONTEXT_SIZE]);
        raw.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
        MockStack {
            base: 0x2000,
            bytes: *raw.as_bytes(),
            fail_word: None,
            reads: Cell::new(0),
        }
    }

    #[test]
    fn bounded_capture_copies_exact_native_record() {
        let stack = mock_stack();
        let captured = RawContext::capture_bounded(&stack, 0x2000, 0x2000, 0x24d0).unwrap();
        assert_eq!(captured.as_bytes(), &stack.bytes);
        assert_eq!(stack.reads.get(), RAW_CONTEXT_SIZE / 8);
    }

    #[test]
    fn bounded_capture_rejects_alignment_extent_and_unreadable_words() {
        let stack = mock_stack();
        for (address, low, high, error) in [
            (0x2001, 0x2000, 0x24d0, RawContextCaptureError::Unaligned),
            (0x2000, 0x2001, 0x24d0, RawContextCaptureError::OutOfBounds),
            (0x2000, 0x2000, 0x24cf, RawContextCaptureError::OutOfBounds),
            (0x2000, 0x24d0, 0x2000, RawContextCaptureError::OutOfBounds),
            (
                u64::MAX & !15,
                0,
                u64::MAX,
                RawContextCaptureError::OutOfBounds,
            ),
        ] {
            assert_eq!(
                RawContext::capture_bounded(&stack, address, low, high),
                Err(error)
            );
        }
        assert_eq!(stack.reads.get(), 0);

        let mut stack = mock_stack();
        stack.fail_word = Some(RAW_CONTEXT_SIZE / 8 - 1);
        assert_eq!(
            RawContext::capture_bounded(&stack, 0x2000, 0x2000, 0x24d0),
            Err(RawContextCaptureError::Unreadable)
        );
        assert_eq!(stack.reads.get(), RAW_CONTEXT_SIZE / 8);
    }

    #[test]
    fn bounded_capture_requires_full_integer_and_float_flags() {
        let mut stack = mock_stack();
        stack.bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4]
            .copy_from_slice(&0x0010_0009u32.to_le_bytes());
        assert_eq!(
            RawContext::capture_bounded(&stack, 0x2000, 0x2000, 0x24d0),
            Err(RawContextCaptureError::InvalidFlags)
        );
        stack.bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4]
            .copy_from_slice(&CONTEXT_AMD64_FULL.to_le_bytes());
        assert!(RawContext::capture_bounded(&stack, 0x2000, 0x2000, 0x24d0).is_ok());
    }

    #[test]
    fn legacy_snapshot_maps_every_register_and_preserves_exact_fx_and_debug_state() {
        let mut registers = [0u64; 20];
        for (index, value) in registers[..18].iter_mut().enumerate() {
            *value = 0x1000 + index as u64;
        }
        registers[2] = 0x246;
        let mut fx = [0u8; 0x200];
        fx[..2].copy_from_slice(&0x37fu16.to_le_bytes());
        fx[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        fx[28..32].copy_from_slice(&0xffbfu32.to_le_bytes());
        for (index, byte) in fx[32..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        let debug = [0x11, 0x22, 0x33, 0x44, 0x66, 0x77];
        let raw = RawContext::from_legacy_snapshot(&registers, &fx, &debug).unwrap();
        assert_eq!(raw.context_flags(), CONTEXT_AMD64_FULL);
        assert!(raw.as_bytes()[SEGMENTS_OFFSET..SEGMENTS_OFFSET + 12].iter().all(|b| *b == 0));
        assert_eq!(raw.rip(), registers[0]);
        assert_eq!(raw.eflags(), 0x246);
        assert_eq!(raw.mxcsr(), 0x1f80);
        assert_eq!(
            &raw.as_bytes()[FXSAVE_OFFSET..FXSAVE_OFFSET + 0x200],
            &fx
        );
        for (index, value) in debug.iter().enumerate() {
            assert_eq!(raw.read_u64(DEBUG_OFFSET + index * 8), *value);
        }
        for (abi_index, legacy_index) in
            [3, 5, 6, 4, 1, 9, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17]
                .into_iter()
                .enumerate()
        {
            assert_eq!(raw.gpr(abi_index), Some(registers[legacy_index]));
        }
        for index in 0..16 {
            let offset = 0xa0 + index * 16;
            assert_eq!(
                raw.xmm(index).unwrap()[0],
                u64::from_le_bytes(fx[offset..offset + 8].try_into().unwrap())
            );
            assert_eq!(
                raw.xmm(index).unwrap()[1],
                u64::from_le_bytes(fx[offset + 8..offset + 16].try_into().unwrap())
            );
        }
    }

    #[test]
    fn legacy_snapshot_rejects_malformed_control_state_without_mutation() {
        let mut registers = [0u64; 20];
        registers[2] = 0x202;
        let mut fx = [0u8; 0x200];
        fx[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        let debug = [0u64; 6];
        let original_fx = fx;
        registers[18] = 1;
        assert_eq!(
            RawContext::from_legacy_snapshot(&registers, &fx, &debug),
            Err(LegacyContextError::ReservedRegisters)
        );
        registers[18] = 0;
        registers[2] = 0x200;
        assert_eq!(
            RawContext::from_legacy_snapshot(&registers, &fx, &debug),
            Err(LegacyContextError::Eflags)
        );
        registers[2] = 0x1_0000_0202;
        assert_eq!(
            RawContext::from_legacy_snapshot(&registers, &fx, &debug),
            Err(LegacyContextError::Eflags)
        );
        registers[2] = 0x202;
        fx[24..28].copy_from_slice(&0x1_0000u32.to_le_bytes());
        assert_eq!(
            RawContext::from_legacy_snapshot(&registers, &fx, &debug),
            Err(LegacyContextError::Mxcsr)
        );
        assert_eq!(fx[28..32], original_fx[28..32]);
    }

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
    fn segment_fields_are_byte_exact_and_separate_from_full_flags() {
        let mut raw = RawContext::zeroed();
        raw.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
        for index in 0..6 {
            assert!(raw.set_segment(index, 0x20 + index as u16));
            assert_eq!(raw.segment(index), Some(0x20 + index as u16));
            assert_eq!(
                &raw.as_bytes()[SEGMENTS_OFFSET + index * 2..SEGMENTS_OFFSET + index * 2 + 2],
                &(0x20 + index as u16).to_le_bytes()
            );
        }
        assert_eq!(raw.context_flags(), 0x0010_000f);
        assert_eq!(raw.segment(6), None);
        assert!(!raw.set_segment(6, 0));
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

    fn restore_fixture() -> RawContext {
        let mut raw = RawContext::zeroed();
        raw.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
        raw.set_rsp(0x3000);
        raw.set_rip(0x4000);
        raw.set_eflags(0x202);
        raw.set_mxcsr(0x1f80);
        raw.write_u32(FXSAVE_MXCSR_MASK_OFFSET, 0xffbf);
        for index in 0..6 {
            raw.set_segment(index, 0x20 + index as u16);
        }
        raw
    }

    fn validate_fixture(
        raw: &RawContext,
        captured: &RawContext,
    ) -> Result<(), RawContextRestoreError> {
        raw.validate_restore(captured, 0x2fe0, 0x4000, |rip| rip == 0x4000)
    }

    #[test]
    fn restore_accepts_status_flags_and_register_updates() {
        let captured = restore_fixture();
        let mut restored = captured.clone();
        restored.set_eflags(0x202 | 0x8d5);
        restored.set_gpr(0, 0x1234);
        restored.set_xmm(15, [0x5678, 0x9abc]);
        assert_eq!(validate_fixture(&restored, &captured), Ok(()));
    }

    #[test]
    fn restore_rejects_unowned_stack_and_unadmitted_pc() {
        let captured = restore_fixture();
        let mut restored = captured.clone();
        restored.set_rsp(0x2ff8);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Stack)
        );
        restored.set_rsp(0x3001);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Stack)
        );
        restored.set_rsp(0x3000);
        restored.set_rip(0x5000);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::InstructionAddress)
        );
        restored.set_rip(0x0001_0000_0000_0000);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::InstructionAddress)
        );
    }

    #[test]
    fn restore_rejects_changed_control_state() {
        let captured = restore_fixture();
        let mut restored = captured.clone();
        restored.set_context_flags(CONTEXT_AMD64_FULL);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::InvalidFlags)
        );
        restored = captured.clone();
        restored.set_segment(0, 0);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Segments)
        );
        restored = captured.clone();
        restored.set_eflags(0x602);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Eflags)
        );
        restored = captured.clone();
        restored.set_mxcsr(0x11f80);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Mxcsr)
        );
        restored = captured.clone();
        restored.write_u32(FXSAVE_MXCSR_OFFSET, 0);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::Mxcsr)
        );
    }

    #[test]
    fn restore_accepts_valid_full_context_without_claiming_segment_selectors() {
        let mut captured = restore_fixture();
        captured.set_context_flags(CONTEXT_AMD64_FULL);
        let mut restored = captured.clone();
        restored.set_gpr(0, 0x1234);
        restored.set_segment(0, 0x99);
        assert_eq!(validate_fixture(&restored, &captured), Ok(()));
        restored.set_context_flags(CONTEXT_AMD64_FULL_SEGMENTS);
        assert_eq!(
            validate_fixture(&restored, &captured),
            Err(RawContextRestoreError::InvalidFlags)
        );
        let mut invalid = captured.clone();
        invalid.set_context_flags(0x0010_0009);
        assert_eq!(
            validate_fixture(&invalid, &invalid),
            Err(RawContextRestoreError::InvalidFlags)
        );
    }
}
