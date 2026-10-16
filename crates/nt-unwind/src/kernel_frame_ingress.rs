//! Exact Win64 entry state for a hosted kernel provider's native frame walk.
//!
//! The packet is only a snapshot of registers and request words. Its addresses do not grant
//! memory access: the executive must acquire the exact paused physical lane, validate the return
//! slot through its stack reader, and keep that lease while reading images and publishing output.

use crate::{Context, StackReader};

pub const FRAME_INGRESS_MAGIC: u64 = 0x4b46_5241_4d45_3031; // "KFRAME01"
pub const FRAME_INGRESS_WORDS: usize = 32;
pub const FRAME_INGRESS_BYTES: usize = FRAME_INGRESS_WORDS * 8;
/// One native walk is bounded so a malicious Count or high-byte skip cannot occupy a lane forever.
pub const FRAME_CHAIN_RESULT_CAPACITY: usize = 128;
/// Results are staged after the captured register header in the same retained provider stack.
pub const FRAME_RESULT_OFFSET: usize = FRAME_INGRESS_BYTES;
pub const FRAME_PACKET_BYTES: usize = FRAME_RESULT_OFFSET + FRAME_CHAIN_RESULT_CAPACITY * 8;

/// A copied provider packet; only the sealed lane reader may supply its words.
///
/// Layout: magic, entry RSP, opaque caller output VA, Count|Flags<<32, RBX/RBP/RSI/RDI/R12-R15,
/// then XMM6-XMM15 (two u64 words each). The native entry shim writes this exact layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(16))]
pub struct KernelFrameIngressPacket {
    words: [u64; FRAME_INGRESS_WORDS],
}

impl KernelFrameIngressPacket {
    /// Copy through a reader tied to one live physical lane. The result suffix and return slot
    /// must both fit in that lane; address equality alone cannot authenticate the backing route.
    pub fn capture_bounded(
        packet_va: u64,
        stack_low: u64,
        stack_high: u64,
        stack: &dyn StackReader,
    ) -> Option<Self> {
        let packet_end = packet_va.checked_add(FRAME_PACKET_BYTES as u64)?;
        let entry_rsp = packet_end.checked_add(8)?;
        if packet_va & 15 != 0
            || packet_va < stack_low
            || entry_rsp.checked_add(8)? > stack_high
        {
            return None;
        }
        let mut words = [0u64; FRAME_INGRESS_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            *word = stack.read_u64(packet_va + index as u64 * 8)?;
        }
        let packet = Self::from_words(&words)?;
        (packet.entry_rsp() == entry_rsp).then_some(packet)
    }

    /// Validate structural fields before consulting the separately authenticated lane and image.
    pub fn from_words(words: &[u64]) -> Option<Self> {
        let words: [u64; FRAME_INGRESS_WORDS] = words.try_into().ok()?;
        let entry_rsp = words[1];
        let count = words[3] as u32 as usize;
        let flags = (words[3] >> 32) as u32;
        let skip = (flags >> 8) as usize;
        if words[0] != FRAME_INGRESS_MAGIC
            || entry_rsp & 7 != 0
            || entry_rsp.checked_add(8).is_none()
            || flags & 0xfe != 0 // only bit 0 may request a separately owned user transition
            || count.checked_add(skip)? > FRAME_CHAIN_RESULT_CAPACITY
            || (count != 0 && (words[2] == 0 || words[2] & 7 != 0))
        {
            return None;
        }
        Some(Self { words })
    }

    pub const fn entry_rsp(&self) -> u64 {
        self.words[1]
    }

    /// Opaque component-side destination. The executive must never dereference this as its VA.
    pub const fn callers(&self) -> u64 {
        self.words[2]
    }

    pub const fn count(&self) -> u32 {
        self.words[3] as u32
    }

    pub const fn flags(&self) -> u32 {
        (self.words[3] >> 32) as u32
    }

    /// Maximum reported count, including proven skipped frames per the native contract.
    pub const fn walk_capacity(&self) -> u32 {
        self.count() + (self.flags() >> 8)
    }

    /// Number of output slots the broker must have populated for a successful native reply.
    /// The reported count includes skipped frames; only the post-skip suffix is copied to the
    /// caller-owned destination after the provider resumes.
    pub const fn published_result_count(&self, reported: u32) -> Option<usize> {
        if reported > self.walk_capacity() {
            return None;
        }
        let skipped = self.flags() >> 8;
        Some(reported.saturating_sub(skipped) as usize)
    }

    /// Construct only the return-site state needed by the pure x64 unwind engine. `return_pc`
    /// must first be read from `entry_rsp` under the exact lane lease and admitted image catalog.
    pub fn context_at_return(&self, return_pc: u64) -> Context {
        let mut context = Context::default();
        context.rip = return_pc;
        context.set_rsp(self.entry_rsp() + 8);
        for (slot, register) in [3, 5, 6, 7, 12, 13, 14, 15].into_iter().enumerate() {
            context.gpr[register] = self.words[4 + slot];
        }
        for xmm in 6..=15 {
            let first = 12 + (xmm - 6) * 2;
            context.xmm[xmm] = [self.words[first], self.words[first + 1]];
        }
        context
    }
}
