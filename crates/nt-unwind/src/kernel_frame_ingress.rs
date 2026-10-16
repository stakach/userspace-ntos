//! Exact Win64 entry state for a hosted kernel provider's native frame walk.
//!
//! The packet is only a snapshot of registers and request words. Its addresses do not grant
//! memory access: the executive must acquire the exact paused physical lane, validate the return
//! slot through its stack reader, and keep that lease while reading images and publishing output.

use crate::Context;

pub const FRAME_INGRESS_MAGIC: u64 = 0x4b46_5241_4d45_3031; // "KFRAME01"
pub const FRAME_INGRESS_WORDS: usize = 32;
pub const FRAME_INGRESS_BYTES: usize = FRAME_INGRESS_WORDS * 8;
/// One native walk is bounded so a malicious Count or high-byte skip cannot occupy a lane forever.
pub const FRAME_CHAIN_RESULT_CAPACITY: usize = 128;

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
            || flags & 0xff != 0 // user transition requires a distinct attached-user owner
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
