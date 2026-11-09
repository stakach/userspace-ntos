//! Checked placement of a hosted IRQ lane's private request and argument banks.

use crate::{HostedWorkerBankLayout, HOSTED_IRQ_ARENA_BYTES, PAGE_SIZE};

/// Physical IRQ workers share a driver address space. Their request bank must fit beyond the
/// lane's typed arena; the native owner also verifies that its absolute range is distinct from
/// the ordinary driver bank and validates the exact lane generation before using it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqPrivateBankLayout {
    shared_offset: u64,
    shared_end: u64,
    arg_offset: u64,
    arg_end: u64,
}

impl HostedIrqPrivateBankLayout {
    pub const fn new(
        arena_offset: u64,
        shared_offset: u64,
        shared_frames: u64,
        arg_offset: u64,
        arg_frames: u64,
        worker_stride: u64,
    ) -> Option<Self> {
        if arena_offset & (PAGE_SIZE - 1) != 0 {
            return None;
        }
        let Some(arena_end) = arena_offset.checked_add(HOSTED_IRQ_ARENA_BYTES) else {
            return None;
        };
        if shared_offset < arena_end {
            return None;
        }
        let Some(worker) = HostedWorkerBankLayout::new(
            shared_offset,
            shared_frames,
            Some(arg_offset),
            arg_frames,
            worker_stride,
        ) else {
            return None;
        };
        let Some(arg_end) = worker.arg_end() else {
            return None;
        };
        Some(Self {
            shared_offset,
            shared_end: worker.bank_end(),
            arg_offset,
            arg_end,
        })
    }

    pub const fn shared_offset(self) -> u64 {
        self.shared_offset
    }
    pub const fn shared_end(self) -> u64 {
        self.shared_end
    }
    pub const fn arg_offset(self) -> u64 {
        self.arg_offset
    }
    pub const fn arg_end(self) -> u64 {
        self.arg_end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARENA: u64 = 0x43000;
    const SHARED: u64 = 0x65000;
    const ARG: u64 = 0x67000;
    const STRIDE: u64 = 0x200000;

    #[test]
    fn private_banks_fit_after_the_complete_irq_arena() {
        let layout = HostedIrqPrivateBankLayout::new(ARENA, SHARED, 2, ARG, 4, STRIDE)
            .expect("two private shared and four argument pages fit after the arena");
        assert_eq!(ARENA + HOSTED_IRQ_ARENA_BYTES, 0x64000);
        assert_eq!(layout.shared_offset(), SHARED);
        assert_eq!(layout.shared_end(), ARG);
        assert_eq!(layout.arg_offset(), ARG);
        assert_eq!(layout.arg_end(), 0x6b000);
    }

    #[test]
    fn overlapping_or_escaping_banks_are_rejected() {
        assert!(HostedIrqPrivateBankLayout::new(ARENA, 0x63000, 2, ARG, 4, STRIDE).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA, SHARED, 2, 0x66000, 4, STRIDE).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA, SHARED + 1, 2, ARG, 4, STRIDE).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA + 1, SHARED, 2, ARG, 4, STRIDE).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA, SHARED, 2, ARG, 4, 0x6a000).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA, SHARED, 0, ARG, 4, STRIDE).is_none());
        assert!(HostedIrqPrivateBankLayout::new(ARENA, SHARED, 2, ARG, 0, STRIDE).is_none());
    }

    #[test]
    fn arithmetic_overflow_cannot_publish_a_partial_layout() {
        assert!(HostedIrqPrivateBankLayout::new(
            u64::MAX - PAGE_SIZE + 1,
            SHARED,
            2,
            ARG,
            4,
            STRIDE,
        )
        .is_none());
        assert!(
            HostedIrqPrivateBankLayout::new(ARENA, SHARED, u64::MAX, ARG, 4, STRIDE,).is_none()
        );
        assert!(
            HostedIrqPrivateBankLayout::new(ARENA, SHARED, 2, ARG, u64::MAX, STRIDE,).is_none()
        );
    }
}
