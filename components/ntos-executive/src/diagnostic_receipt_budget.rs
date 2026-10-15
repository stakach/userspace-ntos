//! Allocation-free window and lifetime limits for diagnostic observations only.
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const RECEIPT_LIMIT: u64 = 128;
pub(crate) const LIFETIME_RECEIPT_LIMIT: u64 = 8192;
const WINDOW_100NS: u64 = 60 * 10_000_000;
const COUNT_BITS: u32 = 8;
const LIFETIME_BITS: u32 = 14;
const EPOCH_BITS: u32 = 35;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;
const LIFETIME_MASK: u64 = (1 << LIFETIME_BITS) - 1;
const EPOCH_MASK: u64 = (1 << EPOCH_BITS) - 1;
const EPOCH_SHIFT: u32 = COUNT_BITS + LIFETIME_BITS;
const CLOCK_KNOWN: u64 = 1 << (EPOCH_SHIFT + EPOCH_BITS);
const _: () = assert!(RECEIPT_LIMIT <= COUNT_MASK);
const _: () = assert!(LIFETIME_RECEIPT_LIMIT <= LIFETIME_MASK);
const _: () = assert!(u64::MAX / WINDOW_100NS <= EPOCH_MASK);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BudgetReceipt {
    pub(crate) receipt: u64,
    pub(crate) lifetime_receipt: u64,
    pub(crate) window: Option<u64>,
}

/// Window and lifetime claims share one CAS, so contention cannot consume a partial claim.
pub(crate) struct ReceiptBudget {
    state: AtomicU64,
}

impl ReceiptBudget {
    pub(crate) const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    pub(crate) fn claim(&self, now: Option<u64>) -> Option<BudgetReceipt> {
        let previous = self.state.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
            next_claim(state, now).map(|(next, _)| next)
        }).ok()?;
        next_claim(previous, now).map(|(_, receipt)| receipt)
    }
}

fn next_claim(state: u64, now: Option<u64>) -> Option<(u64, BudgetReceipt)> {
    let mut count = state & COUNT_MASK;
    let lifetime = (state >> COUNT_BITS) & LIFETIME_MASK;
    let mut epoch = (state >> EPOCH_SHIFT) & EPOCH_MASK;
    let mut known = state & CLOCK_KNOWN != 0;
    if lifetime >= LIFETIME_RECEIPT_LIMIT { return None; }
    if let Some(now) = now {
        let observed = now / WINDOW_100NS;
        if !known || observed > epoch {
            count = 0;
            epoch = observed;
            known = true;
        }
    }
    if count >= RECEIPT_LIMIT { return None; }
    let receipt = BudgetReceipt {
        receipt: count + 1,
        lifetime_receipt: lifetime + 1,
        window: known.then_some(epoch),
    };
    let next = receipt.receipt
        | (receipt.lifetime_receipt << COUNT_BITS)
        | (epoch << EPOCH_SHIFT)
        | if known { CLOCK_KNOWN } else { 0 };
    Some((next, receipt))
}
