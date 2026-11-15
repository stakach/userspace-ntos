//! What a completed win32k dispatch reports of the GDI batch flushes it ran.
//!
//! NT flushes a thread's GDI batch in two places, both on that thread: before a win32k
//! system call (`KiSystemCallHandler`) and when a user callback returns
//! (`KeUserModeCallback`). The provider runs both inside the dispatch they belong to and
//! reports them to the root in one word when that dispatch completes.

use core::sync::atomic::{AtomicU64, Ordering};

/// Batch records handed to win32k's flush routine, and flush calls that did not consume
/// their batch, for one completed dispatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GdiBatchFlushReceipt {
    pub records: u32,
    pub failed_flushes: u32,
}

impl GdiBatchFlushReceipt {
    pub const fn pack(self) -> u64 {
        ((self.failed_flushes as u64) << 32) | self.records as u64
    }

    pub const fn unpack(word: u64) -> Self {
        Self { records: word as u32, failed_flushes: (word >> 32) as u32 }
    }

    /// Account one flush call over `count` batch records.
    pub const fn credit(self, count: u32, consumed: bool) -> Self {
        if consumed {
            Self { records: self.records.saturating_add(count), ..self }
        } else {
            Self { failed_flushes: self.failed_flushes.saturating_add(1), ..self }
        }
    }

    pub const fn merged(self, other: Self) -> Self {
        Self {
            records: self.records.saturating_add(other.records),
            failed_flushes: self.failed_flushes.saturating_add(other.failed_flushes),
        }
    }
}

/// Callback-return flushes of one physical lane, credited to the dispatch that issued the
/// callback. A nested dispatch runs on the same lane while a callback is outstanding, so
/// each dispatch opens its own scope and the enclosing one is restored when it ends.
pub struct CallbackFlushLedger(AtomicU64);

impl CallbackFlushLedger {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn enter_dispatch(&self) -> DispatchFlushScope<'_> {
        DispatchFlushScope { ledger: self, enclosing: self.0.swap(0, Ordering::Relaxed) }
    }

    /// Account one callback-return flush to the dispatch whose scope is open.
    pub fn credit(&self, count: u32, consumed: bool) {
        let current = GdiBatchFlushReceipt::unpack(self.0.load(Ordering::Relaxed));
        self.0.store(current.credit(count, consumed).pack(), Ordering::Relaxed);
    }
}

impl Default for CallbackFlushLedger {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DispatchFlushScope<'a> {
    ledger: &'a CallbackFlushLedger,
    enclosing: u64,
}

impl DispatchFlushScope<'_> {
    /// The callback-return flushes of this dispatch so far.
    pub fn receipt(&self) -> GdiBatchFlushReceipt {
        GdiBatchFlushReceipt::unpack(self.ledger.0.load(Ordering::Relaxed))
    }
}

impl Drop for DispatchFlushScope<'_> {
    fn drop(&mut self) {
        self.ledger.0.store(self.enclosing, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_receipt_round_trips_through_its_word() {
        let receipt = GdiBatchFlushReceipt { records: 0x1234_5678, failed_flushes: 3 };
        assert_eq!(GdiBatchFlushReceipt::unpack(receipt.pack()), receipt);
        assert_eq!(GdiBatchFlushReceipt::unpack(0), GdiBatchFlushReceipt::default());
        // A word that only ever carried a record count still reads as that count.
        assert_eq!(GdiBatchFlushReceipt::unpack(7).records, 7);
        assert_eq!(GdiBatchFlushReceipt::unpack(7).failed_flushes, 0);
    }

    #[test]
    fn a_flush_that_left_its_batch_counts_as_a_failure_not_as_records() {
        let receipt = GdiBatchFlushReceipt::default().credit(5, true).credit(9, false);
        assert_eq!(receipt, GdiBatchFlushReceipt { records: 5, failed_flushes: 1 });
        assert_eq!(
            receipt.merged(GdiBatchFlushReceipt { records: 2, failed_flushes: 0 }),
            GdiBatchFlushReceipt { records: 7, failed_flushes: 1 },
        );
    }

    /// Dispatch D issues a callback; the client makes nested syscall N inside it; the callback
    /// returns and D's continuation flushes. N must not report D's flush and D must not lose
    /// what it had before N ran.
    #[test]
    fn a_callback_return_flush_is_credited_to_the_dispatch_that_issued_the_callback() {
        let lane = CallbackFlushLedger::new();
        let outer = lane.enter_dispatch();
        lane.credit(4, true); // an earlier callback of D returned
        {
            let nested = lane.enter_dispatch();
            assert_eq!(nested.receipt(), GdiBatchFlushReceipt::default());
            lane.credit(2, true); // a callback N itself issued returned
            assert_eq!(nested.receipt().records, 2);
        }
        lane.credit(6, true); // the callback that carried N returned
        assert_eq!(outer.receipt(), GdiBatchFlushReceipt { records: 10, failed_flushes: 0 });
        drop(outer);
        assert_eq!(lane.enter_dispatch().receipt(), GdiBatchFlushReceipt::default());
    }
}
