//! One pass over retained owner rows for the first ready one.
//!
//! Readiness gates run in every nested pump turn. Each row is evaluated once, in slot order,
//! and the retry clock is read at most once per pass, only for a row that has a retry deadline.

/// A clock sample shared by one readiness pass.
pub(crate) struct PassClock<F: FnMut() -> u64> {
    read: F,
    now: Option<u64>,
}

impl<F: FnMut() -> u64> PassClock<F> {
    pub(crate) fn new(read: F) -> Self { Self { read, now: None } }

    /// Whether a nonzero `retry_after` deadline is still in the future.
    pub(crate) fn deferred(&mut self, retry_after: u64) -> bool {
        retry_after != 0 && retry_after > *self.now.get_or_insert_with(&mut self.read)
    }
}

/// The first slot for which `ready` holds, evaluating each slot at most once.
pub(crate) fn first_ready<F: FnMut() -> u64>(
    len: usize,
    clock: &mut PassClock<F>,
    mut ready: impl FnMut(usize, &mut PassClock<F>) -> bool,
) -> Option<usize> {
    (0..len).find(|slot| ready(*slot, clock))
}
