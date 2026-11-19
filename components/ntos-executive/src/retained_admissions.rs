//! Retained ownership for a wait admission whose outcome is not `Accepted` (#336).
//!
//! A completed user callback can leave its dispatch suspended in a provider, LPC, receive or
//! service wait. Admitting that wait has three outcomes. A refusal with no effect consumed
//! nothing: the item and its bound Reply are kept and admission is retried later. An
//! indeterminate outcome (for example a stale LPC reservation cancel) proves nothing about the
//! effect: the item and its Reply are quarantined. They are never answered, replayed or reused.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetainedWaitAdmission {
    Accepted,
    RefusedNoEffect,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Disposition {
    Admitted,
    RetryLater,
    Quarantined,
}

pub(crate) struct RetainedAdmissions<T> {
    retry: alloc::vec::Vec<T>,
    quarantined: alloc::vec::Vec<T>,
}

impl<T> RetainedAdmissions<T> {
    pub(crate) const fn new() -> Self {
        Self { retry: alloc::vec::Vec::new(), quarantined: alloc::vec::Vec::new() }
    }

    /// Keep `item` according to its admission outcome. `Err(item)` means no record could be
    /// allocated; the caller must still keep the item's Reply unanswered.
    pub(crate) fn retain(&mut self, item: T, outcome: RetainedWaitAdmission) -> Result<Disposition, T> {
        let list = match outcome {
            RetainedWaitAdmission::Accepted => return Ok(Disposition::Admitted),
            RetainedWaitAdmission::RefusedNoEffect => &mut self.retry,
            RetainedWaitAdmission::Indeterminate => &mut self.quarantined,
        };
        if list.try_reserve(1).is_err() {
            return Err(item);
        }
        list.push(item);
        Ok(match outcome {
            RetainedWaitAdmission::RefusedNoEffect => Disposition::RetryLater,
            _ => Disposition::Quarantined,
        })
    }

    /// Attempt each retryable admission once. Admitted items leave; a later indeterminate
    /// outcome moves its item to quarantine. Returns the number admitted.
    pub(crate) fn retry(&mut self, mut admit: impl FnMut(&T) -> RetainedWaitAdmission) -> usize {
        let mut admitted = 0;
        let mut index = 0;
        while index < self.retry.len() {
            match admit(&self.retry[index]) {
                RetainedWaitAdmission::Accepted => {
                    self.retry.swap_remove(index);
                    admitted += 1;
                }
                RetainedWaitAdmission::RefusedNoEffect => index += 1,
                RetainedWaitAdmission::Indeterminate => {
                    if self.quarantined.try_reserve(1).is_ok() {
                        let item = self.retry.swap_remove(index);
                        self.quarantined.push(item);
                    } else {
                        // Keep it where it is; it is retained either way and never retried
                        // into an answer without a fresh `Accepted`.
                        index += 1;
                    }
                }
            }
        }
        admitted
    }

    pub(crate) fn retrying(&self) -> usize {
        self.retry.len()
    }

    pub(crate) fn quarantined(&self) -> usize {
        self.quarantined.len()
    }
}
