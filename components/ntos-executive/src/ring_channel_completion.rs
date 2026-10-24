//! Completion identity handling for a reentered SURT client wait.

extern crate alloc;
use alloc::vec::Vec;

/// A completion must remain owned by its exact request while another wait is active.
pub(crate) struct CompletionInbox<T> {
    active_request: Option<u64>,
    pending: Vec<(u64, T)>,
}

impl<T> CompletionInbox<T> {
    pub(crate) const fn new() -> Self {
        Self {
            active_request: None,
            pending: Vec::new(),
        }
    }

    /// The shared request and reply frames admit only one submitted request at a time.
    pub(crate) fn begin(&mut self, request_id: u64) -> bool {
        if request_id == 0 || self.active_request.is_some() {
            return false;
        }
        self.active_request = Some(request_id);
        true
    }

    pub(crate) fn finish(&mut self, request_id: u64) {
        assert_eq!(self.active_request, Some(request_id));
        self.active_request = None;
    }

    pub(crate) fn active_request(&self) -> Option<u64> {
        self.active_request
    }

    pub(crate) fn take(&mut self, request_id: u64) -> Option<T> {
        let index = self.pending.iter().position(|(id, _)| *id == request_id)?;
        Some(self.pending.swap_remove(index).1)
    }

    pub(crate) fn accept(
        &mut self,
        waiting_request_id: u64,
        completed_request_id: u64,
        completion: T,
    ) -> Option<T> {
        if completed_request_id == waiting_request_id {
            return Some(completion);
        }
        // A nested wait must never consume the outer request's terminal receipt.
        self.pending.try_reserve(1).expect("SURT completion identity must be retained");
        self.pending.push((completed_request_id, completion));
        None
    }
}

#[cfg(test)]
mod tests {
    use super::CompletionInbox;

    #[test]
    fn active_request_remains_owned_until_exact_terminal_receipt() {
        let mut inbox = CompletionInbox::<u32>::new();
        assert!(inbox.begin(41));
        assert_eq!(inbox.active_request(), Some(41));
        assert!(!inbox.begin(42));
        assert_eq!(inbox.accept(42, 41, 7), None);
        assert_eq!(inbox.take(41), Some(7));
        assert_eq!(inbox.active_request(), Some(41));
        inbox.finish(41);
        assert_eq!(inbox.active_request(), None);
    }
}
