//! Completion identity handling for a reentered SURT client wait.

/// A completion must remain owned by its exact request while another wait is active.
pub(crate) struct CompletionInbox<T> {
    active_request: Option<u64>,
    parked_owned: Option<(u64, T)>,
    unexpected: Option<(u64, T)>,
}

impl<T> CompletionInbox<T> {
    pub(crate) const fn new() -> Self {
        Self {
            active_request: None,
            parked_owned: None,
            unexpected: None,
        }
    }

    /// The shared request and reply frames admit only one submitted request at a time.
    pub(crate) fn begin(&mut self, request_id: u64) -> bool {
        if request_id == 0 || self.active_request.is_some() || self.unexpected.is_some() {
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

    /// A single logical owned terminal may outlive its shared frame lease.
    pub(crate) fn begin_owned(&mut self, request_id: u64) -> bool {
        self.parked_owned.is_none() && self.begin(request_id)
    }

    /// The CQE and reply bytes have been copied; free the shared frame but retain the effect.
    pub(crate) fn park_active_owned(&mut self, request_id: u64, terminal: T) -> Result<(), T> {
        if self.active_request != Some(request_id)
            || self.parked_owned.is_some() || self.unexpected.is_some() { return Err(terminal); }
        self.parked_owned = Some((request_id, terminal));
        self.active_request = None;
        Ok(())
    }

    pub(crate) fn take_parked_owned(&mut self, request_id: u64) -> Option<T> {
        if self.parked_owned.as_ref().is_some_and(|(id, _)| *id == request_id) {
            self.parked_owned.take().map(|(_, terminal)| terminal)
        } else { None }
    }

    pub(crate) fn has_parked_owned(&self) -> bool {
        self.parked_owned.is_some()
    }

    /// A CQE for an unowned identity cannot be discarded or authorize frame reuse.
    pub(crate) fn quarantine_unexpected(&mut self, request_id: u64, terminal: T) -> Result<(), T> {
        if self.unexpected.is_some() { return Err(terminal); }
        self.unexpected = Some((request_id, terminal));
        Ok(())
    }

    pub(crate) fn unexpected_receipt(&self) -> Option<(u64, &T)> {
        self.unexpected.as_ref().map(|(id, terminal)| (*id, terminal))
    }

}

#[cfg(test)]
mod tests {
    use super::CompletionInbox;

    #[test]
    fn active_request_remains_owned_on_unexpected_terminal() {
        let mut inbox = CompletionInbox::<u32>::new();
        assert!(inbox.begin(41));
        assert_eq!(inbox.active_request(), Some(41));
        assert!(!inbox.begin(42));
        assert_eq!(inbox.quarantine_unexpected(42, 7), Ok(()));
        assert_eq!(inbox.unexpected_receipt(), Some((42, &7)));
        assert_eq!(inbox.active_request(), Some(41));
        assert_eq!(inbox.park_active_owned(41, 9), Err(9));
    }
}
