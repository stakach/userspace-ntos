//! Host-testable dispatch boundary for loader DLL notifications.

/// Cursor over the registrations that existed when notification dispatch began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchCursor {
    current: u64,
    original_tail: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalDisposition {
    ReclaimNow,
    Defer,
}

/// Allocation-independent registry accounting used while the notification lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationState {
    live_capacity: usize,
    retained_capacity: usize,
    live: usize,
    dispatch_depth: usize,
    retired: usize,
}

impl NotificationState {
    pub const fn new(live_capacity: usize, retained_capacity: usize) -> Self {
        Self {
            live_capacity,
            retained_capacity,
            live: 0,
            dispatch_depth: 0,
            retired: 0,
        }
    }

    pub fn can_register(&self) -> bool {
        self.live < self.live_capacity && self.retained() < self.retained_capacity
    }

    pub fn registered(&mut self) {
        self.live += 1;
    }

    pub fn begin_dispatch(&mut self) {
        self.dispatch_depth += 1;
    }

    pub fn removed(&mut self) -> RemovalDisposition {
        debug_assert!(self.live != 0);
        self.live = self.live.saturating_sub(1);
        if self.dispatch_depth == 0 {
            RemovalDisposition::ReclaimNow
        } else {
            self.retired += 1;
            RemovalDisposition::Defer
        }
    }

    /// End one nested dispatch and return the number of retired entries now safe to reclaim.
    pub fn finish_dispatch(&mut self) -> usize {
        debug_assert!(self.dispatch_depth != 0);
        self.dispatch_depth = self.dispatch_depth.saturating_sub(1);
        if self.dispatch_depth == 0 {
            let retired = self.retired;
            self.retired = 0;
            retired
        } else {
            0
        }
    }

    pub fn live(&self) -> usize {
        self.live
    }

    pub fn retained(&self) -> usize {
        self.live + self.retired
    }
}

impl DispatchCursor {
    /// Capture a circular list's first entry and tail. An empty list points `first` at `head`.
    pub fn new(head: u64, first: u64, tail: u64) -> Self {
        Self {
            current: if first == head { 0 } else { first },
            original_tail: tail,
        }
    }

    pub fn current(&self) -> Option<u64> {
        (self.current != 0).then_some(self.current)
    }

    /// Advance using the saved pre-callback link, stopping after the original tail.
    pub fn advance(&mut self, current: u64, saved_next: u64) {
        self.current = if current == self.original_tail {
            0
        } else {
            saved_next
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_has_no_dispatch() {
        assert_eq!(DispatchCursor::new(10, 10, 10).current(), None);
    }

    #[test]
    fn dispatch_stops_at_original_tail() {
        let mut cursor = DispatchCursor::new(10, 20, 30);
        assert_eq!(cursor.current(), Some(20));
        cursor.advance(20, 30);
        assert_eq!(cursor.current(), Some(30));
        cursor.advance(30, 40); // 40 was registered during dispatch.
        assert_eq!(cursor.current(), None);
    }

    #[test]
    fn saved_links_allow_removed_nodes_to_be_skipped_by_caller() {
        let mut cursor = DispatchCursor::new(10, 20, 40);
        cursor.advance(20, 30);
        assert_eq!(cursor.current(), Some(30));
        cursor.advance(30, 40);
        assert_eq!(cursor.current(), Some(40));
        cursor.advance(40, 10);
        assert_eq!(cursor.current(), None);
    }

    #[test]
    fn removal_is_deferred_until_outermost_dispatch_finishes() {
        let mut state = NotificationState::new(4, 8);
        state.registered();
        state.registered();
        state.begin_dispatch();
        state.begin_dispatch();
        assert_eq!(state.removed(), RemovalDisposition::Defer);
        assert_eq!(state.live(), 1);
        assert_eq!(state.retained(), 2);
        assert_eq!(state.finish_dispatch(), 0);
        assert_eq!(state.finish_dispatch(), 1);
        assert_eq!(state.retained(), 1);
    }

    #[test]
    fn removed_live_slot_can_be_replaced_during_dispatch() {
        let mut state = NotificationState::new(1, 2);
        state.registered();
        state.begin_dispatch();
        assert_eq!(state.removed(), RemovalDisposition::Defer);
        assert!(state.can_register());
        state.registered();
        assert_eq!(state.live(), 1);
        assert_eq!(state.retained(), 2);
        assert_eq!(state.finish_dispatch(), 1);
        assert_eq!(state.retained(), 1);
    }

    #[test]
    fn capacity_counts_live_registrations() {
        let mut state = NotificationState::new(2, 4);
        assert!(state.can_register());
        state.registered();
        state.registered();
        assert!(!state.can_register());
        assert_eq!(state.removed(), RemovalDisposition::ReclaimNow);
        assert!(state.can_register());
    }

    #[test]
    fn retained_capacity_bounds_reentrant_replacement() {
        let mut state = NotificationState::new(1, 2);
        state.registered();
        state.begin_dispatch();
        assert_eq!(state.removed(), RemovalDisposition::Defer);
        state.registered();
        assert_eq!(state.removed(), RemovalDisposition::Defer);
        assert!(!state.can_register());
        assert_eq!(state.finish_dispatch(), 2);
        assert!(state.can_register());
    }
}
