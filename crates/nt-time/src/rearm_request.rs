//! Coalesced rearm requests whose publication may recur during timer initialization or IPC.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RearmRequest(u64);

pub struct DeferredRearm {
    requested: u64,
    completed: u64,
}

impl DeferredRearm {
    pub const fn new() -> Self {
        Self {
            requested: 0,
            completed: 0,
        }
    }

    pub fn request(&mut self) -> bool {
        let Some(next) = self.requested.checked_add(1) else {
            return false;
        };
        self.requested = next;
        true
    }

    pub fn pending(&self) -> Option<RearmRequest> {
        (self.requested != self.completed).then_some(RearmRequest(self.requested))
    }

    /// Call only after a successful arm or authoritative no-demand scan, never on refusal.
    pub fn complete(&mut self, request: RearmRequest) -> bool {
        if request.0 <= self.completed || request.0 > self.requested {
            return false;
        }
        self.completed = request.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_published_during_programming_remain_pending() {
        let mut owner = DeferredRearm::new();
        assert!(owner.pending().is_none());
        assert!(owner.request());
        let first = owner.pending().unwrap();
        assert!(owner.request());
        assert!(owner.complete(first));
        assert!(!owner.complete(first));
        let next = owner.pending().unwrap();
        assert_ne!(next, first);
        assert!(owner.complete(next));
        assert!(owner.pending().is_none());
    }

    #[test]
    fn refusal_and_exhaustion_never_acknowledge_or_wrap_demand() {
        let mut owner = DeferredRearm {
            requested: u64::MAX - 1,
            completed: 0,
        };
        assert!(owner.request());
        let pending = owner.pending().unwrap();
        assert!(!owner.request());
        assert_eq!(owner.pending(), Some(pending));
        // A refused hardware attempt leaves the same request available.
        assert_eq!(owner.pending(), Some(pending));
        assert!(owner.complete(pending));
        assert!(owner.pending().is_none());
    }
}
