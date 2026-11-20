//! A reply owed to a lane whose parent restore was refused while its service ran (#333).
//!
//! The service has finished, but its lane is still held. Replying and then receiving on that
//! lane would block the root on a lane nobody resumes. The reply is therefore intercepted and
//! kept until the exact parent is restored; only the restore's continuation releases it, once.

extern crate alloc;
use alloc::vec::Vec;

/// Parents whose next reply is owed after their restore, then the replies they intercepted.
pub struct DeferredReplies<P, R> {
    parents: Vec<P>,
    replies: Vec<(P, R)>,
}

/// Capacity for one deferral and its later reply could not be reserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeferralCapacity;

impl<P: Copy + Eq, R> DeferredReplies<P, R> {
    pub const fn new() -> Self { Self { parents: Vec::new(), replies: Vec::new() } }

    /// Defer the next reply to `parent`'s lane. Both rows are reserved here, so a later
    /// interception never allocates and cannot fail.
    pub fn defer(&mut self, parent: P) -> Result<(), DeferralCapacity> {
        self.parents.try_reserve(1).map_err(|_| DeferralCapacity)?;
        self.replies.try_reserve(self.parents.len() + 1).map_err(|_| DeferralCapacity)?;
        self.parents.push(parent);
        Ok(())
    }

    /// Called before a reply is sent. A reply to a deferred parent's lane is kept, and the
    /// parent whose restore is owed is returned instead; any other reply is handed back.
    pub fn intercept(&mut self, owns: impl Fn(&P) -> bool, reply: R) -> Result<P, R> {
        let Some(index) = self.parents.iter().position(owns) else { return Err(reply) };
        let parent = self.parents.swap_remove(index);
        self.replies.push((parent, reply));
        Ok(parent)
    }

    /// After `parent` is restored, release its kept reply exactly once.
    pub fn release(&mut self, parent: P) -> Option<R> {
        let index = self.replies.iter().position(|(owner, _)| *owner == parent)?;
        Some(self.replies.swap_remove(index).1)
    }

    pub fn is_empty(&self) -> bool { self.parents.is_empty() }
}

impl<P: Copy + Eq, R> Default for DeferredReplies<P, R> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_to_a_held_lane_is_kept_instead_of_sent() {
        let mut deferred = DeferredReplies::<u32, &str>::new();
        deferred.defer(7).unwrap();
        assert_eq!(deferred.intercept(|parent| *parent == 7, "status"), Ok(7),
            "the pump must yield the owed restore, not reply to the held lane");
        assert!(deferred.is_empty());
    }

    #[test]
    fn the_kept_reply_is_released_once_after_the_restore() {
        let mut deferred = DeferredReplies::<u32, &str>::new();
        deferred.defer(3).unwrap();
        let parent = deferred.intercept(|parent| *parent == 3, "status").unwrap();
        assert_eq!(deferred.release(parent), Some("status"));
        assert_eq!(deferred.release(parent), None, "a released reply is never sent twice");
    }

    #[test]
    fn another_lane_replies_normally() {
        let mut deferred = DeferredReplies::<u32, &str>::new();
        deferred.defer(3).unwrap();
        assert_eq!(deferred.intercept(|parent| *parent == 4, "other"), Err("other"));
        assert_eq!(deferred.intercept(|parent| *parent == 3, "mine"), Ok(3));
    }

    #[test]
    fn a_parent_never_deferred_has_no_reply_to_release() {
        let mut deferred = DeferredReplies::<u32, u8>::new();
        assert_eq!(deferred.release(9), None);
    }
}
