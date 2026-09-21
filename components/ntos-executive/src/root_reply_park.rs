//! Park the current root Call without inventing a replacement for shared ingress.

use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::*;

pub(crate) struct RootReplyPark {
    active: u64,
    replacement: Option<(usize, u64)>,
}

impl RootReplyPark {
    pub(crate) unsafe fn prepare() -> Option<Self> {
        let active = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let index = wait_reply_pool_find_cap(active)?;
        if !wait_reply_pool_ref().get(index)?.used {
            return None;
        }
        let replacement = if runtime::owns_ingress_reply(active) {
            if !runtime::can_park_hosted_reply(active) {
                return None;
            }
            None
        } else {
            Some(wait_reply_pool_find_free()?)
        };
        Some(Self {
            active,
            replacement,
        })
    }

    /// The semantic continuation (or the returned transfer value) must retain `active`.
    pub(crate) unsafe fn commit(self) {
        assert_eq!(REPLY_MAIN_SLOT.load(Ordering::Relaxed), self.active);
        let index = wait_reply_pool_find_cap(self.active)
            .expect("parked root Call lost its semantic pool record");
        assert!(wait_reply_pool_ref()[index].used);
        match self.replacement {
            None => {
                assert!(runtime::can_park_hosted_reply(self.active));
                REPLY_MAIN_SLOT.store(0, Ordering::Relaxed);
            }
            Some((index, cap)) => {
                let record = &wait_reply_pool_ref()[index];
                assert_eq!(record.cap, cap);
                assert!(!record.used);
                assert!(!runtime::owns_ingress_reply(cap));
                wait_reply_pool_mark_used(index);
                REPLY_MAIN_SLOT.store(cap, Ordering::Relaxed);
            }
        }
    }
}
