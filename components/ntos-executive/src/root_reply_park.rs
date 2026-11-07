//! Park the current root Call without inventing a replacement for shared ingress.

use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::*;

pub(crate) struct RootReplyPark {
    active: u64,
    replacement: Option<(usize, u64)>,
}

pub(crate) enum SelectedParkRefusal {
    /// The selected attempt made no Reply-pool or main-selector change. The native child owner
    /// must still recheck exact CALLS and physical binding before reopening its pure pass.
    NoEffect(nt_user_host::root_ingress_pass::RootReplyParkNoEffect<crate::HostedThreadRole>),
}

impl RootReplyPark {
    pub(crate) unsafe fn prepare() -> Option<Self> {
        let active = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
        let identity = wait_reply_pool_ref().find_cap(active)?;
        if wait_reply_pool_ref().state(identity).ok() != Some(
            nt_component_suspension::RootReplySlotState::Used)
        {
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

    /// A selected held-parent pass may park only its exact hosted root Reply. It cannot
    /// publish a replacement cap or borrow another caller's Reply pool generation.
    pub(crate) unsafe fn prepare_exact_hosted(expected: u64) -> Option<Self> {
        let prepared = Self::prepare()?;
        (prepared.active == expected && prepared.replacement.is_none()
            && runtime::can_park_hosted_reply(expected)).then_some(prepared)
    }

    /// The semantic continuation (or the returned transfer value) must retain `active`.
    pub(crate) unsafe fn commit(self) {
        if self.try_commit().is_err() {
            panic!("parked root Call lost its prepared Reply ownership");
        }
    }

    /// Park a Reply whose semantic owner is already retained after a native effect. Every
    /// refusal is checked before touching the pool or main slot, so the owner can keep the
    /// original Reply without a panic or an uncertain replacement.
    pub(crate) unsafe fn try_commit(self) -> Result<(), Self> {
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) != self.active {
            return Err(self);
        }
        let Some(active_identity) = wait_reply_pool_ref().find_cap(self.active) else {
            return Err(self);
        };
        if wait_reply_pool_ref().state(active_identity).ok() != Some(
            nt_component_suspension::RootReplySlotState::Used)
        {
            return Err(self);
        }
        match self.replacement {
            None => {
                if !runtime::can_park_hosted_reply(self.active) {
                    return Err(self);
                }
                REPLY_MAIN_SLOT.store(0, Ordering::Relaxed);
            }
            Some((index, cap)) => {
                if !wait_reply_pool_ref().at(index).is_some_and(|identity| {
                    identity.cap() == cap && wait_reply_pool_ref().state(identity).ok()
                        == Some(nt_component_suspension::RootReplySlotState::Free)
                }) || runtime::owns_ingress_reply(cap) {
                    return Err(self);
                }
                if !wait_reply_pool_mark_used(index) { return Err(self); }
                REPLY_MAIN_SLOT.store(cap, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// Only this selected wrapper converts a proven pre-effect refusal to a move-only receipt.
    /// A mismatched prepared Reply is refused before try_commit can affect that other Reply.
    pub(crate) unsafe fn try_commit_selected(
        self,
        attempt: nt_user_host::root_ingress_pass::RootIngressParkAttempt<crate::HostedThreadRole>,
    ) -> Result<nt_user_host::root_ingress_pass::RootReplyParkCommitted<crate::HostedThreadRole>, SelectedParkRefusal> {
        if self.active != attempt.reply() {
            // `self` is only a read-only prepared plan. No selected native effect was entered.
            return Err(SelectedParkRefusal::NoEffect(
                attempt.after_no_effect_native_refusal(),
            ));
        }
        match self.try_commit() {
            Ok(()) => Ok(attempt.after_positive_native_park()),
            Err(_park) => Err(SelectedParkRefusal::NoEffect(
                attempt.after_no_effect_native_refusal(),
            )),
        }
    }
}

/// Keep a refused hosted Call's Reply in its existing shared owner while allowing the root
/// receiver to accept a different Call. This does not cancel, reuse, or retry the old Reply.
/// The used pool record stays unavailable until its exact retained owner settles it.
pub(crate) unsafe fn quarantine_current_hosted_reply() -> bool {
    let active = REPLY_MAIN_SLOT.load(Ordering::Relaxed);
    let Some(identity) = wait_reply_pool_ref().find_cap(active) else {
        return false;
    };
    if active == 0
        || wait_reply_pool_ref().state(identity).ok()
            != Some(nt_component_suspension::RootReplySlotState::Used)
        || !runtime::owns_hosted_reply(active)
    {
        return false;
    }
    REPLY_MAIN_SLOT.store(0, Ordering::Relaxed);
    true
}
