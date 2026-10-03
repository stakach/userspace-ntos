//! Dispatch-return policy for legacy hosted source IRPs, separate from terminal ownership.
//!
//! A disposition records a provider result; it neither authenticates a source ticket nor
//! releases its retained File, device, IRP, completion cursor, or reply owner.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedForwardDispatchReply {
    Rejected(i32),
    InlineTerminal(i32),
    Pending,
}

impl HostedForwardDispatchReply {
    /// Status and disposition share the existing service reply's two scalar words.
    pub const fn words(self) -> Option<(i32, u64)> {
        let pending = nt_status::NtStatus::PENDING.raw();
        match self {
            Self::Rejected(status) if status != pending => Some((status, 0)),
            Self::InlineTerminal(status) if status != pending => Some((status, 1)),
            Self::Pending => Some((pending, 2)),
            _ => None,
        }
    }

    pub const fn decode(status: i32, disposition: u64) -> Option<Self> {
        let pending = nt_status::NtStatus::PENDING.raw();
        match disposition {
            0 if status != pending => Some(Self::Rejected(status)),
            1 if status != pending => Some(Self::InlineTerminal(status)),
            2 if status == pending => Some(Self::Pending),
            _ => None,
        }
    }
}

/// Source output publication is distinct from the provider's dispatch return.
/// A genuine Pending dispatch returns before completion without publishing source output.
pub const fn hosted_forward_dispatch_reply_ready(
    reply: HostedForwardDispatchReply,
    source_terminal_published: bool,
) -> bool {
    match reply {
        HostedForwardDispatchReply::Rejected(_) | HostedForwardDispatchReply::Pending => true,
        HostedForwardDispatchReply::InlineTerminal(_) => source_terminal_published,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InlineHoldPhase { Unreported, Held, Retired }

/// Scheduling observation only; none of these values supplies native authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedForwardOriginProgress {
    pub reply_entered: bool,
    pub disposition: Option<HostedForwardDispatchReply>,
    pub phase: crate::source_terminal::OriginCallPhase,
    pub terminal_entered: bool,
    pub terminal_completed: bool,
    pub terminal_held: bool,
    pub lane_acknowledged: bool,
    pub inline_hold: InlineHoldPhase,
    pub prepared: bool,
}

/// A copied phase snapshot does not own the Work, source pin, or Reply it describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostedForwardWorkProgress {
    pub initial_status: Option<i32>,
    pub canonical_irp: Option<u64>,
    pub retained: bool,
    pub terminal: bool,
    pub completion: bool,
    pub source_released: bool,
    pub source_published: bool,
    pub cancel_requested: bool,
    pub actor_held: bool,
    pub reply_entered: bool,
    pub origin: Option<HostedForwardOriginProgress>,
    pub ack: Option<bool>,
}

impl HostedForwardWorkProgress {
    pub fn advanced(before: Self, after: Self, finished: bool) -> bool {
        finished || before != after
    }
}

/// Bound an initial scheduling pass by its retained table size. The caller owns the cursor
/// and must report actual phase progress, not eligibility or a retained terminal.
pub fn redrive_ready_pass(attempts: usize, mut redrive: impl FnMut() -> bool) -> bool {
    for _ in 0..attempts {
        if redrive() { return true; }
    }
    false
}

/// Value-only progress. Native owners authenticate the token and completion/stop proof.
#[derive(Debug)]
pub struct HostedForwardInlineHold {
    token: u64,
    phase: InlineHoldPhase,
}

impl HostedForwardInlineHold {
    pub fn new(token: u64) -> Option<Self> {
        (token != 0).then_some(Self { token, phase: InlineHoldPhase::Unreported })
    }

    pub fn phase(&self) -> InlineHoldPhase { self.phase }

    pub fn report_held(&mut self, token: u64) -> bool {
        if token != self.token || self.phase != InlineHoldPhase::Unreported { return false; }
        self.phase = InlineHoldPhase::Held;
        true
    }

    pub fn retirement_ready(&self, terminal_finished: bool, owner_stopped: bool) -> bool {
        self.phase == InlineHoldPhase::Held && (terminal_finished || owner_stopped)
    }

    /// Record acknowledged native retirement, never authorize an unwind or dispatch replay.
    pub fn retire(&mut self, token: u64, terminal_finished: bool, owner_stopped: bool) -> bool {
        if token != self.token || !self.retirement_ready(terminal_finished, owner_stopped) {
            return false;
        }
        self.phase = InlineHoldPhase::Retired;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_and_inline_terminal_keep_their_existing_publication_boundaries() {
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::Rejected(-1), false));
        assert!(!hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::InlineTerminal(0), false));
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::InlineTerminal(0), true));
    }

    #[test]
    fn dispatch_disposition_roundtrip_rejects_pending_status_mismatch() {
        for reply in [
            HostedForwardDispatchReply::Rejected(nt_status::NtStatus::INVALID_HANDLE.raw()),
            HostedForwardDispatchReply::InlineTerminal(0),
            HostedForwardDispatchReply::InlineTerminal(nt_status::NtStatus::INVALID_PARAMETER.raw()),
            HostedForwardDispatchReply::Pending,
        ] {
            let (status, disposition) = reply.words().unwrap();
            assert_eq!(HostedForwardDispatchReply::decode(status, disposition), Some(reply));
        }
        let pending = nt_status::NtStatus::PENDING.raw();
        assert_eq!(HostedForwardDispatchReply::Rejected(pending).words(), None);
        assert_eq!(HostedForwardDispatchReply::InlineTerminal(pending).words(), None);
        for (status, disposition) in [(pending, 0), (pending, 1), (0, 2), (0, 3), (pending, u64::MAX)] {
            assert_eq!(HostedForwardDispatchReply::decode(status, disposition), None);
        }
        assert!(hosted_forward_dispatch_reply_ready(HostedForwardDispatchReply::Pending, true));
    }

    fn pending_progress() -> HostedForwardWorkProgress {
        HostedForwardWorkProgress {
            initial_status: Some(nt_status::NtStatus::PENDING.raw()),
            canonical_irp: Some(1),
            retained: true,
            terminal: false,
            completion: false,
            source_released: false,
            source_published: false,
            cancel_requested: false,
            actor_held: true,
            reply_entered: true,
            origin: Some(HostedForwardOriginProgress {
                reply_entered: true,
                disposition: Some(HostedForwardDispatchReply::Pending),
                phase: crate::source_terminal::OriginCallPhase::Armed(1),
                terminal_entered: false,
                terminal_completed: false,
                terminal_held: false,
                lane_acknowledged: false,
                inline_hold: InlineHoldPhase::Unreported,
                prepared: true,
            }),
            ack: None,
        }
    }

    #[test]
    fn unchanged_admitted_pending_forward_is_not_nested_progress() {
        let before = pending_progress();
        assert!(!HostedForwardWorkProgress::advanced(before, before, false),
            "eligibility and an old STATUS_PENDING do not justify bypassing physical receive");
    }

    #[test]
    fn unchanged_completed_or_ack_waiting_forward_is_not_nested_progress() {
        let mut before = pending_progress();
        before.origin.as_mut().unwrap().terminal_completed = true;
        before.origin.as_mut().unwrap().lane_acknowledged = true;
        before.terminal = true;
        assert!(!HostedForwardWorkProgress::advanced(before, before, false));
        before.source_released = true;
        before.ack = Some(true);
        assert!(!HostedForwardWorkProgress::advanced(before, before, false),
            "an unsettled physical ACK is retained ownership, not newly made progress");
    }

    #[test]
    fn every_owned_forward_phase_delta_is_nested_progress() {
        let mut before = pending_progress();
        before.initial_status = None;
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut after = before;
                after.$field = $value;
                assert!(HostedForwardWorkProgress::advanced(before, after, false), stringify!($field));
            }};
        }
        changed!(initial_status, Some(0));
        changed!(canonical_irp, None);
        changed!(retained, false);
        changed!(terminal, true);
        changed!(completion, true);
        changed!(source_released, true);
        changed!(source_published, true);
        changed!(cancel_requested, true);
        changed!(actor_held, false);
        changed!(reply_entered, false);
        changed!(ack, Some(false));
        changed!(origin, None);
        macro_rules! origin_changed {
            ($field:ident, $value:expr) => {{
                let mut after = before;
                after.origin.as_mut().unwrap().$field = $value;
                assert!(HostedForwardWorkProgress::advanced(before, after, false), stringify!($field));
            }};
        }
        origin_changed!(reply_entered, false);
        origin_changed!(disposition, Some(HostedForwardDispatchReply::InlineTerminal(0)));
        origin_changed!(phase, crate::source_terminal::OriginCallPhase::Indeterminate);
        origin_changed!(terminal_entered, true);
        origin_changed!(terminal_completed, true);
        origin_changed!(terminal_held, true);
        origin_changed!(lane_acknowledged, true);
        origin_changed!(inline_hold, InlineHoldPhase::Held);
        origin_changed!(prepared, false);
    }

    #[test]
    fn acknowledged_work_retirement_is_progress_even_without_snapshot_delta() {
        let before = pending_progress();
        assert!(HostedForwardWorkProgress::advanced(before, before, true));
    }

    #[test]
    fn empty_redrive_pass_has_no_effect() {
        assert!(!redrive_ready_pass(0, || panic!("empty pass must not enter work")));
    }

    #[test]
    fn stalled_candidate_does_not_hide_later_phase_progress() {
        let mut calls = 0;
        assert!(redrive_ready_pass(3, || {
            calls += 1;
            calls == 2
        }));
        assert_eq!(calls, 2, "stop the pass at the first actual phase transition");
    }

    #[test]
    fn unchanged_ready_candidates_end_at_the_initial_pass_bound() {
        let before = pending_progress();
        let mut calls = 0;
        assert!(!redrive_ready_pass(3, || {
            calls += 1;
            HostedForwardWorkProgress::advanced(before, before, false)
        }));
        assert_eq!(calls, 3, "no extra attempt or replay after an unchanged pass");
    }
}
