//! Pure owner selection for retained native ALPC service work.
//!
//! An active ring request is exclusive. New invocation tokens must first reach the
//! service in sequence; once admitted, a completed owner takes its terminal ACK
//! before another parked listener can consume the next bounded service pass.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedrivePhase {
    Ready,
    Submitted(u64),
    AckReady,
    AckSubmitted(u64),
    ReplyReady,
    ReplyIndeterminate,
    InvalidTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedriveOwner {
    pub phase: RedrivePhase,
    pub submitted_once: bool,
    pub token_sequence: u64,
}

pub fn select_redrive_owner(
    count: usize,
    active_request: Option<u64>,
    cursor: usize,
    mut owner: impl FnMut(usize) -> RedriveOwner,
) -> Option<usize> {
    if count == 0 { return None; }
    if let Some(request_id) = active_request {
        return (0..count).find(|&index| matches!(owner(index).phase,
            RedrivePhase::Submitted(id) | RedrivePhase::AckSubmitted(id) if id == request_id));
    }
    let first_unsubmitted = (0..count)
        .filter_map(|index| {
            let candidate = owner(index);
            (candidate.phase == RedrivePhase::Ready && !candidate.submitted_once)
                .then_some((index, candidate.token_sequence))
        })
        .min_by_key(|(_, token)| *token)
        .map(|(index, _)| index);
    if first_unsubmitted.is_some() { return first_unsubmitted; }
    if let Some(index) = (0..count).find(|&index| owner(index).phase == RedrivePhase::ReplyReady) {
        return Some(index);
    }
    if let Some((index, _)) = (0..count)
        .filter_map(|index| {
            let candidate = owner(index);
            (candidate.phase == RedrivePhase::AckReady)
                .then_some((index, candidate.token_sequence))
        })
        .min_by_key(|(_, token)| *token)
    { return Some(index); }
    (0..count).map(|offset| (cursor + offset) % count)
        .find(|&index| owner(index).phase != RedrivePhase::InvalidTerminal)
}
