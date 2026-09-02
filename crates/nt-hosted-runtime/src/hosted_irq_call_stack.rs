use crate::{HostedIrqArenaToken, HostedIrqLaneDirection, HostedIrqLaneIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedIrqCallFrame {
    pub source: HostedIrqLaneIdentity,
    pub service: HostedIrqArenaToken,
    pub target: HostedIrqLaneIdentity,
    pub dispatch: HostedIrqArenaToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedIrqCallStackError {
    InvalidFrame,
    SourceIsNotLeaf,
    ActiveTargetHasNoParent,
    InvalidTargetDepth,
    NotTopFrame,
}

fn token_belongs_to_lane(token: HostedIrqArenaToken, lane: HostedIrqLaneIdentity) -> bool {
    token.lane_generation == lane.lane_generation
}

pub fn validate_hosted_irq_call_push(
    frames: &[HostedIrqCallFrame],
    frame: HostedIrqCallFrame,
) -> Result<(), HostedIrqCallStackError> {
    if frame.source == frame.target
        || frame.service.direction != HostedIrqLaneDirection::Service
        || frame.dispatch.direction != HostedIrqLaneDirection::Dispatch
        || !token_belongs_to_lane(frame.service, frame.source)
        || !token_belongs_to_lane(frame.dispatch, frame.target)
    {
        return Err(HostedIrqCallStackError::InvalidFrame);
    }

    if let Some(parent) = frames.last() {
        if frame.source != parent.target
            || frame.service.transaction != parent.dispatch.transaction
            || frame.service.depth != parent.dispatch.depth
        {
            return Err(HostedIrqCallStackError::SourceIsNotLeaf);
        }
    }

    let target_parent = frames
        .iter()
        .rev()
        .find(|candidate| candidate.source == frame.target);
    match target_parent {
        Some(parent) => {
            if parent.service.transaction != frame.dispatch.transaction {
                return Err(HostedIrqCallStackError::ActiveTargetHasNoParent);
            }
            let expected_depth = parent
                .service
                .depth
                .checked_add(1)
                .ok_or(HostedIrqCallStackError::InvalidTargetDepth)?;
            if frame.dispatch.depth != expected_depth {
                return Err(HostedIrqCallStackError::InvalidTargetDepth);
            }
        }
        None if frame.dispatch.depth != 0 => {
            return Err(HostedIrqCallStackError::InvalidTargetDepth)
        }
        None => {}
    }
    Ok(())
}

pub fn validate_hosted_irq_call_pop(
    frames: &[HostedIrqCallFrame],
    frame: HostedIrqCallFrame,
) -> Result<(), HostedIrqCallStackError> {
    if frames.last() == Some(&frame) {
        Ok(())
    } else {
        Err(HostedIrqCallStackError::NotTopFrame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lane(domain_id: u64, generation: u64) -> HostedIrqLaneIdentity {
        HostedIrqLaneIdentity {
            domain_id,
            domain_cookie: domain_id + 10,
            lane_generation: generation,
        }
    }

    fn token(
        lane: HostedIrqLaneIdentity,
        transaction: u64,
        sequence: u64,
        depth: u8,
        direction: HostedIrqLaneDirection,
    ) -> HostedIrqArenaToken {
        HostedIrqArenaToken {
            lane_generation: lane.lane_generation,
            transaction,
            sequence,
            depth,
            direction,
        }
    }

    fn frame(
        source: HostedIrqLaneIdentity,
        source_transaction: u64,
        target: HostedIrqLaneIdentity,
        target_transaction: u64,
        depth: u8,
    ) -> HostedIrqCallFrame {
        HostedIrqCallFrame {
            source,
            service: token(
                source,
                source_transaction,
                100 + depth as u64,
                depth.saturating_sub(1),
                HostedIrqLaneDirection::Service,
            ),
            target,
            dispatch: token(
                target,
                target_transaction,
                200 + depth as u64,
                depth,
                HostedIrqLaneDirection::Dispatch,
            ),
        }
    }

    #[test]
    fn new_target_starts_at_depth_zero() {
        let a = lane(1, 11);
        let b = lane(2, 12);
        let frame = frame(a, 21, b, 22, 0);
        assert_eq!(validate_hosted_irq_call_push(&[], frame), Ok(()));

        let mut invalid = frame;
        invalid.dispatch.depth = 1;
        assert_eq!(
            validate_hosted_irq_call_push(&[], invalid),
            Err(HostedIrqCallStackError::InvalidTargetDepth)
        );
    }

    #[test]
    fn reverse_callback_requires_the_parked_source_parent() {
        let a = lane(1, 11);
        let b = lane(2, 12);
        let import = frame(a, 21, b, 22, 0);
        let callback = frame(b, 22, a, 21, 1);
        assert_eq!(validate_hosted_irq_call_push(&[], import), Ok(()));
        assert_eq!(validate_hosted_irq_call_push(&[import], callback), Ok(()));

        let mut wrong_transaction = callback;
        wrong_transaction.dispatch.transaction = 23;
        assert_eq!(
            validate_hosted_irq_call_push(&[import], wrong_transaction),
            Err(HostedIrqCallStackError::ActiveTargetHasNoParent)
        );

        let mut wrong_depth = callback;
        wrong_depth.dispatch.depth = 0;
        assert_eq!(
            validate_hosted_irq_call_push(&[import], wrong_depth),
            Err(HostedIrqCallStackError::InvalidTargetDepth)
        );
    }

    #[test]
    fn only_the_leaf_lane_can_issue_the_next_call() {
        let a = lane(1, 11);
        let b = lane(2, 12);
        let c = lane(3, 13);
        let import = frame(a, 21, b, 22, 0);
        let invalid = frame(a, 21, c, 23, 0);
        assert_eq!(
            validate_hosted_irq_call_push(&[import], invalid),
            Err(HostedIrqCallStackError::SourceIsNotLeaf)
        );
    }

    #[test]
    fn unwind_is_exact_lifo() {
        let a = lane(1, 11);
        let b = lane(2, 12);
        let import = frame(a, 21, b, 22, 0);
        let callback = frame(b, 22, a, 21, 1);
        let stack = [import, callback];
        assert_eq!(validate_hosted_irq_call_pop(&stack, callback), Ok(()));
        assert_eq!(
            validate_hosted_irq_call_pop(&stack, import),
            Err(HostedIrqCallStackError::NotTopFrame)
        );
    }
}
