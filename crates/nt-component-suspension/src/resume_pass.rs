use super::*;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Position {
    sequence: u64,
    index: u32,
    generation: u64,
}

/// Bounded traversal of original suspension lanes, not a queue or execution authority.
/// Admissions/rearms during a pass must use sequence numbers greater than its starting maximum.
/// A yielded candidate is visited once even if its subsequent claim fails; start a new pass
/// to retry it. Selection still requires an exact live claim before executing any mechanism.
#[derive(Debug)]
pub struct ResumePass {
    after: Option<Position>,
    through: u64,
    exhausted: bool,
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    pub fn resume_pass(&self) -> ResumePass {
        ResumePass {
            after: None,
            through: self
                .frames()
                .map(|(_, frame)| frame.admission_sequence)
                .max()
                .unwrap_or(0),
            exhausted: false,
        }
    }
}

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    fn resumable_tops(&self) -> impl Iterator<Item = (Position, &Lane<C, R, T>)> {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let lane = slot.lane.as_ref()?;
            if lane.phase != LanePhase::Suspended {
                return None;
            }
            let frame = lane.suspensions.top()?;
            if !matches!(
                frame.phase,
                SuspensionPhase::Selected { .. } | SuspensionPhase::Cancelled { .. }
            ) {
                return None;
            }
            Some((
                Position {
                    sequence: frame.admission_sequence,
                    index: index as u32,
                    generation: slot.generation,
                },
                lane,
            ))
        })
    }

    fn resume_at(position: Position, lane: &Lane<C, R, T>) -> LaneResume<R> {
        LaneResume {
            lane: LaneHandle {
                index: position.index,
                generation: position.generation,
            },
            binding: lane.binding,
            suspension: lane
                .suspensions
                .top_resume()
                .expect("selected top has resume state"),
        }
    }

    /// Select the oldest eligible lane top without changing any frame or lane phase. Rejected
    /// tops remain retained and never expose buried frames. The predicate sees only selected or
    /// cancelled tops of suspended lanes, and is not called while a provider lane is running.
    pub fn next_resumable_if(
        &self,
        mut predicate: impl FnMut(&SuspensionFrame<C, R>) -> bool,
    ) -> Option<LaneResume<R>> {
        if self.execution_busy() {
            return None;
        }
        self.resumable_tops()
            .filter(|(_, lane)| predicate(lane.suspensions.top().expect("selected top")))
            .min_by_key(|(position, _)| *position)
            .map(|(position, lane)| Self::resume_at(position, lane))
    }

    /// Visit selected/cancelled lane tops in admission order, including both caller kinds.
    /// Ineligible tops are skipped without exposing buried frames or changing lane ownership.
    /// A busy physical executor leaves the cursor untouched so its owner may retry later.
    pub fn next_resumable_in_pass(
        &self,
        pass: &mut ResumePass,
        mut predicate: impl FnMut(&SuspensionFrame<C, R>) -> bool,
    ) -> Option<LaneResume<R>> {
        if pass.exhausted || self.execution_busy() {
            return None;
        }
        loop {
            let next = self
                .resumable_tops()
                .filter(|(position, _)| {
                    position.sequence <= pass.through
                        && pass.after.is_none_or(|after| *position > after)
                })
                .min_by_key(|(position, _)| *position);
            let Some((position, lane)) = next else {
                pass.exhausted = true;
                return None;
            };
            pass.after = Some(position);
            if predicate(lane.suspensions.top().expect("selected top")) {
                return Some(Self::resume_at(position, lane));
            }
        }
    }
}

#[cfg(test)]
#[path = "resume_pass_tests.rs"]
mod tests;
