//! Retain native terminal authority after the physical component has returned.

use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalIdentity {
    dispatch: LaneDispatchIdentity,
    resume_epoch: u64,
    binding: LaneBinding,
    key: SuspensionKey,
    owner: SuspensionOwner,
}

impl TerminalIdentity {
    pub const fn lane(self) -> LaneHandle {
        self.dispatch.lane()
    }

    pub const fn key(self) -> SuspensionKey {
        self.key
    }

    pub const fn owner(self) -> SuspensionOwner {
        self.owner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStage {
    Output,
    Context,
    Reply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalPhase {
    Ready {
        stage: TerminalStage,
        last_error: Option<u32>,
    },
    Invoking {
        stage: TerminalStage,
        attempt: u64,
    },
    Indeterminate {
        stage: TerminalStage,
        status: u32,
    },
    Acknowledged {
        local_error: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStageOutcome {
    Acknowledged,
    /// The adapter proves the selected operation performed no effects and may be retried.
    NoEffects(u32),
    /// The operation may have entered. Retain authority without replaying it.
    Indeterminate(u32),
}

/// Exact, single-use evidence for one entered stage. Dropping it never makes replay safe.
///
/// ```compile_fail
/// use nt_component_suspension::TerminalAttempt;
/// fn duplicate(attempt: TerminalAttempt) {
///     let _copy = attempt.clone();
/// }
/// ```
#[derive(Debug)]
pub struct TerminalAttempt {
    identity: TerminalIdentity,
    stage: TerminalStage,
    attempt: u64,
    consumed: bool,
}

pub struct TerminalView<'a, C, R, T> {
    pub frame: &'a SuspensionFrame<C, R>,
    pub payload: &'a T,
    pub phase: TerminalPhase,
}

pub struct RetiredTerminal<C, R, T> {
    pub suspension: CompletedSuspension<C, R>,
    pub payload: T,
}

pub(super) struct TerminalRecord<T> {
    identity: TerminalIdentity,
    payload: T,
    phase: TerminalPhase,
    next_attempt: u64,
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Publish the returned result without releasing its original suspension or native authority.
    /// The resume epoch was reserved before the provider ran; this transition cannot allocate.
    pub fn retain_terminal_running(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        owner: SuspensionOwner,
        payload: T,
    ) -> Result<TerminalIdentity, LaneError> {
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        let frame = lane
            .suspensions
            .top()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key {
            return Err(LaneError::Suspension(SuspensionError::NotTop));
        }
        if frame.owner != owner {
            return Err(LaneError::Suspension(SuspensionError::InvalidIdentity));
        }
        if lane.terminal.is_some()
            || lane.resume_epoch == 0
            || !matches!(frame.phase, SuspensionPhase::Resuming { .. })
        {
            return Err(LaneError::InvalidPhase);
        }
        let identity = TerminalIdentity {
            dispatch: lane.dispatch.ok_or(LaneError::InvalidPhase)?,
            resume_epoch: lane.resume_epoch,
            binding: lane.binding,
            key,
            owner,
        };
        lane.terminal = Some(TerminalRecord {
            identity,
            payload,
            phase: TerminalPhase::Ready {
                stage: TerminalStage::Output,
                last_error: None,
            },
            next_attempt: 1,
        });
        lane.phase = LanePhase::Terminal;
        self.running = None;
        Ok(identity)
    }

    pub fn terminal(
        &self,
        identity: TerminalIdentity,
        reply_object: u64,
    ) -> Result<TerminalView<'_, C, R, T>, LaneError> {
        let record = self.terminal_record(identity, reply_object)?;
        let frame = self
            .lane(identity.lane())?
            .suspensions
            .top()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        Ok(TerminalView {
            frame,
            payload: &record.payload,
            phase: record.phase,
        })
    }

    pub fn terminal_identities(&self) -> impl Iterator<Item = TerminalIdentity> + '_ {
        self.slots.iter().filter_map(|slot| {
            slot.lane
                .as_ref()?
                .terminal
                .as_ref()
                .map(|record| record.identity)
        })
    }

    /// Oldest actionable terminal result. An acknowledged result is eligible only for local
    /// retirement; in-flight and uncertain mechanisms are never selected for replay.
    pub fn next_terminal(&self) -> Option<TerminalIdentity> {
        self.next_terminal_if(|_, _| true)
    }

    /// Skip ineligible terminal results without changing their ownership or stage. Selection is
    /// ordered by admission sequence and lane index, allowing a bounded drain to advance past a
    /// failed local retirement while retaining it for a later local-only retry.
    pub fn next_terminal_if(
        &self,
        mut predicate: impl FnMut(TerminalIdentity, &TerminalView<'_, C, R, T>) -> bool,
    ) -> Option<TerminalIdentity> {
        self.slots
            .iter()
            .filter_map(|slot| {
                let lane = slot.lane.as_ref()?;
                let record = lane.terminal.as_ref()?;
                if !matches!(
                    record.phase,
                    TerminalPhase::Ready { .. } | TerminalPhase::Acknowledged { .. }
                ) {
                    return None;
                }
                let frame = lane.suspensions.top()?;
                let view = TerminalView {
                    frame,
                    payload: &record.payload,
                    phase: record.phase,
                };
                if !predicate(record.identity, &view) {
                    return None;
                }
                Some((
                    (frame.admission_sequence, record.identity.lane().index),
                    record.identity,
                ))
            })
            .min_by_key(|(sequence, _)| *sequence)
            .map(|(_, identity)| identity)
    }

    pub fn has_terminal_in_scope(&self, scope: SuspensionScope) -> bool {
        scope.is_valid()
            && self.slots.iter().any(|slot| {
                slot.lane.as_ref().is_some_and(|lane| {
                    lane.terminal.is_some() && lane.suspensions.contains_scope(scope)
                })
            })
    }

    pub fn begin_terminal_stage(
        &mut self,
        identity: TerminalIdentity,
        reply_object: u64,
        expected: TerminalStage,
    ) -> Result<TerminalAttempt, LaneError> {
        self.terminal_record(identity, reply_object)?;
        let record = self.lane_mut(identity.lane())?.terminal.as_mut().unwrap();
        if !matches!(record.phase, TerminalPhase::Ready { stage, .. } if stage == expected) {
            return Err(LaneError::InvalidPhase);
        }
        let attempt = record.next_attempt;
        record.next_attempt = attempt.checked_add(1).ok_or(LaneError::NoCapacity)?;
        record.phase = TerminalPhase::Invoking {
            stage: expected,
            attempt,
        };
        Ok(TerminalAttempt {
            identity,
            stage: expected,
            attempt,
            consumed: false,
        })
    }

    pub fn record_terminal_stage(
        &mut self,
        attempt: &mut TerminalAttempt,
        reply_object: u64,
        outcome: TerminalStageOutcome,
    ) -> Result<(), LaneError> {
        self.validate_terminal_attempt(attempt, reply_object)?;
        let record = self
            .lane_mut(attempt.identity.lane())?
            .terminal
            .as_mut()
            .unwrap();
        record.phase = next_phase(attempt.stage, outcome);
        attempt.consumed = true;
        Ok(())
    }

    /// Atomically acknowledge output processing and retain its final native status/payload.
    /// Copyout failure can be a completed output stage; it must not replay on a later Reply error.
    pub fn record_terminal_stage_with_payload(
        &mut self,
        attempt: &mut TerminalAttempt,
        reply_object: u64,
        payload: T,
    ) -> Result<(), LaneError> {
        self.validate_terminal_attempt(attempt, reply_object)?;
        if attempt.stage != TerminalStage::Output {
            return Err(LaneError::InvalidPhase);
        }
        let record = self
            .lane_mut(attempt.identity.lane())?
            .terminal
            .as_mut()
            .unwrap();
        record.payload = payload;
        record.phase = next_phase(attempt.stage, TerminalStageOutcome::Acknowledged);
        attempt.consumed = true;
        Ok(())
    }

    fn terminal_record(
        &self,
        identity: TerminalIdentity,
        reply_object: u64,
    ) -> Result<&TerminalRecord<T>, LaneError> {
        self.validate(identity.lane(), reply_object)?;
        let lane = self.lane(identity.lane())?;
        if lane.binding != identity.binding {
            return Err(LaneError::WrongBinding);
        }
        let record = lane.terminal.as_ref().ok_or(LaneError::InvalidPhase)?;
        if record.identity != identity {
            return Err(LaneError::InvalidIdentity);
        }
        let frame = lane.suspensions.top().ok_or(LaneError::InvalidPhase)?;
        if lane.phase != LanePhase::Terminal
            || lane.dispatch != Some(identity.dispatch)
            || frame.key != identity.key
            || frame.owner != identity.owner
            || !matches!(frame.phase, SuspensionPhase::Resuming { .. })
        {
            return Err(LaneError::InvalidPhase);
        }
        Ok(record)
    }

    fn validate_terminal_attempt(
        &self,
        attempt: &TerminalAttempt,
        reply_object: u64,
    ) -> Result<(), LaneError> {
        let record = self.terminal_record(attempt.identity, reply_object)?;
        if attempt.consumed
            || record.phase
                != (TerminalPhase::Invoking {
                    stage: attempt.stage,
                    attempt: attempt.attempt,
                })
        {
            return Err(LaneError::InvalidPhase);
        }
        Ok(())
    }
}

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    /// Retire only after every mechanism ACK and exact local native-authority bookkeeping.
    /// A local failure retains the acknowledged result and permits only another local attempt.
    pub fn finish_terminal(
        &mut self,
        identity: TerminalIdentity,
        reply_object: u64,
        local_retirement: Result<(), u32>,
    ) -> Result<Option<RetiredTerminal<C, R, T>>, LaneError> {
        let record = self.terminal_record(identity, reply_object)?;
        if !matches!(record.phase, TerminalPhase::Acknowledged { .. }) {
            return Err(LaneError::InvalidPhase);
        }
        let lane = self.lane_mut(identity.lane())?;
        if let Err(status) = local_retirement {
            lane.terminal.as_mut().unwrap().phase = TerminalPhase::Acknowledged {
                local_error: Some(status),
            };
            return Ok(None);
        }
        let suspension = lane
            .suspensions
            .complete_dispatch(identity.key, identity.owner)
            .map_err(LaneError::Suspension)?;
        let record = lane.terminal.take().unwrap();
        lane.phase = if lane.suspensions.is_empty() && lane.external_tokens.is_empty() {
            LanePhase::Idle
        } else {
            LanePhase::Suspended
        };
        if lane.phase == LanePhase::Idle {
            lane.dispatch = None;
        }
        Ok(Some(RetiredTerminal {
            suspension,
            payload: record.payload,
        }))
    }
}

fn next_phase(stage: TerminalStage, outcome: TerminalStageOutcome) -> TerminalPhase {
    match outcome {
        TerminalStageOutcome::Acknowledged => match stage {
            TerminalStage::Output => TerminalPhase::Ready {
                stage: TerminalStage::Context,
                last_error: None,
            },
            TerminalStage::Context => TerminalPhase::Ready {
                stage: TerminalStage::Reply,
                last_error: None,
            },
            TerminalStage::Reply => TerminalPhase::Acknowledged { local_error: None },
        },
        TerminalStageOutcome::NoEffects(status) => TerminalPhase::Ready {
            stage,
            last_error: Some(status),
        },
        TerminalStageOutcome::Indeterminate(status) => {
            TerminalPhase::Indeterminate { stage, status }
        }
    }
}

#[cfg(test)]
mod tests;
