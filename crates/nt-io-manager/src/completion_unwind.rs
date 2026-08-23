//! Host-testable NT IRP completion-stack traversal.

use nt_status::NtStatus;

use crate::StackControl;

/// A malformed completion cursor or stack location.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletionUnwindError {
    EmptyStack,
    InvalidCurrentLocation,
    MissingCompletionRoutine,
}

/// The next stack location consumed by `IoCompleteRequest`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompletionUnwindFrame {
    /// The location being completed, using NT's one-based location numbering.
    pub completed_location: u8,
    /// The location visible to a completion routine. NT advances before calling it.
    pub next_location: u8,
    /// The completed location returned pending to its caller.
    pub pending_returned: bool,
    /// Whether this location's completion routine must run.
    pub invoke_routine: bool,
    /// The next location whose `DeviceObject` is passed to the routine, or `None` at the top.
    pub completion_device_location: Option<u8>,
    /// Propagate `SL_PENDING_RETURNED` to the next location when no routine handles this frame.
    pub propagate_pending: bool,
    /// No higher stack location remains after this frame.
    pub final_frame: bool,
}

/// Whether a completion callback returns ownership to the unwinder.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletionRoutineDisposition {
    Continue,
    Stop,
}

impl CompletionRoutineDisposition {
    pub const fn from_status(status: NtStatus) -> Self {
        if status.raw() == NtStatus::MORE_PROCESSING_REQUIRED.raw() {
            Self::Stop
        } else {
            Self::Continue
        }
    }
}

/// Retained-request ownership phases that affect completion publication.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletionOwnerPhase {
    Dispatching,
    StoppedDispatch,
    Pending,
    CancelRoutine,
    CompletingDispatch,
    CompletingPending,
    CompletingCancel,
    CompletedDispatch,
    Ready,
    CompletedCancel,
    CompletingDeferred,
}

/// Why an in-flight completion claim is being released.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CompletionClaimRelease {
    Restore,
    Stop,
    Terminal,
}

/// A completion claim that preserves the exact owner phase from which it was acquired.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompletionOwnerClaim {
    origin: CompletionOwnerPhase,
    claimed: CompletionOwnerPhase,
}

impl CompletionOwnerClaim {
    pub const fn begin(origin: CompletionOwnerPhase) -> Option<Self> {
        let claimed = match origin {
            CompletionOwnerPhase::Dispatching | CompletionOwnerPhase::StoppedDispatch => {
                CompletionOwnerPhase::CompletingDispatch
            }
            CompletionOwnerPhase::Pending => CompletionOwnerPhase::CompletingPending,
            CompletionOwnerPhase::CancelRoutine => CompletionOwnerPhase::CompletingCancel,
            _ => return None,
        };
        Some(Self { origin, claimed })
    }

    pub const fn origin(self) -> CompletionOwnerPhase {
        self.origin
    }

    pub const fn claimed(self) -> CompletionOwnerPhase {
        self.claimed
    }

    /// Resolve the claim. `caller_handed_off` means the dispatch/cancel caller observed the claim
    /// in flight and returned, so ownership can only be published asynchronously.
    pub const fn release(
        self,
        release: CompletionClaimRelease,
        caller_handed_off: bool,
    ) -> CompletionOwnerPhase {
        if caller_handed_off {
            return match release {
                CompletionClaimRelease::Terminal => CompletionOwnerPhase::Ready,
                CompletionClaimRelease::Restore | CompletionClaimRelease::Stop => {
                    CompletionOwnerPhase::Pending
                }
            };
        }
        match release {
            CompletionClaimRelease::Restore => self.origin,
            CompletionClaimRelease::Stop => match self.origin {
                CompletionOwnerPhase::Dispatching | CompletionOwnerPhase::StoppedDispatch => {
                    CompletionOwnerPhase::StoppedDispatch
                }
                CompletionOwnerPhase::Pending => CompletionOwnerPhase::Pending,
                CompletionOwnerPhase::CancelRoutine => CompletionOwnerPhase::CancelRoutine,
                _ => unreachable!(),
            },
            CompletionClaimRelease::Terminal => match self.origin {
                CompletionOwnerPhase::Dispatching | CompletionOwnerPhase::StoppedDispatch => {
                    CompletionOwnerPhase::CompletedDispatch
                }
                CompletionOwnerPhase::Pending => CompletionOwnerPhase::Ready,
                CompletionOwnerPhase::CancelRoutine => CompletionOwnerPhase::CompletedCancel,
                _ => unreachable!(),
            },
        }
    }
}

impl CompletionOwnerPhase {
    /// Transfer a retained inline unwind when the originating dispatch returns.
    pub const fn dispatch_handoff(self) -> Option<Self> {
        match self {
            Self::StoppedDispatch => Some(Self::Pending),
            Self::CompletingDispatch => Some(Self::CompletingDeferred),
            _ => None,
        }
    }
}

/// Stateful bottom-to-top traversal of a fixed NT IRP stack snapshot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CompletionUnwindCursor {
    stack_count: u8,
    current_location: u8,
}

impl CompletionUnwindCursor {
    pub fn new(stack_count: u8, current_location: u8) -> Result<Self, CompletionUnwindError> {
        let terminal_location = stack_count
            .checked_add(1)
            .ok_or(CompletionUnwindError::InvalidCurrentLocation)?;
        if stack_count == 0 {
            return Err(CompletionUnwindError::EmptyStack);
        }
        if current_location == 0 || current_location > terminal_location {
            return Err(CompletionUnwindError::InvalidCurrentLocation);
        }
        Ok(Self {
            stack_count,
            current_location,
        })
    }

    pub const fn stack_count(self) -> u8 {
        self.stack_count
    }

    pub const fn current_location(self) -> u8 {
        self.current_location
    }

    pub const fn is_terminal(self) -> bool {
        self.current_location > self.stack_count
    }

    /// Consume one location and describe the work the component executor must perform.
    pub fn next_frame(
        &mut self,
        control: StackControl,
        completion_routine_present: bool,
        status: NtStatus,
        cancelled: bool,
    ) -> Result<Option<CompletionUnwindFrame>, CompletionUnwindError> {
        if self.is_terminal() {
            return Ok(None);
        }

        let invoke = status.is_success() && control.contains(StackControl::INVOKE_ON_SUCCESS)
            || status.is_error() && control.contains(StackControl::INVOKE_ON_ERROR)
            || cancelled && control.contains(StackControl::INVOKE_ON_CANCEL);
        if invoke && !completion_routine_present {
            return Err(CompletionUnwindError::MissingCompletionRoutine);
        }

        let completed_location = self.current_location;
        self.current_location = self
            .current_location
            .checked_add(1)
            .ok_or(CompletionUnwindError::InvalidCurrentLocation)?;
        let has_upper_location = self.current_location <= self.stack_count;
        let pending_returned = control.contains(StackControl::PENDING_RETURNED);

        Ok(Some(CompletionUnwindFrame {
            completed_location,
            next_location: self.current_location,
            pending_returned,
            invoke_routine: invoke,
            completion_device_location: if invoke && has_upper_location {
                Some(self.current_location)
            } else {
                None
            },
            propagate_pending: !invoke && pending_returned && has_upper_location,
            final_frame: !has_upper_location,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_unwinds_three_locations_bottom_to_top() {
        let mut cursor = CompletionUnwindCursor::new(3, 1).unwrap();
        for expected in 1..=3 {
            let frame = cursor
                .next_frame(
                    StackControl::INVOKE_ON_SUCCESS,
                    true,
                    NtStatus::SUCCESS,
                    false,
                )
                .unwrap()
                .unwrap();
            assert_eq!(frame.completed_location, expected);
            assert_eq!(frame.next_location, expected + 1);
            assert!(frame.invoke_routine);
            assert_eq!(
                frame.completion_device_location,
                (expected < 3).then_some(expected + 1)
            );
            assert_eq!(frame.final_frame, expected == 3);
        }
        assert!(cursor.is_terminal());
        assert_eq!(
            cursor
                .next_frame(StackControl::empty(), false, NtStatus::SUCCESS, false)
                .unwrap(),
            None
        );
    }

    #[test]
    fn error_and_cancel_controls_are_independent() {
        let cases = [
            (
                StackControl::INVOKE_ON_SUCCESS,
                NtStatus::SUCCESS,
                false,
                true,
            ),
            (
                StackControl::INVOKE_ON_SUCCESS,
                NtStatus::UNSUCCESSFUL,
                false,
                false,
            ),
            (
                StackControl::INVOKE_ON_ERROR,
                NtStatus::UNSUCCESSFUL,
                false,
                true,
            ),
            (
                StackControl::INVOKE_ON_ERROR,
                NtStatus::SUCCESS,
                false,
                false,
            ),
            (
                StackControl::INVOKE_ON_CANCEL,
                NtStatus::SUCCESS,
                true,
                true,
            ),
            (
                StackControl::INVOKE_ON_CANCEL,
                NtStatus::UNSUCCESSFUL,
                true,
                true,
            ),
        ];
        for (control, status, cancelled, expected) in cases {
            let mut cursor = CompletionUnwindCursor::new(1, 1).unwrap();
            assert_eq!(
                cursor
                    .next_frame(control, true, status, cancelled)
                    .unwrap()
                    .unwrap()
                    .invoke_routine,
                expected
            );
        }
    }

    #[test]
    fn skipped_pending_frame_propagates_only_to_an_upper_location() {
        let mut cursor = CompletionUnwindCursor::new(2, 1).unwrap();
        let lower = cursor
            .next_frame(
                StackControl::PENDING_RETURNED,
                false,
                NtStatus::SUCCESS,
                false,
            )
            .unwrap()
            .unwrap();
        assert!(lower.pending_returned);
        assert!(lower.propagate_pending);

        let upper = cursor
            .next_frame(
                StackControl::PENDING_RETURNED,
                false,
                NtStatus::SUCCESS,
                false,
            )
            .unwrap()
            .unwrap();
        assert!(upper.pending_returned);
        assert!(!upper.propagate_pending);
    }

    #[test]
    fn invoked_routine_owns_pending_propagation() {
        let mut cursor = CompletionUnwindCursor::new(2, 1).unwrap();
        let frame = cursor
            .next_frame(
                StackControl::PENDING_RETURNED | StackControl::INVOKE_ON_SUCCESS,
                true,
                NtStatus::SUCCESS,
                false,
            )
            .unwrap()
            .unwrap();
        assert!(frame.pending_returned);
        assert!(frame.invoke_routine);
        assert!(!frame.propagate_pending);
    }

    #[test]
    fn caller_can_stop_after_advanced_frame_and_resume_later() {
        let mut cursor = CompletionUnwindCursor::new(3, 1).unwrap();
        let lower = cursor
            .next_frame(
                StackControl::INVOKE_ON_SUCCESS,
                true,
                NtStatus::SUCCESS,
                false,
            )
            .unwrap()
            .unwrap();
        assert_eq!(lower.next_location, 2);

        // STATUS_MORE_PROCESSING_REQUIRED is interpreted by the executor. A later
        // IoCompleteRequest resumes from the cursor already visible to the callback.
        assert_eq!(
            CompletionRoutineDisposition::from_status(NtStatus::MORE_PROCESSING_REQUIRED),
            CompletionRoutineDisposition::Stop
        );
        assert_eq!(
            CompletionRoutineDisposition::from_status(NtStatus::SUCCESS),
            CompletionRoutineDisposition::Continue
        );
        let resumed = CompletionUnwindCursor::new(3, lower.next_location).unwrap();
        assert_eq!(resumed.current_location(), 2);
    }

    #[test]
    fn inline_more_processing_preserves_dispatch_origin() {
        let first = CompletionOwnerClaim::begin(CompletionOwnerPhase::Dispatching).unwrap();
        assert_eq!(first.claimed(), CompletionOwnerPhase::CompletingDispatch);
        let stopped = first.release(CompletionClaimRelease::Stop, false);
        assert_eq!(stopped, CompletionOwnerPhase::StoppedDispatch);

        let second = CompletionOwnerClaim::begin(stopped).unwrap();
        assert_eq!(second.claimed(), CompletionOwnerPhase::CompletingDispatch);
        assert_eq!(
            second.release(CompletionClaimRelease::Terminal, false),
            CompletionOwnerPhase::CompletedDispatch
        );
    }

    #[test]
    fn stopped_dispatch_becomes_async_only_when_dispatch_returns() {
        let first = CompletionOwnerClaim::begin(CompletionOwnerPhase::Dispatching).unwrap();
        let stopped = first.release(CompletionClaimRelease::Stop, false);
        let pending = stopped.dispatch_handoff().unwrap();
        assert_eq!(pending, CompletionOwnerPhase::Pending);

        let later = CompletionOwnerClaim::begin(pending).unwrap();
        assert_eq!(later.claimed(), CompletionOwnerPhase::CompletingPending);
        assert_eq!(
            later.release(CompletionClaimRelease::Terminal, false),
            CompletionOwnerPhase::Ready
        );
    }

    #[test]
    fn caller_handoff_during_completion_resolves_without_origin_race() {
        let claim = CompletionOwnerClaim::begin(CompletionOwnerPhase::Dispatching).unwrap();
        assert_eq!(
            claim.claimed().dispatch_handoff(),
            Some(CompletionOwnerPhase::CompletingDeferred)
        );
        assert_eq!(
            claim.release(CompletionClaimRelease::Stop, true),
            CompletionOwnerPhase::Pending
        );
        assert_eq!(
            claim.release(CompletionClaimRelease::Restore, true),
            CompletionOwnerPhase::Pending
        );
        assert_eq!(
            claim.release(CompletionClaimRelease::Terminal, true),
            CompletionOwnerPhase::Ready
        );
    }

    #[test]
    fn rejects_corrupt_locations_and_missing_routines() {
        assert_eq!(
            CompletionUnwindCursor::new(0, 1),
            Err(CompletionUnwindError::EmptyStack)
        );
        assert_eq!(
            CompletionUnwindCursor::new(2, 0),
            Err(CompletionUnwindError::InvalidCurrentLocation)
        );
        assert_eq!(
            CompletionUnwindCursor::new(2, 4),
            Err(CompletionUnwindError::InvalidCurrentLocation)
        );

        let mut cursor = CompletionUnwindCursor::new(1, 1).unwrap();
        assert_eq!(
            cursor.next_frame(
                StackControl::INVOKE_ON_SUCCESS,
                false,
                NtStatus::SUCCESS,
                false,
            ),
            Err(CompletionUnwindError::MissingCompletionRoutine)
        );
        assert_eq!(cursor.current_location(), 1);
    }
}
