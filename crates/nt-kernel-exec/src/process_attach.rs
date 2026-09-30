//! Per-thread process attachment state for the Ke attach family.
//!
//! Process identities supplied to this model must retain the exact process
//! object, including its generation. The caller performs the address-space
//! transition before this model commits a changed attachment.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError<E> {
    WrongThread,
    StaleTarget,
    InvalidNesting,
    InvalidSavedState,
    Exhausted,
    Transition(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SavedAttachState {
    thread: u64,
    sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttachKind {
    Plain,
    Stack,
}

struct AttachFrame<P> {
    previous: P,
    sequence: u64,
    kind: AttachKind,
    changed: bool,
}

/// One KTHREAD's attachment stack. `P` is an exact, retained process identity.
pub struct ProcessAttachState<P> {
    thread: u64,
    original: P,
    current: P,
    frames: Vec<AttachFrame<P>>,
    next_sequence: u64,
}

impl<P: Clone + Eq> ProcessAttachState<P> {
    pub fn new(thread: u64, original: P) -> Self {
        Self {
            thread,
            original: original.clone(),
            current: original,
            frames: Vec::new(),
            next_sequence: 1,
        }
    }

    pub fn current(&self) -> &P {
        &self.current
    }

    /// ReactOS's `KeIsAttachedProcess` tests the APC state index, not whether
    /// the current process differs from the original one.
    pub fn is_attached(&self) -> bool {
        self.frames.iter().any(|frame| frame.changed)
    }

    pub fn original(&self) -> &P {
        &self.original
    }

    pub fn active_depth(&self) -> usize {
        self.frames.len()
    }

    /// Process teardown must retain every identity still reachable through an
    /// active APC state, including the original process.
    pub fn references_process(&self, process: &P) -> bool {
        &self.original == process
            || &self.current == process
            || self.frames.iter().any(|frame| &frame.previous == process)
    }

    /// A thread cannot retire while an attach frame still owns a process.
    /// On failure ownership of all retained identities stays with the caller.
    pub fn retire(self, thread: u64) -> Result<P, (AttachError<()>, Self)> {
        if self.thread != thread {
            return Err((AttachError::WrongThread, self));
        }
        if !self.frames.is_empty() {
            return Err((AttachError::InvalidNesting, self));
        }
        Ok(self.original)
    }

    pub fn attach<E>(
        &mut self,
        thread: u64,
        target: P,
        admit: impl FnOnce(&P) -> bool,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<(), AttachError<E>> {
        self.check_thread(thread)?;
        if !admit(&target) {
            return Err(AttachError::StaleTarget);
        }
        if self.current == target {
            return Ok(());
        }
        if self.is_attached() {
            return Err(AttachError::InvalidNesting);
        }
        self.push(target, AttachKind::Plain, transition).map(|_| ())
    }

    pub fn detach<E>(
        &mut self,
        thread: u64,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<(), AttachError<E>> {
        self.check_thread(thread)?;
        if !self.is_attached() {
            return Ok(());
        }
        let Some(frame) = self.frames.last() else {
            return Ok(());
        };
        if frame.kind != AttachKind::Plain {
            return Err(AttachError::InvalidNesting);
        }
        self.pop(transition)
    }

    pub fn stack_attach<E>(
        &mut self,
        thread: u64,
        target: P,
        admit: impl FnOnce(&P) -> bool,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<SavedAttachState, AttachError<E>> {
        self.check_thread(thread)?;
        if !admit(&target) {
            return Err(AttachError::StaleTarget);
        }
        let sequence = self.push(target, AttachKind::Stack, transition)?;
        Ok(SavedAttachState { thread, sequence })
    }

    pub fn unstack_detach<E>(
        &mut self,
        thread: u64,
        saved: SavedAttachState,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<(), AttachError<E>> {
        self.check_thread(thread)?;
        if saved.thread != thread
            || self.frames.last().is_none_or(|frame| {
                frame.kind != AttachKind::Stack || frame.sequence != saved.sequence
            })
        {
            return Err(AttachError::InvalidSavedState);
        }
        self.pop(transition)
    }

    fn check_thread<E>(&self, thread: u64) -> Result<(), AttachError<E>> {
        if self.thread == thread {
            Ok(())
        } else {
            Err(AttachError::WrongThread)
        }
    }

    fn push<E>(
        &mut self,
        target: P,
        kind: AttachKind,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<u64, AttachError<E>> {
        let sequence = self.next_sequence;
        let next = sequence.checked_add(1).ok_or(AttachError::Exhausted)?;
        self.frames
            .try_reserve(1)
            .map_err(|_| AttachError::Exhausted)?;
        let changed = self.current != target;
        let previous = self.current.clone();
        if changed {
            transition(&self.current, &target).map_err(AttachError::Transition)?;
        }
        self.frames.push(AttachFrame {
            previous,
            sequence,
            kind,
            changed,
        });
        self.current = target;
        self.next_sequence = next;
        Ok(sequence)
    }

    fn pop<E>(
        &mut self,
        transition: impl FnOnce(&P, &P) -> Result<(), E>,
    ) -> Result<(), AttachError<E>> {
        let frame = self.frames.last().expect("admitted attach frame");
        if frame.changed {
            transition(&self.current, &frame.previous).map_err(AttachError::Transition)?;
        }
        let frame = self.frames.pop().expect("admitted attach frame");
        self.current = frame.previous;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_attach_is_single_level_and_same_target_is_noop() {
        let mut state = ProcessAttachState::new(7, (1, 10));
        state
            .attach(7, (1, 10), |_| true, |_, _| -> Result<(), ()> {
                panic!("same target")
            })
            .unwrap();
        assert!(!state.is_attached());
        state
            .attach(7, (2, 20), |_| true, |from, to| {
                assert_eq!((*from, *to), ((1, 10), (2, 20)));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(state.is_attached());
        assert_eq!(
            state.attach(7, (3, 30), |_| true, |_, _| Ok::<_, ()>(())),
            Err(AttachError::InvalidNesting)
        );
        state
            .detach(7, |from, to| {
                assert_eq!((*from, *to), ((2, 20), (1, 10)));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert_eq!(*state.current(), (1, 10));
    }

    #[test]
    fn stack_attach_nests_and_same_target_has_no_alias_transition() {
        let mut state = ProcessAttachState::new(7, 1);
        let original = state
            .stack_attach(7, 1, |_| true, |_, _| -> Result<(), ()> {
                panic!("same original process")
            })
            .unwrap();
        assert!(!state.is_attached());
        state
            .detach(7, |_, _| -> Result<(), ()> {
                panic!("unattached detach")
            })
            .unwrap();
        state
            .unstack_detach(7, original, |_, _| -> Result<(), ()> {
                panic!("same original process")
            })
            .unwrap();
        let first = state.stack_attach(7, 2, |_| true, |_, _| Ok::<_, ()>(())).unwrap();
        let same = state
            .stack_attach(7, 2, |_| true, |_, _| -> Result<(), ()> { panic!("same target") })
            .unwrap();
        let nested = state.stack_attach(7, 3, |_| true, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(*state.current(), 3);
        assert_eq!(
            state.unstack_detach(7, first, |_, _| Ok::<_, ()>(())),
            Err(AttachError::InvalidSavedState)
        );
        state
            .unstack_detach(7, nested, |from, to| {
                assert_eq!((*from, *to), (3, 2));
                Ok::<_, ()>(())
            })
            .unwrap();
        state
            .unstack_detach(7, same, |_, _| -> Result<(), ()> { panic!("same target") })
            .unwrap();
        state
            .unstack_detach(7, first, |from, to| {
                assert_eq!((*from, *to), (2, 1));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(!state.is_attached());
    }

    #[test]
    fn wrong_thread_stale_saved_state_and_failed_transition_do_not_mutate() {
        let mut state = ProcessAttachState::new(7, 1);
        assert_eq!(
            state.stack_attach(8, 2, |_| true, |_, _| Ok::<_, ()>(())),
            Err(AttachError::WrongThread)
        );
        assert_eq!(
            state.stack_attach(7, 2, |_| true, |_, _| Err::<(), _>(5)),
            Err(AttachError::Transition(5))
        );
        assert!(!state.is_attached());
        let saved = state.stack_attach(7, 2, |_| true, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(
            state.unstack_detach(8, saved, |_, _| Ok::<_, ()>(())),
            Err(AttachError::WrongThread)
        );
        assert_eq!(
            state.unstack_detach(7, saved, |_, _| Err::<(), _>(6)),
            Err(AttachError::Transition(6))
        );
        assert_eq!(*state.current(), 2);
        state
            .unstack_detach(7, saved, |_, _| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(
            state.unstack_detach(7, saved, |_, _| Ok::<_, ()>(())),
            Err(AttachError::InvalidSavedState)
        );
    }

    #[test]
    fn process_generation_is_part_of_attachment_identity() {
        let mut state = ProcessAttachState::new(7, (1, 10));
        let saved = state
            .stack_attach(7, (1, 11), |_| true, |_, _| Ok::<_, ()>(()))
            .unwrap();
        assert!(state.is_attached());
        assert_eq!(*state.current(), (1, 11));
        state
            .unstack_detach(7, saved, |_, _| Ok::<_, ()>(()))
            .unwrap();
    }

    #[test]
    fn stale_target_is_refused_before_same_process_shortcut_or_transition() {
        let mut state = ProcessAttachState::new(7, (1, 10));
        assert_eq!(
            state.attach(7, (1, 10), |_| false, |_, _| -> Result<(), ()> {
                panic!("stale same-process attach transitioned")
            }),
            Err(AttachError::StaleTarget)
        );
        assert_eq!(
            state.stack_attach(7, (2, 20), |_| false, |_, _| -> Result<(), ()> {
                panic!("stale process transitioned")
            }),
            Err(AttachError::StaleTarget)
        );
        assert_eq!(state.active_depth(), 0);
        assert_eq!(*state.current(), (1, 10));
    }

    #[test]
    fn thread_and_process_teardown_retains_every_active_identity() {
        let mut state = ProcessAttachState::new(7, (1, 10));
        let first = state
            .stack_attach(7, (2, 20), |_| true, |_, _| Ok::<_, ()>(()))
            .unwrap();
        let second = state
            .stack_attach(7, (3, 30), |_| true, |_, _| Ok::<_, ()>(()))
            .unwrap();
        assert_eq!(state.active_depth(), 2);
        for identity in [(1, 10), (2, 20), (3, 30)] {
            assert!(state.references_process(&identity));
        }
        assert!(!state.references_process(&(2, 21)));
        let state = match state.retire(7) {
            Err((AttachError::InvalidNesting, state)) => state,
            _ => panic!("active attach retired"),
        };
        let mut state = match state.retire(8) {
            Err((AttachError::WrongThread, state)) => state,
            _ => panic!("different thread retired"),
        };
        state.unstack_detach(7, second, |_, _| Ok::<_, ()>(())).unwrap();
        assert!(!state.references_process(&(3, 30)));
        state.unstack_detach(7, first, |_, _| Ok::<_, ()>(())).unwrap();
        assert_eq!(state.active_depth(), 0);
        match state.retire(7) {
            Ok(original) => assert_eq!(original, (1, 10)),
            Err(_) => panic!("detached thread failed to retire"),
        }
    }
}
