//! The backend operations running against one IRP's native storage (#420).
//!
//! A hosted backend's dispatch, cancel, completion copy and completion ACK each enter the
//! IRP's native storage. When one of them stops unfinished, its kept pump `T` stays here under
//! its exact [`IrpOperationKey`]. The next identical call collects it instead of issuing the
//! operation again, and any other operation on the same IRP waits: two operations never run
//! against one IRP's storage at once. An operation whose native effect is uncertain is
//! quarantined: its IRP admits nothing again.

use alloc::vec::Vec;

/// One backend operation on one IRP: its storage instance, the IRP, the operation selector,
/// and the exact extent it reads or writes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrpOperationKey {
    pub instance: usize,
    pub irp: u64,
    pub operation: u64,
    pub offset: u64,
    pub len: usize,
}

/// What a backend call may do now.
#[derive(Debug, Eq, PartialEq)]
pub enum IrpOperationAdmission<T> {
    /// No operation runs against this IRP: issue it.
    Issue,
    /// This exact operation is running: its kept pump, taken for collection. The caller hands
    /// it back with [`IrpOperations::still_running`], or ends it with
    /// [`IrpOperations::settled`] or [`IrpOperations::quarantine`].
    Collect(T),
    /// Another operation runs against this IRP, or its effect is quarantined: answer pending
    /// and issue nothing.
    Busy,
}

enum State<T> {
    Running(T),
    /// Taken for collection; the row still owns the IRP.
    Collecting,
    Quarantined,
}

struct Row<T> {
    key: IrpOperationKey,
    state: State<T>,
}

/// Every operation running against a backend IRP's storage.
pub struct IrpOperations<T> {
    rows: Vec<Row<T>>,
}

impl<T> Default for IrpOperations<T> {
    fn default() -> Self { Self::new() }
}

impl<T> IrpOperations<T> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    /// Decide what a call for `key` may do. One IRP has at most one row.
    pub fn admit(&mut self, key: IrpOperationKey) -> IrpOperationAdmission<T> {
        let Some(row) = self.rows.iter_mut().find(|row| row.key.irp == key.irp) else {
            return IrpOperationAdmission::Issue;
        };
        if row.key != key || !matches!(row.state, State::Running(_)) {
            return IrpOperationAdmission::Busy;
        }
        match core::mem::replace(&mut row.state, State::Collecting) {
            State::Running(kept) => IrpOperationAdmission::Collect(kept),
            _ => unreachable!("checked running above"),
        }
    }

    /// Whether any operation owns `irp`. Changes nothing.
    pub fn owns(&self, irp: u64) -> bool {
        self.rows.iter().any(|row| row.key.irp == irp)
    }

    /// Before `key` is admitted, give up the different operation running against its IRP when
    /// `abandonable` says nothing waits for its result: a copy whose pump has returned reads
    /// completion storage and has no other effect. The removed operation is returned for its
    /// caller to collect and drop. A running operation, an identical key, an ACK or a cancel
    /// (whose effects matter) is never given up.
    pub fn abandon_returned(
        &mut self,
        key: IrpOperationKey,
        abandonable: impl FnOnce(&IrpOperationKey, &T) -> bool,
    ) -> Option<(IrpOperationKey, T)> {
        let index = self.rows.iter().position(|row| row.key.irp == key.irp)?;
        let row = &self.rows[index];
        let State::Running(kept) = &row.state else { return None; };
        if row.key == key || !abandonable(&row.key, kept) { return None; }
        let row = self.rows.swap_remove(index);
        match row.state {
            State::Running(kept) => Some((row.key, kept)),
            _ => unreachable!("checked running above"),
        }
    }

    /// Hold room for one more row before an operation enters, so keeping it never allocates.
    pub fn reserve(&mut self) -> Result<(), ()> {
        self.rows.try_reserve(1).map_err(|_| ())
    }

    /// Keep an issued operation that stopped unfinished. Call only after [`Self::reserve`],
    /// for an IRP [`Self::admit`] answered `Issue`.
    pub fn keep(&mut self, key: IrpOperationKey, kept: T) {
        debug_assert!(!self.owns(key.irp), "one IRP has one running operation");
        self.rows.push(Row { key, state: State::Running(kept) });
    }

    /// Quarantine an issued operation whose native effect is uncertain. Call only after
    /// [`Self::reserve`], for an IRP [`Self::admit`] answered `Issue`.
    pub fn quarantine_issued(&mut self, key: IrpOperationKey) {
        debug_assert!(!self.owns(key.irp), "one IRP has one running operation");
        self.rows.push(Row { key, state: State::Quarantined });
    }

    /// The keys of running operations `ready` selects. Changes nothing.
    pub fn ready<'a>(
        &'a self,
        mut ready: impl FnMut(&IrpOperationKey, &T) -> bool + 'a,
    ) -> impl Iterator<Item = IrpOperationKey> + 'a {
        self.rows.iter().filter_map(move |row| match &row.state {
            State::Running(kept) if ready(&row.key, kept) => Some(row.key),
            _ => None,
        })
    }

    /// Take the running operation `key` names, for collection.
    pub fn take(&mut self, key: IrpOperationKey) -> Option<T> {
        let row = self.rows.iter_mut()
            .find(|row| row.key == key && matches!(row.state, State::Running(_)))?;
        match core::mem::replace(&mut row.state, State::Collecting) {
            State::Running(kept) => Some(kept),
            _ => unreachable!("selected running above"),
        }
    }

    /// The collected operation is still running: keep it.
    pub fn still_running(&mut self, key: IrpOperationKey, kept: T) -> Result<(), T> {
        match self.collecting(key) {
            Some(row) => { row.state = State::Running(kept); Ok(()) }
            None => Err(kept),
        }
    }

    /// The collected operation returned and its result was delivered: the IRP is free.
    pub fn settled(&mut self, key: IrpOperationKey) -> bool {
        match self.rows.iter().position(|row| row.key == key
            && matches!(row.state, State::Collecting))
        {
            Some(index) => { self.rows.swap_remove(index); true }
            None => false,
        }
    }

    /// The collected operation's native effect is uncertain: its IRP admits nothing again.
    pub fn quarantine(&mut self, key: IrpOperationKey) -> bool {
        match self.collecting(key) {
            Some(row) => { row.state = State::Quarantined; true }
            None => false,
        }
    }

    fn collecting(&mut self, key: IrpOperationKey) -> Option<&mut Row<T>> {
        self.rows.iter_mut().find(|row| row.key == key && matches!(row.state, State::Collecting))
    }

    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPY: u64 = 2;
    const ACK: u64 = 3;
    const CANCEL: u64 = 4;

    fn key(irp: u64, operation: u64, offset: u64, len: usize) -> IrpOperationKey {
        IrpOperationKey { instance: 1, irp, operation, offset, len }
    }

    fn kept(ops: &mut IrpOperations<&'static str>, key: IrpOperationKey) {
        assert_eq!(ops.admit(key), IrpOperationAdmission::Issue);
        ops.reserve().unwrap();
        ops.keep(key, "pump");
    }

    #[test]
    fn an_identical_call_collects_the_running_operation_instead_of_issuing_it() {
        let mut ops = IrpOperations::new();
        let copy = key(7, COPY, 16, 32);
        kept(&mut ops, copy);
        assert_eq!(ops.admit(copy), IrpOperationAdmission::Collect("pump"),
            "the next identical call collects; it never issues the copy again");
        ops.still_running(copy, "pump").unwrap();
        assert_eq!(ops.admit(copy), IrpOperationAdmission::Collect("pump"),
            "a pump that stopped again is collected again");
        assert!(ops.settled(copy));
        assert_eq!(ops.admit(copy), IrpOperationAdmission::Issue,
            "once settled, a new call is a new operation");
    }

    #[test]
    fn no_other_operation_runs_against_an_irp_while_one_is_running() {
        let mut ops = IrpOperations::new();
        let copy = key(7, COPY, 0, 32);
        kept(&mut ops, copy);
        assert_eq!(ops.admit(key(7, ACK, 0, 0)), IrpOperationAdmission::Busy);
        assert_eq!(ops.admit(key(7, CANCEL, 0, 0)), IrpOperationAdmission::Busy);
        assert_eq!(ops.admit(key(7, COPY, 32, 32)), IrpOperationAdmission::Busy,
            "another extent is another operation, not a collection");
        assert_eq!(ops.admit(key(7, COPY, 0, 16)), IrpOperationAdmission::Busy);
        assert_eq!(ops.admit(IrpOperationKey { instance: 2, ..copy }), IrpOperationAdmission::Busy);
        assert_eq!(ops.admit(key(8, ACK, 0, 0)), IrpOperationAdmission::Issue,
            "another IRP's storage is independent");
        let IrpOperationAdmission::Collect(pump) = ops.admit(copy) else {
            panic!("the running copy is collectable");
        };
        assert_eq!(ops.admit(copy), IrpOperationAdmission::Busy,
            "an operation being collected still owns its IRP");
        ops.still_running(copy, pump).unwrap();
    }

    #[test]
    fn a_quarantined_operation_is_never_issued_again() {
        let mut ops = IrpOperations::<&str>::new();
        let ack = key(9, ACK, 0, 0);
        assert_eq!(ops.admit(ack), IrpOperationAdmission::Issue);
        ops.reserve().unwrap();
        ops.quarantine_issued(ack);
        assert_eq!(ops.admit(ack), IrpOperationAdmission::Busy);
        assert_eq!(ops.admit(key(9, CANCEL, 0, 0)), IrpOperationAdmission::Busy);

        let copy = key(10, COPY, 0, 8);
        kept(&mut ops, copy);
        let IrpOperationAdmission::Collect(_) = ops.admit(copy) else { panic!() };
        assert!(ops.quarantine(copy));
        assert_eq!(ops.admit(copy), IrpOperationAdmission::Busy,
            "an uncertain collected effect is never replayed");
        assert!(!ops.settled(copy), "a quarantined row cannot be settled");
    }

    #[test]
    fn a_returned_copy_nobody_collects_gives_way_to_the_irps_next_operation() {
        let mut ops = IrpOperations::new();
        let copy = key(5, COPY, 0, 16);
        let ack = key(5, ACK, 0, 0);
        kept(&mut ops, copy);
        assert_eq!(ops.abandon_returned(ack, |_, _| false), None,
            "a copy whose pump still runs keeps the IRP");
        assert_eq!(ops.admit(ack), IrpOperationAdmission::Busy);
        assert_eq!(ops.abandon_returned(copy, |_, _| true), None,
            "the identical call collects; it never abandons its own operation");
        assert_eq!(ops.abandon_returned(ack, |running, _| running.operation == COPY),
            Some((copy, "pump")), "the caller collects and drops the returned copy");
        assert_eq!(ops.admit(ack), IrpOperationAdmission::Issue,
            "the ACK runs once the abandoned copy is gone");
        ops.reserve().unwrap();
        ops.keep(ack, "ack");
        assert_eq!(ops.abandon_returned(key(5, COPY, 0, 16), |running, _| running.operation == COPY),
            None, "a running ACK is never abandoned");
    }

    #[test]
    fn a_ready_operation_is_selected_without_effect_and_taken_once() {
        let mut ops = IrpOperations::new();
        let copy = key(1, COPY, 0, 4);
        let ack = key(2, ACK, 0, 0);
        kept(&mut ops, copy);
        kept(&mut ops, ack);
        assert_eq!(ops.ready(|key, _| key.irp == 2).collect::<Vec<_>>(), [ack]);
        assert_eq!(ops.ready(|key, _| key.irp == 2).count(), 1, "selecting changes nothing");
        assert_eq!(ops.take(ack), Some("pump"));
        assert_eq!(ops.take(ack), None, "a taken row is not running");
        assert_eq!(ops.ready(|_, _| true).collect::<Vec<_>>(), [copy]);
        assert!(ops.owns(2), "a taken row still owns its IRP");
        assert!(ops.settled(ack));
        assert!(!ops.owns(2));
    }
}
