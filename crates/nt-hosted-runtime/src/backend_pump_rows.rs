//! Borrowed backend dispatches whose pump stopped unfinished (#420).
//!
//! A backend caller (an ACK, a copy, a lifecycle `execute`) has no File row. When its pump
//! stops with no lane to keep it, the unfinished pump `P` is kept here and the caller holds a
//! move-only [`BackendTicket`]. The root boundary resumes each kept pump; a return `T` stays
//! in its row until the ticket's holder collects it, exactly once.

use alloc::vec::Vec;

use crate::file_pump_return::{FilePumpCollect, FilePumpReturned, KeptFilePump};

/// The caller's claim on its kept dispatch. It cannot be copied; collecting consumes it.
#[must_use = "a kept backend dispatch is owed its caller's collection"]
#[derive(Debug, Eq, PartialEq)]
pub struct BackendTicket(u64);

impl BackendTicket {
    pub const fn id(&self) -> u64 { self.0 }
}

/// What the caller's turn found for its ticket.
#[derive(Debug, Eq, PartialEq)]
pub enum BackendCollect<T> {
    /// Still running; the ticket is handed back.
    Pending(BackendTicket),
    /// The true result, exactly once.
    Collected(T),
}

struct Row<P, T> {
    id: u64,
    pump: Option<P>,
    state: KeptFilePump<u64, T>,
}

/// Every kept backend dispatch.
pub struct KeptBackendPumps<P, T> {
    rows: Vec<Row<P, T>>,
    next: u64,
}

impl<P, T> Default for KeptBackendPumps<P, T> {
    fn default() -> Self { Self::new() }
}

impl<P, T> KeptBackendPumps<P, T> {
    pub const fn new() -> Self { Self { rows: Vec::new(), next: 1 } }

    /// Hold room for one more kept dispatch before the dispatch enters, so keeping it later
    /// never allocates.
    pub fn reserve(&mut self) -> Result<(), ()> {
        self.rows.try_reserve(1).map_err(|_| ())
    }

    /// Keep an unfinished pump. Call only after a successful [`Self::reserve`].
    pub fn keep(&mut self, pump: P) -> BackendTicket {
        let id = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        self.rows.push(Row { id, pump: Some(pump), state: KeptFilePump::Suspended(id) });
        BackendTicket(id)
    }

    /// Run first in the caller's turn. `None` only if the ticket names no row, which would mean
    /// another holder collected it: impossible for a move-only ticket.
    pub fn collect(&mut self, ticket: BackendTicket) -> Option<BackendCollect<T>> {
        let index = self.rows.iter().position(|row| row.id == ticket.0)?;
        let row = &mut self.rows[index];
        let mut state = Some(core::mem::replace(&mut row.state, KeptFilePump::DeferredCompletion));
        match KeptFilePump::collect(&mut state, ticket.0) {
            FilePumpCollect::Collected(value) => {
                self.rows.swap_remove(index);
                Some(BackendCollect::Collected(value))
            }
            FilePumpCollect::Pending | FilePumpCollect::Mismatch => {
                row.state = state.expect("collect restores an unmatched state");
                Some(BackendCollect::Pending(ticket))
            }
        }
    }

    /// The ids of kept pumps the root boundary may resume now.
    pub fn resumable(&self, mut ready: impl FnMut(&P) -> bool) -> impl Iterator<Item = u64> + '_ {
        let ids: Vec<u64> = self.rows.iter()
            .filter(|row| row.pump.as_ref().is_some_and(&mut ready))
            .map(|row| row.id).collect();
        ids.into_iter()
    }

    /// Take a kept pump to resume it. Hold no borrow of this table across the resume.
    pub fn take_pump(&mut self, id: u64) -> Option<P> {
        self.rows.iter_mut().find(|row| row.id == id)?.pump.take()
    }

    /// The resumed pump stopped again: keep it.
    pub fn unfinished(&mut self, id: u64, pump: P) -> Result<(), P> {
        match self.rows.iter_mut().find(|row| row.id == id && row.pump.is_none()) {
            Some(row) => { row.pump = Some(pump); Ok(()) }
            None => Err(pump),
        }
    }

    /// The resumed pump returned: hold its result for the ticket's holder.
    pub fn returned(&mut self, id: u64, value: T) -> Result<(), T> {
        let Some(row) = self.rows.iter_mut().find(|row| row.id == id && row.pump.is_none())
        else { return Err(value) };
        let state = core::mem::replace(&mut row.state, KeptFilePump::DeferredCompletion);
        match state.returned(value) {
            FilePumpReturned::Kept(state) => { row.state = state; Ok(()) }
            FilePumpReturned::Publish(value) => { row.state = KeptFilePump::DeferredCompletion; Err(value) }
        }
    }

    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept_one() -> (KeptBackendPumps<&'static str, u32>, BackendTicket) {
        let mut table = KeptBackendPumps::new();
        table.reserve().unwrap();
        let ticket = table.keep("pump");
        (table, ticket)
    }

    #[test]
    fn a_kept_dispatch_is_pending_until_its_pump_returns() {
        let (mut table, ticket) = kept_one();
        let Some(BackendCollect::Pending(ticket)) = table.collect(ticket) else {
            panic!("an unfinished pump has no result yet");
        };
        let id = ticket.id();
        let pump = table.take_pump(id).unwrap();
        table.unfinished(id, pump).unwrap();
        assert!(matches!(table.collect(ticket), Some(BackendCollect::Pending(_))),
            "a pump that stopped again is still pending");
    }

    #[test]
    fn a_resumed_return_is_collected_by_its_ticket_exactly_once() {
        let (mut table, ticket) = kept_one();
        let id = ticket.id();
        assert_eq!(table.resumable(|_| true).collect::<Vec<_>>(), [id]);
        assert_eq!(table.take_pump(id), Some("pump"));
        assert!(table.resumable(|_| true).next().is_none(), "a resuming pump is not resumed twice");
        table.returned(id, 7).unwrap();
        assert_eq!(table.collect(ticket), Some(BackendCollect::Collected(7)),
            "the true result reaches the caller, never the root driver that resumed it");
        assert!(table.is_empty(), "a collected row is gone");
    }

    #[test]
    fn a_return_is_held_only_for_its_own_ticket() {
        let mut table = KeptBackendPumps::<&str, u32>::new();
        table.reserve().unwrap();
        let first = table.keep("a");
        table.reserve().unwrap();
        let second = table.keep("b");
        let id = second.id();
        table.take_pump(id).unwrap();
        table.returned(id, 9).unwrap();
        assert!(matches!(table.collect(first), Some(BackendCollect::Pending(_))));
        assert_eq!(table.collect(second), Some(BackendCollect::Collected(9)));
    }

    #[test]
    fn a_return_for_a_pump_not_taken_is_refused() {
        let (mut table, ticket) = kept_one();
        assert_eq!(table.returned(ticket.id(), 3), Err(3),
            "only a pump that was taken for resume can return");
        assert!(matches!(table.collect(ticket), Some(BackendCollect::Pending(_))));
    }
}
