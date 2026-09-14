//! Serialized Event selection, independent of continuation storage and reply transport.

use crate::DispatcherWaitSource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventSignalMode {
    Set,
    Pulse,
}

/// The adapter retains the triggering Event throughout this transaction. Candidate queries must
/// report only ready waits consuming that exact Event, including complete wait-all readiness.
/// Selection consumes one whole wait transaction and durably removes its candidate from further
/// arbitration. Neither selection nor clearing may deliver replies, resume code, or admit waits.
pub trait EventSignalSelector {
    fn oldest_ready(&self, source: DispatcherWaitSource) -> Option<u64>;
    fn select(&mut self, source: DispatcherWaitSource, sequence: u64);
    fn clear(&mut self);
}

/// Arbitrate a newly signaled Event. Recompute after every consumption: a wait-all can consume
/// another synchronization object needed by a candidate from a different continuation family.
/// Delivery is the caller's responsibility after this returns, with pulse state already cleared.
pub fn select_event_signal<B: EventSignalSelector>(backend: &mut B, mode: EventSignalMode) -> u64 {
    let mut selected = 0;
    loop {
        let next = [
            DispatcherWaitSource::Native,
            DispatcherWaitSource::Gui,
            DispatcherWaitSource::Provider,
        ]
        .into_iter()
        .filter_map(|source| {
            backend
                .oldest_ready(source)
                .filter(|sequence| *sequence != 0)
                .map(|sequence| (source, sequence))
        })
        .min_by_key(|(_, sequence)| *sequence);
        let Some((source, sequence)) = next else {
            break;
        };
        backend.select(source, sequence);
        selected += 1;
    }
    if mode == EventSignalMode::Pulse {
        backend.clear();
    }
    selected
}

#[cfg(test)]
#[path = "event_signal_tests.rs"]
mod tests;
