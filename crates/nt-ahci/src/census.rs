//! Allocation-free diagnostic accounting, independent of clocks and command authority.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOperation {
    Read,
    Write,
    Barrier,
}

/// Independently sampled diagnostic totals, not an atomic transaction snapshot.
///
/// `commands` counts attempts, including failures, not completed or durable commands.
/// `sectors` counts requested sectors, not bytes transferred. `ticks` sums wrapping elapsed
/// caller-clock ticks; these are not milliseconds without an external clock conversion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoSnapshot {
    pub commands: u64,
    pub sectors: u64,
    pub ticks: u64,
    pub failures: u64,
}

struct Counters {
    commands: AtomicU64,
    sectors: AtomicU64,
    ticks: AtomicU64,
    failures: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            commands: AtomicU64::new(0),
            sectors: AtomicU64::new(0),
            ticks: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> IoSnapshot {
        IoSnapshot {
            commands: self.commands.load(Ordering::Relaxed),
            sectors: self.sectors.load(Ordering::Relaxed),
            ticks: self.ticks.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

/// Operation-separated totals. Recording and observing never authorize or complete I/O.
pub struct CommandCensus {
    read: Counters,
    write: Counters,
    barrier: Counters,
}

impl CommandCensus {
    pub const fn new() -> Self {
        Self {
            read: Counters::new(),
            write: Counters::new(),
            barrier: Counters::new(),
        }
    }

    fn counters(&self, operation: IoOperation) -> &Counters {
        match operation {
            IoOperation::Read => &self.read,
            IoOperation::Write => &self.write,
            IoOperation::Barrier => &self.barrier,
        }
    }

    /// Record exactly one returned attempt, whether successful or failed.
    ///
    /// Admission and timestamp acquisition belong to the caller. Counters wrap on overflow;
    /// relaxed atomics provide diagnostic totals without synchronizing command lifetimes.
    pub fn record(
        &self,
        operation: IoOperation,
        started: u64,
        finished: u64,
        sectors: u64,
        failed: bool,
    ) {
        let counters = self.counters(operation);
        counters.commands.fetch_add(1, Ordering::Relaxed);
        counters.sectors.fetch_add(sectors, Ordering::Relaxed);
        counters
            .ticks
            .fetch_add(finished.wrapping_sub(started), Ordering::Relaxed);
        counters
            .failures
            .fetch_add(u64::from(failed), Ordering::Relaxed);
    }

    pub fn snapshot(&self, operation: IoOperation) -> IoSnapshot {
        self.counters(operation).snapshot()
    }
}

impl Default for CommandCensus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "census_tests.rs"]
mod tests;
