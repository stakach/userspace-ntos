//! Deadline values copied from canonical stores without consuming timer or wait state.

use nt_delay_execution::{Queue, TimeSnapshot};
use nt_provider_wait::ProviderTimerTable;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatcherDeadlines {
    pub delay: Option<u64>,
    pub provider_timer: Option<u64>,
}

impl DispatcherDeadlines {
    pub fn collect(queue: &Queue, timers: Option<&ProviderTimerTable>, now: TimeSnapshot) -> Self {
        Self {
            delay: queue.next_deadline(now),
            provider_timer: timers.and_then(|timers| timers.next_deadline(now)),
        }
    }
}

#[cfg(test)]
#[path = "dispatcher_deadlines_tests.rs"]
mod tests;
