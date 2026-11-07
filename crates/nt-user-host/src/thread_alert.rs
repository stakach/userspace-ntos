//! Per-thread alert bit and retained native wait owner.

use crate::provider_logical_caller::ProviderLogicalCaller;
use alloc::vec::Vec;
use nt_delay_execution::{Deadline, TimeSnapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadKey {
    pub process_id: u32,
    pub thread_id: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParkedWait {
    pub key: ThreadKey,
    pub caller: ProviderLogicalCaller,
    pub process_index: usize,
    pub badge: u64,
    pub reply_cap: u64,
    pub deadline: Deadline,
}

impl ParkedWait {
    pub fn matches_caller(self, current: Option<ProviderLogicalCaller>) -> bool {
        current == Some(self.caller)
            && self.caller.thread().process_id() == self.key.process_id
            && self.caller.thread().thread_id() == self.key.thread_id
            && self.caller.thread().generation() == self.key.generation
            && self.caller.pi() == self.process_index
            && self.caller.badge() == self.badge
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitDecision {
    Alerted,
    TimedOut,
    Park,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeStatus {
    Alerted,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    key: ThreadKey,
    alerted: bool,
    waiter: Option<ParkedWait>,
    ready: Option<WakeStatus>,
    uncertain_reply: bool,
}

pub struct ThreadAlerts {
    records: Vec<Record>,
}

impl ThreadAlerts {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn reserve(&mut self, capacity: usize) -> bool {
        self.records
            .try_reserve(capacity.saturating_sub(self.records.len()))
            .is_ok()
    }

    fn index(&self, key: ThreadKey) -> Option<usize> {
        self.records.iter().position(|record| record.key == key)
    }

    /// Preserve one alert bit. A second alert before the next wait coalesces with the first.
    pub fn alert(&mut self, key: ThreadKey) -> Result<(), ()> {
        let index = if let Some(index) = self.index(key) {
            index
        } else {
            self.records.try_reserve(1).map_err(|_| ())?;
            self.records.push(Record {
                key,
                alerted: false,
                waiter: None,
                ready: None,
                uncertain_reply: false,
            });
            self.records.len() - 1
        };
        let record = &mut self.records[index];
        record.alerted = true;
        if record.waiter.is_some() && record.ready.is_none() {
            record.ready = Some(WakeStatus::Alerted);
        }
        Ok(())
    }

    /// Decide before stealing the Reply. `Park` reserves row capacity and cannot fail later.
    pub fn begin_wait(
        &mut self,
        key: ThreadKey,
        deadline: Deadline,
        now: TimeSnapshot,
    ) -> Result<WaitDecision, ()> {
        if let Some(index) = self.index(key) {
            let record = &mut self.records[index];
            if record.waiter.is_some() || record.uncertain_reply {
                return Err(());
            }
            if record.alerted {
                record.alerted = false;
                return Ok(WaitDecision::Alerted);
            }
        }
        if deadline.is_due(now) {
            return Ok(WaitDecision::TimedOut);
        }
        if self.index(key).is_none() {
            self.records.try_reserve(1).map_err(|_| ())?;
            self.records.push(Record {
                key,
                alerted: false,
                waiter: None,
                ready: None,
                uncertain_reply: false,
            });
        }
        Ok(WaitDecision::Park)
    }

    pub fn park(&mut self, waiter: ParkedWait) -> Result<(), ParkedWait> {
        let Some(index) = self.index(waiter.key) else {
            return Err(waiter);
        };
        let record = &mut self.records[index];
        if record.waiter.is_some() || record.uncertain_reply || waiter.reply_cap == 0 {
            return Err(waiter);
        }
        record.waiter = Some(waiter);
        if record.alerted {
            record.ready = Some(WakeStatus::Alerted);
        }
        Ok(())
    }

    pub fn expire_due(&mut self, now: TimeSnapshot) {
        for record in &mut self.records {
            if record.ready.is_none()
                && record
                    .waiter
                    .is_some_and(|waiter| waiter.deadline.is_due(now))
            {
                record.ready = Some(WakeStatus::TimedOut);
            }
        }
    }

    pub fn next_deadline(&self, now: TimeSnapshot) -> Option<u64> {
        self.records
            .iter()
            .filter(|record| record.ready.is_none())
            .filter_map(|record| record.waiter?.deadline.monotonic_target(now))
            .min()
    }

    pub fn ready(&self) -> Option<(ParkedWait, WakeStatus)> {
        self.records.iter().find_map(|record| {
            if record.uncertain_reply {
                return None;
            }
            Some((record.waiter?, record.ready?))
        })
    }

    /// Only exact acknowledged delivery releases a Reply owner; a failed delivery stays retained.
    pub fn finish_reply(&mut self, key: ThreadKey, acknowledged: bool) {
        let Some(index) = self.index(key) else { return };
        let record = &mut self.records[index];
        if acknowledged {
            if record.ready == Some(WakeStatus::Alerted) {
                record.alerted = false;
            }
            record.waiter = None;
            record.ready = None;
            record.uncertain_reply = false;
        } else {
            record.uncertain_reply = true;
        }
    }

    pub fn cancel(&mut self, key: ThreadKey) -> Option<ParkedWait> {
        let index = self.index(key)?;
        let record = self.records.swap_remove(index);
        record.waiter
    }

    pub fn parked(&self, key: ThreadKey) -> Option<ParkedWait> {
        self.index(key).and_then(|index| self.records[index].waiter)
    }

    pub fn has_thread_id(&self, thread_id: u32) -> bool {
        self.records
            .iter()
            .any(|record| record.key.thread_id == thread_id && record.waiter.is_some())
    }
}

impl Default for ThreadAlerts {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_identity::{ProcessGeneration, ProcessIdentity};
    use crate::thread_binding::ThreadBinding;
    use nt_process::ProcessManager;

    const KEY: ThreadKey = ThreadKey {
        process_id: 4,
        thread_id: 8,
        generation: 2,
    };
    const NOW: TimeSnapshot = TimeSnapshot {
        monotonic_100ns: 100,
        system_time_100ns: 1000,
        clock_generation: 0,
    };
    const ZERO: Deadline = Deadline::Relative {
        monotonic_100ns: 100,
    };
    const LATER: Deadline = Deadline::Relative {
        monotonic_100ns: 200,
    };
    fn caller() -> ProviderLogicalCaller {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("alert.exe", None, None);
        let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
        ProviderLogicalCaller::capture(
            ThreadBinding {
                pi: 1,
                process: ProcessIdentity {
                    pid,
                    generation: ProcessGeneration::Hosted(3),
                },
                tid: u64::from(tid),
                badge: 12,
                role: (),
                tcb: 33,
                reservations: None,
            },
            pm.thread_lifetime(tid).unwrap(),
        )
        .unwrap()
    }
    fn waiter(key: ThreadKey) -> ParkedWait {
        ParkedWait {
            key,
            caller: caller(),
            process_index: 1,
            badge: 12,
            reply_cap: 55,
            deadline: LATER,
        }
    }

    #[test]
    fn prealert_coalesces_and_one_wait_consumes_it() {
        let mut alerts = ThreadAlerts::new();
        alerts.alert(KEY).unwrap();
        alerts.alert(KEY).unwrap();
        assert_eq!(alerts.begin_wait(KEY, ZERO, NOW), Ok(WaitDecision::Alerted));
        assert_eq!(
            alerts.begin_wait(KEY, ZERO, NOW),
            Ok(WaitDecision::TimedOut)
        );
    }

    #[test]
    fn parked_alert_retains_reply_until_exact_ack() {
        let mut alerts = ThreadAlerts::new();
        assert_eq!(alerts.begin_wait(KEY, LATER, NOW), Ok(WaitDecision::Park));
        alerts.park(waiter(KEY)).unwrap();
        alerts.alert(KEY).unwrap();
        assert_eq!(alerts.ready(), Some((waiter(KEY), WakeStatus::Alerted)));
        alerts.finish_reply(KEY, false);
        assert_eq!(alerts.ready(), None);
        assert_eq!(alerts.begin_wait(KEY, ZERO, NOW), Err(()));
    }

    #[test]
    fn timeout_and_recycled_generation_do_not_consume_another_alert() {
        let mut alerts = ThreadAlerts::new();
        let recycled = ThreadKey {
            generation: KEY.generation + 1,
            ..KEY
        };
        assert_eq!(alerts.begin_wait(KEY, LATER, NOW), Ok(WaitDecision::Park));
        alerts.park(waiter(KEY)).unwrap();
        alerts.alert(recycled).unwrap();
        alerts.expire_due(TimeSnapshot {
            monotonic_100ns: 200,
            ..NOW
        });
        assert_eq!(alerts.ready(), Some((waiter(KEY), WakeStatus::TimedOut)));
        alerts.finish_reply(KEY, true);
        assert_eq!(
            alerts.begin_wait(recycled, ZERO, NOW),
            Ok(WaitDecision::Alerted)
        );
    }

    #[test]
    fn parked_reply_requires_exact_physical_and_process_binding() {
        let old = caller();
        let key = ThreadKey {
            process_id: old.thread().process_id(),
            thread_id: old.thread().thread_id(),
            generation: old.thread().generation(),
        };
        let wait = ParkedWait {
            key,
            caller: old,
            ..waiter(key)
        };
        assert!(wait.matches_caller(Some(old)));
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("alert.exe", None, None);
        let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let lifetime = pm.thread_lifetime(tid).unwrap();
        let changed_tcb = ProviderLogicalCaller::capture(
            ThreadBinding {
                pi: 1,
                process: old.process(),
                tid: u64::from(tid),
                badge: 12,
                role: (),
                tcb: 34,
                reservations: None,
            },
            lifetime,
        )
        .unwrap();
        let changed_process = ProviderLogicalCaller::capture(
            ThreadBinding {
                pi: 1,
                process: ProcessIdentity {
                    pid,
                    generation: ProcessGeneration::Hosted(4),
                },
                tid: u64::from(tid),
                badge: 12,
                role: (),
                tcb: 33,
                reservations: None,
            },
            lifetime,
        )
        .unwrap();
        assert!(!wait.matches_caller(Some(changed_tcb)));
        assert!(!wait.matches_caller(Some(changed_process)));
        assert!(!wait.matches_caller(None));
    }
}
