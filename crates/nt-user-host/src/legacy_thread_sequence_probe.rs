//! Bounded observation of a caller creating several threads before its next event.
//!
//! This is diagnostic state only. It never admits a syscall or owns a Reply.
use nt_types::ProcessIdentity;

const CALLER_SLOTS: usize = 64;
const CREATE_SLOTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedService {
    CreateThread,
    ResumeThread,
    CreateEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub process: ProcessIdentity,
    pub tid: u64,
    pub tcb: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateResult {
    pub status: Option<u32>,
    pub delivered: Option<bool>,
}

impl CreateResult {
    const EMPTY: Self = Self { status: None, delivered: None };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub create_ordinal: u64,
    pub earlier: [CreateResult; 2],
    pub trace: bool,
}

#[derive(Clone, Copy)]
struct Row {
    caller: Option<Caller>,
    creates: u64,
    results: [CreateResult; CREATE_SLOTS],
    traced_calls: u8,
}

impl Row {
    const EMPTY: Self = Self {
        caller: None,
        creates: 0,
        results: [CreateResult::EMPTY; CREATE_SLOTS],
        traced_calls: 0,
    };
}

/// Reuses empty rows first, then evicts the caller with the fewest creates. A caller
/// already approaching the three-create frontier survives unrelated one-off creates.
pub struct LegacyThreadSequenceProbe {
    rows: [Row; CALLER_SLOTS],
    next: usize,
}

impl LegacyThreadSequenceProbe {
    pub const fn new() -> Self {
        Self { rows: [Row::EMPTY; CALLER_SLOTS], next: 0 }
    }

    fn row(&self, caller: Caller) -> Option<usize> {
        self.rows.iter().position(|row| row.caller == Some(caller))
    }

    /// Only the third and later create and its same-caller follow-up become print-worthy.
    pub fn ingress(&mut self, caller: Caller, service: ObservedService) -> Option<Observation> {
        let index = if service == ObservedService::CreateThread {
            match self.row(caller) {
                Some(index) => index,
                None => {
                    let mut index = self.next;
                    let mut fewest_creates = u64::MAX;
                    for offset in 0..CALLER_SLOTS {
                        let candidate = (self.next + offset) % CALLER_SLOTS;
                        let creates = self.rows[candidate].creates;
                        if creates < fewest_creates {
                            index = candidate;
                            fewest_creates = creates;
                            if creates == 0 { break; }
                        }
                    }
                    self.next = (self.next + 1) % CALLER_SLOTS;
                    self.rows[index] = Row { caller: Some(caller), ..Row::EMPTY };
                    index
                }
            }
        } else {
            self.row(caller)?
        };
        let row = &mut self.rows[index];
        if service == ObservedService::CreateThread {
            row.creates = row.creates.saturating_add(1);
            row.results[(row.creates - 1) as usize % CREATE_SLOTS] = CreateResult::EMPTY;
        }
        let trace = row.creates >= 3 && row.traced_calls < 8;
        if trace { row.traced_calls += 1; }
        Some(Observation {
            create_ordinal: row.creates,
            earlier: [row.results[0], row.results[1]],
            trace,
        })
    }

    pub fn replied(&mut self, caller: Caller, service: ObservedService, status: u32, delivered: bool) -> bool {
        let Some(index) = self.row(caller) else { return false };
        let row = &mut self.rows[index];
        if service == ObservedService::CreateThread && row.creates != 0 {
            row.results[(row.creates - 1) as usize % CREATE_SLOTS] = CreateResult {
                status: Some(status), delivered: Some(delivered),
            };
        }
        row.creates >= 3
    }
}

impl Default for LegacyThreadSequenceProbe {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_types::ProcessGeneration;

    fn caller(pid: u32, generation: u64, tid: u64) -> Caller {
        Caller { process: ProcessIdentity { pid, generation: ProcessGeneration::Hosted(generation) },
            tid, tcb: tid + 1000 }
    }

    #[test]
    fn third_create_reports_prior_replies_and_followup_event() {
        let mut probe = LegacyThreadSequenceProbe::new();
        let owner = caller(42, 7, 512);
        for ordinal in 1..=2 {
            assert!(!probe.ingress(owner, ObservedService::CreateThread).unwrap().trace);
            assert!(!probe.replied(owner, ObservedService::CreateThread, 0, true));
            assert_eq!(probe.ingress(owner, ObservedService::ResumeThread).unwrap().create_ordinal, ordinal);
            assert!(!probe.replied(owner, ObservedService::ResumeThread, 0, true));
        }
        let third = probe.ingress(owner, ObservedService::CreateThread).unwrap();
        assert!(third.trace);
        assert_eq!(third.earlier, [CreateResult { status: Some(0), delivered: Some(true) }; 2]);
        assert!(probe.replied(owner, ObservedService::CreateThread, 0, true));
        assert!(probe.ingress(owner, ObservedService::ResumeThread).unwrap().trace);
        assert!(probe.replied(owner, ObservedService::ResumeThread, 0, true));
        assert!(probe.ingress(owner, ObservedService::CreateEvent).unwrap().trace);
    }

    #[test]
    fn reused_tid_in_new_process_generation_cannot_inherit_sequence() {
        let mut probe = LegacyThreadSequenceProbe::new();
        let original = caller(42, 7, 512);
        for _ in 0..3 { probe.ingress(original, ObservedService::CreateThread); }
        assert!(probe.ingress(original, ObservedService::CreateEvent).unwrap().trace);
        assert!(probe.ingress(caller(42, 8, 512), ObservedService::CreateEvent).is_none());
    }

    #[test]
    fn two_create_caller_survives_many_unrelated_one_off_callers() {
        let mut probe = LegacyThreadSequenceProbe::new();
        let original = caller(42, 7, 512);
        for _ in 0..2 { probe.ingress(original, ObservedService::CreateThread); }
        for tid in 1..=128 {
            probe.ingress(caller(43, 8, tid), ObservedService::CreateThread);
        }
        assert!(probe.ingress(original, ObservedService::CreateThread).unwrap().trace);
    }
}
