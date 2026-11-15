//! Bounded, deduplicated record of access-check refusals.
//!
//! An access denial is ordinary for a probing caller, so a refusal is reported once per distinct
//! (object type, object name, desired access, subject) and the report stops at a fixed count.

use alloc::vec::Vec;

/// One refused access, identified by what was asked for and by whom.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessDenialKey {
    /// Caller-chosen object type discriminator.
    pub object_type: u32,
    /// Case-folded hash of the object name; see [`AccessDenialKey::name_hash`].
    pub name: u64,
    pub desired_access: u32,
    pub process: u32,
    /// The effective token the check ran against.
    pub token: u32,
}

impl AccessDenialKey {
    /// FNV-1a over the name with ASCII case folded, as NT object names compare.
    pub fn name_hash(name: impl IntoIterator<Item = u16>) -> u64 {
        name.into_iter().fold(0xcbf2_9ce4_8422_2325, |hash: u64, unit| {
            let unit = if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 0x20 } else { unit };
            (hash ^ u64::from(unit)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    }
}

/// What the reporter should do with a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessDenialReport {
    /// First observation: report it.
    Report,
    /// First observation and the last one the ledger can hold: report it and say reporting stops.
    ReportFinal,
    /// Seen before, or the ledger is full.
    Suppress,
}

pub struct AccessDenialLedger {
    seen: Vec<AccessDenialKey>,
    capacity: usize,
}

impl AccessDenialLedger {
    pub fn new(capacity: usize) -> Self {
        Self { seen: Vec::new(), capacity }
    }

    pub fn observe(&mut self, key: AccessDenialKey) -> AccessDenialReport {
        if self.seen.len() >= self.capacity || self.seen.contains(&key) {
            return AccessDenialReport::Suppress;
        }
        if self.seen.try_reserve(1).is_err() {
            return AccessDenialReport::Suppress;
        }
        self.seen.push(key);
        if self.seen.len() == self.capacity {
            AccessDenialReport::ReportFinal
        } else {
            AccessDenialReport::Report
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, desired_access: u32, token: u32) -> AccessDenialKey {
        AccessDenialKey {
            object_type: 1,
            name: AccessDenialKey::name_hash(name.encode_utf16()),
            desired_access,
            process: 260,
            token,
        }
    }

    #[test]
    fn a_refusal_is_reported_once_per_object_access_and_subject() {
        let mut ledger = AccessDenialLedger::new(8);
        assert_eq!(ledger.observe(key("\\Windows\\ApiPort", 1, 31)), AccessDenialReport::Report);
        assert_eq!(ledger.observe(key("\\WINDOWS\\apiport", 1, 31)), AccessDenialReport::Suppress);
        assert_eq!(ledger.observe(key("\\Windows\\ApiPort", 2, 31)), AccessDenialReport::Report);
        assert_eq!(ledger.observe(key("\\Windows\\ApiPort", 1, 37)), AccessDenialReport::Report);
        assert_eq!(ledger.observe(key("\\Windows\\SbApiPort", 1, 31)), AccessDenialReport::Report);
        let mut other_type = key("\\Windows\\ApiPort", 1, 31);
        other_type.object_type = 2;
        assert_eq!(ledger.observe(other_type), AccessDenialReport::Report);
    }

    #[test]
    fn reporting_stops_at_capacity_and_says_so_once() {
        let mut ledger = AccessDenialLedger::new(2);
        assert_eq!(ledger.observe(key("a", 1, 1)), AccessDenialReport::Report);
        assert_eq!(ledger.observe(key("b", 1, 1)), AccessDenialReport::ReportFinal);
        assert_eq!(ledger.observe(key("c", 1, 1)), AccessDenialReport::Suppress);
        assert_eq!(ledger.observe(key("a", 1, 1)), AccessDenialReport::Suppress);
    }
}
