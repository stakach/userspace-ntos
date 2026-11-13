//! Bounded observations of the latest VM fault for an exact installer thread incarnation.

use super::SpanOwner;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstallerFaultReceipt {
    pub owner: SpanOwner,
    pub badge: u64,
    pub reply: u64,
    pub fault_ip: u64,
    pub fault_addr: u64,
    pub fault_error_code: u64,
    pub entered_at_100ns: u64,
}

pub struct InstallerFaultReceipts<const N: usize> {
    rows: [Option<InstallerFaultReceipt>; N],
}

impl<const N: usize> InstallerFaultReceipts<N> {
    pub const fn new() -> Self { Self { rows: [None; N] } }

    /// A full table refuses a new owner instead of evicting an unresolved fault.
    pub fn record(&mut self, receipt: InstallerFaultReceipt) -> bool {
        if let Some(row) = self.rows.iter_mut().find(|row| {
            row.is_some_and(|old| old.owner == receipt.owner)
        }) {
            *row = Some(receipt);
            return true;
        }
        if let Some(row) = self.rows.iter_mut().find(|row| row.is_none()) {
            *row = Some(receipt);
            return true;
        }
        false
    }

    pub fn latest(&self, owner: SpanOwner, badge: u64) -> Option<InstallerFaultReceipt> {
        self.rows.iter().flatten().copied().find(|row| {
            row.owner == owner && row.badge == badge
        })
    }

    pub fn retire(&mut self, owner: SpanOwner) {
        if let Some(row) = self.rows.iter_mut().find(|row| {
            row.is_some_and(|old| old.owner == owner)
        }) { *row = None; }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(generation: u64) -> SpanOwner {
        SpanOwner { process_index: 8, process_generation: generation,
            thread_id: 100, thread_generation: generation }
    }

    fn receipt(generation: u64, addr: u64) -> InstallerFaultReceipt {
        InstallerFaultReceipt { owner: owner(generation), badge: 42, reply: 71,
            fault_ip: 0x1234, fault_addr: addr, fault_error_code: 2,
            entered_at_100ns: addr }
    }

    #[test]
    fn exact_generation_replaces_only_its_own_fault_and_retirement_frees_capacity() {
        let mut rows = InstallerFaultReceipts::<2>::new();
        assert!(rows.record(receipt(1, 0x1000)));
        assert!(rows.record(receipt(2, 0x2000)));
        assert_eq!(rows.latest(owner(1), 42).unwrap().fault_addr, 0x1000);
        assert!(rows.record(receipt(1, 0x3000)));
        assert_eq!(rows.latest(owner(1), 42).unwrap().fault_addr, 0x3000);
        assert_eq!(rows.latest(owner(2), 42).unwrap().fault_addr, 0x2000);
        assert_eq!(rows.latest(owner(1), 43), None);
        assert!(!rows.record(receipt(3, 0x4000)));
        rows.retire(owner(1));
        assert!(rows.record(receipt(3, 0x4000)));
        assert_eq!(rows.latest(owner(1), 42), None);
    }
}
