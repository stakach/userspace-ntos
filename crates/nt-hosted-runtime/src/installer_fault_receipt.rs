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
    rows: [Option<StoredFault>; N],
}

#[derive(Clone, Copy)]
struct StoredFault {
    receipt: InstallerFaultReceipt,
    claimed: bool,
}

impl<const N: usize> InstallerFaultReceipts<N> {
    pub const fn new() -> Self { Self { rows: [None; N] } }

    /// A full table refuses a new owner instead of evicting an unresolved fault.
    pub fn record(&mut self, receipt: InstallerFaultReceipt) -> bool {
        if let Some(row) = self.rows.iter_mut().find(|row| {
            row.is_some_and(|old| old.receipt.owner == receipt.owner)
        }) {
            *row = Some(StoredFault { receipt, claimed: false });
            return true;
        }
        if let Some(row) = self.rows.iter_mut().find(|row| row.is_none()) {
            *row = Some(StoredFault { receipt, claimed: false });
            return true;
        }
        false
    }

    pub fn latest(&self, owner: SpanOwner, badge: u64) -> Option<InstallerFaultReceipt> {
        self.rows.iter().flatten().map(|row| row.receipt).find(|receipt| {
            receipt.owner == owner && receipt.badge == badge
        })
    }

    /// Claim an ingress witness once, after its exact routed worker and Reply are parked.
    /// Keep the receipt readable for the live gap sampler while its worker is pending.
    /// A matching numeric Reply without the same owner, badge and fault page is insufficient.
    pub fn claim_exact(&mut self, owner: SpanOwner, badge: u64, reply: u64,
        page: u64) -> Option<InstallerFaultReceipt> {
        let row = self.rows.iter_mut().flatten().find(|row| {
            let receipt = row.receipt;
            !row.claimed && receipt.owner == owner && receipt.badge == badge
                && receipt.reply == reply && receipt.fault_addr & !0xfff == page
        })?;
        row.claimed = true;
        Some(row.receipt)
    }

    pub fn retire(&mut self, owner: SpanOwner) {
        if let Some(row) = self.rows.iter_mut().find(|row| {
            row.is_some_and(|old| old.receipt.owner == owner)
        }) {
            *row = None;
        }
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

    #[test]
    fn routed_worker_claim_consumes_only_the_exact_fault_ingress() {
        let mut rows = InstallerFaultReceipts::<1>::new();
        let expected = receipt(1, 0x3123);
        assert!(rows.record(expected));
        assert_eq!(rows.claim_exact(owner(2), 42, 71, 0x3000), None);
        assert_eq!(rows.claim_exact(owner(1), 43, 71, 0x3000), None);
        assert_eq!(rows.claim_exact(owner(1), 42, 72, 0x3000), None);
        assert_eq!(rows.claim_exact(owner(1), 42, 71, 0x4000), None);
        assert_eq!(rows.claim_exact(owner(1), 42, 71, 0x3000), Some(expected));
        assert_eq!(rows.latest(owner(1), 42), Some(expected));
        assert_eq!(rows.claim_exact(owner(1), 42, 71, 0x3000), None);
        let next = receipt(1, 0x4123);
        assert!(rows.record(next));
        assert_eq!(rows.claim_exact(owner(1), 42, 71, 0x4000), Some(next));
    }
}
