use crate::CmIdentitySource;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use nt_hive_core::CellId;

fn take_identity(source: &CmIdentitySource) -> Result<u64, SystemKeyLeaseError> {
    source.take().ok_or(SystemKeyLeaseError::Exhausted)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemKeyLease {
    pub(crate) token: u64,
    pub(crate) key: CellId,
    pub(crate) physical_path: String,
    valid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemKeyLeaseError {
    Exhausted,
    Invalid,
}

/// Growable CM-owned identities for native handles into the mounted SYSTEM hive.
///
/// A lease stores the stable hive cell rather than a caller path. This preserves an open key's
/// physical identity if `Select\Current` later changes. Whole-hive replacement invalidates every
/// lease because cell identities belong to the replaced mount generation.
pub(crate) struct SystemKeyLeaseBank {
    leases: Vec<Option<SystemKeyLease>>,
    receipts: CloseReceiptBank,
    identities: Rc<CmIdentitySource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CloseReceipt {
    pub(crate) bank: u64,
    pub(crate) slot: u64,
    pub(crate) generation: u64,
    pub(crate) lease_token: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloseAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

struct ReceiptSlot {
    acknowledged: u64,
    pending: Option<CloseReceipt>,
}

struct CloseReceiptBank {
    identity: u64,
    slots: Vec<ReceiptSlot>,
}

impl CloseReceiptBank {
    const fn new() -> Self {
        Self {
            identity: 0,
            slots: Vec::new(),
        }
    }

    fn find(&self, lease_token: u64) -> Option<CloseReceipt> {
        self.slots
            .iter()
            .filter_map(|slot| slot.pending)
            .find(|receipt| receipt.lease_token == lease_token)
    }

    fn prepare(
        &mut self,
        lease_token: u64,
        slot_limit: usize,
        counter: &CmIdentitySource,
    ) -> Result<CloseReceipt, SystemKeyLeaseError> {
        let vacant = self
            .slots
            .iter()
            .position(|slot| slot.pending.is_none() && slot.acknowledged != u64::MAX);
        if vacant.is_none() {
            if self.slots.len() >= slot_limit {
                return Err(SystemKeyLeaseError::Exhausted);
            }
            self.slots
                .try_reserve_exact(1)
                .map_err(|_| SystemKeyLeaseError::Exhausted)?;
        }
        if self.identity == 0 {
            self.identity = take_identity(counter)?;
        }
        let index = vacant.unwrap_or(self.slots.len());
        if vacant.is_none() {
            self.slots.push(ReceiptSlot {
                acknowledged: 0,
                pending: None,
            });
        }
        let slot = &mut self.slots[index];
        let receipt = CloseReceipt {
            bank: self.identity,
            slot: index as u64,
            generation: slot.acknowledged + 1,
            lease_token,
        };
        slot.pending = Some(receipt);
        Ok(receipt)
    }

    fn acknowledge(
        &mut self,
        bank: u64,
        index: u64,
        generation: u64,
    ) -> Result<CloseAcknowledgement, SystemKeyLeaseError> {
        if bank == 0 || bank != self.identity || generation == 0 {
            return Err(SystemKeyLeaseError::Invalid);
        }
        let index = usize::try_from(index).map_err(|_| SystemKeyLeaseError::Invalid)?;
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(SystemKeyLeaseError::Invalid)?;
        if generation <= slot.acknowledged {
            return Ok(CloseAcknowledgement::AlreadyAcknowledged);
        }
        if !slot
            .pending
            .is_some_and(|receipt| receipt.generation == generation)
        {
            return Err(SystemKeyLeaseError::Invalid);
        }
        slot.pending = None;
        slot.acknowledged = generation;
        Ok(CloseAcknowledgement::Acknowledged)
    }
}

impl SystemKeyLeaseBank {
    pub(crate) fn new(identities: Rc<CmIdentitySource>) -> Self {
        Self {
            leases: Vec::new(),
            receipts: CloseReceiptBank::new(),
            identities,
        }
    }

    pub(crate) fn open(
        &mut self,
        key: CellId,
        physical_path: String,
    ) -> Result<u64, SystemKeyLeaseError> {
        let vacant = self.leases.iter().position(Option::is_none);
        if vacant.is_none() {
            self.leases
                .try_reserve_exact(1)
                .map_err(|_| SystemKeyLeaseError::Exhausted)?;
        }
        let token = take_identity(&self.identities)?;
        let lease = SystemKeyLease {
            token,
            key,
            physical_path,
            valid: true,
        };
        if let Some(index) = vacant {
            self.leases[index] = Some(lease);
            return Ok(token);
        }
        self.leases.push(Some(lease));
        Ok(token)
    }

    pub(crate) fn get(&self, token: u64) -> Option<&SystemKeyLease> {
        (token != 0)
            .then(|| {
                self.leases
                    .iter()
                    .flatten()
                    .find(|lease| lease.token == token && lease.valid)
            })
            .flatten()
    }

    pub(crate) fn invalidate(&mut self) {
        // The old cell is no longer readable, but its outstanding owner still needs exact close
        // evidence. Keep only that identity until an explicit close consumes it.
        for lease in self.leases.iter_mut().flatten() {
            lease.valid = false;
            lease.physical_path = String::new();
        }
    }

    #[cfg(test)]
    pub(crate) fn outstanding_count(&self) -> usize {
        self.leases.iter().flatten().count()
    }

    pub(crate) fn prepare_close(
        &mut self,
        token: u64,
    ) -> Result<CloseReceipt, SystemKeyLeaseError> {
        self.prepare_close_with_limit(token, usize::MAX)
    }

    fn prepare_close_with_limit(
        &mut self,
        token: u64,
        slot_limit: usize,
    ) -> Result<CloseReceipt, SystemKeyLeaseError> {
        if token == 0 {
            return Err(SystemKeyLeaseError::Invalid);
        }
        if let Some(receipt) = self.receipts.find(token) {
            return Ok(receipt);
        }
        let index = self
            .leases
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|lease| lease.token == token))
            .ok_or(SystemKeyLeaseError::Invalid)?;
        let receipt = self.receipts.prepare(token, slot_limit, &self.identities)?;
        self.leases[index] = None;
        Ok(receipt)
    }

    pub(crate) fn acknowledge_close(
        &mut self,
        bank: u64,
        slot: u64,
        generation: u64,
    ) -> Result<CloseAcknowledgement, SystemKeyLeaseError> {
        self.receipts.acknowledge(bank, slot, generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU32;
    use core::sync::atomic::{AtomicU32, Ordering};

    fn new_bank() -> SystemKeyLeaseBank {
        static NEXT_INCARNATION: AtomicU32 = AtomicU32::new(1);
        let incarnation = NEXT_INCARNATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .unwrap();
        SystemKeyLeaseBank::new(Rc::new(CmIdentitySource::new(
            NonZeroU32::new(incarnation).unwrap(),
        )))
    }

    #[test]
    fn leases_are_opaque_exact_and_reuse_storage_without_reusing_tokens() {
        let mut bank = new_bank();
        let first = bank
            .open(
                CellId(17),
                String::from(r"\Registry\Machine\System\ControlSet002"),
            )
            .unwrap();
        assert_eq!(bank.get(first).unwrap().key, CellId(17));
        let receipt = bank.prepare_close(first).unwrap();
        bank.acknowledge_close(receipt.bank, receipt.slot, receipt.generation).unwrap();
        assert!(bank.get(first).is_none());

        let second = bank
            .open(CellId(23), String::from(r"\Registry\Machine\System\Select"))
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(bank.get(second).unwrap().key, CellId(23));
        assert_eq!(bank.prepare_close(first), Err(SystemKeyLeaseError::Invalid));
    }

    #[test]
    fn mount_replacement_invalidates_every_lease() {
        let mut bank = new_bank();
        let token = bank.open(CellId(1), String::from("key")).unwrap();
        bank.invalidate();
        assert!(bank.get(token).is_none());
    }

    fn open(bank: &mut SystemKeyLeaseBank) -> u64 {
        bank.open(CellId(7), String::from("key")).unwrap()
    }

    #[test]
    fn retained_close_and_ack_are_independently_retryable() {
        let mut bank = new_bank();
        let token = open(&mut bank);
        let receipt = bank.prepare_close(token).unwrap();
        assert!(bank.get(token).is_none());
        assert_eq!(bank.prepare_close(token), Ok(receipt));
        assert_eq!(
            bank.acknowledge_close(receipt.bank, receipt.slot, receipt.generation),
            Ok(CloseAcknowledgement::Acknowledged)
        );
        assert_eq!(
            bank.acknowledge_close(receipt.bank, receipt.slot, receipt.generation),
            Ok(CloseAcknowledgement::AlreadyAcknowledged)
        );
        assert_eq!(bank.prepare_close(token), Err(SystemKeyLeaseError::Invalid));
    }

    #[test]
    fn old_ack_cannot_release_reused_slot_or_other_outstanding_receipt() {
        let mut bank = new_bank();
        let first = open(&mut bank);
        let first = bank.prepare_close(first).unwrap();
        let other = open(&mut bank);
        let other = bank.prepare_close(other).unwrap();
        assert_ne!(first.slot, other.slot);
        bank.acknowledge_close(first.bank, first.slot, first.generation)
            .unwrap();
        let next = open(&mut bank);
        let next = bank.prepare_close(next).unwrap();
        assert_eq!(next.slot, first.slot);
        assert_eq!(next.generation, first.generation + 1);
        assert_eq!(
            bank.acknowledge_close(first.bank, first.slot, first.generation),
            Ok(CloseAcknowledgement::AlreadyAcknowledged)
        );
        assert_eq!(bank.prepare_close(next.lease_token), Ok(next));
        assert_eq!(bank.prepare_close(other.lease_token), Ok(other));
        assert_eq!(bank.receipts.slots.len(), 2);
    }

    #[test]
    fn foreign_and_future_receipts_never_mutate_the_owner() {
        let mut first = new_bank();
        let mut second = new_bank();
        let a = open(&mut first);
        let b = open(&mut second);
        assert_ne!(a, b);
        assert_eq!(second.prepare_close(a), Err(SystemKeyLeaseError::Invalid));
        let a = first.prepare_close(a).unwrap();
        let b = second.prepare_close(b).unwrap();
        assert_ne!(a.bank, b.bank);
        for (bank, slot, generation) in [
            (a.bank, b.slot, b.generation),
            (b.bank, u64::MAX, b.generation),
            (b.bank, b.slot, b.generation + 1),
            (b.bank, b.slot, 0),
        ] {
            assert_eq!(
                second.acknowledge_close(bank, slot, generation),
                Err(SystemKeyLeaseError::Invalid)
            );
        }
        assert_eq!(second.prepare_close(b.lease_token), Ok(b));
        let mut moved = second;
        assert_eq!(
            moved.acknowledge_close(b.bank, b.slot, b.generation),
            Ok(CloseAcknowledgement::Acknowledged)
        );
    }

    #[test]
    fn invalidated_live_owners_and_pending_receipts_survive_mount_replacement() {
        let mut bank = new_bank();
        let live = open(&mut bank);
        let closing = open(&mut bank);
        let closing = bank.prepare_close(closing).unwrap();
        bank.invalidate();
        assert!(bank.get(live).is_none());
        let receipt = bank.prepare_close(live).unwrap();
        assert_eq!(bank.prepare_close(closing.lease_token), Ok(closing));
        bank.acknowledge_close(receipt.bank, receipt.slot, receipt.generation)
            .unwrap();
        bank.acknowledge_close(closing.bank, closing.slot, closing.generation)
            .unwrap();
        assert_eq!(
            bank.prepare_close(u64::MAX),
            Err(SystemKeyLeaseError::Invalid)
        );
    }

    #[test]
    fn receipt_capacity_and_identity_exhaustion_preserve_the_live_lease() {
        let mut bank = new_bank();
        let token = open(&mut bank);
        let sequence = bank.identities.next_sequence.get();
        assert_eq!(
            bank.prepare_close_with_limit(token, 0),
            Err(SystemKeyLeaseError::Exhausted)
        );
        assert!(bank.get(token).is_some());
        assert_eq!(bank.identities.next_sequence.get(), sequence);
        bank.identities.next_sequence.set(0);
        assert_eq!(
            bank.prepare_close_with_limit(token, 1),
            Err(SystemKeyLeaseError::Exhausted)
        );
        assert!(bank.get(token).is_some());
        assert!(bank.receipts.slots.is_empty());
        assert_eq!(bank.receipts.identity, 0);
        bank.identities.next_sequence.set(sequence);
        assert!(bank.prepare_close(token).is_ok());
    }

    #[test]
    fn exhausted_slot_generation_does_not_wrap_or_reuse_receipt_identity() {
        let mut bank = new_bank();
        bank.receipts.slots.push(ReceiptSlot {
            acknowledged: u64::MAX,
            pending: None,
        });
        let token = open(&mut bank);
        let receipt = bank.prepare_close(token).unwrap();
        assert_eq!(receipt.slot, 1);
        assert_eq!(receipt.generation, 1);
        bank.identities.next_sequence.set(u32::MAX);
        assert!(take_identity(&bank.identities).is_ok());
        assert_eq!(
            take_identity(&bank.identities),
            Err(SystemKeyLeaseError::Exhausted)
        );
    }

    #[test]
    fn reconstruction_shared_source_and_restart_incarnation_reject_old_owners() {
        let source = Rc::new(CmIdentitySource::new(NonZeroU32::new(80).unwrap()));
        let mut first = SystemKeyLeaseBank::new(source.clone());
        let token = open(&mut first);
        let receipt = first.prepare_close(token).unwrap();
        let mut reconstructed = SystemKeyLeaseBank::new(source);
        let local = open(&mut reconstructed);
        let local_receipt = reconstructed.prepare_close(local).unwrap();
        assert_ne!(local, token);
        assert_ne!(local_receipt.bank, receipt.bank);
        assert_eq!(
            reconstructed.prepare_close(token),
            Err(SystemKeyLeaseError::Invalid)
        );
        assert_eq!(
            reconstructed.acknowledge_close(receipt.bank, receipt.slot, receipt.generation),
            Err(SystemKeyLeaseError::Invalid)
        );
        let mut restarted =
            SystemKeyLeaseBank::new(Rc::new(CmIdentitySource::new(NonZeroU32::new(81).unwrap())));
        let restarted_token = open(&mut restarted);
        let restarted_receipt = restarted.prepare_close(restarted_token).unwrap();
        assert_ne!(restarted_token, token);
        assert_ne!(restarted_receipt.bank, receipt.bank);
        assert_eq!(
            restarted.prepare_close(token),
            Err(SystemKeyLeaseError::Invalid)
        );
        assert_eq!(
            restarted.acknowledge_close(receipt.bank, receipt.slot, receipt.generation),
            Err(SystemKeyLeaseError::Invalid)
        );
    }
}
