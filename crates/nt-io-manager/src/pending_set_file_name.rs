//! Durable ownership for provider-backed rename/link target-open transactions.
//!
//! The caller buffer is captured once, before the target parent CREATE. Either
//! CREATE or the subsequent SET_INFORMATION may pend, so both buffers and the
//! canonical File identities must outlive an arbitrary provider round trip.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingSetFileNamePhase {
    SourceQuery,
    TargetCreate,
    SourceSet,
    TerminalInline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSetFileName {
    pub source_file_id: u64,
    pub target_file_id: u64,
    pub information_class: u32,
    pub replace_if_exists: bool,
    phase: PendingSetFileNamePhase,
    terminal_status: u32,
    terminal_information: u64,
    target_name: Vec<u8>,
    set_information: Vec<u8>,
}

impl PendingSetFileName {
    fn validate(
        source_file_id: u64,
        target_file_id: u64,
        information_class: u32,
        target_name: &[u8],
        set_information: &[u8],
    ) -> bool {
        source_file_id != 0
            && (target_file_id == 0 || source_file_id != target_file_id)
            && matches!(information_class, 10 | 11)
            && !target_name.is_empty()
            && target_name.len() & 1 == 0
            && !set_information.is_empty()
    }

    pub fn new(
        source_file_id: u64,
        target_file_id: u64,
        information_class: u32,
        replace_if_exists: bool,
        target_name: Vec<u8>,
        set_information: Vec<u8>,
    ) -> Option<Self> {
        (target_file_id != 0
            && Self::validate(
                source_file_id,
                target_file_id,
                information_class,
                &target_name,
                &set_information,
            ))
        .then_some(Self {
            source_file_id,
            target_file_id,
            information_class,
            replace_if_exists,
            phase: PendingSetFileNamePhase::TargetCreate,
            terminal_status: nt_status::NtStatus::PENDING.raw() as u32,
            terminal_information: 0,
            target_name,
            set_information,
        })
    }

    pub fn awaiting_source_query(
        source_file_id: u64,
        information_class: u32,
        replace_if_exists: bool,
        target_name: Vec<u8>,
        set_information: Vec<u8>,
    ) -> Option<Self> {
        Self::validate(
            source_file_id,
            0,
            information_class,
            &target_name,
            &set_information,
        )
        .then_some(Self {
            source_file_id,
            target_file_id: 0,
            information_class,
            replace_if_exists,
            phase: PendingSetFileNamePhase::SourceQuery,
            terminal_status: nt_status::NtStatus::PENDING.raw() as u32,
            terminal_information: 0,
            target_name,
            set_information,
        })
    }

    pub fn phase(&self) -> PendingSetFileNamePhase {
        self.phase
    }

    pub fn target_name(&self) -> &[u8] {
        &self.target_name
    }

    pub fn set_information(&self) -> &[u8] {
        &self.set_information
    }

    pub fn terminal_result(&self) -> Option<(u32, u64)> {
        (self.phase == PendingSetFileNamePhase::TerminalInline)
            .then_some((self.terminal_status, self.terminal_information))
    }

    pub fn advance_to_source_set(&mut self) -> bool {
        if self.phase != PendingSetFileNamePhase::TargetCreate {
            return false;
        }
        self.phase = PendingSetFileNamePhase::SourceSet;
        true
    }

    pub fn advance_to_target_create(&mut self, target_file_id: u64) -> bool {
        if self.phase != PendingSetFileNamePhase::SourceQuery
            || target_file_id == 0
            || target_file_id == self.source_file_id
        {
            return false;
        }
        self.target_file_id = target_file_id;
        self.phase = PendingSetFileNamePhase::TargetCreate;
        true
    }

    pub fn complete_inline(&mut self, status: u32, information: u64) -> bool {
        if !matches!(
            self.phase,
            PendingSetFileNamePhase::SourceQuery | PendingSetFileNamePhase::TargetCreate
        ) || status == nt_status::NtStatus::PENDING.raw() as u32
        {
            return false;
        }
        self.phase = PendingSetFileNamePhase::TerminalInline;
        self.terminal_status = status;
        self.terminal_information = information;
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PendingSetFileNameId(u64);

impl PendingSetFileNameId {
    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    fn new(slot: usize, generation: u32) -> Option<Self> {
        let slot = u32::try_from(slot).ok()?.checked_add(1)?;
        (generation != 0).then_some(Self(((generation as u64) << 32) | slot as u64))
    }

    fn parts(self) -> Option<(usize, u32)> {
        let slot = (self.0 as u32).checked_sub(1)? as usize;
        let generation = (self.0 >> 32) as u32;
        (generation != 0).then_some((slot, generation))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSetFileNameReservation {
    slot: usize,
    generation: u32,
}

#[derive(Clone, Debug)]
struct Slot {
    generation: u32,
    record: Option<PendingSetFileName>,
    updating: bool,
}

#[derive(Clone, Debug)]
pub struct PendingSetFileNameTable {
    slots: Vec<Slot>,
    next_generation: u32,
    initial_reserve: usize,
}

impl Default for PendingSetFileNameTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingSetFileNameTable {
    const DEFAULT_INITIAL_RESERVE: usize = 4;

    pub const fn new() -> Self {
        Self::with_initial_reserve(Self::DEFAULT_INITIAL_RESERVE)
    }

    pub const fn with_initial_reserve(initial_reserve: usize) -> Self {
        Self {
            slots: Vec::new(),
            next_generation: 1,
            initial_reserve,
        }
    }

    pub fn reset(&mut self) -> bool {
        self.slots.clear();
        self.next_generation = 1;
        if self.slots.capacity() < self.initial_reserve {
            self.slots
                .try_reserve(self.initial_reserve - self.slots.capacity())
                .is_ok()
        } else {
            true
        }
    }

    pub fn capacity(&self) -> usize {
        self.slots.capacity()
    }

    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.record.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.generation == 0 && slot.record.is_none() && !slot.updating)
    }

    pub fn reserve(&mut self) -> Option<PendingSetFileNameReservation> {
        let slot = self
            .slots
            .iter()
            .position(|slot| slot.record.is_none() && !slot.updating && slot.generation == 0)
            .or_else(|| {
                let reserve = if self.slots.capacity() == 0 {
                    self.initial_reserve.max(1)
                } else {
                    1
                };
                self.slots.try_reserve(reserve).ok()?;
                self.slots.push(Slot {
                    generation: 0,
                    record: None,
                    updating: false,
                });
                Some(self.slots.len() - 1)
            })?;
        let generation = self.next_generation.max(1);
        self.next_generation = generation.wrapping_add(1).max(1);
        self.slots[slot].generation = generation;
        Some(PendingSetFileNameReservation { slot, generation })
    }

    pub fn cancel_reservation(&mut self, reservation: PendingSetFileNameReservation) -> bool {
        let Some(slot) = self.slots.get_mut(reservation.slot) else {
            return false;
        };
        if slot.generation != reservation.generation || slot.record.is_some() || slot.updating {
            return false;
        }
        slot.generation = 0;
        true
    }

    pub fn park_reserved(
        &mut self,
        reservation: PendingSetFileNameReservation,
        record: PendingSetFileName,
    ) -> Option<PendingSetFileNameId> {
        let slot = self.slots.get_mut(reservation.slot)?;
        if slot.generation != reservation.generation || slot.record.is_some() || slot.updating {
            return None;
        }
        slot.record = Some(record);
        PendingSetFileNameId::new(reservation.slot, reservation.generation)
    }

    pub fn get(&self, id: PendingSetFileNameId) -> Option<&PendingSetFileName> {
        let (slot, generation) = id.parts()?;
        let slot = self.slots.get(slot)?;
        (slot.generation == generation && !slot.updating)
            .then(|| slot.record.as_ref())
            .flatten()
    }

    /// Temporarily remove a record while provider dispatch may re-enter the executive. The slot
    /// remains generation-reserved and cannot be observed or reused until restore/finish.
    pub fn take_for_update(&mut self, id: PendingSetFileNameId) -> Option<PendingSetFileName> {
        let (slot, generation) = id.parts()?;
        let slot = self.slots.get_mut(slot)?;
        if slot.generation != generation || slot.updating {
            return None;
        }
        let record = slot.record.take()?;
        slot.updating = true;
        Some(record)
    }

    pub fn restore_update(&mut self, id: PendingSetFileNameId, record: PendingSetFileName) -> bool {
        let Some((slot, generation)) = id.parts() else {
            return false;
        };
        let Some(slot) = self.slots.get_mut(slot) else {
            return false;
        };
        if slot.generation != generation || !slot.updating || slot.record.is_some() {
            return false;
        }
        slot.record = Some(record);
        slot.updating = false;
        true
    }

    pub fn finish_update(&mut self, id: PendingSetFileNameId) -> bool {
        let Some((slot, generation)) = id.parts() else {
            return false;
        };
        let Some(slot) = self.slots.get_mut(slot) else {
            return false;
        };
        if slot.generation != generation || !slot.updating || slot.record.is_some() {
            return false;
        }
        slot.updating = false;
        slot.generation = 0;
        true
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn record(source: u64, target: u64) -> PendingSetFileName {
        PendingSetFileName::new(source, target, 10, true, vec![b'x', 0], vec![0; 24]).unwrap()
    }

    #[test]
    fn reservation_owns_buffers_across_both_phases_and_rejects_stale_ids() {
        let mut table = PendingSetFileNameTable::with_initial_reserve(1);
        assert!(table.reset());
        let reservation = table.reserve().unwrap();
        let id = table.park_reserved(reservation, record(11, 12)).unwrap();
        assert_eq!(
            table.get(id).unwrap().phase(),
            PendingSetFileNamePhase::TargetCreate
        );
        assert_eq!(table.get(id).unwrap().target_name(), [b'x', 0]);

        let mut owned = table.take_for_update(id).unwrap();
        assert!(table.get(id).is_none());
        let concurrent = table.reserve().unwrap();
        assert!(owned.advance_to_source_set());
        assert!(!owned.advance_to_source_set());
        assert!(table.restore_update(id, owned));
        assert_eq!(
            table.get(id).unwrap().phase(),
            PendingSetFileNamePhase::SourceSet
        );

        let _owned = table.take_for_update(id).unwrap();
        assert!(table.finish_update(id));
        assert!(table.get(id).is_none());
        assert!(table.cancel_reservation(concurrent));
        let replacement = table.reserve().unwrap();
        let replacement_id = table.park_reserved(replacement, record(21, 22)).unwrap();
        assert_ne!(replacement_id, id);
        assert!(table.get(id).is_none());
    }

    #[test]
    fn invalid_records_and_reservation_replays_fail_closed() {
        assert!(PendingSetFileName::new(0, 2, 10, false, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(2, 2, 10, false, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(1, 2, 12, false, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(1, 2, 10, false, vec![1], vec![0; 24]).is_none());

        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        assert!(table.park_reserved(reservation, record(1, 2)).is_some());
        assert!(table.park_reserved(reservation, record(3, 4)).is_none());
        assert!(!table.cancel_reservation(reservation));
    }

    #[test]
    fn inline_terminal_result_is_committed_once() {
        let mut transaction = record(1, 2);
        assert!(transaction.complete_inline(0, 7));
        assert_eq!(transaction.phase(), PendingSetFileNamePhase::TerminalInline);
        assert_eq!(transaction.terminal_result(), Some((0, 7)));
        assert!(!transaction.complete_inline(0, 8));

        let mut pending = record(3, 4);
        assert!(pending.advance_to_source_set());
        assert!(!pending.complete_inline(0, 0));

        let mut query =
            PendingSetFileName::awaiting_source_query(5, 11, false, vec![b'y', 0], vec![0; 24])
                .unwrap();
        assert_eq!(query.phase(), PendingSetFileNamePhase::SourceQuery);
        assert_eq!(query.target_file_id, 0);
        assert!(!query.advance_to_target_create(5));
        assert!(query.advance_to_target_create(6));
        assert_eq!(query.phase(), PendingSetFileNamePhase::TargetCreate);
        assert_eq!(query.target_file_id, 6);
    }
}
