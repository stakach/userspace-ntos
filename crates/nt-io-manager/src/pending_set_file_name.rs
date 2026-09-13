//! Durable ownership for provider-backed rename/link target-open transactions.
//!
//! The caller buffer is captured once, before the target parent CREATE. Either
//! CREATE or the subsequent SET_INFORMATION may pend, so both buffers and the
//! canonical File identities must outlive an arbitrary provider round trip.

use alloc::vec::Vec;

use crate::SetInformationControl;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingSetFileNamePhase {
    SourceQuery,
    TargetCreate,
    SourceSet,
    TerminalInline,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSetFileName<Owner = ()> {
    pub source_file_id: u64,
    pub target_file_id: u64,
    pub information_class: u32,
    pub control: SetInformationControl,
    phase: PendingSetFileNamePhase,
    terminal_status: u32,
    terminal_information: u64,
    target_name: Vec<u8>,
    set_information: Vec<u8>,
    root_directory: u64,
    source_owner: Owner,
}

impl PendingSetFileName<()> {
    fn validate(
        source_file_id: u64,
        target_file_id: u64,
        information_class: u32,
        control: SetInformationControl,
        target_name: &[u8],
        set_information: &[u8],
    ) -> bool {
        source_file_id != 0
            && (target_file_id == 0 || source_file_id != target_file_id)
            && matches!(information_class, 10 | 11 | 31)
            && control.valid_for_class(information_class)
            && !target_name.is_empty()
            && target_name.len() & 1 == 0
            && !set_information.is_empty()
    }

    pub fn new(
        source_file_id: u64,
        target_file_id: u64,
        information_class: u32,
        control: SetInformationControl,
        target_name: Vec<u8>,
        set_information: Vec<u8>,
    ) -> Option<Self> {
        (target_file_id != 0
            && Self::validate(
                source_file_id,
                target_file_id,
                information_class,
                control,
                &target_name,
                &set_information,
            ))
        .then_some(Self {
            source_file_id,
            target_file_id,
            information_class,
            control,
            phase: PendingSetFileNamePhase::TargetCreate,
            terminal_status: nt_status::NtStatus::PENDING.raw() as u32,
            terminal_information: 0,
            target_name,
            set_information,
            root_directory: 0,
            source_owner: (),
        })
    }

    pub fn awaiting_source_query(
        source_file_id: u64,
        information_class: u32,
        control: SetInformationControl,
        target_name: Vec<u8>,
        set_information: Vec<u8>,
    ) -> Option<Self> {
        Self::validate(
            source_file_id,
            0,
            information_class,
            control,
            &target_name,
            &set_information,
        )
        .then_some(Self {
            source_file_id,
            target_file_id: 0,
            information_class,
            control,
            phase: PendingSetFileNamePhase::SourceQuery,
            terminal_status: nt_status::NtStatus::PENDING.raw() as u32,
            terminal_information: 0,
            target_name,
            set_information,
            root_directory: 0,
            source_owner: (),
        })
    }

    /// Preserve the raw caller handle for authentication in the original caller context after
    /// SourceQuery completes. Capturing this value does not resolve or reference its object.
    pub fn with_root_directory(mut self, root_directory: u64) -> Self {
        self.root_directory = root_directory;
        self
    }

    /// Attach the source lifetime exactly once before this transaction can be parked.
    pub fn with_source_owner<Owner>(self, owner: Owner) -> PendingSetFileName<Owner> {
        PendingSetFileName {
            source_file_id: self.source_file_id,
            target_file_id: self.target_file_id,
            information_class: self.information_class,
            control: self.control,
            phase: self.phase,
            terminal_status: self.terminal_status,
            terminal_information: self.terminal_information,
            target_name: self.target_name,
            set_information: self.set_information,
            root_directory: self.root_directory,
            source_owner: owner,
        }
    }
}

impl<Owner> PendingSetFileName<Owner> {
    pub const fn root_directory(&self) -> u64 {
        self.root_directory
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

    pub const fn replace_if_exists(&self) -> bool {
        self.control.replace_if_exists()
    }

    /// Validate postconditions only after a successful target CREATE. Provider failure statuses
    /// remain the caller's responsibility. Hard-link collision precedes the fallible related-device
    /// lookup, so a topology error cannot replace the earlier namespace result.
    pub fn validate_target_open(
        &self,
        create_information: u64,
        related_device: impl FnOnce() -> Result<bool, nt_status::NtStatus>,
    ) -> Result<(), nt_status::NtStatus> {
        const FILE_LINK_INFORMATION: u32 = 11;
        const FILE_EXISTS: u64 = 4;
        if self.information_class == FILE_LINK_INFORMATION
            && !self.replace_if_exists()
            && create_information == FILE_EXISTS
        {
            return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
        }
        if !related_device()? {
            return Err(nt_status::NtStatus::NOT_SAME_DEVICE);
        }
        Ok(())
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
struct Slot<Owner> {
    generation: u32,
    record: Option<PendingSetFileName<Owner>>,
    updating: bool,
    retirement_only: bool,
}

#[derive(Clone, Debug)]
pub struct PendingSetFileNameTable<Owner = ()> {
    slots: Vec<Slot<Owner>>,
    next_generation: u32,
    initial_reserve: usize,
}

impl<Owner> Default for PendingSetFileNameTable<Owner> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Owner> PendingSetFileNameTable<Owner> {
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
        self.slots.iter().all(|slot| {
            slot.generation == 0 && slot.record.is_none() && !slot.updating && !slot.retirement_only
        })
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
                    retirement_only: false,
                });
                Some(self.slots.len() - 1)
            })?;
        let generation = self.next_generation.max(1);
        self.next_generation = generation.wrapping_add(1).max(1);
        self.slots[slot].generation = generation;
        self.slots[slot].retirement_only = false;
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
        slot.retirement_only = false;
        true
    }

    pub fn park_reserved(
        &mut self,
        reservation: PendingSetFileNameReservation,
        record: PendingSetFileName<Owner>,
    ) -> Option<PendingSetFileNameId> {
        let slot = self.slots.get_mut(reservation.slot)?;
        if slot.generation != reservation.generation || slot.record.is_some() || slot.updating {
            return None;
        }
        slot.record = Some(record);
        slot.retirement_only = false;
        PendingSetFileNameId::new(reservation.slot, reservation.generation)
    }

    /// Retain an inline transaction solely until target retirement succeeds. No IRP or reply
    /// identity is manufactured, and the transaction keeps its existing source lifetime owner.
    pub fn park_retirement(
        &mut self,
        reservation: PendingSetFileNameReservation,
        record: PendingSetFileName<Owner>,
    ) -> Option<PendingSetFileNameId> {
        let id = self.park_reserved(reservation, record)?;
        self.slots[reservation.slot].retirement_only = true;
        Some(id)
    }

    /// Select the next idle retirement-only record, returning the next scan cursor and exact
    /// generation identity. Checked-out records are invisible until restored after refusal.
    pub fn next_retirement_from(&self, start: usize) -> Option<(usize, PendingSetFileNameId)> {
        self.slots
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(index, slot)| {
                if !slot.retirement_only || slot.updating || slot.record.is_none() {
                    return None;
                }
                Some((
                    index + 1,
                    PendingSetFileNameId::new(index, slot.generation)?,
                ))
            })
    }

    pub fn get(&self, id: PendingSetFileNameId) -> Option<&PendingSetFileName<Owner>> {
        let (slot, generation) = id.parts()?;
        let slot = self.slots.get(slot)?;
        (slot.generation == generation && !slot.updating)
            .then(|| slot.record.as_ref())
            .flatten()
    }

    /// Temporarily remove a record while provider dispatch may re-enter the executive. The slot
    /// remains generation-reserved and cannot be observed or reused until restore/finish.
    pub fn take_for_update(
        &mut self,
        id: PendingSetFileNameId,
    ) -> Option<PendingSetFileName<Owner>> {
        let (slot, generation) = id.parts()?;
        let slot = self.slots.get_mut(slot)?;
        if slot.generation != generation || slot.updating {
            return None;
        }
        let record = slot.record.take()?;
        slot.updating = true;
        Some(record)
    }

    pub fn restore_update(
        &mut self,
        id: PendingSetFileNameId,
        record: PendingSetFileName<Owner>,
    ) -> bool {
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
        slot.retirement_only = false;
        true
    }

    /// After real completion delivery and ACK, hand a checked-out transaction to target-only
    /// retirement without allocating or changing its generation identity.
    pub fn restore_retirement(
        &mut self,
        id: PendingSetFileNameId,
        record: PendingSetFileName<Owner>,
    ) -> bool {
        let Some((slot, _)) = id.parts() else {
            return false;
        };
        if !self.restore_update(id, record) {
            return false;
        }
        self.slots[slot].retirement_only = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::Cell;

    use super::*;

    fn record(source: u64, target: u64) -> PendingSetFileName {
        PendingSetFileName::new(
            source,
            target,
            10,
            SetInformationControl::ReplaceIfExists(true),
            vec![b'x', 0],
            vec![0; 24],
        )
        .unwrap()
    }

    struct SourceOwner(Rc<Cell<usize>>);

    impl Drop for SourceOwner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn nonclone_source_owner_survives_all_transaction_phases_and_slot_retirement() {
        let drops = Rc::new(Cell::new(0));
        let transaction = PendingSetFileName::awaiting_source_query(
            1,
            10,
            SetInformationControl::ReplaceIfExists(true),
            vec![b'x', 0],
            vec![0; 24],
        )
        .unwrap()
        .with_source_owner(SourceOwner(Rc::clone(&drops)));
        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.park_reserved(reservation, transaction).unwrap();

        let mut transaction = table.take_for_update(id).unwrap();
        assert!(table.take_for_update(id).is_none());
        assert!(table.get(id).is_none());
        assert_eq!(drops.get(), 0);
        assert!(transaction.advance_to_target_create(2));
        assert!(table.restore_update(id, transaction));
        assert_eq!(drops.get(), 0);

        let mut transaction = table.take_for_update(id).unwrap();
        assert!(transaction.advance_to_source_set());
        assert!(table.restore_update(id, transaction));
        assert_eq!(drops.get(), 0);
        let transaction = table.take_for_update(id).unwrap();
        assert!(table.finish_update(id));
        assert!(table.get(id).is_none());
        drop(table);
        assert_eq!(drops.get(), 0);
        assert_eq!(transaction.target_name(), [b'x', 0]);
        assert_eq!(transaction.set_information(), &[0; 24]);
        drop(transaction);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn inline_terminal_record_retains_source_until_transaction_drop() {
        let drops = Rc::new(Cell::new(0));
        let mut transaction = record(1, 2).with_source_owner(SourceOwner(Rc::clone(&drops)));
        assert!(transaction.complete_inline(0xc000_0001, 0));
        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.park_reserved(reservation, transaction).unwrap();
        let transaction = table.take_for_update(id).unwrap();
        assert_eq!(transaction.terminal_result(), Some((0xc000_0001, 0)));
        assert!(table.finish_update(id));
        assert_eq!(drops.get(), 0);
        drop(transaction);
        assert_eq!(drops.get(), 1);
        drop(table);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn dropping_table_releases_only_records_it_still_owns() {
        let drops = Rc::new(Cell::new(0));
        let mut table = PendingSetFileNameTable::new();
        for source in [1, 3] {
            let reservation = table.reserve().unwrap();
            table
                .park_reserved(
                    reservation,
                    record(source, source + 1).with_source_owner(SourceOwner(Rc::clone(&drops))),
                )
                .unwrap();
        }
        assert_eq!(drops.get(), 0);
        drop(table);
        assert_eq!(drops.get(), 2);
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
        let rename = SetInformationControl::ReplaceIfExists(false);
        assert!(PendingSetFileName::new(0, 2, 10, rename, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(2, 2, 10, rename, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(1, 2, 12, rename, vec![1, 0], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(1, 2, 10, rename, vec![1], vec![0; 24]).is_none());
        assert!(PendingSetFileName::new(
            1,
            2,
            31,
            SetInformationControl::ReplaceIfExists(false),
            vec![1, 0],
            vec![0; 24],
        )
        .is_none());
        assert!(PendingSetFileName::new(
            1,
            2,
            31,
            SetInformationControl::ClusterCount(7),
            vec![1, 0],
            vec![0; 24],
        )
        .is_some());

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

        let mut query = PendingSetFileName::awaiting_source_query(
            5,
            11,
            SetInformationControl::ReplaceIfExists(false),
            vec![b'y', 0],
            vec![0; 24],
        )
        .unwrap();
        assert_eq!(query.phase(), PendingSetFileNamePhase::SourceQuery);
        assert_eq!(query.target_file_id, 0);
        assert!(!query.advance_to_target_create(5));
        assert!(query.advance_to_target_create(6));
        assert_eq!(query.phase(), PendingSetFileNamePhase::TargetCreate);
        assert_eq!(query.target_file_id, 6);
    }

    #[test]
    fn root_directory_raw_handle_and_source_owner_survive_all_pending_phases() {
        let drops = Rc::new(Cell::new(0));
        let original_handle = 0xffff_ffff_1234_5678;
        let mut caller_handle = original_handle;
        let transaction = PendingSetFileName::awaiting_source_query(
            1,
            10,
            SetInformationControl::ReplaceIfExists(false),
            vec![b'x', 0],
            vec![0; 24],
        )
        .unwrap()
        .with_root_directory(caller_handle)
        .with_source_owner(SourceOwner(drops.clone()));
        // A changed caller variable or process handle table is not resolved by this container.
        caller_handle = 0x80;
        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.park_reserved(reservation, transaction).unwrap();
        assert_eq!(table.get(id).unwrap().root_directory(), original_handle);
        assert_ne!(table.get(id).unwrap().root_directory(), caller_handle);
        let mut transaction = table.take_for_update(id).unwrap();
        assert_eq!(transaction.root_directory(), original_handle);
        assert!(transaction.advance_to_target_create(2));
        assert!(table.restore_update(id, transaction));
        assert_eq!(drops.get(), 0);
        let mut transaction = table.take_for_update(id).unwrap();
        assert_eq!(transaction.root_directory(), original_handle);
        assert!(transaction.advance_to_source_set());
        assert!(table.restore_update(id, transaction));
        assert_eq!(drops.get(), 0);
        let transaction = table.take_for_update(id).unwrap();
        assert!(table.finish_update(id));
        assert_eq!(transaction.root_directory(), original_handle);
        drop(transaction);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn root_directory_defaults_to_zero_and_survives_inline_terminal() {
        assert_eq!(record(1, 2).root_directory(), 0);
        let query = PendingSetFileName::awaiting_source_query(
            1,
            10,
            SetInformationControl::ReplaceIfExists(false),
            vec![b'x', 0],
            vec![0; 24],
        )
        .unwrap();
        assert_eq!(query.root_directory(), 0);
        let mut query = query.with_root_directory(0x100).with_source_owner(());
        assert!(query.complete_inline(nt_status::NtStatus::INVALID_HANDLE.raw() as u32, 0));
        assert_eq!(query.root_directory(), 0x100);
    }

    #[test]
    fn target_open_nonreplacing_link_collision_skips_related_device_lookup() {
        let link = PendingSetFileName::new(
            1,
            2,
            11,
            SetInformationControl::ReplaceIfExists(false),
            vec![b'x', 0],
            vec![0; 24],
        )
        .unwrap();
        assert_eq!(
            link.validate_target_open(4, || panic!("collision must precede topology lookup")),
            Err(nt_status::NtStatus::OBJECT_NAME_COLLISION)
        );
        for information in [0, 1, 2, 3, 5, u64::MAX] {
            assert_eq!(
                link.validate_target_open(information, || Ok(false)),
                Err(nt_status::NtStatus::NOT_SAME_DEVICE)
            );
            assert_eq!(link.validate_target_open(information, || Ok(true)), Ok(()));
            assert_eq!(
                link.validate_target_open(information, || Err(nt_status::NtStatus::INVALID_HANDLE)),
                Err(nt_status::NtStatus::INVALID_HANDLE)
            );
        }
    }

    #[test]
    fn target_open_existing_name_is_allowed_for_rename_replacing_link_and_move_cluster() {
        for (class, control) in [
            (10, SetInformationControl::ReplaceIfExists(false)),
            (10, SetInformationControl::ReplaceIfExists(true)),
            (11, SetInformationControl::ReplaceIfExists(true)),
            (31, SetInformationControl::ClusterCount(7)),
        ] {
            let transaction =
                PendingSetFileName::new(1, 2, class, control, vec![b'x', 0], vec![0; 24]).unwrap();
            assert_eq!(transaction.validate_target_open(4, || Ok(true)), Ok(()));
            assert_eq!(
                transaction.validate_target_open(4, || Ok(false)),
                Err(nt_status::NtStatus::NOT_SAME_DEVICE)
            );
            assert_eq!(
                transaction
                    .validate_target_open(4, || Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED)),
                Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED)
            );
        }
    }

    #[test]
    fn retirement_only_refusal_restore_retains_owner_until_successful_finish_and_drop() {
        let drops = Rc::new(Cell::new(0));
        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        let mut transaction = record(1, 2)
            .with_root_directory(0x80)
            .with_source_owner(SourceOwner(drops.clone()));
        assert!(transaction.complete_inline(nt_status::NtStatus::INVALID_PARAMETER.raw() as u32, 0));
        let id = table.park_retirement(reservation, transaction).unwrap();
        assert_eq!(table.next_retirement_from(0), Some((1, id)));
        let transaction = table.take_for_update(id).unwrap();
        assert!(table.next_retirement_from(0).is_none());
        assert!(table.take_for_update(id).is_none());
        assert_eq!(drops.get(), 0);
        // A refused target-retirement call returns the same checked-out transaction for retry.
        assert!(table.restore_update(id, transaction));
        assert_eq!(table.next_retirement_from(0), Some((1, id)));
        let transaction = table.take_for_update(id).unwrap();
        assert_eq!(transaction.root_directory(), 0x80);
        assert_eq!(transaction.target_file_id, 2);
        assert_eq!(
            transaction.terminal_result(),
            Some((nt_status::NtStatus::INVALID_PARAMETER.raw() as u32, 0))
        );
        assert!(table.finish_update(id));
        assert!(table.next_retirement_from(0).is_none());
        assert!(table.is_empty());
        assert_eq!(drops.get(), 0);
        drop(transaction);
        assert_eq!(drops.get(), 1);
        drop(table);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn retirement_scan_skips_regular_pending_reserved_and_checked_out_rows() {
        let mut table = PendingSetFileNameTable::new();
        let ordinary = table.reserve().unwrap();
        let ordinary_id = table.park_reserved(ordinary, record(1, 2)).unwrap();
        let empty = table.reserve().unwrap();
        let retirement = table.reserve().unwrap();
        let retirement_id = table.park_retirement(retirement, record(3, 4)).unwrap();
        assert_eq!(table.next_retirement_from(0), Some((3, retirement_id)));
        assert!(table.next_retirement_from(3).is_none());
        assert!(table.next_retirement_from(usize::MAX).is_none());
        let transaction = table.take_for_update(retirement_id).unwrap();
        assert!(table.next_retirement_from(0).is_none());
        assert!(table.get(ordinary_id).is_some());
        assert!(table.restore_update(retirement_id, transaction));
        assert_eq!(table.next_retirement_from(1), Some((3, retirement_id)));
        assert!(table.cancel_reservation(empty));
    }

    #[test]
    fn retirement_slot_reuse_clears_tag_and_cannot_revalidate_stale_identity() {
        let mut table = PendingSetFileNameTable::new();
        let first = table.reserve().unwrap();
        let stale = table.park_retirement(first, record(1, 2)).unwrap();
        let second = table.reserve().unwrap();
        let live = table.park_retirement(second, record(3, 4)).unwrap();
        let retired = table.take_for_update(stale).unwrap();
        assert!(table.finish_update(stale));
        drop(retired);
        let replacement = table.reserve().unwrap();
        assert_eq!(replacement.slot, first.slot);
        let ordinary = table.park_reserved(replacement, record(5, 6)).unwrap();
        assert_ne!(ordinary, stale);
        assert_eq!(table.next_retirement_from(0), Some((2, live)));
        assert!(table.get(stale).is_none());
        assert!(table.take_for_update(stale).is_none());
        assert!(!table.finish_update(stale));
        let record = table.take_for_update(ordinary).unwrap();
        assert!(table.restore_update(ordinary, record));
        assert_eq!(table.next_retirement_from(0), Some((2, live)));
        let record = table.take_for_update(live).unwrap();
        assert!(table.finish_update(live));
        drop(record);
        assert!(table.next_retirement_from(0).is_none());
        assert!(table.get(ordinary).is_some());
    }

    #[test]
    fn completed_pending_transaction_can_restore_as_retirement_without_replacing_owner_or_id() {
        let drops = Rc::new(Cell::new(0));
        let mut transaction = record(1, 2)
            .with_root_directory(0x80)
            .with_source_owner(SourceOwner(drops.clone()));
        assert!(transaction.advance_to_source_set());
        let mut table = PendingSetFileNameTable::new();
        let reservation = table.reserve().unwrap();
        let id = table.park_reserved(reservation, transaction).unwrap();
        assert!(table.next_retirement_from(0).is_none());
        let capacity = table.capacity();
        let transaction = table.take_for_update(id).unwrap();
        assert!(table.restore_retirement(id, transaction));
        assert_eq!(table.capacity(), capacity);
        assert_eq!(table.next_retirement_from(0), Some((1, id)));
        assert_eq!(drops.get(), 0);
        let transaction = table.take_for_update(id).unwrap();
        assert_eq!(transaction.phase(), PendingSetFileNamePhase::SourceSet);
        assert_eq!(transaction.source_file_id, 1);
        assert_eq!(transaction.target_file_id, 2);
        assert_eq!(transaction.root_directory(), 0x80);
        assert!(table.next_retirement_from(0).is_none());
        assert!(table.restore_update(id, transaction));
        assert_eq!(table.next_retirement_from(0), Some((1, id)));
        let transaction = table.take_for_update(id).unwrap();
        assert!(table.finish_update(id));
        assert!(table.is_empty());
        assert_eq!(drops.get(), 0);
        drop(transaction);
        assert_eq!(drops.get(), 1);
        drop(table);
        assert_eq!(drops.get(), 1);
    }
}
