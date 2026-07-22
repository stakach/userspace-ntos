//! Flat ReactOS-compatible fiber-local-storage bookkeeping.
//!
//! The target adapter owns the PEB/TEB pointers, heap blocks, intrusive process list, lock, and
//! callback invocation. This module only plans and commits the fixed 128-slot state transitions so
//! allocation failure and callback re-entrancy can be tested on the host.

pub const SLOT_COUNT: usize = 128;
pub const FIRST_USER_SLOT: u32 = 1;

pub type AllocationWords = [u32; SLOT_COUNT / u32::BITS as usize];
pub type CallbackSlots = [u64; SLOT_COUNT];
pub type ValueSlots = [u64; SLOT_COUNT];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlsError {
    InvalidIndex,
    NotAllocated,
    NoSlots,
    NoData,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    index: u32,
}

impl Reservation {
    pub const fn index(&self) -> u32 {
        self.index
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FreePlan {
    pub index: u32,
    pub callback: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallbackAction {
    pub index: u32,
    pub callback: u64,
    pub value: u64,
}

fn bit(index: u32) -> Option<(usize, u32)> {
    (index < SLOT_COUNT as u32).then(|| {
        let word = index as usize / u32::BITS as usize;
        let mask = 1u32 << (index % u32::BITS);
        (word, mask)
    })
}

/// Reset the allocation map and reserve slot zero, which is never returned to callers.
pub fn initialize_words(words: &mut AllocationWords) {
    *words = [0; SLOT_COUNT / u32::BITS as usize];
    words[0] = 1;
}

pub fn is_allocated(words: &AllocationWords, index: u32) -> bool {
    bit(index).is_some_and(|(word, mask)| words[word] & mask != 0)
}

/// Reserve the first available user slot. The caller must roll this back if later allocation fails.
pub fn reserve(words: &mut AllocationWords) -> Result<Reservation, FlsError> {
    for index in FIRST_USER_SLOT..SLOT_COUNT as u32 {
        let (word, mask) = bit(index).expect("bounded FLS index");
        if words[word] & mask == 0 {
            words[word] |= mask;
            return Ok(Reservation { index });
        }
    }
    Err(FlsError::NoSlots)
}

pub fn rollback_reservation(words: &mut AllocationWords, reservation: Reservation) {
    let (word, mask) = bit(reservation.index).expect("reservation contains a valid FLS index");
    words[word] &= !mask;
}

/// Commit a reserved slot after the target adapter has made the current thread's data available.
pub fn commit_reservation(
    reservation: Reservation,
    callbacks: &mut CallbackSlots,
    current_values: &mut ValueSlots,
    callback: u64,
    high_index: &mut u32,
) {
    let index = reservation.index as usize;
    current_values[index] = 0;
    callbacks[index] = callback;
    *high_index = (*high_index).max(reservation.index);
}

/// Validate and unpublish an allocation before callbacks run. Its callback remains visible until
/// [`finish_free`] so the target can traverse every thread/fiber data block.
///
/// Slot zero is rejected deliberately. ReactOS's kernel32 implementation accidentally frees its
/// reserved bit, while the native Rtl contract consistently treats zero as an invalid FLS index.
pub fn begin_free(
    words: &mut AllocationWords,
    callbacks: &CallbackSlots,
    index: u32,
) -> Result<FreePlan, FlsError> {
    if index < FIRST_USER_SLOT || index >= SLOT_COUNT as u32 {
        return Err(FlsError::InvalidIndex);
    }
    let (word, mask) = bit(index).expect("validated FLS index");
    if words[word] & mask == 0 {
        return Err(FlsError::NotAllocated);
    }
    words[word] &= !mask;
    Ok(FreePlan {
        index,
        callback: callbacks[index as usize],
    })
}

/// Snapshot one non-null callback invocation. Clearing is separate because native callbacks see
/// the old value while they execute and can re-enter FLS APIs.
pub fn callback_action(plan: &FreePlan, values: &ValueSlots) -> Option<CallbackAction> {
    let value = values[plan.index as usize];
    (plan.callback != 0 && value != 0).then_some(CallbackAction {
        index: plan.index,
        callback: plan.callback,
        value,
    })
}

pub fn clear_value(values: &mut ValueSlots, index: u32) -> Result<(), FlsError> {
    if index < FIRST_USER_SLOT || index >= SLOT_COUNT as u32 {
        return Err(FlsError::InvalidIndex);
    }
    values[index as usize] = 0;
    Ok(())
}

pub fn finish_free(callbacks: &mut CallbackSlots, plan: FreePlan) {
    callbacks[plan.index as usize] = 0;
}

/// FLS Get/Set intentionally do not consult the process allocation bitmap on the flat ABI.
pub fn get_value(values: Option<&ValueSlots>, index: u32) -> Result<u64, FlsError> {
    if index < FIRST_USER_SLOT || index >= SLOT_COUNT as u32 {
        return Err(FlsError::InvalidIndex);
    }
    values
        .map(|slots| slots[index as usize])
        .ok_or(FlsError::NoData)
}

pub fn set_value(values: &mut ValueSlots, index: u32, value: u64) -> Result<(), FlsError> {
    if index < FIRST_USER_SLOT || index >= SLOT_COUNT as u32 {
        return Err(FlsError::InvalidIndex);
    }
    values[index as usize] = value;
    Ok(())
}

/// Plan one thread/fiber rundown callback, bounded by the process high-water mark.
pub fn rundown_action(
    callbacks: &CallbackSlots,
    values: &ValueSlots,
    high_index: u32,
    index: u32,
) -> Option<CallbackAction> {
    if index < FIRST_USER_SLOT || index >= SLOT_COUNT as u32 || index > high_index.min(127) {
        return None;
    }
    let callback = callbacks[index as usize];
    let value = values[index as usize];
    (callback != 0 && value != 0).then_some(CallbackAction {
        index,
        callback,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialized_words() -> AllocationWords {
        let mut words = [u32::MAX; 4];
        initialize_words(&mut words);
        words
    }

    #[test]
    fn initialization_reserves_only_slot_zero() {
        let words = initialized_words();
        assert!(is_allocated(&words, 0));
        assert!((1..128).all(|index| !is_allocated(&words, index)));
        assert!(!is_allocated(&words, 128));
    }

    #[test]
    fn reserve_is_first_fit_reuses_and_exhausts() {
        let mut words = initialized_words();
        let reservations: alloc::vec::Vec<_> = (1..128)
            .map(|expected| {
                let reservation = reserve(&mut words).unwrap();
                assert_eq!(reservation.index(), expected);
                reservation
            })
            .collect();
        assert_eq!(reserve(&mut words), Err(FlsError::NoSlots));
        rollback_reservation(&mut words, reservations.into_iter().nth(41).unwrap());
        assert_eq!(reserve(&mut words).unwrap().index(), 42);
    }

    #[test]
    fn rollback_only_releases_the_reserved_bit() {
        let mut words = initialized_words();
        let first = reserve(&mut words).unwrap();
        let second = reserve(&mut words).unwrap();
        rollback_reservation(&mut words, first);
        assert!(!is_allocated(&words, 1));
        assert!(is_allocated(&words, 2));
        assert_eq!(second.index(), 2);
    }

    #[test]
    fn rollback_does_not_publish_partially_allocated_state() {
        let mut words = initialized_words();
        let mut callbacks = [0; SLOT_COUNT];
        let mut values = [0; SLOT_COUNT];
        callbacks[1] = 0x1111;
        values[1] = 0x2222;
        let high_index = 60;
        let reservation = reserve(&mut words).unwrap();

        rollback_reservation(&mut words, reservation);

        assert!(!is_allocated(&words, 1));
        assert_eq!(callbacks[1], 0x1111);
        assert_eq!(values[1], 0x2222);
        assert_eq!(high_index, 60);
    }

    #[test]
    fn commit_clears_current_value_and_only_raises_high_index() {
        let mut words = initialized_words();
        let reservation = reserve(&mut words).unwrap();
        let mut callbacks = [0; SLOT_COUNT];
        let mut values = [0; SLOT_COUNT];
        values[1] = 0xaaaa;
        let mut high_index = 70;
        commit_reservation(
            reservation,
            &mut callbacks,
            &mut values,
            0x1234,
            &mut high_index,
        );
        assert_eq!(callbacks[1], 0x1234);
        assert_eq!(values[1], 0);
        assert_eq!(high_index, 70);
    }

    #[test]
    fn invalid_and_unallocated_free_leave_state_unchanged() {
        let mut words = initialized_words();
        let callbacks = [0x1234; SLOT_COUNT];
        let original = words;
        assert_eq!(
            begin_free(&mut words, &callbacks, 0),
            Err(FlsError::InvalidIndex)
        );
        assert_eq!(
            begin_free(&mut words, &callbacks, 128),
            Err(FlsError::InvalidIndex)
        );
        assert_eq!(
            begin_free(&mut words, &callbacks, 7),
            Err(FlsError::NotAllocated)
        );
        assert_eq!(words, original);
    }

    #[test]
    fn free_keeps_callback_visible_until_values_are_processed() {
        let mut words = initialized_words();
        let reservation = reserve(&mut words).unwrap();
        let mut callbacks = [0; SLOT_COUNT];
        let mut current_values = [0; SLOT_COUNT];
        let mut high_index = 0;
        commit_reservation(
            reservation,
            &mut callbacks,
            &mut current_values,
            0x1000,
            &mut high_index,
        );
        let mut other_values = [0; SLOT_COUNT];
        other_values[1] = 0x2000;

        let plan = begin_free(&mut words, &callbacks, 1).unwrap();
        assert_eq!(callbacks[1], 0x1000);
        assert_eq!(callback_action(&plan, &current_values), None);
        assert_eq!(callback_action(&plan, &other_values).unwrap().value, 0x2000);
        clear_value(&mut other_values, 1).unwrap();
        finish_free(&mut callbacks, plan);
        assert_eq!(other_values[1], 0);
        assert_eq!(callbacks[1], 0);
    }

    #[test]
    fn get_and_set_accept_valid_unallocated_slots() {
        let mut values = [0; SLOT_COUNT];
        set_value(&mut values, 127, 0xfeed).unwrap();
        assert_eq!(get_value(Some(&values), 127), Ok(0xfeed));
        assert_eq!(get_value(None, 127), Err(FlsError::NoData));
        assert_eq!(set_value(&mut values, 0, 1), Err(FlsError::InvalidIndex));
        assert_eq!(get_value(Some(&values), 128), Err(FlsError::InvalidIndex));
    }

    #[test]
    fn rundown_is_bounded_and_skips_null_callback_or_value() {
        let mut callbacks = [0; SLOT_COUNT];
        let mut values = [0; SLOT_COUNT];
        callbacks[2] = 0x20;
        values[2] = 0x200;
        callbacks[3] = 0x30;
        callbacks[4] = 0x40;
        values[4] = 0x400;
        assert_eq!(rundown_action(&callbacks, &values, 3, 1), None);
        assert_eq!(
            rundown_action(&callbacks, &values, 3, 2).unwrap().value,
            0x200
        );
        assert_eq!(rundown_action(&callbacks, &values, 3, 3), None);
        assert_eq!(rundown_action(&callbacks, &values, 3, 4), None);
        assert_eq!(rundown_action(&callbacks, &values, 200, 128), None);
    }

    #[test]
    fn free_reentrancy_can_reserve_the_same_slot_before_finish() {
        let mut words = initialized_words();
        let old = reserve(&mut words).unwrap();
        let mut callbacks = [0; SLOT_COUNT];
        let mut values = [0; SLOT_COUNT];
        let mut high_index = 0;
        commit_reservation(old, &mut callbacks, &mut values, 0x1111, &mut high_index);
        let plan = begin_free(&mut words, &callbacks, 1).unwrap();
        values[1] = 0x2222;
        assert_eq!(callback_action(&plan, &values).unwrap().value, 0x2222);

        let replacement = reserve(&mut words).unwrap();
        assert_eq!(replacement.index(), 1);
        assert_eq!(plan.callback, 0x1111);
        commit_reservation(
            replacement,
            &mut callbacks,
            &mut values,
            0x3333,
            &mut high_index,
        );
        set_value(&mut values, 1, 0x4444).unwrap();

        clear_value(&mut values, 1).unwrap();
        finish_free(&mut callbacks, plan);
        assert_eq!(callbacks[1], 0);
        assert_eq!(values[1], 0);
    }
}
