//! Driver-local File projection lifecycle. Values describe registry state, not memory ownership.

use core::sync::atomic::{AtomicU64, Ordering};

static LAST_RESERVATION: AtomicU64 = AtomicU64::new(0);

/// Decode a File projection service receipt. `None` is an ambiguous or malformed reply, not
/// evidence that binding failed. A negative status with no generation is a definite refusal.
/// Operations are BIND (1), UNBIND (2), and QUERY (3); successful QUERY may report absence (zero).
pub fn decode_file_projection_reply(
    info: u64,
    status: u64,
    generation: u64,
    reserved: [u64; 2],
    operation: u64,
) -> Option<Result<u64, i32>> {
    if info != 4 || status > u32::MAX as u64 || reserved != [0; 2] || !(1..=3).contains(&operation)
    {
        return None;
    }
    let status = status as u32 as i32;
    if status < 0 {
        return (generation == 0).then_some(Err(status));
    }
    if status != 0 {
        return None;
    }
    match operation {
        1 if generation != 0 => Some(Ok(generation)),
        2 if generation == 0 => Some(Ok(0)),
        3 => Some(Ok(generation)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Reserved,
    Live,
    Retiring,
}

/// Opaque snapshot of one local projection reservation. Copying this value cannot free its
/// allocation or unbind its canonical File. Registry updates must match the pre-call snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileProjectionSlot {
    reservation: u64,
    file: u64,
    address: u64,
    generation: u64,
    state: State,
}

impl FileProjectionSlot {
    /// Reserve a nonzero File/address pair before entering binding IPC. Reservation cookies never
    /// repeat, including when a registry slot, pool address, and File identity are reused.
    pub fn new(file: u64, address: u64) -> Option<Self> {
        if file == 0 || address == 0 {
            return None;
        }
        let previous = LAST_RESERVATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok()?;
        Some(Self {
            reservation: previous + 1,
            file,
            address,
            generation: 0,
            state: State::Reserved,
        })
    }

    pub const fn file_id(self) -> u64 {
        self.file
    }

    pub const fn address(self) -> u64 {
        self.address
    }

    /// Zero means the binding generation is unresolved, not proof of authoritative absence.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn is_live(self) -> bool {
        matches!(self.state, State::Live)
    }

    pub const fn is_retiring(self) -> bool {
        matches!(self.state, State::Retiring)
    }

    /// Publish only the exact reservation that entered binding IPC. A reentrant retirement or
    /// slot replacement rejects the receipt instead of resurrecting a usable projection.
    pub fn publish(&mut self, expected: Self, generation: u64) -> bool {
        if *self != expected || self.state != State::Reserved || generation == 0 {
            return false;
        }
        self.generation = generation;
        self.state = State::Live;
        true
    }

    /// Hide the projection irrevocably. Repeated retirement has no effect and returns false.
    pub fn retire(&mut self) -> bool {
        if self.state == State::Retiring {
            return false;
        }
        self.state = State::Retiring;
        true
    }

    /// Match an authoritative QUERY receipt for the exact retiring snapshot. An unresolved
    /// reservation may record a binding or accept absence (zero); a known binding cannot change
    /// generation or become absent through this operation. Success never makes the slot Live.
    /// The registry owner still performs UNBIND/free after the appropriate authoritative receipt.
    pub fn resolve_retirement(&mut self, expected: Self, generation: u64) -> bool {
        if *self != expected || self.state != State::Retiring {
            return false;
        }
        if self.generation != 0 && self.generation != generation {
            return false;
        }
        self.generation = generation;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_codec_accepts_only_operation_specific_success_generations() {
        for operation in 1..=3 {
            for generation in [0, 1, u64::MAX] {
                let expected = match operation {
                    1 if generation == 0 => None,
                    2 if generation != 0 => None,
                    _ => Some(Ok(generation)),
                };
                assert_eq!(
                    decode_file_projection_reply(4, 0, generation, [0; 2], operation),
                    expected
                );
            }
        }
    }

    #[test]
    fn reply_codec_distinguishes_definite_refusal_from_ambiguous_status() {
        for operation in 1..=3 {
            for status in [0x8000_0000u64, 0xc000_000d, 0xffff_ffff] {
                assert_eq!(
                    decode_file_projection_reply(4, status, 0, [0; 2], operation),
                    Some(Err(status as u32 as i32))
                );
                for generation in [1, u64::MAX] {
                    assert_eq!(
                        decode_file_projection_reply(4, status, generation, [0; 2], operation),
                        None
                    );
                }
            }
            // Informational statuses, including STATUS_PENDING, do not certify binding outcome.
            for status in [1, 0x103, 0x4000_0000, 0x7fff_ffff, 0x1_0000_0000, u64::MAX] {
                for generation in [0, 1, u64::MAX] {
                    assert_eq!(
                        decode_file_projection_reply(4, status, generation, [0; 2], operation),
                        None
                    );
                }
            }
        }
    }

    #[test]
    fn reply_codec_rejects_malformed_shape_before_treating_status_as_authoritative() {
        for operation in 1..=3 {
            for status in [0, 0xc000_000d] {
                let generation = if status == 0 && operation == 1 { 1 } else { 0 };
                for info in [0, 1, 3, 5, u64::MAX] {
                    assert_eq!(
                        decode_file_projection_reply(info, status, generation, [0; 2], operation),
                        None
                    );
                }
                for reserved in [[1, 0], [0, 1], [u64::MAX, 0], [0, u64::MAX], [1, 1]] {
                    assert_eq!(
                        decode_file_projection_reply(4, status, generation, reserved, operation),
                        None
                    );
                }
            }
        }
        for operation in [0, 4, u64::MAX] {
            for status in [0, 0xc000_000d] {
                assert_eq!(
                    decode_file_projection_reply(4, status, 0, [0; 2], operation),
                    None
                );
            }
        }
    }

    #[test]
    fn only_nonzero_exact_binding_receipt_publishes_live_projection() {
        assert!(FileProjectionSlot::new(0, 16).is_none());
        assert!(FileProjectionSlot::new(1, 0).is_none());
        let mut slot = FileProjectionSlot::new(1, 16).unwrap();
        let reserved = slot;
        assert_eq!(
            (slot.file_id(), slot.address(), slot.generation()),
            (1, 16, 0)
        );
        assert!(!slot.is_live());
        assert!(!slot.is_retiring());
        assert!(!slot.publish(reserved, 0));
        assert_eq!(slot, reserved);
        assert!(slot.publish(reserved, 7));
        assert!(slot.is_live());
        assert_eq!(slot.generation(), 7);
        assert!(!slot.publish(reserved, 7));
        assert!(!slot.publish(slot, 8));
        assert_eq!(slot.generation(), 7);
    }

    #[test]
    fn reentrant_retirement_rejects_pending_publish_and_cannot_be_reversed() {
        let mut slot = FileProjectionSlot::new(1, 16).unwrap();
        let bind_snapshot = slot;
        assert!(slot.retire());
        assert!(!slot.retire());
        assert!(!slot.publish(bind_snapshot, 7));
        assert!(!slot.publish(slot, 7));
        assert!(slot.is_retiring());
        assert!(!slot.is_live());
        assert_eq!(slot.generation(), 0);
        assert!(!slot.resolve_retirement(bind_snapshot, 7));
        let retiring = slot;
        assert!(slot.resolve_retirement(retiring, 7));
        assert!(slot.is_retiring());
        assert!(!slot.is_live());
        assert!(!slot.resolve_retirement(retiring, 8));
        assert!(!slot.resolve_retirement(slot, 8));
        assert!(!slot.resolve_retirement(slot, 0));
        assert_eq!(slot.generation(), 7);
    }

    #[test]
    fn uncertain_bind_remains_retiring_until_authoritative_resolution() {
        let mut slot = FileProjectionSlot::new(2, 32).unwrap();
        slot.retire();
        let query_snapshot = slot;
        assert!(slot.resolve_retirement(query_snapshot, 0));
        assert_eq!(slot, query_snapshot);
        assert!(!slot.is_live());

        let mut bound = FileProjectionSlot::new(2, 32).unwrap();
        bound.retire();
        assert!(bound.resolve_retirement(bound, 9));
        assert_eq!(bound.generation(), 9);
        assert!(bound.is_retiring());
        assert!(bound.resolve_retirement(bound, 9));
    }

    #[test]
    fn stale_receipts_cannot_update_reused_file_address_or_registry_slot() {
        let mut old = FileProjectionSlot::new(3, 48).unwrap();
        let old_reservation = old;
        old.retire();
        let mut replacement = FileProjectionSlot::new(3, 48).unwrap();
        assert_ne!(old_reservation, replacement);
        assert!(!replacement.publish(old_reservation, 11));
        replacement.retire();
        let current = replacement;
        assert!(!replacement.resolve_retirement(old, 11));
        assert_eq!(replacement, current);
        assert!(replacement.resolve_retirement(current, 12));
        assert!(!old.resolve_retirement(replacement, 12));
    }

    #[test]
    fn live_retirement_preserves_exact_binding_for_unbind() {
        let mut slot = FileProjectionSlot::new(4, 64).unwrap();
        assert!(slot.publish(slot, 13));
        let live = slot;
        assert!(slot.retire());
        assert_eq!(
            (slot.file_id(), slot.address(), slot.generation()),
            (4, 64, 13)
        );
        assert!(slot.is_retiring());
        assert!(!slot.is_live());
        assert!(!slot.resolve_retirement(live, 13));
        assert!(slot.resolve_retirement(slot, 13));
        assert!(!slot.publish(slot, 13));
    }
}
