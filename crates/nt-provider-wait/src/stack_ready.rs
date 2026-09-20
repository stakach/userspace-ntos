//! Wire evidence for a provider's completed stack publication, not execution authority.

use crate::ProviderStackLaneBinding;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStackReadyReceipt {
    pub lane_id: u64,
    pub slot: u32,
    pub generation: u32,
    pub stack_base: u64,
    pub stack_bytes: u64,
}

impl ProviderStackReadyReceipt {
    pub const fn from_binding(binding: ProviderStackLaneBinding) -> Self {
        Self {
            lane_id: binding.lane_id,
            slot: binding.handle.slot(),
            generation: binding.handle.generation(),
            stack_base: binding.stack_base,
            stack_bytes: binding.stack_bytes,
        }
    }

    pub const fn words(self) -> [u64; 5] {
        [
            self.lane_id,
            self.slot as u64,
            self.generation as u64,
            self.stack_base,
            self.stack_bytes,
        ]
    }

    /// The adapter must separately authenticate the sender, message shape and provider lifetime.
    /// These numeric fields cannot manufacture a catalog handle or authorize retirement.
    pub fn decode(
        words: [u64; 5],
        lane_id: u64,
        stack_base: u64,
        stack_bytes: u64,
    ) -> Option<Self> {
        if lane_id == 0 || stack_base == 0 || stack_bytes == 0 {
            return None;
        }
        stack_base.checked_add(stack_bytes)?;
        if words[0] != lane_id || words[3] != stack_base || words[4] != stack_bytes {
            return None;
        }
        let slot = u32::try_from(words[1]).ok()?;
        let generation = u32::try_from(words[2]).ok()?;
        if generation == 0 {
            return None;
        }
        Some(Self {
            lane_id,
            slot,
            generation,
            stack_base,
            stack_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderStackActivationCatalog;

    #[test]
    fn published_binding_round_trips_without_fabricating_a_handle() {
        let mut catalog = ProviderStackActivationCatalog::new(1, 1).unwrap();
        let handle = catalog.register_lane(7, 0x1000, 0x4000).unwrap();
        let receipt = ProviderStackReadyReceipt::from_binding(catalog.binding(handle).unwrap());
        assert_eq!(
            receipt.words(),
            [
                7,
                handle.slot() as u64,
                handle.generation() as u64,
                0x1000,
                0x4000
            ]
        );
        assert_eq!(
            ProviderStackReadyReceipt::decode(receipt.words(), 7, 0x1000, 0x4000),
            Some(receipt)
        );
    }

    #[test]
    fn oversized_identity_words_are_rejected_instead_of_truncated() {
        let words = [7, 0, 1, 0x1000, 0x4000];
        for (index, value) in [
            (1, u32::MAX as u64 + 1),
            (1, u64::MAX),
            (2, 0),
            (2, u32::MAX as u64 + 1),
            (2, u64::MAX),
        ] {
            let mut malformed = words;
            malformed[index] = value;
            assert_eq!(
                ProviderStackReadyReceipt::decode(malformed, 7, 0x1000, 0x4000),
                None
            );
        }
        let max = [7, u32::MAX as u64, u32::MAX as u64, 0x1000, 0x4000];
        assert_eq!(
            ProviderStackReadyReceipt::decode(max, 7, 0x1000, 0x4000)
                .unwrap()
                .words(),
            max
        );
    }

    #[test]
    fn exact_lane_and_stack_range_must_match_expected_owner() {
        let words = [7, 0, 1, 0x1000, 0x4000];
        for index in [0, 3, 4] {
            let mut mismatched = words;
            mismatched[index] += 1;
            assert_eq!(
                ProviderStackReadyReceipt::decode(mismatched, 7, 0x1000, 0x4000),
                None
            );
        }
        for (lane, base, bytes) in [
            (0, 0x1000, 0x4000),
            (7, 0, 0x4000),
            (7, 0x1000, 0),
            (7, u64::MAX, 1),
            (7, u64::MAX - 1, 2),
        ] {
            assert_eq!(
                ProviderStackReadyReceipt::decode([lane, 0, 1, base, bytes], lane, base, bytes),
                None
            );
        }
        let valid = [7, 0, 1, u64::MAX - 1, 1];
        assert!(ProviderStackReadyReceipt::decode(valid, 7, u64::MAX - 1, 1).is_some());
    }
}
