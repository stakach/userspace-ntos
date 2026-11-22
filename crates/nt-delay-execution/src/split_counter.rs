//! A coherent read of a 64-bit counter exposed as two 32-bit halves.
//!
//! A 64-bit MMIO load of the HPET main counter need not be atomic: QEMU serves it as two 32-bit
//! accesses, so a load that straddles a carry out of the low word is 2^32 ticks off. Reading the
//! high half on both sides of the low half and retrying until they agree yields a value the
//! counter actually held.

/// `read_high` and `read_low` each read one half of the same free-running counter.
pub fn read_split_counter(
    mut read_high: impl FnMut() -> u32,
    mut read_low: impl FnMut() -> u32,
) -> u64 {
    let mut high = read_high();
    loop {
        let low = read_low();
        let confirmed = read_high();
        if confirmed == high {
            return (u64::from(high) << 32) | u64::from(low);
        }
        // The low word carried between the two high reads; the new high is current.
        high = confirmed;
    }
}

#[cfg(test)]
mod tests {
    use super::read_split_counter;
    use core::cell::Cell;

    /// A counter that advances by `step` on every half read.
    struct Counter {
        value: Cell<u64>,
        step: u64,
    }

    impl Counter {
        fn read(&self, shift: u32) -> u32 {
            let value = self.value.get();
            self.value.set(value + self.step);
            (value >> shift) as u32
        }
    }

    #[test]
    fn a_read_straddling_a_low_word_carry_is_never_torn() {
        for start in (0xffff_fff0u64..=0x1_0000_0002).chain(0x6_ffff_fffc..=0x7_0000_0001) {
            let counter = Counter {
                value: Cell::new(start),
                step: 1,
            };
            let value = read_split_counter(|| counter.read(32), || counter.read(0));
            let end = counter.value.get();
            assert!(
                start <= value && value < end,
                "{start:#x}: {value:#x} not in [{start:#x}, {end:#x})"
            );
        }
    }

    #[test]
    fn the_naive_low_then_high_order_is_torn_at_a_carry() {
        // What one 64-bit load split as low-then-high observes across the carry.
        let counter = Counter {
            value: Cell::new(0xffff_ffff),
            step: 1,
        };
        let low = counter.read(0);
        let high = counter.read(32);
        let torn = (u64::from(high) << 32) | u64::from(low);
        assert_eq!(torn - 0xffff_ffff, 1 << 32);
    }

    #[test]
    fn a_stable_high_word_needs_no_retry() {
        let reads = Cell::new(0);
        let value = read_split_counter(
            || {
                reads.set(reads.get() + 1);
                7
            },
            || {
                reads.set(reads.get() + 1);
                9
            },
        );
        assert_eq!((value, reads.get()), ((7 << 32) | 9, 3));
    }
}
