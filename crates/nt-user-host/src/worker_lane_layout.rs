//! Packed executive mirror identities for ordinary hosted process threads.

/// The two legacy slots for the first five processes keep their established mirror VAs.
/// All other lanes occupy one dense executive-only arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerLaneLayout {
    processes: usize,
    slots: usize,
    legacy_processes: usize,
    legacy_slots: usize,
    mirror_base: u64,
    stride: u64,
}

impl WorkerLaneLayout {
    pub const fn new(
        processes: usize,
        slots: usize,
        legacy_processes: usize,
        legacy_slots: usize,
        mirror_base: u64,
        stride: u64,
    ) -> Self {
        assert!(legacy_processes > 0 && processes >= legacy_processes && slots > legacy_slots);
        assert!(stride != 0 && mirror_base % stride == 0);
        let total = match processes.checked_mul(slots) {
            Some(total) => total,
            None => panic!("worker lane count overflow"),
        };
        let legacy = match legacy_processes.checked_mul(legacy_slots) {
            Some(legacy) => legacy,
            None => panic!("legacy worker lane count overflow"),
        };
        assert!(total >= legacy);
        let bytes = match (total - legacy).checked_mul(stride as usize) {
            Some(bytes) => bytes,
            None => panic!("worker mirror size overflow"),
        };
        assert!(mirror_base.checked_add(bytes as u64).is_some());
        Self {
            processes,
            slots,
            legacy_processes,
            legacy_slots,
            mirror_base,
            stride,
        }
    }

    pub const fn processes(self) -> usize {
        self.processes
    }
    pub const fn slots(self) -> usize {
        self.slots
    }
    pub const fn legacy_processes(self) -> usize {
        self.legacy_processes
    }
    pub const fn legacy_slots(self) -> usize {
        self.legacy_slots
    }
    pub const fn stride(self) -> u64 {
        self.stride
    }
    pub const fn base(self) -> u64 {
        self.mirror_base
    }
    pub const fn aux_capacity(self) -> usize {
        self.processes * self.slots - self.legacy_processes * self.legacy_slots
    }
    pub const fn mirror_end(self) -> u64 {
        self.mirror_base + self.aux_capacity() as u64 * self.stride
    }
    pub const fn fits_before(self, limit: u64) -> bool {
        self.mirror_end() <= limit
    }

    pub const fn aux_index(self, pi: usize, slot: usize) -> Option<usize> {
        if pi >= self.processes || slot >= self.slots {
            return None;
        }
        if pi < self.legacy_processes {
            if slot < self.legacy_slots {
                return None;
            }
            Some((slot - self.legacy_slots) * self.legacy_processes + pi)
        } else {
            Some(
                (self.slots - self.legacy_slots) * self.legacy_processes
                    + (pi - self.legacy_processes) * self.slots
                    + slot,
            )
        }
    }

    pub const fn decode_aux_index(self, index: usize) -> Option<(usize, usize)> {
        let first = (self.slots - self.legacy_slots) * self.legacy_processes;
        if index < first {
            Some((
                index % self.legacy_processes,
                self.legacy_slots + index / self.legacy_processes,
            ))
        } else {
            let later = index - first;
            if later >= (self.processes - self.legacy_processes) * self.slots {
                return None;
            }
            Some((
                self.legacy_processes + later / self.slots,
                later % self.slots,
            ))
        }
    }

    pub const fn mirror_base(self, pi: usize, slot: usize) -> Option<u64> {
        match self.aux_index(pi, slot) {
            Some(index) => Some(self.mirror_base + index as u64 * self.stride),
            None => None,
        }
    }
}

pub const HOSTED_WORKER_LAYOUT: WorkerLaneLayout =
    WorkerLaneLayout::new(24, 32, 5, 2, 0x0000_0104_0000_0000, 0x4_0000);

#[cfg(test)]
mod tests {
    use super::{WorkerLaneLayout, HOSTED_WORKER_LAYOUT};

    const OLD_BASE: u64 = 0x0000_0100_1800_0000;
    const OLD_LIMIT: u64 = 0x0000_0100_1e00_0000;
    const NEW_BASE: u64 = 0x0000_0104_0000_0000;
    const NEW_LIMIT: u64 = 0x0000_0105_0000_0000;
    const STRIDE: u64 = 0x4_0000;

    #[test]
    fn seventeenth_worker_needs_a_disjoint_mirror_window() {
        let old = WorkerLaneLayout::new(24, 32, 5, 2, OLD_BASE, STRIDE);
        assert!(!old.fits_before(OLD_LIMIT));

        let layout = HOSTED_WORKER_LAYOUT;
        assert_eq!(layout.slots(), 32);
        assert_eq!(layout.base(), NEW_BASE);
        assert!(layout.fits_before(NEW_LIMIT));
        let index = layout.aux_index(9, 16).unwrap();
        assert_eq!(layout.decode_aux_index(index), Some((9, 16)));
        assert_ne!(layout.mirror_base(9, 16), layout.mirror_base(9, 15));
        assert_ne!(layout.mirror_base(9, 16), layout.mirror_base(10, 16));
        assert_eq!(layout.decode_aux_index(layout.aux_capacity()), None);
        assert_eq!(layout.aux_index(24, 0), None);
        assert_eq!(layout.aux_index(9, 32), None);
    }
}
