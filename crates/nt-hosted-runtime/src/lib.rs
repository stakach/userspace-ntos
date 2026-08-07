//! Pure hosted-process runtime VA layout helpers.
//!
//! The executive owns seL4 caps, page-table installation, and the concrete address map. This crate
//! owns only the checked arithmetic: assigning a process index to a scratch/mirror lane and proving
//! that those lanes do not overlap.

#![no_std]

pub const PAGE_SIZE: u64 = 0x1000;
pub const PAGE_TABLE_SPAN: u64 = 0x20_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeRange {
    pub base: u64,
    pub len: u64,
}

impl RuntimeRange {
    pub const fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    pub const fn end(self) -> Option<u64> {
        self.base.checked_add(self.len)
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub const fn overlaps(self, other: Self) -> bool {
        if self.is_empty() || other.is_empty() {
            return false;
        }
        let Some(self_end) = self.end() else {
            return true;
        };
        let Some(other_end) = other.end() else {
            return true;
        };
        self.base < other_end && other.base < self_end
    }

    pub const fn contains(self, other: Self) -> bool {
        if other.is_empty() {
            return true;
        }
        let Some(self_end) = self.end() else {
            return false;
        };
        let Some(other_end) = other.end() else {
            return false;
        };
        self.base <= other.base && other_end <= self_end
    }

    pub const fn is_page_table_aligned(self) -> bool {
        self.base & (PAGE_TABLE_SPAN - 1) == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessRuntimeLayout {
    pub pi: usize,
    pub scratch_base: u64,
    pub env_scratch_va: u64,
    pub stack_mirror_va: u64,
    pub heap_mirror_va: u64,
    pub image_mirror_va: u64,
}

impl ProcessRuntimeLayout {
    pub const fn scratch_range(self, scratch_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.scratch_base, scratch_len)
    }

    pub const fn stack_range(self, stack_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.stack_mirror_va, stack_len)
    }

    pub const fn env_range(self, env_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.env_scratch_va, env_len)
    }

    pub const fn heap_range(self, heap_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.heap_mirror_va, heap_len)
    }

    pub const fn image_range(self, image_len: u64) -> RuntimeRange {
        RuntimeRange::new(self.image_mirror_va, image_len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLayoutError {
    InvalidPi,
    InvalidArena,
    InvalidStride,
    InvalidOffset,
    Overflow,
    OutsideArena,
    Overlap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicRuntimeArena {
    pub first_pi: usize,
    pub max_pi: usize,
    pub base: u64,
    pub limit: u64,
    pub stride: u64,
    pub scratch_offset: u64,
    pub stack_offset: u64,
    pub env_offset: u64,
    pub heap_offset: u64,
    pub image_offset: u64,
    pub scratch_len: u64,
    pub stack_len: u64,
    pub env_len: u64,
    pub heap_len: u64,
    pub image_len: u64,
}

impl DynamicRuntimeArena {
    pub const fn layout_for_pi(
        self,
        pi: usize,
    ) -> Result<ProcessRuntimeLayout, RuntimeLayoutError> {
        if pi < self.first_pi || pi >= self.max_pi {
            return Err(RuntimeLayoutError::InvalidPi);
        }
        if self.base >= self.limit || self.base & (PAGE_TABLE_SPAN - 1) != 0 {
            return Err(RuntimeLayoutError::InvalidArena);
        }
        if self.stride == 0 || self.stride & (PAGE_TABLE_SPAN - 1) != 0 {
            return Err(RuntimeLayoutError::InvalidStride);
        }
        if self.scratch_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.stack_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.heap_offset & (PAGE_TABLE_SPAN - 1) != 0
            || self.image_offset & (PAGE_TABLE_SPAN - 1) != 0
        {
            return Err(RuntimeLayoutError::InvalidOffset);
        }
        let index = pi - self.first_pi;
        let Some(offset) = (index as u64).checked_mul(self.stride) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(lane_base) = self.base.checked_add(offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(lane_end) = lane_base.checked_add(self.stride) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        if lane_end > self.limit {
            return Err(RuntimeLayoutError::OutsideArena);
        }
        let Some(scratch_base) = lane_base.checked_add(self.scratch_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(stack_mirror_va) = lane_base.checked_add(self.stack_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(env_scratch_va) = lane_base.checked_add(self.env_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(heap_mirror_va) = lane_base.checked_add(self.heap_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let Some(image_mirror_va) = lane_base.checked_add(self.image_offset) else {
            return Err(RuntimeLayoutError::Overflow);
        };
        let lane = RuntimeRange::new(lane_base, self.stride);
        let layout = ProcessRuntimeLayout {
            pi,
            scratch_base,
            env_scratch_va,
            stack_mirror_va,
            heap_mirror_va,
            image_mirror_va,
        };
        if !lane.contains(layout.scratch_range(self.scratch_len))
            || !lane.contains(layout.stack_range(self.stack_len))
            || !lane.contains(layout.env_range(self.env_len))
            || !lane.contains(layout.heap_range(self.heap_len))
            || !lane.contains(layout.image_range(self.image_len))
        {
            return Err(RuntimeLayoutError::OutsideArena);
        }
        if layout
            .scratch_range(self.scratch_len)
            .overlaps(layout.stack_range(self.stack_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.env_range(self.env_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .scratch_range(self.scratch_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.env_range(self.env_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .stack_range(self.stack_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .env_range(self.env_len)
                .overlaps(layout.heap_range(self.heap_len))
            || layout
                .env_range(self.env_len)
                .overlaps(layout.image_range(self.image_len))
            || layout
                .heap_range(self.heap_len)
                .overlaps(layout.image_range(self.image_len))
        {
            return Err(RuntimeLayoutError::Overlap);
        }
        Ok(layout)
    }
}

pub fn validate_non_overlapping(ranges: &[RuntimeRange]) -> Result<(), RuntimeLayoutError> {
    for (i, left) in ranges.iter().enumerate() {
        if left.end().is_none() {
            return Err(RuntimeLayoutError::Overflow);
        }
        for right in &ranges[i + 1..] {
            if right.end().is_none() {
                return Err(RuntimeLayoutError::Overflow);
            }
            if left.overlaps(*right) {
                return Err(RuntimeLayoutError::Overlap);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARENA: DynamicRuntimeArena = DynamicRuntimeArena {
        first_pi: 7,
        max_pi: 16,
        base: 0x0000_0101_6000_0000,
        limit: 0x0000_0101_A800_0000,
        stride: 0x0800_0000,
        scratch_offset: 0,
        stack_offset: 0x0400_0000,
        env_offset: 0x0410_0000,
        heap_offset: 0x0420_0000,
        image_offset: 0x0440_0000,
        scratch_len: 0x0400_0000,
        stack_len: 0x4000,
        env_len: 0x9000,
        heap_len: 0x20_0000,
        image_len: 0x20_0000,
    };

    #[test]
    fn dynamic_runtime_arena_assigns_dense_non_overlapping_lanes() {
        let first = ARENA.layout_for_pi(7).unwrap();
        let second = ARENA.layout_for_pi(8).unwrap();
        assert_eq!(first.scratch_base, ARENA.base);
        assert_eq!(first.stack_mirror_va, ARENA.base + ARENA.stack_offset);
        assert_eq!(second.scratch_base, ARENA.base + ARENA.stride);

        let mut ranges = [RuntimeRange::new(0, 0); 45];
        let mut n = 0;
        for pi in ARENA.first_pi..ARENA.max_pi {
            let layout = ARENA.layout_for_pi(pi).unwrap();
            ranges[n] = layout.scratch_range(ARENA.scratch_len);
            n += 1;
            ranges[n] = layout.stack_range(ARENA.stack_len);
            n += 1;
            ranges[n] = layout.env_range(ARENA.env_len);
            n += 1;
            ranges[n] = layout.heap_range(ARENA.heap_len);
            n += 1;
            ranges[n] = layout.image_range(ARENA.image_len);
            n += 1;
        }
        validate_non_overlapping(&ranges[..n]).unwrap();
    }

    #[test]
    fn arena_rejects_pi_outside_dynamic_range() {
        assert_eq!(ARENA.layout_for_pi(6), Err(RuntimeLayoutError::InvalidPi));
        assert_eq!(ARENA.layout_for_pi(16), Err(RuntimeLayoutError::InvalidPi));
    }

    #[test]
    fn arena_rejects_implicit_scratch_mirror_collision() {
        let colliding = DynamicRuntimeArena {
            stack_offset: 0x03e0_0000,
            ..ARENA
        };
        assert_eq!(colliding.layout_for_pi(7), Err(RuntimeLayoutError::Overlap));
    }

    #[test]
    fn validate_non_overlapping_reports_cross_lane_collision() {
        let ranges = [
            RuntimeRange::new(0x1000, 0x2000),
            RuntimeRange::new(0x2fff, 0x1000),
        ];
        assert_eq!(
            validate_non_overlapping(&ranges),
            Err(RuntimeLayoutError::Overlap)
        );
    }
}
