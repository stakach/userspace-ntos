//! Pure hosted-process runtime VA layout helpers.
//!
//! The executive owns seL4 caps, page-table installation, and the concrete address map. This crate
//! owns only the checked arithmetic: assigning a process index to a scratch/mirror lane and proving
//! that those lanes do not overlap.

#![no_std]

pub const PAGE_SIZE: u64 = 0x1000;
pub const PAGE_TABLE_SPAN: u64 = 0x20_0000;
pub const HOSTED_PROVIDER_IMPORT_THUNK_LEN: usize = 33;
pub const HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN: u64 = 64;

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
pub struct HostedProviderImagePlan {
    pub provider_prefix_len: u64,
    pub primary_offset: u64,
    pub private_dependency_offset: u64,
    pub total_image_len: u64,
    pub total_frames: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImagePlanError {
    Overflow,
    ExceedsFrameCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderDomainDescriptor {
    pub image_offset: u64,
    pub image_len: u64,
    pub image_frames: u64,
    pub pool_base: u64,
    pub pool_frames: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderDomainBinding {
    pub image_offset: u64,
    pub image_len: u64,
    pub image_frames: u64,
    pub pool_base: u64,
    pub pool_frames: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderDomainStatus {
    Absent,
    MetadataOnly,
    Callable(HostedProviderDomainBinding),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderDomainError {
    ImageOffsetUnaligned,
    EmptyImage,
    EmptyImageFrames,
    ImageFrameCapacityOverflow,
    ImageExceedsFrames,
    EmptyPoolFrames,
    EmptyProviderDomainCookie,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderExportCallPlan {
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
    pub provider_export_rva: u64,
    pub provider_export_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportCallError {
    Overflow,
    ExportOutsideImage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportBinding {
    PrivateDependencyRequired,
    ProviderDomainCall(HostedProviderExportCallPlan),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportBindingError {
    Domain(HostedProviderDomainError),
    Export(HostedProviderExportCallError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderImportThunkPlan {
    pub thunk_va: u64,
    pub thunk_offset: u64,
    pub export_call_gate: u64,
    pub provider_domain_cookie: u64,
    pub provider_export_rva: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderImportThunkError {
    Overflow,
    ThunkOutsideTable,
    OutputTooSmall,
}

pub fn page_align_up(value: u64) -> Result<u64, HostedProviderImagePlanError> {
    match value.checked_add(PAGE_SIZE - 1) {
        Some(value) => Ok(value & !(PAGE_SIZE - 1)),
        None => Err(HostedProviderImagePlanError::Overflow),
    }
}

pub fn classify_hosted_provider_domain(
    descriptor: Option<HostedProviderDomainDescriptor>,
) -> Result<HostedProviderDomainStatus, HostedProviderDomainError> {
    let Some(descriptor) = descriptor else {
        return Ok(HostedProviderDomainStatus::Absent);
    };
    if descriptor.image_offset & (PAGE_SIZE - 1) != 0 {
        return Err(HostedProviderDomainError::ImageOffsetUnaligned);
    }
    if descriptor.image_len == 0 {
        return Err(HostedProviderDomainError::EmptyImage);
    }
    if descriptor.image_frames == 0 {
        return Err(HostedProviderDomainError::EmptyImageFrames);
    }
    let Some(image_frame_capacity) = descriptor.image_frames.checked_mul(PAGE_SIZE) else {
        return Err(HostedProviderDomainError::ImageFrameCapacityOverflow);
    };
    if descriptor.image_len > image_frame_capacity {
        return Err(HostedProviderDomainError::ImageExceedsFrames);
    }
    if descriptor.pool_frames == 0 {
        return Err(HostedProviderDomainError::EmptyPoolFrames);
    }
    if descriptor.export_call_gate == 0 {
        return Ok(HostedProviderDomainStatus::MetadataOnly);
    }
    if descriptor.provider_domain_cookie == 0 {
        return Err(HostedProviderDomainError::EmptyProviderDomainCookie);
    }
    Ok(HostedProviderDomainStatus::Callable(
        HostedProviderDomainBinding {
            image_offset: descriptor.image_offset,
            image_len: descriptor.image_len,
            image_frames: descriptor.image_frames,
            pool_base: descriptor.pool_base,
            pool_frames: descriptor.pool_frames,
            export_call_gate: descriptor.export_call_gate,
            provider_domain_cookie: descriptor.provider_domain_cookie,
        },
    ))
}

pub fn plan_hosted_provider_export_call(
    binding: HostedProviderDomainBinding,
    provider_export_rva: u64,
) -> Result<HostedProviderExportCallPlan, HostedProviderExportCallError> {
    if provider_export_rva >= binding.image_len {
        return Err(HostedProviderExportCallError::ExportOutsideImage);
    }
    let Some(provider_export_offset) = binding.image_offset.checked_add(provider_export_rva) else {
        return Err(HostedProviderExportCallError::Overflow);
    };
    Ok(HostedProviderExportCallPlan {
        export_call_gate: binding.export_call_gate,
        provider_domain_cookie: binding.provider_domain_cookie,
        provider_export_rva,
        provider_export_offset,
    })
}

pub fn plan_hosted_provider_import_binding(
    descriptor: Option<HostedProviderDomainDescriptor>,
    provider_export_rva: u64,
) -> Result<HostedProviderImportBinding, HostedProviderImportBindingError> {
    match classify_hosted_provider_domain(descriptor)
        .map_err(HostedProviderImportBindingError::Domain)?
    {
        HostedProviderDomainStatus::Absent | HostedProviderDomainStatus::MetadataOnly => {
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        }
        HostedProviderDomainStatus::Callable(binding) => {
            Ok(HostedProviderImportBinding::ProviderDomainCall(
                plan_hosted_provider_export_call(binding, provider_export_rva)
                    .map_err(HostedProviderImportBindingError::Export)?,
            ))
        }
    }
}

pub fn plan_hosted_provider_import_thunk(
    thunk_table_va: u64,
    thunk_table_len: u64,
    thunk_index: u64,
    export_plan: HostedProviderExportCallPlan,
) -> Result<HostedProviderImportThunkPlan, HostedProviderImportThunkError> {
    let Some(thunk_offset) = thunk_index.checked_mul(HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    let Some(thunk_end) = thunk_offset.checked_add(HOSTED_PROVIDER_IMPORT_THUNK_LEN as u64) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    if thunk_end > thunk_table_len {
        return Err(HostedProviderImportThunkError::ThunkOutsideTable);
    }
    let Some(thunk_va) = thunk_table_va.checked_add(thunk_offset) else {
        return Err(HostedProviderImportThunkError::Overflow);
    };
    Ok(HostedProviderImportThunkPlan {
        thunk_va,
        thunk_offset,
        export_call_gate: export_plan.export_call_gate,
        provider_domain_cookie: export_plan.provider_domain_cookie,
        provider_export_rva: export_plan.provider_export_rva,
    })
}

pub fn encode_hosted_provider_import_thunk(
    thunk: HostedProviderImportThunkPlan,
    out: &mut [u8],
) -> Result<(), HostedProviderImportThunkError> {
    if out.len() < HOSTED_PROVIDER_IMPORT_THUNK_LEN {
        return Err(HostedProviderImportThunkError::OutputTooSmall);
    }
    out[..HOSTED_PROVIDER_IMPORT_THUNK_LEN].copy_from_slice(&[
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, imm64
        0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, // mov r10, imm64
        0x49, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, // mov r11, imm64
        0x41, 0xff, 0xe3, // jmp r11
    ]);
    out[2..10].copy_from_slice(&thunk.provider_export_rva.to_le_bytes());
    out[12..20].copy_from_slice(&thunk.provider_domain_cookie.to_le_bytes());
    out[22..30].copy_from_slice(&thunk.export_call_gate.to_le_bytes());
    Ok(())
}

pub fn plan_provider_prefixed_image(
    shared_provider_image_lens: &[u64],
    primary_image_len: u64,
    private_dependency_image_lens: &[u64],
    minimum_frames: u64,
    frame_capacity: u64,
) -> Result<HostedProviderImagePlan, HostedProviderImagePlanError> {
    let mut provider_prefix_len = 0u64;
    for len in shared_provider_image_lens {
        provider_prefix_len = provider_prefix_len
            .checked_add(page_align_up(*len)?)
            .ok_or(HostedProviderImagePlanError::Overflow)?;
    }

    let primary_offset = provider_prefix_len;
    let private_dependency_offset = primary_offset
        .checked_add(page_align_up(primary_image_len)?)
        .ok_or(HostedProviderImagePlanError::Overflow)?;
    let mut total_image_len = private_dependency_offset;
    for len in private_dependency_image_lens {
        total_image_len = total_image_len
            .checked_add(page_align_up(*len)?)
            .ok_or(HostedProviderImagePlanError::Overflow)?;
    }

    let planned_frames = page_align_up(total_image_len)? / PAGE_SIZE;
    let total_frames = if planned_frames < minimum_frames {
        minimum_frames
    } else {
        planned_frames
    };
    if total_frames > frame_capacity {
        return Err(HostedProviderImagePlanError::ExceedsFrameCapacity);
    }

    Ok(HostedProviderImagePlan {
        provider_prefix_len,
        primary_offset,
        private_dependency_offset,
        total_image_len,
        total_frames,
    })
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

    #[test]
    fn provider_prefixed_image_plan_preserves_current_no_provider_layout() {
        let plan = plan_provider_prefixed_image(&[], 0x21_234, &[0x10], 64, 128).unwrap();
        assert_eq!(
            plan,
            HostedProviderImagePlan {
                provider_prefix_len: 0,
                primary_offset: 0,
                private_dependency_offset: 0x22_000,
                total_image_len: 0x23_000,
                total_frames: 64,
            }
        );
    }

    #[test]
    fn provider_prefixed_image_plan_places_primary_after_shared_providers() {
        let plan =
            plan_provider_prefixed_image(&[0x23_001], 0x8_400, &[0x41_000, 0x1], 0, 128).unwrap();
        assert_eq!(plan.provider_prefix_len, 0x24_000);
        assert_eq!(plan.primary_offset, 0x24_000);
        assert_eq!(plan.private_dependency_offset, 0x2d_000);
        assert_eq!(plan.total_image_len, 0x6f_000);
        assert_eq!(plan.total_frames, 0x6f);
    }

    #[test]
    fn provider_prefixed_image_plan_rejects_capacity_and_overflow() {
        assert_eq!(
            plan_provider_prefixed_image(&[0x20_000], 0x20_000, &[], 0, 0x3),
            Err(HostedProviderImagePlanError::ExceedsFrameCapacity)
        );
        assert_eq!(
            plan_provider_prefixed_image(&[u64::MAX], 0, &[], 0, u64::MAX),
            Err(HostedProviderImagePlanError::Overflow)
        );
    }

    #[test]
    fn provider_domain_classifies_absent_metadata_and_callable_domains() {
        assert_eq!(
            classify_hosted_provider_domain(None),
            Ok(HostedProviderDomainStatus::Absent)
        );

        let metadata_only = HostedProviderDomainDescriptor {
            image_offset: 0,
            image_len: 0x12_345,
            image_frames: 0x13,
            pool_base: 0x8800_0000,
            pool_frames: 4,
            export_call_gate: 0,
            provider_domain_cookie: 0,
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(metadata_only)),
            Ok(HostedProviderDomainStatus::MetadataOnly)
        );

        let callable = HostedProviderDomainDescriptor {
            export_call_gate: 0xfeed,
            provider_domain_cookie: 0x55aa,
            ..metadata_only
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(callable)),
            Ok(HostedProviderDomainStatus::Callable(
                HostedProviderDomainBinding {
                    image_offset: callable.image_offset,
                    image_len: callable.image_len,
                    image_frames: callable.image_frames,
                    pool_base: callable.pool_base,
                    pool_frames: callable.pool_frames,
                    export_call_gate: callable.export_call_gate,
                    provider_domain_cookie: callable.provider_domain_cookie,
                }
            ))
        );
    }

    #[test]
    fn provider_domain_rejects_invalid_metadata() {
        let valid = HostedProviderDomainDescriptor {
            image_offset: 0,
            image_len: 0x1000,
            image_frames: 1,
            pool_base: 0x8800_0000,
            pool_frames: 1,
            export_call_gate: 0,
            provider_domain_cookie: 0,
        };
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_offset: 1,
                ..valid
            })),
            Err(HostedProviderDomainError::ImageOffsetUnaligned)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_len: 0,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyImage)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                image_len: 0x1001,
                ..valid
            })),
            Err(HostedProviderDomainError::ImageExceedsFrames)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                pool_frames: 0,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyPoolFrames)
        );
        assert_eq!(
            classify_hosted_provider_domain(Some(HostedProviderDomainDescriptor {
                export_call_gate: 0xbeef,
                ..valid
            })),
            Err(HostedProviderDomainError::EmptyProviderDomainCookie)
        );
    }

    #[test]
    fn provider_export_call_plan_uses_gate_without_direct_client_jump() {
        let binding = HostedProviderDomainBinding {
            image_offset: 0x40_000,
            image_len: 0x20_000,
            image_frames: 0x20,
            pool_base: 0x8800_0000,
            pool_frames: 8,
            export_call_gate: 0xbeef,
            provider_domain_cookie: 0xfeed_cafe,
        };
        assert_eq!(
            plan_hosted_provider_export_call(binding, 0x1234),
            Ok(HostedProviderExportCallPlan {
                export_call_gate: 0xbeef,
                provider_domain_cookie: 0xfeed_cafe,
                provider_export_rva: 0x1234,
                provider_export_offset: 0x41_234,
            })
        );
        assert_eq!(
            plan_hosted_provider_export_call(binding, binding.image_len),
            Err(HostedProviderExportCallError::ExportOutsideImage)
        );
    }

    #[test]
    fn provider_import_binding_requires_private_dependency_without_callable_domain() {
        assert_eq!(
            plan_hosted_provider_import_binding(None, 0x1234),
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        );

        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0,
                    provider_domain_cookie: 0,
                }),
                0x1234,
            ),
            Ok(HostedProviderImportBinding::PrivateDependencyRequired)
        );
    }

    #[test]
    fn provider_import_binding_uses_callable_domain_export_plan() {
        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0x60_000,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x2345,
            ),
            Ok(HostedProviderImportBinding::ProviderDomainCall(
                HostedProviderExportCallPlan {
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                    provider_export_rva: 0x2345,
                    provider_export_offset: 0x62_345,
                }
            ))
        );
    }

    #[test]
    fn provider_import_binding_reports_domain_and_export_errors() {
        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 1,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x1234,
            ),
            Err(HostedProviderImportBindingError::Domain(
                HostedProviderDomainError::ImageOffsetUnaligned
            ))
        );

        assert_eq!(
            plan_hosted_provider_import_binding(
                Some(HostedProviderDomainDescriptor {
                    image_offset: 0,
                    image_len: 0x20_000,
                    image_frames: 0x20,
                    pool_base: 0x9000_0000,
                    pool_frames: 8,
                    export_call_gate: 0xcafe,
                    provider_domain_cookie: 0xabcd,
                }),
                0x20_000,
            ),
            Err(HostedProviderImportBindingError::Export(
                HostedProviderExportCallError::ExportOutsideImage
            ))
        );
    }

    #[test]
    fn provider_import_thunk_planner_assigns_fixed_slots() {
        let export_plan = HostedProviderExportCallPlan {
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0xaaaa_bbbb_cccc_dddd,
            provider_export_rva: 0x4567,
            provider_export_offset: 0x84_567,
        };
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, 0x100, 3, export_plan),
            Ok(HostedProviderImportThunkPlan {
                thunk_va: 0x7000_00c0,
                thunk_offset: 0xc0,
                export_call_gate: export_plan.export_call_gate,
                provider_domain_cookie: export_plan.provider_domain_cookie,
                provider_export_rva: export_plan.provider_export_rva,
            })
        );
    }

    #[test]
    fn provider_import_thunk_planner_rejects_table_overflow() {
        let export_plan = HostedProviderExportCallPlan {
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0xaaaa_bbbb_cccc_dddd,
            provider_export_rva: 0x4567,
            provider_export_offset: 0x84_567,
        };
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, 0x40, 2, export_plan),
            Err(HostedProviderImportThunkError::ThunkOutsideTable)
        );
        assert_eq!(
            plan_hosted_provider_import_thunk(0x7000_0000, u64::MAX, u64::MAX, export_plan),
            Err(HostedProviderImportThunkError::Overflow)
        );
        assert_eq!(
            plan_hosted_provider_import_thunk(u64::MAX, 0x100, 1, export_plan),
            Err(HostedProviderImportThunkError::Overflow)
        );
    }

    #[test]
    fn provider_import_thunk_encoder_preserves_win64_arguments_for_gate() {
        let thunk = HostedProviderImportThunkPlan {
            thunk_va: 0x7000_0040,
            thunk_offset: 0x40,
            export_call_gate: 0x1111_2222_3333_4444,
            provider_domain_cookie: 0x0102_0304_0506_0708,
            provider_export_rva: 0x5566_7788_99aa_bbcc,
        };
        let mut out = [0xcc; HOSTED_PROVIDER_IMPORT_THUNK_SLOT_LEN as usize];
        encode_hosted_provider_import_thunk(thunk, &mut out).unwrap();
        assert_eq!(
            &out[..HOSTED_PROVIDER_IMPORT_THUNK_LEN],
            &[
                0x48, 0xb8, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x49, 0xba, 0x08, 0x07,
                0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x49, 0xbb, 0x44, 0x44, 0x33, 0x33, 0x22, 0x22,
                0x11, 0x11, 0x41, 0xff, 0xe3,
            ]
        );
        assert!(out[HOSTED_PROVIDER_IMPORT_THUNK_LEN..]
            .iter()
            .all(|byte| *byte == 0xcc));

        let mut too_small = [0u8; HOSTED_PROVIDER_IMPORT_THUNK_LEN - 1];
        assert_eq!(
            encode_hosted_provider_import_thunk(thunk, &mut too_small),
            Err(HostedProviderImportThunkError::OutputTooSmall)
        );
    }
}
