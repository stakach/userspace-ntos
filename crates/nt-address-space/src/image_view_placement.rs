//! NT5 x64 image view placement values, independent of PE bytes and native mapping effects.

use crate::{ALLOCATION_GRANULARITY, PAGE_SIZE, STATUS_CONFLICTING_ADDRESSES,
    STATUS_INVALID_PARAMETER_4};

const IMAGE_NOT_AT_BASE: u32 = 0x4000_0003;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageViewPlacementRequest {
    pub preferred_base: u64,
    pub requested_base: Option<u64>,
    /// Candidate supplied by the target's genuine VAD allocator; this is not mapping authority.
    pub alternate_base: Option<u64>,
    pub image_size: u64,
    pub highest_admitted_address: u64,
    /// Raw NtMapViewOfSection x64 ZeroBits: count below 32, mask at or above 32.
    pub zero_bits: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageViewPlacement {
    pub base: u64,
    pub size: u64,
    pub status: u32,
}

fn zero_bits_count(raw: u64) -> Result<u32, u32> {
    let count = if raw >= 32 { raw.leading_zeros() }
        else if raw != 0 { raw as u32 + 32 } else { 0 };
    if count > 53 { Err(STATUS_INVALID_PARAMETER_4) } else { Ok(count) }
}

/// `available` is an already serialized target VAD conflict query, not a physical capability or
/// permission token. The caller must retain exact target ownership through native publication.
pub fn plan_image_view_placement(
    request: ImageViewPlacementRequest,
    mut available: impl FnMut(u64, u64) -> bool,
) -> Result<ImageViewPlacement, u32> {
    let zero_bits = zero_bits_count(request.zero_bits)?;
    let size = request.image_size.checked_add(PAGE_SIZE - 1)
        .map(|size| size & !(PAGE_SIZE - 1)).filter(|size| *size != 0)
        .ok_or(STATUS_CONFLICTING_ADDRESSES)?;
    let valid = |base: u64, constrained: bool| {
        let ceiling = if constrained && zero_bits != 0 {
            request.highest_admitted_address.min(u64::MAX >> zero_bits)
        } else { request.highest_admitted_address };
        base >= ALLOCATION_GRANULARITY && base.checked_add(size - 1).is_some_and(|end| end <= ceiling)
    };
    let plan = |base| ImageViewPlacement {
        base, size,
        status: if base == request.preferred_base { 0 } else { IMAGE_NOT_AT_BASE },
    };
    if let Some(base) = request.requested_base.filter(|base| *base != 0) {
        if zero_bits != 0 && base.checked_add(size)
            .is_none_or(|end| end > u64::MAX >> zero_bits)
        {
            return Err(STATUS_INVALID_PARAMETER_4);
        }
        let base = base & !(ALLOCATION_GRANULARITY - 1);
        return if valid(base, false) && available(base, size) { Ok(plan(base)) }
            else { Err(STATUS_CONFLICTING_ADDRESSES) };
    }
    let preferred = request.preferred_base & !(ALLOCATION_GRANULARITY - 1);
    if valid(preferred, true) && available(preferred, size) { return Ok(plan(preferred)); }
    if let Some(base) = request.alternate_base {
        if base & (ALLOCATION_GRANULARITY - 1) == 0 && valid(base, true) && available(base, size) {
            return Ok(plan(base));
        }
    }
    Err(STATUS_CONFLICTING_ADDRESSES)
}
