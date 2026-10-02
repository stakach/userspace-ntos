//! Value-only admission for a caller-visible subrange of a retained video-memory grant.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerMemoryGrant {
    pub physical: u64,
    pub length: u64,
    pub caller_va: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerMemoryRequest {
    pub physical: u64,
    pub length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerMemoryRejection {
    MissingGrantPhysical,
    MissingGrantLength,
    MissingCallerVa,
    MemoryRangeNotGranted,
    OutsideVideoGrant,
    ArithmeticOverflow,
}

/// `memory_range_granted` is a prior value-policy result, not a physical authority token.
/// Native callers must retain and authenticate the exact resource, owner and mapping themselves.
pub fn admit_caller_memory(
    grant: CallerMemoryGrant,
    request: CallerMemoryRequest,
    memory_range_granted: bool,
) -> Result<u64, CallerMemoryRejection> {
    if grant.physical == 0 {
        return Err(CallerMemoryRejection::MissingGrantPhysical);
    }
    if grant.length == 0 {
        return Err(CallerMemoryRejection::MissingGrantLength);
    }
    if grant.caller_va == 0 {
        return Err(CallerMemoryRejection::MissingCallerVa);
    }
    if !memory_range_granted {
        return Err(CallerMemoryRejection::MemoryRangeNotGranted);
    }
    let grant_end = grant
        .physical
        .checked_add(grant.length)
        .ok_or(CallerMemoryRejection::ArithmeticOverflow)?;
    let request_end = request
        .physical
        .checked_add(request.length)
        .ok_or(CallerMemoryRejection::ArithmeticOverflow)?;
    if request.length == 0 || request.physical < grant.physical || request_end > grant_end {
        return Err(CallerMemoryRejection::OutsideVideoGrant);
    }
    let caller_va = grant
        .caller_va
        .checked_add(request.physical - grant.physical)
        .ok_or(CallerMemoryRejection::ArithmeticOverflow)?;
    caller_va
        .checked_add(request.length)
        .ok_or(CallerMemoryRejection::ArithmeticOverflow)?;
    Ok(caller_va)
}
