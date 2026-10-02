use nt_video_miniport::caller_memory::{
    admit_caller_memory, CallerMemoryGrant, CallerMemoryRejection, CallerMemoryRequest,
};

fn grant() -> CallerMemoryGrant {
    CallerMemoryGrant {
        physical: 0x8000_0000,
        length: 16 * 1024 * 1024,
        caller_va: 0x0000_0100_0900_0000,
    }
}

fn request() -> CallerMemoryRequest {
    CallerMemoryRequest {
        physical: grant().physical,
        length: 1024 * 768 * 4,
    }
}

#[test]
fn exact_current_mode_range_returns_only_the_granted_caller_address() {
    assert_eq!(
        admit_caller_memory(grant(), request(), true),
        Ok(grant().caller_va)
    );
    let requested = CallerMemoryRequest {
        physical: grant().physical + 0x2000,
        length: 0x1000,
    };
    assert_eq!(
        admit_caller_memory(grant(), requested, true),
        Ok(grant().caller_va + 0x2000)
    );
}

#[test]
fn each_missing_grant_field_is_distinct_and_never_falls_back() {
    assert_eq!(
        admit_caller_memory(
            CallerMemoryGrant {
                physical: 0,
                ..grant()
            },
            request(),
            true
        ),
        Err(CallerMemoryRejection::MissingGrantPhysical),
    );
    assert_eq!(
        admit_caller_memory(
            CallerMemoryGrant {
                length: 0,
                ..grant()
            },
            request(),
            true
        ),
        Err(CallerMemoryRejection::MissingGrantLength),
    );
    assert_eq!(
        admit_caller_memory(
            CallerMemoryGrant {
                caller_va: 0,
                ..grant()
            },
            request(),
            true
        ),
        Err(CallerMemoryRejection::MissingCallerVa),
    );
    assert_eq!(
        admit_caller_memory(
            CallerMemoryGrant {
                physical: 0,
                length: 0,
                caller_va: 0
            },
            request(),
            false
        ),
        Err(CallerMemoryRejection::MissingGrantPhysical),
    );
}

#[test]
fn a_video_subrange_cannot_replace_missing_validated_memory_resource_records() {
    assert_eq!(
        admit_caller_memory(grant(), request(), false),
        Err(CallerMemoryRejection::MemoryRangeNotGranted),
    );
    assert_eq!(
        admit_caller_memory(
            grant(),
            CallerMemoryRequest {
                length: 1,
                ..request()
            },
            false
        ),
        Err(CallerMemoryRejection::MemoryRangeNotGranted),
    );
}

#[test]
fn full_extent_and_last_byte_are_valid_but_empty_and_outside_are_not() {
    let granted = grant();
    assert_eq!(
        admit_caller_memory(
            granted,
            CallerMemoryRequest {
                physical: granted.physical,
                length: granted.length
            },
            true
        ),
        Ok(granted.caller_va),
    );
    assert_eq!(
        admit_caller_memory(
            granted,
            CallerMemoryRequest {
                physical: granted.physical + granted.length - 1,
                length: 1
            },
            true
        ),
        Ok(granted.caller_va + granted.length - 1),
    );
    for requested in [
        CallerMemoryRequest {
            physical: granted.physical,
            length: 0,
        },
        CallerMemoryRequest {
            physical: granted.physical - 1,
            length: 1,
        },
        CallerMemoryRequest {
            physical: granted.physical + granted.length,
            length: 1,
        },
        CallerMemoryRequest {
            physical: granted.physical + granted.length - 1,
            length: 2,
        },
        CallerMemoryRequest {
            physical: granted.physical,
            length: granted.length + 1,
        },
    ] {
        assert_eq!(
            admit_caller_memory(granted, requested, true),
            Err(CallerMemoryRejection::OutsideVideoGrant)
        );
    }
}

#[test]
fn physical_extent_overflow_is_refused_even_when_subtraction_would_fit() {
    let granted = CallerMemoryGrant {
        physical: u64::MAX - 7,
        length: 16,
        ..grant()
    };
    assert_eq!(
        admit_caller_memory(
            granted,
            CallerMemoryRequest {
                physical: granted.physical,
                length: 1
            },
            true
        ),
        Err(CallerMemoryRejection::ArithmeticOverflow),
    );
    assert_eq!(
        admit_caller_memory(
            grant(),
            CallerMemoryRequest {
                physical: u64::MAX - 1,
                length: 4
            },
            true
        ),
        Err(CallerMemoryRejection::ArithmeticOverflow),
    );
}

#[test]
fn caller_address_and_returned_extent_never_wrap() {
    let granted = CallerMemoryGrant {
        caller_va: u64::MAX - 7,
        ..grant()
    };
    for requested in [
        CallerMemoryRequest {
            physical: granted.physical + 8,
            length: 1,
        },
        CallerMemoryRequest {
            physical: granted.physical,
            length: 8,
        },
    ] {
        assert_eq!(
            admit_caller_memory(granted, requested, true),
            Err(CallerMemoryRejection::ArithmeticOverflow)
        );
    }
    assert_eq!(
        admit_caller_memory(
            granted,
            CallerMemoryRequest {
                physical: granted.physical,
                length: 7
            },
            true
        ),
        Ok(granted.caller_va),
    );
}
