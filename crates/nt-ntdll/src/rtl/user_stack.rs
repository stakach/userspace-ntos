//! `RtlCreateUserStack` sizing and `INITIAL_TEB` layout helpers.
//!
//! The exported DLL function still performs the live `NtAllocateVirtualMemory` /
//! `NtProtectVirtualMemory` calls. This module keeps the Windows-compatible
//! alignment/defaulting rules host-testable.

use crate::{NtStatus, STATUS_INVALID_PARAMETER};

/// `STATUS_CONFLICTING_ADDRESSES`.
pub const STATUS_CONFLICTING_ADDRESSES: NtStatus = 0xC000_0018;
/// `STATUS_INVALID_PARAMETER_3`.
pub const STATUS_INVALID_PARAMETER_3: NtStatus = 0xC000_00F1;

/// Native AMD64 page size.
pub const DEFAULT_PAGE_SIZE: usize = 0x1000;
/// Native AMD64 allocation granularity.
pub const DEFAULT_RESERVE_ALIGNMENT: usize = 0x1_0000;
/// Conservative fallback when the image optional header is unavailable.
pub const DEFAULT_STACK_COMMIT: usize = 0x1000;
/// Conservative fallback when the image optional header is unavailable.
pub const DEFAULT_STACK_RESERVE: usize = 0x10_0000;

/// Computed stack reservation/commit shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserStackLayout {
    /// Bytes reserved for the stack address range.
    pub reserve: usize,
    /// Bytes usable above the guard page.
    pub commit: usize,
    /// Bytes protected as guard below `StackLimit`, or zero.
    pub guard: usize,
}

/// `INITIAL_TEB` fields on x64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitialTebFields {
    pub previous_stack_base: u64,
    pub previous_stack_limit: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub allocated_stack_base: u64,
}

#[inline]
fn is_valid_alignment(value: usize) -> bool {
    value != 0 && value.is_power_of_two()
}

#[inline]
fn round_up(value: usize, alignment: usize) -> Option<usize> {
    Some(value.checked_add(alignment - 1)? & !(alignment - 1))
}

/// Compute public `RtlCreateUserStack` sizes.
pub fn create_user_stack_layout(
    committed_stack_size: usize,
    maximum_stack_size: usize,
    zero_bits: u32,
    commit_alignment: usize,
    reserve_alignment: usize,
    default_commit: usize,
    default_reserve: usize,
) -> Result<UserStackLayout, NtStatus> {
    if !is_valid_alignment(commit_alignment) || !is_valid_alignment(reserve_alignment) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if zero_bits >= 32 {
        return Err(STATUS_INVALID_PARAMETER_3);
    }
    // The current executive VM allocator ignores ZeroBits, so fail honestly until
    // constrained high-address allocation is modeled.
    if zero_bits != 0 {
        return Err(STATUS_CONFLICTING_ADDRESSES);
    }

    let default_commit = default_commit.max(DEFAULT_PAGE_SIZE);
    let default_reserve = default_reserve.max(DEFAULT_STACK_RESERVE);
    let requested_commit = if committed_stack_size == 0 {
        default_commit
    } else {
        committed_stack_size
    };
    let requested_reserve = if maximum_stack_size == 0 {
        default_reserve
    } else {
        maximum_stack_size
    };

    let commit = round_up(requested_commit, commit_alignment).ok_or(STATUS_INVALID_PARAMETER)?;
    let reserve_floor = if commit >= requested_reserve {
        round_up(commit, DEFAULT_STACK_RESERVE).ok_or(STATUS_INVALID_PARAMETER)?
    } else {
        requested_reserve
    };
    let reserve = round_up(reserve_floor, reserve_alignment).ok_or(STATUS_INVALID_PARAMETER)?;
    let guard = if reserve >= commit.saturating_add(DEFAULT_PAGE_SIZE) {
        DEFAULT_PAGE_SIZE
    } else {
        0
    };

    Ok(UserStackLayout {
        reserve,
        commit,
        guard,
    })
}

/// Fill the `INITIAL_TEB` fields for a stack range returned by the VM plane.
pub fn initial_teb_fields(stack_allocation_base: u64, layout: UserStackLayout) -> InitialTebFields {
    let stack_base = stack_allocation_base + layout.reserve as u64;
    InitialTebFields {
        previous_stack_base: 0,
        previous_stack_limit: 0,
        stack_base,
        stack_limit: stack_base - layout.commit as u64,
        allocated_stack_base: stack_allocation_base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DCOMMIT: usize = 0x3000;
    const DRESERVE: usize = 0x10_0000;

    #[test]
    fn defaults_and_explicit_sizes_are_rounded() {
        assert_eq!(
            create_user_stack_layout(0, 0, 0, 1, 1, DCOMMIT, DRESERVE).unwrap(),
            UserStackLayout {
                commit: DCOMMIT,
                reserve: DRESERVE,
                guard: DEFAULT_PAGE_SIZE
            }
        );
        assert_eq!(
            create_user_stack_layout(0x11_000, 0x14_0000, 0, 0x4000, 0x40000, DCOMMIT, DRESERVE)
                .unwrap(),
            UserStackLayout {
                commit: 0x14_000,
                reserve: 0x14_0000,
                guard: DEFAULT_PAGE_SIZE
            }
        );
    }

    #[test]
    fn explicit_reserve_is_preserved_when_larger_than_commit() {
        assert_eq!(
            create_user_stack_layout(0x20_000, 0x20_000, 0, 1, 1, DCOMMIT, DRESERVE)
                .unwrap()
                .reserve,
            DRESERVE
        );
        assert_eq!(
            create_user_stack_layout(0x20_000, 0x40_000, 0, 0x1000, 0x1_0000, DCOMMIT, DRESERVE)
                .unwrap()
                .reserve,
            0x40_000
        );
    }

    #[test]
    fn invalid_alignment_and_unsupported_zero_bits_fail() {
        assert_eq!(
            create_user_stack_layout(0x11_000, 0x11_0000, 0, 1, 0, DCOMMIT, DRESERVE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            create_user_stack_layout(0x4000, DRESERVE, 1, 0x1000, 0x1000, DCOMMIT, DRESERVE),
            Err(STATUS_CONFLICTING_ADDRESSES)
        );
        assert_eq!(
            create_user_stack_layout(0x4000, DRESERVE, 32, 0x1000, 0x1000, DCOMMIT, DRESERVE),
            Err(STATUS_INVALID_PARAMETER_3)
        );
    }

    #[test]
    fn initial_teb_fields_describe_top_down_stack() {
        let layout = UserStackLayout {
            reserve: 0x10_0000,
            commit: 0x4000,
            guard: 0x1000,
        };
        assert_eq!(
            initial_teb_fields(0x7000_0000, layout),
            InitialTebFields {
                previous_stack_base: 0,
                previous_stack_limit: 0,
                stack_base: 0x7010_0000,
                stack_limit: 0x700f_c000,
                allocated_stack_base: 0x7000_0000,
            }
        );
    }
}
