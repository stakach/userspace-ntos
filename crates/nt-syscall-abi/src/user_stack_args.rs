//! Where an x64 system service finds its fifth and later arguments on the caller's stack.
//!
//! At `syscall` entry RSP points at the caller's return address, followed by the four
//! register home slots; argument 5 (index 4) is at `rsp + 0x28`. NT's system-service entry
//! clamps a non-user RSP to `MmUserProbeAddress` and copies the tail under SEH, so an
//! unreadable tail fails the call with `STATUS_ACCESS_VIOLATION` instead of faulting the
//! kernel (`references/reactos/ntoskrnl/ke/amd64/traphandler.c`, `KiSystemCallHandler`).

/// Lowest address user mode may map; the first 64 KiB is never valid user memory.
pub const MM_LOWEST_USER_ADDRESS: u64 = 0x0000_0000_0001_0000;
/// `MmUserProbeAddress` on x64: the first address a user-mode probe rejects.
pub const MM_USER_PROBE_ADDRESS: u64 = 0x0000_7FFF_FFFF_0000;
pub const STATUS_ACCESS_VIOLATION: i32 = 0xC000_0005u32 as i32;

/// Byte offset from the syscall-entry RSP to stack argument index 4 (the fifth argument).
const FIRST_STACK_ARGUMENT_OFFSET: u64 = 0x28;
const REGISTER_ARGUMENTS: u64 = 4;

/// The address of 0-based argument `index` (which must be a stack argument, `index >= 4`)
/// for a service entered with `caller_sp`, provided the whole 8-byte slot is user memory.
pub fn user_stack_argument_address(caller_sp: u64, index: u64) -> Result<u64, i32> {
    let slot = index
        .checked_sub(REGISTER_ARGUMENTS)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let address = slot
        .checked_mul(8)
        .and_then(|offset| offset.checked_add(FIRST_STACK_ARGUMENT_OFFSET))
        .and_then(|offset| caller_sp.checked_add(offset))
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let end = address.checked_add(8).ok_or(STATUS_ACCESS_VIOLATION)?;
    if address < MM_LOWEST_USER_ADDRESS || end > MM_USER_PROBE_ADDRESS {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(address)
}

/// Validate the complete stack tail of an `argc`-argument service before any slot is read.
/// The tail is contiguous, so its first and last slots bound every slot between them.
pub fn validate_user_stack_argument_tail(caller_sp: u64, argc: u64) -> Result<(), i32> {
    if argc <= REGISTER_ARGUMENTS {
        return Ok(());
    }
    user_stack_argument_address(caller_sp, REGISTER_ARGUMENTS)?;
    user_stack_argument_address(caller_sp, argc - 1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_SP: u64 = 0x0000_0100_105c_26d8;

    #[test]
    fn stack_arguments_follow_the_return_address_and_home_slots() {
        assert_eq!(user_stack_argument_address(CLIENT_SP, 4), Ok(CLIENT_SP + 0x28));
        assert_eq!(user_stack_argument_address(CLIENT_SP, 6), Ok(CLIENT_SP + 0x38));
        assert_eq!(validate_user_stack_argument_tail(CLIENT_SP, 5), Ok(()));
        assert_eq!(validate_user_stack_argument_tail(CLIENT_SP, 16), Ok(()));
    }

    #[test]
    fn register_only_services_need_no_stack() {
        assert_eq!(validate_user_stack_argument_tail(0, 4), Ok(()));
        assert_eq!(user_stack_argument_address(CLIENT_SP, 3), Err(STATUS_ACCESS_VIOLATION));
    }

    /// KVM boot 44038636280: NtUserPeekMessage (5 arguments) arrived with caller RSP 0x31,
    /// a TCB debug-state word left in the root IPC buffer. NT fails that call; it never reads
    /// address 0x59 on the service's behalf.
    #[test]
    fn a_non_user_caller_stack_fails_the_call_with_an_access_violation() {
        assert_eq!(validate_user_stack_argument_tail(0x31, 5), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(validate_user_stack_argument_tail(MM_LOWEST_USER_ADDRESS - 0x28 - 8, 5),
            Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(validate_user_stack_argument_tail(MM_LOWEST_USER_ADDRESS - 0x28, 5), Ok(()));
    }

    #[test]
    fn a_tail_crossing_the_user_probe_address_fails_the_call() {
        let last_valid = MM_USER_PROBE_ADDRESS - 0x28 - 8;
        assert_eq!(validate_user_stack_argument_tail(last_valid, 5), Ok(()));
        assert_eq!(validate_user_stack_argument_tail(last_valid, 6), Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(validate_user_stack_argument_tail(0xFFFF_8000_0000_0000, 5),
            Err(STATUS_ACCESS_VIOLATION));
        assert_eq!(validate_user_stack_argument_tail(u64::MAX - 0x10, 5),
            Err(STATUS_ACCESS_VIOLATION));
    }
}
