//! `NtUserBuildHwndList` as the pinned LiberNT win32k declares it.
//!
//! `win32ss/include/ntuser.h:1561` and `win32ss/w32ksvc64.h` (`SVC_(UserBuildHwndList, 8)`):
//!
//! ```c
//! NTSTATUS NtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren,
//!     BOOLEAN bNonImmersive, ULONG dwThreadId, ULONG cHwnd, HWND *phwndList,
//!     ULONG *pcHwndNeeded);
//! ```
//!
//! The released image registers the same eight arguments in its argument table. A service has
//! one signature per release, so the stack tail is read by position and each value at its
//! declared width; a register or stack slot holding a narrower type has undefined upper bits.

pub const BUILD_HWND_LIST_SSN: u64 = 0x101b;
pub const BUILD_HWND_LIST_ARGUMENTS: usize = 8;
/// Arguments five to eight, at `rsp + 0x28` onwards at syscall entry.
pub const BUILD_HWND_LIST_STACK_ARGUMENTS: usize = BUILD_HWND_LIST_ARGUMENTS - 4;

/// Addresses of the caller's stack arguments, or `None` when they would wrap.
pub fn build_hwnd_list_tail_addresses(sp: u64) -> Option<[u64; BUILD_HWND_LIST_STACK_ARGUMENTS]> {
    if sp == 0 {
        return None;
    }
    Some([
        sp.checked_add(0x28)?,
        sp.checked_add(0x30)?,
        sp.checked_add(0x38)?,
        sp.checked_add(0x40)?,
    ])
}

/// The caller's arguments, each at its declared width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildHwndListCall {
    pub children: bool,
    pub non_immersive: bool,
    pub thread_id: u32,
    pub capacity: u32,
    pub list: u64,
    pub needed: u64,
}

/// What the executive copies back to the caller after the staged dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildHwndListCopyOut {
    /// The value win32k stored through `pcHwndNeeded`, when it stored one.
    pub needed: Option<u32>,
    /// Handles win32k stored through `phwndList`.
    pub handles: usize,
}

impl BuildHwndListCall {
    pub fn capture(registers: [u64; 4], tail: [u64; BUILD_HWND_LIST_STACK_ARGUMENTS]) -> Self {
        Self {
            children: registers[2] as u8 != 0,
            non_immersive: registers[3] as u8 != 0,
            thread_id: tail[0] as u32,
            capacity: tail[1] as u32,
            list: tail[2],
            needed: tail[3],
        }
    }

    /// The capacity win32k is given: the caller's, bounded by the staging buffer.
    pub fn forwarded_capacity(&self, staged_capacity: u32) -> u32 {
        self.capacity.min(staged_capacity)
    }

    /// The stack tail for the staged dispatch. A NULL list stays NULL so win32k still tells a
    /// count query (`!phwndList && cHwnd == 0`) from a short or missing buffer.
    pub fn staged_tail(
        &self,
        staged_list: u64,
        staged_needed: u64,
        staged_capacity: u32,
    ) -> [u64; BUILD_HWND_LIST_STACK_ARGUMENTS] {
        [
            u64::from(self.thread_id),
            u64::from(self.forwarded_capacity(staged_capacity)),
            if self.list == 0 { 0 } else { staged_list },
            staged_needed,
        ]
    }

    /// win32k stores the required count (never zero: it includes the terminator) before it
    /// checks the buffer, and stores handles only when it returns success.
    pub fn copy_out(&self, status: u32, required: u32, staged_capacity: u32) -> BuildHwndListCopyOut {
        let succeeded = (status as i32) >= 0;
        let stored_handles = succeeded && required != 0 && self.list != 0;
        BuildHwndListCopyOut {
            needed: (required != 0).then_some(required),
            handles: if stored_handles {
                required.min(self.forwarded_capacity(staged_capacity)) as usize
            } else {
                0
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fill_call_reads_thread_capacity_list_and_needed_from_the_stack_tail() {
        let call = BuildHwndListCall::capture(
            [0, 0x300c0, 1, 1],
            [0, 12, 0x100_302d_7d40, 0x100_302d_7da0],
        );
        assert_eq!(
            (call.thread_id, call.capacity, call.list, call.needed),
            (0, 12, 0x100_302d_7d40, 0x100_302d_7da0)
        );
    }

    /// KVM run 43595199385, log line 77558: msgina's dialog passed `bNonImmersive` in r9 as
    /// 0x27E01. Only the low byte of a BOOLEAN register argument is defined.
    #[test]
    fn undefined_upper_bytes_of_the_boolean_register_do_not_move_the_stack_arguments() {
        let call = BuildHwndListCall::capture(
            [0, 0x300c0, 0x2_7e01, 0x2_7e01],
            [0, 12, 0x100_302d_7d40, 0x100_302d_7da0],
        );
        assert!(call.children && call.non_immersive);
        assert_eq!(
            (call.thread_id, call.capacity, call.list, call.needed),
            (0, 12, 0x100_302d_7d40, 0x100_302d_7da0)
        );
    }

    /// Same run, line 77560: the ULONG stack slots carried 0x100_0000_0000 above the value.
    #[test]
    fn ulong_stack_slots_are_read_at_their_declared_width() {
        let call = BuildHwndListCall::capture(
            [0, 0x300c0, 1, 1],
            [
                0x100_0000_0000,
                0x100_0000_000c,
                0x100_302d_7d40,
                0x100_302d_7da0,
            ],
        );
        assert_eq!((call.thread_id, call.capacity), (0, 12));
    }

    #[test]
    fn a_count_query_keeps_its_null_list() {
        let call = BuildHwndListCall::capture([0, 0, 0, 1], [0, 0, 0, 0x100_302d_7da0]);
        assert_eq!((call.capacity, call.list, call.needed), (0, 0, 0x100_302d_7da0));
    }

    const STAGED_LIST: u64 = 0x7000_0000;
    const STAGED_NEEDED: u64 = 0x7000_0ff0;
    const STAGED_CAPACITY: u32 = 510;
    const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;

    #[test]
    fn the_staged_dispatch_carries_every_stack_argument_of_the_pinned_service() {
        let call = BuildHwndListCall::capture(
            [0, 0x300c0, 1, 0x2_7e01],
            [0x100_0000_0000, 0x100_0000_000c, 0x100_302d_7d40, 0x100_302d_7da0],
        );
        assert_eq!(
            call.staged_tail(STAGED_LIST, STAGED_NEEDED, STAGED_CAPACITY),
            [0, 12, STAGED_LIST, STAGED_NEEDED]
        );
        assert_eq!(BUILD_HWND_LIST_STACK_ARGUMENTS, 4);
    }

    #[test]
    fn a_null_list_reaches_win32k_as_null_whatever_the_capacity() {
        for capacity in [0, 12] {
            let call = BuildHwndListCall::capture([0, 0, 0, 1], [0, capacity, 0, 0x1000]);
            let tail = call.staged_tail(STAGED_LIST, STAGED_NEEDED, STAGED_CAPACITY);
            assert_eq!((tail[1], tail[2]), (capacity, 0));
        }
        // A buffer with zero capacity is a short buffer, not a count query.
        let call = BuildHwndListCall::capture([0, 0, 0, 1], [0, 0, 0x2000, 0x1000]);
        assert_eq!(
            call.staged_tail(STAGED_LIST, STAGED_NEEDED, STAGED_CAPACITY)[2],
            STAGED_LIST
        );
    }

    #[test]
    fn the_capacity_is_bounded_by_the_staging_buffer() {
        let call = BuildHwndListCall::capture([0, 0, 0, 1], [0, 4096, 0x2000, 0x1000]);
        assert_eq!(
            call.staged_tail(STAGED_LIST, STAGED_NEEDED, STAGED_CAPACITY)[1],
            u64::from(STAGED_CAPACITY)
        );
    }

    #[test]
    fn copy_out_follows_what_win32k_stored() {
        let fill = BuildHwndListCall::capture([0, 0, 0, 1], [0, 12, 0x2000, 0x1000]);
        assert_eq!(
            fill.copy_out(0, 9, STAGED_CAPACITY),
            BuildHwndListCopyOut { needed: Some(9), handles: 9 }
        );
        assert_eq!(
            fill.copy_out(STATUS_BUFFER_TOO_SMALL, 40, STAGED_CAPACITY),
            BuildHwndListCopyOut { needed: Some(40), handles: 0 }
        );
        // A failure before the count was stored leaves both caller outputs alone.
        assert_eq!(
            fill.copy_out(0xc000_0008, 0, STAGED_CAPACITY),
            BuildHwndListCopyOut { needed: None, handles: 0 }
        );
        let count = BuildHwndListCall::capture([0, 0, 0, 1], [0, 0, 0, 0x1000]);
        assert_eq!(
            count.copy_out(0, 9, STAGED_CAPACITY),
            BuildHwndListCopyOut { needed: Some(9), handles: 0 }
        );
    }

    #[test]
    fn tail_addresses_reject_a_missing_or_wrapping_stack_pointer() {
        assert_eq!(build_hwnd_list_tail_addresses(0), None);
        assert_eq!(build_hwnd_list_tail_addresses(u64::MAX - 0x30), None);
        assert_eq!(
            build_hwnd_list_tail_addresses(0x1000),
            Some([0x1028, 0x1030, 0x1038, 0x1040])
        );
    }
}
