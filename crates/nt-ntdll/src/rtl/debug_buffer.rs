//! Layout and checked allocation policy for `RTL_DEBUG_INFORMATION`.

use core::ffi::c_void;

pub const DEBUG_INFORMATION_SIZE: usize = 0xd0;
pub const DEFAULT_VIEW_SIZE: usize = 0x400000;
pub const PAGE_SIZE: usize = 0x1000;
pub const QUERY_MODULES: u32 = 0x01;
pub const SUPPORTED_QUERY_MASK: u32 = QUERY_MODULES;

#[repr(C)]
pub struct DebugInformation {
    pub section_handle_client: *mut c_void,
    pub view_base_client: *mut c_void,
    pub view_base_target: *mut c_void,
    pub view_base_delta: u32,
    pub _padding0: u32,
    pub event_pair_client: *mut c_void,
    pub event_pair_target: *mut c_void,
    pub target_process_id: *mut c_void,
    pub target_thread_handle: *mut c_void,
    pub flags: u32,
    pub _padding1: u32,
    pub offset_free: usize,
    pub commit_size: usize,
    pub view_size: usize,
    pub modules: *mut c_void,
    pub back_traces: *mut c_void,
    pub heaps: *mut c_void,
    pub locks: *mut c_void,
    pub specific_heap: *mut c_void,
    pub target_process_handle: *mut c_void,
    pub verifier_options: *mut c_void,
    pub process_heap: *mut c_void,
    pub critical_section_handle: *mut c_void,
    pub critical_section_owner_thread: *mut c_void,
    pub reserved: [*mut c_void; 4],
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CommitPlan {
    pub result_offset: usize,
    pub commit_offset: usize,
    pub commit_size: usize,
    pub new_commit_size: usize,
    pub new_offset_free: usize,
}

fn align_page(value: usize) -> Option<usize> {
    value
        .checked_add(PAGE_SIZE - 1)
        .map(|size| size & !(PAGE_SIZE - 1))
}

pub fn reservation_size(requested: u32) -> Option<usize> {
    align_page(if requested == 0 {
        DEFAULT_VIEW_SIZE
    } else {
        requested as usize
    })
}

pub fn initial_information(base: *mut c_void, view_size: usize) -> DebugInformation {
    DebugInformation {
        section_handle_client: core::ptr::null_mut(),
        view_base_client: base,
        view_base_target: core::ptr::null_mut(),
        view_base_delta: 0,
        _padding0: 0,
        event_pair_client: core::ptr::null_mut(),
        event_pair_target: core::ptr::null_mut(),
        target_process_id: core::ptr::null_mut(),
        target_thread_handle: core::ptr::null_mut(),
        flags: 0,
        _padding1: 0,
        offset_free: DEBUG_INFORMATION_SIZE,
        commit_size: PAGE_SIZE,
        view_size,
        modules: core::ptr::null_mut(),
        back_traces: core::ptr::null_mut(),
        heaps: core::ptr::null_mut(),
        locks: core::ptr::null_mut(),
        specific_heap: core::ptr::null_mut(),
        target_process_handle: core::ptr::null_mut(),
        verifier_options: core::ptr::null_mut(),
        process_heap: core::ptr::null_mut(),
        critical_section_handle: core::ptr::null_mut(),
        critical_section_owner_thread: core::ptr::null_mut(),
        reserved: [core::ptr::null_mut(); 4],
    }
}

pub fn plan_commit(
    offset_free: usize,
    commit_size: usize,
    view_size: usize,
    size: usize,
) -> Option<CommitPlan> {
    let end = offset_free.checked_add(size)?;
    if end > view_size || offset_free > commit_size || commit_size > view_size {
        return None;
    }
    let new_commit_size = if end > commit_size {
        align_page(end)?.min(view_size)
    } else {
        commit_size
    };
    Some(CommitPlan {
        result_offset: offset_free,
        commit_offset: commit_size,
        commit_size: new_commit_size - commit_size,
        new_commit_size,
        new_offset_free: end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x64_debug_information_layout_matches_reactos() {
        assert_eq!(
            core::mem::size_of::<DebugInformation>(),
            DEBUG_INFORMATION_SIZE
        );
        assert_eq!(
            core::mem::offset_of!(DebugInformation, view_base_client),
            0x08
        );
        assert_eq!(core::mem::offset_of!(DebugInformation, flags), 0x40);
        assert_eq!(core::mem::offset_of!(DebugInformation, offset_free), 0x48);
        assert_eq!(core::mem::offset_of!(DebugInformation, modules), 0x60);
        assert_eq!(core::mem::offset_of!(DebugInformation, reserved), 0xb0);
    }

    #[test]
    fn reservation_sizes_match_native_rounding() {
        assert_eq!(reservation_size(0), Some(DEFAULT_VIEW_SIZE));
        assert_eq!(reservation_size(1), Some(PAGE_SIZE));
        assert_eq!(reservation_size(0x1000), Some(PAGE_SIZE));
        assert_eq!(reservation_size(0x1001), Some(0x2000));
    }

    #[test]
    fn initial_header_owns_the_first_committed_page() {
        let base = 0x1234_0000usize as *mut c_void;
        let info = initial_information(base, DEFAULT_VIEW_SIZE);
        assert_eq!(info.view_base_client, base);
        assert_eq!(info.offset_free, DEBUG_INFORMATION_SIZE);
        assert_eq!(info.commit_size, PAGE_SIZE);
        assert_eq!(info.view_size, DEFAULT_VIEW_SIZE);
        assert_eq!(info.flags, 0);
        assert!(info.modules.is_null());
    }

    #[test]
    fn commit_plan_grows_by_pages_but_advances_by_requested_bytes() {
        let plan = plan_commit(0xff0, 0x1000, 0x4000, 0x30).unwrap();
        assert_eq!(
            plan,
            CommitPlan {
                result_offset: 0xff0,
                commit_offset: 0x1000,
                commit_size: 0x1000,
                new_commit_size: 0x2000,
                new_offset_free: 0x1020,
            }
        );
        assert_eq!(
            plan_commit(0xd0, 0x1000, 0x1000, 0x20).unwrap().commit_size,
            0
        );
    }

    #[test]
    fn commit_plan_rejects_view_and_integer_overflow() {
        assert_eq!(plan_commit(0xff0, 0x1000, 0x1000, 0x20), None);
        assert_eq!(plan_commit(usize::MAX, usize::MAX, usize::MAX, 1), None);
        assert_eq!(plan_commit(0x2000, 0x1000, 0x4000, 1), None);
    }
}
