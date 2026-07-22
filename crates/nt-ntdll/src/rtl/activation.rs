//! Activation-context stack layouts and transition validation.

use crate::NtStatus;

pub const FRAME_FLAG_RELEASE_ON_DEACTIVATION: u32 = 0x01;
pub const FRAME_FLAG_NO_DEACTIVATE: u32 = 0x02;
pub const FRAME_FLAG_HEAP_ALLOCATED: u32 = 0x08;
pub const FRAME_FLAG_NOT_REALLY_ACTIVATED: u32 = 0x10;
pub const FRAME_FLAG_ACTIVATED: u32 = 0x20;
pub const FRAME_FLAG_DEACTIVATED: u32 = 0x40;
pub const DEACTIVATE_FLAG_FORCE_EARLY: u32 = 0x01;
pub const ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION: u32 = 0x01;
pub const CALLER_FRAME_FORMAT_WHISTLER: u32 = 1;

pub const STATUS_SXS_EARLY_DEACTIVATION: NtStatus = 0xC015_000F;
pub const STATUS_SXS_INVALID_DEACTIVATION: NtStatus = 0xC015_0010;
pub const INVALID_COOKIE: usize = usize::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextStackFrame {
    pub previous: u64,
    pub activation_context: u64,
    pub flags: u32,
    pub padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActivationContextStack {
    pub active_frame: u64,
    pub frame_list_cache_flink: u64,
    pub frame_list_cache_blink: u64,
    pub flags: u32,
    pub next_cookie_sequence_number: u32,
    pub stack_id: u32,
    pub padding: u32,
}

impl ActivationContextStack {
    pub const SIZE: usize = 40;

    pub fn new(address: u64) -> Self {
        Self {
            frame_list_cache_flink: address + 8,
            frame_list_cache_blink: address + 8,
            next_cookie_sequence_number: 1,
            stack_id: 1,
            ..Self::default()
        }
    }
}

impl ActivationContextStackFrame {
    pub const SIZE: usize = 24;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallerAllocatedFrameBasic {
    pub size: u64,
    pub format: u32,
    pub padding: u32,
    pub frame: ActivationContextStackFrame,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallerAllocatedFrameExtended {
    pub basic: CallerAllocatedFrameBasic,
    pub extra: [u64; 4],
}

impl CallerAllocatedFrameBasic {
    pub const SIZE: usize = 40;
}

impl CallerAllocatedFrameExtended {
    pub const SIZE: usize = 72;
}

const _: [(); ActivationContextStack::SIZE] = [(); core::mem::size_of::<ActivationContextStack>()];
const _: [(); ActivationContextStackFrame::SIZE] =
    [(); core::mem::size_of::<ActivationContextStackFrame>()];
const _: [(); CallerAllocatedFrameBasic::SIZE] =
    [(); core::mem::size_of::<CallerAllocatedFrameBasic>()];
const _: [(); CallerAllocatedFrameExtended::SIZE] =
    [(); core::mem::size_of::<CallerAllocatedFrameExtended>()];

pub fn heap_frame_flags(activate_flags: u32) -> u32 {
    FRAME_FLAG_HEAP_ALLOCATED
        | if activate_flags & ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION != 0 {
            FRAME_FLAG_NO_DEACTIVATE | FRAME_FLAG_RELEASE_ON_DEACTIVATION
        } else {
            0
        }
}

pub fn release_count(flags: u32) -> usize {
    usize::from(flags & (FRAME_FLAG_HEAP_ALLOCATED | FRAME_FLAG_RELEASE_ON_DEACTIVATION) != 0)
}

pub fn validate_deactivation(
    frame_found: bool,
    frame_is_top: bool,
    frame_is_heap_allocated: bool,
    flags: u32,
) -> Result<(), NtStatus> {
    if flags & !DEACTIVATE_FLAG_FORCE_EARLY != 0 {
        return Err(crate::STATUS_INVALID_PARAMETER);
    }
    if !frame_found || !frame_is_heap_allocated {
        return Err(STATUS_SXS_INVALID_DEACTIVATION);
    }
    if !frame_is_top && flags & DEACTIVATE_FLAG_FORCE_EARLY == 0 {
        return Err(STATUS_SXS_EARLY_DEACTIVATION);
    }
    Ok(())
}

pub fn validate_activate_ex(flags: u32, teb_present: bool, context: usize) -> Result<(), NtStatus> {
    if flags & !ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION != 0
        || !teb_present
        || context == usize::MAX
    {
        return Err(crate::STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

pub fn validate_caller_frame(size: usize, format: u32) -> bool {
    size >= CallerAllocatedFrameBasic::SIZE && format == CALLER_FRAME_FORMAT_WHISTLER
}

pub fn caller_frame_can_deactivate(flags: u32) -> bool {
    flags & FRAME_FLAG_ACTIVATED != 0 && flags & FRAME_FLAG_DEACTIVATED == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_initializes_empty_cache_and_sequence() {
        let stack = ActivationContextStack::new(0x1000);
        assert_eq!(stack.active_frame, 0);
        assert_eq!(stack.frame_list_cache_flink, 0x1008);
        assert_eq!(stack.frame_list_cache_blink, 0x1008);
        assert_eq!(stack.next_cookie_sequence_number, 1);
        assert_eq!(stack.stack_id, 1);
    }

    #[test]
    fn deactivation_requires_a_live_cookie_and_top_order() {
        assert_eq!(
            validate_deactivation(false, false, false, 0),
            Err(STATUS_SXS_INVALID_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, false, true, 0),
            Err(STATUS_SXS_EARLY_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, false, true, DEACTIVATE_FLAG_FORCE_EARLY),
            Ok(())
        );
        assert_eq!(validate_deactivation(true, true, true, 0), Ok(()));
        assert_eq!(
            validate_deactivation(true, true, false, 0),
            Err(STATUS_SXS_INVALID_DEACTIVATION)
        );
        assert_eq!(
            validate_deactivation(true, true, true, 2),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn native_x64_frame_layouts_match_the_reactos_contract() {
        assert_eq!(
            core::mem::offset_of!(ActivationContextStack, active_frame),
            0
        );
        assert_eq!(
            core::mem::offset_of!(ActivationContextStack, frame_list_cache_flink),
            8
        );
        assert_eq!(core::mem::offset_of!(ActivationContextStack, flags), 24);
        assert_eq!(core::mem::offset_of!(ActivationContextStack, stack_id), 32);
        assert_eq!(core::mem::offset_of!(CallerAllocatedFrameBasic, frame), 16);
        assert_eq!(
            core::mem::offset_of!(CallerAllocatedFrameExtended, extra),
            40
        );
    }

    #[test]
    fn heap_frame_ownership_tracks_transferred_references() {
        let ordinary = heap_frame_flags(0);
        assert_eq!(release_count(ordinary), 1);

        let transferred = heap_frame_flags(ACTIVATE_EX_FLAG_RELEASE_ON_STACK_DEALLOCATION);
        assert_ne!(transferred & FRAME_FLAG_RELEASE_ON_DEACTIVATION, 0);
        assert_ne!(transferred & FRAME_FLAG_NO_DEACTIVATE, 0);
        assert_eq!(release_count(transferred), 1);
        assert_eq!(release_count(FRAME_FLAG_ACTIVATED), 0);
    }

    #[test]
    fn activation_and_caller_frame_validation_rejects_invalid_native_inputs() {
        assert_eq!(validate_activate_ex(0, true, 1), Ok(()));
        assert_eq!(
            validate_activate_ex(2, true, 1),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            validate_activate_ex(0, false, 1),
            Err(crate::STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            validate_activate_ex(0, true, usize::MAX),
            Err(crate::STATUS_INVALID_PARAMETER)
        );

        assert!(validate_caller_frame(CallerAllocatedFrameBasic::SIZE, 1));
        assert!(!validate_caller_frame(
            CallerAllocatedFrameBasic::SIZE - 1,
            1
        ));
        assert!(!validate_caller_frame(CallerAllocatedFrameBasic::SIZE, 0));
        assert!(caller_frame_can_deactivate(FRAME_FLAG_ACTIVATED));
        assert!(!caller_frame_can_deactivate(
            FRAME_FLAG_ACTIVATED | FRAME_FLAG_DEACTIVATED
        ));
    }
}
