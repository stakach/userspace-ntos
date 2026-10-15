//! Status policy for the driver-visible kernel debugger control export.
//!
//! The native host has no kernel debugger or ReactOS internal dump provider.
//! Classify the command without inspecting caller pointers or claiming an effect.

/// ReactOS internal debugger command used by i8042prt's Tab-key ISR path.
pub const ROS_INTERNAL_COMMAND: u32 = u32::from_le_bytes(*b"Ros ");

const STATUS_NOT_IMPLEMENTED: i32 = 0xc000_0002_u32 as i32;
const STATUS_INVALID_INFO_CLASS: i32 = 0xc000_0003_u32 as i32;

/// Return the explicit failure for a debugger operation without a provider.
///
/// ReactOS recognizes `Ros ` only in DBG builds. Its non-DBG implementation
/// falls through to `STATUS_INVALID_INFO_CLASS`. Commands 7 through 20 are
/// defined debugger operations, but no corresponding native provider exists.
pub const fn classify_command(command: u32) -> i32 {
    match command {
        ROS_INTERNAL_COMMAND => STATUS_INVALID_INFO_CLASS,
        7..=20 => STATUS_NOT_IMPLEMENTED,
        _ => STATUS_INVALID_INFO_CLASS,
    }
}
