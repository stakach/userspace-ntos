//! ALPC ntdll helper routines that are pure buffer/layout math.
//!
//! The kernel-backed `NtAlpc*` syscalls live behind the syscall transport. These helpers are the
//! user-mode support functions around `ALPC_MESSAGE_ATTRIBUTES`: size the attribute buffer, initialize
//! its header, and locate a selected per-attribute structure in the packed buffer.

use core::mem::size_of;

use nt_alpc_abi::{
    msg_attr_flag, AlpcContextAttr, AlpcDataViewAttr, AlpcHandleAttr, AlpcMessageAttributes,
    AlpcSecurityAttr, AlpcTokenAttr,
};

/// Windows exposes a 64 KiB ALPC maximum through `AlpcMaxAllowedMessageLength`.
pub const MAX_ALLOWED_MESSAGE_LENGTH: u32 = 0x1_0000;

pub const VALID_MESSAGE_ATTRIBUTE_FLAGS: u32 = msg_attr_flag::SECURITY
    | msg_attr_flag::VIEW
    | msg_attr_flag::CONTEXT
    | msg_attr_flag::HANDLE
    | msg_attr_flag::TOKEN;

const ATTRIBUTE_ORDER: [u32; 5] = [
    msg_attr_flag::SECURITY,
    msg_attr_flag::VIEW,
    msg_attr_flag::CONTEXT,
    msg_attr_flag::HANDLE,
    msg_attr_flag::TOKEN,
];

#[inline]
pub const fn valid_attribute_flags(flags: u32) -> bool {
    flags & !VALID_MESSAGE_ATTRIBUTE_FLAGS == 0
}

#[inline]
pub const fn valid_single_attribute_flag(flag: u32) -> bool {
    flag != 0 && (flag & (flag - 1)) == 0 && valid_attribute_flags(flag)
}

#[inline]
pub const fn attribute_struct_size(flag: u32) -> Option<usize> {
    match flag {
        msg_attr_flag::SECURITY => Some(size_of::<AlpcSecurityAttr>()),
        msg_attr_flag::VIEW => Some(size_of::<AlpcDataViewAttr>()),
        msg_attr_flag::CONTEXT => Some(size_of::<AlpcContextAttr>()),
        msg_attr_flag::HANDLE => Some(size_of::<AlpcHandleAttr>()),
        msg_attr_flag::TOKEN => Some(size_of::<AlpcTokenAttr>()),
        _ => None,
    }
}

/// Return the total `ALPC_MESSAGE_ATTRIBUTES` buffer size for an allocated-attributes mask.
pub const fn message_attribute_buffer_size(flags: u32) -> Option<usize> {
    if !valid_attribute_flags(flags) {
        return None;
    }
    let mut total = size_of::<AlpcMessageAttributes>();
    let mut i = 0usize;
    while i < ATTRIBUTE_ORDER.len() {
        let flag = ATTRIBUTE_ORDER[i];
        if flags & flag != 0 {
            if let Some(size) = attribute_struct_size(flag) {
                total += size;
            }
        }
        i += 1;
    }
    Some(total)
}

/// Return the byte offset of one attribute structure within a packed attribute buffer.
pub const fn message_attribute_offset(allocated_flags: u32, attribute_flag: u32) -> Option<usize> {
    if !valid_attribute_flags(allocated_flags) || !valid_single_attribute_flag(attribute_flag) {
        return None;
    }
    if allocated_flags & attribute_flag == 0 {
        return None;
    }

    let mut offset = size_of::<AlpcMessageAttributes>();
    let mut i = 0usize;
    while i < ATTRIBUTE_ORDER.len() {
        let flag = ATTRIBUTE_ORDER[i];
        if flag == attribute_flag {
            return Some(offset);
        }
        if allocated_flags & flag != 0 {
            if let Some(size) = attribute_struct_size(flag) {
                offset += size;
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_includes_selected_structs_in_fixed_order() {
        assert_eq!(
            message_attribute_buffer_size(msg_attr_flag::CONTEXT),
            Some(size_of::<AlpcMessageAttributes>() + size_of::<AlpcContextAttr>())
        );
        assert_eq!(
            message_attribute_buffer_size(msg_attr_flag::SECURITY | msg_attr_flag::VIEW),
            Some(
                size_of::<AlpcMessageAttributes>()
                    + size_of::<AlpcSecurityAttr>()
                    + size_of::<AlpcDataViewAttr>()
            )
        );
        assert_eq!(message_attribute_buffer_size(0), Some(size_of::<AlpcMessageAttributes>()));
    }

    #[test]
    fn offsets_skip_only_allocated_preceding_attributes() {
        let flags = msg_attr_flag::VIEW | msg_attr_flag::HANDLE | msg_attr_flag::TOKEN;
        assert_eq!(
            message_attribute_offset(flags, msg_attr_flag::VIEW),
            Some(size_of::<AlpcMessageAttributes>())
        );
        assert_eq!(
            message_attribute_offset(flags, msg_attr_flag::HANDLE),
            Some(size_of::<AlpcMessageAttributes>() + size_of::<AlpcDataViewAttr>())
        );
        assert_eq!(
            message_attribute_offset(flags, msg_attr_flag::TOKEN),
            Some(
                size_of::<AlpcMessageAttributes>()
                    + size_of::<AlpcDataViewAttr>()
                    + size_of::<AlpcHandleAttr>()
            )
        );
    }

    #[test]
    fn invalid_or_absent_flags_are_rejected() {
        assert_eq!(message_attribute_buffer_size(0x40), None);
        assert_eq!(
            message_attribute_offset(msg_attr_flag::VIEW, msg_attr_flag::CONTEXT),
            None
        );
        assert_eq!(
            message_attribute_offset(msg_attr_flag::VIEW, msg_attr_flag::VIEW | msg_attr_flag::HANDLE),
            None
        );
    }
}
