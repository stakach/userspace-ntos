//! `PS_ATTRIBUTE_HANDLE_LIST`: a process created with inheritance and an explicit handle list
//! inherits only the listed handles, at the same values (`ObInitProcess`). Each listed handle must
//! be a handle of the parent that carries `OBJ_INHERIT`; kernel32 checks the same with
//! `GetHandleInformation` before it calls `NtCreateUserProcess`.

use crate::{
    Handle, HandleObject, InheritedHandle, ProcessId, ProcessManager, STATUS_ACCESS_VIOLATION,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};
use alloc::vec::Vec;

/// Handles one `PS_ATTRIBUTE_HANDLE_LIST` may name. Wine's conhost launch lists one; a longer list
/// fails the creation with `STATUS_INSUFFICIENT_RESOURCES` rather than being truncated.
pub const INHERIT_HANDLE_LIST_CAPACITY: usize = 32;

/// A captured `PS_ATTRIBUTE_HANDLE_LIST`: handle values as the caller passed them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InheritHandleList {
    values: [u64; INHERIT_HANDLE_LIST_CAPACITY],
    len: usize,
}

impl InheritHandleList {
    pub fn values(&self) -> &[u64] {
        &self.values[..self.len]
    }
}

/// Decode the private process-creation service our ntdll's `NtCreateUserProcess` composition
/// issues: the nine `NtCreateProcessEx` arguments, then the `PS_ATTRIBUTE_HANDLE_LIST` value
/// (an array of `HANDLE`) and its byte size. `read` copies caller memory.
pub fn decode_process_create_with_handle_list(
    args: &[u64],
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
) -> Result<crate::ProcessCreateInput, u32> {
    if args.len() < 11 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut create = crate::decode_process_create_input(&args[..9], true)?;
    let (address, size) = (args[9], args[10]);
    // The list only restricts inheritance: without INHERIT_HANDLES nothing is inherited, so a
    // list is a malformed request. NT also rejects an empty or partial-handle list.
    if create.flags & crate::PROCESS_CREATE_FLAGS_INHERIT_HANDLES == 0
        || address == 0
        || size == 0
        || size % 8 != 0
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let len = usize::try_from(size / 8).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    if len > INHERIT_HANDLE_LIST_CAPACITY {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut bytes = [0u8; INHERIT_HANDLE_LIST_CAPACITY * 8];
    if !read(address, &mut bytes[..len * 8]) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let mut values = [0u64; INHERIT_HANDLE_LIST_CAPACITY];
    for (index, value) in values.iter_mut().take(len).enumerate() {
        *value = u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
    }
    create.inherit_list = Some(InheritHandleList { values, len });
    Ok(create)
}

impl ProcessManager {
    /// The parent handles a child created with `list` inherits: each listed handle once, in list
    /// order. A value that is not a handle of `pid` fails with `STATUS_INVALID_HANDLE`; a handle
    /// without `OBJ_INHERIT` (or an ALPC port, which never inherits) with
    /// `STATUS_INVALID_PARAMETER`, the status kernel32's own check reports as
    /// `ERROR_INVALID_PARAMETER`.
    pub fn inheritable_handles_from_list(
        &self,
        pid: ProcessId,
        list: &[u64],
    ) -> Result<Vec<InheritedHandle>, u32> {
        let mut inherited = Vec::new();
        inherited.try_reserve(list.len()).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        for &value in list {
            let handle = Handle::try_from(value).map_err(|_| STATUS_INVALID_HANDLE)?;
            let object = self.lookup_handle(pid, handle).ok_or(STATUS_INVALID_HANDLE)?;
            let flags = self.handle_flags(pid, handle).ok_or(STATUS_INVALID_HANDLE)?;
            if !flags.inherit || matches!(object, HandleObject::AlpcPort { .. }) {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if inherited.iter().any(|entry: &InheritedHandle| entry.handle == handle) {
                continue;
            }
            inherited.push(InheritedHandle {
                handle,
                object,
                granted_access: self.handle_access(pid, handle).ok_or(STATUS_INVALID_HANDLE)?,
                flags,
            });
        }
        Ok(inherited)
    }
}
