//! `PS_ATTRIBUTE_HANDLE_LIST`: a process created with inheritance and an explicit handle list
//! inherits only the listed handles, at the same values (`ObInitProcess`). Each listed handle must
//! be a handle of the parent that carries `OBJ_INHERIT`; kernel32 checks the same with
//! `GetHandleInformation` before it calls `NtCreateUserProcess`.

use crate::{
    Handle, HandleObject, InheritedHandle, ProcessId, ProcessManager, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};
use alloc::vec::Vec;

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
