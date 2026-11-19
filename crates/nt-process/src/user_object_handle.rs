//! Process-owned handles to provider USER objects (WindowStation, Desktop and any other type the
//! provider registers). Ps owns only the handle-table entry; the provider domain retains the
//! body, its type and its generation, and resolves the returned target back to that body.

use crate::native_handle::{
    NativeHandleCaller, NativeHandleInformation, NativeHandleScope, NativePsCloseError,
    STATUS_OBJECT_TYPE_MISMATCH,
};
use crate::{
    Handle, HandleObject, HandleTargetKind, ProcessId, ProcessManager, TypedHandlePublication,
    STATUS_INVALID_HANDLE,
};
use nt_types::AccessMode;

/// The exact provider body a USER handle names. `generation` prevents a recycled body address
/// from inheriting an earlier object's handles; `object_type` is the registered type identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UserObjectTarget {
    pub domain: u64,
    pub object_type: u64,
    pub body: u64,
    pub generation: u64,
}

#[derive(Debug)]
pub enum UserObjectKind {}

impl HandleTargetKind for UserObjectKind {
    type Target = UserObjectTarget;
    fn object(target: UserObjectTarget) -> HandleObject {
        HandleObject::UserObject(target)
    }
}

pub type UserObjectHandlePublication = TypedHandlePublication<UserObjectKind>;

impl ProcessManager {
    /// Reserve an invisible USER handle in the caller's effective table, or the system table
    /// for OBJ_KERNEL_HANDLE from kernel mode.
    pub fn reserve_native_user_object_handle(
        &mut self,
        caller: NativeHandleCaller,
        attributes: u32,
    ) -> Result<UserObjectHandlePublication, u32> {
        self.reserve_native_typed_handle(caller, attributes)
    }

    /// ObReferenceObjectByHandle for a USER handle: the exact caller table, the optional
    /// expected type and, for user-mode callers, the handle's granted access.
    pub fn lookup_native_user_object_handle(
        &self,
        caller: NativeHandleCaller,
        value: u64,
        desired_access: u32,
        expected_type: Option<u64>,
    ) -> Result<UserObjectTarget, u32> {
        let NativeHandleScope::Table { owner, handle, .. } =
            self.decode_native_handle(caller, value)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let HandleObject::UserObject(target) =
            self.lookup_handle(owner, handle).ok_or(STATUS_INVALID_HANDLE)?
        else {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        };
        if expected_type.is_some_and(|expected| expected != target.object_type) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        let granted = self.handle_access(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
        if caller.mode() == AccessMode::UserMode && desired_access & !granted != 0 {
            return Err(crate::STATUS_ACCESS_DENIED);
        }
        Ok(target)
    }

    /// Remove the exact table entry and return the target for the provider's dereference.
    pub fn close_native_user_object_handle(
        &mut self,
        caller: NativeHandleCaller,
        value: u64,
    ) -> Result<UserObjectTarget, NativePsCloseError> {
        let inspected = self
            .inspect_native_close_target(caller, value)
            .map_err(NativePsCloseError::Status)?;
        let HandleObject::UserObject(target) = inspected.object() else {
            return Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH));
        };
        let removed = self.close_native_handle(caller, value)?;
        debug_assert_eq!(removed.into_object(), HandleObject::UserObject(target));
        Ok(target)
    }

    /// ObFindHandleForObject over the explicit target process. `None` Object or ObjectType is a
    /// wildcard and `information` must match exactly; only published entries are searched and
    /// no reference is acquired.
    pub fn find_native_user_object_handle(
        &self,
        caller: NativeHandleCaller,
        process: ProcessId,
        body: Option<u64>,
        object_type: Option<u64>,
        information: Option<NativeHandleInformation>,
    ) -> Result<Option<Handle>, u32> {
        self.find_native_handle(caller, process, information, |object| {
            matches!(object, HandleObject::UserObject(target)
                if body.is_none_or(|body| body == target.body)
                    && object_type.is_none_or(|object_type| object_type == target.object_type))
        })
    }
}

#[cfg(test)]
mod tests;
