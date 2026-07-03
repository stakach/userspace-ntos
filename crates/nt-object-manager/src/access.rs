//! Minimal access checks (spec §10). v0.1 has no security descriptors, so the
//! policy is: resolve generic rights, then grant the requested access masked by
//! the type's valid access. A user-mode caller that asks for specific rights the
//! type does not define is denied; a kernel-mode caller (Driver Host, executive)
//! is trusted and simply gets the masked subset.

use nt_status::NtStatus;
use nt_types::{AccessMask, AccessMode, ClientId, GenericMapping, HandleValue, ObjAttrFlags};

use crate::store::ObjectRef;
use crate::ObjectManager;

/// Compute the access to grant for `desired` against a type's `valid` access and
/// generic `mapping`.
///
/// Resolves `GENERIC_*` (via `mapping`) and `MAXIMUM_ALLOWED` (→ all valid
/// rights), then grants `mapped ∩ valid`. If, after mapping, a **user-mode**
/// caller still requests bits outside `valid` (unsupported/privileged rights),
/// the check fails with `STATUS_ACCESS_DENIED`; a **kernel-mode** caller is
/// trusted and those bits are just masked off.
pub fn compute_granted(
    desired: AccessMask,
    valid: AccessMask,
    mapping: &GenericMapping,
    mode: AccessMode,
) -> Result<AccessMask, NtStatus> {
    let mut mapped = mapping.map(desired); // resolves GENERIC_* to specific rights
    if mapped.contains(AccessMask::MAXIMUM_ALLOWED) {
        let without = mapped.bits() & !AccessMask::MAXIMUM_ALLOWED.bits();
        mapped = AccessMask::from_bits_retain(without) | valid;
    }
    let granted = AccessMask::from_bits_retain(mapped.bits() & valid.bits());
    let over = mapped.bits() & !valid.bits();
    if mode == AccessMode::UserMode && over != 0 {
        return Err(NtStatus::ACCESS_DENIED);
    }
    Ok(granted)
}

impl ObjectManager {
    /// Access-check `desired` against `object`'s type for a client in `mode`,
    /// returning the access to grant (minimal policy, no security descriptor).
    pub fn check_access(
        &self,
        object: &ObjectRef,
        desired: AccessMask,
        mode: AccessMode,
    ) -> Result<AccessMask, NtStatus> {
        let ty = self
            .object_type(object.type_id())
            .ok_or(NtStatus::INVALID_PARAMETER)?;
        compute_granted(desired, ty.valid_access(), ty.generic_mapping(), mode)
    }

    /// Open a handle to `object` for `client`, running an access check on
    /// `desired_access` first (using the client's access mode). The handle
    /// records the *granted* access; a later `reference_by_handle` is checked
    /// against it. `STATUS_ACCESS_DENIED` if the access cannot be granted.
    pub fn open(
        &mut self,
        client: ClientId,
        object: &ObjectRef,
        desired_access: AccessMask,
        attributes: ObjAttrFlags,
    ) -> Result<HandleValue, NtStatus> {
        let mode = self.clients.client_mode(client)?;
        let granted = self.check_access(object, desired_access, mode)?;
        self.open_handle(client, object, granted, attributes)
    }
}
