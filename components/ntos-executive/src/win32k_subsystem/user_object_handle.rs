//! The provider side of process-owned USER handles: bodies and counts live in `OBJ_TABLE`,
//! handles live in the caller's ProcessManager table and are reached through the root broker
//! ([`nt_user_host::user_object_handle_wire`]).

use super::*;
use nt_object_manager::win32k_user_objects::{UserObjectIdentity, UserObjectRelease};
use nt_types::AccessMode;
use nt_user_host::user_object_handle_wire as wire;
use nt_user_host::user_object_handles::HandleDelta;

const LABEL: u64 = W32_USER_OBJECT_LABEL;
/// `WIN32_CALLOUTS_FPNS.DesktopDeleteProcedure` / `WindowStationDeleteProcedure`.
const DESKTOP_DELETE_OFF: u64 = 10 * 8;
const WINDOW_STATION_DELETE_OFF: u64 = 13 * 8;

pub(super) fn access_mode(mode: u64) -> AccessMode {
    if mode as u8 == 0 { AccessMode::KernelMode } else { AccessMode::UserMode }
}

pub(super) fn store() -> &'static mut UserObjectStore {
    unsafe { &mut *core::ptr::addr_of_mut!(OBJ_TABLE) }
}

unsafe fn call(words: wire::Words) -> (i32, [u64; 3]) {
    let (info, status, first, second, third) =
        crate::driver_launch::call_on4_raw((LABEL << 12) | 4, words[0], words[1], words[2], words[3]);
    let canonical = status == status as u32 as u64 || status == status as u32 as i32 as i64 as u64;
    if info & 0xFFF != 4 || !canonical {
        crate::provider_bugcheck::report(0xc4, [LABEL, words[0], info, status]);
    }
    (status as u32 as i32, [first, second, third])
}

/// Run the type's delete procedure for a body whose last reference is gone, then free it.
pub(super) unsafe fn finalize(identity: UserObjectIdentity) {
    let offset = match identity.kind {
        ObKind::Desktop => DESKTOP_DELETE_OFF,
        ObKind::WindowStation => WINDOW_STATION_DELETE_OFF,
        ObKind::Other => panic!("USER object lacks a registered type delete method"),
    };
    let routine = read_volatile((WIN32_CALLOUTS + offset) as *const u64);
    assert_ne!(routine, 0, "USER object delete method is unregistered");
    let parameters = identity.body;
    let _ = call_win32k_pe(routine, &[(&parameters as *const u64) as u64]);
    assert!(provider_pool_free(identity.body), "USER object body retirement failed");
}

fn settle(release: UserObjectRelease) {
    if let UserObjectRelease::Final(identity) = release {
        unsafe { finalize(identity) };
    }
}

/// Apply every handle copy and removal the root recorded for this provider.
pub(super) unsafe fn drain() {
    loop {
        let (status, words) = call([wire::OP_DRAIN, 0, 0, 0]);
        if status != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, wire::OP_DRAIN, status as u32 as u64, 0]);
        }
        if words == [0; 3] {
            return;
        }
        // The provider's own domain is implicit: decode with a placeholder; only body, type,
        // generation and count are compared here.
        let delta = wire::decode_delta(0, words).unwrap_or_else(|_| {
            crate::provider_bugcheck::report(0xc4, [LABEL, words[0], words[1], words[2]])
        });
        let target = delta.target();
        let identity = store().identity(target.body).filter(|identity| {
            identity.generation == target.generation && identity.object_type == target.object_type
        });
        let Some(identity) = identity else {
            crate::provider_bugcheck::report(0xc4, [LABEL, target.body, target.generation, 1]);
        };
        let applied = match delta {
            HandleDelta::Acquired { count, .. } => {
                store().apply_acquired_handles(identity, count).map(|()| None)
            }
            HandleDelta::Released { count, .. } => {
                store().apply_released_handles(identity, count).map(Some)
            }
        };
        let release = applied.unwrap_or_else(|_| {
            crate::provider_bugcheck::report(0xc4, [LABEL, target.body, target.generation, 2])
        });
        let (ack, _) = call([wire::OP_ACKNOWLEDGE, words[0], words[1], words[2]]);
        if ack != 0 {
            crate::provider_bugcheck::report(0xc4, [LABEL, wire::OP_ACKNOWLEDGE, ack as u32 as u64, 0]);
        }
        if let Some(release) = release {
            settle(release);
        }
    }
}

/// Publish one handle the store has already counted. A refusal closes that count again, which
/// may finalize the body (ObInsertObject consumes the creator reference on failure).
pub(super) unsafe fn publish_counted(
    identity: UserObjectIdentity,
    attributes: u32,
    granted_access: u32,
    mode: AccessMode,
) -> Result<u64, i32> {
    let request = wire::Publish {
        mode,
        attributes: attributes & wire::PUBLISH_ATTRIBUTES,
        body: identity.body,
        object_type: identity.object_type,
        generation: identity.generation,
        granted_access,
    };
    let (status, [handle, _, _]) = call(request.encode());
    if status == 0 && handle != 0 {
        return Ok(handle);
    }
    let release = store()
        .close_handle(identity)
        .expect("a counted unpublished USER handle closes");
    settle(release);
    Err(if status != 0 { status } else { STATUS_INVALID_HANDLE_I32 })
}

/// A new handle that takes its own reference (ObOpenObjectByPointer, open by name).
pub(super) unsafe fn open(
    identity: UserObjectIdentity,
    attributes: u32,
    granted_access: u32,
    mode: AccessMode,
) -> Result<u64, i32> {
    drain();
    let identity = store()
        .open_handle(identity.body, identity.generation)
        .map_err(|_| STATUS_INVALID_HANDLE_I32)?;
    publish_counted(identity, attributes, granted_access, mode)
}

/// ObReferenceObjectByHandle: the caller's exact handle, resolved to this provider's body.
pub(super) unsafe fn lookup(
    handle: u64,
    desired_access: u32,
    expected_type: u64,
    mode: AccessMode,
) -> Result<(UserObjectIdentity, wire::Resolved), i32> {
    let request = wire::Lookup { mode, handle, desired_access, expected_type };
    let (status, words) = call(request.encode());
    if status != 0 {
        return Err(status);
    }
    let resolved = wire::Resolved::decode(words)
        .unwrap_or_else(|_| crate::provider_bugcheck::report(0xc4, [LABEL, handle, words[0], 3]));
    let identity = store()
        .inserted_identity(resolved.body, resolved.generation)
        .filter(|identity| identity.object_type == resolved.object_type)
        .unwrap_or_else(|| {
            crate::provider_bugcheck::report(0xc4, [LABEL, handle, resolved.body, resolved.generation])
        });
    Ok((identity, resolved))
}

/// The body a handle names, without a reference (diagnostics and parse roots).
pub(super) unsafe fn body_for_handle(handle: u64, expected_type: u64) -> Option<u64> {
    lookup(handle, 0, expected_type, AccessMode::KernelMode)
        .ok()
        .map(|(identity, _)| identity.body)
}

/// ObCloseHandle of a USER handle. INVALID_HANDLE / OBJECT_TYPE_MISMATCH mean "not a USER handle".
pub(super) unsafe fn close(handle: u64, mode: AccessMode) -> i32 {
    let (status, [code, first, second]) = call(wire::Close { mode, handle }.encode());
    if status != 0 {
        return status;
    }
    if code != 0 {
        crate::provider_bugcheck::report(code as u32, [first, second, 0, 0]);
    }
    drain();
    0
}

/// ObFindHandleForObject over the explicit target process.
pub(super) unsafe fn find(
    process: u64,
    body: u64,
    object_type: u64,
    information: Option<(u32, u32)>,
) -> Option<u64> {
    if process == 0 {
        return None;
    }
    let (status, [found, handle, _]) =
        call(wire::Find { process, body, object_type, information }.encode());
    (status == 0 && found == 1).then_some(handle)
}
