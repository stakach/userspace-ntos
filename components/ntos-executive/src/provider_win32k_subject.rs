//! Canonical caller-subject leases retained through nested win32k Object Manager calls.

use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_process::native_handle::NativeHandleCaller;
use nt_user_host::win32k_subject_lease::{Win32kSubjectLeases, Win32kSubjectOwner};

const STATUS_INVALID_PARAMETER: i32 = 0xc000_000du32 as i32;
const BEGIN: u64 = 1;
const RELEASE: u64 = 2;

static mut LEASES: Win32kSubjectLeases<PeerRoute, LaneDispatchIdentity> =
    Win32kSubjectLeases::new();

fn owner(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
) -> Win32kSubjectOwner<PeerRoute, LaneDispatchIdentity> {
    Win32kSubjectOwner {
        route,
        dispatch,
        caller,
    }
}

pub(crate) unsafe fn dispatch(
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    let owner = owner(route, dispatch, caller);
    match op {
        BEGIN if first == 0 && second == 0 && third == 0 => {
            match crate::service_sec_image::with_provider_security_managers(|pm, tokens| {
                (&mut *core::ptr::addr_of_mut!(LEASES)).admit(pm, tokens, owner, None)
            }) {
                Ok(id) => (0, id, 0, 0),
                Err(status) => (status as i32, 0, 0, 0),
            }
        }
        RELEASE if first != 0 && second == 0 && third == 0 => {
            match crate::service_sec_image::with_provider_security_managers(|_, tokens| {
                (&mut *core::ptr::addr_of_mut!(LEASES)).release(tokens, first, owner, None)
            }) {
                Ok(()) => (0, 0, 0, 0),
                Err(status) => (status as i32, 0, 0, 0),
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0, 0, 0),
    }
}

/// Called only by canonical shared-ingress terminal completion. Failed token release retains the
/// exact row and is fatal; it must not silently drop an owned reference.
pub(crate) unsafe fn retire_completed(route: PeerRoute, dispatch: LaneDispatchIdentity) {
    if (&*core::ptr::addr_of!(LEASES)).is_empty() {
        return;
    }
    crate::service_sec_image::with_provider_security_managers(|_, tokens| {
        (&mut *core::ptr::addr_of_mut!(LEASES))
            .drain_dispatch(tokens, route, dispatch)
            .map(|_| ())
    })
    .expect("terminal win32k subject lease must release its canonical token references");
}
