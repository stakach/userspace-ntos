//! Dispatch-bound ownership of win32k native Section unmaps.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_memory_manager::GenericSectionView;
use nt_process::native_handle::NativeHandleCaller;
use nt_user_host::provider_section_unmap::{UnmapPhase, UnmapPublication};

use crate::ExecNtHandler;

const OP_UNMAP: u64 = 1;
const OP_ACK: u64 = 2;
const STATUS_INVALID_HANDLE: u32 = nt_process::STATUS_INVALID_HANDLE;
const STATUS_INVALID_PARAMETER: u32 = nt_process::STATUS_INVALID_PARAMETER;
const STATUS_INSUFFICIENT_RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const STATUS_NOT_MAPPED_VIEW: u32 = 0xC000_0019;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Owner {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    token: u64,
    base: u64,
}

struct Pending {
    publication: UnmapPublication<Owner, GenericSectionView>,
}

static mut PENDING: Vec<Pending> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

unsafe fn position(owner: Owner) -> Option<usize> {
    (&*core::ptr::addr_of!(PENDING))
        .iter()
        .position(|entry| entry.publication.owner() == owner)
}

unsafe fn unmap(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    process_handle: u64,
    base: u64,
) -> (i32, u64, u64, u64) {
    if (&*core::ptr::addr_of!(PENDING)).iter().any(|entry| {
        let owner = entry.publication.owner();
        owner.route == route
            && owner.dispatch == dispatch
            && owner.caller == caller
            && owner.base == base
    }) {
        return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    }
    let (target_pid, target_pi, view) =
        match handler.capture_provider_section_unmap_view(caller, process_handle, base) {
            Ok(captured) => captured,
            Err(status) => return (status as i32, 0, 0, 0),
        };
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => return (STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0),
    };
    let owner = Owner {
        route,
        dispatch,
        caller,
        token,
        base,
    };
    let pending = &mut *core::ptr::addr_of_mut!(PENDING);
    if pending.try_reserve(1).is_err() {
        return (STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0);
    }
    pending.push(Pending {
        publication: UnmapPublication::new(owner, view),
    });
    let index = pending.len() - 1;
    pending[index]
        .publication
        .begin_effect(owner)
        .expect("reserved unmap owner starts prepared");

    let status = match handler.unmap_generic_section_view_for_target(
        target_pid,
        target_pi,
        base,
        Some(view),
    ) {
        Ok(true) => 0,
        Ok(false) => STATUS_NOT_MAPPED_VIEW,
        Err(status) => status,
    };
    let Some(index) = position(owner) else {
        return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    };
    if (&mut *core::ptr::addr_of_mut!(PENDING))[index]
        .publication
        .complete(owner, status)
        .is_err()
    {
        // Physical retirement during the effect keeps the exact view in EffectUncertain.
        return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    }
    (status as i32, token, 0, 0)
}

pub(crate) unsafe fn dispatch(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    op: u64,
    first: u64,
    second: u64,
    third: u64,
) -> (i32, u64, u64, u64) {
    if third != 0 {
        return (STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
    }
    match op {
        OP_UNMAP => unmap(handler, route, dispatch, caller, first, second),
        OP_ACK if first != 0 && second != 0 => {
            let owner = Owner {
                route,
                dispatch,
                caller,
                token: first,
                base: second,
            };
            let Some(index) = position(owner) else {
                return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
            };
            let pending = &mut *core::ptr::addr_of_mut!(PENDING);
            if pending[index].publication.acknowledge(owner).is_err() {
                return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
            }
            pending.swap_remove(index);
            (0, 0, 0, 0)
        }
        _ => (STATUS_INVALID_PARAMETER as i32, 0, 0, 0),
    }
}

pub(crate) unsafe fn retire_completed(route: PeerRoute, dispatch: LaneDispatchIdentity) {
    let mut index = 0;
    while index < (&*core::ptr::addr_of!(PENDING)).len() {
        let owner = (&*core::ptr::addr_of!(PENDING))[index].publication.owner();
        if owner.route != route || owner.dispatch != dispatch {
            index += 1;
            continue;
        }
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        match pending[index].publication.retire_dispatch(owner) {
            Ok(UnmapPhase::Aborted) => {
                pending.swap_remove(index);
            }
            Ok(UnmapPhase::EffectUncertain) => index += 1,
            _ => index += 1,
        }
    }
}
