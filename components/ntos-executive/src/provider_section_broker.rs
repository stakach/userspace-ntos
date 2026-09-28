//! Dispatch-bound publication of win32k-created native data sections.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::win32k_section_create_wire::{self as wire, SectionCreateRequest};
use nt_process::native_handle::NativeHandleCaller;

use crate::exec_handler::section_create::ReservedGenericDataSection;
use crate::ExecNtHandler;

pub(crate) const OP_CREATE: u64 = 1;
pub(crate) const OP_PUBLISH: u64 = 2;
pub(crate) const OP_ABORT: u64 = 3;
pub(crate) const OP_ACK: u64 = 4;

const STATUS_INVALID_HANDLE: u32 = nt_process::STATUS_INVALID_HANDLE;
const STATUS_INVALID_PARAMETER: u32 = nt_process::STATUS_INVALID_PARAMETER;
const STATUS_INSUFFICIENT_RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const SEC_IMAGE: u32 = 0x0100_0000;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Owner {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    token: u64,
}

enum Phase {
    Creating,
    CancelledCreating,
    Reserved(ReservedGenericDataSection),
    Publishing,
    Aborted,
    PublishedUnacknowledged,
    EffectUncertain,
}

struct Pending {
    owner: Owner,
    handle: u64,
    phase: Phase,
}

static mut PENDING: Vec<Pending> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

unsafe fn position(owner: Owner, handle: u64) -> Option<usize> {
    (&*core::ptr::addr_of!(PENDING))
        .iter()
        .position(|entry| entry.owner == owner && entry.handle == handle)
}

unsafe fn create(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    packet: u64,
    length: u64,
) -> Result<(u64, u64), u32> {
    if length != wire::PACKET_BYTES as u64 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_, bytes) =
        crate::win32k_subsystem::capture_provider_pool_packet(packet, wire::PACKET_BYTES)?;
    let SectionCreateRequest {
        desired_access,
        object_attributes,
        maximum_size,
        page_protection,
        allocation_attributes,
        file_handle,
    } = wire::decode(&bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if allocation_attributes & SEC_IMAGE != 0 {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let owner_pi = handler.native_section_owner_pi(caller)?;
    let token = NEXT_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let owner = Owner {
        route,
        dispatch,
        caller,
        token,
    };
    {
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        pending
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        pending.push(Pending {
            owner,
            handle: 0,
            phase: Phase::Creating,
        });
    }
    let result = handler.reserve_generic_data_section(
        caller,
        owner_pi,
        desired_access,
        object_attributes.unwrap_or(0),
        maximum_size.unwrap_or(0),
        page_protection,
        allocation_attributes,
        file_handle,
    );
    match result {
        Ok(mut reserved) => {
            let handle = reserved.value();
            let Some(index) = position(owner, 0) else {
                reserved.abort(handler);
                return Err(STATUS_INVALID_HANDLE);
            };
            let mut reserved = Some(reserved);
            let active = {
                let pending = &mut *core::ptr::addr_of_mut!(PENDING);
                if matches!(pending[index].phase, Phase::Creating) {
                    pending[index].handle = handle;
                    pending[index].phase = Phase::Reserved(reserved.take().unwrap());
                    true
                } else {
                    pending.swap_remove(index);
                    false
                }
            };
            if !active {
                let mut reserved = reserved.unwrap();
                reserved.abort(handler);
                return Err(STATUS_INVALID_HANDLE);
            }
            Ok((token, handle))
        }
        Err(status) => {
            if let Some(index) = position(owner, 0) {
                (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
            }
            Err(status)
        }
    }
}

unsafe fn publish(handler: &mut ExecNtHandler, owner: Owner, handle: u64) -> Result<(), u32> {
    let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
    let mut reserved = {
        let pending = &mut *core::ptr::addr_of_mut!(PENDING);
        if !matches!(pending[index].phase, Phase::Reserved(_)) {
            return Err(STATUS_INVALID_HANDLE);
        }
        let Phase::Reserved(reserved) =
            core::mem::replace(&mut pending[index].phase, Phase::Publishing)
        else {
            unreachable!()
        };
        reserved
    };
    match reserved.publish(handler) {
        Ok(value) => {
            assert_eq!(
                value, handle,
                "Section publication changed its reserved handle"
            );
            let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
            (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::PublishedUnacknowledged;
            Ok(())
        }
        Err(status) => {
            reserved.abort(handler);
            let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
            (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::Aborted;
            Err(status)
        }
    }
}

unsafe fn abort(handler: &mut ExecNtHandler, owner: Owner, handle: u64) -> Result<(), u32> {
    let index = position(owner, handle).ok_or(STATUS_INVALID_HANDLE)?;
    if !matches!(
        (&*core::ptr::addr_of!(PENDING))[index].phase,
        Phase::Reserved(_) | Phase::Aborted
    ) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let pending = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
    if let Phase::Reserved(mut reserved) = pending.phase {
        reserved.abort(handler);
    }
    Ok(())
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
    let result = match op {
        OP_CREATE if third == 0 => create(handler, route, dispatch, caller, first, second),
        OP_PUBLISH | OP_ABORT | OP_ACK if third == 0 && first != 0 && second != 0 => {
            let owner = Owner {
                route,
                dispatch,
                caller,
                token: first,
            };
            match op {
                OP_PUBLISH => publish(handler, owner, second).map(|()| (0, 0)),
                OP_ABORT => abort(handler, owner, second).map(|()| (0, 0)),
                OP_ACK => {
                    let index = match position(owner, second) {
                        Some(index) => index,
                        None => return (STATUS_INVALID_HANDLE as i32, 0, 0, 0),
                    };
                    if !matches!(
                        (&*core::ptr::addr_of!(PENDING))[index].phase,
                        Phase::PublishedUnacknowledged
                    ) {
                        Err(STATUS_INVALID_HANDLE)
                    } else {
                        (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                        Ok((0, 0))
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    };
    match result {
        Ok((first, second)) => (0, first, second, 0),
        Err(status) => (status as i32, 0, 0, 0),
    }
}

/// Called after exact physical dispatch retirement, not merely after a Reply is sent.
pub(crate) unsafe fn retire_completed(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
) {
    let mut index = 0;
    while index < (&*core::ptr::addr_of!(PENDING)).len() {
        let owner = (&*core::ptr::addr_of!(PENDING))[index].owner;
        if owner.route != route || owner.dispatch != dispatch {
            index += 1;
            continue;
        }
        let phase = match (&*core::ptr::addr_of!(PENDING))[index].phase {
            Phase::Creating => 0,
            Phase::Reserved(_) => 1,
            Phase::Aborted => 2,
            Phase::Publishing => 3,
            Phase::PublishedUnacknowledged => 4,
            Phase::CancelledCreating => 5,
            Phase::EffectUncertain => 6,
        };
        match phase {
            0 => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::CancelledCreating;
                index += 1;
            }
            1 | 2 => {
                let entry = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                if let Phase::Reserved(mut reserved) = entry.phase {
                    reserved.abort(handler);
                }
            }
            3 | 4 => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::EffectUncertain;
                index += 1;
            }
            _ => index += 1,
        }
    }
}
