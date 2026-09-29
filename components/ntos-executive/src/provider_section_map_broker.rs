//! Dispatch-bound ownership of win32k native Section view maps.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_component_suspension::{peer_registry::PeerRoute, LaneDispatchIdentity};
use nt_io_manager::win32k_section_map_wire::{self as wire, SectionMapRequest};
use nt_memory_manager::GenericSectionView;
use nt_process::native_handle::NativeHandleCaller;

use crate::ExecNtHandler;

pub(crate) const OP_MAP: u64 = 1;
pub(crate) const OP_PUBLISH: u64 = 2;
pub(crate) const OP_ABORT: u64 = 3;
pub(crate) const OP_ACK: u64 = 4;

const STATUS_INVALID_HANDLE: u32 = nt_process::STATUS_INVALID_HANDLE;
const STATUS_INVALID_PARAMETER: u32 = nt_process::STATUS_INVALID_PARAMETER;
const STATUS_INSUFFICIENT_RESOURCES: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Owner {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    token: u64,
}

#[derive(Clone, Copy)]
enum Phase {
    Mapping,
    CancelledMapping,
    Mapped(GenericSectionView),
    PublishedUnacknowledged(GenericSectionView),
    EffectUncertain(GenericSectionView),
}

struct Pending {
    owner: Owner,
    base: u64,
    phase: Phase,
}

static mut PENDING: Vec<Pending> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

unsafe fn position(owner: Owner, base: u64) -> Option<usize> {
    (&*core::ptr::addr_of!(PENDING))
        .iter()
        .position(|entry| entry.owner == owner && entry.base == base)
}

unsafe fn decode_request(packet: u64, length: u64) -> Result<SectionMapRequest, u32> {
    if length != wire::PACKET_BYTES as u64 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let (_, bytes) =
        crate::win32k_subsystem::capture_provider_pool_packet(packet, wire::PACKET_BYTES)?;
    let request = wire::decode(&bytes).map_err(|_| STATUS_INVALID_PARAMETER)?;
    if !request.is_supported_provider_shape() {
        return Err(STATUS_NOT_SUPPORTED);
    }
    Ok(request)
}

unsafe fn map(
    handler: &mut ExecNtHandler,
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    caller: NativeHandleCaller,
    request: SectionMapRequest,
) -> Result<(u64, u64, u64), u32> {
    let token = NEXT_TOKEN
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
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
            base: 0,
            phase: Phase::Mapping,
        });
    }

    match handler.map_provider_section_view(caller, request) {
        Ok(view) => {
            let Some(index) = position(owner, 0) else {
                handler.rollback_or_defer_generic_section_view(view);
                return Err(STATUS_INVALID_HANDLE);
            };
            let cancelled = {
                let pending = &mut *core::ptr::addr_of_mut!(PENDING);
                if matches!(&pending[index].phase, Phase::CancelledMapping) {
                    pending.swap_remove(index);
                    true
                } else {
                    false
                }
            };
            if cancelled {
                handler.rollback_or_defer_generic_section_view(view);
                return Err(STATUS_INVALID_HANDLE);
            }
            if !matches!(
                (&*core::ptr::addr_of!(PENDING))[index].phase,
                Phase::Mapping
            ) {
                handler.rollback_or_defer_generic_section_view(view);
                return Err(STATUS_INVALID_HANDLE);
            }
            let pending = &mut *core::ptr::addr_of_mut!(PENDING);
            pending[index].base = view.base;
            pending[index].phase = Phase::Mapped(view);
            Ok((token, view.base, view.size))
        }
        Err(status) => {
            if let Some(index) = position(owner, 0) {
                (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
            }
            Err(status)
        }
    }
}

fn result_words(result: Result<(u64, u64, u64), u32>) -> (i32, u64, u64, u64) {
    match result {
        Ok((first, second, third)) => (0, first, second, third),
        Err(status) => (status as i32, 0, 0, 0),
    }
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
        OP_MAP if third == 0 => decode_request(first, second)
            .and_then(|request| map(handler, route, dispatch, caller, request)),
        OP_PUBLISH | OP_ABORT | OP_ACK if third == 0 && first != 0 && second != 0 => {
            let owner = Owner {
                route,
                dispatch,
                caller,
                token: first,
            };
            let Some(index) = position(owner, second) else {
                return (STATUS_INVALID_HANDLE as i32, 0, 0, 0);
            };
            match op {
                OP_PUBLISH
                    if matches!(
                        (&*core::ptr::addr_of!(PENDING))[index].phase,
                        Phase::Mapped(_)
                    ) =>
                {
                    let pending = &mut *core::ptr::addr_of_mut!(PENDING);
                    let Phase::Mapped(view) = pending[index].phase else {
                        unreachable!()
                    };
                    pending[index].phase = Phase::PublishedUnacknowledged(view);
                    Ok((0, 0, 0))
                }
                OP_ABORT
                    if matches!(
                        (&*core::ptr::addr_of!(PENDING))[index].phase,
                        Phase::Mapped(_)
                    ) =>
                {
                    let entry = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                    if let Phase::Mapped(view) = entry.phase {
                        handler.rollback_or_defer_generic_section_view(view);
                    }
                    Ok((0, 0, 0))
                }
                OP_ACK
                    if matches!(
                        (&*core::ptr::addr_of!(PENDING))[index].phase,
                        Phase::PublishedUnacknowledged(_)
                    ) =>
                {
                    (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                    Ok((0, 0, 0))
                }
                _ => Err(STATUS_INVALID_HANDLE),
            }
        }
        _ => Err(STATUS_INVALID_PARAMETER),
    };
    result_words(result)
}

/// Only exact physical dispatch retirement can settle an unpublished map.
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
        let phase = (&*core::ptr::addr_of!(PENDING))[index].phase;
        match phase {
            Phase::Mapping => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::CancelledMapping;
                index += 1;
            }
            Phase::Mapped(_) => {
                let entry = (&mut *core::ptr::addr_of_mut!(PENDING)).swap_remove(index);
                if let Phase::Mapped(view) = entry.phase {
                    handler.rollback_or_defer_generic_section_view(view);
                }
            }
            Phase::PublishedUnacknowledged(view) => {
                (&mut *core::ptr::addr_of_mut!(PENDING))[index].phase = Phase::EffectUncertain(view);
                index += 1;
            }
            Phase::CancelledMapping | Phase::EffectUncertain(_) => index += 1,
        }
    }
}
