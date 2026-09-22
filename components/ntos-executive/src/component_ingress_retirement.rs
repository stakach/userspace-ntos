//! Ordered native retirement; stopped transport is cancelled before aliases are destroyed.

use super::*;
use nt_component_suspension::{CancelledStoppedCall, PeerRetirementPhase, ReplyBindingObservation};

struct RetirementDrain {
    route: PeerRoute,
    calls: Vec<CancelledStoppedCall<ReceivedMessage>>,
    cancelled: bool,
    lane_released: bool,
    final_reply: Option<nt_component_suspension::ComponentIngress<ReceivedMessage>>,
    finished: bool,
}

// Payloads and spare Replies remain durable even if recycling or later alias removal fails.
static mut DRAINS: Vec<RetirementDrain> = Vec::new();

pub(super) fn failure(stage: &str, error: impl core::fmt::Debug) -> Error {
    struct Serial;
    impl core::fmt::Write for Serial {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            crate::print_str(text.as_bytes());
            Ok(())
        }
    }
    let _ = core::fmt::write(
        &mut Serial,
        format_args!("[shared-ingress-retire] {stage}: {error:?}\n"),
    );
    Error::Retirement
}

unsafe fn native_drained(route: PeerRoute) -> bool {
    if resolve(route, true) != Some(route.identity().executor) {
        return false;
    }
    let canonical = &*core::ptr::addr_of!(COMPONENT_SUSPENSIONS);
    let Ok(binding) = canonical.binding(route.identity().lane) else {
        return false;
    };
    crate::spawn_hosts::query_component_reply_binding(binding.executor_id, binding.reply_object)
        == Ok(ReplyBindingObservation::Free)
}

/// Retire only this exact physical source. Frames, callbacks, waits and terminal ownership must
/// already have been discharged by their owners; a stopped executor cannot erase NT obligations.
pub(crate) unsafe fn retire(route: PeerRoute) -> Result<(), Error> {
    // A finished receipt outlives both its physical owner and its reusable installation slot.
    if (&*core::ptr::addr_of!(DRAINS))
        .iter()
        .any(|drain| drain.route == route && drain.finished)
    {
        return Ok(());
    }
    let index = (&*core::ptr::addr_of!(NATIVE_PEERS))
        .iter()
        .position(|row| row.route == Some(route))
        .ok_or(Error::UnknownPeer)?;
    let installation_index = owner()
        .installations
        .iter()
        .position(|installation| installation.route() == route)
        .ok_or(Error::UnknownPeer)?;
    if resolve(route, true).is_none() {
        return Err(Error::PhysicalIdentity);
    }
    let drains = &mut *core::ptr::addr_of_mut!(DRAINS);
    let drain_index = match drains.iter().position(|drain| drain.route == route) {
        Some(index) => index,
        None => {
            let _durable = crate::allocator::enter_durable();
            drains.try_reserve(1).map_err(|_| Error::Capacity)?;
            drains.push(RetirementDrain {
                route,
                calls: Vec::new(),
                cancelled: false,
                lane_released: false,
                final_reply: None,
                finished: false,
            });
            drains.len() - 1
        }
    };
    if !(&*core::ptr::addr_of!(NATIVE_PEERS))[index].quarantined {
        quarantine(route)?;
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    loop {
        let owner = owner();
        let phase = owner.installations[installation_index].phase();
        match phase {
            PeerInstallationPhase::Retiring(PeerRetirementPhase::Stopped) => {
                if owner.pending_reply.is_some() {
                    owner
                        .recycle_pending_reply(lanes(), route.identity().executor)
                        .map_err(|_| failure("pending-reply", "pool admission refused"))?;
                }
                let drain = &mut (&mut *core::ptr::addr_of_mut!(DRAINS))[drain_index];
                if !drain.cancelled {
                    let _durable = crate::allocator::enter_durable();
                    owner
                        .receiver
                        .as_mut()
                        .ok_or(Error::Initialization)?
                        .cancel_stopped_route(
                            &owner.installations[installation_index],
                            lanes(),
                            owner.peers.as_mut().ok_or(Error::Initialization)?,
                            &mut drain.calls,
                            |tcb, reply| {
                                crate::spawn_hosts::query_component_reply_binding(tcb, reply)
                            },
                        )
                        .map_err(|error| failure("cancel-calls", error))?;
                    drain.cancelled = true;
                }
                for call in &mut drain.calls {
                    if call.reply.is_none() {
                        continue;
                    }
                    owner
                        .replacements
                        .as_mut()
                        .ok_or(Error::Initialization)?
                        .insert_pending(
                            &mut call.reply,
                            owner.receiver.as_ref().ok_or(Error::Initialization)?,
                            lanes(),
                            |reply| {
                                crate::spawn_hosts::query_component_reply_binding(
                                    route.identity().executor,
                                    reply,
                                )
                            },
                        )
                        .map_err(|_| Error::Reply)?;
                }
                owner.installations[installation_index]
                    .prove_retirement_drain(
                        owner.peers.as_ref().ok_or(Error::Initialization)?,
                        lanes(),
                        |candidate| Ok::<_, ()>(native_drained(candidate)),
                    )
                    .map_err(|error| failure("prove-drain", error))?;
            }
            PeerInstallationPhase::Retiring(
                PeerRetirementPhase::Drained
                | PeerRetirementPhase::FaultCleared
                | PeerRetirementPhase::ChildDeleted,
            ) => {
                owner.installations[installation_index]
                    .retire_effect(
                        owner.peers.as_ref().ok_or(Error::Initialization)?,
                        lanes(),
                        |effect| {
                            let status = match effect {
                                PeerRetirementEffect::ClearFaultHandler(binding) => {
                                    crate::tcb_set_space_r(
                                        binding.executor,
                                        0,
                                        binding.cnode,
                                        binding.vspace,
                                    )
                                }
                                PeerRetirementEffect::DeleteChildAlias(destination) => {
                                    crate::cnode_delete_in_cnode_r(
                                        destination.cnode,
                                        destination.slot,
                                    )
                                }
                                PeerRetirementEffect::DeleteRootAlias(slot) => {
                                    crate::cnode_delete_recycle_r(slot)
                                }
                                PeerRetirementEffect::StopExecutor(_) => return Err(u64::MAX),
                            };
                            if status == 0 {
                                Ok(())
                            } else {
                                Err(status)
                            }
                        },
                    )
                    .map_err(|error| failure("retire-alias", error))?;
            }
            PeerInstallationPhase::Retiring(PeerRetirementPhase::RootDeleted) => {
                owner.installations[installation_index]
                    .finish_retirement(
                        owner.peers.as_mut().ok_or(Error::Initialization)?,
                        lanes(),
                        |candidate| Ok::<_, ()>(native_drained(candidate)),
                    )
                    .map_err(|error| failure("finish-peer", error))?;
            }
            PeerInstallationPhase::Retired => {
                let drain = &mut (&mut *core::ptr::addr_of_mut!(DRAINS))[drain_index];
                if !drain.lane_released {
                    let binding = lanes()
                        .binding(route.identity().lane)
                        .map_err(|_| Error::Retirement)?;
                    let pending = nt_component_suspension::ComponentIngress::new(
                        route.endpoint(),
                        binding.reply_object,
                    )
                    .map_err(|_| Error::Reply)?;
                    lanes()
                        .release(route.identity().lane, binding.reply_object)
                        .map_err(|error| failure("release-lane", error))?;
                    drain.final_reply = Some(pending);
                    drain.lane_released = true;
                }
                if drain.final_reply.is_some() {
                    owner
                        .replacements
                        .as_mut()
                        .ok_or(Error::Initialization)?
                        .insert_pending(
                            &mut drain.final_reply,
                            owner.receiver.as_ref().ok_or(Error::Initialization)?,
                            lanes(),
                            |reply| {
                                crate::spawn_hosts::query_component_reply_binding(
                                    route.identity().executor,
                                    reply,
                                )
                            },
                        )
                        .map_err(|_| Error::Reply)?;
                }
                let row = &(&*core::ptr::addr_of!(NATIVE_PEERS))[index];
                (&mut *core::ptr::addr_of_mut!(SOURCES))
                    .finish_retirement(row.source, |physical| {
                        physical == row.physical && (row.verify)(physical)
                    })
                    .map_err(|error| failure("finish-source", error))?;
                (&mut *core::ptr::addr_of_mut!(DRAINS))[drain_index].finished = true;
                // Only the final receipt releases bounded installation capacity. Retired alone
                // is insufficient: lane release, Reply return or source retirement may still fail.
                // Fresh routes and source tombstones remain in their independent durable owners.
                let _retired = owner.installations.swap_remove(installation_index);
                // Only confirmed physical retirement permits reclaiming invisible publications.
                // Published handles have already left this dispatch journal, even if ACK was lost.
                let _ = owner;
                crate::driver_launch::driver_registry_handles::retire_confirmed_dispatches(route);
                return Ok(());
            }
            // Entered uncertain effects are deliberately not replayed.
            _ => return Err(Error::Retirement),
        }
    }
}
