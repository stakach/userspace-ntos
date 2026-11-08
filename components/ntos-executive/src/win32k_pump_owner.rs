//! Durable owner of a native win32k pump from entry through returned handoff.
//!
//! The table guard covers only pure row operations. Physical queries and the pump run outside
//! it. A ticket selects storage; the row retains the pending metadata, channel, and returned
//! result until an exact downstream owner acknowledges transfer.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_user_host::retained_owner_table::{
    RetainedOwnerError, RetainedOwnerFinishError, RetainedOwnerTable, RetainedOwnerTicket,
    RetainedOwnerTransitionError,
};
use nt_user_host::returned_pump_owner::{
    ReturnedPumpError, ReturnedPumpKey, ReturnedPumpObservation, ReturnedPumpOwner,
    ReturnedPumpPhase,
};

use crate::spawn_hosts::{PumpChannel, PumpResult};
use crate::win32k_glue::Win32kClientContext;

#[derive(Clone, Copy)]
pub(crate) struct PumpContext {
    pub channel: PumpChannel,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
}

#[derive(Clone, Copy)]
pub(crate) struct PumpContinuation {
    context: PumpContext,
    displaced_parent: Option<crate::nested_restore_owner::NestedRestoreOwnerTicket>,
}

impl PumpContinuation {
    pub(crate) const fn context(self) -> PumpContext { self.context }
}

pub(crate) type PumpOwner = ReturnedPumpOwner<PumpContinuation, PumpResult>;
pub(crate) type PumpTicket = RetainedOwnerTicket<ReturnedPumpKey>;

/// A source Work item retains this move-only bundle on every uncertain physical return.
/// The Ticket variant selects the canonical returned row; the offered variant covers an
/// explicit table refusal without dropping its PumpResult. PreEntry covers a fenced lane
/// whose shared page or displaced parent changed before pump entry.
pub(crate) enum SourcePumpRetained {
    Ticket(PumpTicket),
    Offered {
        context: PumpContext,
        displaced_parent: Option<crate::nested_restore_owner::NestedRestoreOwnerTicket>,
        pump: PumpResult,
        current_reply: u64,
    },
    PreEntry {
        context: PumpContext,
        displaced_parent: Option<crate::nested_restore_owner::NestedRestoreOwnerTicket>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BeginError {
    PhysicalIdentity,
    Exhausted,
    Storage(RetainedOwnerError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReturnError {
    StaleTicket,
    Refused(ReturnedPumpError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReturnDisposition {
    Returned,
    Quarantined(ReturnedPumpError),
}

static BUSY: AtomicBool = AtomicBool::new(false);
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);
static mut OWNERS: RetainedOwnerTable<ReturnedPumpKey, PumpOwner> =
    RetainedOwnerTable::new();

struct Guard;

impl Guard {
    fn acquire() -> Self {
        while BUSY.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

fn with_owners<R>(f: impl FnOnce(&mut RetainedOwnerTable<ReturnedPumpKey, PumpOwner>) -> R) -> R {
    let _guard = Guard::acquire();
    // The guard serializes this short transition. No table reference escapes the closure.
    f(unsafe { &mut *core::ptr::addr_of_mut!(OWNERS) })
}

/// Retain the source Work's exact physical continuation before entering its pump.
pub(crate) unsafe fn begin_source_terminal(
    context: PumpContext,
    displaced_parent: Option<crate::nested_restore_owner::NestedRestoreOwnerTicket>,
) -> Result<PumpTicket, BeginError> {
    let continuation = PumpContinuation { context, displaced_parent };
    let context = continuation.context();
    if !crate::win32k_glue::win32k_client_context_is_admitted(context.client)
        || context.channel.client_pi != context.client.pi as u64
        || context.channel.client_generation != context.client.generation
    {
        return Err(BeginError::PhysicalIdentity);
    }
    let route = crate::spawn_hosts::shared_ingress::owner::runtime::channel_route(&context.channel)
        .map_err(|_| BeginError::PhysicalIdentity)?
        .ok_or(BeginError::PhysicalIdentity)?;
    let dispatch = crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(route)
        .map_err(|_| BeginError::PhysicalIdentity)?;
    let reply = crate::spawn_hosts::shared_ingress::owner::runtime::current_reply(route)
        .map_err(|_| BeginError::PhysicalIdentity)?;
    let attempt = NEXT_ATTEMPT.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |value| value.checked_add(1)).map_err(|_| BeginError::Exhausted)?;
    let key = ReturnedPumpKey::new(
        route, dispatch, context.dispatch,
        crate::win32k_glue::shared_page_client_identity(context.client), reply, attempt,
    ).ok_or(BeginError::PhysicalIdentity)?;
    with_owners(|owners| {
        let reservation = owners.reserve().map_err(BeginError::Storage)?;
        let owner = PumpOwner::active(key, continuation);
        // Reservation and retention run in the same guard; this reservation cannot become stale.
        owners.retain(reservation, key, owner)
            .map_err(|(error, _owner)| BeginError::Storage(error))
    })
}

/// Move the returned result into the same row immediately after native pump return.
/// A missing/duplicate row returns the offered result to the caller for durable quarantine.
pub(crate) unsafe fn record_return(
    ticket: PumpTicket,
    pump: PumpResult,
) -> Result<ReturnDisposition, (ReturnError, PumpResult)> {
    let Some(continuation) = with_owners(|owners| owners.get(ticket).map(|owner| *owner.continuation()))
    else { return Err((ReturnError::StaleTicket, pump)); };
    let context = continuation.context();
    let key = ticket.key();
    let observation = crate::spawn_hosts::shared_ingress::owner::runtime::channel_route(&context.channel)
        .ok().flatten().and_then(|route| {
            let dispatch = crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(route).ok()?;
            let reply = crate::spawn_hosts::shared_ingress::owner::runtime::current_reply(route).ok()?;
            let observed = ReturnedPumpKey::new(
                route, dispatch, context.dispatch,
                crate::win32k_glue::shared_page_client_identity(context.client),
                key.initial_reply(), key.attempt(),
            )?;
            Some((observed, reply))
        });
    // A failed physical query is an uncertain return. Reply zero forces quarantine while
    // preserving the returned pump and both observed Reply numbers in the same row.
    let (observed, current_reply) = observation.unwrap_or((key, 0));
    let pump_reply = pump.reply_cap;
    with_owners(|owners| {
        let mut result = ReturnDisposition::Returned;
        let transitioned = owners.transition_held(ticket, |mut owner| {
            match owner.record_return(observed, current_reply, pump_reply, pump) {
                ReturnedPumpObservation::Accepted => Ok(owner),
                ReturnedPumpObservation::Quarantined(error) => {
                    result = ReturnDisposition::Quarantined(error);
                    Ok(owner)
                }
                ReturnedPumpObservation::Refused(error, offered) => Err(((error, offered), owner)),
            }
        });
        match transitioned {
            Ok(()) => Ok(result),
            Err(RetainedOwnerTransitionError::Refused((error, offered))) =>
                Err((ReturnError::Refused(error), offered)),
            Err(RetainedOwnerTransitionError::StaleTicket) => Err((ReturnError::StaleTicket, pump)),
        }
    })
}

/// An uncertain downstream capture leaves the returned pump in this exact quarantined row.
pub(crate) fn quarantine_capture(
    ticket: PumpTicket,
) -> Result<(), RetainedOwnerTransitionError<ReturnedPumpError>> {
    with_owners(|owners| owners.transition_held(ticket, |mut owner| {
        match owner.quarantine_capture() {
            Ok(()) => Ok(owner),
            Err(error) => Err((error, owner)),
        }
    }))
}

/// Source terminal transport may retire the lane only after a certified terminal pump.
/// A callback or wait yield is an uncertain source effect and remains in this row.
pub(crate) fn classify_source_terminal(
    ticket: PumpTicket,
) -> Result<(), RetainedOwnerTransitionError<ReturnedPumpError>> {
    with_owners(|owners| owners.transition_held(ticket, |mut owner| {
        let classified = owner.capture_or_quarantine(|_, pump| {
            (pump.completed
                && !pump.callback_suspended && !pump.provider_wait_suspended
                && !pump.lpc_wait_suspended && pump.receive_yield.is_none()
                && pump.root_ingress_yield.is_none() && pump.service_wait_yield.is_none()
                && pump.maintenance_yield.is_none() && pump.nested_restore_yield.is_none()
                && pump.nested_restore_quarantined.is_none()).then_some(())
        });
        match classified {
            Ok(()) => Ok(owner),
            Err(error) => Err((error, owner)),
        }
    }))
}

/// Checkout only a classified returned owner for exact downstream transfer.
pub(crate) fn take_returned(ticket: PumpTicket) -> Option<PumpOwner> {
    with_owners(|owners| {
        if owners.get(ticket)?.phase() != ReturnedPumpPhase::Returned { return None; }
        owners.take(ticket)
    })
}

pub(crate) fn restore(ticket: PumpTicket, owner: PumpOwner)
    -> Result<(), PumpOwner>
{
    with_owners(|owners| owners.restore(ticket, owner))
}

pub(crate) fn finish_taken(ticket: PumpTicket) -> Result<(), RetainedOwnerFinishError> {
    with_owners(|owners| owners.finish_taken(ticket))
}

/// The Work owner has accepted a completed source return and the physical lane has finished.
/// Only then may the exact returned row be retired.
pub(crate) fn acknowledge_terminal(ticket: PumpTicket) -> bool {
    let Some(owner) = take_returned(ticket) else { return false; };
    if owner.key() != ticket.key() || owner.phase() != ReturnedPumpPhase::Returned {
        let _ = restore(ticket, owner);
        return false;
    }
    match finish_taken(ticket) {
        Ok(()) => true,
        Err(_) => {
            let _ = restore(ticket, owner);
            false
        }
    }
}
