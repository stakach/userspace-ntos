use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_process::native_handle::NativeThreadProcessReference;

struct Work {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    actor: NativeThreadProcessReference,
    ticket: Option<nt_pnp_manager::SyncDeviceRelationTicket>,
    terminal: Option<nt_status::NtStatus>,
    admitting: bool,
    reply_entered: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    mi: u64,
    device_object: u64,
    relation_type: u64,
    reserved: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    if mi != ((crate::win32k_subsystem::W32_REGISTRY_LABEL << 12) | 4)
        || reply_cap != channel.reply_cap
        || reserved != 0
    {
        return Some(nt_status::NtStatus::INVALID_PARAMETER.raw());
    }
    let Ok(relation_type) = u32::try_from(relation_type) else {
        return Some(nt_status::NtStatus::INVALID_PARAMETER.raw());
    };
    let access = match crate::win32k_device_consumer::authenticate(
        channel,
        reply_cap,
        device_object,
    ) {
        Ok(access) => access,
        Err(status) => return Some(status),
    };
    let parent = match access.require_pdo() {
        Ok(parent) => parent,
        Err(status) => return Some(status),
    };
    match relation_type {
        nt_pnp_abi::TARGET_DEVICE_RELATION => return Some(nt_status::NtStatus::SUCCESS.raw()),
        nt_pnp_abi::POWER_RELATIONS => return Some(nt_status::NtStatus::NOT_IMPLEMENTED.raw()),
        nt_pnp_abi::BUS_RELATIONS => {}
        _ => return Some(nt_status::NtStatus::NOT_SUPPORTED.raw()),
    }
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(status as i32),
    };
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return Some(nt_status::NtStatus::INVALID_HANDLE.raw()),
    };
    let (dispatch, reply) = match (runtime::dispatch(route), runtime::current_reply(route)) {
        (Ok(dispatch), Ok(reply)) if dispatch == access.dispatch() => (dispatch, reply),
        _ => return Some(nt_status::NtStatus::INVALID_HANDLE.raw()),
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => return Some(status as i32),
    };
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index))
                .then_some(index)
        });
    if (slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err())
        || (&mut *core::ptr::addr_of_mut!(EXECUTING)).try_reserve(1).is_err()
    {
        release_actor(actor);
        return Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw());
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        value.checked_add(1)
    }) {
        Ok(token) if token != 0 => token,
        _ => {
            release_actor(actor);
            return Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw());
        }
    };
    let work = Work {
        route,
        dispatch,
        reply,
        token,
        actor,
        ticket: None,
        terminal: None,
        admitting: true,
        reply_entered: false,
    };
    let index = if let Some(index) = slot {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        index
    } else {
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        rows.push(Some(work));
        rows.len() - 1
    };
    if runtime::park_retained_service(route, token).is_err() {
        let work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked synchronous relation owner");
        release_actor(work.actor);
        return Some(nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw());
    }

    let endpoint = nt_pnp::AcpiPciProviderEndpoint {
        device_id: access.device().raw(),
        hosted_domain_id: access.domain().domain_id.raw(),
        hosted_domain_cookie: access.domain().cookie,
        pdo_object: access.address(),
    };
    let work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
        .as_mut()
        .expect("parked synchronous relation owner");
    match enqueue_hosted_sync_device_relations(endpoint, parent) {
        Ok(ticket) => work.ticket = Some(ticket),
        Err(status) => work.terminal = Some(status),
    }
    work.admitting = false;
    None
}

unsafe fn release_actor(mut actor: NativeThreadProcessReference) {
    crate::service_sec_image::with_provider_process_manager(|pm| {
        actor.release(pm)?;
        Ok(())
    })
    .expect("synchronous relation actor release");
}

impl Work {
    unsafe fn advance(&mut self) -> bool {
        if self.terminal.is_none() {
            let ticket = self.ticket.expect("pending synchronous relation ticket");
            match hosted_device_relation_invalidations_mut().sync_status(ticket) {
                Ok(Some(_)) => {
                    self.terminal = Some(
                        hosted_device_relation_invalidations_mut()
                            .take_sync_status(ticket)
                            .expect("terminal synchronous relation ticket"),
                    );
                    self.ticket = None;
                }
                Ok(None) => return false,
                Err(_) => panic!("synchronous relation lost its exact ticket"),
            }
        }
        if self.reply_entered {
            if !runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("synchronous relation Reply identity")
            {
                return false;
            }
        } else if runtime::retained_service_cancelled(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        ) {
            runtime::acknowledge_retained_service_cancellation(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("cancelled synchronous relation owner");
            return true;
        } else {
            self.reply_entered = true;
            let _ = runtime::wake_registry_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
                self.terminal.expect("terminal synchronous relation status").raw(),
                0,
                0,
            );
            if !runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("synchronous relation Reply identity")
            {
                return false;
            }
        }
        runtime::retire_stopped_acknowledged_retained_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("synchronous relation Reply retirement");
        true
    }
}

pub(crate) unsafe fn drain() -> usize {
    let mut progress = 0usize;
    let mut index = 0usize;
    while index < (&*core::ptr::addr_of!(WORK)).len() {
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index)
            || (&*core::ptr::addr_of!(WORK))[index]
                .as_ref()
                .is_some_and(|work| work.admitting)
        {
            index += 1;
            continue;
        }
        let Some(mut work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].take() else {
            index += 1;
            continue;
        };
        if (&mut *core::ptr::addr_of_mut!(EXECUTING))
            .try_reserve(1)
            .is_err()
        {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
            return progress;
        }
        (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
        let finished = work.advance();
        (&mut *core::ptr::addr_of_mut!(EXECUTING)).pop();
        if finished {
            release_actor(work.actor);
            progress = progress.saturating_add(1);
        } else {
            (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        }
        index += 1;
    }
    progress
}
