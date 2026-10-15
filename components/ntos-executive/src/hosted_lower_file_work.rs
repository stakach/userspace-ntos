//! Retained lower File lifecycle work for an already dispatched upper File IRP.
//!
//! The source packet belongs to the forwarding driver. A separate canonical
//! subsidiary IRP belongs to the lower provider; neither numeric IRP address
//! authorizes the other. Both remain owned through native completion and ACK.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::retained_file_lifecycle_forward::{
    FileLifecycleDispatchReturn, FileLifecycleForwardIdentity, FileLifecycleForwardPhase,
};
use nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity;
use nt_io_manager::CompletionAcknowledgement;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const STATUS_INVALID_HANDLE_LOCAL: i32 = nt_status::NtStatus::INVALID_HANDLE.raw();
const STATUS_INVALID_DEVICE_REQUEST_LOCAL: i32 = nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw();
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: i32 = nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw();
const STATUS_DEVICE_BUSY_LOCAL: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();

struct RetainedAck {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    reply_entered: bool,
}

struct Work {
    source: hosted_lower_file_capture::CapturedLowerFileLifecycle,
    source_instance: DriverInstance,
    provider_instance: DriverInstance,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    origin: hosted_forward_origin::HostedForwardOrigin,
    outer_irp: IrpId,
    subsidiary_irp: Option<IrpId>,
    forward: Option<nt_io_manager::retained_file_lifecycle_forward::RetainedFileLifecycleForward>,
    file_reference: Option<nt_io_manager::FileReference>,
    initial_status: Option<i32>,
    source_published: bool,
    source_released: bool,
    provider_acknowledged: bool,
    /// The exact subsidiary is retired. Only fallible source/actor retirement remains;
    /// its release mode must not change if the source stops during a retry.
    post_retirement_pending_terminal: Option<bool>,
    ack: Option<RetainedAck>,
    cancel_requested: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<(usize, DriverInstance, SourceIrpForwardIdentity, bool)> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn status_for_capture(error: hosted_lower_file_capture::CaptureError) -> i32 {
    use hosted_lower_file_capture::CaptureError;
    match error {
        CaptureError::InvalidCaller
        | CaptureError::InvalidSourceIrp
        | CaptureError::InvalidFile => STATUS_INVALID_HANDLE_LOCAL,
        CaptureError::InvalidTarget => STATUS_INVALID_DEVICE_REQUEST_LOCAL,
    }
}

fn source_work_index(
    source_instance: DriverInstance,
    incoming: SourceIrpForwardIdentity,
) -> Option<usize> {
    let active = unsafe { &*core::ptr::addr_of!(EXECUTING) }
        .iter()
        .find(|(_, instance, identity, pin_owned)| {
            instance.pml4 == source_instance.pml4
                && instance.hosted_domain_id == source_instance.hosted_domain_id
                && instance.hosted_domain_cookie == source_instance.hosted_domain_cookie
                && identity.duplicates_owned(incoming, *pin_owned)
        })
        .map(|(index, _, _, _)| *index);
    active.or_else(|| {
        unsafe { &*core::ptr::addr_of!(WORK) }
            .iter()
            .position(|slot| {
                slot.as_ref().is_some_and(|work| {
                    work.source_instance.pml4 == source_instance.pml4
                        && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                        && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                        && work.source_instance.hosted_domain_cookie
                            == source_instance.hosted_domain_cookie
                        && work
                            .source
                            .source_identity()
                            .duplicates_owned(incoming, !work.source_released)
                })
            })
    })
}

fn source_ack_work_index(
    source_instance: DriverInstance,
    source_irp_address: u64,
) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(WORK) }
        .iter()
        .position(|slot| {
            slot.as_ref().is_some_and(|work| {
                !work.source_released
                    && work.source_instance.pml4 == source_instance.pml4
                    && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                    && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                    && work.source_instance.hosted_domain_cookie
                        == source_instance.hosted_domain_cookie
                    && work.source.source_irp_address() == source_irp_address
                    && work.source.validate_source().is_ok()
            })
        })
}

unsafe fn reconcile_source_acks(route: nt_component_suspension::peer_registry::PeerRoute) -> bool {
    for row in &mut *core::ptr::addr_of_mut!(WORK) {
        let Some(work) = row.as_ref() else {
            continue;
        };
        let Some(ack) = work.ack.as_ref().filter(|ack| ack.route == route) else {
            continue;
        };
        if !work.source_released || work.actor.is_held() || !ack.reply_entered {
            return false;
        }
        if !matches!(
            runtime::reconcile_retained_service_reply(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            ),
            Ok(true)
        ) {
            return false;
        }
        if runtime::retire_stopped_acknowledged_retained_service(
            ack.route,
            ack.dispatch,
            ack.reply,
            ack.token,
        )
        .is_err()
        {
            return false;
        }
        *row = None;
    }
    true
}

/// An accepted source Call stays parked while the lower provider is pending.
pub(super) unsafe fn submit(
    ch: &crate::spawn_hosts::PumpChannel,
    source_irp_address: u64,
    lower_device_address: u64,
    caller_badge: u64,
    active_reply_cap: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, active_reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(route) = runtime::channel_route(ch).ok().flatten() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if !reconcile_source_acks(route) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let mut source = match hosted_lower_file_capture::capture(
        ch,
        active_reply_cap,
        source_irp_address,
        lower_device_address,
    ) {
        Ok(source) => source,
        Err(error) => return Some(status_for_capture(error)),
    };
    if source_work_index(source_instance, source.source_identity()).is_some() {
        source
            .release()
            .expect("duplicate lower File capture rollback");
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let outer_irp = match source.canonical_outer_irp() {
        Ok(outer_irp) => outer_irp,
        Err(error) => {
            source
                .release()
                .expect("unentered lower File outer IRP rollback");
            return Some(status_for_capture(error));
        }
    };
    let Some((target_index, _, _)) = hosted_driver_device_route_by_device_id(
        source.lower_device_registration().device_id().raw(),
    ) else {
        source
            .release()
            .expect("unentered lower File route rollback");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
        .map_or(target_index, |route| route.provider_instance);
    let Some(provider_instance) = instance(provider_index) else {
        source
            .release()
            .expect("unentered lower File provider rollback");
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    };
    let Ok(dispatch) = runtime::dispatch(route) else {
        source
            .release()
            .expect("unentered lower File dispatch rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(reply) = runtime::current_reply(route) else {
        source
            .release()
            .expect("unentered lower File Reply rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let Ok(caller) = crate::provider_registry_caller::resolve(ch) else {
        source
            .release()
            .expect("unentered lower File caller rollback");
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.reference_native_requestor(caller)
    }) {
        Ok(actor) => actor,
        Err(status) => {
            source
                .release()
                .expect("unentered lower File actor rollback");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none()
                && !(&*core::ptr::addr_of!(EXECUTING))
                    .iter()
                    .any(|(active, _, _, _)| *active == index))
            .then_some(index)
        });
    if slot.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err()
    {
        let mut actor = actor;
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered lower File actor release");
        source
            .release()
            .expect("unentered lower File allocation rollback");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered lower File actor release");
            source
                .release()
                .expect("unentered lower File token rollback");
            return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
        }
    };
    let work = Work {
        source,
        source_instance,
        provider_instance,
        caller,
        actor,
        origin: hosted_forward_origin::HostedForwardOrigin::new(route, dispatch, reply, token),
        outer_irp,
        subsidiary_irp: None,
        forward: None,
        file_reference: None,
        initial_status: None,
        source_published: false,
        source_released: false,
        provider_acknowledged: false,
        post_retirement_pending_terminal: None,
        ack: None,
        cancel_requested: false,
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
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked lower File owner");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked lower File actor");
        work.source.release().expect("unparked lower File source");
        return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    None
}

impl Work {
    unsafe fn actor_release(&mut self) -> Result<(), u32> {
        crate::service_sec_image::with_provider_process_manager(|pm| self.actor.release(pm))
    }

    unsafe fn provider_instance_if_exact(&self) -> Option<usize> {
        self.source.validate_source().ok()?;
        let lower = self.source.lower_device_registration();
        let (target_index, _, _) =
            hosted_driver_device_route_by_device_id(lower.device_id().raw())?;
        let provider_index = hosted_provider_dispatch_route_for_instance(target_index)
            .map_or(target_index, |route| route.provider_instance);
        instance(provider_index)
            .filter(|live| {
                live.pml4 == self.provider_instance.pml4
                    && live.exec_pool_va == self.provider_instance.exec_pool_va
                    && live.hosted_domain_id == self.provider_instance.hosted_domain_id
                    && live.hosted_domain_cookie == self.provider_instance.hosted_domain_cookie
                    && live.driver_id == self.provider_instance.driver_id
            })
            .map(|_| target_index)
    }

    unsafe fn provider_dispatch_ready(&self) -> bool {
        let Some(index) = self.provider_instance_if_exact() else {
            return true;
        };
        let Some(route) = hosted_ingress_sources::primary_route(index) else {
            return true;
        };
        !matches!(runtime::ready_for_admission(route), Ok(false))
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if self.post_retirement_pending_terminal.is_some() {
            return true;
        }
        if self.origin.inline_held() {
            return self.source_released
                || self.source.completion_finished()
                || self.origin.stopped();
        }
        if let Some(ack) = &self.ack {
            return !ack.reply_entered;
        }
        if self.origin.pending() {
            if self.origin.stopped() {
                return self.origin.may_discard();
            }
            if !self.origin.armed() {
                return false;
            }
            if self.origin.completed() {
                return true;
            }
            if self.origin.held() && self.source.completion_finished() {
                return true;
            }
            return self
                .source
                .completion_command(self.origin.token)
                .is_ok_and(|command| self.origin.terminal_ready(command))
                && self
                    .subsidiary_irp
                    .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some());
        }
        if self.origin.reply_entered {
            return false;
        }
        if self.initial_status.is_none() {
            return !self.origin.preparation_uncertain()
                && self.provider_dispatch_ready()
                && self
                    .source
                    .completion_command(self.origin.token)
                    .is_ok_and(|command| self.origin.terminal_ready(command));
        }
        self.forward.as_ref().is_some_and(|forward| matches!(forward.phase(),
            nt_io_manager::retained_file_lifecycle_forward::FileLifecycleForwardPhase::Terminal { .. }))
            || self.subsidiary_irp.is_some_and(|irp| completed_irp_exact(irp.raw()).is_some())
    }

    unsafe fn release_source(&mut self, pending_terminal: bool) -> bool {
        if self.source_released {
            return true;
        }
        if let Some(reference) = self.file_reference.as_mut() {
            if io_manager_mut().release_file_reference(reference).is_err() {
                return false;
            }
            self.file_reference = None;
        }
        let result = if pending_terminal {
            self.source.release_pending_terminal()
        } else {
            self.source.release()
        };
        if result.is_err() {
            return false;
        }
        self.source_released = true;
        let identity = self.source.source_identity();
        for (_, _, active, pin_owned) in &mut *core::ptr::addr_of_mut!(EXECUTING) {
            if *active == identity {
                *pin_owned = false;
            }
        }
        true
    }

    unsafe fn release_unentered_owners(&mut self) -> bool {
        if self.subsidiary_irp.is_some() || self.forward.is_some() {
            return false;
        }
        if !self.origin.release_prepared() || !self.release_source(false) {
            return false;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn dispatch_provider(&mut self, handler: *mut ExecNtHandler) {
        assert!(self.forward.is_none() && self.subsidiary_irp.is_none());
        if let Err(status) = self.actor.validate(&(*handler).pm) {
            self.initial_status = Some(status as i32);
            return;
        }
        if self.source.validate_packet().is_err() || self.provider_instance_if_exact().is_none() {
            self.initial_status = Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
            return;
        }
        let subsidiary = match io_manager_mut().prepare_subsidiary_file_lifecycle(
            self.outer_irp,
            self.source.source_device_registration(),
            self.source.lower_device_registration(),
        ) {
            Ok(subsidiary) => subsidiary,
            Err(nt_status::NtStatus::DEVICE_BUSY) => return,
            Err(status) => {
                self.initial_status = Some(status.raw());
                return;
            }
        };
        self.subsidiary_irp = Some(subsidiary);
        let (target, file_reference) = self
            .source
            .take_forward_owners()
            .expect("prepared subsidiary lost exact source ownership");
        self.file_reference = file_reference;
        let identity = FileLifecycleForwardIdentity {
            source: self.source.source_identity(),
            source_device: self.source.source_device_registration(),
            lower_device: self.source.lower_device_registration(),
            file: self.source.file_id(),
            outer_irp: self.outer_irp,
            subsidiary_irp: subsidiary,
            major: self.source.major(),
        };
        let mut forward =
            nt_io_manager::retained_file_lifecycle_forward::RetainedFileLifecycleForward::new(
                io_manager_mut(),
                identity,
                target,
            )
            .expect("prepared lower File owner identity");
        let projection = io_manager_mut()
            .subsidiary_file_lifecycle_projection(self.outer_irp, subsidiary)
            .expect("prepared lower File projection");
        forward
            .enter(io_manager_mut(), identity)
            .expect("lower File entry owner identity");
        io_manager_mut()
            .begin_subsidiary_file_lifecycle(self.outer_irp, subsidiary)
            .expect("lower File subsidiary entry");
        // From this point the native provider may have observed the request. No
        // uncertain return can permit a second dispatch of the same File effect.
        self.forward = Some(forward);
        let provider = self
            .provider_instance_if_exact()
            .expect("entered lower File provider identity");
        let result =
            hosted_file_dispatch::execute(provider, Some(self.caller), &projection, &[], &mut []);
        let outcome = match result {
            HostedIrpTransportResult::NotDispatched { status } => {
                FileLifecycleDispatchReturn::NotEntered(status)
            }
            HostedIrpTransportResult::Returned {
                status: nt_status::NtStatus::PENDING,
                ..
            } => FileLifecycleDispatchReturn::Pending,
            HostedIrpTransportResult::Returned {
                status,
                information,
                ..
            } => FileLifecycleDispatchReturn::InlineTerminal {
                status,
                information,
            },
            HostedIrpTransportResult::Indeterminate { transport_status } => {
                FileLifecycleDispatchReturn::Indeterminate(transport_status)
            }
        };
        io_manager_mut()
            .record_subsidiary_file_lifecycle_return(self.outer_irp, subsidiary, outcome)
            .expect("lower File exact dispatch return");
        self.forward
            .as_mut()
            .unwrap()
            .dispatch_returned(io_manager_mut(), identity, outcome)
            .expect("lower File retained return identity");
        match outcome {
            FileLifecycleDispatchReturn::NotEntered(status) => {
                self.initial_status = Some(status.raw());
                let forward = self
                    .forward
                    .take()
                    .expect("proven lower File no-entry owner");
                match forward.discard_not_entered(io_manager_mut(), identity) {
                    Ok(()) => self.subsidiary_irp = None,
                    Err((_, forward)) => self.forward = Some(forward),
                }
            }
            FileLifecycleDispatchReturn::InlineTerminal {
                status,
                information,
            } => {
                self.initial_status = Some(status.raw());
                let driver_id = projection.driver_id;
                if io_manager_mut().completed_irp(subsidiary).is_none() {
                    assert!(
                        io_manager_mut().publish_driver_completion(
                            driver_id,
                            nt_io_manager::DriverCompletion {
                                irp_id: subsidiary,
                                status,
                                information,
                                file_context: None,
                            },
                        ),
                        "genuine inline lower File terminal publication"
                    );
                }
            }
            FileLifecycleDispatchReturn::Pending => {
                self.initial_status = Some(STATUS_PENDING as i32);
            }
            FileLifecycleDispatchReturn::Indeterminate(_) => {
                // A possibly entered effect owns its physical request and source
                // Reply until an exact lower completion resolves it.
                self.initial_status = Some(STATUS_PENDING as i32);
            }
        }
    }

    unsafe fn poll_provider(&mut self) {
        let Some(subsidiary) = self.subsidiary_irp else {
            return;
        };
        let Some(completion) = completed_irp_exact(subsidiary.raw()) else {
            return;
        };
        let Some(forward) = self.forward.as_mut() else {
            return;
        };
        let identity = forward.identity();
        assert_eq!(completion.client_id, IO_MANAGER_COMPONENT_ID);
        assert_eq!(completion.file_id, self.source.file_id().raw());
        assert_eq!(
            completion.device_id,
            self.source.lower_device_registration().device_id().raw()
        );
        assert_eq!(
            completion.requestor_tid,
            u64::from(self.caller.original_thread().thread_id())
        );
        assert_eq!(completion.major, self.source.major());
        if matches!(
            forward.phase(),
            FileLifecycleForwardPhase::Pending | FileLifecycleForwardPhase::Indeterminate(_)
        ) {
            forward
                .provider_terminal(
                    io_manager_mut(),
                    identity,
                    nt_status::NtStatus(completion.status as i32),
                    completion.information,
                )
                .expect("exact lower File provider terminal");
        }
    }

    unsafe fn publish_source(&mut self) {
        let forward = self.forward.as_mut().expect("lower File forward owner");
        let identity = forward.identity();
        let (status, information) = forward
            .hold_source_completion(io_manager_mut(), identity)
            .expect("lower File terminal before source callback");
        let irp = self
            .source
            .source_irp_exec()
            .expect("live lower File source IRP");
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_STATUS_OFFSET) as *mut i32,
            status.raw(),
        );
        write_unaligned(
            (irp + WDM_X64_IRP_IO_STATUS_INFORMATION_OFFSET) as *mut u64,
            information,
        );
        self.source
            .arm_callback_free()
            .expect("deferred lower File source IRP free");
        self.source_published = true;
    }

    unsafe fn retire_after_terminal(&mut self, stopped: bool) -> bool {
        if self.post_retirement_pending_terminal.is_some() {
            return self.finish_post_retirement();
        }
        let provider = self.provider_instance_if_exact();
        let Some(forward) = self.forward.as_mut() else {
            return false;
        };
        let identity = forward.identity();
        if matches!(
            forward.phase(),
            FileLifecycleForwardPhase::SourceCompletionHeld { .. }
        ) {
            if !self.source.completion_finished() {
                return false;
            }
            forward
                .source_completion_finished(io_manager_mut(), identity)
                .expect("lower File source completion identity");
        } else if stopped && matches!(forward.phase(), FileLifecycleForwardPhase::Terminal { .. }) {
            forward
                .source_stopped(io_manager_mut(), identity)
                .expect("stopped lower File source identity");
        }
        if !matches!(
            forward.phase(),
            FileLifecycleForwardPhase::SourceCompleted
                | FileLifecycleForwardPhase::SourceStopped
                | FileLifecycleForwardPhase::AckIndeterminate(_)
                | FileLifecycleForwardPhase::Acknowledged
                | FileLifecycleForwardPhase::Retiring
        ) {
            return false;
        }
        // A possibly accepted ACK cannot be sent again merely because the
        // first transport response was uncertain.
        if matches!(
            forward.phase(),
            FileLifecycleForwardPhase::AckIndeterminate(_)
        ) {
            return false;
        }
        if !self.provider_acknowledged {
            let Some(provider) = provider else {
                return false;
            };
            let result = hosted_file_dispatch::control(
                provider,
                identity.subsidiary_irp,
                FSD_DISPATCH_ACK_COMPLETION,
                0,
                &mut [],
            );
            match result {
                HostedIrpTransportResult::Returned {
                    status: nt_status::NtStatus::SUCCESS,
                    information: 0,
                    file_context: 0,
                } => {
                    self.provider_acknowledged = true;
                    forward
                        .acknowledge(
                            io_manager_mut(),
                            identity,
                            CompletionAcknowledgement::Acknowledged,
                        )
                        .expect("lower File physical ACK identity");
                }
                HostedIrpTransportResult::NotDispatched { .. } => return false,
                HostedIrpTransportResult::Indeterminate { transport_status } => {
                    forward
                        .acknowledge(
                            io_manager_mut(),
                            identity,
                            CompletionAcknowledgement::Indeterminate { transport_status },
                        )
                        .expect("lower File uncertain ACK identity");
                    return false;
                }
                HostedIrpTransportResult::Returned { status, .. } => {
                    forward
                        .acknowledge(
                            io_manager_mut(),
                            identity,
                            CompletionAcknowledgement::Indeterminate {
                                transport_status: status,
                            },
                        )
                        .expect("lower File unexpected ACK identity");
                    return false;
                }
            }
        }
        let forward = self.forward.take().expect("acknowledged lower File owner");
        match forward.retire(io_manager_mut(), identity) {
            Ok(()) => {
                self.subsidiary_irp = None;
                self.post_retirement_pending_terminal = Some(self.origin.pending() && !stopped);
            }
            Err((_, forward)) => {
                self.forward = Some(forward);
                return false;
            }
        }
        self.finish_post_retirement()
    }

    unsafe fn finish_post_retirement(&mut self) -> bool {
        let Some(pending_terminal) = self.post_retirement_pending_terminal else {
            return false;
        };
        if !self.release_source(pending_terminal) {
            return false;
        }
        !self.actor.is_held() || self.actor_release().is_ok()
    }

    unsafe fn advance_inline_held(&mut self) -> bool {
        let finished = self.source_released || self.source.completion_finished();
        let stopped = self.origin.stopped();
        if !finished && !stopped {
            return false;
        }
        if !self.retire_after_terminal(!finished) || !self.origin.retire_receipt() {
            return false;
        }
        self.origin.retire_inline_held(finished, stopped)
    }

    unsafe fn advance_ack(&mut self) -> bool {
        let ack = self.ack.as_ref().expect("retained lower File ACK");
        if ack.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("lower File ACK Reply identity");
            if !acknowledged {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                ack.route,
                ack.dispatch,
                ack.reply,
                ack.token,
            )
            .expect("lower File ACK Reply retirement");
            return true;
        }
        if !self.retire_after_terminal(false) {
            return false;
        }
        let ack = self.ack.as_mut().expect("retained lower File ACK");
        ack.reply_entered = true;
        let _ = runtime::wake_query_path_service(ack.route, ack.dispatch, ack.reply, ack.token, 0);
        false
    }

    unsafe fn advance_stopped_source(&mut self) -> bool {
        if self.post_retirement_pending_terminal.is_some() {
            return self.finish_post_retirement() && self.origin.retire_receipt();
        }
        if !self.origin.release_prepared() {
            return false;
        }
        if self.forward.is_none() {
            if !self.release_unentered_owners() {
                return false;
            }
            return runtime::acknowledge_retained_service_cancellation(
                self.origin.route,
                self.origin.dispatch,
                self.origin.reply,
                self.origin.token,
            )
            .is_ok();
        }
        if !self.cancel_requested {
            if let Some(irp) = self.subsidiary_irp {
                let _ = cancel_irp_if_pending(irp.raw());
            }
            self.cancel_requested = true;
        }
        self.poll_provider();
        if !self.retire_after_terminal(true) {
            return false;
        }
        self.origin.retire_receipt()
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.origin.inline_held() {
            return self.advance_inline_held();
        }
        if self.ack.is_some() {
            return self.advance_ack();
        }
        if self.origin.pending() {
            if self.post_retirement_pending_terminal.is_some() {
                return self.finish_post_retirement() && self.origin.retire_receipt();
            }
            if self.origin.stopped() {
                if !self.origin.may_discard() {
                    return false;
                }
                return self.advance_stopped_source();
            }
            if !self.origin.armed() {
                return false;
            }
            self.poll_provider();
            if !self.forward.as_ref().is_some_and(|forward| {
                matches!(
                    forward.phase(),
                    FileLifecycleForwardPhase::Terminal { .. }
                        | FileLifecycleForwardPhase::SourceCompletionHeld { .. }
                        | FileLifecycleForwardPhase::SourceCompleted,
                )
            }) {
                return false;
            }
            if !self.source_published {
                self.publish_source();
            }
            if self.origin.held() && self.source.completion_finished() {
                self.origin.acknowledge_held_completion();
            }
            if !self.origin.completed() {
                let command = self
                    .source
                    .completion_command(self.origin.token)
                    .expect("pending lower File exact completion owner");
                if !self.origin.begin_terminal(command) {
                    return false;
                }
            }
            return self.retire_after_terminal(false) && self.origin.retire_receipt();
        }
        if self.origin.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                self.origin.route,
                self.origin.dispatch,
                self.origin.reply,
                self.origin.token,
            )
            .expect("lower File Reply identity");
            if !acknowledged {
                return false;
            }
            if self.forward.as_ref().is_some_and(|forward| {
                matches!(
                    forward.phase(),
                    FileLifecycleForwardPhase::NotEntered(_)
                        | FileLifecycleForwardPhase::Discarding
                )
            }) {
                let forward = self.forward.take().unwrap();
                let identity = forward.identity();
                match forward.discard_not_entered(io_manager_mut(), identity) {
                    Ok(()) => self.subsidiary_irp = None,
                    Err((_, forward)) => self.forward = Some(forward),
                }
            }
            if self.forward.is_some() {
                return false;
            }
            if !self.release_unentered_owners() {
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.origin.route,
                self.origin.dispatch,
                self.origin.reply,
                self.origin.token,
            )
            .expect("rejected lower File service retirement");
            return true;
        }
        if runtime::retained_service_cancelled(
            self.origin.route,
            self.origin.dispatch,
            self.origin.reply,
            self.origin.token,
        ) {
            return self.advance_stopped_source();
        }
        if self.initial_status.is_none() {
            if !self.provider_dispatch_ready() {
                return false;
            }
            match self.source.completion_command(self.origin.token) {
                Ok(command) => match self.origin.prepare_lane(command) {
                    hosted_source_completion_lane::SourceCompletionPreparation::Ready =>
                        self.dispatch_provider(handler),
                    hosted_source_completion_lane::SourceCompletionPreparation::KnownRejected(status) =>
                        self.initial_status = Some(status as i32),
                    hosted_source_completion_lane::SourceCompletionPreparation::RetainedUncertain =>
                        return false,
                },
                Err(error) => self.initial_status = Some(status_for_capture(error)),
            }
            if self.initial_status.is_none() {
                return false;
            }
        }
        self.poll_provider();
        let status = self.initial_status.expect("lower File dispatch status");
        use nt_io_manager::hosted_forward_progress::HostedForwardDispatchReply;
        let disposition = if status == STATUS_PENDING as i32 {
            HostedForwardDispatchReply::Pending
        } else if self.forward.as_ref().is_some_and(|forward| {
            matches!(forward.phase(), FileLifecycleForwardPhase::Terminal { .. },)
        }) {
            if !self.origin.release_prepared() {
                return false;
            }
            self.publish_source();
            HostedForwardDispatchReply::InlineTerminal(status)
        } else {
            if !self.origin.release_prepared() {
                return false;
            }
            HostedForwardDispatchReply::Rejected(status)
        };
        self.origin
            .reply_dispatch(disposition, self.source_published);
        false
    }
}

unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 {
        return false;
    }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING))
            .iter()
            .any(|(active, _, _, _)| *active == index)
        {
            return None;
        }
        if nested_ready_only
            && !(&*core::ptr::addr_of!(WORK))[index]
                .as_ref()
                .is_some_and(|work| work.ready_for_nested_step())
        {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .map(|work| (index, work))
    }) else {
        return false;
    };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING))
        .try_reserve(1)
        .is_err()
    {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return false;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push((
        index,
        work.source_instance,
        work.source.source_identity(),
        !work.source_released,
    ));
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING))
            .pop()
            .map(|row| row.0),
        Some(index)
    );
    true
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _ = redrive_one(handler, false);
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .any(|(index, row)| {
            !(&*core::ptr::addr_of!(EXECUTING))
                .iter()
                .any(|(active, _, _, _)| *active == index)
                && row
                    .as_ref()
                    .is_some_and(|work| work.ready_for_nested_step())
        })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    let attempts = (&*core::ptr::addr_of!(WORK)).len();
    nt_io_manager::hosted_forward_progress::redrive_ready_pass(attempts, || {
        redrive_one(handler, true)
    })
}

fn source_token_work_index(
    source_instance: DriverInstance,
    source_irp_address: u64,
    token: u64,
) -> Option<usize> {
    unsafe { &*core::ptr::addr_of!(WORK) }
        .iter()
        .position(|slot| {
            slot.as_ref().is_some_and(|work| {
                !work.source_released
                    && work.origin.token == token
                    && work.source_instance.pml4 == source_instance.pml4
                    && work.source_instance.exec_pool_va == source_instance.exec_pool_va
                    && work.source_instance.hosted_domain_id == source_instance.hosted_domain_id
                    && work.source_instance.hosted_domain_cookie
                        == source_instance.hosted_domain_cookie
                    && work.source.source_irp_address() == source_irp_address
                    && work.source.validate_source().is_ok()
            })
        })
}

pub(super) unsafe fn arm_pending(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    token: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_token_work_index(source_instance, source_irp_address, token) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _, _)| *active == index)
    {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || runtime::channel_route(ch).ok().flatten() != Some(work.origin.route)
        || work.source.completion_command(token).is_err()
    {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    Some(work.origin.arm(token).err().unwrap_or(STATUS_SUCCESS))
}

pub(super) unsafe fn acknowledge_held(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
    token: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_token_work_index(source_instance, source_irp_address, token) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _, _)| *active == index)
    {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if work.ack.is_some()
        || work.forward.is_none()
        || crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || runtime::channel_route(ch).ok().flatten() != Some(work.origin.route)
        || work.source.completion_command(token).is_err()
    {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    Some(
        work.origin
            .hold_inline(token)
            .err()
            .unwrap_or(STATUS_SUCCESS),
    )
}

pub(super) unsafe fn acknowledge(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    caller_badge: u64,
    source_irp_address: u64,
) -> Option<i32> {
    let Some((_, source_instance)) = instance_for_pump_channel(ch, reply_cap) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if hosted_driver_pump_caller_tcb(ch, reply_cap, caller_badge).is_none() {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    }
    let Some(index) = source_ack_work_index(source_instance, source_irp_address) else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if (&*core::ptr::addr_of!(EXECUTING))
        .iter()
        .any(|(active, _, _, _)| *active == index)
    {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    let Some(work) = (&mut *core::ptr::addr_of_mut!(WORK))[index].as_mut() else {
        return Some(STATUS_INVALID_HANDLE_LOCAL);
    };
    if crate::provider_registry_caller::resolve(ch) != Ok(work.caller)
        || work.ack.is_some()
        || !work.origin.reply_entered
        || work.forward.is_none()
        || !work.source.completion_finished()
    {
        return Some(STATUS_INVALID_DEVICE_REQUEST_LOCAL);
    }
    if !matches!(
        runtime::reconcile_retained_service_reply(
            work.origin.route,
            work.origin.dispatch,
            work.origin.reply,
            work.origin.token,
        ),
        Ok(true)
    ) {
        return Some(STATUS_DEVICE_BUSY_LOCAL);
    }
    work.source
        .validate_source()
        .expect("ACK lower File source and File identity");
    let route = match runtime::channel_route(ch) {
        Ok(Some(route)) if route == work.origin.route => route,
        _ => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        Err(_) => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        Err(_) => return Some(STATUS_INVALID_HANDLE_LOCAL),
    };
    let token = match runtime::next_service_wait_token() {
        Ok(token) => token,
        Err(_) => return Some(STATUS_INSUFFICIENT_RESOURCES_LOCAL),
    };
    runtime::retire_stopped_acknowledged_retained_service(
        work.origin.route,
        work.origin.dispatch,
        work.origin.reply,
        work.origin.token,
    )
    .expect("ACK original lower File Reply retirement");
    runtime::park_retained_service(route, token)
        .expect("ACK lower File Call admission after original retirement");
    work.ack = Some(RetainedAck {
        route,
        dispatch,
        reply,
        token,
        reply_entered: false,
    });
    None
}
