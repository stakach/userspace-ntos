//! Retained provider-originated CREATE, independent of the syscall-tail File owner.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::io_create_file_reply::IoCreateFileReply;
use nt_io_manager::provider_create_delivery::{
    CreateIdentity, CreateTerminal, DispatchNotEnteredProof, Phase,
    ProviderCreateDelivery, PublicationRollbackReceipt,
    StopUnacknowledgedProof,
};
use nt_process::native_handle::NativeThreadProcessReference;
use nt_process::RoutedFileHandlePublication;
use nt_security::{CapturedSubjectContext, SubjectClientIdentity};

const STATUS_CANCELLED_LOCAL: u32 = 0xc000_0120;
const STATUS_INSUFFICIENT_RESOURCES_LOCAL: u32 = 0xc000_009a;
const STATUS_NOT_SUPPORTED_LOCAL: u32 = 0xc000_00bb;
const STATUS_REPARSE_LOCAL: u32 = nt_status::NtStatus::REPARSE.raw() as u32;
const MAX_REPARSE_TRAVERSAL: u8 = 32;

pub(super) enum SubmitResult {
    Ready(IoCreateFileReply),
    Deferred,
}

struct ReparseTarget {
    device_id: u64,
    absolute_name: Vec<u16>,
    relative_name: Vec<u16>,
}

struct Work {
    captured: hosted_io_create_file_ingress::CapturedCreate,
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    actor: NativeThreadProcessReference,
    subject: Option<CapturedSubjectContext>,
    publication: Option<RoutedFileHandlePublication>,
    delivery: Option<ProviderCreateDelivery>,
    file_id: Option<u64>,
    completion_reserved: bool,
    lifecycle_reserved: bool,
    terminal: Option<(u32, u64)>,
    reply_completion: Option<IoCreateFileReply>,
    reply_entered: bool,
    backend_ack_entered: bool,
    completion_committed: bool,
    published_handle: Option<u64>,
    cancel_requested: bool,
    stop_acknowledged: bool,
    preentry_failure: Option<u32>,
    publication_failure: Option<u32>,
    reparse_hops: u8,
    reparse_target: Option<ReparseTarget>,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static mut EXECUTING: Vec<usize> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn rejected(status: u32) -> SubmitResult {
    SubmitResult::Ready(IoCreateFileReply::Rejected { status })
}

/// Ownership is published before the exact physical lane is parked. The driver packet is
/// already fully captured, so no raw component pointer enters this work queue.
pub(super) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    captured: hosted_io_create_file_ingress::CapturedCreate,
) -> SubmitResult {
    let _durable = crate::allocator::enter_durable();
    // The non-ordinary extras need their own typed object/security transactions. Reject them
    // before CREATE, rather than silently discarding requested NT semantics.
    if captured.request.policy.major != major::IRP_MJ_CREATE
        || captured.request.security_descriptor.is_some()
        || captured.request.security_qos.is_some()
        || captured.request.extra_create_parameters.is_some()
    {
        return rejected(STATUS_NOT_SUPPORTED_LOCAL);
    }
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return rejected(STATUS_INVALID_HANDLE as u32),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        Err(_) => return rejected(STATUS_INVALID_HANDLE as u32),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        Err(_) => return rejected(STATUS_INVALID_HANDLE as u32),
    };
    let actor = match crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(captured.caller)?;
        pm.reference_native_requestor(captured.caller)
    }) {
        Ok(actor) => actor,
        Err(status) => return rejected(status),
    };
    let mut subject = match crate::with_provider_security_managers(|pm, tokens| {
        pm.validate_native_handle_caller(captured.caller)?;
        let original = captured.caller.original_thread();
        let primary = pm.process_primary_token(original.process_id())
            .ok_or(STATUS_INVALID_HANDLE as u32)?;
        let client = pm.thread_impersonation(original.thread_id())
            .map(|context| SubjectClientIdentity {
                token: context.token,
                level: context.level,
            });
        CapturedSubjectContext::capture(
            tokens, primary, client, u64::from(original.process_id()),
        )
    }) {
        Ok(subject) => subject,
        Err(status) => {
            let mut actor = actor;
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unadmitted provider CREATE actor");
            return rejected(status);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index))
            .then_some(index)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        let mut actor = actor;
        crate::with_provider_security_managers(|pm, tokens| {
            subject.release(tokens)?;
            actor.release(pm)
        }).expect("unadmitted provider CREATE owners");
        return rejected(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => {
            let mut actor = actor;
            crate::with_provider_security_managers(|pm, tokens| {
                subject.release(tokens)?;
                actor.release(pm)
            }).expect("unadmitted provider CREATE owners");
            return rejected(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
        }
    };
    let work = Work {
        captured, route, dispatch, reply, token, actor, subject: Some(subject), publication: None,
        delivery: None, file_id: None, completion_reserved: false,
        lifecycle_reserved: false, terminal: None, reply_completion: None,
        reply_entered: false, backend_ack_entered: false, completion_committed: false,
        published_handle: None, cancel_requested: false,
        stop_acknowledged: false,
        preentry_failure: None, publication_failure: None,
        reparse_hops: 0, reparse_target: None,
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
            .take().expect("unparked provider CREATE work");
        crate::with_provider_security_managers(|pm, tokens| {
            work.subject.as_mut().expect("unparked CREATE subject").release(tokens)?;
            work.actor.release(pm)
        }).expect("unparked provider CREATE owners");
        return rejected(STATUS_INSUFFICIENT_RESOURCES_LOCAL);
    }
    SubmitResult::Deferred
}

impl Work {
    fn cancelled(&self) -> bool {
        unsafe {
            runtime::retained_service_cancelled(
                self.route, self.dispatch, self.reply, self.token,
            )
        }
    }

    unsafe fn ready_for_nested_step(&self) -> bool {
        if self.cancelled() { return true; }
        if self.reply_entered { return false; }
        if self.reply_completion.is_some() || self.delivery.is_none() { return true; }
        match self.delivery.as_ref().unwrap().phase() {
            Phase::Prepared | Phase::Terminal | Phase::Aborted => true,
            Phase::Finished if self.reparse_target.is_some() => true,
            Phase::AwaitTerminal => self.delivery.as_ref().unwrap().irp()
                .is_some_and(|irp| completed_irp_exact(irp.raw()).is_some()),
            _ => false,
        }
    }

    unsafe fn prepare(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        if self.cancelled() { return Err(STATUS_CANCELLED_LOCAL); }
        let request = &self.captured.request;
        let mode = nt_io_completion::FileIoMode::from_create_flags(
            request.policy.create_options & nt_fs::FILE_SYNCHRONOUS_IO_ALERT != 0,
            request.policy.create_options & nt_fs::FILE_SYNCHRONOUS_IO_NONALERT != 0,
            request.desired_access
                & (nt_fs::SYNCHRONIZE | 0xf000_0000 | 0x0200_0000) != 0,
        )?;
        if self.publication.is_none() {
            let publication = (*handler).pm.reserve_native_routed_file_handle(
                self.captured.caller,
                request.object_attributes & (nt_process::native_handle::OBJ_KERNEL_HANDLE | 2),
            )?;
            self.publication = Some(publication);
        }
        let file_id = match self.captured.related_file.as_ref() {
            Some(parent) => allocate_owned_hosted_relative_file(
                parent, request.desired_access, request.share_access,
                request.policy.create_options, &self.captured.relative_name,
            )?,
            None => allocate_hosted_file(
                self.captured.device_id, request.desired_access, request.share_access,
                request.policy.create_options, &self.captured.relative_name,
            )?,
        };
        self.file_id = Some(file_id);
        let lifecycle_actor = (*handler).pm.reference_native_requestor(self.captured.caller)?;
        match reserve_hosted_file_lifecycle(file_id, self.captured.caller, lifecycle_actor) {
            Ok(()) => self.lifecycle_reserved = true,
            Err((status, mut actor)) => {
                actor.release(&mut (*handler).pm)?;
                return Err(status.raw() as u32);
            }
        }
        (*handler).file_completion.reserve_file_handle_publication(
            file_id, self.captured.device_id, mode,
        )?;
        self.completion_reserved = true;
        self.delivery = Some(ProviderCreateDelivery::new(CreateIdentity {
            file: FileId(file_id),
            requestor_tid: u64::from(self.captured.caller.original_thread().thread_id()),
            major: request.policy.major,
        }));
        Ok(())
    }

    unsafe fn dispatch_create(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        if self.cancelled() { return Err(STATUS_CANCELLED_LOCAL); }
        self.actor.validate(&(*handler).pm)?;
        (*handler).pm.validate_native_handle_caller(self.captured.caller)?;
        let request = &self.captured.request;
        let name = &self.captured.relative_name;
        let length = name.len().checked_mul(2)
            .and_then(|bytes| bytes.checked_add(request.ea.len()))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
        let mut input = Vec::new();
        input.try_reserve_exact(length).map_err(|_| STATUS_INSUFFICIENT_RESOURCES_LOCAL)?;
        for unit in name { input.extend_from_slice(&unit.to_le_bytes()); }
        input.extend_from_slice(&request.ea);
        let file_id = self.file_id.expect("prepared provider CREATE File");
        let delivery = self.delivery.as_mut().expect("prepared provider CREATE delivery");
        delivery.enter_dispatch().expect("one provider CREATE dispatch");
        let result = dispatch_hosted_file_create_irp_result_exact(
            file_id, request.policy.major, self.captured.caller,
            CreateParameters {
                opened_case_sensitive: request.object_attributes & 0x40 == 0,
                desired_access: AccessMask::from_bits_retain(request.desired_access),
                share_access: ShareAccess::from_bits_retain(request.share_access),
                create_options: CreateOptions::from_bits_retain(request.policy.create_options),
                create_disposition: request.disposition,
                file_attributes: request.file_attributes,
                ea_length: request.ea.len() as u32,
                related_file: self.captured.related_file_id.map(FileId),
            },
            &input,
        );
        match result {
            Ok((_, _, Some(irp), _)) => {
                delivery.retain_irp(irp).expect("retained provider CREATE IRP");
            }
            Ok((status, information, None, _)) => {
                delivery.observe_inline_terminal(status as u32, information)
                    .expect("inline provider CREATE terminal");
                self.terminal = Some((status as u32, information));
            }
            Err(status) => {
                delivery.abort_not_entered(DispatchNotEnteredProof::ProviderNotEntered)
                    .expect("pre-entry provider CREATE rejection");
                self.terminal = Some((status, 0));
            }
        }
        Ok(())
    }

    unsafe fn observe_terminal(&mut self) -> Result<bool, u32> {
        let delivery = self.delivery.as_mut().expect("provider CREATE delivery");
        let Some(irp) = delivery.irp() else { return Ok(true); };
        let Some(terminal) = completed_irp_exact(irp.raw()) else { return Ok(false); };
        if terminal.file_id != self.file_id.expect("provider CREATE File")
            || terminal.requestor_tid != delivery.identity().requestor_tid
            || terminal.major != delivery.identity().major
        {
            panic!("provider CREATE terminal identity mismatch");
        }
        delivery.observe_terminal(CreateTerminal {
            irp: Some(irp), identity: delivery.identity(),
            status: terminal.status, information: terminal.information,
        }).expect("exact provider CREATE terminal");
        self.terminal = Some((terminal.status, terminal.information));
        Ok(true)
    }

    unsafe fn rollback_unpublished(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        if let Some(publication) = self.publication.as_mut() {
            publication.abort(&mut (*handler).pm)?;
            self.publication = None;
        }
        if let Some(file_id) = self.file_id {
            let committed = self.completion_committed;
            if self.completion_reserved {
                (*handler).file_completion.cancel_reserved_file_handle(file_id)?;
                self.completion_reserved = false;
            } else if self.completion_committed {
                (*handler).release_file_handle_reference(file_id);
                self.completion_committed = false;
            }
            if !committed {
                abandon_unpublished_hosted_file(file_id)?;
            }
            self.file_id = None;
        }
        Ok(())
    }

    unsafe fn fail_reparse(&mut self, handler: *mut ExecNtHandler, status: u32) -> Result<(), u32> {
        let file = self.file_id.expect("reparsed source File");
        self.rollback_unpublished(handler)?;
        self.delivery.as_mut().expect("reparsed CREATE delivery")
            .rollback_publication(
                PublicationRollbackReceipt::after_exact_retirement(FileId(file), None),
                status,
            ).expect("reparse failure revokes unpublished File");
        self.reply_completion = Some(IoCreateFileReply::Completed {
            status, iosb_status: status, information: 0, handle: 0,
        });
        Ok(())
    }

    unsafe fn advance_reparse(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        let (status, information) = self.terminal.expect("reparse terminal");
        debug_assert_eq!(status, STATUS_REPARSE_LOCAL);
        if self.reparse_target.is_none() {
            if information != 0 || self.reparse_hops >= MAX_REPARSE_TRAVERSAL {
                return self.fail_reparse(handler, STATUS_NOT_SUPPORTED_LOCAL);
            }
            let file = self.file_id.expect("reparsed source File");
            let target = crate::driver_launch::hosted_reparse_name::capture(
                file, self.captured.device_id,
            ).and_then(|absolute_name| {
                let (device_id, relative_name) =
                    crate::driver_launch::hosted_io_create_file_ingress::resolve_absolute_name(
                        &absolute_name, true,
                    )?;
                require_hosted_device_ready_for_dispatch(device_id)?;
                Ok(ReparseTarget { device_id, absolute_name, relative_name })
            });
            match target {
                Ok(target) => self.reparse_target = Some(target),
                Err(status) => return self.fail_reparse(handler, status),
            }
        }
        let delivery = self.delivery.as_mut().expect("reparsed CREATE delivery");
        if delivery.phase() != Phase::Finished {
            if let Some(irp) = delivery.irp() {
                if !self.backend_ack_entered {
                    delivery.enter_reparse_backend_ack()
                        .expect("IO_REPARSE enters internal backend ACK");
                    self.backend_ack_entered = true;
                }
                acknowledge_completed_irp(irp.raw())?;
                delivery.acknowledge_backend().expect("reparse backend ACK receipt");
                delivery.finish().expect("reparsed hop retired without client Reply");
            } else {
                delivery.finish_inline_reparse()
                    .expect("inline reparse retired without client Reply");
            }
        }
        let file = self.file_id.expect("reparsed source File");
        if self.completion_reserved {
            (*handler).file_completion.cancel_reserved_file_handle(file)?;
            self.completion_reserved = false;
        }
        abandon_unpublished_hosted_file(file)?;
        self.file_id = None;
        self.lifecycle_reserved = false;
        let target = self.reparse_target.take().expect("retained reparse target");
        self.captured.device_id = target.device_id;
        self.captured.request.name = target.absolute_name;
        self.captured.request.root_directory = 0;
        self.captured.related_file = None;
        self.captured.related_file_id = None;
        self.captured.relative_name = target.relative_name;
        self.reparse_hops += 1;
        self.delivery = None;
        self.terminal = None;
        self.backend_ack_entered = false;
        Ok(())
    }

    unsafe fn rollback_published(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        let Some(handle) = self.published_handle else { return Ok(()); };
        let (expected_file, expected_device) = (*handler).pm.lookup_native_routed_file_handle(
            self.captured.caller, handle, 0,
        )?;
        if Some(expected_file) != self.file_id || expected_device != self.captured.device_id {
            return Err(STATUS_INVALID_HANDLE as u32);
        }
        let (file, device) = (*handler).pm.close_native_routed_file_handle(self.captured.caller, handle)
            .map_err(|error| match error {
                nt_process::native_handle::NativePsCloseError::Status(status) => status,
                _ => STATUS_INVALID_HANDLE as u32,
            })?;
        assert_eq!((file, device), (expected_file, expected_device));
        self.published_handle = None;
        (*handler).release_file_handle_reference(file);
        self.completion_committed = false;
        self.publication = None;
        self.delivery.as_mut().expect("published provider CREATE delivery")
            .rollback_cancelled_handle(handle)
            .expect("cancelled CREATE handle rollback");
        Ok(())
    }

    unsafe fn cancel_pending(&mut self) {
        if self.cancel_requested { return; }
        let Some(irp) = self.delivery.as_ref().and_then(ProviderCreateDelivery::irp) else {
            return;
        };
        self.cancel_requested = true;
        // The canonical IRP owner retains and retries uncertain cancellation; the CREATE work
        // continues to wait for its exact terminal record before backend acknowledgement.
        let _ = cancel_irp_if_pending(irp.raw());
    }

    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> Result<bool, u32> {
        if let Some(delivery) = self.delivery.as_mut() {
            if !delivery.cancelled()
                && !matches!(delivery.phase(), Phase::Aborted | Phase::Finished) {
                delivery.cancel().expect("cancelled provider CREATE before Reply");
            }
        }
        if self.published_handle.is_some() {
            self.rollback_published(handler)?;
        } else if self.file_id.is_some() || self.publication.is_some() {
            self.rollback_unpublished(handler)?;
        }
        if !self.stop_acknowledged {
            runtime::acknowledge_retained_service_cancellation(
                self.route, self.dispatch, self.reply, self.token,
            ).map_err(|_| STATUS_INVALID_HANDLE as u32)?;
            self.stop_acknowledged = true;
            if let Some(delivery) = self.delivery.as_mut() {
                if !matches!(delivery.phase(), Phase::Aborted | Phase::Finished) {
                    delivery.acknowledge_stop().expect("sealed provider CREATE stop");
                }
            }
        }
        self.ack_backend()?;
        self.release_actor(handler)?;
        Ok(true)
    }

    unsafe fn release_actor(&mut self, handler: *mut ExecNtHandler) -> Result<(), u32> {
        if let Some(subject) = self.subject.as_mut() {
            subject.release(&mut (*handler).token_store)?;
            self.subject = None;
        }
        self.actor.release(&mut (*handler).pm)
    }

    unsafe fn ack_backend(&mut self) -> Result<(), u32> {
        let Some(delivery) = self.delivery.as_mut() else { return Ok(()); };
        if delivery.phase() == Phase::Finished { return Ok(()); }
        let Some(irp) = delivery.irp() else {
            if matches!(delivery.phase(), Phase::ReplyAcknowledged | Phase::Terminal)
                && delivery.terminal().is_some()
            {
                delivery.finish().expect("inline provider CREATE retired");
            }
            return Ok(());
        };
        if !self.backend_ack_entered {
            delivery.enter_backend_ack().expect("terminal CREATE backend ACK permission");
            self.backend_ack_entered = true;
        }
        acknowledge_completed_irp(irp.raw())?;
        delivery.acknowledge_backend().expect("CREATE backend ACK receipt");
        delivery.finish().expect("CREATE terminal delivery finished");
        Ok(())
    }

    unsafe fn publish_success(&mut self, handler: *mut ExecNtHandler) -> Result<u64, u32> {
        let file = self.file_id.expect("provider CREATE File");
        let publication = self.publication.as_mut().expect("provider CREATE reservation");
        publication.bind(&mut (*handler).pm, file, self.captured.device_id,
            self.captured.request.desired_access)?;
        (*handler).file_completion.commit_reserved_file_handle(file)?;
        self.completion_reserved = false;
        self.completion_committed = true;
        let handle = publication.publish(&mut (*handler).pm)?;
        self.published_handle = Some(handle);
        assert!(cancel_hosted_file_lifecycle_reservation(file));
        self.lifecycle_reserved = false;
        let delivery = self.delivery.as_mut().expect("provider CREATE delivery");
        delivery.bind_handle(handle).expect("bound provider CREATE handle");
        delivery.publish_handle(handle).expect("published provider CREATE handle");
        Ok(handle)
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> Result<bool, u32> {
        if self.reply_entered {
            if !runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).map_err(|_| STATUS_INVALID_HANDLE as u32)? {
                if self.cancelled() {
                    if let Some(delivery) = self.delivery.as_mut() {
                        if delivery.phase() == Phase::ReplyEntered {
                            delivery.cancel_unacknowledged_reply_after_stop(
                                StopUnacknowledgedProof::SealedStop,
                            ).expect("sealed unacknowledged CREATE Reply");
                            self.stop_acknowledged = true;
                        }
                    }
                    // The state machine owns the exact stop receipt now. Complete the external
                    // wait token once, then retire any handle and backend IRP.
                    runtime::acknowledge_retained_service_cancellation(
                        self.route, self.dispatch, self.reply, self.token,
                    ).map_err(|_| STATUS_INVALID_HANDLE as u32)?;
                    return self.finish_cancelled(handler);
                }
                // The entered Reply is uncertain. Never send it again or release its handle.
                return Ok(false);
            }
            if let Some(delivery) = self.delivery.as_mut() {
                if delivery.phase() == Phase::ReplyEntered {
                    delivery.acknowledge_reply().expect("provider CREATE Reply ACK");
                }
            }
            self.ack_backend()?;
            runtime::retire_stopped_acknowledged_retained_service(
                self.route, self.dispatch, self.reply, self.token,
            ).map_err(|_| STATUS_INVALID_HANDLE as u32)?;
            self.release_actor(handler)?;
            return Ok(true);
        }
        if self.delivery.is_none() && self.reply_completion.is_none() {
            if self.cancelled() { return self.finish_cancelled(handler); }
            if let Some(status) = self.preentry_failure {
                self.rollback_unpublished(handler)?;
                self.reply_completion = Some(IoCreateFileReply::Rejected { status });
                return Ok(false);
            }
            if let Err(status) = self.prepare(handler) {
                self.preentry_failure = Some(status);
                self.rollback_unpublished(handler)?;
                self.reply_completion = Some(IoCreateFileReply::Rejected { status });
            }
            return Ok(false);
        }
        if self.reply_completion.is_none() {
            let phase = self.delivery.as_ref().expect("provider CREATE delivery").phase();
            if phase == Phase::Prepared {
                if self.cancelled() { return self.finish_cancelled(handler); }
                if let Some(status) = self.preentry_failure {
                    self.rollback_unpublished(handler)?;
                    self.reply_completion = Some(IoCreateFileReply::Rejected { status });
                    return Ok(false);
                }
                if let Err(status) = self.dispatch_create(handler) {
                    if self.delivery.as_ref().unwrap().phase() == Phase::Prepared {
                        self.preentry_failure = Some(status);
                        self.rollback_unpublished(handler)?;
                        self.reply_completion = Some(IoCreateFileReply::Rejected { status });
                    }
                    // An entered dispatch must retain its exact IRP; a transport error is not a
                    // new negative CREATE result and cannot be retried as a fresh request.
                }
                return Ok(false);
            }
            if phase == Phase::AwaitTerminal {
                if self.cancelled() { self.cancel_pending(); }
                if !self.observe_terminal()? { return Ok(false); }
            }
            if self.cancelled() { return self.finish_cancelled(handler); }
            let phase = self.delivery.as_ref().unwrap().phase();
            if matches!(phase, Phase::Finished | Phase::BackendAckEntered)
                && self.reparse_target.is_some() {
                self.advance_reparse(handler)?;
                return Ok(false);
            }
            if phase == Phase::Aborted {
                let status = self.terminal.expect("pre-entry CREATE status").0;
                self.rollback_unpublished(handler)?;
                self.reply_completion = Some(IoCreateFileReply::Rejected { status });
            } else if phase == Phase::Terminal {
                let (status, information) = self.terminal.expect("CREATE terminal");
                if status == STATUS_REPARSE_LOCAL {
                    self.advance_reparse(handler)?;
                } else if (status as i32) < 0 {
                    self.rollback_unpublished(handler)?;
                    self.reply_completion = Some(IoCreateFileReply::Completed {
                        status, iosb_status: status, information, handle: 0,
                    });
                } else {
                    if let Some(publication_status) = self.publication_failure {
                        let file = self.file_id.expect("failed CREATE publication File");
                        self.rollback_unpublished(handler)?;
                        self.delivery.as_mut().expect("failed CREATE delivery")
                            .rollback_publication(
                                PublicationRollbackReceipt::after_exact_retirement(
                                    FileId(file), None,
                                ),
                                publication_status,
                            ).expect("exact failed CREATE publication rollback");
                        self.reply_completion = Some(IoCreateFileReply::Completed {
                            status: publication_status,
                            iosb_status: publication_status,
                            information: 0,
                            handle: 0,
                        });
                        return Ok(false);
                    }
                    match self.publish_success(handler) {
                        Ok(handle) => {
                            self.reply_completion = Some(IoCreateFileReply::Completed {
                                status, iosb_status: status, information, handle,
                            });
                        }
                        Err(publication_status) => {
                            self.publication_failure = Some(publication_status);
                        }
                    }
                }
            }
            return Ok(false);
        }
        if self.cancelled() { return self.finish_cancelled(handler); }
        let completion = self.reply_completion.expect("prepared CREATE reply");
        if let Some(delivery) = self.delivery.as_mut() {
            if delivery.phase() != Phase::Aborted {
                delivery.enter_reply().expect("terminal provider CREATE Reply");
            }
        }
        self.reply_entered = true;
        // Even on a wrapper error, the physical Reply may have been consumed. The next sweep
        // reconciles its exact acknowledgement bit; it never sends a second Reply.
        let _ = runtime::wake_file_create_service(
            self.route, self.dispatch, self.reply, self.token, completion,
        );
        Ok(false)
    }
}

/// Drive one retained transaction per sweep; nested hosted dispatch may re-enter this function.
unsafe fn redrive_one(handler: *mut ExecNtHandler, nested_ready_only: bool) -> bool {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count != 0 {
        let start = CURSOR.load(Ordering::Relaxed) as usize % count;
        if let Some((index, mut work)) = (0..count).find_map(|step| {
            let index = (start + step) % count;
            if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
            if nested_ready_only && !(&*core::ptr::addr_of!(WORK))[index]
                .as_ref().is_some_and(|work| work.ready_for_nested_step()) {
                return None;
            }
            (&mut *core::ptr::addr_of_mut!(WORK))[index]
                .take().map(|work| (index, work))
        }) {
            {
                let executing = &mut *core::ptr::addr_of_mut!(EXECUTING);
                if executing.try_reserve(1).is_err() {
                    (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
                    return false;
                }
                executing.push(index);
            }
            CURSOR.store(index as u64 + 1, Ordering::Relaxed);
            let done = match work.advance(handler) {
                Ok(done) => done,
                Err(_) => false,
            };
            if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
            assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
            return true;
        }
    }
    false
}

pub(super) unsafe fn redrive(handler: *mut ExecNtHandler) {
    // The outer service loop must reconcile entered Replies as well as ready
    // provider completions. Nested dispatch cannot retry an uncertain Reply.
    let count = (&*core::ptr::addr_of!(WORK)).len();
    for _ in 0..count.saturating_mul(2) {
        if !redrive_one(handler, false) { break; }
    }
    // Inline provider completions need no new ingress event to advance their retained Reply.
    // A bounded drain also covers a full chain of STATUS_REPARSE name traversals.
    for _ in 0..(MAX_REPARSE_TRAVERSAL as usize * 8) {
        if !nested_work_ready() || !redrive_one(handler, true) { break; }
    }
}

pub(super) unsafe fn nested_work_ready() -> bool {
    (&*core::ptr::addr_of!(WORK)).iter().enumerate().any(|(index, row)| {
        !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)
            && row.as_ref().is_some_and(|work| work.ready_for_nested_step())
    })
}

pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool {
    redrive_one(handler, true)
}
