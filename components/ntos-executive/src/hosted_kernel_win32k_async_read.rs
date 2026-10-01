//! Asynchronous win32k kernel File reads with retained provider-stack delivery.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_manager::retained_read_forward::ReadCompletion;
use nt_io_manager::win32k_async_read_wire as wire;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

const FILE_READ_DATA: u32 = 1;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

struct Work {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    handle: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    file: super::hosted_file_capture::Capture,
    lease: crate::win32k_subsystem::ProviderPoolPacketLease,
    packet: Vec<u8>,
    parameters: ReadWriteParameters,
    output_alias: u64,
    iosb_alias: u64,
    output: Vec<u8>,
    delivery: nt_io_manager::hosted_kernel_read_delivery::HostedKernelReadDelivery<u64>,
    irp: Option<IrpId>,
    entered: bool,
    reply_entered: bool,
    reply_acked: bool,
    packet_prepared: bool,
    cancel_requested: bool,
    inline_error: bool,
    terminal: Option<(u32, u64)>,
    terminal_captured: bool,
    ack_claimed: bool,
    cancel_ack_claimed: bool,
    prior_file_signal: Option<bool>,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
// A completed token remains queryable until its provider consumes the exact completion.
type OperationIdentity = (nt_component_suspension::peer_registry::PeerRoute, u64, u64);
static mut ACTIVE: Vec<OperationIdentity> = Vec::new();
static mut COMPLETED: Vec<OperationIdentity> = Vec::new();
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn wire_status(error: wire::AsyncReadWireError) -> i32 {
    match error {
        wire::AsyncReadWireError::BufferTooSmall | wire::AsyncReadWireError::LengthMismatch => {
            STATUS_INVALID_BUFFER_SIZE as i32
        }
        wire::AsyncReadWireError::Malformed => STATUS_INVALID_PARAMETER,
    }
}

/// The service Reply only says that the IRP was accepted. The provider must not release either
/// pinned stack target until this exact operation reports terminal publication and IRP ACK.
pub(crate) unsafe fn completion_for_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    handle: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    if token == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Ok(Some(route)) = runtime::channel_route(channel) else {
        return STATUS_INVALID_HANDLE;
    };
    let identity = (route, handle, token);
    if (&*core::ptr::addr_of!(COMPLETED)).contains(&identity) {
        return STATUS_SUCCESS;
    }
    if (&*core::ptr::addr_of!(ACTIVE)).contains(&identity) {
        return STATUS_PENDING as i32;
    }
    STATUS_INVALID_PARAMETER
}

/// Drop the root completion receipt after the provider has released both local stack pins.
/// An uncertain reply may be retried: INVALID_PARAMETER is only a valid duplicate to a provider
/// that already observed terminal completion for this exact token and released its pins.
pub(crate) unsafe fn release_token(
    channel: &crate::spawn_hosts::PumpChannel,
    token: u64,
    handle: u64,
) -> i32 {
    let _durable = crate::allocator::enter_durable();
    if token == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Ok(Some(route)) = runtime::channel_route(channel) else {
        return STATUS_INVALID_HANDLE;
    };
    let identity = (route, handle, token);
    let Some(index) = (&*core::ptr::addr_of!(COMPLETED))
        .iter()
        .position(|row| *row == identity)
    else {
        return STATUS_INVALID_PARAMETER;
    };
    (&mut *core::ptr::addr_of_mut!(COMPLETED)).swap_remove(index);
    STATUS_SUCCESS
}

/// Rejections before `park_retained_service` have no external read effect: the request packet
/// remains token-zero, and the provider may release its pins after the direct NT error Reply.
pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    packet: u64,
    packet_length: u64,
    handle: u64,
) -> Option<i32> {
    let _durable = crate::allocator::enter_durable();
    let caller = match crate::provider_registry_caller::resolve(channel) {
        Ok(caller) => caller,
        Err(status) => return Some(status as i32),
    };
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return Some(STATUS_INVALID_HANDLE),
    };
    let Ok(length) = usize::try_from(packet_length) else {
        return Some(STATUS_INVALID_BUFFER_SIZE as i32);
    };
    let (lease, bytes) = match crate::win32k_subsystem::capture_provider_pool_packet(packet, length)
    {
        Ok(captured) => captured,
        Err(status) => return Some(status as i32),
    };
    let request = match wire::decode_request(&bytes) {
        Ok(request) => request,
        Err(error) => return Some(wire_status(error)),
    };
    let iosb_alias =
        match crate::win32k_glue::win32k_stack_alias_for_route(route, request.iosb_va, 16) {
            Some(alias) => alias,
            None => return Some(STATUS_INVALID_PARAMETER),
        };
    let output_alias = if request.parameters.length == 0 {
        0
    } else {
        match crate::win32k_glue::win32k_stack_alias_for_route(
            route,
            request.output_va,
            u64::from(request.parameters.length),
        ) {
            Some(alias) => alias,
            None => return Some(STATUS_INVALID_PARAMETER),
        }
    };
    let (file_id, device_id, granted, mut actor) =
        match crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)?;
            let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
            let target = pm.inspect_native_close_target(caller, handle)?;
            if target.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
                return Err(STATUS_INVALID_HANDLE as u32);
            }
            let granted = target
                .information()
                .granted_access
                .ok_or(STATUS_INVALID_HANDLE as u32)?;
            if granted & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) == 0 {
                return Err(STATUS_ACCESS_DENIED as u32);
            }
            let actor = pm.reference_native_requestor(caller)?;
            Ok((file_id, device_id, granted, actor))
        }) {
            Ok(value) => value,
            Err(status) => return Some(status as i32),
        };
    let file = match super::hosted_file_capture::capture(file_id, device_id, granted) {
        Ok(file) => file,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unentered win32k read actor");
            return Some(status as i32);
        }
    };
    let mut output = Vec::new();
    if output
        .try_reserve_exact(request.parameters.length as usize)
        .is_err()
    {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered win32k read actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    output.resize(request.parameters.length as usize, 0);
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
        });
    if (slot.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err())
        || (&mut *core::ptr::addr_of_mut!(COMPLETED))
            .try_reserve(1)
            .is_err()
        || (&mut *core::ptr::addr_of_mut!(ACTIVE))
            .try_reserve(1)
            .is_err()
    {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered win32k read actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token =
        match runtime::next_service_wait_token() {
            Ok(token) if token != 0 => token,
            _ => {
                crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                    .expect("unentered win32k read actor");
                return Some(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
    let work = Work {
        route,
        dispatch,
        reply,
        token,
        handle,
        caller,
        actor,
        file,
        lease,
        packet: bytes,
        parameters: request.parameters,
        output_alias,
        iosb_alias,
        output,
        delivery: nt_io_manager::hosted_kernel_read_delivery::HostedKernelReadDelivery::admit(
            token,
            request.parameters.length,
        ),
        irp: None,
        entered: false,
        reply_entered: false,
        reply_acked: false,
        packet_prepared: false,
        cancel_requested: false,
        inline_error: false,
        terminal: None,
        terminal_captured: false,
        ack_claimed: false,
        cancel_ack_claimed: false,
        prior_file_signal: None,
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
            .expect("unparked win32k read");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked win32k read actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    (&mut *core::ptr::addr_of_mut!(ACTIVE)).push((route, handle, token));
    None
}

impl Work {
    fn cancelled(&self) -> bool {
        unsafe {
            runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
        }
    }

    unsafe fn release(&mut self, handler: *mut ExecNtHandler) {
        let identity = (self.route, self.handle, self.token);
        let index = (&*core::ptr::addr_of!(ACTIVE))
            .iter()
            .position(|row| *row == identity)
            .expect("active win32k read identity");
        (&mut *core::ptr::addr_of_mut!(ACTIVE)).swap_remove(index);
        self.actor
            .release(&mut (*handler).pm)
            .expect("win32k read actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> bool {
        // Once an early Reply was attempted, cancellation alone cannot prove that the provider
        // did not observe STATUS_PENDING. Keep the stack-target owner until exact delivery.
        if self.reply_entered {
            return false;
        }
        if let Some(irp) = self.irp {
            if !self.cancel_requested {
                self.cancel_requested = true;
                let _ = cancel_irp_if_pending(irp.raw());
            }
            if self.cancel_ack_claimed || completed_irp_exact(irp.raw()).is_none() {
                return false;
            }
            self.cancel_ack_claimed = true;
            if acknowledge_completed_irp(irp.raw()).is_err() {
                return false;
            }
            self.irp = None;
        }
        if let Some(previous) = self.prior_file_signal {
            (*handler)
                .file_completion
                .set_signaled(self.file.file_id(), previous)
                .expect("restore File event after cancelled read");
            if previous {
                let mut objects = (*handler).dispatcher_objects(None);
                crate::service_sec_image::provider_wait_select_ready(&mut objects);
            }
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("win32k read cancellation");
        self.release(handler);
        true
    }

    unsafe fn capture_terminal(&mut self, status: u32, information: u64) -> bool {
        let (status, information) = if information > self.output.len() as u64 {
            (nt_fs::STATUS_DATA_ERROR, 0)
        } else {
            (status, information)
        };
        let transfer = if nt_io_completion::file_io_status_copies_output(status) {
            nt_io_manager::completion_output_transfer_len(information, self.output.len() as u64)
                as usize
        } else {
            0
        };
        if let Some(irp) = self.irp {
            if transfer != 0 {
                match copy_completed_irp_output_exact(irp.raw(), 0, &mut self.output[..transfer]) {
                    Ok(bytes) if bytes == transfer => {}
                    _ => return false,
                }
            }
        }
        // Information may be nonzero for a warning, but this owner only exposes bytes actually
        // copied from the exact IRP. An impossible status/information pair is a data error.
        let (status, information) = if transfer as u64 != information {
            (nt_fs::STATUS_DATA_ERROR, 0)
        } else {
            (status, information)
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(transfer).is_err() {
            return false;
        }
        bytes.extend_from_slice(&self.output[..transfer]);
        let completion = ReadCompletion::from_owned(status, information, bytes);
        self.delivery
            .capture_terminal(&self.token, completion)
            .expect("submitted win32k read terminal");
        self.terminal = Some((status, information));
        self.terminal_captured = true;
        true
    }

    unsafe fn publish_pending(&mut self) -> bool {
        if !self.packet_prepared {
            if wire::publish_pending(&mut self.packet, self.token).is_err() {
                crate::provider_bugcheck::report(0xc4, [self.token, self.file.file_id(), 0, 0]);
            }
            self.packet_prepared = true;
        }
        if !crate::win32k_subsystem::publish_provider_pool_packet(self.lease, &self.packet) {
            return false;
        }
        self.delivery
            .begin_pending_reply(&self.token)
            .expect("pending read Reply claim");
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            STATUS_PENDING as i32,
        );
        false
    }

    unsafe fn publish_inline_error(&mut self, handler: *mut ExecNtHandler) -> bool {
        let (status, _) = self.terminal.expect("inline read error");
        if !self.packet_prepared {
            if wire::publish_inline_terminal(&mut self.packet, self.token, status, &[]).is_err() {
                crate::provider_bugcheck::report(
                    0xc4,
                    [self.token, self.file.file_id(), status as u64, 0],
                );
            }
            self.packet_prepared = true;
        }
        if !crate::win32k_subsystem::publish_provider_pool_packet(self.lease, &self.packet) {
            return false;
        }
        if let Some(previous) = self.prior_file_signal {
            (*handler)
                .file_completion
                .set_signaled(self.file.file_id(), previous)
                .expect("restore File event after inline read error");
            if previous {
                let mut objects = (*handler).dispatcher_objects(None);
                crate::service_sec_image::provider_wait_select_ready(&mut objects);
            }
        }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            status as i32,
        );
        false
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.entered {
            if self.cancelled() {
                return self.finish_cancelled(handler);
            }
            self.entered = true;
            self.delivery
                .submitted(&self.token)
                .expect("admitted win32k read");
            if let Err(status) = self.actor.validate(&(*handler).pm) {
                self.inline_error = true;
                self.terminal = Some((status, 0));
            } else {
                self.prior_file_signal = Some(
                    (*handler)
                        .file_completion
                        .is_signaled(self.file.file_id())
                        .expect("live win32k read File event"),
                );
                (*handler)
                    .file_completion
                    .set_signaled(self.file.file_id(), false)
                    .expect("live win32k read File event");
                match dispatch_hosted_file_read_write_irp_result_exact(
                    self.file.file_id(),
                    major::IRP_MJ_READ,
                    self.caller,
                    self.parameters,
                    &[],
                    &mut self.output,
                ) {
                    Ok((_, _, Some(irp), _)) => self.irp = Some(irp),
                    Ok((status, information, None, _)) => {
                        if !nt_io_completion::file_io_status_publishes_completion(
                            status as u32,
                            true,
                        ) {
                            self.inline_error = true;
                        }
                        self.terminal = Some((status as u32, information));
                    }
                    Err(status) => {
                        self.inline_error = true;
                        self.terminal = Some((status, 0));
                    }
                }
            }
            if self.inline_error {
                let (status, _) = self.terminal.expect("inline read error");
                self.delivery
                    .returned_inline(
                        &self.token,
                        ReadCompletion::from_owned(status, 0, Vec::new()),
                    )
                    .expect("inline read error state");
                return self.publish_inline_error(handler);
            }
            self.delivery
                .returned_pending(&self.token)
                .expect("pending win32k read state");
            return self.publish_pending();
        }
        if !self.reply_entered {
            if self.cancelled() {
                return self.finish_cancelled(handler);
            }
            return if self.inline_error {
                self.publish_inline_error(handler)
            } else {
                self.publish_pending()
            };
        }
        if self.reply_entered && !self.reply_acked {
            self.reply_acked = runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("win32k read Reply identity");
            if !self.reply_acked {
                // A cancelled route does not prove whether the early Reply was delivered.
                return false;
            }
            if !self.inline_error {
                self.delivery
                    .confirm_pending_reply(&self.token)
                    .expect("acknowledged pending win32k read Reply");
            }
        }
        if self.inline_error {
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("inline win32k read Reply retirement");
            self.release(handler);
            return true;
        }
        if !self.terminal_captured {
            if self.cancelled() && !self.cancel_requested {
                if let Some(irp) = self.irp {
                    self.cancel_requested = true;
                    let _ = cancel_irp_if_pending(irp.raw());
                }
            }
            if let Some(irp) = self.irp {
                let Some(completion) = completed_irp_exact(irp.raw()) else {
                    return false;
                };
                if completion.file_id != self.file.file_id()
                    || completion.requestor_tid
                        != u64::from(self.caller.original_thread().thread_id())
                    || completion.major != major::IRP_MJ_READ
                {
                    panic!("win32k read terminal identity mismatch");
                }
                if !self.capture_terminal(completion.status, completion.information) {
                    return false;
                }
            } else {
                let (status, information) = self.terminal.expect("inline read terminal");
                if !self.capture_terminal(status, information) {
                    return false;
                }
            }
        }
        // `acknowledge_completed_irp` may have had an uncertain native effect. A claimed ACK is
        // never replayed, nor are the already published stack bytes or File event.
        if self.ack_claimed {
            return false;
        }
        let bytes = self
            .delivery
            .begin_output(&self.token)
            .expect("win32k read output claim");
        if !bytes.is_empty() {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.output_alias as *mut u8,
                bytes.len(),
            );
        }
        self.delivery
            .confirm_output(&self.token)
            .expect("win32k read output publication");
        let (status, information) = self
            .delivery
            .begin_iosb(&self.token)
            .expect("win32k read IOSB claim");
        core::ptr::write_unaligned(self.iosb_alias as *mut u32, status);
        core::ptr::write_unaligned((self.iosb_alias + 8) as *mut u64, information);
        self.delivery
            .confirm_iosb(&self.token)
            .expect("win32k read IOSB publication");
        self.delivery
            .begin_file_event(&self.token)
            .expect("win32k read File event claim");
        (*handler)
            .file_completion
            .set_signaled(self.file.file_id(), true)
            .expect("terminal win32k read File event");
        let mut objects = (*handler).dispatcher_objects(None);
        crate::service_sec_image::provider_wait_select_ready(&mut objects);
        self.delivery
            .confirm_file_event(&self.token)
            .expect("win32k read File event publication");
        self.delivery
            .begin_irp_ack(&self.token)
            .expect("win32k read IRP ACK claim");
        self.ack_claimed = true;
        if let Some(irp) = self.irp {
            if acknowledge_completed_irp(irp.raw()).is_err() {
                return false;
            }
            self.irp = None;
        }
        self.delivery
            .confirm_irp_ack(&self.token)
            .expect("win32k read IRP ACK");
        runtime::retire_stopped_acknowledged_retained_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("win32k read Reply retirement");
        (&mut *core::ptr::addr_of_mut!(COMPLETED)).push((self.route, self.handle, self.token));
        self.release(handler);
        true
    }
}

pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 {
        return;
    }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) {
            return None;
        }
        (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .map(|work| (index, work))
    }) else {
        return;
    };
    if (&mut *core::ptr::addr_of_mut!(EXECUTING))
        .try_reserve(1)
        .is_err()
    {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    (&mut *core::ptr::addr_of_mut!(EXECUTING)).push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
    }
    assert_eq!(
        (&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(),
        Some(index)
    );
}
