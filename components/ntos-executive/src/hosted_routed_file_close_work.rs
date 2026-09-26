//! Provider-originated RoutedFile close, retained through canonical CLEANUP and Reply ACK.

use crate::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_process::native_handle::{NativeCloseError, NativeHandleCaller, NativeThreadProcessReference};

const STATUS_NO_MEMORY: u32 = 0xc000_009a;

pub(crate) enum SubmitResult {
    Ready(i32),
    Deferred,
}

struct Work {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    caller: NativeHandleCaller,
    actor: Option<NativeThreadProcessReference>,
    capture: Option<crate::driver_launch::hosted_file_capture::Capture>,
    handle: u64,
    table_owner: nt_process::ProcessId,
    file_id: u64,
    device_id: u64,
    needs_cleanup: bool,
    close_entered: bool,
    status: Option<u32>,
    reply_entered: bool,
    fault_ep: u64,
    tcb: u64,
    pml4: u64,
    reply_cap: u64,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

fn ready(status: u32) -> SubmitResult {
    SubmitResult::Ready(status as i32)
}

/// The caller is authenticated again against the current physical provider job. No table
/// mutation occurs until the work row owns its actor, File pointer and exact Reply.
pub(crate) unsafe fn submit(
    channel: &crate::spawn_hosts::PumpChannel,
    caller: NativeHandleCaller,
    handle: u64,
) -> SubmitResult {
    let _durable = crate::allocator::enter_durable();
    if crate::provider_registry_caller::resolve(channel) != Ok(caller) {
        return ready(nt_process::STATUS_INVALID_HANDLE);
    }
    let route = match runtime::channel_route(channel) {
        Ok(Some(route)) => route,
        _ => return ready(nt_process::STATUS_INVALID_HANDLE),
    };
    let dispatch = match runtime::dispatch(route) {
        Ok(dispatch) => dispatch,
        _ => return ready(nt_process::STATUS_INVALID_HANDLE),
    };
    let reply = match runtime::current_reply(route) {
        Ok(reply) => reply,
        _ => return ready(nt_process::STATUS_INVALID_HANDLE),
    };
    let admitted = crate::service_sec_image::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
        let target = pm.inspect_native_close_target(caller, handle)?;
        if target.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
            return Err(nt_process::STATUS_INVALID_HANDLE);
        }
        let grant = target.information().granted_access.ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let actor = pm.reference_native_requestor(caller)?;
        Ok((file_id, device_id, grant, target.table_owner(), actor))
    });
    let (file_id, device_id, grant, table_owner, mut actor) = match admitted {
        Ok(admitted) => admitted,
        Err(status) => return ready(status),
    };
    let capture = match crate::driver_launch::hosted_file_capture::capture(file_id, device_id, grant) {
        Ok(capture) => capture,
        Err(status) => {
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unsubmitted RoutedFile close actor");
            return ready(status);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK)).iter().enumerate().find_map(|(index, row)| {
        (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
    });
    if slot.is_none() && (&mut *core::ptr::addr_of_mut!(WORK)).try_reserve(1).is_err() {
        drop(capture);
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unsubmitted RoutedFile close actor");
        return ready(STATUS_NO_MEMORY);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
        next.checked_add(1)
    }) {
        Ok(token) => token,
        Err(_) => {
            drop(capture);
            crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                .expect("unsubmitted RoutedFile close actor");
            return ready(STATUS_NO_MEMORY);
        }
    };
    let work = Work {
        route, dispatch, reply, token, caller, actor: Some(actor), capture: Some(capture),
        handle, table_owner, file_id, device_id, needs_cleanup: false, close_entered: false,
        status: None,
        reply_entered: false, fault_ep: channel.fault_ep, tcb: channel.tcb,
        pml4: channel.pml4, reply_cap: channel.reply_cap,
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
            .take().expect("unparked RoutedFile close");
        work.capture.take();
        crate::service_sec_image::with_provider_process_manager(|pm| {
            work.actor.take().expect("unparked RoutedFile close actor").release(pm)
        }).expect("unparked RoutedFile close actor");
        return ready(STATUS_NO_MEMORY);
    }
    SubmitResult::Deferred
}

impl Work {
    unsafe fn cancelled(&self) -> bool {
        runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
    }

    unsafe fn release_actor(&mut self, handler: &mut ExecNtHandler) {
        self.actor.take().expect("retained RoutedFile close actor")
            .release(&mut handler.pm)
            .expect("retained RoutedFile close actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: &mut ExecNtHandler) -> bool {
        self.capture.take();
        runtime::acknowledge_retained_service_cancellation(
            self.route, self.dispatch, self.reply, self.token,
        ).expect("sealed RoutedFile close cancellation");
        self.release_actor(handler);
        true
    }

    unsafe fn bugcheck(&self, code: u32, parameters: [u64; 4]) -> ! {
        use nt_kernel_exec::provider_bugcheck::{FatalReport, ProviderChannel, BUGCHECK_MESSAGE_INFO};
        let report = FatalReport::decode(
            ProviderChannel {
                endpoint: self.fault_ep, tcb: self.tcb, vspace: self.pml4,
                reply_object: self.reply_cap, expected_badge: 0,
            },
            0,
            BUGCHECK_MESSAGE_INFO,
            [code as u64, parameters[0], parameters[1], parameters[2], parameters[3]],
        ).expect("canonical protected RoutedFile close bugcheck");
        crate::provider_bugcheck::stop(report)
    }

    unsafe fn advance(&mut self, handler: &mut ExecNtHandler) -> bool {
        if self.reply_entered {
            let acknowledged = runtime::reconcile_retained_service_reply(
                self.route, self.dispatch, self.reply, self.token,
            ).expect("retained RoutedFile close Reply identity");
            if acknowledged {
                runtime::retire_stopped_acknowledged_retained_service(
                    self.route, self.dispatch, self.reply, self.token,
                ).expect("acknowledged RoutedFile close Reply retirement");
                self.release_actor(handler);
                return true;
            }
            if self.cancelled() { return self.finish_cancelled(handler); }
            return false;
        }
        if !self.close_entered {
            if self.cancelled() { return self.finish_cancelled(handler); }
            if let Err(status) = self.actor.as_ref().expect("retained RoutedFile close actor")
                .validate(&handler.pm)
            {
                self.close_entered = true;
                self.capture.take();
                self.status = Some(status);
                return false;
            }
            self.needs_cleanup = match handler.file_completion
                .cleanup_required_on_handle_close(self.file_id)
            {
                Ok(needed) => needed,
                Err(status) => {
                    self.close_entered = true;
                    self.capture.take();
                    self.status = Some(status);
                    return false;
                }
            };
            let peer_cleanup = if self.needs_cleanup {
                match crate::driver_launch::registered_file_target(
                    self.device_id,
                    nt_io_abi::major::IRP_MJ_CLEANUP,
                ) {
                    Ok(crate::driver_launch::RegisteredFileTarget::DriverPeer) => true,
                    Ok(crate::driver_launch::RegisteredFileTarget::Kernel) => false,
                    Err(status) => {
                        self.close_entered = true;
                        self.capture.take();
                        self.status = Some(status);
                        return false;
                    }
                }
            } else {
                false
            };
            let lifecycle_reserved = if peer_cleanup {
                let reserved = (|| {
                    let executor = handler.pm.capture_native_handle_caller(
                        self.caller.original_thread(), nt_types::AccessMode::KernelMode,
                    )?;
                    let requestor = handler.pm.reference_native_requestor(executor)?;
                    match crate::driver_launch::reserve_hosted_file_lifecycle(
                        self.file_id, executor, requestor,
                    ) {
                        Ok(()) => Ok(()),
                        Err((status, mut requestor)) => {
                            requestor.release(&mut handler.pm)?;
                            Err(status.raw() as u32)
                        }
                    }
                })();
                match reserved {
                    Ok(()) => true,
                    Err(status) => {
                        self.close_entered = true;
                        self.capture.take();
                        self.status = Some(status);
                        return false;
                    }
                }
            } else {
                false
            };
            self.close_entered = true;
            match handler.pm.close_native_routed_file_handle(self.caller, self.handle) {
                Ok((file, device)) => {
                    assert_eq!((file, device), (self.file_id, self.device_id));
                    crate::driver_launch::hosted_consumer_file_objects::handle_closed(
                        self.table_owner, self.handle, file,
                    ).expect("closed RoutedFile has exact consumer projection owner");
                    crate::driver_launch::win32k_file_owners::handle_closed(
                        self.table_owner, self.handle, file,
                    ).expect("closed RoutedFile has exact win32k consumer projection owner");
                    // The File still has its handle reference. Drop this temporary pointer
                    // before last-handle release starts and pumps CLEANUP/CLOSE inline.
                    self.capture.take();
                    handler.release_file_handle_reference(file);
                    if lifecycle_reserved {
                        crate::driver_launch::pump_hosted_file_lifecycle();
                    } else if self.needs_cleanup {
                        crate::driver_launch::pump_registered_file_lifecycle();
                    }
                    if !self.needs_cleanup {
                        self.status = Some(0);
                    }
                }
                Err(NativeCloseError::Status(status)) => {
                    if lifecycle_reserved {
                        assert!(crate::driver_launch::cancel_hosted_file_lifecycle_reservation(
                            self.file_id,
                        ));
                    }
                    self.capture.take();
                    self.status = Some(status);
                }
                Err(NativeCloseError::BugCheck { code, parameters }) => {
                    if lifecycle_reserved {
                        assert!(crate::driver_launch::cancel_hosted_file_lifecycle_reservation(
                            self.file_id,
                        ));
                    }
                    self.bugcheck(code, parameters)
                }
            }
        }
        if self.status.is_none() {
            let cleanup_complete = crate::driver_launch::hosted_file_cleanup_terminal(self.file_id);
            if !cleanup_complete { return false; }
            // CLEANUP can resolve inline. Drive newly eligible CLOSE before replying.
            crate::driver_launch::pump_registered_file_lifecycle();
            crate::driver_launch::pump_hosted_file_lifecycle();
            self.status = Some(0);
        }
        if self.cancelled() { return self.finish_cancelled(handler); }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route, self.dispatch, self.reply, self.token,
            self.status.expect("completed RoutedFile close") as i32,
        );
        false
    }
}

/// A moved-out row prevents nested dispatch from replaying its table removal.
pub(crate) unsafe fn redrive(handler: &mut ExecNtHandler) {
    let _durable = crate::allocator::enter_durable();
    let count = (&*core::ptr::addr_of!(WORK)).len();
    if count == 0 { return; }
    let start = CURSOR.load(Ordering::Relaxed) as usize % count;
    let Some((index, mut work)) = (0..count).find_map(|step| {
        let index = (start + step) % count;
        if (&*core::ptr::addr_of!(EXECUTING)).contains(&index) { return None; }
        (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take().map(|work| (index, work))
    }) else { return; };
    let executing = &mut *core::ptr::addr_of_mut!(EXECUTING);
    if executing.try_reserve(1).is_err() {
        (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work);
        return;
    }
    executing.push(index);
    CURSOR.store(index as u64 + 1, Ordering::Relaxed);
    let done = work.advance(handler);
    if !done { (&mut *core::ptr::addr_of_mut!(WORK))[index] = Some(work); }
    assert_eq!((&mut *core::ptr::addr_of_mut!(EXECUTING)).pop(), Some(index));
}
