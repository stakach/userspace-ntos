//! Win32k ZwCancelIoFile on an authenticated routed File.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_process::native_handle::{NativeHandleCaller, NativeThreadProcessReference};

struct Work {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
    reply: u64,
    token: u64,
    caller: NativeHandleCaller,
    actor: NativeThreadProcessReference,
    file: super::hosted_file_capture::Capture,
    entered: bool,
    drain_required: bool,
    terminal: Option<u32>,
    reply_entered: bool,
}

static mut WORK: Vec<Option<Work>> = Vec::new();
static mut EXECUTING: Vec<usize> = Vec::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static CURSOR: AtomicU64 = AtomicU64::new(0);

/// Park the provider Reply until all current-thread IRPs on the exact File have drained.
/// The provider wrapper owns IOSB publication after this status-only service returns.
pub(crate) unsafe fn submit_win32k(
    channel: &crate::spawn_hosts::PumpChannel,
    handle: u64,
    expected_file: u64,
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
    let (file_id, device_id, granted, mut actor) =
        match crate::service_sec_image::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(caller)?;
            let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, handle, 0)?;
            if expected_file != 0 && file_id != expected_file {
                return Err(STATUS_INVALID_HANDLE as u32);
            }
            let target = pm.inspect_native_close_target(caller, handle)?;
            if target.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
                return Err(STATUS_INVALID_HANDLE as u32);
            }
            let granted = target
                .information()
                .granted_access
                .ok_or(STATUS_INVALID_HANDLE as u32)?;
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
                .expect("unentered hosted File cancel actor");
            return Some(status as i32);
        }
    };
    let slot = (&*core::ptr::addr_of!(WORK))
        .iter()
        .enumerate()
        .find_map(|(index, row)| {
            (row.is_none() && !(&*core::ptr::addr_of!(EXECUTING)).contains(&index)).then_some(index)
        });
    if slot.is_none()
        && (&mut *core::ptr::addr_of_mut!(WORK))
            .try_reserve(1)
            .is_err()
    {
        crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
            .expect("unentered hosted File cancel actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    let token =
        match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1)) {
            Ok(token) => token,
            Err(_) => {
                crate::service_sec_image::with_provider_process_manager(|pm| actor.release(pm))
                    .expect("unentered hosted File cancel actor");
                return Some(STATUS_INSUFFICIENT_RESOURCES);
            }
        };
    let work = Work {
        route,
        dispatch,
        reply,
        token,
        caller,
        actor,
        file,
        entered: false,
        drain_required: false,
        terminal: None,
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
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index]
            .take()
            .expect("unparked hosted File cancel");
        crate::service_sec_image::with_provider_process_manager(|pm| work.actor.release(pm))
            .expect("unparked hosted File cancel actor");
        return Some(STATUS_INSUFFICIENT_RESOURCES);
    }
    None
}

impl Work {
    fn cancelled(&self) -> bool {
        unsafe {
            runtime::retained_service_cancelled(self.route, self.dispatch, self.reply, self.token)
        }
    }

    fn drained(&self) -> bool {
        !self.drain_required
            || super::file_thread_io_drain_state(
                self.file.file_id(),
                u64::from(self.caller.original_thread().thread_id()),
            )
            .is_drained()
    }

    unsafe fn release(&mut self, handler: *mut ExecNtHandler) {
        self.actor
            .release(&mut (*handler).pm)
            .expect("hosted File cancel actor identity");
    }

    unsafe fn finish_cancelled(&mut self, handler: *mut ExecNtHandler) -> bool {
        if !self.drained() {
            return false;
        }
        runtime::acknowledge_retained_service_cancellation(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
        )
        .expect("hosted File cancel cancellation");
        self.release(handler);
        true
    }

    unsafe fn advance(&mut self, handler: *mut ExecNtHandler) -> bool {
        if self.reply_entered {
            let acked = runtime::reconcile_retained_service_reply(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("hosted File cancel Reply identity");
            if !acked {
                if self.cancelled() {
                    return self.finish_cancelled(handler);
                }
                return false;
            }
            runtime::retire_stopped_acknowledged_retained_service(
                self.route,
                self.dispatch,
                self.reply,
                self.token,
            )
            .expect("hosted File cancel Reply retirement");
            self.release(handler);
            return true;
        }
        if !self.entered {
            if self.cancelled() {
                return self.finish_cancelled(handler);
            }
            self.entered = true;
            match self.actor.validate(&(*handler).pm) {
                Err(status) => self.terminal = Some(status),
                Ok(()) => {
                    // Record the effect boundary before calling the manager. A refused call may
                    // already have requested cancellation of earlier selected IRPs.
                    self.drain_required = true;
                    self.terminal = Some(
                        match super::cancel_file_thread_io(
                            self.file.file_id(),
                            u64::from(self.caller.original_thread().thread_id()),
                        ) {
                            Ok(_) => 0,
                            Err(status) => status,
                        },
                    );
                }
            }
        }
        if !self.drained() {
            return false;
        }
        if self.cancelled() {
            return self.finish_cancelled(handler);
        }
        self.reply_entered = true;
        let _ = runtime::wake_service(
            self.route,
            self.dispatch,
            self.reply,
            self.token,
            self.terminal.expect("entered hosted File cancel status") as i32,
        );
        false
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
