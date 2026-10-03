//! Exact retained Busy acquisition shared by driver-backed and local executive File work.

use super::*;
use nt_io_manager::FileIoWaitRoute;

impl ExecNtHandler {
    unsafe fn owned_file_io_mode(&self, route: FileIoWaitRoute) -> Result<nt_io_completion::FileIoMode, u32> {
        match route {
            FileIoWaitRoute::Hosted { file_id, .. } => self.file_completion.io_mode(file_id),
            FileIoWaitRoute::LocalOverlay { file_object } => crate::writable_fs::file_io_mode(file_object),
        }
    }

    unsafe fn retain_owned_file_io(&mut self, route: FileIoWaitRoute) -> Result<(), u32> {
        match route {
            FileIoWaitRoute::Hosted { file_id, .. } => self.file_completion.retain_file(file_id),
            FileIoWaitRoute::LocalOverlay { file_object } => crate::writable_fs::retain_io_reference(file_object),
        }
    }

    unsafe fn adopt_owned_file_io(&mut self, route: FileIoWaitRoute, tid: u64) -> Result<(), u32> {
        match route {
            FileIoWaitRoute::Hosted { file_id, .. } => self.file_completion.adopt_io_grant(file_id, tid),
            FileIoWaitRoute::LocalOverlay { file_object } => crate::writable_fs::adopt_file_io(file_object, tid),
        }
    }

    unsafe fn acquire_owned_file_io(&mut self, route: FileIoWaitRoute, tid: u64,
        mode: nt_io_completion::FileIoMode) -> Result<nt_io_completion::FileIoAcquireResult, u32> {
        match route {
            FileIoWaitRoute::Hosted { file_id, .. } => self.file_completion.acquire_file_io_with_mode(file_id, tid, mode),
            FileIoWaitRoute::LocalOverlay { file_object } => crate::writable_fs::acquire_file_io(file_object, tid, mode),
        }
    }

    pub(super) unsafe fn prepare_owned_file_io(
        &mut self,
        wait_route: nt_io_manager::FileIoWaitRoute,
        handle: u64,
        granted_access: u32,
    ) -> Result<bool, u32> {
        const STATUS_USER_APC: u32 = 0x0000_00C0;
        let live_mode = self.owned_file_io_mode(wait_route)?;
        let retry = self.synchronous_file_retry_for(handle);
        if self.active_synchronous_file_retry.is_some() && retry.is_none() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mode = if let Some(retry) = retry {
            if retry.route != wait_route
                || retry.mode.is_synchronous() != live_mode.is_synchronous()
            {
                return Err(STATUS_INVALID_PARAMETER);
            }
            retry.mode
        } else {
            live_mode
        };
        if mode == nt_io_completion::FileIoMode::Asynchronous {
            self.retain_owned_file_io(wait_route)?;
            return Ok(true);
        }

        assert!(self.current_synchronous_file.is_none(),
            "one syscall acquired more than one synchronous File");
        let admission = crate::service_sec_image::inline_file_retirement::reserve(
            nt_io_manager::FileIoBusyOwner {
                key: wait_route.key(),
                tid: self.current_tid,
                mode,
            },
        )?;

        if retry.is_some() {
            let mut ingress = self.active_synchronous_file_retry.take()
                .expect("promoted File acquisition lost its ingress claim");
            let identity = ingress.identity();
            let mut attempt = match (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                .begin_adoption(&mut ingress)
            {
                Ok(attempt) => attempt,
                Err(error) => {
                    let status = if error == nt_io_manager::SynchronousFileIngressError::Exhausted {
                        STATUS_INSUFFICIENT_RESOURCES
                    } else {
                        nt_fs::STATUS_CANCELLED
                    };
                    let identity = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                        .reject_ingress(&mut ingress, status)
                        .expect("unstarted File adoption lost its claim");
                    crate::service_sec_image::synchronous_file_cancellation::drive(self, identity);
                    return Err(status);
                }
            };
            let result = self.adopt_owned_file_io(wait_route, self.current_tid);
            let adopted = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                .record_adoption(&mut attempt, result)
                .expect("File adoption receipt lost its entered owner");
            if let Some(owner) = adopted {
                // The policy transition and transfer are memory-only. No callback can request
                // cancellation between grant adoption and publication of current-syscall Busy.
                assert!(!owner.cancellation_requested());
                self.current_synchronous_file = Some(admission.activate());
                return Ok(true);
            }
            crate::service_sec_image::synchronous_file_cancellation::drive(self, identity);
            return Err(result.expect_err("rejected File adoption reported success"));
        }

        let reservation = (&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
            .reserve().ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if REPLY_MAIN_SLOT.load(Ordering::Relaxed) == 0 || !wait_reply_pool_has_free() {
            assert!((&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                .cancel_reservation(reservation));
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        let mut waiter = nt_io_manager::SynchronousFileWaiter::waiting(
            wait_route, handle as u32, granted_access, self.current_service_number,
            self.pi as u32, self.current_tid, self.current_badge, mode,
            self.current_native_call_transport, 0, self.current_resume_ip,
            self.current_sp, self.current_flags,
        );
        // Capture before counting contention: copyin can re-enter the executive. A bad retry
        // frame matters only if this acquisition actually needs to park.
        let retry_ip = if waiter.native_call_transport {
            Ok(0)
        } else if let Some(ip) = waiter.resume_ip.checked_sub(2) {
            let mut syscall = [0u8; 2];
            if self.xas_read(ip, &mut syscall) && syscall == [0x0f, 0x05] {
                Ok(ip)
            } else {
                Err(STATUS_ACCESS_VIOLATION)
            }
        } else {
            Err(STATUS_ACCESS_VIOLATION)
        };
        if self.owned_file_io_mode(wait_route).map(|mode| mode.is_synchronous()) != Ok(mode.is_synchronous()) {
            assert!((&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                .cancel_reservation(reservation));
            return Err(STATUS_INVALID_HANDLE);
        }
        match self.acquire_owned_file_io(wait_route, waiter.tid, mode) {
            Ok(nt_io_completion::FileIoAcquireResult::Acquired) => {
                assert!((&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                    .cancel_reservation(reservation));
                self.current_synchronous_file = Some(admission.activate());
                Ok(true)
            }
            Ok(nt_io_completion::FileIoAcquireResult::Contended { alertable }) => {
                let apc_queued = alertable && self.pm.peek_user_apc(waiter.tid as u32).is_some();
                if apc_queued || retry_ip.is_err() {
                    if !crate::service_sec_image::synchronous_file_cancellation::cancel_unpublished(
                        self, reservation, waiter,
                    ) {
                        return Err(STATUS_UNSUCCESSFUL);
                    }
                    if !apc_queued {
                        return Err(retry_ip.expect_err("File rollback lost its retry-frame refusal"));
                    }
                    // No counted File acquisition remains when APC staging takes ownership of
                    // the current syscall's still-untransferred reply.
                    return match self.try_deliver_current_user_apc(STATUS_USER_APC) {
                        Ok(true) => Err(STATUS_USER_APC),
                        Ok(false) => Err(STATUS_UNSUCCESSFUL),
                        Err(status) => Err(status),
                    };
                }
                waiter.retry_ip = retry_ip.expect("parked File lost its captured retry frame");
                assert!(self.pending_synchronous_file_wait.is_none());
                self.pending_synchronous_file_wait = Some((waiter, reservation));
                Ok(false)
            }
            Ok(nt_io_completion::FileIoAcquireResult::Bypassed) => {
                unreachable!("synchronous File admission bypassed its captured mode")
            }
            Err(status) => {
                // Atomic admission rejected before retaining a reference or counting a waiter.
                assert!((&mut *core::ptr::addr_of_mut!(SYNCHRONOUS_FILE_WAITERS))
                    .cancel_reservation(reservation));
                Err(status)
            }
        }
    }

}
