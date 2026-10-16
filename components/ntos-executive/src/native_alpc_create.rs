//! Native ALPC create ingress binding. No port-service effect occurs here.

use core::sync::atomic::{AtomicU64, Ordering};
use nt_alpc_native_capture::{CreateOwner, RetainedCreate};
use nt_process::native_alpc_port::{AlpcPortIdentity, NativeAlpcPortPublication};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
static NEXT_ALPC_CREATE_INVOCATION: AtomicU64 = AtomicU64::new(1);

pub(crate) struct PreparedCreatePort {
    pub(crate) pi: usize,
    pub(crate) badge: u64,
    pub(crate) process_id: u64,
    pub(crate) thread_id: u64,
    pub(crate) process_generation: u64,
    pub(crate) captured: nt_alpc_native_capture::CapturedCreatePort,
}

/// Owns the original Reply, exact service request, and invisible process
/// handle. The service route may move this across waits but may not drop it
/// after submission or expose its table slot before checked copyout.
#[must_use = "retain ALPC create across uncertain service and Reply effects"]
pub(crate) struct PendingCreatePort {
    pi: usize,
    output: u64,
    process_id: u64,
    process_generation: u64,
    retained: RetainedCreate,
    publication: NativeAlpcPortPublication,
}

impl PendingCreatePort {
    pub(crate) fn request(&self) -> &[u8] { self.retained.request() }
    pub(crate) fn reply_cap(&self) -> u64 { self.retained.reply_cap() }
    pub(crate) fn token(&self) -> (u64, u64) { self.retained.token() }
    pub(crate) fn process_handle(&self) -> u64 { self.publication.value() }

    pub(crate) fn begin(&mut self, request_id: u64) -> Result<(), u32> {
        self.retained.begin(request_id).map_err(|_| STATUS_INVALID_PARAMETER)
    }

    /// A rejected SQE is known to have no service effect; retire the table
    /// reservation before the caller can receive its failure status.
    pub(crate) fn no_effect(&mut self, pm: &mut nt_process::ProcessManager,
        status: i32) -> Result<(), u32> {
        self.retained.no_effect(status).map_err(|_| STATUS_INVALID_PARAMETER)?;
        assert!(self.publication.abort(pm)?.is_none(), "unsubmitted ALPC port was bound");
        self.retained.process_handle_aborted(self.process_handle())
            .map_err(|_| STATUS_INVALID_HANDLE)
    }

    /// Bind only an exact terminal CQE. An uncertain result leaves both the
    /// request and invisible process slot owned by this pending operation.
    pub(crate) fn complete(&mut self, pm: &mut nt_process::ProcessManager,
        request_id: u64, status: i32, service_handle: u64) -> Result<(), u32> {
        self.retained.complete(request_id, status, service_handle)
            .map_err(|_| STATUS_INVALID_PARAMETER)?;
        if status == 0 {
            if let Err(error) = self.publication.bind(pm, service_handle) {
                assert!(self.publication.abort(pm)?.is_none(), "failed ALPC bind published a handle");
                self.retained.process_handle_aborted(self.process_handle())
                    .map_err(|_| STATUS_INVALID_HANDLE)?;
                return Err(error);
            }
        } else {
            assert!(self.publication.abort(pm)?.is_none(), "failed ALPC create published a handle");
            self.retained.process_handle_aborted(self.process_handle())
                .map_err(|_| STATUS_INVALID_HANDLE)?;
        }
        Ok(())
    }

    /// Write the process-local handle into the exact captured process address
    /// space, then make its pre-bound slot visible. Failed publication retains
    /// the service handle for exact checked close.
    pub(crate) unsafe fn copyout(&mut self, handler: &mut crate::ExecNtHandler)
        -> Result<(), u32> {
        if handler.pm_pid_for_pi(self.pi).map(u64::from) != Some(self.process_id)
            || handler.hosted_process_generation(self.pi) != Some(self.process_generation)
        {
            self.abort_bound(&mut handler.pm)?;
            return Err(STATUS_INVALID_HANDLE);
        }
        let handle = self.process_handle();
        let written = handler.process_memory_write_status(
            self.pi, self.output, &handle.to_le_bytes()).is_ok();
        self.retained.copyout(handle, written).map_err(|_| STATUS_INVALID_PARAMETER)?;
        if !written {
            self.abort_bound(&mut handler.pm)?;
            return Ok(());
        }
        match self.publication.publish(&mut handler.pm) {
            Ok(published) => self.retained.process_handle_published(published)
                .map_err(|_| STATUS_INVALID_HANDLE),
            Err(error) => {
                self.abort_bound(&mut handler.pm)?;
                Err(error)
            }
        }
    }

    fn abort_bound(&mut self, pm: &mut nt_process::ProcessManager) -> Result<(), u32> {
        let expected = self.retained.terminal().and_then(|result|
            (result.status == 0).then_some(result.handle));
        let identity = self.publication.abort(pm)?;
        if identity.map(|identity| identity.service_handle) != expected {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.retained.process_handle_aborted(self.process_handle())
            .map_err(|_| STATUS_INVALID_HANDLE)
    }

    /// The service close request must carry every checked-create authority
    /// field; a raw numeric handle has no cleanup authority.
    pub(crate) fn cleanup_request(&self) -> Option<nt_alpc_abi::AlpcCloseCreatedPortRequest> {
        let service_handle = self.retained.cleanup_handle()?;
        let token = self.token();
        Some(nt_alpc_abi::AlpcCloseCreatedPortRequest {
            abi_size: core::mem::size_of::<nt_alpc_abi::AlpcCloseCreatedPortRequest>() as u16,
            handle: service_handle,
            owner_process: self.process_id,
            owner_thread: self.retained.owner().thread_id,
            owner_generation: self.process_generation,
            invocation_hi: token.0,
            invocation_lo: token.1,
            ..Default::default()
        })
    }

    pub(crate) fn cleanup_complete(&mut self, identity: AlpcPortIdentity,
        status: i32) -> Result<(), u32> {
        if identity.owner_process as u64 != self.process_id
            || identity.owner_generation != self.process_generation
            || (identity.invocation_hi, identity.invocation_lo) != self.token()
        { return Err(STATUS_INVALID_HANDLE); }
        self.retained.cleanup_complete(identity.service_handle, status)
            .map_err(|_| STATUS_INVALID_HANDLE)
    }

    pub(crate) fn reply_status(&self) -> Option<i32> { self.retained.reply_status() }
    pub(crate) fn finish_after_reply(self, acknowledged: bool) -> Result<(), Self> {
        if acknowledged && self.retained.reply_status().is_some() { Ok(()) } else { Err(self) }
    }
}

impl crate::ExecNtHandler {
    /// Bind copied arguments to the hosted thread and process incarnation
    /// admitted for this native call. RootDirectory and SecurityDescriptor
    /// policy, token ownership, and Reply retention precede any live submission.
    pub(crate) unsafe fn prepare_native_alpc_create_port(
        &mut self,
        args: [u64; 3],
    ) -> Result<PreparedCreatePort, u32> {
        let pi = self.pi;
        let badge = self.current_badge;
        if self.hosted_thread_pi_for_badge(badge) != Some(pi) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let process_id = self.pm_pid_for_pi(pi).ok_or(STATUS_INVALID_PARAMETER)? as u64;
        let thread_id = self.hosted_thread_tid_for_badge(badge)
            .filter(|tid| *tid != 0 && *tid == self.current_tid)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let process_generation = self.hosted_process_generation(pi)
            .filter(|generation| *generation != 0)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let output_valid = self.probe_user_output(args[0], 8);
        let captured = nt_alpc_native_capture::capture(
            args,
            |address, out| self.xas_read(address, out),
            |_, _| output_valid,
        )?;
        Ok(PreparedCreatePort {
            pi,
            badge,
            process_id,
            thread_id,
            process_generation,
            captured,
        })
    }

    /// Complete all pre-effect ownership work. The returned object must be
    /// installed into a retained service-loop owner before any ring SQE.
    pub(crate) fn reserve_native_alpc_create_port(
        &mut self,
        prepared: PreparedCreatePort,
        reply_cap: u64,
    ) -> Result<PendingCreatePort, u32> {
        if !self.current_native_call_transport || reply_cap == 0
            || self.pi != prepared.pi || self.current_badge != prepared.badge
        { return Err(STATUS_INVALID_PARAMETER); }
        let caller = self.native_handle_caller(nt_syscall::ProcessorMode::UserMode)?;
        if u64::from(caller.effective_process()) != prepared.process_id {
            return Err(STATUS_INVALID_HANDLE);
        }
        let sequence = NEXT_ALPC_CREATE_INVOCATION.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed, |next| next.checked_add(1))
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let token = (prepared.process_generation, sequence);
        let owner = CreateOwner { process_id: prepared.process_id,
            thread_id: prepared.thread_id, process_generation: prepared.process_generation };
        let request = prepared.captured.checked_wire(owner, token)?;
        let mut publication = self.pm.reserve_native_alpc_port_handle(
            caller, prepared.process_generation, token)?;
        let retained = match RetainedCreate::new(owner, token, reply_cap,
            publication.value(), request) {
            Ok(retained) => retained,
            Err(_) => {
                assert!(publication.abort(&mut self.pm)?.is_none());
                return Err(STATUS_INVALID_PARAMETER);
            }
        };
        Ok(PendingCreatePort { pi: prepared.pi, output: prepared.captured.output,
            process_id: prepared.process_id, process_generation: prepared.process_generation,
            retained, publication })
    }
}
