//! Initial-thread admission against the process's pre-created mechanism.

use super::*;

#[derive(Debug)]
pub(crate) struct PendingInitialThreadCreation {
    plan: nt_process::InitialThreadCreationPlan,
    handle: Option<nt_process::HandleReservation>,
    bound: bool,
    origin: InitialCreationOrigin,
}

pub(crate) type Binding = nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>;

#[derive(Clone, Copy, Debug)]
enum InitialCreationOrigin {
    Configured,
    Foreign(ForeignInitialCreation),
}

#[derive(Clone, Copy, Debug)]
struct ForeignInitialCreation {
    caller: Binding,
    handle_out: u64,
    client_id_out: u64,
    desired_access: u32,
    create_suspended: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitialCreationDelivery {
    Queue,
    Direct,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessCalloutProgress {
    Ready,
    Suspended,
}

unsafe fn runtime(handler: &ExecNtHandler, binding: Binding) -> Option<&HostedThreadRuntimeOwner> {
    (&*handler.thread_runtime.table)
        .entries
        .iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.binding() == binding)
}

/// Capture the dormant target's exact provider identity before initial-thread ownership closes
/// ordinary executable lookup. The callout may then use only this already authenticated target.
unsafe fn capture_initial_win32k_client(
    handler: &ExecNtHandler,
    binding: Binding,
) -> Result<Option<crate::win32k_glue::Win32kClientContext>, u32> {
    let role = handler.hosted_process_role(binding.pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if !role.uses_win32_client_gdi() { return Ok(None); }
    if crate::win32k_subsystem::registered_win32k_callouts().is_none() {
        return Err(0xC000_00A3);
    }
    if handler.capture_process_identity(binding.pi) != Some(binding.process) {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    let mut client = crate::win32k_lifecycle_client(binding.tid, handler)
        .ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    if client.pi as usize != binding.pi || client.tid != binding.tid
        || client.badge != binding.badge || client.tcb != binding.tcb
    { return Err(nt_process::STATUS_INVALID_HANDLE); }
    let lifetime = handler.pm.thread_lifetime(binding.tid as nt_process::ThreadId)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    client.logical_caller = Some(
        nt_user_host::provider_logical_caller::ProviderLogicalCaller::capture(binding, lifetime)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?,
    );
    Ok(Some(client))
}

/// The initial TCB is deliberately closed to ordinary hosted ingress while its one-shot
/// creation plan is retained. Only its exact in-flight Ps process-create callout may still use
/// its logical caller authority to service native provider faults and waits.
pub(crate) unsafe fn validate_process_create_provider_caller(
    handler: &ExecNtHandler,
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
) -> bool {
    use nt_user_host::process_create_callout::ProcessCreateCalloutPhase;
    let Some(target) = (&*handler.thread_runtime.table).entries.iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.binding().tid == u64::from(caller.thread().thread_id()))
    else { return false; };
    let binding = target.binding();
    if caller.validate(
        Some(binding), handler.pm.thread_lifetime(caller.thread().thread_id()),
    ).is_err()
        || handler.capture_process_identity(binding.pi) != Some(binding.process)
        || !target.initial_creation.try_borrow().is_ok_and(|slot| slot.is_some())
    { return false; }
    target.process_create_callout.try_borrow().is_ok_and(|slot| {
        slot.as_ref().is_some_and(|owner| matches!(
            owner.phase(),
            ProcessCreateCalloutPhase::Invoking | ProcessCreateCalloutPhase::Suspended,
        ))
    })
}

/// Complete the genuine win32k process-create callback while the initial TCB is still dormant.
/// The published main runtime is an exact Ps target at this boundary, and has not yet entered
/// initial-thread control (which correctly closes ordinary logical-caller admission).
unsafe fn create_win32_process_before_loader(
    handler: &mut ExecNtHandler,
    binding: Binding,
    client: Option<crate::win32k_glue::Win32kClientContext>,
) -> Result<ProcessCalloutProgress, u32> {
    use nt_user_host::process_create_callout::{
        CalloutResult, ProcessCreateCalloutOwner, ProcessCreateCalloutPhase,
    };
    let Some(client) = client else { return Ok(ProcessCalloutProgress::Ready); };
    let process = handler.capture_process_identity(binding.pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if process != binding.process { return Err(nt_process::STATUS_INVALID_HANDLE); }
    {
        let owner = runtime(handler, binding).ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        let mut slot = owner.process_create_callout.try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        if slot.is_none() {
            *slot = Some(ProcessCreateCalloutOwner::new(binding.pi, process)
                .ok_or(nt_process::STATUS_INVALID_HANDLE)?);
        }
        let callout = slot.as_mut().unwrap();
        if callout.ready(binding.pi, process) { return Ok(ProcessCalloutProgress::Ready); }
        callout.begin(binding.pi, process)
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    }
    let outcome = crate::win32k_glue::win32k_create_process_before_loader(client);
    {
        let owner = runtime(handler, binding).ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        let mut slot = owner.process_create_callout.try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        let callout = slot.as_mut().ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        let result = match outcome {
            crate::win32k_glue::Win32kProcessCreateResult::NotEntered(status) =>
                CalloutResult::NotEntered(status),
            crate::win32k_glue::Win32kProcessCreateResult::Returned(status) =>
                CalloutResult::Returned(status),
            crate::win32k_glue::Win32kProcessCreateResult::Indeterminate(status) =>
                CalloutResult::Indeterminate(status),
            crate::win32k_glue::Win32kProcessCreateResult::Suspended =>
                CalloutResult::Suspended,
        };
        callout.record(result).map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        if callout.phase() == ProcessCreateCalloutPhase::Suspended {
            return Ok(ProcessCalloutProgress::Suspended);
        }
        if callout.phase() != ProcessCreateCalloutPhase::Returned {
            return Err(match outcome {
                crate::win32k_glue::Win32kProcessCreateResult::NotEntered(status)
                | crate::win32k_glue::Win32kProcessCreateResult::Returned(status)
                | crate::win32k_glue::Win32kProcessCreateResult::Indeterminate(status) => {
                    if status == 0 { nt_process::STATUS_DEVICE_BUSY } else { status }
                },
                crate::win32k_glue::Win32kProcessCreateResult::Suspended =>
                    nt_process::STATUS_DEVICE_BUSY,
            });
        }
    }
    finish_win32_process_projection(handler, binding)?;
    Ok(ProcessCalloutProgress::Ready)
}

unsafe fn finish_win32_process_projection(
    handler: &mut ExecNtHandler,
    binding: Binding,
) -> Result<(), u32> {
    use nt_user_host::process_create_callout::ProcessCreateCalloutPhase;
    let process = handler.capture_process_identity(binding.pi)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    if process != binding.process { return Err(nt_process::STATUS_INVALID_HANDLE); }
    let owner = runtime(handler, binding).ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    if owner.process_create_callout.try_borrow().map_err(|_| nt_process::STATUS_DEVICE_BUSY)?
        .as_ref().map(|callout| callout.phase()) != Some(ProcessCreateCalloutPhase::Returned)
    { return Err(nt_process::STATUS_DEVICE_BUSY); }
    let imported = crate::service_sec_image::import_early_win32k_process_context(
        handler, binding.pi, process, binding.tid,
    );
    {
        let owner = runtime(handler, binding).ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        let mut slot = owner.process_create_callout.try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        let callout = slot.as_mut().ok_or(nt_process::STATUS_DEVICE_BUSY)?;
        match imported {
            Some(w32process) => callout.confirm_process_import(binding.pi, process, w32process)
                .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?,
            None => {
                callout.fail_projection(nt_process::STATUS_UNSUCCESSFUL)
                    .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
                return Err(nt_process::STATUS_UNSUCCESSFUL);
            }
        }
    }
    let pml4 = handler.process_vspaces.get(binding.pi).copied().unwrap_or(0);
    let projected = pml4 != 0
        && crate::win32k_glue::map_gdi_shared_handle_table_into_client(
            handler, pml4, binding.pi,
        ) != 0;
    let owner = runtime(handler, binding).ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    let mut slot = owner.process_create_callout.try_borrow_mut()
        .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    let callout = slot.as_mut().ok_or(nt_process::STATUS_DEVICE_BUSY)?;
    if !projected {
        callout.fail_projection(nt_process::STATUS_UNSUCCESSFUL)
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        return Err(nt_process::STATUS_UNSUCCESSFUL);
    }
    callout.confirm_projection(binding.pi, process)
        .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    Ok(())
}

unsafe fn callout_may_retire(handler: &ExecNtHandler, binding: Binding) -> bool {
    runtime(handler, binding).is_some_and(|runtime| {
        runtime.process_create_callout.try_borrow().is_ok_and(|slot| {
            slot.as_ref().is_none_or(|callout| callout.may_retire())
        })
    })
}

/// A provider completion belongs to this exact suspended Ps target. Import and projection are
/// performed once, after the callout's returned success has been authenticated by the pump.
pub(crate) unsafe fn complete_suspended_process_callout(
    handler: &mut ExecNtHandler,
    binding: Binding,
    status: u32,
    completed: bool,
) -> Result<(), u32> {
    use nt_user_host::process_create_callout::CalloutResult;
    let owner = runtime(handler, binding).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    let mut slot = owner.process_create_callout.try_borrow_mut()
        .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    let callout = slot.as_mut().ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    callout.resolve_suspended(
        binding.pi,
        binding.process,
        if completed { CalloutResult::Returned(status) }
        else { CalloutResult::Indeterminate(status) },
    ).map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
    drop(slot);
    if !completed || status != 0 {
        return Err(if status == 0 { nt_process::STATUS_DEVICE_BUSY } else { status });
    }
    finish_win32_process_projection(handler, binding)
}

/// Locate the sole initial-thread creation whose source caller is this exact live runtime.
/// A recycled PID, TID, badge, or process slot cannot adopt the provider continuation.
pub(crate) unsafe fn suspended_for_caller(
    handler: &ExecNtHandler,
    caller: Binding,
) -> Option<Binding> {
    use nt_user_host::process_create_callout::ProcessCreateCalloutPhase;
    let mut match_binding = None;
    for target in (&*handler.thread_runtime.table).entries.iter().filter_map(|slot| slot.owner()) {
        let matches_caller = target.initial_creation.try_borrow().is_ok_and(|slot| {
            slot.as_ref().is_some_and(|owner| {
                matches!(owner.origin, InitialCreationOrigin::Foreign(origin) if origin.caller == caller)
            })
        });
        let suspended = target.process_create_callout.try_borrow().is_ok_and(|slot| {
            slot.as_ref().is_some_and(|owner| owner.phase() == ProcessCreateCalloutPhase::Suspended)
        });
        if matches_caller && suspended {
            assert!(match_binding.is_none(), "caller cannot own two suspended initial creations");
            match_binding = Some(target.binding());
        }
    }
    match_binding
}

pub(crate) unsafe fn finish_suspended_initial_creation(
    handler: &mut ExecNtHandler,
    binding: Binding,
    status: u32,
    completed: bool,
    source_abandoned: bool,
) -> u32 {
    if let Err(status) = complete_suspended_process_callout(handler, binding, status, completed) {
        return status;
    }
    let Some(target) = runtime(handler, binding) else { return nt_process::STATUS_INVALID_HANDLE; };
    let Ok(slot) = target.initial_creation.try_borrow() else { return nt_process::STATUS_DEVICE_BUSY; };
    let Some(owner) = slot.as_ref() else { return nt_process::STATUS_INVALID_HANDLE; };
    let origin = owner.origin;
    drop(slot);
    match origin {
        InitialCreationOrigin::Foreign(_) =>
            handler.finish_foreign_initial_thread(binding, if source_abandoned {
                InitialCreationDelivery::Abandoned
            } else {
                InitialCreationDelivery::Direct
            }),
        InitialCreationOrigin::Configured =>
            handler.finish_configured_initial_thread(binding),
    }
}

/// No native entry occurred, or the suspension owner proved definitive no-effects rejection.
/// Any failed local cleanup retains the plan and the remaining handle ownership in the runtime.
unsafe fn cancel_creation(handler: &mut ExecNtHandler, binding: Binding, status: u32) -> u32 {
    let table = &*handler.thread_runtime.table;
    let Some(runtime) = table
        .entries
        .iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.binding() == binding)
    else {
        return nt_process::STATUS_DEVICE_BUSY;
    };
    let Ok(mut slot) = runtime.initial_creation.try_borrow_mut() else {
        return nt_process::STATUS_DEVICE_BUSY;
    };
    let Some(owner) = slot.as_mut() else {
        return nt_process::STATUS_DEVICE_BUSY;
    };
    if let Some(handle) = owner.handle {
        let result = if owner.bound {
            handler.pm.cancel_bound_handle(handle).map(|_| ())
        } else {
            handler.pm.cancel_reserved_handle(handle)
        };
        if let Err(error) = result {
            return error;
        }
        owner.handle = None;
    }
    if let Err(error) = handler.pm.cancel_initial_thread_creation(&owner.plan) {
        return error;
    }
    *slot = None;
    status
}

impl ExecNtHandler {
    pub(crate) unsafe fn start_configured_initial_thread(
        &mut self,
        pi: usize,
        main_tcb: u64,
    ) -> u32 {
        let Some(process) = self.capture_process_identity(pi) else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        let Some(tid) = self.pm.main_thread(process.pid) else {
            return nt_process::STATUS_INVALID_HANDLE;
        };
        // Capture executable authority before publishing the retained creation owner, which
        // deliberately closes ordinary dispatch and retirement until creation is committed.
        let Some(binding) = self
            .thread_runtime
            .executable_by_tid(u64::from(tid))
            .map(|runtime| runtime.binding())
        else {
            return nt_process::STATUS_DEVICE_BUSY;
        };
        if binding.pi != pi || binding.process != process || binding.tcb != main_tcb {
            return nt_process::STATUS_INVALID_PARAMETER;
        }
        let plan = match self.pm.prepare_initial_thread_creation(process.pid) {
            Ok(Some(plan)) => plan,
            Ok(None) => return nt_process::STATUS_INVALID_PARAMETER,
            Err(status) => return status,
        };
        let client = match capture_initial_win32k_client(self, binding) {
            Ok(client) => client,
            Err(status) => {
                self.pm.cancel_initial_thread_creation(&plan)
                    .expect("unentered initial creation retains its canonical reservation");
                return status;
            }
        };
        {
            let runtime = runtime(self, binding).expect("configured initial runtime retained");
            let mut slot = runtime.initial_creation.borrow_mut();
            assert!(
                slot.is_none(),
                "configured initial creation has exclusive ownership"
            );
            *slot = Some(PendingInitialThreadCreation {
                plan,
                handle: None,
                bound: false,
                origin: InitialCreationOrigin::Configured,
            });
        }
        match create_win32_process_before_loader(self, binding, client) {
            Ok(ProcessCalloutProgress::Ready) => {}
            Ok(ProcessCalloutProgress::Suspended) => return nt_user_callback::STATUS_PENDING as u32,
            Err(status) if callout_may_retire(self, binding) => {
                return cancel_creation(self, binding, status);
            }
            Err(status) => return status,
        }
        self.finish_configured_initial_thread(binding)
    }

    unsafe fn finish_configured_initial_thread(&mut self, binding: Binding) -> u32 {
        let Some(target) = runtime(self, binding) else { return nt_process::STATUS_INVALID_HANDLE; };
        let Ok(slot) = target.initial_creation.try_borrow() else { return nt_process::STATUS_DEVICE_BUSY; };
        let Some(owner) = slot.as_ref() else { return nt_process::STATUS_INVALID_HANDLE; };
        if !matches!(owner.origin, InitialCreationOrigin::Configured) {
            return nt_process::STATUS_INVALID_PARAMETER;
        }
        let lifetime = owner.plan.lifetime();
        drop(slot);
        match crate::thread_suspend::create_initial_thread(self, lifetime, false, binding) {
            crate::thread_suspend::InitialThreadStartOutcome::Committed => {}
            crate::thread_suspend::InitialThreadStartOutcome::RefusedNoEffects(status) => {
                return cancel_creation(self, binding, status);
            }
            crate::thread_suspend::InitialThreadStartOutcome::Retained(status) => return status,
        }
        {
            let table = &*self.thread_runtime.table;
            let runtime = table
                .entries
                .iter()
                .filter_map(|slot| slot.owner())
                .find(|owner| owner.binding() == binding)
                .expect("acknowledged configured initial runtime retained");
            let mut slot = runtime.initial_creation.borrow_mut();
            let owner = slot.as_ref().expect("configured creation receipt retained");
            if let Err(status) = self.pm.commit_initial_thread_creation(&owner.plan) {
                return status;
            }
            *slot = None;
            drop(slot);
        }
        trace_created(lifetime, false);
        0
    }

    pub(super) unsafe fn create_foreign_thread(
        &mut self,
        args: &[u64],
        start: nt_thread_start::Amd64ThreadContext,
        initial_context: nt_thread_start::amd64_context::InitialAmd64Context,
        initial_stack: nt_thread_start::InitialTeb64,
    ) -> u32 {
        let caller_pid = match self.pm_pid_for_pi(self.pi) {
            Some(pid) => pid,
            None => return 0xC000_0008,
        };
        let caller = match self.thread_runtime.executable_by_tid(self.current_tid) {
            Some(runtime) if runtime.pi == self.pi => runtime.binding(),
            _ => return nt_process::STATUS_DEVICE_BUSY,
        };
        let (target_pid, _) = match self.resolve_process_for_access(args[3], 0x0002) {
            Ok(target) => target,
            Err(status) => return status,
        };
        if self.pm.process(target_pid).is_some_and(|process| {
            matches!(
                process.state,
                nt_process::ProcessState::Exiting | nt_process::ProcessState::Terminated
            )
        }) {
            return nt_process::STATUS_PROCESS_IS_TERMINATING;
        }
        if let Some(tid) = self.pm.main_thread(target_pid) {
            if (&*self.thread_runtime.table)
                .entries
                .iter()
                .filter_map(|slot| slot.owner())
                .find(|owner| owner.tid == u64::from(tid))
                .is_some_and(|owner| {
                    owner
                        .initial_creation
                        .try_borrow()
                        .map_or(true, |slot| slot.is_some())
                })
            {
                return nt_process::STATUS_DEVICE_BUSY;
            }
        }
        let plan = match self.pm.prepare_initial_thread_creation(target_pid) {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                return self.create_remote_thread(args, start, initial_context, initial_stack)
            }
            Err(status) => return status,
        };
        let lifetime = plan.lifetime();
        let tid = lifetime.thread_id();
        let binding = match self.thread_runtime.executable_by_tid(u64::from(tid)) {
            Some(runtime) => runtime.binding(),
            None => {
                self.pm
                    .cancel_initial_thread_creation(&plan)
                    .expect("unentered initial creation retains its exact canonical reservation");
                return nt_process::STATUS_DEVICE_BUSY;
            }
        };
        let client = match capture_initial_win32k_client(self, binding) {
            Ok(client) => client,
            Err(status) => {
                self.pm.cancel_initial_thread_creation(&plan)
                    .expect("unentered initial creation retains its canonical reservation");
                return status;
            }
        };
        let origin = ForeignInitialCreation {
            caller,
            handle_out: args[0],
            client_id_out: args[NT_CREATE_THREAD_CLIENT_ID_ARG],
            desired_access: nt_ulong_arg(args[1]),
            create_suspended: nt_boolean_arg(args[NT_CREATE_THREAD_CREATE_SUSPENDED_ARG]),
        };
        {
            let runtime = runtime(self, binding).expect("validated initial runtime");
            let mut slot = runtime.initial_creation.borrow_mut();
            assert!(
                slot.is_none(),
                "initial creation owns its exact fresh runtime"
            );
            *slot = Some(PendingInitialThreadCreation {
                plan,
                handle: None,
                bound: false,
                origin: InitialCreationOrigin::Foreign(origin),
            });
        }
        match create_win32_process_before_loader(self, binding, client) {
            Ok(ProcessCalloutProgress::Ready) => {}
            Ok(ProcessCalloutProgress::Suspended) => return nt_user_callback::STATUS_PENDING as u32,
            Err(status) if callout_may_retire(self, binding) => {
                return cancel_creation(self, binding, status);
            }
            Err(status) => return status,
        }
        self.finish_foreign_initial_thread(binding, InitialCreationDelivery::Queue)
    }

    /// Commit a retained one-shot initial thread only after the exact process callout and GDI
    /// projection have returned. Terminal delivery uses the captured caller rather than whatever
    /// process happens to own the service loop when the provider finally completes.
    unsafe fn finish_foreign_initial_thread(
        &mut self,
        binding: Binding,
        delivery: InitialCreationDelivery,
    ) -> u32 {
        let Some(target) = runtime(self, binding) else { return nt_process::STATUS_INVALID_HANDLE; };
        let Ok(slot) = target.initial_creation.try_borrow() else { return nt_process::STATUS_DEVICE_BUSY; };
        let Some(owner) = slot.as_ref() else { return nt_process::STATUS_INVALID_HANDLE; };
        let InitialCreationOrigin::Foreign(origin) = owner.origin else {
            return nt_process::STATUS_INVALID_PARAMETER;
        };
        let lifetime = owner.plan.lifetime();
        drop(slot);
        let tid = lifetime.thread_id();
        let target_pid = lifetime.process_id();
        let caller_pid = origin.caller.process.pid;
        let create_suspended = origin.create_suspended;
        if delivery == InitialCreationDelivery::Abandoned {
            match crate::thread_suspend::create_initial_thread(
                self, lifetime, create_suspended, binding,
            ) {
                crate::thread_suspend::InitialThreadStartOutcome::Committed => {}
                crate::thread_suspend::InitialThreadStartOutcome::RefusedNoEffects(status) => {
                    return cancel_creation(self, binding, status);
                }
                crate::thread_suspend::InitialThreadStartOutcome::Retained(status) => return status,
            }
            {
                let table = &*self.thread_runtime.table;
                let runtime = table.entries.iter().filter_map(|slot| slot.owner())
                    .find(|owner| owner.binding() == binding)
                    .expect("initial creation runtime retained");
                let mut slot = runtime.initial_creation.borrow_mut();
                let owner = slot.as_ref().expect("acknowledged initial creation retained");
                if let Err(status) = self.pm.commit_initial_thread_creation(&owner.plan) {
                    return status;
                }
                *slot = None;
            }
            if !create_suspended {
                self.observe_desktop_thread_activation(u64::from(tid));
            }
            trace_created(lifetime, create_suspended);
            return 0;
        }
        if runtime(self, origin.caller).is_none()
            || self.capture_process_identity(origin.caller.pi) != Some(origin.caller.process)
        { return nt_process::STATUS_INVALID_HANDLE; }
        let handle_capacity = self.pm.handle_capacity(caller_pid);
        let handle_reservation = match self.pm.try_reserve_handle_slot(caller_pid) {
            Ok(reservation) => reservation,
            Err(status) => return cancel_creation(self, binding, status),
        };
        runtime(self, binding)
            .expect("initial creation runtime retained")
            .initial_creation
            .borrow_mut()
            .as_mut()
            .unwrap()
            .handle = Some(handle_reservation);
        if let Err(status) = self.pm.bind_reserved_handle(
            handle_reservation,
            nt_process::HandleObject::Thread(tid),
            origin.desired_access,
        ) {
            return cancel_creation(self, binding, status);
        }
        runtime(self, binding)
            .expect("initial creation runtime retained")
            .initial_creation
            .borrow_mut()
            .as_mut()
            .unwrap()
            .bound = true;
        match crate::thread_suspend::create_initial_thread(
            self,
            lifetime,
            create_suspended,
            binding,
        ) {
            crate::thread_suspend::InitialThreadStartOutcome::Committed => {}
            crate::thread_suspend::InitialThreadStartOutcome::RefusedNoEffects(status) => {
                return cancel_creation(self, binding, status);
            }
            crate::thread_suspend::InitialThreadStartOutcome::Retained(status) => return status,
        }
        let handle = {
            let table = &*self.thread_runtime.table;
            let runtime = table
                .entries
                .iter()
                .filter_map(|slot| slot.owner())
                .find(|owner| owner.binding() == binding)
                .expect("acknowledged initial runtime retained");
            let mut slot = runtime.initial_creation.borrow_mut();
            let owner = slot
                .as_ref()
                .expect("acknowledged initial creation retained");
            if let Err(status) = self.pm.commit_initial_thread_creation(&owner.plan) {
                return status;
            }
            let handle = match self.pm.publish_reserved_handle(handle_reservation) {
                Ok(handle) => u64::from(handle),
                Err(status) => return status,
            };
            *slot = None;
            handle
        };
        if !create_suspended {
            self.observe_desktop_thread_activation(u64::from(tid));
        }
        self.record_process_handle_insert(caller_pid, handle_capacity);
        match delivery {
            InitialCreationDelivery::Queue => {
                self.queue_write(origin.handle_out, handle);
                if origin.client_id_out != 0 {
                    self.queue_write(origin.client_id_out, target_pid as u64);
                    self.queue_write(origin.client_id_out + 8, tid as u64);
                }
            }
            InitialCreationDelivery::Direct => {
                let pi = origin.caller.pi;
                let mut client_id = [0u8; 16];
                client_id[..8].copy_from_slice(&(target_pid as u64).to_le_bytes());
                client_id[8..].copy_from_slice(&(tid as u64).to_le_bytes());
                if self.process_memory_write_checked(pi, origin.handle_out, &handle.to_le_bytes()).is_err()
                    || (origin.client_id_out != 0
                        && self.process_memory_write_checked(
                            pi, origin.client_id_out, &client_id,
                        ).is_err())
                { return 0xC000_0005; }
            }
            InitialCreationDelivery::Abandoned => unreachable!("abandoned caller has no copyout"),
        }
        let trace = THREAD_LIFECYCLE_TRACE_N.fetch_add(1, Ordering::Relaxed);
        if trace < 4 {
            print_str(b"[thread-life] create caller_pi=");
            print_u64(origin.caller.pi as u64);
            print_str(b" foreign-process-pid=");
            print_str(b" resolved_pid=");
            print_u64(target_pid as u64);
            print_str(b" main_tid=");
            print_u64(tid as u64);
            print_str(b" suspended=");
            print_u64(create_suspended as u64);
            print_str(b" handle=0x");
            print_hex(handle as u32);
            print_str(b" status=0\n");
        }
        trace_created(lifetime, create_suspended);
        0
    }
}

fn trace_created(lifetime: nt_process::ThreadLifetime, create_suspended: bool) {
    print_str(b"[initial-thread-created] pid=");
    print_u64(u64::from(lifetime.process_id()));
    print_str(b" tid=");
    print_u64(u64::from(lifetime.thread_id()));
    print_str(b" thread-generation=");
    print_u64(lifetime.generation());
    print_str(b" suspended=");
    print_u64(create_suspended as u64);
    print_str(b"\n");
}
