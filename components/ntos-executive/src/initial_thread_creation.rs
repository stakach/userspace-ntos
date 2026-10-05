//! Initial-thread admission against the process's pre-created mechanism.

use super::*;

#[derive(Debug)]
pub(crate) struct PendingInitialThreadCreation {
    plan: nt_process::InitialThreadCreationPlan,
    handle: Option<nt_process::HandleReservation>,
    bound: bool,
}

type Binding = nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>;

unsafe fn runtime(handler: &ExecNtHandler, binding: Binding) -> Option<&HostedThreadRuntimeOwner> {
    (&*handler.thread_runtime.table)
        .entries
        .iter()
        .filter_map(|slot| slot.owner())
        .find(|owner| owner.binding() == binding)
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
        let lifetime = plan.lifetime();
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
            });
        }
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
            });
        }
        let create_suspended = nt_boolean_arg(args[NT_CREATE_THREAD_CREATE_SUSPENDED_ARG]);
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
            nt_ulong_arg(args[1]),
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
        self.queue_write(args[0], handle);
        let cid_ptr = args[NT_CREATE_THREAD_CLIENT_ID_ARG];
        if cid_ptr != 0 {
            self.queue_write(cid_ptr, target_pid as u64);
            self.queue_write(cid_ptr + 8, tid as u64);
        }
        let trace = THREAD_LIFECYCLE_TRACE_N.fetch_add(1, Ordering::Relaxed);
        if trace < 4 {
            print_str(b"[thread-life] create caller_pi=");
            print_u64(self.pi as u64);
            print_str(b" foreign_process=0x");
            print_hex(args[3] as u32);
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
