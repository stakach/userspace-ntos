//! Provider service ownership for the shared retained SYSTEM mutation engine.

use super::*;
use crate::driver_launch::DeferredRegistryCreate;
use crate::driver_launch::driver_registry_handles::{
    self, OwnedDriverRegistryPublication, RegistryPublicationDispatch,
};
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_process::native_handle::NativeHandleCaller;
use nt_user_host::registry_subject::RegistrySubject;

pub(crate) enum ProviderRegistryResult {
    Ready((i32, u64, u64)),
    Deferred,
}

pub(crate) enum ProviderValueMutation {
    Set { name: String, value_type: u32, data: Vec<u8> },
    Delete { name: String },
}

/// Owns an invisible PM reference to the exact Key while CM and the provider Reply are pending.
/// The mutation payload is copied out of provider scratch memory before the lane is parked.
pub(crate) struct DeferredRegistryExisting {
    caller: NativeHandleCaller,
    dispatch: RegistryPublicationDispatch,
    key_owner: OwnedDriverRegistryPublication,
    lease: SystemHiveKeyLease,
    physical_path: String,
    expected_generation: u64,
    pub(super) mutation: ProviderValueMutation,
}

impl DeferredRegistryExisting {
    pub(crate) unsafe fn admit(
        caller: NativeHandleCaller,
        dispatch: RegistryPublicationDispatch,
        handle: u64,
        mutation: ProviderValueMutation,
    ) -> Result<Self, i32> {
        let slot = driver_registry_handles::driver_registry_handle_slot(caller, handle, 2)?;
        let crate::driver_launch::DriverRegistryHandleTarget::System { lease, physical_path } = slot.target else {
            return Err(0xC000_000Du32 as i32);
        };
        let target = with_provider_process_manager(|pm|
            pm.lookup_native_registry_key_handle(caller, handle, 2))
            .map_err(|status| status as i32)?;
        let current = registry_key_targets::system(target).ok_or(0xC000_0008u32 as i32)?;
        if current.lease != lease
            || nt_hive_core::canon_path(&current.physical_path)
                != nt_hive_core::canon_path(physical_path.as_str())
        {
            return Err(0xC000_0008u32 as i32);
        }
        let mut key_owner = driver_registry_handles::reserve_driver_registry_publication(
            dispatch, caller, 0,
        )?;
        if let Err(status) = key_owner.bind_borrowed_target(target, 0) {
            key_owner.abort().expect("unbound provider Key reservation");
            return Err(status);
        }
        let information = config_manager_query_leased_system_hive_key_information(lease);
        let information = match information {
            Ok(information) if nt_hive_core::canon_path(&information.path)
                == nt_hive_core::canon_path(physical_path.as_str()) => information,
            Ok(_) => {
                key_owner.abort().expect("mismatched provider Key reservation");
                return Err(0xC000_0008u32 as i32);
            }
            Err(status) => {
                key_owner.abort().expect("unqueried provider Key reservation");
                return Err(status);
            }
        };
        Ok(Self {
            caller, dispatch, key_owner, lease,
            physical_path: nt_hive_core::canon_path(physical_path.as_str()),
            expected_generation: information.mount_generation, mutation,
        })
    }

    unsafe fn abort(&mut self) -> Result<(), i32> {
        self.key_owner.abort()
    }
}

pub(super) enum ProviderAdmission {
    Create(DeferredRegistryCreate),
    Existing(DeferredRegistryExisting),
}

impl ProviderAdmission {
    fn caller(&self) -> NativeHandleCaller {
        match self { Self::Create(value) => value.caller, Self::Existing(value) => value.caller }
    }

    fn dispatch(&self) -> RegistryPublicationDispatch {
        match self { Self::Create(value) => value.dispatch, Self::Existing(value) => value.dispatch }
    }

    unsafe fn cleanup(&mut self, publish: bool) -> Result<(), i32> {
        match self {
            Self::Create(value) => {
                value.release_parent()?;
                if !publish { value.abort_child()?; }
            }
            Self::Existing(value) => value.abort()?,
        }
        Ok(())
    }

    unsafe fn abort_child(&mut self) -> Result<(), i32> {
        match self { Self::Create(value) => value.abort_child(), Self::Existing(_) => Ok(()) }
    }

    unsafe fn release_existing(&mut self) -> Result<(), i32> {
        match self { Self::Create(_) => Ok(()), Self::Existing(value) => value.abort() }
    }

    unsafe fn return_child_pending(&mut self) -> Result<Option<u64>, i32> {
        match self {
            Self::Create(value) => value.return_child_pending().map(Some),
            Self::Existing(_) => Ok(None),
        }
    }
}

pub(super) struct ProviderCaller {
    pub(super) admission: ProviderAdmission,
    pub(super) logical: Option<ProviderLogicalCaller>,
    subject: Option<RegistrySubject>,
    reference: NativeThreadProcessReference,
    reply: u64,
    token: u64,
    child_handle: Option<u64>,
    reply_entered: bool,
}

static LAST_TOKEN: AtomicU64 = AtomicU64::new(0);

pub(crate) unsafe fn submit_provider(
    channel: &spawn_hosts::PumpChannel,
    admission: DeferredRegistryCreate,
    subject: RegistrySubject,
) -> ProviderRegistryResult {
    submit_provider_inner(channel, ProviderAdmission::Create(admission), Some(subject))
}

pub(crate) unsafe fn submit_provider_existing(
    channel: &spawn_hosts::PumpChannel,
    admission: DeferredRegistryExisting,
) -> ProviderRegistryResult {
    submit_provider_inner(channel, ProviderAdmission::Existing(admission), None)
}

unsafe fn submit_provider_inner(
    channel: &spawn_hosts::PumpChannel,
    mut admission: ProviderAdmission,
    mut subject: Option<RegistrySubject>,
) -> ProviderRegistryResult {
    let _durable = allocator::enter_durable();
    let admitted = (|| {
        if subject.as_ref().is_some_and(|subject| admission.caller() != subject.caller())
            || crate::driver_launch::driver_registry_handles::RegistryPublicationDispatch::capture(channel)
                .map_err(|status| status as i32)? != admission.dispatch() {
            return Err(0xC000_0008u32 as i32);
        }
        let reply = runtime::current_reply(admission.dispatch().route())
            .map_err(|_| 0xC000_0008u32 as i32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32 as i32)?; }
        let token = LAST_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |value| value.checked_add(1)).map_err(|_| 0xC000_009Au32 as i32)? + 1;
        let reference = with_provider_process_manager(|pm| {
            let requestor = pm.capture_native_handle_caller(
                admission.caller().original_thread(), nt_types::AccessMode::KernelMode,
            )?;
            pm.reference_native_requestor(requestor)
        })
            .map_err(|status| status as i32)?;
        Ok((reply, token, index, reference))
    })();
    let (reply, token, index, reference) = match admitted {
        Ok(admitted) => admitted,
        Err(status) => {
            admission.cleanup(false).expect("unsubmitted provider registry owner");
            if let Some(mut subject) = subject.take() {
                with_provider_security_managers(|_, tokens| subject.release(tokens))
                    .expect("unsubmitted provider subject");
            }
            return ProviderRegistryResult::Ready((status, 0, 0));
        }
    };
    let route = admission.dispatch().route();
    let caller = ProviderCaller {
        admission, logical: channel.logical_caller, subject, reference,
        reply, token, child_handle: None, reply_entered: false,
    };
    let work = Some(Work {
        caller: Caller::Provider(caller), phase: Phase::ProviderAdmit,
        prepared: None, journal: None, receipt: None, opening: None, status: 0,
        cancelled: false, commit_entered: false, published: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = match index {
        Some(index) => { rows[index] = work; index }
        None => { let index = rows.len(); rows.push(work); index }
    };
    // Publish all semantic owners before changing the exact physical service lane.
    if runtime::park_registry_service(route, token).is_err() {
        let mut work = (&mut *core::ptr::addr_of_mut!(WORK))[index].take().unwrap();
        let Caller::Provider(caller) = &mut work.caller else { unreachable!() };
        caller.cleanup(false).expect("unparked provider registry cleanup");
        caller.admission.release_existing().expect("unparked provider Key owner");
        with_provider_process_manager(|pm| caller.reference.release(pm))
            .expect("unparked provider registry actor");
        return ProviderRegistryResult::Ready((0xC000_009Au32 as i32, 0, 0));
    }
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    ProviderRegistryResult::Deferred
}

impl ProviderCaller {
    pub(super) unsafe fn cancelled(&self) -> bool {
        self.service_cancelled() || with_provider_process_manager(|pm| {
            let thread = self.admission.caller().original_thread();
            Ok(pm.thread(thread.thread_id())
                .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                || pm.process(thread.process_id())
                    .is_some_and(|process| process.state == nt_process::ProcessState::Terminated))
        }).unwrap_or(false)
    }

    unsafe fn service_cancelled(&self) -> bool {
        runtime::registry_service_cancelled(self.admission.dispatch().route(),
            self.admission.dispatch().dispatch(), self.reply, self.token)
    }

    pub(super) unsafe fn begin(&self) -> Result<CmMutationBeginAttempt<()>, i32> {
        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32 as i32)?;
        let (expected_generation, mutation) = match &self.admission {
            ProviderAdmission::Create(value) => (
                value.expected_generation,
                SystemHiveMutation::CreateChildRelative {
                    parent: value.parent_lease,
                    name: &value.leaf,
                    class_name: value.class_name.as_deref(),
                    descriptor: &value.descriptor,
                    volatile: value.volatile,
                },
            ),
            ProviderAdmission::Existing(value) => (
                value.expected_generation,
                match &value.mutation {
                    ProviderValueMutation::Set { name, value_type, data } => SystemHiveMutation::SetValue {
                        path: &value.physical_path, name, value_type: *value_type, data,
                    },
                    ProviderValueMutation::Delete { name } => SystemHiveMutation::DeleteValue {
                        path: &value.physical_path, name,
                    },
                },
            ),
        };
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS))
            .reserve(mount, expected_generation, &[mutation], ())
            .map_err(|(status, ())| status)
    }

    pub(super) unsafe fn bind_target(&mut self, target: KeyRef) -> Result<(), i32> {
        if self.cancelled() {
            let retired = with_provider_process_manager(|pm|
                Ok(registry_key_targets::take_unreferenced(pm, target)))
                .expect("retained provider PM");
            if let Some(retired) = retired { registry_key_targets::retire(retired); }
            return Err(0xC000_0120u32 as i32);
        }
        let ProviderAdmission::Create(admission) = &mut self.admission else {
            unreachable!("existing provider Key does not bind a child")
        };
        admission.bind_child(target)
    }

    pub(super) unsafe fn cleanup(&mut self, publish: bool) -> Result<(), i32> {
        if let ProviderAdmission::Create(value) = &mut self.admission {
            value.release_parent()?;
            if !publish { value.abort_child()?; }
        }
        if let Some(mut subject) = self.subject.take() {
            with_provider_security_managers(|_, tokens| subject.release(tokens))
                .expect("retained provider registry subject");
        }
        Ok(())
    }

    pub(super) unsafe fn finish(&mut self, status: u32, publish: bool) -> Result<bool, i32> {
        let dispatch = self.admission.dispatch();
        if self.reply_entered && runtime::reconcile_registry_service_reply(
            dispatch.route(), dispatch.dispatch(), self.reply, self.token,
        ).map_err(|_| 0xC000_00A3u32 as i32)? {
            self.admission.release_existing()?;
            runtime::retire_stopped_acknowledged_registry_service(
                dispatch.route(), dispatch.dispatch(), self.reply, self.token,
            ).map_err(|_| 0xC000_00A3u32 as i32)?;
            with_provider_process_manager(|pm| self.reference.release(pm))
                .expect("acknowledged provider registry actor");
            return Ok(true);
        }
        if self.service_cancelled() {
            if let Some(handle) = self.child_handle {
                crate::driver_launch::driver_registry_handles::abort_driver_registry_publication(
                    dispatch, self.admission.caller(), handle,
                )?;
                self.child_handle = None;
            } else {
                self.admission.abort_child()?;
            }
            self.admission.release_existing()?;
            runtime::acknowledge_registry_service_cancellation(dispatch.route(),
                dispatch.dispatch(), self.reply, self.token)
                .map_err(|_| 0xC000_00A3u32 as i32)?;
            with_provider_process_manager(|pm| self.reference.release(pm))
                .expect("stopped provider registry actor");
            return Ok(true);
        }
        if self.reply_entered { return Err(0xC000_00A3u32 as i32); }
        if publish && status == 0 && self.child_handle.is_none() {
            self.child_handle = self.admission.return_child_pending()?;
        } else if status != 0 {
            self.admission.abort_child()?;
        }
        self.reply_entered = true;
        runtime::wake_registry_service(dispatch.route(),
            dispatch.dispatch(), self.reply, self.token,
            status as i32, self.child_handle.unwrap_or(0),
            u64::from(status == 0 && matches!(&self.admission, ProviderAdmission::Create(_))))
            .map_err(|_| 0xC000_00A3u32 as i32)?;
        self.admission.release_existing()?;
        runtime::retire_stopped_acknowledged_registry_service(
            dispatch.route(), dispatch.dispatch(), self.reply, self.token,
        ).map_err(|_| 0xC000_00A3u32 as i32)?;
        with_provider_process_manager(|pm| self.reference.release(pm))
            .expect("completed provider registry actor");
        Ok(true)
    }
}
