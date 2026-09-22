//! Provider service ownership for the shared retained SYSTEM mutation engine.

use super::*;
use crate::driver_launch::DeferredRegistryCreate;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_user_host::registry_subject::RegistrySubject;

pub(crate) enum ProviderRegistryResult {
    Ready((i32, u64, u64)),
    Deferred,
}

pub(super) struct ProviderCaller {
    pub(super) admission: DeferredRegistryCreate,
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
    mut admission: DeferredRegistryCreate,
    mut subject: RegistrySubject,
) -> ProviderRegistryResult {
    let _durable = allocator::enter_durable();
    let admitted = (|| {
        if admission.caller != subject.caller()
            || crate::driver_launch::driver_registry_handles::RegistryPublicationDispatch::capture(channel)
                .map_err(|status| status as i32)? != admission.dispatch {
            return Err(0xC000_0008u32 as i32);
        }
        let reply = runtime::current_reply(admission.dispatch.route())
            .map_err(|_| 0xC000_0008u32 as i32)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32 as i32)?; }
        let token = LAST_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |value| value.checked_add(1)).map_err(|_| 0xC000_009Au32 as i32)? + 1;
        let reference = with_provider_process_manager(|pm| pm.reference_native_requestor(admission.caller))
            .map_err(|status| status as i32)?;
        Ok((reply, token, index, reference))
    })();
    let (reply, token, index, reference) = match admitted {
        Ok(admitted) => admitted,
        Err(status) => {
            admission.abort_child().expect("unsubmitted provider child");
            admission.release_parent().expect("unsubmitted provider parent");
            with_provider_security_managers(|_, tokens| subject.release(tokens))
                .expect("unsubmitted provider subject");
            return ProviderRegistryResult::Ready((status, 0, 0));
        }
    };
    let route = admission.dispatch.route();
    let caller = ProviderCaller {
        admission, logical: channel.logical_caller, subject: Some(subject), reference,
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
            let thread = self.admission.caller.original_thread();
            Ok(pm.thread(thread.thread_id())
                .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                || pm.process(thread.process_id())
                    .is_some_and(|process| process.state == nt_process::ProcessState::Terminated))
        }).unwrap_or(false)
    }

    unsafe fn service_cancelled(&self) -> bool {
        runtime::registry_service_cancelled(self.admission.dispatch.route(),
            self.admission.dispatch.dispatch(), self.reply, self.token)
    }

    pub(super) unsafe fn begin(&self) -> Result<CmMutationBeginAttempt<()>, i32> {
        let mount = LIVE_CONFIG_MANAGER_SYSTEM_MOUNT.ok_or(0xC000_00A3u32 as i32)?;
        (&mut *core::ptr::addr_of_mut!(ATTEMPTS)).reserve(
            mount, self.admission.expected_generation,
            &[SystemHiveMutation::CreateChildRelative {
                parent: self.admission.parent_lease,
                name: &self.admission.leaf,
                class_name: self.admission.class_name.as_deref(),
                descriptor: &self.admission.descriptor,
                volatile: self.admission.volatile,
            }], (),
        ).map_err(|(status, ())| status)
    }

    pub(super) unsafe fn bind_target(&mut self, target: KeyRef) -> Result<(), i32> {
        if self.cancelled() {
            let retired = with_provider_process_manager(|pm|
                Ok(registry_key_targets::take_unreferenced(pm, target)))
                .expect("retained provider PM");
            if let Some(retired) = retired { registry_key_targets::retire(retired); }
            return Err(0xC000_0120u32 as i32);
        }
        self.admission.bind_child(target)
    }

    pub(super) unsafe fn cleanup(&mut self, publish: bool) -> Result<(), i32> {
        self.admission.release_parent()?;
        if !publish { self.admission.abort_child()?; }
        if let Some(mut subject) = self.subject.take() {
            with_provider_security_managers(|_, tokens| subject.release(tokens))
                .expect("retained provider registry subject");
        }
        Ok(())
    }

    pub(super) unsafe fn finish(&mut self, status: u32, publish: bool) -> Result<bool, i32> {
        if self.reply_entered && runtime::reconcile_registry_service_reply(
            self.admission.dispatch.route(), self.admission.dispatch.dispatch(), self.reply, self.token,
        ).map_err(|_| 0xC000_00A3u32 as i32)? {
            runtime::retire_stopped_acknowledged_registry_service(
                self.admission.dispatch.route(), self.admission.dispatch.dispatch(), self.reply, self.token,
            ).map_err(|_| 0xC000_00A3u32 as i32)?;
            with_provider_process_manager(|pm| self.reference.release(pm))
                .expect("acknowledged provider registry actor");
            return Ok(true);
        }
        if self.service_cancelled() {
            if let Some(handle) = self.child_handle {
                crate::driver_launch::driver_registry_handles::abort_driver_registry_publication(
                    self.admission.dispatch, self.admission.caller, handle,
                )?;
                self.child_handle = None;
            } else {
                self.admission.abort_child()?;
            }
            runtime::acknowledge_registry_service_cancellation(self.admission.dispatch.route(),
                self.admission.dispatch.dispatch(), self.reply, self.token)
                .map_err(|_| 0xC000_00A3u32 as i32)?;
            with_provider_process_manager(|pm| self.reference.release(pm))
                .expect("stopped provider registry actor");
            return Ok(true);
        }
        if self.reply_entered { return Err(0xC000_00A3u32 as i32); }
        if publish && status == 0 && self.child_handle.is_none() {
            self.child_handle = Some(self.admission.return_child_pending()?);
        } else if status != 0 {
            self.admission.abort_child()?;
        }
        self.reply_entered = true;
        runtime::wake_registry_service(self.admission.dispatch.route(),
            self.admission.dispatch.dispatch(), self.reply, self.token,
            status as i32, self.child_handle.unwrap_or(0), u64::from(status == 0))
            .map_err(|_| 0xC000_00A3u32 as i32)?;
        runtime::retire_stopped_acknowledged_registry_service(
            self.admission.dispatch.route(), self.admission.dispatch.dispatch(), self.reply, self.token,
        ).map_err(|_| 0xC000_00A3u32 as i32)?;
        with_provider_process_manager(|pm| self.reference.release(pm))
            .expect("completed provider registry actor");
        Ok(true)
    }
}
