//! A kernel provider (a hosted driver or win32k) waiting for its mutable-hive edit.
//!
//! NT lets a driver's `ZwSetValueKey`/`ZwDeleteValueKey` and win32k's registry writes reach the
//! hive log like any hosted caller's. On the native stack the record must be anchored in the
//! native WAL first, so the provider's service lane parks here, exactly as a SYSTEM edit parks
//! in `registry_mutation_work`. The row keeps the lane's Reply and service token, a reference
//! to the requesting thread, and a hidden handle to the exact Key until the lane is woken with
//! the real status. An uncertain effect keeps every owner; nothing is replayed.

use super::*;
use crate::driver_launch::driver_registry_handles::{
    reserve_driver_registry_publication, OwnedDriverRegistryPublication,
    RegistryPublicationDispatch,
};
use crate::registry_mutation_work::{ProviderRegistryResult, ProviderValueMutation};
use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::mutable_hive_edit_route::{EditOwner, STATUS_DEVICE_NOT_READY};
use nt_process::native_handle::NativeHandleCaller;

pub(crate) struct ProviderCaller {
    caller: NativeHandleCaller,
    dispatch: RegistryPublicationDispatch,
    key_owner: OwnedDriverRegistryPublication,
    reference: NativeThreadProcessReference,
    reply: u64,
    token: u64,
    reply_entered: bool,
}

/// How a provider's edit of an executive-held Key proceeds.
pub(crate) enum ProviderEditAdmission {
    /// Not a mutable-hive Key, or its edit is journalled inside the call.
    Inline,
    /// The boot source is draining: [`STATUS_DEVICE_NOT_READY`], with no effect.
    NotReady,
    /// The lane parks in the native WAL work until the exact record is anchored.
    NativeWal(ResolvedHiveKey),
}

/// The same route policy as a hosted caller's edit of `key`.
pub(crate) unsafe fn provider_edit_admission(key: KeyRef) -> ProviderEditAdmission {
    let Ok(handler) = crate::service_sec_image::registry_live_handler() else {
        return ProviderEditAdmission::Inline;
    };
    let Some(mutable) = handler.mutable_registry_key(key) else {
        return ProviderEditAdmission::Inline;
    };
    match handler.mutable_edit_owner() {
        EditOwner::NativeWal => ProviderEditAdmission::NativeWal(mutable),
        EditOwner::NotReady => ProviderEditAdmission::NotReady,
        EditOwner::BootWal | EditOwner::LegacyJournal => ProviderEditAdmission::Inline,
    }
}

pub(crate) const PROVIDER_EDIT_NOT_READY: ProviderRegistryResult =
    ProviderRegistryResult::Ready((STATUS_DEVICE_NOT_READY as i32, 0, 0));

/// Park the provider's service lane with its edit of `key`. Every owner is published before
/// the lane parks; a refusal releases them and leaves the lane's Reply current.
pub(crate) unsafe fn submit_provider_edit(
    caller: NativeHandleCaller,
    dispatch: RegistryPublicationDispatch,
    key_ref: KeyRef,
    key: ResolvedHiveKey,
    mutation: ProviderValueMutation,
) -> ProviderRegistryResult {
    let ready = |status: u32| ProviderRegistryResult::Ready((status as i32, 0, 0));
    let _durable = allocator::enter_durable();
    let handler = match crate::service_sec_image::registry_live_handler() {
        Ok(handler) => handler,
        Err(status) => return ready(status),
    };
    let edit = match mutation {
        ProviderValueMutation::Set { name, value_type, data } => {
            let Some(value_type) = RegistryValueType::from_u32(value_type) else {
                return ready(nt_fs::STATUS_INVALID_PARAMETER);
            };
            ExistingEdit::SetValue { name, value_type, data }
        }
        ProviderValueMutation::Delete { name } => ExistingEdit::DeleteValue { name },
    };
    let (pending, log_path) = match pending_existing_edit(handler, key, edit) {
        Ok(parts) => parts,
        Err(status) => return ready(status),
    };
    let mut key_owner = match reserve_driver_registry_publication(dispatch, caller, 0) {
        Ok(owner) => owner,
        Err(status) => return ready(status as u32),
    };
    if let Err(status) = key_owner.bind_borrowed_target(key_ref, 0) {
        key_owner.abort().expect("unbound provider mutable Key reservation");
        return ready(status as u32);
    }
    let admitted = (|| {
        let reply = runtime::current_reply(dispatch.route()).map_err(|_| STATUS_INVALID_HANDLE)?;
        let rows = &mut *core::ptr::addr_of_mut!(WORK);
        let index = rows.iter().enumerate().find_map(|(index, row)|
            (row.is_none() && EXECUTING_INDEX.load(Ordering::Relaxed) != index as u64)
                .then_some(index));
        if index.is_none() { rows.try_reserve(1).map_err(|_| 0xC000_009Au32)?; }
        let token = runtime::next_service_wait_token().map_err(|_| 0xC000_009Au32)?;
        let mut reference = crate::with_provider_process_manager(|pm| {
            let requestor = pm.capture_native_handle_caller(
                caller.original_thread(), nt_types::AccessMode::KernelMode)?;
            pm.reference_native_requestor(requestor)
        })?;
        match reserve_order() {
            Ok(order) => Ok((reply, index, token, reference, order)),
            Err(status) => {
                crate::with_provider_process_manager(|pm| reference.release(pm))
                    .expect("unsubmitted provider mutable caller");
                Err(status)
            }
        }
    })();
    let (reply, index, token, reference, order) = match admitted {
        Ok(admitted) => admitted,
        Err(status) => {
            key_owner.abort().expect("unsubmitted provider mutable Key");
            return ready(status);
        }
    };
    let work = Some(Work {
        order, hive: key.hive, reported: None, log_path,
        pending: Some(pending), prepared: None, journal_id: None, receipt: None,
        installation: None,
        caller: Caller::Provider(ProviderCaller {
            caller, dispatch, key_owner, reference, reply, token, reply_entered: false,
        }),
        phase: Phase::Prepare, status: 0, cancelled: false,
    });
    let rows = &mut *core::ptr::addr_of_mut!(WORK);
    let index = match index {
        Some(index) => { rows[index] = work; index }
        None => { rows.push(work); rows.len() - 1 }
    };
    if runtime::park_retained_service(dispatch.route(), token).is_err() {
        let work = rows[index].take().expect("unparked provider mutable row");
        let Caller::Provider(mut caller) = work.caller else { unreachable!() };
        caller.key_owner.abort().expect("unparked provider mutable Key");
        crate::with_provider_process_manager(|pm| caller.reference.release(pm))
            .expect("unparked provider mutable caller");
        return ready(0xC000_009A);
    }
    PENDING.fetch_add(1, Ordering::Release);
    NEXT.store(monotonic_time_100ns(), Ordering::Release);
    ProviderRegistryResult::Deferred
}

impl ProviderCaller {
    unsafe fn service_cancelled(&self) -> bool {
        runtime::retained_service_cancelled(self.dispatch.route(), self.dispatch.dispatch(),
            self.reply, self.token)
    }

    pub(super) unsafe fn cancelled(&self) -> bool {
        self.service_cancelled() || crate::with_provider_process_manager(|pm| {
            let thread = self.caller.original_thread();
            Ok(pm.thread(thread.thread_id())
                .is_some_and(|thread| thread.state == nt_process::ThreadState::Terminated)
                || pm.process(thread.process_id())
                    .is_some_and(|process| process.state == nt_process::ProcessState::Terminated))
        }).unwrap_or(false)
    }

    /// Release the Key and the requestor once the lane's Reply is settled.
    unsafe fn retire(&mut self) -> Result<(), u32> {
        self.key_owner.abort().map_err(|status| status as u32)?;
        runtime::retire_stopped_acknowledged_retained_service(self.dispatch.route(),
            self.dispatch.dispatch(), self.reply, self.token).map_err(|_| 0xC000_00A3u32)?;
        crate::with_provider_process_manager(|pm| self.reference.release(pm))
            .expect("completed provider mutable caller");
        Ok(())
    }

    /// Wake the parked lane with the edit's real status, or acknowledge its cancellation.
    /// A Reply that may have entered is reconciled, never sent twice.
    pub(super) unsafe fn finish(&mut self, status: u32) -> Result<(), u32> {
        let (route, dispatch) = (self.dispatch.route(), self.dispatch.dispatch());
        if self.reply_entered && runtime::reconcile_retained_service_reply(
            route, dispatch, self.reply, self.token,
        ).map_err(|_| 0xC000_00A3u32)? {
            return self.retire();
        }
        if self.service_cancelled() {
            self.key_owner.abort().map_err(|status| status as u32)?;
            runtime::acknowledge_retained_service_cancellation(route, dispatch,
                self.reply, self.token).map_err(|_| 0xC000_00A3u32)?;
            crate::with_provider_process_manager(|pm| self.reference.release(pm))
                .expect("stopped provider mutable caller");
            return Ok(());
        }
        if self.reply_entered { return Err(0xC000_00A3); }
        self.reply_entered = true;
        runtime::wake_registry_service(route, dispatch, self.reply, self.token,
            status as i32, 0, 0).map_err(|_| 0xC000_00A3u32)?;
        self.retire()
    }
}
