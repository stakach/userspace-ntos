//! Canonical PM Key publications for isolated drivers. CM owns all lease retries.

use super::*;
use nt_process::{native_handle::NativeHandleCaller, RegistryKeyHandlePublication};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegistryPublicationDispatch {
    route: nt_component_suspension::peer_registry::PeerRoute,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
}

impl RegistryPublicationDispatch {
    pub(crate) fn route(self) -> nt_component_suspension::peer_registry::PeerRoute {
        self.route
    }

    pub(crate) fn dispatch(self) -> nt_component_suspension::LaneDispatchIdentity {
        self.dispatch
    }

    pub(crate) unsafe fn capture(channel: &crate::spawn_hosts::PumpChannel) -> Result<Self, u32> {
        use crate::spawn_hosts::shared_ingress::owner::runtime;
        crate::provider_registry_caller::resolve(channel)?;
        let route = runtime::channel_route(channel)
            .map_err(|_| nt_process::STATUS_INVALID_HANDLE)?
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        let dispatch = runtime::dispatch(route).map_err(|_| nt_process::STATUS_INVALID_HANDLE)?;
        Ok(Self { route, dispatch })
    }
}

struct Pending {
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    publication: RegistryKeyHandlePublication,
}

static mut PENDING: Vec<Option<Pending>> = Vec::new();

unsafe fn pending_index(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    value: u64,
) -> Result<usize, i32> {
    (&*core::ptr::addr_of!(PENDING))
        .iter()
        .position(|row| {
            row.as_ref().is_some_and(|row| {
                row.dispatch == dispatch && row.caller == caller && row.publication.value() == value
            })
        })
        .ok_or(STATUS_INVALID_HANDLE)
}

#[must_use = "an owned publication must be aborted or returned to the client publication owner"]
pub(crate) struct OwnedDriverRegistryPublication {
    pending: Option<Pending>,
}

pub(crate) unsafe fn reserve_driver_registry_publication(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    attributes: u32,
) -> Result<OwnedDriverRegistryPublication, i32> {
    let _durable = crate::allocator::enter_durable();
    let publication = crate::with_provider_process_manager(|pm| {
        pm.reserve_native_registry_key_handle(caller, attributes)
    })
    .map_err(|status| status as i32)?;
    Ok(OwnedDriverRegistryPublication {
        pending: Some(Pending {
            dispatch,
            caller,
            publication,
        }),
    })
}

pub(crate) unsafe fn take_pending_owned(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    value: u64,
) -> Result<OwnedDriverRegistryPublication, i32> {
    let index = pending_index(dispatch, caller, value)?;
    Ok(OwnedDriverRegistryPublication {
        pending: (&mut *core::ptr::addr_of_mut!(PENDING))[index].take(),
    })
}

impl OwnedDriverRegistryPublication {
    /// Consume the acquired target even on failure; the reservation remains owned.
    pub(crate) unsafe fn bind_reserved_target(
        &mut self,
        target: u32,
        grant: u32,
    ) -> Result<(), i32> {
        let result = self.bind_borrowed_target(target, grant);
        if result.is_err() {
            release_target(target);
        }
        result
    }

    /// A handle lookup borrows its target; a failed bind cannot retire that existing Key.
    unsafe fn bind_borrowed_target(&mut self, target: u32, grant: u32) -> Result<(), i32> {
        let row = self.pending.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
        crate::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(row.caller)?;
            row.publication.bind(pm, target, grant)
        })
        .map_err(|status| status as i32)
    }

    pub(crate) unsafe fn authorize_bound_grant(&mut self, grant: u32) -> Result<(), i32> {
        let row = self.pending.as_mut().ok_or(STATUS_INVALID_HANDLE)?;
        crate::with_provider_process_manager(|pm| {
            pm.validate_native_handle_caller(row.caller)?;
            row.publication.authorize_bound_grant(pm, grant)
        })
        .map_err(|status| status as i32)
    }

    pub(crate) unsafe fn abort(&mut self) -> Result<(), i32> {
        let Some(row) = self.pending.as_mut() else {
            return Ok(());
        };
        let retired = crate::with_provider_process_manager(|pm| row.publication.abort(pm))
            .map_err(|status| status as i32)?;
        self.pending = None;
        if let Some(target) = retired {
            release_target(target);
        }
        Ok(())
    }

    /// Restore the client PUBLISH owner after all in-flight CM and admission work completes.
    /// Allocation failure leaves ownership here for a later retry.
    pub(crate) unsafe fn return_pending(&mut self) -> Result<u64, i32> {
        let row = self.pending.as_ref().ok_or(STATUS_INVALID_HANDLE)?;
        if crate::spawn_hosts::shared_ingress::owner::runtime::dispatch(row.dispatch.route())
            .ok() != Some(row.dispatch.dispatch())
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let value = row.publication.value();
        let _durable = crate::allocator::enter_durable();
        let rows = &mut *core::ptr::addr_of_mut!(PENDING);
        let slot = rows.iter().position(Option::is_none).unwrap_or(rows.len());
        if slot == rows.len() {
            rows.try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            rows.push(self.pending.take());
        } else {
            rows[slot] = self.pending.take();
        }
        Ok(value)
    }
}

pub(crate) unsafe fn publish_driver_registry_handle(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    value: u64,
) -> Result<(), i32> {
    let index = pending_index(dispatch, caller, value)?;
    crate::with_provider_process_manager(|pm| {
        pm.validate_native_handle_caller(caller)?;
        (&mut *core::ptr::addr_of_mut!(PENDING))[index]
            .as_mut()
            .unwrap()
            .publication
            .publish(pm)?;
        Ok(())
    })
    .map_err(|status| status as i32)?;
    (&mut *core::ptr::addr_of_mut!(PENDING))[index] = None;
    Ok(())
}

pub(crate) unsafe fn abort_driver_registry_publication(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    value: u64,
) -> Result<(), i32> {
    let index = pending_index(dispatch, caller, value)?;
    let retired = crate::with_provider_process_manager(|pm| {
        let target = (&mut *core::ptr::addr_of_mut!(PENDING))[index]
            .as_mut()
            .unwrap()
            .publication
            .abort(pm)?;
        Ok(target)
    })
    .map_err(|status| status as i32)?;
    (&mut *core::ptr::addr_of_mut!(PENDING))[index] = None;
    if let Some(retired) = retired {
        release_target(retired);
    }
    Ok(())
}

fn target_snapshot(target: u32) -> Result<DriverRegistryHandleTarget, i32> {
    if let Some(system) = crate::registry_key_targets::system(target) {
        let mut physical_path = HostedAscii::empty();
        if !physical_path.push_str(&system.physical_path) {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(DriverRegistryHandleTarget::System {
            lease: system.lease,
            physical_path,
        })
    } else if let Some(runtime) = crate::registry_key_targets::runtime(target) {
        let mut path = HostedAscii::empty();
        if !path.push_str(&runtime.path) {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(DriverRegistryHandleTarget::Generic {
            key: runtime.key,
            path,
        })
    } else {
        let full = unsafe { driver_registry_live_handler()? }
            .registry_target_path(target)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let mut path = HostedAscii::empty();
        if !path.push_str(&full) {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        Ok(DriverRegistryHandleTarget::Hosted { key: target, path })
    }
}

pub(crate) unsafe fn driver_registry_handle_slot(
    caller: NativeHandleCaller,
    value: u64,
    desired_access: u32,
) -> Result<DriverRegistryHandleSlot, i32> {
    let target = crate::with_provider_process_manager(|pm| {
        pm.lookup_native_registry_key_handle(caller, value, desired_access)
    })
    .map_err(|status| status as i32)?;
    Ok(DriverRegistryHandleSlot {
        handle: value,
        target: target_snapshot(target)?,
    })
}

/// Authorize against an owned lease before installing a shared target. No store or PM borrow
/// survives CM IPC. Failed/uncertain CM effects remain in the common lease journal.
pub(crate) unsafe fn open_driver_registry_handle(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    root: Option<DriverRegistryHandleTarget>,
    attributes: u32,
    authorize: impl FnOnce(DriverRegistryHandleTarget) -> Result<u32, i32>,
) -> Result<DriverRegistryHandleSlot, i32> {
    let _durable = crate::allocator::enter_durable();
    if path.is_empty() && root.is_none() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut publication = reserve_driver_registry_publication(dispatch, caller, attributes)?;
    let outcome = (|| {
        let key = if let Some(root) = root {
            acquire_relative_target(root, path.as_str())?
        } else if hosted_registry_path_is_system(path) {
            let opened = crate::config_manager_open_system_hive_key(path.as_str())?;
            match crate::registry_key_targets::install_system(crate::CmSystemKeyTarget {
                lease: opened.lease,
                physical_path: opened.physical_path,
            }) {
                Ok(key) => key,
                Err(status) => {
                    let _ = crate::config_manager_retire_system_hive_key(opened.lease);
                    return Err(status as i32);
                }
            }
        } else if let Ok(handler) = driver_registry_live_handler() {
            handler
                .acquire_registry_target(path.as_str())
                .map_err(|status| status as i32)?
        } else {
            let key = crate::config_manager_open_key_id(path.as_str())?;
            crate::registry_key_targets::install_runtime(String::from(path.as_str()), key)
                .map_err(|status| status as i32)?
        };
        publication.bind_reserved_target(key, 0)?;
        let target = target_snapshot(key)?;
        let grant = authorize(target)?;
        publication.authorize_bound_grant(grant)?;
        let value = publication.return_pending()?;
        Ok(DriverRegistryHandleSlot {
            handle: value,
            target,
        })
    })();
    if outcome.is_err() {
        publication.abort().expect("failed open retains exact PM reservation");
    }
    outcome
}

/// The temporary bound entry keeps the exact KeyRef alive even if another thread closes the
/// supplied handle during a CM exchange. The caller never re-looks up that numeric handle.
pub(crate) unsafe fn with_registry_root<T>(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    handle: Option<u64>,
    operation: impl FnOnce(Option<DriverRegistryHandleTarget>) -> Result<T, i32>,
) -> Result<T, i32> {
    let Some(handle) = handle else {
        return operation(None);
    };
    let mut retained = reserve_driver_registry_publication(dispatch, caller, 0)?;
    let acquired = crate::with_provider_process_manager(|pm| {
        pm.lookup_native_registry_key_handle(caller, handle, 0)
    })
    .map_err(|status| status as i32);
    let result = acquired
        .and_then(|key| {
            retained.bind_borrowed_target(key, 0)?;
            target_snapshot(key)
        })
        .and_then(|root| operation(Some(root)));
    retained.abort()
        .expect("relative registry admission retains its exact root target");
    result
}

unsafe fn acquire_relative_target(
    root: DriverRegistryHandleTarget,
    name: &str,
) -> Result<u32, i32> {
    match root {
        DriverRegistryHandleTarget::System { lease, .. } => {
            let opened = crate::config_manager_open_relative_system_hive_key(lease, name)?;
            match crate::registry_key_targets::install_system(crate::CmSystemKeyTarget {
                lease: opened.lease,
                physical_path: opened.physical_path,
            }) {
                Ok(key) => Ok(key),
                Err(status) => {
                    let _ = crate::config_manager_retire_system_hive_key(opened.lease);
                    Err(status as i32)
                }
            }
        }
        DriverRegistryHandleTarget::Generic { key, path } => {
            let (reply, _) = crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::OPEN_RELATIVE,
                0,
                name,
                0,
                &[],
            )?;
            let mut diagnostic_path = String::from(path.as_str());
            if !name.is_empty() {
                if !diagnostic_path.ends_with('\\') {
                    diagnostic_path.push('\\');
                }
                diagnostic_path.push_str(name);
            }
            crate::registry_key_targets::install_runtime(diagnostic_path, reply.detail0)
                .map_err(|status| status as i32)
        }
        DriverRegistryHandleTarget::Hosted { key, .. } => driver_registry_live_handler()?
            .acquire_relative_registry_target(key, name)
            .map_err(|status| status as i32),
    }
}

unsafe fn release_target(target: u32) {
    if crate::cm_system_key_idx(target).is_some() || crate::cm_runtime_key_idx(target).is_some() {
        let retired = crate::with_provider_process_manager(|pm| {
            Ok(crate::registry_key_targets::take_unreferenced(pm, target))
        })
        .expect("canonical Key target has its original manager");
        if let Some(retired) = retired {
            crate::registry_key_targets::retire(retired);
        }
    } else {
        driver_registry_live_handler()
            .expect("hosted Key target outlives canonical handler")
            .release_registry_key_target(target);
    }
}

/// Transfer a target acquired by the canonical mutable-hive creation path into a native slot.
pub(crate) unsafe fn prepare_driver_registry_target(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    target: u32,
    attributes: u32,
    authorize: impl FnOnce(DriverRegistryHandleTarget) -> Result<u32, i32>,
) -> Result<DriverRegistryHandleSlot, i32> {
    let mut publication = match reserve_driver_registry_publication(dispatch, caller, attributes) {
        Ok(publication) => publication,
        Err(status) => {
            release_target(target);
            return Err(status);
        }
    };
    let result = (|| {
        publication.bind_reserved_target(target, 0)?;
        let snapshot = target_snapshot(target)?;
        let grant = authorize(snapshot)?;
        publication.authorize_bound_grant(grant)?;
        let value = publication.return_pending()?;
        Ok(DriverRegistryHandleSlot {
            handle: value,
            target: snapshot,
        })
    })();
    if result.is_err() {
        publication.abort().expect("failed target admission retains publication");
    }
    result
}

pub(crate) unsafe fn close_driver_registry_handle(
    caller: NativeHandleCaller,
    value: u64,
) -> Result<(), nt_process::native_handle::NativePsCloseError> {
    let retired = crate::with_provider_process_manager(|pm| {
        Ok(pm.close_native_registry_key_handle(caller, value))
    })
    .map_err(nt_process::native_handle::NativePsCloseError::Status)??;
    driver_registry_value_transfers::close(caller, value)
        .expect("closed canonical table scope remains admitted");
    release_target(retired);
    Ok(())
}

pub(crate) unsafe fn retire_driver_registry_handle(
    dispatch: RegistryPublicationDispatch,
    caller: NativeHandleCaller,
    value: u64,
) -> Result<(), i32> {
    abort_driver_registry_publication(dispatch, caller, value)
}

/// The shared ingress owner invokes this only after exact physical retirement has completed.
/// Published entries are no longer in PENDING, even if their ACK Reply outcome was uncertain.
/// A parked callback or an unconfirmed stop is not permission to invoke this cleanup.
pub(crate) unsafe fn retire_confirmed_dispatches(
    route: nt_component_suspension::peer_registry::PeerRoute,
) {
    loop {
        let next = (&*core::ptr::addr_of!(PENDING))
            .iter()
            .flatten()
            .find(|row| row.dispatch.route == route)
            .map(|row| (row.dispatch, row.caller, row.publication.value()));
        let Some((dispatch, caller, value)) = next else {
            break;
        };
        abort_driver_registry_publication(dispatch, caller, value)
            .expect("confirmed retired provider retains exact unpublished Key ownership");
    }
}
