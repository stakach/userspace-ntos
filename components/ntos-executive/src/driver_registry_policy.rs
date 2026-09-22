//! Shared registry authorization and secured creation for native driver providers.

use super::*;

pub(crate) struct DriverRegistryOpenMetadata {
    pub(crate) dispatch: driver_registry_handles::RegistryPublicationDispatch,
    pub(crate) desired_access: u32,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: Option<Vec<u8>>,
    pub(crate) root_handle: Option<u64>,
}

#[must_use = "deferred creation owns canonical reservations until terminal publication or abort"]
pub(crate) enum DriverRegistryCreateResult {
    Ready((i32, u64, u64)),
    Deferred(DeferredRegistryCreate),
}

pub(crate) struct DeferredRegistryCreate {
    pub(crate) caller: nt_process::native_handle::NativeHandleCaller,
    pub(crate) dispatch: driver_registry_handles::RegistryPublicationDispatch,
    parent: driver_registry_handles::OwnedDriverRegistryPublication,
    pub(crate) parent_lease: nt_config_client::SystemHiveKeyLease,
    child: driver_registry_handles::OwnedDriverRegistryPublication,
    pub(crate) leaf: String,
    pub(crate) class_name: Option<String>,
    pub(crate) descriptor: Vec<u8>,
    pub(crate) grant: u32,
    pub(crate) volatile: bool,
    pub(crate) expected_generation: u64,
}

impl DeferredRegistryCreate {
    pub(crate) unsafe fn bind_child(&mut self, target: u32) -> Result<(), i32> {
        self.child.bind_reserved_target(target, self.grant)
    }

    pub(crate) unsafe fn release_parent(&mut self) -> Result<(), i32> {
        self.parent.abort()
    }

    pub(crate) unsafe fn abort_child(&mut self) -> Result<(), i32> {
        self.child.abort()
    }

    pub(crate) unsafe fn return_child_pending(&mut self) -> Result<u64, i32> {
        self.child.return_pending()
    }
}

pub(super) struct DriverRegistrySubject(pub(super) Option<nt_user_host::registry_subject::RegistrySubject>);

impl Drop for DriverRegistrySubject {
    fn drop(&mut self) {
        if let Some(subject) = self.0.as_mut() {
            unsafe { crate::with_provider_security_managers(|_, tokens| subject.release(tokens)) }
                .expect("captured registry subject retains its canonical token references");
        }
    }
}

pub(crate) unsafe fn driver_registry_target_security(
    target: DriverRegistryHandleTarget,
) -> Result<Vec<u8>, i32> {
    match target {
        DriverRegistryHandleTarget::Hosted { key, .. } => {
            let handler = driver_registry_live_handler()?;
            handler
                .registry_key_security_descriptor(key)
                .map_err(|status| status as i32)?
                .ok_or(0xc000_0079u32 as i32)
        }
        DriverRegistryHandleTarget::System { lease, .. } => {
            crate::config_manager_query_leased_system_hive_key_information(lease)?
                .security_descriptor
                .ok_or(0xc000_0079u32 as i32)
        }
        DriverRegistryHandleTarget::Generic { key, .. } => {
            crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::SECURITY,
                0,
                "",
                0,
                &[],
            )
            .map(|(_, data)| data)
        }
    }
}

pub(crate) unsafe fn driver_registry_live_handler() -> Result<&'static mut crate::ExecNtHandler, i32>
{
    crate::service_sec_image::registry_live_handler().map_err(|status| status as i32)
}

pub(crate) unsafe fn authorize_driver_registry_open(
    subject: &nt_user_host::registry_subject::RegistrySubject,
    metadata: &DriverRegistryOpenMetadata,
    target: DriverRegistryHandleTarget,
) -> Result<u32, i32> {
    let mode = if metadata.attributes & 0x400 != 0 {
        nt_security::ProcessorMode::UserMode
    } else {
        subject.mode()
    };
    let descriptor = if mode == nt_security::ProcessorMode::UserMode {
        driver_registry_target_security(target)?
    } else {
        Vec::new()
    };
    crate::with_provider_security_managers(|_, tokens| {
        let captured = subject.resolve(tokens)?;
        let decision =
            nt_security::authorize_key_open(&captured, &descriptor, metadata.desired_access, mode)?;
        crate::registry_security_audit::access(&decision);
        if decision.status == 0 {
            Ok(decision.granted_access)
        } else {
            Err(decision.status)
        }
    })
    .map_err(|status| status as i32)
}

pub(crate) unsafe fn finish_driver_registry_close(
    channel: &crate::spawn_hosts::PumpChannel,
    result: Result<(), nt_process::native_handle::NativePsCloseError>,
) -> (i32, u64, u64) {
    match result {
        Ok(()) => (STATUS_SUCCESS, 0, 0),
        Err(nt_process::native_handle::NativePsCloseError::Status(status)) => (status as i32, 0, 0),
        Err(nt_process::native_handle::NativePsCloseError::BugCheck { code, parameters }) => {
            use nt_kernel_exec::provider_bugcheck::{
                FatalReport, ProviderChannel, BUGCHECK_MESSAGE_INFO,
            };
            let report = FatalReport::decode(
                ProviderChannel {
                    endpoint: channel.fault_ep,
                    tcb: channel.tcb,
                    vspace: channel.pml4,
                    reply_object: channel.reply_cap,
                    expected_badge: 0,
                },
                0,
                BUGCHECK_MESSAGE_INFO,
                [
                    code as u64,
                    parameters[0],
                    parameters[1],
                    parameters[2],
                    parameters[3],
                ],
            )
            .expect("canonical protected-handle bugcheck");
            crate::provider_bugcheck::stop(report)
        }
    }
}

pub(crate) unsafe fn service_hosted_driver_open_registry_path(
    caller: nt_process::native_handle::NativeHandleCaller,
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    metadata: &DriverRegistryOpenMetadata,
    subject: &nt_user_host::registry_subject::RegistrySubject,
) -> (i32, u64, u64) {
    let result = driver_registry_handles::with_registry_root(
        metadata.dispatch,
        caller,
        metadata.root_handle,
        |root| {
            open_driver_registry_handle(
                metadata.dispatch,
                caller,
                path,
                root,
                metadata.attributes & 0x202,
                |target| authorize_driver_registry_open(subject, metadata, target),
            )
        },
    );
    match result {
        Ok(slot) => (STATUS_SUCCESS, slot.handle, 0),
        Err(status) => (status, 0, 0),
    }
}

pub(super) fn hosted_registry_path_is_system(path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>) -> bool {
    let path = path.as_str();
    path.eq_ignore_ascii_case(r"\Registry\Machine\System")
        || ascii_prefix_eq_ignore_case(path, r"\Registry\Machine\System\")
}

pub(crate) unsafe fn service_hosted_driver_create_registry_path(
    caller: nt_process::native_handle::NativeHandleCaller,
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    options: u32,
    metadata: &DriverRegistryOpenMetadata,
    subject: &nt_user_host::registry_subject::RegistrySubject,
    class: Option<&str>,
) -> DriverRegistryCreateResult {
    let _durable = crate::allocator::enter_durable();
    match driver_registry_handles::with_registry_root(
        metadata.dispatch,
        caller,
        metadata.root_handle,
        |root| {
            Ok(create_registry_path(
                caller, path, options, metadata, subject, class, root,
            ))
        },
    ) {
        Ok(result) => result,
        Err(status) => DriverRegistryCreateResult::Ready((status, 0, 0)),
    }
}

unsafe fn create_registry_path(
    caller: nt_process::native_handle::NativeHandleCaller,
    path: HostedAscii<HOSTED_REGISTRY_PATH_MAX>,
    options: u32,
    metadata: &DriverRegistryOpenMetadata,
    subject: &nt_user_host::registry_subject::RegistrySubject,
    class: Option<&str>,
    root: Option<DriverRegistryHandleTarget>,
) -> DriverRegistryCreateResult {
    use DriverRegistryCreateResult::{Deferred, Ready};
    if options & !5 != 0 {
        return Ready((STATUS_NOT_SUPPORTED, 0, 0));
    }
    let volatile = options & 1 != 0;
    let backup = options & 4 != 0;
    let mode = if metadata.attributes & 0x400 != 0 {
        nt_security::ProcessorMode::UserMode
    } else {
        subject.mode()
    };
    let open = |target| {
        if !backup {
            return authorize_driver_registry_open(subject, metadata, target);
        }
        crate::with_provider_security_managers(|_, tokens| {
            let captured = subject.resolve(tokens)?;
            let decision = nt_security::authorize_key_backup_restore(&captured, mode);
            crate::registry_security_audit::backup(decision);
            if decision.status == 0 {
                Ok(decision.granted_access)
            } else {
                Err(decision.status)
            }
        })
        .map_err(|status| status as i32)
    };
    let expected_generation = crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire);
    match open_driver_registry_handle(
        metadata.dispatch,
        caller,
        path,
        root,
        metadata.attributes & 0x202,
        open,
    ) {
        Ok(slot) => return Ready((STATUS_SUCCESS, slot.handle, REG_OPENED_EXISTING_KEY as u64)),
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => (),
        Err(status) => return Ready((status, 0, 0)),
    }
    let absolute_system = root.is_none() && hosted_registry_path_is_system(path);
    let physical = if root.is_some() {
        alloc::string::String::from(path.as_str())
    } else if absolute_system {
        let resolved = match crate::config_manager_resolve_system_hive_path(path.as_str()) {
            Ok(resolved) => resolved,
            Err(status) => return Ready((status, 0, 0)),
        };
        if resolved.mount_generation != expected_generation {
            return Ready((0xc000_0059u32 as i32, 0, 0));
        }
        resolved.physical_path
    } else {
        alloc::string::String::from(path.as_str())
    };
    let separator = physical.rfind('\\');
    if separator.is_none() && root.is_none() {
        return Ready((STATUS_OBJECT_PATH_NOT_FOUND, 0, 0));
    }
    let mut parent_path = HostedAscii::empty();
    if !parent_path.push_str(separator.map_or("", |index| &physical[..index])) {
        return Ready((STATUS_INSUFFICIENT_RESOURCES, 0, 0));
    }
    let mut prepared = None;
    let mut parent_revision = None;
    let mut hosted_parent = None;
    let parent_owner = match open_driver_registry_handle(
        metadata.dispatch,
        caller,
        parent_path,
        root,
        0,
        |target| {
            let descriptor = if let DriverRegistryHandleTarget::Generic { key, .. } = target {
                let (reply, descriptor) = crate::config_manager_runtime_key_operation(
                    key,
                    nt_config_abi::runtime_key_op::SECURITY,
                    0,
                    "",
                    0,
                    &[],
                )?;
                parent_revision = Some((
                    key,
                    u32::try_from(reply.detail1).map_err(|_| STATUS_INVALID_PARAMETER)?,
                ));
                descriptor
            } else {
                if let DriverRegistryHandleTarget::Hosted { key, .. } = target {
                    hosted_parent = Some(key);
                }
                driver_registry_target_security(target)?
            };
            let security = crate::with_provider_security_managers(|_, tokens| {
                let captured = subject.resolve(tokens)?;
                if backup {
                    let mut audit = nt_security::KeyBackupRestoreCreationAudit::default();
                    let result = nt_security::prepare_key_backup_restore_creation_security(
                        &captured,
                        &descriptor,
                        metadata.security_descriptor.as_deref(),
                        mode,
                        &mut audit,
                    );
                    if let Some(privileges) = audit.privileges {
                        crate::registry_security_audit::backup(privileges);
                    }
                    crate::registry_security_audit::assignment(audit.assignment);
                    result
                } else {
                    let mut audit = nt_security::KeyCreationAudit::default();
                    let result = nt_security::prepare_key_creation_security(
                        &captured,
                        &descriptor,
                        metadata.security_descriptor.as_deref(),
                        metadata.desired_access,
                        mode,
                        &mut audit,
                    );
                    crate::registry_security_audit::creation(&audit);
                    result
                }
            })
            .map_err(|status| status as i32)?;
            prepared = Some(security);
            Ok(4)
        },
    ) {
        Ok(opened) => opened,
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ready((STATUS_OBJECT_PATH_NOT_FOUND, 0, 0)),
        Err(status) => return Ready((status, 0, 0)),
    };
    let prepared = prepared.expect("parent authorization prepares child security");
    // Relative opens can cross from a virtual root into the CM-owned SYSTEM mount.
    let system = matches!(parent_owner.target, DriverRegistryHandleTarget::System { .. });
    let physical = if root.is_some() {
        let mut admitted = String::from(parent_owner.target.path().as_str());
        if !admitted.ends_with('\\') {
            admitted.push('\\');
        }
        admitted.push_str(separator.map_or(physical.as_str(), |index| &physical[index + 1..]));
        admitted
    } else {
        physical
    };
    if let Some(parent) = hosted_parent {
        let created = driver_registry_live_handler().and_then(|handler| {
            handler
                .create_secured_registry_child(
                    parent,
                    &physical,
                    &prepared.descriptor,
                    class,
                    volatile,
                )
                .map_err(|status| status as i32)
        });
        let result = match created {
            Ok((key, created)) => driver_registry_handles::prepare_driver_registry_target(
                metadata.dispatch,
                caller,
                key,
                metadata.attributes & 0x202,
                |target| {
                    if created {
                        Ok(prepared.granted_access)
                    } else {
                        open(target)
                    }
                },
            )
            .map(|slot| (slot, created)),
            Err(status) => Err(status),
        };
        retire_driver_registry_handle(metadata.dispatch, caller, parent_owner.handle)
            .expect("hosted parent remains retained through mutation");
        return Ready(match result {
            Ok((slot, created)) => (
                STATUS_SUCCESS,
                slot.handle,
                if created {
                    REG_CREATED_NEW_KEY
                } else {
                    REG_OPENED_EXISTING_KEY
                } as u64,
            ),
            Err(status) => (status, 0, 0),
        });
    }
    if !system {
        let result = match parent_revision {
            Some((key, generation)) => crate::config_manager_create_secured_key_checked_with_class(
                &physical,
                &prepared.descriptor,
                volatile,
                key,
                generation,
                class,
            )
            .and_then(|(key, created)| {
                let target = crate::registry_key_targets::install_runtime(physical.clone(), key)
                    .map_err(|status| status as i32)?;
                driver_registry_handles::prepare_driver_registry_target(
                    metadata.dispatch,
                    caller,
                    target,
                    metadata.attributes & 0x202,
                    |target| {
                        if created {
                            Ok(prepared.granted_access)
                        } else {
                            open(target)
                        }
                    },
                )
                .map(|slot| (slot, created))
            }),
            None => Err(STATUS_INVALID_HANDLE),
        };
        retire_driver_registry_handle(metadata.dispatch, caller, parent_owner.handle)
            .expect("runtime parent retains publication");
        return Ready(match result {
            Ok((slot, created)) => (
                STATUS_SUCCESS,
                slot.handle,
                if created {
                    REG_CREATED_NEW_KEY
                } else {
                    REG_OPENED_EXISTING_KEY
                } as u64,
            ),
            Err(status) => (status, 0, 0),
        });
    }
    let DriverRegistryHandleTarget::System { lease, .. } = parent_owner.target else {
        unreachable!("SYSTEM parent admission retains a CM lease")
    };
    let child = match driver_registry_handles::reserve_driver_registry_publication(
        metadata.dispatch,
        caller,
        metadata.attributes & 0x202,
    ) {
        Ok(child) => child,
        Err(status) => {
            retire_driver_registry_handle(metadata.dispatch, caller, parent_owner.handle)
                .expect("failed child reservation retains parent publication");
            return Ready((status, 0, 0));
        }
    };
    let parent =
        driver_registry_handles::take_pending_owned(metadata.dispatch, caller, parent_owner.handle)
            .expect("authorized parent publication remains owned before BEGIN");
    Deferred(DeferredRegistryCreate {
        caller,
        dispatch: metadata.dispatch,
        parent,
        parent_lease: lease,
        child,
        leaf: String::from(physical.rsplit('\\').next().unwrap_or("")),
        class_name: class.map(String::from),
        descriptor: prepared.descriptor,
        grant: prepared.granted_access,
        volatile,
        expected_generation,
    })
}
