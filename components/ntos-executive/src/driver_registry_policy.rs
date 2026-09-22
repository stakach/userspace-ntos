//! Shared registry authorization and secured creation for native driver providers.

use super::*;

pub(crate) struct DriverRegistryOpenMetadata {
    pub(crate) dispatch: driver_registry_handles::RegistryPublicationDispatch,
    pub(crate) desired_access: u32,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: Option<Vec<u8>>,
    pub(crate) root_handle: Option<u64>,
}

pub(super) struct DriverRegistrySubject(pub(super) nt_user_host::registry_subject::RegistrySubject);

impl Drop for DriverRegistrySubject {
    fn drop(&mut self) {
        unsafe { crate::with_provider_security_managers(|_, tokens| self.0.release(tokens)) }
            .expect("captured registry subject retains its canonical token references");
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
) -> (i32, u64, u64) {
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
        Err(status) => (status, 0, 0),
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
) -> (i32, u64, u64) {
    if options & !5 != 0 {
        return (STATUS_NOT_SUPPORTED, 0, 0);
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
        Ok(slot) => return (STATUS_SUCCESS, slot.handle, REG_OPENED_EXISTING_KEY as u64),
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => (),
        Err(status) => return (status, 0, 0),
    }
    let system = match root {
        Some(DriverRegistryHandleTarget::System { .. }) => true,
        Some(_) => false,
        None => hosted_registry_path_is_system(path),
    };
    let physical = if root.is_some() {
        alloc::string::String::from(path.as_str())
    } else if system {
        let resolved = match crate::config_manager_resolve_system_hive_path(path.as_str()) {
            Ok(resolved) => resolved,
            Err(status) => return (status, 0, 0),
        };
        if resolved.mount_generation != expected_generation {
            return (0xc000_0059u32 as i32, 0, 0);
        }
        resolved.physical_path
    } else {
        alloc::string::String::from(path.as_str())
    };
    let separator = physical.rfind('\\');
    if separator.is_none() && root.is_none() {
        return (STATUS_OBJECT_PATH_NOT_FOUND, 0, 0);
    }
    let mut parent_path = HostedAscii::empty();
    if !parent_path.push_str(separator.map_or("", |index| &physical[..index])) {
        return (STATUS_INSUFFICIENT_RESOURCES, 0, 0);
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
        Err(STATUS_OBJECT_NAME_NOT_FOUND) => return (STATUS_OBJECT_PATH_NOT_FOUND, 0, 0),
        Err(status) => return (status, 0, 0),
    };
    let prepared = prepared.expect("parent authorization prepares child security");
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
        return match result {
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
        };
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
        return match result {
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
        };
    }
    let mutation = if system {
        let DriverRegistryHandleTarget::System { lease, .. } = parent_owner.target else {
            unreachable!("SYSTEM parent admission retains a CM lease")
        };
        let name = physical.rsplit('\\').next().unwrap_or("");
        crate::persist_and_publish_system_hive_mutation(expected_generation, &[
            nt_config_client::SystemHiveMutation::CreateChildRelative {
                parent: lease,
                name,
                class_name: class,
                descriptor: &prepared.descriptor,
                volatile,
            },
        ])
            .map(|_| true)
            .map_err(|status| status as i32)
    } else {
        unreachable!("runtime creation returned above")
    };
    let result = mutation.and_then(|created| {
        let mut leaf = HostedAscii::empty();
        if !leaf.push_str(physical.rsplit('\\').next().unwrap_or("")) {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        open_driver_registry_handle(
            metadata.dispatch,
            caller,
            leaf,
            Some(parent_owner.target),
            metadata.attributes & 0x202,
            |target| {
                if created {
                    Ok(prepared.granted_access)
                } else {
                    open(target)
                }
            },
        ).map(|slot| (slot, created))
    });
    retire_driver_registry_handle(metadata.dispatch, caller, parent_owner.handle)
        .expect("parent publication remains bound through child acquisition");
    match result {
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
    }
}
