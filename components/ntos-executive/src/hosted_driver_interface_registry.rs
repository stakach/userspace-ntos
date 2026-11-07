//! Native `IoOpenDeviceInterfaceRegistryKey` ingress and canonical Key publication.
//! The provider supplies a link name; only an exact live registration can name the CM parent.

use super::*;
use crate::registry_mutation_work::ProviderRegistryResult;
use nt_io_manager::hosted_interface_registry::{
    HostedInterfaceRegistration, resolve_interface_instance_key,
    revalidate_interface_registration_revision,
};

/// Retained across CM BEGIN, durable storage, COMMIT and terminal ACK. No provider scratch
/// pointer is used after admission except the instance-owned output buffer after publication.
pub(crate) struct DeferredInterfaceRegistration {
    pub(crate) caller: nt_process::native_handle::NativeHandleCaller,
    pub(crate) dispatch: driver_registry_handles::RegistryPublicationDispatch,
    pub(crate) expected_generation: u64,
    pub(crate) mount: nt_config_client::SystemHiveMount,
    pub(crate) registry_parent: String,
    owner: HostedDomainIdentity,
    pdo: nt_io_manager::DeviceId,
    devnode_generation: u64,
    instance_path: HostedAscii<HOSTED_INSTANCE_PATH_MAX>,
    class_guid: [u64; 2],
    reference: HostedAscii<HOSTED_DRIVER_KEY_NAME_MAX>,
    symbolic_link: HostedAscii<HOSTED_INTERFACE_LINK_MAX>,
    output_arg: u64,
}

impl DeferredInterfaceRegistration {
    pub(crate) unsafe fn revalidate_for_revision_retry(
        &self,
        mount: nt_config_client::SystemHiveMount,
        previous_generation: u64,
        generation: u64,
    ) -> Result<(), i32> {
        let guid = guid_words_to_hosted_ascii(self.class_guid)
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        let registration = HostedInterfaceRegistration {
            owner: self.owner,
            pdo: self.pdo,
            devnode_generation: self.devnode_generation,
            instance_path: String::from(self.instance_path.as_str()),
            class_guid: String::from(guid.as_str()),
            reference: String::from(self.reference.as_str()),
            symbolic_link: String::from(self.symbolic_link.as_str()),
        };
        let live_path = hosted_interface_instance_path(self.pdo.raw())
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        revalidate_interface_registration_revision(
            &registration,
            &self.registry_parent,
            self.mount.identity_token(),
            mount.identity_token(),
            previous_generation,
            generation,
            live_path.as_str(),
            |owner, pdo, devnode_generation| {
                io_manager_mut().hosted_device_address_by_identity(owner, pdo).is_some()
                    && hosted_pnp_manager_mut()
                        .devnode_identity_for_pdo(pdo.raw())
                        .is_some_and(|identity| identity.generation() == devnode_generation)
            },
        ).map_err(|status| status.raw())
    }

    pub(crate) unsafe fn publish(&mut self) -> Result<(), i32> {
        if io_manager_mut()
            .hosted_device_address_by_identity(self.owner, self.pdo)
            .is_none()
            || hosted_pnp_manager_mut()
                .devnode_identity_for_pdo(self.pdo.raw())
                .is_none_or(|identity| identity.generation() != self.devnode_generation)
            || hosted_interface_instance_path(self.pdo.raw())
                .is_none_or(|path| !path.as_str().eq_ignore_ascii_case(self.instance_path.as_str()))
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        register_hosted_device_interface(
            self.owner,
            self.pdo.raw(),
            self.devnode_generation,
            self.instance_path,
            self.class_guid,
            self.reference,
            self.symbolic_link,
        ).map_err(|status| status.raw())?;
        let arg = self.output_arg;
        write_volatile((arg + HOSTED_REGISTRY_ARG_KEY_LEN) as *mut u32, self.symbolic_link.len as u32);
        for (index, byte) in self.symbolic_link.as_bytes().iter().enumerate() {
            write_volatile((arg + HOSTED_REGISTRY_ARG_KEY_OFF + index as u64) as *mut u8, *byte);
        }
        Ok(())
    }
}

pub(super) fn service_register(
    channel: &crate::spawn_hosts::PumpChannel,
    pdo_object: u64,
    guid_low: u64,
    guid_high: u64,
    active_reply_cap: u64,
) -> ProviderRegistryResult {
    let ready = |status| ProviderRegistryResult::Ready((status, 0, 0));
    unsafe {
        let (_, instance, pdo) = match authenticated_hosted_pdo(channel, pdo_object, active_reply_cap) {
            Ok(value) => value,
            Err(status) => return ready(status.raw()),
        };
        if instance.exec_arg_va == 0 {
            return ready(STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(reference) = read_registry_arg_ascii_at::<HOSTED_DRIVER_KEY_NAME_MAX>(
            instance.exec_arg_va,
            HOSTED_REGISTRY_ARG_KEY_LEN,
            HOSTED_REGISTRY_ARG_KEY_OFF,
            true,
        ) else {
            return ready(STATUS_INVALID_PARAMETER);
        };
        if reference.as_bytes().iter().any(|byte| matches!(*byte, b'\\' | b'/' | 0)) {
            return ready(STATUS_INVALID_PARAMETER);
        }
        let class_guid = [guid_low, guid_high];
        let Some(guid) = guid_words_to_hosted_ascii(class_guid) else {
            return ready(STATUS_INVALID_PARAMETER);
        };
        let Some(devnode) = hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo.raw()) else {
            return ready(STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(instance_path) = hosted_interface_instance_path(pdo.raw()) else {
            return ready(STATUS_INVALID_DEVICE_REQUEST);
        };
        let Some(symbolic_link) = build_hosted_interface_link(&guid, &instance_path, &reference) else {
            return ready(STATUS_INVALID_PARAMETER);
        };
        let registry_parent = nt_config_manager::interface_reference_registry_path(
            guid.as_str(), instance_path.as_str(), reference.as_str(),
        );
        if registry_parent.len() > HOSTED_REGISTRY_PATH_MAX {
            return ready(0xC000_0106u32 as i32);
        }
        let caller = match crate::provider_registry_caller::resolve(channel) {
            Ok(caller) => caller,
            Err(status) => return ready(status as i32),
        };
        let dispatch = match driver_registry_handles::RegistryPublicationDispatch::capture(channel) {
            Ok(dispatch) => dispatch,
            Err(status) => return ready(status as i32),
        };
        let Some(mount) = crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT else {
            return ready(STATUS_DEVICE_NOT_READY);
        };
        let admission = DeferredInterfaceRegistration {
            caller,
            dispatch,
            expected_generation: crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire),
            mount,
            registry_parent,
            owner: HostedDomainIdentity {
                domain_id: nt_io_manager::HostedDomainId(instance.hosted_domain_id),
                cookie: instance.hosted_domain_cookie,
            },
            pdo,
            devnode_generation: devnode.generation(),
            instance_path,
            class_guid,
            reference,
            symbolic_link,
            output_arg: instance.exec_arg_va,
        };
        crate::registry_mutation_work::submit_provider_interface(channel, admission)
    }
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "IoOpenDeviceInterfaceRegistryKey",
        open as *const () as usize as u64,
    );
}

/// WDK `NTSTATUS IoOpenDeviceInterfaceRegistryKey(PUNICODE_STRING, ACCESS_MASK, PHANDLE)`.
pub(super) extern "win64" fn open(link: u64, desired_access: u32, handle_out: u64) -> i32 {
    if handle_out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        write_unaligned(handle_out as *mut u64, 0);
        let Some(symbolic_link) = unicode_string_to_hosted_ascii::<HOSTED_INTERFACE_LINK_MAX>(link, false) else {
            return STATUS_INVALID_PARAMETER;
        };
        if !write_registry_arg_ascii(
            HOSTED_REGISTRY_ARG_KEY_LEN,
            HOSTED_REGISTRY_ARG_KEY_OFF,
            &symbolic_link,
        ) {
            return STATUS_INVALID_PARAMETER;
        }
        if let Err(status) = stage_registry_open_metadata(
            desired_access,
            nt_process::native_handle::OBJ_KERNEL_HANDLE | 0x40,
            0,
        ) {
            return status;
        }
        let (status, handle, _) = hosted_registry_broker_call(
            HOSTED_REGISTRY_OP_OPEN_INTERFACE_KEY,
            0,
            0,
            0,
        );
        if status != STATUS_SUCCESS {
            return status;
        }
        write_unaligned(handle_out as *mut u64, handle);
        let published = acknowledge_registry_handle_output(handle);
        if published != STATUS_SUCCESS {
            write_unaligned(handle_out as *mut u64, 0);
        }
        published
    }
}

unsafe fn registered_instance_key(symbolic_link: &str) -> Result<String, i32> {
    let rows = hosted_device_interface_registrations_mut();
    let mut registrations = Vec::new();
    registrations
        .try_reserve(rows.iter().filter(|row| row.used).count())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for row in rows.iter().filter(|row| row.used) {
        let guid = guid_words_to_hosted_ascii(row.class_guid)
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        registrations.push(HostedInterfaceRegistration {
            owner: row.owner_domain,
            pdo: nt_io_manager::DeviceId(row.pdo_device_id),
            devnode_generation: row.devnode_generation,
            instance_path: String::from(row.instance_path.as_str()),
            class_guid: String::from(guid.as_str()),
            reference: String::from(row.reference.as_str()),
            symbolic_link: String::from(row.symbolic_link.as_str()),
        });
    }
    resolve_interface_instance_key(&registrations, symbolic_link, |owner, pdo, generation| {
        io_manager_mut()
            .hosted_device_address_by_identity(owner, pdo)
            .is_some()
            && hosted_pnp_manager_mut()
                .devnode_identity_for_pdo(pdo.raw())
                .is_some_and(|identity| identity.generation() == generation)
    })
    .map_err(|status| status.raw())
}

/// The existing secured create path retains the CM mutation and Key publication on defer.
pub(super) fn service_open(
    channel: &crate::spawn_hosts::PumpChannel,
    active_reply_cap: u64,
) -> ProviderRegistryResult {
    let ready = |status| ProviderRegistryResult::Ready((status, 0, 0));
    unsafe {
        let Some((_, instance)) = instance_for_pump_channel(channel, active_reply_cap) else {
            return ready(STATUS_ACCESS_DENIED);
        };
        if instance.exec_arg_va == 0 {
            return ready(STATUS_INVALID_DEVICE_REQUEST);
        }
        let Some(link) = read_registry_arg_ascii_at::<HOSTED_INTERFACE_LINK_MAX>(
            instance.exec_arg_va,
            HOSTED_REGISTRY_ARG_KEY_LEN,
            HOSTED_REGISTRY_ARG_KEY_OFF,
            false,
        ) else {
            return ready(STATUS_INVALID_PARAMETER);
        };
        let instance_path = match registered_instance_key(link.as_str()) {
            Ok(path) => path,
            Err(status) => return ready(status as i32),
        };
        let caller = match crate::provider_registry_caller::resolve(channel) {
            Ok(caller) => caller,
            Err(status) => return ready(status as i32),
        };
        let dispatch = match driver_registry_handles::RegistryPublicationDispatch::capture(channel) {
            Ok(dispatch) => dispatch,
            Err(status) => return ready(status as i32),
        };
        let metadata = match capture_registry_open_metadata(instance.exec_arg_va, dispatch) {
            Ok(metadata) if metadata.attributes & !0x6c2 == 0 => metadata,
            Ok(_) => return ready(STATUS_INVALID_PARAMETER),
            Err(status) => return ready(status),
        };
        let mut subject = match crate::with_provider_security_managers(|pm, tokens| {
            nt_user_host::registry_subject::RegistrySubject::capture(pm, tokens, caller)
        }) {
            Ok(subject) => DriverRegistrySubject(Some(subject)),
            Err(status) => return ready(status as i32),
        };
        let mut parameters_path = instance_path;
        parameters_path.push_str(r"\Device Parameters");
        match service_hosted_driver_create_registry_path(
            caller,
            &parameters_path,
            0,
            &metadata,
            subject.0.as_ref().unwrap(),
            None,
        ) {
            DriverRegistryCreateResult::Ready(result) => ProviderRegistryResult::Ready(result),
            DriverRegistryCreateResult::Deferred(admission) => {
                crate::registry_mutation_work::submit_provider(
                    channel,
                    admission,
                    subject.0.take().unwrap(),
                )
            }
        }
    }
}
