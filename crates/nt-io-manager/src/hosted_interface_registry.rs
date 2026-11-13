//! Resolve hosted device-interface links to their canonical Configuration Manager keys.
//!
//! The native broker authenticates the caller and checks registry access. This pure boundary
//! instead binds a link to its exact live registration; a path-shaped string cannot authorize
//! access to a registry key on its own.

use alloc::string::String;

use nt_config_manager::{
    device_interface_symbolic_link, guid_text_to_memory_bytes,
    interface_reference_registry_path,
};
use nt_status::NtStatus;

use crate::{DeviceId, HostedDomainIdentity};

/// Identity captured at registration, before publishing the interface link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostedInterfaceRegistration {
    pub owner: HostedDomainIdentity,
    pub pdo: DeviceId,
    pub devnode_generation: u64,
    pub instance_path: String,
    pub class_guid: String,
    pub reference: String,
    pub symbolic_link: String,
}

fn canonical_guid(guid: &str) -> bool {
    let bytes = guid.as_bytes();
    if bytes.len() != 38 || bytes[0] != b'{' || bytes[37] != b'}' {
        return false;
    }
    bytes[1..37].iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    }) && guid_text_to_memory_bytes(guid).is_some()
}

/// Resolve only a registered, structurally consistent link whose owner and PDO remain live.
///
/// The liveness callback must check the exact domain cookie, generation-bearing PDO identity,
/// and PnP devnode generation. The caller's domain is intentionally absent: a different kernel
/// driver may open the interface, with its requested access checked by the registry broker.
pub fn resolve_interface_instance_key(
    registrations: &[HostedInterfaceRegistration],
    symbolic_link: &str,
    mut is_live: impl FnMut(HostedDomainIdentity, DeviceId, u64) -> bool,
) -> Result<String, NtStatus> {
    let mut matched = None;
    for registration in registrations {
        if !registration.symbolic_link.eq_ignore_ascii_case(symbolic_link) {
            continue;
        }
        if matched.is_some() {
            return Err(NtStatus::OBJECT_NAME_COLLISION);
        }
        matched = Some(registration);
    }
    let registration = matched.ok_or(NtStatus::OBJECT_NAME_NOT_FOUND)?;
    if registration.owner.domain_id.raw() == 0
        || registration.owner.cookie == 0
        || registration.pdo.raw() == 0
        || registration.devnode_generation == 0
        || registration.instance_path.is_empty()
        || registration.instance_path.contains(['\0', '/'])
        || registration.reference.contains(['\0', '\\', '/'])
        || !canonical_guid(&registration.class_guid)
        || !device_interface_symbolic_link(
            &registration.class_guid,
            &registration.instance_path,
            &registration.reference,
        )
        .eq_ignore_ascii_case(&registration.symbolic_link)
    {
        return Err(NtStatus::INVALID_DEVICE_REQUEST);
    }
    if !is_live(
        registration.owner,
        registration.pdo,
        registration.devnode_generation,
    ) {
        return Err(NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(interface_reference_registry_path(
        &registration.class_guid,
        &registration.instance_path,
        &registration.reference,
    ))
}

/// Admit a fresh BEGIN only after an acknowledged, no-effect revision mismatch. The caller
/// supplies observations from the exact retained PDO and its current PnP devnode; this check
/// prevents a new SYSTEM generation from silently rebinding the original journal to a remount,
/// retired device, or replacement instance.
pub fn revalidate_interface_registration_revision(
    registration: &HostedInterfaceRegistration,
    registry_parent: &str,
    captured_mount: u64,
    live_mount: u64,
    previous_generation: u64,
    live_generation: u64,
    live_instance_path: &str,
    is_live: impl FnMut(HostedDomainIdentity, DeviceId, u64) -> bool,
) -> Result<(), NtStatus> {
    if captured_mount == 0 || captured_mount != live_mount {
        return Err(NtStatus::DEVICE_NOT_READY);
    }
    if live_generation <= previous_generation {
        return Err(NtStatus::DEVICE_BUSY);
    }
    if !registration.instance_path.eq_ignore_ascii_case(live_instance_path) {
        return Err(NtStatus::INVALID_DEVICE_REQUEST);
    }
    let canonical_parent = resolve_interface_instance_key(
        core::slice::from_ref(registration), &registration.symbolic_link, is_live,
    )?;
    if !canonical_parent.eq_ignore_ascii_case(registry_parent) {
        return Err(NtStatus::INVALID_DEVICE_REQUEST);
    }
    Ok(())
}
