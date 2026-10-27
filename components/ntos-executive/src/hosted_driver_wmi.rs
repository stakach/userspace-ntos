//! Exact hosted DEVICE_OBJECT to 32-bit WMI provider identity.
//! Registration and event delivery remain separate contracts: assigning an ID
//! does not advertise GUIDs or accept an event.

use super::*;
use nt_wmi::{RegInfoTicket, WmiDeviceIdentity, WmiRegistry};

pub(super) const LABEL: u64 = 0x7E5;
const OP_PROVIDER_ID: u64 = 1;
const OP_REGINFO_BEGIN: u64 = 2;
const OP_REGINFO_DISPATCHED: u64 = 3;
const OP_REGINFO_ABORT_PRE_DISPATCH: u64 = 4;

// Root pump entry and exact device retirement serialize access to this store.
static mut DEVICE_REGISTRY: WmiRegistry = WmiRegistry::new();

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind(
        "IoWMIDeviceObjectToProviderId",
        device_object_to_provider_id as *const () as usize as u64,
    );
}

/// `ULONG IoWMIDeviceObjectToProviderId(PDEVICE_OBJECT)`.
pub(super) extern "win64" fn device_object_to_provider_id(device_object: u64) -> u32 {
    if device_object == 0 {
        return 0;
    }
    let (words, raw, id, extra_a, extra_b) = unsafe {
        call_on4_raw((LABEL << 12) | 4, OP_PROVIDER_ID, device_object, 0, 0)
    };
    if words != 2 || extra_a != 0 || extra_b != 0
        || (raw as u32 as i32 == STATUS_SUCCESS && id == 0)
    {
        unsafe {
            crate::provider_bugcheck::report(
                0xc4,
                [LABEL, OP_PROVIDER_ID, words, raw],
            );
        }
    }
    if raw as u32 as i32 != STATUS_SUCCESS {
        return 0;
    }
    u32::try_from(id).unwrap_or(0)
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    device_object: u64,
    arg2: u64,
    arg3: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    if device_object == 0 || arg3 != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(identity) = authenticated_device(ch, device_object, badge, reply_cap) else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_REGISTRY) };
    match op {
        OP_PROVIDER_ID if arg2 == 0 => match registry.register_device(identity) {
            Ok(id) => (STATUS_SUCCESS, u64::from(id)),
            Err(status) => (status as i32, 0),
        },
        OP_REGINFO_BEGIN if arg2 == 0 => {
            if let Err(status) = registry.register_device(identity) {
                return (status as i32, 0);
            }
            match registry.begin_reginfo(identity) {
                Ok(ticket) => (STATUS_SUCCESS, ticket.raw()),
                Err(status) => (status as i32, 0),
            }
        }
        OP_REGINFO_DISPATCHED if arg2 != 0 => {
            let ticket = RegInfoTicket::for_authenticated_device(arg2, identity);
            match registry.mark_reginfo_dispatched(ticket) {
                Ok(()) => (STATUS_SUCCESS, 0),
                Err(status) => (status as i32, 0),
            }
        }
        OP_REGINFO_ABORT_PRE_DISPATCH if arg2 != 0 => {
            let ticket = RegInfoTicket::for_authenticated_device(arg2, identity);
            match registry.abort_reginfo_before_dispatch(ticket) {
                Ok(()) => (STATUS_SUCCESS, 0),
                Err(status) => (status as i32, 0),
            }
        }
        _ => (STATUS_INVALID_PARAMETER, 0),
    }
}

fn authenticated_device(
    ch: &crate::spawn_hosts::PumpChannel,
    device_object: u64,
    badge: u64,
    reply_cap: u64,
) -> Option<WmiDeviceIdentity> {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return None;
    };
    if hosted_driver_caller(index, inst, badge).is_none() {
        return None;
    }
    let Some(domain) = instance_domain_identity(inst) else {
        return None;
    };
    let registration = unsafe {
        io_manager_mut().hosted_device_pointer_registration(domain, device_object)
    };
    let Some(registration) = registration else {
        return None;
    };
    if registration.address() != device_object
        || registration.domain() != domain
        || hosted_device_binding_by_device_id(registration.device_id().raw()).is_none_or(|binding| {
            binding.device_object != device_object
                || binding.projection_domain != domain
                || binding.instance != index
        })
    {
        return None;
    }
    Some(WmiDeviceIdentity {
        domain: domain.domain_id.raw(),
        generation: registration.generation(),
        device_object,
    })
}

pub(super) fn retire_device(
    registration: nt_io_manager::HostedDevicePointerRegistration,
) -> Result<(), u32> {
    let identity = WmiDeviceIdentity {
        domain: registration.domain().domain_id.raw(),
        generation: registration.generation(),
        device_object: registration.address(),
    };
    let registry = unsafe { &mut *core::ptr::addr_of_mut!(DEVICE_REGISTRY) };
    if registry.device_provider_id(identity).is_ok() {
        registry.unregister_device(identity)
    } else {
        Ok(())
    }
}
