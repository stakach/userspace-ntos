//! Generation-bound i8042 port-to-class callback thunk.
//!
//! The four-argument Win64 callback originates in the port DPC and must stay on its private IRQ
//! lane. The executable slot carries only a cookie and class-domain identity; root validates the
//! exact source and alias registrations before it copies records or schedules class code. A
//! missing lease or handler is a protocol fault, never a successful empty callback.

use super::*;
use nt_io_manager::{
    class_service_callback::ClassServiceThunk, retained_connect_forward::ConnectControl,
    HostedDevicePointerRegistration,
};

const PURPOSE_CLASS_SERVICE: u8 = 4;
const THUNK_BYTES: usize = 55;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Reserved,
    Published,
    Blocked,
}

struct Record {
    cookie: u64,
    phase: Phase,
    port_instance: usize,
    class_instance: usize,
    port_domain: HostedDomainIdentity,
    class_domain: HostedDomainIdentity,
    reverse_owner_id: u64,
    class_main: HostedDevicePointerRegistration,
    port_alias_main: HostedDevicePointerRegistration,
    class_service: u64,
    class_image_frame_base: u64,
    class_image_frames: u64,
    control: ConnectControl,
    binding: HostedExecutableThunkBinding,
    run_va: u64,
}

static mut RECORDS: Vec<Record> = Vec::new();
static mut NEXT_COOKIE: u64 = 1;

fn records() -> &'static mut Vec<Record> {
    unsafe { &mut *core::ptr::addr_of_mut!(RECORDS) }
}

fn record(cookie: u64) -> Option<&'static Record> {
    records().iter().find(|row| row.cookie == cookie)
}

#[derive(Clone, Copy)]
pub(super) struct PublishedClassServiceThunk {
    pub(super) cookie: u64,
    pub(super) port_address: u64,
    pub(super) port_class_alias: HostedDevicePointerRegistration,
    pub(super) class_service: ClassServiceThunk,
}

/// Use only after reverse aliases have been acknowledged in port memory. The returned address
/// replaces ClassService in the port-local CONNECT_DATA; the original class address stays in the
/// source payload and in this retained record until an acknowledged disconnect.
pub(super) unsafe fn publish(
    reverse_owner_id: u64,
    port_instance: usize,
    class_instance: usize,
    class_main: HostedDevicePointerRegistration,
    class_service: u64,
    control: ConnectControl,
) -> Result<PublishedClassServiceThunk, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let projected = hosted_reverse_class_projection::validate(reverse_owner_id)?;
    let port_inst = instance(port_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let class_inst = instance(class_instance).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let port_domain =
        instance_domain_identity(port_inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let class_domain =
        instance_domain_identity(class_inst).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
    let image_end = class_inst
        .image_frames
        .checked_mul(0x1000)
        .and_then(|length| FSD_CODE_VA.checked_add(length))
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if port_domain == class_domain
        || projected.class_do_registration.domain() != port_domain
        || projected.class_do_registration.device_id() != class_main.device_id()
        || class_main.domain() != class_domain
        || io_manager_mut().hosted_device_pointer_registration(class_domain, class_main.address())
            != Some(class_main)
        || !(FSD_CODE_VA..image_end).contains(&class_service)
        || records().iter().any(|row| {
            row.phase != Phase::Blocked
                && (row.reverse_owner_id == reverse_owner_id
                    || row.port_alias_main == projected.class_do_registration)
        })
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let owner = HostedProviderObjectOwner::new(
        port_domain.domain_id.raw(),
        port_domain.cookie,
        class_domain.domain_id.raw(),
        class_domain.cookie,
    )
    .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let discriminator = class_main.generation()
        ^ projected.class_do_registration.generation().rotate_left(17)
        ^ (u64::from(control.code()) << 32);
    let key = HostedThunkSlotKey::new(owner, PURPOSE_CLASS_SERVICE, class_service, discriminator)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    records()
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let cookie = unsafe { NEXT_COOKIE };
    let next = cookie
        .checked_add(1)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let reservation =
        reserve_instance_executable_thunk(port_instance, key).map_err(nt_status::NtStatus)?;
    if reservation.existing {
        abort_instance_executable_thunk(port_instance, reservation);
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    let binding = reservation.address(port_instance).binding;
    records().push(Record {
        cookie,
        phase: Phase::Reserved,
        port_instance,
        class_instance,
        port_domain,
        class_domain,
        reverse_owner_id,
        class_main,
        port_alias_main: projected.class_do_registration,
        class_service,
        control,
        class_image_frame_base: class_inst.image_frame_base,
        class_image_frames: class_inst.image_frames,
        binding,
        run_va: reservation.run_va,
    });
    unsafe {
        NEXT_COOKIE = next;
    }
    let slot = core::slice::from_raw_parts_mut(reservation.exec_va as *mut u8, THUNK_BYTES);
    if !encode(cookie, class_domain, class_service_gate_va(), slot)
        || !commit_instance_executable_thunk(port_instance, reservation)
    {
        records().last_mut().unwrap().phase = Phase::Blocked;
        abort_instance_executable_thunk(port_instance, reservation);
        return Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    records().last_mut().unwrap().phase = Phase::Published;
    Ok(PublishedClassServiceThunk {
        cookie,
        port_address: reservation.run_va,
        port_class_alias: projected.class_do_registration,
        class_service: ClassServiceThunk {
            domain: class_domain,
            address: class_service,
            generation: class_domain.cookie,
        },
    })
}

/// CONNECT may publish the thunk address to i8042 only when a separate IRQ execution owner has
/// installed the corresponding permit. This check keeps the preparation API unusable by itself.
pub(super) unsafe fn verify_permit(
    permit: &hosted_class_callback_lane::ClassCallbackExecutionPermit,
    thunk: PublishedClassServiceThunk,
) -> bool {
    permit.verifies(thunk.cookie, thunk.port_address, thunk.port_class_alias)
        && record(thunk.cookie).is_some_and(|row| {
            row.phase == Phase::Published
                && row.run_va == thunk.port_address
                && row.port_alias_main == thunk.port_class_alias
                && hosted_reverse_class_projection::validate(row.reverse_owner_id)
                    .is_ok_and(|projected| projected.class_do_registration == row.port_alias_main)
        })
}

fn encode(cookie: u64, class_domain: HostedDomainIdentity, gate: u64, out: &mut [u8]) -> bool {
    if cookie == 0 || gate == 0 || class_domain.cookie == 0 || out.len() < THUNK_BYTES {
        return false;
    }
    // Same four-register preserving encoding as the provider callback thunk, but the gate below
    // has its own authority, four-argument ABI and IRQ service kind.
    out[..THUNK_BYTES].copy_from_slice(&[
        0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0x4c, 0x8d, 0x1d,
        0x04, 0, 0, 0, 0x41, 0xff, 0x63, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ]);
    out[2..10].copy_from_slice(&cookie.to_le_bytes());
    out[12..20].copy_from_slice(&class_domain.cookie.to_le_bytes());
    out[31..39].copy_from_slice(&class_domain.domain_id.raw().to_le_bytes());
    out[39..47].copy_from_slice(&class_domain.cookie.to_le_bytes());
    out[47..55].copy_from_slice(&gate.to_le_bytes());
    true
}

/// Root-side admission for the dedicated IRQ service. The caller must then acquire exact port
/// input and consumed-output memory leases and retain the class execution transaction. This
/// function returns no execution permit; its purpose is to reject stale executable slots.
pub(super) unsafe fn admit_irq_request(
    cookie: u64,
    class_domain: HostedDomainIdentity,
    port_class_alias: u64,
) -> Result<
    (
        usize,
        usize,
        HostedDevicePointerRegistration,
        HostedDevicePointerRegistration,
        u64,
        ConnectControl,
    ),
    nt_status::NtStatus,
> {
    let row = record(cookie).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let projected = hosted_reverse_class_projection::validate(row.reverse_owner_id)?;
    if row.phase != Phase::Published
        || row.class_domain != class_domain
        || projected.class_do_registration != row.port_alias_main
        || port_class_alias != row.port_alias_main.address()
        || instance(row.port_instance).and_then(instance_domain_identity) != Some(row.port_domain)
        || instance(row.class_instance).and_then(instance_domain_identity) != Some(row.class_domain)
        || instance(row.class_instance).is_none_or(|inst| {
            inst.image_frame_base != row.class_image_frame_base
                || inst.image_frames != row.class_image_frames
        })
        || io_manager_mut()
            .hosted_device_pointer_registration(row.class_domain, row.class_main.address())
            != Some(row.class_main)
    {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok((
        row.port_instance,
        row.class_instance,
        row.port_alias_main,
        row.class_main,
        row.class_service,
        row.control,
    ))
}

/// Stop any new ingress when source completion or disconnect becomes uncertain.
pub(super) fn block(cookie: u64) {
    if let Some(row) = records().iter_mut().find(|row| row.cookie == cookie) {
        row.phase = Phase::Blocked;
    }
}

pub(super) fn instance_quiesced(index: usize) -> bool {
    records()
        .iter()
        .all(|row| row.port_instance != index && row.class_instance != index)
}

core::arch::global_asm!(
    ".text",
    ".globl hosted_class_service_gate",
    "hosted_class_service_gate:",
    "sub rsp, 0x48",
    "mov [rsp + 0x20], rcx",
    "mov [rsp + 0x28], rdx",
    "mov [rsp + 0x30], r8",
    "mov [rsp + 0x38], r9",
    "mov rcx, rax",
    "mov rdx, r10",
    "mov r8, [r11]",
    "mov r9, [r11 + 8]",
    "call s_hosted_class_service_gate_body",
    "add rsp, 0x48",
    "ret",
);

extern "win64" {
    fn hosted_class_service_gate();
}

fn class_service_gate_va() -> u64 {
    hosted_class_service_gate as *const () as usize as u64
}

#[no_mangle]
extern "win64" fn s_hosted_class_service_gate_body(
    cookie: u64,
    thunk_generation: u64,
    class_domain_id: u64,
    class_domain_cookie: u64,
    class_alias: u64,
    input_start: u64,
    input_end: u64,
    consumed_output: u64,
) {
    unsafe {
        // A normal component request cannot carry an interrupt/DPC continuation. The root-side
        // service verifies the publication cookie and both port memory leases before dispatch.
        let Some((_, _, _, _, grant)) = hosted_irq_lane_context() else {
            hosted_irq_lane_protocol_fault(cookie);
        };
        if cookie == 0
            || thunk_generation == 0
            || thunk_generation != class_domain_cookie
            || class_domain_id == 0
            || class_alias == 0
            || input_start == 0
            || input_end <= input_start
            || consumed_output == 0
        {
            hosted_irq_lane_protocol_fault(cookie);
        }
        let mut arguments = [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_ARGUMENT_CAP];
        arguments[..4].copy_from_slice(&[class_alias, input_start, input_end, consumed_output]);
        let result = hosted_irq_lane_service(nt_hosted_runtime::HostedIrqServiceCommand {
            kind: nt_hosted_runtime::HostedIrqServiceKind::ClassServiceRequest,
            service_id: cookie,
            target_domain_id: class_domain_id,
            target_domain_cookie: class_domain_cookie,
            authority_cookie: thunk_generation,
            grant,
            argument_count: 4,
            arguments,
        });
        if result.faulted || result.status != STATUS_SUCCESS || result.value_count != 0 {
            hosted_irq_lane_protocol_fault(cookie);
        }
    }
}
