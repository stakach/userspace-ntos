//! Driver PnP interface notifications with root-owned registration and callback tickets.

use super::*;
use nt_io_manager::{DeviceReference, FileReference, HostedDeviceProjectionReference,
    HostedFileIdentity, HostedFilePublicationLease};
use nt_pnp_manager::{DevnodeIdentity, target_device_change::{
    CustomTargetNotification, NotificationError,
}};

const EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE: u32 = 2;
const EVENT_CATEGORY_TARGET_DEVICE_CHANGE: u32 = 3;
const GUID_DEVICE_INTERFACE_ARRIVAL: [u8; 16] = [
    0x04, 0x40, 0x3a, 0xcb, 0xf0, 0x46, 0xd0, 0x11,
    0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
];
const GUID_DEVICE_INTERFACE_REMOVAL: [u8; 16] = [
    0x05, 0x40, 0x3a, 0xcb, 0xf0, 0x46, 0xd0, 0x11,
    0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
];
const OP_REGISTER: u64 = 1;
const OP_UNREGISTER: u64 = 2;
const OP_REPORT_TARGET: u64 = 3;
const ARG_GUID: u64 = 0;
const ARG_CALLBACK: u64 = 16;
const ARG_CONTEXT: u64 = 24;
const ARG_EVENT_KIND: u64 = 32;
const ARG_LINK_LEN: u64 = 36;
const ARG_LINK_BUF: u64 = 40;
const DISPATCH_TARGET: u32 = 2;
const DISPATCH_TARGET_COMPLETE: u32 = 3;
const _: () = assert!(ARG_LINK_BUF + (HOSTED_INTERFACE_LINK_MAX as u64 + 1) * 2 <= FSD_ARG_BYTES);

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(0);
static NEXT_EVENT: AtomicU64 = AtomicU64::new(0);
static mut REGISTRATIONS: Vec<Registration> = Vec::new();
static mut EVENTS: Vec<Event> = Vec::new();
static mut TARGET_REGISTRATIONS: Vec<TargetRegistration> = Vec::new();
static mut TARGET_REPORTS: Vec<TargetReport> = Vec::new();

struct TargetRegistration {
    cookie: u64,
    instance: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
    driver_object: u64,
    callback: u64,
    context: u64,
    file: HostedFileIdentity,
    file_reference: FileReference,
    file_lease: HostedFilePublicationLease,
    pdo: nt_io_manager::DeviceId,
    devnode: DevnodeIdentity,
    pdo_reference: DeviceReference,
}

struct TargetReport {
    ticket: u64,
    reporter_instance: usize,
    reporter_driver_id: u64,
    reporter_domain: HostedDomainIdentity,
    reporter_driver_object: u64,
    completion: u64,
    completion_context: u64,
    pdo: nt_io_manager::DeviceId,
    devnode: DevnodeIdentity,
    pdo_owner: HostedDeviceProjectionReference,
    notification: CustomTargetNotification,
    subscribers: Vec<u64>,
    next: usize,
    state: EventState,
    // Kept across an uncertain callback. The provider pool allocation may still be in use.
    delivery_allocation: Option<(usize, u64)>,
}

#[derive(Clone, Copy)]
struct Registration {
    cookie: u64,
    instance: usize,
    driver_id: u64,
    domain: HostedDomainIdentity,
    driver_object: u64,
    callback: u64,
    context: u64,
    class_guid: [u8; 16],
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EventState { Pending, Executing }

#[derive(Clone, Copy)]
struct Event {
    ticket: u64,
    cookie: u64,
    domain: HostedDomainIdentity,
    class_guid: [u8; 16],
    link: HostedAscii<HOSTED_INTERFACE_LINK_MAX>,
    enabled: bool,
    state: EventState,
}

/// NTSTATUS IoRegisterPlugPlayNotification(..., PVOID *NotificationEntry).
pub(super) extern "win64" fn register(
    category: u32,
    flags: u32,
    class_guid: u64,
    driver_object: u64,
    callback: u64,
    context: u64,
    output: u64,
) -> i32 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    unsafe { write_unaligned(output as *mut u64, 0); }
    if !matches!(category, EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE | EVENT_CATEGORY_TARGET_DEVICE_CHANGE)
        || flags != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if class_guid == 0 || driver_object == 0 || callback == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let _guard = component_device_reply_lock();
        if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE {
            let guid = read_unaligned(class_guid as *const [u8; 16]);
            core::ptr::copy_nonoverlapping(guid.as_ptr(), (FSD_ARG_VADDR + ARG_GUID) as *mut u8, 16);
        } else {
            write_volatile((FSD_ARG_VADDR + ARG_LINK_BUF) as *mut u64, class_guid);
        }
        write_volatile((FSD_ARG_VADDR + ARG_CALLBACK) as *mut u64, callback);
        write_volatile((FSD_ARG_VADDR + ARG_CONTEXT) as *mut u64, context);
        let (info, status, cookie, _, _) = call_on4_raw(
            (FSD_SERVICE_PNP_NOTIFICATION_LABEL << 12) | 4,
            OP_REGISTER, category as u64, flags as u64, driver_object,
        );
        if info != 2 || (status as u32 as i32 == STATUS_SUCCESS && cookie == 0) {
            // Root may have committed the registration. Never replay or lose that owner.
            crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_PNP_NOTIFICATION_LABEL, OP_REGISTER, info, status]);
        }
        let status = status as u32 as i32;
        if status == STATUS_SUCCESS { write_unaligned(output as *mut u64, cookie); }
        status
    }
}

/// A successful call owns a queued report even if the provider never receives its reply.
pub(super) extern "win64" fn report_target_async(
    pdo: u64, notification: u64, callback: u64, context: u64,
) -> i32 {
    if pdo == 0 || notification == 0 { return STATUS_INVALID_PARAMETER; }
    unsafe {
        let _guard = component_device_reply_lock();
        write_volatile((FSD_ARG_VADDR + ARG_CALLBACK) as *mut u64, callback);
        write_volatile((FSD_ARG_VADDR + ARG_CONTEXT) as *mut u64, context);
        let (info, status, reserved0, reserved1, reserved2) = call_on4_raw(
            (FSD_SERVICE_PNP_NOTIFICATION_LABEL << 12) | 4,
            OP_REPORT_TARGET, pdo, notification, 0,
        );
        if info != 2 || reserved0 != 0 || reserved1 != 0 || reserved2 != 0 {
            crate::provider_bugcheck::report(0xc4,
                [FSD_SERVICE_PNP_NOTIFICATION_LABEL, OP_REPORT_TARGET, info, status]);
        }
        status as u32 as i32
    }
}

/// NTSTATUS IoUnregisterPlugPlayNotification(PVOID NotificationEntry).
pub(super) extern "win64" fn unregister(cookie: u64) -> i32 {
    if cookie == 0 { return STATUS_INVALID_PARAMETER; }
    let (info, status, _, _, _) = unsafe {
        call_on4_raw((FSD_SERVICE_PNP_NOTIFICATION_LABEL << 12) | 4, OP_UNREGISTER, cookie, 0, 0)
    };
    if info != 2 {
        unsafe { crate::provider_bugcheck::report(
            0xc4, [FSD_SERVICE_PNP_NOTIFICATION_LABEL, OP_UNREGISTER, info, status],
        ); }
    }
    status as u32 as i32
}

/// The Ex contract guarantees that no callback can run after success. The root
/// service removes pending deliveries and the registration in one serialized
/// operation; an executing/uncertain callback keeps both owners and cannot be
/// acknowledged as quiescent.
pub(super) extern "win64" fn unregister_ex(cookie: u64) -> i32 {
    let status = unregister(cookie);
    if status == nt_status::NtStatus::DEVICE_BUSY.raw() {
        unsafe { crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_PNP_NOTIFICATION_LABEL, OP_UNREGISTER, cookie, status as u32 as u64]); }
    }
    status
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, reply_cap) else {
        return (STATUS_ACCESS_DENIED, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else { return (STATUS_ACCESS_DENIED, 0); };
    if hosted_driver_caller(index, inst, badge).is_none() { return (STATUS_ACCESS_DENIED, 0); }
    if op == OP_UNREGISTER {
        if arg2 != 0 || arg3 != 0 { return (STATUS_INVALID_PARAMETER, 0); }
        let rows = unsafe { &mut *core::ptr::addr_of_mut!(REGISTRATIONS) };
        let position = rows.iter().position(|row| row.cookie == arg1 && row.domain == domain);
        if position.is_none() {
            return unsafe { unregister_target(arg1, domain) };
        }
        let events = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
        if events.iter().any(|event| event.cookie == arg1 && event.state == EventState::Executing) {
            return (nt_status::NtStatus::DEVICE_BUSY.raw(), 0);
        }
        events.retain(|event| event.cookie != arg1);
        rows.remove(position.expect("registration position"));
        return (STATUS_SUCCESS, 0);
    }
    if op == OP_REPORT_TARGET {
        if arg3 != 0 { return (STATUS_INVALID_PARAMETER, 0); }
        return unsafe { report_target(ch, index, inst, domain, arg1, arg2, reply_cap) };
    }
    if op != OP_REGISTER || arg2 != 0 || !matches!(arg1,
        x if x == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE as u64
            || x == EVENT_CATEGORY_TARGET_DEVICE_CHANGE as u64) {
        return (STATUS_NOT_SUPPORTED, 0);
    }
    if inst.exec_arg_va == 0 || arg3 == 0 || inst.driver_id == 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let Some(image_end) = inst.image_frames.checked_mul(0x1000)
        .and_then(|bytes| FSD_CODE_VA.checked_add(bytes)) else { return (STATUS_INVALID_PARAMETER, 0); };
    let current_driver = unsafe { read_volatile((ch.shared_va + SH_DRVOBJ) as *const u64) };
    if current_driver != arg3 || inst.driver_object != arg3 {
        return (STATUS_ACCESS_DENIED, 0);
    }
    let callback = unsafe { read_volatile((inst.exec_arg_va + ARG_CALLBACK) as *const u64) };
    let context = unsafe { read_volatile((inst.exec_arg_va + ARG_CONTEXT) as *const u64) };
    if callback < FSD_CODE_VA || callback >= image_end { return (STATUS_INVALID_PARAMETER, 0); }
    if arg1 == EVENT_CATEGORY_TARGET_DEVICE_CHANGE as u64 {
        let file_address = unsafe { read_volatile((inst.exec_arg_va + ARG_LINK_BUF) as *const u64) };
        return unsafe { register_target(index, inst, domain, file_address, arg3, callback, context) };
    }
    let guid = unsafe { read_unaligned((inst.exec_arg_va + ARG_GUID) as *const [u8; 16]) };
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(REGISTRATIONS) };
    if rows.try_reserve(1).is_err() { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
    let cookie = match NEXT_COOKIE.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| last.checked_add(1)) {
        Ok(last) => last + 1,
        Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0),
    };
    rows.push(Registration {
        cookie, instance: index, driver_id: inst.driver_id, domain,
        driver_object: arg3, callback, context, class_guid: guid,
    });
    (STATUS_SUCCESS, cookie)
}

unsafe fn target_pdo_for_file(file: nt_io_manager::FileId) -> Option<nt_io_manager::DeviceId> {
    let io = io_manager_mut();
    let mut current = io.related_device_for_file(file).ok()?;
    for _ in 0..=io.device_count() {
        let device = io.device(current)?;
        match device.attached_to {
            Some(lower) if lower != current => current = lower,
            Some(_) => return None,
            None => return Some(current),
        }
    }
    None
}

unsafe fn register_target(
    index: usize, inst: DriverInstance, domain: HostedDomainIdentity,
    file_address: u64, driver_object: u64, callback: u64, context: u64,
) -> (i32, u64) {
    if file_address == 0 { return (STATUS_INVALID_PARAMETER, 0); }
    let rows = &mut *core::ptr::addr_of_mut!(TARGET_REGISTRATIONS);
    if rows.try_reserve(1).is_err() { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
    let file = match io_manager_mut().hosted_file_identity_at_address(domain, file_address) {
        Ok(Some(file)) => file,
        _ => return (STATUS_INVALID_HANDLE, 0),
    };
    if hosted_device_allocations::file_storage_bound_generation(
        inst, file.file_id().raw(), file_address,
    ) != Some(file.binding_generation()) {
        return (STATUS_INVALID_HANDLE, 0);
    }
    let Some(pdo) = target_pdo_for_file(file.file_id()) else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let Some(devnode) = hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo.raw()) else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let mut lease = match io_manager_mut().lease_hosted_file_identity(file) {
        Ok(lease) => lease,
        Err(status) => return (status.raw(), 0),
    };
    let mut file_reference = match io_manager_mut().retain_file_reference(file.file_id()) {
        Ok(reference) => reference,
        Err(status) => {
            io_manager_mut().release_hosted_file_publication(&mut lease)
                .expect("unentered target File lease rollback");
            return (status.raw(), 0);
        }
    };
    let pdo_reference = match io_manager_mut().retain_device_reference(pdo) {
        Ok(reference) => reference,
        Err(status) => {
            io_manager_mut().release_file_reference(&mut file_reference)
                .expect("unentered target File reference rollback");
            io_manager_mut().release_hosted_file_publication(&mut lease)
                .expect("unentered target File lease rollback");
            return (status.raw(), 0);
        }
    };
    let cookie = match NEXT_COOKIE.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |last| last.checked_add(1)) {
        Ok(last) => last + 1,
        Err(_) => {
            let mut pdo_reference = pdo_reference;
            io_manager_mut().release_device_reference(&mut pdo_reference)
                .expect("unentered target PDO reference rollback");
            io_manager_mut().release_file_reference(&mut file_reference)
                .expect("unentered target File reference rollback");
            io_manager_mut().release_hosted_file_publication(&mut lease)
                .expect("unentered target File lease rollback");
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
    };
    rows.push(TargetRegistration {
        cookie, instance: index, driver_id: inst.driver_id, domain, driver_object,
        callback, context, file, file_reference, file_lease: lease,
        pdo, devnode, pdo_reference,
    });
    (STATUS_SUCCESS, cookie)
}

unsafe fn unregister_target(cookie: u64, domain: HostedDomainIdentity) -> (i32, u64) {
    let rows = &mut *core::ptr::addr_of_mut!(TARGET_REGISTRATIONS);
    let Some(index) = rows.iter().position(|row| row.cookie == cookie && row.domain == domain)
        else { return (STATUS_INVALID_PARAMETER, 0); };
    let reports = &*core::ptr::addr_of!(TARGET_REPORTS);
    if reports.iter().any(|report| report.state == EventState::Executing
        && report.subscribers.get(report.next) == Some(&cookie)) {
        return (nt_status::NtStatus::DEVICE_BUSY.raw(), 0);
    }
    let row = &mut rows[index];
    if row.pdo_reference.is_held() {
        if let Err(status) = io_manager_mut().release_device_reference(&mut row.pdo_reference) {
            return (status.raw(), 0);
        }
    }
    if row.file_reference.is_held() {
        if let Err(status) = io_manager_mut().release_file_reference(&mut row.file_reference) {
            return (status.raw(), 0);
        }
    }
    if row.file_lease.is_held() {
        if let Err(status) = io_manager_mut().release_hosted_file_publication(&mut row.file_lease) {
            return (status.raw(), 0);
        }
    }
    rows.remove(index);
    (STATUS_SUCCESS, 0)
}

unsafe fn copy_target_notification(
    index: usize, inst: DriverInstance, pointer: u64,
) -> Result<CustomTargetNotification, i32> {
    let in_pool = pointer >= FSD_POOL_VADDR
        && pointer < FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000;
    let in_stack = pointer >= FSD_STACK_VADDR
        && pointer < FSD_STACK_VADDR + FSD_STACK_BYTES;
    if !in_pool && !in_stack { return Err(STATUS_INVALID_PARAMETER); }
    let _pool_guard = if in_pool {
        hosted_instance_pool_lock(inst.exec_pool_va).ok_or(STATUS_INVALID_PARAMETER)?
    } else { return copy_stack_target_notification(index, inst, pointer); };
    let (exec, capacity) = hosted_pool_allocation_exec_range(inst.exec_pool_va, pointer)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if hosted_instance_pool_allocation_is_free_unlocked(inst, pointer) != Some(false)
        || capacity < 36 { return Err(STATUS_INVALID_PARAMETER); }
    let size = read_volatile((exec + 2) as *const u16) as usize;
    if size < 36 || size as u64 > capacity { return Err(STATUS_INVALID_PARAMETER); }
    CustomTargetNotification::parse(core::slice::from_raw_parts(exec as *const u8, size))
        .map_err(target_parse_status)
}

fn target_parse_status(error: NotificationError) -> i32 {
    match error {
        NotificationError::Allocation => STATUS_INSUFFICIENT_RESOURCES,
        _ => STATUS_INVALID_PARAMETER,
    }
}

unsafe fn copy_stack_target_notification(
    index: usize, inst: DriverInstance, pointer: u64,
) -> Result<CustomTargetNotification, i32> {
    let head = component_to_exec_va_for_instance(index, inst, pointer, 36)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let size = read_volatile((head + 2) as *const u16) as usize;
    let body = component_to_exec_va_for_instance(index, inst, pointer, size as u64)
        .ok_or(STATUS_INVALID_PARAMETER)?;
    if size < 36 || pointer.checked_add(size as u64)
        .is_none_or(|end| end > FSD_STACK_VADDR + FSD_STACK_BYTES) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    CustomTargetNotification::parse(core::slice::from_raw_parts(body as *const u8, size))
        .map_err(target_parse_status)
}

unsafe fn report_target(
    ch: &crate::spawn_hosts::PumpChannel, index: usize, inst: DriverInstance,
    domain: HostedDomainIdentity, pdo_address: u64, notification_pointer: u64,
    reply_cap: u64,
) -> (i32, u64) {
    let (_, _, pdo) = match authenticated_hosted_pdo(ch, pdo_address, reply_cap) {
        Ok(target) => target,
        Err(status) => return (status.raw(), 0),
    };
    let Some(registration) = io_manager_mut().hosted_device_pointer_registration(domain, pdo_address)
        .filter(|row| row.device_id() == pdo) else { return (STATUS_INVALID_DEVICE_REQUEST, 0); };
    let Some(devnode) = hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo.raw()) else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    };
    let completion = read_volatile((inst.exec_arg_va + ARG_CALLBACK) as *const u64);
    let completion_context = read_volatile((inst.exec_arg_va + ARG_CONTEXT) as *const u64);
    let image_end = inst.image_frames.checked_mul(0x1000)
        .and_then(|bytes| FSD_CODE_VA.checked_add(bytes)).unwrap_or(0);
    if completion != 0 && (completion < FSD_CODE_VA || completion >= image_end) {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let notification = match copy_target_notification(index, inst, notification_pointer) {
        Ok(notification) => notification,
        Err(status) => return (status, 0),
    };
    let registrations = &*core::ptr::addr_of!(TARGET_REGISTRATIONS);
    let mut subscribers = Vec::new();
    if subscribers.try_reserve_exact(registrations.len()).is_err() {
        return (STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    for row in registrations.iter().filter(|row| row.pdo == pdo && row.devnode == devnode) {
        subscribers.push(row.cookie);
    }
    let reports = &mut *core::ptr::addr_of_mut!(TARGET_REPORTS);
    if reports.try_reserve(1).is_err() { return (STATUS_INSUFFICIENT_RESOURCES, 0); }
    let pdo_owner = match io_manager_mut().retain_hosted_device_projection_reference(registration) {
        Ok(owner) => owner,
        Err(status) => return (status.raw(), 0),
    };
    let ticket = match NEXT_EVENT.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |last| last.checked_add(1)) {
        Ok(last) => last + 1,
        Err(_) => {
            let mut owner = pdo_owner;
            io_manager_mut().release_hosted_device_projection_reference(&mut owner)
                .expect("unentered target PDO rollback");
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
    };
    reports.push(TargetReport {
        ticket, reporter_instance: index, reporter_driver_id: inst.driver_id,
        reporter_domain: domain, reporter_driver_object: inst.driver_object,
        completion, completion_context, pdo, devnode, pdo_owner,
        notification, subscribers, next: 0, state: EventState::Pending,
        delivery_allocation: None,
    });
    (nt_status::NtStatus::PENDING.raw(), 0)
}

/// Reserve every matching delivery before the interface state becomes visible. Caller performs
/// this after all canonical PDO/link checks and immediately before changing `enabled`.
pub(super) unsafe fn set_hosted_device_interface_state(
    class_guid: [u64; 2],
    symbolic_link: HostedAscii<HOSTED_INTERFACE_LINK_MAX>,
    enable: bool,
) -> Result<(), nt_status::NtStatus> {
    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&class_guid[0].to_le_bytes());
    guid[8..].copy_from_slice(&class_guid[1].to_le_bytes());
    let registrations = &*core::ptr::addr_of!(REGISTRATIONS);
    let matches = registrations.iter().filter(|row| row.class_guid == guid).count();
    let events = &mut *core::ptr::addr_of_mut!(EVENTS);
    events.try_reserve(matches).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let first = NEXT_EVENT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
        last.checked_add(matches as u64)
    }).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for (offset, row) in registrations.iter().filter(|row| row.class_guid == guid).enumerate() {
        events.push(Event {
            ticket: first + offset as u64 + 1,
            cookie: row.cookie,
            domain: row.domain,
            class_guid: guid,
            link: symbolic_link,
            enabled: enable,
            state: EventState::Pending,
        });
    }
    Ok(())
}

#[repr(C)]
struct UnicodeString { len: u16, max_len: u16, _pad: u32, buffer: u64 }
#[repr(C)]
struct DeviceInterfaceChangeNotification {
    version: u16,
    size: u16,
    event: [u8; 16],
    class_guid: [u8; 16],
    link: u64,
}
const _: () = assert!(core::mem::size_of::<DeviceInterfaceChangeNotification>() == 48);

pub(super) unsafe fn component_dispatch() -> (i32, u64) {
    let callback = read_volatile((FSD_SHARED_VADDR + SH_REQ_FILEID) as *const u64);
    let context = read_volatile((FSD_SHARED_VADDR + SH_REQ_FSCTL) as *const u64);
    if callback == 0 { return (STATUS_INVALID_PARAMETER, 0); }
    let dispatch_kind = read_volatile((FSD_ARG_VADDR + ARG_EVENT_KIND) as *const u32);
    if matches!(dispatch_kind, DISPATCH_TARGET | DISPATCH_TARGET_COMPLETE) {
        let notification = if dispatch_kind == DISPATCH_TARGET {
            read_volatile((FSD_ARG_VADDR + ARG_LINK_BUF) as *const u64)
        } else { 0 };
        if dispatch_kind == DISPATCH_TARGET && notification == 0 {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
        jb[0] = 0; jb[1] = 0; jb[2] = 0;
        let boundary = read_volatile((FSD_SHARED_VADDR + SH_SEH_FOREIGN_CALL16_VA) as *const u64);
        if boundary == 0 { return (STATUS_INVALID_DEVICE_REQUEST, 0); }
        let args = [if dispatch_kind == DISPATCH_TARGET { notification } else { context },
            if dispatch_kind == DISPATCH_TARGET { context } else { 0 },
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let result = fsd_guarded_call_vector(callback, args.as_ptr(), 12, jb.as_mut_ptr(), boundary);
        let bugchecked = jb[2] != 0;
        jb[1] = 0; jb[2] = 0;
        return if bugchecked { (STATUS_UNSUCCESSFUL, 0) } else { (STATUS_SUCCESS, result) };
    }
    let len = read_volatile((FSD_ARG_VADDR + ARG_LINK_LEN) as *const u16) as usize;
    if len > HOSTED_INTERFACE_LINK_MAX * 2 || len & 1 != 0 { return (STATUS_INVALID_PARAMETER, 0); }
    let mut link_units = [0u16; HOSTED_INTERFACE_LINK_MAX + 1];
    for (index, unit) in link_units.iter_mut().take(len / 2).enumerate() {
        *unit = read_volatile((FSD_ARG_VADDR + ARG_LINK_BUF + index as u64 * 2) as *const u16);
    }
    let link = UnicodeString {
        len: len as u16,
        max_len: (len + 2) as u16,
        _pad: 0,
        buffer: link_units.as_ptr() as u64,
    };
    let notification = DeviceInterfaceChangeNotification {
        version: 1,
        size: core::mem::size_of::<DeviceInterfaceChangeNotification>() as u16,
        event: if read_volatile((FSD_ARG_VADDR + ARG_EVENT_KIND) as *const u32) != 0 {
            GUID_DEVICE_INTERFACE_ARRIVAL
        } else {
            GUID_DEVICE_INTERFACE_REMOVAL
        },
        class_guid: read_unaligned((FSD_ARG_VADDR + ARG_GUID) as *const [u8; 16]),
        link: &link as *const _ as u64,
    };
    let jb = &mut *core::ptr::addr_of_mut!(BUGCHECK_JB);
    jb[0] = 0; jb[1] = 0; jb[2] = 0;
    let boundary = read_volatile((FSD_SHARED_VADDR + SH_SEH_FOREIGN_CALL16_VA) as *const u64);
    if boundary == 0 { return (STATUS_INVALID_DEVICE_REQUEST, 0); }
    let args = [&notification as *const _ as u64, context, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let result = fsd_guarded_call_vector(callback, args.as_ptr(), 12, jb.as_mut_ptr(), boundary);
    let bugchecked = jb[2] != 0;
    jb[1] = 0; jb[2] = 0;
    if bugchecked { return (STATUS_UNSUCCESSFUL, 0); }
    (STATUS_SUCCESS, result)
}

/// Timer-driven root dispatch runs only after the originating SetInterfaceState Call replied.
/// An uncertain callback remains Executing and cannot be retried or discarded during unload.
pub(crate) unsafe fn wake_due() -> u64 {
    if wake_target_due() != 0 { return 1; }
    let Some(event) = (&*core::ptr::addr_of!(EVENTS)).iter()
        .copied().find(|event| event.state == EventState::Pending) else { return 0; };
    let Some(registration) = (&*core::ptr::addr_of!(REGISTRATIONS))
        .iter().copied().find(|row| row.cookie == event.cookie
            && row.domain == event.domain && row.class_guid == event.class_guid)
    else {
        (&mut *core::ptr::addr_of_mut!(EVENTS)).retain(|row| row.ticket != event.ticket);
        return 1;
    };
    let Some(inst) = instance(registration.instance) else { return 0; };
    if !inst.ready || inst.driver_id != registration.driver_id
        || instance_domain_identity(inst) != Some(registration.domain)
        || inst.driver_object != registration.driver_object || inst.exec_arg_va == 0
    { return 0; }
    // Begin has an irreversible native callback effect. Retain this event on any uncertain result.
    if let Some(row) = (&mut *core::ptr::addr_of_mut!(EVENTS)).iter_mut()
        .find(|row| row.ticket == event.ticket)
    { row.state = EventState::Executing; }
    let arg = inst.exec_arg_va;
    core::ptr::copy_nonoverlapping(event.class_guid.as_ptr(), (arg + ARG_GUID) as *mut u8, 16);
    write_volatile((arg + ARG_EVENT_KIND) as *mut u32, u32::from(event.enabled));
    write_volatile((arg + ARG_LINK_LEN) as *mut u16, (event.link.len * 2) as u16);
    for (offset, byte) in event.link.as_bytes().iter().enumerate() {
        write_volatile((arg + ARG_LINK_BUF + offset as u64 * 2) as *mut u16, *byte as u16);
    }
    let dispatched = dispatch_device_projection_control_for_instance(
        registration.instance,
        registration.driver_object,
        FSD_DISPATCH_PNP_NOTIFICATION,
        registration.callback,
        registration.context,
        false,
        None,
        crate::initial_system_driver_caller(),
    );
    if dispatched.is_ok() {
        (&mut *core::ptr::addr_of_mut!(EVENTS)).retain(|row| row.ticket != event.ticket);
    }
    1
}

unsafe fn target_registration_dispatch(cookie: u64, pdo: nt_io_manager::DeviceId,
    devnode: DevnodeIdentity,
) -> Option<(usize, u64, u64, u64, u64)> {
    let row = (&*core::ptr::addr_of!(TARGET_REGISTRATIONS)).iter()
        .find(|row| row.cookie == cookie && row.pdo == pdo && row.devnode == devnode)?;
    let inst = instance(row.instance)?;
    if !inst.ready || inst.driver_id != row.driver_id
        || instance_domain_identity(inst) != Some(row.domain)
        || inst.driver_object != row.driver_object || inst.exec_arg_va == 0
        || io_manager_mut().hosted_file_identity_at_address(row.domain, row.file.address()).ok()?
            != Some(row.file)
        || hosted_device_allocations::file_storage_bound_generation(
            inst, row.file.file_id().raw(), row.file.address(),
        ) != Some(row.file.binding_generation())
    { return None; }
    Some((row.instance, row.driver_object, row.callback, row.context, row.file.address()))
}

unsafe fn finish_target_report(ticket: u64) -> bool {
    let reports = &mut *core::ptr::addr_of_mut!(TARGET_REPORTS);
    let Some(index) = reports.iter().position(|row| row.ticket == ticket) else { return false; };
    let report = &mut reports[index];
    if io_manager_mut().release_hosted_device_projection_reference(&mut report.pdo_owner).is_err() {
        return false;
    }
    reports.remove(index);
    true
}

unsafe fn wake_target_due() -> u64 {
    let (ticket, pdo, devnode, cookie, completion, reporter_index,
        reporter_driver_id, reporter_domain, reporter_driver_object, completion_context) = {
        let reports = &mut *core::ptr::addr_of_mut!(TARGET_REPORTS);
        let Some(report) = reports.iter_mut().find(|row| row.state == EventState::Pending)
            else { return 0; };
        if hosted_pnp_manager_mut().devnode_identity_for_pdo(report.pdo.raw()) != Some(report.devnode) {
            report.next = report.subscribers.len();
        }
        (report.ticket, report.pdo, report.devnode,
            report.subscribers.get(report.next).copied(), report.completion,
            report.reporter_instance, report.reporter_driver_id, report.reporter_domain,
            report.reporter_driver_object, report.completion_context)
    };
    if let Some(cookie) = cookie {
        let Some((instance_index, driver_object, callback, context, file_address)) =
            target_registration_dispatch(cookie, pdo, devnode) else {
                if let Some(report) = (&mut *core::ptr::addr_of_mut!(TARGET_REPORTS))
                    .iter_mut().find(|row| row.ticket == ticket) {
                    report.next += 1;
                }
                return 1;
            };
        let Some(inst) = instance(instance_index) else { return 0; };
        let size = (&*core::ptr::addr_of!(TARGET_REPORTS)).iter()
            .find(|row| row.ticket == ticket).expect("pending target report").notification.bytes().len();
        let Some(allocation) = hosted_instance_pool_alloc(inst, size as u64) else {
            // Resource failure precedes native entry. Leave the report pending for a later wake.
            return 0;
        };
        let Some(exec) = component_pool_to_exec_va(inst.exec_pool_va, allocation, size as u64) else {
            let report = (&mut *core::ptr::addr_of_mut!(TARGET_REPORTS)).iter_mut()
                .find(|row| row.ticket == ticket).expect("pending target report");
            report.delivery_allocation = Some((instance_index, allocation));
            report.state = EventState::Executing;
            return 1;
        };
        {
            let report = (&*core::ptr::addr_of!(TARGET_REPORTS)).iter()
                .find(|row| row.ticket == ticket).expect("pending target report");
            let bytes = report.notification.bytes();
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), exec as *mut u8, bytes.len());
        }
        write_unaligned((exec + 24) as *mut u64, file_address);
        write_volatile((inst.exec_arg_va + ARG_EVENT_KIND) as *mut u32, DISPATCH_TARGET);
        write_volatile((inst.exec_arg_va + ARG_LINK_BUF) as *mut u64, allocation);
        {
            let report = (&mut *core::ptr::addr_of_mut!(TARGET_REPORTS)).iter_mut()
                .find(|row| row.ticket == ticket).expect("pending target report");
            report.delivery_allocation = Some((instance_index, allocation));
            report.state = EventState::Executing;
        }
        let result = dispatch_device_projection_control_for_instance(
            instance_index, driver_object, FSD_DISPATCH_PNP_NOTIFICATION,
            callback, context, false, None, crate::initial_system_driver_caller(),
        );
        if result.is_ok() {
            let Some(_guard) = hosted_instance_pool_lock(inst.exec_pool_va) else { return 1; };
            if !hosted_instance_pool_free_unlocked(inst, allocation) { return 1; }
            let Some(report) = (&mut *core::ptr::addr_of_mut!(TARGET_REPORTS))
                .iter_mut().find(|row| row.ticket == ticket) else { return 1; };
            report.delivery_allocation = None;
            report.next += 1;
            report.state = EventState::Pending;
        }
        return 1;
    }
    if completion == 0 {
        return u64::from(finish_target_report(ticket));
    }
    let Some(inst) = instance(reporter_index) else { return 0; };
    if !inst.ready || inst.driver_id != reporter_driver_id
        || instance_domain_identity(inst) != Some(reporter_domain)
        || inst.driver_object != reporter_driver_object || inst.exec_arg_va == 0 {
        return 0;
    }
    write_volatile((inst.exec_arg_va + ARG_EVENT_KIND) as *mut u32, DISPATCH_TARGET_COMPLETE);
    (&mut *core::ptr::addr_of_mut!(TARGET_REPORTS)).iter_mut()
        .find(|row| row.ticket == ticket).expect("pending target report").state = EventState::Executing;
    let result = dispatch_device_projection_control_for_instance(
        reporter_index, inst.driver_object, FSD_DISPATCH_PNP_NOTIFICATION,
        completion, completion_context, false, None,
        crate::initial_system_driver_caller(),
    );
    if result.is_ok() { let _ = finish_target_report(ticket); }
    1
}

pub(crate) unsafe fn retire_domain(domain: HostedDomainIdentity) {
    (&mut *core::ptr::addr_of_mut!(REGISTRATIONS)).retain(|row| row.domain != domain);
    let live = &*core::ptr::addr_of!(REGISTRATIONS);
    (&mut *core::ptr::addr_of_mut!(EVENTS)).retain(|event| live.iter().any(|row| row.cookie == event.cookie));
    let cookies: Vec<u64> = (&*core::ptr::addr_of!(TARGET_REGISTRATIONS)).iter()
        .filter(|row| row.domain == domain).map(|row| row.cookie).collect();
    for cookie in cookies { let _ = unregister_target(cookie, domain); }
}

pub(crate) unsafe fn quiesced(domain: HostedDomainIdentity) -> bool {
    (&*core::ptr::addr_of!(REGISTRATIONS)).iter().all(|row| row.domain != domain)
        && (&*core::ptr::addr_of!(EVENTS)).iter().all(|row| row.domain != domain)
        && (&*core::ptr::addr_of!(TARGET_REGISTRATIONS)).iter().all(|row| row.domain != domain)
        && (&*core::ptr::addr_of!(TARGET_REPORTS)).iter().all(|row| row.reporter_domain != domain
            && !row.subscribers.iter().any(|cookie| {
                (&*core::ptr::addr_of!(TARGET_REGISTRATIONS)).iter()
                    .any(|registration| registration.cookie == *cookie && registration.domain == domain)
            }))
}
