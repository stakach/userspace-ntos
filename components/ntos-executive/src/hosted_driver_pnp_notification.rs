//! Driver PnP interface notifications with root-owned registration and callback tickets.

use super::*;

const EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE: u32 = 2;
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
const ARG_GUID: u64 = 0;
const ARG_CALLBACK: u64 = 16;
const ARG_CONTEXT: u64 = 24;
const ARG_EVENT_KIND: u64 = 32;
const ARG_LINK_LEN: u64 = 36;
const ARG_LINK_BUF: u64 = 40;
const _: () = assert!(ARG_LINK_BUF + (HOSTED_INTERFACE_LINK_MAX as u64 + 1) * 2 <= FSD_ARG_BYTES);

static NEXT_COOKIE: AtomicU64 = AtomicU64::new(0);
static NEXT_EVENT: AtomicU64 = AtomicU64::new(0);
static mut REGISTRATIONS: Vec<Registration> = Vec::new();
static mut EVENTS: Vec<Event> = Vec::new();

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
    if category != EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE || flags != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    if class_guid == 0 || driver_object == 0 || callback == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        let _guard = component_device_reply_lock();
        let guid = read_unaligned(class_guid as *const [u8; 16]);
        core::ptr::copy_nonoverlapping(guid.as_ptr(), (FSD_ARG_VADDR + ARG_GUID) as *mut u8, 16);
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
        let Some(position) = rows.iter().position(|row| row.cookie == arg1 && row.domain == domain) else {
            return (STATUS_INVALID_PARAMETER, 0);
        };
        let events = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
        if events.iter().any(|event| event.cookie == arg1 && event.state == EventState::Executing) {
            return (nt_status::NtStatus::DEVICE_BUSY.raw(), 0);
        }
        events.retain(|event| event.cookie != arg1);
        rows.remove(position);
        return (STATUS_SUCCESS, 0);
    }
    if op != OP_REGISTER || arg1 != EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE as u64 || arg2 != 0 {
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

pub(crate) unsafe fn retire_domain(domain: HostedDomainIdentity) {
    (&mut *core::ptr::addr_of_mut!(REGISTRATIONS)).retain(|row| row.domain != domain);
    let live = &*core::ptr::addr_of!(REGISTRATIONS);
    (&mut *core::ptr::addr_of_mut!(EVENTS)).retain(|event| live.iter().any(|row| row.cookie == event.cookie));
}

pub(crate) unsafe fn quiesced(domain: HostedDomainIdentity) -> bool {
    (&*core::ptr::addr_of!(REGISTRATIONS)).iter().all(|row| row.domain != domain)
        && (&*core::ptr::addr_of!(EVENTS)).iter().all(|row| row.domain != domain)
}
