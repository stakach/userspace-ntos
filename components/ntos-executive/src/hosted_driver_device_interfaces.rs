//! `IoGetDeviceInterfaces` for isolated hosted drivers, backed by the CM snapshot.

use super::*;

static NEXT_TRANSFER: AtomicU64 = AtomicU64::new(0);
static mut TRANSFERS: Vec<Transfer> = Vec::new();

#[derive(Clone, Copy, Eq, PartialEq)]
struct Owner {
    domain: HostedDomainIdentity,
    pdo: u64,
    pdo_id: Option<nt_io_manager::DeviceId>,
    devnode: Option<nt_pnp_manager::DevnodeIdentity>,
}

struct Transfer {
    owner: Owner,
    token: u64,
    bytes: Vec<u8>,
    next: usize,
}

fn encode_multi_sz(links: &[String]) -> Result<Vec<u8>, i32> {
    let units = links.iter().try_fold(1usize, |count, link| {
        if link.contains('\0') { return None; }
        count.checked_add(link.encode_utf16().count())?.checked_add(1)
    }).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut result = Vec::new();
    result.try_reserve_exact(units.checked_mul(2).ok_or(STATUS_INSUFFICIENT_RESOURCES)?)
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for link in links {
        for unit in link.encode_utf16().chain(core::iter::once(0)) {
            result.extend_from_slice(&unit.to_le_bytes());
        }
    }
    result.extend_from_slice(&0u16.to_le_bytes());
    Ok(result)
}

fn exchange(op: u64, pdo: u64, arg2: u64, arg3: u64) -> Result<(u64, u64, usize), i32> {
    let (info, status, total, token, chunk) = unsafe {
        call_on4_raw((FSD_SERVICE_DEVICE_LABEL << 12) | 4, op, pdo, arg2, arg3)
    };
    if info >> 12 != 0 || (info & 0xf80) != 0 || (info & 0x7f) != 4
        || chunk > device_property::PROPERTY_CHUNK_BYTES as u64
    {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    if status as i32 != STATUS_SUCCESS {
        return Err(status as i32);
    }
    Ok((total, token, chunk as usize))
}

/// NTSTATUS IoGetDeviceInterfaces(const GUID*, PDEVICE_OBJECT, ULONG, PWSTR*).
pub(super) extern "win64" fn s_io_get_device_interfaces(
    guid_pointer: u64,
    pdo: u64,
    flags: u32,
    output: u64,
) -> i32 {
    if guid_pointer == 0 || output == 0 || flags > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe {
        write_unaligned(output as *mut u64, 0);
        let guid = read_unaligned(guid_pointer as *const [u8; 16]);
        let _guard = component_device_reply_lock();
        write_volatile(FSD_ARG_VADDR as *mut u32, flags);
        let (total, token, first) = match exchange(
            HOSTED_DEVICE_OP_GET_INTERFACE_BEGIN,
            pdo,
            u64::from_le_bytes(guid[..8].try_into().unwrap()),
            u64::from_le_bytes(guid[8..].try_into().unwrap()),
        ) { Ok(reply) => reply, Err(status) => return status };
        let Ok(total) = usize::try_from(total) else { return STATUS_INSUFFICIENT_RESOURCES; };
        if total < 2 || total % 2 != 0 || first > total || (first == total) != (token == 0) {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        let allocation = pool_alloc(total as u64);
        if allocation == 0 {
            if token != 0 {
                let _ = exchange(HOSTED_DEVICE_OP_GET_INTERFACE_ABORT, pdo, token, 0);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        copy_bytes_unchecked(allocation, FSD_ARG_VADDR + HOSTED_DEVICE_ARG_DATA_OFF, first as u64);
        let mut offset = first;
        while offset < total {
            let (reported, reply_token, written) = match exchange(
                HOSTED_DEVICE_OP_GET_INTERFACE_PULL, pdo, token, offset as u64,
            ) {
                Ok(reply) => reply,
                Err(status) => {
                    // The root retains uncertain transfers until the owner domain retires.
                    pool_free(allocation);
                    return status;
                }
            };
            if reported != total as u64 || reply_token != token || written == 0
                || written > total - offset
            {
                pool_free(allocation);
                return STATUS_INVALID_DEVICE_REQUEST;
            }
            copy_bytes_unchecked(
                allocation + offset as u64,
                FSD_ARG_VADDR + HOSTED_DEVICE_ARG_DATA_OFF,
                written as u64,
            );
            offset += written;
        }
        write_unaligned(output as *mut u64, allocation);
        STATUS_SUCCESS
    }
}

fn owner(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    pdo: u64,
) -> Result<(Owner, u64), i32> {
    let (instance, inst) = instance_for_pump_channel(ch, reply_cap)
        .ok_or(STATUS_ACCESS_DENIED)?;
    if hosted_driver_caller(instance, inst, badge).is_none() || inst.exec_arg_va == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(inst.hosted_domain_id),
        cookie: inst.hosted_domain_cookie,
    };
    if pdo == 0 {
        return Ok((Owner { domain, pdo, pdo_id: None, devnode: None }, inst.exec_arg_va));
    }
    let (_, _, pdo_id) = authenticated_hosted_pdo(ch, pdo, reply_cap)
        .map_err(|status| status.raw())?;
    let devnode = unsafe { hosted_pnp_manager_mut().devnode_identity_for_pdo(pdo_id.raw()) }
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    Ok((Owner { domain, pdo, pdo_id: Some(pdo_id), devnode: Some(devnode) }, inst.exec_arg_va))
}

fn instance_path(owner: Owner) -> Result<String, i32> {
    if let (Some(pdo_id), Some(devnode)) = (owner.pdo_id, owner.devnode) {
        unsafe { win32k_pdo_instance_path(pdo_id, devnode) }
    } else {
        Ok(String::from(nt_config_manager::PNP_ROOT_DEVICE_INSTANCE))
    }
}

fn reply(total: usize, token: u64, written: usize) -> (i32, u64, u64, u64) {
    (STATUS_SUCCESS, total as u64, token, written as u64)
}

pub(crate) fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    op: u64,
    pdo: u64,
    arg2: u64,
    arg3: u64,
    badge: u64,
    reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let (owner, arg_va) = match owner(ch, reply_cap, badge, pdo) {
        Ok(owner) => owner,
        Err(status) => return (status, 0, 0, 0),
    };
    let bank = unsafe { core::slice::from_raw_parts_mut(
        (arg_va + HOSTED_DEVICE_ARG_DATA_OFF) as *mut u8,
        device_property::PROPERTY_CHUNK_BYTES,
    ) };
    let transfers = unsafe { &mut *core::ptr::addr_of_mut!(TRANSFERS) };
    if op == HOSTED_DEVICE_OP_GET_INTERFACE_ABORT {
        if arg3 != 0 { return (STATUS_INVALID_PARAMETER, 0, 0, 0); }
        if let Some(index) = transfers.iter().position(|row| row.owner == owner && row.token == arg2) {
            transfers.remove(index);
            return (STATUS_SUCCESS, 0, 0, 0);
        }
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    if op == HOSTED_DEVICE_OP_GET_INTERFACE_PULL {
        let Ok(offset) = usize::try_from(arg3) else { return (STATUS_INVALID_PARAMETER, 0, 0, 0); };
        let Some(index) = transfers.iter().position(|row| row.owner == owner && row.token == arg2) else {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        };
        let row = &mut transfers[index];
        if offset != row.next || row.next >= row.bytes.len() {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        }
        let count = (row.bytes.len() - row.next).min(bank.len());
        bank[..count].copy_from_slice(&row.bytes[row.next..row.next + count]);
        row.next += count;
        let answer = reply(row.bytes.len(), row.token, count);
        if row.next == row.bytes.len() { transfers.remove(index); }
        return answer;
    }
    if op != HOSTED_DEVICE_OP_GET_INTERFACE_BEGIN {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    if transfers.iter().any(|row| row.owner.domain == owner.domain) {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    let flags = unsafe { read_volatile(arg_va as *const u32) };
    if flags > 1 { return (STATUS_INVALID_PARAMETER, 0, 0, 0); }
    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&arg2.to_le_bytes());
    guid[8..].copy_from_slice(&arg3.to_le_bytes());
    let instance = match instance_path(owner) { Ok(path) => path, Err(status) => return (status, 0, 0, 0) };
    let selector = if flags == 1 { nt_config_abi::pnp_query_kind::INTERFACE_LINKS_INCLUDE_NONACTIVE } else { 0 };
    let snapshot = match unsafe { crate::config_manager_query_pnp(
        nt_config_abi::pnp_query_kind::INTERFACE_LINKS, selector, &instance, &guid,
    ) } {
        Ok(snapshot) if snapshot.payload.is_empty() => snapshot,
        Ok(_) => return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0),
        Err(status) => return (status, 0, 0, 0),
    };
    if instance_path(owner).as_deref() != Ok(instance.as_str()) {
        return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0);
    }
    let bytes = match encode_multi_sz(&snapshot.strings) {
        Ok(bytes) => bytes,
        Err(status) => return (status, 0, 0, 0),
    };
    let first = bytes.len().min(bank.len());
    if first == bytes.len() {
        bank[..first].copy_from_slice(&bytes);
        return reply(bytes.len(), 0, first);
    }
    if transfers.try_reserve(1).is_err() {
        return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
    }
    let token = match NEXT_TRANSFER.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| last.checked_add(1)) {
        Ok(last) => last + 1,
        Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0),
    };
    bank[..first].copy_from_slice(&bytes[..first]);
    let total = bytes.len();
    transfers.push(Transfer { owner, token, bytes, next: first });
    reply(total, token, first)
}

pub(crate) unsafe fn retire_domain(domain: HostedDomainIdentity) {
    (&mut *core::ptr::addr_of_mut!(TRANSFERS)).retain(|row| row.owner.domain != domain);
}

pub(crate) unsafe fn transfers_quiesced(domain: HostedDomainIdentity) -> bool {
    (&*core::ptr::addr_of!(TRANSFERS))
        .iter()
        .all(|row| row.owner.domain != domain)
}
