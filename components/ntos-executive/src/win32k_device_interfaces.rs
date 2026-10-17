//! `IoGetDeviceInterfaces` through the authenticated win32k lane and CM snapshot service.

use super::win32k_device_consumer::{self as consumer, DeviceAccess};
use super::*;
use nt_component_suspension::LaneDispatchIdentity;

pub(crate) const BEGIN: u64 = 1;
pub(crate) const PULL: u64 = 2;
pub(crate) const ABORT: u64 = 3;
const CHUNK_BYTES: usize = super::device_property::PROPERTY_CHUNK_BYTES;
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Eq, PartialEq)]
struct PdoOwner {
    device: nt_io_manager::DeviceId,
    identity: nt_pnp_manager::DevnodeIdentity,
    address: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Owner {
    dispatch: LaneDispatchIdentity,
    domain: HostedDomainIdentity,
    pdo: Option<PdoOwner>,
}

struct Transfer {
    owner: Owner,
    token: u64,
    next: usize,
    bytes: Vec<u8>,
}

static mut TRANSFERS: Vec<Transfer> = Vec::new();

unsafe fn authenticate(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    pdo: u64,
) -> Result<(Owner, Option<DeviceAccess>), i32> {
    let (dispatch, domain) = consumer::authenticate_channel(ch, reply_cap)?;
    let device = if pdo != 0 {
        Some(consumer::authenticate(ch, reply_cap, pdo)?)
    } else {
        None
    };
    let pdo_owner = if let Some(device) = device {
        let pdo_identity = device.require_pdo()?;
        Some(PdoOwner {
            device: device.device(),
            identity: pdo_identity,
            address: device.address(),
        })
    } else {
        None
    };
    Ok((Owner { dispatch, domain, pdo: pdo_owner }, device))
}

unsafe fn owner_still_live(owner: Owner, device: Option<DeviceAccess>) -> Result<(), i32> {
    if let Some(pdo_identity) = owner.pdo.map(|pdo| pdo.identity) {
        let device = device.ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        if device.require_pdo()? != pdo_identity {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
    }
    Ok(())
}

fn encode_multi_sz(links: &[String]) -> Result<Vec<u8>, i32> {
    let mut units = 1usize;
    for link in links {
        if link.contains('\0') {
            return Err(STATUS_INVALID_PARAMETER);
        }
        units = units
            .checked_add(link.encode_utf16().count())
            .and_then(|n| n.checked_add(1))
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    }
    let bytes = units.checked_mul(2).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut result = Vec::new();
    result.try_reserve_exact(bytes).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for link in links {
        for unit in link.encode_utf16().chain(core::iter::once(0)) {
            result.extend_from_slice(&unit.to_le_bytes());
        }
    }
    result.extend_from_slice(&0u16.to_le_bytes());
    Ok(result)
}

unsafe fn retire_stale() {
    (&mut *core::ptr::addr_of_mut!(TRANSFERS)).retain(|transfer| {
        crate::service_sec_image::component_execution_dispatch_identity(transfer.owner.dispatch.lane())
            == Some(transfer.owner.dispatch)
    });
}

pub(super) unsafe fn retire_quiescent_transfers(domain: HostedDomainIdentity) -> Result<(), i32> {
    let transfers = &mut *core::ptr::addr_of_mut!(TRANSFERS);
    if transfers.iter().any(|transfer| {
        transfer.owner.domain == domain
            && crate::service_sec_image::component_execution_dispatch_identity(
                transfer.owner.dispatch.lane(),
            )
                .is_some()
    }) {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    transfers.retain(|transfer| transfer.owner.domain != domain);
    Ok(())
}

fn reply_chunk(bytes: &[u8], token: u64, bank: &mut [u8; CHUNK_BYTES]) -> (i32, u64, u64, u64) {
    let written = bytes.len().min(bank.len());
    bank[..written].copy_from_slice(&bytes[..written]);
    (STATUS_SUCCESS, bytes.len() as u64, token, written as u64)
}

/// The fifth request word is a GUID half for BEGIN and zero for later operations. The reply's
/// first four words hold status, total bytes, token, and chunk bytes; the chunk follows in IPC.
pub(crate) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    op: u64,
    pdo: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    bank: &mut [u8; CHUNK_BYTES],
) -> (i32, u64, u64, u64) {
    retire_stale();
    let (owner, device) = match authenticate(ch, reply_cap, pdo) {
        Ok(value) => value,
        Err(status) => return (status, 0, 0, 0),
    };
    if op == ABORT {
        if arg3 != 0 || arg4 != 0 {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        }
        let transfers = &mut *core::ptr::addr_of_mut!(TRANSFERS);
        if let Some(index) = transfers.iter().position(|row| row.owner == owner && row.token == arg2) {
            transfers.remove(index);
            return (STATUS_SUCCESS, 0, 0, 0);
        }
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    if op == PULL {
        if arg4 != 0 {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        }
        let transfers = &mut *core::ptr::addr_of_mut!(TRANSFERS);
        let Some(index) = transfers.iter().position(|row| row.owner == owner && row.token == arg2) else {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        };
        if let Err(status) = owner_still_live(owner, device) {
            transfers.remove(index);
            return (status, 0, 0, 0);
        }
        let row = &mut transfers[index];
        if usize::try_from(arg3) != Ok(row.next) {
            return (STATUS_INVALID_PARAMETER, 0, 0, 0);
        }
        let remaining = &row.bytes[row.next..];
        let written = remaining.len().min(bank.len());
        bank[..written].copy_from_slice(&remaining[..written]);
        row.next += written;
        let reply = (STATUS_SUCCESS, row.bytes.len() as u64, row.token, written as u64);
        if row.next == row.bytes.len() {
            transfers.remove(index);
        }
        return reply;
    }
    if op != BEGIN || arg2 > 1 {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    if (&*core::ptr::addr_of!(TRANSFERS))
        .iter()
        .any(|row| row.owner.dispatch.lane() == owner.dispatch.lane())
    {
        return (STATUS_DEVICE_NOT_READY, 0, 0, 0);
    }
    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&arg3.to_le_bytes());
    guid[8..].copy_from_slice(&arg4.to_le_bytes());
    let instance = if let Some(device) = device {
        let pdo_identity = match device.require_pdo() {
            Ok(identity) => identity,
            Err(status) => return (status, 0, 0, 0),
        };
        match win32k_pdo_instance_path(device.device(), pdo_identity) {
            Ok(path) => path,
            Err(status) => return (status, 0, 0, 0),
        }
    } else {
        String::from(nt_config_manager::PNP_ROOT_DEVICE_INSTANCE)
    };
    let selector = if arg2 == 1 {
        nt_config_abi::pnp_query_kind::INTERFACE_LINKS_INCLUDE_NONACTIVE
    } else {
        0
    };
    let snapshot = match crate::config_manager_query_pnp(
        nt_config_abi::pnp_query_kind::INTERFACE_LINKS,
        selector,
        &instance,
        &guid,
    ) {
        Ok(snapshot) if snapshot.payload.is_empty() => snapshot,
        Ok(_) => return (STATUS_INVALID_PARAMETER, 0, 0, 0),
        Err(status) => return (status, 0, 0, 0),
    };
    if let Err(status) = owner_still_live(owner, device) {
        return (status, 0, 0, 0);
    }
    let bytes = match encode_multi_sz(&snapshot.strings) {
        Ok(bytes) => bytes,
        Err(status) => return (status, 0, 0, 0),
    };
    let first = bytes.len().min(bank.len());
    if first == bytes.len() {
        return reply_chunk(&bytes, 0, bank);
    }
    let token = match NEXT_TOKEN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| last.checked_add(1)) {
        Ok(previous) => previous + 1,
        Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0),
    };
    let transfers = &mut *core::ptr::addr_of_mut!(TRANSFERS);
    if transfers.try_reserve(1).is_err() {
        return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
    }
    bank[..first].copy_from_slice(&bytes[..first]);
    let total = bytes.len() as u64;
    transfers.push(Transfer { owner, token, next: first, bytes });
    (STATUS_SUCCESS, total, token, first as u64)
}

enum ExchangeFailure {
    Rejected(i32),
    Ambiguous,
}

impl ExchangeFailure {
    fn status(&self) -> i32 {
        match self {
            Self::Rejected(status) => *status,
            Self::Ambiguous => STATUS_INVALID_PARAMETER,
        }
    }
}

unsafe fn exchange(
    ipc: u64,
    op: u64,
    pdo: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    bank: &mut [u8; CHUNK_BYTES],
) -> Result<(u64, u64, usize), ExchangeFailure> {
    core::ptr::write_volatile((ipc + 8 + 4 * 8) as *mut u64, arg4);
    let (info, status, total, token, chunk) = call_on4_raw(
        (crate::win32k_subsystem::W32_DEVICE_INTERFACES_LABEL << 12) | 5,
        op,
        pdo,
        arg2,
        arg3,
    );
    if info >> 12 != 0
        || (info & 0xf80) != 0
        || chunk > CHUNK_BYTES as u64
        || (info & 0x7f) != 4 + (chunk + 7) / 8
    {
        return Err(ExchangeFailure::Ambiguous);
    }
    if status as i32 != STATUS_SUCCESS {
        return Err(ExchangeFailure::Rejected(status as i32));
    }
    for (index, byte) in bank.iter_mut().take(chunk as usize).enumerate() {
        *byte = core::ptr::read_volatile((ipc + 8 + 4 * 8 + index as u64) as *const u8);
    }
    Ok((total, token, chunk as usize))
}

/// Win64 import. The only output allocation is the final caller-owned win32k pool buffer.
pub(crate) extern "win64" fn io_get_device_interfaces(
    guid_pointer: u64,
    pdo: u64,
    flags: u32,
    symbolic_link_list: u64,
) -> i32 {
    unsafe {
        if guid_pointer == 0 || symbolic_link_list == 0 || flags > 1 {
            return STATUS_INVALID_PARAMETER;
        }
        core::ptr::write_unaligned(symbolic_link_list as *mut u64, 0);
        let Some(ipc) = super::win32k_device_properties::component_ipc_buffer() else {
            return STATUS_ACCESS_DENIED;
        };
        let guid = core::ptr::read_unaligned(guid_pointer as *const [u8; 16]);
        let mut bank = [0u8; CHUNK_BYTES];
        let (total, token, first) = match exchange(
            ipc,
            BEGIN,
            pdo,
            flags as u64,
            u64::from_le_bytes(guid[..8].try_into().unwrap()),
            u64::from_le_bytes(guid[8..].try_into().unwrap()),
            &mut bank,
        ) {
            Ok(reply) => reply,
            Err(error) => return error.status(),
        };
        let Ok(total) = usize::try_from(total) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        if total < 2 || total % 2 != 0 || first > total || (first == total) != (token == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        let allocation = crate::win32k_subsystem::pool_alloc_export(total as u64);
        if allocation == 0 {
            if token != 0 {
                let _ = exchange(ipc, ABORT, pdo, token, 0, 0, &mut bank);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::copy_nonoverlapping(bank.as_ptr(), allocation as *mut u8, first);
        let mut offset = first;
        while offset < total {
            let reply = exchange(ipc, PULL, pdo, token, offset as u64, 0, &mut bank);
            let (actual_total, actual_token, written) = match reply {
                Ok(reply) => reply,
                Err(error) => {
                    // The server definitively rejected this request; abort exactly its retained
                    // transfer. An ambiguous envelope leaves ownership at the service until lane
                    // retirement because the cursor may already have advanced or completed.
                    if matches!(&error, ExchangeFailure::Rejected(_)) {
                        let _ = exchange(ipc, ABORT, pdo, token, 0, 0, &mut bank);
                    }
                    crate::win32k_subsystem::property_pool_free(allocation);
                    return error.status();
                }
            };
            if actual_total != total as u64 || actual_token != token || written == 0
                || written > total - offset
            {
                crate::win32k_subsystem::property_pool_free(allocation);
                return STATUS_INVALID_PARAMETER;
            }
            core::ptr::copy_nonoverlapping(bank.as_ptr(), (allocation as *mut u8).add(offset), written);
            offset += written;
        }
        // A successful final pull consumes the server token; no replay or post-hoc retry occurs.
        core::ptr::write_unaligned(symbolic_link_list as *mut u64, allocation);
        STATUS_SUCCESS
    }
}
