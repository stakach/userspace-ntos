//! Lane-owned property snapshots over the independent win32k device consumer.

use super::device_property::{
    PropertyQueryReply, PropertyQueryRequest, PropertyQueryTransport, PropertyScratch,
    PropertyTransfers, PROPERTY_CHUNK_BYTES,
};
use super::win32k_device_consumer::{self as consumer, DeviceAccess};
use super::*;
use nt_component_suspension::LaneDispatchIdentity;

struct LaneTransfers {
    dispatch: LaneDispatchIdentity,
    domain: HostedDomainIdentity,
    table: HostedDevicePropertyTransferTable,
}

static mut LANES: Vec<LaneTransfers> = Vec::new();
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static QUERIES: AtomicU64 = AtomicU64::new(0);
static PULLS: AtomicU64 = AtomicU64::new(0);
static ABORTS: AtomicU64 = AtomicU64::new(0);
static FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Default)]
pub(crate) struct ConsumerStats {
    pub requests: u64,
    pub queries: u64,
    pub pulls: u64,
    pub aborts: u64,
    pub failures: u64,
    pub projections: usize,
    pub references: usize,
    pub transfers: usize,
    pub retiring: bool,
    pub domain: u64,
    pub cookie: u64,
}

pub(crate) unsafe fn stats() -> ConsumerStats {
    let consumer = consumer::stats();
    ConsumerStats {
        requests: REQUESTS.load(Ordering::Relaxed),
        queries: QUERIES.load(Ordering::Relaxed),
        pulls: PULLS.load(Ordering::Relaxed),
        aborts: ABORTS.load(Ordering::Relaxed),
        failures: FAILURES.load(Ordering::Relaxed),
        projections: consumer.projections,
        references: consumer.references,
        transfers: (&*core::ptr::addr_of!(LANES))
            .iter()
            .map(|lane| lane.table.len())
            .sum(),
        retiring: consumer.retiring,
        domain: consumer.domain,
        cookie: consumer.cookie,
    }
}

/// Release completed/replaced job snapshots, never a suspended job or its device projection.
pub(crate) unsafe fn retire_completed_transfers() {
    for lane in &mut *core::ptr::addr_of_mut!(LANES) {
        if crate::service_sec_image::component_execution_dispatch_identity(lane.dispatch.lane())
            != Some(lane.dispatch)
        {
            lane.table.remove_domain(lane.domain);
        }
    }
}

pub(super) unsafe fn retire_quiescent_transfers(domain: HostedDomainIdentity) -> Result<(), i32> {
    let lanes = &mut *core::ptr::addr_of_mut!(LANES);
    if lanes.iter().any(|lane| {
        lane.domain == domain
            && crate::service_sec_image::component_execution_dispatch_identity(lane.dispatch.lane())
                .is_some()
    }) {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    for lane in lanes.iter_mut().filter(|lane| lane.domain == domain) {
        lane.table.remove_domain(domain);
    }
    lanes.retain(|lane| lane.domain != domain);
    Ok(())
}

#[derive(Clone, Copy)]
struct TransferAccess {
    device: DeviceAccess,
    owner: HostedDevicePropertyOwner,
    pdo_identity: nt_pnp_manager::DevnodeIdentity,
}

impl TransferAccess {
    unsafe fn table(&self) -> Result<&'static mut HostedDevicePropertyTransferTable, i32> {
        if self.device.require_pdo()? != self.pdo_identity {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        (&mut *core::ptr::addr_of_mut!(LANES))
            .iter_mut()
            .find(|lane| {
                lane.dispatch == self.device.dispatch() && lane.domain == self.device.domain()
            })
            .map(|lane| &mut lane.table)
            .ok_or(STATUS_ACCESS_DENIED)
    }
}

impl PropertyTransfers for TransferAccess {
    fn busy(&self, domain: HostedDomainIdentity) -> Result<bool, i32> {
        if domain != self.owner.domain {
            return Err(STATUS_ACCESS_DENIED);
        }
        Ok(unsafe { self.table()?.domain_busy(domain) })
    }
    fn begin(
        &mut self,
        owner: HostedDevicePropertyOwner,
        value: Vec<u8>,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32> {
        if owner != self.owner {
            return Err(STATUS_ACCESS_DENIED);
        }
        unsafe { self.table()?.begin(owner, value, data) }
            .map(|p| (p.total_len, p.token, p.written))
            .map_err(hosted_device_property_transfer_status)
    }
    fn pull(
        &mut self,
        owner: HostedDevicePropertyOwner,
        token: u64,
        offset: usize,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32> {
        if owner != self.owner {
            return Err(STATUS_ACCESS_DENIED);
        }
        unsafe { self.table()?.pull(owner, token, offset, data) }
            .map(|p| (p.total_len, p.token, p.written))
            .map_err(hosted_device_property_transfer_status)
    }
    fn abort(&mut self, owner: HostedDevicePropertyOwner, token: u64) -> bool {
        owner == self.owner && unsafe { self.table().is_ok_and(|table| table.abort(owner, token)) }
    }
}

unsafe fn authenticate(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> Result<(HostedDevicePropertyOwner, TransferAccess), i32> {
    let device = consumer::authenticate(ch, reply_cap, address)?;
    let pdo_identity = device.require_pdo()?;
    let dispatch = device.dispatch();
    let domain = device.domain();
    let lanes = &mut *core::ptr::addr_of_mut!(LANES);
    if let Some(row) = lanes
        .iter_mut()
        .find(|row| row.dispatch.lane() == dispatch.lane())
    {
        if row.dispatch != dispatch || row.domain != domain {
            row.table.remove_domain(row.domain);
            row.dispatch = dispatch;
            row.domain = domain;
        }
    } else {
        lanes
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        lanes.push(LaneTransfers {
            dispatch,
            domain,
            table: HostedDevicePropertyTransferTable::new(),
        });
    }
    let owner = HostedDevicePropertyOwner {
        domain,
        pdo_device_id: device.device(),
        pdo_address: device.address(),
    };
    Ok((
        owner,
        TransferAccess {
            device,
            owner,
            pdo_identity,
        },
    ))
}

/// Reply bytes stay stack-owned while snapshot acquisition performs nested CM IPC.
pub(crate) unsafe fn service(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    op: u64,
    address: u64,
    arg2: u64,
    arg3: u64,
    data: &mut [u8; PROPERTY_CHUNK_BYTES],
) -> (i32, u64, u64, u64) {
    retire_completed_transfers();
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    if op == HOSTED_DEVICE_OP_QUERY_PROPERTY_BEGIN {
        QUERIES.fetch_add(1, Ordering::Relaxed);
    } else if op == HOSTED_DEVICE_OP_QUERY_PROPERTY_PULL {
        PULLS.fetch_add(1, Ordering::Relaxed);
    } else if op == HOSTED_DEVICE_OP_QUERY_PROPERTY_ABORT {
        ABORTS.fetch_add(1, Ordering::Relaxed);
    }
    let (owner, mut access) = match authenticate(ch, reply_cap, address) {
        Ok(authenticated) => authenticated,
        Err(status) => {
            FAILURES.fetch_add(1, Ordering::Relaxed);
            return (status, 0, 0, 0);
        }
    };
    let reply = super::device_property::service(owner, op, arg2, arg3, data, &mut access);
    if reply.0 != STATUS_SUCCESS {
        FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    reply
}

struct Win32kPropertyClient;

fn component_ipc_buffer() -> Option<u64> {
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem, preserves_flags));
    }
    use crate::win32k_subsystem::*;
    if (WIN32K_STACK_VADDR..WIN32K_STACK_VADDR + 32 * 0x1000).contains(&rsp) {
        return Some(crate::IPCBUF_VADDR);
    }
    nt_component_suspension::LaneAddressLayout {
        base: WIN32K_LANE_ARENA_VADDR,
        stride: WIN32K_LANE_STRIDE,
        stack_bytes: WIN32K_LANE_STACK_FRAMES * 0x1000,
        ipc_buffer_offset: WIN32K_LANE_IPCBUF_OFFSET,
        capacity: WIN32K_LANE_CAPACITY,
    }
    .ipc_buffer_for_stack_pointer(rsp)
}

impl PropertyQueryTransport for Win32kPropertyClient {
    type Scratch = PropertyScratch;

    fn exchange(
        &mut self,
        request: PropertyQueryRequest,
    ) -> Result<PropertyQueryReply, nt_status::NtStatus> {
        let ipc = component_ipc_buffer().ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
        let (op, pdo, arg2, arg3) = super::device_property::request_words(request);
        let (info, status, total_len, token, chunk_len) = unsafe {
            call_on4_raw(
                (crate::win32k_subsystem::W32_DEVICE_PROPERTY_LABEL << 12) | 4,
                op,
                pdo,
                arg2,
                arg3,
            )
        };
        let mut reply = PropertyQueryReply {
            status: nt_status::NtStatus(status as i32),
            total_len,
            token,
            chunk_len,
            data: [0u8; PROPERTY_CHUNK_BYTES],
        };
        if chunk_len > PROPERTY_CHUNK_BYTES as u64
            || info >> 12 != 0
            || (info & 0x7f) != 4 + (chunk_len + 7) / 8
            || (info & 0xf80) != 0
        {
            reply.status = nt_status::NtStatus::INVALID_PARAMETER;
            reply.total_len = 0;
            return Ok(reply);
        }
        if reply.status == nt_status::NtStatus::SUCCESS {
            for (index, byte) in reply.data.iter_mut().take(chunk_len as usize).enumerate() {
                *byte = unsafe { read_volatile((ipc + 8 + 4 * 8 + index as u64) as *const u8) };
            }
        }
        Ok(reply)
    }

    fn allocate(&mut self, bytes: usize) -> Option<PropertyScratch> {
        unsafe {
            PropertyScratch::from_allocation(
                crate::win32k_subsystem::pool_alloc_export(bytes as u64),
                bytes,
            )
        }
    }

    fn release(&mut self, scratch: PropertyScratch) {
        unsafe { crate::win32k_subsystem::property_pool_free(scratch.address()) }
    }
}

pub(crate) extern "win64" fn io_get_device_property(
    pdo: u64,
    property: u32,
    buffer_len: u32,
    buffer: u64,
    result_len: u64,
) -> i32 {
    unsafe {
        super::device_property::query(
            &mut Win32kPropertyClient,
            pdo,
            property,
            buffer_len,
            buffer,
            result_len,
        )
    }
}
