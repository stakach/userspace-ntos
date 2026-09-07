//! Win32k's independent I/O consumer domain and lane-owned property snapshots.

use super::device_property::{
    PropertyQueryReply, PropertyQueryRequest, PropertyQueryTransport, PropertyScratch,
    PropertyTransfers, PROPERTY_CHUNK_BYTES,
};
use super::*;
use nt_component_suspension::LaneDispatchIdentity;
use nt_provider_wait::{CatalogIdentity, ProviderDomainIdentity};

struct Projection {
    address: u64,
    reference: nt_io_manager::DeviceReference,
    bound: bool,
    pdo_identity: Option<nt_pnp_manager::DevnodeIdentity>,
}

struct LaneTransfers {
    dispatch: LaneDispatchIdentity,
    table: HostedDevicePropertyTransferTable,
}

struct Consumer {
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    domain: HostedDomainIdentity,
    pml4: u64,
    retiring: bool,
    projections: Vec<Projection>,
    lanes: Vec<LaneTransfers>,
}

static mut CONSUMER: Option<Consumer> = None;
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
    let mut stats = ConsumerStats {
        requests: REQUESTS.load(Ordering::Relaxed),
        queries: QUERIES.load(Ordering::Relaxed),
        pulls: PULLS.load(Ordering::Relaxed),
        aborts: ABORTS.load(Ordering::Relaxed),
        failures: FAILURES.load(Ordering::Relaxed),
        ..ConsumerStats::default()
    };
    if let Some(consumer) = (&*core::ptr::addr_of!(CONSUMER)).as_ref() {
        stats.projections = consumer.projections.len();
        stats.references = consumer
            .projections
            .iter()
            .filter(|p| p.reference.is_held())
            .count();
        stats.transfers = consumer.lanes.iter().map(|lane| lane.table.len()).sum();
        stats.retiring = consumer.retiring;
        stats.domain = consumer.domain.domain_id.raw();
        stats.cookie = consumer.domain.cookie;
    }
    stats
}

/// Release only snapshots belonging to completed/replaced jobs. This neither retires live
/// projections nor touches a suspended job, and is safe at a normal executive event boundary.
pub(crate) unsafe fn retire_completed_transfers() {
    let Some(consumer) = (&mut *core::ptr::addr_of_mut!(CONSUMER)).as_mut() else {
        return;
    };
    for lane in &mut consumer.lanes {
        if crate::service_sec_image::component_execution_dispatch_identity(lane.dispatch.lane())
            != Some(lane.dispatch)
        {
            lane.table.remove_domain(consumer.domain);
        }
    }
}

unsafe fn consumer_mut() -> Result<&'static mut Consumer, i32> {
    (&mut *core::ptr::addr_of_mut!(CONSUMER))
        .as_mut()
        .ok_or(STATUS_DEVICE_NOT_READY)
}

unsafe fn live_consumer() -> Result<&'static mut Consumer, i32> {
    let consumer = consumer_mut()?;
    if consumer.retiring
        || (&*core::ptr::addr_of!(crate::PROVIDER_WAIT_DOMAINS)).identity()
            != Some(consumer.catalog)
        || !crate::win32k_provider_domain_is_current(consumer.provider)
    {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(consumer)
}

/// Root-only registration before the genuine primary DriverEntry dispatch starts.
pub(crate) unsafe fn register_consumer(pml4: u64) -> Result<(), i32> {
    if pml4 == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let provider = crate::current_win32k_provider_domain().ok_or(STATUS_DEVICE_NOT_READY)?;
    let catalog = (&*core::ptr::addr_of!(crate::PROVIDER_WAIT_DOMAINS))
        .identity()
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    if let Some(existing) = (&*core::ptr::addr_of!(CONSUMER)).as_ref() {
        return if !existing.retiring
            && existing.catalog == catalog
            && existing.provider == provider
            && existing.pml4 == pml4
        {
            Ok(())
        } else {
            Err(STATUS_ACCESS_DENIED)
        };
    }
    let domain = io_manager_mut().register_hosted_domain();
    *core::ptr::addr_of_mut!(CONSUMER) = Some(Consumer {
        catalog,
        provider,
        domain,
        pml4,
        retiring: false,
        projections: Vec::new(),
        lanes: Vec::new(),
    });
    Ok(())
}

/// Retain the canonical device before publishing its provider-local identity. Failed binding
/// keeps the exact reference in the registry for retry; it never borrows a driver's domain.
pub(crate) unsafe fn bind_projection(
    address: u64,
    device: nt_io_manager::DeviceId,
) -> Result<(), i32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let consumer = live_consumer()?;
    let index = if let Some(index) = consumer
        .projections
        .iter()
        .position(|p| p.address == address)
    {
        if consumer.projections[index].reference.device_id() != device {
            return Err(STATUS_ACCESS_DENIED);
        }
        index
    } else {
        if consumer
            .projections
            .iter()
            .any(|p| p.reference.device_id() == device)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        consumer
            .projections
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let reference = io_manager_mut()
            .retain_device_reference(device)
            .map_err(|e| e.raw())?;
        let pdo_identity = hosted_pnp_manager_mut().devnode_identity_for_pdo(device.raw());
        consumer.projections.push(Projection {
            address,
            reference,
            bound: false,
            pdo_identity,
        });
        consumer.projections.len() - 1
    };
    io_manager_mut()
        .bind_hosted_device_identity(consumer.domain, address, device)
        .map_err(|e| e.raw())?;
    consumer.projections[index].bound = true;
    Ok(())
}

#[derive(Clone, Copy)]
struct TransferAccess {
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    dispatch: LaneDispatchIdentity,
    owner: HostedDevicePropertyOwner,
    pdo_identity: nt_pnp_manager::DevnodeIdentity,
}

impl TransferAccess {
    unsafe fn table(&self) -> Result<&'static mut HostedDevicePropertyTransferTable, i32> {
        let consumer = live_consumer()?;
        if consumer.catalog != self.catalog
            || consumer.provider != self.provider
            || crate::service_sec_image::component_execution_dispatch_identity(self.dispatch.lane())
                != Some(self.dispatch)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if consumer.domain != self.owner.domain
            || !consumer.projections.iter().any(|p| {
                p.address == self.owner.pdo_address
                    && p.bound
                    && p.reference.is_held()
                    && p.reference.device_id() == self.owner.pdo_device_id
                    && p.pdo_identity == Some(self.pdo_identity)
            })
            || io_manager_mut().hosted_device_by_identity(self.owner.domain, self.owner.pdo_address)
                != Some(self.owner.pdo_device_id)
            || hosted_pnp_manager_mut()
                .devnode_for_pdo(self.owner.pdo_device_id.raw())
                .is_none()
            || hosted_pnp_manager_mut().devnode_identity_for_pdo(self.owner.pdo_device_id.raw())
                != Some(self.pdo_identity)
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        consumer
            .lanes
            .iter_mut()
            .find(|lane| lane.dispatch == self.dispatch)
            .map(|lane| &mut lane.table)
            .ok_or(STATUS_ACCESS_DENIED)
    }
}

impl PropertyTransfers for TransferAccess {
    fn busy(&self, domain: HostedDomainIdentity) -> Result<bool, i32> {
        Ok(unsafe { self.table()?.domain_busy(domain) })
    }
    fn begin(
        &mut self,
        owner: HostedDevicePropertyOwner,
        value: Vec<u8>,
        data: &mut [u8],
    ) -> Result<(usize, u64, usize), i32> {
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
        unsafe { self.table()?.pull(owner, token, offset, data) }
            .map(|p| (p.total_len, p.token, p.written))
            .map_err(hosted_device_property_transfer_status)
    }
    fn abort(&mut self, owner: HostedDevicePropertyOwner, token: u64) -> bool {
        unsafe { self.table().is_ok_and(|table| table.abort(owner, token)) }
    }
}

unsafe fn authenticate(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> Result<(HostedDevicePropertyOwner, TransferAccess), i32> {
    let consumer = live_consumer()?;
    if ch.caps.kind != crate::spawn_hosts::ReqKind::Syscall
        || ch.pml4 != consumer.pml4
        || ch.shared_va != crate::win32k_subsystem::WIN32K_SHARED_VADDR
        || ch.code_va != crate::win32k_subsystem::WIN32K_CODE_VA
    {
        return Err(STATUS_ACCESS_DENIED);
    }
    let lane = crate::win32k_glue::win32k_physical_lane_for_channel(ch.tcb, ch.fault_ep, reply_cap)
        .ok_or(STATUS_ACCESS_DENIED)?;
    let dispatch = crate::service_sec_image::component_execution_dispatch_identity(lane)
        .ok_or(STATUS_ACCESS_DENIED)?;
    let projection = consumer
        .projections
        .iter()
        .find(|p| p.address == address && p.bound && p.reference.is_held())
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let device = projection.reference.device_id();
    if io_manager_mut().hosted_device_by_identity(consumer.domain, address) != Some(device)
        || hosted_pnp_manager_mut()
            .devnode_for_pdo(device.raw())
            .is_none()
        || projection.pdo_identity.is_none()
        || hosted_pnp_manager_mut().devnode_identity_for_pdo(device.raw())
            != projection.pdo_identity
    {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let pdo_identity = projection
        .pdo_identity
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    if let Some(row) = consumer
        .lanes
        .iter_mut()
        .find(|row| row.dispatch.lane() == lane)
    {
        if row.dispatch != dispatch {
            row.table.remove_domain(consumer.domain);
            row.dispatch = dispatch;
        }
    } else {
        consumer
            .lanes
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        consumer.lanes.push(LaneTransfers {
            dispatch,
            table: HostedDevicePropertyTransferTable::new(),
        });
    }
    let owner = HostedDevicePropertyOwner {
        domain: consumer.domain,
        pdo_device_id: device,
        pdo_address: address,
    };
    Ok((
        owner,
        TransferAccess {
            catalog: consumer.catalog,
            provider: consumer.provider,
            dispatch,
            owner,
            pdo_identity,
        },
    ))
}

/// The returned bytes remain stack-owned while snapshot acquisition performs nested CM IPC.
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

/// This is not a wall-timeout/bugcheck cleanup. The caller must have retired every provider-local
/// projection pointer and mapping and quiesced every physical lane. Failure retains all unfinished
/// ownership and denies further admission; invoke again only with the same quiescence proof.
#[allow(dead_code)]
pub(crate) unsafe fn retire_quiescent_projections() -> Result<(), i32> {
    let consumer = consumer_mut()?;
    consumer.retiring = true;
    if !crate::win32k_glue::win32k_physical_lanes_quiescent() {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    for lane in &consumer.lanes {
        if crate::service_sec_image::component_execution_dispatch_identity(lane.dispatch.lane())
            .is_some()
        {
            return Err(STATUS_DEVICE_NOT_READY);
        }
    }
    for lane in &mut consumer.lanes {
        lane.table.remove_domain(consumer.domain);
    }
    while let Some(row) = consumer.projections.last_mut() {
        if row.bound {
            if !io_manager_mut().unbind_hosted_device_identity(
                consumer.domain,
                row.address,
                row.reference.device_id(),
            ) {
                return Err(STATUS_ACCESS_DENIED);
            }
            row.bound = false;
        }
        io_manager_mut()
            .release_device_reference(&mut row.reference)
            .map_err(|e| e.raw())?;
        consumer.projections.pop();
    }
    io_manager_mut()
        .unregister_hosted_domain(consumer.domain)
        .map_err(|e| e.raw())?;
    *core::ptr::addr_of_mut!(CONSUMER) = None;
    Ok(())
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
