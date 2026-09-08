//! Canonical device projections for the independent win32k I/O consumer.

use super::*;
use nt_component_suspension::LaneDispatchIdentity;
use nt_provider_wait::{CatalogIdentity, ProviderDomainIdentity};

struct Projection {
    address: u64,
    device: nt_io_manager::DeviceId,
    registration: Option<nt_io_manager::HostedDevicePointerRegistration>,
    bound: bool,
    pdo_identity: Option<nt_pnp_manager::DevnodeIdentity>,
}

struct Consumer {
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    domain: HostedDomainIdentity,
    pml4: u64,
    retiring: bool,
    projections: Vec<Projection>,
}

static mut CONSUMER: Option<Consumer> = None;

#[derive(Clone, Copy, Default)]
pub(crate) struct ConsumerStats {
    pub projections: usize,
    pub references: usize,
    pub retiring: bool,
    pub domain: u64,
    pub cookie: u64,
}

pub(crate) unsafe fn stats() -> ConsumerStats {
    let Some(consumer) = (&*core::ptr::addr_of!(CONSUMER)).as_ref() else {
        return ConsumerStats::default();
    };
    ConsumerStats {
        projections: consumer.projections.len(),
        references: consumer
            .projections
            .iter()
            .filter(|p| p.registration.is_some())
            .count(),
        retiring: consumer.retiring,
        domain: consumer.domain.domain_id.raw(),
        cookie: consumer.domain.cookie,
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
    let _durable = crate::allocator::enter_durable();
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
    });
    Ok(())
}

/// Admit the pointer ledger before native publication. Partial binding remains recorded for retry;
/// only the registered ledger anchor grants lifetime, independently of caller pointer references.
pub(crate) unsafe fn bind_projection(
    address: u64,
    device: nt_io_manager::DeviceId,
) -> Result<(), i32> {
    let _durable = crate::allocator::enter_durable();
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let consumer = live_consumer()?;
    let index = if let Some(index) = consumer
        .projections
        .iter()
        .position(|p| p.address == address)
    {
        if consumer.projections[index].device != device {
            return Err(STATUS_ACCESS_DENIED);
        }
        index
    } else {
        if consumer.projections.iter().any(|p| p.device == device) {
            return Err(STATUS_ACCESS_DENIED);
        }
        consumer
            .projections
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let pdo_identity = hosted_pnp_manager_mut().devnode_identity_for_pdo(device.raw());
        consumer.projections.push(Projection {
            address,
            device,
            registration: None,
            bound: false,
            pdo_identity,
        });
        consumer.projections.len() - 1
    };
    io_manager_mut()
        .bind_hosted_device_identity(consumer.domain, address, device)
        .map_err(|e| e.raw())?;
    consumer.projections[index].bound = true;
    if let Some(registration) = consumer.projections[index].registration {
        io_manager_mut()
            .hosted_device_pointer_count(registration)
            .map_err(|e| e.raw())?;
    } else {
        let registration = io_manager_mut()
            .register_hosted_device_pointer(consumer.domain, address)
            .map_err(|e| e.raw())?;
        consumer.projections[index].registration = Some(registration);
    }
    Ok(())
}

/// A revalidatable observation, not a new device reference or permission to outlive a dispatch.
/// Ownership stays with the consumer projection; asynchronous I/O must acquire its own references.
#[derive(Clone, Copy)]
pub(crate) struct DeviceAccess {
    catalog: CatalogIdentity,
    provider: ProviderDomainIdentity,
    dispatch: LaneDispatchIdentity,
    domain: HostedDomainIdentity,
    address: u64,
    device: nt_io_manager::DeviceId,
    registration: nt_io_manager::HostedDevicePointerRegistration,
}

impl DeviceAccess {
    pub(crate) fn dispatch(&self) -> LaneDispatchIdentity {
        self.dispatch
    }
    pub(crate) fn domain(&self) -> HostedDomainIdentity {
        self.domain
    }
    pub(crate) fn address(&self) -> u64 {
        self.address
    }
    pub(crate) fn device(&self) -> nt_io_manager::DeviceId {
        self.device
    }

    pub(crate) unsafe fn validate(&self) -> Result<(), i32> {
        let consumer = live_consumer()?;
        if consumer.catalog != self.catalog
            || consumer.provider != self.provider
            || consumer.domain != self.domain
            || crate::service_sec_image::component_execution_dispatch_identity(self.dispatch.lane())
                != Some(self.dispatch)
        {
            return Err(STATUS_ACCESS_DENIED);
        }
        if !consumer.projections.iter().any(|p| {
            p.address == self.address
                && p.bound
                && p.registration == Some(self.registration)
                && p.device == self.device
        }) || io_manager_mut().hosted_device_by_identity(self.domain, self.address)
            != Some(self.device)
            || io_manager_mut()
                .hosted_device_pointer_count(self.registration)
                .is_err()
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        Ok(())
    }

    /// PDO-only APIs additionally require the exact PnP incarnation captured at projection binding.
    /// A valid FDO remains a valid I/O target but does not acquire PDO property authority.
    pub(crate) unsafe fn require_pdo(&self) -> Result<nt_pnp_manager::DevnodeIdentity, i32> {
        self.validate()?;
        let consumer = live_consumer()?;
        let expected = consumer
            .projections
            .iter()
            .find(|p| p.address == self.address)
            .and_then(|p| p.pdo_identity)
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
        if hosted_pnp_manager_mut()
            .devnode_for_pdo(self.device.raw())
            .is_none()
            || hosted_pnp_manager_mut().devnode_identity_for_pdo(self.device.raw())
                != Some(expected)
        {
            return Err(STATUS_INVALID_DEVICE_REQUEST);
        }
        Ok(expected)
    }
}

/// Authenticate the actual physical channel and active dispatch before interpreting a device
/// address. This common boundary accepts canonical FDOs and PDOs; operation policy comes later.
pub(crate) unsafe fn authenticate(
    ch: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    address: u64,
) -> Result<DeviceAccess, i32> {
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
        .find(|p| p.address == address && p.bound && p.registration.is_some())
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let access = DeviceAccess {
        catalog: consumer.catalog,
        provider: consumer.provider,
        dispatch,
        domain: consumer.domain,
        address,
        device: projection.device,
        registration: projection
            .registration
            .ok_or(STATUS_INVALID_DEVICE_REQUEST)?,
    };
    access.validate()?;
    Ok(access)
}

/// Not timeout cleanup: the caller must retire provider-local pointers and mappings and quiesce
/// every physical lane first. Failed retirement denies new admission and retains unfinished owners.
#[allow(dead_code)]
pub(crate) unsafe fn retire_quiescent_projections() -> Result<(), i32> {
    let consumer = consumer_mut()?;
    consumer.retiring = true;
    if !crate::win32k_glue::win32k_physical_lanes_quiescent() {
        return Err(STATUS_DEVICE_NOT_READY);
    }
    super::win32k_device_properties::retire_quiescent_transfers(consumer.domain)?;
    while let Some(row) = consumer.projections.last_mut() {
        if let Some(registration) = row.registration {
            io_manager_mut()
                .unregister_hosted_device_pointer(registration)
                .map_err(|e| e.raw())?;
            row.registration = None;
        }
        if row.bound {
            if !io_manager_mut().unbind_hosted_device_identity(
                consumer.domain,
                row.address,
                row.device,
            ) {
                return Err(STATUS_ACCESS_DENIED);
            }
            row.bound = false;
        }
        consumer.projections.pop();
    }
    io_manager_mut()
        .unregister_hosted_domain(consumer.domain)
        .map_err(|e| e.raw())?;
    *core::ptr::addr_of_mut!(CONSUMER) = None;
    Ok(())
}
