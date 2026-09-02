use alloc::vec::Vec;

use nt_interrupt_authority::{
    PhysicalInterruptAssignment, PhysicalInterruptAuthorityError, PhysicalInterruptClaim,
    PhysicalInterruptConnectionLease, PhysicalInterruptLineCatalog, PhysicalInterruptOwner,
    PhysicalInterruptRequest, PhysicalInterruptRoute, PhysicalInterruptVectorRequest,
    PreparedPhysicalInterruptPublication,
};

const HOSTED_INTERRUPT_VECTOR_LIMIT: u32 = 64;
const PLATFORM_OWNER_KIND: u32 = 1;
const PCI_ROUTE_OWNER_KIND: u32 = 2;
const KERNEL_TIMER_OWNER_KIND: u32 = 3;
const ACPI_SCI_OWNER_ID: u64 = 1;
const PCI_ROUTE_OWNER_ID: u64 = 1;
const DELAY_TIMER_OWNER_ID: u64 = 1;

static mut PHYSICAL_INTERRUPT_LINES: PhysicalInterruptLineCatalog =
    PhysicalInterruptLineCatalog::new();

fn authority_status(error: PhysicalInterruptAuthorityError) -> nt_status::NtStatus {
    match error {
        PhysicalInterruptAuthorityError::Allocation => nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        PhysicalInterruptAuthorityError::SharingConflict
        | PhysicalInterruptAuthorityError::VectorConflict => {
            nt_status::NtStatus::CONFLICTING_ADDRESSES
        }
        PhysicalInterruptAuthorityError::Busy => nt_status::NtStatus::DEVICE_BUSY,
        PhysicalInterruptAuthorityError::Fenced
        | PhysicalInterruptAuthorityError::StaleClaim
        | PhysicalInterruptAuthorityError::StaleLease
        | PhysicalInterruptAuthorityError::StaleMutation
        | PhysicalInterruptAuthorityError::StaleOwner => {
            nt_status::NtStatus::INVALID_DEVICE_REQUEST
        }
        PhysicalInterruptAuthorityError::Exhausted => {
            nt_status::NtStatus::INSUFFICIENT_RESOURCES
        }
        PhysicalInterruptAuthorityError::InvalidGeneration
        | PhysicalInterruptAuthorityError::InvalidOwner
        | PhysicalInterruptAuthorityError::InvalidVector
        | PhysicalInterruptAuthorityError::InvalidVectorLimit
        | PhysicalInterruptAuthorityError::RouteConflict => nt_status::NtStatus::INVALID_PARAMETER,
    }
}

unsafe fn catalog_mut() -> &'static mut PhysicalInterruptLineCatalog {
    &mut *core::ptr::addr_of_mut!(PHYSICAL_INTERRUPT_LINES)
}

fn platform_owner() -> PhysicalInterruptOwner {
    PhysicalInterruptOwner::new(PLATFORM_OWNER_KIND, ACPI_SCI_OWNER_ID)
        .expect("static platform interrupt owner must be valid")
}

fn pci_owner() -> PhysicalInterruptOwner {
    PhysicalInterruptOwner::new(PCI_ROUTE_OWNER_KIND, PCI_ROUTE_OWNER_ID)
        .expect("static PCI route interrupt owner must be valid")
}

fn delay_timer_owner() -> PhysicalInterruptOwner {
    PhysicalInterruptOwner::new(KERNEL_TIMER_OWNER_KIND, DELAY_TIMER_OWNER_ID)
        .expect("static delay-timer interrupt owner must be valid")
}

pub(crate) unsafe fn prepare_delay_timer_interrupt_claim(
) -> Result<PreparedPhysicalInterruptPublication, nt_status::NtStatus> {
    let owner = delay_timer_owner();
    let base_generation = catalog_mut().owner_generation(owner);
    let target_generation = base_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    catalog_mut()
        .prepare_replace_owner(
            owner,
            base_generation,
            target_generation,
            &[PhysicalInterruptRequest {
                gsi: 0,
                controller_ordinal: 0,
                local_pin: 0,
                vector: PhysicalInterruptVectorRequest::Exact(crate::DELAY_TIMER_IRQ as u32),
                level_sensitive: false,
                active_low: false,
                shared: false,
            }],
            HOSTED_INTERRUPT_VECTOR_LIMIT,
        )
        .map_err(authority_status)
}

pub(crate) unsafe fn prepare_acpi_sci_interrupt_claim(
    gsi: u32,
    vector: u32,
    level_sensitive: bool,
    active_low: bool,
    shared: bool,
) -> Result<PreparedPhysicalInterruptPublication, nt_status::NtStatus> {
    let hardware = crate::resolve_platform_ioapic_gsi(gsi)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let owner = platform_owner();
    let base_generation = catalog_mut().owner_generation(owner);
    let target_generation = base_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    catalog_mut()
        .prepare_replace_owner(
            owner,
            base_generation,
            target_generation,
            &[PhysicalInterruptRequest {
                gsi,
                controller_ordinal: hardware.controller_ordinal,
                local_pin: hardware.local_pin,
                vector: PhysicalInterruptVectorRequest::Exact(vector),
                level_sensitive,
                active_low,
                shared,
            }],
            HOSTED_INTERRUPT_VECTOR_LIMIT,
        )
        .map_err(authority_status)
}

pub(crate) unsafe fn prepare_pci_interrupt_claims(
    owner_generation: u64,
    routes: &[nt_pnp::PciInterruptRoute],
) -> Result<PreparedPhysicalInterruptPublication, nt_status::NtStatus> {
    let mut requests = Vec::new();
    requests
        .try_reserve_exact(routes.len())
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    for route in routes {
        let hardware = crate::resolve_platform_ioapic_gsi(route.gsi)
            .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
        requests.push(PhysicalInterruptRequest {
            gsi: route.gsi,
            controller_ordinal: hardware.controller_ordinal,
            local_pin: hardware.local_pin,
            vector: PhysicalInterruptVectorRequest::Allocate,
            level_sensitive: route.level_sensitive,
            active_low: route.active_low,
            shared: route.shared,
        });
    }
    let owner = pci_owner();
    let base_generation = catalog_mut().owner_generation(owner);
    catalog_mut()
        .prepare_replace_owner(
            owner,
            base_generation,
            owner_generation,
            &requests,
            HOSTED_INTERRUPT_VECTOR_LIMIT,
        )
        .map_err(authority_status)
}

pub(crate) unsafe fn commit_physical_interrupt_claims(
    prepared: PreparedPhysicalInterruptPublication,
) -> Result<Vec<PhysicalInterruptAssignment>, nt_status::NtStatus> {
    catalog_mut()
        .commit_replace_owner(prepared)
        .map_err(authority_status)
}

pub(crate) unsafe fn fence_pci_interrupt_claims(
    owner_generation: u64,
) -> Result<(), nt_status::NtStatus> {
    let owner = pci_owner();
    let current_generation = catalog_mut().owner_generation(owner);
    if current_generation == 0 {
        return Ok(());
    }
    if current_generation != owner_generation {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    catalog_mut()
        .fence_owner(owner, owner_generation)
        .map_err(authority_status)
}

pub(crate) unsafe fn validate_physical_interrupt_claim(
    claim: PhysicalInterruptClaim,
) -> Result<PhysicalInterruptRoute, nt_status::NtStatus> {
    catalog_mut().resolve_claim(claim).map_err(authority_status)
}

pub(crate) unsafe fn acquire_physical_interrupt_connection(
    claim: PhysicalInterruptClaim,
) -> Result<PhysicalInterruptConnectionLease, nt_status::NtStatus> {
    catalog_mut()
        .acquire_connection(claim)
        .map_err(authority_status)
}

pub(crate) unsafe fn validate_physical_interrupt_connection(
    lease: &PhysicalInterruptConnectionLease,
) -> Result<PhysicalInterruptRoute, nt_status::NtStatus> {
    catalog_mut()
        .resolve_connection(lease)
        .map_err(authority_status)
}

pub(crate) unsafe fn release_physical_interrupt_connection(
    lease: PhysicalInterruptConnectionLease,
) -> Result<(), (nt_status::NtStatus, PhysicalInterruptConnectionLease)> {
    catalog_mut()
        .release_connection(lease)
        .map_err(|(error, lease)| (authority_status(error), lease))
}
