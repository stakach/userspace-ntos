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
const ACPI_CHILD_OWNER_KIND: u32 = 4;
const ACPI_SCI_OWNER_ID: u64 = 1;
const PCI_ROUTE_OWNER_ID: u64 = 1;
const DELAY_TIMER_OWNER_ID: u64 = 1;

static mut PHYSICAL_INTERRUPT_LINES: PhysicalInterruptLineCatalog =
    PhysicalInterruptLineCatalog::new();
static mut ACPI_CHILD_INTERRUPT_CLAIMS: Vec<AcpiChildInterruptClaim> = Vec::new();

/// Exact accepted relation and function-stack generation supplied by the caller's PnP owner.
/// The constructor prevents mixing a child PDO with another provider's relation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcpiChildInterruptIdentity {
    provider: nt_pnp_manager::AcceptedPdoProviderAuthority,
    child: nt_pnp_manager::DevnodeIdentity,
    fdo_device_id: u64,
    fdo_owner_generation: u64,
}

impl AcpiChildInterruptIdentity {
    pub(crate) const fn fdo_owner_generation(self) -> u64 {
        self.fdo_owner_generation
    }
    pub(crate) fn new(
        provider: nt_pnp_manager::AcceptedPdoProviderAuthority,
        child: nt_pnp_manager::DevnodeIdentity,
        fdo_device_id: u64,
        fdo_owner_generation: u64,
    ) -> Option<Self> {
        (provider.pdo_object_id() == child.pdo_object_id()
            && child.generation() != 0
            && provider.parent_relation().relation().generation() != 0
            && fdo_device_id != 0
            && fdo_owner_generation != 0)
            .then_some(Self {
                provider,
                child,
                fdo_device_id,
                fdo_owner_generation,
            })
    }
}

#[derive(Clone, Copy)]
struct AcpiChildInterruptClaim {
    identity: AcpiChildInterruptIdentity,
    assignment: PhysicalInterruptAssignment,
    active: bool,
}

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

/// Claim a physical line for one accepted ACPI child and its exact FDO owner generation.
/// The caller must validate that `identity` is still the live accepted PDO/FDO pair before
/// calling; the route must come from that PDO's admitted resource assignment.
pub(crate) unsafe fn claim_acpi_child_interrupt(
    identity: AcpiChildInterruptIdentity,
    gsi: u32,
    level_sensitive: bool,
    active_low: bool,
    shared: bool,
) -> Result<PhysicalInterruptAssignment, nt_status::NtStatus> {
    let hardware = crate::resolve_platform_ioapic_gsi(gsi)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let rows = &mut *core::ptr::addr_of_mut!(ACPI_CHILD_INTERRUPT_CLAIMS);
    let existing = rows.iter().position(|row| row.identity.fdo_device_id == identity.fdo_device_id);
    if let Some(row) = existing.and_then(|index| rows.get(index)) {
        if row.active {
            let route = row.assignment.route;
            if row.identity == identity
                && route.gsi == gsi
                && route.controller_ordinal == hardware.controller_ordinal
                && route.local_pin == hardware.local_pin
                && route.level_sensitive == level_sensitive
                && route.active_low == active_low
                && route.shared == shared
            {
                return Ok(row.assignment);
            }
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    } else {
        rows.try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    }

    let owner = PhysicalInterruptOwner::new(ACPI_CHILD_OWNER_KIND, identity.fdo_device_id)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    let catalog = catalog_mut();
    let base_generation = catalog.owner_generation(owner);
    let target_generation = base_generation
        .checked_add(1)
        .filter(|generation| *generation != 0)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let publication = catalog
        .prepare_replace_owner(
            owner,
            base_generation,
            target_generation,
            &[PhysicalInterruptRequest {
                gsi,
                controller_ordinal: hardware.controller_ordinal,
                local_pin: hardware.local_pin,
                vector: PhysicalInterruptVectorRequest::Allocate,
                level_sensitive,
                active_low,
                shared,
            }],
            HOSTED_INTERRUPT_VECTOR_LIMIT,
        )
        .map_err(authority_status)?;
    let assignments = catalog.commit_replace_owner(publication).map_err(authority_status)?;
    let assignment = assignments
        .first()
        .copied()
        .expect("one child IRQ request must publish one physical assignment");
    let record = AcpiChildInterruptClaim {
        identity,
        assignment,
        active: true,
    };
    if let Some(index) = existing {
        rows[index] = record;
    } else {
        rows.push(record);
    }
    Ok(assignment)
}

/// Stop new IRQ connections during failed START or retirement. Existing connection leases
/// retain the physical line until their ordinary disconnect path releases them.
pub(crate) unsafe fn fence_acpi_child_interrupt(
    identity: AcpiChildInterruptIdentity,
) -> Result<(), nt_status::NtStatus> {
    let rows = &mut *core::ptr::addr_of_mut!(ACPI_CHILD_INTERRUPT_CLAIMS);
    let row = rows
        .iter_mut()
        .find(|row| row.identity.fdo_device_id == identity.fdo_device_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if row.identity != identity {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if !row.active {
        return Ok(());
    }
    catalog_mut()
        .fence_owner(row.assignment.claim.owner, row.assignment.claim.owner_generation)
        .map_err(authority_status)?;
    row.active = false;
    Ok(())
}

/// Drop the FDO's bookkeeping only after its claim has been fenced. The physical catalog
/// independently retains any old connection lease and its line until disconnect completes.
pub(crate) unsafe fn retire_acpi_child_interrupt(
    identity: AcpiChildInterruptIdentity,
) -> Result<(), nt_status::NtStatus> {
    let rows = &mut *core::ptr::addr_of_mut!(ACPI_CHILD_INTERRUPT_CLAIMS);
    let index = rows
        .iter()
        .position(|row| row.identity.fdo_device_id == identity.fdo_device_id)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    let row = rows[index];
    if row.identity != identity {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if row.active {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    rows.remove(index);
    Ok(())
}

/// Resolve the saved claim by its exact function-device and hosted domain generation. This
/// remains valid while a parent relation is being removed, when fresh catalog lookup cannot be
/// used to retire the old child.
pub(crate) unsafe fn acpi_child_interrupt_identity_for_fdo(
    fdo_device_id: u64,
    fdo_owner_generation: u64,
) -> Result<Option<AcpiChildInterruptIdentity>, nt_status::NtStatus> {
    let row = (&*core::ptr::addr_of!(ACPI_CHILD_INTERRUPT_CLAIMS))
        .iter()
        .find(|row| row.identity.fdo_device_id == fdo_device_id);
    match row {
        None => Ok(None),
        Some(row) if row.identity.fdo_owner_generation == fdo_owner_generation =>
            Ok(Some(row.identity)),
        Some(_) => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
    }
}

/// A fresh START cannot replace an active child claim. An inactive row may still have a retained
/// connection lease; physical admission will then decide whether the line is reusable.
pub(crate) unsafe fn ensure_acpi_child_interrupt_claim_inactive(
    identity: AcpiChildInterruptIdentity,
) -> Result<(), nt_status::NtStatus> {
    let row = (&*core::ptr::addr_of!(ACPI_CHILD_INTERRUPT_CLAIMS))
        .iter()
        .find(|row| row.identity.fdo_device_id == identity.fdo_device_id);
    match row {
        None => Ok(()),
        Some(row) if row.identity != identity => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
        Some(row) if row.active => Err(nt_status::NtStatus::DEVICE_BUSY),
        Some(_) => Ok(()),
    }
}

/// Fence only the claim projected in the retiring resource state. A rebalance may already have
/// published a newer generation for the same FDO while the old projection is being cleared.
pub(crate) unsafe fn fence_acpi_child_projected_interrupt(
    fdo_device_id: u64,
    fdo_owner_generation: u64,
    projected: PhysicalInterruptClaim,
) -> Result<(), nt_status::NtStatus> {
    let Some(identity) = acpi_child_interrupt_identity_for_fdo(
        fdo_device_id, fdo_owner_generation,
    )? else {
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    let row = (&*core::ptr::addr_of!(ACPI_CHILD_INTERRUPT_CLAIMS))
        .iter()
        .find(|row| row.identity == identity)
        .ok_or(nt_status::NtStatus::INVALID_DEVICE_REQUEST)?;
    if row.assignment.claim == projected {
        fence_acpi_child_interrupt(identity)?;
    }
    Ok(())
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
