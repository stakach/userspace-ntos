//! Retained provider targets for pending buffered device controls.

use super::*;
use nt_provider_wait::{ProviderAllocationPin, ProviderStackLanePin};

#[must_use = "retain the target until the exact operation is terminal and acknowledged"]
pub(super) enum PinnedIoctlOutput {
    None,
    Stack(ProviderStackLanePin),
    Pool(ProviderAllocationPin),
    Image,
}

#[derive(Clone, Copy)]
pub(crate) enum RootIoctlOutputTarget {
    Pool {
        provider: nt_provider_wait::ProviderDomainIdentity,
        identity: shared_pool::AllocationIdentity,
        address: u64,
        length: u64,
    },
    Image {
        provider: nt_provider_wait::ProviderDomainIdentity,
        map_owner: u64,
        address: u64,
        length: u64,
    },
}

fn writable_image_range(address: u64, length: u64) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if length == 0 || address < WIN32K_CODE_VA || end > WIN32K_CODE_VA + WIN32K_IMAGE_BYTES {
        return false;
    }
    let first = ((address - WIN32K_CODE_VA) / 0x1000) as usize;
    let last = ((end - 1 - WIN32K_CODE_VA) / 0x1000) as usize;
    code_rights()[first..=last]
        .iter()
        .all(|&rights| rights == RW_NX)
}

/// Pin exactly the caller-visible target. The stack receipt also fences activation retirement;
/// the allocation receipt makes an ExFreePool* call refuse the allocation until publication ends.
pub(super) unsafe fn pin_output(
    activation: ProviderStackEventActivation,
    address: u64,
    length: u64,
) -> Result<PinnedIoctlOutput, i32> {
    if length == 0 {
        return Ok(PinnedIoctlOutput::None);
    }
    if address == 0 || address.checked_add(length).is_none() {
        return Err(STATUS_INVALID_PARAMETER_I32);
    }
    if let Some(catalog) = (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS)).as_mut()
    {
        if catalog.resolve(address, length).is_ok() {
            return catalog
                .pin_active_range(activation, address, length)
                .map(|(_, pin)| PinnedIoctlOutput::Stack(pin))
                .map_err(|_| STATUS_ACCESS_VIOLATION_I32);
        }
    }
    if provider_pool_contains(address) {
        let pin = with_provider_allocations(|catalog| catalog.pin_containing(address, length))
            .ok_or(STATUS_NOT_SUPPORTED_I32)?
            .map(|(_, pin)| pin)
            .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?;
        if capture_root_output(address, length).is_some() {
            return Ok(PinnedIoctlOutput::Pool(pin));
        }
        release_output(PinnedIoctlOutput::Pool(pin));
        return Err(STATUS_ACCESS_VIOLATION_I32);
    }
    // CODE_RIGHTS is finalized by the root loader; the provider's copy may still contain its
    // default rights. This is only preliminary admission. Root capture checks its own loaded
    // image rights before the operation is issued or any completion target is written.
    if writable_image_range(address, length)
        && WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) != 0
        && registered_provider_wait_domain().is_some()
    {
        return Ok(PinnedIoctlOutput::Image);
    }
    Err(STATUS_ACCESS_VIOLATION_I32)
}

pub(super) unsafe fn release_output(pin: PinnedIoctlOutput) {
    let released = match pin {
        PinnedIoctlOutput::None | PinnedIoctlOutput::Image => true,
        PinnedIoctlOutput::Stack(pin) => {
            (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS))
                .as_mut()
                .is_some_and(|catalog| catalog.release_pin(pin).is_ok())
        }
        PinnedIoctlOutput::Pool(pin) => {
            with_provider_allocations(|catalog| catalog.release_pin(pin).is_ok()) == Some(true)
        }
    };
    if !released {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, 0, 0, 1]);
    }
}

/// Root-side non-stack provenance. The root's CODE_RIGHTS is authoritative for image writes.
/// A stack target must instead use the retained physical lane's authenticated alias; this
/// function deliberately cannot turn an arbitrary pointer into one.
pub(crate) unsafe fn capture_root_output(
    address: u64,
    length: u64,
) -> Option<RootIoctlOutputTarget> {
    let provider = registered_provider_wait_domain()?;
    if length == 0 || address == 0 || address.checked_add(length).is_none() {
        return None;
    }
    if provider_pool_contains(address) {
        let _guard = provider_pool_lock()?;
        let location = shared_pool::containing_allocation(
            &ProviderPoolMemory,
            address - WIN32K_POOL_VADDR,
            length,
        )
        .ok()?;
        return Some(RootIoctlOutputTarget::Pool {
            provider,
            identity: location.identity,
            address,
            length,
        });
    }
    if writable_image_range(address, length) {
        let map_owner = WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire);
        if map_owner != 0 {
            return Some(RootIoctlOutputTarget::Image {
                provider,
                map_owner,
                address,
                length,
            });
        }
    }
    None
}

impl RootIoctlOutputTarget {
    pub(crate) fn address(self) -> u64 {
        match self {
            Self::Pool { address, .. } | Self::Image { address, .. } => address,
        }
    }

    pub(crate) fn length(self) -> u64 {
        match self {
            Self::Pool { length, .. } | Self::Image { length, .. } => length,
        }
    }

    pub(crate) unsafe fn is_live(self) -> bool {
        match self {
            Self::Pool {
                provider,
                identity,
                address,
                length,
            } => {
                if registered_provider_wait_domain() != Some(provider) {
                    return false;
                }
                let Some(_guard) = provider_pool_lock() else {
                    return false;
                };
                shared_pool::containing_allocation(
                    &ProviderPoolMemory,
                    address - WIN32K_POOL_VADDR,
                    length,
                )
                .is_ok_and(|location| location.identity == identity)
            }
            Self::Image {
                provider,
                map_owner,
                address,
                length,
            } => {
                registered_provider_wait_domain() == Some(provider)
                    && WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) == map_owner
                    && writable_image_range(address, length)
            }
        }
    }
}
