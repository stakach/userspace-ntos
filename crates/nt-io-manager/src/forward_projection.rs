//! Source-IRP geometry shared by every cross-domain IRP forward.
//!
//! A hosted driver's `IofCallDriver` names its target in the IRP's next stack location. The
//! component addresses here are lookup keys inside the source domain's registered packet,
//! never authority of their own.

use nt_kernel_abi::{IoStackLocation, Irp};

use crate::source_irp_ledger::SourceIrpAllocation;

/// `IO_TYPE_IRP`.
const IO_TYPE_IRP: i16 = 6;
const IRP_BYTES: u64 = core::mem::size_of::<Irp>() as u64;
const STACK_LOCATION_BYTES: u64 = core::mem::size_of::<IoStackLocation>() as u64;

/// The component address of the next stack location of a source IRP registered as
/// `allocation`: the location an `IofCallDriver` caller fills for its target. `None` unless
/// the packet header is the registered packet with a current location that has a next one.
pub fn next_stack_location(allocation: SourceIrpAllocation, irp: &Irp) -> Option<u64> {
    if irp.type_ != IO_TYPE_IRP || irp.size as u64 != allocation.bytes {
        return None;
    }
    let location = u8::try_from(irp.current_location).ok()?;
    if location < 2
        || location > allocation.stack_count.saturating_add(1)
        || irp.stack_count != allocation.stack_count as i8
    {
        return None;
    }
    let stack_base = allocation.component_address + IRP_BYTES;
    let current_stack = stack_base + (location as u64 - 1) * STACK_LOCATION_BYTES;
    if irp.current_stack_location.0 != current_stack {
        return None;
    }
    Some(current_stack - STACK_LOCATION_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_irp_ledger::SourceIrpOwner;
    use crate::{HostedDomainId, HostedDomainIdentity};
    use nt_kernel_abi::GuestAddr;

    const PACKET: u64 = 0x9000;

    fn allocation(stack_count: u8) -> SourceIrpAllocation {
        SourceIrpAllocation {
            owner: SourceIrpOwner::HostedDriver(3),
            domain: HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 11 },
            component_address: PACKET,
            bytes: 208 + 72 * stack_count as u64,
            stack_count,
            pool_generation: 1,
        }
    }

    /// The header `IoAllocateIrp` writes, at current location `location`.
    fn packet(allocation: SourceIrpAllocation, location: i8) -> Irp {
        // SAFETY: `Irp` is a plain-old-data ABI record; all-zero is a valid value.
        let mut irp: Irp = unsafe { core::mem::zeroed() };
        irp.type_ = 6;
        irp.size = allocation.bytes as u16;
        irp.stack_count = allocation.stack_count as i8;
        irp.current_location = location;
        irp.current_stack_location =
            GuestAddr(PACKET + 208 + (location as u64).wrapping_sub(1) * 72);
        irp
    }

    #[test]
    fn next_location_is_the_one_below_the_current_location() {
        let registered = allocation(3);
        // A fresh packet sits at StackCount + 1; its first IofCallDriver fills location 3.
        assert_eq!(next_stack_location(registered, &packet(registered, 4)),
            Some(PACKET + 208 + 2 * 72));
        assert_eq!(next_stack_location(registered, &packet(registered, 2)), Some(PACKET + 208));
    }

    #[test]
    fn a_packet_with_no_next_location_or_a_foreign_header_has_none() {
        let registered = allocation(3);
        assert_eq!(next_stack_location(registered, &packet(registered, 1)), None,
            "the last location has no next one");
        assert_eq!(next_stack_location(registered, &packet(registered, 5)), None);
        let mut irp = packet(registered, 3);
        irp.type_ = 5;
        assert_eq!(next_stack_location(registered, &irp), None);
        let mut irp = packet(registered, 3);
        irp.size += 72;
        assert_eq!(next_stack_location(registered, &irp), None, "not the registered size");
        let mut irp = packet(registered, 3);
        irp.stack_count = 2;
        assert_eq!(next_stack_location(registered, &irp), None);
        let mut irp = packet(registered, 3);
        irp.current_stack_location.0 += 72;
        assert_eq!(next_stack_location(registered, &irp), None,
            "CurrentStackLocation must agree with CurrentLocation");
    }
}
