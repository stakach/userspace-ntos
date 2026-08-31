use alloc::vec::Vec;

use crate::PciInterruptRoute;

/// One platform-vector assignment shared by every PCI route targeting the same GSI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciInterruptVector {
    pub gsi: u32,
    pub vector: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciInterruptVectorError {
    InvalidVectorLimit,
    InvalidReservedVector(u32),
    Exhausted,
    Allocation,
}

/// Allocate stable nonzero platform vectors for the distinct GSIs in one route publication.
///
/// Vector zero is reserved as the NT "no interrupt" sentinel. The caller supplies the exclusive
/// platform limit and vectors already owned by kernel facilities. Sorting by GSI makes the result
/// independent of firmware table order, while routes sharing a GSI receive one vector.
pub fn allocate_pci_interrupt_vectors(
    routes: &[PciInterruptRoute],
    vector_limit: u32,
    reserved: &[u32],
) -> Result<Vec<PciInterruptVector>, PciInterruptVectorError> {
    if vector_limit <= 1 {
        return Err(PciInterruptVectorError::InvalidVectorLimit);
    }
    if let Some(vector) = reserved
        .iter()
        .copied()
        .find(|vector| *vector == 0 || *vector >= vector_limit)
    {
        return Err(PciInterruptVectorError::InvalidReservedVector(vector));
    }

    let mut gsis = Vec::new();
    gsis.try_reserve_exact(routes.len())
        .map_err(|_| PciInterruptVectorError::Allocation)?;
    gsis.extend(routes.iter().map(|route| route.gsi));
    gsis.sort_unstable();
    gsis.dedup();

    let mut assignments = Vec::new();
    assignments
        .try_reserve_exact(gsis.len())
        .map_err(|_| PciInterruptVectorError::Allocation)?;
    let mut candidate = 1u32;
    for gsi in gsis {
        while candidate < vector_limit && reserved.contains(&candidate) {
            candidate += 1;
        }
        if candidate >= vector_limit {
            return Err(PciInterruptVectorError::Exhausted);
        }
        assignments.push(PciInterruptVector {
            gsi,
            vector: candidate,
        });
        candidate += 1;
    }
    Ok(assignments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PciRouteFunction;
    use alloc::vec;

    fn route(device: u8, gsi: u32) -> PciInterruptRoute {
        PciInterruptRoute {
            segment: 0,
            bus: 0,
            device,
            function: PciRouteFunction::Any,
            pin: 0,
            gsi,
            level_sensitive: true,
            active_low: true,
            shared: true,
        }
    }

    #[test]
    fn allocation_is_stable_shared_and_skips_kernel_vectors() {
        let assignments = allocate_pci_interrupt_vectors(
            &[route(3, 19), route(2, 0), route(4, 19), route(5, 10)],
            8,
            &[2, 4],
        )
        .unwrap();
        assert_eq!(
            assignments,
            vec![
                PciInterruptVector { gsi: 0, vector: 1 },
                PciInterruptVector { gsi: 10, vector: 3 },
                PciInterruptVector { gsi: 19, vector: 5 },
            ]
        );
    }

    #[test]
    fn allocation_rejects_invalid_limits_and_reserved_vectors() {
        assert_eq!(
            allocate_pci_interrupt_vectors(&[], 1, &[]),
            Err(PciInterruptVectorError::InvalidVectorLimit)
        );
        assert_eq!(
            allocate_pci_interrupt_vectors(&[], 8, &[0]),
            Err(PciInterruptVectorError::InvalidReservedVector(0))
        );
        assert_eq!(
            allocate_pci_interrupt_vectors(&[], 8, &[8]),
            Err(PciInterruptVectorError::InvalidReservedVector(8))
        );
    }

    #[test]
    fn allocation_fails_when_distinct_gsis_exceed_platform_vectors() {
        assert_eq!(
            allocate_pci_interrupt_vectors(&[route(0, 1), route(1, 2), route(2, 3)], 4, &[2],),
            Err(PciInterruptVectorError::Exhausted)
        );
    }
}
