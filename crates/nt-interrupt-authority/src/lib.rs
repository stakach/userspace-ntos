//! Canonical physical interrupt-line arbitration.
//!
//! PnP route discovery, resource assignment, and interrupt delivery all need the same answer for
//! which GSI owns a translated vector. This crate owns that answer without knowing about driver
//! pointers, seL4 capabilities, or bus policy. Route publishers hold generation-exact claims;
//! connected interrupts hold exact leases. Fencing a publisher rejects new leases while preserving
//! the line until every old lease drains.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptOwner {
    kind: u32,
    id: u64,
}

impl PhysicalInterruptOwner {
    pub const fn new(kind: u32, id: u64) -> Option<Self> {
        if kind == 0 || id == 0 {
            None
        } else {
            Some(Self { kind, id })
        }
    }

    pub const fn kind(self) -> u32 {
        self.kind
    }

    pub const fn id(self) -> u64 {
        self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptRoute {
    pub gsi: u32,
    pub controller_ordinal: u16,
    pub local_pin: u16,
    pub vector: u32,
    pub level_sensitive: bool,
    pub active_low: bool,
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalInterruptVectorRequest {
    Exact(u32),
    Allocate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptRequest {
    pub gsi: u32,
    pub controller_ordinal: u16,
    pub local_pin: u16,
    pub vector: PhysicalInterruptVectorRequest,
    pub level_sensitive: bool,
    pub active_low: bool,
    pub shared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptLineId {
    pub gsi: u32,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptClaim {
    pub line: PhysicalInterruptLineId,
    pub claim_id: u64,
    pub owner: PhysicalInterruptOwner,
    pub owner_generation: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct PhysicalInterruptConnectionLease {
    line: PhysicalInterruptLineId,
    claim_id: u64,
    lease_id: u64,
}

impl PhysicalInterruptConnectionLease {
    pub const fn line(&self) -> PhysicalInterruptLineId {
        self.line
    }

    pub const fn claim_id(&self) -> u64 {
        self.claim_id
    }

    pub const fn lease_id(&self) -> u64 {
        self.lease_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalInterruptAssignment {
    pub claim: PhysicalInterruptClaim,
    pub route: PhysicalInterruptRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhysicalInterruptAuthorityError {
    InvalidOwner,
    InvalidGeneration,
    InvalidVectorLimit,
    InvalidVector,
    RouteConflict,
    VectorConflict,
    SharingConflict,
    Busy,
    StaleMutation,
    StaleOwner,
    StaleClaim,
    StaleLease,
    Fenced,
    Exhausted,
    Allocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimState {
    Active,
    Fenced,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LineRecord {
    id: PhysicalInterruptLineId,
    route: PhysicalInterruptRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimRecord {
    claim: PhysicalInterruptClaim,
    state: ClaimState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseRecord {
    line: PhysicalInterruptLineId,
    claim_id: u64,
    lease_id: u64,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OwnerRecord {
    owner: PhysicalInterruptOwner,
    generation: u64,
    admitted: bool,
}

pub struct PreparedPhysicalInterruptPublication {
    base_mutation_generation: u64,
    target_mutation_generation: u64,
    owner: PhysicalInterruptOwner,
    base_owner_generation: u64,
    target_owner_generation: u64,
    new_lines: Vec<LineRecord>,
    new_claims: Vec<ClaimRecord>,
    assignments: Vec<PhysicalInterruptAssignment>,
    next_line_generation: u64,
    next_claim_id: u64,
}

impl PreparedPhysicalInterruptPublication {
    pub fn assignments(&self) -> &[PhysicalInterruptAssignment] {
        &self.assignments
    }

    pub const fn target_owner_generation(&self) -> u64 {
        self.target_owner_generation
    }
}

#[derive(Default)]
pub struct PhysicalInterruptLineCatalog {
    lines: Vec<LineRecord>,
    claims: Vec<ClaimRecord>,
    leases: Vec<LeaseRecord>,
    owners: Vec<OwnerRecord>,
    mutation_generation: u64,
    next_line_generation: u64,
    next_claim_id: u64,
    next_lease_id: u64,
}

impl PhysicalInterruptLineCatalog {
    pub const fn new() -> Self {
        Self {
            lines: Vec::new(),
            claims: Vec::new(),
            leases: Vec::new(),
            owners: Vec::new(),
            mutation_generation: 0,
            next_line_generation: 1,
            next_claim_id: 1,
            next_lease_id: 1,
        }
    }

    pub const fn mutation_generation(&self) -> u64 {
        self.mutation_generation
    }

    pub fn owner_generation(&self, owner: PhysicalInterruptOwner) -> u64 {
        self.owners
            .iter()
            .find(|record| record.owner == owner)
            .map(|record| record.generation)
            .unwrap_or(0)
    }

    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn active_lease_count(&self) -> usize {
        self.leases.iter().filter(|lease| lease.active).count()
    }

    pub fn prepare_replace_owner(
        &mut self,
        owner: PhysicalInterruptOwner,
        base_owner_generation: u64,
        target_owner_generation: u64,
        requests: &[PhysicalInterruptRequest],
        vector_limit: u32,
    ) -> Result<PreparedPhysicalInterruptPublication, PhysicalInterruptAuthorityError> {
        if owner.kind == 0 || owner.id == 0 {
            return Err(PhysicalInterruptAuthorityError::InvalidOwner);
        }
        if target_owner_generation == 0 || target_owner_generation <= base_owner_generation {
            return Err(PhysicalInterruptAuthorityError::InvalidGeneration);
        }
        if self.owner_generation(owner) != base_owner_generation {
            return Err(PhysicalInterruptAuthorityError::StaleOwner);
        }
        if vector_limit <= 1 {
            return Err(PhysicalInterruptAuthorityError::InvalidVectorLimit);
        }

        let target_mutation_generation = self
            .mutation_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(PhysicalInterruptAuthorityError::Exhausted)?;
        let mut routes = Vec::new();
        routes
            .try_reserve_exact(requests.len())
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;

        for request in requests {
            let existing = self.lines.iter().find(|line| line.id.gsi == request.gsi);
            let prepared = routes
                .iter()
                .find(|route: &&PhysicalInterruptRoute| route.gsi == request.gsi)
                .copied();
            let vector = match request.vector {
                PhysicalInterruptVectorRequest::Exact(vector) => {
                    if vector == 0 || vector >= vector_limit {
                        return Err(PhysicalInterruptAuthorityError::InvalidVector);
                    }
                    vector
                }
                PhysicalInterruptVectorRequest::Allocate => {
                    if let Some(line) = existing {
                        line.route.vector
                    } else if let Some(route) = prepared {
                        route.vector
                    } else {
                        (1..vector_limit)
                            .find(|vector| {
                                self.lines.iter().all(|line| line.route.vector != *vector)
                                    && routes.iter().all(|route| route.vector != *vector)
                            })
                            .ok_or(PhysicalInterruptAuthorityError::Exhausted)?
                    }
                }
            };
            let route = PhysicalInterruptRoute {
                gsi: request.gsi,
                controller_ordinal: request.controller_ordinal,
                local_pin: request.local_pin,
                vector,
                level_sensitive: request.level_sensitive,
                active_low: request.active_low,
                shared: request.shared,
            };

            if let Some(prepared) = prepared {
                if prepared != route {
                    return Err(PhysicalInterruptAuthorityError::RouteConflict);
                }
                continue;
            }
            if let Some(line) = existing {
                if line.route != route {
                    return Err(PhysicalInterruptAuthorityError::RouteConflict);
                }
                if self.line_has_retained_claim_except_replaceable(
                    line.id,
                    owner,
                    base_owner_generation,
                ) && !route.shared
                {
                    return Err(PhysicalInterruptAuthorityError::SharingConflict);
                }
            } else if self
                .lines
                .iter()
                .any(|line| line.route.vector == route.vector && line.id.gsi != route.gsi)
                || routes
                    .iter()
                    .any(|other| other.vector == route.vector && other.gsi != route.gsi)
            {
                return Err(PhysicalInterruptAuthorityError::VectorConflict);
            }
            routes.push(route);
        }

        let new_line_count = routes
            .iter()
            .filter(|route| self.lines.iter().all(|line| line.id.gsi != route.gsi))
            .count();
        self.lines
            .try_reserve(new_line_count)
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        self.claims
            .try_reserve(routes.len())
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        if self.owners.iter().all(|record| record.owner != owner) {
            self.owners
                .try_reserve(1)
                .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        }

        let mut new_lines = Vec::new();
        new_lines
            .try_reserve_exact(new_line_count)
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        let mut new_claims = Vec::new();
        new_claims
            .try_reserve_exact(routes.len())
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        let mut assignments = Vec::new();
        assignments
            .try_reserve_exact(routes.len())
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;

        let mut next_line_generation = self.next_line_generation;
        let mut next_claim_id = self.next_claim_id;
        for route in routes {
            let line = if let Some(line) = self.lines.iter().find(|line| line.id.gsi == route.gsi) {
                line.id
            } else {
                let generation = next_line_generation;
                next_line_generation = next_line_generation
                    .checked_add(1)
                    .filter(|next| *next != 0)
                    .ok_or(PhysicalInterruptAuthorityError::Exhausted)?;
                let id = PhysicalInterruptLineId {
                    gsi: route.gsi,
                    generation,
                };
                new_lines.push(LineRecord { id, route });
                id
            };
            let claim = PhysicalInterruptClaim {
                line,
                claim_id: next_claim_id,
                owner,
                owner_generation: target_owner_generation,
            };
            next_claim_id = next_claim_id
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(PhysicalInterruptAuthorityError::Exhausted)?;
            new_claims.push(ClaimRecord {
                claim,
                state: ClaimState::Active,
            });
            assignments.push(PhysicalInterruptAssignment { claim, route });
        }

        Ok(PreparedPhysicalInterruptPublication {
            base_mutation_generation: self.mutation_generation,
            target_mutation_generation,
            owner,
            base_owner_generation,
            target_owner_generation,
            new_lines,
            new_claims,
            assignments,
            next_line_generation,
            next_claim_id,
        })
    }

    pub fn commit_replace_owner(
        &mut self,
        prepared: PreparedPhysicalInterruptPublication,
    ) -> Result<Vec<PhysicalInterruptAssignment>, PhysicalInterruptAuthorityError> {
        if self.mutation_generation != prepared.base_mutation_generation {
            return Err(PhysicalInterruptAuthorityError::StaleMutation);
        }
        if self.owner_generation(prepared.owner) != prepared.base_owner_generation {
            return Err(PhysicalInterruptAuthorityError::StaleOwner);
        }

        for claim in self.claims.iter_mut().filter(|claim| {
            claim.claim.owner == prepared.owner
                && claim.claim.owner_generation == prepared.base_owner_generation
                && claim.state == ClaimState::Active
        }) {
            claim.state = ClaimState::Fenced;
        }
        self.lines.extend(prepared.new_lines);
        self.claims.extend(prepared.new_claims);
        if let Some(record) = self
            .owners
            .iter_mut()
            .find(|record| record.owner == prepared.owner)
        {
            record.generation = prepared.target_owner_generation;
            record.admitted = true;
        } else {
            self.owners.push(OwnerRecord {
                owner: prepared.owner,
                generation: prepared.target_owner_generation,
                admitted: true,
            });
        }
        self.next_line_generation = prepared.next_line_generation;
        self.next_claim_id = prepared.next_claim_id;
        self.mutation_generation = prepared.target_mutation_generation;
        self.retire_drained_fenced_claims();
        self.collect_drained_lines();
        Ok(prepared.assignments)
    }

    pub fn fence_owner(
        &mut self,
        owner: PhysicalInterruptOwner,
        generation: u64,
    ) -> Result<(), PhysicalInterruptAuthorityError> {
        let next_mutation_generation = self.next_mutation_generation()?;
        let record = self
            .owners
            .iter_mut()
            .find(|record| record.owner == owner && record.generation == generation)
            .ok_or(PhysicalInterruptAuthorityError::StaleOwner)?;
        record.admitted = false;
        for claim in self.claims.iter_mut().filter(|claim| {
            claim.claim.owner == owner
                && claim.claim.owner_generation == generation
                && claim.state == ClaimState::Active
        }) {
            claim.state = ClaimState::Fenced;
        }
        self.mutation_generation = next_mutation_generation;
        self.retire_drained_fenced_claims();
        self.collect_drained_lines();
        Ok(())
    }

    pub fn resolve_claim(
        &self,
        claim: PhysicalInterruptClaim,
    ) -> Result<PhysicalInterruptRoute, PhysicalInterruptAuthorityError> {
        let record = self
            .claims
            .iter()
            .find(|record| record.claim == claim && record.state != ClaimState::Retired)
            .ok_or(PhysicalInterruptAuthorityError::StaleClaim)?;
        self.lines
            .iter()
            .find(|line| line.id == record.claim.line)
            .map(|line| line.route)
            .ok_or(PhysicalInterruptAuthorityError::StaleClaim)
    }

    pub fn acquire_connection(
        &mut self,
        claim: PhysicalInterruptClaim,
    ) -> Result<PhysicalInterruptConnectionLease, PhysicalInterruptAuthorityError> {
        let claim_record = self
            .claims
            .iter()
            .find(|record| record.claim == claim)
            .ok_or(PhysicalInterruptAuthorityError::StaleClaim)?;
        if claim_record.state != ClaimState::Active {
            return Err(PhysicalInterruptAuthorityError::Fenced);
        }
        if !self.owners.iter().any(|record| {
            record.owner == claim.owner
                && record.generation == claim.owner_generation
                && record.admitted
        }) {
            return Err(PhysicalInterruptAuthorityError::Fenced);
        }
        let route = self
            .lines
            .iter()
            .find(|line| line.id == claim.line)
            .map(|line| line.route)
            .ok_or(PhysicalInterruptAuthorityError::StaleClaim)?;
        if !route.shared
            && self
                .leases
                .iter()
                .any(|lease| lease.active && lease.line == claim.line)
        {
            return Err(PhysicalInterruptAuthorityError::Busy);
        }
        let lease_id = self.next_lease_id;
        let next_lease_id = lease_id
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(PhysicalInterruptAuthorityError::Exhausted)?;
        let next_mutation_generation = self.next_mutation_generation()?;
        self.leases
            .try_reserve(1)
            .map_err(|_| PhysicalInterruptAuthorityError::Allocation)?;
        self.leases.push(LeaseRecord {
            line: claim.line,
            claim_id: claim.claim_id,
            lease_id,
            active: true,
        });
        self.next_lease_id = next_lease_id;
        self.mutation_generation = next_mutation_generation;
        Ok(PhysicalInterruptConnectionLease {
            line: claim.line,
            claim_id: claim.claim_id,
            lease_id,
        })
    }

    pub fn resolve_connection(
        &self,
        lease: &PhysicalInterruptConnectionLease,
    ) -> Result<PhysicalInterruptRoute, PhysicalInterruptAuthorityError> {
        let live = self.leases.iter().any(|record| {
            record.active
                && record.line == lease.line
                && record.claim_id == lease.claim_id
                && record.lease_id == lease.lease_id
        });
        if !live {
            return Err(PhysicalInterruptAuthorityError::StaleLease);
        }
        self.lines
            .iter()
            .find(|line| line.id == lease.line)
            .map(|line| line.route)
            .ok_or(PhysicalInterruptAuthorityError::StaleLease)
    }

    pub fn release_connection(
        &mut self,
        lease: PhysicalInterruptConnectionLease,
    ) -> Result<
        (),
        (
            PhysicalInterruptAuthorityError,
            PhysicalInterruptConnectionLease,
        ),
    > {
        let next_mutation_generation = match self.next_mutation_generation() {
            Ok(generation) => generation,
            Err(error) => return Err((error, lease)),
        };
        let Some(index) = self.leases.iter().position(|record| {
            record.active
                && record.line == lease.line
                && record.claim_id == lease.claim_id
                && record.lease_id == lease.lease_id
        }) else {
            return Err((PhysicalInterruptAuthorityError::StaleLease, lease));
        };
        self.leases[index].active = false;
        self.mutation_generation = next_mutation_generation;
        self.retire_drained_fenced_claims();
        self.collect_drained_lines();
        Ok(())
    }

    fn line_has_retained_claim_except_replaceable(
        &self,
        line: PhysicalInterruptLineId,
        owner: PhysicalInterruptOwner,
        owner_generation: u64,
    ) -> bool {
        self.claims.iter().any(|record| {
            if record.claim.line != line || record.state == ClaimState::Retired {
                return false;
            }
            let replaced = record.claim.owner == owner
                && record.claim.owner_generation == owner_generation
                && !self.leases.iter().any(|lease| {
                    lease.active && lease.line == line && lease.claim_id == record.claim.claim_id
                });
            !replaced
        })
    }

    fn retire_drained_fenced_claims(&mut self) {
        let leases = &self.leases;
        for claim in &mut self.claims {
            if claim.state == ClaimState::Fenced
                && !leases.iter().any(|lease| {
                    lease.active
                        && lease.line == claim.claim.line
                        && lease.claim_id == claim.claim.claim_id
                })
            {
                claim.state = ClaimState::Retired;
            }
        }
    }

    fn collect_drained_lines(&mut self) {
        self.leases.retain(|lease| lease.active);
        self.claims
            .retain(|claim| claim.state != ClaimState::Retired);
        let claims = &self.claims;
        let leases = &self.leases;
        self.lines.retain(|line| {
            claims.iter().any(|claim| claim.claim.line == line.id)
                || leases.iter().any(|lease| lease.line == line.id)
        });
    }

    fn next_mutation_generation(&self) -> Result<u64, PhysicalInterruptAuthorityError> {
        self.mutation_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(PhysicalInterruptAuthorityError::Exhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCI: PhysicalInterruptOwner = PhysicalInterruptOwner { kind: 1, id: 1 };
    const SCI: PhysicalInterruptOwner = PhysicalInterruptOwner { kind: 2, id: 1 };

    fn request(gsi: u32, vector: PhysicalInterruptVectorRequest) -> PhysicalInterruptRequest {
        PhysicalInterruptRequest {
            gsi,
            controller_ordinal: 0,
            local_pin: gsi as u16,
            vector,
            level_sensitive: true,
            active_low: true,
            shared: true,
        }
    }

    fn publish(
        catalog: &mut PhysicalInterruptLineCatalog,
        owner: PhysicalInterruptOwner,
        base: u64,
        target: u64,
        requests: &[PhysicalInterruptRequest],
    ) -> Vec<PhysicalInterruptAssignment> {
        let prepared = catalog
            .prepare_replace_owner(owner, base, target, requests, 32)
            .unwrap();
        catalog.commit_replace_owner(prepared).unwrap()
    }

    #[test]
    fn sci_vector_is_reserved_from_distinct_pci_gsi() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let sci = publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        let pci = publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(23, PhysicalInterruptVectorRequest::Allocate)],
        );
        assert_eq!(sci[0].route.vector, 9);
        assert_ne!(pci[0].route.vector, 9);
        assert_eq!(catalog.line_count(), 2);
    }

    #[test]
    fn compatible_same_gsi_reuses_line_and_vector() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let first = publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        let second = publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Allocate)],
        );
        assert_eq!(first[0].claim.line, second[0].claim.line);
        assert_eq!(second[0].route.vector, 9);
        assert_eq!(catalog.line_count(), 1);
    }

    #[test]
    fn conflicting_same_gsi_policy_is_atomic() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        let generation = catalog.mutation_generation();
        let mut conflict = request(9, PhysicalInterruptVectorRequest::Allocate);
        conflict.active_low = false;
        assert!(matches!(
            catalog.prepare_replace_owner(PCI, 0, 1, &[conflict], 32),
            Err(PhysicalInterruptAuthorityError::RouteConflict)
        ));
        assert_eq!(catalog.mutation_generation(), generation);
        assert_eq!(catalog.line_count(), 1);
    }

    #[test]
    fn exact_vector_cannot_alias_a_distinct_gsi() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        assert!(matches!(
            catalog.prepare_replace_owner(
                PCI,
                0,
                1,
                &[request(23, PhysicalInterruptVectorRequest::Exact(9))],
                32,
            ),
            Err(PhysicalInterruptAuthorityError::VectorConflict)
        ));
    }

    #[test]
    fn duplicate_batch_gsi_collapses_to_one_claim() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let request = request(23, PhysicalInterruptVectorRequest::Allocate);
        let assignments = publish(&mut catalog, PCI, 0, 1, &[request, request]);
        assert_eq!(assignments.len(), 1);
        assert_eq!(catalog.line_count(), 1);
    }

    #[test]
    fn fence_blocks_new_leases_but_preserves_existing_connection() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let assignments = publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(23, PhysicalInterruptVectorRequest::Allocate)],
        );
        let claim = assignments[0].claim;
        let lease = catalog.acquire_connection(claim).unwrap();
        catalog.fence_owner(PCI, 1).unwrap();
        assert_eq!(
            catalog.acquire_connection(claim),
            Err(PhysicalInterruptAuthorityError::Fenced)
        );
        assert_eq!(catalog.resolve_connection(&lease), Ok(assignments[0].route));
        assert_eq!(catalog.line_count(), 1);
        catalog.release_connection(lease).unwrap();
        assert_eq!(catalog.line_count(), 0);
    }

    #[test]
    fn shared_line_accepts_independent_connection_leases() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let sci = publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        let pci = publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Allocate)],
        );
        let first = catalog.acquire_connection(sci[0].claim).unwrap();
        let second = catalog.acquire_connection(pci[0].claim).unwrap();
        assert_eq!(catalog.active_lease_count(), 2);
        catalog.release_connection(first).unwrap();
        assert_eq!(catalog.resolve_connection(&second), Ok(pci[0].route));
    }

    #[test]
    fn shared_owner_republication_fences_old_claim_and_preserves_its_lease() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let first = publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(23, PhysicalInterruptVectorRequest::Allocate)],
        );
        let old_lease = catalog.acquire_connection(first[0].claim).unwrap();
        let second = publish(
            &mut catalog,
            PCI,
            1,
            2,
            &[request(23, PhysicalInterruptVectorRequest::Allocate)],
        );
        assert_eq!(first[0].claim.line, second[0].claim.line);
        assert_eq!(first[0].route.vector, second[0].route.vector);
        assert_eq!(catalog.resolve_connection(&old_lease), Ok(first[0].route));
        assert_eq!(
            catalog.acquire_connection(first[0].claim),
            Err(PhysicalInterruptAuthorityError::Fenced)
        );
        let new_lease = catalog.acquire_connection(second[0].claim).unwrap();
        catalog.release_connection(old_lease).unwrap();
        assert_eq!(catalog.resolve_connection(&new_lease), Ok(second[0].route));
    }

    #[test]
    fn exclusive_replacement_waits_for_old_lease() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let mut exclusive = request(5, PhysicalInterruptVectorRequest::Exact(5));
        exclusive.shared = false;
        let first = publish(&mut catalog, PCI, 0, 1, &[exclusive]);
        let lease = catalog.acquire_connection(first[0].claim).unwrap();
        assert!(matches!(
            catalog.prepare_replace_owner(PCI, 1, 2, &[exclusive], 32),
            Err(PhysicalInterruptAuthorityError::SharingConflict)
        ));
        catalog.fence_owner(PCI, 1).unwrap();
        catalog.release_connection(lease).unwrap();
        let second = publish(&mut catalog, PCI, 1, 2, &[exclusive]);
        assert_ne!(
            first[0].claim.line.generation,
            second[0].claim.line.generation
        );
    }

    #[test]
    fn stale_preparation_cannot_commit_after_lease_mutation() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        let first = publish(
            &mut catalog,
            SCI,
            0,
            1,
            &[request(9, PhysicalInterruptVectorRequest::Exact(9))],
        );
        let prepared = catalog
            .prepare_replace_owner(
                PCI,
                0,
                1,
                &[request(23, PhysicalInterruptVectorRequest::Allocate)],
                32,
            )
            .unwrap();
        let _lease = catalog.acquire_connection(first[0].claim).unwrap();
        assert_eq!(
            catalog.commit_replace_owner(prepared),
            Err(PhysicalInterruptAuthorityError::StaleMutation)
        );
    }

    #[test]
    fn empty_replacement_fences_old_claims() {
        let mut catalog = PhysicalInterruptLineCatalog::new();
        publish(
            &mut catalog,
            PCI,
            0,
            1,
            &[request(23, PhysicalInterruptVectorRequest::Allocate)],
        );
        let removed = publish(&mut catalog, PCI, 1, 2, &[]);
        assert!(removed.is_empty());
        assert_eq!(catalog.line_count(), 0);
        assert_eq!(catalog.owner_generation(PCI), 2);
    }
}
