//! Caller video memory is an exact resource mapping, not a precomputed virtual address.

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> ApertureIdentity {
        ApertureIdentity {
            context: 1,
            context_lease: 2,
            device: 3,
            resource_index: 0,
            bus: 0,
            device_number: 2,
            function: 0,
            caller_domain: 4,
            caller_generation: 5,
            caller_authority: 6,
            caller_vspace: 7,
            physical: 0x80000000,
            length: 0x3010,
            virtual_base: 0x10009000000,
            backing_pages: 4,
            writable: true,
        }
    }
    #[test]
    fn admission_maps_entire_aperture_including_partial_final_page() {
        let plan = AperturePlan::new(key(), 0).unwrap();
        assert_eq!(plan.pages(), 4);
        assert_eq!(plan.page(3), Some((0x80003000, 0x10009003000)));
        assert_eq!(plan.page(4), None);
        assert_eq!(
            AperturePlan::new(
                ApertureIdentity {
                    backing_pages: 3,
                    ..key()
                },
                0
            ),
            Err(ApertureError::IncompleteBacking)
        );
    }
    #[test]
    fn process_handle_request_never_aliases_kernel_caller() {
        assert_eq!(
            AperturePlan::new(key(), 0x123),
            Err(ApertureError::ProcessMappingUnsupported)
        );
    }
    #[test]
    fn stale_generation_or_different_resource_cannot_reuse_mapping() {
        let plan = AperturePlan::new(key(), 0).unwrap();
        assert!(plan.matches(key()));
        assert!(!plan.matches(ApertureIdentity {
            context_lease: 9,
            ..key()
        }));
        assert!(!plan.matches(ApertureIdentity {
            caller_generation: 9,
            ..key()
        }));
        assert!(!plan.matches(ApertureIdentity { device: 9, ..key() }));
        assert!(!plan.matches(ApertureIdentity {
            physical: 0x90000000,
            ..key()
        }));
    }
    #[test]
    fn ownership_precedes_map_and_only_full_commit_permits_publication() {
        let mut tx = ApertureTransaction::new(AperturePlan::new(key(), 0).unwrap());
        assert_eq!(tx.begin_map(), Err(ApertureError::NoOwnedMapCapability));
        for index in 0..4 {
            tx.record_map_capability(index).unwrap();
            tx.begin_map().unwrap();
            assert!(!tx.publishable());
            tx.acknowledge_map(MapEffect::Mapped).unwrap();
        }
        tx.commit().unwrap();
        assert!(tx.publishable());
        assert_eq!(tx.begin_map(), Err(ApertureError::WrongPhase));
    }
    #[test]
    fn unknown_effect_forbids_replay_and_no_effect_requires_exact_rollback() {
        let mut tx = ApertureTransaction::new(AperturePlan::new(key(), 0).unwrap());
        tx.record_map_capability(0).unwrap();
        tx.begin_map().unwrap();
        assert_eq!(tx.begin_map(), Err(ApertureError::WrongPhase));
        tx.acknowledge_map(MapEffect::Unknown).unwrap();
        assert_eq!(tx.phase(), AperturePhase::Quarantined);
        assert_eq!(tx.rollback_complete(), Err(ApertureError::WrongPhase));
        let mut known = ApertureTransaction::new(AperturePlan::new(key(), 0).unwrap());
        known.record_map_capability(0).unwrap();
        known.begin_map().unwrap();
        known.acknowledge_map(MapEffect::NoEffect).unwrap();
        assert_eq!(known.phase(), AperturePhase::RollbackRequired);
        known.rollback_complete().unwrap();
        assert!(!known.publishable());
        assert_eq!(known.phase(), AperturePhase::Retired);
    }
    #[test]
    fn invalid_extent_or_identity_fails_before_native_effect() {
        assert!(AperturePlan::new(
            ApertureIdentity {
                caller_generation: 0,
                ..key()
            },
            0
        )
        .is_err());
        assert!(AperturePlan::new(
            ApertureIdentity {
                physical: u64::MAX & !0xfff,
                ..key()
            },
            0
        )
        .is_err());
        assert!(AperturePlan::new(
            ApertureIdentity {
                virtual_base: 1,
                ..key()
            },
            0
        )
        .is_err());
    }

    #[test]
    fn no_effect_failure_between_maps_requires_rollback_without_replay() {
        let mut tx = ApertureTransaction::new(AperturePlan::new(key(), 0).unwrap());
        tx.record_map_capability(0).unwrap();
        tx.begin_map().unwrap();
        tx.acknowledge_map(MapEffect::Mapped).unwrap();
        tx.abort_before_map().unwrap();
        assert_eq!(tx.phase(), AperturePhase::RollbackRequired);
        assert_eq!(tx.mapped(), 1);
        assert_eq!(tx.begin_map(), Err(ApertureError::WrongPhase));
        tx.rollback_complete().unwrap();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApertureIdentity<C = u64> {
    pub context: u64,
    pub context_lease: u64,
    pub device: u64,
    pub resource_index: u8,
    pub bus: u8,
    pub device_number: u8,
    pub function: u8,
    pub caller_domain: u64,
    pub caller_generation: u64,
    pub caller_authority: C,
    pub caller_vspace: u64,
    pub physical: u64,
    pub length: u64,
    pub virtual_base: u64,
    pub backing_pages: u64,
    pub writable: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApertureError {
    InvalidIdentity,
    InvalidExtent,
    IncompleteBacking,
    ProcessMappingUnsupported,
    WrongPhase,
    NoOwnedMapCapability,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AperturePlan<C = u64> {
    identity: ApertureIdentity<C>,
    pages: u64,
}
impl<C: Copy + Eq> AperturePlan<C> {
    pub fn new(
        identity: ApertureIdentity<C>,
        incoming_virtual_address: u64,
    ) -> Result<Self, ApertureError> {
        if incoming_virtual_address != 0 {
            return Err(ApertureError::ProcessMappingUnsupported);
        }
        if identity.context == 0
            || identity.context_lease == 0
            || identity.device == 0
            || identity.caller_domain == 0
            || identity.caller_generation == 0
            || identity.caller_vspace == 0
            || identity.resource_index >= 6
            || identity.device_number >= 32
            || identity.function >= 8
        {
            return Err(ApertureError::InvalidIdentity);
        }
        if identity.length == 0
            || identity.physical == 0
            || identity.virtual_base == 0
            || identity.physical & 0xfff != 0
            || identity.virtual_base & 0xfff != 0
        {
            return Err(ApertureError::InvalidExtent);
        }
        let pages = identity
            .length
            .checked_add(0xfff)
            .ok_or(ApertureError::InvalidExtent)?
            / 0x1000;
        let bytes = pages
            .checked_mul(0x1000)
            .ok_or(ApertureError::InvalidExtent)?;
        identity
            .physical
            .checked_add(bytes)
            .ok_or(ApertureError::InvalidExtent)?;
        identity
            .virtual_base
            .checked_add(bytes)
            .ok_or(ApertureError::InvalidExtent)?;
        if identity.backing_pages < pages {
            return Err(ApertureError::IncompleteBacking);
        }
        Ok(Self { identity, pages })
    }
    pub const fn identity(self) -> ApertureIdentity<C> {
        self.identity
    }
    pub const fn pages(self) -> u64 {
        self.pages
    }
    pub fn matches(self, identity: ApertureIdentity<C>) -> bool {
        self.identity == identity
    }
    pub fn page(self, index: u64) -> Option<(u64, u64)> {
        if index >= self.pages {
            return None;
        }
        Some((
            self.identity.physical + index * 0x1000,
            self.identity.virtual_base + index * 0x1000,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AperturePhase {
    Preparing,
    MapInFlight,
    RollbackRequired,
    Committed,
    Quarantined,
    Retired,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapEffect {
    Mapped,
    NoEffect,
    Unknown,
}
pub struct ApertureTransaction<C = u64> {
    plan: AperturePlan<C>,
    phase: AperturePhase,
    mapped: u64,
    owned_next: bool,
}
impl<C: Copy + Eq> ApertureTransaction<C> {
    pub fn new(plan: AperturePlan<C>) -> Self {
        Self {
            plan,
            phase: AperturePhase::Preparing,
            mapped: 0,
            owned_next: false,
        }
    }
    pub const fn phase(&self) -> AperturePhase {
        self.phase
    }
    pub const fn mapped(&self) -> u64 {
        self.mapped
    }
    pub const fn plan(&self) -> AperturePlan<C> {
        self.plan
    }
    pub fn record_map_capability(&mut self, index: u64) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::Preparing
            || self.owned_next
            || index != self.mapped
            || index >= self.plan.pages
        {
            return Err(ApertureError::WrongPhase);
        }
        self.owned_next = true;
        Ok(())
    }
    pub fn begin_map(&mut self) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::Preparing {
            return Err(ApertureError::WrongPhase);
        }
        if !self.owned_next {
            return Err(ApertureError::NoOwnedMapCapability);
        }
        self.phase = AperturePhase::MapInFlight;
        Ok(())
    }
    /// A checked failure before entering the next native Map permits cleanup, not replay.
    pub fn abort_before_map(&mut self) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::Preparing {
            return Err(ApertureError::WrongPhase);
        }
        self.phase = AperturePhase::RollbackRequired;
        Ok(())
    }
    pub fn acknowledge_map(&mut self, effect: MapEffect) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::MapInFlight {
            return Err(ApertureError::WrongPhase);
        }
        self.phase = match effect {
            MapEffect::Mapped => {
                self.mapped += 1;
                self.owned_next = false;
                AperturePhase::Preparing
            }
            MapEffect::NoEffect => AperturePhase::RollbackRequired,
            MapEffect::Unknown => AperturePhase::Quarantined,
        };
        Ok(())
    }
    pub fn commit(&mut self) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::Preparing
            || self.owned_next
            || self.mapped != self.plan.pages
        {
            return Err(ApertureError::WrongPhase);
        }
        self.phase = AperturePhase::Committed;
        Ok(())
    }
    pub fn publishable(&self) -> bool {
        self.phase == AperturePhase::Committed
    }
    pub fn rollback_complete(&mut self) -> Result<(), ApertureError> {
        if self.phase != AperturePhase::RollbackRequired {
            return Err(ApertureError::WrongPhase);
        }
        self.phase = AperturePhase::Retired;
        Ok(())
    }
}
