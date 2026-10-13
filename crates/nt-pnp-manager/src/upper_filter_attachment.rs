//! Ordered class/device UpperFilter AddDevice ownership for one canonical devnode generation.

use alloc::vec::Vec;

use crate::{DevnodeIdentity, PnpManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpperFilterAttachmentKey {
    mount_generation: u64,
    child: DevnodeIdentity,
    function_fdo: u64,
}

impl UpperFilterAttachmentKey {
    pub const fn mount_generation(self) -> u64 {
        self.mount_generation
    }
    pub const fn child(self) -> DevnodeIdentity {
        self.child
    }
    pub const fn function_fdo(self) -> u64 {
        self.function_fdo
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpperFilterAttachmentClaim {
    key: UpperFilterAttachmentKey,
    index: usize,
    token: u64,
    driver_id: u64,
    lower_device: u64,
}

impl UpperFilterAttachmentClaim {
    pub const fn key(self) -> UpperFilterAttachmentKey {
        self.key
    }
    pub const fn index(self) -> usize {
        self.index
    }
    pub const fn driver_id(self) -> u64 {
        self.driver_id
    }
    pub const fn lower_device(self) -> u64 {
        self.lower_device
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpperFilterAttachmentState {
    Reserved,
    Claimed,
    Entered,
    Attached { filter_fdo: u64 },
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpperFilterAttachmentError {
    InvalidIdentity,
    StaleDevnode,
    ConflictingPlan,
    WrongPhase,
    WrongClaim,
    WrongLower,
    InsufficientResources,
}

struct Slot {
    driver_id: u64,
    state: UpperFilterAttachmentState,
    token: u64,
}

struct Plan {
    key: UpperFilterAttachmentKey,
    slots: Vec<Slot>,
}

/// Retains entered AddDevice ownership even if its native outcome is uncertain.
pub struct UpperFilterAttachmentLedger {
    plans: Vec<Plan>,
    next_token: u64,
}

impl Default for UpperFilterAttachmentLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl UpperFilterAttachmentLedger {
    pub const fn new() -> Self {
        Self {
            plans: Vec::new(),
            next_token: 1,
        }
    }

    /// Fence a retained plan against the current canonical PDO generation and function FDO.
    pub fn validate_current(
        pnp: &PnpManager,
        key: UpperFilterAttachmentKey,
    ) -> Result<(), UpperFilterAttachmentError> {
        if key.mount_generation == 0 || key.function_fdo == 0 {
            return Err(UpperFilterAttachmentError::InvalidIdentity);
        }
        if pnp.devnode_identity_for_pdo(key.child.pdo_object_id()) != Some(key.child)
            || pnp.fdo(key.child.devnode_id()) != Some(key.function_fdo)
        {
            return Err(UpperFilterAttachmentError::StaleDevnode);
        }
        Ok(())
    }

    pub fn reserve(
        &mut self,
        pnp: &PnpManager,
        mount_generation: u64,
        pdo_object_id: u64,
        function_fdo: u64,
        ordered_driver_ids: &[u64],
    ) -> Result<UpperFilterAttachmentKey, UpperFilterAttachmentError> {
        let child = pnp
            .devnode_identity_for_pdo(pdo_object_id)
            .ok_or(UpperFilterAttachmentError::StaleDevnode)?;
        let key = UpperFilterAttachmentKey {
            mount_generation,
            child,
            function_fdo,
        };
        Self::validate_current(pnp, key)?;
        if ordered_driver_ids.iter().any(|driver| *driver == 0) {
            return Err(UpperFilterAttachmentError::InvalidIdentity);
        }
        if let Some(plan) = self
            .plans
            .iter()
            .find(|plan| plan.key.child == child && plan.key.mount_generation == mount_generation)
        {
            return if plan.key == key
                && plan
                    .slots
                    .iter()
                    .map(|slot| slot.driver_id)
                    .eq(ordered_driver_ids.iter().copied())
            {
                Ok(key)
            } else {
                Err(UpperFilterAttachmentError::ConflictingPlan)
            };
        }
        if self.plans.iter().any(|plan| plan.key.child == child) {
            return Err(UpperFilterAttachmentError::ConflictingPlan);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(ordered_driver_ids.len())
            .map_err(|_| UpperFilterAttachmentError::InsufficientResources)?;
        slots.extend(ordered_driver_ids.iter().map(|driver_id| Slot {
            driver_id: *driver_id,
            state: UpperFilterAttachmentState::Reserved,
            token: 0,
        }));
        self.plans
            .try_reserve(1)
            .map_err(|_| UpperFilterAttachmentError::InsufficientResources)?;
        self.plans.push(Plan { key, slots });
        Ok(key)
    }

    pub fn claim_next(
        &mut self,
        pnp: &PnpManager,
        key: UpperFilterAttachmentKey,
    ) -> Result<Option<UpperFilterAttachmentClaim>, UpperFilterAttachmentError> {
        Self::validate_current(pnp, key)?;
        let plan = self
            .plans
            .iter_mut()
            .find(|plan| plan.key == key)
            .ok_or(UpperFilterAttachmentError::WrongClaim)?;
        let mut lower_device = key.function_fdo;
        for (index, slot) in plan.slots.iter_mut().enumerate() {
            match slot.state {
                UpperFilterAttachmentState::Attached { filter_fdo } => lower_device = filter_fdo,
                UpperFilterAttachmentState::Reserved => {
                    let token = self.next_token;
                    self.next_token = token
                        .checked_add(1)
                        .ok_or(UpperFilterAttachmentError::InsufficientResources)?;
                    slot.token = token;
                    slot.state = UpperFilterAttachmentState::Claimed;
                    return Ok(Some(UpperFilterAttachmentClaim {
                        key,
                        index,
                        token,
                        driver_id: slot.driver_id,
                        lower_device,
                    }));
                }
                UpperFilterAttachmentState::Claimed
                | UpperFilterAttachmentState::Entered
                | UpperFilterAttachmentState::Uncertain => {
                    return Err(UpperFilterAttachmentError::WrongPhase);
                }
            }
        }
        Ok(None)
    }

    fn slot_mut(
        &mut self,
        claim: UpperFilterAttachmentClaim,
    ) -> Result<&mut Slot, UpperFilterAttachmentError> {
        let plan = self
            .plans
            .iter_mut()
            .find(|plan| plan.key == claim.key)
            .ok_or(UpperFilterAttachmentError::WrongClaim)?;
        let slot = plan
            .slots
            .get_mut(claim.index)
            .ok_or(UpperFilterAttachmentError::WrongClaim)?;
        if slot.driver_id != claim.driver_id || slot.token != claim.token || claim.token == 0 {
            return Err(UpperFilterAttachmentError::WrongClaim);
        }
        Ok(slot)
    }

    pub fn mark_entered(
        &mut self,
        pnp: &PnpManager,
        claim: UpperFilterAttachmentClaim,
    ) -> Result<(), UpperFilterAttachmentError> {
        Self::validate_current(pnp, claim.key)?;
        let slot = self.slot_mut(claim)?;
        if slot.state != UpperFilterAttachmentState::Claimed {
            return Err(UpperFilterAttachmentError::WrongPhase);
        }
        slot.state = UpperFilterAttachmentState::Entered;
        Ok(())
    }

    pub fn complete(
        &mut self,
        pnp: &PnpManager,
        claim: UpperFilterAttachmentClaim,
        filter_fdo: u64,
        observed_lower: u64,
    ) -> Result<(), UpperFilterAttachmentError> {
        Self::validate_current(pnp, claim.key)?;
        if filter_fdo == 0 || filter_fdo == claim.key.function_fdo {
            return Err(UpperFilterAttachmentError::InvalidIdentity);
        }
        if observed_lower != claim.lower_device {
            return Err(UpperFilterAttachmentError::WrongLower);
        }
        let plan = self
            .plans
            .iter()
            .find(|plan| plan.key == claim.key)
            .ok_or(UpperFilterAttachmentError::WrongClaim)?;
        let mut expected_lower = claim.key.function_fdo;
        for prior in plan.slots.iter().take(claim.index) {
            let UpperFilterAttachmentState::Attached {
                filter_fdo: prior_fdo,
            } = prior.state
            else {
                return Err(UpperFilterAttachmentError::WrongPhase);
            };
            if prior_fdo == filter_fdo {
                return Err(UpperFilterAttachmentError::InvalidIdentity);
            }
            expected_lower = prior_fdo;
        }
        if claim.lower_device != expected_lower {
            return Err(UpperFilterAttachmentError::WrongLower);
        }
        let slot = self.slot_mut(claim)?;
        if slot.state != UpperFilterAttachmentState::Entered {
            return Err(UpperFilterAttachmentError::WrongPhase);
        }
        slot.state = UpperFilterAttachmentState::Attached { filter_fdo };
        Ok(())
    }

    pub fn mark_uncertain(
        &mut self,
        _pnp: &PnpManager,
        claim: UpperFilterAttachmentClaim,
    ) -> Result<(), UpperFilterAttachmentError> {
        let slot = self.slot_mut(claim)?;
        if slot.state != UpperFilterAttachmentState::Entered {
            return Err(UpperFilterAttachmentError::WrongPhase);
        }
        slot.state = UpperFilterAttachmentState::Uncertain;
        Ok(())
    }

    /// A claim with no native effect may be retried with a fresh token.
    pub fn release_unentered(
        &mut self,
        claim: UpperFilterAttachmentClaim,
    ) -> Result<(), UpperFilterAttachmentError> {
        let slot = self.slot_mut(claim)?;
        if slot.state != UpperFilterAttachmentState::Claimed {
            return Err(UpperFilterAttachmentError::WrongPhase);
        }
        slot.state = UpperFilterAttachmentState::Reserved;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PdoCapabilities, PdoProperties, PnpBusInformation, PropertyBlobState, GUID_BUS_TYPE_PCI,
        INTERFACE_TYPE_PCI_BUS,
    };

    fn committed_function_stack(pdo: u64, fdo: u64) -> PnpManager {
        let mut pnp = PnpManager::new();
        let properties = PdoProperties::enumerated(
            PnpBusInformation {
                bus_type_guid: GUID_BUS_TYPE_PCI,
                legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
                bus_number: 0,
            },
            PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                address: 1,
            },
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
        );
        pnp.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, properties)
            .unwrap();
        pnp.commit_device_stack(pdo, fdo, 0x55).unwrap();
        pnp
    }

    #[test]
    fn ordered_filters_claim_exact_previous_top_and_enter_once() {
        let pnp = committed_function_stack(0x1000, 0x2000);
        let mut ledger = UpperFilterAttachmentLedger::new();
        let key = ledger
            .reserve(&pnp, 7, 0x1000, 0x2000, &[0x30, 0x40])
            .unwrap();
        let first = ledger.claim_next(&pnp, key).unwrap().expect("first filter");
        assert_eq!(
            (first.index, first.driver_id, first.lower_device),
            (0, 0x30, 0x2000)
        );
        ledger.mark_entered(&pnp, first).unwrap();
        assert_eq!(
            ledger.claim_next(&pnp, key),
            Err(UpperFilterAttachmentError::WrongPhase)
        );
        ledger.complete(&pnp, first, 0x3000, 0x2000).unwrap();
        let second = ledger
            .claim_next(&pnp, key)
            .unwrap()
            .expect("second filter");
        assert_eq!(
            (second.index, second.driver_id, second.lower_device),
            (1, 0x40, 0x3000)
        );
        ledger.mark_entered(&pnp, second).unwrap();
        assert_eq!(
            ledger.complete(&pnp, second, 0x4000, 0x2000),
            Err(UpperFilterAttachmentError::WrongLower)
        );
        ledger.complete(&pnp, second, 0x4000, 0x3000).unwrap();
        assert_eq!(ledger.claim_next(&pnp, key), Ok(None));
    }

    #[test]
    fn entered_or_uncertain_add_device_cannot_replay_after_reserve_retry() {
        let pnp = committed_function_stack(0x1000, 0x2000);
        let mut ledger = UpperFilterAttachmentLedger::new();
        let key = ledger.reserve(&pnp, 7, 0x1000, 0x2000, &[0x30]).unwrap();
        let claim = ledger.claim_next(&pnp, key).unwrap().unwrap();
        ledger.mark_entered(&pnp, claim).unwrap();
        assert_eq!(ledger.reserve(&pnp, 7, 0x1000, 0x2000, &[0x30]), Ok(key));
        assert_eq!(
            ledger.claim_next(&pnp, key),
            Err(UpperFilterAttachmentError::WrongPhase)
        );
        ledger.mark_uncertain(&pnp, claim).unwrap();
        assert_eq!(
            ledger.claim_next(&pnp, key),
            Err(UpperFilterAttachmentError::WrongPhase)
        );
        assert_eq!(
            ledger.complete(&pnp, claim, 0x3000, 0x2000),
            Err(UpperFilterAttachmentError::WrongPhase)
        );
    }

    #[test]
    fn changed_plan_and_stale_generation_cannot_take_over_entered_filter() {
        let mut pnp = committed_function_stack(0x1000, 0x2000);
        let mut ledger = UpperFilterAttachmentLedger::new();
        let key = ledger.reserve(&pnp, 7, 0x1000, 0x2000, &[0x30]).unwrap();
        assert_eq!(
            ledger.reserve(&pnp, 7, 0x1000, 0x2000, &[0x40]),
            Err(UpperFilterAttachmentError::ConflictingPlan)
        );
        let claim = ledger.claim_next(&pnp, key).unwrap().unwrap();
        ledger.mark_entered(&pnp, claim).unwrap();
        let id = key.child.devnode_id();
        pnp.rollback_device_stack(0x1000, 0x2000, 0x55).unwrap();
        assert_eq!(
            ledger.complete(&pnp, claim, 0x3000, 0x2000),
            Err(UpperFilterAttachmentError::StaleDevnode)
        );
        assert_eq!(pnp.fdo(id), Some(0));
    }

    #[test]
    fn unentered_claim_can_be_retried_only_with_a_fresh_token() {
        let pnp = committed_function_stack(0x1000, 0x2000);
        let mut ledger = UpperFilterAttachmentLedger::new();
        let key = ledger.reserve(&pnp, 7, 0x1000, 0x2000, &[0x30]).unwrap();
        let first = ledger.claim_next(&pnp, key).unwrap().unwrap();
        ledger.release_unentered(first).unwrap();
        let retry = ledger.claim_next(&pnp, key).unwrap().unwrap();
        assert_ne!(first.token, retry.token);
        assert_eq!(
            ledger.mark_entered(&pnp, first),
            Err(UpperFilterAttachmentError::WrongClaim)
        );
        ledger.mark_entered(&pnp, retry).unwrap();
        assert_eq!(
            ledger.release_unentered(retry),
            Err(UpperFilterAttachmentError::WrongPhase)
        );
    }
}
