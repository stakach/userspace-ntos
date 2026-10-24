//! Exact source child retention for a cross-domain SCSI SRB dispatch.
//!
//! An IRP pin does not cover a separately allocated SRB, MDL or transfer buffer. This
//! ledger is acquired before provider entry and consulted by source pool/MDL free paths.
//! It refuses reuse after Pending or uncertain entry until the exact provider completion and
//! acknowledgement have both been observed. The native adapter still owns the physical pins.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::scsi_srb_transport::ScsiSrbRoute;
use crate::source_irp_auxiliary::{
    SourceMdlAllocationIdentity, SourceMemoryIdentity, SourcePoolAllocationIdentity,
};
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner};
use crate::{HostedDomainIdentity, IrpId};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScsiSourceChildren {
    pub source: SourceIrpAllocation,
    pub ticket: SourceIrpTicket,
    pub route: ScsiSrbRoute,
    pub srb: SourcePoolAllocationIdentity,
    pub sense: Option<SourcePoolAllocationIdentity>,
    pub sense_length: u8,
    pub mdl: Option<SourceMdlAllocationIdentity>,
    pub data: Option<SourceMemoryIdentity>,
    pub transfer_length: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiSourceRetentionError {
    Invalid,
    AlreadyOwned,
    WrongIdentity,
    WrongPhase,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiSourcePhase {
    Prepared,
    Entered,
    Pending,
    Uncertain,
    Terminal,
    ProviderAcknowledged,
    SourceCompleted,
    ReadyToRelease,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Row {
    children: ScsiSourceChildren,
    provider_irp: Option<IrpId>,
    phase: ScsiSourcePhase,
}

#[derive(Default)]
pub struct ScsiSourceRetentionLedger {
    rows: Vec<Row>,
}

impl ScsiSourceRetentionLedger {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn retain(&mut self, children: ScsiSourceChildren) -> Result<(), ScsiSourceRetentionError> {
        if !valid(children) {
            return Err(ScsiSourceRetentionError::Invalid);
        }
        if self.rows.iter().any(|row| {
            row.children.ticket == children.ticket || row.children.source == children.source
        }) {
            return Err(ScsiSourceRetentionError::AlreadyOwned);
        }
        self.rows
            .try_reserve(1)
            .map_err(|_| ScsiSourceRetentionError::NoCapacity)?;
        self.rows.push(Row {
            children,
            provider_irp: None,
            phase: ScsiSourcePhase::Prepared,
        });
        Ok(())
    }

    pub fn phase(&self, ticket: SourceIrpTicket) -> Option<ScsiSourcePhase> {
        self.rows
            .iter()
            .find(|row| row.children.ticket == ticket)
            .map(|row| row.phase)
    }

    pub fn contains_exact(&self, children: ScsiSourceChildren) -> bool {
        self.rows.iter().any(|row| row.children == children)
    }

    /// Only an owner that never entered a provider may discard its physical child pins.
    pub fn abandon_prepared(
        &mut self,
        children: ScsiSourceChildren,
    ) -> Result<(), ScsiSourceRetentionError> {
        let index = self
            .rows
            .iter()
            .position(|row| row.children.ticket == children.ticket)
            .ok_or(ScsiSourceRetentionError::WrongIdentity)?;
        if self.rows[index].children != children {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        if self.rows[index].phase != ScsiSourcePhase::Prepared {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn enter(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        if provider_irp.is_null() {
            return Err(ScsiSourceRetentionError::Invalid);
        }
        let row = self.exact_mut(children)?;
        if row.phase != ScsiSourcePhase::Prepared {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        row.provider_irp = Some(provider_irp);
        row.phase = ScsiSourcePhase::Entered;
        Ok(())
    }

    /// A proved not-entered dispatch may retry with the same source owner. After uncertainty,
    /// no retry is legal even if the provider never sent an ordinary Pending response.
    pub fn not_entered(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        let row = self.exact_mut(children)?;
        if row.phase != ScsiSourcePhase::Entered || row.provider_irp != Some(provider_irp) {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        row.provider_irp = None;
        row.phase = ScsiSourcePhase::Prepared;
        Ok(())
    }

    pub fn pending(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        self.transition(
            children,
            provider_irp,
            &[ScsiSourcePhase::Entered],
            ScsiSourcePhase::Pending,
        )
    }

    pub fn uncertain(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        self.transition(
            children,
            provider_irp,
            &[ScsiSourcePhase::Entered, ScsiSourcePhase::Pending],
            ScsiSourcePhase::Uncertain,
        )
    }

    pub fn terminal(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        self.transition(
            children,
            provider_irp,
            &[
                ScsiSourcePhase::Entered,
                ScsiSourcePhase::Pending,
                ScsiSourcePhase::Uncertain,
            ],
            ScsiSourcePhase::Terminal,
        )
    }

    /// Provider completion alone is insufficient: caller-local completion may still access
    /// the SRB and MDL. ACK and source-local completion can arrive in either order.
    pub fn acknowledge(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        let row = self.exact_mut(children)?;
        if row.provider_irp != Some(provider_irp) {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        row.phase = match row.phase {
            ScsiSourcePhase::Terminal => ScsiSourcePhase::ProviderAcknowledged,
            ScsiSourcePhase::SourceCompleted => ScsiSourcePhase::ReadyToRelease,
            _ => return Err(ScsiSourceRetentionError::WrongPhase),
        };
        Ok(())
    }

    /// Caller-local completion has unwound and the native adapter still holds this exact
    /// source ticket. A provider ACK does not prove this event.
    pub fn source_completed(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        let row = self.exact_mut(children)?;
        if row.provider_irp != Some(provider_irp) {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        row.phase = match row.phase {
            ScsiSourcePhase::Terminal => ScsiSourcePhase::SourceCompleted,
            ScsiSourcePhase::ProviderAcknowledged => ScsiSourcePhase::ReadyToRelease,
            _ => return Err(ScsiSourceRetentionError::WrongPhase),
        };
        Ok(())
    }

    /// Release only after the source-local completion path has retired its exact IRP pin.
    pub fn release(
        &mut self,
        children: ScsiSourceChildren,
    ) -> Result<(), ScsiSourceRetentionError> {
        let index = self
            .rows
            .iter()
            .position(|row| row.children.ticket == children.ticket)
            .ok_or(ScsiSourceRetentionError::WrongIdentity)?;
        if self.rows[index].children != children {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        if self.rows[index].phase != ScsiSourcePhase::ReadyToRelease {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        self.rows.swap_remove(index);
        Ok(())
    }

    pub fn protects_pool(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> bool {
        self.rows.iter().any(|row| row.children.source.owner == owner
            && row.children.source.domain == domain
            && (row.children.srb.component_address == address
                || row.children.sense.is_some_and(|sense| sense.component_address == address)
                || row.children.mdl.is_some_and(|mdl| mdl.pool.component_address == address)
                || matches!(row.children.data, Some(SourceMemoryIdentity::Pool { allocation, .. })
                    if allocation.component_address == address)))
    }

    pub fn protects_mdl(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        address: u64,
    ) -> bool {
        self.rows.iter().any(|row| {
            row.children.source.owner == owner
                && row.children.source.domain == domain
                && row
                    .children
                    .mdl
                    .is_some_and(|mdl| mdl.pool.component_address == address)
        })
    }

    fn exact_mut(
        &mut self,
        children: ScsiSourceChildren,
    ) -> Result<&mut Row, ScsiSourceRetentionError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.children.ticket == children.ticket)
            .ok_or(ScsiSourceRetentionError::WrongIdentity)?;
        if row.children != children {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        Ok(row)
    }

    fn transition(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
        from: &[ScsiSourcePhase],
        to: ScsiSourcePhase,
    ) -> Result<(), ScsiSourceRetentionError> {
        let row = self.exact_mut(children)?;
        if row.provider_irp != Some(provider_irp) {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        if !from.contains(&row.phase) {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        row.phase = to;
        Ok(())
    }
}

fn valid(children: ScsiSourceChildren) -> bool {
    let source = children.source;
    let srb = children.srb;
    let route = children.route;
    let source_valid = source.valid() && source.domain == children.ticket.domain;
    let route_valid = !route.pdo.is_null()
        && !route.provider.domain_id.is_null()
        && route.provider.cookie != 0
        && route.relation_generation != 0
        && route.provider_pdo != 0;
    let srb_valid = srb.component_address != 0 && srb.capacity >= 0x58 && srb.pool_generation != 0;
    let sense_valid = match (children.sense_length, children.sense) {
        (0, None) => true,
        (length, Some(sense)) => length != 0 && sense.component_address != 0
            && sense.capacity >= u64::from(length) && sense.pool_generation != 0,
        _ => false,
    };
    let data_valid = match (children.transfer_length, children.data, children.mdl) {
        (0, None, None) => true,
        (
            length,
            Some(SourceMemoryIdentity::Pool {
                allocation,
                component_address,
                bytes,
            }),
            Some(mdl),
        ) => {
            length != 0
                && bytes == u64::from(length)
                && allocation.component_address != 0
                && allocation.capacity != 0
                && allocation.pool_generation != 0
                && component_address >= allocation.component_address
                && component_address.checked_add(bytes).is_some_and(|end| {
                    allocation
                        .component_address
                        .checked_add(allocation.capacity)
                        .is_some_and(|allocation_end| end <= allocation_end)
                })
                && mdl.pool.component_address != 0
                && mdl.pool.capacity >= 0x30
                && mdl.pool.pool_generation != 0
                && mdl.registry_generation != 0
        }
        // A native mapped range is not currently guarded by the source pool/MDL free paths.
        // Its address mapping could disappear while the provider is Pending. Admit it only
        // after an exact mapping lease and unmap fence are integrated.
        (_, Some(SourceMemoryIdentity::MappedRange { .. }), _) => false,
        _ => false,
    };
    source_valid && route_valid && srb_valid && sense_valid && data_valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_irp_ledger::SourceIrpOwner;
    use crate::{DeviceId, HostedDomainId};

    fn fixture() -> ScsiSourceChildren {
        let domain = HostedDomainIdentity {
            domain_id: HostedDomainId::new(2, 1),
            cookie: 9,
        };
        ScsiSourceChildren {
            source: SourceIrpAllocation {
                owner: SourceIrpOwner::HostedDriver(3),
                domain,
                component_address: 0x1000,
                bytes: 0x1b0,
                stack_count: 2,
                pool_generation: 4,
            },
            ticket: SourceIrpTicket::new(domain, 1, 1).unwrap(),
            route: ScsiSrbRoute {
                pdo: DeviceId::new(2, 4),
                provider: domain,
                relation_generation: 7,
                provider_pdo: 0x9000,
            },
            srb: SourcePoolAllocationIdentity {
                component_address: 0x2000,
                capacity: 0x58,
                pool_generation: 5,
            },
            sense: Some(SourcePoolAllocationIdentity {
                component_address: 0x5000,
                capacity: 0x20,
                pool_generation: 12,
            }),
            sense_length: 0x20,
            mdl: Some(SourceMdlAllocationIdentity {
                pool: SourcePoolAllocationIdentity {
                    component_address: 0x3000,
                    capacity: 0x30,
                    pool_generation: 6,
                },
                registry_generation: 8,
            }),
            data: Some(SourceMemoryIdentity::Pool {
                allocation: SourcePoolAllocationIdentity {
                    component_address: 0x4000,
                    capacity: 0x1000,
                    pool_generation: 11,
                },
                component_address: 0x4100,
                bytes: 0x200,
            }),
            transfer_length: 0x200,
        }
    }

    #[test]
    fn pending_and_uncertain_pin_all_children_until_ack_and_source_release() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let irp = IrpId::new(3, 7);
        ledger.retain(children).unwrap();
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x2000));
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x3000));
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x4000));
        assert!(ledger.protects_mdl(children.source.owner, children.source.domain, 0x3000));
        ledger.enter(children, irp).unwrap();
        ledger.pending(children, irp).unwrap();
        ledger.uncertain(children, irp).unwrap();
        assert_eq!(
            ledger.enter(children, irp),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        assert_eq!(
            ledger.release(children),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        ledger.terminal(children, irp).unwrap();
        assert_eq!(
            ledger.release(children),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        ledger.acknowledge(children, irp).unwrap();
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x2000));
        assert_eq!(
            ledger.release(children),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        ledger.source_completed(children, irp).unwrap();
        ledger.release(children).unwrap();
        assert!(!ledger.protects_pool(children.source.owner, children.source.domain, 0x2000));
    }

    #[test]
    fn source_completion_before_provider_ack_keeps_children_retained() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let irp = IrpId::new(3, 7);
        ledger.retain(children).unwrap();
        ledger.enter(children, irp).unwrap();
        ledger.terminal(children, irp).unwrap();
        ledger.source_completed(children, irp).unwrap();
        assert_eq!(
            ledger.release(children),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        assert!(ledger.protects_mdl(children.source.owner, children.source.domain, 0x3000));
        ledger.acknowledge(children, irp).unwrap();
        ledger.release(children).unwrap();
    }

    #[test]
    fn only_unentered_preparation_can_be_abandoned() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let irp = IrpId::new(3, 7);
        ledger.retain(children).unwrap();
        assert!(ledger.contains_exact(children));
        ledger.abandon_prepared(children).unwrap();
        assert!(!ledger.contains_exact(children));
        ledger.retain(children).unwrap();
        ledger.enter(children, irp).unwrap();
        ledger.uncertain(children, irp).unwrap();
        assert_eq!(
            ledger.abandon_prepared(children),
            Err(ScsiSourceRetentionError::WrongPhase)
        );
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x2000));
    }

    #[test]
    fn stale_physical_generation_or_relation_cannot_release_or_complete() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let irp = IrpId::new(3, 7);
        ledger.retain(children).unwrap();
        ledger.enter(children, irp).unwrap();
        let mut stale = children;
        stale.srb.pool_generation += 1;
        assert_eq!(
            ledger.terminal(stale, irp),
            Err(ScsiSourceRetentionError::WrongIdentity)
        );
        stale = children;
        stale.route.relation_generation += 1;
        assert_eq!(
            ledger.terminal(stale, irp),
            Err(ScsiSourceRetentionError::WrongIdentity)
        );
        assert_eq!(
            ledger.terminal(children, IrpId::new(3, 8)),
            Err(ScsiSourceRetentionError::WrongIdentity)
        );
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x2000));
    }

    #[test]
    fn data_path_requires_exact_mdl_and_bounded_memory_identity() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let mut children = fixture();
        children.mdl = None;
        assert_eq!(
            ledger.retain(children),
            Err(ScsiSourceRetentionError::Invalid)
        );
        children = fixture();
        children.data = Some(SourceMemoryIdentity::Pool {
            allocation: SourcePoolAllocationIdentity {
                component_address: 0x4000,
                capacity: 0x1000,
                pool_generation: 11,
            },
            component_address: 0x4f00,
            bytes: 0x200,
        });
        assert_eq!(
            ledger.retain(children),
            Err(ScsiSourceRetentionError::Invalid)
        );
        children = fixture();
        children.data = Some(SourceMemoryIdentity::MappedRange {
            component_address: 0x9000,
            bytes: 0x200,
            exec_address: 0x19000,
        });
        assert_eq!(
            ledger.retain(children),
            Err(ScsiSourceRetentionError::Invalid)
        );
    }

    #[test]
    fn sense_buffer_is_an_independent_retained_child() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        ledger.retain(children).unwrap();
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x5000));
        let mut stale = children;
        stale.sense.as_mut().unwrap().pool_generation += 1;
        assert!(!ledger.contains_exact(stale));
        ledger.abandon_prepared(children).unwrap();

        let mut missing = children;
        missing.sense = None;
        assert_eq!(ledger.retain(missing), Err(ScsiSourceRetentionError::Invalid));
        let mut short = children;
        short.sense.as_mut().unwrap().capacity = 0x1f;
        assert_eq!(ledger.retain(short), Err(ScsiSourceRetentionError::Invalid));
        let mut zero = children;
        zero.sense_length = 0;
        assert_eq!(ledger.retain(zero), Err(ScsiSourceRetentionError::Invalid));
    }
}
