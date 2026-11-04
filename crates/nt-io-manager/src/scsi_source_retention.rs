//! Exact source child retention for a cross-domain SCSI SRB dispatch.
//!
//! An IRP pin does not cover a separately allocated SRB, MDL or transfer buffer. This
//! ledger is acquired before provider entry and consulted by source pool/MDL free paths.
//! A new use of the same source waits for terminal provider status and published source
//! copyback. Each old use keeps its physical children until its own source completion and
//! provider acknowledgement. The native adapter still owns the physical pins.

use alloc::vec::Vec;

use crate::retained_query_path_forward::SourceIrpTicket;
use crate::retained_connect_forward::ConnectStackRange;
use crate::scsi_srb_transport::ScsiSrbRoute;
use crate::source_irp_auxiliary::{
    SourceMdlAllocationIdentity, SourceMemoryIdentity, SourcePoolAllocationIdentity,
};
use crate::source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner, SourceIrpUseTicket};
use crate::{HostedDomainIdentity, IrpId};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScsiSourceChildren {
    pub source: SourceIrpAllocation,
    pub ticket: SourceIrpTicket,
    pub use_ticket: SourceIrpUseTicket,
    pub route: ScsiSrbRoute,
    pub srb: ScsiSrbSource,
    pub sense: Option<SourceMemoryIdentity>,
    pub sense_length: u8,
    pub mdl: Option<SourceMdlAllocationIdentity>,
    pub data: Option<SourceMemoryIdentity>,
    pub data_stack: Option<ConnectStackRange>,
    pub transfer_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScsiSrbSource {
    Pool(SourcePoolAllocationIdentity),
    Stack { range: ConnectStackRange, component_address: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiStackAccess {
    RetainedThroughAck,
    SourceCopyback,
}

/// The native adapter proves physical thread/stack identity separately. This rule decides
/// whether that same physical stack must still be on its original retained Reply.
pub fn scsi_stack_reply_admits(access: ScsiStackAccess, original_reply_current: bool) -> bool {
    match access {
        ScsiStackAccess::RetainedThroughAck => true,
        ScsiStackAccess::SourceCopyback => original_reply_current,
    }
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
    SourcePublished,
    ProviderAcknowledged,
    SourceCompleted,
    ReadyToRelease,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Row {
    children: ScsiSourceChildren,
    provider_irp: Option<IrpId>,
    phase: ScsiSourcePhase,
    source_published: bool,
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
            if row.children.use_ticket == children.use_ticket {
                return true;
            }
            let same_registration = row.children.ticket == children.ticket;
            let same_address = row.children.source.domain == children.source.domain
                && row.children.source.component_address == children.source.component_address;
            if !same_registration && !same_address {
                return false;
            }
            row.children.source != children.source
                || !same_registration
                || row.children.use_ticket.epoch() >= children.use_ticket.epoch()
                || !row.source_published
                || !matches!(row.phase,
                    ScsiSourcePhase::SourcePublished
                        | ScsiSourcePhase::ProviderAcknowledged
                        | ScsiSourcePhase::SourceCompleted
                        | ScsiSourcePhase::ReadyToRelease)
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
            source_published: false,
        });
        Ok(())
    }

    pub fn phase(&self, use_ticket: SourceIrpUseTicket) -> Option<ScsiSourcePhase> {
        self.rows
            .iter()
            .find(|row| row.children.use_ticket == use_ticket)
            .map(|row| row.phase)
    }

    /// Provider acknowledgement may arrive before source copyback. Reuse
    /// requires this exact use's publication receipt, not its phase alone.
    pub fn source_published(&self, use_ticket: SourceIrpUseTicket) -> bool {
        self.rows.iter().any(|row| {
            row.children.use_ticket == use_ticket && row.source_published
        })
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
            .position(|row| row.children.use_ticket == children.use_ticket)
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

    /// Provider terminal alone does not permit the caller to reuse its IRP:
    /// the old SRB, sense, data and IRP status must be copied back first.
    /// The native adapter publishes this receipt after all source writes and
    /// before the terminal Reply can resume a ClassPnP retry.
    pub fn publish_source(
        &mut self,
        children: ScsiSourceChildren,
        provider_irp: IrpId,
    ) -> Result<(), ScsiSourceRetentionError> {
        let row = self.exact_mut(children)?;
        if row.provider_irp != Some(provider_irp) {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        if row.source_published { return Ok(()); }
        match row.phase {
            ScsiSourcePhase::Terminal => row.phase = ScsiSourcePhase::SourcePublished,
            ScsiSourcePhase::ProviderAcknowledged => {},
            _ => return Err(ScsiSourceRetentionError::WrongPhase),
        }
        row.source_published = true;
        Ok(())
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
            ScsiSourcePhase::Terminal | ScsiSourcePhase::SourcePublished =>
                ScsiSourcePhase::ProviderAcknowledged,
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
        if !row.source_published {
            return Err(ScsiSourceRetentionError::WrongPhase);
        }
        row.phase = match row.phase {
            ScsiSourcePhase::SourcePublished => ScsiSourcePhase::SourceCompleted,
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
            .position(|row| row.children.use_ticket == children.use_ticket)
            .ok_or(ScsiSourceRetentionError::WrongIdentity)?;
        if self.rows[index].children != children {
            return Err(ScsiSourceRetentionError::WrongIdentity);
        }
        if self.rows[index].phase != ScsiSourcePhase::ReadyToRelease
            || !self.rows[index].source_published {
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
            && (matches!(row.children.srb, ScsiSrbSource::Pool(srb) if srb.component_address == address)
                || matches!(row.children.sense, Some(SourceMemoryIdentity::Pool { allocation, .. })
                    if allocation.component_address == address)
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

    /// A partial packet MDL may refer to a distinct source MDL. Protect that
    /// source while provider effects are pending or uncertain. A terminal
    /// callback may unlock its source after the result is retained.
    pub fn protects_partial_source_in_flight(
        &self,
        owner: SourceIrpOwner,
        domain: HostedDomainIdentity,
        mut target_matches: impl FnMut(u64) -> bool,
    ) -> bool {
        self.rows.iter().any(|row| {
            row.children.source.owner == owner
                && row.children.source.domain == domain
                && matches!(row.phase,
                    ScsiSourcePhase::Prepared | ScsiSourcePhase::Entered
                        | ScsiSourcePhase::Pending | ScsiSourcePhase::Uncertain)
                && row.children.mdl.is_some_and(|mdl| {
                    target_matches(mdl.pool.component_address)
                })
        })
    }

    fn exact_mut(
        &mut self,
        children: ScsiSourceChildren,
    ) -> Result<&mut Row, ScsiSourceRetentionError> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.children.use_ticket == children.use_ticket)
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
    let source_valid = source.valid()
        && source.domain == children.ticket.domain
        && children.use_ticket.registration() == children.ticket;
    let route_valid = !route.pdo.is_null()
        && !route.provider.domain_id.is_null()
        && route.provider.cookie != 0
        && route.relation_generation != 0
        && route.provider_pdo != 0;
    let srb_valid = match srb {
        ScsiSrbSource::Pool(srb) => srb.component_address != 0 && srb.capacity >= 0x58 && srb.pool_generation != 0,
        ScsiSrbSource::Stack { range, component_address } => {
            range.domain == source.domain
                && range.thread != 0
                && range.generation != 0
                && range.base != 0
                && range.bytes >= 0x58
                && component_address & 7 == 0
                && range.base.checked_add(range.bytes).is_some_and(|end| {
                    component_address >= range.base
                        && component_address.checked_add(0x58).is_some_and(|last| last <= end)
                })
        }
    };
    let sense_valid = match (children.sense_length, children.sense) {
        (0, None) => true,
        (length, Some(SourceMemoryIdentity::Pool {
            allocation, component_address, bytes,
        })) => {
            length != 0
                && bytes == u64::from(length)
                && allocation.component_address != 0
                && allocation.capacity != 0
                && allocation.pool_generation != 0
                && component_address >= allocation.component_address
                && component_address.checked_add(bytes).is_some_and(|end| {
                    allocation.component_address.checked_add(allocation.capacity)
                        .is_some_and(|allocation_end| end <= allocation_end)
                })
        }
        _ => false,
    };
    let data_valid = match (children.transfer_length, children.data, children.mdl) {
        (0, None, None) => children.data_stack.is_none(),
        (
            length,
            Some(SourceMemoryIdentity::Pool {
                allocation,
                component_address,
                bytes,
            }),
            Some(mdl),
        ) => {
            children.data_stack.is_none()
                && length != 0
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
        (
            length,
            Some(SourceMemoryIdentity::MappedRange {
                component_address,
                bytes,
                exec_address,
            }),
            Some(mdl),
        ) => children.data_stack.is_some_and(|range| {
            length != 0
                && bytes == u64::from(length)
                && exec_address != 0
                && mdl.pool.component_address != 0
                && mdl.pool.capacity >= 0x30
                && mdl.pool.pool_generation != 0
                && mdl.registry_generation != 0
                && range.domain == source.domain
                && range.thread != 0
                && range.generation != 0
                && range.base != 0
                && range.base.checked_add(range.bytes).is_some_and(|end| {
                    component_address >= range.base
                        && component_address.checked_add(bytes).is_some_and(|last| last <= end)
                })
        }),
        _ => false,
    };
    let stack_children_disjoint = match (srb, children.data, children.data_stack) {
        (
            ScsiSrbSource::Stack { range: srb_range, component_address: srb_address },
            Some(SourceMemoryIdentity::MappedRange { component_address: data_address, bytes, .. }),
            Some(data_range),
        ) if srb_range.domain == data_range.domain
            && srb_range.thread == data_range.thread
            && srb_range.generation == data_range.generation => {
                srb_address.checked_add(0x58).is_some_and(|srb_end| {
                    data_address.checked_add(bytes).is_some_and(|data_end| {
                        srb_end <= data_address || data_end <= srb_address
                    })
                })
            }
        _ => true,
    };
    source_valid && route_valid && srb_valid && sense_valid && data_valid && stack_children_disjoint
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::num::NonZeroU64;
    use crate::source_irp_ledger::{SourceIrpOwner, SourceIrpUseTicket};
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
            use_ticket: SourceIrpUseTicket::new(
                SourceIrpTicket::new(domain, 1, 1).unwrap(),
                NonZeroU64::new(1).unwrap(),
            ).unwrap(),
            route: ScsiSrbRoute {
                pdo: DeviceId::new(2, 4),
                provider: domain,
                relation_generation: 7,
                provider_pdo: 0x9000,
            },
            srb: ScsiSrbSource::Pool(SourcePoolAllocationIdentity {
                component_address: 0x2000,
                capacity: 0x58,
                pool_generation: 5,
            }),
            sense: Some(SourceMemoryIdentity::Pool {
                allocation: SourcePoolAllocationIdentity {
                    component_address: 0x5000,
                    capacity: 0x20,
                    pool_generation: 12,
                },
                component_address: 0x5000,
                bytes: 0x20,
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
            data_stack: None,
            transfer_length: 0x200,
        }
    }

    #[test]
    fn stack_local_claim_srb_is_retained_until_source_completion_and_provider_ack() {
        let mut children = fixture();
        children.srb = ScsiSrbSource::Stack {
            range: ConnectStackRange {
                domain: children.source.domain,
                thread: 7,
                base: 0x8000,
                bytes: 0x1000,
                generation: 11,
            },
            component_address: 0x8100,
        };
        children.sense = None;
        children.sense_length = 0;
        children.mdl = None;
        children.data = None;
        children.transfer_length = 0;
        let mut ledger = ScsiSourceRetentionLedger::new();
        ledger.retain(children).expect("live stack-local SRB must be admissible");
        assert!(!ledger.protects_pool(
            children.source.owner,
            children.source.domain,
            0x8100,
        ));
        let irp = IrpId::new(3, 8);
        ledger.enter(children, irp).unwrap();
        ledger.pending(children, irp).unwrap();
        ledger.terminal(children, irp).unwrap();
        ledger.publish_source(children, irp).unwrap();
        ledger.source_completed(children, irp).unwrap();
        assert_eq!(ledger.phase(children.use_ticket), Some(ScsiSourcePhase::SourceCompleted));
        ledger.acknowledge(children, irp).unwrap();
        ledger.release(children).unwrap();
    }

    #[test]
    fn stale_or_unbounded_stack_local_srb_is_refused() {
        let mut children = fixture();
        children.sense = None;
        children.sense_length = 0;
        children.mdl = None;
        children.data = None;
        children.transfer_length = 0;
        let live = ConnectStackRange {
            domain: children.source.domain,
            thread: 7,
            base: 0x8000,
            bytes: 0x1000,
            generation: 11,
        };
        for (range, address) in [
            (ConnectStackRange { thread: 0, ..live }, 0x8100),
            (ConnectStackRange { generation: 0, ..live }, 0x8100),
            (live, 0x8fc0),
            (live, 0x8101),
        ] {
            children.srb = ScsiSrbSource::Stack {
                range,
                component_address: address,
            };
            assert_eq!(
                ScsiSourceRetentionLedger::new().retain(children),
                Err(ScsiSourceRetentionError::Invalid),
            );
        }
    }

    #[test]
    fn stack_owner_survives_successor_ack_reply_but_copyback_requires_original_reply() {
        assert!(scsi_stack_reply_admits(
            ScsiStackAccess::RetainedThroughAck, false,
        ));
        assert!(!scsi_stack_reply_admits(
            ScsiStackAccess::SourceCopyback, false,
        ));
        assert!(scsi_stack_reply_admits(
            ScsiStackAccess::SourceCopyback, true,
        ));
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
        assert!(!ledger.source_published(children.use_ticket));
        let mut next = children;
        next.use_ticket = SourceIrpUseTicket::new(next.ticket, NonZeroU64::new(2).unwrap()).unwrap();
        assert_eq!(ledger.retain(next), Err(ScsiSourceRetentionError::AlreadyOwned),
            "provider ACK without source publication cannot authorize reuse");
        ledger.publish_source(children, irp).unwrap();
        assert!(ledger.source_published(children.use_ticket));
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
    fn terminal_use_can_overlap_next_use_without_old_ack_releasing_it() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let old = fixture();
        let mut next = old;
        next.use_ticket = SourceIrpUseTicket::new(next.ticket, NonZeroU64::new(2).unwrap()).unwrap();
        let old_provider = IrpId::new(3, 31);
        let next_provider = IrpId::new(3, 32);

        ledger.retain(old).unwrap();
        ledger.enter(old, old_provider).unwrap();
        ledger.pending(old, old_provider).unwrap();
        assert_eq!(ledger.retain(next), Err(ScsiSourceRetentionError::AlreadyOwned));
        ledger.uncertain(old, old_provider).unwrap();
        assert_eq!(ledger.retain(next), Err(ScsiSourceRetentionError::AlreadyOwned));

        ledger.terminal(old, old_provider).unwrap();
        assert_eq!(ledger.retain(next), Err(ScsiSourceRetentionError::AlreadyOwned),
            "provider terminal alone does not prove source copyback is published");
        ledger.publish_source(old, old_provider).unwrap();
        ledger.publish_source(old, old_provider).unwrap();
        ledger.retain(next).expect("published source copyback permits a distinct use");
        ledger.enter(next, next_provider).unwrap();
        ledger.pending(next, next_provider).unwrap();
        assert_eq!(ledger.phase(old.use_ticket), Some(ScsiSourcePhase::SourcePublished));
        assert_eq!(ledger.phase(next.use_ticket), Some(ScsiSourcePhase::Pending));

        ledger.acknowledge(old, old_provider).unwrap();
        ledger.source_completed(old, old_provider).unwrap();
        ledger.release(old).unwrap();
        assert!(!ledger.contains_exact(old));
        assert!(ledger.contains_exact(next));
        assert_eq!(ledger.phase(next.use_ticket), Some(ScsiSourcePhase::Pending));
        for address in [0x2000, 0x3000, 0x4000, 0x5000] {
            assert!(ledger.protects_pool(next.source.owner, next.source.domain, address),
                "new use still owns each physical child after old ACK");
        }
        assert!(ledger.protects_mdl(next.source.owner, next.source.domain, 0x3000));
        ledger.terminal(next, next_provider).unwrap();
        ledger.publish_source(next, next_provider).unwrap();
        ledger.source_completed(next, next_provider).unwrap();
        ledger.acknowledge(next, next_provider).unwrap();
        ledger.release(next).unwrap();
        assert!(!ledger.protects_pool(next.source.owner, next.source.domain, 0x2000));
    }

    #[test]
    fn use_ticket_must_name_the_same_exact_registration_and_advance_epoch() {
        let old = fixture();
        let mut duplicate = old;
        duplicate.use_ticket = SourceIrpUseTicket::new(duplicate.ticket, NonZeroU64::new(1).unwrap()).unwrap();
        let mut ledger = ScsiSourceRetentionLedger::new();
        ledger.retain(old).unwrap();
        let old_provider = IrpId::new(3, 33);
        ledger.enter(old, old_provider).unwrap();
        assert_eq!(ledger.publish_source(old, old_provider),
            Err(ScsiSourceRetentionError::WrongPhase));
        ledger.terminal(old, old_provider).unwrap();
        ledger.publish_source(old, old_provider).unwrap();
        assert_eq!(ledger.retain(duplicate), Err(ScsiSourceRetentionError::AlreadyOwned));

        let mut stale = old;
        stale.use_ticket = SourceIrpUseTicket::new(
            SourceIrpTicket::new(old.source.domain, 2, 2).unwrap(),
            NonZeroU64::new(2).unwrap(),
        ).unwrap();
        assert_eq!(ledger.retain(stale), Err(ScsiSourceRetentionError::Invalid));

        let mut foreign = old;
        foreign.use_ticket = SourceIrpUseTicket::new(
            SourceIrpTicket::new(
                HostedDomainIdentity { cookie: old.source.domain.cookie + 1, ..old.source.domain }, 1, 1,
            ).unwrap(),
            NonZeroU64::new(2).unwrap(),
        ).unwrap();
        assert_eq!(ledger.retain(foreign), Err(ScsiSourceRetentionError::Invalid));
    }

    #[test]
    fn partial_source_is_protected_only_while_provider_effect_is_in_flight() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let owner = children.source.owner;
        let domain = children.source.domain;
        let irp = IrpId::new(3, 17);
        ledger.retain(children).unwrap();
        let protects = |ledger: &ScsiSourceRetentionLedger| {
            ledger.protects_partial_source_in_flight(owner, domain, |address| address == 0x3000)
        };
        assert!(protects(&ledger));
        assert!(!ledger.protects_partial_source_in_flight(owner, domain, |address| address == 0x3010));
        ledger.enter(children, irp).unwrap();
        ledger.pending(children, irp).unwrap();
        assert!(protects(&ledger));
        ledger.uncertain(children, irp).unwrap();
        assert!(protects(&ledger));
        ledger.terminal(children, irp).unwrap();
        assert!(!protects(&ledger));
        assert!(ledger.protects_mdl(owner, domain, 0x3000));
    }

    #[test]
    fn source_completion_before_provider_ack_keeps_children_retained() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        let irp = IrpId::new(3, 7);
        ledger.retain(children).unwrap();
        ledger.enter(children, irp).unwrap();
        ledger.terminal(children, irp).unwrap();
        ledger.publish_source(children, irp).unwrap();
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
        if let ScsiSrbSource::Pool(srb) = &mut stale.srb {
            srb.pool_generation += 1;
        }
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
    fn stack_data_requires_exact_generation_bound_range_and_transfer_extent() {
        let mut children = fixture();
        let range = ConnectStackRange {
            domain: children.source.domain,
            thread: 7,
            base: 0x9000,
            bytes: 0x1000,
            generation: 11,
        };
        children.data = Some(SourceMemoryIdentity::MappedRange {
            component_address: 0x9100,
            bytes: 0x200,
            exec_address: 0x19100,
        });
        // An address translation alone is not authority to retain a caller stack.
        assert_eq!(
            ScsiSourceRetentionLedger::new().retain(children),
            Err(ScsiSourceRetentionError::Invalid)
        );

        children.data_stack = Some(range);
        ScsiSourceRetentionLedger::new().retain(children)
            .expect("the exact pinned stack range admits the transfer");

        let mut wrong_generation = children;
        wrong_generation.data_stack.as_mut().unwrap().generation = 0;
        assert_eq!(
            ScsiSourceRetentionLedger::new().retain(wrong_generation),
            Err(ScsiSourceRetentionError::Invalid)
        );
        let mut escaped = children;
        escaped.data = Some(SourceMemoryIdentity::MappedRange {
            component_address: 0x9f00,
            bytes: 0x200,
            exec_address: 0x19f00,
        });
        assert_eq!(
            ScsiSourceRetentionLedger::new().retain(escaped),
            Err(ScsiSourceRetentionError::Invalid)
        );
        let mut wrong_extent = children;
        wrong_extent.transfer_length = 0x201;
        assert_eq!(
            ScsiSourceRetentionLedger::new().retain(wrong_extent),
            Err(ScsiSourceRetentionError::Invalid)
        );

        let mut overlapping_srb = children;
        overlapping_srb.srb = ScsiSrbSource::Stack {
            range,
            component_address: 0x92f8,
        };
        assert_eq!(
            ScsiSourceRetentionLedger::new().retain(overlapping_srb),
            Err(ScsiSourceRetentionError::Invalid)
        );
        let mut touching_srb = children;
        touching_srb.srb = ScsiSrbSource::Stack {
            range,
            component_address: 0x9300,
        };
        ScsiSourceRetentionLedger::new().retain(touching_srb)
            .expect("adjacent stack snapshots do not interfere with copyback");
    }

    #[test]
    fn sense_buffer_is_an_independent_retained_child() {
        let mut ledger = ScsiSourceRetentionLedger::new();
        let children = fixture();
        ledger.retain(children).unwrap();
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x5000));
        let mut stale = children;
        if let Some(SourceMemoryIdentity::Pool { allocation, .. }) = &mut stale.sense {
            allocation.pool_generation += 1;
        }
        assert!(!ledger.contains_exact(stale));
        ledger.abandon_prepared(children).unwrap();

        let mut missing = children;
        missing.sense = None;
        assert_eq!(ledger.retain(missing), Err(ScsiSourceRetentionError::Invalid));
        let mut short = children;
        if let Some(SourceMemoryIdentity::Pool { allocation, .. }) = &mut short.sense {
            allocation.capacity = 0x1f;
        }
        assert_eq!(ledger.retain(short), Err(ScsiSourceRetentionError::Invalid));
        let mut zero = children;
        zero.sense_length = 0;
        assert_eq!(ledger.retain(zero), Err(ScsiSourceRetentionError::Invalid));
    }

    #[test]
    fn embedded_sense_range_retains_exact_pool_generation_and_offset() {
        let mut children = fixture();
        let allocation = SourcePoolAllocationIdentity {
            component_address: 0x5000,
            capacity: 0x100,
            pool_generation: 12,
        };
        children.sense = Some(SourceMemoryIdentity::Pool {
            allocation,
            component_address: 0x5060,
            bytes: 0x20,
        });
        let mut ledger = ScsiSourceRetentionLedger::new();
        ledger.retain(children)
            .expect("ClassPnP embeds its sense buffer inside a live transfer-packet allocation");
        assert!(ledger.protects_pool(children.source.owner, children.source.domain, 0x5000));

        let mut escaped = children;
        escaped.sense = Some(SourceMemoryIdentity::Pool {
            allocation,
            component_address: 0x50f0,
            bytes: 0x20,
        });
        assert_eq!(ScsiSourceRetentionLedger::new().retain(escaped),
            Err(ScsiSourceRetentionError::Invalid));

        let mut stale = children;
        stale.sense = Some(SourceMemoryIdentity::Pool {
            allocation: SourcePoolAllocationIdentity { pool_generation: 0, ..allocation },
            component_address: 0x5060,
            bytes: 0x20,
        });
        assert_eq!(ScsiSourceRetentionLedger::new().retain(stale),
            Err(ScsiSourceRetentionError::Invalid));

        let mut wrong_length = children;
        wrong_length.sense = Some(SourceMemoryIdentity::Pool {
            allocation,
            component_address: 0x5060,
            bytes: 0x10,
        });
        assert_eq!(ScsiSourceRetentionLedger::new().retain(wrong_length),
            Err(ScsiSourceRetentionError::Invalid));
    }
}
