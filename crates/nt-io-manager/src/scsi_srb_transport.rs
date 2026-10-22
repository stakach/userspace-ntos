//! Retained ownership for an `IRP_MJ_SCSI` request sent to an authenticated storage PDO.
//!
//! Major 0x0f also means internal device control. The caller must establish this route from
//! its accepted PDO relation and provider registration before selecting the SCSI stack decoder.
//! This contract keeps the legacy SRB, MDL and transfer bytes together across Pending and
//! indeterminate dispatch. It does not turn a provider pointer into routing authority.

use alloc::vec::Vec;

use crate::{DeviceId, HostedDomainIdentity, IrpId};

/// Legacy x64 `SCSI_REQUEST_BLOCK` from the WDK/ReactOS `srb.h` contract.
pub const WDM_X64_LEGACY_SRB_SIZE: usize = 0x58;
const SRB_DATA_TRANSFER_LENGTH: usize = 0x10;
const SRB_DATA_BUFFER: usize = 0x18;
const MDL_BYTE_COUNT: usize = 0x28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScsiSrbRoute {
    pub pdo: DeviceId,
    pub provider: HostedDomainIdentity,
    pub relation_generation: u64,
    /// Authenticated pointer registration for this PDO in the provider address space.
    pub provider_pdo: u64,
}

impl ScsiSrbRoute {
    fn valid(self) -> bool {
        !self.pdo.is_null()
            && !self.provider.domain_id.is_null()
            && self.provider.cookie != 0
            && self.relation_generation != 0
            && self.provider_pdo != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScsiSrbProjection {
    pub irp: u64,
    pub srb: u64,
    pub mdl: u64,
    pub data: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiSrbError {
    InvalidRoute,
    InvalidProjection,
    InvalidSrb,
    InvalidMdl,
    WrongIdentity,
    WrongPhase,
    ExcessInformation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiSrbPhase {
    Prepared,
    Entered,
    Pending,
    Uncertain,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiSrbDispatchOutcome {
    /// Dispatch was proved not to have entered the provider.
    NotEntered,
    /// Provider has retained the IRP and its referenced buffers.
    Pending,
    /// Entry may have happened. No replay or resource reuse is permitted.
    Uncertain,
    /// Synchronous provider completion, still requiring exact terminal observation.
    Returned,
}

/// Owns all data whose address the native transport exposes. The caller allocates stable
/// provider-visible memory for these bytes before dispatch; these owned snapshots must remain
/// retained beside those allocations until exact completion and acknowledgement.
#[derive(Debug)]
#[must_use = "retain through provider completion and acknowledgement"]
pub struct ScsiSrbTransport {
    route: ScsiSrbRoute,
    irp_id: IrpId,
    projection: ScsiSrbProjection,
    srb: Vec<u8>,
    mdl: Option<Vec<u8>>,
    data: Vec<u8>,
    phase: ScsiSrbPhase,
}

impl ScsiSrbTransport {
    pub fn new(
        route: ScsiSrbRoute,
        irp_id: IrpId,
        projection: ScsiSrbProjection,
        srb: Vec<u8>,
        mdl: Option<Vec<u8>>,
        data: Vec<u8>,
    ) -> Result<Self, ScsiSrbError> {
        if !route.valid() || irp_id.is_null() {
            return Err(ScsiSrbError::InvalidRoute);
        }
        if projection.irp == 0 || projection.srb == 0 {
            return Err(ScsiSrbError::InvalidProjection);
        }
        if srb.len() < WDM_X64_LEGACY_SRB_SIZE
            || usize::from(u16::from_le_bytes([srb[0], srb[1]])) != WDM_X64_LEGACY_SRB_SIZE
        {
            return Err(ScsiSrbError::InvalidSrb);
        }
        let transfer_length = u32::from_le_bytes(
            srb[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let data_pointer = u64::from_le_bytes(
            srb[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8]
                .try_into()
                .unwrap(),
        );
        if transfer_length != data.len()
            || (transfer_length != 0 && (projection.data == 0 || data_pointer != projection.data))
        {
            return Err(ScsiSrbError::InvalidSrb);
        }
        if transfer_length != 0 {
            let mdl_bytes = mdl.as_ref().ok_or(ScsiSrbError::InvalidMdl)?;
            if projection.mdl == 0 || mdl_bytes.len() < MDL_BYTE_COUNT + 4 {
                return Err(ScsiSrbError::InvalidMdl);
            }
            let mdl_count = u32::from_le_bytes(
                mdl_bytes[MDL_BYTE_COUNT..MDL_BYTE_COUNT + 4]
                    .try_into()
                    .unwrap(),
            );
            if mdl_count < transfer_length as u32 {
                return Err(ScsiSrbError::InvalidMdl);
            }
        } else if mdl.is_some() != (projection.mdl != 0) {
            return Err(ScsiSrbError::InvalidMdl);
        }
        Ok(Self {
            route,
            irp_id,
            projection,
            srb,
            mdl,
            data,
            phase: ScsiSrbPhase::Prepared,
        })
    }

    pub fn route(&self) -> ScsiSrbRoute {
        self.route
    }
    pub fn irp_id(&self) -> IrpId {
        self.irp_id
    }
    pub fn projection(&self) -> ScsiSrbProjection {
        self.projection
    }
    pub fn phase(&self) -> ScsiSrbPhase {
        self.phase
    }
    pub fn srb(&self) -> &[u8] {
        &self.srb
    }
    pub fn mdl(&self) -> Option<&[u8]> {
        self.mdl.as_deref()
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Only a new, exact accepted relation may enter dispatch. A pending or uncertain call
    /// cannot be entered again, even if transport did not return an acknowledgement.
    pub fn enter(&mut self, route: ScsiSrbRoute, irp_id: IrpId) -> Result<(), ScsiSrbError> {
        if route != self.route || irp_id != self.irp_id {
            return Err(ScsiSrbError::WrongIdentity);
        }
        if self.phase != ScsiSrbPhase::Prepared {
            return Err(ScsiSrbError::WrongPhase);
        }
        self.phase = ScsiSrbPhase::Entered;
        Ok(())
    }

    pub fn observe_dispatch(
        &mut self,
        outcome: ScsiSrbDispatchOutcome,
    ) -> Result<(), ScsiSrbError> {
        if self.phase != ScsiSrbPhase::Entered {
            return Err(ScsiSrbError::WrongPhase);
        }
        self.phase = match outcome {
            ScsiSrbDispatchOutcome::NotEntered => ScsiSrbPhase::Prepared,
            ScsiSrbDispatchOutcome::Pending => ScsiSrbPhase::Pending,
            ScsiSrbDispatchOutcome::Uncertain => ScsiSrbPhase::Uncertain,
            ScsiSrbDispatchOutcome::Returned => ScsiSrbPhase::Entered,
        };
        Ok(())
    }

    /// Capture native completion before retiring the exact canonical IRP. The transport owner
    /// stays live on every failure, including an uncertain earlier dispatch result.
    pub fn complete(
        &mut self,
        route: ScsiSrbRoute,
        irp_id: IrpId,
        information: u64,
        returned_srb: &[u8],
        returned_data: &[u8],
    ) -> Result<(), ScsiSrbError> {
        if route != self.route || irp_id != self.irp_id {
            return Err(ScsiSrbError::WrongIdentity);
        }
        if !matches!(
            self.phase,
            ScsiSrbPhase::Entered | ScsiSrbPhase::Pending | ScsiSrbPhase::Uncertain
        ) {
            return Err(ScsiSrbError::WrongPhase);
        }
        if returned_srb.len() != self.srb.len() || returned_data.len() != self.data.len() {
            return Err(ScsiSrbError::InvalidSrb);
        }
        if information > self.data.len() as u64 {
            return Err(ScsiSrbError::ExcessInformation);
        }
        self.srb.copy_from_slice(returned_srb);
        self.data.copy_from_slice(returned_data);
        self.phase = ScsiSrbPhase::Completed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostedDomainId;

    fn route() -> ScsiSrbRoute {
        ScsiSrbRoute {
            pdo: DeviceId::new(4, 9),
            provider: HostedDomainIdentity {
                domain_id: HostedDomainId::new(3, 2),
                cookie: 77,
            },
            relation_generation: 5,
            provider_pdo: 0x1500,
        }
    }

    fn transport() -> ScsiSrbTransport {
        let mut srb = alloc::vec![0; WDM_X64_LEGACY_SRB_SIZE];
        srb[..2].copy_from_slice(&(WDM_X64_LEGACY_SRB_SIZE as u16).to_le_bytes());
        srb[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
            .copy_from_slice(&8u32.to_le_bytes());
        srb[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8].copy_from_slice(&0x3000u64.to_le_bytes());
        let mut mdl = alloc::vec![0; 0x30];
        mdl[MDL_BYTE_COUNT..MDL_BYTE_COUNT + 4].copy_from_slice(&8u32.to_le_bytes());
        ScsiSrbTransport::new(
            route(),
            IrpId::new(2, 3),
            ScsiSrbProjection {
                irp: 0x1000,
                srb: 0x2000,
                mdl: 0x2500,
                data: 0x3000,
            },
            srb,
            Some(mdl),
            alloc::vec![1; 8],
        )
        .unwrap()
    }

    #[test]
    fn retains_srb_mdl_and_data_across_pending_then_exact_completion() {
        let mut owner = transport();
        owner.enter(route(), IrpId::new(2, 3)).unwrap();
        owner
            .observe_dispatch(ScsiSrbDispatchOutcome::Pending)
            .unwrap();
        assert_eq!(owner.srb().len(), WDM_X64_LEGACY_SRB_SIZE);
        assert_eq!(owner.mdl().unwrap().len(), 0x30);
        assert_eq!(owner.data(), &[1; 8]);
        assert_eq!(
            owner.enter(route(), IrpId::new(2, 3)),
            Err(ScsiSrbError::WrongPhase)
        );
        let srb = owner.srb().to_vec();
        owner
            .complete(route(), IrpId::new(2, 3), 8, &srb, &[2; 8])
            .unwrap();
        assert_eq!(owner.data(), &[2; 8]);
        assert_eq!(owner.phase(), ScsiSrbPhase::Completed);
    }

    #[test]
    fn stale_relation_and_provider_domain_cannot_enter_or_complete() {
        let mut owner = transport();
        let mut stale = route();
        stale.relation_generation -= 1;
        assert_eq!(
            owner.enter(stale, IrpId::new(2, 3)),
            Err(ScsiSrbError::WrongIdentity)
        );
        owner.enter(route(), IrpId::new(2, 3)).unwrap();
        owner
            .observe_dispatch(ScsiSrbDispatchOutcome::Pending)
            .unwrap();
        let srb = owner.srb().to_vec();
        stale = route();
        stale.provider.cookie += 1;
        assert_eq!(
            owner.complete(stale, IrpId::new(2, 3), 0, &srb, &[0; 8]),
            Err(ScsiSrbError::WrongIdentity)
        );
        assert_eq!(owner.phase(), ScsiSrbPhase::Pending);
    }

    #[test]
    fn uncertain_entry_forbids_replay_but_accepts_authenticated_terminal() {
        let mut owner = transport();
        owner.enter(route(), IrpId::new(2, 3)).unwrap();
        owner
            .observe_dispatch(ScsiSrbDispatchOutcome::Uncertain)
            .unwrap();
        assert_eq!(
            owner.enter(route(), IrpId::new(2, 3)),
            Err(ScsiSrbError::WrongPhase)
        );
        let srb = owner.srb().to_vec();
        assert_eq!(
            owner.complete(route(), IrpId::new(2, 3), 9, &srb, &[0; 8]),
            Err(ScsiSrbError::ExcessInformation)
        );
        assert_eq!(owner.phase(), ScsiSrbPhase::Uncertain);
        owner
            .complete(route(), IrpId::new(2, 3), 0, &srb, &[0; 8])
            .unwrap();
    }

    #[test]
    fn mismatched_srb_data_or_mdl_is_rejected_before_entry() {
        let base = transport();
        let mut bad = base.srb().to_vec();
        bad[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8].copy_from_slice(&0x4000u64.to_le_bytes());
        assert_eq!(
            ScsiSrbTransport::new(
                route(),
                IrpId::new(2, 3),
                base.projection(),
                bad,
                base.mdl().map(<[u8]>::to_vec),
                base.data().to_vec()
            )
            .unwrap_err(),
            ScsiSrbError::InvalidSrb
        );
        let mut mdl = base.mdl().unwrap().to_vec();
        mdl[MDL_BYTE_COUNT..MDL_BYTE_COUNT + 4].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(
            ScsiSrbTransport::new(
                route(),
                IrpId::new(2, 3),
                base.projection(),
                base.srb().to_vec(),
                Some(mdl),
                base.data().to_vec()
            )
            .unwrap_err(),
            ScsiSrbError::InvalidMdl
        );
    }

    #[test]
    fn legacy_x64_srb_layout_matches_wdk_header() {
        // references/ReactOS/sdk/include/ddk/srb.h: `Length` at 0, ten UCHAR fields
        // through SenseInfoBufferLength at 0x0b, SrbFlags at 0x0c, transfer length at
        // 0x10, timeout at 0x14, DataBuffer at 0x18, and 16-byte Cdb at 0x48.
        assert_eq!(WDM_X64_LEGACY_SRB_SIZE, 0x58);
        assert_eq!(SRB_DATA_TRANSFER_LENGTH, 0x10);
        assert_eq!(SRB_DATA_BUFFER, 0x18);
        let owner = transport();
        assert_eq!(&owner.srb()[0x10..0x14], &8u32.to_le_bytes());
        assert_eq!(&owner.srb()[0x18..0x20], &0x3000u64.to_le_bytes());
        assert_eq!(owner.srb()[0x48..].len(), 16);
    }
}
