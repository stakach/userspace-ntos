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
const SRB_SENSE_BUFFER: usize = 0x20;
const SRB_NEXT: usize = 0x28;
#[cfg(test)]
const SRB_ORIGINAL_REQUEST: usize = 0x30;
const SRB_EXTENSION: usize = 0x38;
const MDL_BYTE_COUNT: usize = 0x28;

/// Copy only scalar SRB state onto the provider wire. The five x64 pointer slots are
/// source-domain addresses and must never be serialized across an address domain.
pub fn sanitized_legacy_srb(
    source: &[u8],
    data_length: usize,
    sense_length: usize,
) -> Result<[u8; WDM_X64_LEGACY_SRB_SIZE], ScsiSrbError> {
    if source.len() != WDM_X64_LEGACY_SRB_SIZE
        || usize::from(u16::from_le_bytes([source[0], source[1]])) != WDM_X64_LEGACY_SRB_SIZE
        || u32::from_le_bytes(
            source[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
                .try_into()
                .unwrap(),
        ) as usize
            != data_length
        || usize::from(source[0x0b]) != sense_length
        || (data_length != 0
            && u64::from_le_bytes(
                source[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8]
                    .try_into()
                    .unwrap(),
            ) == 0)
        || (sense_length != 0
            && u64::from_le_bytes(
                source[SRB_SENSE_BUFFER..SRB_SENSE_BUFFER + 8]
                    .try_into()
                    .unwrap(),
            ) == 0)
        || source[SRB_NEXT..SRB_NEXT + 8] != [0; 8]
    {
        return Err(ScsiSrbError::InvalidSrb);
    }
    let mut wire = [0; WDM_X64_LEGACY_SRB_SIZE];
    wire.copy_from_slice(source);
    wire[SRB_DATA_BUFFER..SRB_EXTENSION + 8].fill(0);
    Ok(wire)
}

/// Project a failed terminal result from the captured source SRB when the
/// provider's completion cannot be accepted. The returned provider-shaped
/// image contains no source pointers or claimed transfer/sense bytes.
pub fn failed_legacy_srb(
    source: &[u8],
    data_length: usize,
    sense_length: usize,
) -> Result<[u8; WDM_X64_LEGACY_SRB_SIZE], ScsiSrbError> {
    let mut failed = sanitized_legacy_srb(source, data_length, sense_length)?;
    failed[3] = 0x30; // SRB_STATUS_INTERNAL_ERROR, with no autosense flag.
    failed[4] = 0; // ScsiStatus
    failed[0x0b] = 0; // SenseInfoBufferLength
    failed[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4].fill(0);
    Ok(failed)
}

/// Merge provider completion into the retained source SRB without importing its address-space
/// pointers. Data and sense bytes are copied through their separately bounded allocations.
pub fn merge_provider_legacy_srb(
    source: &[u8],
    provider: &[u8],
    data_capacity: usize,
    sense_capacity: usize,
) -> Result<[u8; WDM_X64_LEGACY_SRB_SIZE], ScsiSrbError> {
    sanitized_legacy_srb(source, data_capacity, sense_capacity)?;
    if provider.len() != WDM_X64_LEGACY_SRB_SIZE
        || usize::from(u16::from_le_bytes([provider[0], provider[1]])) != WDM_X64_LEGACY_SRB_SIZE
        || u32::from_le_bytes(
            provider[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
                .try_into()
                .unwrap(),
        ) as usize
            > data_capacity
        || usize::from(provider[0x0b]) > sense_capacity
        || provider[SRB_NEXT..SRB_NEXT + 8] != [0; 8]
    {
        return Err(ScsiSrbError::InvalidSrb);
    }
    let mut merged = [0; WDM_X64_LEGACY_SRB_SIZE];
    merged.copy_from_slice(source);
    merged[..SRB_DATA_BUFFER].copy_from_slice(&provider[..SRB_DATA_BUFFER]);
    merged[SRB_EXTENSION + 8..].copy_from_slice(&provider[SRB_EXTENSION + 8..]);
    Ok(merged)
}

/// Apply an authenticated CLAIM_DEVICE result to the caller's own PDO alias. The provider's
/// pointer never appears in the wire SRB, and the caller alias comes from a retained target.
pub fn project_claim_source_alias(
    merged: &mut [u8; WDM_X64_LEGACY_SRB_SIZE],
    claim_result: bool,
    source_pdo_alias: u64,
) -> Result<(), ScsiSrbError> {
    if !claim_result { return Ok(()); }
    if merged[2] != 1
        || merged[3] != 1
        || source_pdo_alias == 0
        || u32::from_le_bytes(merged[0x10..0x14].try_into().unwrap()) != 0
        || u64::from_le_bytes(merged[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8].try_into().unwrap()) != 0
    { return Err(ScsiSrbError::InvalidSrb); }
    merged[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8]
        .copy_from_slice(&source_pdo_alias.to_le_bytes());
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScsiSrbRoute {
    pub pdo: DeviceId,
    pub provider: HostedDomainIdentity,
    pub relation_generation: u64,
    /// Authenticated pointer registration for this PDO in the provider address space.
    pub provider_pdo: u64,
}

/// Provider-local receipt for the root reservation queried before entering a SCSI driver.
/// The root retains the actual DMA reservation until canonical completion acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScsiDmaReceipt {
    route: ScsiSrbRoute,
    irp_id: IrpId,
    grant_va: u64,
    grant_len: u64,
    reservation_id: u64,
}

impl ScsiDmaReceipt {
    pub fn from_authenticated_query(
        route: ScsiSrbRoute, irp_id: IrpId, grant_va: u64,
        grant_len: u64, reservation_id: u64, data_len: u64,
    ) -> Option<Self> {
        if !route.valid() || irp_id.is_null() || grant_va == 0
            || reservation_id == 0 || grant_len == 0 || grant_len != data_len
            || grant_va.checked_add(grant_len).is_none()
        { return None; }
        Some(Self { route, irp_id, grant_va, grant_len, reservation_id })
    }

    pub const fn grant_va(self) -> u64 { self.grant_va }

    /// Validate the retained grant and the driver's terminal SRB before touching DMA bytes.
    pub fn completion_source(
        self, route: ScsiSrbRoute, irp_id: IrpId, data_capacity: u64,
        srb_data_pointer: u64, transferred: u64,
    ) -> Option<u64> {
        (self.route == route && self.irp_id == irp_id
            && self.reservation_id != 0 && self.grant_va != 0
            && self.grant_len == data_capacity && data_capacity != 0
            && self.grant_va.checked_add(self.grant_len).is_some()
            && srb_data_pointer == self.grant_va && transferred <= self.grant_len)
            .then_some(self.grant_va)
    }
}

/// Canonical major-0x0f stack parameters. The SRB image is pointer-free; retained transfer
/// and sense bytes live in the detached owner's buffers, not in this copyable stack value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScsiParameters {
    pub route: ScsiSrbRoute,
    pub srb: [u8; WDM_X64_LEGACY_SRB_SIZE],
    pub data_length: u32,
    pub sense_length: u8,
}

impl ScsiParameters {
    pub fn from_source(
        route: ScsiSrbRoute,
        source_srb: &[u8],
        data_length: u32,
        sense_length: u8,
    ) -> Result<Self, ScsiSrbError> {
        let wire = sanitized_legacy_srb(source_srb, data_length as usize, sense_length as usize)?;
        Self::from_wire(route, wire, data_length, sense_length)
    }

    pub fn from_wire(
        route: ScsiSrbRoute,
        srb: [u8; WDM_X64_LEGACY_SRB_SIZE],
        data_length: u32,
        sense_length: u8,
    ) -> Result<Self, ScsiSrbError> {
        if !route.valid() {
            return Err(ScsiSrbError::InvalidRoute);
        }
        if usize::from(u16::from_le_bytes([srb[0], srb[1]])) != WDM_X64_LEGACY_SRB_SIZE
            || u32::from_le_bytes(srb[0x10..0x14].try_into().unwrap()) != data_length
            || srb[0x0b] != sense_length
            || srb[SRB_DATA_BUFFER..SRB_EXTENSION + 8] != [0; 0x28]
        {
            return Err(ScsiSrbError::InvalidSrb);
        }
        Ok(Self {
            route,
            srb,
            data_length,
            sense_length,
        })
    }
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
    pub sense: u64,
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

/// IoStatus.Information is a byte count, not an address or the SRB's returned transfer length.
/// Keep its native scalar value only inside the captured data allocation's bound.
pub fn bounded_scsi_information(
    information: u64,
    data_capacity: usize,
) -> Result<u64, ScsiSrbError> {
    if information > data_capacity as u64 {
        Err(ScsiSrbError::ExcessInformation)
    } else {
        Ok(information)
    }
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
    sense: Vec<u8>,
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
        sense: Vec<u8>,
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
        let sense_length = usize::from(srb[0x0b]);
        let sense_pointer = u64::from_le_bytes(
            srb[SRB_SENSE_BUFFER..SRB_SENSE_BUFFER + 8]
                .try_into()
                .unwrap(),
        );
        if sense_length != sense.len()
            || (sense_length != 0 && (projection.sense == 0 || sense_pointer != projection.sense))
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
            sense,
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
    pub fn sense(&self) -> &[u8] {
        &self.sense
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
        returned_sense: &[u8],
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
        if returned_srb.len() != self.srb.len()
            || returned_data.len() != self.data.len()
            || returned_sense.len() != self.sense.len()
        {
            return Err(ScsiSrbError::InvalidSrb);
        }
        bounded_scsi_information(information, self.data.len())?;
        let merged =
            merge_provider_legacy_srb(&self.srb, returned_srb, self.data.len(), self.sense.len())?;
        self.srb.copy_from_slice(&merged);
        self.data.copy_from_slice(returned_data);
        self.sense.copy_from_slice(returned_sense);
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

    #[test]
    fn dma_receipt_admits_only_the_exact_pending_scsi_completion() {
        let irp = IrpId::new(2, 3);
        let receipt = ScsiDmaReceipt::from_authenticated_query(
            route(), irp, 0x3000, 8, 17, 8,
        ).unwrap();
        assert_eq!(receipt.completion_source(route(), irp, 8, 0x3000, 8), Some(0x3000));
        assert_eq!(receipt.completion_source(route(), irp, 8, 0x3000, 9), None);
        assert_eq!(receipt.completion_source(route(), irp, 8, 0x3001, 8), None);
        assert_eq!(receipt.completion_source(route(), IrpId::new(2, 4), 8, 0x3000, 8), None);
        let mut stale_route = route();
        stale_route.relation_generation += 1;
        assert_eq!(receipt.completion_source(stale_route, irp, 8, 0x3000, 8), None);
        let mut other_provider = route();
        other_provider.provider_pdo += 1;
        assert_eq!(receipt.completion_source(other_provider, irp, 8, 0x3000, 8), None);
    }

    #[test]
    fn dma_receipt_rejects_unbound_or_inconsistent_grants() {
        let irp = IrpId::new(2, 3);
        assert!(ScsiDmaReceipt::from_authenticated_query(route(), irp, 0x3000, 8, 17, 9).is_none());
        assert!(ScsiDmaReceipt::from_authenticated_query(route(), irp, 0x3000, 8, 0, 8).is_none());
        assert!(ScsiDmaReceipt::from_authenticated_query(route(), irp, 0, 8, 17, 8).is_none());
        assert!(ScsiDmaReceipt::from_authenticated_query(route(), irp, u64::MAX, 8, 17, 8).is_none());
        assert!(ScsiDmaReceipt::from_authenticated_query(route(), IrpId::new(0, 0),
            0x3000, 8, 17, 8).is_none());
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
                sense: 0,
            },
            srb,
            Some(mdl),
            alloc::vec![1; 8],
            Vec::new(),
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
            .complete(route(), IrpId::new(2, 3), 8, &srb, &[2; 8], &[])
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
            owner.complete(stale, IrpId::new(2, 3), 0, &srb, &[0; 8], &[]),
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
            owner.complete(route(), IrpId::new(2, 3), 9, &srb, &[0; 8], &[]),
            Err(ScsiSrbError::ExcessInformation)
        );
        assert_eq!(owner.phase(), ScsiSrbPhase::Uncertain);
        owner
            .complete(route(), IrpId::new(2, 3), 0, &srb, &[0; 8], &[])
            .unwrap();
    }

    #[test]
    fn information_cannot_smuggle_a_provider_address_into_a_zero_data_srb() {
        assert_eq!(bounded_scsi_information(0, 0), Ok(0));
        assert_eq!(
            bounded_scsi_information(u64::MAX, 0),
            Err(ScsiSrbError::ExcessInformation)
        );
        assert_eq!(bounded_scsi_information(7, 8), Ok(7));
        assert_eq!(
            bounded_scsi_information(9, 8),
            Err(ScsiSrbError::ExcessInformation)
        );
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
                base.data().to_vec(),
                Vec::new(),
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
                base.data().to_vec(),
                Vec::new(),
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

    #[test]
    fn serialized_srb_carries_no_source_domain_addresses_or_chained_request() {
        let mut source = transport().srb().to_vec();
        source[0x0b] = 0x20;
        for (offset, address) in [
            (SRB_SENSE_BUFFER, 0x1122_3344_5566_7788u64),
            (SRB_ORIGINAL_REQUEST, 0x2233_4455_6677_8899),
            (SRB_EXTENSION, 0x3344_5566_7788_99aa),
        ] {
            source[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
        }
        let wire = sanitized_legacy_srb(&source, 8, 0x20).unwrap();
        assert_eq!(&wire[SRB_DATA_BUFFER..SRB_EXTENSION + 8], &[0; 0x28]);
        assert_eq!(&wire[0x10..0x14], &8u32.to_le_bytes());
        assert_eq!(wire[0x0b], 0x20);
        assert_eq!(&wire[0x48..], &source[0x48..]);

        source[SRB_NEXT..SRB_NEXT + 8].copy_from_slice(&0x4455_6677_8899_aabbu64.to_le_bytes());
        assert_eq!(
            sanitized_legacy_srb(&source, 8, 0x20),
            Err(ScsiSrbError::InvalidSrb)
        );
    }

    #[test]
    fn completion_merges_scalar_state_and_keeps_every_source_pointer() {
        let mut source = transport().srb().to_vec();
        source[0x0b] = 0x20;
        for (offset, address) in [
            (SRB_SENSE_BUFFER, 0x1122_3344_5566_7788u64),
            (SRB_ORIGINAL_REQUEST, 0x2233_4455_6677_8899),
            (SRB_EXTENSION, 0x3344_5566_7788_99aa),
        ] {
            source[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
        }
        let mut provider = sanitized_legacy_srb(&source, 8, 0x20).unwrap();
        provider[3] = 1; // SrbStatus
        provider[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        provider[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8]
            .copy_from_slice(&0xaabb_ccdd_eeff_0011u64.to_le_bytes());
        provider[SRB_SENSE_BUFFER..SRB_SENSE_BUFFER + 8]
            .copy_from_slice(&0xbbcc_ddee_ff00_1122u64.to_le_bytes());
        provider[SRB_ORIGINAL_REQUEST..SRB_ORIGINAL_REQUEST + 8]
            .copy_from_slice(&0xccdd_eeff_0011_2233u64.to_le_bytes());
        provider[0x48] = 0x28;
        let merged = merge_provider_legacy_srb(&source, &provider, 8, 0x20).unwrap();
        assert_eq!(merged[3], 1);
        assert_eq!(
            &merged[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4],
            &4u32.to_le_bytes()
        );
        assert_eq!(
            &merged[SRB_DATA_BUFFER..SRB_EXTENSION + 8],
            &source[SRB_DATA_BUFFER..SRB_EXTENSION + 8]
        );
        assert_eq!(merged[0x48], 0x28);

        provider[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4]
            .copy_from_slice(&9u32.to_le_bytes());
        assert_eq!(
            merge_provider_legacy_srb(&source, &provider, 8, 0x20),
            Err(ScsiSrbError::InvalidSrb)
        );
    }

    #[test]
    fn failed_legacy_srb_projects_error_without_source_pointers_or_transfer() {
        let mut source = transport().srb().to_vec();
        source[0x0b] = 0x20;
        for (offset, address) in [
            (SRB_SENSE_BUFFER, 0x1122_3344_5566_7788u64),
            (SRB_ORIGINAL_REQUEST, 0x2233_4455_6677_8899),
            (SRB_EXTENSION, 0x3344_5566_7788_99aau64),
        ] {
            source[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
        }
        let failed = failed_legacy_srb(&source, 8, 0x20).unwrap();
        assert_eq!(failed[2], source[2]);
        assert_eq!(failed[3], 0x30); // SRB_STATUS_INTERNAL_ERROR
        assert_eq!(failed[4], 0); // ScsiStatus
        assert_eq!(failed[0x0b], 0); // no autosense bytes
        assert_eq!(&failed[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4], &[0; 4]);
        assert_eq!(&failed[SRB_DATA_BUFFER..SRB_EXTENSION + 8], &[0; 0x28]);

        let merged = merge_provider_legacy_srb(&source, &failed, 8, 0x20).unwrap();
        assert_eq!(merged[2], source[2]);
        assert_eq!(merged[3], 0x30);
        assert_eq!(merged[4], 0);
        assert_eq!(merged[0x0b], 0);
        assert_eq!(&merged[SRB_DATA_TRANSFER_LENGTH..SRB_DATA_TRANSFER_LENGTH + 4], &[0; 4]);
        assert_eq!(
            &merged[SRB_DATA_BUFFER..SRB_EXTENSION + 8],
            &source[SRB_DATA_BUFFER..SRB_EXTENSION + 8],
        );
        assert_eq!(
            failed_legacy_srb(&source, 7, 0x20),
            Err(ScsiSrbError::InvalidSrb),
        );
    }

    #[test]
    fn claimed_provider_pdo_projects_only_the_retained_source_alias() {
        let mut source = [0u8; WDM_X64_LEGACY_SRB_SIZE];
        source[..2].copy_from_slice(&(WDM_X64_LEGACY_SRB_SIZE as u16).to_le_bytes());
        source[2] = 1;
        let mut completed = source;
        completed[3] = 1;
        project_claim_source_alias(&mut completed, true, 0x1234_5000).unwrap();
        assert_eq!(
            u64::from_le_bytes(completed[SRB_DATA_BUFFER..SRB_DATA_BUFFER + 8].try_into().unwrap()),
            0x1234_5000,
        );
        let mut nonclaim = source;
        nonclaim[2] = 2;
        nonclaim[3] = 1;
        assert_eq!(project_claim_source_alias(&mut nonclaim, true, 0x1234_5000),
            Err(ScsiSrbError::InvalidSrb));
        assert_eq!(project_claim_source_alias(&mut source, true, 0),
            Err(ScsiSrbError::InvalidSrb));
    }
}
