//! Root-owned, provider-read-only authority for one coherent SCSI data slice.

use bytemuck::{Pod, Zeroable};
use crate::{major, IrpDispatchRequest, IRP_DISPATCH_SCSI_SRB};

pub const SCSI_DMA_AUTHORITY_SLOTS: usize = 16;
pub const SCSI_DMA_AUTHORITY_ALIASES: usize = 8;
pub const SCSI_DMA_AUTHORITY_BYTES: usize = 4096;
pub const SCSI_COHERENT_RECORD_KIND: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ScsiCoherentAlias {
    pub adapter_id: u64,
    pub alias_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ScsiCoherentAuthority {
    /// Published last and cleared first. Zero means this slot carries no authority.
    pub irp_id: u64,
    pub pdo: u64,
    pub provider_domain_id: u64,
    pub provider_cookie: u64,
    pub provider_pdo: u64,
    pub relation_generation: u64,
    pub window_lease_id: u64,
    pub window_generation: u64,
    pub reservation_id: u64,
    pub provider_va: u64,
    pub length: u64,
    pub logical: u64,
    pub window_va: u64,
    pub window_length: u64,
    pub window_logical: u64,
    pub alias_count: u64,
    pub aliases: [ScsiCoherentAlias; SCSI_DMA_AUTHORITY_ALIASES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
pub struct ScsiCoherentProjection {
    pub kind: u64,
    pub irp_id: u64,
    pub reservation_id: u64,
    pub alias_id: u64,
    pub adapter_id: u64,
    pub provider_va: u64,
    pub length: u64,
    pub logical: u64,
}

const _: () = assert!(core::mem::size_of::<ScsiCoherentAuthority>()
    * SCSI_DMA_AUTHORITY_SLOTS == SCSI_DMA_AUTHORITY_BYTES);

fn subrange_offset(base: u64, span: u64, address: u64, length: u64) -> Option<u64> {
    base.checked_add(span)?;
    address.checked_add(length)?;
    let offset = address.checked_sub(base)?;
    (length != 0 && offset <= span && length <= span - offset).then_some(offset)
}

/// Compare a root-authored descriptor with the received IRP and every projected adapter alias.
/// The caller must read `authority` from a root-owned RO mapping, not from the shared DMA bank.
pub fn validate_scsi_coherent_authority(
    request: &IrpDispatchRequest,
    provider_pdo: u64,
    authority: &ScsiCoherentAuthority,
    projections: &[ScsiCoherentProjection],
) -> Option<(u64, u64)> {
    if request._reserved0 != IRP_DISPATCH_SCSI_SRB
        || request.major != major::IRP_MJ_INTERNAL_DEVICE_CONTROL
        || request.irp_id == 0
        || authority.irp_id != request.irp_id
        || authority.pdo != request.device_id
        || authority.provider_domain_id != request.target_domain_id
        || authority.provider_cookie != request.target_domain_cookie
        || authority.relation_generation != request.scsi_relation_generation
        || provider_pdo == 0
        || authority.provider_pdo != provider_pdo
        || authority.window_lease_id == 0
        || authority.window_generation == 0
        || authority.reservation_id == 0
        || authority.window_va == 0
        || authority.window_logical == 0
        || authority.provider_va == 0
        || authority.logical == 0
        || authority.alias_count == 0
        || authority.alias_count > SCSI_DMA_AUTHORITY_ALIASES as u64
        || authority.alias_count != projections.len() as u64
    { return None; }
    let offset = subrange_offset(
        authority.window_va, authority.window_length,
        authority.provider_va, authority.length,
    )?;
    authority.window_logical.checked_add(authority.window_length)?;
    if authority.window_logical.checked_add(offset) != Some(authority.logical) {
        return None;
    }
    let aliases = &authority.aliases[..authority.alias_count as usize];
    for (index, alias) in aliases.iter().enumerate() {
        if alias.adapter_id == 0 || alias.alias_id == 0
            || aliases[..index].iter().any(|earlier| earlier.adapter_id == alias.adapter_id
                || earlier.alias_id == alias.alias_id)
        { return None; }
        let mut matches = 0usize;
        for projection in projections {
            if projection.adapter_id == alias.adapter_id && projection.alias_id == alias.alias_id {
                if projection.kind != SCSI_COHERENT_RECORD_KIND
                    || projection.irp_id != authority.irp_id
                    || projection.reservation_id != authority.reservation_id
                    || projection.provider_va != authority.provider_va
                    || projection.length != authority.length
                    || projection.logical != authority.logical
                { return None; }
                matches += 1;
            }
        }
        if matches != 1 { return None; }
    }
    Some((authority.provider_va, authority.length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> (IrpDispatchRequest, ScsiCoherentAuthority, [ScsiCoherentProjection; 1]) {
        let request = IrpDispatchRequest {
            major: major::IRP_MJ_INTERNAL_DEVICE_CONTROL,
            _reserved0: IRP_DISPATCH_SCSI_SRB,
            irp_id: 7, device_id: 8, target_domain_id: 9,
            target_domain_cookie: 10, scsi_relation_generation: 11,
            ..Default::default()
        };
        let mut authority = ScsiCoherentAuthority {
            irp_id: 7, pdo: 8, provider_domain_id: 9, provider_cookie: 10,
            provider_pdo: 12, relation_generation: 11,
            window_lease_id: 13, window_generation: 14, reservation_id: 15,
            provider_va: 0x1100, length: 3, logical: 0x2100,
            window_va: 0x1000, window_length: 0x1000, window_logical: 0x2000,
            alias_count: 1, ..Default::default()
        };
        authority.aliases[0] = ScsiCoherentAlias { adapter_id: 16, alias_id: 17 };
        let projection = ScsiCoherentProjection {
            kind: SCSI_COHERENT_RECORD_KIND, irp_id: 7, reservation_id: 15,
            adapter_id: 16, alias_id: 17,
            provider_va: 0x1100, length: 3, logical: 0x2100,
        };
        (request, authority, [projection])
    }

    #[test]
    fn exact_authority_accepts_and_every_changed_projection_field_rejects() {
        let (request, authority, projection) = valid();
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &projection), Some((0x1100, 3)));
        for changed in [
            ScsiCoherentProjection { provider_va: 0x1200, ..projection[0] },
            ScsiCoherentProjection { logical: 0x2200, ..projection[0] },
            ScsiCoherentProjection { length: 4, ..projection[0] },
            ScsiCoherentProjection { reservation_id: 16, ..projection[0] },
            ScsiCoherentProjection { alias_id: 18, ..projection[0] },
            ScsiCoherentProjection { adapter_id: 18, ..projection[0] },
            ScsiCoherentProjection { irp_id: 8, ..projection[0] },
        ] {
            assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &[changed]), None);
        }
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &[]), None);
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &[projection[0], projection[0]]), None);
    }

    #[test]
    fn stale_window_and_out_of_grant_reject() {
        let (request, mut authority, projection) = valid();
        authority.window_generation = 0;
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &projection), None);
        authority.window_generation = 14;
        authority.window_length = 0x100;
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &projection), None);
        authority.window_length = 0x1000;
        authority.window_va = u64::MAX - 1;
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &projection), None);
    }

    #[test]
    fn alias_count_and_duplicate_adapter_cannot_be_truncated() {
        let (request, mut authority, projection) = valid();
        authority.alias_count = (SCSI_DMA_AUTHORITY_ALIASES + 1) as u64;
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &projection), None);
        authority.alias_count = 2;
        authority.aliases[1] = ScsiCoherentAlias { adapter_id: 16, alias_id: 18 };
        let second = ScsiCoherentProjection { alias_id: 18, ..projection[0] };
        assert_eq!(validate_scsi_coherent_authority(&request, 12, &authority, &[projection[0], second]), None);
    }
}
