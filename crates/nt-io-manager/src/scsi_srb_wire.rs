//! Pointer-free wire image for one authenticated legacy SCSI SRB dispatch.
//!
//! The receiver compares the route with its live accepted PDO/provider registration before
//! allocating any provider-local IRP, SRB, MDL, data, or sense memory.

use alloc::vec::Vec;

use crate::scsi_srb_transport::{sanitized_legacy_srb, ScsiParameters, ScsiSrbRoute, WDM_X64_LEGACY_SRB_SIZE};
use crate::IrpId;

const MAGIC: u32 = u32::from_le_bytes(*b"SCSI");
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 64;
const SRB_OFFSET: usize = HEADER_SIZE;
const DATA_OFFSET: usize = SRB_OFFSET + WDM_X64_LEGACY_SRB_SIZE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScsiWireError {
    InvalidRoute,
    InvalidPayload,
    NoCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedScsiWireRequest<'a> {
    pub srb: &'a [u8],
    pub data: &'a [u8],
    pub sense: &'a [u8],
}

/// Encode only sanitized SRB bytes. No source-domain address is placed in this packet.
pub fn encode_scsi_request(
    route: ScsiSrbRoute,
    irp: IrpId,
    source_srb: &[u8],
    data: &[u8],
    sense: &[u8],
) -> Result<Vec<u8>, ScsiWireError> {
    let srb = sanitized_legacy_srb(source_srb, data.len(), sense.len())
        .map_err(|_| ScsiWireError::InvalidPayload)?;
    encode_scsi_wire_request(route, irp, srb, data, sense)
}

/// The source adapter may pass its already sanitized SRB without re-exposing source pointers.
pub fn encode_scsi_wire_request(
    route: ScsiSrbRoute,
    irp: IrpId,
    srb: [u8; WDM_X64_LEGACY_SRB_SIZE],
    data: &[u8],
    sense: &[u8],
) -> Result<Vec<u8>, ScsiWireError> {
    if route.pdo.is_null() || route.provider.domain_id.is_null()
        || route.provider.cookie == 0 || route.relation_generation == 0
        || route.provider_pdo == 0 || irp.is_null()
        || data.len() > u32::MAX as usize || sense.len() > u8::MAX as usize
    {
        return Err(ScsiWireError::InvalidRoute);
    }
    if !valid_wire_srb(&srb, data.len(), sense.len(), false) {
        return Err(ScsiWireError::InvalidPayload);
    }
    encode_packet(route, irp, srb, data, sense)
}

/// Convert the canonical detached IRP transfer bytes into the provider's pointer-free packet.
/// Every native dispatch path uses the same exact data/sense split and route identity.
pub fn encode_scsi_dispatch_input(
    parameters: &ScsiParameters,
    irp: IrpId,
    transfer: &[u8],
) -> Result<Vec<u8>, ScsiWireError> {
    let data_len = parameters.data_length as usize;
    let expected = data_len.checked_add(parameters.sense_length as usize)
        .ok_or(ScsiWireError::InvalidPayload)?;
    if transfer.len() != expected {
        return Err(ScsiWireError::InvalidPayload);
    }
    encode_scsi_wire_request(
        parameters.route, irp, parameters.srb,
        &transfer[..data_len], &transfer[data_len..],
    )
}

fn encode_packet(
    route: ScsiSrbRoute, irp: IrpId, srb: [u8; WDM_X64_LEGACY_SRB_SIZE],
    data: &[u8], sense: &[u8],
) -> Result<Vec<u8>, ScsiWireError> {
    if route.pdo.is_null() || route.provider.domain_id.is_null()
        || route.provider.cookie == 0 || route.relation_generation == 0
        || route.provider_pdo == 0 || irp.is_null()
        || data.len() > u32::MAX as usize || sense.len() > u8::MAX as usize
    { return Err(ScsiWireError::InvalidRoute); }
    let capacity = DATA_OFFSET.checked_add(data.len())
        .and_then(|length| length.checked_add(sense.len()))
        .ok_or(ScsiWireError::InvalidPayload)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| ScsiWireError::NoCapacity)?;
    for word in [MAGIC, VERSION] { bytes.extend_from_slice(&word.to_le_bytes()); }
    for word in [
        irp.raw(), route.pdo.raw(), route.provider.domain_id.raw(),
        route.provider.cookie, route.relation_generation, route.provider_pdo,
    ] { bytes.extend_from_slice(&word.to_le_bytes()); }
    bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(sense.len() as u32).to_le_bytes());
    debug_assert_eq!(bytes.len(), HEADER_SIZE);
    bytes.extend_from_slice(&srb);
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(sense);
    Ok(bytes)
}

/// Provider completion carries the original capacity extents, but reports actual transfer and
/// sense lengths in the SRB. Its local pointer values are cleared before publication.
pub fn encode_scsi_completion(
    route: ScsiSrbRoute, irp: IrpId, provider_srb: &[u8],
    data: &[u8], sense: &[u8],
) -> Result<Vec<u8>, ScsiWireError> {
    if provider_srb.len() != WDM_X64_LEGACY_SRB_SIZE
        || provider_srb[0x28..0x30] != [0; 8] {
        return Err(ScsiWireError::InvalidPayload);
    }
    let mut srb = [0; WDM_X64_LEGACY_SRB_SIZE];
    srb.copy_from_slice(provider_srb);
    srb[0x18..0x40].fill(0);
    if !valid_wire_srb(&srb, data.len(), sense.len(), true) {
        return Err(ScsiWireError::InvalidPayload);
    }
    encode_packet(route, irp, srb, data, sense)
}

/// Capture a provider-local SRB in the retained packet allocation before publishing terminal
/// completion. The packet keeps its exact route/IRP header and full data/sense capacities.
pub fn capture_scsi_completion_in_place(
    packet: &mut [u8], route: ScsiSrbRoute, irp: IrpId, provider_srb: &[u8],
) -> Result<(), ScsiWireError> {
    let current = decode_scsi_request(packet, route, irp)?;
    let data_len = current.data.len();
    let sense_len = current.sense.len();
    if provider_srb.len() != WDM_X64_LEGACY_SRB_SIZE
        || provider_srb[0x28..0x30] != [0; 8]
    { return Err(ScsiWireError::InvalidPayload); }
    let mut completed = [0; WDM_X64_LEGACY_SRB_SIZE];
    completed.copy_from_slice(provider_srb);
    completed[0x18..0x40].fill(0);
    if !valid_wire_srb(&completed, data_len, sense_len, true) {
        return Err(ScsiWireError::InvalidPayload);
    }
    packet[SRB_OFFSET..DATA_OFFSET].copy_from_slice(&completed);
    Ok(())
}

/// `route` and `irp` are the independent live authority, never identities inferred from bytes.
pub fn decode_scsi_request<'a>(
    bytes: &'a [u8], route: ScsiSrbRoute, irp: IrpId,
) -> Result<DecodedScsiWireRequest<'a>, ScsiWireError> {
    decode_packet(bytes, route, irp, false)
}

pub fn decode_scsi_completion<'a>(
    bytes: &'a [u8], route: ScsiSrbRoute, irp: IrpId,
) -> Result<DecodedScsiWireRequest<'a>, ScsiWireError> {
    decode_packet(bytes, route, irp, true)
}

fn decode_packet<'a>(
    bytes: &'a [u8], route: ScsiSrbRoute, irp: IrpId, completion: bool,
) -> Result<DecodedScsiWireRequest<'a>, ScsiWireError> {
    if bytes.len() < DATA_OFFSET
        || read_u32(bytes, 0) != MAGIC || read_u32(bytes, 4) != VERSION
        || read_u64(bytes, 8) != irp.raw()
        || read_u64(bytes, 16) != route.pdo.raw()
        || read_u64(bytes, 24) != route.provider.domain_id.raw()
        || read_u64(bytes, 32) != route.provider.cookie
        || read_u64(bytes, 40) != route.relation_generation
        || read_u64(bytes, 48) != route.provider_pdo
        || irp.is_null() || route.pdo.is_null() || route.provider.domain_id.is_null()
        || route.provider.cookie == 0 || route.relation_generation == 0 || route.provider_pdo == 0
    {
        return Err(ScsiWireError::InvalidRoute);
    }
    let data_len = read_u32(bytes, 56) as usize;
    let sense_len = read_u32(bytes, 60) as usize;
    let sense_offset = DATA_OFFSET.checked_add(data_len).ok_or(ScsiWireError::InvalidPayload)?;
    if sense_len > u8::MAX as usize
        || sense_offset.checked_add(sense_len) != Some(bytes.len())
    {
        return Err(ScsiWireError::InvalidPayload);
    }
    let srb = &bytes[SRB_OFFSET..DATA_OFFSET];
    if !valid_wire_srb(srb, data_len, sense_len, completion) {
        return Err(ScsiWireError::InvalidPayload);
    }
    Ok(DecodedScsiWireRequest {
        srb,
        data: &bytes[DATA_OFFSET..sense_offset],
        sense: &bytes[sense_offset..],
    })
}

fn valid_wire_srb(srb: &[u8], data_len: usize, sense_len: usize, completion: bool) -> bool {
    if srb.len() != WDM_X64_LEGACY_SRB_SIZE || sense_len > u8::MAX as usize {
        return false;
    }
    let transfer = u32::from_le_bytes(srb[0x10..0x14].try_into().unwrap()) as usize;
    let returned_sense = usize::from(srb[0x0b]);
    usize::from(u16::from_le_bytes([srb[0], srb[1]])) == WDM_X64_LEGACY_SRB_SIZE
        && if completion { transfer <= data_len && returned_sense <= sense_len }
            else { transfer == data_len && returned_sense == sense_len }
        && srb[0x18..0x40] == [0; 0x28]
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DeviceId, HostedDomainId, HostedDomainIdentity};

    fn route() -> ScsiSrbRoute {
        ScsiSrbRoute {
            pdo: DeviceId::new(4, 5),
            provider: HostedDomainIdentity {
                domain_id: HostedDomainId::new(2, 3), cookie: 0x55,
            },
            relation_generation: 7,
            provider_pdo: 0x9000,
        }
    }

    fn source_srb() -> [u8; WDM_X64_LEGACY_SRB_SIZE] {
        let mut source = [0; WDM_X64_LEGACY_SRB_SIZE];
        source[..2].copy_from_slice(&(WDM_X64_LEGACY_SRB_SIZE as u16).to_le_bytes());
        source[0x0b] = 4;
        source[0x10..0x14].copy_from_slice(&3u32.to_le_bytes());
        for (offset, value) in [
            (0x18, 0x1111_2222_3333_4444u64),
            (0x20, 0x2222_3333_4444_5555),
            (0x30, 0x3333_4444_5555_6666),
            (0x38, 0x4444_5555_6666_7777),
        ] { source[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }
        source
    }

    #[test]
    fn canonical_scsi_transfer_is_encoded_once_for_native_dispatch() {
        let irp = IrpId::new(6, 7);
        let parameters = crate::scsi_srb_transport::ScsiParameters::from_source(
            route(), &source_srb(), 3, 4,
        ).unwrap();
        let packet = encode_scsi_dispatch_input(&parameters, irp, &[1, 2, 3, 4, 5, 6, 7]).unwrap();
        let decoded = decode_scsi_request(&packet, route(), irp).unwrap();
        assert_eq!(decoded.data, &[1, 2, 3]);
        assert_eq!(decoded.sense, &[4, 5, 6, 7]);
        assert_eq!(encode_scsi_dispatch_input(&parameters, irp, &[1, 2, 3]),
            Err(ScsiWireError::InvalidPayload));
    }

    #[test]
    fn wire_round_trip_contains_no_source_pointer_and_requires_exact_route() {
        let irp = IrpId::new(6, 7);
        let bytes = encode_scsi_request(route(), irp, &source_srb(), &[1, 2, 3], &[4; 4]).unwrap();
        let decoded = decode_scsi_request(&bytes, route(), irp).unwrap();
        assert_eq!(decoded.data, &[1, 2, 3]);
        assert_eq!(decoded.sense, &[4; 4]);
        assert_eq!(&decoded.srb[0x18..0x40], &[0; 0x28]);
        let mut stale = route();
        stale.relation_generation += 1;
        assert_eq!(decode_scsi_request(&bytes, stale, irp), Err(ScsiWireError::InvalidRoute));
        assert_eq!(decode_scsi_request(&bytes, route(), IrpId::new(6, 8)),
            Err(ScsiWireError::InvalidRoute));
        let mut corrupt = bytes;
        corrupt[SRB_OFFSET + 0x30] = 0xaa;
        assert_eq!(decode_scsi_request(&corrupt, route(), irp),
            Err(ScsiWireError::InvalidPayload));
    }

    #[test]
    fn completion_scrubs_provider_pointers_and_bounds_actual_lengths() {
        let irp = IrpId::new(6, 7);
        let mut provider = source_srb();
        provider[0x0b] = 2;
        provider[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        let bytes = encode_scsi_completion(route(), irp, &provider, &[1, 2, 3], &[4; 4]).unwrap();
        let completed = decode_scsi_completion(&bytes, route(), irp).unwrap();
        assert_eq!(&completed.srb[0x18..0x40], &[0; 0x28]);
        assert_eq!(completed.data, &[1, 2, 3]);
        assert_eq!(completed.sense, &[4; 4]);
        assert_eq!(decode_scsi_request(&bytes, route(), irp), Err(ScsiWireError::InvalidPayload));
        let mut retained = encode_scsi_request(route(), irp, &source_srb(), &[1, 2, 3], &[4; 4]).unwrap();
        capture_scsi_completion_in_place(&mut retained, route(), irp, &provider).unwrap();
        assert_eq!(retained, bytes);

        provider[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(encode_scsi_completion(route(), irp, &provider, &[1, 2, 3], &[4; 4]),
            Err(ScsiWireError::InvalidPayload));
    }
}
