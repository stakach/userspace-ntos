//! Correlation wire for one file-less win32k TargetDeviceRelation source IRP.
//! The physical provider lane and exact source/device leases remain the authority.

use crate::win32k_source_irp_ioctl_wire::EventIdentity;

pub const PACKET_BYTES: usize = 128;
pub const STATUS_PENDING: u32 = 0x103;
const KIND: u32 = 2;
const VERSION: u32 = 1;
const TOKEN_OFF: usize = 80;
const STATUS_OFF: usize = 88;
const INFORMATION_OFF: usize = 96;
const COMPLETED_OFF: usize = 104;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourcePnpRequest {
    pub nonce: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub device_object_va: u64,
    pub relation_type: u32,
    pub event: Option<EventIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePnpResponse {
    Pending { token: u64 },
    Inline { token: u64, status: u32, information: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    LengthMismatch,
    Malformed,
}

fn u32_at(packet: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(packet[offset..offset + 4].try_into().unwrap())
}

fn u64_at(packet: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(packet[offset..offset + 8].try_into().unwrap())
}

fn put_u32(packet: &mut [u8], offset: usize, value: u32) {
    packet[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(packet: &mut [u8], offset: usize, value: u64) {
    packet[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn valid_request(request: SourcePnpRequest) -> bool {
    request.nonce != 0
        && request.source_irp_va != 0
        && request.source_ticket_serial != 0
        && request.native_allocation_generation != 0
        && request.device_object_va != 0
        && request.relation_type == nt_pnp_abi::TARGET_DEVICE_RELATION
        && request.event.is_none_or(|event| {
            event.local_id != 0
                && event.object_slot_plus_one != 0
                && event.object_generation != 0
        })
}

pub fn encode_request(request: SourcePnpRequest, packet: &mut [u8]) -> Result<(), WireError> {
    if packet.len() != PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if !valid_request(request) {
        return Err(WireError::Malformed);
    }
    packet.fill(0);
    put_u32(packet, 0, KIND);
    put_u32(packet, 4, VERSION);
    put_u64(packet, 8, request.nonce);
    put_u64(packet, 16, request.source_irp_va);
    put_u64(packet, 24, request.source_ticket_serial);
    put_u64(packet, 32, request.native_allocation_generation);
    put_u64(packet, 40, request.device_object_va);
    put_u32(packet, 48, request.relation_type);
    if let Some(event) = request.event {
        put_u64(packet, 56, event.local_id);
        put_u64(packet, 64, event.object_slot_plus_one);
        put_u64(packet, 72, event.object_generation);
    }
    Ok(())
}

fn header(packet: &[u8]) -> Result<SourcePnpRequest, WireError> {
    if packet.len() != PACKET_BYTES {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND || u32_at(packet, 4) != VERSION || u32_at(packet, 52) != 0
        || packet[108..].iter().any(|byte| *byte != 0)
    {
        return Err(WireError::Malformed);
    }
    let event = match (u64_at(packet, 56), u64_at(packet, 64), u64_at(packet, 72)) {
        (0, 0, 0) => None,
        (local_id, object_slot_plus_one, object_generation) => Some(EventIdentity {
            local_id,
            object_slot_plus_one,
            object_generation,
        }),
    };
    let request = SourcePnpRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        relation_type: u32_at(packet, 48),
        event,
    };
    if !valid_request(request) {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

pub fn decode_request(packet: &[u8]) -> Result<SourcePnpRequest, WireError> {
    let request = header(packet)?;
    if u64_at(packet, TOKEN_OFF) != 0
        || u32_at(packet, STATUS_OFF) != 0
        || u32_at(packet, 92) != 0
        || u64_at(packet, INFORMATION_OFF) != 0
        || u32_at(packet, COMPLETED_OFF) != 0
    {
        return Err(WireError::Malformed);
    }
    Ok(request)
}

pub fn publish_pending(packet: &mut [u8], token: u64) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0 {
        return Err(WireError::Malformed);
    }
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, STATUS_PENDING);
    Ok(())
}

pub fn publish_inline_terminal(
    packet: &mut [u8],
    token: u64,
    status: u32,
    information: u64,
) -> Result<(), WireError> {
    decode_request(packet)?;
    if token == 0
        || status == STATUS_PENDING
        || (status & 0x8000_0000 == 0 && information == 0)
        || (status & 0x8000_0000 != 0 && information != 0)
    {
        return Err(WireError::Malformed);
    }
    put_u64(packet, TOKEN_OFF, token);
    put_u32(packet, STATUS_OFF, status);
    put_u64(packet, INFORMATION_OFF, information);
    put_u32(packet, COMPLETED_OFF, 1);
    Ok(())
}

pub fn decode_response(packet: &[u8]) -> Result<SourcePnpResponse, WireError> {
    header(packet)?;
    let token = u64_at(packet, TOKEN_OFF);
    let status = u32_at(packet, STATUS_OFF);
    let information = u64_at(packet, INFORMATION_OFF);
    if token == 0 || u32_at(packet, 92) != 0 {
        return Err(WireError::Malformed);
    }
    match u32_at(packet, COMPLETED_OFF) {
        0 if status == STATUS_PENDING && information == 0 => {
            Ok(SourcePnpResponse::Pending { token })
        }
        1 if status != STATUS_PENDING
            && ((status & 0x8000_0000 == 0 && information != 0)
                || (status & 0x8000_0000 != 0 && information == 0)) =>
        {
            Ok(SourcePnpResponse::Inline { token, status, information })
        }
        _ => Err(WireError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SourcePnpRequest {
        SourcePnpRequest {
            nonce: 1,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            device_object_va: 0x2000,
            relation_type: nt_pnp_abi::TARGET_DEVICE_RELATION,
            event: Some(EventIdentity {
                local_id: 4,
                object_slot_plus_one: 5,
                object_generation: 6,
            }),
        }
    }

    #[test]
    fn request_and_retained_terminal_round_trip() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        assert_eq!(decode_request(&packet), Ok(request()));
        publish_inline_terminal(&mut packet, 7, 0, 0x3000).unwrap();
        assert_eq!(decode_response(&packet), Ok(SourcePnpResponse::Inline {
            token: 7, status: 0, information: 0x3000,
        }));
    }

    #[test]
    fn pending_requires_token_and_zero_information() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        publish_pending(&mut packet, 8).unwrap();
        assert_eq!(decode_response(&packet), Ok(SourcePnpResponse::Pending { token: 8 }));
        packet[INFORMATION_OFF] = 1;
        assert_eq!(decode_response(&packet), Err(WireError::Malformed));
    }

    #[test]
    fn rejects_unowned_success_and_forged_identity() {
        let mut packet = [0; PACKET_BYTES];
        encode_request(request(), &mut packet).unwrap();
        assert_eq!(publish_inline_terminal(&mut packet, 9, 0, 0), Err(WireError::Malformed));
        packet[24..32].fill(0);
        assert_eq!(decode_request(&packet), Err(WireError::Malformed));
    }
}
