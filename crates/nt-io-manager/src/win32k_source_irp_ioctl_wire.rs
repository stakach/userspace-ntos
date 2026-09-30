//! Bounded request wire for win32k file-less, kernel-built METHOD_BUFFERED IRPs.
//!
//! Every identity here is correlation data. The receiver must derive authority
//! from its physical provider lane and revalidate the live source IRP, device,
//! and optional Event before dispatch.

use nt_io_abi::ioctl;

pub const HEADER_BYTES: usize = 96;
pub const MAX_BUFFER_BYTES: u32 = 64 * 1024;
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + MAX_BUFFER_BYTES as usize;
const KIND: u32 = 1;
const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventIdentity {
    pub local_id: u64,
    pub object_slot_plus_one: u64,
    pub object_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceIrpIoctlRequest<'a> {
    pub nonce: u64,
    pub source_irp_va: u64,
    pub source_ticket_serial: u64,
    pub native_allocation_generation: u64,
    pub device_object_va: u64,
    pub code: u32,
    pub input: &'a [u8],
    pub output_capacity: u32,
    pub event: Option<EventIdentity>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall,
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

pub fn packet_len(input_len: u32, output_capacity: u32) -> Result<usize, WireError> {
    if input_len > MAX_BUFFER_BYTES || output_capacity > MAX_BUFFER_BYTES {
        return Err(WireError::LengthMismatch);
    }
    Ok(HEADER_BYTES + input_len as usize)
}

fn validate(request: &SourceIrpIoctlRequest<'_>) -> Result<(), WireError> {
    if request.nonce == 0
        || request.source_irp_va == 0
        || request.source_ticket_serial == 0
        || request.native_allocation_generation == 0
        || request.device_object_va == 0
        || ioctl::method(request.code) != ioctl::METHOD_BUFFERED
        || request.event.is_some_and(|event| {
            event.local_id == 0 || event.object_slot_plus_one == 0 || event.object_generation == 0
        })
    {
        return Err(WireError::Malformed);
    }
    Ok(())
}

pub fn encode_request(
    request: SourceIrpIoctlRequest<'_>,
    packet: &mut [u8],
) -> Result<(), WireError> {
    let input_len = u32::try_from(request.input.len()).map_err(|_| WireError::LengthMismatch)?;
    if packet.len() != packet_len(input_len, request.output_capacity)? {
        return Err(WireError::LengthMismatch);
    }
    validate(&request)?;
    packet.fill(0);
    put_u32(packet, 0, KIND);
    put_u32(packet, 4, VERSION);
    put_u64(packet, 8, request.nonce);
    put_u64(packet, 16, request.source_irp_va);
    put_u64(packet, 24, request.source_ticket_serial);
    put_u64(packet, 32, request.native_allocation_generation);
    put_u64(packet, 40, request.device_object_va);
    put_u32(packet, 48, request.code);
    put_u32(packet, 52, input_len);
    put_u32(packet, 56, request.output_capacity);
    if let Some(event) = request.event {
        put_u64(packet, 64, event.local_id);
        put_u64(packet, 72, event.object_slot_plus_one);
        put_u64(packet, 80, event.object_generation);
    }
    packet[HEADER_BYTES..].copy_from_slice(request.input);
    Ok(())
}

pub fn decode_request(packet: &[u8]) -> Result<SourceIrpIoctlRequest<'_>, WireError> {
    if packet.len() < HEADER_BYTES {
        return Err(WireError::BufferTooSmall);
    }
    let input_len = u32_at(packet, 52);
    let output_capacity = u32_at(packet, 56);
    if packet.len() != packet_len(input_len, output_capacity)? {
        return Err(WireError::LengthMismatch);
    }
    if u32_at(packet, 0) != KIND
        || u32_at(packet, 4) != VERSION
        || u32_at(packet, 60) != 0
        || u64_at(packet, 88) != 0
    {
        return Err(WireError::Malformed);
    }
    let event = match (u64_at(packet, 64), u64_at(packet, 72), u64_at(packet, 80)) {
        (0, 0, 0) => None,
        (local_id, object_slot_plus_one, object_generation) => Some(EventIdentity {
            local_id,
            object_slot_plus_one,
            object_generation,
        }),
    };
    let request = SourceIrpIoctlRequest {
        nonce: u64_at(packet, 8),
        source_irp_va: u64_at(packet, 16),
        source_ticket_serial: u64_at(packet, 24),
        native_allocation_generation: u64_at(packet, 32),
        device_object_va: u64_at(packet, 40),
        code: u32_at(packet, 48),
        input: &packet[HEADER_BYTES..],
        output_capacity,
        event,
    };
    validate(&request)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(input: &'a [u8]) -> SourceIrpIoctlRequest<'a> {
        SourceIrpIoctlRequest {
            nonce: 1,
            source_irp_va: 0x1000,
            source_ticket_serial: 2,
            native_allocation_generation: 3,
            device_object_va: 0x2000,
            code: ioctl::ctl_code(0x22, 0x800, ioctl::METHOD_BUFFERED, ioctl::FILE_ANY_ACCESS),
            input,
            output_capacity: 16,
            event: None,
        }
    }

    #[test]
    fn round_trip_with_and_without_event() {
        for event in [
            None,
            Some(EventIdentity {
                local_id: 4,
                object_slot_plus_one: 5,
                object_generation: 6,
            }),
        ] {
            let mut expected = request(b"abc");
            expected.event = event;
            let mut packet = [0xff; HEADER_BYTES + 3];
            encode_request(expected, &mut packet).unwrap();
            assert_eq!(decode_request(&packet), Ok(expected));
            assert_eq!(u32_at(&packet, 60), 0);
            assert_eq!(u64_at(&packet, 88), 0);
        }
    }

    #[test]
    fn refuses_malformed_identity_or_header() {
        let mut packet = [0; HEADER_BYTES];
        encode_request(request(b""), &mut packet).unwrap();
        for offset in [8, 16, 24, 32, 40] {
            let mut bad = packet;
            bad[offset..offset + 8].fill(0);
            assert_eq!(
                decode_request(&bad),
                Err(WireError::Malformed),
                "offset {offset}"
            );
        }
        for offset in [0, 4, 60, 64, 72, 80, 88] {
            let mut bad = packet;
            bad[offset] ^= 1;
            assert_eq!(
                decode_request(&bad),
                Err(WireError::Malformed),
                "offset {offset}"
            );
        }
        let mut bad = packet;
        bad[48] |= 1;
        assert_eq!(decode_request(&bad), Err(WireError::Malformed));
    }

    #[test]
    fn bounds_and_exact_length() {
        assert_eq!(
            packet_len(MAX_BUFFER_BYTES + 1, 0),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            packet_len(0, MAX_BUFFER_BYTES + 1),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            decode_request(&[0; HEADER_BYTES - 1]),
            Err(WireError::BufferTooSmall)
        );
        let mut packet = [0; HEADER_BYTES + 1];
        encode_request(request(b"x"), &mut packet).unwrap();
        assert_eq!(
            decode_request(&packet[..HEADER_BYTES]),
            Err(WireError::LengthMismatch)
        );
        assert_eq!(
            decode_request(&[&packet[..], &[0]].concat()),
            Err(WireError::LengthMismatch)
        );
    }
}
