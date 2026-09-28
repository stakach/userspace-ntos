//! Pointer-free, versioned win32k `ZwCreateSection` request.

pub const PACKET_BYTES: usize = 48;
const MAGIC: u32 = u32::from_le_bytes(*b"WSEC");
const VERSION: u16 = 1;
const OA_PRESENT: u32 = 1;
const MAX_SIZE_PRESENT: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionCreateRequest {
    pub desired_access: u32,
    pub object_attributes: Option<u32>,
    pub maximum_size: Option<u64>,
    pub page_protection: u32,
    pub allocation_attributes: u32,
    pub file_handle: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionCreateWireError {
    Length,
    Malformed,
    UnsupportedVersion,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn encode(
    request: SectionCreateRequest,
    packet: &mut [u8],
) -> Result<(), SectionCreateWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionCreateWireError::Length);
    }
    packet.fill(0);
    packet[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    packet[4..6].copy_from_slice(&VERSION.to_le_bytes());
    packet[6..8].copy_from_slice(&(PACKET_BYTES as u16).to_le_bytes());
    packet[8..12].copy_from_slice(&(PACKET_BYTES as u32).to_le_bytes());
    let flags = u32::from(request.object_attributes.is_some()) * OA_PRESENT
        | u32::from(request.maximum_size.is_some()) * MAX_SIZE_PRESENT;
    packet[12..16].copy_from_slice(&flags.to_le_bytes());
    packet[16..20].copy_from_slice(&request.desired_access.to_le_bytes());
    packet[20..24].copy_from_slice(&request.object_attributes.unwrap_or(0).to_le_bytes());
    packet[24..28].copy_from_slice(&request.page_protection.to_le_bytes());
    packet[28..32].copy_from_slice(&request.allocation_attributes.to_le_bytes());
    packet[32..40].copy_from_slice(&request.file_handle.to_le_bytes());
    packet[40..48].copy_from_slice(&request.maximum_size.unwrap_or(0).to_le_bytes());
    Ok(())
}

pub fn decode(packet: &[u8]) -> Result<SectionCreateRequest, SectionCreateWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionCreateWireError::Length);
    }
    if u32_at(packet, 0) != MAGIC {
        return Err(SectionCreateWireError::Malformed);
    }
    if u16_at(packet, 4) != VERSION {
        return Err(SectionCreateWireError::UnsupportedVersion);
    }
    if u16_at(packet, 6) as usize != PACKET_BYTES || u32_at(packet, 8) as usize != PACKET_BYTES {
        return Err(SectionCreateWireError::Length);
    }
    let flags = u32_at(packet, 12);
    if flags & !(OA_PRESENT | MAX_SIZE_PRESENT) != 0
        || (flags & OA_PRESENT == 0 && u32_at(packet, 20) != 0)
        || (flags & MAX_SIZE_PRESENT == 0 && u64_at(packet, 40) != 0)
    {
        return Err(SectionCreateWireError::Malformed);
    }
    Ok(SectionCreateRequest {
        desired_access: u32_at(packet, 16),
        object_attributes: (flags & OA_PRESENT != 0).then(|| u32_at(packet, 20)),
        page_protection: u32_at(packet, 24),
        allocation_attributes: u32_at(packet, 28),
        file_handle: u64_at(packet, 32),
        maximum_size: (flags & MAX_SIZE_PRESENT != 0).then(|| u64_at(packet, 40)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reactos_request() -> SectionCreateRequest {
        SectionCreateRequest {
            desired_access: 0xF0007,
            object_attributes: None,
            maximum_size: None,
            page_protection: 2,
            allocation_attributes: 0x0800_0000,
            file_handle: 0xFFFF_FFFF_8000_0040,
        }
    }

    #[test]
    fn reactos_request_roundtrips_without_pointer_fields() {
        let request = reactos_request();
        let mut packet = [0; PACKET_BYTES];
        encode(request, &mut packet).unwrap();
        assert_eq!(decode(&packet), Ok(request));
        assert_eq!(&packet[0..4], b"WSEC");
        assert_eq!(u32_at(&packet, 12), 0);
    }

    #[test]
    fn present_zero_is_distinct_from_absent() {
        let mut request = reactos_request();
        request.object_attributes = Some(0);
        request.maximum_size = Some(0);
        let mut packet = [0; PACKET_BYTES];
        encode(request, &mut packet).unwrap();
        assert_eq!(u32_at(&packet, 12), 3);
        assert_eq!(decode(&packet), Ok(request));
    }

    #[test]
    fn malformed_version_lengths_flags_and_absent_payloads_are_rejected() {
        let mut packet = [0; PACKET_BYTES];
        encode(reactos_request(), &mut packet).unwrap();
        assert_eq!(decode(&packet[..47]), Err(SectionCreateWireError::Length));
        for (offset, bytes, error) in [
            (0, &b"FAIL"[..], SectionCreateWireError::Malformed),
            (4, &[2, 0][..], SectionCreateWireError::UnsupportedVersion),
            (6, &[47, 0][..], SectionCreateWireError::Length),
            (8, &[49, 0, 0, 0][..], SectionCreateWireError::Length),
            (12, &[4, 0, 0, 0][..], SectionCreateWireError::Malformed),
            (20, &[1, 0, 0, 0][..], SectionCreateWireError::Malformed),
            (
                40,
                &[1, 0, 0, 0, 0, 0, 0, 0][..],
                SectionCreateWireError::Malformed,
            ),
        ] {
            let mut changed = packet;
            changed[offset..offset + bytes.len()].copy_from_slice(bytes);
            assert_eq!(decode(&changed), Err(error));
        }
    }
}
