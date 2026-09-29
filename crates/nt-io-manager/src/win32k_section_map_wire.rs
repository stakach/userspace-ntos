//! Pointer-free, versioned win32k `ZwMapViewOfSection` request.

pub const PACKET_BYTES: usize = 88;
const MAGIC: u32 = u32::from_le_bytes(*b"WMAP");
const VERSION: u16 = 1;
const OFFSET_PRESENT: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectionMapRequest {
    pub section_handle: u64,
    pub process_handle: u64,
    pub base_address: u64,
    pub zero_bits: u64,
    pub commit_size: u64,
    pub section_offset: Option<u64>,
    pub view_size: u64,
    pub inherit_disposition: u32,
    pub allocation_type: u32,
    pub win32_protect: u32,
}

impl SectionMapRequest {
    pub const fn is_supported_reactos_shape(self) -> bool {
        self.process_handle == u64::MAX
            && self.zero_bits == 0
            && self.commit_size == 0
            && self.inherit_disposition == 1
            && self.allocation_type == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionMapWireError {
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

pub fn encode(request: SectionMapRequest, packet: &mut [u8]) -> Result<(), SectionMapWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionMapWireError::Length);
    }
    packet.fill(0);
    packet[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    packet[4..6].copy_from_slice(&VERSION.to_le_bytes());
    packet[6..8].copy_from_slice(&(PACKET_BYTES as u16).to_le_bytes());
    packet[8..12].copy_from_slice(&(PACKET_BYTES as u32).to_le_bytes());
    packet[12..16].copy_from_slice(
        &(u32::from(request.section_offset.is_some()) * OFFSET_PRESENT).to_le_bytes(),
    );
    packet[16..24].copy_from_slice(&request.section_handle.to_le_bytes());
    packet[24..32].copy_from_slice(&request.process_handle.to_le_bytes());
    packet[32..40].copy_from_slice(&request.base_address.to_le_bytes());
    packet[40..48].copy_from_slice(&request.zero_bits.to_le_bytes());
    packet[48..56].copy_from_slice(&request.commit_size.to_le_bytes());
    packet[56..64].copy_from_slice(&request.section_offset.unwrap_or(0).to_le_bytes());
    packet[64..72].copy_from_slice(&request.view_size.to_le_bytes());
    packet[72..76].copy_from_slice(&request.inherit_disposition.to_le_bytes());
    packet[76..80].copy_from_slice(&request.allocation_type.to_le_bytes());
    packet[80..84].copy_from_slice(&request.win32_protect.to_le_bytes());
    Ok(())
}

pub fn decode(packet: &[u8]) -> Result<SectionMapRequest, SectionMapWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionMapWireError::Length);
    }
    if u32_at(packet, 0) != MAGIC {
        return Err(SectionMapWireError::Malformed);
    }
    if u16_at(packet, 4) != VERSION {
        return Err(SectionMapWireError::UnsupportedVersion);
    }
    if u16_at(packet, 6) as usize != PACKET_BYTES || u32_at(packet, 8) as usize != PACKET_BYTES {
        return Err(SectionMapWireError::Length);
    }
    let flags = u32_at(packet, 12);
    if flags & !OFFSET_PRESENT != 0
        || (flags & OFFSET_PRESENT == 0 && u64_at(packet, 56) != 0)
        || u32_at(packet, 84) != 0
    {
        return Err(SectionMapWireError::Malformed);
    }
    Ok(SectionMapRequest {
        section_handle: u64_at(packet, 16),
        process_handle: u64_at(packet, 24),
        base_address: u64_at(packet, 32),
        zero_bits: u64_at(packet, 40),
        commit_size: u64_at(packet, 48),
        section_offset: (flags & OFFSET_PRESENT != 0).then(|| u64_at(packet, 56)),
        view_size: u64_at(packet, 64),
        inherit_disposition: u32_at(packet, 72),
        allocation_type: u32_at(packet, 76),
        win32_protect: u32_at(packet, 80),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SectionMapRequest {
        SectionMapRequest {
            section_handle: 0xffff_ffff_8000_0040,
            process_handle: u64::MAX,
            base_address: 0,
            zero_bits: 0,
            commit_size: 0x3000,
            section_offset: None,
            view_size: 0x4000,
            inherit_disposition: 1,
            allocation_type: 0,
            win32_protect: 4,
        }
    }

    #[test]
    fn supported_reactos_shape_is_narrow_and_explicit() {
        let mut input = request();
        input.commit_size = 0;
        assert!(input.is_supported_reactos_shape());
        input.process_handle = 4;
        assert!(!input.is_supported_reactos_shape());
        input.process_handle = u64::MAX;
        input.zero_bits = 1;
        assert!(!input.is_supported_reactos_shape());
        input.zero_bits = 0;
        input.commit_size = 1;
        assert!(!input.is_supported_reactos_shape());
        input.commit_size = 0;
        input.inherit_disposition = 2;
        assert!(!input.is_supported_reactos_shape());
        input.inherit_disposition = 1;
        input.allocation_type = 1;
        assert!(!input.is_supported_reactos_shape());
    }

    #[test]
    fn all_native_arguments_roundtrip_without_pointers() {
        let mut packet = [0; PACKET_BYTES];
        let input = request();
        encode(input, &mut packet).unwrap();
        assert_eq!(decode(&packet), Ok(input));
        assert_eq!(&packet[0..4], b"WMAP");
        assert_eq!(u32_at(&packet, 12), 0);
    }

    #[test]
    fn present_zero_offset_is_distinct_from_absent() {
        let mut packet = [0; PACKET_BYTES];
        let mut input = request();
        input.section_offset = Some(0);
        encode(input, &mut packet).unwrap();
        assert_eq!(u32_at(&packet, 12), OFFSET_PRESENT);
        assert_eq!(decode(&packet), Ok(input));
    }

    #[test]
    fn full_width_values_roundtrip() {
        let mut packet = [0; PACKET_BYTES];
        let input = SectionMapRequest {
            section_handle: u64::MAX,
            process_handle: u64::MAX,
            base_address: u64::MAX,
            zero_bits: u64::MAX,
            commit_size: u64::MAX,
            section_offset: Some(u64::MAX),
            view_size: u64::MAX,
            inherit_disposition: u32::MAX,
            allocation_type: u32::MAX,
            win32_protect: u32::MAX,
        };
        encode(input, &mut packet).unwrap();
        assert_eq!(decode(&packet), Ok(input));
    }

    #[test]
    fn malformed_header_flags_offset_and_reserved_tail_are_rejected() {
        let mut packet = [0; PACKET_BYTES];
        encode(request(), &mut packet).unwrap();
        assert_eq!(
            decode(&packet[..PACKET_BYTES - 1]),
            Err(SectionMapWireError::Length)
        );
        assert_eq!(
            encode(request(), &mut packet[..PACKET_BYTES - 1]),
            Err(SectionMapWireError::Length)
        );
        for (offset, bytes, error) in [
            (0, &b"FAIL"[..], SectionMapWireError::Malformed),
            (4, &[2, 0][..], SectionMapWireError::UnsupportedVersion),
            (6, &[87, 0][..], SectionMapWireError::Length),
            (8, &[89, 0, 0, 0][..], SectionMapWireError::Length),
            (12, &[2, 0, 0, 0][..], SectionMapWireError::Malformed),
            (
                56,
                &[1, 0, 0, 0, 0, 0, 0, 0][..],
                SectionMapWireError::Malformed,
            ),
            (84, &[1, 0, 0, 0][..], SectionMapWireError::Malformed),
        ] {
            let mut changed = packet;
            changed[offset..offset + bytes.len()].copy_from_slice(bytes);
            assert_eq!(decode(&changed), Err(error));
        }
    }
}
