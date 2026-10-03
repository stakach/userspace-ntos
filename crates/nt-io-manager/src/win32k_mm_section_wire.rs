//! Captured eight-argument `MmCreateSection` request. Addresses name projections;
//! the authenticated broker must validate their exact ownership before use.

use crate::win32k_section_create_wire::{self as base_wire, SectionCreateRequest, SectionCreateWireError};

pub const PACKET_BYTES: usize = 72;
pub const OP_CREATE_OBJECT: u64 = 5;
pub const OP_REFERENCE: u64 = 6;
pub const OP_DEREFERENCE: u64 = 7;
pub const OP_MAP: u64 = 8;
pub const OP_UNMAP: u64 = 9;
const HEADER_BYTES: usize = 16;
const FILE_OBJECT_OFFSET: usize = HEADER_BYTES + base_wire::PACKET_BYTES;
const MAGIC: u32 = u32::from_le_bytes(*b"WMSC");
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmSectionCreateRequest {
    pub base: SectionCreateRequest,
    pub file_object: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionFileSource {
    Anonymous,
    Handle(u64),
    Object(u64),
}

impl MmSectionCreateRequest {
    /// NT prefers the supplied FileObject. Selecting it does not resolve or validate
    /// the ignored FileHandle; the broker must reference the selected source exactly.
    pub const fn file_source(self) -> SectionFileSource {
        if self.file_object != 0 {
            SectionFileSource::Object(self.file_object)
        } else if self.base.file_handle != 0 {
            SectionFileSource::Handle(self.base.file_handle)
        } else {
            SectionFileSource::Anonymous
        }
    }
}

pub fn encode(
    request: MmSectionCreateRequest,
    packet: &mut [u8],
) -> Result<(), SectionCreateWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionCreateWireError::Length);
    }
    packet.fill(0);
    packet[..4].copy_from_slice(&MAGIC.to_le_bytes());
    packet[4..6].copy_from_slice(&VERSION.to_le_bytes());
    packet[6..8].copy_from_slice(&(PACKET_BYTES as u16).to_le_bytes());
    packet[8..12].copy_from_slice(&(PACKET_BYTES as u32).to_le_bytes());
    base_wire::encode(request.base, &mut packet[HEADER_BYTES..FILE_OBJECT_OFFSET])?;
    packet[FILE_OBJECT_OFFSET..PACKET_BYTES].copy_from_slice(&request.file_object.to_le_bytes());
    Ok(())
}

pub fn decode(packet: &[u8]) -> Result<MmSectionCreateRequest, SectionCreateWireError> {
    if packet.len() != PACKET_BYTES {
        return Err(SectionCreateWireError::Length);
    }
    if u32::from_le_bytes(packet[..4].try_into().unwrap()) != MAGIC {
        return Err(SectionCreateWireError::Malformed);
    }
    if u16::from_le_bytes(packet[4..6].try_into().unwrap()) != VERSION {
        return Err(SectionCreateWireError::UnsupportedVersion);
    }
    if u16::from_le_bytes(packet[6..8].try_into().unwrap()) as usize != PACKET_BYTES
        || u32::from_le_bytes(packet[8..12].try_into().unwrap()) as usize != PACKET_BYTES
    {
        return Err(SectionCreateWireError::Length);
    }
    if packet[12..HEADER_BYTES] != [0; 4] {
        return Err(SectionCreateWireError::Malformed);
    }
    Ok(MmSectionCreateRequest {
        base: base_wire::decode(&packet[HEADER_BYTES..FILE_OBJECT_OFFSET])?,
        file_object: u64::from_le_bytes(packet[FILE_OBJECT_OFFSET..PACKET_BYTES].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32k_section_create_wire::{SectionCreateRequest, SectionCreateWireError};

    fn font_request() -> MmSectionCreateRequest {
        MmSectionCreateRequest {
            base: SectionCreateRequest {
                desired_access: 0x000f_0005,
                object_attributes: None,
                maximum_size: Some(0),
                page_protection: 2,
                allocation_attributes: 0x0800_0000,
                file_handle: 0xffff_ffff_8000_0040,
            },
            file_object: 0x100_1234_5000,
        }
    }

    #[test]
    fn full_mm_create_section_values_roundtrip_in_a_distinct_fixed_packet() {
        assert_eq!(PACKET_BYTES, 72);
        let request = font_request();
        let mut packet = [0xff; PACKET_BYTES];
        encode(request, &mut packet).unwrap();
        assert_eq!(&packet[..4], b"WMSC");
        assert_eq!(&packet[4..6], &1u16.to_le_bytes());
        assert_eq!(&packet[12..16], &[0; 4]);
        assert_eq!(&packet[16..20], b"WSEC");
        assert_eq!(&packet[64..72], &request.file_object.to_le_bytes());
        assert_eq!(decode(&packet), Ok(request));
    }

    #[test]
    fn supplied_file_object_precedes_even_an_invalid_file_handle() {
        let mut request = font_request();
        request.base.file_handle = u64::MAX;
        assert_eq!(request.file_source(), SectionFileSource::Object(request.file_object));
        let mut packet = [0; PACKET_BYTES];
        encode(request, &mut packet).unwrap();
        let decoded = decode(&packet).unwrap();
        assert_eq!(decoded.base.file_handle, u64::MAX,
            "wire capture must not resolve, discard, or rewrite an ignored handle");
        assert_eq!(decoded.file_source(), SectionFileSource::Object(request.file_object));
        request.file_object = 0;
        assert_eq!(request.file_source(), SectionFileSource::Handle(u64::MAX));
        request.base.file_handle = 0;
        assert_eq!(request.file_source(), SectionFileSource::Anonymous);
    }

    #[test]
    fn absent_fields_and_present_zero_remain_distinct() {
        let mut request = font_request();
        for attributes in [None, Some(0), Some(0x240)] {
            for maximum_size in [None, Some(0), Some(0x12345)] {
                request.base.object_attributes = attributes;
                request.base.maximum_size = maximum_size;
                let mut packet = [0; PACKET_BYTES];
                encode(request, &mut packet).unwrap();
                assert_eq!(decode(&packet), Ok(request));
            }
        }
    }

    #[test]
    fn outer_and_embedded_lengths_versions_reserved_fields_are_strict() {
        let mut packet = [0; PACKET_BYTES];
        encode(font_request(), &mut packet).unwrap();
        assert_eq!(decode(&packet[..PACKET_BYTES - 1]), Err(SectionCreateWireError::Length));
        assert_eq!(decode(&[0; PACKET_BYTES + 1]), Err(SectionCreateWireError::Length));
        assert_eq!(encode(font_request(), &mut [0; PACKET_BYTES - 1]), Err(SectionCreateWireError::Length));
        for (offset, bytes, error) in [
            (0, &b"FAIL"[..], SectionCreateWireError::Malformed),
            (4, &[2, 0][..], SectionCreateWireError::UnsupportedVersion),
            (6, &[71, 0][..], SectionCreateWireError::Length),
            (8, &[73, 0, 0, 0][..], SectionCreateWireError::Length),
            (12, &[1, 0, 0, 0][..], SectionCreateWireError::Malformed),
            (20, &[2, 0][..], SectionCreateWireError::UnsupportedVersion),
            (22, &[47, 0][..], SectionCreateWireError::Length),
            (28, &[4, 0, 0, 0][..], SectionCreateWireError::Malformed),
            (36, &[1, 0, 0, 0][..], SectionCreateWireError::Malformed),
        ] {
            let mut changed = packet;
            changed[offset..offset + bytes.len()].copy_from_slice(bytes);
            assert_eq!(decode(&changed), Err(error), "invalid field at {offset}");
        }
    }
}
