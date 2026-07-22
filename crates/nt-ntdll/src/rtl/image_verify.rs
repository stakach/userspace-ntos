//! Checked raw-PE verification for `LdrVerifyImageMatchesChecksum`.

use alloc::vec::Vec;

use nt_pe_loader::PeFile;

/// Matches the loader's maximum supported mapped image size.
pub const MAX_IMAGE_FILE_BYTES: usize = 256 * 1024 * 1024;

const CHECKSUM_OFFSET_IN_OPTIONAL_HEADER: usize = 64;
const OPTIONAL_HEADER_OFFSET_FROM_NT_HEADER: usize = 24;
const MAX_IMPORT_DESCRIPTORS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageVerificationError {
    MalformedImage,
    ChecksumMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedImage<'a> {
    pub characteristics: u16,
    /// Borrowed import module names in descriptor order. Each slice is followed by a NUL in the
    /// source image, as required by `LDR_IMPORT_MODULE_CALLBACK`.
    pub import_names: Vec<&'a [u8]>,
    pub stored_checksum: u32,
    pub calculated_checksum: u32,
}

fn u32_from(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn calculate_checksum(image: &[u8], checksum_offset: usize) -> Option<u32> {
    if image.len() > u32::MAX as usize
        || checksum_offset & 1 != 0
        || checksum_offset.checked_add(4)? > image.len()
    {
        return None;
    }

    let mut sum = 0u64;
    for (index, chunk) in image.chunks(2).enumerate() {
        let offset = index * 2;
        let word = if offset == checksum_offset || offset == checksum_offset + 2 {
            0
        } else if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            chunk[0] as u16
        };
        sum += word as u64;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    Some((sum as u32).wrapping_add(image.len() as u32))
}

/// Parse a raw PE32+ image, verify its standard PE checksum, and collect its import module names.
/// A stored checksum of zero is accepted, matching the Windows loader contract. `bypass_checksum`
/// implements the low-bit KnownDLL handle tag but does not bypass structural validation.
pub fn verify_image(
    image: &[u8],
    bypass_checksum: bool,
    enumerate_imports: bool,
) -> Result<VerifiedImage<'_>, ImageVerificationError> {
    if image.len() > MAX_IMAGE_FILE_BYTES {
        return Err(ImageVerificationError::MalformedImage);
    }
    let pe = PeFile::parse(image).map_err(|_| ImageVerificationError::MalformedImage)?;
    let checksum_offset = pe
        .headers()
        .nt_offset
        .checked_add(OPTIONAL_HEADER_OFFSET_FROM_NT_HEADER)
        .and_then(|offset| offset.checked_add(CHECKSUM_OFFSET_IN_OPTIONAL_HEADER))
        .ok_or(ImageVerificationError::MalformedImage)?;
    let stored_checksum = image
        .get(checksum_offset..checksum_offset + 4)
        .and_then(u32_from)
        .ok_or(ImageVerificationError::MalformedImage)?;
    let calculated_checksum =
        calculate_checksum(image, checksum_offset).ok_or(ImageVerificationError::MalformedImage)?;
    if !bypass_checksum && stored_checksum != 0 && stored_checksum != calculated_checksum {
        return Err(ImageVerificationError::ChecksumMismatch);
    }

    let directory = pe.headers().data_directory(1);
    let mut import_names = Vec::new();
    if enumerate_imports && directory.virtual_address != 0 && directory.size != 0 {
        let mut descriptor_rva = directory.virtual_address;
        let mut terminated = false;
        for _ in 0..MAX_IMPORT_DESCRIPTORS {
            let descriptor = pe
                .bytes_at_rva(descriptor_rva, 20)
                .ok_or(ImageVerificationError::MalformedImage)?;
            let name_rva =
                u32_from(&descriptor[12..16]).ok_or(ImageVerificationError::MalformedImage)?;
            if name_rva == 0 {
                terminated = true;
                break;
            }
            import_names.push(
                pe.cstr_bytes_at_rva(name_rva)
                    .map_err(|_| ImageVerificationError::MalformedImage)?,
            );
            descriptor_rva = descriptor_rva
                .checked_add(20)
                .ok_or(ImageVerificationError::MalformedImage)?;
        }
        if !terminated {
            return Err(ImageVerificationError::MalformedImage);
        }
    }

    Ok(VerifiedImage {
        characteristics: pe.headers().characteristics,
        import_names,
        stored_checksum,
        calculated_checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const NT_OFFSET: usize = 0x80;
    const OPTIONAL_OFFSET: usize = NT_OFFSET + 24;
    const CHECKSUM_OFFSET: usize = OPTIONAL_OFFSET + 64;
    const RAW_OFFSET: usize = 0x200;
    const SECTION_RVA: u32 = 0x1000;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn test_image(imports: &[&[u8]]) -> Vec<u8> {
        let mut image = vec![0u8; 0x400];
        put_u16(&mut image, 0, 0x5a4d);
        put_u32(&mut image, 0x3c, NT_OFFSET as u32);
        put_u32(&mut image, NT_OFFSET, 0x0000_4550);
        put_u16(&mut image, NT_OFFSET + 4, 0x8664);
        put_u16(&mut image, NT_OFFSET + 6, 1);
        put_u16(&mut image, NT_OFFSET + 20, 0xf0);
        put_u16(&mut image, NT_OFFSET + 22, 0x2002); // EXECUTABLE_IMAGE | DLL
        put_u16(&mut image, OPTIONAL_OFFSET, 0x20b);
        put_u64(&mut image, OPTIONAL_OFFSET + 24, 0x1_4000_0000);
        put_u32(&mut image, OPTIONAL_OFFSET + 32, 0x1000);
        put_u32(&mut image, OPTIONAL_OFFSET + 36, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 56, 0x2000);
        put_u32(&mut image, OPTIONAL_OFFSET + 60, 0x200);
        put_u32(&mut image, OPTIONAL_OFFSET + 108, 16);
        if !imports.is_empty() {
            put_u32(&mut image, OPTIONAL_OFFSET + 120, SECTION_RVA);
            put_u32(
                &mut image,
                OPTIONAL_OFFSET + 124,
                ((imports.len() + 1) * 20) as u32,
            );
        }

        let section = OPTIONAL_OFFSET + 0xf0;
        image[section..section + 8].copy_from_slice(b".rdata\0\0");
        put_u32(&mut image, section + 8, 0x200);
        put_u32(&mut image, section + 12, SECTION_RVA);
        put_u32(&mut image, section + 16, 0x200);
        put_u32(&mut image, section + 20, RAW_OFFSET as u32);
        put_u32(&mut image, section + 36, 0x4000_0040);

        let mut name_offset = (imports.len() + 1) * 20;
        for (index, name) in imports.iter().enumerate() {
            put_u32(
                &mut image,
                RAW_OFFSET + index * 20 + 12,
                SECTION_RVA + name_offset as u32,
            );
            let raw_name = RAW_OFFSET + name_offset;
            image[raw_name..raw_name + name.len()].copy_from_slice(name);
            image[raw_name + name.len()] = 0;
            name_offset += name.len() + 1;
        }
        image
    }

    fn install_checksum(image: &mut [u8]) -> u32 {
        put_u32(image, CHECKSUM_OFFSET, 0);
        let checksum = calculate_checksum(image, CHECKSUM_OFFSET).unwrap();
        put_u32(image, CHECKSUM_OFFSET, checksum);
        checksum
    }

    #[test]
    fn accepts_zero_checksum_and_lists_imports_in_order() {
        let image = test_image(&[b"ntdll.dll", b"kernel32.dll"]);
        let verified = verify_image(&image, false, true).unwrap();
        assert_eq!(verified.characteristics, 0x2002);
        assert_eq!(verified.stored_checksum, 0);
        assert_eq!(
            verified.import_names,
            vec![b"ntdll.dll".as_slice(), b"kernel32.dll".as_slice()]
        );
    }

    #[test]
    fn accepts_valid_checksum_for_even_and_odd_file_lengths() {
        let mut even = test_image(&[]);
        let expected = install_checksum(&mut even);
        assert_eq!(
            verify_image(&even, false, false)
                .unwrap()
                .calculated_checksum,
            expected
        );

        let mut odd = test_image(&[]);
        odd.push(0x5a);
        let expected = install_checksum(&mut odd);
        assert_eq!(
            verify_image(&odd, false, false)
                .unwrap()
                .calculated_checksum,
            expected
        );
    }

    #[test]
    fn rejects_mismatch_but_knowndll_tag_bypasses_only_checksum() {
        let mut image = test_image(&[b"ntdll.dll"]);
        install_checksum(&mut image);
        image[RAW_OFFSET + 0x80] ^= 0x40;
        assert_eq!(
            verify_image(&image, false, true),
            Err(ImageVerificationError::ChecksumMismatch)
        );
        assert_eq!(
            verify_image(&image, true, true).unwrap().import_names,
            vec![b"ntdll.dll".as_slice()]
        );
    }

    #[test]
    fn bypass_does_not_accept_malformed_images_or_import_names() {
        assert_eq!(
            verify_image(b"not a PE", true, true),
            Err(ImageVerificationError::MalformedImage)
        );

        let mut image = test_image(&[b"ntdll.dll"]);
        let name_offset = RAW_OFFSET + 40;
        image[name_offset..].fill(b'x');
        assert_eq!(
            verify_image(&image, true, true),
            Err(ImageVerificationError::MalformedImage)
        );
    }

    #[test]
    fn rejects_truncated_advertised_optional_header() {
        let mut image = test_image(&[]);
        put_u16(&mut image, NT_OFFSET + 20, 2);
        assert_eq!(
            verify_image(&image, true, false),
            Err(ImageVerificationError::MalformedImage)
        );
    }

    #[test]
    fn accepts_header_resident_import_descriptors_and_names() {
        let mut image = test_image(&[]);
        const DESCRIPTOR_OFFSET: usize = 0x1c0;
        const NAME_OFFSET: usize = 0x1e8;
        put_u32(&mut image, OPTIONAL_OFFSET + 120, DESCRIPTOR_OFFSET as u32);
        put_u32(&mut image, OPTIONAL_OFFSET + 124, 40);
        put_u32(&mut image, DESCRIPTOR_OFFSET + 12, NAME_OFFSET as u32);
        image[NAME_OFFSET..NAME_OFFSET + 10].copy_from_slice(b"ntdll.dll\0");
        assert_eq!(
            verify_image(&image, true, true).unwrap().import_names,
            vec![b"ntdll.dll".as_slice()]
        );
    }

    #[test]
    fn checksum_math_excludes_field_and_folds_odd_byte() {
        let mut bytes = [1, 0, 0xff, 0xff, 0, 0, 0, 0, 2, 0, 3];
        assert_eq!(calculate_checksum(&bytes, 4), Some(17));
        bytes[4..8].copy_from_slice(&0xdead_beefu32.to_le_bytes());
        assert_eq!(calculate_checksum(&bytes, 4), Some(17));
    }
}
