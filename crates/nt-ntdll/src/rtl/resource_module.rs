//! Module handles as the resource APIs receive them.
//!
//! `LoadLibraryExW(..., LOAD_LIBRARY_AS_DATAFILE)` maps the file as flat data and returns its
//! base with bit 0 set; `LOAD_LIBRARY_AS_IMAGE_RESOURCE` maps it as an image and sets bit 1.
//! ReactOS `RtlImageDirectoryEntryToData` and `LdrpAccessResource` (`sdk/lib/rtl/image.c`,
//! `sdk/lib/rtl/res.c`) treat a bit-0 handle as "not mapped as image": every RVA is translated
//! through the section table to a file offset instead of being added to the base.

/// `LDR_IS_DATAFILE`.
pub const LDR_IS_DATAFILE: usize = 1;
/// `LDR_IS_IMAGEMAPPING`.
pub const LDR_IS_IMAGEMAPPING: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceModule {
    /// Address of the mapping, with the tag bits removed.
    pub base: usize,
    /// Whether the mapping has the image layout (sections at their RVAs) rather than the
    /// file's own layout.
    pub mapped_as_image: bool,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u32::from(u16::from_le_bytes([field[0], field[1]])))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

impl ResourceModule {
    pub fn from_handle(handle: usize) -> Self {
        Self {
            base: handle & !(LDR_IS_DATAFILE | LDR_IS_IMAGEMAPPING),
            mapped_as_image: handle & LDR_IS_DATAFILE == 0,
        }
    }

    /// Offset from `base` of the `size` bytes at `rva`, or `None` when the image does not hold
    /// that span. `headers` are the module's first `SizeOfHeaders` bytes; PE32 and PE32+ images
    /// keep the fields used here at the same offsets.
    pub fn span_offset(&self, headers: &[u8], rva: u32, size: u32) -> Option<usize> {
        let nt = u32_at(headers, 0x3c)? as usize;
        if u16_at(headers, 0)? != 0x5a4d || u32_at(headers, nt)? != 0x0000_4550 {
            return None;
        }
        let optional = nt.checked_add(24)?;
        let end = rva.checked_add(size)?;
        if self.mapped_as_image {
            let size_of_image = u32_at(headers, optional.checked_add(56)?)?;
            return super::image::image_span_is_valid(size_of_image, rva, size)
                .then_some(rva as usize);
        }
        // `RtlImageRvaToVa`: header bytes keep their offset; anything else lies in the raw
        // data of the section that covers it.
        if end <= u32_at(headers, optional.checked_add(60)?)? {
            return Some(rva as usize);
        }
        let sections = optional.checked_add(u16_at(headers, nt + 20)? as usize)?;
        for index in 0..u16_at(headers, nt + 6)? as usize {
            let section = sections.checked_add(index.checked_mul(40)?)?;
            let virtual_address = u32_at(headers, section + 12)?;
            let raw_size = u32_at(headers, section + 16)?;
            let raw_offset = u32_at(headers, section + 20)?;
            let Some(delta) = rva.checked_sub(virtual_address) else {
                continue;
            };
            if delta <= raw_size && size <= raw_size - delta {
                return (raw_offset as usize).checked_add(delta as usize);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::super::pe_resource::{self, ResName};
    use super::*;

    const RESOURCE_RVA: u32 = 0x3000;
    const RESOURCE_FILE_OFFSET: usize = 0x200;
    const PAYLOAD: &[u8] = b"MSFT typelib bytes";

    fn put<const N: usize>(bytes: &mut [u8], offset: usize, value: [u8; N]) {
        bytes[offset..offset + N].copy_from_slice(&value);
    }

    /// A PE32+ file whose only section is `.rsrc` (RVA 0x3000, file offset 0x200) holding one
    /// resource of the named type `TYPELIB`, id 1, language 0 -- the shape oleaut32 looks up in
    /// a type-library container loaded as a data file.
    fn typelib_container() -> Vec<u8> {
        const NT: usize = 0x40;
        const OPTIONAL: usize = NT + 24;
        const SECTIONS: usize = OPTIONAL + 240;
        let mut file = vec![0u8; RESOURCE_FILE_OFFSET + 0x200];
        put(&mut file, 0, 0x5a4du16.to_le_bytes());
        put(&mut file, 0x3c, (NT as u32).to_le_bytes());
        put(&mut file, NT, 0x0000_4550u32.to_le_bytes());
        put(&mut file, NT + 4, 0x8664u16.to_le_bytes());
        put(&mut file, NT + 6, 1u16.to_le_bytes());
        put(&mut file, NT + 20, 240u16.to_le_bytes());
        put(&mut file, NT + 22, 0x2002u16.to_le_bytes());
        put(&mut file, OPTIONAL, 0x020bu16.to_le_bytes());
        put(&mut file, OPTIONAL + 24, 0x1_8000_0000u64.to_le_bytes());
        put(&mut file, OPTIONAL + 32, 0x1000u32.to_le_bytes());
        put(&mut file, OPTIONAL + 36, 0x200u32.to_le_bytes());
        put(&mut file, OPTIONAL + 56, 0x4000u32.to_le_bytes());
        put(&mut file, OPTIONAL + 60, 0x200u32.to_le_bytes());
        put(&mut file, OPTIONAL + 108, 16u32.to_le_bytes());
        put(&mut file, OPTIONAL + 112 + 2 * 8, RESOURCE_RVA.to_le_bytes());
        put(&mut file, OPTIONAL + 112 + 2 * 8 + 4, 0x200u32.to_le_bytes());
        put(&mut file, SECTIONS, *b".rsrc\0\0\0");
        put(&mut file, SECTIONS + 8, 0x200u32.to_le_bytes());
        put(&mut file, SECTIONS + 12, RESOURCE_RVA.to_le_bytes());
        put(&mut file, SECTIONS + 16, 0x200u32.to_le_bytes());
        put(&mut file, SECTIONS + 20, (RESOURCE_FILE_OFFSET as u32).to_le_bytes());
        put(&mut file, SECTIONS + 36, 0x4000_0040u32.to_le_bytes());

        let root = RESOURCE_FILE_OFFSET;
        // Type directory: one named entry "TYPELIB" -> name directory at 0x18.
        put(&mut file, root + 12, 1u16.to_le_bytes());
        put(&mut file, root + 16, 0x8000_0060u32.to_le_bytes());
        put(&mut file, root + 20, 0x8000_0018u32.to_le_bytes());
        // Name directory: id 1 -> language directory at 0x30.
        put(&mut file, root + 0x18 + 14, 1u16.to_le_bytes());
        put(&mut file, root + 0x28, 1u32.to_le_bytes());
        put(&mut file, root + 0x2c, 0x8000_0030u32.to_le_bytes());
        // Language directory: language 0 -> data entry at 0x48.
        put(&mut file, root + 0x30 + 14, 1u16.to_le_bytes());
        put(&mut file, root + 0x40, 0u32.to_le_bytes());
        put(&mut file, root + 0x44, 0x48u32.to_le_bytes());
        put(&mut file, root + 0x48, (RESOURCE_RVA + 0x80).to_le_bytes());
        put(&mut file, root + 0x4c, (PAYLOAD.len() as u32).to_le_bytes());
        let name: Vec<u16> = "TYPELIB".encode_utf16().collect();
        put(&mut file, root + 0x60, (name.len() as u16).to_le_bytes());
        for (index, unit) in name.iter().enumerate() {
            put(&mut file, root + 0x62 + index * 2, unit.to_le_bytes());
        }
        file[root + 0x80..root + 0x80 + PAYLOAD.len()].copy_from_slice(PAYLOAD);
        file
    }

    #[test]
    fn handle_tags_select_the_mapping_layout() {
        assert_eq!(
            ResourceModule::from_handle(0x7ff0_0000),
            ResourceModule { base: 0x7ff0_0000, mapped_as_image: true }
        );
        assert_eq!(
            ResourceModule::from_handle(0x7ff0_0001),
            ResourceModule { base: 0x7ff0_0000, mapped_as_image: false }
        );
        assert_eq!(
            ResourceModule::from_handle(0x7ff0_0002),
            ResourceModule { base: 0x7ff0_0000, mapped_as_image: true }
        );
    }

    #[test]
    fn typelib_resource_of_a_data_file_module_is_read_at_its_file_offset() {
        // `FindResourceW(LoadLibraryExW(path, 0, LOAD_LIBRARY_AS_DATAFILE), 1, L"TYPELIB")`,
        // then `LoadResource`: the mapping is the file itself.
        let file = typelib_container();
        let headers = &file[..0x200];
        let module = ResourceModule::from_handle(0x1000_0001);
        assert!(!module.mapped_as_image);

        let directory = module.span_offset(headers, RESOURCE_RVA, 0x200).unwrap();
        assert_eq!(directory, RESOURCE_FILE_OFFSET);
        let rsrc = &file[directory..directory + 0x200];
        let typelib: Vec<u16> = "TYPELIB".encode_utf16().collect();
        let found = pe_resource::find_entry(
            rsrc,
            &ResName::Name(&typelib),
            &ResName::Id(1),
            &[0, 0x409],
            true,
            3,
            false,
        )
        .unwrap();
        let (data_rva, size) = pe_resource::data_entry(rsrc, found.offset).unwrap();
        let data = module.span_offset(headers, data_rva, size).unwrap();
        assert_eq!(&file[data..data + size as usize], PAYLOAD);

        // The image layout would place the same resource past the end of the file mapping.
        let image = ResourceModule::from_handle(0x1000_0000);
        assert_eq!(image.span_offset(headers, data_rva, size), Some(data_rva as usize));
        assert!(data_rva as usize > file.len());
    }

    #[test]
    fn spans_outside_the_image_are_refused_in_either_layout() {
        let file = typelib_container();
        let headers = &file[..0x200];
        let data_file = ResourceModule::from_handle(1);
        // Past the section's raw data, in a gap between sections, and overflowing.
        assert_eq!(data_file.span_offset(headers, RESOURCE_RVA + 0x1f0, 0x20), None);
        assert_eq!(data_file.span_offset(headers, 0x1000, 4), None);
        assert_eq!(data_file.span_offset(headers, u32::MAX, 2), None);
        // Header bytes keep their offset.
        assert_eq!(data_file.span_offset(headers, 0x40, 4), Some(0x40));
        let image = ResourceModule::from_handle(0);
        assert_eq!(image.span_offset(headers, 0x3ff0, 0x20), None);
        assert_eq!(image.span_offset(&headers[..0x40], 0x3000, 4), None);
    }
}
