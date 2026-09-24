//! Admission of the per-instance SEH linkage PE before hosted driver imports are resolved.

use crate::exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader};
use nt_pe_loader::{
    immutable_support_image, DataDirectory, ExportedSymbol, MappedImage, PeFile, Section,
    DIRECTORY_ENTRY_EXPORT,
};

const NAMES: [&str; 7] = [
    "SehCallFilter",
    "SehCallFinally",
    "SehExecuteHandlerForException",
    "SehExecuteHandlerForUnwind",
    "SehRaiseStatus",
    "SehResumeContext",
    "SehRaiseDispatch",
];
const RAISE_LEN: u32 = 0x12a;
const RESUME_LEN: u32 = 0xb4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SehLinkageImageError {
    InvalidImage,
    Exports,
    Forwarder,
    SectionRights,
    DispatchSlot,
    AddressOverflow,
    ExceptionMetadata,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SehLinkageImage {
    pub image_base: u64,
    pub raise_va: u64,
    pub resume_va: u64,
    pub dispatch_slot_rva: u32,
}

fn exact_function(
    result: Result<ExceptionFunction, ExceptionImageError>,
    pc: u64,
    image_base: u64,
) -> bool {
    let Some(expected_rva) = pc.checked_sub(image_base) else {
        return false;
    };
    matches!(result,
        Ok(ExceptionFunction::Function { image_base: found_base, function })
            if found_base == image_base && u64::from(function.begin) == expected_rva
    )
}

impl SehLinkageImage {
    /// Both entry PCs must start real runtime-function rows in this exact admitted image.
    pub fn validate_catalog(
        &self,
        catalog: &dyn ExceptionImageReader,
    ) -> Result<(), SehLinkageImageError> {
        for pc in [self.raise_va, self.resume_va] {
            if !exact_function(catalog.lookup_exception_function(pc), pc, self.image_base) {
                return Err(SehLinkageImageError::ExceptionMetadata);
            }
        }
        Ok(())
    }
}

fn section_covers(section: &Section, rva: u32, length: u32) -> bool {
    let Some(end) = rva.checked_add(length) else {
        return false;
    };
    let Some(section_end) = section
        .virtual_address
        .checked_add(section.virtual_size.max(section.size_of_raw_data))
    else {
        return false;
    };
    rva >= section.virtual_address && end <= section_end
}

fn placed_in_section(sections: &[Section], rva: u32, length: u32, executable: bool) -> bool {
    sections.iter().any(|section| {
        section_covers(section, rva, length)
            && section.is_readable()
            && section.is_executable() == executable
            && !section.is_writable()
            && !section.is_shared()
    })
}

fn checked_export_rvas(
    exports: &[ExportedSymbol],
    sections: &[Section],
    export_directory: DataDirectory,
) -> Result<(u32, u32, u32), SehLinkageImageError> {
    if exports.len() != NAMES.len() {
        return Err(SehLinkageImageError::Exports);
    }
    let directory_end = export_directory
        .virtual_address
        .checked_add(export_directory.size)
        .ok_or(SehLinkageImageError::Exports)?;
    let mut found = [None; NAMES.len()];
    for export in exports {
        let index = NAMES
            .iter()
            .position(|name| *name == export.name.as_str())
            .ok_or(SehLinkageImageError::Exports)?;
        if found[index].replace(export.rva).is_some() || export.rva == 0 {
            return Err(SehLinkageImageError::Exports);
        }
        if export.rva >= export_directory.virtual_address && export.rva < directory_end {
            return Err(SehLinkageImageError::Forwarder);
        }
        if index != 6 && !placed_in_section(sections, export.rva, 1, true) {
            return Err(SehLinkageImageError::SectionRights);
        }
    }
    let raise = found[4].ok_or(SehLinkageImageError::Exports)?;
    let resume = found[5].ok_or(SehLinkageImageError::Exports)?;
    let slot = found[6].ok_or(SehLinkageImageError::Exports)?;
    if !placed_in_section(sections, raise, RAISE_LEN, true)
        || !placed_in_section(sections, resume, RESUME_LEN, true)
        || !placed_in_section(sections, slot, 8, false)
        || slot & 7 != 0
    {
        return Err(SehLinkageImageError::SectionRights);
    }
    Ok((raise, resume, slot))
}

/// Admit the exact relocated instance. The dispatch slot must still be zero: the component
/// callback may be installed only after its physical lane and component VA are authenticated.
pub fn admit(
    pe: &PeFile<'_>,
    mapped: &MappedImage,
) -> Result<SehLinkageImage, SehLinkageImageError> {
    immutable_support_image::validate(pe).map_err(|_| SehLinkageImageError::InvalidImage)?;
    if mapped.bytes.len() != pe.size_of_image() as usize {
        return Err(SehLinkageImageError::InvalidImage);
    }
    let exports = pe.exports().map_err(|_| SehLinkageImageError::Exports)?;
    let (raise, resume, slot) = checked_export_rvas(
        &exports,
        pe.sections(),
        pe.headers().data_directory(DIRECTORY_ENTRY_EXPORT),
    )?;
    if !slot_is_zero(
        pe.bytes_at_rva(slot, 8),
        mapped.bytes.get(slot as usize..slot as usize + 8),
    ) {
        return Err(SehLinkageImageError::DispatchSlot);
    }
    let raise_va = mapped
        .load_base
        .checked_add(u64::from(raise))
        .ok_or(SehLinkageImageError::AddressOverflow)?;
    let resume_va = mapped
        .load_base
        .checked_add(u64::from(resume))
        .ok_or(SehLinkageImageError::AddressOverflow)?;
    Ok(SehLinkageImage {
        image_base: mapped.load_base,
        raise_va,
        resume_va,
        dispatch_slot_rva: slot,
    })
}

fn slot_is_zero(source: Option<&[u8]>, mapped: Option<&[u8]>) -> bool {
    source == Some(&[0; 8]) && mapped == Some(&[0; 8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeFunction;
    use alloc::vec::Vec;
    const EXECUTE: u32 = 0x2000_0000;
    const READ: u32 = 0x4000_0000;
    const WRITE: u32 = 0x8000_0000;

    fn fixture() -> (Vec<ExportedSymbol>, [Section; 2], DataDirectory) {
        let rvas = [0x1200, 0x1300, 0x1400, 0x1500, 0x1000, 0x112a, 0x3000];
        let exports = NAMES
            .iter()
            .zip(rvas)
            .map(|(name, rva)| ExportedSymbol {
                name: (*name).into(),
                rva,
                ordinal: 1,
            })
            .collect();
        let sections = [
            Section {
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                characteristics: READ | EXECUTE,
                ..Section::default()
            },
            Section {
                virtual_address: 0x3000,
                virtual_size: 0x1000,
                characteristics: READ,
                ..Section::default()
            },
        ];
        (
            exports,
            sections,
            DataDirectory {
                virtual_address: 0x3200,
                size: 0x100,
            },
        )
    }

    #[test]
    fn exact_exports_and_placements_are_required() {
        let (exports, sections, directory) = fixture();
        assert_eq!(
            checked_export_rvas(&exports, &sections, directory),
            Ok((0x1000, 0x112a, 0x3000))
        );
        let mut missing = exports.clone();
        missing.pop();
        assert_eq!(
            checked_export_rvas(&missing, &sections, directory),
            Err(SehLinkageImageError::Exports)
        );
        let mut duplicate = exports.clone();
        duplicate[6].name = duplicate[5].name.clone();
        assert_eq!(
            checked_export_rvas(&duplicate, &sections, directory),
            Err(SehLinkageImageError::Exports)
        );
        let mut forwarded = exports.clone();
        forwarded[4].rva = 0x3200;
        assert_eq!(
            checked_export_rvas(&forwarded, &sections, directory),
            Err(SehLinkageImageError::Forwarder)
        );
    }

    #[test]
    fn code_and_slot_rights_must_not_cross_sections() {
        let (mut exports, mut sections, directory) = fixture();
        exports[4].rva = 0x1fff;
        assert_eq!(
            checked_export_rvas(&exports, &sections, directory),
            Err(SehLinkageImageError::SectionRights)
        );
        exports[4].rva = 0x1000;
        exports[6].rva = 0x1000;
        assert_eq!(
            checked_export_rvas(&exports, &sections, directory),
            Err(SehLinkageImageError::SectionRights)
        );
        exports[6].rva = 0x3000;
        sections[1].characteristics |= WRITE;
        assert_eq!(
            checked_export_rvas(&exports, &sections, directory),
            Err(SehLinkageImageError::SectionRights)
        );
    }

    #[test]
    fn every_code_export_and_both_slot_views_are_checked() {
        let (mut exports, sections, directory) = fixture();
        exports[0].rva = 0x3000;
        assert_eq!(
            checked_export_rvas(&exports, &sections, directory),
            Err(SehLinkageImageError::SectionRights)
        );
        assert!(slot_is_zero(Some(&[0; 8]), Some(&[0; 8])));
        assert!(!slot_is_zero(None, Some(&[0; 8])));
        assert!(!slot_is_zero(Some(&[0; 8]), None));
        assert!(!slot_is_zero(
            Some(&[1, 0, 0, 0, 0, 0, 0, 0]),
            Some(&[0; 8])
        ));
        assert!(!slot_is_zero(
            Some(&[0; 8]),
            Some(&[1, 0, 0, 0, 0, 0, 0, 0])
        ));
    }

    #[test]
    fn exact_exception_function_requires_same_image_and_entry_start() {
        let function = RuntimeFunction {
            begin: 0x1000,
            end: 0x112a,
            unwind_info: 0x2000,
        };
        let exact = Ok(ExceptionFunction::Function {
            image_base: 0x4000,
            function,
        });
        assert!(exact_function(exact, 0x5000, 0x4000));
        assert!(!exact_function(exact, 0x5001, 0x4000));
        assert!(!exact_function(exact, 0x5000, 0x3000));
        assert!(!exact_function(Ok(ExceptionFunction::Leaf), 0x5000, 0x4000));
        assert!(!exact_function(
            Err(ExceptionImageError::UnknownImage),
            0x5000,
            0x4000
        ));
    }
}
