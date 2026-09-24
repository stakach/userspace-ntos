//! Static gate for a real compiler-emitted x64 C SEH driver. No runtime claim is made here.

use std::{env, fs, process::ExitCode};

use nt_pe_loader::{ImportRef, PeFile};
use nt_unwind::{
    exception_images::BorrowedExceptionImage, unw_flag, UnwindInfoHeader, DIRECTORY_ENTRY_EXCEPTION,
};

const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const COMPONENT_LOAD_BASE: u64 = 0x0000_0100_0e00_0000;

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| format!("missing u16 at 0x{offset:x}"))?
        .try_into()
        .map_err(|_| format!("invalid u16 at 0x{offset:x}"))?;
    Ok(u16::from_le_bytes(raw))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("missing u32 at 0x{offset:x}"))?
        .try_into()
        .map_err(|_| format!("invalid u32 at 0x{offset:x}"))?;
    Ok(u32::from_le_bytes(raw))
}

/// COFF object relocations are the pre-link source of truth for whether code will remain valid
/// after loading the linked image at the component VA. ADDR32NB is image-base-relative; REL32
/// and REL32_1..5 are instruction-relative. Absolute ADDR64/ADDR32 need a PE .reloc record and
/// are deliberately rejected for this tiny position-independent fixture.
fn verify_position_independent_object(bytes: &[u8]) -> Result<usize, String> {
    if u16_at(bytes, 0)? != 0x8664 {
        return Err("fixture object is not AMD64 COFF".into());
    }
    let section_count = usize::from(u16_at(bytes, 2)?);
    let optional_size = usize::from(u16_at(bytes, 16)?);
    if section_count == 0 || section_count > 96 {
        return Err("fixture COFF section count is invalid".into());
    }
    let sections_start = 20usize
        .checked_add(optional_size)
        .ok_or("COFF section table overflow")?;
    let sections_end = sections_start
        .checked_add(
            section_count
                .checked_mul(40)
                .ok_or("COFF section table overflow")?,
        )
        .ok_or("COFF section table overflow")?;
    if sections_end > bytes.len() {
        return Err("COFF section table exceeds object".into());
    }
    let mut relocations = 0usize;
    for index in 0..section_count {
        let section = sections_start + index * 40;
        let offset = u32_at(bytes, section + 24)? as usize;
        let count = usize::from(u16_at(bytes, section + 32)?);
        if count == 0 {
            continue;
        }
        if count == 0xffff {
            return Err("extended COFF relocations are unsupported".into());
        }
        let end = offset
            .checked_add(
                count
                    .checked_mul(10)
                    .ok_or("COFF relocation extent overflow")?,
            )
            .ok_or("COFF relocation extent overflow")?;
        if bytes.get(offset..end).is_none() {
            return Err("COFF relocations exceed object".into());
        }
        for row in 0..count {
            let kind = u16_at(bytes, offset + row * 10 + 8)?;
            if kind != 0x0003 && !(0x0004..=0x0009).contains(&kind) {
                return Err(format!(
                    "unsupported/absolute COFF relocation type 0x{kind:04x} in section {index}"
                ));
            }
        }
        relocations += count;
    }
    if relocations == 0 {
        return Err("fixture object has no relocations to audit".into());
    }
    Ok(relocations)
}

fn verify(path: &str, object_path: &str) -> Result<(), String> {
    let object = fs::read(object_path).map_err(|error| format!("read {object_path}: {error}"))?;
    let relocation_count = verify_position_independent_object(&object)?;
    let bytes = fs::read(path).map_err(|error| format!("read {path}: {error}"))?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("PE parse: {error:?}"))?;
    if pe.headers().characteristics & IMAGE_FILE_DLL == 0
        || !pe.headers().is_executable()
        || pe.subsystem() != IMAGE_SUBSYSTEM_NATIVE
        || pe.entry_point_rva() == 0
    {
        return Err("fixture must be an executable native driver with DriverEntry".into());
    }
    if !pe.sections().iter().any(|section| {
        section.is_executable()
            && pe.entry_point_rva() >= section.virtual_address
            && pe.entry_point_rva()
                < section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(section.size_of_raw_data))
    }) {
        return Err("DriverEntry is not in executable code".into());
    }
    if !pe
        .sections()
        .iter()
        .any(|section| section.name_str() == ".pdata")
    {
        return Err("fixture lacks .pdata".into());
    }

    let imports = pe
        .imports()
        .map_err(|error| format!("imports: {error:?}"))?;
    if imports.len() != 1 || !imports[0].name.eq_ignore_ascii_case("ntoskrnl.exe") {
        return Err(format!("expected only ntoskrnl.exe imports: {imports:?}"));
    }
    let mut names: Vec<&str> = imports[0]
        .functions
        .iter()
        .map(|function| match function {
            ImportRef::ByName { name, .. } => Ok(name.as_str()),
            ImportRef::ByOrdinal { .. } => Err("ordinal import is forbidden".to_string()),
        })
        .collect::<Result<_, _>>()?;
    names.sort_unstable();
    if names != ["DbgPrint", "ExRaiseStatus", "__C_specific_handler"] {
        return Err(format!("unexpected ntoskrnl imports: {names:?}"));
    }

    let exports = pe
        .exports()
        .map_err(|error| format!("exports: {error:?}"))?;
    if exports.len() != 1 || exports[0].name != "SehFixtureEvidence" {
        return Err(format!("expected only evidence data export: {exports:?}"));
    }
    if !pe.sections().iter().any(|section| {
        section.is_writable()
            && !section.is_executable()
            && exports[0].rva >= section.virtual_address
            && exports[0].rva
                < section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(section.size_of_raw_data))
    }) {
        return Err("evidence export is not in writable, non-executable data".into());
    }

    let mapped = pe
        .map(COMPONENT_LOAD_BASE)
        .map_err(|error| format!("map: {error:?}"))?;
    let image = BorrowedExceptionImage::from_mapped_image(mapped.load_base, &mapped.bytes)
        .map_err(|error| format!("exception admission: {error:?}"))?;
    let directory = pe.headers().data_directory(DIRECTORY_ENTRY_EXCEPTION);
    if directory.size == 0 || directory.size % 12 != 0 {
        return Err("missing or malformed x64 exception directory".into());
    }
    let mut except_scopes = 0u32;
    let mut finally_scopes = 0u32;
    for index in 0..directory.size / 12 {
        let row = directory
            .virtual_address
            .checked_add(index * 12)
            .ok_or("runtime function RVA overflow")? as usize;
        let unwind_rva = u32_at(&mapped.bytes, row + 8)?;
        if unwind_rva & 1 != 0 {
            continue;
        }
        let header: [u8; 4] = mapped
            .bytes
            .get(unwind_rva as usize..unwind_rva as usize + 4)
            .ok_or("unwind header outside mapped image")?
            .try_into()
            .map_err(|_| "invalid unwind header")?;
        let header = UnwindInfoHeader::parse(&header);
        if header.flags & (unw_flag::EHANDLER | unw_flag::UHANDLER) == 0 {
            continue;
        }
        let handler_data = unwind_rva
            .checked_add(header.tail_offset() as u32)
            .and_then(|tail| tail.checked_add(4))
            .ok_or("handler data RVA overflow")?;
        let scopes = image
            .read_c_scope_table(mapped.load_base + u64::from(handler_data))
            .map_err(|error| format!("invalid C scope table: {error:?}"))?;
        for scope in scopes {
            if scope.target == 0 && header.flags & unw_flag::UHANDLER != 0 {
                finally_scopes += 1;
            }
            if scope.target != 0 && header.flags & unw_flag::EHANDLER != 0 {
                except_scopes += 1;
            }
        }
    }
    if except_scopes == 0 || finally_scopes == 0 {
        return Err(format!(
            "missing compiler-emitted C exception/finally scopes: except={except_scopes} finally={finally_scopes}"
        ));
    }
    println!(
        "driver_seh.sys admitted at 0x{COMPONENT_LOAD_BASE:x}: except-scopes={except_scopes} finally-scopes={finally_scopes} imports={names:?} coff-relocations={relocation_count}"
    );
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: seh-driver-fixture-verify <driver_seh.sys> <driver_seh.obj>");
        return ExitCode::FAILURE;
    };
    let Some(object_path) = args.next() else {
        eprintln!("missing compiled COFF object path");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("expected exactly one fixture path");
        return ExitCode::FAILURE;
    }
    match verify(&path, &object_path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("SEH driver fixture verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coff_relocation_gate_rejects_absolute_addresses() {
        let mut object = vec![0u8; 70];
        object[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        object[2..4].copy_from_slice(&1u16.to_le_bytes());
        object[44..48].copy_from_slice(&60u32.to_le_bytes());
        object[52..54].copy_from_slice(&1u16.to_le_bytes());
        object[68..70].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(verify_position_independent_object(&object), Ok(1));
        for absolute in [1u16, 2u16] {
            object[68..70].copy_from_slice(&absolute.to_le_bytes());
            assert!(verify_position_independent_object(&object).is_err());
        }
    }
}
