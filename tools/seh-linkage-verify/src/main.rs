//! Static proof of the hosted SEH linkage image. This does not prove native handler semantics.

use std::{env, fs, process::ExitCode};

use nt_pe_loader::{ExportedSymbol, PeFile, DIRECTORY_ENTRY_TLS};
use nt_unwind::{
    exception_images::BorrowedExceptionImage,
    exception_walk::{ExceptionFunction, ExceptionImageReader},
    UnwindInfoHeader,
};

const EXPORTS: [&str; 2] = ["SehCallFilter", "SehCallFinally"];
const IMAGE_FILE_DLL: u16 = 0x2000;
const DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;

fn exact_exports(exports: &[ExportedSymbol]) -> bool {
    exports.len() == EXPORTS.len()
        && exports
            .iter()
            .all(|export| EXPORTS.contains(&export.name.as_str()))
        && EXPORTS
            .iter()
            .all(|name| exports.iter().filter(|export| export.name == *name).count() == 1)
}

fn frame_encoding_is_exact(bytes: &[u8], function_rva: u32, unwind_rva: u32) -> bool {
    let Some(function) = bytes.get(function_rva as usize..function_rva as usize + 4) else {
        return false;
    };
    let Some(unwind) = bytes.get(unwind_rva as usize + 4..unwind_rva as usize + 6) else {
        return false;
    };
    function == [0x48, 0x83, 0xec, 0x28] && unwind == [4, 0x42]
}

fn verify(path: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {path}: {error}"))?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("PE parse: {error:?}"))?;
    if pe.headers().characteristics & IMAGE_FILE_DLL == 0 || !pe.headers().is_executable() {
        return Err("linkage image must be an executable PE DLL".into());
    }
    let tls = pe.headers().data_directory(DIRECTORY_ENTRY_TLS);
    let delay_import = pe.headers().data_directory(DIRECTORY_ENTRY_DELAY_IMPORT);
    if pe.entry_point_rva() != 0
        || !pe
            .imports()
            .map_err(|e| format!("imports: {e:?}"))?
            .is_empty()
        || tls.virtual_address != 0
        || tls.size != 0
        || delay_import.virtual_address != 0
        || delay_import.size != 0
    {
        return Err(
            "linkage image must have no entry point, imports, delay imports, or TLS".into(),
        );
    }
    for name in [".text", ".pdata"] {
        if !pe
            .sections()
            .iter()
            .any(|section| section.name_str() == name)
        {
            return Err(format!("missing {name} section"));
        }
    }
    let exports = pe
        .exports()
        .map_err(|error| format!("exports: {error:?}"))?;
    if !exact_exports(&exports) {
        return Err(format!("unexpected exports: {exports:?}"));
    }
    let mapped = pe
        .map(pe.image_base())
        .map_err(|error| format!("map: {error:?}"))?;
    let image = BorrowedExceptionImage::from_mapped_image(mapped.load_base, &mapped.bytes)
        .map_err(|error| format!("exception admission: {error:?}"))?;
    for export in exports {
        let pc = mapped
            .load_base
            .checked_add(u64::from(export.rva))
            .ok_or_else(|| format!("{} VA overflow", export.name))?;
        let function = match image.lookup_exception_function(pc) {
            Ok(ExceptionFunction::Function {
                image_base,
                function,
            }) if image_base == mapped.load_base && function.begin == export.rva => function,
            other => {
                return Err(format!(
                    "{} lacks exact runtime function: {other:?}",
                    export.name
                ))
            }
        };
        let header_bytes: [u8; 4] = mapped
            .bytes
            .get(function.unwind_info as usize..function.unwind_info as usize + 4)
            .ok_or_else(|| format!("{} unwind header outside image", export.name))?
            .try_into()
            .map_err(|_| format!("{} invalid unwind header", export.name))?;
        let header = UnwindInfoHeader::parse(&header_bytes);
        if !pe.sections().iter().any(|section| {
            let start = section.virtual_address;
            let end = start.saturating_add(section.virtual_size.max(section.size_of_raw_data));
            function.unwind_info >= start
                && function.unwind_info < end
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        }) {
            return Err(format!(
                "{} unwind metadata is not read-only NX",
                export.name
            ));
        }
        if header.version != 1
            || header.has_handler()
            || header.is_chained()
            || header.size_of_prolog != 4
            || header.count_of_codes != 1
            || header.frame_register != 0
            || header.frame_offset != 0
        {
            return Err(format!(
                "{} has unsupported linkage unwind header: {header:?}",
                export.name
            ));
        }
        if !frame_encoding_is_exact(&mapped.bytes, export.rva, function.unwind_info) {
            return Err(format!("{} prologue and unwind code disagree", export.name));
        }
        println!(
            "{} RVA=0x{:x} unwind=0x{:x}",
            export.name, export.rva, function.unwind_info
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(name: &str) -> ExportedSymbol {
        ExportedSymbol {
            name: name.into(),
            rva: 0x1000,
            ordinal: 1,
        }
    }

    #[test]
    fn export_set_rejects_duplicates_and_extra_names() {
        assert!(exact_exports(&[export(EXPORTS[0]), export(EXPORTS[1])]));
        assert!(!exact_exports(&[export(EXPORTS[0]), export(EXPORTS[0])]));
        assert!(!exact_exports(&[export(EXPORTS[0]), export("Unexpected")]));
        assert!(!exact_exports(&[export(EXPORTS[0])]));
    }

    #[test]
    fn frame_encoding_rejects_prologue_and_unwind_mutations() {
        let mut bytes = [0u8; 64];
        bytes[8..12].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        bytes[36..38].copy_from_slice(&[4, 0x42]);
        assert!(frame_encoding_is_exact(&bytes, 8, 32));
        for offset in [8, 9, 10, 11, 36, 37] {
            bytes[offset] ^= 1;
            assert!(!frame_encoding_is_exact(&bytes, 8, 32));
            bytes[offset] ^= 1;
        }
        assert!(!frame_encoding_is_exact(&bytes, 61, 32));
        assert!(!frame_encoding_is_exact(&bytes, 8, 63));
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: seh-linkage-verify <nt-seh-linkage.dll>");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("expected exactly one image path");
        return ExitCode::FAILURE;
    }
    match verify(&path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("SEH linkage verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}
