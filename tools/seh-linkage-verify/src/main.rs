//! Static proof of the hosted SEH linkage image. This does not prove native handler semantics.

use std::{env, fs, process::ExitCode};

use nt_pe_loader::{immutable_support_image, ExportedSymbol, PeFile};
use nt_unwind::{
    exception_images::BorrowedExceptionImage,
    exception_walk::{ExceptionFunction, ExceptionImageReader},
    unw_flag, UnwindInfoHeader,
};
use sha2::{Digest, Sha256};

const EXPORTS: [&str; 10] = [
    "SehCallFilter",
    "SehCallFinally",
    "SehExecuteHandlerForException",
    "SehExecuteHandlerForUnwind",
    "SehRaiseStatus",
    "SehResumeContext",
    "SehRaiseDispatch",
    "SehUnwindEx",
    "SehUnwindDispatch",
    "SehForeignCall2",
];
const RAISE_PROLOGUE: [u8; 8] = [0x9c, 0x48, 0x81, 0xec, 0xf0, 0x04, 0x00, 0x00];
const RAISE_UNWIND_CODES: [u8; 6] = [8, 1, 0x9e, 0, 1, 2];
const RAISE_FUNCTION_LEN: u32 = 0x12a;
const RESUME_PROLOGUE: [u8; 4] = [0x48, 0x83, 0xec, 0x08];
const RESUME_UNWIND_CODES: [u8; 2] = [4, 2];
const RESUME_TRANSFER: [u8; 11] = [
    0x48, 0x8d, 0x62, 0xe0, 0x5a, 0x9d, 0xc2, 0x08, 0, 0x0f, 0x0b,
];
const RESUME_FUNCTION_LEN: u32 = 0xb4;
const RESUME_CODE_SHA256: [u8; 32] = [
    0x38, 0xe2, 0x78, 0xe1, 0xc3, 0x86, 0xb3, 0x2a, 0xa0, 0x9f, 0x0f, 0x1b, 0xcd, 0x1e, 0x70, 0x0b,
    0x7e, 0x34, 0x5c, 0xeb, 0x0b, 0x6e, 0x83, 0x21, 0xee, 0x67, 0x67, 0x1d, 0xd1, 0xb6, 0x65, 0xd6,
];
// Reviewed Win64 capture body, including all GPR stores, FXSAVE, selectors and the fail-closed
// dispatcher call. A changed digest requires disassembly review before native admission.
const RAISE_CODE_SHA256: [u8; 32] = [
    0x89, 0xfb, 0x08, 0x39, 0x59, 0x8f, 0x2e, 0x04, 0xd4, 0xd2, 0x28, 0x21, 0xcc, 0x28, 0xb7, 0x2e,
    0x20, 0x93, 0xc5, 0xba, 0xdf, 0xf7, 0x6f, 0x8e, 0x2f, 0xc0, 0x95, 0x88, 0x52, 0x36, 0x3c, 0x28,
];
const UNWIND_PROLOGUE: [u8; 8] = [0x9c, 0x48, 0x81, 0xec, 0x30, 0x05, 0x00, 0x00];
const UNWIND_UNWIND_CODES: [u8; 6] = [8, 1, 0xa6, 0, 1, 2];
// Reviewed Win64 six-argument capture, caller CONTEXT copy and fail-closed dispatch body.
const UNWIND_FUNCTION_LEN: u32 = 0x1a4;
const UNWIND_CODE_SHA256: [u8; 32] = [
    0x66, 0x62, 0x30, 0xec, 0xce, 0xef, 0xc1, 0xf6, 0xdb, 0x71, 0xdf, 0x36, 0xaa, 0xd6, 0x33, 0x3a,
    0x94, 0xd1, 0xf5, 0x19, 0xf2, 0xad, 0x23, 0xa5, 0xba, 0xf2, 0xb2, 0x21, 0x67, 0xb4, 0x1e, 0xd1,
];
const CALL_FRAME: [u8; 4] = [0x48, 0x83, 0xec, 0x28];
const UNWIND_ALLOC_40: [u8; 2] = [4, 0x42];
const EXECUTE_BODY: [u8; 15] = [
    0x4c, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+32], r9
    0x41, 0xff, 0x51, 0x30, // call qword ptr [r9+48]
    0x90, // return site must be in the function body, not its epilogue
    0x48, 0x83, 0xc4, 0x28, 0xc3, // add rsp,40; ret
];
const FILTER_BODY: [u8; 22] = [
    0x4c, 0x89, 0x4c, 0x24, 0x20, // save dispatcher context R9 at [rsp+32]
    0x48, 0x89, 0xc8, // mov rax,rcx
    0x48, 0x89, 0xd1, // mov rcx,rdx
    0x4c, 0x89, 0xc2, // mov rdx,r8
    0xff, 0xd0, // call rax
    0x90, // keep callback return site out of the epilogue
    0x48, 0x83, 0xc4, 0x28, 0xc3, // add rsp,40; ret
];
const FINALLY_BODY: [u8; 21] = [
    0x4c, 0x89, 0x44, 0x24, 0x20, // save dispatcher context R8 at [rsp+32]
    0x48, 0x89, 0xc8, // mov rax,rcx
    0xb9, 1, 0, 0, 0, // mov ecx,1
    0xff, 0xd0, // call rax
    0x90, // keep callback return site out of the epilogue
    0x48, 0x83, 0xc4, 0x28, 0xc3, // add rsp,40; ret
];
const FOREIGN_CALL2_BODY: [u8; 17] = [
    0x48, 0x89, 0xc8, // mov rax,rcx (target)
    0x48, 0x89, 0xd1, // mov rcx,rdx (arg1)
    0x4c, 0x89, 0xc2, // mov rdx,r8 (arg2)
    0xff, 0xd0, // call rax
    0x90, // the return PC must precede the epilogue
    0x48, 0x83, 0xc4, 0x28, 0xc3, // add rsp,40; ret
];
const NESTED_HANDLER: [u8; 32] = [
    0xb8, 1, 0, 0, 0, // ExceptionContinueSearch
    0xf7, 0x41, 4, 0x66, 0, 0, 0, // reject unwind/exit/target/collided flags
    0x75, 0x11, // skip the state update on those flags
    0x48, 0x8b, 0x42, 0x20, // DispatcherContext from establisher home slot
    0x48, 0x8b, 0x40, 0x18, // parent EstablisherFrame
    0x49, 0x89, 0x41, 0x18, // child EstablisherFrame
    0xb8, 2, 0, 0, 0, // ExceptionNestedException
    0xc3,
];
const COLLIDED_HANDLER: [u8; 88] = [
    0x48, 0x8b, 0x42, 0x20, // parent dispatcher from home slot
    0x4c, 0x8b, 0x10, 0x4d, 0x89, 0x11, // ControlPc
    0x4c, 0x8b, 0x50, 0x08, 0x4d, 0x89, 0x51, 0x08, // ImageBase
    0x4c, 0x8b, 0x50, 0x10, 0x4d, 0x89, 0x51, 0x10, // FunctionEntry
    0x4c, 0x8b, 0x50, 0x18, 0x4d, 0x89, 0x51, 0x18, // EstablisherFrame
    0x4c, 0x8b, 0x50, 0x20, 0x4d, 0x89, 0x51, 0x20, // TargetIp
    0x4c, 0x8b, 0x50, 0x28, 0x4d, 0x89, 0x51, 0x28, // ContextRecord
    0x4c, 0x8b, 0x50, 0x30, 0x4d, 0x89, 0x51, 0x30, // LanguageHandler
    0x4c, 0x8b, 0x50, 0x38, 0x4d, 0x89, 0x51, 0x38, // HandlerData
    0x4c, 0x8b, 0x50, 0x40, 0x4d, 0x89, 0x51, 0x40, // HistoryTable
    0x44, 0x8b, 0x50, 0x48, 0x45, 0x89, 0x51, 0x48, // ScopeIndex
    0xb8, 3, 0, 0, 0, 0xc3, // ExceptionCollidedUnwind
];

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
    function == CALL_FRAME && unwind == UNWIND_ALLOC_40
}

fn body_is_exact(bytes: &[u8], function_rva: u32, expected: &[u8]) -> bool {
    let Some(body_start) = (function_rva as usize).checked_add(CALL_FRAME.len()) else {
        return false;
    };
    let Some(body_end) = body_start.checked_add(expected.len()) else {
        return false;
    };
    let Some(body) = bytes.get(body_start..body_end) else {
        return false;
    };
    body == expected
}

fn nested_handler_is_exact(bytes: &[u8], rva: u32) -> bool {
    let start = rva as usize;
    start
        .checked_add(NESTED_HANDLER.len())
        .and_then(|end| bytes.get(start..end))
        == Some(NESTED_HANDLER.as_slice())
}

fn collided_handler_is_exact(bytes: &[u8], rva: u32) -> bool {
    let start = rva as usize;
    start
        .checked_add(COLLIDED_HANDLER.len())
        .and_then(|end| bytes.get(start..end))
        == Some(COLLIDED_HANDLER.as_slice())
}

fn section_contains(section: &nt_pe_loader::Section, rva: u32, length: usize) -> bool {
    let start = u64::from(section.virtual_address);
    let end = start + u64::from(section.virtual_size.max(section.size_of_raw_data));
    let rva = u64::from(rva);
    rva >= start
        && rva
            .checked_add(length as u64)
            .is_some_and(|last| last <= end)
}

fn expected_flags(name: &str) -> u8 {
    match name {
        "SehCallFilter" | "SehExecuteHandlerForException" => unw_flag::EHANDLER,
        "SehCallFinally" | "SehExecuteHandlerForUnwind" => unw_flag::UHANDLER,
        _ => unreachable!("the export set was already checked"),
    }
}

fn expected_body(name: &str) -> &'static [u8] {
    match name {
        "SehCallFilter" => &FILTER_BODY,
        "SehCallFinally" => &FINALLY_BODY,
        "SehExecuteHandlerForException" | "SehExecuteHandlerForUnwind" => &EXECUTE_BODY,
        _ => unreachable!("the export set was already checked"),
    }
}

fn valid_unwind_header(header: UnwindInfoHeader, flags: u8) -> bool {
    header.version == 1
        && header.flags == flags
        && !header.is_chained()
        && header.size_of_prolog == 4
        && header.count_of_codes == 1
        && header.frame_register == 0
        && header.frame_offset == 0
}

fn raise_layout_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    begin.checked_add(RAISE_FUNCTION_LEN) == Some(end)
        && bytes.get(begin as usize..begin as usize + RAISE_PROLOGUE.len())
            == Some(RAISE_PROLOGUE.as_slice())
        && bytes.get(unwind as usize + 4..unwind as usize + 10)
            == Some(RAISE_UNWIND_CODES.as_slice())
        && bytes.get(end as usize - 2..end as usize) == Some(&[0x0f, 0x0b])
}

fn raise_encoding_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    let Some(code) = bytes.get(begin as usize..end as usize) else {
        return false;
    };
    raise_layout_is_exact(bytes, begin, end, unwind)
        && Sha256::digest(code).as_slice() == RAISE_CODE_SHA256
}

fn unwind_layout_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    begin.checked_add(UNWIND_FUNCTION_LEN) == Some(end)
        && bytes.get(begin as usize..begin as usize + UNWIND_PROLOGUE.len())
            == Some(UNWIND_PROLOGUE.as_slice())
        && bytes.get(unwind as usize + 4..unwind as usize + 10)
            == Some(UNWIND_UNWIND_CODES.as_slice())
        && bytes.get(end as usize - 2..end as usize) == Some(&[0x0f, 0x0b])
}

fn unwind_encoding_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    let Some(code) = bytes.get(begin as usize..end as usize) else {
        return false;
    };
    unwind_layout_is_exact(bytes, begin, end, unwind)
        && Sha256::digest(code).as_slice() == UNWIND_CODE_SHA256
}

fn raise_dispatch_slot_is_zero(bytes: &[u8], rva: u32) -> bool {
    rva & 7 == 0 && bytes.get(rva as usize..rva as usize + 8) == Some(&[0; 8])
}

fn resume_layout_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    begin.checked_add(RESUME_FUNCTION_LEN) == Some(end)
        && bytes.get(begin as usize..begin as usize + RESUME_PROLOGUE.len())
            == Some(RESUME_PROLOGUE.as_slice())
        && bytes.get(unwind as usize + 4..unwind as usize + 6)
            == Some(RESUME_UNWIND_CODES.as_slice())
        && bytes.get(end as usize - RESUME_TRANSFER.len()..end as usize)
            == Some(RESUME_TRANSFER.as_slice())
}

fn resume_encoding_is_exact(bytes: &[u8], begin: u32, end: u32, unwind: u32) -> bool {
    let Some(code) = bytes.get(begin as usize..end as usize) else {
        return false;
    };
    resume_layout_is_exact(bytes, begin, end, unwind)
        && Sha256::digest(code).as_slice() == RESUME_CODE_SHA256
}

fn verify_raise_entry(
    pe: &PeFile<'_>,
    mapped: &nt_pe_loader::MappedImage,
    image: &BorrowedExceptionImage<'_>,
    export: &ExportedSymbol,
) -> Result<(), String> {
    let pc = mapped
        .load_base
        .checked_add(u64::from(export.rva))
        .ok_or("raise entry VA overflow")?;
    let function = match image.lookup_exception_function(pc) {
        Ok(ExceptionFunction::Function {
            image_base,
            function,
        }) if image_base == mapped.load_base && function.begin == export.rva => function,
        other => {
            return Err(format!(
                "raise entry lacks exact runtime function: {other:?}"
            ))
        }
    };
    let header: [u8; 4] = mapped
        .bytes
        .get(function.unwind_info as usize..function.unwind_info as usize + 4)
        .ok_or("raise entry unwind header outside image")?
        .try_into()
        .map_err(|_| "raise entry unwind header malformed")?;
    let header = UnwindInfoHeader::parse(&header);
    let function_len = function
        .end
        .checked_sub(function.begin)
        .ok_or("raise entry reversed")?;
    if header.version != 1
        || header.flags != 0
        || header.is_chained()
        || header.size_of_prolog != RAISE_PROLOGUE.len() as u8
        || header.frame_register != 0
        || header.count_of_codes != 3
        || !raise_encoding_is_exact(
            &mapped.bytes,
            function.begin,
            function.end,
            function.unwind_info,
        )
        || !pe.sections().iter().any(|section| {
            section.name_str() == ".text"
                && section_contains(section, export.rva, function_len as usize)
                && section.is_readable()
                && section.is_executable()
                && !section.is_writable()
        })
        || !pe.sections().iter().any(|section| {
            section_contains(section, function.unwind_info, 8)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        })
    {
        return Err("raise entry code or unwind metadata invalid".into());
    }
    println!(
        "{} RVA=0x{:x} unwind=0x{:x} flags={}",
        export.name, export.rva, function.unwind_info, header.flags
    );
    Ok(())
}

fn verify_unwind_entry(
    pe: &PeFile<'_>,
    mapped: &nt_pe_loader::MappedImage,
    image: &BorrowedExceptionImage<'_>,
    export: &ExportedSymbol,
) -> Result<(), String> {
    let pc = mapped
        .load_base
        .checked_add(u64::from(export.rva))
        .ok_or("unwind entry VA overflow")?;
    let function = match image.lookup_exception_function(pc) {
        Ok(ExceptionFunction::Function {
            image_base,
            function,
        }) if image_base == mapped.load_base && function.begin == export.rva => function,
        other => {
            return Err(format!(
                "unwind entry lacks exact runtime function: {other:?}"
            ))
        }
    };
    let header: [u8; 4] = mapped
        .bytes
        .get(function.unwind_info as usize..function.unwind_info as usize + 4)
        .ok_or("unwind entry header outside image")?
        .try_into()
        .map_err(|_| "unwind entry header malformed")?;
    let header = UnwindInfoHeader::parse(&header);
    let function_len = function
        .end
        .checked_sub(function.begin)
        .ok_or("unwind entry reversed")?;
    if header.version != 1
        || header.flags != 0
        || header.is_chained()
        || header.size_of_prolog != UNWIND_PROLOGUE.len() as u8
        || header.frame_register != 0
        || header.count_of_codes != 3
        || !unwind_encoding_is_exact(
            &mapped.bytes,
            function.begin,
            function.end,
            function.unwind_info,
        )
        || !pe.sections().iter().any(|section| {
            section.name_str() == ".text"
                && section_contains(section, export.rva, function_len as usize)
                && section.is_readable()
                && section.is_executable()
                && !section.is_writable()
        })
        || !pe.sections().iter().any(|section| {
            section_contains(section, function.unwind_info, 10)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        })
    {
        return Err("unwind entry code or unwind metadata invalid".into());
    }
    println!(
        "{} RVA=0x{:x} unwind=0x{:x} flags={}",
        export.name, export.rva, function.unwind_info, header.flags
    );
    Ok(())
}

fn verify_raise_dispatch_slot(
    pe: &PeFile<'_>,
    mapped: &nt_pe_loader::MappedImage,
    export: &ExportedSymbol,
) -> Result<(), String> {
    if !raise_dispatch_slot_is_zero(&mapped.bytes, export.rva)
        || !pe.sections().iter().any(|section| {
            section.name_str() == ".rdata"
                && section_contains(section, export.rva, 8)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        })
    {
        return Err("raise dispatch slot is not zeroed RO_NX data".into());
    }
    Ok(())
}

fn verify_resume_entry(
    pe: &PeFile<'_>,
    mapped: &nt_pe_loader::MappedImage,
    image: &BorrowedExceptionImage<'_>,
    export: &ExportedSymbol,
) -> Result<(), String> {
    let pc = mapped
        .load_base
        .checked_add(u64::from(export.rva))
        .ok_or("resume entry VA overflow")?;
    let function = match image.lookup_exception_function(pc) {
        Ok(ExceptionFunction::Function {
            image_base,
            function,
        }) if image_base == mapped.load_base && function.begin == export.rva => function,
        other => {
            return Err(format!(
                "resume entry lacks exact runtime function: {other:?}"
            ))
        }
    };
    let header: [u8; 4] = mapped
        .bytes
        .get(function.unwind_info as usize..function.unwind_info as usize + 4)
        .ok_or("resume entry unwind header outside image")?
        .try_into()
        .map_err(|_| "resume entry unwind header malformed")?;
    let header = UnwindInfoHeader::parse(&header);
    let function_len = function
        .end
        .checked_sub(function.begin)
        .ok_or("resume entry reversed")?;
    if header.version != 1
        || header.flags != 0
        || header.is_chained()
        || header.size_of_prolog != RESUME_PROLOGUE.len() as u8
        || header.count_of_codes != 1
        || header.frame_register != 0
        || !resume_encoding_is_exact(
            &mapped.bytes,
            function.begin,
            function.end,
            function.unwind_info,
        )
        || !pe.sections().iter().any(|section| {
            section.name_str() == ".text"
                && section_contains(section, export.rva, function_len as usize)
                && section.is_readable()
                && section.is_executable()
                && !section.is_writable()
        })
        || !pe.sections().iter().any(|section| {
            section_contains(section, function.unwind_info, 8)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        })
    {
        return Err("resume entry code or unwind metadata invalid".into());
    }
    println!(
        "{} RVA=0x{:x} unwind=0x{:x} flags={}",
        export.name, export.rva, function.unwind_info, header.flags
    );
    Ok(())
}

fn verify_foreign_call2(
    pe: &PeFile<'_>,
    mapped: &nt_pe_loader::MappedImage,
    image: &BorrowedExceptionImage<'_>,
    export: &ExportedSymbol,
) -> Result<(), String> {
    let pc = mapped
        .load_base
        .checked_add(u64::from(export.rva))
        .ok_or("foreign callback VA overflow")?;
    let function = match image.lookup_exception_function(pc) {
        Ok(ExceptionFunction::Function {
            image_base,
            function,
        }) if image_base == mapped.load_base && function.begin == export.rva => function,
        other => {
            return Err(format!(
                "foreign callback lacks exact runtime function: {other:?}"
            ))
        }
    };
    let header: [u8; 4] = mapped
        .bytes
        .get(function.unwind_info as usize..function.unwind_info as usize + 4)
        .ok_or("foreign callback unwind header outside image")?
        .try_into()
        .map_err(|_| "foreign callback unwind header malformed")?;
    let header = UnwindInfoHeader::parse(&header);
    let function_len = function
        .end
        .checked_sub(function.begin)
        .ok_or("foreign callback reversed runtime function")? as usize;
    if !valid_unwind_header(header, 0)
        || !frame_encoding_is_exact(&mapped.bytes, export.rva, function.unwind_info)
        || function_len != CALL_FRAME.len() + FOREIGN_CALL2_BODY.len()
        || !body_is_exact(&mapped.bytes, export.rva, &FOREIGN_CALL2_BODY)
        || !pe.sections().iter().any(|section| {
            section.name_str() == ".text"
                && section_contains(section, export.rva, function_len)
                && section.is_readable()
                && section.is_executable()
                && !section.is_writable()
        })
        || !pe.sections().iter().any(|section| {
            section_contains(section, function.unwind_info, 6)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        })
    {
        return Err("foreign callback code or unwind metadata invalid".into());
    }
    println!(
        "{} RVA=0x{:x} unwind=0x{:x} flags={}",
        export.name, export.rva, function.unwind_info, header.flags
    );
    Ok(())
}

fn verify(path: &str) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {path}: {error}"))?;
    let pe = PeFile::parse(&bytes).map_err(|error| format!("PE parse: {error:?}"))?;
    immutable_support_image::validate(&pe)
        .map_err(|error| format!("support-image admission: {error:?}"))?;
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
    let mut nested_handler = None;
    let mut collided_handler = None;
    for export in exports {
        if export.name == "SehRaiseDispatch" || export.name == "SehUnwindDispatch" {
            verify_raise_dispatch_slot(&pe, &mapped, &export)?;
            continue;
        }
        if export.name == "SehRaiseStatus" {
            verify_raise_entry(&pe, &mapped, &image, &export)?;
            continue;
        }
        if export.name == "SehUnwindEx" {
            verify_unwind_entry(&pe, &mapped, &image, &export)?;
            continue;
        }
        if export.name == "SehResumeContext" {
            verify_resume_entry(&pe, &mapped, &image, &export)?;
            continue;
        }
        if export.name == "SehForeignCall2" {
            verify_foreign_call2(&pe, &mapped, &image, &export)?;
            continue;
        }
        let expected_flags = expected_flags(&export.name);
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
        let function_len = function
            .end
            .checked_sub(function.begin)
            .ok_or_else(|| format!("{} has reversed runtime function", export.name))?
            as usize;
        if !pe.sections().iter().any(|section| {
            section_contains(section, function.unwind_info, 12)
                && section.is_readable()
                && !section.is_writable()
                && !section.is_executable()
        }) {
            return Err(format!(
                "{} unwind metadata is not read-only NX",
                export.name
            ));
        }
        if !valid_unwind_header(header, expected_flags) {
            return Err(format!(
                "{} has unsupported linkage unwind header: {header:?}",
                export.name
            ));
        }
        if !frame_encoding_is_exact(&mapped.bytes, export.rva, function.unwind_info) {
            return Err(format!("{} prologue and unwind code disagree", export.name));
        }
        if !pe.sections().iter().any(|section| {
            section.name_str() == ".text"
                && section_contains(section, export.rva, function_len)
                && section.is_readable()
                && section.is_executable()
                && !section.is_writable()
        }) {
            return Err(format!("{} does not have an RX .text body", export.name));
        }
        let expected_body = expected_body(&export.name);
        if function_len != CALL_FRAME.len() + expected_body.len()
            || !body_is_exact(&mapped.bytes, export.rva, expected_body)
        {
            return Err(format!("{} has unexpected linkage code", export.name));
        }
        {
            let tail = (function.unwind_info as usize)
                .checked_add(header.tail_offset())
                .ok_or_else(|| format!("{} handler tail overflow", export.name))?;
            let handler_bytes = tail
                .checked_add(4)
                .and_then(|end| mapped.bytes.get(tail..end))
                .ok_or_else(|| format!("{} missing private handler RVA", export.name))?;
            let handler_rva = u32::from_le_bytes(
                handler_bytes
                    .try_into()
                    .map_err(|_| format!("{} has invalid private handler RVA", export.name))?,
            );
            let correct_code = if expected_flags == unw_flag::EHANDLER {
                nested_handler_is_exact(&mapped.bytes, handler_rva)
            } else {
                collided_handler_is_exact(&mapped.bytes, handler_rva)
            };
            let handler_len = if expected_flags == unw_flag::EHANDLER {
                NESTED_HANDLER.len()
            } else {
                COLLIDED_HANDLER.len()
            };
            if handler_rva == 0
                || !correct_code
                || !pe.sections().iter().any(|section| {
                    section.name_str() == ".text"
                        && section_contains(section, handler_rva, handler_len)
                        && section.is_readable()
                        && section.is_executable()
                        && !section.is_writable()
                })
                || (function.begin..function.end).contains(&handler_rva)
            {
                return Err(format!("{} has invalid private handler", export.name));
            }
            let shared_handler = if expected_flags == unw_flag::EHANDLER {
                &mut nested_handler
            } else {
                &mut collided_handler
            };
            if let Some(prior) = *shared_handler {
                if prior != handler_rva {
                    return Err(format!(
                        "{} does not share its private handler",
                        export.name
                    ));
                }
            } else {
                *shared_handler = Some(handler_rva);
            }
        }
        println!(
            "{} RVA=0x{:x} unwind=0x{:x} flags={}",
            export.name, export.rva, function.unwind_info, header.flags
        );
    }
    if nested_handler == collided_handler {
        return Err("nested and collided handler RVAs must differ".into());
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
        let all: Vec<_> = EXPORTS.iter().map(|name| export(name)).collect();
        assert!(exact_exports(&all));
        for index in 0..EXPORTS.len() {
            let mut missing = all.clone();
            missing.remove(index);
            assert!(!exact_exports(&missing));
        }
        let mut duplicate = all.clone();
        duplicate[3] = duplicate[2].clone();
        assert!(!exact_exports(&duplicate));
        let mut extra = all;
        extra[3] = export("Unexpected");
        assert!(!exact_exports(&extra));
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

    #[test]
    fn wrapper_bodies_reject_home_slot_call_and_return_site_mutations() {
        for body in [
            &FILTER_BODY[..],
            &FINALLY_BODY[..],
            &EXECUTE_BODY[..],
            &FOREIGN_CALL2_BODY[..],
        ] {
            let mut bytes = [0u8; 64];
            bytes[8..12].copy_from_slice(&CALL_FRAME);
            bytes[12..12 + body.len()].copy_from_slice(body);
            assert!(body_is_exact(&bytes, 8, body));
            for offset in 12..12 + body.len() {
                bytes[offset] ^= 1;
                assert!(!body_is_exact(&bytes, 8, body), "offset {offset}");
                bytes[offset] ^= 1;
            }
            assert!(!body_is_exact(&bytes, 63, body));
        }
    }

    #[test]
    fn foreign_callback_is_an_unhandled_call_frame() {
        let header = UnwindInfoHeader::parse(&[1, 4, 1, 0]);
        assert!(valid_unwind_header(header, 0));
        assert!(!valid_unwind_header(header, unw_flag::EHANDLER));
        let mut body = FOREIGN_CALL2_BODY;
        body[11] ^= 1;
        assert_ne!(body, FOREIGN_CALL2_BODY);
        assert_eq!(FOREIGN_CALL2_BODY[11], 0x90);
    }

    #[test]
    fn handler_flags_are_exact_and_mutations_fail() {
        for (name, flags) in [
            (EXPORTS[0], unw_flag::EHANDLER),
            (EXPORTS[1], unw_flag::UHANDLER),
            (EXPORTS[2], unw_flag::EHANDLER),
            (EXPORTS[3], unw_flag::UHANDLER),
        ] {
            assert_eq!(expected_flags(name), flags);
            let bytes = [(flags << 3) | 1, 4, 1, 0];
            assert!(valid_unwind_header(UnwindInfoHeader::parse(&bytes), flags));
            for replacement in [0, unw_flag::EHANDLER, unw_flag::UHANDLER, 3, 4] {
                if replacement != flags {
                    let mut mutated = bytes;
                    mutated[0] = (replacement << 3) | 1;
                    assert!(!valid_unwind_header(
                        UnwindInfoHeader::parse(&mutated),
                        flags
                    ));
                }
            }
        }
    }

    #[test]
    fn private_handler_opcode_mutations_fail() {
        let mut nested = NESTED_HANDLER.to_vec();
        assert!(nested_handler_is_exact(&nested, 0));
        for offset in 0..nested.len() {
            nested[offset] ^= 1;
            assert!(!nested_handler_is_exact(&nested, 0), "nested {offset}");
            nested[offset] ^= 1;
        }

        let mut collided = COLLIDED_HANDLER.to_vec();
        assert!(collided_handler_is_exact(&collided, 0));
        for offset in 0..collided.len() {
            collided[offset] ^= 1;
            assert!(
                !collided_handler_is_exact(&collided, 0),
                "collided {offset}"
            );
            collided[offset] ^= 1;
        }
    }

    #[test]
    fn raise_entry_and_dispatch_slot_reject_mutations() {
        let mut bytes = vec![0u8; 0x2200];
        bytes[0x1000..0x1008].copy_from_slice(&RAISE_PROLOGUE);
        bytes[0x1128..0x112a].copy_from_slice(&[0x0f, 0x0b]);
        bytes[0x2100..0x2106].copy_from_slice(&RAISE_UNWIND_CODES);
        assert!(raise_layout_is_exact(&bytes, 0x1000, 0x112a, 0x20fc));
        assert!(!raise_encoding_is_exact(&bytes, 0x1000, 0x112a, 0x20fc));
        assert!(raise_dispatch_slot_is_zero(&bytes, 0x2000));
        assert!(!raise_layout_is_exact(&bytes, 0x1000, 0x112b, 0x20fc));
        assert!(!raise_dispatch_slot_is_zero(&bytes, 0x2001));
        for offset in (0x1000..0x1008).chain(0x1128..0x112a).chain(0x2100..0x2106) {
            bytes[offset] ^= 1;
            assert!(!raise_layout_is_exact(&bytes, 0x1000, 0x112a, 0x20fc));
            bytes[offset] ^= 1;
        }
        bytes[0x2007] = 1;
        assert!(!raise_dispatch_slot_is_zero(&bytes, 0x2000));
    }

    #[test]
    fn unwind_entry_rejects_prologue_epilogue_and_unwind_mutations() {
        let mut bytes = vec![0u8; 0x2300];
        let begin = 0x1000;
        let end = begin + UNWIND_FUNCTION_LEN;
        let unwind = 0x2100;
        bytes[begin as usize..begin as usize + UNWIND_PROLOGUE.len()]
            .copy_from_slice(&UNWIND_PROLOGUE);
        bytes[end as usize - 2..end as usize].copy_from_slice(&[0x0f, 0x0b]);
        bytes[unwind as usize + 4..unwind as usize + 10].copy_from_slice(&UNWIND_UNWIND_CODES);
        assert!(unwind_layout_is_exact(&bytes, begin, end, unwind));
        assert!(!unwind_encoding_is_exact(&bytes, begin, end, unwind));
        assert!(!unwind_layout_is_exact(&bytes, begin, end + 1, unwind));
        for offset in (begin as usize..begin as usize + UNWIND_PROLOGUE.len())
            .chain(end as usize - 2..end as usize)
            .chain(unwind as usize + 4..unwind as usize + 10)
        {
            bytes[offset] ^= 1;
            assert!(!unwind_layout_is_exact(&bytes, begin, end, unwind));
            bytes[offset] ^= 1;
        }
    }

    #[test]
    fn resume_entry_rejects_unwind_and_transfer_mutations() {
        let mut bytes = vec![0u8; 0x2200];
        bytes[0x112a..0x112e].copy_from_slice(&RESUME_PROLOGUE);
        bytes[0x11d3..0x11de].copy_from_slice(&RESUME_TRANSFER);
        bytes[0x2120..0x2122].copy_from_slice(&RESUME_UNWIND_CODES);
        assert!(resume_layout_is_exact(&bytes, 0x112a, 0x11de, 0x211c));
        assert!(!resume_encoding_is_exact(&bytes, 0x112a, 0x11de, 0x211c));
        assert!(!resume_layout_is_exact(&bytes, 0x112a, 0x11df, 0x211c));
        for offset in (0x112a..0x112e).chain(0x11d3..0x11de).chain(0x2120..0x2122) {
            bytes[offset] ^= 1;
            assert!(!resume_layout_is_exact(&bytes, 0x112a, 0x11de, 0x211c));
            bytes[offset] ^= 1;
        }
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
