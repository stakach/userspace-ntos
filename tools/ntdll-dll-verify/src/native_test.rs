//! Static native suspension fixture validation through the executive's PE loader.
use std::{collections::BTreeSet, path::Path, process::ExitCode};

use nt_pe_loader::{ImportRef, PeFile};
use sha2::{Digest, Sha256};

const IMPORTS: [&str; 12] = [
    "RtlCreateUserThread",
    "NtCreateEvent",
    "NtSuspendThread",
    "NtResumeThread",
    "NtWaitForSingleObject",
    "NtSignalAndWaitForSingleObject",
    "NtSetEvent",
    "NtDelayExecution",
    "NtClose",
    "NtDisplayString",
    "NtTerminateThread",
    "NtTerminateProcess",
];

fn require(condition: bool, message: &str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.to_owned())
}

fn verify(exe_path: &Path, dll_path: &Path) -> Result<(), String> {
    let exe_bytes = std::fs::read(exe_path).map_err(|e| format!("fixture: {e}"))?;
    let dll_bytes = std::fs::read(dll_path).map_err(|e| format!("ntdll: {e}"))?;
    let exe = PeFile::parse(&exe_bytes).map_err(|e| format!("fixture parse: {e:?}"))?;
    let dll = PeFile::parse(&dll_bytes).map_err(|e| format!("ntdll parse: {e:?}"))?;
    for (name, image) in [("fixture", &exe), ("ntdll", &dll)] {
        require(
            image.headers().machine == 0x8664 && image.headers().magic == 0x20b,
            &format!("{name} must be AMD64 PE32+"),
        )?;
    }
    require(
        exe.subsystem() == 1,
        "fixture must use the native subsystem",
    )?;
    require(
        exe.subsystem_version() == (5, 2),
        "fixture must target NT 5.2",
    )?;
    require(
        dll.headers().characteristics & 0x2000 != 0,
        "ntdll input must be a DLL",
    )?;
    require(
        exe.headers().is_executable() && exe.headers().characteristics & 0x2000 == 0,
        "fixture must be an executable, not a DLL",
    )?;
    require(
        exe.entry_point_rva() != 0
            && exe.protection_at(exe.entry_point_rva()).executable()
            && exe.bytes_at_rva(exe.entry_point_rva(), 1).is_some(),
        "entry must identify file-backed executable code",
    )?;
    require(!exe.has_tls_directory(), "unexpected TLS startup")?;
    let delay = exe.headers().data_directory(13);
    require(
        delay.virtual_address == 0 && delay.size == 0,
        "delay imports",
    )?;
    let imports = exe.imports().map_err(|e| format!("imports: {e:?}"))?;
    require(
        imports.len() == 1 && imports[0].name.eq_ignore_ascii_case("ntdll.dll"),
        "imports must come exclusively from ntdll.dll",
    )?;
    let mut seen = BTreeSet::new();
    let mut slots = BTreeSet::new();
    require(
        exe.headers().characteristics & 1 == 0,
        "fixture strips relocation support",
    )?;
    let exe_base = exe
        .image_base()
        .checked_add(0x20_0000)
        .ok_or("fixture nonpreferred base overflow")?;
    let dll_base = dll
        .image_base()
        .checked_add(0x100_0000)
        .ok_or("ntdll nonpreferred base overflow")?;
    let mut mapped = exe
        .map(exe_base)
        .map_err(|e| format!("fixture nonpreferred map: {e:?}"))?;
    let _mapped_dll = dll
        .map(dll_base)
        .map_err(|e| format!("ntdll nonpreferred map: {e:?}"))?;
    let export_directory = dll.headers().data_directory(0);
    let forwarder_end =
        u64::from(export_directory.virtual_address) + u64::from(export_directory.size);
    for import in &imports[0].functions {
        let ImportRef::ByName {
            name, iat_slot_rva, ..
        } = import
        else {
            return Err("ordinal import".into());
        };
        require(seen.insert(name.as_str()), "duplicate imported name")?;
        require(slots.insert(*iat_slot_rva), "duplicate IAT slot")?;
        let rva = dll
            .export_rva_by_name(name)
            .map_err(|e| format!("resolve {name}: {e:?}"))?
            .ok_or_else(|| format!("ntdll lacks {name}"))?;
        require(
            rva != 0
                && !(rva >= export_directory.virtual_address && u64::from(rva) < forwarder_end),
            &format!("{name} is null or forwarded"),
        )?;
        require(
            dll.protection_at(rva).executable() && dll.bytes_at_rva(rva, 1).is_some(),
            &format!("{name} must resolve to executable code"),
        )?;
        let address = dll_base
            .checked_add(u64::from(rva))
            .ok_or_else(|| format!("{name} address overflow"))?;
        mapped
            .patch_iat(*iat_slot_rva, address)
            .map_err(|e| format!("bind {name}: {e:?}"))?;
        let actual = mapped
            .u64_at_rva(*iat_slot_rva)
            .map_err(|e| format!("read bound {name}: {e:?}"))?;
        require(actual == address, &format!("{name} IAT readback mismatch"))?;
    }
    require(
        seen == IMPORTS.into_iter().collect(),
        &format!("fixture import set differs from the exact twelve APIs: {seen:?}"),
    )?;
    println!(
        "PASS static artifact: AMD64 native PE, twelve exact ntdll imports bound by nt-pe-loader"
    );
    println!("nonpreferred mapping: fixture={exe_base:#x} ntdll={dll_base:#x}");
    println!("fixture SHA256 {:x}", Sha256::digest(&exe_bytes));
    println!("ntdll SHA256 {:x}", Sha256::digest(&dll_bytes));
    println!("Guest execution and suspension acceptance have NOT been run by this verifier.");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        eprintln!("usage: nt-native-test-verify <thread_suspend.exe> <our-ntdll.dll>");
        return ExitCode::FAILURE;
    }
    match verify(Path::new(&args[0]), Path::new(&args[1])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("FAIL static artifact: {error}");
            ExitCode::FAILURE
        }
    }
}
