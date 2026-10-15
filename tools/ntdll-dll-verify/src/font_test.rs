//! Strict build-only checks for the isolated native setup and Win32 font cleanup fixtures.
use std::{collections::BTreeSet, path::Path, process::ExitCode};
use nt_pe_loader::{module_namespace::{self, ImageExports, Symbol}, ImportRef, PeFile};
use sha2::{Digest, Sha256};

fn contract(font: bool) -> BTreeSet<(&'static str, &'static str)> {
    let mut result = BTreeSet::new();
    for name in ["NtDisplayString", "NtQueryInformationProcess", "NtTerminateProcess"] {
        result.insert(("ntdll.dll", name));
    }
    if font {
        result.insert(("kernel32.dll", "GetWindowsDirectoryW"));
        result.insert(("kernel32.dll", "GetLastError"));
        result.insert(("gdi32.dll", "AddFontResourceExW"));
    } else {
        for name in ["NtCreateKey", "NtSetValueKey", "NtQueryValueKey", "NtClose"] {
            result.insert(("ntdll.dll", name));
        }
    }
    result
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.to_owned())
}

fn verify(font: bool, exe_path: &Path, dll_paths: &[(&str, &Path)]) -> Result<(), String> {
    let exe_bytes = std::fs::read(exe_path).map_err(|error| error.to_string())?;
    let exe = PeFile::parse(&exe_bytes).map_err(|error| format!("fixture: {error:?}"))?;
    require(exe.headers().machine == 0x8664 && exe.headers().magic == 0x20b, "AMD64 PE32+ fixture")?;
    require(exe.headers().is_executable() && exe.headers().characteristics & 0x2000 == 0, "fixture must be an executable")?;
    require(exe.subsystem() == if font { 2 } else { 1 }, "incorrect subsystem")?;
    require(exe.subsystem_version() == (5, 2), "NT 5.2 subsystem contract")?;
    require(exe.entry_point_rva() != 0 && exe.protection_at(exe.entry_point_rva()).executable()
        && exe.bytes_at_rva(exe.entry_point_rva(), 1).is_some(), "file-backed executable entry")?;
    require(!exe.has_tls_directory(), "unexpected fixture TLS startup")?;
    let delay = exe.headers().data_directory(13);
    require(delay.virtual_address == 0 && delay.size == 0, "unexpected delay imports")?;
    require(exe.headers().characteristics & 1 == 0, "relocations must not be stripped")?;
    let dll_bytes: Vec<_> = dll_paths.iter().map(|(_, path)| std::fs::read(path)
        .map_err(|error| error.to_string())).collect::<Result<_, _>>()?;
    let dlls: Vec<_> = dll_bytes.iter().map(|bytes| PeFile::parse(bytes)
        .map_err(|error| format!("DLL: {error:?}"))).collect::<Result<_, _>>()?;
    let mut exports = Vec::new();
    for (index, dll) in dlls.iter().enumerate() {
        require(dll.headers().machine == 0x8664 && dll.headers().magic == 0x20b
            && dll.headers().characteristics & 0x2000 != 0, "actual import dependency must be AMD64 DLL")?;
        let base = 0x5000_0000 + (index as u64) * 0x1000_0000;
        let mapped = dll.map(base).map_err(|error| format!("actual DLL map: {error:?}"))?;
        exports.push(ImageExports::from_mapped(dll_paths[index].0, base, &mapped.bytes)
            .map_err(|error| format!("actual DLL exports: {error:?}"))?);
    }
    let fixture_base = exe.image_base().checked_add(0x20_0000).ok_or("fixture base overflow")?;
    let mut mapped = exe.map(fixture_base).map_err(|error| format!("fixture map: {error:?}"))?;
    let mut seen = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for library in exe.imports().map_err(|error| format!("fixture imports: {error:?}"))? {
        let leaf = module_namespace::module_leaf(&library.name).map_err(|error| format!("module: {error:?}"))?;
        require(dll_paths.iter().any(|(name, _)| *name == leaf), "unexpected import library")?;
        require(!library.functions.is_empty(), "empty fixture import library")?;
        for import in library.functions {
            let ImportRef::ByName { name, iat_slot_rva, .. } = import else { return Err("ordinal fixture import".into()); };
            require(seen.insert((leaf.clone(), name.clone())), "duplicate import")?;
            require(slots.insert(iat_slot_rva), "duplicate IAT slot")?;
            let address = module_namespace::resolve(&exports, &leaf, &Symbol::Name(name.clone()))
                .map_err(|error| format!("actual dependency {leaf}!{name}: {error:?}"))?;
            let (index, owner) = exports.iter().enumerate().find(|(_, image)| address >= image.base
                && address < image.base + u64::from(image.size)).ok_or("resolved address lacks actual DLL owner")?;
            let rva = (address - owner.base) as u32;
            require(dlls[index].protection_at(rva).executable() && dlls[index].bytes_at_rva(rva, 1).is_some(), "import must resolve to actual executable DLL code")?;
            mapped.patch_iat(iat_slot_rva, address).map_err(|error| format!("IAT: {error:?}"))?;
            require(mapped.u64_at_rva(iat_slot_rva).map_err(|error| format!("IAT read: {error:?}"))? == address, "IAT readback mismatch")?;
        }
    }
    let expected: BTreeSet<_> = contract(font).into_iter().map(|(module, name)| (module.to_owned(), name.to_owned())).collect();
    require(seen == expected, "fixture imports differ from exact declared contract")?;
    println!("PASS static font fixture: actual DLL resolution and nonpreferred IAT binding");
    println!("fixture SHA256 {:x}", Sha256::digest(&exe_bytes));
    for ((name, _), bytes) in dll_paths.iter().zip(&dll_bytes) {
        println!("{name} SHA256 {:x}", Sha256::digest(bytes));
    }
    println!("Guest execution, process cleanup and desktop acceptance have NOT been run.");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (font, dlls) = if args.len() == 3 && args[0] == "setup" {
        (false, vec![("ntdll.dll", Path::new(&args[2]))])
    } else if args.len() == 5 && args[0] == "font" {
        (true, vec![("ntdll.dll", Path::new(&args[2])), ("kernel32.dll", Path::new(&args[3])), ("gdi32.dll", Path::new(&args[4]))])
    } else {
        eprintln!("usage: nt-font-test-verify setup <fixture.exe> <our-ntdll.dll> | font <fixture.exe> <our-ntdll.dll> <actual-kernel32.dll> <actual-gdi32.dll>");
        return ExitCode::FAILURE;
    };
    match verify(font, Path::new(&args[1]), &dlls) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("FAIL static font fixture: {error}"); ExitCode::FAILURE }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn setup_and_font_have_separate_exact_import_contracts() {
        assert_eq!(contract(false).len(), 7);
        assert_eq!(contract(true).len(), 6);
        assert!(contract(false).iter().all(|(module, _)| *module == "ntdll.dll"));
        assert!(contract(true).contains(&("gdi32.dll", "AddFontResourceExW")));
        assert!(!contract(true).iter().any(|(_, name)| name.contains("RemoveFont")));
        assert!(!contract(false).contains(&("ntdll.dll", "NtCreateProcess")));
    }
}
