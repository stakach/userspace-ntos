//! Step 4.0 proof: parse our emitted PE32+ `ntdll.dll` with the executive's OWN loader
//! (`nt-pe-loader::PeFile`) and assert the properties Step 4.B relies on.
//!
//! Usage:
//! - `ntdll-dll-verify [path-to-dll]` (defaults to `.tmp/nt-ntdll.dll`)
//! - `ntdll-dll-verify --wine-manifest [path-to-ntdll.spec]`
//! - `ntdll-dll-verify --wine-report [path-to-dll]`
//! - `ntdll-dll-verify --compare-exports <reference-dll> <built-dll>` (names gate; ordinals report)
//!
//! If our own loader can read it — headers, export directory, relocations — then the executive can
//! load it in-boot. Exits non-zero on any failure so the build script / CI can gate on it.

use std::path::Path;
use std::process::ExitCode;

use nt_pe_loader::PeFile;
use nt_syscall_abi::{NT_SYSCALLS, ZW_ALIASES};

mod native_stub;
mod wine_spec;

// IMAGE_FILE_CHARACTERISTICS.IMAGE_FILE_DLL
const IMAGE_FILE_DLL: u16 = 0x2000;
// PE32+ optional-header magic.
const PE32PLUS_MAGIC: u16 = 0x020b;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--compare-exports") {
        let Some(reference) = args.next() else {
            eprintln!("!! --compare-exports requires a reference DLL and a built DLL");
            return ExitCode::FAILURE;
        };
        let Some(built) = args.next() else {
            eprintln!("!! --compare-exports requires a built DLL");
            return ExitCode::FAILURE;
        };
        if let Some(extra) = args.next() {
            eprintln!("!! unexpected argument {extra:?}");
            return ExitCode::FAILURE;
        }
        return match compare_exports(Path::new(&reference), Path::new(&built)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("!! {error}");
                ExitCode::FAILURE
            }
        };
    }
    if matches!(first.as_deref(), Some("--wine-manifest" | "--wine-report")) {
        let mode = first.as_deref().unwrap();
        let path = args.next().unwrap_or_else(|| match mode {
            "--wine-manifest" => "references/wine/dlls/ntdll/ntdll.spec".to_string(),
            "--wine-report" => ".tmp/nt-ntdll.dll".to_string(),
            _ => unreachable!(),
        });
        if let Some(extra) = args.next() {
            eprintln!("!! unexpected argument {extra:?}");
            return ExitCode::FAILURE;
        }
        let result = match mode {
            "--wine-manifest" => wine_spec::generate_manifest(Path::new(&path)),
            "--wine-report" => wine_spec::report(Path::new(&path)),
            _ => unreachable!(),
        };
        return match result {
            Ok(output) => {
                print!("{output}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("!! {error}");
                ExitCode::FAILURE
            }
        };
    }
    let path = first.unwrap_or_else(|| ".tmp/nt-ntdll.dll".to_string());
    if let Some(extra) = args.next() {
        eprintln!("!! unexpected argument {extra:?}");
        return ExitCode::FAILURE;
    }

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("!! cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "==> verifying {path} ({} bytes) with nt-pe-loader::PeFile",
        bytes.len()
    );

    let pe = match PeFile::parse(&bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("!! nt-pe-loader failed to parse the DLL: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let h = pe.headers();

    let mut ok = true;
    let mut check = |cond: bool, msg: &str| {
        println!("   [{}] {msg}", if cond { "PASS" } else { "FAIL" });
        ok &= cond;
    };

    check(
        h.magic == PE32PLUS_MAGIC,
        &format!("PE32+ (magic {:#06x})", h.magic),
    );
    check(
        h.characteristics & IMAGE_FILE_DLL != 0,
        &format!(
            "IMAGE_FILE_DLL set (characteristics {:#06x})",
            h.characteristics
        ),
    );
    println!(
        "       image_base={:#x} size_of_image={:#x} entry_rva={:#x} subsystem={}",
        pe.image_base(),
        pe.size_of_image(),
        pe.entry_point_rva(),
        pe.subsystem()
    );

    // Sections.
    let secs: Vec<&str> = pe.sections().iter().map(|s| s.name_str()).collect();
    println!("       sections: {}", secs.join(" "));
    check(secs.iter().any(|s| s.starts_with(".text")), ".text present");
    check(
        secs.iter().any(|s| s.starts_with(".reloc")),
        ".reloc section present",
    );

    // Exports: parse the export directory with our own loader.
    let exports = match pe.exports() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("!! nt-pe-loader failed to parse the export directory: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let names: std::collections::BTreeSet<&str> = exports.iter().map(|e| e.name.as_str()).collect();
    println!("       total exports: {}", exports.len());

    // LdrpInitialize present + report its RVA (Step 4.B points the trampoline here).
    let ldr = exports.iter().find(|e| e.name == "LdrpInitialize");
    check(ldr.is_some(), "LdrpInitialize exported");
    if let Some(l) = ldr {
        println!("       LdrpInitialize RVA = {:#x}", l.rva);
    }

    // Every Nt* from the shared ABI must be exported.
    let mut missing = Vec::new();
    for e in NT_SYSCALLS {
        if !names.contains(e.name) {
            missing.push(e.name);
        }
    }
    check(
        missing.is_empty(),
        &format!(
            "all {} Nt* stubs exported ({} missing)",
            NT_SYSCALLS.len(),
            missing.len()
        ),
    );
    if !missing.is_empty() {
        eprintln!("   missing Nt* exports: {missing:?}");
    }

    let mut missing_zw = Vec::new();
    for alias in ZW_ALIASES {
        if !names.contains(alias.zw_name) {
            missing_zw.push(alias.zw_name);
        }
    }
    check(
        missing_zw.is_empty(),
        &format!(
            "all {} Zw* aliases exported ({} missing)",
            ZW_ALIASES.len(),
            missing_zw.len()
        ),
    );
    if !missing_zw.is_empty() {
        eprintln!("   missing Zw* exports: {missing_zw:?}");
    }

    // Spot-check the canonical few.
    for spot in [
        "KiUserCallbackDispatcher",
        "NtCallbackReturn",
        "NtClose",
        "NtCreateFile",
        "NtOpenFile",
        "NtDelayExecution",
        "NtWaitForSingleObject",
        "NtProtectVirtualMemory",
        "ZwCallbackReturn",
    ] {
        check(names.contains(spot), &format!("export {spot}"));
    }

    let nt_callback_return = exports.iter().find(|e| e.name == "NtCallbackReturn");
    let zw_callback_return = exports.iter().find(|e| e.name == "ZwCallbackReturn");
    if let (Some(nt), Some(zw)) = (nt_callback_return, zw_callback_return) {
        let image = pe.map(pe.image_base()).expect("map emitted ntdll");
        let nt_stub = &image.bytes[nt.rva as usize..];
        check(
            native_stub::matches(nt_stub, 22, 3),
            "NtCallbackReturn encodes SSN 22",
        );
        let zw_stub = &image.bytes[zw.rva as usize..zw.rva as usize + 5];
        check(
            zw_stub.first() == Some(&0xe9),
            "ZwCallbackReturn is a tail-jump alias",
        );
    }

    // A whole-body template validates every instruction and control-flow edge, including the
    // retained argument vector, retry restaging, IPC selection and complete Win64 epilogue.
    let image = pe.map(pe.image_base()).expect("map emitted ntdll");
    let mut bad_native = Vec::new();
    let mut bad_unwind = Vec::new();
    let exception_directory = pe.headers().data_directory(3);
    let pdata = pe
        .bytes_at_rva(
            exception_directory.virtual_address,
            exception_directory.size as usize,
        )
        .unwrap_or(&[]);
    for syscall in NT_SYSCALLS {
        let Some(export) = exports.iter().find(|export| export.name == syscall.name) else {
            continue;
        };
        let argc = nt_syscall_abi::exact_argc_of(syscall.name)
            .expect("every canonical syscall has an exact argument count");
        if !image
            .bytes
            .get(export.rva as usize..)
            .is_some_and(|stub| native_stub::matches(stub, syscall.ssn, argc))
        {
            bad_native.push(syscall.name);
        }
        if !native_stub::unwind_matches(pdata, &image.bytes, export.rva) {
            bad_unwind.push(syscall.name);
        }
    }
    check(
        bad_native.is_empty(),
        &format!(
            "all {} native Nt* bodies preserve Win64 state, exact arguments and retry framing ({} violations)",
            NT_SYSCALLS.len(), bad_native.len()
        ),
    );
    if !bad_native.is_empty() {
        eprintln!("   native instruction-template violations: {bad_native:?}");
    }
    check(
        bad_unwind.is_empty(),
        &format!(
            "all {} native Nt* bodies have exact runtime-function/unwind coverage ({} violations)",
            NT_SYSCALLS.len(),
            bad_unwind.len()
        ),
    );
    if !bad_unwind.is_empty() {
        eprintln!("   native unwind-metadata violations: {bad_unwind:?}");
    }

    // Base relocations parse cleanly (the .reloc directory the loader will apply).
    match pe.relocations() {
        Ok(relocs) => check(
            !relocs.is_empty(),
            &format!("base relocations parse ({} fixups)", relocs.len()),
        ),
        Err(e) => check(false, &format!("base relocations parse ({e:?})")),
    }

    // ---------------------------------------------------------------------------------------------
    // Step 4.0b — smss import-coverage gate: parse smss.exe's ntdll imports and assert EVERY symbol
    // it imports from ntdll is present in OUR export table (0 missing). smss statically imports ONLY
    // ntdll, so this proves our DLL is a complete drop-in for smss (the Step 4.A first target).
    // ---------------------------------------------------------------------------------------------
    if let Some(smss_missing) = smss_import_coverage(&names) {
        check(
            smss_missing.is_empty(),
            &format!(
                "smss.exe ntdll import set fully covered ({} missing)",
                smss_missing.len()
            ),
        );
        if !smss_missing.is_empty() {
            let mut m = smss_missing;
            m.sort();
            eprintln!("   MISSING smss ntdll imports (not exported by our DLL): {m:?}");
        }
    } else {
        println!("   [SKIP] smss.exe not found — skipping the smss import-coverage cross-check");
    }

    // ---------------------------------------------------------------------------------------------
    // BATCH 4 — Win32-stack import-coverage gate: for EACH DLL the csrss cascade loads, assert its
    // COMPLETE ntdll import set (direct imports + forwards-to-ntdll) is present in OUR export table
    // (0 missing). This is the export-completion bar for the whole client stack (like the smss check
    // generalized). A DLL absent from the checkout is skipped (not failed).
    // ---------------------------------------------------------------------------------------------
    const STACK_DLLS: &[&str] = &[
        "csrsrv", "basesrv", "winsrv", "gdi32", "user32", "advapi32", "rpcrt4", "kernel32",
        "ws2_32", "ws2help", "msvcrt",
    ];
    for dll in STACK_DLLS {
        match stack_dll_import_coverage(dll, &names) {
            Some((imported, missing)) => {
                check(
                    missing.is_empty(),
                    &format!(
                        "{dll}.dll ntdll import set fully covered ({imported} imported, {} missing)",
                        missing.len()
                    ),
                );
                if !missing.is_empty() {
                    let mut m = missing;
                    m.sort();
                    eprintln!("   MISSING {dll} ntdll imports (not exported by our DLL): {m:?}");
                }
            }
            None => {
                println!("   [SKIP] {dll}.dll not found — skipping its import-coverage cross-check")
            }
        }
    }

    if ok {
        println!("==> OK: nt-pe-loader can load our ntdll.dll (PE32+/DLL, complete Nt* ABI + LdrpInitialize, .reloc)");
        ExitCode::SUCCESS
    } else {
        eprintln!("!! verification FAILED");
        ExitCode::FAILURE
    }
}

fn compare_exports(reference: &Path, built: &Path) -> Result<(), String> {
    use std::collections::BTreeMap;

    fn read_exports(path: &Path) -> Result<BTreeMap<String, u16>, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let pe = PeFile::parse(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
        let exports = pe.exports().map_err(|e| format!("{}: {e:?}", path.display()))?;
        Ok(exports.into_iter().map(|e| (e.name, e.ordinal)).collect())
    }

    let expected = read_exports(reference)?;
    let actual = read_exports(built)?;
    let missing: Vec<_> = expected.keys().filter(|name| !actual.contains_key(*name)).collect();
    let wrong_ordinal: Vec<_> = expected
        .iter()
        .filter_map(|(name, ordinal)| {
            actual.get(name).filter(|found| *found != ordinal).map(|found| (name, ordinal, found))
        })
        .collect();
    println!(
        "LiberNT ntdll exports: {} reference, {} built; {} missing names, {} ordinal mismatches",
        expected.len(), actual.len(), missing.len(), wrong_ordinal.len()
    );
    for name in missing.iter().take(30) {
        eprintln!("   missing: {name}");
    }
    for (name, expected, found) in wrong_ordinal.iter().take(30) {
        eprintln!("   ordinal: {name} expected {expected}, found {found}");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err("source-built ntdll is missing installed LiberNT export names".into())
    }
}

/// Parse a Win32-stack DLL's `ntdll.dll` imports (BY-NAME import descriptor + any exports that
/// FORWARD to `ntdll.X`, which also require us to export `X`) and return `(imported_count,
/// missing_names)`. `None` if the DLL isn't in the checkout.
fn stack_dll_import_coverage(
    dll: &str,
    our_exports: &std::collections::BTreeSet<&str>,
) -> Option<(usize, Vec<String>)> {
    let candidates = [
        format!("rust-micro/.tmp/reactos/reactos/system32/{dll}.dll"),
        format!(".tmp/reactos/reactos/system32/{dll}.dll"),
    ];
    let path = candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())?;
    let bytes = std::fs::read(path).ok()?;
    let pe = PeFile::parse(&bytes).ok()?;

    let mut needed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    // (1) direct by-name imports from the ntdll.dll descriptor.
    if let Ok(imports) = pe.imports() {
        for d in &imports {
            if d.name.eq_ignore_ascii_case("ntdll.dll") {
                for f in &d.functions {
                    if let nt_pe_loader::ImportRef::ByName { name, .. } = f {
                        needed.insert(name.clone());
                    }
                }
            }
        }
    }

    // (2) exports that FORWARD to ntdll.X (e.g. kernel32!GetLastError -> ntdll.RtlGetLastWin32Error):
    // resolving the DLL requires us to export X too. A forwarder export's RVA falls inside the export
    // directory range and its target string is `"TARGETDLL.func"`.
    if let Ok(exports) = pe.exports() {
        let dir = pe
            .headers()
            .data_directory(nt_pe_loader::DIRECTORY_ENTRY_EXPORT);
        let (lo, hi) = (dir.virtual_address, dir.virtual_address + dir.size);
        for e in &exports {
            if e.rva >= lo && e.rva < hi {
                if let Ok(s) = pe.cstr_at_rva(e.rva) {
                    if let Some((tgt_dll, tgt_fn)) = s.rsplit_once('.') {
                        if tgt_dll.eq_ignore_ascii_case("ntdll") && !tgt_fn.starts_with('#') {
                            needed.insert(tgt_fn.to_string());
                        }
                    }
                }
            }
        }
    }

    let imported = needed.len();
    let missing: Vec<String> = needed
        .into_iter()
        .filter(|n| !our_exports.contains(n.as_str()))
        .collect();
    Some((imported, missing))
}

/// Parse smss.exe's `ntdll.dll` import descriptor and return the names it imports that are NOT in
/// `our_exports` (i.e. the missing coverage). Returns `None` if smss.exe can't be found (so the
/// check is skipped, not failed, in a checkout without the staged ReactOS tree).
fn smss_import_coverage(our_exports: &std::collections::BTreeSet<&str>) -> Option<Vec<String>> {
    // Candidate locations for the staged ReactOS smss.exe (relative to CWD = repo root at build).
    const CANDIDATES: &[&str] = &[
        "rust-micro/.tmp/reactos/reactos/system32/smss.exe",
        ".tmp/reactos/reactos/system32/smss.exe",
    ];
    let path = CANDIDATES
        .iter()
        .find(|p| std::path::Path::new(p).exists())?;
    let bytes = std::fs::read(path).ok()?;
    let pe = PeFile::parse(&bytes).ok()?;
    let imports = pe.imports().ok()?;

    // Collect the by-name imports from the ntdll.dll descriptor.
    let mut ntdll_imports: Vec<String> = Vec::new();
    for dll in &imports {
        if dll.name.eq_ignore_ascii_case("ntdll.dll") {
            for f in &dll.functions {
                if let nt_pe_loader::ImportRef::ByName { name, .. } = f {
                    ntdll_imports.push(name.clone());
                }
            }
        }
    }
    println!(
        "==> smss.exe imports {} symbols from ntdll.dll ({})",
        ntdll_imports.len(),
        path
    );

    let missing: Vec<String> = ntdll_imports
        .into_iter()
        .filter(|n| !our_exports.contains(n.as_str()))
        .collect();
    Some(missing)
}
