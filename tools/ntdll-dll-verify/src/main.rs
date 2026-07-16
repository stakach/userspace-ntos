//! Step 4.0 proof: parse our emitted PE32+ `ntdll.dll` with the executive's OWN loader
//! (`nt-pe-loader::PeFile`) and assert the properties Step 4.B relies on.
//!
//! Usage: `ntdll-dll-verify [path-to-dll]` (defaults to `.tmp/nt-ntdll.dll`).
//!
//! If our own loader can read it — headers, export directory, relocations — then the executive can
//! load it in-boot. Exits non-zero on any failure so the build script / CI can gate on it.

use std::process::ExitCode;

use nt_pe_loader::PeFile;
use nt_syscall_abi::NT_SYSCALLS;

// IMAGE_FILE_CHARACTERISTICS.IMAGE_FILE_DLL
const IMAGE_FILE_DLL: u16 = 0x2000;
// PE32+ optional-header magic.
const PE32PLUS_MAGIC: u16 = 0x020b;

fn main() -> ExitCode {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".tmp/nt-ntdll.dll".to_string());

    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("!! cannot read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("==> verifying {path} ({} bytes) with nt-pe-loader::PeFile", bytes.len());

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

    check(h.magic == PE32PLUS_MAGIC, &format!("PE32+ (magic {:#06x})", h.magic));
    check(
        h.characteristics & IMAGE_FILE_DLL != 0,
        &format!("IMAGE_FILE_DLL set (characteristics {:#06x})", h.characteristics),
    );
    println!("       image_base={:#x} size_of_image={:#x} entry_rva={:#x} subsystem={}",
        pe.image_base(), pe.size_of_image(), pe.entry_point_rva(), pe.subsystem());

    // Sections.
    let secs: Vec<&str> = pe.sections().iter().map(|s| s.name_str()).collect();
    println!("       sections: {}", secs.join(" "));
    check(secs.iter().any(|s| s.starts_with(".text")), ".text present");
    check(secs.iter().any(|s| s.starts_with(".reloc")), ".reloc section present");

    // Exports: parse the export directory with our own loader.
    let exports = match pe.exports() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("!! nt-pe-loader failed to parse the export directory: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let names: std::collections::BTreeSet<&str> =
        exports.iter().map(|e| e.name.as_str()).collect();
    println!("       total exports: {}", exports.len());

    // LdrpInitialize present + report its RVA (Step 4.B points the trampoline here).
    let ldr = exports.iter().find(|e| e.name == "LdrpInitialize");
    check(ldr.is_some(), "LdrpInitialize exported");
    if let Some(l) = ldr {
        println!("       LdrpInitialize RVA = {:#x}", l.rva);
    }

    // All 188 Nt* from the shared ABI must be exported.
    let mut missing = Vec::new();
    for e in NT_SYSCALLS {
        if !names.contains(e.name) {
            missing.push(e.name);
        }
    }
    check(
        missing.is_empty(),
        &format!("all {} Nt* stubs exported ({} missing)", NT_SYSCALLS.len(), missing.len()),
    );
    if !missing.is_empty() {
        eprintln!("   missing Nt* exports: {missing:?}");
    }

    // Spot-check the canonical few.
    for spot in [
        "NtClose",
        "NtCreateFile",
        "NtOpenFile",
        "NtDelayExecution",
        "NtWaitForSingleObject",
        "NtProtectVirtualMemory",
    ] {
        check(names.contains(spot), &format!("export {spot}"));
    }

    // Base relocations parse cleanly (the .reloc directory the loader will apply).
    match pe.relocations() {
        Ok(relocs) => check(!relocs.is_empty(), &format!("base relocations parse ({} fixups)", relocs.len())),
        Err(e) => check(false, &format!("base relocations parse ({e:?})")),
    }

    if ok {
        println!("==> OK: nt-pe-loader can load our ntdll.dll (PE32+/DLL, 188 Nt* + LdrpInitialize, .reloc)");
        ExitCode::SUCCESS
    } else {
        eprintln!("!! verification FAILED");
        ExitCode::FAILURE
    }
}
