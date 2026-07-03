#![no_main]
//! Fuzz the PE parser (spec §7.2: "Fuzz PE parsing before running real driver
//! images"). No input may panic; every path returns a structured error.
//!
//!   cargo +nightly fuzz run pe_parse
use libfuzzer_sys::fuzz_target;
use nt_pe_loader::PeFile;

fuzz_target!(|data: &[u8]| {
    if let Ok(pe) = PeFile::parse(data) {
        let _ = pe.imports();
        let _ = pe.relocations();
        let _ = pe.map(0x1_0000_0000);
    }
});
