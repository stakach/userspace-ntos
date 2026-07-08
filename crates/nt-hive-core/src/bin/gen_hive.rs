//! Host-side build tool: emit a minimal NT registry hive (nt-hive-core image format) for the
//! Config Manager to read off the boot disk. Writes `argv[1]` (default `hive.dat`). Uses std
//! (a host tool); the nt-hive-core *library* stays `no_std` — cargo builds bins only for the
//! host, and path-dep builds (the executive) don't build bins, so this is invisible there.

use nt_hive_core::{encode_image, Hive, HiveKind};

fn main() {
    let out = std::env::args().nth(1).unwrap_or_else(|| "hive.dat".to_string());
    let mut hive = Hive::new(HiveKind::System);
    // A recognizable marker the executive reads back: ...\NtosTest\Answer = REG_DWORD 42.
    let key = hive.create_key(r"ControlSet001\Services\NtosTest");
    hive.set_dword(key, "Answer", 42);
    let bytes = encode_image(&hive);
    std::fs::write(&out, &bytes).expect("write hive image");
    eprintln!("gen_hive: wrote {} ({} bytes)", out, bytes.len());
}
