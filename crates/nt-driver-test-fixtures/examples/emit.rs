//! Emit a synthetic .sys image to a path, for manual tool testing.
//!   cargo run -p nt-driver-test-fixtures --example emit -- <out.sys> [imports...]
//!   cargo run -p nt-driver-test-fixtures --example emit -- <out.sys> --irp-fsd
use nt_driver_test_fixtures::{irp_fsd_pe, minimal_pe, pe_importing};

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("usage: emit <out.sys> [func...] | <out.sys> --irp-fsd");
    let rest: Vec<String> = args.collect();
    let bytes = if rest.first().map(|s| s.as_str()) == Some("--irp-fsd") {
        irp_fsd_pe()
    } else if rest.is_empty() {
        minimal_pe()
    } else {
        let refs: Vec<&str> = rest.iter().map(|s| s.as_str()).collect();
        pe_importing("ntoskrnl.exe", &refs)
    };
    std::fs::write(&out, bytes).unwrap();
    eprintln!("wrote {out}");
}
