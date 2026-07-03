//! Emit a synthetic .sys image to a path, for manual tool testing.
//!   cargo run -p nt-driver-test-fixtures --example emit -- <out.sys> [imports...]
use nt_driver_test_fixtures::{minimal_pe, pe_importing};

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("usage: emit <out.sys> [func...]");
    let funcs: Vec<String> = args.collect();
    let bytes = if funcs.is_empty() {
        minimal_pe()
    } else {
        let refs: Vec<&str> = funcs.iter().map(|s| s.as_str()).collect();
        pe_importing("ntoskrnl.exe", &refs)
    };
    std::fs::write(&out, bytes).unwrap();
    eprintln!("wrote {out}");
}
