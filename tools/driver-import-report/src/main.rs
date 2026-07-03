//! `driver-import-report <driver.sys>` — print a driver's imports + whether the
//! Driver Host can run it, exiting non-zero when it cannot (spec §15).

use std::process::ExitCode;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: driver-import-report <driver.sys>");
            return ExitCode::from(2);
        }
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    match driver_import_report::analyze(&bytes) {
        Ok(a) => {
            print!("{}", driver_import_report::render(&a));
            if a.runnable() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(2)
        }
    }
}
