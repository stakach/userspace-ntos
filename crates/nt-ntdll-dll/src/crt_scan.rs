//! Scanning entry point.  The full CRT format grammar is not implemented yet.

/// A failed scan is explicit.  Returning an assignment count here would claim
/// that caller-owned output arguments were initialized when they were not.
#[export_name = "sscanf"]
pub unsafe extern "C" fn sscanf(_input: *const u8, _format: *const u8, _args: ...) -> i32 {
    -1
}
