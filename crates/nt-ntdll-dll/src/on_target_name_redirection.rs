//! `LdrpApplyFileNameRedirection` for the live loader, and its failure diagnostics.

use crate::loader_extra::{current_api_set_version, RELEASE_API_SETS};
use nt_ntdll::loader::failure_trace::{
    failure_hash, record_load_failure, record_procedure_miss, record_redirected_load,
    record_redirected_unload, FailureLedger, FailureRecord,
};
use nt_ntdll::loader::file_name_redirection::{LoadName, OPEN_CAPACITY};
use nt_ntdll::rtl::activation_redirection::RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL;
use nt_ntdll_layout::UnicodeString;

const STATUS_SXS_KEY_NOT_FOUND: u32 = 0xc015_0008;

static LOAD_FAILURES: FailureLedger<24> = FailureLedger::new();
static PROCEDURE_MISSES: FailureLedger<24> = FailureLedger::new();
static REDIRECTED_LOADS: FailureLedger<24> = FailureLedger::new();

pub(super) fn reset() {
    LOAD_FAILURES.reset();
    PROCEDURE_MISSES.reset();
    REDIRECTED_LOADS.reset();
}

fn counted(buffer: *const u16, length: usize, maximum_length: usize) -> UnicodeString {
    let mut string = UnicodeString::default();
    string.length = length as u16;
    string.maximum_length = maximum_length as u16;
    string.buffer = buffer as u64;
    string
}

fn emit(record: &FailureRecord) {
    unsafe { crate::dbg_print_bytes(record.bytes().as_ptr(), record.bytes().len()) };
}

/// Rewrite `name` to the image it loads: an api-set contract's host, or the path the active
/// activation context redirects it to. A name neither applies to is unchanged.
///
/// # Safety
/// On-target with the process heap installed; the loader lock is held.
// Kept out of line: the callers recurse, and these buffers must not sit in every frame.
#[inline(never)]
pub(super) unsafe fn apply(name: &mut LoadName) -> u32 {
    let versions = unsafe { current_api_set_version() };
    match name.apply_api_set(RELEASE_API_SETS, versions) {
        Ok(true) => return 0,
        Ok(false) => {}
        Err(status) => return status,
    }

    let mut original = [0u16; OPEN_CAPACITY];
    let requested = name.open_name();
    for (unit, &byte) in original.iter_mut().zip(requested) {
        *unit = u16::from(byte);
    }
    let original = counted(original.as_ptr(), requested.len() * 2, requested.len() * 2);
    // `LdrApiDefaultExtension`.
    let extension_units = [b'.' as u16, b'D' as u16, b'L' as u16, b'L' as u16];
    let extension = counted(extension_units.as_ptr(), 8, 8);
    let mut static_units = [0u16; 264];
    let mut static_string = counted(static_units.as_mut_ptr(), 0, static_units.len() * 2);
    let mut dynamic_string = UnicodeString::default();
    let mut full_path: *mut UnicodeString = core::ptr::null_mut();
    let status = unsafe {
        crate::exports::rtl_dos_apply_file_isolation_redirection_ustr(
            RTL_DOS_APPLY_FILE_REDIRECTION_USTR_FLAG_RESPECT_DOT_LOCAL,
            &original,
            &extension,
            &mut static_string,
            &mut dynamic_string,
            &mut full_path,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let result = if status == 0 && !full_path.is_null() {
        let redirected = unsafe { core::ptr::read_unaligned(full_path) };
        let path = unsafe {
            core::slice::from_raw_parts(
                redirected.buffer as *const u16,
                redirected.length as usize / 2,
            )
        };
        let system_root = unsafe { crate::exports::isolation_system_root() };
        match name.apply_redirected_path(path, &system_root) {
            Ok(()) => 0,
            Err(status) => status,
        }
    } else if status == STATUS_SXS_KEY_NOT_FOUND {
        0
    } else {
        status
    };
    if dynamic_string.buffer != 0 {
        unsafe { crate::process_heap_free(dynamic_string.buffer as *mut u8) };
    }
    result
}

/// Report a DLL that could not be loaded, once per distinct name and status.
pub(super) fn report_load_failure(requested: &[u8], opened: &[u8], status: u32) {
    if LOAD_FAILURES.admit(failure_hash(&[requested, opened, &status.to_le_bytes()])) {
        emit(&record_load_failure(requested, opened, status));
    }
}

/// Report a failed `LdrGetProcedureAddress`, once per distinct module, export and status.
pub(super) fn report_procedure_miss(module: &[u8], name: Option<&[u8]>, ordinal: u32, status: u32) {
    let hash = failure_hash(&[
        module,
        name.unwrap_or(&[]),
        &ordinal.to_le_bytes(),
        &status.to_le_bytes(),
    ]);
    if PROCEDURE_MISSES.admit(hash) {
        emit(&record_procedure_miss(module, name, ordinal, status));
    }
}

/// Report a load whose name file-name redirection sent to another image, once per distinct
/// name, image and status.
pub(super) fn report_redirected_load(requested: &[u8], opened: &[u8], status: u32, base: u64) {
    if requested == opened {
        return;
    }
    if REDIRECTED_LOADS.admit(failure_hash(&[requested, opened, &status.to_le_bytes()])) {
        emit(&record_redirected_load(requested, opened, status, base));
    }
}

/// Report the unload of a module loaded from a redirected path (bounded by the same ledger).
pub(super) fn report_redirected_unload(path: &[u8], base: u64, status: u32) {
    if !path.is_empty()
        && REDIRECTED_LOADS.admit(failure_hash(&[b"unload", path, &base.to_le_bytes()]))
    {
        emit(&record_redirected_unload(path, base, status));
    }
}
