//! Bounded, deduplicated diagnostics for loader lookups that failed.
//!
//! One line names the module and export of a failed `LdrGetProcedureAddress`, the requested and
//! opened name of a failed DLL load, or the section and key of a failed activation-context
//! lookup. A [`FailureLedger`] admits each distinct failure once and at most `N` per process.

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use nt_printf::record::RecordBuffer;

/// Distinct failures already reported, by hash. Lock-free: lookups run on any thread.
pub struct FailureLedger<const N: usize> {
    seen: [AtomicU64; N],
}

impl<const N: usize> FailureLedger<N> {
    pub const fn new() -> Self {
        Self {
            seen: [const { AtomicU64::new(0) }; N],
        }
    }

    /// Whether this failure is new and there is still room to report it.
    pub fn admit(&self, failure: u64) -> bool {
        let failure = failure.max(1);
        for slot in &self.seen {
            match slot.compare_exchange(0, failure, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(existing) if existing == failure => return false,
                Err(_) => {}
            }
        }
        false
    }

    pub fn reset(&self) {
        for slot in &self.seen {
            slot.store(0, Ordering::Release);
        }
    }
}

impl<const N: usize> Default for FailureLedger<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// FNV-1a over the parts, with a separator so `("ab", "c")` and `("a", "bc")` differ.
pub fn failure_hash(parts: &[&[u8]]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for part in parts {
        for &byte in part.iter().chain(&[0xff]) {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

pub type FailureRecord = RecordBuffer<320>;

fn push_quoted(record: &mut FailureRecord, text: impl IntoIterator<Item = u16>) {
    record.push_bytes(b"\"");
    for unit in text {
        let byte = match unit {
            0x20..=0x7e if unit != 0x22 => unit as u8,
            _ => b'?',
        };
        record.push_bytes(&[byte]);
    }
    record.push_bytes(b"\"");
}

fn ascii(text: &[u8]) -> impl Iterator<Item = u16> + '_ {
    text.iter().map(|&byte| u16::from(byte))
}

fn finish(mut record: FailureRecord, status: u32) -> FailureRecord {
    let _ = core::write!(&mut record, " status=0x{status:08x}\n");
    record
}

/// A failed `LdrGetProcedureAddress`: `name` is the export name, or `None` for a lookup by
/// `ordinal`.
pub fn record_procedure_miss(
    module: &[u8],
    name: Option<&[u8]>,
    ordinal: u32,
    status: u32,
) -> FailureRecord {
    let mut record = FailureRecord::new();
    record.push_bytes(b"[ldr-proc-miss] module=");
    push_quoted(&mut record, ascii(module));
    match name {
        Some(name) => {
            record.push_bytes(b" export=");
            push_quoted(&mut record, ascii(name));
        }
        None => {
            let _ = core::write!(&mut record, " ordinal={ordinal}");
        }
    }
    finish(record, status)
}

/// A DLL that could not be loaded: the name asked for and the name file-name redirection opened.
pub fn record_load_failure(requested: &[u8], opened: &[u8], status: u32) -> FailureRecord {
    let mut record = FailureRecord::new();
    record.push_bytes(b"[ldr-load-failed] name=");
    push_quoted(&mut record, ascii(requested));
    if opened != requested {
        record.push_bytes(b" open=");
        push_quoted(&mut record, ascii(opened));
    }
    finish(record, status)
}

/// A DLL name that file-name redirection sent to another image, and how its load ended.
pub fn record_redirected_load(requested: &[u8], opened: &[u8], status: u32, base: u64) -> FailureRecord {
    let mut record = FailureRecord::new();
    record.push_bytes(b"[ldr-redirect] name=");
    push_quoted(&mut record, ascii(requested));
    record.push_bytes(b" open=");
    push_quoted(&mut record, ascii(opened));
    let _ = core::write!(&mut record, " base=0x{base:x}");
    finish(record, status)
}

/// A module loaded from a redirected path was unloaded.
pub fn record_redirected_unload(path: &[u8], base: u64, status: u32) -> FailureRecord {
    let mut record = FailureRecord::new();
    record.push_bytes(b"[ldr-unload-redirected] path=");
    push_quoted(&mut record, ascii(path));
    let _ = core::write!(&mut record, " base=0x{base:x}");
    finish(record, status)
}

/// A failed activation-context section lookup by string key.
pub fn record_section_lookup_failure(section_id: u32, key: &[u16], status: u32) -> FailureRecord {
    let mut record = FailureRecord::new();
    let _ = core::write!(&mut record, "[actctx-lookup-failed] section={section_id} key=");
    push_quoted(&mut record, key.iter().copied().take(96));
    finish(record, status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_module_and_export_of_a_failed_procedure_lookup() {
        assert_eq!(
            record_procedure_miss(b"browseui", Some(b"DllGetClassObject"), 0, 0xc000_0139).bytes(),
            &b"[ldr-proc-miss] module=\"browseui\" export=\"DllGetClassObject\" status=0xc0000139\n"[..]
        );
        assert_eq!(
            record_procedure_miss(b"comctl32", None, 17, 0xc000_0138).bytes(),
            &b"[ldr-proc-miss] module=\"comctl32\" ordinal=17 status=0xc0000138\n"[..]
        );
    }

    #[test]
    fn names_the_requested_and_opened_dll_of_a_failed_load() {
        assert_eq!(
            record_load_failure(
                b"api-ms-win-composition-windowmanager-l1-1-0.dll",
                b"udwm.dll",
                0xc000_0135
            )
            .bytes(),
            &b"[ldr-load-failed] name=\"api-ms-win-composition-windowmanager-l1-1-0.dll\" open=\"udwm.dll\" status=0xc0000135\n"[..]
        );
        assert_eq!(
            record_load_failure(b"system32\\nfs41_np.dll", b"system32\\nfs41_np.dll", 0xc000_0135)
                .bytes(),
            &b"[ldr-load-failed] name=\"system32\\nfs41_np.dll\" status=0xc0000135\n"[..]
        );
    }

    #[test]
    fn names_the_redirected_image_and_its_base() {
        assert_eq!(
            record_redirected_load(b"comctl32.dll", b"c:\\w\\winsxs\\a\\comctl32.dll", 0, 0x7ff0_0000).bytes(),
            &b"[ldr-redirect] name=\"comctl32.dll\" open=\"c:\\w\\winsxs\\a\\comctl32.dll\" base=0x7ff00000 status=0x00000000\n"[..]
        );
    }

    #[test]
    fn names_an_unloaded_redirected_module() {
        assert_eq!(
            record_redirected_unload(b"c:\\a\\x.dll", 0x10000, 0).bytes(),
            &b"[ldr-unload-redirected] path=\"c:\\a\\x.dll\" base=0x10000 status=0x00000000\n"[..]
        );
    }

    #[test]
    fn names_the_section_and_key_of_a_failed_lookup_in_printable_ascii() {
        let key: alloc::vec::Vec<u16> = "Sta\"tic\u{4e2d}".encode_utf16().collect();
        assert_eq!(
            record_section_lookup_failure(3, &key, 0xc015_0001).bytes(),
            &b"[actctx-lookup-failed] section=3 key=\"Sta?tic?\" status=0xc0150001\n"[..]
        );
    }

    #[test]
    fn a_long_name_is_truncated_not_dropped() {
        let record = record_load_failure(&[b'a'; 400], &[b'a'; 400], 0xc000_0135);
        assert_eq!(record.bytes().len(), 320);
        assert!(record.bytes().starts_with(b"[ldr-load-failed] name=\"aaaa"));
    }

    #[test]
    fn ledger_reports_each_failure_once_and_stops_at_capacity() {
        let ledger = FailureLedger::<3>::new();
        let a = failure_hash(&[b"browseui", b"DllGetClassObject"]);
        let b = failure_hash(&[b"browseu", b"iDllGetClassObject"]);
        assert_ne!(a, b);
        assert!(ledger.admit(a));
        assert!(!ledger.admit(a));
        assert!(ledger.admit(b));
        assert!(ledger.admit(0));
        assert!(!ledger.admit(1)); // 0 is recorded as 1
        assert!(!ledger.admit(failure_hash(&[b"fourth"])));
        assert!(!ledger.admit(a));
        ledger.reset();
        assert!(ledger.admit(failure_hash(&[b"fourth"])));
    }
}
