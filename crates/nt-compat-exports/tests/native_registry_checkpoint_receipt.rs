//! Exercise the actual native formatter with the real census and journal observation types.
extern crate self as sel4_rt;

use nt_ahci::{CommandWindowSnapshot, IoSnapshot};
use nt_fs::SnapshotJournalPhase;
use nt_memory_manager::SectionMountIds;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CLOCK_AVAILABLE: AtomicBool = AtomicBool::new(false);
static CLOCK: AtomicU64 = AtomicU64::new(0);

fn diagnostic_time_100ns() -> Option<u64> {
    CLOCK_AVAILABLE.load(Ordering::Relaxed).then(|| CLOCK.load(Ordering::Relaxed))
}

pub fn print_record(bytes: &[u8]) {
    OUTPUT.lock().unwrap().extend_from_slice(bytes);
}

#[path = "../../../components/ntos-executive/src/diagnostic_receipt_budget.rs"]
mod diagnostic_receipt_budget;
#[path = "../../../components/ntos-executive/src/registry_checkpoint_audit.rs"]
mod native_audit;

fn output() -> String {
    String::from_utf8(std::mem::take(&mut *OUTPUT.lock().unwrap())).unwrap()
}

#[test]
fn actual_checkpoint_receipt_reports_observations_without_fabricated_proof() {
    let mount = SectionMountIds::new().allocate().unwrap();
    let empty = CommandWindowSnapshot {
        read: IoSnapshot::default(),
        write: IoSnapshot::default(),
        barrier: IoSnapshot::default(),
        elapsed_100ns: None,
    };
    native_audit::system_journal(mount, 195, SnapshotJournalPhase::FlushPending,
        SnapshotJournalPhase::FlushPending, None, Err(0xc0000185), empty);
    let failed = output();
    for field in ["actor=unavailable", "window=unavailable", "mount=1 journal-bytes=195",
        "phase-before=FlushPending phase-after=FlushPending", "result=error status=0xc0000185",
        "retained-proof=unavailable", "elapsed-100ns=unavailable", "io-scope=inclusive",
        "commands=attempts sectors=requested ticks=caller-clock", "write-attempts=0"] {
        assert!(failed.contains(field), "missing {field}: {failed}");
    }
    assert_eq!(failed.lines().count(), 1);
    assert!(!failed.contains("snapshot-generation="));

    CLOCK_AVAILABLE.store(true, Ordering::Relaxed);
    let maximum = IoSnapshot {
        commands: u64::MAX, sectors: u64::MAX, ticks: u64::MAX, failures: u64::MAX,
    };
    native_audit::system_journal(mount, usize::MAX, SnapshotJournalPhase::Durable,
        SnapshotJournalPhase::Durable, Some((u64::MAX, usize::MAX)), Ok(()),
        CommandWindowSnapshot {
            read: maximum, write: maximum, barrier: maximum, elapsed_100ns: Some(u64::MAX),
        });
    let repeated = output();
    for field in ["window=0", "phase-before=Durable phase-after=Durable",
        "result=ok status=0x00000000", "retained-proof=present", "snapshot-generation=18446744073709551615",
        "elapsed-100ns=18446744073709551615", "barrier-failures=18446744073709551615"] {
        assert!(repeated.contains(field), "missing {field}: {repeated}");
    }
    assert!(repeated.len() <= 2048);
    assert!(!repeated.contains("record-truncated"));
    assert!(!repeated.contains("new-commit"));

    // The first known epoch renews the unavailable epoch; its second claim is ordinal two.
    for _ in 2..128 {
        native_audit::system_journal(mount, 1, SnapshotJournalPhase::Durable,
            SnapshotJournalPhase::Durable, None, Ok(()), empty);
    }
    assert_eq!(output().lines().count(), 126);
    native_audit::system_journal(mount, 1, SnapshotJournalPhase::Durable,
        SnapshotJournalPhase::Durable, None, Ok(()), empty);
    assert_eq!(output().lines().count(), 1);
    native_audit::system_journal(mount, 1, SnapshotJournalPhase::Durable,
        SnapshotJournalPhase::Durable, None, Ok(()), empty);
    assert!(output().is_empty());
    CLOCK.store(60 * 10_000_000, Ordering::Relaxed);
    native_audit::system_journal(mount, 1, SnapshotJournalPhase::Durable,
        SnapshotJournalPhase::Durable, None, Ok(()), empty);
    let renewed = output();
    assert!(renewed.contains("receipt=1/128 lifetime-receipt=130/8192 window=1"));
}
