//! Bounded observations of SYSTEM-journal attempts, never persistence or caller authority.
use crate::diagnostic_receipt_budget::{ReceiptBudget, LIFETIME_RECEIPT_LIMIT, RECEIPT_LIMIT};
use core::fmt::Write;
use nt_ahci::CommandWindowSnapshot;
use nt_fs::SnapshotJournalPhase;
use nt_memory_manager::SectionMountId;

static BUDGET: ReceiptBudget = ReceiptBudget::new();

/// Inputs are copied from the actual retained journal and its attempted durability operation.
/// A retained proof may predate this attempt; phases and result must be interpreted together.
pub(crate) fn system_journal(
    mount: SectionMountId,
    journal_bytes: usize,
    phase_before: SnapshotJournalPhase,
    phase_after: SnapshotJournalPhase,
    durability: Option<(u64, usize)>,
    result: Result<(), u32>,
    window: CommandWindowSnapshot,
) {
    let Some(receipt) = BUDGET.claim(crate::diagnostic_time_100ns()) else { return; };
    let mut record = nt_printf::record::RecordBuffer::<2048>::new();
    let _ = write!(
        record,
        "[registry-checkpoint] cause=system-journal actor=unavailable receipt={}/{} lifetime-receipt={}/{} window=",
        receipt.receipt, RECEIPT_LIMIT, receipt.lifetime_receipt, LIFETIME_RECEIPT_LIMIT,
    );
    match receipt.window {
        Some(epoch) => { let _ = write!(record, "{epoch}"); }
        None => { let _ = write!(record, "unavailable"); }
    }
    let _ = write!(
        record,
        " mount={} journal-bytes={journal_bytes} phase-before={phase_before:?} phase-after={phase_after:?}",
        mount.value(),
    );
    match result {
        Ok(()) => { let _ = write!(record, " result=ok status=0x00000000"); }
        Err(status) => { let _ = write!(record, " result=error status=0x{status:08x}"); }
    }
    match durability {
        Some((generation, bytes)) => {
            let _ = write!(record,
                " retained-proof=present snapshot-generation={generation} snapshot-bytes={bytes}");
        }
        None => { let _ = write!(record, " retained-proof=unavailable"); }
    }
    let _ = write!(record, " elapsed-100ns=");
    match window.elapsed_100ns {
        Some(elapsed) => { let _ = write!(record, "{elapsed}"); }
        None => { let _ = write!(record, "unavailable"); }
    }
    let _ = write!(record, " io-scope=inclusive commands=attempts sectors=requested ticks=caller-clock");
    for (name, delta) in [("read", window.read), ("write", window.write), ("barrier", window.barrier)] {
        let _ = write!(record,
            " {name}-attempts={} {name}-sectors={} {name}-ticks={} {name}-failures={}",
            delta.commands, delta.sectors, delta.ticks, delta.failures);
    }
    let _ = writeln!(record);
    sel4_rt::print_record(if record.overflowed() {
        b"[registry-checkpoint] record-truncated\n"
    } else {
        record.bytes()
    });
}
