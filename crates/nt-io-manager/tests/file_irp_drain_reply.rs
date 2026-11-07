//! A parked NtCancelIoFile call retains its Reply and File owner through uncertain delivery.

use nt_io_manager::{PendingFileIrpDrain, PendingFileIrpDrainTable};

fn pending(file_id: u64, tid: u64, reply_cap: u64) -> PendingFileIrpDrain {
    PendingFileIrpDrain {
        file_id,
        pi: 2,
        process: Some(nt_types::ProcessIdentity {
            pid: 72,
            generation: nt_types::ProcessGeneration::Hosted(1),
        }),
        tid,
        badge: tid,
        iosb_va: 0x1000,
        reply_cap,
        ..PendingFileIrpDrain::default()
    }
}

#[test]
fn uncertain_reply_keeps_original_cap_and_file_while_other_drain_finishes() {
    let mut table = PendingFileIrpDrainTable::new();
    let first = table.reserve().unwrap();
    let first = table.park_reserved(first, pending(10, 20, 30)).unwrap();
    let second = table.reserve().unwrap();
    let second = table.park_reserved(second, pending(11, 21, 31)).unwrap();
    table.mark_iosb_published_exact(first, 10, 20).unwrap();
    table.mark_iosb_published_exact(second, 11, 21).unwrap();

    assert_eq!(table.begin_reply_exact(first, 10, 20), Some(30));
    assert_eq!(table.get(first).unwrap().reply_cap, 30);
    let exact = pending(10, 20, 30).process.unwrap();
    assert!(table.has_process_exact(2, exact));
    assert!(!table.has_process_exact(3, exact));
    assert!(!table.has_process_exact(2, nt_types::ProcessIdentity {
        pid: exact.pid,
        generation: nt_types::ProcessGeneration::Hosted(2),
    }));
    assert_eq!(table.take_thread_with(20, |_| panic!("entered Reply cannot be discarded")), 0);
    assert_eq!(table.begin_reply_exact(first, 10, 20), None, "uncertain send cannot replay");
    assert_eq!(table.finish_reply_exact(first, 10, 20, false), None);
    assert!(table.finish_exact(first, 10, 20).is_none());
    assert_eq!(table.get(first).unwrap().file_id, 10);
    assert_eq!(table.get(first).unwrap().reply_cap, 30);

    assert_eq!(table.begin_reply_exact(second, 11, 21), Some(31));
    assert!(table.finish_reply_exact(second, 11, 21, true).is_some());
    let finished = table.finish_exact(second, 11, 21).unwrap();
    assert_eq!((finished.file_id, finished.reply_cap), (11, 31));
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(first).unwrap().reply_cap, 30);
}
