//! Background snapshot I/O must not deadlock a nested foreground owner (#412).
//!
//! Boot 44403153453 resumed a dirty disk. The lazy checkpoint became due as the route turned
//! Native and took the snapshot reserve. Only the outer root loop claims its I/O, but the root
//! was nested in bochsmp's PnP start. That start's registry write retried `acquire()` forever
//! with `storage-owner=unadmitted error=0x80000011`, so neither side could make progress.

#[path = "../../../components/ntos-executive/src/outer_native_io.rs"]
mod outer_native_io;

use outer_native_io::OuterNativeIo;

/// Minimal model: the reserve holder needs `io` outer claims; the nested foreground owner needs
/// the reserve. The nested frame yields to the outer owner only when `yields` says so.
fn run(yields: impl Fn(OuterNativeIo) -> bool) -> Result<usize, &'static str> {
    let mut checkpoint_io_left = 3u32;
    let mut reserve_held = true;
    for step in 0..32 {
        if !reserve_held {
            return Ok(step); // the foreground registry write acquires and completes
        }
        let work = OuterNativeIo { sector: false, background_snapshot: checkpoint_io_left != 0 };
        if yields(work) {
            checkpoint_io_left -= 1; // the outer owner claims and completes one command
            if checkpoint_io_left == 0 {
                reserve_held = false; // the checkpoint publishes and drops its lease
            }
        }
        // Otherwise the nested foreground owner sees BUSY and waits again.
    }
    Err("nested foreground owner and background reserve holder deadlocked")
}

#[test]
fn sector_only_readiness_reproduces_the_cycle() {
    assert!(run(|work| work.sector).is_err());
}

#[test]
fn background_snapshot_io_is_outer_work_and_breaks_the_cycle() {
    assert!(run(OuterNativeIo::queued).is_ok());
    assert!(OuterNativeIo { sector: false, background_snapshot: true }.queued());
    assert!(OuterNativeIo { sector: true, background_snapshot: false }.queued());
    assert!(!OuterNativeIo::default().queued());
}

#[test]
fn nested_readiness_and_wakes_count_background_snapshot_owners() {
    let block = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let queued = block
        .split("fn queued_timer_work() -> bool {")
        .nth(1)
        .expect("queued outer work")
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(queued.contains("background_snapshot:"), "background snapshot I/O is outer work");
    assert!(queued.contains(".queued()"));
    let io = include_str!("../../../components/ntos-executive/src/writable_fs/native_snapshot_io.rs");
    let background = io
        .split("pub(crate) unsafe fn background_outer_io_queued() -> bool {")
        .nth(1)
        .expect("background predicate")
        .split("\n}\n")
        .next()
        .unwrap();
    for owner in ["native_checkpoint::outer_io_queued()", "system_wal_fold::native::outer_io_queued()"] {
        assert!(background.contains(owner), "{owner}");
    }
}
