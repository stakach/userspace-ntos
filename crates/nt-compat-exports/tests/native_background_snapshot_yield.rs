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

// Boot 44455362107 (e3f7a3bc): the same cycle recurred through a frame the yield cannot leave.
// bochsmp's BochsInitialize registry write runs in a *provider service-wait* nested frame
// during its PnP start. That frame is not an IRP receive and has no kernel IRQ yield, so
// `pump_scheduler_work_bits` is 0 for it and no outer-work readiness can make it yield.

const PUMP: &str = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
const HOSTS: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");

/// The nested frame kinds that matter here.
#[derive(Clone, Copy)]
struct Frame { irp: bool, kernel_irq_yield: bool }

/// `pump_scheduler_work_bits`: a frame yields to the outer owner only on IRP or kernel IRQ.
fn frame_can_yield(frame: Frame) -> bool { frame.irp || frame.kernel_irq_yield }

/// Model of the PnP-start service-wait frame: each turn the foreground registry write retries
/// admission; the holder progresses by the outer loop (only after a yield) or in-frame.
fn run_frame(frame: Frame, in_frame_holder_service: bool) -> Result<usize, &'static str> {
    let mut checkpoint_io_left = 3u32;
    for turn in 0..64 {
        if checkpoint_io_left == 0 { return Ok(turn); } // reserve released; write admitted
        let queued = OuterNativeIo { sector: false, background_snapshot: true }.queued();
        if (frame_can_yield(frame) && queued) || in_frame_holder_service {
            checkpoint_io_left -= 1;
        }
    }
    Err("provider registry write and background checkpoint deadlocked")
}

#[test]
fn a_provider_service_wait_frame_never_yields_so_yield_readiness_alone_deadlocks() {
    let service_wait = Frame { irp: false, kernel_irq_yield: false };
    assert!(run_frame(service_wait, false).is_err());
    let gate = HOSTS
        .split("unsafe fn pump_scheduler_work_bits(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(gate.contains("ch.caps.kind != ReqKind::Irp && !ch.caps.kernel_irq_yield { return 0; }"),
        "the yield gate this model encodes");
}

#[test]
fn the_nested_frame_drives_the_background_holder_in_place() {
    assert!(run_frame(Frame { irp: false, kernel_irq_yield: false }, true).is_ok());
    let wal = PUMP.find("service_mounted_native_registry_wal(id)").expect("registry WAL section");
    let holder = PUMP
        .find("if crate::driver_launch::mounted_native_background_holder_ready() {")
        .expect("in-frame background holder service");
    assert!(wal < holder, "serviced in the same nested loop as the provider registry write");
    let section = &PUMP[holder..];
    let section = &section[..section.find("let nested_file_ready").unwrap()];
    let park = section.find("runtime::nested::park_current()").unwrap();
    let service = section.find("service_mounted_native_background_holder()").unwrap();
    let restore = section.find("runtime::nested::restore_or_retain(&mut parent)").unwrap();
    assert!(park < service && service < restore, "the exact parent stays parked across it");
    assert!(section.contains("trace_background_holder_service(ch, gates, serviced)"),
        "the three gate values are logged");
    let block = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let ready = block
        .split("pub(super) unsafe fn background_holder_ready() -> bool {")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(ready.contains("background_owner_holds_reserve()"),
        "only a background owner that holds the reserve is driven");
}

#[test]
fn kernel_job_and_bootstrap_frames_drive_the_holder_through_their_scheduler_pass() {
    // The PnP-start kernel job and bootstrap receive loops redrive provider registry writes
    // after `service_irq_yield`, which runs with their parent parked.
    let scheduler = include_str!("../../../components/ntos-executive/src/component_scheduler.rs");
    let pass = scheduler.split("pub(crate) unsafe fn service_irq_yield(").nth(1).unwrap();
    let park = pass.find("nested::park_current()").unwrap();
    let holder = pass.find("service_mounted_native_background_holder()").expect("holder serviced");
    let restore = pass.find("nested::restore(&mut parent)").unwrap();
    assert!(park < holder && holder < restore);
    for (file, source) in [
        ("kernel_provider_activation.rs", include_str!("../../../components/ntos-executive/src/kernel_provider_activation.rs")),
        ("bootstrap_receive.rs", include_str!("../../../components/ntos-executive/src/bootstrap_receive.rs")),
    ] {
        let irq = source.find("scope.service_irq_yield(0)").unwrap_or_else(|| panic!("{file}"));
        let registry = source.find("registry_mutation_work::redrive_provider()").unwrap();
        assert!(irq < registry, "{file} drives the holder before redriving the blocked write");
    }
}

// Boot 44458933051 (2df2f110): the in-frame holder service kept the single physical slot busy
// with the lazy checkpoint's 16 KiB payload reads. An IRP frame yields to the outer owner for a
// queued mounted sector only with a vacant slot (`nested_ready`), so its foreground sectors
// starved: `kind-irp=1 nested-ready=0 outer-io-queued=0` thousands of times, no video publish.

use outer_native_io::{background_holder_step, BackgroundHolderStep};

/// One nested IRP frame turn. The frame drives the holder at two points (its scheduler pass
/// and its nested-work pass), then yields to the outer owner when the slot is vacant and a
/// sector is queued. A background command entered in a turn settles at the next one.
/// Returns the turns at which the foreground sectors and the checkpoint each finished.
fn run_irp_frame(policy: impl Fn(bool, bool, bool, bool) -> BackgroundHolderStep) -> (usize, usize) {
    let (mut sectors_left, mut checkpoint_left) = (4u32, 40u32);
    let (mut sectors_done, mut checkpoint_done) = (usize::MAX, usize::MAX);
    let mut slot: Option<bool> = None; // Some(is_background)
    for turn in 0..400 {
        let mut entered_this_turn = false;
        for _pass in 0..2 {
            let step = policy(slot.is_some(), slot == Some(true), sectors_left != 0,
                checkpoint_left != 0);
            match step {
                BackgroundHolderStep::Settle if !entered_this_turn => {
                    slot = None;
                    checkpoint_left -= 1;
                }
                BackgroundHolderStep::Enter => { slot = Some(true); entered_this_turn = true; }
                _ => {}
            }
        }
        if slot.is_none() && sectors_left != 0 {
            sectors_left -= 1; // the yield fires; the outer owner claims and completes it
        }
        if sectors_left == 0 && sectors_done == usize::MAX { sectors_done = turn; }
        if checkpoint_left == 0 && checkpoint_done == usize::MAX { checkpoint_done = turn; }
    }
    (sectors_done, checkpoint_done)
}

/// 2df2f110's policy: settle a background command, and enter the next whenever the slot is
/// vacant, regardless of queued foreground sectors.
fn greedy(occupied: bool, background: bool, _sector: bool, enterable: bool) -> BackgroundHolderStep {
    if occupied {
        if background { BackgroundHolderStep::Settle } else { BackgroundHolderStep::None }
    } else if enterable {
        BackgroundHolderStep::Enter
    } else {
        BackgroundHolderStep::None
    }
}

#[test]
fn a_holder_that_always_takes_the_slot_starves_the_frames_foreground_sectors() {
    let (sectors_done, checkpoint_done) = run_irp_frame(greedy);
    assert!(sectors_done > checkpoint_done,
        "no foreground sector ran while the whole checkpoint held the slot");
}

#[test]
fn foreground_sectors_keep_priority_and_the_holder_still_completes() {
    let (sectors_done, checkpoint_done) = run_irp_frame(background_holder_step);
    assert!(sectors_done < 8, "foreground sectors run first");
    assert!(checkpoint_done != usize::MAX, "the holder still completes");
    assert_eq!(background_holder_step(false, false, true, true), BackgroundHolderStep::None);
    assert_eq!(background_holder_step(true, false, false, true), BackgroundHolderStep::None,
        "a foreground command is settled by its own owner");
    assert_eq!(background_holder_step(true, true, true, true), BackgroundHolderStep::Settle);
    assert_eq!(background_holder_step(false, false, false, true), BackgroundHolderStep::Enter);
}
