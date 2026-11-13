//! Bounded, observation-only mounted READ state at the final root receive.

use super::*;

static LAST_IRP: AtomicU64 = AtomicU64::new(0);
static OWNER_SAMPLES: AtomicU64 = AtomicU64::new(0);
static TOTAL_SAMPLES: AtomicU64 = AtomicU64::new(0);
static BORROWED_SAMPLES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn receive_boundary_snapshot() {
    let owner = crate::mounted_volume::mounted_read_receive_snapshot();
    let sample = match owner {
        Ok(Some(fields)) => {
            if LAST_IRP.swap(fields[0], Ordering::AcqRel) != fields[0] {
                OWNER_SAMPLES.store(0, Ordering::Release);
            }
            let sample = OWNER_SAMPLES.fetch_add(1, Ordering::AcqRel) + 1;
            if !sample.is_power_of_two() { return; }
            sample
        }
        Err(()) => {
            let sample = BORROWED_SAMPLES.fetch_add(1, Ordering::Relaxed) + 1;
            if sample > 8 { return; }
            sample
        }
        Ok(None) => return,
    };
    if TOTAL_SAMPLES.fetch_add(1, Ordering::Relaxed) >= 128 { return; }
    let now = crate::monotonic_time_100ns();
    let retry = crate::driver_launch::mounted_native_block_next_deadline(now);
    crate::print_str(b"[mounted-read-receive] irp/file/mount/bytes/claimable/claim-generation/terminal/published/count=");
    match owner {
        Ok(Some(fields)) => {
            for (index, field) in fields.into_iter().enumerate() {
                if index != 0 { crate::print_str(b"/"); }
                if index < 3 { crate::print_hex_u64(field); }
                else { crate::print_u64(field); }
            }
        }
        Err(()) => crate::print_str(b"queue-borrowed"),
        Ok(None) => unreachable!(),
    }
    crate::print_str(b" sample/physical/queue-claimable/retry-ms/rearm-requested/pit-armed/pit-source/pit-deadline-ms/irq-state/tick-pending=");
    crate::print_u64(sample);
    crate::print_str(b"/"); crate::print_hex_u64(crate::driver_launch::mounted_native_physical_irp_id());
    crate::print_str(b"/");
    match crate::mounted_volume::mounted_sector_claimable() {
        Some(value) => crate::print_u64(u64::from(value)),
        None => crate::print_str(b"?"),
    }
    crate::print_str(b"/");
    match retry {
        Some(deadline) => crate::print_u64(deadline / 10_000),
        None => crate::print_str(b"-"),
    }
    crate::print_str(b"/");
    crate::print_u64(u64::from(super::MOUNTED_NATIVE_TIMER_REARM_DEMAND.is_pending()));
    crate::print_str(b"/"); crate::print_u64(u64::from(crate::LAST_REARM_AUTHORITY.is_armed()));
    crate::print_str(b"/"); crate::print_u64(crate::LAST_REARM_SOURCE.load(Ordering::Relaxed));
    crate::print_str(b"/"); crate::print_u64(crate::LAST_REARM_DEADLINE.load(Ordering::Relaxed) / 10_000);
    crate::print_str(b"/"); crate::print_u64(crate::DELAY_TIMER_IRQ_STATE.load(Ordering::Acquire));
    crate::print_str(b"/"); crate::print_u64(crate::DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed));
    crate::print_str(b"\n");
}
