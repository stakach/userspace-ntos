//! Bounded observation of a synchronous hosted DeviceControl IRP's exact delivery owner.
//!
//! This records transitions once per table identity and IRP. It grants no authority to a
//! provider or caller; stale rows are reaped only after the canonical table stops naming them.

use super::*;

const CAPACITY: usize = 128;

#[derive(Clone, Copy)]
struct Sample {
    identity: nt_io_manager::PendingFileIoIdentity,
    irp: u64,
    pi: u32,
    process_generation: u64,
    tid: u64,
    badge: u64,
    file: u64,
    control: u32,
    seen: u16,
}

static mut SAMPLES: [Option<Sample>; CAPACITY] = [None; CAPACITY];
static mut OVERFLOW: u64 = 0;

#[derive(Clone, Copy)]
pub(super) enum Stage {
    AwaitTerminal,
    Terminal,
    CallerInvalid,
    ProviderCopyRetry,
    OutputCopyRetry,
    Busy,
    ReplyFailed,
    ReplyPublished,
    WakeReady,
    AckFailed,
    BackendAcked,
    Retired,
}

impl Stage {
    fn bit(self) -> u16 { 1 << self as u8 }

    fn name(self) -> &'static [u8] {
        match self {
            Self::AwaitTerminal => b"await-terminal",
            Self::Terminal => b"terminal",
            Self::CallerInvalid => b"caller-invalid",
            Self::ProviderCopyRetry => b"provider-copy-retry",
            Self::OutputCopyRetry => b"output-copy-retry",
            Self::Busy => b"busy",
            Self::ReplyFailed => b"reply-failed",
            Self::ReplyPublished => b"reply-published",
            Self::WakeReady => b"wake-ready",
            Self::AckFailed => b"ack-failed",
            Self::BackendAcked => b"backend-acked",
            Self::Retired => b"retired",
        }
    }
}

fn progress(irp: u64) -> &'static [u8] {
    match driver_launch::hosted_dispatch_progress(irp) {
        Some(nt_hosted_runtime::DispatchProgress::InFlight) => b"in-flight",
        Some(nt_hosted_runtime::DispatchProgress::ReturnedPending) => b"returned-pending",
        Some(nt_hosted_runtime::DispatchProgress::Completed) => b"completed",
        None => b"unknown",
    }
}

fn print_key(sample: Sample) {
    print_str(b" pi/gen/tid/badge/table/slot/rowgen/irp/file/ioctl=");
    print_u64(sample.pi as u64);
    print_str(b"/");
    print_u64(sample.process_generation);
    print_str(b"/");
    print_u64(sample.tid);
    print_str(b"/0x");
    print_hex_u64(sample.badge);
    print_str(b"/");
    print_u64(sample.identity.table());
    print_str(b"/");
    print_u64(sample.identity.slot() as u64);
    print_str(b"/");
    print_u64(sample.identity.generation());
    print_str(b"/0x");
    print_hex_u64(sample.irp);
    print_str(b"/0x");
    print_hex_u64(sample.file);
    print_str(b"/0x");
    print_hex_u64(sample.control as u64);
}

fn matching(identity: nt_io_manager::PendingFileIoIdentity, irp: u64)
    -> Option<&'static mut Sample>
{
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SAMPLES)).iter_mut().flatten()
            .find(|sample| sample.identity == identity && sample.irp == irp)
    }
}

fn reap_stale() {
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    for slot in samples.iter_mut() {
        if slot.is_some_and(|sample| {
            (unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) })
                .get_exact(sample.identity).is_none_or(|row| row.irp_id != sample.irp)
        }) {
            *slot = None;
        }
    }
}

pub(super) fn parked(
    handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
    wait_for_completion: bool,
) {
    if !wait_for_completion || pending.major != nt_io_abi::major::IRP_MJ_DEVICE_CONTROL {
        return;
    }
    let Some(file) = pending.route.hosted_file_id() else { return; };
    reap_stale();
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    let Some(slot) = samples.iter_mut().find(|slot| slot.is_none()) else {
        let overflow = unsafe { &mut *core::ptr::addr_of_mut!(OVERFLOW) };
        *overflow = overflow.saturating_add(1);
        if overflow.is_power_of_two() {
            print_str(b"[pending-device-control] overflow=");
            print_u64(*overflow);
            print_str(b"\n");
        }
        return;
    };
    let sample = Sample {
        identity, irp: pending.irp_id, pi: pending.pi,
        process_generation: handler.hosted_process_generation(pending.pi as usize).unwrap_or(0),
        tid: pending.tid, badge: pending.badge, file, control: pending.control_code, seen: 0,
    };
    *slot = Some(sample);
    print_str(b"[pending-device-control] stage=park");
    print_key(sample);
    print_str(b" reply-required=");
    print_u64(pending.reply_required as u64);
    print_str(b" native-transport=");
    print_u64(pending.native_call_transport as u64);
    print_str(b" dispatch=");
    print_str(progress(pending.irp_id));
    print_str(b"\n");
}

pub(super) fn stage(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp: u64,
    stage: Stage,
    status: Option<(u32, u64)>,
) {
    let Some(sample) = matching(identity, irp) else { return; };
    if sample.seen & stage.bit() != 0 { return; }
    sample.seen |= stage.bit();
    let sample = *sample;
    print_str(b"[pending-device-control] stage=");
    print_str(stage.name());
    print_key(sample);
    if let Some((status, information)) = status {
        print_str(b" status=0x");
        print_hex_u64(status as u64);
        print_str(b" information=");
        print_u64(information);
    }
    if matches!(stage, Stage::AwaitTerminal) {
        print_str(b" dispatch=");
        print_str(progress(irp));
    }
    print_str(b"\n");
    if matches!(stage, Stage::Retired) {
        let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
        if let Some(slot) = samples.iter_mut().find(|slot| {
            slot.is_some_and(|entry| entry.identity == identity && entry.irp == irp)
        }) {
            *slot = None;
        }
    }
}
