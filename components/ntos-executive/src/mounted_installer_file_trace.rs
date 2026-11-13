//! Bounded observation of mounted CREATE and directory query latency.
//!
//! These samples are never owners: only the I/O Manager File row authorizes completion,
//! Reply publication, and backend acknowledgement. Missing samples lose diagnostics only.

use super::*;

const CAPACITY: usize = 128;
const UNBOUND_EXPIRY_100NS: u64 = 60 * 10_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind { Create, Directory }

impl Kind {
    fn index(self) -> usize { match self { Self::Create => 0, Self::Directory => 1 } }
    fn label(self) -> &'static [u8] { match self { Self::Create => b"create", Self::Directory => b"directory" } }
}

#[derive(Clone, Copy)]
struct Sample {
    irp: u64,
    file: u64,
    mount: u64,
    kind: Kind,
    owner: Option<nt_io_manager::PendingFileIoIdentity>,
    pi: u32,
    generation: u64,
    entered: u64,
    terminal: Option<u64>,
    reply: Option<u64>,
    status: u32,
    copied_sectors: u64,
    physical_sectors: u64,
}

#[derive(Clone, Copy)]
struct Aggregate {
    generation: u64,
    completed: u64,
    reported: u64,
    failed: u64,
    no_reply: u64,
    copied_sectors: u64,
    physical_sectors: u64,
    ingress_terminal_total_ms: u64,
    ingress_terminal_max_ms: u64,
    terminal_reply_total_ms: u64,
    terminal_reply_max_ms: u64,
    reply_ack_total_ms: u64,
    reply_ack_max_ms: u64,
    ingress_ack_total_ms: u64,
    ingress_ack_max_ms: u64,
}

impl Aggregate {
    const EMPTY: Self = Self {
        generation: 0, completed: 0, reported: 0, failed: 0, no_reply: 0,
        copied_sectors: 0, physical_sectors: 0,
        ingress_terminal_total_ms: 0, ingress_terminal_max_ms: 0,
        terminal_reply_total_ms: 0, terminal_reply_max_ms: 0,
        reply_ack_total_ms: 0, reply_ack_max_ms: 0,
        ingress_ack_total_ms: 0, ingress_ack_max_ms: 0,
    };

    fn add(&mut self, sample: Sample, ack: u64) {
        self.completed = self.completed.saturating_add(1);
        self.failed = self.failed.saturating_add(u64::from(sample.status & 0xc000_0000 == 0xc000_0000));
        self.no_reply = self.no_reply.saturating_add(u64::from(sample.reply.is_none()));
        self.copied_sectors = self.copied_sectors.saturating_add(sample.copied_sectors);
        self.physical_sectors = self.physical_sectors.saturating_add(sample.physical_sectors);
        add_span(&mut self.ingress_terminal_total_ms, &mut self.ingress_terminal_max_ms,
            Some(sample.entered), sample.terminal);
        add_span(&mut self.terminal_reply_total_ms, &mut self.terminal_reply_max_ms,
            sample.terminal, sample.reply);
        add_span(&mut self.reply_ack_total_ms, &mut self.reply_ack_max_ms,
            sample.reply, Some(ack));
        add_span(&mut self.ingress_ack_total_ms, &mut self.ingress_ack_max_ms,
            Some(sample.entered), Some(ack));
    }
}

fn add_span(total: &mut u64, max: &mut u64, start: Option<u64>, end: Option<u64>) {
    if let Some(ms) = start.zip(end).and_then(|(start, end)| end.checked_sub(start))
        .map(|ticks| ticks / 10_000) {
        *total = total.saturating_add(ms);
        *max = (*max).max(ms);
    }
}

static mut SAMPLES: [Option<Sample>; CAPACITY] = [None; CAPACITY];
static mut STATS: [[Aggregate; 2]; MAX_PI] = [[Aggregate::EMPTY; 2]; MAX_PI];
static mut OVERFLOW: u64 = 0;
static mut EXPIRED_UNBOUND: u64 = 0;
static mut STALE_GENERATION: u64 = 0;
static mut REPORTED_DROPS: (u64, u64, u64) = (0, 0, 0);

/// Called only after the native mounted backend has retained the exact IRP.
pub(crate) fn ingress(irp: u64, file: u64, mount: u64, major: u8) {
    let kind = match major {
        nt_io_abi::major::IRP_MJ_CREATE => Kind::Create,
        nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL => Kind::Directory,
        _ => return,
    };
    if irp == 0 || file == 0 || mount == 0 { return; }
    let now = crate::monotonic_time_100ns();
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    for slot in slots.iter_mut() {
        if slot.is_some_and(|sample| sample.owner.is_none()
            && now.saturating_sub(sample.entered) > UNBOUND_EXPIRY_100NS) {
            *slot = None;
            unsafe { EXPIRED_UNBOUND = EXPIRED_UNBOUND.saturating_add(1); }
        }
    }
    if let Some(slot) = slots.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(Sample { irp, file, mount, kind, owner: None, pi: 0,
            generation: 0, entered: now, terminal: None, reply: None,
            status: 0, copied_sectors: 0, physical_sectors: 0 });
    } else {
        unsafe { OVERFLOW = OVERFLOW.saturating_add(1); }
    }
}

/// Sector attribution is joined by the retained logical IRP and physical mount, not by an SRB.
pub(crate) fn sector(irp: u64, mount: u64, copied: bool) {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    if let Some(sample) = slots.iter_mut().flatten().find(|sample|
        sample.irp == irp && sample.mount == mount) {
        let count = if copied { &mut sample.copied_sectors } else { &mut sample.physical_sectors };
        *count = count.saturating_add(1);
    }
}

pub(super) fn parked(handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity, pending: nt_io_manager::PendingFileIo) {
    let Some(file) = pending.route.hosted_file_id() else { return; };
    let pi = pending.pi as usize;
    if pi >= MAX_PI { return; }
    let Some(generation) = handler.hosted_process_generation(pi) else { return; };
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    let Some(sample) = slots.iter_mut().flatten().find(|sample|
        sample.owner.is_none() && sample.irp == pending.irp_id && sample.file == file
            && match sample.kind {
                Kind::Create => pending.major == nt_io_abi::major::IRP_MJ_CREATE,
                Kind::Directory => pending.major == nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
            }) else { return; };
    sample.owner = Some(identity);
    sample.pi = pending.pi;
    sample.generation = generation;
    let stats = unsafe { &mut *core::ptr::addr_of_mut!(STATS) };
    let entry = &mut stats[pi][sample.kind.index()];
    if entry.generation != generation {
        *entry = Aggregate { generation, ..Aggregate::EMPTY };
    }
}

fn owned(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) -> Option<&'static mut Sample> {
    unsafe { (&mut *core::ptr::addr_of_mut!(SAMPLES)).iter_mut().flatten()
        .find(|sample| sample.owner == Some(identity) && sample.irp == irp) }
}

pub(super) fn terminal(identity: nt_io_manager::PendingFileIoIdentity, irp: u64, status: u32) {
    if let Some(sample) = owned(identity, irp) {
        sample.terminal.get_or_insert_with(crate::monotonic_time_100ns);
        sample.status = status;
    }
}

pub(super) fn reply(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    if let Some(sample) = owned(identity, irp) {
        sample.reply.get_or_insert_with(crate::monotonic_time_100ns);
    }
}

pub(super) fn ack(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    let now = crate::monotonic_time_100ns();
    let Some(sample) = owned(identity, irp).map(|sample| *sample) else { return; };
    let pi = sample.pi as usize;
    if pi >= MAX_PI || sample.generation == 0 { return; }
    let stats = unsafe { &mut *core::ptr::addr_of_mut!(STATS) };
    let entry = &mut stats[pi][sample.kind.index()];
    if entry.generation != sample.generation {
        unsafe { STALE_GENERATION = STALE_GENERATION.saturating_add(1); }
        return;
    }
    entry.add(sample, now);
}

pub(super) fn retired(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    let slots = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    if let Some(slot) = slots.iter_mut().find(|slot|
        slot.is_some_and(|sample| sample.owner == Some(identity) && sample.irp == irp)) {
        *slot = None;
    }
}

/// Summaries advance at process-local doubling thresholds; serial output is independent of IRP rate.
pub(crate) fn print_summary() {
    let stats = unsafe { &mut *core::ptr::addr_of_mut!(STATS) };
    for (pi, kinds) in stats.iter_mut().enumerate() {
        for (index, entry) in kinds.iter_mut().enumerate() {
            if entry.completed == entry.reported
                || (entry.reported >= 4 && entry.completed < entry.reported.saturating_mul(2)) { continue; }
            entry.reported = entry.completed;
            let kind = if index == 0 { Kind::Create } else { Kind::Directory };
            print_str(b"[mounted-installer-file] pi/gen/kind/completed/failed/no-reply/cache-sectors/physical-sectors=");
            print_u64(pi as u64); print_str(b"/"); print_u64(entry.generation);
            print_str(b"/"); print_str(kind.label()); print_str(b"/");
            print_u64(entry.completed); print_str(b"/"); print_u64(entry.failed);
            print_str(b"/"); print_u64(entry.no_reply);
            print_str(b"/"); print_u64(entry.copied_sectors);
            print_str(b"/"); print_u64(entry.physical_sectors);
            print_str(b" ingress-terminal-total/max-ms=");
            print_u64(entry.ingress_terminal_total_ms); print_str(b"/"); print_u64(entry.ingress_terminal_max_ms);
            print_str(b" terminal-reply-total/max-ms=");
            print_u64(entry.terminal_reply_total_ms); print_str(b"/"); print_u64(entry.terminal_reply_max_ms);
            print_str(b" reply-ack-total/max-ms=");
            print_u64(entry.reply_ack_total_ms); print_str(b"/"); print_u64(entry.reply_ack_max_ms);
            print_str(b" ingress-ack-total/max-ms=");
            print_u64(entry.ingress_ack_total_ms); print_str(b"/"); print_u64(entry.ingress_ack_max_ms);
            print_str(b"\n");
        }
    }
    let drops = unsafe { (OVERFLOW, EXPIRED_UNBOUND, STALE_GENERATION) };
    let reported = unsafe { &mut *core::ptr::addr_of_mut!(REPORTED_DROPS) };
    if drops != *reported {
        *reported = drops;
        print_str(b"[mounted-installer-file] dropped overflow/unbound-expired/stale-generation-ack=");
        print_u64(drops.0); print_str(b"/"); print_u64(drops.1);
        print_str(b"/"); print_u64(drops.2); print_str(b"\n");
    }
}
