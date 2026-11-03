//! Bounded observations of SMSS path probes; no File or Reply ownership lives here.

use core::sync::atomic::{AtomicU64, Ordering};

use super::*;

#[path = "exec_smss_attribute_probe_sampling.rs"]
mod sampling;

pub(crate) const SMSS_ATTRIBUTE_PROBE_SAMPLE_LIMIT: u64 = sampling::NORMAL_SAMPLE_LIMIT;
static SMSS_ATTRIBUTE_PROBE_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_RESOLVE_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_TARGET_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_RETARGET_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_TERMINAL_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_RESOLVE_FAILURE_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_TARGET_FAILURE_COUNT: AtomicU64 = AtomicU64::new(0);
static SMSS_ATTRIBUTE_TERMINAL_FAILURE_COUNT: AtomicU64 = AtomicU64::new(0);

fn route_phase() -> &'static [u8] {
    match unsafe { crate::fs_loader::exec_fs_mount_identity() }
        .and_then(crate::fs_loader::exec_block_route_kind)
    {
        Some(nt_fs::BlockSourceKind::Boot) => b"boot",
        Some(nt_fs::BlockSourceKind::Draining) => b"draining",
        Some(nt_fs::BlockSourceKind::Native) => b"native",
        None => b"none",
    }
}

fn normal_sample(counter: &AtomicU64) -> bool {
    counter.fetch_add(1, Ordering::Relaxed) < SMSS_ATTRIBUTE_PROBE_SAMPLE_LIMIT
}

fn failure_sample(counter: &AtomicU64) -> bool {
    sampling::sample_failure(counter.fetch_add(1, Ordering::Relaxed))
}

fn sample_status(status: u32, normal: &AtomicU64, failure: &AtomicU64) -> bool {
    if (status as i32) < 0 { failure_sample(failure) } else { normal_sample(normal) }
}

pub(crate) fn trace_smss_attribute_candidate(
    pi: usize,
    tid: u64,
    name: &[u16],
    absolute: bool,
) {
    if pi != 0 || !absolute || !normal_sample(&SMSS_ATTRIBUTE_PROBE_COUNT) {
        return;
    }
    print_str(b"[smss-attr-candidate] pi=0 tid=");
    print_u64(tid);
    print_str(b" route=");
    print_str(route_phase());
    print_str(b" name=\"");
    print_sanitized_utf16_ascii(name, 160);
    print_str(b"\"\n");
}

/// Includes failures before a File exists, such as an Object Manager resolution error.
pub(crate) fn trace_smss_attribute_resolution(
    pi: usize,
    tid: u64,
    name: &[u16],
    target: Option<(u64, &[u16])>,
    status: u32,
) {
    if pi != 0 || !sample_status(status, &SMSS_ATTRIBUTE_RESOLVE_COUNT,
        &SMSS_ATTRIBUTE_RESOLVE_FAILURE_COUNT) {
        return;
    }
    print_str(b"[smss-attr-resolve] pi=0 tid=");
    print_u64(tid);
    print_str(b" route=");
    print_str(route_phase());
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" name=\"");
    print_sanitized_utf16_ascii(name, 160);
    print_str(b"\"");
    if let Some((device_id, relative)) = target {
        print_str(b" device=");
        print_u64(device_id);
        print_str(b" relative=\"");
        print_sanitized_utf16_ascii(relative, 160);
        print_str(b"\"");
    }
    print_str(b"\n");
}

pub(crate) fn trace_smss_attribute_target(
    pi: usize,
    tid: u64,
    device_id: u64,
    relative: &[u16],
    file_id: u64,
    irp_id: Option<u64>,
    stage: &[u8],
    status: u32,
) {
    if pi != 0 || !sample_status(status, &SMSS_ATTRIBUTE_TARGET_COUNT,
        &SMSS_ATTRIBUTE_TARGET_FAILURE_COUNT) {
        return;
    }
    print_str(b"[smss-attr-target] pi=0 tid=");
    print_u64(tid);
    print_str(b" route=");
    print_str(route_phase());
    print_str(b" stage=");
    print_str(stage);
    print_str(b" device=");
    print_u64(device_id);
    print_str(b" relative=\"");
    print_sanitized_utf16_ascii(relative, 160);
    print_str(b"\" file=");
    print_u64(file_id);
    print_str(b" irp=");
    print_u64(irp_id.unwrap_or(0));
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

pub(crate) fn trace_smss_attribute_retarget(
    pi: u32,
    tid: u64,
    file_id: u64,
    old_irp: u64,
    new_irp: u64,
) {
    if pi != 0 || !normal_sample(&SMSS_ATTRIBUTE_RETARGET_COUNT) {
        return;
    }
    print_str(b"[smss-attr-retarget] pi=0 tid=");
    print_u64(tid);
    print_str(b" file=");
    print_u64(file_id);
    print_str(b" create-irp=");
    print_u64(old_irp);
    print_str(b" query-irp=");
    print_u64(new_irp);
    print_str(b"\n");
}

/// Called only when the retained owner is about to retire, after user-facing surfaces settle.
pub(crate) fn trace_smss_attribute_terminal(
    pi: u32,
    tid: u64,
    file_id: Option<u64>,
    irp_id: u64,
    terminal_status: u32,
    returned_status: u32,
) {
    if pi != 0 || !sample_status(returned_status, &SMSS_ATTRIBUTE_TERMINAL_COUNT,
        &SMSS_ATTRIBUTE_TERMINAL_FAILURE_COUNT) {
        return;
    }
    print_str(b"[smss-attr-terminal] pi=0 tid=");
    print_u64(tid);
    print_str(b" file=");
    print_u64(file_id.unwrap_or(0));
    print_str(b" irp=");
    print_u64(irp_id);
    print_str(b" terminal=0x");
    print_hex(terminal_status);
    print_str(b" returned=0x");
    print_hex(returned_status);
    print_str(b"\n");
}
