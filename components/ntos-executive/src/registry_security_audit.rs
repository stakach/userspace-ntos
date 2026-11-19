//! Shared instrumentation of actual registry security decisions, not an authorization source.

use crate::diagnostic_receipt_budget::ReceiptBudget;
use crate::diagnostic_repeat_filter::{fingerprint, RepeatFilter, Sighting};
use core::sync::atomic::{AtomicU64, Ordering};
use nt_security::{
    AccessCheckResult, KeyBackupRestoreAudit, KeyCreationAudit, KeyHandleSecurityAudit,
    SecurityAssignmentAudit, SecurityAssignmentPrivilegeOutcome,
};

static ACCESS_CHECKS: AtomicU64 = AtomicU64::new(0);
static ACCESS_DENIALS: AtomicU64 = AtomicU64::new(0);
static PRIVILEGES_USED: AtomicU64 = AtomicU64::new(0);
static PRIVILEGE_DENIALS: AtomicU64 = AtomicU64::new(0);
static ASSIGNMENT_CHECKS: AtomicU64 = AtomicU64::new(0);
/// A guest polling one missing key would otherwise pay a ~180-byte serial record per call.
static ADMISSION_SIGHTINGS: RepeatFilter = RepeatFilter::new();
static ADMISSION_UNTRACKED: ReceiptBudget = ReceiptBudget::new();
static ADMISSION_UNTRACKED_SUPPRESSED: AtomicU64 = AtomicU64::new(0);
/// Distinct misses are bounded too: a shell enumerating ~1,000 absent CLSID keys would pay
/// ~5.5M TSC ticks of serial output per record, more than the lookup itself.
static ADMISSION_FIRST: ReceiptBudget = ReceiptBudget::new();
static ADMISSION_FIRST_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

pub(crate) fn admission_error(operation: &[u8], path: &str, status: u32, pi: usize, tid: u64) {
    if !matches!(status, 0xc000_0034 | 0xc000_003a
        | nt_security::STATUS_INVALID_SECURITY_DESCR
        | nt_security::STATUS_INVALID_ACL | nt_security::STATUS_INVALID_SID)
    {
        return;
    }
    // The first sighting of each process/operation/status/path is reported; repeats are
    // counted in the periodic census. The thread is reported, not part of the identity.
    let sighting = ADMISSION_SIGHTINGS.observe(fingerprint(&[
        operation, &status.to_le_bytes(), &(pi as u64).to_le_bytes(), path.as_bytes(),
    ]));
    match sighting {
        Sighting::Repeat => return,
        Sighting::Untracked
            if ADMISSION_UNTRACKED.claim(crate::diagnostic_time_100ns()).is_none() =>
        {
            ADMISSION_UNTRACKED_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Sighting::First
            if ADMISSION_FIRST.claim(crate::diagnostic_time_100ns()).is_none() =>
        {
            ADMISSION_FIRST_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Sighting::First | Sighting::Untracked => {}
    }
    crate::print_str(b"[registry-admission-error] pi=");
    crate::print_u64(pi as u64);
    crate::print_str(b" tid=");
    crate::print_u64(tid);
    crate::print_str(b" operation=");
    crate::print_str(operation);
    crate::print_str(b" status=");
    crate::print_hex(status);
    crate::print_str(b" path=\"");
    crate::print_str(path.as_bytes());
    crate::print_str(match sighting {
        Sighting::Untracked => b"\" sighting=untracked\n",
        _ => b"\" sighting=first\n",
    });
}

pub(crate) fn print_admission_census() {
    let counts = ADMISSION_SIGHTINGS.counts();
    crate::print_str(
        b"[census] registry-admission-error first/repeats/untracked/untracked-suppressed/first-suppressed=");
    for (index, value) in [counts.first, counts.repeats, counts.untracked,
        ADMISSION_UNTRACKED_SUPPRESSED.load(Ordering::Relaxed),
        ADMISSION_FIRST_SUPPRESSED.load(Ordering::Relaxed)].into_iter().enumerate()
    {
        if index != 0 { crate::print_str(b"/"); }
        crate::print_u64(value);
    }
    crate::print_str(b"\n");
}

pub(crate) fn access(result: &AccessCheckResult) {
    ACCESS_CHECKS.fetch_add(1, Ordering::Relaxed);
    ACCESS_DENIALS.fetch_add(u64::from(result.status != 0), Ordering::Relaxed);
    PRIVILEGES_USED.fetch_add(result.privileges_used.len() as u64, Ordering::Relaxed);
}

pub(crate) fn handle(result: KeyHandleSecurityAudit) {
    // A KernelMode bypass grants without setting SE_PRIVILEGE_USED_FOR_ACCESS.
    PRIVILEGES_USED.fetch_add(
        u64::from(result.attributes & 0x8000_0000 != 0),
        Ordering::Relaxed,
    );
    PRIVILEGE_DENIALS.fetch_add(u64::from(!result.granted), Ordering::Relaxed);
}

pub(crate) fn assignment(result: SecurityAssignmentAudit) {
    for decision in [result.security, result.restore].into_iter().flatten() {
        ASSIGNMENT_CHECKS.fetch_add(1, Ordering::Relaxed);
        let granted = decision == SecurityAssignmentPrivilegeOutcome::Granted;
        PRIVILEGES_USED.fetch_add(u64::from(granted), Ordering::Relaxed);
        PRIVILEGE_DENIALS.fetch_add(u64::from(!granted), Ordering::Relaxed);
    }
}

pub(crate) fn creation(result: &KeyCreationAudit) {
    if let Some(parent) = &result.parent_access {
        access(parent);
    }
    assignment(result.assignment);
    if let Some(privilege) = result.handle_security {
        handle(privilege);
    }
}

pub(crate) fn backup(result: KeyBackupRestoreAudit) {
    handle(result.backup);
    handle(result.restore);
}

pub(crate) fn print_stats() {
    crate::print_str(b"[registry-security]");
    for (label, counter) in [
        (&b" access-checks="[..], &ACCESS_CHECKS),
        (&b" access-denials="[..], &ACCESS_DENIALS),
        (&b" assignment-checks="[..], &ASSIGNMENT_CHECKS),
        (&b" privileges-used="[..], &PRIVILEGES_USED),
        (&b" privilege-denials="[..], &PRIVILEGE_DENIALS),
    ] {
        crate::print_str(label);
        crate::print_u64(counter.load(Ordering::Relaxed));
    }
    crate::print_str(b"\n");
}
