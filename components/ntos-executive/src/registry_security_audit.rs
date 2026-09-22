//! Shared instrumentation of actual registry security decisions, not an authorization source.

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
