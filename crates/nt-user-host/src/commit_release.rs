//! Failure-atomic commitment release across MM and Ps job ledgers.
use nt_memory_manager::ProcessCommitLedger;
use nt_process::{ProcessId, ProcessManager};

/// The caller owns the address-space delta. Validate every ledger before the first debit;
/// exclusive borrows span the complete allocation-free commit, with no backend call or reentry.
/// This does not retire mappings, release an address reservation, or infer absent ownership.
pub fn release(
    mm: &mut ProcessCommitLedger,
    pm: &mut ProcessManager,
    pid: ProcessId,
    bytes: u64,
) -> Result<(), u32> {
    if bytes == 0 {
        return Ok(());
    }
    mm.validate_release(pid, bytes)?;
    pm.validate_job_memory_release(pid, bytes)?;
    mm.release(pid, bytes)
        .expect("exclusive MM release preflight remains current");
    pm.release_job_memory(pid, bytes)
        .expect("exclusive Ps release preflight remains current");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_process::{STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

    fn fixture(
        mm_bytes: u64,
        job_bytes: Option<u64>,
    ) -> (ProcessCommitLedger, ProcessManager, ProcessId) {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("test.exe", None, None);
        if let Some(bytes) = job_bytes {
            let job = pm.create_job(0).unwrap();
            pm.assign_process_to_job_with_commit(job, pid, bytes)
                .unwrap();
        }
        let mut mm = ProcessCommitLedger::new();
        mm.register(pid, mm_bytes).unwrap();
        (mm, pm, pid)
    }

    #[test]
    fn paired_release_preserves_peaks_and_rejects_unowned_replay() {
        let (mut mm, mut pm, pid) = fixture(0x4000, Some(0x4000));
        release(&mut mm, &mut pm, pid, 0x4000).unwrap();
        assert_eq!(mm.accounting(pid).unwrap().current_bytes, 0);
        assert_eq!(mm.accounting(pid).unwrap().peak_bytes, 0x4000);
        assert_eq!(pm.job_memory_usage(pid), Ok((0, 0)));
        assert_eq!(
            release(&mut mm, &mut pm, pid, 0x1000),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(pm.job_memory_usage(pid), Ok((0, 0)));
        assert_eq!(release(&mut mm, &mut pm, pid, 0), Ok(()));
    }

    #[test]
    fn job_refusal_never_debits_mm_and_retry_uses_current_ledgers() {
        let (mut mm, mut pm, pid) = fixture(0x2000, Some(0x1000));
        let before = mm.accounting(pid);
        for _ in 0..2 {
            assert_eq!(
                release(&mut mm, &mut pm, pid, 0x2000),
                Err(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(mm.accounting(pid), before);
            assert_eq!(pm.job_memory_usage(pid), Ok((0x1000, 0x1000)));
        }
        let charge = pm.prepare_job_memory_charge(pid, 0x1000).unwrap().unwrap();
        pm.commit_job_memory_charge(charge).unwrap();
        release(&mut mm, &mut pm, pid, 0x2000).unwrap();
        assert_eq!(mm.accounting(pid).unwrap().current_bytes, 0);
        assert_eq!(pm.job_memory_usage(pid), Ok((0, 0)));
    }

    #[test]
    fn mm_refusal_never_debits_job() {
        let (mut mm, mut pm, pid) = fixture(0x1000, Some(0x2000));
        let before = mm.accounting(pid);
        for bytes in [0x2000, 1] {
            assert_eq!(
                release(&mut mm, &mut pm, pid, bytes),
                Err(STATUS_INVALID_PARAMETER)
            );
            assert_eq!(mm.accounting(pid), before);
            assert_eq!(pm.job_memory_usage(pid), Ok((0x2000, 0x2000)));
        }
        let charge = mm.prepare_charge(pid, 0x1000).unwrap();
        mm.commit_charge(charge).unwrap();
        release(&mut mm, &mut pm, pid, 0x2000).unwrap();
        assert_eq!(pm.job_memory_usage(pid), Ok((0, 0)));
    }

    #[test]
    fn no_job_is_distinct_from_a_missing_process_owner() {
        let (mut mm, mut pm, pid) = fixture(0x2000, None);
        release(&mut mm, &mut pm, pid, 0x1000).unwrap();
        assert_eq!(mm.accounting(pid).unwrap().current_bytes, 0x1000);
        let foreign = pid + 100;
        mm.register(foreign, 0x3000).unwrap();
        assert_eq!(
            release(&mut mm, &mut pm, foreign, 0x1000),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(mm.accounting(foreign).unwrap().current_bytes, 0x3000);
    }
}
