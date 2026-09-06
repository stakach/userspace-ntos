//! Admission for new private backing outside a view's existing COW reservation.

use super::*;

impl ExecNtHandler {
    /// Call after any working-set/page-table work, and publish the charge immediately after the
    /// frame record. No intervening MM/Ps charge may invalidate this prepared transaction.
    pub(crate) unsafe fn prepare_private_mapping_backing(
        &mut self,
        pi: usize,
        page: u64,
    ) -> Result<PreparedProcessCommitCharge, u32> {
        let info = process_committed_mapping_basic_information(pi as u64, page)
            .filter(|info| {
                matches!(
                    info.type_,
                    nt_address_space::MEM_IMAGE | nt_address_space::MEM_MAPPED
                )
            })
            .ok_or(nt_address_space::STATUS_NOT_COMMITTED)?;
        let private = csrss_frame_get_exact_record(pi as u64, page)
            .is_some_and(|record| record.owns_frame)
            || (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).contains(pi as u64, page);
        let bytes = nt_address_space::commitment::private_backing_admission_bytes(info, private);
        if bytes == 0 {
            return Ok(PreparedProcessCommitCharge::default());
        }
        let pid = self
            .pm_pid_for_pi(pi)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.prepare_process_commit_charge(pid, pi, bytes)
    }
}
