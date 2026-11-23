//! Exact process ownership and completed registry evidence for bounded INF installer grace.

use super::*;

type ProcessIdentity = nt_user_host::process_identity::ProcessIdentity;
type InstallerOwner = nt_hosted_runtime::InstallerOwner<ProcessIdentity>;

impl ExecNtHandler {
    fn live_installer_owner_for_pi(&self, worker_pi: usize) -> Option<InstallerOwner> {
        let worker = self.capture_process_identity(worker_pi)?;
        let target = nt_exe_image::SpawnTarget::from_image(self.hosted_process_image(worker_pi)?);
        let (parent, service) = self.execution_roles.installer_service_owner(
            target,
            worker,
            |target, process| self.is_live_execution_process(target, process),
        )?;
        Some(InstallerOwner { worker, parent, service })
    }

    /// Called only at the exact `NtOpenKey` completion boundary. A missing IniFileMapping child is
    /// a completed probe of that INF, even though it does not create or mutate a registry key.
    pub(crate) fn note_completed_installer_inf_probe(&mut self, path: &str, status: u32) {
        let Some(owner) = self.live_installer_owner_for_pi(self.pi) else { return };
        let now = monotonic_time_100ns();
        let epoch = boot_progress_epoch();
        if let Some(progress) = self.installer_progress.as_mut() {
            progress.observe_epoch(epoch, now);
            let _ = progress.observe_completed_probe(owner, path, status, now);
            return;
        }
        let mut progress = nt_hosted_runtime::InstallerProgressDeferral::new(owner, epoch, now);
        if progress.observe_completed_probe(owner, path, status, now) {
            self.installer_progress = Some(progress);
        }
    }

    /// The service-loop deadline may use a recent completed probe only while the worker
    /// and every link to the same service owner are still running in their original generations.
    pub(crate) fn grant_installer_inf_progress(
        &mut self,
        epoch: u64,
        now_100ns: u64,
        window_100ns: u64,
    ) -> bool {
        let Some(owner) = self.installer_progress.as_ref().map(|progress| progress.owner()) else {
            return false;
        };
        let current_pi = self.process_mechanisms.pi_for_pid(owner.worker.pid);
        let live = current_pi.and_then(|pi| self.live_installer_owner_for_pi(pi));
        let progress = self.installer_progress.as_mut().expect("checked installer state");
        progress.observe_epoch(epoch, now_100ns);
        progress.grant(live, now_100ns, window_100ns)
    }

    pub(crate) fn installer_inf_grants(&self) -> u8 {
        self.installer_progress.as_ref().map_or(0, |progress| progress.grants())
    }
}
