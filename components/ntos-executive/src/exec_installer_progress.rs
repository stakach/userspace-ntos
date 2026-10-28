//! Exact process ownership and completed registry evidence for bounded INF installer grace.

use super::*;

type ProcessIdentity = nt_user_host::process_identity::ProcessIdentity;
type InstallerOwner = nt_hosted_runtime::InstallerOwner<ProcessIdentity>;

impl ExecNtHandler {
    fn live_installer_owner_for_pi(&self, worker_pi: usize) -> Option<InstallerOwner> {
        let worker = self.capture_process_identity(worker_pi)?;
        let process = self.pm.process(worker.pid)?;
        if process.state != nt_process::ProcessState::Running {
            return None;
        }
        let parent_pid = process.parent?;
        let parent_pi = self.process_mechanisms.pi_for_pid(parent_pid)
            .or_else(|| self.temporary_pi_for_pid(parent_pid))?;
        let parent = self.capture_process_identity(parent_pi)?;
        if parent.pid != parent_pid {
            return None;
        }
        let mut ancestor_pi = parent_pi;
        // The installer can be a Win32 child of a service-host child. Follow PM's exact parent
        // relation to registered service metadata, with a finite bound and no image-name routing.
        for _ in 0..MAX_PI {
            let ancestor = self.capture_process_identity(ancestor_pi)?;
            let process = self.pm.process(ancestor.pid)?;
            if process.state != nt_process::ProcessState::Running {
                return None;
            }
            // Dynamic PE instances retain the generic subsystem role. The exact image
            // observation carries the registered service role for this boot-only signal.
            if self.hosted_process_observation_role(ancestor_pi)?.is_noninteractive_service_class() {
                return Some(InstallerOwner { worker, parent, service: ancestor });
            }
            let next_pid = process.parent?;
            ancestor_pi = self.process_mechanisms.pi_for_pid(next_pid)
                .or_else(|| self.temporary_pi_for_pid(next_pid))?;
        }
        None
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

    /// The service-loop deadline may only use a recent completed probe while the same worker and
    /// parent are still running with their original process generations and parent relation.
    pub(crate) fn grant_installer_inf_progress(
        &mut self,
        epoch: u64,
        now_100ns: u64,
        window_100ns: u64,
    ) -> bool {
        let Some(owner) = self.installer_progress.as_ref().map(|progress| progress.owner()) else {
            return false;
        };
        let current_pi = self.process_mechanisms.pi_for_pid(owner.worker.pid)
            .or_else(|| self.temporary_pi_for_pid(owner.worker.pid));
        let live = current_pi.and_then(|pi| self.live_installer_owner_for_pi(pi));
        let progress = self.installer_progress.as_mut().expect("checked installer state");
        progress.observe_epoch(epoch, now_100ns);
        progress.grant(live, now_100ns, window_100ns)
    }

    pub(crate) fn installer_inf_grants(&self) -> u8 {
        self.installer_progress.as_ref().map_or(0, |progress| progress.grants())
    }
}
