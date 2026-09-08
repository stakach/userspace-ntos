//! Executive ownership of withdrawn Ps records through provider cleanup.

use alloc::vec::Vec;
use nt_process::process_object_retirement::ProcessObjectRetirement;
use nt_process::{ProcessManager, ProcessObjectDeletion};
use nt_user_host::provider_finalization::{ProviderFinalization, ProviderFinalizationPhase};
use nt_user_host::ProcessDeletionCandidate;

struct Row {
    candidate: ProcessDeletionCandidate,
    owner: Option<ProcessObjectRetirement>,
    provider: ProviderFinalization,
    backing: Option<crate::ps_object_backing::ProcessBackingRetirement>,
    deletion: Option<ProcessObjectDeletion>,
}

#[derive(Default)]
pub(crate) struct Retirements {
    rows: Vec<Row>,
    last_census: [usize; 8],
}

impl Retirements {
    pub(crate) fn print_census_changes(&mut self) {
        crate::ps_object_backing::print_census_changes();
        let mut counts = [0usize; 8];
        for row in &self.rows {
            counts[0] += 1;
            counts[1] += usize::from(row.owner.is_none() && row.deletion.is_none());
            counts[6] += usize::from(row.backing.is_some());
            counts[7] += usize::from(row.deletion.is_some());
            let phase = match row.provider.phase() {
                ProviderFinalizationPhase::Pending => 2,
                ProviderFinalizationPhase::Invoking => 3,
                ProviderFinalizationPhase::Accepted => 4,
                ProviderFinalizationPhase::Indeterminate(_) => 5,
            };
            counts[phase] += 1;
        }
        if counts == self.last_census {
            return;
        }
        self.last_census = counts;
        crate::print_str(b"[ps-retirements]");
        for (label, count) in [
            (b" owners=".as_slice(), counts[0]),
            (b" prepared=".as_slice(), counts[1]),
            (b" provider-pending=".as_slice(), counts[2]),
            (b" invoking=".as_slice(), counts[3]),
            (b" accepted=".as_slice(), counts[4]),
            (b" indeterminate=".as_slice(), counts[5]),
            (b" backing-drained=".as_slice(), counts[6]),
            (b" pm-finished=".as_slice(), counts[7]),
        ] {
            crate::print_str(label);
            crate::print_u64(count as u64);
        }
        crate::print_str(b"\n");
    }

    fn index(&self, candidate: ProcessDeletionCandidate) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.candidate.same_identity(candidate))
    }

    pub(crate) fn contains(&self, candidate: ProcessDeletionCandidate) -> bool {
        self.index(candidate).is_some()
    }

    pub(crate) fn owns_mechanism_slot(&self, pi: usize) -> bool {
        self.rows.iter().any(|row| row.candidate.pi == pi)
    }

    pub(crate) fn withdraw(
        &mut self,
        candidate: ProcessDeletionCandidate,
        pm: &mut ProcessManager,
    ) -> Result<(), u32> {
        let _durable = crate::allocator::enter_durable();
        let index = match self.index(candidate) {
            Some(index) => index,
            None => {
                self.rows
                    .try_reserve(1)
                    .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
                let index = self.rows.len();
                self.rows.push(Row {
                    candidate,
                    owner: None,
                    provider: ProviderFinalization::new(candidate.provider_objects),
                    backing: None,
                    deletion: None,
                });
                index
            }
        };
        if self.rows[index].owner.is_none() && self.rows[index].deletion.is_none() {
            // This call cannot enter a provider. The prepared native row receives the
            // sole ticket before any subsequent operation may invoke external code.
            self.rows[index].owner =
                Some(pm.withdraw_process_object_if_unreferenced(candidate.pid)?);
        }
        Ok(())
    }

    pub(crate) fn provider_ready(&self, candidate: ProcessDeletionCandidate) -> Result<bool, u32> {
        let index = self
            .index(candidate)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        match self.rows[index].provider.phase() {
            ProviderFinalizationPhase::Pending => Ok(false),
            ProviderFinalizationPhase::Invoking => Err(nt_process::STATUS_PENDING),
            ProviderFinalizationPhase::Accepted => Ok(true),
            ProviderFinalizationPhase::Indeterminate(status) => Err(status),
        }
    }

    pub(crate) fn begin_provider(
        &mut self,
        candidate: ProcessDeletionCandidate,
    ) -> Result<(), u32> {
        let index = self
            .index(candidate)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        self.rows[index]
            .provider
            .begin()
            .map_err(|_| nt_process::STATUS_INVALID_PARAMETER)
    }

    pub(crate) fn record_provider_result(
        &mut self,
        candidate: ProcessDeletionCandidate,
        outcome: crate::win32k_glue::PsProviderFinalization,
    ) {
        let index = self
            .index(candidate)
            .expect("provider retirement retains its Ps ticket");
        self.rows[index]
            .provider
            .record(outcome)
            .expect("provider result belongs to the exact invoking retirement owner");
    }

    pub(crate) fn release_job_memory(
        &self,
        candidate: ProcessDeletionCandidate,
        pm: &mut ProcessManager,
        bytes: u64,
    ) -> Result<(), u32> {
        let _durable = crate::allocator::enter_durable();
        let owner = self
            .index(candidate)
            .and_then(|index| self.rows[index].owner.as_ref())
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        pm.release_retired_process_job_memory(owner, bytes)
    }

    pub(crate) fn finish(
        &mut self,
        candidate: ProcessDeletionCandidate,
        pm: &mut ProcessManager,
    ) -> Result<ProcessObjectDeletion, u32> {
        let _durable = crate::allocator::enter_durable();
        if !self.provider_ready(candidate)? {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let index = self
            .index(candidate)
            .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
        if self.rows[index].backing.is_none() {
            let owner = self.rows[index]
                .owner
                .as_ref()
                .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
            self.rows[index].backing = Some(unsafe {
                crate::ps_object_backing::retire_withdrawn(
                    pm,
                    owner,
                    crate::ACTIVE_SCRATCH_BASE.load(core::sync::atomic::Ordering::Relaxed),
                )?
            });
        }
        if self.rows[index].deletion.is_none() {
            let owner = self.rows[index]
                .owner
                .take()
                .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
            match pm.finish_process_object_retirement(owner) {
                Ok(deletion) => self.rows[index].deletion = Some(deletion),
                Err((status, owner)) => {
                    self.rows[index].owner = Some(owner);
                    return Err(status);
                }
            }
        }
        let receipt = self.rows[index]
            .backing
            .take()
            .expect("physical retirement precedes PM finish");
        if let Err((status, receipt)) =
            unsafe { crate::ps_object_backing::release_retired_addresses(receipt) }
        {
            self.rows[index].backing = Some(receipt);
            return Err(status);
        }
        let deletion = self.rows[index]
            .deletion
            .take()
            .expect("PM payload remains retained until address release");
        self.rows.swap_remove(index);
        Ok(deletion)
    }
}
