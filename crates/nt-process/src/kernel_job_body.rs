//! Mechanism receipts for native PEJOB bodies published by the Process Manager.
//!
//! The Process Manager owns job identity and UI state. This ledger owns only the
//! exact native allocation receipt, including one whose release was uncertain.

use alloc::vec::Vec;

use crate::{job::{JobDestruction, JobId}, ProcessManager};

pub trait JobBodyReceipt: Copy {
    fn address(self) -> u64;
}

struct Row<R> {
    job: JobId,
    body: u64,
    receipt: R,
    retirement_uncertain: bool,
}

pub struct KernelJobBodyOwner<R> {
    rows: Vec<Row<R>>,
}

impl<R: JobBodyReceipt> Default for KernelJobBodyOwner<R> {
    fn default() -> Self { Self::new() }
}

impl<R: JobBodyReceipt> KernelJobBodyOwner<R> {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    /// The caller retains the returned receipt on any failure. Capacity is
    /// reserved before PM publication, so the final owner record cannot fail.
    pub fn publish(
        &mut self,
        pm: &mut ProcessManager,
        job: JobId,
        receipt: R,
    ) -> Result<(), R> {
        let body = receipt.address();
        if body == 0
            || pm.job_kernel_object(job).is_some()
            || self.rows.iter().any(|row| row.job == job || row.body == body)
            || self.rows.try_reserve(1).is_err()
        {
            return Err(receipt);
        }
        if !pm.publish_job_kernel_object(job, body) {
            return Err(receipt);
        }
        self.rows.push(Row { job, body, receipt, retirement_uncertain: false });
        Ok(())
    }

    pub fn receipt_for(&self, job: JobId) -> Option<R> {
        self.rows.iter().find(|row| row.job == job).map(|row| row.receipt)
    }

    fn retirement_row(&self, destruction: JobDestruction) -> Option<usize> {
        let body = destruction.kernel_job_object?;
        self.rows.iter().position(|row| row.job == destruction.id && row.body == body)
    }

    /// Observation alone never releases the receipt. Native retirement must
    /// succeed before `acknowledge_retirement` removes its owner record.
    pub fn retirement_receipt(&self, destruction: JobDestruction) -> Option<R> {
        let row = &self.rows[self.retirement_row(destruction)?];
        (!row.retirement_uncertain).then_some(row.receipt)
    }

    pub fn acknowledge_retirement(&mut self, destruction: JobDestruction) -> bool {
        let Some(index) = self.retirement_row(destruction) else { return false };
        if self.rows[index].retirement_uncertain { return false; }
        self.rows.swap_remove(index);
        true
    }

    /// An uncertain native release keeps the receipt and prevents replay.
    pub fn quarantine_retirement(&mut self, job: JobId, body: u64) -> bool {
        let Some(row) = self.rows.iter_mut().find(|row| row.job == job && row.body == body) else {
            return false;
        };
        row.retirement_uncertain = true;
        true
    }
}
