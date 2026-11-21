//! A later synchronous return of an IRP its backend already reported pending (#420).
//!
//! A hosted dispatch whose native pump stops unfinished, where its caller cannot wait, tells
//! the I/O Manager `Pending`: the driver has not returned, which is the true state. When the
//! pump later returns, its terminal is not a pended completion the driver retains. The I/O
//! Manager publishes it as the IRP's ordinary completion and holds its output itself, so
//! delivery reads it as it reads any pending IRP's completion, and no backend copy or ACK is
//! ever issued for state no backend holds. This is the legacy-dispatch counterpart of
//! [`IoManager::queue_external_file_irp_terminal`].

use alloc::vec::Vec;

use nt_status::NtStatus;

use crate::dispatch::DriverCompletion;
use crate::irp::{IrpCompletionOrigin, IrpState};
use crate::object_port::ObjectManagerPort;
use crate::{DriverId, IoManager, IrpId};

/// The driver's genuine non-pending return and the output it wrote.
#[derive(Debug, Eq, PartialEq)]
pub struct ReturnedIrp {
    pub irp_id: IrpId,
    pub status: NtStatus,
    pub information: u64,
    pub file_context: Option<u64>,
    pub output: Vec<u8>,
}

/// A return the I/O Manager refused, handed back whole: nothing was published.
#[derive(Debug, Eq, PartialEq)]
pub struct ReturnedIrpRejection {
    pub status: NtStatus,
    pub returned: ReturnedIrp,
}

impl<P: ObjectManagerPort> IoManager<P> {
    /// Publish `returned` as the ordinary completion of the pending IRP `driver_id` owns,
    /// exactly once. The IRP must still be pending (or cancel-requested) at that driver; a
    /// refusal changes nothing and hands the return back.
    pub fn complete_returned_irp(
        &mut self,
        driver_id: DriverId,
        returned: ReturnedIrp,
    ) -> Result<(), ReturnedIrpRejection> {
        let valid = (|| {
            if returned.status == NtStatus::PENDING {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let irp = self.irp(returned.irp_id).ok_or(NtStatus::INVALID_PARAMETER)?;
            if !matches!(irp.state, IrpState::Pending | IrpState::CancelRequested)
                || irp.detached_file_owner
                || irp.returned_output.is_some()
                || irp.current_stack().is_none_or(|stack| stack.driver_id != driver_id)
            {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            self.completed_irps
                .try_reserve(1)
                .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)
        })();
        if let Err(status) = valid {
            return Err(ReturnedIrpRejection { status, returned });
        }
        let ReturnedIrp { irp_id, status, information, file_context, output } = returned;
        let published = self.publish_verified_completion(
            DriverCompletion { irp_id, status, information, file_context },
            IrpCompletionOrigin::Driver,
        );
        assert!(published, "a validated pending IRP publishes its returned terminal");
        self.irp_mut(irp_id).expect("a published IRP is live").returned_output = Some(output);
        Ok(())
    }

    /// Whether a published completion's output and acknowledgement belong to a backend. A
    /// returned completion's belong to the I/O Manager.
    pub(crate) fn completion_owes_backend(&self, irp_id: IrpId) -> bool {
        self.irp(irp_id).is_none_or(|irp| irp.returned_output.is_none())
    }

    /// Copy `[offset, offset + output.len())` of a returned completion's held output, bounded
    /// by `transfer_len`. `None` when the completion's output belongs to a backend.
    pub(crate) fn copy_returned_output(
        &self,
        irp_id: IrpId,
        transfer_len: usize,
        offset: usize,
        output: &mut [u8],
    ) -> Option<Result<usize, NtStatus>> {
        let held = self.irp(irp_id)?.returned_output.as_ref()?;
        Some((|| {
            if offset > transfer_len {
                return Err(NtStatus::INVALID_PARAMETER);
            }
            let count = output.len().min(transfer_len - offset);
            let source = held.get(offset..offset + count).ok_or(NtStatus::INVALID_PARAMETER)?;
            output[..count].copy_from_slice(source);
            Ok(count)
        })())
    }
}
