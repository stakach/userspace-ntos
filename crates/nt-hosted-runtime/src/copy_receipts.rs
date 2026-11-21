//! Completion copies a repeating delivery path has already taken (#420).
//!
//! Some File delivery paths repeat every step before their settlement on each retry: copy the
//! completed IRP's output, publish it, then ACK the IRP. Once the ACK answers that it is still
//! running, the IRP's storage belongs to that ACK ([`crate::IrpOperations`]), so a repeated copy
//! would wait for it forever and the ACK would never be collected. The path copies through
//! these receipts instead: each exact copy reaches the backend once, and its bytes serve every
//! repetition until the IRP's ACK settles and the receipts are released.

use alloc::vec::Vec;

struct Receipt {
    irp: u64,
    offset: u64,
    len: usize,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub struct CopyReceipts {
    rows: Vec<Receipt>,
}

impl CopyReceipts {
    pub const fn new() -> Self { Self { rows: Vec::new() } }

    /// Copy `irp`'s output at `offset` into `output`, through `copy` only the first time. Room
    /// for the receipt is reserved before `copy` runs, so a taken copy is never lost; a refused
    /// reservation issues nothing.
    pub fn copy(
        &mut self,
        irp: u64,
        offset: u64,
        output: &mut [u8],
        copy: impl FnOnce(&mut [u8]) -> Result<usize, u32>,
        insufficient_resources: u32,
    ) -> Result<usize, u32> {
        let len = output.len();
        if let Some(receipt) = self.rows.iter()
            .find(|row| row.irp == irp && row.offset == offset && row.len == len)
        {
            output[..receipt.bytes.len()].copy_from_slice(&receipt.bytes);
            return Ok(receipt.bytes.len());
        }
        let mut bytes = Vec::new();
        if self.rows.try_reserve(1).is_err() || bytes.try_reserve_exact(len).is_err() {
            return Err(insufficient_resources);
        }
        let copied = copy(output)?;
        let kept = copied.min(len);
        bytes.extend_from_slice(&output[..kept]);
        self.rows.push(Receipt { irp, offset, len, bytes });
        Ok(copied)
    }

    /// The IRP's ACK settled: its output is gone, and so are its receipts.
    pub fn release(&mut self, irp: u64) {
        self.rows.retain(|row| row.irp != irp);
    }

    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompletionStep, IrpOperationAdmission, IrpOperationKey, IrpOperations};

    const PENDING: u32 = 0x103;
    const RESOURCES: u32 = 0xC000_009A;
    const COPY: u64 = 2;
    const ACK: u64 = 3;

    /// A backend whose copies return in place and whose ACK stops unfinished once.
    struct Backend {
        operations: IrpOperations<()>,
        ack_returned: bool,
        copies: usize,
        acks: usize,
    }

    impl Backend {
        fn admit(&mut self, operation: u64, offset: u64, len: usize) -> IrpOperationAdmission<()> {
            self.operations.admit(IrpOperationKey { instance: 1, irp: 7, operation, offset, len })
        }

        fn copy(&mut self, offset: u64, output: &mut [u8]) -> Result<usize, u32> {
            match self.admit(COPY, offset, output.len()) {
                IrpOperationAdmission::Issue => {
                    self.copies += 1;
                    output.fill(9);
                    Ok(output.len())
                }
                _ => Err(PENDING),
            }
        }

        fn acknowledge(&mut self) -> Result<(), u32> {
            let key = IrpOperationKey { instance: 1, irp: 7, operation: ACK, offset: 0, len: 0 };
            match self.operations.admit(key) {
                IrpOperationAdmission::Issue => {
                    self.acks += 1;
                    self.operations.reserve().unwrap();
                    self.operations.keep(key, ());
                    Err(PENDING)
                }
                IrpOperationAdmission::Collect(()) if self.ack_returned => {
                    assert!(self.operations.settled(key));
                    Ok(())
                }
                IrpOperationAdmission::Collect(()) => {
                    self.operations.still_running(key, ()).unwrap();
                    Err(PENDING)
                }
                IrpOperationAdmission::Busy => Err(PENDING),
            }
        }
    }

    /// One delivery turn: copy, publish, ACK. Returns the published bytes once settled.
    fn turn(receipts: &mut CopyReceipts, backend: &mut Backend) -> Option<[u8; 4]> {
        let mut output = [0u8; 4];
        let copied = receipts.copy(7, 0, &mut output, |out| backend.copy(0, out), RESOURCES);
        if !matches!(CompletionStep::of(copied), CompletionStep::Done(4)) { return None; }
        match CompletionStep::of(backend.acknowledge()) {
            CompletionStep::Done(()) => {
                receipts.release(7);
                Some(output)
            }
            _ => None,
        }
    }

    #[test]
    fn a_delivery_repeated_behind_a_running_ack_copies_once_and_collects_the_ack() {
        let mut receipts = CopyReceipts::new();
        let mut backend = Backend {
            operations: IrpOperations::new(), ack_returned: false, copies: 0, acks: 0,
        };
        assert_eq!(turn(&mut receipts, &mut backend), None, "the ACK is still running");
        assert_eq!(turn(&mut receipts, &mut backend), None);
        backend.ack_returned = true;
        assert_eq!(turn(&mut receipts, &mut backend), Some([9; 4]),
            "the repeated copy is served by its receipt, so the identical ACK is collected");
        assert_eq!((backend.copies, backend.acks), (1, 1),
            "the copy and the ACK each reached the backend once");
        assert!(receipts.is_empty(), "a settled ACK releases the IRP's receipts");
    }

    #[test]
    fn a_receipt_serves_only_its_exact_copy() {
        let mut receipts = CopyReceipts::new();
        let calls = core::cell::Cell::new(0u8);
        let copy = |out: &mut [u8]| {
            calls.set(calls.get() + 1);
            out.fill(calls.get());
            Ok(out.len())
        };
        let mut first = [0u8; 4];
        assert_eq!(receipts.copy(7, 0, &mut first, copy, RESOURCES), Ok(4));
        let mut other_offset = [0u8; 4];
        assert_eq!(receipts.copy(7, 4, &mut other_offset, copy, RESOURCES), Ok(4));
        let mut other_irp = [0u8; 4];
        assert_eq!(receipts.copy(8, 0, &mut other_irp, copy, RESOURCES), Ok(4));
        let mut again = [0u8; 4];
        assert_eq!(receipts.copy(7, 0, &mut again, copy, RESOURCES), Ok(4));
        assert_eq!((again, calls.get()), ([1; 4], 3), "only the identical copy is served by a receipt");
        receipts.release(7);
        assert_eq!(receipts.copy(7, 0, &mut again, copy, RESOURCES), Ok(4));
        assert_eq!(calls.get(), 4, "a released IRP's next copy reaches the backend again");
        let mut failing = [0u8; 4];
        assert_eq!(receipts.copy(9, 0, &mut failing, |_| Err(PENDING), RESOURCES), Err(PENDING));
        assert_eq!(receipts.copy(9, 0, &mut failing, |_| Ok(4), RESOURCES), Ok(4),
            "a copy that did not return is not a receipt");
    }
}
