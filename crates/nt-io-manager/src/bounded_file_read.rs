//! Source-only planning for a count-returning, bounded regular-file reader.

use nt_status::NtStatus;

use crate::ResolvedFileOffset;

const STATUS_IO_DEVICE_ERROR: u32 = 0xc000_0185;

/// Immutable source geometry captured before allocating output or beginning I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedFileReadPlan {
    resolved: ResolvedFileOffset,
    requested: usize,
    transfer_len: usize,
    at_eof: bool,
}

/// Accepted source result, independent of later publication to user memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedFileReadCompletion {
    pub status: u32,
    pub information: usize,
    pub position: Option<u64>,
}

impl BoundedFileReadPlan {
    pub fn new(
        resolved: ResolvedFileOffset,
        file_extent: u64,
        requested: usize,
    ) -> Result<Self, NtStatus> {
        crate::read_write::validate_transfer(requested)?;
        let offset = resolved.value();
        let transfer_len = file_extent
            .saturating_sub(offset)
            .min(requested as u64) as usize;
        Ok(Self {
            resolved,
            requested,
            transfer_len,
            at_eof: offset >= file_extent,
        })
    }

    pub const fn offset(self) -> u64 {
        self.resolved.value()
    }

    /// Exact output allocation and source-read extent; no arbitrary chunk cap.
    pub const fn transfer_len(self) -> usize {
        self.transfer_len
    }

    /// Accept the bounded source result before any user copy or completion surface.
    /// A short read inside the advertised file extent is a source failure, not
    /// a partial logical transfer. Bytes in the source buffer are then discarded.
    pub fn complete(
        self,
        synchronous: bool,
        source_count: usize,
    ) -> Result<BoundedFileReadCompletion, NtStatus> {
        if source_count > self.transfer_len {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        let (status, information) = if self.requested == 0 {
            (NtStatus::SUCCESS.raw() as u32, 0)
        } else if self.at_eof {
            (NtStatus::END_OF_FILE.raw() as u32, 0)
        } else if source_count < self.transfer_len {
            (STATUS_IO_DEVICE_ERROR, 0)
        } else {
            (NtStatus::SUCCESS.raw() as u32, source_count)
        };
        let position = self.resolved.completion_position(
            synchronous,
            self.requested,
            status,
            information,
        )?;
        Ok(BoundedFileReadCompletion {
            status,
            information,
            position,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(offset: u64, extent: u64, requested: usize) -> BoundedFileReadPlan {
        BoundedFileReadPlan::new(ResolvedFileOffset::Absolute(offset), extent, requested).unwrap()
    }

    #[test]
    fn full_read_has_no_chunk_cap_and_advances_by_accepted_bytes() {
        let plan = plan(17, 200_000, 100_000);
        assert_eq!(plan.offset(), 17);
        assert_eq!(plan.transfer_len(), 100_000);
        assert_eq!(
            plan.complete(true, 100_000),
            Ok(BoundedFileReadCompletion {
                status: 0,
                information: 100_000,
                position: Some(100_017),
            })
        );
        assert_eq!(plan.complete(false, 100_000).unwrap().position, None);
    }

    #[test]
    fn eof_truncation_is_a_successful_full_source_transfer() {
        let plan = plan(90, 100, 100_000);
        assert_eq!(plan.transfer_len(), 10);
        assert_eq!(
            plan.complete(true, 10).unwrap(),
            BoundedFileReadCompletion {
                status: 0,
                information: 10,
                position: Some(100),
            }
        );
    }

    #[test]
    fn zero_request_precedes_eof_and_never_moves_position() {
        for (offset, extent) in [(0, 0), (5, 10), (10, 10), (u64::MAX, 10)] {
            let plan = plan(offset, extent, 0);
            assert_eq!(plan.transfer_len(), 0);
            assert_eq!(
                plan.complete(true, 0).unwrap(),
                BoundedFileReadCompletion {
                    status: 0,
                    information: 0,
                    position: None,
                }
            );
        }
    }

    #[test]
    fn eof_uses_full_offset_without_narrowing_or_requested_end_overflow() {
        for (offset, extent) in [(0, 0), (10, 10), (20, 10), (u64::MAX, 10)] {
            let plan = plan(offset, extent, u32::MAX as usize);
            assert_eq!(plan.offset(), offset);
            assert_eq!(plan.transfer_len(), 0);
            let result = plan.complete(true, 0).unwrap();
            assert_eq!(result.status, NtStatus::END_OF_FILE.raw() as u32);
            assert_eq!(result.information, 0);
            assert_eq!(result.position, Some(offset));
            assert_eq!(plan.complete(false, 0).unwrap().position, None);
        }
    }

    #[test]
    fn short_source_never_accepts_buffered_prefix_or_advances_position() {
        let plan = plan(10, 30, 100);
        for count in [0, 1, 19] {
            for synchronous in [false, true] {
                assert_eq!(
                    plan.complete(synchronous, count).unwrap(),
                    BoundedFileReadCompletion {
                        status: STATUS_IO_DEVICE_ERROR,
                        information: 0,
                        position: None,
                    }
                );
            }
        }
    }

    #[test]
    fn oversized_source_result_is_rejected_against_transfer_not_request() {
        assert_eq!(
            plan(90, 100, 1000).complete(true, 11),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            plan(100, 100, 1000).complete(true, 1),
            Err(NtStatus::INVALID_PARAMETER)
        );
        assert_eq!(
            plan(0, 100, 0).complete(true, 1),
            Err(NtStatus::INVALID_PARAMETER)
        );
    }

    #[test]
    fn extent_bounds_completed_position_without_blanket_overflow_preflight() {
        let plan = plan(u64::MAX - 5, u64::MAX, u32::MAX as usize);
        assert_eq!(plan.transfer_len(), 5);
        assert_eq!(plan.complete(true, 5).unwrap().position, Some(u64::MAX));
    }

    #[test]
    fn current_offset_resolution_keeps_the_same_completion_contract() {
        let plan = BoundedFileReadPlan::new(ResolvedFileOffset::Current(7), 12, 3).unwrap();
        assert_eq!(plan.offset(), 7);
        assert_eq!(plan.complete(true, 3).unwrap().position, Some(10));
    }

    #[test]
    fn length_must_fit_the_nt_ulong_contract() {
        assert_eq!(plan(0, u64::MAX, u32::MAX as usize).transfer_len(), u32::MAX as usize);
        if let Some(too_large) = (u32::MAX as usize).checked_add(1) {
            assert_eq!(
                BoundedFileReadPlan::new(ResolvedFileOffset::Absolute(0), u64::MAX, too_large),
                Err(NtStatus::INVALID_PARAMETER)
            );
        }
    }
}
