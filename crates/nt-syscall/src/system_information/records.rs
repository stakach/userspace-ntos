//! Fixed records for the system-information classes user-mode start-up reads beyond the boot set.

pub const SYSTEM_PERFORMANCE_INFORMATION_CLASS: u32 = 2;
pub const SYSTEM_TIME_ADJUSTMENT_INFORMATION_CLASS: u32 = 28;
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS: u32 = 35;
pub const SYSTEM_RANGE_START_INFORMATION_CLASS: u32 = 50;

/// NT 5.2 `SYSTEM_PERFORMANCE_INFORMATION`: four LARGE_INTEGERs and seventy ULONGs.
pub const SYSTEM_PERFORMANCE_INFORMATION_SIZE: usize = 0x138;
pub const SYSTEM_QUERY_TIME_ADJUST_INFORMATION_SIZE: usize = 0x0c;
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION_SIZE: usize = 0x02;
pub const SYSTEM_RANGE_START_INFORMATION_SIZE: usize = 0x08;

/// Last byte a hosted process may address (`SYSTEM_BASIC_INFORMATION.MaximumUserModeAddress`).
pub const HIGHEST_USER_ADDRESS: u64 = 0x0000_07ff_fffe_ffff;

/// First address that never belongs to a hosted process. A hosted address space carries no
/// kernel half, so the system range begins directly above the highest user address.
pub const SYSTEM_RANGE_START: u64 = HIGHEST_USER_ADDRESS + 1;

/// Alignment `NtQuerySystemInformation` requires of the output buffer for `class`.
pub const fn query_output_alignment(class: u32) -> u64 {
    if class == SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS { 1 } else { 4 }
}

/// The memory-manager facts of `SYSTEM_PERFORMANCE_INFORMATION`. Every other counter in the
/// record (I/O transfers, fault kinds, pool and cache statistics, context switches) has no
/// producer in this executive and is reported as zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemPerformanceInformation {
    pub available_pages: u32,
    pub committed_pages: u32,
    pub commit_limit_pages: u32,
    pub peak_commitment_pages: u32,
}

impl SystemPerformanceInformation {
    /// Builds the record from byte and page totals, saturating each ULONG page count.
    pub fn from_memory(
        available_bytes: u64,
        committed_bytes: u64,
        peak_committed_bytes: u64,
        commit_limit_pages: u64,
    ) -> Self {
        let pages = |bytes: u64| (bytes >> 12).min(u32::MAX as u64) as u32;
        Self {
            available_pages: pages(available_bytes),
            committed_pages: pages(committed_bytes),
            commit_limit_pages: commit_limit_pages.min(u32::MAX as u64) as u32,
            peak_commitment_pages: pages(peak_committed_bytes),
        }
    }

    pub fn encode(self) -> [u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE] {
        let mut output = [0u8; SYSTEM_PERFORMANCE_INFORMATION_SIZE];
        output[0x2c..0x30].copy_from_slice(&self.available_pages.to_le_bytes());
        output[0x30..0x34].copy_from_slice(&self.committed_pages.to_le_bytes());
        output[0x34..0x38].copy_from_slice(&self.commit_limit_pages.to_le_bytes());
        output[0x38..0x3c].copy_from_slice(&self.peak_commitment_pages.to_le_bytes());
        output
    }
}

/// `SYSTEM_QUERY_TIME_ADJUST_INFORMATION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemTimeAdjustmentInformation {
    pub time_adjustment_100ns: u32,
    pub time_increment_100ns: u32,
    /// The record's `Enable` member: TRUE while periodic time adjustment is disabled.
    pub adjustment_disabled: bool,
}

impl SystemTimeAdjustmentInformation {
    pub fn encode(self) -> [u8; SYSTEM_QUERY_TIME_ADJUST_INFORMATION_SIZE] {
        let mut output = [0u8; SYSTEM_QUERY_TIME_ADJUST_INFORMATION_SIZE];
        output[0..4].copy_from_slice(&self.time_adjustment_100ns.to_le_bytes());
        output[4..8].copy_from_slice(&self.time_increment_100ns.to_le_bytes());
        output[8] = self.adjustment_disabled as u8;
        output
    }
}

/// `SYSTEM_KERNEL_DEBUGGER_INFORMATION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemKernelDebuggerInformation {
    pub enabled: bool,
    pub not_present: bool,
}

impl SystemKernelDebuggerInformation {
    pub fn encode(self) -> [u8; SYSTEM_KERNEL_DEBUGGER_INFORMATION_SIZE] {
        [self.enabled as u8, self.not_present as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_information::{query_plan, supports_query_output, QueryError,
        QueryOutputPages, SYSTEM_MODULE_INFORMATION_CLASS};
    use crate::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

    fn lengths(class: u32, length: usize) -> Result<(usize, u32), QueryError> {
        query_plan(class, length).map(|plan| (plan.copy_length, plan.return_length))
    }

    const MISMATCH: u32 = STATUS_INFO_LENGTH_MISMATCH;

    #[test]
    fn range_start_requires_exactly_one_pointer() {
        assert_eq!(lengths(0x32, 8), Ok((8, 8)));
        // ReactOS leaves the required size unset when the length is wrong.
        for length in [0, 4, 16] {
            assert_eq!(
                lengths(0x32, length),
                Err(QueryError { status: MISMATCH, return_length: 0 })
            );
        }
    }

    #[test]
    fn performance_accepts_a_larger_buffer_and_reports_the_nt5_size() {
        assert_eq!(lengths(2, 0x138), Ok((0x138, 0x138)));
        assert_eq!(lengths(2, 0x158), Ok((0x138, 0x138)));
        assert_eq!(
            lengths(2, 0x137),
            Err(QueryError { status: MISMATCH, return_length: 0x138 })
        );
    }

    #[test]
    fn time_adjustment_requires_the_exact_record() {
        assert_eq!(lengths(28, 12), Ok((12, 12)));
        for length in [0, 8, 16] {
            assert_eq!(
                lengths(28, length),
                Err(QueryError { status: MISMATCH, return_length: 12 })
            );
        }
    }

    #[test]
    fn kernel_debugger_accepts_a_larger_buffer_and_sets_no_size_on_mismatch() {
        assert_eq!(lengths(35, 2), Ok((2, 2)));
        assert_eq!(lengths(35, 8), Ok((2, 2)));
        assert_eq!(
            lengths(35, 1),
            Err(QueryError { status: MISMATCH, return_length: 0 })
        );
    }

    #[test]
    fn classes_without_a_backing_fact_stay_invalid() {
        for class in [5, 8, 16, 21, 23, 37, 0x47, 73, 0x1000] {
            assert_eq!(
                query_plan(class, 0x1000).map(|plan| plan.kind),
                Err(QueryError { status: STATUS_INVALID_INFO_CLASS, return_length: 0 })
            );
        }
    }

    #[test]
    fn probed_classes_are_exactly_the_planned_classes_and_the_module_list() {
        for class in 0..0x200 {
            let planned = query_plan(class, 0).map_or_else(
                |error| error.status != STATUS_INVALID_INFO_CLASS, |_| true);
            assert_eq!(
                supports_query_output(class),
                planned || class == SYSTEM_MODULE_INFORMATION_CLASS,
                "class {class}"
            );
        }
    }

    #[test]
    fn system_range_starts_directly_above_the_highest_user_address() {
        assert_eq!(SYSTEM_RANGE_START, 0x0000_07ff_ffff_0000);
        assert_eq!(SYSTEM_RANGE_START & 0xffff, 0);
    }

    #[test]
    fn performance_record_places_the_memory_counters_and_zeroes_the_rest() {
        let record = SystemPerformanceInformation::from_memory(
            0x1234_5000, 0x0abc_d000, 0x0fff_f000, 0x8_0000);
        let output = record.encode();
        let word = |offset: usize| u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0x2c), 0x1_2345);
        assert_eq!(word(0x30), 0xabcd);
        assert_eq!(word(0x34), 0x8_0000);
        assert_eq!(word(0x38), 0xffff);
        assert!(output[..0x2c].iter().chain(&output[0x3c..]).all(|byte| *byte == 0));
        let saturated = SystemPerformanceInformation::from_memory(u64::MAX, 0, 0, u64::MAX);
        assert_eq!((saturated.available_pages, saturated.commit_limit_pages), (u32::MAX, u32::MAX));
    }

    #[test]
    fn time_adjustment_and_debugger_records_have_the_native_layout() {
        let adjust = SystemTimeAdjustmentInformation {
            time_adjustment_100ns: 0x11, time_increment_100ns: 0x22, adjustment_disabled: true,
        }.encode();
        assert_eq!(adjust, [0x11, 0, 0, 0, 0x22, 0, 0, 0, 1, 0, 0, 0]);
        let debugger = SystemKernelDebuggerInformation { enabled: false, not_present: true };
        assert_eq!(debugger.encode(), [0, 1]);
    }

    #[test]
    fn only_the_debugger_class_accepts_an_unaligned_buffer() {
        const LIMIT: u64 = 0x20_000;
        assert!(QueryOutputPages::new(35, 0x1001, 2, 0, LIMIT).is_ok());
        assert!(matches!(QueryOutputPages::new(2, 0x1001, 0x138, 0, LIMIT), Err(0x8000_0002)));
        assert!(matches!(QueryOutputPages::new(50, 0x1002, 8, 0, LIMIT), Err(0x8000_0002)));
    }
}
