//! Windows x64 native job-object information layouts.

use crate::job::{IoCounters, JobAccounting, JobBasicLimits, JobExtendedLimits};

pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

pub const BASIC_ACCOUNTING_SIZE: usize = 48;
pub const BASIC_LIMIT_SIZE: usize = 64;
pub const BASIC_PROCESS_ID_LIST_HEADER_SIZE: usize = 8;
pub const BASIC_PROCESS_ID_LIST_MINIMUM_SIZE: usize = 16;
pub const BASIC_UI_RESTRICTIONS_SIZE: usize = 4;
pub const SECURITY_LIMIT_SIZE: usize = 40;
pub const END_OF_JOB_TIME_SIZE: usize = 4;
pub const ASSOCIATE_COMPLETION_PORT_SIZE: usize = 16;
pub const BASIC_AND_IO_ACCOUNTING_SIZE: usize = 96;
pub const EXTENDED_LIMIT_SIZE: usize = 144;
pub const JOB_SET_INFORMATION_SIZE: usize = 4;
pub const JOB_SET_ARRAY_ENTRY_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum JobInformationClass {
    BasicAccounting = 1,
    BasicLimit = 2,
    BasicProcessIdList = 3,
    BasicUiRestrictions = 4,
    SecurityLimit = 5,
    EndOfJobTime = 6,
    AssociateCompletionPort = 7,
    BasicAndIoAccounting = 8,
    ExtendedLimit = 9,
    JobSet = 10,
}

impl JobInformationClass {
    pub fn from_u32(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::BasicAccounting,
            2 => Self::BasicLimit,
            3 => Self::BasicProcessIdList,
            4 => Self::BasicUiRestrictions,
            5 => Self::SecurityLimit,
            6 => Self::EndOfJobTime,
            7 => Self::AssociateCompletionPort,
            8 => Self::BasicAndIoAccounting,
            9 => Self::ExtendedLimit,
            10 => Self::JobSet,
            _ => return None,
        })
    }

    pub const fn minimum_length(self) -> usize {
        match self {
            Self::BasicAccounting => BASIC_ACCOUNTING_SIZE,
            Self::BasicLimit => BASIC_LIMIT_SIZE,
            Self::BasicProcessIdList => BASIC_PROCESS_ID_LIST_MINIMUM_SIZE,
            Self::BasicUiRestrictions => BASIC_UI_RESTRICTIONS_SIZE,
            Self::SecurityLimit => SECURITY_LIMIT_SIZE,
            Self::EndOfJobTime => END_OF_JOB_TIME_SIZE,
            Self::AssociateCompletionPort => ASSOCIATE_COMPLETION_PORT_SIZE,
            Self::BasicAndIoAccounting => BASIC_AND_IO_ACCOUNTING_SIZE,
            Self::ExtendedLimit => EXTENDED_LIMIT_SIZE,
            Self::JobSet => JOB_SET_INFORMATION_SIZE,
        }
    }

    pub const fn alignment(self) -> usize {
        match self {
            Self::AssociateCompletionPort => 8,
            _ => 4,
        }
    }

    pub const fn variable_length(self) -> bool {
        matches!(self, Self::BasicProcessIdList | Self::SecurityLimit)
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated job buffer"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated job buffer"),
    )
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn encode_io(io: IoCounters, bytes: &mut [u8], offset: usize) {
    write_u64(bytes, offset, io.read_operation_count);
    write_u64(bytes, offset + 8, io.write_operation_count);
    write_u64(bytes, offset + 16, io.other_operation_count);
    write_u64(bytes, offset + 24, io.read_transfer_count);
    write_u64(bytes, offset + 32, io.write_transfer_count);
    write_u64(bytes, offset + 40, io.other_transfer_count);
}

fn decode_io(bytes: &[u8], offset: usize) -> IoCounters {
    IoCounters {
        read_operation_count: read_u64(bytes, offset),
        write_operation_count: read_u64(bytes, offset + 8),
        other_operation_count: read_u64(bytes, offset + 16),
        read_transfer_count: read_u64(bytes, offset + 24),
        write_transfer_count: read_u64(bytes, offset + 32),
        other_transfer_count: read_u64(bytes, offset + 40),
    }
}

pub fn encode_accounting(accounting: JobAccounting, bytes: &mut [u8]) -> Option<usize> {
    (bytes.len() >= BASIC_ACCOUNTING_SIZE).then_some(())?;
    bytes[..BASIC_ACCOUNTING_SIZE].fill(0);
    write_u64(bytes, 0, accounting.total_user_time as u64);
    write_u64(bytes, 8, accounting.total_kernel_time as u64);
    write_u64(bytes, 16, accounting.this_period_total_user_time as u64);
    write_u64(bytes, 24, accounting.this_period_total_kernel_time as u64);
    write_u32(bytes, 32, accounting.total_page_fault_count);
    write_u32(bytes, 36, accounting.total_processes);
    write_u32(bytes, 40, accounting.active_processes);
    write_u32(bytes, 44, accounting.total_terminated_processes);
    Some(BASIC_ACCOUNTING_SIZE)
}

pub fn encode_basic_and_io_accounting(
    accounting: JobAccounting,
    bytes: &mut [u8],
) -> Option<usize> {
    (bytes.len() >= BASIC_AND_IO_ACCOUNTING_SIZE).then_some(())?;
    encode_accounting(accounting, bytes)?;
    encode_io(accounting.io, bytes, BASIC_ACCOUNTING_SIZE);
    Some(BASIC_AND_IO_ACCOUNTING_SIZE)
}

pub fn encode_basic_limits(limits: JobBasicLimits, bytes: &mut [u8]) -> Option<usize> {
    (bytes.len() >= BASIC_LIMIT_SIZE).then_some(())?;
    bytes[..BASIC_LIMIT_SIZE].fill(0);
    write_u64(bytes, 0, limits.per_process_user_time_limit as u64);
    write_u64(bytes, 8, limits.per_job_user_time_limit as u64);
    write_u32(bytes, 16, limits.limit_flags);
    write_u64(bytes, 24, limits.minimum_working_set_size);
    write_u64(bytes, 32, limits.maximum_working_set_size);
    write_u32(bytes, 40, limits.active_process_limit);
    write_u64(bytes, 48, limits.affinity);
    write_u32(bytes, 56, limits.priority_class);
    write_u32(bytes, 60, limits.scheduling_class);
    Some(BASIC_LIMIT_SIZE)
}

pub fn decode_basic_limits(bytes: &[u8]) -> Option<JobBasicLimits> {
    (bytes.len() >= BASIC_LIMIT_SIZE).then_some(JobBasicLimits {
        per_process_user_time_limit: read_u64(bytes, 0) as i64,
        per_job_user_time_limit: read_u64(bytes, 8) as i64,
        limit_flags: read_u32(bytes, 16),
        minimum_working_set_size: read_u64(bytes, 24),
        maximum_working_set_size: read_u64(bytes, 32),
        active_process_limit: read_u32(bytes, 40),
        affinity: read_u64(bytes, 48),
        priority_class: read_u32(bytes, 56),
        scheduling_class: read_u32(bytes, 60),
    })
}

pub fn encode_extended_limits(limits: JobExtendedLimits, bytes: &mut [u8]) -> Option<usize> {
    (bytes.len() >= EXTENDED_LIMIT_SIZE).then_some(())?;
    bytes[..EXTENDED_LIMIT_SIZE].fill(0);
    encode_basic_limits(limits.basic, bytes)?;
    encode_io(limits.io, bytes, BASIC_LIMIT_SIZE);
    write_u64(bytes, 112, limits.process_memory_limit);
    write_u64(bytes, 120, limits.job_memory_limit);
    write_u64(bytes, 128, limits.peak_process_memory_used);
    write_u64(bytes, 136, limits.peak_job_memory_used);
    Some(EXTENDED_LIMIT_SIZE)
}

pub fn decode_extended_limits(bytes: &[u8]) -> Option<JobExtendedLimits> {
    (bytes.len() >= EXTENDED_LIMIT_SIZE).then_some(JobExtendedLimits {
        basic: decode_basic_limits(bytes)?,
        io: decode_io(bytes, BASIC_LIMIT_SIZE),
        process_memory_limit: read_u64(bytes, 112),
        job_memory_limit: read_u64(bytes, 120),
        peak_process_memory_used: read_u64(bytes, 128),
        peak_job_memory_used: read_u64(bytes, 136),
    })
}

pub fn encode_process_ids(
    assigned: u32,
    process_ids: &[u32],
    bytes: &mut [u8],
) -> Result<usize, u32> {
    if bytes.len() < BASIC_PROCESS_ID_LIST_MINIMUM_SIZE {
        return Err(crate::STATUS_INFO_LENGTH_MISMATCH);
    }
    bytes.fill(0);
    write_u32(bytes, 0, assigned);
    let capacity = (bytes.len() - BASIC_PROCESS_ID_LIST_HEADER_SIZE) / 8;
    let written = process_ids.len().min(capacity);
    write_u32(bytes, 4, written as u32);
    for (index, process_id) in process_ids.iter().take(written).enumerate() {
        write_u64(
            bytes,
            BASIC_PROCESS_ID_LIST_HEADER_SIZE + index * 8,
            *process_id as u64,
        );
    }
    let length = BASIC_PROCESS_ID_LIST_HEADER_SIZE + written * 8;
    if written == process_ids.len() {
        Ok(length)
    } else {
        Err(STATUS_BUFFER_OVERFLOW)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn information_class_contract_matches_nt5_x64() {
        let lengths = [48, 64, 16, 4, 40, 4, 16, 96, 144, 4];
        for (index, expected) in lengths.into_iter().enumerate() {
            let class = JobInformationClass::from_u32((index + 1) as u32).unwrap();
            assert_eq!(class.minimum_length(), expected);
        }
        assert_eq!(JobInformationClass::from_u32(0), None);
        assert_eq!(JobInformationClass::from_u32(11), None);
        assert_eq!(JobInformationClass::AssociateCompletionPort.alignment(), 8);
    }

    #[test]
    fn basic_and_extended_limits_roundtrip_exact_offsets() {
        let basic = JobBasicLimits {
            per_process_user_time_limit: 1,
            per_job_user_time_limit: 2,
            limit_flags: 3,
            minimum_working_set_size: 4,
            maximum_working_set_size: 5,
            active_process_limit: 6,
            affinity: 7,
            priority_class: 8,
            scheduling_class: 9,
        };
        let mut bytes = [0xCC; EXTENDED_LIMIT_SIZE];
        let extended = JobExtendedLimits {
            basic,
            io: IoCounters {
                read_operation_count: 10,
                write_operation_count: 11,
                other_operation_count: 12,
                read_transfer_count: 13,
                write_transfer_count: 14,
                other_transfer_count: 15,
            },
            process_memory_limit: 16,
            job_memory_limit: 17,
            peak_process_memory_used: 18,
            peak_job_memory_used: 19,
        };
        assert_eq!(
            encode_extended_limits(extended, &mut bytes),
            Some(EXTENDED_LIMIT_SIZE)
        );
        assert_eq!(decode_extended_limits(&bytes), Some(extended));
        assert_eq!(read_u32(&bytes, 16), 3);
        assert_eq!(read_u64(&bytes, 48), 7);
        assert_eq!(read_u64(&bytes, 112), 16);
    }

    #[test]
    fn process_id_list_reports_overflow_without_overwriting_bounds() {
        let mut bytes = [0xCC; 24];
        assert_eq!(
            encode_process_ids(3, &[4, 8, 12], &mut bytes),
            Err(STATUS_BUFFER_OVERFLOW)
        );
        assert_eq!(read_u32(&bytes, 0), 3);
        assert_eq!(read_u32(&bytes, 4), 2);
        assert_eq!(read_u64(&bytes, 8), 4);
        assert_eq!(read_u64(&bytes, 16), 8);
    }
}
