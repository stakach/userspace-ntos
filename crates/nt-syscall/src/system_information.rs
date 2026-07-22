//! Fixed-layout NT5 x64 system-information records and query-size policy.

use crate::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

pub const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SYSTEM_PROCESSOR_INFORMATION_CLASS: u32 = 1;
pub const SYSTEM_TIME_OF_DAY_INFORMATION_CLASS: u32 = 3;

pub const SYSTEM_BASIC_INFORMATION_SIZE: usize = 0x40;
pub const SYSTEM_PROCESSOR_INFORMATION_SIZE: usize = 0x0c;
pub const SYSTEM_TIME_OF_DAY_INFORMATION_SIZE: usize = 0x30;

pub const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Vendor {
    Intel,
    Amd,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemBasicInformation {
    pub timer_resolution_100ns: u32,
    pub page_size: u32,
    pub number_of_physical_pages: u32,
    pub lowest_physical_page_number: u32,
    pub highest_physical_page_number: u32,
    pub allocation_granularity: u32,
    pub minimum_user_mode_address: u64,
    pub maximum_user_mode_address: u64,
    pub active_processors_affinity_mask: u64,
    pub number_of_processors: u8,
}

impl SystemBasicInformation {
    pub fn encode(self) -> [u8; SYSTEM_BASIC_INFORMATION_SIZE] {
        let mut output = [0u8; SYSTEM_BASIC_INFORMATION_SIZE];
        put_u32(&mut output, 0x04, self.timer_resolution_100ns);
        put_u32(&mut output, 0x08, self.page_size);
        put_u32(&mut output, 0x0c, self.number_of_physical_pages);
        put_u32(&mut output, 0x10, self.lowest_physical_page_number);
        put_u32(&mut output, 0x14, self.highest_physical_page_number);
        put_u32(&mut output, 0x18, self.allocation_granularity);
        put_u64(&mut output, 0x20, self.minimum_user_mode_address);
        put_u64(&mut output, 0x28, self.maximum_user_mode_address);
        put_u64(&mut output, 0x30, self.active_processors_affinity_mask);
        output[0x38] = self.number_of_processors;
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemProcessorInformation {
    pub processor_architecture: u16,
    pub processor_level: u16,
    pub processor_revision: u16,
    pub processor_feature_bits: u32,
}

impl SystemProcessorInformation {
    pub fn encode(self) -> [u8; SYSTEM_PROCESSOR_INFORMATION_SIZE] {
        let mut output = [0u8; SYSTEM_PROCESSOR_INFORMATION_SIZE];
        put_u16(&mut output, 0x00, self.processor_architecture);
        put_u16(&mut output, 0x02, self.processor_level);
        put_u16(&mut output, 0x04, self.processor_revision);
        put_u32(&mut output, 0x08, self.processor_feature_bits);
        output
    }
}

/// Converts architectural CPUID leaves to the NT kernel's AMD64 processor fields and KF_* mask.
pub fn amd64_processor_information_from_cpuid(
    vendor: X86Vendor,
    version_eax: u32,
    feature_ecx: u32,
    feature_edx: u32,
    extended_feature_edx: u32,
    xstate_enabled: bool,
) -> SystemProcessorInformation {
    const KF_RDTSC: u32 = 0x0000_0002;
    const KF_CR4: u32 = 0x0000_0004;
    const KF_CMOV: u32 = 0x0000_0008;
    const KF_GLOBAL_PAGE: u32 = 0x0000_0010;
    const KF_LARGE_PAGE: u32 = 0x0000_0020;
    const KF_MTRR: u32 = 0x0000_0040;
    const KF_CMPXCHG8B: u32 = 0x0000_0080;
    const KF_MMX: u32 = 0x0000_0100;
    const KF_DTS: u32 = 0x0000_0200;
    const KF_PAT: u32 = 0x0000_0400;
    const KF_FXSR: u32 = 0x0000_0800;
    const KF_FAST_SYSCALL: u32 = 0x0000_1000;
    const KF_XMMI: u32 = 0x0000_2000;
    const KF_XMMI64: u32 = 0x0001_0000;
    const KF_BRANCH: u32 = 0x0002_0000;
    const KF_SSE3: u32 = 0x0008_0000;
    const KF_CMPXCHG16B: u32 = 0x0010_0000;
    const KF_AUTHENTICAMD: u32 = 0x0020_0000;
    const KF_XSTATE: u32 = 0x0080_0000;
    const KF_GENUINE_INTEL: u32 = 0x0100_0000;
    const KF_NX_BIT: u32 = 0x2000_0000;
    const KF_NX_ENABLED: u32 = 0x8000_0000;

    let base_family = ((version_eax >> 8) & 0x0f) as u16;
    let extended_family = ((version_eax >> 20) & 0xff) as u16;
    let processor_level = if base_family == 0x0f {
        base_family.saturating_add(extended_family)
    } else {
        base_family
    };

    let mut model = ((version_eax >> 4) & 0x0f) as u16;
    if base_family == 0x0f || (base_family == 6 && vendor == X86Vendor::Intel) {
        model |= (((version_eax >> 16) & 0x0f) as u16) << 4;
    }
    let processor_revision = (model << 8) | (version_eax & 0x0f) as u16;

    let mut bits = 0u32;
    if feature_edx & (1 << 1) != 0 {
        bits |= KF_CR4;
    }
    if feature_edx & (1 << 3) != 0 {
        bits |= KF_LARGE_PAGE | KF_CR4;
    }
    if feature_edx & (1 << 4) != 0 {
        bits |= KF_RDTSC;
    }
    if feature_edx & (1 << 8) != 0 {
        bits |= KF_CMPXCHG8B;
    }
    if feature_edx & (1 << 11) != 0 {
        bits |= KF_FAST_SYSCALL;
    }
    if feature_edx & (1 << 12) != 0 {
        bits |= KF_MTRR;
    }
    if feature_edx & (1 << 13) != 0 {
        bits |= KF_GLOBAL_PAGE | KF_CR4;
    }
    if feature_edx & (1 << 15) != 0 {
        bits |= KF_CMOV;
    }
    if feature_edx & (1 << 16) != 0 {
        bits |= KF_PAT;
    }
    if feature_edx & (1 << 21) != 0 {
        bits |= KF_DTS;
    }
    if feature_edx & (1 << 23) != 0 {
        bits |= KF_MMX;
    }
    if feature_edx & (1 << 24) != 0 {
        bits |= KF_FXSR;
    }
    if feature_edx & (1 << 25) != 0 {
        bits |= KF_XMMI;
    }
    if feature_edx & (1 << 26) != 0 {
        bits |= KF_XMMI64;
    }
    if feature_ecx & 1 != 0 {
        bits |= KF_SSE3;
    }
    if feature_ecx & (1 << 13) != 0 {
        bits |= KF_CMPXCHG16B;
    }
    if xstate_enabled && feature_ecx & (1 << 26) != 0 {
        bits |= KF_XSTATE;
    }
    if extended_feature_edx & (1 << 20) != 0 {
        bits |= KF_NX_BIT | KF_NX_ENABLED;
    }
    bits |= match vendor {
        X86Vendor::Intel => KF_GENUINE_INTEL,
        X86Vendor::Amd => KF_AUTHENTICAMD | KF_BRANCH,
        X86Vendor::Other => 0,
    };

    SystemProcessorInformation {
        processor_architecture: PROCESSOR_ARCHITECTURE_AMD64,
        processor_level,
        processor_revision,
        processor_feature_bits: bits,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemTimeOfDayInformation {
    pub boot_time_100ns: u64,
    pub current_time_100ns: u64,
    pub time_zone_bias_100ns: i64,
    pub time_zone_id: u32,
}

impl SystemTimeOfDayInformation {
    pub fn encode(self) -> [u8; SYSTEM_TIME_OF_DAY_INFORMATION_SIZE] {
        let mut output = [0u8; SYSTEM_TIME_OF_DAY_INFORMATION_SIZE];
        put_u64(&mut output, 0x00, self.boot_time_100ns);
        put_u64(&mut output, 0x08, self.current_time_100ns);
        put_u64(&mut output, 0x10, self.time_zone_bias_100ns as u64);
        put_u32(&mut output, 0x18, self.time_zone_id);
        output
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInformationKind {
    Basic,
    Processor,
    TimeOfDay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryPlan {
    pub kind: SystemInformationKind,
    pub copy_length: usize,
    pub return_length: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryError {
    pub status: u32,
    pub return_length: u32,
}

/// Applies the ReactOS NT5 query-size rules after the generic syscall buffer probe.
pub fn query_plan(class: u32, buffer_length: usize) -> Result<QueryPlan, QueryError> {
    match class {
        SYSTEM_BASIC_INFORMATION_CLASS => {
            if buffer_length != SYSTEM_BASIC_INFORMATION_SIZE {
                return Err(QueryError {
                    status: STATUS_INFO_LENGTH_MISMATCH,
                    return_length: SYSTEM_BASIC_INFORMATION_SIZE as u32,
                });
            }
            Ok(QueryPlan {
                kind: SystemInformationKind::Basic,
                copy_length: SYSTEM_BASIC_INFORMATION_SIZE,
                return_length: SYSTEM_BASIC_INFORMATION_SIZE as u32,
            })
        }
        SYSTEM_PROCESSOR_INFORMATION_CLASS => {
            if buffer_length < SYSTEM_PROCESSOR_INFORMATION_SIZE {
                return Err(QueryError {
                    status: STATUS_INFO_LENGTH_MISMATCH,
                    return_length: SYSTEM_PROCESSOR_INFORMATION_SIZE as u32,
                });
            }
            Ok(QueryPlan {
                kind: SystemInformationKind::Processor,
                copy_length: SYSTEM_PROCESSOR_INFORMATION_SIZE,
                return_length: SYSTEM_PROCESSOR_INFORMATION_SIZE as u32,
            })
        }
        SYSTEM_TIME_OF_DAY_INFORMATION_CLASS => {
            if buffer_length > SYSTEM_TIME_OF_DAY_INFORMATION_SIZE {
                return Err(QueryError {
                    status: STATUS_INFO_LENGTH_MISMATCH,
                    return_length: 0,
                });
            }
            Ok(QueryPlan {
                kind: SystemInformationKind::TimeOfDay,
                copy_length: buffer_length,
                return_length: buffer_length as u32,
            })
        }
        _ => Err(QueryError {
            status: STATUS_INVALID_INFO_CLASS,
            return_length: 0,
        }),
    }
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_information_has_the_nt5_x64_layout() {
        let output = SystemBasicInformation {
            timer_resolution_100ns: 10_000,
            page_size: 0x1000,
            number_of_physical_pages: 0x8000,
            lowest_physical_page_number: 0x100,
            highest_physical_page_number: 0x80ff,
            allocation_granularity: 0x1_0000,
            minimum_user_mode_address: 0x1_0000,
            maximum_user_mode_address: 0x0000_07ff_fffe_ffff,
            active_processors_affinity_mask: 1,
            number_of_processors: 1,
        }
        .encode();

        assert_eq!(output.len(), 0x40);
        assert_eq!(&output[0x00..0x04], &[0; 4]);
        assert_eq!(
            u32::from_le_bytes(output[0x04..0x08].try_into().unwrap()),
            10_000
        );
        assert_eq!(
            u32::from_le_bytes(output[0x08..0x0c].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u32::from_le_bytes(output[0x0c..0x10].try_into().unwrap()),
            0x8000
        );
        assert_eq!(
            u32::from_le_bytes(output[0x10..0x14].try_into().unwrap()),
            0x100
        );
        assert_eq!(
            u32::from_le_bytes(output[0x14..0x18].try_into().unwrap()),
            0x80ff
        );
        assert_eq!(
            u32::from_le_bytes(output[0x18..0x1c].try_into().unwrap()),
            0x1_0000
        );
        assert_eq!(&output[0x1c..0x20], &[0; 4]);
        assert_eq!(
            u64::from_le_bytes(output[0x20..0x28].try_into().unwrap()),
            0x1_0000
        );
        assert_eq!(
            u64::from_le_bytes(output[0x28..0x30].try_into().unwrap()),
            0x0000_07ff_fffe_ffff
        );
        assert_eq!(
            u64::from_le_bytes(output[0x30..0x38].try_into().unwrap()),
            1
        );
        assert_eq!(output[0x38], 1);
        assert_eq!(&output[0x39..], &[0; 7]);
    }

    #[test]
    fn processor_information_has_the_nt5_x64_layout() {
        let output = SystemProcessorInformation {
            processor_architecture: PROCESSOR_ARCHITECTURE_AMD64,
            processor_level: 6,
            processor_revision: 0x9702,
            processor_feature_bits: 0xa111_39fe,
        }
        .encode();

        assert_eq!(output, [9, 0, 6, 0, 2, 0x97, 0, 0, 0xfe, 0x39, 0x11, 0xa1]);
    }

    #[test]
    fn cpuid_is_translated_to_nt_processor_fields() {
        // Intel family 6, extended model 9, model 7, stepping 2.
        let version = 2 | (7 << 4) | (6 << 8) | (9 << 16);
        let info = amd64_processor_information_from_cpuid(
            X86Vendor::Intel,
            version,
            1 | (1 << 13) | (1 << 26),
            (1 << 1)
                | (1 << 3)
                | (1 << 4)
                | (1 << 8)
                | (1 << 11)
                | (1 << 12)
                | (1 << 13)
                | (1 << 15)
                | (1 << 16)
                | (1 << 23)
                | (1 << 24)
                | (1 << 25)
                | (1 << 26),
            1 << 20,
            true,
        );
        assert_eq!(info.processor_architecture, PROCESSOR_ARCHITECTURE_AMD64);
        assert_eq!(info.processor_level, 6);
        assert_eq!(info.processor_revision, 0x9702);
        assert_ne!(info.processor_feature_bits & 0x0100_0000, 0);
        assert_ne!(info.processor_feature_bits & 0xa000_0000, 0);
        assert_ne!(info.processor_feature_bits & 0x0080_0000, 0);
    }

    #[test]
    fn xstate_requires_kernel_context_support() {
        let info =
            amd64_processor_information_from_cpuid(X86Vendor::Intel, 6 << 8, 1 << 26, 0, 0, false);
        assert_eq!(info.processor_feature_bits & 0x0080_0000, 0);
    }

    #[test]
    fn fixed_class_length_rules_match_reactos() {
        for length in [0, 63, 65] {
            assert_eq!(
                query_plan(0, length).unwrap_err().status,
                STATUS_INFO_LENGTH_MISMATCH
            );
            assert_eq!(query_plan(0, length).unwrap_err().return_length, 64);
        }
        assert_eq!(query_plan(0, 64).unwrap().copy_length, 64);

        for length in [0, 11] {
            assert_eq!(
                query_plan(1, length).unwrap_err().status,
                STATUS_INFO_LENGTH_MISMATCH
            );
            assert_eq!(query_plan(1, length).unwrap_err().return_length, 12);
        }
        assert_eq!(query_plan(1, 12).unwrap().copy_length, 12);
        assert_eq!(query_plan(1, 13).unwrap().copy_length, 12);
    }

    #[test]
    fn time_of_day_supports_prefix_queries() {
        for length in [0, 24, 32, 48] {
            let plan = query_plan(3, length).unwrap();
            assert_eq!(plan.copy_length, length);
            assert_eq!(plan.return_length, length as u32);
        }
        assert_eq!(
            query_plan(3, 49).unwrap_err().status,
            STATUS_INFO_LENGTH_MISMATCH
        );
        assert_eq!(query_plan(3, 49).unwrap_err().return_length, 0);
    }

    #[test]
    fn unsupported_classes_are_rejected() {
        assert_eq!(
            query_plan(u32::MAX, 0).unwrap_err().status,
            STATUS_INVALID_INFO_CLASS
        );
    }

    #[test]
    fn time_of_day_fields_are_encoded_and_the_tail_is_zero() {
        let output = SystemTimeOfDayInformation {
            boot_time_100ns: 10,
            current_time_100ns: 20,
            time_zone_bias_100ns: -30,
            time_zone_id: 2,
        }
        .encode();
        assert_eq!(u64::from_le_bytes(output[0..8].try_into().unwrap()), 10);
        assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 20);
        assert_eq!(i64::from_le_bytes(output[16..24].try_into().unwrap()), -30);
        assert_eq!(u32::from_le_bytes(output[24..28].try_into().unwrap()), 2);
        assert_eq!(&output[28..], &[0; 20]);
    }
}
