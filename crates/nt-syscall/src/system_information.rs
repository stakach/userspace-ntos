//! Fixed-layout NT5 x64 system-information records and query-size policy.

use crate::{STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_INFO_CLASS};

pub const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SYSTEM_PROCESSOR_INFORMATION_CLASS: u32 = 1;
pub const SYSTEM_TIME_OF_DAY_INFORMATION_CLASS: u32 = 3;
pub const SYSTEM_MODULE_INFORMATION_CLASS: u32 = 11;
pub const SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS: u32 = 44;

pub const SYSTEM_BASIC_INFORMATION_SIZE: usize = 0x40;
pub const SYSTEM_PROCESSOR_INFORMATION_SIZE: usize = 0x0c;
pub const SYSTEM_TIME_OF_DAY_INFORMATION_SIZE: usize = 0x30;
pub const RTL_PROCESS_MODULES_HEADER_SIZE: usize = 0x08;
pub const RTL_PROCESS_MODULE_INFORMATION_SIZE: usize = 0x128;
pub const RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE: usize = 256;
pub const SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE: usize = 0xac;

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
pub struct SystemModuleEntry {
    pub section: u32,
    pub mapped_base: u64,
    pub image_base: u64,
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name_len: u16,
    pub full_path_name: [u8; RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE],
}

impl SystemModuleEntry {
    pub const EMPTY: Self = Self {
        section: 0,
        mapped_base: 0,
        image_base: 0,
        image_size: 0,
        flags: 0,
        load_order_index: 0,
        init_order_index: 0,
        load_count: 0,
        offset_to_file_name: 0,
        full_path_name_len: 0,
        full_path_name: [0; RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE],
    };

    pub fn new(
        full_path_name: &[u8],
        mapped_base: u64,
        image_base: u64,
        image_size: u32,
        flags: u32,
        load_order_index: u16,
        init_order_index: u16,
        load_count: u16,
    ) -> Option<Self> {
        if full_path_name.is_empty()
            || full_path_name.len() > RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE
            || image_base == 0
            || image_size == 0
        {
            return None;
        }

        let mut entry = Self {
            section: 0,
            mapped_base,
            image_base,
            image_size,
            flags,
            load_order_index,
            init_order_index,
            load_count,
            offset_to_file_name: module_file_name_offset(full_path_name),
            full_path_name_len: full_path_name.len() as u16,
            full_path_name: [0; RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE],
        };
        entry.full_path_name[..full_path_name.len()].copy_from_slice(full_path_name);
        Some(entry)
    }

    pub fn path(&self) -> &[u8] {
        &self.full_path_name[..self.full_path_name_len as usize]
    }
}

pub fn system_module_information_required_length(module_count: usize) -> Option<usize> {
    module_count
        .checked_mul(RTL_PROCESS_MODULE_INFORMATION_SIZE)
        .and_then(|modules| RTL_PROCESS_MODULES_HEADER_SIZE.checked_add(modules))
}

pub fn encode_system_module_information(
    output: &mut [u8],
    modules: &[SystemModuleEntry],
) -> Result<u32, QueryError> {
    let required_length =
        system_module_information_required_length(modules.len()).ok_or(QueryError {
            status: STATUS_INFO_LENGTH_MISMATCH,
            return_length: u32::MAX,
        })?;
    let return_length = required_length.min(u32::MAX as usize) as u32;

    output.fill(0);
    if output.len() >= RTL_PROCESS_MODULES_HEADER_SIZE {
        put_u32(output, 0, modules.len() as u32);
    }

    for (index, module) in modules.iter().enumerate() {
        let Some(entry_span) = index.checked_mul(RTL_PROCESS_MODULE_INFORMATION_SIZE) else {
            break;
        };
        let Some(offset) = RTL_PROCESS_MODULES_HEADER_SIZE.checked_add(entry_span) else {
            break;
        };
        if output.len() < offset + RTL_PROCESS_MODULE_INFORMATION_SIZE {
            break;
        }
        encode_module_entry(output, offset, module);
    }

    if output.len() < required_length {
        Err(QueryError {
            status: STATUS_INFO_LENGTH_MISMATCH,
            return_length,
        })
    } else {
        Ok(return_length)
    }
}

fn encode_module_entry(output: &mut [u8], offset: usize, module: &SystemModuleEntry) {
    put_u32(output, offset, module.section);
    put_u64(output, offset + 0x08, module.mapped_base);
    put_u64(output, offset + 0x10, module.image_base);
    put_u32(output, offset + 0x18, module.image_size);
    put_u32(output, offset + 0x1c, module.flags);
    put_u16(output, offset + 0x20, module.load_order_index);
    put_u16(output, offset + 0x22, module.init_order_index);
    put_u16(output, offset + 0x24, module.load_count);
    put_u16(output, offset + 0x26, module.offset_to_file_name);
    let path_len = (module.full_path_name_len as usize).min(RTL_PROCESS_MODULE_FULL_PATH_NAME_SIZE);
    output[offset + 0x28..offset + 0x28 + path_len]
        .copy_from_slice(&module.full_path_name[..path_len]);
}

fn module_file_name_offset(path: &[u8]) -> u16 {
    let mut offset = 0usize;
    for (index, &byte) in path.iter().enumerate() {
        if byte == b'\\' || byte == b'/' {
            offset = index + 1;
        }
    }
    offset.min(u16::MAX as usize) as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemInformationKind {
    Basic,
    Processor,
    TimeOfDay,
    CurrentTimeZone,
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
        SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS => {
            if buffer_length != SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE {
                return Err(QueryError {
                    status: STATUS_INFO_LENGTH_MISMATCH,
                    return_length: SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE as u32,
                });
            }
            Ok(QueryPlan {
                kind: SystemInformationKind::CurrentTimeZone,
                copy_length: SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE,
                return_length: SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE as u32,
            })
        }
        _ => Err(QueryError {
            status: STATUS_INVALID_INFO_CLASS,
            return_length: 0,
        }),
    }
}

/// Validate class 44's set length and return the prefix consumed by the kernel.
pub fn set_current_time_zone_plan(buffer_length: usize) -> Result<usize, u32> {
    if buffer_length < SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE {
        Err(STATUS_INFO_LENGTH_MISMATCH)
    } else {
        Ok(SYSTEM_CURRENT_TIME_ZONE_INFORMATION_SIZE)
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
    use alloc::vec;

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
    fn current_timezone_uses_reactos_query_and_set_length_rules() {
        for length in [0, 171, 173] {
            let error = query_plan(SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS, length).unwrap_err();
            assert_eq!(error.status, STATUS_INFO_LENGTH_MISMATCH);
            assert_eq!(error.return_length, 172);
        }
        let plan = query_plan(SYSTEM_CURRENT_TIME_ZONE_INFORMATION_CLASS, 172).unwrap();
        assert_eq!(plan.kind, SystemInformationKind::CurrentTimeZone);
        assert_eq!(plan.copy_length, 172);
        assert_eq!(plan.return_length, 172);

        for length in [0, 171] {
            assert_eq!(
                set_current_time_zone_plan(length),
                Err(STATUS_INFO_LENGTH_MISMATCH),
            );
        }
        assert_eq!(set_current_time_zone_plan(172), Ok(172));
        assert_eq!(set_current_time_zone_plan(173), Ok(172));
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

    #[test]
    fn system_module_information_has_the_nt5_x64_layout() {
        let modules = [
            SystemModuleEntry::new(
                b"\\SystemRoot\\system32\\drivers\\npfs.sys",
                0x1000,
                0x2000,
                0x14000,
                0x20,
                0,
                0,
                1,
            )
            .unwrap(),
            SystemModuleEntry::new(
                b"\\SystemRoot\\system32\\win32k.sys",
                0x3000,
                0x3000,
                0x220000,
                0,
                1,
                0,
                1,
            )
            .unwrap(),
        ];
        let required = system_module_information_required_length(modules.len()).unwrap();
        assert_eq!(required, 0x08 + 2 * 0x128);

        let mut output = vec![0xcc; required];
        assert_eq!(
            encode_system_module_information(&mut output, &modules),
            Ok(required as u32)
        );

        assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()), 2);
        assert_eq!(&output[4..8], &[0; 4]);
        let first = RTL_PROCESS_MODULES_HEADER_SIZE;
        assert_eq!(
            u32::from_le_bytes(output[first..first + 4].try_into().unwrap()),
            0
        );
        assert_eq!(
            u64::from_le_bytes(output[first + 0x08..first + 0x10].try_into().unwrap()),
            0x1000
        );
        assert_eq!(
            u64::from_le_bytes(output[first + 0x10..first + 0x18].try_into().unwrap()),
            0x2000
        );
        assert_eq!(
            u32::from_le_bytes(output[first + 0x18..first + 0x1c].try_into().unwrap()),
            0x14000
        );
        assert_eq!(
            u32::from_le_bytes(output[first + 0x1c..first + 0x20].try_into().unwrap()),
            0x20
        );
        assert_eq!(
            u16::from_le_bytes(output[first + 0x20..first + 0x22].try_into().unwrap()),
            0
        );
        assert_eq!(
            u16::from_le_bytes(output[first + 0x24..first + 0x26].try_into().unwrap()),
            1
        );
        assert_eq!(
            u16::from_le_bytes(output[first + 0x26..first + 0x28].try_into().unwrap()),
            29
        );
        assert_eq!(
            &output[first + 0x28..first + 0x28 + modules[0].path().len()],
            modules[0].path()
        );

        let second = RTL_PROCESS_MODULES_HEADER_SIZE + RTL_PROCESS_MODULE_INFORMATION_SIZE;
        assert_eq!(
            u16::from_le_bytes(output[second + 0x20..second + 0x22].try_into().unwrap()),
            1
        );
        assert_eq!(
            &output[second + 0x28..second + 0x28 + modules[1].path().len()],
            modules[1].path()
        );
    }

    #[test]
    fn system_module_information_reports_required_length_and_prefix() {
        let modules = [SystemModuleEntry::new(
            b"\\SystemRoot\\system32\\win32k.sys",
            0x3000,
            0x3000,
            0x220000,
            0,
            0,
            0,
            1,
        )
        .unwrap()];
        let required = system_module_information_required_length(modules.len()).unwrap();

        let mut header = vec![0xcc; RTL_PROCESS_MODULES_HEADER_SIZE];
        let error = encode_system_module_information(&mut header, &modules).unwrap_err();
        assert_eq!(error.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(error.return_length, required as u32);
        assert_eq!(u32::from_le_bytes(header[0..4].try_into().unwrap()), 1);
        assert_eq!(&header[4..], &[0; 4]);

        let mut too_small_for_header = vec![0xcc; 4];
        let error =
            encode_system_module_information(&mut too_small_for_header, &modules).unwrap_err();
        assert_eq!(error.status, STATUS_INFO_LENGTH_MISMATCH);
        assert_eq!(error.return_length, required as u32);
        assert_eq!(too_small_for_header, [0; 4]);
    }
}
