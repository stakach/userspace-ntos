//! Win7 x64 `KUSER_SHARED_DATA` byte layout and page initialization.

pub const PAGE_SIZE: usize = 0x1000;
pub const TICK_COUNT_LOW_DEPRECATED: usize = 0x000;
pub const TICK_COUNT_MULTIPLIER: usize = 0x004;
pub const INTERRUPT_TIME: usize = 0x008;
pub const SYSTEM_TIME: usize = 0x014;
pub const TIME_ZONE_BIAS: usize = 0x020;
pub const TIME_ZONE_ID: usize = 0x240;
pub const IMAGE_NUMBER_LOW: usize = 0x02c;
pub const IMAGE_NUMBER_HIGH: usize = 0x02e;
pub const NT_SYSTEM_ROOT: usize = 0x030;
pub const NT_PRODUCT_TYPE: usize = 0x264;
pub const PRODUCT_TYPE_IS_VALID: usize = 0x268;
pub const NT_MAJOR_VERSION: usize = 0x26c;
pub const NT_MINOR_VERSION: usize = 0x270;
pub const PROCESSOR_FEATURES: usize = 0x274;
pub const NUMBER_OF_PHYSICAL_PAGES: usize = 0x2e8;
pub const TICK_COUNT: usize = 0x320;
pub const COOKIE: usize = 0x330;
pub const ACTIVE_PROCESSOR_COUNT: usize = 0x3c0;

pub const PROCESSOR_FEATURE_COUNT: usize = 64;
pub const TICK_COUNT_MULTIPLIER_ONE_MS: u32 = 1 << 24;

const KF_MMX: u32 = 0x0000_0100;
const KF_FXSR: u32 = 0x0000_0800;
const KF_XMMI: u32 = 0x0000_2000;
const KF_XMMI64: u32 = 0x0001_0000;
const KF_SSE3: u32 = 0x0008_0000;
const KF_CMPXCHG16B: u32 = 0x0010_0000;
const KF_NX_ENABLED: u32 = 0x8000_0000;

const PF_COMPARE_EXCHANGE_DOUBLE: usize = 2;
const PF_MMX_INSTRUCTIONS_AVAILABLE: usize = 3;
const PF_XMMI_INSTRUCTIONS_AVAILABLE: usize = 6;
const PF_RDTSC_INSTRUCTION_AVAILABLE: usize = 8;
const PF_PAE_ENABLED: usize = 9;
const PF_XMMI64_INSTRUCTIONS_AVAILABLE: usize = 10;
const PF_NX_ENABLED: usize = 12;
const PF_SSE3_INSTRUCTIONS_AVAILABLE: usize = 13;
const PF_COMPARE_EXCHANGE128: usize = 14;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticInformation {
    pub nt_product_type: u32,
    pub nt_major_version: u32,
    pub nt_minor_version: u32,
    pub image_number_low: u16,
    pub image_number_high: u16,
    pub number_of_physical_pages: u32,
    pub active_processor_count: u32,
    pub processor_feature_bits: u32,
    pub cookie: u32,
}

/// Initializes a complete page snapshot. Dynamic clocks may later be refreshed in place.
pub fn initialize_page(
    page: &mut [u8; PAGE_SIZE],
    information: StaticInformation,
    interrupt_time_100ns: u64,
    system_time_100ns: u64,
) {
    page.fill(0);
    put_u32(page, TICK_COUNT_MULTIPLIER, TICK_COUNT_MULTIPLIER_ONE_MS);
    put_ksystem_time(page, INTERRUPT_TIME, interrupt_time_100ns);
    put_ksystem_time(page, SYSTEM_TIME, system_time_100ns);
    update_time_zone(page, 0, 0);
    put_u16(page, IMAGE_NUMBER_LOW, information.image_number_low);
    put_u16(page, IMAGE_NUMBER_HIGH, information.image_number_high);
    put_utf16_z(page, NT_SYSTEM_ROOT, b"C:\\Windows");
    put_u32(page, NT_PRODUCT_TYPE, information.nt_product_type);
    page[PRODUCT_TYPE_IS_VALID] = 1;
    put_u32(page, NT_MAJOR_VERSION, information.nt_major_version);
    put_u32(page, NT_MINOR_VERSION, information.nt_minor_version);
    page[PROCESSOR_FEATURES..PROCESSOR_FEATURES + PROCESSOR_FEATURE_COUNT]
        .copy_from_slice(&processor_features(information.processor_feature_bits));
    put_u32(
        page,
        NUMBER_OF_PHYSICAL_PAGES,
        information.number_of_physical_pages,
    );
    let tick_count_ms = interrupt_time_100ns / 10_000;
    put_ksystem_time(page, TICK_COUNT, tick_count_ms);
    put_u32(page, TICK_COUNT_LOW_DEPRECATED, tick_count_ms as u32);
    put_u32(page, COOKIE, information.cookie);
    put_u32(
        page,
        ACTIVE_PROCESSOR_COUNT,
        information.active_processor_count,
    );
}

/// Publish the effective timezone fields consumed directly through `KUSER_SHARED_DATA`.
pub fn update_time_zone(page: &mut [u8; PAGE_SIZE], bias_100ns: i64, time_zone_id: u32) {
    put_ksystem_time(page, TIME_ZONE_BIAS, bias_100ns as u64);
    put_u32(page, TIME_ZONE_ID, time_zone_id);
}

/// Publish timezone fields to a live, concurrently readable shared-data page.
///
/// # Safety
/// `page` is an 8-byte-aligned, writable `KUSER_SHARED_DATA` page mapping.
pub unsafe fn publish_time_zone(page: *mut u8, bias_100ns: i64, time_zone_id: u32) {
    let bias = bias_100ns as u64;
    let high = (bias >> 32) as u32;
    debug_assert_eq!(page as usize & 7, 0);
    unsafe {
        // Readers retry unless High1 == High2. Publish High2 first, then Low+High1 atomically.
        core::ptr::write_volatile(page.add(TIME_ZONE_BIAS + 8) as *mut u32, high);
        core::ptr::write_volatile(page.add(TIME_ZONE_BIAS) as *mut u64, bias);
        core::ptr::write_volatile(page.add(TIME_ZONE_ID) as *mut u32, time_zone_id);
    }
}

pub fn processor_features(feature_bits: u32) -> [u8; PROCESSOR_FEATURE_COUNT] {
    let mut features = [0u8; PROCESSOR_FEATURE_COUNT];
    features[PF_COMPARE_EXCHANGE_DOUBLE] = 1;
    features[PF_RDTSC_INSTRUCTION_AVAILABLE] = 1;
    features[PF_PAE_ENABLED] = 1;
    features[PF_MMX_INSTRUCTIONS_AVAILABLE] = (feature_bits & KF_MMX != 0) as u8;
    features[PF_XMMI_INSTRUCTIONS_AVAILABLE] =
        (feature_bits & (KF_FXSR | KF_XMMI) == (KF_FXSR | KF_XMMI)) as u8;
    features[PF_XMMI64_INSTRUCTIONS_AVAILABLE] =
        (feature_bits & (KF_FXSR | KF_XMMI64) == (KF_FXSR | KF_XMMI64)) as u8;
    features[PF_NX_ENABLED] = (feature_bits & KF_NX_ENABLED != 0) as u8;
    features[PF_SSE3_INSTRUCTIONS_AVAILABLE] = (feature_bits & KF_SSE3 != 0) as u8;
    features[PF_COMPARE_EXCHANGE128] = (feature_bits & KF_CMPXCHG16B != 0) as u8;
    features
}

fn put_ksystem_time(page: &mut [u8], offset: usize, value: u64) {
    put_u32(page, offset, value as u32);
    put_u32(page, offset + 4, (value >> 32) as u32);
    put_u32(page, offset + 8, (value >> 32) as u32);
}

fn put_utf16_z(page: &mut [u8], offset: usize, ascii: &[u8]) {
    for (index, &byte) in ascii.iter().enumerate() {
        put_u16(page, offset + index * 2, byte as u16);
    }
    put_u16(page, offset + ascii.len() * 2, 0);
}

fn put_u16(page: &mut [u8], offset: usize, value: u16) {
    page[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(page: &mut [u8], offset: usize, value: u32) {
    page[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(page: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(page[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn initializes_win7_x64_offsets_and_clocks() {
        let mut page = [0xcc; PAGE_SIZE];
        initialize_page(
            &mut page,
            StaticInformation {
                nt_product_type: 1,
                nt_major_version: 6,
                nt_minor_version: 1,
                image_number_low: 0x14c,
                image_number_high: 0x8664,
                number_of_physical_pages: 0x1_0000,
                active_processor_count: 4,
                processor_feature_bits: KF_MMX | KF_FXSR | KF_XMMI | KF_XMMI64 | KF_NX_ENABLED,
                cookie: 0xa3b1_c2d3,
            },
            1_230_000,
            0x01da_0000_0012_3456,
        );
        assert_eq!(read_u32(&page, TICK_COUNT_MULTIPLIER), 1 << 24);
        assert_eq!(read_u32(&page, INTERRUPT_TIME), 1_230_000);
        assert_eq!(read_u32(&page, SYSTEM_TIME), 0x0012_3456);
        assert_eq!(read_u32(&page, NUMBER_OF_PHYSICAL_PAGES), 0x1_0000);
        assert_eq!(read_u32(&page, TICK_COUNT), 123);
        assert_eq!(read_u32(&page, COOKIE), 0xa3b1_c2d3);
        assert_eq!(read_u32(&page, ACTIVE_PROCESSOR_COUNT), 4);
        assert_eq!(page[PROCESSOR_FEATURES], 0);
        assert_eq!(
            page[PROCESSOR_FEATURES + PF_XMMI64_INSTRUCTIONS_AVAILABLE],
            1
        );
    }

    #[test]
    fn does_not_advertise_xsave_without_an_os_backed_flag() {
        const PF_XSAVE_ENABLED: usize = 17;
        let features = processor_features(u32::MAX);
        assert_eq!(features[PF_XSAVE_ENABLED], 0);
    }

    #[test]
    fn publishes_signed_timezone_bias_and_id() {
        #[repr(align(8))]
        struct AlignedPage([u8; PAGE_SIZE]);

        let mut page = AlignedPage([0u8; PAGE_SIZE]);
        unsafe { publish_time_zone(page.0.as_mut_ptr(), -36_000_000_000, 2) };
        assert_eq!(read_u32(&page.0, TIME_ZONE_BIAS), 0x9e3b_9800);
        assert_eq!(read_u32(&page.0, TIME_ZONE_BIAS + 4), 0xffff_fff7);
        assert_eq!(read_u32(&page.0, TIME_ZONE_BIAS + 8), 0xffff_fff7);
        assert_eq!(read_u32(&page.0, TIME_ZONE_ID), 2);
    }
}
