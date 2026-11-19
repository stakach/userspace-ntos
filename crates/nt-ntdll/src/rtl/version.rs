//! The OS version an application is told, as ReactOS `dll/ntdll/rtl/version.c` reports it.
//!
//! The kernel publishes the version in the PEB (`OSMajorVersion`, `OSMinorVersion`,
//! `OSBuildNumber`, `OSCSDVersion`, `OSPlatformId`), and product type and suite mask in
//! KUSER_SHARED_DATA. `RtlGetVersion` and `RtlGetNtVersionNumbers` copy them; nothing here
//! chooses a version.

/// `sizeof(RTL_OSVERSIONINFOW)` and `sizeof(RTL_OSVERSIONINFOEXW)`.
pub const OSVERSIONINFOW_SIZE: u32 = 0x114;
pub const OSVERSIONINFOEXW_SIZE: u32 = 0x11c;

/// `PRODUCT_*` and `NtProduct*` values used by `RtlGetProductInfo`.
const PRODUCT_UNDEFINED: u32 = 0;
const PRODUCT_BUSINESS: u32 = 0x06;
const PRODUCT_ENTERPRISE_SERVER: u32 = 0x0a;
const PRODUCT_STANDARD_SERVER: u32 = 0x07;
const PRODUCT_PROFESSIONAL: u32 = 0x30;
const NT_PRODUCT_WIN_NT: u32 = 1;
const NT_PRODUCT_LAN_MAN_NT: u32 = 2;
const NT_PRODUCT_SERVER: u32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PebVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u16,
    /// `OSCSDVersion`: service pack major in bits 8-15, minor in bits 0-7.
    pub csd_version: u16,
    pub platform: u32,
}

/// `Some(extended)` for the two structure sizes `RtlGetVersion` accepts.
pub fn version_info_kind(size: u32) -> Option<bool> {
    match size {
        OSVERSIONINFOW_SIZE => Some(false),
        OSVERSIONINFOEXW_SIZE => Some(true),
        _ => None,
    }
}

fn put_u16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Fill an `RTL_OSVERSIONINFO(EX)W` whose size field was accepted by [`version_info_kind`].
/// `out` is the whole structure; `csd` is the PEB's CSD version string.
pub fn fill_version_info(
    out: &mut [u8],
    version: PebVersion,
    csd: &[u16],
    product_type: u32,
    suite_mask: u32,
) {
    put_u32(out, 4, version.major);
    put_u32(out, 8, version.minor);
    put_u32(out, 12, u32::from(version.build));
    put_u32(out, 16, version.platform);
    // szCSDVersion[128]: the PEB string, cut to leave room for its terminator.
    out[0x14..0x114].fill(0);
    let length = csd.iter().position(|&unit| unit == 0).unwrap_or(csd.len()).min(127);
    for (index, &unit) in csd[..length].iter().enumerate() {
        put_u16(out, 0x14 + index * 2, unit);
    }
    if out.len() >= OSVERSIONINFOEXW_SIZE as usize {
        put_u16(out, 0x114, (version.csd_version >> 8) & 0xff);
        put_u16(out, 0x116, version.csd_version & 0xff);
        put_u16(out, 0x118, suite_mask as u16);
        out[0x11a] = product_type as u8;
        out[0x11b] = 0;
    }
}

/// `RtlGetNtVersionNumbers`: at least 5.1, and the build tagged with 0xF0000000.
pub fn nt_version_numbers(major: u32, minor: u32, build: u16) -> (u32, u32, u32) {
    let reported_major = major.max(5);
    let reported_minor = if major < 5 || (major == 5 && minor < 1) { 1 } else { minor };
    (reported_major, reported_minor, 0xf000_0000 | u32::from(build))
}

/// `RtlGetProductInfo` (ReactOS `sdk/lib/rtl/product.c`): the product for the requested
/// version and the system's product type, and whether the request was valid.
pub fn product_info(os_major: u32, os_minor: u32, product_type: u32) -> (u32, bool) {
    if os_major < 6 {
        return (PRODUCT_UNDEFINED, false);
    }
    match product_type {
        NT_PRODUCT_WIN_NT if os_major == 6 && os_minor == 0 => (PRODUCT_BUSINESS, true),
        NT_PRODUCT_WIN_NT => (PRODUCT_PROFESSIONAL, true),
        NT_PRODUCT_LAN_MAN_NT => (PRODUCT_ENTERPRISE_SERVER, true),
        NT_PRODUCT_SERVER => (PRODUCT_STANDARD_SERVER, true),
        _ => (PRODUCT_UNDEFINED, false),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    const LIBERNT: PebVersion = PebVersion {
        major: 10,
        minor: 0,
        build: 26100,
        csd_version: 0x0102,
        platform: 2,
    };

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    #[test]
    fn reports_the_published_version_not_a_constant() {
        let mut info = vec![0xccu8; OSVERSIONINFOEXW_SIZE as usize];
        info[..4].copy_from_slice(&OSVERSIONINFOEXW_SIZE.to_le_bytes());
        let csd: Vec<u16> = "Service Pack 1".encode_utf16().collect();
        fill_version_info(&mut info, LIBERNT, &csd, 1, 0x0100);
        assert_eq!(u32_at(&info, 0), OSVERSIONINFOEXW_SIZE);
        assert_eq!((u32_at(&info, 4), u32_at(&info, 8), u32_at(&info, 12)), (10, 0, 26100));
        assert_eq!(u32_at(&info, 16), 2);
        let text: Vec<u16> = info[0x14..0x14 + csd.len() * 2]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(text, csd);
        assert_eq!(&info[0x14 + csd.len() * 2..0x14 + csd.len() * 2 + 2], &[0, 0]);
        assert_eq!(&info[0x114..0x11c], &[1, 0, 2, 0, 0, 1, 1, 0]);
    }

    #[test]
    fn the_short_structure_is_not_written_past_its_end() {
        let mut info = vec![0xccu8; OSVERSIONINFOW_SIZE as usize];
        fill_version_info(&mut info, LIBERNT, &[], 1, 0);
        assert_eq!(u32_at(&info, 4), 10);
        assert!(info[0x14..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn only_the_two_documented_sizes_are_accepted() {
        assert_eq!(version_info_kind(0x114), Some(false));
        assert_eq!(version_info_kind(0x11c), Some(true));
        assert_eq!(version_info_kind(0), None);
        assert_eq!(version_info_kind(0x120), None);
    }

    #[test]
    fn nt_version_numbers_follow_reactos() {
        assert_eq!(nt_version_numbers(10, 0, 26100), (10, 0, 0xf000_65f4));
        assert_eq!(nt_version_numbers(4, 0, 1381), (5, 1, 0xf000_0565));
        assert_eq!(nt_version_numbers(5, 0, 2195), (5, 1, 0xf000_0893));
        assert_eq!(nt_version_numbers(5, 2, 3790), (5, 2, 0xf000_0ece));
    }

    #[test]
    fn product_info_follows_the_product_type() {
        assert_eq!(product_info(5, 2, 1), (0, false));
        assert_eq!(product_info(6, 0, 1), (0x06, true));
        assert_eq!(product_info(10, 0, 1), (0x30, true));
        assert_eq!(product_info(10, 0, 2), (0x0a, true));
        assert_eq!(product_info(10, 0, 3), (0x07, true));
        assert_eq!(product_info(10, 0, 9), (0, false));
    }
}
