//! Class storage drivers consume these driver-neutral RTL wire contracts.

use nt_compat_exports::rtl::classpnp::{format_guid_utf16, write_version_info, GUID_STRING_UNITS};

#[path = "../../../components/ntos-executive/src/ntoskrnl_classpnp_rtl.rs"]
mod native;

#[test]
fn guid_formatter_preserves_windows_mixed_endian_layout_and_nul() {
    let guid = [
        0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x10,
    ];
    let formatted = format_guid_utf16(&guid);
    assert_eq!(GUID_STRING_UNITS, 39);
    assert_eq!(formatted[38], 0);
    assert_eq!(String::from_utf16(&formatted[..38]).unwrap(), "{11223344-5566-7788-99aa-bbccddeeff10}");
    assert_eq!(nt_compat_exports::rtl::guid::guid_from_string(&formatted[..38]), Some(guid));
}

#[test]
fn version_writer_rejects_wrong_size_before_touching_output() {
    for declared in [0, 1, 0x113, 0x115, 0x11b, 0x11d, u32::MAX] {
        let mut output = [0xa5; 0x11c];
        output[..4].copy_from_slice(&declared.to_le_bytes());
        let before = output;
        assert_eq!(write_version_info(&mut output), None);
        assert_eq!(output, before);
    }
}

#[test]
fn version_writer_populates_only_declared_base_or_extended_layout() {
    let mut base = [0xa5; 0x11c];
    base[..4].copy_from_slice(&0x114u32.to_le_bytes());
    assert_eq!(write_version_info(&mut base), Some(0x114));
    assert_eq!(u32::from_le_bytes(base[4..8].try_into().unwrap()), 5);
    assert_eq!(u32::from_le_bytes(base[8..12].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(base[12..16].try_into().unwrap()), 3790);
    assert_eq!(u32::from_le_bytes(base[16..20].try_into().unwrap()), 2);
    assert_eq!(&base[20..0x114], &[0xa5; 0x100]);
    assert_eq!(&base[0x114..], &[0xa5; 8]);

    let mut extended = [0xa5; 0x11c];
    extended[..4].copy_from_slice(&0x11cu32.to_le_bytes());
    assert_eq!(write_version_info(&mut extended), Some(0x11c));
    assert_eq!(&extended[0x114..0x11a], &[0; 6]);
    assert_eq!(extended[0x11a], 1);
    assert_eq!(extended[0x11b], 0);
}

#[test]
fn native_guid_string_is_owned_by_supplied_pool_and_releasable() {
    let guid = [
        0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0x88, 0x77, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x10,
    ];
    let mut descriptor = [0xa5u8; 16];
    let status = unsafe {
        native::rtl_string_from_guid_with_pool(guid.as_ptr(), descriptor.as_mut_ptr(), |size| {
            assert_eq!(size, 78);
            Box::into_raw(Box::new([0u8; 78])) as u64
        })
    };
    assert_eq!(status, 0);
    assert_eq!(u16::from_le_bytes(descriptor[..2].try_into().unwrap()), 76);
    assert_eq!(u16::from_le_bytes(descriptor[2..4].try_into().unwrap()), 78);
    let pointer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    assert_ne!(pointer, 0);
    let owned = unsafe { Box::from_raw(pointer as *mut [u8; 78]) };
    let units: Vec<u16> = owned.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    assert_eq!(String::from_utf16(&units[..38]).unwrap(), "{11223344-5566-7788-99aa-bbccddeeff10}");
    assert_eq!(units[38], 0);
}

#[test]
fn native_version_guard_prevents_bad_size_overwrite() {
    let mut output = [0xa5u8; 0x11c];
    output[..4].copy_from_slice(&0x11du32.to_le_bytes());
    let before = output;
    assert_eq!(native::rtl_get_version(output.as_mut_ptr()) as u32, 0xc000000d);
    assert_eq!(output, before);
}
