//! A retained mounted FILE_OBJECT keeps a device-relative name. Process metadata must accept
//! that spelling without using the name to reopen or select the image source.

use nt_exe_image::{canonical_hosted_nt_image_path, HostedImageRoot, MAX_NT_IMAGE_PATH};

#[test]
fn mounted_file_name_with_leading_separator_has_canonical_process_metadata() {
    let mut out = [0u8; MAX_NT_IMAGE_PATH];
    let (len, root) = canonical_hosted_nt_image_path(
        br"\windows\system32\csrss.exe",
        b"windows",
        &mut out,
    )
    .expect("the exact mounted File name must be usable as process metadata");
    assert_eq!(root, HostedImageRoot::System32);
    assert_eq!(&out[..len], br"\SystemRoot\System32\csrss.exe");
}

#[test]
fn canonical_process_metadata_is_component_exact_and_case_insensitive() {
    let mut out = [0u8; MAX_NT_IMAGE_PATH];
    let (len, root) = canonical_hosted_nt_image_path(
        br"\Windows\SYSTEM32\CSRSS.EXE",
        b"windows",
        &mut out,
    )
    .expect("NT mounted File names preserve caller casing");
    assert_eq!(root, HostedImageRoot::System32);
    assert_eq!(&out[..len], br"\SystemRoot\System32\CSRSS.EXE");

    assert!(canonical_hosted_nt_image_path(
        br"\windows\system32extra\csrss.exe",
        b"windows",
        &mut out,
    )
    .is_none());
    assert!(canonical_hosted_nt_image_path(
        br"\other\system32\csrss.exe",
        b"windows",
        &mut out,
    )
    .is_none());
}
