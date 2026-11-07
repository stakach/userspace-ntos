extern crate alloc;

#[path = "../../../components/ntos-executive/src/mounted_directory_source.rs"]
mod mounted_directory_source;

use mounted_directory_source::capture_directory_source;

#[test]
fn overlay_on_installed_directory_keeps_lower_path_without_directory_open() {
    let opened: Vec<u16> = "Windows\\ServiceProfiles\\NetworkService"
        .encode_utf16()
        .collect();
    let source = capture_directory_source(
        nt_fs::LayeredOpenSource::Overlay { file_id: 0x1234 },
        &opened,
        None,
    )
    .expect("overlay CREATE retains its own lower path, without an installed DirectoryOpen");
    assert_eq!(source.relative, b"windows\\serviceprofiles\\networkservice");
    assert_eq!(source.overlay_file, Some(0x1234));
}

#[test]
fn installed_directory_uses_its_exact_open_description() {
    let source = capture_directory_source(
        nt_fs::LayeredOpenSource::Installed {
            first_cluster: 7,
            metadata: nt_fs::FileMetadata::default(),
            alternate_name: nt_fs::FatShortName::EMPTY,
        },
        &"ignored".encode_utf16().collect::<Vec<_>>(),
        Some(b"windows\\serviceprofiles"),
    )
    .expect("installed directory has a retained DirectoryOpen");
    assert_eq!(source.relative, b"windows\\serviceprofiles");
    assert_eq!(source.overlay_file, None);
}
