//! Check the emitted win32k import route against the same generic owner path
//! exercised by the I/O Manager lifetime regression.

#[test]
fn win32k_device_pointer_uses_canonical_file_open_reference_and_close() {
    let import = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let start = import.find("fn s_io_get_device_object_pointer(").unwrap();
    let end = import[start..].find("/// `PDEVICE_OBJECT IoGetRelatedDeviceObject").unwrap() + start;
    let body = &import[start..end];
    let opened = body.find("file_open::open(").expect("canonical named File open");
    let referenced = body.find("s_ob_reference_object_by_handle(").expect("exact typed handle reference");
    let closed = body.find("s_zw_close(").expect("temporary handle close");
    assert!(opened < referenced && referenced < closed);
    assert!(body.contains("W32_FILE_OBJECT_RELATED_DEVICE"), "related top comes from the exact File owner");
    assert!(!body.contains("W32_FILE_OBJECT_OPEN_DEVICE"));
    let broker = include_str!("../../../components/ntos-executive/src/provider_file_objects.rs");
    assert!(!broker.contains("match crate::video_device::video_get_device_object_pointer(&name"));
}
