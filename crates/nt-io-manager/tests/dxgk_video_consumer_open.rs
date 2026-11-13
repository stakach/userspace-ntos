//! A real DXGK-owned Video device uses the ordinary named File and consumer
//! projection lifecycle. Closing IoGetDeviceObjectPointer's temporary handle
//! must leave its exact File pointer and Device owner live.

use nt_io_manager::{
    consumer_file_projection::ConsumerFileProjection, CreateOptions, DeviceCharacteristics,
    DeviceFlags, DeviceType, IoManager, MockDriverBackend, MockObjectPort, ShareAccess,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

#[test]
fn dxgk_named_device_pointer_survives_temporary_handle_close_with_exact_owner() {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let dxgk = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\DxgKrnl").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let other = io
        .create_driver(
            &NtPath::parse_str(r"\Driver\Other").unwrap(),
            Box::new(MockDriverBackend::new()),
        )
        .unwrap();
    let name = NtPath::parse_str(r"\Device\Video0").unwrap();
    let video = io
        .create_device(
            dxgk,
            Some(&name),
            DeviceType(0x23),
            DeviceCharacteristics::DEVICE_SECURE_OPEN,
            DeviceFlags::BUFFERED_IO,
            8,
        )
        .unwrap();
    io.create_device(
        other,
        Some(&NtPath::parse_str(r"\Device\Video1").unwrap()),
        DeviceType(0x23),
        DeviceCharacteristics::empty(),
        DeviceFlags::empty(),
        0,
    )
    .unwrap();

    let handle = io
        .open(
            client,
            &name,
            AccessMask::GENERIC_READ,
            ShareAccess::empty(),
            CreateOptions::NON_DIRECTORY_FILE,
            1,
        )
        .unwrap();
    let (file, opened_device, object) = io
        .reference_open_file_details(client, handle, AccessMask::empty())
        .unwrap();
    assert_eq!(opened_device, video);
    assert_eq!(io.device(video).unwrap().driver_id, dxgk);
    assert_eq!(object, io.file(file).unwrap().object_id);

    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x4000, video).unwrap();
    let device_registration = io.register_hosted_device_pointer(domain, 0x4000).unwrap();
    let identity = io.bind_hosted_file_identity(domain, 0x5000, file).unwrap();
    let mut projection = ConsumerFileProjection::new(&mut io, identity, device_registration).unwrap();
    assert_eq!(projection.reference_by_handle(&mut io, identity), Ok(0x5000));
    assert_eq!(projection.related_device_address(&io), Ok(0x4000));

    io.close(client, handle).unwrap();
    projection.handle_closed(identity).unwrap();
    io.pump();
    assert!(io.file(file).is_some(), "the consumer pointer retains its exact File");
    assert_eq!(projection.reference_by_pointer(&mut io, identity), Ok(0x5000));
    let foreign_domain = io.register_hosted_domain();
    assert_eq!(
        io.hosted_file_identity_at(foreign_domain, file, 0x5000),
        Ok(None),
        "same numeric address in another domain has no authority"
    );

    projection.dereference(&mut io, identity).unwrap();
    projection.dereference(&mut io, identity).unwrap();
    assert_eq!(projection.reference_by_pointer(&mut io, identity), Err(NtStatus::INVALID_HANDLE));
    projection.retire(&mut io).unwrap();
    io.unregister_hosted_device_pointer(device_registration).unwrap();
    io.pump();
    assert!(io.file(file).is_none());
}
