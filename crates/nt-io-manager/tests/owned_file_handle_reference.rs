//! condrv references its own console Files by handle (IOCTL 0x5000d4 carries the target handle).
//! Boot 44914465319: every such reference failed with STATUS_OBJECT_NAME_COLLISION because a
//! consumer projection tried to bind a second FILE_OBJECT for a File the domain already owns, so
//! cmd.exe's console I/O failed and cmd (then conhost) exited.

use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend,
    MockObjectPort, ShareAccess,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, NtPath};

#[test]
fn the_owning_domain_finds_its_own_file_object_for_a_handle() {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let condrv = io
        .create_driver(&NtPath::parse_str(r"\Driver\condrv").unwrap(), Box::new(MockDriverBackend::new()))
        .unwrap();
    let name = NtPath::parse_str(r"\Device\ConDrv").unwrap();
    io.create_device(condrv, Some(&name), DeviceType(0x50), DeviceCharacteristics::empty(), DeviceFlags::BUFFERED_IO, 1)
        .unwrap();
    let handle = io
        .open(client, &name, AccessMask::GENERIC_READ, ShareAccess::empty(), CreateOptions::NON_DIRECTORY_FILE, 1)
        .unwrap();
    let (file, _, _) = io.reference_open_file_details(client, handle, AccessMask::empty()).unwrap();

    let owner = io.register_hosted_domain();
    io.bind_hosted_file_identity(owner, 0x5000, file).unwrap();
    // A second projection of the same File in that domain collides; the owner's object is the answer.
    assert_eq!(io.bind_hosted_file_identity(owner, 0x6000, file), Err(NtStatus::OBJECT_NAME_COLLISION));
    assert_eq!(io.owned_hosted_file_address(owner, file), Ok(Some(0x5000)));

    let consumer = io.register_hosted_domain();
    assert_eq!(io.owned_hosted_file_address(consumer, file), Ok(None));
}
