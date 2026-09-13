//! Canonical mode and completion policy commit together under an already-owned File.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::{
    CreateOptions, DeviceCharacteristics, DeviceFlags, DeviceId, DeviceType, FileId, IoManager,
    MockDriverBackend, MockObjectPort, ShareAccess,
};
use nt_status::NtStatus;
use nt_types::{AccessMask, ClientId, HandleValue, NtPath};

const ORIGINAL: CreateOptions =
    CreateOptions::WRITE_THROUGH.union(CreateOptions::SYNCHRONOUS_IO_NONALERT);
const CHANGED: u32 = nt_fs::FILE_SEQUENTIAL_ONLY | nt_fs::FILE_SYNCHRONOUS_IO_ALERT;

struct Fixture {
    io: IoManager<MockObjectPort>,
    policy: FileCompletionTable<4>,
    client: ClientId,
    handle: HandleValue,
    file: FileId,
    device: DeviceId,
}

impl Fixture {
    fn new() -> Self {
        let mut io = IoManager::new(MockObjectPort::new());
        let client = io.register_client();
        let driver = io
            .create_driver(
                &NtPath::parse_str(r"\Driver\ModeCommit").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let path = NtPath::parse_str(r"\Device\ModeCommit").unwrap();
        let device = io
            .create_device(
                driver,
                Some(&path),
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        let handle = io
            .open(
                client,
                &path,
                AccessMask::GENERIC_READ | AccessMask::SYNCHRONIZE,
                ShareAccess::READ,
                ORIGINAL,
                0,
            )
            .unwrap();
        let file = io
            .reference_open_file_details(client, handle, AccessMask::empty())
            .unwrap()
            .0;
        let mut policy = FileCompletionTable::new();
        policy
            .insert_file_with_mode(
                file.raw(),
                device.raw(),
                FileIoMode::SynchronousNonAlertable,
            )
            .unwrap();
        assert_eq!(
            policy.acquire_file_io(file.raw(), 1),
            Ok(FileIoAcquireResult::Acquired)
        );
        Self {
            io,
            policy,
            client,
            handle,
            file,
            device,
        }
    }

    fn commit(&mut self, device: DeviceId, requested: u32) -> Result<(), u32> {
        self.policy.update_io_mode_with(
            self.file.raw(),
            self.device.raw(),
            1,
            FileIoMode::SynchronousNonAlertable,
            FileIoMode::SynchronousAlertable,
            || {
                self.io
                    .set_owned_file_mode(self.client, self.file, device, requested)
                    .map(|_| ())
                    .map_err(|status| status.raw() as u32)
            },
        )
    }

    fn query_mode(&self, class: u32) -> u32 {
        let mut output = [0xa5; 104];
        assert_eq!(
            self.io.encode_owned_file_query_information(
                self.client,
                self.file,
                self.device,
                0x81,
                class,
                &mut output,
            ),
            Ok(if class == nt_fs::FILE_ALL_INFORMATION {
                12
            } else {
                4
            })
        );
        let offset = if class == nt_fs::FILE_ALL_INFORMATION {
            88
        } else {
            0
        };
        u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap())
    }

    fn finish(mut self) {
        self.policy.release_io(self.file.raw(), 1).unwrap();
        self.policy.release_file(self.file.raw()).unwrap();
        assert!(
            self.policy
                .release_handle(self.file.raw())
                .unwrap()
                .cleanup_required
        );
        assert_eq!(
            self.policy.begin_cleanup(self.file.raw()),
            Ok(FileIoAcquireResult::Acquired)
        );
        assert!(self
            .policy
            .mark_cleanup_lifecycle_started(self.file.raw())
            .unwrap());
        self.io.close(self.client, self.handle).unwrap();
        self.io.pump();
        assert!(self.io.file(self.file).is_none());
        self.policy.release_cleanup_io(self.file.raw()).unwrap();
        assert!(
            self.policy
                .release_cleanup_reference(self.file.raw())
                .unwrap()
                .close_required
        );
        assert_eq!(
            self.policy.io_mode(self.file.raw()),
            Err(nt_io_completion::STATUS_INVALID_HANDLE)
        );
    }
}

#[test]
fn committed_mode_is_live_for_queries_and_new_waits_but_not_captured_waits() {
    let mut f = Fixture::new();
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    assert_eq!(
        f.policy
            .acquire_file_io_with_mode(f.file.raw(), 2, FileIoMode::SynchronousNonAlertable,),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    f.policy.set_signaled(f.file.raw(), false).unwrap();
    f.commit(f.device, CHANGED).unwrap();
    assert_eq!(f.query_mode(nt_fs::FILE_MODE_INFORMATION), CHANGED);
    assert_eq!(f.query_mode(nt_fs::FILE_ALL_INFORMATION), CHANGED);
    assert_eq!(f.io.project_file(f.file).unwrap().flags, 0x26);
    assert_eq!(f.io.file(f.file).unwrap().create_options, ORIGINAL);
    assert_eq!(f.policy.is_signaled(f.file.raw()), Ok(false));
    assert_eq!(
        f.policy.io_mode(f.file.raw()),
        Ok(FileIoMode::SynchronousAlertable)
    );
    assert_eq!(
        f.policy.acquire_file_io(f.file.raw(), 3),
        Ok(FileIoAcquireResult::Contended { alertable: true })
    );
    // This operation captured its policy before reentrant input copying allowed the mode change.
    assert_eq!(
        f.policy
            .acquire_file_io_with_mode(f.file.raw(), 4, FileIoMode::SynchronousNonAlertable,),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(f.policy.io_waiter_count(f.file.raw()), Ok(3));
    for _ in 0..3 {
        f.policy.cancel_io_waiter(f.file.raw()).unwrap();
        f.policy.release_file(f.file.raw()).unwrap();
    }
    f.io.release_file_reference(&mut owner).unwrap();
    f.finish();
}

#[test]
fn canonical_failure_leaves_completion_policy_and_file_mode_unchanged() {
    let mut f = Fixture::new();
    let mut owner = f.io.retain_file_reference(f.file).unwrap();
    for (device, requested, expected) in [
        (DeviceId::NULL, CHANGED, NtStatus::INVALID_HANDLE),
        (
            f.device,
            CHANGED | nt_fs::FILE_SYNCHRONOUS_IO_NONALERT,
            NtStatus::INVALID_PARAMETER,
        ),
        (f.device, 0, NtStatus::INVALID_PARAMETER),
    ] {
        assert_eq!(f.commit(device, requested), Err(expected.raw() as u32));
        assert_eq!(f.query_mode(nt_fs::FILE_MODE_INFORMATION), ORIGINAL.bits());
        assert_eq!(
            f.policy.io_mode(f.file.raw()),
            Ok(FileIoMode::SynchronousNonAlertable)
        );
    }
    assert_eq!(
        f.policy.update_io_mode_with(
            f.file.raw(),
            f.device.raw(),
            2,
            FileIoMode::SynchronousNonAlertable,
            FileIoMode::SynchronousAlertable,
            || panic!("wrong Busy owner reached canonical commit"),
        ),
        Err(nt_io_completion::STATUS_INVALID_PARAMETER)
    );
    assert_eq!(f.query_mode(nt_fs::FILE_MODE_INFORMATION), ORIGINAL.bits());
    f.io.release_file_reference(&mut owner).unwrap();
    f.finish();
}
