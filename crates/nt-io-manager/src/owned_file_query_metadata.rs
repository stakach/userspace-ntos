//! Canonical metadata for a File whose lifetime is already owned by the caller.

use nt_io_abi::{DeviceId, FileId};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{CreateOptions, FileState, IoManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedFileQueryMetadata {
    pub create_options: CreateOptions,
    pub alignment_requirement: u32,
}

impl<P> IoManager<P> {
    /// The caller must hold a canonical capture reference or an adopted File Busy/reference
    /// owner. This reads the owned body, not a fresh handle, so CLEANUP does not invalidate it.
    /// Metadata remains live: alignment follows current attachment topology and create options
    /// are read from the canonical File rather than snapshotted into the capture token.
    pub fn owned_file_query_metadata(
        &self,
        client: ClientId,
        file: FileId,
        expected_device: DeviceId,
    ) -> Result<OwnedFileQueryMetadata, NtStatus> {
        let record = self.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        if expected_device == DeviceId::NULL
            || record.client_id != client
            || record.device_id != expected_device
        {
            return Err(NtStatus::INVALID_HANDLE);
        }
        if record.close_dispatched || record.state == FileState::Closed {
            return Err(NtStatus::FILE_CLOSED);
        }
        if matches!(
            record.state,
            FileState::Allocated | FileState::CreateIrpDispatched
        ) {
            return Err(NtStatus::INVALID_HANDLE);
        }
        Ok(OwnedFileQueryMetadata {
            create_options: record.create_options,
            alignment_requirement: self.file_alignment_requirement(file)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_io_capture::FileIoCaptureTable;
    use crate::{
        DeviceCharacteristics, DeviceFlags, DeviceType, MockDriverBackend, MockObjectPort,
        ShareAccess,
    };
    use alloc::boxed::Box;
    use nt_types::{AccessMask, HandleValue, NtPath};

    struct Fixture {
        io: IoManager<MockObjectPort>,
        client: ClientId,
        handle: HandleValue,
        file: FileId,
        device: DeviceId,
    }

    impl Fixture {
        fn new(options: CreateOptions) -> Self {
            let mut io = IoManager::new(MockObjectPort::new());
            let client = io.register_client();
            let driver = io
                .create_driver(
                    &NtPath::parse_str(r"\Driver\OwnedMetadata").unwrap(),
                    Box::new(MockDriverBackend::new()),
                )
                .unwrap();
            let path = NtPath::parse_str(r"\Device\OwnedMetadata").unwrap();
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
                    AccessMask::GENERIC_READ,
                    ShareAccess::empty(),
                    options,
                    0,
                )
                .unwrap();
            let file = io
                .reference_open_file(client, handle, AccessMask::empty())
                .unwrap()
                .0;
            Self {
                io,
                client,
                handle,
                file,
                device,
            }
        }

        fn query(&self) -> Result<OwnedFileQueryMetadata, NtStatus> {
            self.io
                .owned_file_query_metadata(self.client, self.file, self.device)
        }
    }

    #[test]
    fn returns_every_canonical_create_option_bit_without_mode_reduction() {
        let options = CreateOptions::WRITE_THROUGH
            | CreateOptions::SEQUENTIAL_ONLY
            | CreateOptions::NO_INTERMEDIATE_BUFFERING
            | CreateOptions::SYNCHRONOUS_IO_NONALERT
            | CreateOptions::NON_DIRECTORY_FILE
            | CreateOptions::OPEN_FOR_BACKUP_INTENT;
        let mut f = Fixture::new(options);
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        assert_eq!(f.query().unwrap().create_options, options);
        let updated = CreateOptions::from_bits_retain(options.bits() | 0x8000_0000);
        f.io.file_mut(f.file).unwrap().create_options = updated;
        assert_eq!(f.query().unwrap().create_options, updated);
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn resolves_current_attached_alignment_without_changing_authenticated_route() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
        assert_eq!(f.query().unwrap().alignment_requirement, 0x1ff);
        let driver =
            f.io.create_driver(
                &NtPath::parse_str(r"\Driver\OwnedMetadataFilter").unwrap(),
                Box::new(MockDriverBackend::new()),
            )
            .unwrap();
        let top =
            f.io.create_device(
                driver,
                None,
                DeviceType::UNKNOWN,
                DeviceCharacteristics::empty(),
                DeviceFlags::BUFFERED_IO,
                0,
            )
            .unwrap();
        f.io.device_mut(top).unwrap().alignment_requirement = 0xfff;
        f.io.attach_device_to_stack(top, f.device).unwrap();
        assert_eq!(f.query().unwrap().alignment_requirement, 0xfff);
        assert_eq!(
            f.io.owned_file_query_metadata(f.client, f.file, top),
            Err(NtStatus::INVALID_HANDLE),
        );
        f.io.detach_device_from_stack(top).unwrap();
        assert_eq!(f.query().unwrap().alignment_requirement, 0x1ff);
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn rejects_wrong_client_route_and_file_identity() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        let other_client = f.io.register_client();
        assert_eq!(
            f.io.owned_file_query_metadata(other_client, f.file, f.device),
            Err(NtStatus::INVALID_HANDLE),
        );
        assert_eq!(
            f.io.owned_file_query_metadata(f.client, f.file, DeviceId::NULL),
            Err(NtStatus::INVALID_HANDLE),
        );
        assert_eq!(
            f.io.owned_file_query_metadata(f.client, FileId::NULL, f.device),
            Err(NtStatus::INVALID_HANDLE),
        );
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn rejects_precreate_closed_and_entered_close_states() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        for state in [FileState::Allocated, FileState::CreateIrpDispatched] {
            f.io.file_mut(f.file).unwrap().state = state;
            assert_eq!(f.query(), Err(NtStatus::INVALID_HANDLE));
        }
        f.io.file_mut(f.file).unwrap().state = FileState::Closed;
        assert_eq!(f.query(), Err(NtStatus::FILE_CLOSED));
        f.io.file_mut(f.file).unwrap().state = FileState::Open;
        f.io.file_mut(f.file).unwrap().close_dispatched = true;
        assert_eq!(f.query(), Err(NtStatus::FILE_CLOSED));
        f.io.file_mut(f.file).unwrap().close_dispatched = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn capture_keeps_metadata_readable_after_real_cleanup_until_retirement() {
        let options = CreateOptions::WRITE_THROUGH | CreateOptions::SEQUENTIAL_ONLY;
        let mut f = Fixture::new(options);
        let mut captures = FileIoCaptureTable::new();
        let mut capture = captures.capture(&mut f.io, f.file, f.device, 1).unwrap();
        f.io.close(f.client, f.handle).unwrap();
        assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
        assert!(f.io.file(f.file).unwrap().cleanup_dispatched);
        assert_eq!(f.io.file_reference_count(f.file), 1);
        assert_eq!(f.query().unwrap().create_options, options);
        f.io.pump();
        assert_eq!(f.query().unwrap().create_options, options);
        captures.retire(&mut capture).unwrap();
        captures
            .release_retired(&mut f.io, capture.identity())
            .unwrap();
        f.io.pump();
        assert!(f.io.file(f.file).is_none());
        assert_eq!(f.query(), Err(NtStatus::INVALID_HANDLE));
    }

    #[test]
    fn deleted_topology_is_an_error_not_zero_alignment() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.device_mut(f.device).unwrap().delete_pending = true;
        assert_eq!(f.query(), Err(NtStatus::DELETE_PENDING));
        f.io.device_mut(f.device).unwrap().delete_pending = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }
}
