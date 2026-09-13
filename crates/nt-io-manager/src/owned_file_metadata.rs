//! Canonical body and query metadata for a File whose lifetime is already owned by the caller.

use nt_io_abi::{DeviceId, FileId};
use nt_status::NtStatus;
use nt_types::ClientId;

use crate::{CreateOptions, FileState, IoManager};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnedFileMetadata {
    pub device_id: DeviceId,
    pub create_options: CreateOptions,
    pub opened_case_sensitive: bool,
}

impl<P> IoManager<P> {
    /// Read an already-owned File body without resolving device attachment topology.
    /// The caller holds a canonical reference, such as a capture or adopted Busy owner.
    pub fn owned_file_metadata(
        &self,
        client: ClientId,
        file: FileId,
    ) -> Result<OwnedFileMetadata, NtStatus> {
        self.owned_file_metadata_for(client, file, None)
    }

    /// The caller must hold a canonical capture reference or an adopted File Busy/reference
    /// owner. This reads the owned body, not a fresh handle, so CLEANUP does not invalidate it.
    /// Access comes from the retained handle grant; mode reads the live File body. Only
    /// Alignment and All queries resolve attachment topology. All seeds the I/O manager fields
    /// for a subsequent provider dispatch; its byte count is not a contiguous transfer extent.
    pub fn encode_owned_file_query_information(
        &self,
        client: ClientId,
        file: FileId,
        expected_device: DeviceId,
        granted_access: u32,
        information_class: u32,
        output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        if !matches!(
            information_class,
            nt_fs::FILE_ACCESS_INFORMATION
                | nt_fs::FILE_MODE_INFORMATION
                | nt_fs::FILE_ALIGNMENT_INFORMATION
                | nt_fs::FILE_ALL_INFORMATION
        ) {
            return Err(NtStatus(nt_fs::STATUS_INVALID_INFO_CLASS as i32));
        }
        let metadata = self.owned_file_metadata_for(client, file, Some(expected_device))?;
        let mut query = nt_fs::QueryMetadata {
            access_flags: granted_access,
            // Authoritative mutable FO_* mode state remains a separate implementation gap.
            mode: nt_fs::file_mode_from_create_options(metadata.create_options.bits()),
            ..Default::default()
        };
        if matches!(
            information_class,
            nt_fs::FILE_ALIGNMENT_INFORMATION | nt_fs::FILE_ALL_INFORMATION
        ) {
            query.alignment_requirement = self.file_alignment_requirement(file)?;
        }
        if information_class == nt_fs::FILE_ALL_INFORMATION {
            nt_fs::encode_file_all_io_manager_information(query, output)
        } else {
            nt_fs::encode_query_information(information_class, query, output)
        }
        .map_err(|status| NtStatus(status as i32))
    }

    fn owned_file_metadata_for(
        &self,
        client: ClientId,
        file: FileId,
        expected_device: Option<DeviceId>,
    ) -> Result<OwnedFileMetadata, NtStatus> {
        let record = self.file(file).ok_or(NtStatus::INVALID_HANDLE)?;
        if record.client_id != client
            || expected_device
                .is_some_and(|device| device == DeviceId::NULL || record.device_id != device)
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
        Ok(OwnedFileMetadata {
            device_id: record.device_id,
            create_options: record.create_options,
            opened_case_sensitive: record.opened_case_sensitive(),
        })
    }
}

#[cfg(test)]
mod tests {
    mod query_encoding_tests;

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

        fn query(&self) -> Result<u32, NtStatus> {
            self.query_for(
                self.client,
                self.file,
                self.device,
                nt_fs::FILE_ALIGNMENT_INFORMATION,
            )
        }

        fn query_for(
            &self,
            client: ClientId,
            file: FileId,
            device: DeviceId,
            class: u32,
        ) -> Result<u32, NtStatus> {
            let mut output = [0xa5; 4];
            let result = self.io.encode_owned_file_query_information(
                client,
                file,
                device,
                0x81,
                class,
                &mut output,
            );
            match result {
                Ok(length) => {
                    assert_eq!(length, 4);
                    Ok(u32::from_le_bytes(output))
                }
                Err(status) => {
                    assert_eq!(output, [0xa5; 4]);
                    Err(status)
                }
            }
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
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file)
                .unwrap()
                .create_options,
            options
        );
        let updated = CreateOptions::from_bits_retain(options.bits() | 0x8000_0000);
        f.io.file_mut(f.file).unwrap().create_options = updated;
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file)
                .unwrap()
                .create_options,
            updated
        );
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(nt_fs::file_mode_from_create_options(updated.bits()))
        );
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn resolves_current_attached_alignment_without_changing_authenticated_route() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
        assert_eq!(f.query(), Ok(0x1ff));
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
        assert_eq!(f.query(), Ok(0xfff));
        assert_eq!(
            f.query_for(f.client, f.file, top, nt_fs::FILE_ALIGNMENT_INFORMATION),
            Err(NtStatus::INVALID_HANDLE),
        );
        f.io.detach_device_from_stack(top).unwrap();
        assert_eq!(f.query(), Ok(0x1ff));
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn rejects_wrong_client_route_and_file_identity() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        let other_client = f.io.register_client();
        assert_eq!(
            f.query_for(
                other_client,
                f.file,
                f.device,
                nt_fs::FILE_ALIGNMENT_INFORMATION
            ),
            Err(NtStatus::INVALID_HANDLE),
        );
        assert_eq!(
            f.query_for(
                f.client,
                f.file,
                DeviceId::NULL,
                nt_fs::FILE_ALIGNMENT_INFORMATION
            ),
            Err(NtStatus::INVALID_HANDLE),
        );
        assert_eq!(
            f.query_for(
                f.client,
                FileId::NULL,
                f.device,
                nt_fs::FILE_ALIGNMENT_INFORMATION
            ),
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
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(options.bits())
        );
        f.io.pump();
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(options.bits())
        );
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

    #[test]
    fn owned_body_metadata_does_not_require_usable_alignment_topology() {
        let options =
            CreateOptions::from_bits_retain(0x8000_0000) | CreateOptions::NON_DIRECTORY_FILE;
        let mut f = Fixture::new(CreateOptions::NON_DIRECTORY_FILE);
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.file_mut(f.file).unwrap().create_options = options;
        f.io.device_mut(f.device).unwrap().delete_pending = true;
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Ok(OwnedFileMetadata {
                device_id: f.device,
                create_options: options,
                opened_case_sensitive: false,
            })
        );
        assert_eq!(f.query(), Err(NtStatus::DELETE_PENDING));
        f.io.device_mut(f.device).unwrap().delete_pending = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn owned_body_rejects_wrong_identity_precreate_and_entered_close() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        let other_client = f.io.register_client();
        assert_eq!(
            f.io.owned_file_metadata(other_client, f.file),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            f.io.owned_file_metadata(f.client, FileId::NULL),
            Err(NtStatus::INVALID_HANDLE)
        );
        for state in [FileState::Allocated, FileState::CreateIrpDispatched] {
            f.io.file_mut(f.file).unwrap().state = state;
            assert_eq!(
                f.io.owned_file_metadata(f.client, f.file),
                Err(NtStatus::INVALID_HANDLE)
            );
        }
        f.io.file_mut(f.file).unwrap().state = FileState::Closed;
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Err(NtStatus::FILE_CLOSED)
        );
        f.io.file_mut(f.file).unwrap().state = FileState::Open;
        f.io.file_mut(f.file).unwrap().close_dispatched = true;
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Err(NtStatus::FILE_CLOSED)
        );
        f.io.file_mut(f.file).unwrap().close_dispatched = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn query_route_identity_failure_precedes_owned_body_state_failure() {
        let mut f = Fixture::new(CreateOptions::empty());
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        let other_client = f.io.register_client();
        f.io.file_mut(f.file).unwrap().close_dispatched = true;
        assert_eq!(
            f.query_for(
                f.client,
                f.file,
                DeviceId::NULL,
                nt_fs::FILE_ALIGNMENT_INFORMATION
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            f.query_for(
                f.client,
                f.file,
                DeviceId(f.device.raw() + 1),
                nt_fs::FILE_ALIGNMENT_INFORMATION
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            f.io.owned_file_metadata(other_client, f.file),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(f.query(), Err(NtStatus::FILE_CLOSED));
        f.io.file_mut(f.file).unwrap().close_dispatched = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn retained_rename_source_metadata_and_name_survive_real_cleanup() {
        let options = CreateOptions::NON_DIRECTORY_FILE | CreateOptions::WRITE_THROUGH;
        let mut f = Fixture::new(options);
        let mut captures = FileIoCaptureTable::new();
        let mut capture = captures.capture(&mut f.io, f.file, f.device, 1).unwrap();
        f.io.close(f.client, f.handle).unwrap();
        f.io.pump();
        assert!(f.io.file(f.file).unwrap().cleanup_dispatched);
        assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Ok(OwnedFileMetadata {
                device_id: f.device,
                create_options: options,
                opened_case_sensitive: false,
            })
        );
        let absolute = nt_types::UnicodeString::from_str(r"\Device\OwnedMetadata\target\leaf");
        let expected = nt_types::UnicodeString::from_str(r"\target\leaf");
        let mut output = [0u16; 32];
        let length = f
            .io
            .external_file_device_relative_name(f.client, f.file, absolute.as_units(), &mut output)
            .unwrap();
        assert_eq!(&output[..length], expected.as_units());
        captures.retire(&mut capture).unwrap();
        captures
            .release_retired(&mut f.io, capture.identity())
            .unwrap();
        f.io.pump();
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Err(NtStatus::INVALID_HANDLE)
        );
        assert_eq!(
            f.io.external_file_device_relative_name(
                f.client,
                f.file,
                absolute.as_units(),
                &mut output,
            ),
            Err(NtStatus::INVALID_HANDLE)
        );
    }
}
