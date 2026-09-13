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
        self.owned_file_metadata_for(client, file, Some(expected_device))?;
        let mut query = nt_fs::QueryMetadata {
            access_flags: granted_access,
            mode: self
                .file(file)
                .expect("validated owned File")
                .mode_state()
                .query_bits(),
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

    /// Update canonical mode while the caller owns the File reference and its I/O serialization.
    /// Provider mode publication is a separate obligation; this performs no IPC or topology lookup.
    pub fn set_owned_file_mode(
        &mut self,
        client: ClientId,
        file: FileId,
        expected_device: DeviceId,
        requested: u32,
    ) -> Result<crate::FileModeState, NtStatus> {
        self.owned_file_metadata_for(client, file, Some(expected_device))?;
        let record = self.file_mut(file).expect("validated owned File");
        let mode = record.mode_state().transition(requested)?;
        record.set_mode_state(mode);
        Ok(mode)
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
        let updated =
            f.io.set_owned_file_mode(f.client, f.file, f.device, nt_fs::FILE_SYNCHRONOUS_IO_ALERT)
                .unwrap();
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file)
                .unwrap()
                .create_options,
            options
        );
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(updated.query_bits())
        );
        assert_eq!(
            updated.query_bits(),
            nt_fs::FILE_WRITE_THROUGH
                | nt_fs::FILE_NO_INTERMEDIATE_BUFFERING
                | nt_fs::FILE_SYNCHRONOUS_IO_ALERT
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
        let options = CreateOptions::NON_DIRECTORY_FILE | CreateOptions::SEQUENTIAL_ONLY;
        let mut f = Fixture::new(options);
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.device_mut(f.device).unwrap().delete_pending = true;
        assert_eq!(
            f.io.set_owned_file_mode(f.client, f.file, f.device, nt_fs::FILE_WRITE_THROUGH)
                .unwrap()
                .query_bits(),
            nt_fs::FILE_WRITE_THROUGH
        );
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
    fn owned_mode_update_changes_class16_and_all_without_rewriting_create_options() {
        let options = CreateOptions::SYNCHRONOUS_IO_NONALERT
            | CreateOptions::WRITE_THROUGH
            | CreateOptions::NON_DIRECTORY_FILE;
        let mut f = Fixture::new(options);
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        f.io.device_mut(f.device).unwrap().alignment_requirement = 0x1ff;
        let requested = nt_fs::FILE_SYNCHRONOUS_IO_ALERT | nt_fs::FILE_SEQUENTIAL_ONLY;
        assert_eq!(
            f.io.set_owned_file_mode(f.client, f.file, f.device, requested)
                .unwrap()
                .query_bits(),
            requested
        );
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(requested)
        );
        let mut output = [0xa5; 104];
        assert_eq!(
            f.io.encode_owned_file_query_information(
                f.client,
                f.file,
                f.device,
                0x1234,
                nt_fs::FILE_ALL_INFORMATION,
                &mut output,
            ),
            Ok(12)
        );
        assert_eq!(&output[76..80], &0x1234u32.to_le_bytes());
        assert_eq!(&output[88..92], &requested.to_le_bytes());
        assert_eq!(&output[92..96], &0x1ffu32.to_le_bytes());
        assert_eq!(&output[96..], &[0xa5; 8]);
        assert_eq!(f.io.file(f.file).unwrap().create_options, options);
        assert_eq!(f.io.irp_count(), 0);
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn owned_mode_update_survives_real_cleanup_and_missing_device_topology() {
        let options = CreateOptions::WRITE_THROUGH | CreateOptions::DELETE_ON_CLOSE;
        let mut f = Fixture::new(options);
        let mut captures = FileIoCaptureTable::new();
        let mut capture = captures.capture(&mut f.io, f.file, f.device, 1).unwrap();
        f.io.close(f.client, f.handle).unwrap();
        f.io.pump();
        assert_eq!(f.io.file(f.file).unwrap().state, FileState::ClosePending);
        f.io.device_mut(f.device).unwrap().top_of_stack = DeviceId::NULL;
        let requested = nt_fs::FILE_SEQUENTIAL_ONLY;
        let mode =
            f.io.set_owned_file_mode(f.client, f.file, f.device, requested)
                .unwrap();
        assert_eq!(mode.query_bits(), requested | nt_fs::FILE_DELETE_ON_CLOSE);
        assert_eq!(
            f.query_for(f.client, f.file, f.device, nt_fs::FILE_MODE_INFORMATION),
            Ok(mode.query_bits())
        );
        assert_eq!(f.io.file(f.file).unwrap().create_options, options);
        assert_eq!(f.io.file_reference_count(f.file), 1);
        f.io.device_mut(f.device).unwrap().top_of_stack = f.device;
        captures.retire(&mut capture).unwrap();
        captures
            .release_retired(&mut f.io, capture.identity())
            .unwrap();
        f.io.pump();
        assert!(f.io.file(f.file).is_none());
        assert_eq!(
            f.io.set_owned_file_mode(f.client, f.file, f.device, 0),
            Err(NtStatus::INVALID_HANDLE)
        );
    }

    #[test]
    fn owned_mode_update_errors_leave_mode_original_options_and_references_unchanged() {
        let options = CreateOptions::SYNCHRONOUS_IO_NONALERT | CreateOptions::WRITE_THROUGH;
        let mut f = Fixture::new(options);
        let mut owner = f.io.retain_file_reference(f.file).unwrap();
        let original = f.io.file(f.file).unwrap().mode_state();
        let other_client = f.io.register_client();
        for (client, file, device, requested, status) in [
            (
                other_client,
                f.file,
                f.device,
                0x10,
                NtStatus::INVALID_HANDLE,
            ),
            (
                f.client,
                FileId::NULL,
                f.device,
                0x10,
                NtStatus::INVALID_HANDLE,
            ),
            (
                f.client,
                f.file,
                DeviceId::NULL,
                0x10,
                NtStatus::INVALID_HANDLE,
            ),
            (
                f.client,
                f.file,
                DeviceId(u64::MAX),
                0x10,
                NtStatus::INVALID_HANDLE,
            ),
            (f.client, f.file, f.device, 0, NtStatus::INVALID_PARAMETER),
            (
                f.client,
                f.file,
                f.device,
                0x30,
                NtStatus::INVALID_PARAMETER,
            ),
            (
                f.client,
                f.file,
                f.device,
                0x1020,
                NtStatus::INVALID_PARAMETER,
            ),
        ] {
            assert_eq!(
                f.io.set_owned_file_mode(client, file, device, requested),
                Err(status)
            );
            assert_eq!(f.io.file(f.file).unwrap().mode_state(), original);
        }
        for (state, status) in [
            (FileState::Allocated, NtStatus::INVALID_HANDLE),
            (FileState::CreateIrpDispatched, NtStatus::INVALID_HANDLE),
            (FileState::Closed, NtStatus::FILE_CLOSED),
        ] {
            f.io.file_mut(f.file).unwrap().state = state;
            assert_eq!(
                f.io.set_owned_file_mode(f.client, f.file, f.device, 0x10),
                Err(status)
            );
            assert_eq!(f.io.file(f.file).unwrap().mode_state(), original);
        }
        f.io.file_mut(f.file).unwrap().state = FileState::Open;
        f.io.file_mut(f.file).unwrap().close_dispatched = true;
        assert_eq!(
            f.io.set_owned_file_mode(f.client, f.file, f.device, 0x10),
            Err(NtStatus::FILE_CLOSED)
        );
        assert_eq!(f.io.file(f.file).unwrap().mode_state(), original);
        assert_eq!(f.io.file(f.file).unwrap().create_options, options);
        assert_eq!(f.io.file_reference_count(f.file), 1);
        assert_eq!(f.io.file(f.file).unwrap().outstanding_irp_refs, 0);
        assert_eq!(f.io.irp_count(), 0);
        f.io.file_mut(f.file).unwrap().close_dispatched = false;
        f.io.release_file_reference(&mut owner).unwrap();
    }

    #[test]
    fn retained_rename_source_metadata_survives_real_cleanup() {
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
        captures.retire(&mut capture).unwrap();
        captures
            .release_retired(&mut f.io, capture.identity())
            .unwrap();
        f.io.pump();
        assert_eq!(
            f.io.owned_file_metadata(f.client, f.file),
            Err(NtStatus::INVALID_HANDLE)
        );
    }
}
