//! Real filesystem/offset-policy composition, not an executable native admission test.

use nt_fs::*;
use nt_io_manager::{
    resolve_regular_file_read_offset, resolve_regular_file_write_offset, ResolvedFileOffset,
    FILE_USE_FILE_POINTER_POSITION, FILE_WRITE_TO_END_OF_FILE,
};

fn fixture(synchronous: bool) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    assert!(fs.provision_file(r"\??\C:\Temp\transfer", b"abcdef"));
    let file = fs.zw_create_file(
        r"\??\C:\Temp\transfer",
        FILE_READ_DATA | FILE_WRITE_DATA | if synchronous { SYNCHRONIZE } else { 0 },
        0,
        0,
        FILE_OPEN,
        if synchronous {
            FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            0
        },
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    (fs, file.handle)
}

fn read_completed(
    fs: &mut FileSystem,
    file: u64,
    offset: ResolvedFileOffset,
    synchronous: bool,
    output: &mut [u8],
) -> (u32, usize) {
    let result = fs.read_backing_into(file, offset.value(), output);
    let position = offset
        .completion_position(synchronous, output.len(), result.0, result.1)
        .unwrap();
    if result.0 == STATUS_SUCCESS || result.1 != 0 || position.is_some() {
        assert_eq!(fs.complete_read(file, result.1, position), STATUS_SUCCESS);
    }
    result
}

fn write_completed(
    fs: &mut FileSystem,
    file: u64,
    offset: ResolvedFileOffset,
    synchronous: bool,
    input: &[u8],
) -> (u32, usize) {
    let result = fs.zw_write_file(file, Some(offset.value()), input);
    let position = offset
        .completion_position(synchronous, input.len(), result.0, result.1)
        .unwrap();
    assert_eq!(fs.complete_file_position(file, position), STATUS_SUCCESS);
    result
}

#[test]
fn synchronous_explicit_and_current_reads_publish_actual_short_transfer_position() {
    let (mut fs, file) = fixture(true);
    assert_eq!(fs.complete_file_position(file, Some(1)), STATUS_SUCCESS);
    let offset = resolve_regular_file_read_offset(Some(3), true, 1).unwrap();
    let mut output = [0xcc; 8];
    assert_eq!(
        read_completed(&mut fs, file, offset, true, &mut output),
        (STATUS_SUCCESS, 3)
    );
    assert_eq!(&output[..3], b"def");
    assert_eq!(&output[3..], &[0xcc; 5]);
    assert_eq!(fs.current_offset(file), Some(6));

    assert_eq!(fs.complete_file_position(file, Some(1)), STATUS_SUCCESS);
    for supplied in [None, Some(FILE_USE_FILE_POINTER_POSITION)] {
        let current = fs.current_offset(file).unwrap();
        let offset = resolve_regular_file_read_offset(supplied, true, current).unwrap();
        let mut byte = [0];
        assert_eq!(
            read_completed(&mut fs, file, offset, true, &mut byte),
            (STATUS_SUCCESS, 1)
        );
        assert_eq!(byte[0], b"abcdef"[current as usize]);
        assert_eq!(fs.current_offset(file), Some(current + 1));
    }
}

#[test]
fn synchronous_writes_use_explicit_current_and_end_offsets() {
    let (mut fs, file) = fixture(true);
    for (supplied, expected_position, bytes) in [
        (Some(1), 2, &b"X"[..]),
        (Some(FILE_USE_FILE_POINTER_POSITION), 3, &b"Y"[..]),
        (Some(FILE_WRITE_TO_END_OF_FILE), 8, &b"ZZ"[..]),
    ] {
        let info = fs.query_file_object_information(file).unwrap();
        let offset = resolve_regular_file_write_offset(
            supplied,
            true,
            info.current_offset,
            info.metadata.end_of_file,
            false,
        )
        .unwrap();
        assert_eq!(
            write_completed(&mut fs, file, offset, true, bytes),
            (STATUS_SUCCESS, bytes.len())
        );
        assert_eq!(fs.current_offset(file), Some(expected_position));
    }
    assert_eq!(
        fs.file_bytes(r"\??\C:\Temp\transfer"),
        Some(&b"aXYdefZZ"[..])
    );
}

#[test]
fn asynchronous_transfers_leave_position_unchanged() {
    let (mut fs, file) = fixture(false);
    assert_eq!(fs.complete_file_position(file, Some(4)), STATUS_SUCCESS);
    let read = resolve_regular_file_read_offset(Some(1), false, 4).unwrap();
    let mut output = [0; 2];
    assert_eq!(
        read_completed(&mut fs, file, read, false, &mut output),
        (STATUS_SUCCESS, 2)
    );
    assert_eq!(output, *b"bc");
    let write = resolve_regular_file_write_offset(Some(0), false, 4, 6, false).unwrap();
    assert_eq!(
        write_completed(&mut fs, file, write, false, b"X"),
        (STATUS_SUCCESS, 1)
    );
    assert_eq!(fs.current_offset(file), Some(4));
}

#[test]
fn zero_length_and_maximum_offset_eof_do_not_require_requested_end_to_fit() {
    let (mut fs, file) = fixture(true);
    assert_eq!(fs.complete_file_position(file, Some(2)), STATUS_SUCCESS);
    let metadata = fs.zw_query_metadata(file).unwrap();
    fs.set_current_time_100ns(100);
    assert_eq!(
        read_completed(
            &mut fs,
            file,
            ResolvedFileOffset::Absolute(u64::MAX),
            true,
            &mut []
        ),
        (STATUS_SUCCESS, 0)
    );
    assert_eq!(
        write_completed(
            &mut fs,
            file,
            ResolvedFileOffset::Absolute(u64::MAX),
            true,
            &[]
        ),
        (STATUS_SUCCESS, 0)
    );
    assert_eq!(fs.current_offset(file), Some(2));
    assert_eq!(fs.zw_query_metadata(file).unwrap(), metadata);

    for current in [6, u64::MAX] {
        assert_eq!(
            fs.complete_file_position(file, Some(current)),
            STATUS_SUCCESS
        );
        let offset = resolve_regular_file_read_offset(None, true, current).unwrap();
        let mut output = [0xcc; 8];
        assert_eq!(
            read_completed(&mut fs, file, offset, true, &mut output),
            (STATUS_END_OF_FILE, 0)
        );
        assert_eq!(output, [0xcc; 8]);
        assert_eq!(fs.current_offset(file), Some(current));
        assert_eq!(fs.zw_query_metadata(file).unwrap(), metadata);
    }
}

#[test]
fn backing_fragments_publish_access_metadata_and_notification_only_at_logical_completion() {
    let (mut fs, file) = fixture(true);
    let directory = fs.zw_create_file(
        r"\??\C:\Temp",
        FILE_LIST_DIRECTORY,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(directory.status, STATUS_SUCCESS);
    let notify = fs
        .zw_notify_change_directory_file(
            directory.handle,
            FILE_NOTIFY_CHANGE_LAST_ACCESS,
            false,
            256,
            42,
        )
        .unwrap();
    let before = fs.zw_query_metadata(file).unwrap();
    fs.set_current_time_100ns(123);
    let mut output = [0; 6];
    assert_eq!(
        fs.read_backing_into(file, 0, &mut output[..2]),
        (STATUS_SUCCESS, 2)
    );
    assert_eq!(
        fs.read_backing_into(file, 2, &mut output[2..]),
        (STATUS_SUCCESS, 4)
    );
    assert_eq!(output, *b"abcdef");
    assert_eq!(fs.zw_query_metadata(file).unwrap(), before);
    assert_eq!(fs.current_offset(file), Some(0));
    assert!(fs.pop_directory_notify_completion().is_none());

    let position = ResolvedFileOffset::Absolute(0)
        .completion_position(true, 6, STATUS_SUCCESS, 6)
        .unwrap();
    assert_eq!(fs.complete_read(file, 6, position), STATUS_SUCCESS);
    assert_eq!(fs.current_offset(file), Some(6));
    assert_eq!(fs.zw_query_metadata(file).unwrap().last_access_time, 123);
    let completion = fs.pop_directory_notify_completion().unwrap();
    assert_eq!(completion.id, notify);
    assert_eq!(completion.context, 42);
    assert_eq!(completion.status, STATUS_SUCCESS);
    assert!(fs.pop_directory_notify_completion().is_none());
}

#[test]
fn rejected_write_preserves_position_bytes_and_metadata() {
    let (mut fs, file) = fixture(true);
    assert_eq!(fs.complete_file_position(file, Some(3)), STATUS_SUCCESS);
    let metadata = fs.zw_query_metadata(file).unwrap();
    fs.set_current_time_100ns(200);
    assert_eq!(
        write_completed(
            &mut fs,
            file,
            ResolvedFileOffset::Absolute(u64::MAX),
            true,
            b"X"
        ),
        (STATUS_INSUFFICIENT_RESOURCES, 0)
    );
    assert_eq!(fs.current_offset(file), Some(3));
    assert_eq!(fs.zw_query_metadata(file).unwrap(), metadata);
    assert_eq!(fs.file_bytes(r"\??\C:\Temp\transfer"), Some(&b"abcdef"[..]));
}

#[test]
fn cleanup_preserves_transfer_and_completion_until_last_io_reference_release() {
    let (mut fs, file) = fixture(true);
    fs.zw_retain_io_reference(file).unwrap();
    assert_eq!(fs.zw_close(file), STATUS_SUCCESS);
    let mut output = [0; 2];
    assert_eq!(
        read_completed(
            &mut fs,
            file,
            ResolvedFileOffset::Absolute(1),
            true,
            &mut output
        ),
        (STATUS_SUCCESS, 2)
    );
    assert_eq!(output, *b"bc");
    assert_eq!(
        write_completed(&mut fs, file, ResolvedFileOffset::Current(3), true, b"X"),
        (STATUS_SUCCESS, 1)
    );
    assert_eq!(fs.current_offset(file), Some(4));
    fs.zw_release_io_reference(file).unwrap();
    assert_eq!(
        fs.query_file_object_information(file),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(fs.file_bytes(r"\??\C:\Temp\transfer"), Some(&b"abcXef"[..]));
}
