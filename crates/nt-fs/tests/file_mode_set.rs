use nt_fs::*;

const PATH: &str = r"\??\C:\mode.txt";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

fn open(options: u32) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(PATH, b"contents"));
    let file = fs.zw_create_file(PATH, FILE_READ_DATA | DELETE | SYNCHRONIZE, 0, SHARE,
        FILE_OPEN, options | FILE_NON_DIRECTORY_FILE);
    assert_eq!(file.status, STATUS_SUCCESS);
    (fs, file.handle)
}

#[test]
fn local_mode_set_roundtrips_body_and_query_without_changing_an_independent_open() {
    let initial = FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE;
    let (mut fs, file) = open(initial);
    let independent = fs.zw_create_file(PATH, FILE_READ_DATA | DELETE | SYNCHRONIZE, 0, SHARE,
        FILE_OPEN, initial | FILE_NON_DIRECTORY_FILE);
    assert_eq!(independent.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_retain(file), STATUS_SUCCESS);
    let before = fs.query_file_object_information(file).unwrap();
    let requested = FILE_SYNCHRONOUS_IO_ALERT | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY;
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION, &requested.to_le_bytes()),
        STATUS_SUCCESS);
    let expected = requested | FILE_DELETE_ON_CLOSE;
    assert_eq!(fs.file_mode(file), Some(expected));
    let after = fs.query_file_object_information(file).unwrap();
    assert_eq!(after.mode, expected);
    assert_eq!(after.metadata, before.metadata);
    assert_eq!(after.current_offset, before.current_offset);
    assert_eq!(fs.file_mode(independent.handle), Some(initial));
    assert_eq!(fs.zw_close(file), STATUS_SUCCESS);
    assert_eq!(fs.file_mode(file), Some(expected), "the duplicated handle owns the same body");
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION,
        &FILE_SYNCHRONOUS_IO_NONALERT.to_le_bytes()), STATUS_SUCCESS);
    assert_eq!(fs.query_file_object_information(file).unwrap().mode, initial);
}

#[test]
fn local_mode_set_preserves_unbuffered_write_through_and_rejects_invalid_transitions() {
    let initial = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH;
    let (mut fs, file) = open(initial);
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION,
        &FILE_SYNCHRONOUS_IO_ALERT.to_le_bytes()), STATUS_SUCCESS);
    let expected = FILE_SYNCHRONOUS_IO_ALERT | FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH;
    assert_eq!(fs.file_mode(file), Some(expected));
    for requested in [0, FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_SYNCHRONOUS_IO_ALERT | FILE_DELETE_ON_CLOSE,
        FILE_SYNCHRONOUS_IO_ALERT | 0x8000_0000] {
        assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION, &requested.to_le_bytes()),
            STATUS_INVALID_PARAMETER);
        assert_eq!(fs.query_file_object_information(file).unwrap().mode, expected);
    }
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION, &[0; 3]),
        STATUS_INFO_LENGTH_MISMATCH);
    assert_eq!(fs.file_mode(file), Some(expected));
}

#[test]
fn asynchronous_local_mode_set_does_not_convert_to_synchronous_io() {
    let (mut fs, file) = open(0);
    let requested = FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY;
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION, &requested.to_le_bytes()),
        STATUS_SUCCESS);
    assert_eq!(fs.file_mode(file), Some(requested));
    assert_eq!(fs.zw_set_information_file(file, FILE_MODE_INFORMATION,
        &FILE_SYNCHRONOUS_IO_NONALERT.to_le_bytes()), STATUS_INVALID_PARAMETER);
    assert_eq!(fs.file_mode(file), Some(requested));
}
