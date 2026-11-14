use super::*;

const FILE: &str = r"\??\C:\Dir\Report.txt";
const DIRECTORY: &str = r"\??\C:\Dir\Sub";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const UNCHANGED: u64 = 0;
const CREATED_AT: u64 = 100;
const NOW: u64 = 500;

fn open(path: &str, options: u32) -> (FileSystem, u64) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.initialize_timestamps(CREATED_AT));
    assert!(fs.provision_directory(r"\??\C:\Dir"));
    let opened = fs.zw_create_file(path, FILE_WRITE_DATA | SYNCHRONIZE, 0, SHARE, FILE_CREATE, options);
    assert_eq!(opened.status, STATUS_SUCCESS);
    fs.set_current_time_100ns(NOW);
    (fs, opened.handle)
}

fn basic(times: [u64; 4], attributes: u32) -> [u8; 40] {
    let mut data = [0u8; 40];
    for (index, time) in times.iter().enumerate() {
        data[index * 8..index * 8 + 8].copy_from_slice(&time.to_le_bytes());
    }
    data[32..36].copy_from_slice(&attributes.to_le_bytes());
    data
}

fn set(fs: &mut FileSystem, handle: u64, times: [u64; 4], attributes: u32) -> u32 {
    fs.zw_set_information_file(handle, FILE_BASIC_INFORMATION, &basic(times, attributes))
}

fn metadata(fs: &FileSystem, handle: u64) -> FileMetadata {
    fs.query_file_object_information(handle).unwrap().metadata
}

/// What `FileBasicInformation` reports back for the same File.
fn reported_attributes(fs: &FileSystem, handle: u64) -> u32 {
    let mut output = [0u8; 40];
    crate::encode_query_information(
        FILE_BASIC_INFORMATION,
        metadata(fs, handle).query_metadata(),
        &mut output,
    )
    .unwrap();
    u32::from_le_bytes(output[32..36].try_into().unwrap())
}

#[test]
fn zero_fields_leave_every_value_unchanged() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    let before = metadata(&fs, handle);
    assert_eq!(set(&mut fs, handle, [UNCHANGED; 4], 0), STATUS_SUCCESS);
    assert_eq!(metadata(&fs, handle), before);
}

#[test]
fn minus_one_times_are_not_stored_as_timestamps() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    let before = metadata(&fs, handle);
    assert_eq!(set(&mut fs, handle, [u64::MAX; 4], 0), STATUS_SUCCESS);
    assert_eq!(metadata(&fs, handle), before);
}

#[test]
fn each_supplied_time_is_stored_and_the_others_kept() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(set(&mut fs, handle, [UNCHANGED, UNCHANGED, 300, UNCHANGED], 0), STATUS_SUCCESS);
    let after = metadata(&fs, handle);
    assert_eq!(after.creation_time, CREATED_AT);
    assert_eq!(after.last_access_time, CREATED_AT);
    assert_eq!(after.last_write_time, 300);
    // The change itself is a metadata change.
    assert_eq!(after.change_time, NOW);

    assert_eq!(set(&mut fs, handle, [201, 202, 203, 204], 0), STATUS_SUCCESS);
    let after = metadata(&fs, handle);
    assert_eq!(
        (after.creation_time, after.last_access_time, after.last_write_time, after.change_time),
        (201, 202, 203, 204)
    );
}

#[test]
fn a_time_set_after_the_last_write_is_the_time_the_file_keeps() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(fs.zw_write_file(handle, None, b"copied"), (STATUS_SUCCESS, 6));
    assert_eq!(set(&mut fs, handle, [UNCHANGED, UNCHANGED, 300, UNCHANGED], 0), STATUS_SUCCESS);
    assert_eq!(fs.zw_close(handle), STATUS_SUCCESS);
    assert_eq!(fs.query_metadata(FILE).unwrap().last_write_time, 300);
}

#[test]
fn attributes_replace_the_stored_set_and_normal_means_none() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(
        set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN),
        STATUS_SUCCESS
    );
    assert_eq!(
        reported_attributes(&fs, handle),
        FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN
    );
    // FILE_ATTRIBUTE_NORMAL is only meaningful alone.
    assert_eq!(
        set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE),
        STATUS_SUCCESS
    );
    assert_eq!(reported_attributes(&fs, handle), FILE_ATTRIBUTE_ARCHIVE);
    assert_eq!(set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_NORMAL), STATUS_SUCCESS);
    assert_eq!(reported_attributes(&fs, handle), FILE_ATTRIBUTE_NORMAL);
    assert_eq!(metadata(&fs, handle).attributes & FILE_ATTRIBUTE_READONLY, 0);
}

#[test]
fn a_directory_keeps_its_directory_attribute() {
    let (mut fs, handle) = open(DIRECTORY, FILE_DIRECTORY_FILE);
    assert_eq!(
        set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM),
        STATUS_SUCCESS
    );
    assert_eq!(
        reported_attributes(&fs, handle),
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
    );
    assert_eq!(
        set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY),
        STATUS_SUCCESS
    );
    assert_eq!(
        reported_attributes(&fs, handle),
        FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_READONLY
    );
    assert_eq!(set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_NORMAL), STATUS_SUCCESS);
    assert_eq!(reported_attributes(&fs, handle), FILE_ATTRIBUTE_DIRECTORY);
}

#[test]
fn a_file_cannot_be_given_the_directory_attribute() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    let before = metadata(&fs, handle);
    assert_eq!(
        set(&mut fs, handle, [201, 202, 203, 204], FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_HIDDEN),
        STATUS_INVALID_PARAMETER
    );
    // Nothing of a refused request is applied.
    assert_eq!(metadata(&fs, handle), before);
}

#[test]
fn a_directory_cannot_be_given_the_temporary_attribute() {
    let (mut fs, handle) = open(DIRECTORY, FILE_DIRECTORY_FILE);
    let before = metadata(&fs, handle);
    assert_eq!(
        set(&mut fs, handle, [UNCHANGED; 4], FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(metadata(&fs, handle), before);
}

#[test]
fn a_short_buffer_is_a_length_mismatch() {
    let (mut fs, handle) = open(FILE, FILE_NON_DIRECTORY_FILE);
    assert_eq!(
        fs.zw_set_information_file(handle, FILE_BASIC_INFORMATION, &[0u8; 39]),
        STATUS_INFO_LENGTH_MISMATCH
    );
}
