use super::*;

fn files() -> FileCompletionTable<2> {
    let mut files = FileCompletionTable::new();
    files.insert_file(10, 7, true).unwrap();
    files
}

#[test]
fn fresh_admission_commits_reference_and_serialization_together() {
    let mut files = files();
    assert_eq!(
        files.acquire_file_io(10, 20),
        Ok(FileIoAcquireResult::Acquired)
    );
    assert_eq!(files.entry(10).unwrap().references, 2);
    assert_eq!(
        files.acquire_file_io(10, 21),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    assert_eq!(files.entry(10).unwrap().references, 3);
    assert_eq!(files.io_waiter_count(10), Ok(1));
}

#[test]
fn invalid_tid_missing_file_and_reference_overflow_do_not_change_busy() {
    let mut files = files();
    for tid in [0, u64::MAX] {
        assert_eq!(
            files.acquire_file_io(10, tid),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(files.entry(10).unwrap().references, 1);
        assert_eq!(
            files.entry(10).unwrap().serialization,
            FileIoSerialization::new()
        );
    }
    assert_eq!(files.acquire_file_io(99, 20), Err(STATUS_INVALID_HANDLE));
    files.entry_mut(10).unwrap().references = u32::MAX;
    assert_eq!(
        files.acquire_file_io(10, 20),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(files.entry(10).unwrap().references, u32::MAX);
    assert_eq!(
        files.entry(10).unwrap().serialization,
        FileIoSerialization::new()
    );
}

#[test]
fn unpublished_and_cleaned_up_files_refuse_fresh_admission_without_retain() {
    let mut files = files();
    files.reserve_file_handle_publication(11, 7, true).unwrap();
    assert_eq!(files.acquire_file_io(11, 20), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.adopt_io_grant(11, 20), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.entry(11).unwrap().references, 1);
    files.retain_file(10).unwrap();
    files.release_handle(10).unwrap();
    let refs = files.entry(10).unwrap().references;
    let serialization = files.entry(10).unwrap().serialization;
    assert_eq!(files.acquire_file_io(10, 20), Err(STATUS_INVALID_HANDLE));
    assert_eq!(files.entry(10).unwrap().references, refs);
    assert_eq!(files.entry(10).unwrap().serialization, serialization);
}

#[test]
fn only_explicit_adoption_consumes_grant_and_never_adds_reference_or_waiter() {
    let mut files = files();
    assert_eq!(files.adopt_io_grant(10, 20), Err(STATUS_INVALID_PARAMETER));
    files.acquire_file_io(10, 20).unwrap();
    files.acquire_file_io(10, 21).unwrap();
    files.release_io(10, 20).unwrap();
    files.release_file(10).unwrap();
    files.promote_io_waiter(10, 21).unwrap();
    let refs = files.entry(10).unwrap().references;
    let serialization = files.entry(10).unwrap().serialization;
    assert_eq!(files.acquire_file_io(10, 21), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.adopt_io_grant(10, 22), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.entry(10).unwrap().serialization, serialization);
    assert_eq!(files.entry(10).unwrap().references, refs);
    files.release_handle(10).unwrap();
    let refs = files.entry(10).unwrap().references;
    assert_eq!(files.adopt_io_grant(10, 21), Ok(()));
    let serialization = files.entry(10).unwrap().serialization;
    assert_eq!(files.adopt_io_grant(10, 21), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(files.entry(10).unwrap().serialization, serialization);
    assert_eq!(files.entry(10).unwrap().references, refs);
    assert_eq!(files.io_waiter_count(10), Ok(0));
}

#[test]
fn asynchronous_admission_retains_without_busy_and_cannot_adopt() {
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file(10, 7, false).unwrap();
    assert_eq!(
        files.acquire_file_io(10, 20),
        Ok(FileIoAcquireResult::Bypassed)
    );
    assert_eq!(files.entry(10).unwrap().references, 2);
    assert_eq!(
        files.entry(10).unwrap().serialization,
        FileIoSerialization::new()
    );
    assert_eq!(files.adopt_io_grant(10, 20), Err(STATUS_INVALID_PARAMETER));
}
