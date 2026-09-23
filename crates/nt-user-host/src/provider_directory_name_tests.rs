use super::*;

fn owner() -> DirectoryUploadOwner<u64, u64, u64> {
    DirectoryUploadOwner {
        route: 1,
        dispatch: 7,
        caller: 11,
    }
}

fn metadata(total_units: usize) -> DirectoryNameMetadata {
    DirectoryNameMetadata {
        root_directory: 0x1234,
        attributes: 0x40,
        desired_access: 0xf,
        total_units,
    }
}

#[test]
fn exact_owner_and_generation_guard_each_step() {
    let mut uploads = DirectoryNameUploads::new();
    uploads.begin(owner(), metadata(2)).unwrap();
    for wrong in [
        DirectoryUploadOwner {
            route: 2,
            ..owner()
        },
        DirectoryUploadOwner {
            dispatch: 8,
            ..owner()
        },
        DirectoryUploadOwner {
            caller: 12,
            ..owner()
        },
    ] {
        assert_eq!(
            uploads.append(wrong, 0, &[b'A' as u16]),
            Err(DirectoryUploadError::WrongOwner)
        );
        assert_eq!(uploads.commit(wrong), Err(DirectoryUploadError::WrongOwner));
        assert_eq!(uploads.abort(wrong), Err(DirectoryUploadError::WrongOwner));
    }
    assert_eq!(
        uploads.begin(
            DirectoryUploadOwner {
                dispatch: 8,
                ..owner()
            },
            metadata(2)
        ),
        Err(DirectoryUploadError::RouteOccupied)
    );
    uploads
        .append(owner(), 0, &[b'A' as u16, b'B' as u16])
        .unwrap();
    let capture = uploads.commit(owner()).unwrap();
    assert_eq!(capture.name, [b'A' as u16, b'B' as u16]);
    assert_eq!(capture.root_directory, 0x1234);
    assert_eq!(capture.attributes, 0x40);
    assert_eq!(capture.desired_access, 0xf);
}

#[test]
fn bounded_chunks_offsets_and_overflow_do_not_change_progress() {
    let mut uploads = DirectoryNameUploads::new();
    assert_eq!(
        uploads.begin(owner(), metadata(MAX_NAME_UNITS + 1)),
        Err(DirectoryUploadError::InvalidLength)
    );
    uploads.begin(owner(), metadata(2)).unwrap();
    assert_eq!(
        uploads.append(owner(), 0, &[]),
        Err(DirectoryUploadError::InvalidChunk)
    );
    assert_eq!(
        uploads.append(owner(), 0, &[1; MAX_CHUNK_UNITS + 1]),
        Err(DirectoryUploadError::InvalidChunk)
    );
    assert_eq!(
        uploads.append(owner(), 1, &[1]),
        Err(DirectoryUploadError::WrongOffset)
    );
    assert_eq!(
        uploads.append(owner(), 0, &[1, 2, 3]),
        Err(DirectoryUploadError::Overflow)
    );
    uploads.append(owner(), 0, &[1]).unwrap();
    assert_eq!(
        uploads.append(owner(), 0, &[1]),
        Err(DirectoryUploadError::WrongOffset)
    );
    assert_eq!(
        uploads.append(owner(), 1, &[2, 3]),
        Err(DirectoryUploadError::Overflow)
    );
    uploads.append(owner(), 1, &[2]).unwrap();
    assert_eq!(uploads.commit(owner()).unwrap().name, [1, 2]);
}

#[test]
fn incomplete_and_terminal_operations_cannot_replay() {
    let mut uploads = DirectoryNameUploads::new();
    uploads.begin(owner(), metadata(2)).unwrap();
    uploads.append(owner(), 0, &[1]).unwrap();
    assert_eq!(
        uploads.commit(owner()),
        Err(DirectoryUploadError::Incomplete)
    );
    uploads.append(owner(), 1, &[2]).unwrap();
    uploads.commit(owner()).unwrap();
    assert_eq!(
        uploads.commit(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.abort(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.append(owner(), 0, &[1]),
        Err(DirectoryUploadError::InvalidPhase)
    );
    uploads.mark_effect_uncertain(owner()).unwrap();
    assert_eq!(
        uploads.mark_effect_uncertain(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.commit(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.begin(owner(), metadata(2)),
        Err(DirectoryUploadError::RouteOccupied)
    );
    assert_eq!(
        uploads.begin(
            DirectoryUploadOwner {
                dispatch: 8,
                ..owner()
            },
            metadata(2)
        ),
        Err(DirectoryUploadError::RouteOccupied)
    );
    uploads.retire_definite(owner()).unwrap();
    assert_eq!(
        uploads.retire_definite(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.begin(owner(), metadata(2)),
        Err(DirectoryUploadError::RouteOccupied)
    );
    let next = DirectoryUploadOwner {
        dispatch: 8,
        ..owner()
    };
    uploads.begin(next, metadata(1)).unwrap();
    assert_eq!(
        uploads.append(owner(), 0, &[1]),
        Err(DirectoryUploadError::WrongOwner)
    );
    assert_eq!(
        uploads.commit(owner()),
        Err(DirectoryUploadError::WrongOwner)
    );
    uploads.append(next, 0, &[3]).unwrap();
    assert_eq!(uploads.commit(next).unwrap().name, [3]);
}

#[test]
fn abort_is_terminal_but_new_dispatch_can_reuse_route() {
    let mut uploads = DirectoryNameUploads::new();
    uploads.begin(owner(), metadata(1)).unwrap();
    uploads.abort(owner()).unwrap();
    assert_eq!(uploads.phase(owner()), Some(DirectoryUploadPhase::Aborted));
    assert_eq!(
        uploads.abort(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.commit(owner()),
        Err(DirectoryUploadError::InvalidPhase)
    );
    assert_eq!(
        uploads.begin(owner(), metadata(1)),
        Err(DirectoryUploadError::RouteOccupied)
    );
    uploads
        .begin(
            DirectoryUploadOwner {
                dispatch: 8,
                ..owner()
            },
            metadata(1),
        )
        .unwrap();
}

#[test]
fn repeated_dispatches_keep_only_one_generation_per_route() {
    let mut uploads = DirectoryNameUploads::new();
    for dispatch in 1..=1000 {
        let current = DirectoryUploadOwner {
            dispatch,
            ..owner()
        };
        uploads.begin(current, metadata(1)).unwrap();
        uploads.append(current, 0, &[dispatch as u16]).unwrap();
        uploads.commit(current).unwrap();
        uploads.retire_definite(current).unwrap();
        assert_eq!(uploads.entries.len(), 1);
    }
    assert_eq!(uploads.phase(owner()), None);
}

#[test]
fn retirement_removes_only_the_completed_dispatch() {
    let mut uploads = DirectoryNameUploads::new();
    let other = DirectoryUploadOwner {
        route: 2,
        ..owner()
    };
    uploads.begin(owner(), metadata(1)).unwrap();
    uploads.begin(other, metadata(1)).unwrap();
    uploads.retire_matching(|candidate| {
        candidate.route == owner().route && candidate.dispatch == owner().dispatch
    });
    assert_eq!(uploads.phase(owner()), None);
    assert_eq!(uploads.phase(other), Some(DirectoryUploadPhase::Uploading));
    uploads.append(other, 0, &[1]).unwrap();
    assert_eq!(uploads.commit(other).unwrap().name, [1]);
}
