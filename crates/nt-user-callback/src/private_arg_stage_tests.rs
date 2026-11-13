use super::{ArgStageError, DirtyArgSpan, PrivateArgStage};

#[test]
fn staged_graph_uses_provider_addresses_without_writing_provider_memory() {
    let mut storage = [0; 64];
    let mut stage = PrivateArgStage::<4>::new(0x1000, &mut storage).unwrap();
    let string_pointer = stage.provider_va(24).unwrap();
    stage.write(0, &string_pointer.to_le_bytes()).unwrap();
    stage.write(24, b"NT").unwrap();

    let mut published = [0xAA; 64];
    assert_eq!(published[0], 0xAA);
    stage.for_each_dirty(|provider_va, bytes| {
        let offset = (provider_va - 0x1000) as usize;
        published[offset..offset + bytes.len()].copy_from_slice(bytes);
    });
    assert_eq!(&published[..8], &string_pointer.to_le_bytes());
    assert_eq!(&published[24..26], b"NT");
    assert_eq!(published[8], 0xAA);
    assert_eq!(published[26], 0xAA);
    assert_eq!(
        stage.dirty_spans(),
        &[
            DirtyArgSpan { offset: 0, len: 8 },
            DirtyArgSpan { offset: 24, len: 2 },
        ]
    );
}

#[test]
fn adjacent_and_overlapping_writes_merge_without_overwriting_untouched_bytes() {
    let mut storage = [0; 16];
    let mut stage = PrivateArgStage::<2>::new(0x2000, &mut storage).unwrap();
    stage.write(4, b"AB").unwrap();
    stage.write(6, b"CD").unwrap();
    stage.write(5, b"xy").unwrap();
    assert_eq!(stage.dirty_spans(), &[DirtyArgSpan { offset: 4, len: 4 }]);
    stage.for_each_dirty(|va, bytes| {
        assert_eq!(va, 0x2004);
        assert_eq!(bytes, b"AxyD");
    });
}

#[test]
fn rejected_writes_do_not_change_bytes_or_dirty_ownership() {
    let mut storage = [0; 16];
    let mut stage = PrivateArgStage::<1>::new(0x3000, &mut storage).unwrap();
    stage.write(0, b"A").unwrap();
    assert_eq!(stage.write(8, b"B"), Err(ArgStageError::TooManyDirtySpans));
    assert_eq!(stage.zero(15, 2), Err(ArgStageError::OutOfBounds));
    assert_eq!(stage.dirty_spans(), &[DirtyArgSpan { offset: 0, len: 1 }]);
    stage.for_each_dirty(|va, bytes| {
        assert_eq!(va, 0x3000);
        assert_eq!(bytes, b"A");
    });
}

#[test]
fn provider_address_range_cannot_wrap_or_name_outside_the_stage() {
    let mut overflow_storage = [0; 16];
    assert!(matches!(
        PrivateArgStage::<2>::new(u64::MAX - 15, &mut overflow_storage),
        Err(ArgStageError::InvalidProviderRange)
    ));
    let mut storage = [0; 16];
    let stage = PrivateArgStage::<2>::new(0x4000, &mut storage).unwrap();
    assert_eq!(stage.provider_va(15), Ok(0x400F));
    assert_eq!(stage.provider_va(16), Err(ArgStageError::OutOfBounds));
}
