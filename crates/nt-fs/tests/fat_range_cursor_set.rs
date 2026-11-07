use nt_fs::FatRangeCursorSet;

const END: u32 = 0x0fff_ffff;

#[test]
fn interleaved_files_resume_their_own_verified_chain_positions() {
    let mut cursors = FatRangeCursorSet::<4>::new();
    let mut links = vec![END; 5_000];
    for first in [100usize, 2_100] {
        for cluster in first..first + 1_000 {
            links[cluster] = (cluster + 1) as u32;
        }
    }
    let mut hops = 0;
    for target in (100..900).step_by(100) {
        for first in [100u32, 2_100] {
            let found = cursors.locate(77, first, 512_000, target, |cluster| {
                hops += 1;
                links[cluster as usize]
            });
            assert_eq!(found, Some(first + target));
        }
    }
    assert_eq!(hops, 1_600, "interleaving restarted a verified FAT chain");
}

#[test]
fn volume_and_size_are_part_of_cursor_identity() {
    let mut cursors = FatRangeCursorSet::<4>::new();
    assert_eq!(cursors.locate(77, 100, 1_024, 1, |_| 101), Some(101));
    assert_eq!(cursors.locate(78, 100, 1_024, 1, |_| 201), Some(201));
    assert_eq!(cursors.locate(77, 100, 2_048, 1, |_| 301), Some(301));
}

#[test]
fn invalidation_discards_every_verified_position() {
    let mut cursors = FatRangeCursorSet::<4>::new();
    assert_eq!(cursors.locate(77, 100, 2_048, 1, |_| 101), Some(101));
    cursors.invalidate();
    assert_eq!(cursors.locate(77, 100, 2_048, 1, |_| 201), Some(201));
}

#[test]
fn failed_link_does_not_publish_a_partial_position() {
    let mut cursors = FatRangeCursorSet::<4>::new();
    assert_eq!(cursors.locate(77, 100, 2_048, 2, |_| END), None);
    let mut hops = 0;
    assert_eq!(
        cursors.locate(77, 100, 2_048, 2, |cluster| {
            hops += 1;
            cluster + 1
        }),
        Some(102)
    );
    assert_eq!(hops, 2);
}
