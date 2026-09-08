use super::select_cyclic_ids;

#[test]
fn reversed_rows_progress_through_every_batch() {
    let mut output = [0; 32];
    let mut cursor = 1;
    for first in [1, 33, 65] {
        let selected = select_cyclic_ids((1..=100).rev(), cursor, &mut output);
        assert_eq!(selected.count, 32);
        for (offset, id) in output.iter().enumerate() {
            assert_eq!(*id, first + offset as u64);
        }
        cursor = selected.next_cursor;
    }
    let selected = select_cyclic_ids((1..=100).rev(), cursor, &mut output);
    assert_eq!(&output[..4], &[97, 98, 99, 100]);
    for (offset, id) in output[4..].iter().enumerate() {
        assert_eq!(*id, offset as u64 + 1);
    }
    assert_eq!(selected.next_cursor, 29);
}

#[test]
fn scrambled_and_removed_rows_do_not_change_cyclic_order() {
    let mut output = [0; 4];
    let selected = select_cyclic_ids([90, 4, 80, 10, 70, 40, 30], 31, &mut output);
    assert_eq!(output, [40, 70, 80, 90]);
    assert_eq!(selected.next_cursor, 91);
    let selected = select_cyclic_ids([30, 80, 4, 10, 70], selected.next_cursor, &mut output);
    assert_eq!(output, [4, 10, 30, 70]);
    assert_eq!(selected.next_cursor, 71);
}

#[test]
fn wraps_after_exhausting_ids_at_or_above_cursor() {
    let mut output = [0; 5];
    let selected = select_cyclic_ids([6, 2, 8, 4], 5, &mut output);
    assert_eq!(selected.count, 4);
    assert_eq!(&output[..4], &[6, 8, 2, 4]);
    assert_eq!(selected.next_cursor, 5);
}

#[test]
fn one_slot_still_advances_across_wrap() {
    let mut output = [0];
    let first = select_cyclic_ids([9, 3, 6], 5, &mut output);
    assert_eq!(output, [6]);
    let second = select_cyclic_ids([9, 3, 6], first.next_cursor, &mut output);
    assert_eq!(output, [9]);
    let third = select_cyclic_ids([9, 3, 6], second.next_cursor, &mut output);
    assert_eq!(output, [3]);
    assert_eq!(third.next_cursor, 4);
}

#[test]
fn empty_budget_does_not_consume_input_or_advance_cursor() {
    let input = core::iter::from_fn(|| -> Option<u64> {
        panic!("zero-budget selection must not consume input")
    });
    let selected = select_cyclic_ids(input, u64::MAX, &mut []);
    assert_eq!(selected.count, 0);
    assert_eq!(selected.next_cursor, u64::MAX);
}

#[test]
fn empty_input_preserves_cursor_and_storage() {
    let mut output = [91, 92, 93];
    let selected = select_cyclic_ids([], 47, &mut output);
    assert_eq!(selected.count, 0);
    assert_eq!(selected.next_cursor, 47);
    assert_eq!(output, [91, 92, 93]);
}

#[test]
fn unused_suffix_is_unchanged() {
    let mut output = [99; 5];
    let selected = select_cyclic_ids([7, 2], 0, &mut output);
    assert_eq!(selected.count, 2);
    assert_eq!(output, [2, 7, 99, 99, 99]);
}

#[test]
fn full_u64_domain_has_no_reserved_identity_or_overflow() {
    let mut output = [0; 3];
    let selected = select_cyclic_ids([u64::MAX, 0, u64::MAX - 1], 0, &mut output);
    assert_eq!(output, [0, u64::MAX - 1, u64::MAX]);
    assert_eq!(selected.next_cursor, 0);
    let selected = select_cyclic_ids([0, u64::MAX - 1, u64::MAX], u64::MAX, &mut output);
    assert_eq!(output, [u64::MAX, 0, u64::MAX - 1]);
    assert_eq!(selected.next_cursor, u64::MAX);
}

#[test]
fn repeated_ids_do_not_consume_budget() {
    let mut output = [0; 4];
    let selected = select_cyclic_ids([9, 1, 9, 2, 1, 3, 3], 2, &mut output);
    assert_eq!(selected.count, 4);
    assert_eq!(output, [2, 3, 9, 1]);
    assert_eq!(selected.next_cursor, 2);
}

#[test]
fn every_input_permutation_has_the_same_selection() {
    let mut baseline = [0; 3];
    let expected = select_cyclic_ids([1, 4, 7, 10], 5, &mut baseline);
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    if a == b || a == c || a == d || b == c || b == d || c == d {
                        continue;
                    }
                    let ids = [1, 4, 7, 10];
                    let mut actual = [0; 3];
                    let selected =
                        select_cyclic_ids([ids[a], ids[b], ids[c], ids[d]], 5, &mut actual);
                    assert_eq!(selected, expected);
                    assert_eq!(actual, baseline);
                }
            }
        }
    }
}
