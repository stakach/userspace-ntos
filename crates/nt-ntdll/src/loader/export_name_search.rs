//! Locate a name in a PE export name pointer table.

use core::cmp::Ordering;

/// Return the name-table index matching the requested export.
///
/// `compare_at` compares the requested name with the name at an index. PE
/// export name pointers are ordered by their ASCII bytes.
pub fn find_sorted_export_name(
    count: u32,
    mut compare_at: impl FnMut(u32) -> Ordering,
) -> Option<u32> {
    let mut first = 0;
    let mut past_last = count;
    while first < past_last {
        let middle = first + (past_last - first) / 2;
        match compare_at(middle) {
            Ordering::Less => past_last = middle,
            Ordering::Equal => return Some(middle),
            Ordering::Greater => first = middle + 1,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_exact_name_and_rejects_missing_names() {
        let names = [b"Alpha".as_slice(), b"Beta", b"Gamma", b"Omega"];
        for (wanted, expected) in [
            (b"Alpha".as_slice(), Some(0)),
            (b"Gamma", Some(2)),
            (b"Omega", Some(3)),
            (b"A", None),
            (b"Delta", None),
            (b"Zeta", None),
        ] {
            assert_eq!(
                find_sorted_export_name(names.len() as u32, |index| {
                    wanted.cmp(names[index as usize])
                }),
                expected,
            );
        }
        assert_eq!(find_sorted_export_name(0, |_| unreachable!()), None);
    }

    #[test]
    fn bounds_comparisons_for_large_export_tables() {
        const COUNT: u32 = 1991;
        for wanted in [0, COUNT / 2, COUNT - 1, COUNT] {
            let mut comparisons = 0;
            let found = find_sorted_export_name(COUNT, |index| {
                comparisons += 1;
                wanted.cmp(&index)
            });
            assert_eq!(found, (wanted < COUNT).then_some(wanted));
            assert!(comparisons <= 11, "{comparisons} comparisons for {wanted}");
        }
    }
}
