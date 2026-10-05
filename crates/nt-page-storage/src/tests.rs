use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

#[test]
fn slot_sized_leaves_and_all_directory_levels_remain_page_bounded() {
    let mut values = PageSequence::<[u64; 24]>::new();
    values.try_reserve(1).unwrap();
    values.push([0; 24]);
    let first = &values[0] as *const _;
    for index in 1..36_353 {
        values.try_reserve(1).unwrap();
        values.push([index as u64; 24]);
    }
    assert_eq!(&values[0] as *const _, first);
    assert_eq!(values.len(), 36_353);
    let mut leaves = 0;
    let mut directories = 0;
    values.visit_allocations(|leaf, len, bytes| {
        assert!(bytes <= PAGE_BYTES);
        if leaf {
            leaves += 1;
            assert!(len <= PageSequence::<[u64; 24]>::leaf_capacity());
        } else {
            directories += 1;
        }
    });
    assert!(
        directories > 1,
        "exercise directory growth, not only leaf growth"
    );
    assert_eq!(leaves, (36_353 + 20) / 21);
    for (index, value) in values.iter().enumerate() {
        assert_eq!(*value, [index as u64; 24]);
    }
}

#[test]
fn sorted_copy_entries_shift_across_reserved_leaf_and_directory_boundaries() {
    let mut values = PageSequence::<(u64, u64, u64)>::new();
    for value in (0..2049).rev() {
        let position = values
            .binary_search_by_key(&value, |entry| entry.0)
            .unwrap_err();
        values.try_reserve(1).unwrap();
        values.insert(position, (value, value + 1, value + 2));
    }
    for value in 0..2049 {
        assert_eq!(
            values.binary_search_by_key(&value, |entry| entry.0),
            Ok(value as usize)
        );
    }
    for _ in 0..1024 {
        values.remove(1);
    }
    assert_eq!(values[0], (0, 1, 2));
    assert_eq!(values[1], (1025, 1026, 1027));
    values.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
}

#[test]
fn noncopy_owner_swap_removal_drops_only_the_removed_owner() {
    struct Owner(Rc<Cell<usize>>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut values = PageSequence::new();
    for _ in 0..1025 {
        values.try_reserve(1).unwrap();
        values.push(Owner(drops.clone()));
    }
    drop(values.swap_remove(0));
    assert_eq!(drops.get(), 1);
    assert_eq!(values.len(), 1024);
    drop(values.pop());
    assert_eq!(drops.get(), 2);
    drop(values);
    assert_eq!(drops.get(), 1025);
}

#[test]
fn invalid_geometry_and_length_overflow_refuse_without_publishing() {
    let mut oversized = PageSequence::<[u8; PAGE_BYTES + 1]>::new();
    assert!(oversized.try_reserve(1).is_err());
    assert!(oversized.is_empty());
    let mut values = PageSequence::<u64>::new();
    values.try_reserve(1).unwrap();
    values.push(7);
    let first = &values[0] as *const _;
    assert!(values.try_reserve(usize::MAX).is_err());
    assert_eq!(values.len(), 1);
    assert_eq!(values[0], 7);
    assert_eq!(&values[0] as *const _, first);
}
