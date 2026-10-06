use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

#[test]
fn impossible_logical_byte_extent_is_refused_before_metadata_allocation() {
    let mut values = PageSequence::<[u8; 160]>::new();
    for count in [usize::MAX - 1, isize::MAX as usize / 160 + 1] {
        assert_eq!(values.try_reserve(count), Err(()));
        assert_eq!(values.len(), 0);
        assert_eq!(values.depth, 0);
        assert!(matches!(values.root, Node::Empty));
    }
}

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

#[test]
fn clones_reserve_complete_leaves_and_preserve_independent_values() {
    let leaf_capacity = PageSequence::<u64>::leaf_capacity();
    let mut original = PageSequence::new();
    let len = leaf_capacity + 3;
    original.resize_with(len, || 7u64);
    let mut cloned = original.try_clone().unwrap();
    assert_eq!(cloned.len(), len);
    assert_ne!(&original[0] as *const _, &cloned[0] as *const _);
    cloned[0] = 99;
    assert_eq!(original[0], 7);
    assert_eq!(cloned[0], 99);
    // Logical cloning must reserve full leaves, not inherit Vec::clone's exact-length capacity.
    for index in len..2 * leaf_capacity {
        cloned.push(index as u64);
    }
    assert_eq!(cloned.len(), 2 * leaf_capacity);
    let copied = cloned.clone();
    assert!(copied.iter().eq(cloned.iter()));
    copied.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
    original.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
    cloned.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
}

#[test]
fn mutable_iteration_retains_disjoint_references_across_three_tree_levels() {
    type Slot = Option<[u64; 24]>;
    let leaf_capacity = PageSequence::<Slot>::leaf_capacity();
    let len = leaf_capacity * PageSequence::<Slot>::fanout() + 3;
    let mut values = PageSequence::new();
    values.resize_with(len, || None::<[u64; 24]>);
    // Keep unused leaves and empty directory entries beside the published logical prefix.
    values.try_reserve(2 * leaf_capacity).unwrap();
    assert_eq!(values.depth, 2);
    let mut iterator = values.iter_mut();
    assert_eq!(iterator.len(), len);
    let first = iterator.next().unwrap();
    assert_eq!(iterator.len(), len - 1);
    let mut retained = Vec::new();
    retained.push(first);
    retained.extend(iterator);
    assert_eq!(retained.len(), len);
    for (index, slot) in retained.iter_mut().enumerate() {
        **slot = Some([index as u64; 24]);
    }
    for pair in retained.windows(2) {
        assert_ne!(core::ptr::from_ref(&*pair[0]), core::ptr::from_ref(&*pair[1]));
    }
    drop(retained);
    for (index, slot) in values.iter().enumerate() {
        assert_eq!(*slot, Some([index as u64; 24]));
    }
    values.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
}

#[test]
fn truncate_and_regrow_reuse_reserved_pages_and_keep_surviving_addresses() {
    let leaf_capacity = PageSequence::<u64>::leaf_capacity();
    let len = leaf_capacity + 3;
    let mut values = PageSequence::new();
    let mut generated = 0u64;
    values.resize_with(len, || {
        generated += 1;
        generated
    });
    let first = &values[0] as *const _;
    let mut backing = Vec::new();
    values.visit_allocations(|leaf, len, bytes| backing.push((leaf, len, bytes)));
    values.truncate(2);
    assert_eq!(values.len(), 2);
    assert_eq!(values.iter().copied().collect::<Vec<_>>(), [1, 2]);
    values.resize_with(len, || 77);
    assert_eq!(&values[0] as *const _, first);
    assert_eq!(values[1], 2);
    assert!(values.iter().skip(2).all(|value| *value == 77));
    let mut regrown = Vec::new();
    values.visit_allocations(|leaf, len, bytes| regrown.push((leaf, len, bytes)));
    assert_eq!(backing, regrown);
    values.truncate(0);
    let mut iterator = values.iter_mut();
    assert_eq!(iterator.len(), 0);
    assert!(iterator.next().is_none());
    assert!(iterator.next().is_none());
    drop(iterator);
    values.resize_with(1, || 88);
    assert_eq!(&values[0] as *const _, first);
    assert_eq!(values[0], 88);
    values.visit_allocations(|_, _, bytes| assert!(bytes <= PAGE_BYTES));
}

#[test]
fn shrinking_and_truncating_noncopy_owners_drop_each_removed_element_once() {
    struct Owner(Rc<Cell<usize>>);
    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let drops = Rc::new(Cell::new(0));
    let mut values = PageSequence::new();
    let len = PageSequence::<Owner>::leaf_capacity() + 3;
    values.resize_with(len, || Owner(drops.clone()));
    values.resize_with(3, || panic!("shrinking must not generate elements"));
    assert_eq!(drops.get(), len - 3);
    values.truncate(1);
    assert_eq!(drops.get(), len - 1);
    values.truncate(2);
    assert_eq!(drops.get(), len - 1);
    drop(values);
    assert_eq!(drops.get(), len);
}

#[test]
fn empty_and_invalid_geometry_resize_without_publishing_or_calling_generators() {
    let mut empty = PageSequence::<u64>::new();
    assert!(empty.iter_mut().next().is_none());
    empty.resize_with(0, || panic!("empty resize must not generate elements"));
    assert!(empty.try_clone().unwrap().is_empty());

    let mut zero = PageSequence::<()>::new();
    let mut generated = 0;
    assert!(zero
        .try_resize_with(1, || {
            generated += 1;
        })
        .is_err());
    assert_eq!(generated, 0);
    assert!(zero.is_empty());
    assert!(zero.iter_mut().next().is_none());
    assert!(zero.try_clone().unwrap().is_empty());
    zero.resize_with(0, || panic!("empty resize must not generate elements"));

    let mut oversized = PageSequence::<[u8; PAGE_BYTES + 1]>::new();
    assert!(oversized
        .try_resize_with(1, || {
            generated += 1;
            [0; PAGE_BYTES + 1]
        })
        .is_err());
    assert_eq!(generated, 0);
    assert!(oversized.is_empty());
    assert!(oversized.iter_mut().next().is_none());
    assert!(oversized.clone().is_empty());
}
