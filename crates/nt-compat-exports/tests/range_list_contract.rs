//! Pure NT range-list policy, drawn from references/reactos/sdk/lib/rtl/rangelist.c
//! and references/reactos/modules/rostests/kmtests/rtl/RtlRangeList.c.

use nt_compat_exports::range_list::{Range, RangeList, RangeListError, ADD_IF_CONFLICT,
    ADD_SHARED, SHARED_OK, NULL_CONFLICT_OK};

fn range(start: u64, end: u64, owner: u64) -> Range {
    Range { start, end, owner, user_data: 0, attributes: 0, shared: false }
}

#[test]
fn add_rejects_invalid_or_conflicting_closed_intervals_without_mutation() {
    let mut list = RangeList::new();
    list.add(range(0x100, 0x200, 1), 0).unwrap();
    let before = list.ranges().to_vec();
    assert_eq!(list.add(range(0x300, 0x2ff, 2), 0), Err(RangeListError::InvalidParameter));
    assert_eq!(list.add(range(0x180, 0x280, 2), 0), Err(RangeListError::Conflict));
    assert_eq!(list.ranges(), before);

    list.add(range(0x180, 0x280, 2), ADD_IF_CONFLICT).unwrap();
    assert_eq!(list.ranges(), &[range(0x100, 0x200, 1), range(0x180, 0x280, 2)]);
}

#[test]
fn copy_and_delete_owner_preserve_independent_ownership() {
    let mut source = RangeList::new();
    source.add(range(0x100, 0x200, 1), 0).unwrap();
    source.add(range(0x300, 0x400, 2), 0).unwrap();
    source.add(range(0x500, 0x600, 2), 0).unwrap();
    let mut copy = source.clone();

    copy.delete_owner(2);
    assert_eq!(copy.ranges(), &[range(0x100, 0x200, 1)]);
    assert_eq!(source.ranges().len(), 3);
    copy.clear();
    assert!(copy.ranges().is_empty());
    assert_eq!(source.ranges().len(), 3);
}

#[test]
fn find_searches_downward_and_invert_emits_all_gaps() {
    let mut list = RangeList::new();
    list.add(range(0x100, 0x200, 1), 0).unwrap();
    list.add(range(0x400, 0x500, 2), 0).unwrap();

    assert_eq!(list.find(0, 0x200, 0x10, 1, 0, 0, |_| false), Ok(0xf0));
    assert_eq!(list.find(0, 0x1000, 0x10, 0x100, 0, 0, |_| false), Ok(0xf00));
    assert_eq!(list.find(0x100, 0x200, 0x10, 1, 0, 0, |_| false), Err(RangeListError::NotFound));
    assert_eq!(list.find(0, 0x1000, 0, 1, 0, 0, |_| false), Err(RangeListError::InvalidParameter));

    let gaps = list.invert().unwrap();
    assert_eq!(gaps.ranges(), &[
        range(0, 0xff, 0),
        range(0x201, 0x3ff, 0),
        range(0x501, u64::MAX, 0),
    ]);
    assert_eq!(list.ranges().len(), 2);
}

#[test]
fn shared_attributes_null_owner_and_callback_control_conflicts() {
    let mut list = RangeList::new();
    let mut first = range(0x100, 0x1ff, 0);
    first.attributes = 0x4;
    list.add(first, ADD_SHARED).unwrap();
    assert_eq!(list.add(range(0x180, 0x1a0, 2), 0), Err(RangeListError::Conflict));
    list.add(range(0x180, 0x1a0, 2), ADD_SHARED).unwrap();
    assert_eq!(list.find(0x100, 0x1ff, 0x10, 1, 0, 0, |_| false), Err(RangeListError::NotFound));
    assert_eq!(list.find(0x100, 0x1ff, 0x10, 1, SHARED_OK, 0, |_| false), Ok(0x1f0));
    assert_eq!(list.find(0x180, 0x1af, 0x10, 1, NULL_CONFLICT_OK, 0, |_| false), Err(RangeListError::NotFound));
    assert_eq!(list.find(0x180, 0x1af, 0x10, 1, 0, 0x4, |r| r.owner == 2), Ok(0x1a0));
}

#[test]
fn copy_and_invert_accept_initialized_nonempty_destinations() {
    let mut source = RangeList::new();
    source.add(range(0x100, 0x200, 1), 0).unwrap();
    source.add(range(0x400, 0x500, 2), 0).unwrap();
    let mut copy = RangeList::new();
    copy.add(range(0x300, 0x350, 3), 0).unwrap();
    copy.append_from(&source).unwrap();
    assert_eq!(copy.ranges(), &[
        range(0x100, 0x200, 1), range(0x300, 0x350, 3), range(0x400, 0x500, 2),
    ]);

    let mut inverted = RangeList::new();
    inverted.add(range(0x300, 0x350, 3), 0).unwrap();
    source.invert_into(&mut inverted).unwrap();
    assert_eq!(inverted.ranges(), &[
        range(0, 0xff, 0), range(0x201, 0x3ff, 0),
        range(0x300, 0x350, 3), range(0x501, u64::MAX, 0),
    ]);
}
