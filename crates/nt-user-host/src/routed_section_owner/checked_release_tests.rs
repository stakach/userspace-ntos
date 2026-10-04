use super::RoutedSectionOwners;

#[derive(Debug, PartialEq, Eq)]
struct FilePin {
    released: bool,
}

#[test]
fn checked_release_retains_the_exact_owner_until_file_release_acknowledges() {
    let mut owners = RoutedSectionOwners::<FilePin, (usize, u64)>::new();
    let lease = owners.reserve(FilePin { released: false }).unwrap();
    let section = (3, 7);
    assert!(owners.bind(lease, section));

    assert_eq!(owners.release_checked(lease, section, |pin| {
        assert!(!pin.released);
        Err(0xc000_009au32)
    }), Err(0xc000_009a));
    assert_eq!(owners.get(lease, section), Some(&FilePin { released: false }));
    assert!(!owners.is_empty());

    assert_eq!(owners.release_checked(lease, (3, 8), |_| {
        panic!("a reused Section index is not the retained incarnation")
    }), Ok::<_, u32>(false));
    assert_eq!(owners.release_checked(lease, section, |pin| {
        assert!(!pin.released);
        pin.released = true;
        Ok::<_, u32>(())
    }), Ok(true));
    assert!(owners.is_empty());
    assert_eq!(owners.release_checked(lease, section, |_| {
        panic!("an acknowledged File release cannot replay")
    }), Ok::<_, u32>(false));
}

#[test]
fn checked_cancel_preserves_unbound_owner_on_refusal_and_never_cancels_bound_owner() {
    let mut owners = RoutedSectionOwners::<FilePin, (usize, u64)>::new();
    let lease = owners.reserve(FilePin { released: false }).unwrap();
    assert_eq!(owners.cancel_unbound_checked(lease, |_| Err(0xc000_009au32)),
        Err(0xc000_009a));
    assert!(!owners.is_empty());
    assert!(owners.bind(lease, (0, 1)));
    assert_eq!(owners.cancel_unbound_checked(lease, |_| {
        panic!("published Section ownership requires exact retirement")
    }), Ok::<_, u32>(false));
    assert!(owners.release_checked(lease, (0, 1), |_| Ok::<_, u32>(())).unwrap());

    let next = owners.reserve(FilePin { released: false }).unwrap();
    assert_ne!(next, lease);
    assert_eq!(owners.cancel_unbound_checked(next, |pin| {
        assert!(!pin.released);
        pin.released = true;
        Ok::<_, u32>(())
    }), Ok(true));
    assert!(owners.is_empty());
}
