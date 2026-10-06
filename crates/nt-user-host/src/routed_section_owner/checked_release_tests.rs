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

    assert_eq!(
        owners.release_checked(lease, section, |pin| {
            assert!(!pin.released);
            Err(0xc000_009au32)
        }),
        Err(0xc000_009a)
    );
    assert_eq!(
        owners.get(lease, section),
        Some(&FilePin { released: false })
    );
    assert!(!owners.is_empty());

    assert_eq!(
        owners.release_checked(lease, (3, 8), |_| {
            panic!("a reused Section index is not the retained incarnation")
        }),
        Ok::<_, u32>(false)
    );
    assert_eq!(
        owners.release_checked(lease, section, |pin| {
            assert!(!pin.released);
            pin.released = true;
            Ok::<_, u32>(())
        }),
        Ok(true)
    );
    assert!(owners.is_empty());
    assert_eq!(
        owners.release_checked(lease, section, |_| {
            panic!("an acknowledged File release cannot replay")
        }),
        Ok::<_, u32>(false)
    );
}

#[test]
fn checked_cancel_preserves_unbound_owner_on_refusal_and_never_cancels_bound_owner() {
    let mut owners = RoutedSectionOwners::<FilePin, (usize, u64)>::new();
    let lease = owners.reserve(FilePin { released: false }).unwrap();
    assert_eq!(
        owners.cancel_unbound_checked(lease, |_| Err(0xc000_009au32)),
        Err(0xc000_009a)
    );
    assert!(!owners.is_empty());
    assert!(owners.bind(lease, (0, 1)));
    assert_eq!(
        owners.cancel_unbound_checked(lease, |_| {
            panic!("published Section ownership requires exact retirement")
        }),
        Ok::<_, u32>(false)
    );
    assert!(owners
        .release_checked(lease, (0, 1), |_| Ok::<_, u32>(()))
        .unwrap());

    let next = owners.reserve(FilePin { released: false }).unwrap();
    assert_ne!(next, lease);
    assert_eq!(
        owners.cancel_unbound_checked(next, |pin| {
            assert!(!pin.released);
            pin.released = true;
            Ok::<_, u32>(())
        }),
        Ok(true)
    );
    assert!(owners.is_empty());
}

#[test]
fn retained_readonly_file_pin_survives_close_until_exact_section_release() {
    let mut files = nt_fs::ReadOnlyFileOpenTable::<1>::new();
    let metadata = nt_fs::FileMetadata {
        end_of_file: 64,
        file_id: 41,
        ..Default::default()
    };
    let old = files
        .create(
            41,
            64,
            b"reactos\\system32\\data.bin",
            nt_fs::FILE_READ_DATA,
            0,
            nt_fs::FILE_SYNCHRONOUS_IO_NONALERT,
            metadata,
            nt_fs::FatShortName::EMPTY,
        )
        .unwrap();
    let mut owners = RoutedSectionOwners::<u32, (usize, u64)>::new();
    let lease = owners.reserve(old).unwrap();
    files.retain_io(old).unwrap();
    let section = (3, 7);
    assert!(owners.bind(lease, section));
    files.release(old).unwrap();
    assert_eq!(files.get(old).unwrap().metadata.file_id, 41);

    assert_eq!(
        owners.release_checked(lease, (3, 8), |id| files.release_io(*id)),
        Ok(false)
    );
    assert!(files.get(old).is_ok());
    assert_eq!(
        owners.release_checked(lease, section, |id| files.release_io(*id)),
        Ok(true)
    );
    assert_eq!(files.get(old).err(), Some(nt_fs::STATUS_INVALID_HANDLE));
    let new = files
        .create(
            42,
            64,
            b"reactos\\system32\\other.bin",
            nt_fs::FILE_READ_DATA,
            0,
            nt_fs::FILE_SYNCHRONOUS_IO_NONALERT,
            metadata,
            nt_fs::FatShortName::EMPTY,
        )
        .unwrap();
    assert_ne!(old, new);
    assert_eq!(
        owners.release_checked(lease, section, |_| {
            panic!("a retired Section cannot release a reused readonly File slot")
        }),
        Ok::<_, u32>(false)
    );
    assert!(files.get(new).is_ok());
}
