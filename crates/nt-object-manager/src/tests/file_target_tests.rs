use super::*;

#[test]
fn raw_filesystem_suffix_keeps_every_separator_and_utf16_unit() {
    let mut om = bootstrapped();
    let device = om.lookup_path(&path("\\Device"), CI).unwrap();
    let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
    let volume = om
        .create_device(&device, &uni("Exact"), ComponentId(7), 70, true)
        .unwrap();
    om.create_symbolic_link(&dosdev, &uni("Drive"), path("\\Device\\Exact"), true)
        .unwrap();
    for prefix in ["\\Device\\Exact", "\\??\\Drive"] {
        for suffix in ["", "\\", "\\\\", "\\Dir\\\\LeAf\\"] {
            let input = uni(&std::format!("{prefix}{suffix}"));
            assert_eq!(
                om.resolve_file_target(input.as_units(), CI),
                Ok(FilePathTarget {
                    device_object: volume.id(),
                    remaining_name: uni(suffix).as_units().to_vec(),
                })
            );
        }
        let mut input = uni(prefix).as_units().to_vec();
        let suffix = [b'\\' as u16, 0xd800, 0x0000, 0xdc00, b'\\' as u16];
        input.extend_from_slice(&suffix);
        assert_eq!(
            om.resolve_file_target(&input, CI).unwrap().remaining_name,
            suffix
        );
    }
}

#[test]
fn nested_aliases_select_identity_and_raw_suffix_in_one_traversal() {
    let mut om = bootstrapped();
    let device = om.lookup_path(&path("\\Device"), CI).unwrap();
    let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
    let first = om
        .create_device(&device, &uni("First"), ComponentId(7), 70, true)
        .unwrap();
    let second = om
        .create_device(&device, &uni("Second"), ComponentId(7), 71, true)
        .unwrap();
    om.create_symbolic_link_target(
        &dosdev,
        &uni("Nested"),
        uni("\\Device\\Second\\Parent\\"),
        true,
    )
    .unwrap();
    om.create_symbolic_link(&dosdev, &uni("Drive"), path("\\??\\Nested"), true)
        .unwrap();
    let target = om
        .resolve_file_target(uni("\\??\\Drive\\Child\\").as_units(), CI)
        .unwrap();
    assert_eq!(target.device_object, second.id());
    assert_ne!(target.device_object, first.id());
    assert_eq!(target.remaining_name, uni("\\Parent\\Child\\").as_units());
    assert_eq!(
        om.resolve_file_target(uni("\\??\\Drive\\\\Child\\").as_units(), CI)
            .unwrap()
            .remaining_name,
        uni("\\Parent\\\\Child\\").as_units()
    );
    om.remove_named_object(&dosdev, &uni("Drive"), CI).unwrap();
    om.create_symbolic_link(&dosdev, &uni("Drive"), path("\\Device\\First"), true)
        .unwrap();
    let changed = om
        .resolve_file_target(uni("\\??\\Drive\\Child\\").as_units(), CI)
        .unwrap();
    assert_eq!(changed.device_object, first.id());
    assert_eq!(changed.remaining_name, uni("\\Child\\").as_units());
}

#[test]
fn directory_alias_restarts_namespace_without_duplicating_boundary_separator() {
    let mut om = bootstrapped();
    let device = om.lookup_path(&path("\\Device"), CI).unwrap();
    let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
    let volume = om
        .create_device(&device, &uni("RootAlias"), ComponentId(7), 70, true)
        .unwrap();
    om.create_symbolic_link(&dosdev, &uni("Root"), path("\\"), true)
        .unwrap();
    om.create_symbolic_link_target(&dosdev, &uni("Devices"), uni("\\Device\\"), true)
        .unwrap();
    assert_eq!(
        om.resolve_file_target(uni("\\??\\Devices\\RootAlias\\Leaf\\").as_units(), CI),
        Ok(FilePathTarget {
            device_object: volume.id(),
            remaining_name: uni("\\Leaf\\").as_units().to_vec(),
        })
    );
    assert_eq!(
        om.resolve_file_target(uni("\\??\\Root\\Device\\RootAlias\\Leaf\\").as_units(), CI),
        Ok(FilePathTarget {
            device_object: volume.id(),
            remaining_name: uni("\\Leaf\\").as_units().to_vec(),
        })
    );
}

#[test]
fn malformed_namespace_and_non_namespace_link_targets_fail() {
    let mut om = bootstrapped();
    let dosdev = om.lookup_path(&path("\\??"), CI).unwrap();
    om.create_symbolic_link_target(&dosdev, &uni("Relative"), uni("C:\\Windows"), true)
        .unwrap();
    for input in ["", "Device\\Volume", "\\\\Device", "\\Device\\\\Volume"] {
        assert_eq!(
            om.resolve_file_target(uni(input).as_units(), CI),
            Err(NtStatus::INVALID_PARAMETER),
            "{input}"
        );
    }
    for (input, status) in [
        ("\\", NtStatus::OBJECT_PATH_NOT_FOUND),
        ("\\??\\Relative\\Leaf", NtStatus::OBJECT_PATH_NOT_FOUND),
        ("\\Device\\Absent", NtStatus::OBJECT_NAME_NOT_FOUND),
        ("\\Device\\Absent\\Leaf", NtStatus::OBJECT_PATH_NOT_FOUND),
    ] {
        assert_eq!(
            om.resolve_file_target(uni(input).as_units(), CI),
            Err(status),
            "{input}"
        );
    }
}
