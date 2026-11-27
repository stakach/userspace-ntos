use super::*;

#[test]
fn checked_provisioning_allocation_failure_preserves_the_whole_tree_and_id_sequence() {
    for file in [false, true] {
        let mut failures = 0usize;
        let mut completed = false;
        for stage in 0..64 {
            let mut fs = FileSystem::new(MemFs::new());
            let before = fs.export_volume_snapshot().unwrap();
            fs.set_snapshot_payload_capacity(before.len() + 8192).unwrap();
            let first_entry = fs.volume.next_entry_id;
            let first_file = fs.volume.next_file_id;
            let first_nodes = fs.volume.nodes.len();
            fs.create_fail_at = Some(stage);
            let result = if file {
                fs.provision_file_relative_checked(b"alpha\\beta\\gamma.dat", b"installed")
            } else {
                fs.provision_directory_relative_checked(b"alpha\\beta\\gamma")
            };
            match result {
                Err(STATUS_INSUFFICIENT_RESOURCES) => {
                    failures += 1;
                    assert_eq!(fs.volume.next_entry_id, first_entry, "stage {stage}");
                    assert_eq!(fs.volume.next_file_id, first_file, "stage {stage}");
                    assert_eq!(fs.volume.nodes.len(), first_nodes, "stage {stage}");
                    assert_eq!(fs.export_volume_snapshot().unwrap(), before, "stage {stage}");
                    assert_eq!(fs.query_metadata_relative(b"alpha"), None, "stage {stage}");
                }
                Ok(true) => { completed = true; break; }
                other => panic!("unexpected result at stage {stage}: {other:?}"),
            }
        }
        assert!(completed, "provisioning never completed after all injected stages");
        assert!(failures > 4, "allocation fault did not reach later parent components");
    }
}

#[test]
fn owned_provisioning_returns_the_image_on_parent_allocation_refusal() {
    let mut fs = FileSystem::new(MemFs::new());
    let before = fs.export_volume_snapshot().unwrap();
    fs.create_fail_at = Some(0);
    let image = b"owned image".to_vec();
    assert_eq!(fs.provision_file_owned(r"\??\C:\alpha\beta\SYSTEM", image.clone()),
        Err(image));
    assert_eq!(fs.query_metadata(r"\??\C:\alpha"), None);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
}
