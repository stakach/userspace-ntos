use nt_fs::FatRangeBatch;

const END: u32 = 0x0fff_ffff;

#[test]
fn contiguous_range_uses_one_bounded_read_and_keeps_partial_sector_bytes() {
    let batch = FatRangeBatch::plan(100, 100, 1_400, 512, 4, |cluster| cluster + 1).unwrap();
    assert_eq!(batch.sectors, 3);
    assert_eq!(batch.skip_bytes, 100);
    assert_eq!(batch.copy_bytes, 1_400);
    assert_eq!(batch.next_cluster, None);

    let disk: Vec<u8> = (0..3 * 512).map(|index| (index % 251) as u8).collect();
    let mut output = vec![0; batch.copy_bytes];
    output.copy_from_slice(&disk[batch.skip_bytes..batch.skip_bytes + batch.copy_bytes]);
    assert_eq!(output, disk[100..1_500]);
}

#[test]
fn fragmented_range_stops_before_the_first_nonadjacent_cluster() {
    let batch = FatRangeBatch::plan(100, 100, 1_400, 512, 4, |cluster| match cluster {
        100 => 104,
        104 => 105,
        _ => END,
    })
    .unwrap();
    assert_eq!(batch.sectors, 1);
    assert_eq!(batch.skip_bytes, 100);
    assert_eq!(batch.copy_bytes, 412);
    assert_eq!(batch.next_cluster, Some(104));
}

#[test]
fn long_contiguous_range_stops_at_the_dma_window() {
    let batch = FatRangeBatch::plan(100, 0, 5_000, 512, 4, |cluster| cluster + 1).unwrap();
    assert_eq!(batch.sectors, 4);
    assert_eq!(batch.copy_bytes, 2_048);
    assert_eq!(batch.next_cluster, Some(104));
}

#[test]
fn invalid_geometry_and_cyclic_fat_links_are_not_batched() {
    assert!(FatRangeBatch::plan(100, 0, 512, 0, 4, |_| END).is_none());
    assert!(FatRangeBatch::plan(100, 512, 512, 512, 4, |_| END).is_none());
    assert!(FatRangeBatch::plan(100, 0, 512, 512, 0, |_| END).is_none());
    let batch = FatRangeBatch::plan(100, 0, 1_024, 512, 4, |_| 100).unwrap();
    assert_eq!(batch.sectors, 1);
    assert_eq!(batch.next_cluster, None);
}

#[test]
fn partial_fragmented_file_range_matches_scalar_bytes_in_four_reads() {
    let mut links = vec![END; 208];
    for cluster in 100..107 {
        links[cluster] = (cluster + 1) as u32;
    }
    links[107] = 200;
    for cluster in 200..207 {
        links[cluster] = (cluster + 1) as u32;
    }
    let mut disk = vec![0; 208 * 512];
    for cluster in 100..108 {
        disk[cluster * 512..(cluster + 1) * 512].fill(cluster as u8);
    }
    for cluster in 200..208 {
        disk[cluster * 512..(cluster + 1) * 512].fill(cluster as u8);
    }
    let logical: Vec<u8> = (100..108)
        .chain(200..208)
        .flat_map(|cluster| disk[cluster * 512..(cluster + 1) * 512].iter().copied())
        .collect();
    let mut output = Vec::new();
    let mut cluster = 100;
    let mut skip = 173;
    let mut reads = 0;
    while output.len() < 6_500 {
        let batch = FatRangeBatch::plan(cluster, skip, 6_500 - output.len(), 512, 4, |current| {
            links[current as usize]
        })
        .unwrap();
        let start = cluster as usize * 512 + batch.skip_bytes;
        output.extend_from_slice(&disk[start..start + batch.copy_bytes]);
        reads += 1;
        if output.len() < 6_500 {
            cluster = batch.next_cluster.unwrap();
            skip = 0;
        }
    }
    assert_eq!(reads, 4);
    assert_eq!(output, logical[173..6_673]);
}
