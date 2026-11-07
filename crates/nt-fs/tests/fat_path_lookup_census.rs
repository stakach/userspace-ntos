use nt_fs::FatPathLookupCensus;

#[test]
fn bounded_parent_candidates_keep_hot_cluster_without_exact_frequency_claim() {
    let mut census = FatPathLookupCensus::<3>::new();
    census.begin();
    for _ in 0..10 { census.directory_sector(42); }
    for parent in 100..110 { census.directory_sector(parent); }
    for _ in 0..10 { census.directory_sector(42); }
    census.found();
    census.begin();
    census.not_found();
    assert_eq!((census.lookups(), census.found_count(), census.not_found_count()), (2, 1, 1));
    assert_eq!(census.directory_sectors(), 30);
    assert!((0..3).filter_map(|index| census.parent_candidate(index)).any(|(cluster, estimate)|
        cluster == 42 && estimate > 0));
}
