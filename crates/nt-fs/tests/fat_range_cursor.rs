use nt_fs::FatRangeCursor;

const CLUSTERS: usize = 2_048;
const CLUSTER_BYTES: usize = 512;
const PAGE_BYTES: usize = 4_096;
const END_OF_CHAIN: u32 = 0x0fff_ffff;

fn fragmented_chain() -> (u32, Vec<u32>, Vec<u8>) {
    let mut links = vec![END_OF_CHAIN; 3_100];
    let mut data = vec![0; links.len() * CLUSTER_BYTES];
    let cluster = |index: usize| 1_000 + ((index * 17) % CLUSTERS) as u32;
    for index in 0..CLUSTERS {
        let current = cluster(index) as usize;
        links[current] = if index + 1 == CLUSTERS {
            END_OF_CHAIN
        } else {
            cluster(index + 1)
        };
        data[current * CLUSTER_BYTES..(current + 1) * CLUSTER_BYTES]
            .fill((index % 251) as u8);
    }
    (cluster(0), links, data)
}

#[test]
fn sequential_fragmented_four_kib_reads_reuse_verified_chain_position() {
    let (first, links, data) = fragmented_chain();
    let file_size = (CLUSTERS * CLUSTER_BYTES) as u32;
    let mut cursor = FatRangeCursor::new();
    let mut fat_reads = 0;
    let mut data_reads = 0;
    for page in 0..file_size as usize / PAGE_BYTES {
        let offset = page * PAGE_BYTES;
        let mut cluster = cursor
            .locate(first, file_size, (offset / CLUSTER_BYTES) as u32, |cluster| {
                fat_reads += 1;
                links[cluster as usize]
            })
            .unwrap();
        let mut bytes = [0; PAGE_BYTES];
        for part in 0..PAGE_BYTES / CLUSTER_BYTES {
            let start = cluster as usize * CLUSTER_BYTES;
            bytes[part * CLUSTER_BYTES..(part + 1) * CLUSTER_BYTES]
                .copy_from_slice(&data[start..start + CLUSTER_BYTES]);
            data_reads += 1;
            if part + 1 != PAGE_BYTES / CLUSTER_BYTES {
                fat_reads += 1;
                cluster = links[cluster as usize];
            }
        }
        for part in 0..PAGE_BYTES / CLUSTER_BYTES {
            assert!(bytes[part * CLUSTER_BYTES..(part + 1) * CLUSTER_BYTES]
                .iter()
                .all(|byte| *byte == ((page * 8 + part) % 251) as u8));
        }
    }
    assert_eq!(data_reads, CLUSTERS);
    assert!(fat_reads <= 3 * CLUSTERS, "{fat_reads} FAT reads for {CLUSTERS} clusters");
}

#[test]
fn backward_seek_and_file_change_restart_at_the_correct_first_cluster() {
    let (first, links, _) = fragmented_chain();
    let mut cursor = FatRangeCursor::new();
    let size = (CLUSTERS * CLUSTER_BYTES) as u32;
    let mut next = |cluster: u32| links[cluster as usize];
    let far = cursor.locate(first, size, 400, &mut next).unwrap();
    assert_eq!(far, 1_000 + ((400 * 17) % CLUSTERS) as u32);
    assert_eq!(cursor.locate(first, size, 2, &mut next), Some(1_034));
    assert_eq!(cursor.locate(first, size - 1, 2, &mut next), Some(1_034));
    assert_eq!(cursor.locate(first + 17, size, 1, &mut next), Some(1_034));
}
