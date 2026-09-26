//! Fallible FAT directory traversal for mounted-volume queries.

use alloc::vec::Vec;

use crate::{
    FatDirectoryDecoder, FatDirectoryRecord, FatDirectorySlot, STATUS_DATA_ERROR,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
};

const FAT_EOC_MIN: u32 = 0x0fff_fff8;
const FAT_BAD_CLUSTER: u32 = 0x0fff_fff7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatDirectoryGeometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub data_start_sector: u32,
    pub total_sectors: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatDirectoryWalkEnd {
    Complete,
    VisitorStopped,
}

/// Reads a complete directory stream or reports the first disk/chain error. A visitor stop is
/// separate from completion so a caller cannot treat an interrupted listing as exhaustive.
pub fn walk_fat_directory(
    geometry: FatDirectoryGeometry,
    directory_cluster: u32,
    mut read_sector: impl FnMut(u32) -> Result<[u8; 512], u32>,
    mut next_cluster: impl FnMut(u32) -> Result<u32, u32>,
    mut visit: impl FnMut(FatDirectoryRecord) -> bool,
) -> Result<FatDirectoryWalkEnd, u32> {
    if geometry.bytes_per_sector != 512
        || geometry.sectors_per_cluster == 0
        || geometry.data_start_sector >= geometry.total_sectors
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let data_clusters =
        (geometry.total_sectors - geometry.data_start_sector) / geometry.sectors_per_cluster;
    let last_cluster = data_clusters.checked_add(1).ok_or(STATUS_DATA_ERROR)?;
    if directory_cluster < 2 || directory_cluster > last_cluster {
        return Err(STATUS_DATA_ERROR);
    }
    let cluster_bytes = geometry
        .bytes_per_sector
        .checked_mul(geometry.sectors_per_cluster)
        .ok_or(STATUS_DATA_ERROR)?;
    let mut visited = Vec::new();
    let mut decoder = FatDirectoryDecoder::new();
    let mut file_index = 0u32;
    let mut cluster = directory_cluster;
    loop {
        if cluster < 2 || cluster > last_cluster || visited.contains(&cluster) {
            return Err(STATUS_DATA_ERROR);
        }
        visited
            .try_reserve(1)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        visited.push(cluster);
        for sector_in_cluster in 0..geometry.sectors_per_cluster {
            let sector = geometry
                .data_start_sector
                .checked_add(
                    (cluster - 2)
                        .checked_mul(geometry.sectors_per_cluster)
                        .ok_or(STATUS_DATA_ERROR)?,
                )
                .and_then(|base| base.checked_add(sector_in_cluster))
                .filter(|sector| *sector < geometry.total_sectors)
                .ok_or(STATUS_DATA_ERROR)?;
            let bytes = read_sector(sector)?;
            for slot in bytes.chunks_exact(32) {
                let mut record = [0; 32];
                record.copy_from_slice(slot);
                match decoder.consume(&record, file_index, cluster_bytes) {
                    FatDirectorySlot::End => return Ok(FatDirectoryWalkEnd::Complete),
                    FatDirectorySlot::Skipped => {}
                    FatDirectorySlot::Entry(entry) => {
                        if !visit(entry.with_parent_cluster(directory_cluster)) {
                            return Ok(FatDirectoryWalkEnd::VisitorStopped);
                        }
                    }
                }
                file_index = file_index.checked_add(32).ok_or(STATUS_DATA_ERROR)?;
            }
        }
        let next = next_cluster(cluster)?;
        if next >= FAT_EOC_MIN {
            return Ok(FatDirectoryWalkEnd::Complete);
        }
        if next == FAT_BAD_CLUSTER || next < 2 || next > last_cluster {
            return Err(STATUS_DATA_ERROR);
        }
        cluster = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn geometry() -> FatDirectoryGeometry {
        FatDirectoryGeometry {
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            data_start_sector: 10,
            total_sectors: 14,
        }
    }

    fn entry_sector(name: &[u8; 11], terminate: bool) -> [u8; 512] {
        let mut sector = [0xe5; 512];
        sector[..11].copy_from_slice(name);
        sector[11] = 0x20;
        if terminate {
            sector[32] = 0;
        }
        sector
    }

    #[test]
    fn visits_entries_in_stream_order_and_stops_at_end_marker() {
        let mut seen = vec![];
        let result = walk_fat_directory(
            geometry(),
            2,
            |_| Ok(entry_sector(b"README  TXT", true)),
            |_| panic!("end marker must not read FAT"),
            |entry| {
                seen.push(entry);
                true
            },
        );
        assert_eq!(result, Ok(FatDirectoryWalkEnd::Complete));
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].entry.name(),
            "README.TXT".encode_utf16().collect::<Vec<_>>()
        );
        assert_eq!(seen[0].entry.file_id, 2u64 << 32);
    }

    #[test]
    fn sector_error_cannot_be_reported_as_complete_listing() {
        let result = walk_fat_directory(
            geometry(),
            2,
            |_| Err(0xc000_00a3),
            |_| panic!("failed sector must not read FAT"),
            |_| true,
        );
        assert_eq!(result, Err(0xc000_00a3));
    }

    #[test]
    fn fat_error_and_cycles_are_not_end_of_chain() {
        let first = entry_sector(b"README  TXT", false);
        assert_eq!(
            walk_fat_directory(geometry(), 2, |_| Ok(first), |_| Err(0xc000_00a3), |_| true),
            Err(0xc000_00a3)
        );
        assert_eq!(
            walk_fat_directory(
                geometry(),
                2,
                |_| Ok(first),
                |cluster| Ok(if cluster == 2 { 3 } else { 2 }),
                |_| true,
            ),
            Err(STATUS_DATA_ERROR)
        );
        for invalid in [0, FAT_BAD_CLUSTER, 6] {
            assert_eq!(
                walk_fat_directory(geometry(), 2, |_| Ok(first), |_| Ok(invalid), |_| true,),
                Err(STATUS_DATA_ERROR)
            );
        }
    }

    #[test]
    fn invalid_geometry_and_out_of_volume_cluster_never_read_disk() {
        let mut invalid = geometry();
        invalid.bytes_per_sector = 0;
        assert_eq!(
            walk_fat_directory(
                invalid,
                2,
                |_| panic!("invalid geometry"),
                |_| unreachable!(),
                |_| true
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            walk_fat_directory(
                geometry(),
                6,
                |_| panic!("invalid cluster"),
                |_| unreachable!(),
                |_| true
            ),
            Err(STATUS_DATA_ERROR)
        );
    }

    #[test]
    fn visitor_stop_is_distinct_from_exhaustion() {
        let result = walk_fat_directory(
            geometry(),
            2,
            |_| Ok(entry_sector(b"README  TXT", true)),
            |_| panic!("visitor stop must not read FAT"),
            |_| false,
        );
        assert_eq!(result, Ok(FatDirectoryWalkEnd::VisitorStopped));
    }
}
