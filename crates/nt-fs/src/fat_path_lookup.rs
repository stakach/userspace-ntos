//! Resumable installed FAT path lookup over caller-supplied sector snapshots.

use alloc::vec::Vec;

use crate::{FatDirectoryDecoder, FatDirectoryRecord, FatDirectorySlot};

const FAT_EOC_MIN: u32 = 0x0fff_fff8;
const FAT_BAD_CLUSTER: u32 = 0x0fff_fff7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatPathGeometry {
    pub fat_start_sector: u32,
    pub data_start_sector: u32,
    pub total_sectors: u32,
    pub sectors_per_cluster: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatPathRequestKind { Directory, Fat }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatPathRequest {
    pub sector: u32,
    pub kind: FatPathRequestKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatPathProgress { Pending, Found, NotFound }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatPathError { Invalid, NoCapacity, WrongRequest, Corrupt }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Directory, Fat, Found, NotFound }

pub struct FatPathLookup {
    geometry: FatPathGeometry,
    path: Vec<u8>,
    component_start: usize,
    component_end: usize,
    directory_cluster: u32,
    cluster: u32,
    sector_in_cluster: u32,
    file_index: u32,
    decoder: FatDirectoryDecoder,
    visited: Vec<u32>,
    found: Option<FatDirectoryRecord>,
    phase: Phase,
}

impl FatPathLookup {
    pub fn new(geometry: FatPathGeometry, start_cluster: u32, path: &[u8]) -> Result<Self, FatPathError> {
        let data_clusters = geometry.total_sectors.checked_sub(geometry.data_start_sector)
            .and_then(|remaining| remaining.checked_div(geometry.sectors_per_cluster))
            .ok_or(FatPathError::Invalid)?;
        let fat_sectors = data_clusters.checked_add(2)
            .and_then(|entries| entries.checked_mul(4))
            .map(|bytes| bytes.div_ceil(512))
            .ok_or(FatPathError::Invalid)?;
        if geometry.fat_start_sector >= geometry.data_start_sector
            || geometry.data_start_sector >= geometry.total_sectors
            || geometry.sectors_per_cluster == 0
            || geometry.fat_start_sector.checked_add(fat_sectors).is_none_or(|end| end > geometry.data_start_sector)
            || start_cluster < 2
            || !valid_cluster(geometry, start_cluster)
            || path.last().is_some_and(|byte| *byte == b'\\' || *byte == b'/')
            || path.iter().any(|byte| *byte > 0x7f || *byte == 0)
        {
            return Err(FatPathError::Invalid);
        }
        let (component_start, component_end) = next_component(path, 0).ok_or(FatPathError::Invalid)?;
        let mut owned_path = Vec::new();
        owned_path.try_reserve_exact(path.len()).map_err(|_| FatPathError::NoCapacity)?;
        owned_path.extend_from_slice(path);
        let mut visited = Vec::new();
        visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
        visited.push(start_cluster);
        Ok(Self {
            geometry,
            path: owned_path,
            component_start,
            component_end,
            directory_cluster: start_cluster,
            cluster: start_cluster,
            sector_in_cluster: 0,
            file_index: 0,
            decoder: FatDirectoryDecoder::new(),
            visited,
            found: None,
            phase: Phase::Directory,
        })
    }

    pub fn request(&self) -> Option<FatPathRequest> {
        let (sector, kind) = match self.phase {
            Phase::Directory => {
                let base = self.geometry.data_start_sector.checked_add(
                    (self.cluster - 2).checked_mul(self.geometry.sectors_per_cluster)?
                )?;
                (base.checked_add(self.sector_in_cluster)?, FatPathRequestKind::Directory)
            }
            Phase::Fat => {
                let byte = self.cluster.checked_mul(4)?;
                (self.geometry.fat_start_sector.checked_add(byte / 512)?, FatPathRequestKind::Fat)
            }
            Phase::Found | Phase::NotFound => return None,
        };
        let limit = if kind == FatPathRequestKind::Fat { self.geometry.data_start_sector } else { self.geometry.total_sectors };
        (sector < limit).then_some(FatPathRequest { sector, kind })
    }

    pub fn feed(&mut self, request: FatPathRequest, bytes: &[u8; 512]) -> Result<FatPathProgress, FatPathError> {
        if self.request() != Some(request) { return Err(FatPathError::WrongRequest); }
        match request.kind {
            FatPathRequestKind::Directory => self.feed_directory(bytes),
            FatPathRequestKind::Fat => self.feed_fat(bytes),
        }
    }

    pub fn take_found(&mut self) -> Option<FatDirectoryRecord> {
        if self.phase != Phase::Found { return None; }
        self.found.take()
    }

    fn feed_directory(&mut self, bytes: &[u8; 512]) -> Result<FatPathProgress, FatPathError> {
        let cluster_bytes = self.geometry.sectors_per_cluster.checked_mul(512).ok_or(FatPathError::Corrupt)?;
        for slot in bytes.chunks_exact(32) {
            let mut raw = [0; 32];
            raw.copy_from_slice(slot);
            let decoded = self.decoder.consume(&raw, self.file_index, cluster_bytes);
            self.file_index = self.file_index.checked_add(32).ok_or(FatPathError::Corrupt)?;
            match decoded {
                FatDirectorySlot::End => {
                    self.phase = Phase::NotFound;
                    return Ok(FatPathProgress::NotFound);
                }
                FatDirectorySlot::Skipped => {}
                FatDirectorySlot::Entry(record) if name_matches(record.entry.name(), &self.path[self.component_start..self.component_end])
                    || name_matches(record.entry.short_name(), &self.path[self.component_start..self.component_end]) => {
                    let record = record.with_parent_cluster(self.directory_cluster);
                    if let Some((start, end)) = next_component(&self.path, self.component_end) {
                        if !record.metadata().is_directory {
                            self.phase = Phase::NotFound;
                            return Ok(FatPathProgress::NotFound);
                        }
                        if !valid_cluster(self.geometry, record.first_cluster) {
                            return Err(FatPathError::Corrupt);
                        }
                        self.component_start = start;
                        self.component_end = end;
                        self.directory_cluster = record.first_cluster;
                        self.cluster = record.first_cluster;
                        self.sector_in_cluster = 0;
                        self.file_index = 0;
                        self.decoder = FatDirectoryDecoder::new();
                        self.visited.clear();
                        self.visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
                        self.visited.push(record.first_cluster);
                        return Ok(FatPathProgress::Pending);
                    }
                    self.found = Some(record);
                    self.phase = Phase::Found;
                    return Ok(FatPathProgress::Found);
                }
                FatDirectorySlot::Entry(_) => {}
            }
        }
        self.sector_in_cluster = self.sector_in_cluster.checked_add(1).ok_or(FatPathError::Corrupt)?;
        if self.sector_in_cluster == self.geometry.sectors_per_cluster {
            self.phase = Phase::Fat;
        }
        Ok(FatPathProgress::Pending)
    }

    fn feed_fat(&mut self, bytes: &[u8; 512]) -> Result<FatPathProgress, FatPathError> {
        let byte = self.cluster.checked_mul(4).ok_or(FatPathError::Corrupt)?;
        let offset = (byte % 512) as usize;
        let next = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) & 0x0fff_ffff;
        if next >= FAT_EOC_MIN {
            self.phase = Phase::NotFound;
            return Ok(FatPathProgress::NotFound);
        }
        if next == FAT_BAD_CLUSTER || !valid_cluster(self.geometry, next) || self.visited.contains(&next) {
            return Err(FatPathError::Corrupt);
        }
        self.visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
        self.visited.push(next);
        self.cluster = next;
        self.sector_in_cluster = 0;
        self.phase = Phase::Directory;
        Ok(FatPathProgress::Pending)
    }
}

fn next_component(path: &[u8], after: usize) -> Option<(usize, usize)> {
    let start = (after..path.len()).find(|index| path[*index] != b'\\' && path[*index] != b'/')?;
    let end = (start..path.len()).find(|index| path[*index] == b'\\' || path[*index] == b'/').unwrap_or(path.len());
    Some((start, end))
}

fn name_matches(name: &[u16], wanted: &[u8]) -> bool {
    name.len() == wanted.len() && name.iter().zip(wanted).all(|(unit, byte)|
        *unit <= 0x7f && (*unit as u8).eq_ignore_ascii_case(byte))
}

fn valid_cluster(geometry: FatPathGeometry, cluster: u32) -> bool {
    if cluster < 2 || cluster >= FAT_BAD_CLUSTER { return false; }
    let data_clusters = (geometry.total_sectors - geometry.data_start_sector) / geometry.sectors_per_cluster;
    cluster.checked_sub(2).is_some_and(|index| index < data_clusters)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry() -> FatPathGeometry {
        FatPathGeometry {
            fat_start_sector: 1,
            data_start_sector: 100,
            total_sectors: 200,
            sectors_per_cluster: 1,
        }
    }

    fn entry(name: &[u8; 11], directory: bool, first_cluster: u32, size: u32) -> [u8; 512] {
        let mut bytes = [0; 512];
        bytes[..11].copy_from_slice(name);
        bytes[11] = if directory { 0x10 } else { 0x20 };
        bytes[26..28].copy_from_slice(&(first_cluster as u16).to_le_bytes());
        bytes[28..32].copy_from_slice(&size.to_le_bytes());
        bytes
    }

    #[test]
    fn nested_lookup_retains_exact_sector_progress() {
        let mut lookup = FatPathLookup::new(geometry(), 2, b"windows\\file.txt").unwrap();
        let root = lookup.request().unwrap();
        assert_eq!(root, FatPathRequest { sector: 100, kind: FatPathRequestKind::Directory });
        assert_eq!(lookup.feed(root, &entry(b"WINDOWS    ", true, 3, 0)), Ok(FatPathProgress::Pending));
        let child = lookup.request().unwrap();
        assert_eq!(child, FatPathRequest { sector: 101, kind: FatPathRequestKind::Directory });
        assert_eq!(lookup.feed(root, &[0; 512]), Err(FatPathError::WrongRequest));
        assert_eq!(lookup.feed(child, &entry(b"FILE    TXT", false, 4, 4)), Ok(FatPathProgress::Found));
        let found = lookup.take_found().unwrap();
        assert_eq!(found.first_cluster, 4);
        assert_eq!(found.metadata().end_of_file, 4);
        assert_eq!(found.metadata().file_id >> 32, 3);
    }

    #[test]
    fn scans_fat_link_once_and_rejects_chain_cycle() {
        let mut lookup = FatPathLookup::new(geometry(), 2, b"missing.txt").unwrap();
        let first = lookup.request().unwrap();
        let mut sector = entry(b"OTHER   TXT", false, 4, 4);
        sector[32] = 0xe5;
        for offset in (64..512).step_by(32) { sector[offset] = 0xe5; }
        assert_eq!(lookup.feed(first, &sector), Ok(FatPathProgress::Pending));
        let fat = lookup.request().unwrap();
        assert_eq!(fat, FatPathRequest { sector: 1, kind: FatPathRequestKind::Fat });
        let mut links = [0; 512];
        links[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(lookup.feed(fat, &links), Err(FatPathError::Corrupt));
    }

    #[test]
    fn missing_final_entry_is_distinct_from_io_failure() {
        let mut lookup = FatPathLookup::new(geometry(), 2, b"missing.txt").unwrap();
        let request = lookup.request().unwrap();
        assert_eq!(lookup.feed(request, &[0; 512]), Ok(FatPathProgress::NotFound));
        assert_eq!(lookup.request(), None);
    }

    #[test]
    fn libernt_fonts_directory_finds_names_across_real_fat_sector_chain() {
        // These five immutable sector snapshots come from the pinned LiberNT installed tree
        // staged in our Simpleboot FAT image. The live win32k trace reports ZwOpenFile failures
        // for some names even though neighboring names in the same directory succeed.
        let fixture = include_str!("../tests/fixtures/libernt_fonts_directory.hex");
        let geometry = FatPathGeometry {
            fat_start_sector: 8,
            data_start_sector: 32_728,
            total_sectors: 2_093_056,
            sectors_per_cluster: 1,
        };
        for name in [
            b"georgiaz.ttf".as_slice(),
            b"palab.ttf",
            b"symbol.ttf",
            b"couri.ttf",
            b"SourceSansPro-It.ttf",
            b"FSEX301-L2.ttf",
        ] {
            let mut lookup = FatPathLookup::new(geometry, 379_146, name).unwrap();
            for _ in 0..8 {
                let request = lookup.request().expect("font directory lookup still pending");
                let sector = fixture.lines().filter(|line| !line.starts_with('#'))
                    .find_map(|line| {
                        let (number, hex) = line.split_once(' ')?;
                        (number.parse::<u32>().ok()? == request.sector).then_some(hex)
                    })
                    .expect("requested sector must be in captured directory chain");
                let mut bytes = [0u8; 512];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&sector[index * 2..index * 2 + 2], 16)
                        .expect("fixture contains hexadecimal sector bytes");
                }
                match lookup.feed(request, &bytes).unwrap() {
                    FatPathProgress::Found => {
                        let found = lookup.take_found().expect("found directory record");
                        assert!(name_matches(found.entry.name(), name),
                            "wrong installed font entry for {:?}", name);
                        break;
                    }
                    FatPathProgress::Pending => {}
                    FatPathProgress::NotFound => panic!("pinned font was not found: {:?}", name),
                }
            }
            assert!(lookup.request().is_none(), "lookup exceeded captured sector chain");
        }
    }
}
