//! Pure FAT directory-slot decoding for native directory queries.

use crate::{DirectoryEntry, MAX_DIRECTORY_NAME};

const LFN_ATTRIBUTE: u8 = 0x0f;
const VOLUME_ID_ATTRIBUTE: u8 = 0x08;
const LFN_LAST: u8 = 0x40;
const LFN_ORDINAL_MASK: u8 = 0x1f;
const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatDirectoryRecord {
    pub entry: DirectoryEntry,
    pub first_cluster: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatDirectorySlot {
    End,
    Skipped,
    Entry(FatDirectoryRecord),
}

#[derive(Clone, Copy)]
struct LongNameState {
    active: bool,
    checksum: u8,
    expected_ordinal: u8,
    units: u16,
    name: [u16; MAX_DIRECTORY_NAME],
}

impl LongNameState {
    const fn new() -> Self {
        Self {
            active: false,
            checksum: 0,
            expected_ordinal: 0,
            units: 0,
            name: [0xffff; MAX_DIRECTORY_NAME],
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

pub struct FatDirectoryDecoder {
    long_name: LongNameState,
}

impl FatDirectoryDecoder {
    pub const fn new() -> Self {
        Self {
            long_name: LongNameState::new(),
        }
    }

    pub fn consume(
        &mut self,
        slot: &[u8; 32],
        file_index: u32,
        cluster_bytes: u32,
    ) -> FatDirectorySlot {
        match slot[0] {
            0x00 => {
                self.long_name.reset();
                return FatDirectorySlot::End;
            }
            0xe5 => {
                self.long_name.reset();
                return FatDirectorySlot::Skipped;
            }
            _ => {}
        }

        let attributes = slot[11];
        if attributes == LFN_ATTRIBUTE {
            self.consume_long_name(slot);
            return FatDirectorySlot::Skipped;
        }
        if attributes & VOLUME_ID_ATTRIBUTE != 0 {
            self.long_name.reset();
            return FatDirectorySlot::Skipped;
        }

        let mut short_raw = [0u8; 11];
        short_raw.copy_from_slice(&slot[..11]);
        let long_name_len = self.finish_long_name(&short_raw);
        let mut record = FatDirectoryRecord {
            entry: DirectoryEntry::default(),
            first_cluster: ((read_u16(slot, 20) as u32) << 16 | read_u16(slot, 26) as u32)
                & 0x0fff_ffff,
        };
        record.entry.file_index = file_index;
        record.entry.file_id = file_index as u64;
        record.entry.attributes = attributes as u32;
        record.entry.end_of_file = read_u32(slot, 28) as u64;
        record.entry.allocation_size = allocation_size(record.entry.end_of_file, cluster_bytes);
        record.entry.creation_time = fat_timestamp(
            read_u16(slot, 16),
            read_u16(slot, 14),
            slot[13],
        );
        record.entry.last_access_time = fat_timestamp(read_u16(slot, 18), 0, 0);
        record.entry.last_write_time = fat_timestamp(read_u16(slot, 24), read_u16(slot, 22), 0);
        record.entry.change_time = record.entry.last_write_time;

        if let Some(length) = long_name_len {
            let _ = record.entry.set_name(&self.long_name.name[..length]);
            let mut alias = [0u16; 12];
            let alias_len = decode_short_name(&short_raw, slot[12], false, &mut alias);
            let _ = record.entry.set_short_name(&alias[..alias_len]);
        } else {
            let mut name = [0u16; 12];
            let name_len = decode_short_name(&short_raw, slot[12], true, &mut name);
            let _ = record.entry.set_name(&name[..name_len]);
        }
        self.long_name.reset();
        FatDirectorySlot::Entry(record)
    }

    fn consume_long_name(&mut self, slot: &[u8; 32]) {
        let raw_ordinal = slot[0];
        let ordinal = raw_ordinal & LFN_ORDINAL_MASK;
        let last = raw_ordinal & LFN_LAST != 0;
        let structurally_valid = ordinal != 0
            && ordinal <= 20
            && slot[12] == 0
            && read_u16(slot, 26) == 0;
        if !structurally_valid {
            self.long_name.reset();
            return;
        }
        if last {
            self.long_name.reset();
            self.long_name.active = true;
            self.long_name.checksum = slot[13];
            self.long_name.expected_ordinal = ordinal;
            self.long_name.units = (ordinal as u16) * 13;
        }
        if !self.long_name.active
            || self.long_name.checksum != slot[13]
            || self.long_name.expected_ordinal != ordinal
        {
            self.long_name.reset();
            return;
        }
        let base = (ordinal as usize - 1) * 13;
        for (index, offset) in LFN_OFFSETS.iter().enumerate() {
            self.long_name.name[base + index] = read_u16(slot, *offset);
        }
        self.long_name.expected_ordinal = ordinal - 1;
    }

    fn finish_long_name(&self, short_name: &[u8; 11]) -> Option<usize> {
        if !self.long_name.active
            || self.long_name.expected_ordinal != 0
            || self.long_name.checksum != fat_short_name_checksum(short_name)
        {
            return None;
        }
        let units = self.long_name.units as usize;
        if units > self.long_name.name.len() {
            return None;
        }
        let mut length = units;
        for index in 0..units {
            match self.long_name.name[index] {
                0 => {
                    length = index;
                    if self.long_name.name[index + 1..units]
                        .iter()
                        .any(|unit| *unit != 0xffff)
                    {
                        return None;
                    }
                    break;
                }
                0xffff => return None,
                _ => {}
            }
        }
        (length <= 255).then_some(length)
    }
}

impl Default for FatDirectoryDecoder {
    fn default() -> Self {
        Self::new()
    }
}

pub fn fat_short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |checksum, byte| {
        checksum.rotate_right(1).wrapping_add(*byte)
    })
}

fn decode_short_name(
    raw: &[u8; 11],
    nt_case: u8,
    restore_case: bool,
    output: &mut [u16; 12],
) -> usize {
    let base_len = raw[..8]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    let extension_len = raw[8..]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1);
    let mut length = 0;
    for (index, byte) in raw[..base_len].iter().copied().enumerate() {
        let byte = if index == 0 && byte == 0x05 { 0xe5 } else { byte };
        output[length] = short_character(byte, restore_case && nt_case & 0x08 != 0);
        length += 1;
    }
    if extension_len != 0 {
        output[length] = b'.' as u16;
        length += 1;
        for byte in raw[8..8 + extension_len].iter().copied() {
            output[length] = short_character(byte, restore_case && nt_case & 0x10 != 0);
            length += 1;
        }
    }
    length
}

fn short_character(byte: u8, lowercase: bool) -> u16 {
    if lowercase && byte.is_ascii_uppercase() {
        (byte + 32) as u16
    } else {
        byte as u16
    }
}

fn read_u16(slot: &[u8; 32], offset: usize) -> u16 {
    u16::from_le_bytes([slot[offset], slot[offset + 1]])
}

fn read_u32(slot: &[u8; 32], offset: usize) -> u32 {
    u32::from_le_bytes([
        slot[offset],
        slot[offset + 1],
        slot[offset + 2],
        slot[offset + 3],
    ])
}

fn allocation_size(size: u64, cluster_bytes: u32) -> u64 {
    if size == 0 || cluster_bytes == 0 {
        return 0;
    }
    let cluster_bytes = cluster_bytes as u64;
    size.saturating_add(cluster_bytes - 1) / cluster_bytes * cluster_bytes
}

fn fat_timestamp(date: u16, time: u16, creation_fraction: u8) -> u64 {
    let year = 1980u32 + ((date >> 9) & 0x7f) as u32;
    let month = ((date >> 5) & 0x0f) as u32;
    let day = (date & 0x1f) as u32;
    let hour = ((time >> 11) & 0x1f) as u32;
    let minute = ((time >> 5) & 0x3f) as u32;
    let second = ((time & 0x1f) as u32) * 2;
    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return 0;
    }
    let days = days_before_year(year) + days_before_month(year, month) + day as u64 - 1;
    let seconds = days * 86_400 + hour as u64 * 3_600 + minute as u64 * 60 + second as u64;
    seconds * 10_000_000 + creation_fraction.min(199) as u64 * 100_000
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_before_year(year: u32) -> u64 {
    let previous = year - 1;
    let base = 1600;
    (year - 1601) as u64 * 365
        + (previous / 4 - base / 4) as u64
        - (previous / 100 - base / 100) as u64
        + (previous / 400 - base / 400) as u64
}

fn days_before_month(year: u32, month: u32) -> u64 {
    const DAYS: [u16; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    DAYS[month as usize - 1] as u64 + u64::from(month > 2 && is_leap_year(year))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap_year(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn short_slot(name: [u8; 11]) -> [u8; 32] {
        let mut slot = [0u8; 32];
        slot[..11].copy_from_slice(&name);
        slot[11] = 0x20;
        slot[20..22].copy_from_slice(&1u16.to_le_bytes());
        slot[26..28].copy_from_slice(&2u16.to_le_bytes());
        slot[28..32].copy_from_slice(&513u32.to_le_bytes());
        slot
    }

    fn lfn_slot(ordinal: u8, checksum: u8, text: &[u16]) -> [u8; 32] {
        let mut slot = [0xffu8; 32];
        slot[0] = ordinal;
        slot[11] = LFN_ATTRIBUTE;
        slot[12] = 0;
        slot[13] = checksum;
        slot[26..28].copy_from_slice(&0u16.to_le_bytes());
        for (index, offset) in LFN_OFFSETS.iter().enumerate() {
            let value = text.get(index).copied().unwrap_or(if index == text.len() { 0 } else { 0xffff });
            slot[*offset..*offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        slot
    }

    #[test]
    fn validated_lfn_preserves_utf16_and_alias() {
        let raw = *b"LONGNA~1TXT";
        let checksum = fat_short_name_checksum(&raw);
        let name: std::vec::Vec<u16> = "Long name.txt".encode_utf16().collect();
        let mut decoder = FatDirectoryDecoder::new();
        assert_eq!(decoder.consume(&lfn_slot(0x41, checksum, &name), 0, 4096), FatDirectorySlot::Skipped);
        let FatDirectorySlot::Entry(record) = decoder.consume(&short_slot(raw), 32, 4096) else { panic!() };
        assert_eq!(record.entry.name(), name);
        assert_eq!(record.entry.short_name(), "LONGNA~1.TXT".encode_utf16().collect::<std::vec::Vec<_>>());
        assert_eq!(record.first_cluster, 0x0001_0002);
        assert_eq!(record.entry.allocation_size, 4096);
    }

    #[test]
    fn bad_checksum_falls_back_to_restored_short_name() {
        let raw = *b"README  TXT";
        let mut short = short_slot(raw);
        short[12] = 0x18;
        let mut decoder = FatDirectoryDecoder::new();
        decoder.consume(&lfn_slot(0x41, 7, &"ignored".encode_utf16().collect::<std::vec::Vec<_>>()), 0, 4096);
        let FatDirectorySlot::Entry(record) = decoder.consume(&short, 32, 4096) else { panic!() };
        assert_eq!(record.entry.name(), "readme.txt".encode_utf16().collect::<std::vec::Vec<_>>());
        assert!(record.entry.short_name().is_empty());
    }

    #[test]
    fn descending_multi_slot_lfn_is_required() {
        let raw = *b"LONGNA~1TXT";
        let checksum = fat_short_name_checksum(&raw);
        let name: std::vec::Vec<u16> = "a-name-longer-than-thirteen.txt".encode_utf16().collect();
        let mut decoder = FatDirectoryDecoder::new();
        decoder.consume(&lfn_slot(0x43, checksum, &name[26..]), 0, 4096);
        decoder.consume(&lfn_slot(2, checksum, &name[13..26]), 32, 4096);
        decoder.consume(&lfn_slot(1, checksum, &name[..13]), 64, 4096);
        let FatDirectorySlot::Entry(record) = decoder.consume(&short_slot(raw), 96, 4096) else { panic!() };
        assert_eq!(record.entry.name(), name);

        let mut decoder = FatDirectoryDecoder::new();
        decoder.consume(&lfn_slot(0x43, checksum, &name[26..]), 0, 4096);
        decoder.consume(&lfn_slot(1, checksum, &name[..13]), 32, 4096);
        let FatDirectorySlot::Entry(record) = decoder.consume(&short_slot(raw), 64, 4096) else { panic!() };
        assert_eq!(record.entry.name(), "LONGNA~1.TXT".encode_utf16().collect::<std::vec::Vec<_>>());
    }

    #[test]
    fn deleted_and_volume_slots_break_lfn_chain() {
        let raw = *b"FILE    TXT";
        let checksum = fat_short_name_checksum(&raw);
        let mut decoder = FatDirectoryDecoder::new();
        decoder.consume(&lfn_slot(0x41, checksum, &"long.txt".encode_utf16().collect::<std::vec::Vec<_>>()), 0, 4096);
        let mut deleted = [0u8; 32];
        deleted[0] = 0xe5;
        decoder.consume(&deleted, 32, 4096);
        let FatDirectorySlot::Entry(record) = decoder.consume(&short_slot(raw), 64, 4096) else { panic!() };
        assert_eq!(record.entry.name(), "FILE.TXT".encode_utf16().collect::<std::vec::Vec<_>>());

        let mut volume = short_slot(*b"VOLUME     ");
        volume[11] = VOLUME_ID_ATTRIBUTE;
        assert_eq!(decoder.consume(&volume, 96, 4096), FatDirectorySlot::Skipped);
    }

    #[test]
    fn end_marker_and_e5_first_character_are_handled() {
        let mut decoder = FatDirectoryDecoder::new();
        assert_eq!(decoder.consume(&[0u8; 32], 0, 4096), FatDirectorySlot::End);
        let mut raw = *b"FILE    TXT";
        raw[0] = 0x05;
        let FatDirectorySlot::Entry(record) = decoder.consume(&short_slot(raw), 0, 4096) else { panic!() };
        assert_eq!(record.entry.name()[0], 0xe5);
    }

    #[test]
    fn fat_epoch_converts_to_nt_ticks() {
        let date = (1 << 5) | 1;
        assert_eq!(fat_timestamp(date, 0, 0), 119_600_064_000_000_000);
        assert_eq!(fat_timestamp(0, 0, 0), 0);
    }
}
