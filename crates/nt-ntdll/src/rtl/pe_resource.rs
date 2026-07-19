//! PE `.rsrc` resource-directory walker — the pure host-testable core behind
//! `LdrFindResource_U` / `LdrFindResourceDirectory_U` / `LdrAccessResource`.
//!
//! Faithful to `references/reactos/dll/ntdll/rtl/libsupp.c::find_entry` and
//! `references/reactos/sdk/lib/rtl/res.c` (`find_entry_by_id` / `find_entry_by_name` /
//! `find_first_entry`). A PE resource section is a three-level tree of
//! `IMAGE_RESOURCE_DIRECTORY` nodes: level 1 = resource **type** (e.g. `RT_DIALOG`), level 2 =
//! **name/id**, level 3 = **language**; the language leaves point at `IMAGE_RESOURCE_DATA_ENTRY`.
//!
//! Every offset in the tree (`OffsetToDirectory` / `NameOffset`) is relative to the section **root**
//! (the resource-directory RVA base). This core works purely in terms of byte offsets within the
//! section slice: callers pass the `.rsrc` bytes and get back the byte offset (within that slice) of
//! the matched directory or `IMAGE_RESOURCE_DATA_ENTRY`. The DLL wrapper adds `root` to recover the
//! mapped VA. No allocation, no image parsing beyond the resource section — the image-header /
//! directory lookup (`RtlImageDirectoryEntryToData`) is the caller's job.
//!
//! The name matching mirrors `CompareResourceString`: a resource string (`IMAGE_RESOURCE_DIR_STRING_U`
//! = `USHORT Length; WCHAR NameString[Length]`) is compared case-insensitively (upcased) against a
//! NUL-terminated UTF-16 search string. IDs (the low 16 bits when the high bits are clear) use a
//! binary search over the sorted id entries, exactly like ReactOS.

// ---- on-disk layout constants (all little-endian) ----

/// `sizeof(IMAGE_RESOURCE_DIRECTORY)`: Characteristics(4) TimeDateStamp(4) Major(2) Minor(2)
/// NumberOfNamedEntries(2) NumberOfIdEntries(2).
pub const DIR_SIZE: usize = 16;
/// Byte offset of `NumberOfNamedEntries` within an `IMAGE_RESOURCE_DIRECTORY`.
const OFF_NUM_NAMED: usize = 12;
/// Byte offset of `NumberOfIdEntries` within an `IMAGE_RESOURCE_DIRECTORY`.
const OFF_NUM_ID: usize = 14;
/// `sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)`: Name/Id(4) OffsetToData(4).
pub const ENTRY_SIZE: usize = 8;
/// `sizeof(IMAGE_RESOURCE_DATA_ENTRY)`: OffsetToData(4) Size(4) CodePage(4) Reserved(4).
pub const DATA_ENTRY_SIZE: usize = 16;

/// The high bit of the directory-entry `OffsetToData` field = `DataIsDirectory`.
const DATA_IS_DIRECTORY: u32 = 0x8000_0000;
/// The high bit of the directory-entry `Name` field = `NameIsString` (used by the test builder; the
/// walker treats named-directory entries as strings by position, matching ntdll).
#[cfg_attr(not(test), allow(dead_code))]
const NAME_IS_STRING: u32 = 0x8000_0000;

/// A resource selector — an id (`MAKEINTRESOURCE`) or a wide-string name.
///
/// Matches the ntdll convention: a `ULONG_PTR` whose high bits are clear is an integer id (the low
/// 16 bits); otherwise it is a pointer to a NUL-terminated wide string. Here we make that explicit.
#[derive(Clone, Debug)]
pub enum ResName<'a> {
    /// An integer resource id (`MAKEINTRESOURCEW`).
    Id(u16),
    /// A NUL-terminated (the terminator is implicit) UTF-16 name (no length prefix).
    Name(&'a [u16]),
}

/// A single `IMAGE_RESOURCE_DIRECTORY_ENTRY`, decoded.
#[derive(Copy, Clone, Debug)]
struct DirEntry {
    /// The raw Name/Id field.
    name: u32,
    /// The raw OffsetToData field.
    offset: u32,
}

impl DirEntry {
    #[inline]
    fn is_directory(&self) -> bool {
        (self.offset & DATA_IS_DIRECTORY) != 0
    }
    /// The id (low 16 bits) when this entry is keyed by id.
    #[inline]
    fn id(&self) -> u16 {
        (self.name & 0xFFFF) as u16
    }
    /// The name-string offset (bits 0..31) when this entry is keyed by name.
    #[inline]
    fn name_offset(&self) -> usize {
        (self.name & 0x7FFF_FFFF) as usize
    }
    /// The child directory / data offset (bits 0..31), relative to the section root.
    #[inline]
    fn child_offset(&self) -> usize {
        (self.offset & 0x7FFF_FFFF) as usize
    }
}

#[inline]
fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    buf.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
#[inline]
fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read the `(named, id)` entry counts of the directory at `dir_off`.
fn dir_counts(rsrc: &[u8], dir_off: usize) -> Option<(usize, usize)> {
    let named = rd_u16(rsrc, dir_off + OFF_NUM_NAMED)? as usize;
    let id = rd_u16(rsrc, dir_off + OFF_NUM_ID)? as usize;
    Some((named, id))
}

/// Decode the `i`-th entry of the directory at `dir_off` (entries start right after the 16-byte header).
fn dir_entry(rsrc: &[u8], dir_off: usize, i: usize) -> Option<DirEntry> {
    let base = dir_off + DIR_SIZE + i * ENTRY_SIZE;
    Some(DirEntry {
        name: rd_u32(rsrc, base)?,
        offset: rd_u32(rsrc, base + 4)?,
    })
}

/// `CompareResourceString` — case-insensitive (upcased) compare of a NUL-terminated search string
/// against an `IMAGE_RESOURCE_DIR_STRING_U` at `str_off` (USHORT Length; WCHAR NameString[Length]).
/// Returns 0 on equal, matching ReactOS semantics (search string must end exactly at the resource
/// string's end).
fn compare_resource_string(rsrc: &[u8], str_off: usize, search: &[u16]) -> Option<i32> {
    let len = rd_u16(rsrc, str_off)? as usize;
    let mut si = 0usize;
    for k in 0..len {
        let c2 = rd_u16(rsrc, str_off + 2 + k * 2)?;
        // The search string is NUL-terminated; treat missing chars as 0.
        let c1 = search.get(si).copied().unwrap_or(0);
        si += 1;
        if c1 != c2 {
            let u1 = upcase(c1);
            let u2 = upcase(c2);
            if u1 != u2 {
                return Some(u1 as i32 - u2 as i32);
            }
        }
    }
    // All resource chars matched; the search string must end here too.
    if search.get(si).copied().unwrap_or(0) != 0 {
        Some(1)
    } else {
        Some(0)
    }
}

#[inline]
fn upcase(c: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&c) {
        c - (b'a' as u16 - b'A' as u16)
    } else {
        c
    }
}

/// `find_entry_by_id` — binary-search the id entries for `id`, returning the child offset if the
/// entry's directory-ness matches `want_dir`.
fn find_entry_by_id(rsrc: &[u8], dir_off: usize, id: u16, want_dir: bool) -> Option<usize> {
    let (named, ids) = dir_counts(rsrc, dir_off)?;
    if ids == 0 {
        return None;
    }
    let mut min = named as isize;
    let mut max = (named + ids) as isize - 1;
    while min <= max {
        let pos = (min + max) / 2;
        let e = dir_entry(rsrc, dir_off, pos as usize)?;
        if e.id() == id {
            if e.is_directory() == want_dir {
                return Some(e.child_offset());
            }
            break;
        }
        if e.id() > id {
            max = pos - 1;
        } else {
            min = pos + 1;
        }
    }
    None
}

/// `find_entry_by_name` — for an integer name, defer to `find_entry_by_id`; for a string name,
/// binary-search the named entries (case-insensitive compare).
fn find_entry_by_name(rsrc: &[u8], dir_off: usize, name: &ResName, want_dir: bool) -> Option<usize> {
    let search = match name {
        ResName::Id(id) => return find_entry_by_id(rsrc, dir_off, *id, want_dir),
        ResName::Name(s) => *s,
    };
    let (named, _ids) = dir_counts(rsrc, dir_off)?;
    if named == 0 {
        return None;
    }
    let mut min = 0isize;
    let mut max = named as isize - 1;
    while min <= max {
        let pos = (min + max) / 2;
        let e = dir_entry(rsrc, dir_off, pos as usize)?;
        // Named entries always have NameIsString set; the string lives at root+NameOffset.
        let str_off = e.name_offset();
        let res = compare_resource_string(rsrc, str_off, search)?;
        if res == 0 {
            if e.is_directory() == want_dir {
                return Some(e.child_offset());
            }
            break;
        }
        if res < 0 {
            max = pos - 1;
        } else {
            min = pos + 1;
        }
    }
    None
}

/// `find_first_entry` — the first entry whose directory-ness matches `want_dir` (used for the
/// LANG_NEUTRAL "just take the first language" fallback).
fn find_first_entry(rsrc: &[u8], dir_off: usize, want_dir: bool) -> Option<usize> {
    let (named, ids) = dir_counts(rsrc, dir_off)?;
    for pos in 0..(named + ids) {
        let e = dir_entry(rsrc, dir_off, pos)?;
        if e.is_directory() == want_dir {
            return Some(e.child_offset());
        }
    }
    None
}

/// The result of a resource lookup: the byte offset (within the `.rsrc` slice) of the matched node.
///
/// For a data lookup (`want_dir == false`, `level == 3`) this is an `IMAGE_RESOURCE_DATA_ENTRY`;
/// for a directory lookup it is an `IMAGE_RESOURCE_DIRECTORY`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FindResult {
    /// Byte offset within the resource section (add `root` for the mapped VA).
    pub offset: usize,
}

/// The status categories `find_entry` distinguishes (mapped to NTSTATUS by the caller).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FindStatus {
    /// Located.
    Success,
    /// The type level had no match (`STATUS_RESOURCE_TYPE_NOT_FOUND`).
    TypeNotFound,
    /// The name level had no match (`STATUS_RESOURCE_NAME_NOT_FOUND`).
    NameNotFound,
    /// The language level had no match (`STATUS_RESOURCE_LANG_NOT_FOUND`).
    LangNotFound,
    /// `level > 3` (`STATUS_INVALID_PARAMETER`).
    InvalidParameter,
    /// The resource section is malformed / truncated (`STATUS_RESOURCE_DATA_NOT_FOUND`).
    DataNotFound,
}

/// `find_entry` — walk the resource tree by `(type, name, language)` down to `level` levels.
///
/// * `rsrc` is the resource-section bytes (starting at the section root).
/// * `level` is the ntdll `Level` (1 = type, 2 = +name, 3 = +language). Levels above the requested
///   one are ignored.
/// * `want_dir` = TRUE returns the directory node at the requested level; FALSE returns the data
///   entry (only meaningful at level 3).
/// * `languages` is the ordered list of language ids to try at the language level (the ntdll default
///   list — caller-supplied; usually `[requested, neutral, 0, LANG_ENGLISH]`). If empty and the
///   requested language is neutral, the first entry is taken.
/// * `neutral_first_fallback` mirrors ntdll's `PRIMARYLANGID(Language) == LANG_NEUTRAL` "return the
///   first entry" fallback after the language list is exhausted.
pub fn find_entry(
    rsrc: &[u8],
    type_name: &ResName,
    res_name: &ResName,
    languages: &[u16],
    neutral_first_fallback: bool,
    level: u32,
    want_dir: bool,
) -> Result<FindResult, FindStatus> {
    if rsrc.len() < DIR_SIZE {
        return Err(FindStatus::DataNotFound);
    }
    // Level 0 (want the root directory itself).
    if level == 0 {
        return Ok(FindResult { offset: 0 });
    }

    // --- Level 1: type ---
    let want_dir_l1 = want_dir || level > 1;
    let type_off = find_entry_by_name(rsrc, 0, type_name, want_dir_l1)
        .ok_or(FindStatus::TypeNotFound)?;
    if level == 1 {
        return Ok(FindResult { offset: type_off });
    }

    // --- Level 2: name ---
    let want_dir_l2 = want_dir || level > 2;
    let name_off = find_entry_by_name(rsrc, type_off, res_name, want_dir_l2)
        .ok_or(FindStatus::NameNotFound)?;
    if level == 2 {
        return Ok(FindResult { offset: name_off });
    }
    if level > 3 {
        return Err(FindStatus::InvalidParameter);
    }

    // --- Level 3: language ---
    for &lang in languages {
        if let Some(off) = find_entry_by_id(rsrc, name_off, lang, want_dir) {
            return Ok(FindResult { offset: off });
        }
    }
    if neutral_first_fallback {
        if let Some(off) = find_first_entry(rsrc, name_off, want_dir) {
            return Ok(FindResult { offset: off });
        }
    }
    Err(FindStatus::LangNotFound)
}

/// Decode the `(OffsetToData, Size)` of an `IMAGE_RESOURCE_DATA_ENTRY` at `data_off` within the
/// section. `OffsetToData` here is an **image RVA** (relative to the image base, not the section).
pub fn data_entry(rsrc: &[u8], data_off: usize) -> Option<(u32, u32)> {
    let rva = rd_u32(rsrc, data_off)?;
    let size = rd_u32(rsrc, data_off + 4)?;
    Some((rva, size))
}

#[cfg(test)]
mod tests;
