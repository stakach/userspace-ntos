//! Generate the api-set contract table from the pinned release's own `ntdll.dll`.
//!
//! The hosted user-mode release resolves `api-ms-*` / `ext-ms-*` contract names through a table
//! compiled into its ntdll (ReactOS `sdk/lib/apisets/apisets.table.c` layout: a name
//! `UNICODE_STRING`, a host `UNICODE_STRING` and a version mask per entry, sorted by name). The
//! source-built ntdll that replaces it must send each contract to the same host, so the table is
//! read from the release at build time and is never copied into this repository.
//!
//! `NT_RELEASE_NTDLL` names the release DLL; the default is the tree `run.sh` extracts.

use std::{env, fmt::Write as _, fs, path::PathBuf};

const ENTRY_SIZE: usize = 40;

struct Image<'a> {
    data: &'a [u8],
    image_base: u64,
    /// `(rva, size, file offset)`.
    sections: Vec<(u64, u64, u64)>,
}

fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(offset..offset + 8)?.try_into().ok()?))
}

impl<'a> Image<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let pe = u32_at(data, 0x3c)? as usize;
        if data.get(pe..pe + 4)? != b"PE\0\0" || u16_at(data, pe + 24)? != 0x20b {
            return None;
        }
        let section_count = u16_at(data, pe + 6)? as usize;
        let table = pe + 24 + u16_at(data, pe + 20)? as usize;
        let mut sections = Vec::new();
        for index in 0..section_count {
            let header = table + index * 40;
            let virtual_size = u32_at(data, header + 8)? as u64;
            let rva = u32_at(data, header + 12)? as u64;
            let raw_size = u32_at(data, header + 16)? as u64;
            let raw = u32_at(data, header + 20)? as u64;
            sections.push((rva, virtual_size.max(raw_size), raw));
        }
        Some(Self {
            data,
            image_base: u64_at(data, pe + 24 + 24)?,
            sections,
        })
    }

    fn file_offset(&self, address: u64) -> Option<usize> {
        let rva = address.checked_sub(self.image_base)?;
        self.sections
            .iter()
            .find(|(start, size, _)| (*start..start + size).contains(&rva))
            .map(|(start, _, raw)| (raw + rva - start) as usize)
    }

    fn address_of(&self, offset: usize) -> Option<u64> {
        let offset = offset as u64;
        self.sections
            .iter()
            .find(|(_, size, raw)| (*raw..raw + size).contains(&offset))
            .map(|(start, _, raw)| self.image_base + start + offset - raw)
    }

    /// A counted ASCII `UNICODE_STRING` at `offset`, lowercased.
    fn counted(&self, offset: usize) -> Option<String> {
        let length = u16_at(self.data, offset)? as usize;
        if length == 0 {
            return Some(String::new());
        }
        if length % 2 != 0 || length > 400 {
            return None;
        }
        let buffer = self.file_offset(u64_at(self.data, offset + 8)?)?;
        self.data
            .get(buffer..buffer + length)?
            .chunks_exact(2)
            .map(|unit| match (unit[0], unit[1]) {
                (byte @ 0x21..=0x7e, 0) if byte != b'"' && byte != b'\\' => {
                    Some(byte.to_ascii_lowercase() as char)
                }
                _ => None,
            })
            .collect()
    }

    fn entry(&self, offset: usize) -> Option<(String, String, u32)> {
        let name = self.counted(offset)?;
        if !(name.starts_with("api-") || name.starts_with("ext-")) {
            return None;
        }
        Some((name, self.counted(offset + 16)?, u32_at(self.data, offset + 32)?))
    }
}

fn api_sets(data: &[u8]) -> Result<Vec<(String, String, u32)>, String> {
    let image = Image::parse(data).ok_or("not a PE32+ image")?;
    // Find the table through one contract every release of this lineage carries.
    let anchor: Vec<u8> = "api-ms-win-core-synch-l1-2-0\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let string = data
        .windows(anchor.len())
        .position(|window| window == anchor)
        .ok_or("no api-set contract strings")?;
    let pointer = image
        .address_of(string)
        .ok_or("contract string is outside every section")?
        .to_le_bytes();
    let mut cursor = data
        .windows(8)
        .position(|window| window == pointer)
        .and_then(|position| position.checked_sub(8))
        .ok_or("no api-set table entry points at the contract string")?;
    while cursor >= ENTRY_SIZE && image.entry(cursor - ENTRY_SIZE).is_some() {
        cursor -= ENTRY_SIZE;
    }
    let mut entries = Vec::new();
    while let Some(entry) = image.entry(cursor) {
        entries.push(entry);
        cursor += ENTRY_SIZE;
    }
    // A wrong pointer match or a rejected string would otherwise leave a short table that
    // silently sends contracts to the file search.
    if !entries.iter().any(|(name, _, _)| name == "api-ms-win-core-synch-l1-2-0") {
        return Err(format!("parsed {} entries without the anchor contract", entries.len()));
    }
    if image.entry(cursor + ENTRY_SIZE).is_some() {
        return Err(format!("table has an unreadable entry after {} entries", entries.len()));
    }
    for pair in entries.windows(2) {
        if pair[0].0 >= pair[1].0 {
            return Err(format!("table is not sorted: {} then {}", pair[0].0, pair[1].0));
        }
    }
    for (name, host, versions) in &entries {
        if name.ends_with(".dll") || *versions == 0 || *versions > 0xff {
            return Err(format!("unexpected entry {name} -> {host} ({versions:#x})"));
        }
    }
    Ok(entries)
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=NT_RELEASE_NTDLL");
    let source = env::var_os("NT_RELEASE_NTDLL").map(PathBuf::from).unwrap_or_else(|| {
        manifest.join("../../rust-micro/.tmp/libernt/tree/Windows/system32/ntdll.dll")
    });
    println!("cargo:rerun-if-changed={}", source.display());
    let data = fs::read(&source).unwrap_or_else(|error| {
        panic!(
            "cannot read the release ntdll.dll at {} ({error}); fetch the pinned release \
             (rust-micro/scripts/fetch_libernt.sh) or set NT_RELEASE_NTDLL",
            source.display()
        )
    });
    let entries = api_sets(&data)
        .unwrap_or_else(|error| panic!("{}: {error}", source.display()));

    let mut table = String::from(
        "/// `(contract name without extension, host DLL, APISET_* version mask)`, sorted by name.\n\
         pub(crate) static RELEASE_API_SETS: &[nt_ntdll::loader::api_set::ApiSetEntry] = &[\n",
    );
    for (name, host, versions) in &entries {
        writeln!(table, "    (\"{name}\", \"{host}\", {versions:#x}),").unwrap();
    }
    table.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("release_api_sets.rs");
    fs::write(output, table).unwrap();
}
