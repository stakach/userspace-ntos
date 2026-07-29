//! Bounded identities for the USER global cursor/icon cache.
//!
//! ReactOS keys shared cursors by module name, resource name (or integer resource), and whether the
//! object is an icon. Cursor dimensions are intentionally not part of the lookup: win32k's
//! `NtUserFindExistingCursorIcon` ignores them too. This module contains no client-memory access;
//! callers must capture and validate counted strings before constructing a key.

/// Maximum captured module or resource-name length, in UTF-16 code units.
pub const CURSOR_TEXT_CAP: usize = 260;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorStringDescriptor {
    Atom(u16),
    Text { byte_len: usize, buffer: u64 },
}

/// Validate a captured x64 `UNICODE_STRING` descriptor without touching its Buffer.
pub fn parse_string_descriptor(raw: &[u8; 16], allow_atom: bool) -> Option<CursorStringDescriptor> {
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length & 1 != 0 || buffer == 0 {
        return None;
    }
    if allow_atom && buffer <= u16::MAX as u64 {
        return Some(CursorStringDescriptor::Atom(buffer as u16));
    }
    if length == 0 || length > maximum || length > CURSOR_TEXT_CAP * 2 {
        return None;
    }
    Some(CursorStringDescriptor::Text {
        byte_len: length,
        buffer,
    })
}

/// Decode an already captured UTF-16 buffer into fixed storage.
pub fn decode_utf16(bytes: &[u8], units: &mut [u16; CURSOR_TEXT_CAP]) -> Option<usize> {
    if bytes.is_empty() || bytes.len() & 1 != 0 || bytes.len() > units.len() * 2 {
        return None;
    }
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        units[index] = u16::from_le_bytes([pair[0], pair[1]]);
    }
    Some(bytes.len() / 2)
}

#[derive(Clone, Copy, Debug)]
pub struct CursorText {
    len: u16,
    units: [u16; CURSOR_TEXT_CAP],
}

impl CursorText {
    const EMPTY: Self = Self {
        len: 0,
        units: [0; CURSOR_TEXT_CAP],
    };

    /// Construct a non-empty bounded string from captured UTF-16.
    pub fn new(units: &[u16]) -> Option<Self> {
        if units.is_empty() || units.len() > CURSOR_TEXT_CAP {
            return None;
        }
        let mut text = Self::EMPTY;
        text.units[..units.len()].copy_from_slice(units);
        text.len = units.len() as u16;
        Some(text)
    }

    fn equals_case_insensitive(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }
        self.units[..self.len as usize]
            .iter()
            .zip(&other.units[..other.len as usize])
            .all(|(&left, &right)| fold_boot_unicode(left) == fold_boot_unicode(right))
    }
}

/// The allocation-free ASCII + Latin-1 folding used by our current ntdll RTL string core. The live
/// system-cursor path is narrower still: an ASCII module path plus an integer resource.
const fn fold_boot_unicode(unit: u16) -> u16 {
    match unit {
        0x61..=0x7a => unit - 0x20,
        0xe0..=0xfe if unit != 0xf7 => unit - 0x20,
        _ => unit,
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CursorResource {
    Atom(u16),
    Name(CursorText),
}

impl CursorResource {
    const EMPTY: Self = Self::Atom(0);

    pub const fn atom(atom: u16) -> Self {
        Self::Atom(atom)
    }

    pub fn name(units: &[u16]) -> Option<Self> {
        CursorText::new(units).map(Self::Name)
    }

    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Atom(left), Self::Atom(right)) => left == right,
            (Self::Name(left), Self::Name(right)) => left.equals_case_insensitive(right),
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CursorLookupKey {
    module: CursorText,
    resource: CursorResource,
    icon_kind: u32,
}

impl CursorLookupKey {
    const EMPTY: Self = Self {
        module: CursorText::EMPTY,
        resource: CursorResource::EMPTY,
        icon_kind: 0,
    };

    pub fn new(module: &[u16], resource: CursorResource, icon_kind: u32) -> Option<Self> {
        Some(Self {
            module: CursorText::new(module)?,
            resource,
            icon_kind,
        })
    }

    fn equals(&self, other: &Self) -> bool {
        self.icon_kind == other.icon_kind
            && self.module.equals_case_insensitive(&other.module)
            && self.resource.same_identity(&other.resource)
    }
}

#[derive(Clone, Copy)]
struct CursorCacheEntry {
    key: CursorLookupKey,
    handle: u32,
    occupied: bool,
}

impl CursorCacheEntry {
    const EMPTY: Self = Self {
        key: CursorLookupKey::EMPTY,
        handle: 0,
        occupied: false,
    };
}

/// Mirror of only the cursor identities and handles observed from real win32k calls.
///
/// A lookup becomes externally visible only after `NtUserSetSystemCursor` has successfully promoted
/// its handle. This matches the second, global-list search in ReactOS and prevents exporting a
/// process-owned USER handle to another process.
pub struct GlobalCursorMirror<const ENTRIES: usize, const PROMOTED: usize> {
    entries: [CursorCacheEntry; ENTRIES],
    promoted: [u32; PROMOTED],
    next_entry: usize,
    next_promoted: usize,
}

impl<const ENTRIES: usize, const PROMOTED: usize> GlobalCursorMirror<ENTRIES, PROMOTED> {
    pub const fn new() -> Self {
        Self {
            entries: [CursorCacheEntry::EMPTY; ENTRIES],
            promoted: [0; PROMOTED],
            next_entry: 0,
            next_promoted: 0,
        }
    }

    /// Record a real key and handle assigned by successful `NtUserSetCursorIconData`.
    pub fn observe_identity(&mut self, key: &CursorLookupKey, handle: u32) {
        if handle == 0 || ENTRIES == 0 {
            return;
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.occupied && entry.key.equals(key))
        {
            entry.handle = handle;
            return;
        }
        self.entries[self.next_entry] = CursorCacheEntry {
            key: *key,
            handle,
            occupied: true,
        };
        self.next_entry = (self.next_entry + 1) % ENTRIES;
    }

    /// Record that real win32k successfully promoted `handle` into its global cursor list.
    pub fn promote(&mut self, handle: u32) {
        if handle == 0 || PROMOTED == 0 || self.promoted.contains(&handle) {
            return;
        }
        self.promoted[self.next_promoted] = handle;
        self.next_promoted = (self.next_promoted + 1) % PROMOTED;
    }

    /// Return the real globally promoted handle for an exact lookup, or `None` on a cache miss.
    pub fn lookup_global(&self, key: &CursorLookupKey) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| {
                entry.occupied && entry.key.equals(key) && self.promoted.contains(&entry.handle)
            })
            .map(|entry| entry.handle)
    }
}

impl<const ENTRIES: usize, const PROMOTED: usize> Default
    for GlobalCursorMirror<ENTRIES, PROMOTED>
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(module: &str, resource: CursorResource, icon_kind: u32) -> CursorLookupKey {
        let module: alloc::vec::Vec<u16> = module.encode_utf16().collect();
        CursorLookupKey::new(&module, resource, icon_kind).unwrap()
    }

    fn named(name: &str) -> CursorResource {
        let name: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        CursorResource::name(&name).unwrap()
    }

    #[test]
    fn exports_only_real_promoted_handles() {
        let key = key(
            "C:\\ReactOS\\system32\\user32.dll",
            CursorResource::atom(32512),
            0,
        );
        let mut mirror = GlobalCursorMirror::<8, 4>::new();
        mirror.observe_identity(&key, 0x0002_0024);
        assert_eq!(mirror.lookup_global(&key), None);
        mirror.promote(0x0002_0024);
        assert_eq!(mirror.lookup_global(&key), Some(0x0002_0024));
    }

    #[test]
    fn matching_is_case_insensitive_but_other_fields_are_exact() {
        let original = key("C:\\ReactOS\\USER32.DLL", named("Arrow"), 0);
        let same = key("c:\\reactos\\user32.dll", named("aRRoW"), 0);
        let atom = key("c:\\reactos\\user32.dll", CursorResource::atom(32512), 0);
        let icon = key("c:\\reactos\\user32.dll", named("arrow"), 1);
        let mut mirror = GlobalCursorMirror::<8, 4>::new();
        mirror.observe_identity(&original, 0x0002_0024);
        mirror.promote(0x0002_0024);
        assert_eq!(mirror.lookup_global(&same), Some(0x0002_0024));
        assert_eq!(mirror.lookup_global(&atom), None);
        assert_eq!(mirror.lookup_global(&icon), None);
    }

    #[test]
    fn duplicate_observation_updates_the_real_handle() {
        let key = key("user32.dll", CursorResource::atom(32512), 0);
        let mut mirror = GlobalCursorMirror::<2, 2>::new();
        mirror.observe_identity(&key, 0x1111);
        mirror.observe_identity(&key, 0x2222);
        mirror.promote(0x1111);
        assert_eq!(mirror.lookup_global(&key), None);
        mirror.promote(0x2222);
        assert_eq!(mirror.lookup_global(&key), Some(0x2222));
    }

    #[test]
    fn rejects_empty_and_overlong_text() {
        assert!(CursorText::new(&[]).is_none());
        assert!(CursorText::new(&[b'a' as u16; CURSOR_TEXT_CAP + 1]).is_none());
    }

    fn descriptor(length: u16, maximum: u16, buffer: u64) -> [u8; 16] {
        let mut raw = [0u8; 16];
        raw[0..2].copy_from_slice(&length.to_le_bytes());
        raw[2..4].copy_from_slice(&maximum.to_le_bytes());
        raw[8..16].copy_from_slice(&buffer.to_le_bytes());
        raw
    }

    #[test]
    fn atom_descriptor_never_requires_a_buffer_read() {
        assert_eq!(
            parse_string_descriptor(&descriptor(0, 0, 32512), true),
            Some(CursorStringDescriptor::Atom(32512))
        );
        assert_eq!(
            parse_string_descriptor(&descriptor(0, 0, 32512), false),
            None
        );
        assert_eq!(
            parse_string_descriptor(&descriptor(4, 4, 32512), true),
            Some(CursorStringDescriptor::Atom(32512))
        );
    }

    #[test]
    fn rejects_malformed_or_oversized_descriptors() {
        assert_eq!(
            parse_string_descriptor(&descriptor(3, 4, 0x1_0000), true),
            None
        );
        assert_eq!(
            parse_string_descriptor(&descriptor(6, 4, 0x1_0000), true),
            None
        );
        assert_eq!(
            parse_string_descriptor(
                &descriptor((CURSOR_TEXT_CAP as u16 + 1) * 2, u16::MAX, 0x1_0000),
                true
            ),
            None
        );
        assert_eq!(parse_string_descriptor(&descriptor(4, 4, 0), true), None);
        assert_eq!(parse_string_descriptor(&descriptor(0, 0, 0), true), None);
        assert_eq!(
            parse_string_descriptor(&descriptor(0, 0, 0x1_0000), true),
            None
        );
    }

    #[test]
    fn decodes_captured_named_resource() {
        let mut units = [0u16; CURSOR_TEXT_CAP];
        assert_eq!(decode_utf16(&[b'A', 0, b'R', 0], &mut units), Some(2));
        assert_eq!(&units[..2], &[b'A' as u16, b'R' as u16]);
        assert_eq!(decode_utf16(&[b'A', 0, b'R'], &mut units), None);
    }

    #[test]
    fn latin1_names_fold_without_changing_raw_cursor_kind() {
        let lower = key("módulo.dll", named("flèche"), 1);
        let upper = key("MÓDULO.DLL", named("FLÈCHE"), 1);
        let noncanonical_bool = key("MÓDULO.DLL", named("FLÈCHE"), 2);
        let mut mirror = GlobalCursorMirror::<2, 2>::new();
        mirror.observe_identity(&lower, 0x20024);
        mirror.promote(0x20024);
        assert_eq!(mirror.lookup_global(&upper), Some(0x20024));
        assert_eq!(mirror.lookup_global(&noncanonical_bool), None);
    }

    #[test]
    fn cursor_dimensions_are_deliberately_not_in_the_identity() {
        let first = key("user32.dll", CursorResource::atom(32512), 0);
        let different_size_same_key = key("user32.dll", CursorResource::atom(32512), 0);
        let mut mirror = GlobalCursorMirror::<2, 2>::new();
        mirror.observe_identity(&first, 0x20024);
        mirror.promote(0x20024);
        assert_eq!(
            mirror.lookup_global(&different_size_same_key),
            Some(0x20024)
        );
    }
}
