//! Bounded identities for USER cursor/icon lookups.
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
    pub fn new(module: &[u16], resource: CursorResource, icon_kind: u32) -> Option<Self> {
        Some(Self {
            module: CursorText::new(module)?,
            resource,
            icon_kind,
        })
    }

    pub fn same_identity(&self, other: &Self) -> bool {
        self.icon_kind == other.icon_kind
            && self.module.equals_case_insensitive(&other.module)
            && self.resource.same_identity(&other.resource)
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
    fn matching_is_case_insensitive_but_other_fields_are_exact() {
        let original = key("C:\\ReactOS\\USER32.DLL", named("Arrow"), 0);
        let same = key("c:\\reactos\\user32.dll", named("aRRoW"), 0);
        let atom = key("c:\\reactos\\user32.dll", CursorResource::atom(32512), 0);
        let icon = key("c:\\reactos\\user32.dll", named("arrow"), 1);
        assert!(original.same_identity(&same));
        assert!(!original.same_identity(&atom));
        assert!(!original.same_identity(&icon));
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
        assert!(lower.same_identity(&upper));
        assert!(!lower.same_identity(&noncanonical_bool));
    }

    #[test]
    fn cursor_dimensions_are_deliberately_not_in_the_identity() {
        let first = key("user32.dll", CursorResource::atom(32512), 0);
        let different_size_same_key = key("user32.dll", CursorResource::atom(32512), 0);
        assert!(first.same_identity(&different_size_same_key));
    }
}
