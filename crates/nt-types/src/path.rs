//! Owned UTF-16 strings and the NT path parser (`alloc` only).

use alloc::vec::Vec;
use nt_status::NtStatus;

/// The NT path separator (`\`).
pub const SEPARATOR: u16 = b'\\' as u16;

/// An owned UTF-16 string — the NT-native string encoding. Names and paths are
/// stored and compared as `u16` code units.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct UnicodeString {
    units: Vec<u16>,
}

impl UnicodeString {
    /// An empty string.
    pub fn new() -> Self {
        Self { units: Vec::new() }
    }

    /// Build from UTF-16 code units.
    pub fn from_units(units: &[u16]) -> Self {
        Self {
            units: units.to_vec(),
        }
    }

    /// Build from a Rust `&str` (UTF-8 → UTF-16). Handy for tests and static
    /// bootstrap tables; `encode_utf16` is `core`, so this needs no `std`.
    #[allow(clippy::should_implement_trait)] // infallible &str -> Self, not FromStr
    pub fn from_str(s: &str) -> Self {
        Self {
            units: s.encode_utf16().collect(),
        }
    }

    /// The code units.
    pub fn as_units(&self) -> &[u16] {
        &self.units
    }

    /// Number of code units.
    pub fn len(&self) -> usize {
        self.units.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Case-insensitive equality using ASCII case folding (MVP; full Unicode
    /// folding is deferred — see the compat notes).
    pub fn eq_ignore_ascii_case(&self, other: &UnicodeString) -> bool {
        self.units.len() == other.units.len()
            && self
                .units
                .iter()
                .zip(other.units.iter())
                .all(|(&a, &b)| fold_ascii(a) == fold_ascii(b))
    }

    /// An ASCII-lowercased copy, used as the lookup key for case-insensitive
    /// directories.
    pub fn to_ascii_folded(&self) -> UnicodeString {
        UnicodeString {
            units: self.units.iter().map(|&u| fold_ascii(u)).collect(),
        }
    }
}

#[inline]
fn fold_ascii(u: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&u) {
        u + 32
    } else {
        u
    }
}

impl FromIterator<u16> for UnicodeString {
    fn from_iter<T: IntoIterator<Item = u16>>(iter: T) -> Self {
        Self {
            units: iter.into_iter().collect(),
        }
    }
}

impl core::fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Lossy ASCII rendering for readable test output / traces.
        f.write_str("\"")?;
        for &u in &self.units {
            let c = if (0x20..0x7f).contains(&u) {
                u as u8 as char
            } else {
                '.'
            };
            f.write_fmt(format_args!("{c}"))?;
        }
        f.write_str("\"")
    }
}

/// A parsed absolute NT path: an ordered list of name components (the root `\`
/// has zero components). Only absolute paths are supported in v0.1.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct NtPath {
    components: Vec<UnicodeString>,
}

impl NtPath {
    /// Parse an absolute NT path from UTF-16 code units.
    ///
    /// Rules (spec §9.4): the separator is `\`; the path must be absolute (start
    /// with `\`); empty components (`\\` or a trailing `\`) are rejected; the
    /// bare root `\` parses to zero components.
    pub fn parse(s: &[u16]) -> Result<NtPath, NtStatus> {
        if s.first() != Some(&SEPARATOR) {
            return Err(NtStatus::INVALID_PARAMETER); // not absolute
        }
        let rest = &s[1..];
        let mut components = Vec::new();
        if rest.is_empty() {
            return Ok(NtPath { components }); // root "\"
        }
        for comp in rest.split(|&c| c == SEPARATOR) {
            if comp.is_empty() {
                return Err(NtStatus::INVALID_PARAMETER); // empty component
            }
            components.push(UnicodeString::from_units(comp));
        }
        Ok(NtPath { components })
    }

    /// Parse from a Rust `&str` (test/bootstrap convenience).
    pub fn parse_str(s: &str) -> Result<NtPath, NtStatus> {
        let units: Vec<u16> = s.encode_utf16().collect();
        Self::parse(&units)
    }

    /// The path components (empty for the root).
    pub fn components(&self) -> &[UnicodeString] {
        &self.components
    }

    /// True for the root path `\`.
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// The final component (the leaf name), if any.
    pub fn leaf(&self) -> Option<&UnicodeString> {
        self.components.last()
    }

    /// The parent path (all components but the last), or `None` for the root.
    pub fn parent(&self) -> Option<NtPath> {
        if self.components.is_empty() {
            None
        } else {
            Some(NtPath {
                components: self.components[..self.components.len() - 1].to_vec(),
            })
        }
    }

    /// Build a path directly from components (absolute; empty = root).
    pub fn from_components(components: Vec<UnicodeString>) -> NtPath {
        NtPath { components }
    }

    /// Serialise back to absolute NT-path UTF-16 code units (`\` + components
    /// joined by `\`; the root is a single `\`).
    pub fn to_units(&self) -> Vec<u16> {
        let mut out = Vec::new();
        if self.components.is_empty() {
            out.push(SEPARATOR);
            return out;
        }
        for comp in &self.components {
            out.push(SEPARATOR);
            out.extend_from_slice(comp.as_units());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<NtPath, NtStatus> {
        NtPath::parse_str(s)
    }

    #[test]
    fn root_parses_to_zero_components() {
        let root = p("\\").unwrap();
        assert!(root.is_root());
        assert_eq!(root.components().len(), 0);
    }

    #[test]
    fn absolute_multi_component() {
        let path = p("\\Device\\Example0").unwrap();
        assert_eq!(path.components().len(), 2);
        assert_eq!(path.components()[0], UnicodeString::from_str("Device"));
        assert_eq!(path.leaf().unwrap(), &UnicodeString::from_str("Example0"));
    }

    #[test]
    fn dos_devices_prefix() {
        let path = p("\\??\\Example").unwrap();
        assert_eq!(path.components()[0], UnicodeString::from_str("??"));
    }

    #[test]
    fn rejects_relative_and_empty_components() {
        assert_eq!(p("Device").unwrap_err(), NtStatus::INVALID_PARAMETER); // not absolute
        assert_eq!(p("\\Device\\").unwrap_err(), NtStatus::INVALID_PARAMETER); // trailing sep
        assert_eq!(p("\\\\Device").unwrap_err(), NtStatus::INVALID_PARAMETER); // double sep
        assert_eq!(p("").unwrap_err(), NtStatus::INVALID_PARAMETER); // empty
    }

    #[test]
    fn case_folding() {
        let a = UnicodeString::from_str("Event");
        let b = UnicodeString::from_str("EVENT");
        assert!(a.eq_ignore_ascii_case(&b));
        assert_eq!(a.to_ascii_folded(), UnicodeString::from_str("event"));
        assert_ne!(a, b); // exact comparison still distinguishes
    }
}
