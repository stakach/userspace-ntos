//! `Rtl*` character-set conversion — the NLS-table-driven unicode↔ansi↔oem surface.
//!
//! Real ntdll drives these from the code-page tables the executive stages into the PEB
//! (`AnsiCodePageData` / `OemCodePageData` at `PEB+0xA0/0xA8`, see `nt-ntdll-layout`). Those tables
//! are 8-bit-lead-byte NLS tables; for the ReactOS default code pages (1252 ANSI, 437 OEM) the low
//! 0x80 is plain ASCII and the high half is a fixed mapping. We model the conversion over a
//! [`CodePage`] abstraction so the pure logic is host-testable now; wiring the real PEB tables is a
//! loader concern (Step 3). The default [`CodePage::LATIN1`] treats bytes as Latin-1 (identity in
//! `u16`), which is exact for the ASCII range every early boot path exercises
//! (`RtlUnicodeToMultiByteN` in smss's `RtlUnicodeToMultiByteN` NLS path).
//!
//! Category A. Host-tested.

use alloc::vec::Vec;

/// A single-byte code-page mapping: byte → UTF-16 (widen) and UTF-16 → byte (narrow, with a
/// default char for unrepresentable units). Modelled as a 256-entry widen table.
#[derive(Clone)]
pub struct CodePage {
    /// `widen[b]` is the UTF-16 code unit for byte `b`.
    widen: [u16; 256],
    /// Byte substituted for a UTF-16 unit with no reverse mapping (Windows uses `'?'`).
    default_char: u8,
}

impl CodePage {
    /// The Latin-1 (ISO-8859-1) identity code page: byte `b` ↔ `u16` `b`. Exact for ASCII and the
    /// Latin-1 supplement; the correct default until the real 1252/437 PEB tables are wired.
    pub const LATIN1: CodePage = {
        let mut w = [0u16; 256];
        let mut i = 0;
        while i < 256 {
            w[i] = i as u16;
            i += 1;
        }
        CodePage {
            widen: w,
            default_char: b'?',
        }
    };

    /// Build a code page from an explicit 256-entry widen table.
    pub const fn from_widen(widen: [u16; 256], default_char: u8) -> Self {
        CodePage { widen, default_char }
    }

    /// Widen one byte to its UTF-16 code unit.
    #[inline]
    pub fn widen_byte(&self, b: u8) -> u16 {
        self.widen[b as usize]
    }

    /// Narrow one UTF-16 unit to a byte via reverse lookup; returns [`Self::default_char`] if the
    /// unit is unrepresentable in this code page.
    #[inline]
    pub fn narrow_unit(&self, c: u16) -> u8 {
        // Fast path: ASCII maps to itself in every ANSI/OEM code page.
        if c < 0x80 {
            return c as u8;
        }
        match self.widen.iter().position(|&w| w == c) {
            Some(b) => b as u8,
            None => self.default_char,
        }
    }
}

/// `RtlMultiByteToUnicodeN` / `RtlOemStringToUnicodeString`: widen `src` bytes to UTF-16 via `cp`.
pub fn multi_byte_to_unicode(cp: &CodePage, src: &[u8]) -> Vec<u16> {
    src.iter().map(|&b| cp.widen_byte(b)).collect()
}

/// `RtlUnicodeToMultiByteN` / `RtlUnicodeStringToAnsiString`: narrow `src` UTF-16 to bytes via `cp`.
pub fn unicode_to_multi_byte(cp: &CodePage, src: &[u16]) -> Vec<u8> {
    src.iter().map(|&c| cp.narrow_unit(c)).collect()
}

/// `RtlUnicodeToMultiByteSize`: the byte count a narrow conversion of `src` would produce. For a
/// single-byte code page this is simply the number of code units (no multi-byte lead-byte
/// expansion for 1252/437).
pub fn unicode_to_multi_byte_size(src: &[u16]) -> usize {
    src.len()
}

/// `RtlxUnicodeStringToAnsiSize` / `RtlxUnicodeStringToOemSize`: the ANSI/OEM byte size *including*
/// the trailing NUL (the `Rtlx*` variants add room for the terminator).
pub fn unicode_string_to_ansi_size(src: &[u16]) -> usize {
    unicode_to_multi_byte_size(src) + 1
}

/// `RtlxAnsiStringToUnicodeSize` / `RtlxOemStringToUnicodeSize`: the widened UTF-16 **byte** size
/// including the trailing NUL unit.
pub fn ansi_string_to_unicode_size(src: &[u8]) -> usize {
    (src.len() + 1) * 2
}

/// `RtlAnsiCharToUnicodeChar`: widen a single ANSI byte via the default (Latin-1) code page.
pub fn ansi_char_to_unicode_char(b: u8) -> u16 {
    CodePage::LATIN1.widen_byte(b)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn latin1_roundtrip_ascii_and_supplement() {
        let cp = &CodePage::LATIN1;
        for b in 0u8..=0xFF {
            let w = cp.widen_byte(b);
            assert_eq!(w, b as u16);
            assert_eq!(cp.narrow_unit(w), b);
        }
    }

    #[test]
    fn narrow_unrepresentable_uses_default() {
        let cp = &CodePage::LATIN1;
        // A code unit above the Latin-1 range (e.g. a CJK char) narrows to '?'.
        assert_eq!(cp.narrow_unit(0x4E00), b'?');
    }

    #[test]
    fn multibyte_widen_narrow() {
        let cp = &CodePage::LATIN1;
        let bytes = b"System32";
        let wide = multi_byte_to_unicode(cp, bytes);
        assert_eq!(wide, "System32".encode_utf16().collect::<Vec<_>>());
        let back = unicode_to_multi_byte(cp, &wide);
        assert_eq!(&back, bytes);
    }

    #[test]
    fn sizes() {
        let w: Vec<u16> = "abc".encode_utf16().collect();
        assert_eq!(unicode_to_multi_byte_size(&w), 3);
        assert_eq!(unicode_string_to_ansi_size(&w), 4); // + NUL
        assert_eq!(ansi_string_to_unicode_size(b"abc"), 8); // (3+1)*2
    }

    #[test]
    fn custom_codepage_reverse_lookup() {
        // A tiny custom page: byte 0x80 -> U+20AC (euro), like cp1252.
        let mut w = CodePage::LATIN1.widen;
        w[0x80] = 0x20AC;
        let cp = CodePage::from_widen(w, b'?');
        assert_eq!(cp.widen_byte(0x80), 0x20AC);
        assert_eq!(cp.narrow_unit(0x20AC), 0x80);
    }
}
