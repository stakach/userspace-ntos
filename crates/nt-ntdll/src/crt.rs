//! Category A' — the C-runtime re-exports ntdll ships (`mem*`/`str*`/`wcs*`/`_snprintf`/`qsort`/
//! `bsearch`/math) + the 3 data exports.
//!
//! ntdll re-exports a small CRT so early binaries (that link the CRT names but load before msvcrt)
//! resolve them against ntdll. Many alias the `Rtl*` mem/str primitives; a few (formatting, sort,
//! search) are authored here. These are pure and host-tested. The narrow/wide byte primitives are
//! provided in slice-based form (the real exports take NUL-terminated pointers; the loader/CRT
//! marshalling layer bridges pointer ↔ slice).

use alloc::vec::Vec;

// --- memory (mem*) — alias core/Rtl -----------------------------------------------------------

/// `memcmp`: lexical byte comparison over the common prefix length `n`.
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let n = n.min(a.len()).min(b.len());
    a[..n].cmp(&b[..n])
}

/// `memchr`: index of the first byte equal to `c` within the first `n` bytes.
pub fn memchr(haystack: &[u8], c: u8, n: usize) -> Option<usize> {
    haystack[..n.min(haystack.len())].iter().position(|&b| b == c)
}

// --- narrow strings (str*) --------------------------------------------------------------------

/// `strlen`: bytes up to the NUL.
pub fn strlen(s: &[u8]) -> usize {
    s.iter().position(|&b| b == 0).unwrap_or(s.len())
}

/// `strcmp`: compare two NUL-terminated byte strings.
pub fn strcmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    a[..strlen(a)].cmp(&b[..strlen(b)])
}

/// `_stricmp` / `_strcmpi`: case-insensitive ASCII compare.
pub fn stricmp(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
    let fold = |s: &[u8]| -> Vec<u8> { s[..strlen(s)].iter().map(|c| c.to_ascii_lowercase()).collect() };
    fold(a).cmp(&fold(b))
}

/// `strncmp`: compare up to `n` bytes.
pub fn strncmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let ea = strlen(a).min(n);
    let eb = strlen(b).min(n);
    a[..ea].cmp(&b[..eb])
}

/// `strchr`: index of the first `c`.
pub fn strchr(s: &[u8], c: u8) -> Option<usize> {
    s[..strlen(s)].iter().position(|&b| b == c)
}

/// `strrchr`: index of the last `c`.
pub fn strrchr(s: &[u8], c: u8) -> Option<usize> {
    s[..strlen(s)].iter().rposition(|&b| b == c)
}

/// `strstr`: index of the first occurrence of `needle`.
pub fn strstr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let (h, n) = (&hay[..strlen(hay)], &needle[..strlen(needle)]);
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

// --- wide strings (wcs*) ----------------------------------------------------------------------

/// `wcslen`.
pub fn wcslen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// `wcscmp`.
pub fn wcscmp(a: &[u16], b: &[u16]) -> core::cmp::Ordering {
    a[..wcslen(a)].cmp(&b[..wcslen(b)])
}

/// `_wcsicmp` / `_wcsnicmp` core: case-insensitive wide compare (ASCII + Latin-1 fold).
pub fn wcsicmp(a: &[u16], b: &[u16]) -> core::cmp::Ordering {
    let fold = |s: &[u16]| -> Vec<u16> {
        s[..wcslen(s)].iter().map(|&c| crate::rtl::strings::downcase_char(c)).collect()
    };
    fold(a).cmp(&fold(b))
}

/// `wcschr`.
pub fn wcschr(s: &[u16], c: u16) -> Option<usize> {
    s[..wcslen(s)].iter().position(|&x| x == c)
}

/// `wcspbrk`.
pub fn wcspbrk(s: &[u16], accept: &[u16]) -> Option<usize> {
    let hay = &s[..wcslen(s)];
    let set = &accept[..wcslen(accept)];
    if set.is_empty() {
        return None;
    }
    hay.iter().position(|c| set.contains(c))
}

/// `wcsstr`.
pub fn wcsstr(hay: &[u16], needle: &[u16]) -> Option<usize> {
    let (h, n) = (&hay[..wcslen(hay)], &needle[..wcslen(needle)]);
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

// --- narrow parse (atoi / strtol / strtoul) ---------------------------------------------------

/// `atoi`: parse a leading signed decimal.
pub fn atoi(s: &[u8]) -> i32 {
    let n = strlen(s);
    let mut i = 0;
    while i < n && (s[i] == b' ' || s[i] == b'\t') {
        i += 1;
    }
    let (neg, start) = match s.get(i) {
        Some(b'-') => (true, i + 1),
        Some(b'+') => (false, i + 1),
        _ => (false, i),
    };
    let mut acc: i64 = 0;
    let mut j = start;
    while j < n && s[j].is_ascii_digit() {
        acc = acc.saturating_mul(10).saturating_add((s[j] - b'0') as i64);
        j += 1;
    }
    let v = if neg { -acc } else { acc };
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// `strtoul` (the pure core): parse an unsigned integer in `base` (0 auto-detects `0x`/`0`).
pub fn strtoul(s: &[u8], base: u32) -> u32 {
    crate::rtl::integer::char_to_integer(&s[..strlen(s)], base).unwrap_or(0)
}

// --- formatting (_snprintf core, decimal/hex only) --------------------------------------------

/// A minimal `_snprintf`-style formatter supporting `%d %u %x %X %s %c %%` (the subset the early
/// boot paths use). Writes into `out` (up to its capacity) and returns the number of bytes that
/// *would* be written (C semantics). `args` are supplied pre-rendered as `FmtArg`s.
#[derive(Clone, Debug)]
pub enum FmtArg<'a> {
    /// `%d`.
    Int(i64),
    /// `%u`.
    Uint(u64),
    /// `%x`/`%X` (lower/upper controlled by the spec).
    Hex(u64),
    /// `%s` (narrow bytes).
    Str(&'a [u8]),
    /// `%c`.
    Char(u8),
}

/// Format `fmt` with `args` into a fresh `Vec<u8>` (the pure, allocation-based core; the pointer
/// `_snprintf` wraps this + copies into the caller's buffer). Returns the rendered bytes.
pub fn format(fmt: &[u8], args: &[FmtArg]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ai = 0;
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        let spec = fmt[i];
        i += 1;
        let next = || -> Option<&FmtArg> { args.get(ai) };
        match spec {
            b'%' => out.push(b'%'),
            b'd' | b'i' => {
                if let Some(FmtArg::Int(v)) = next() {
                    render_int(&mut out, *v);
                }
                ai += 1;
            }
            b'u' => {
                if let Some(FmtArg::Uint(v)) = next() {
                    render_uint(&mut out, *v, 10, false);
                }
                ai += 1;
            }
            b'x' | b'X' => {
                if let Some(FmtArg::Hex(v)) = next() {
                    render_uint(&mut out, *v, 16, spec == b'X');
                }
                ai += 1;
            }
            b's' => {
                if let Some(FmtArg::Str(s)) = next() {
                    out.extend_from_slice(&s[..strlen(s)]);
                }
                ai += 1;
            }
            b'c' => {
                if let Some(FmtArg::Char(c)) = next() {
                    out.push(*c);
                }
                ai += 1;
            }
            other => {
                out.push(b'%');
                out.push(other);
            }
        }
    }
    out
}

fn render_int(out: &mut Vec<u8>, v: i64) {
    if v < 0 {
        out.push(b'-');
        render_uint(out, (v as i128).unsigned_abs() as u64, 10, false);
    } else {
        render_uint(out, v as u64, 10, false);
    }
}

fn render_uint(out: &mut Vec<u8>, v: u64, base: u64, upper: bool) {
    if v == 0 {
        out.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    let mut x = v;
    while x > 0 {
        let d = (x % base) as u8;
        tmp[n] = if d < 10 {
            b'0' + d
        } else if upper {
            b'A' + (d - 10)
        } else {
            b'a' + (d - 10)
        };
        n += 1;
        x /= base;
    }
    for &c in tmp[..n].iter().rev() {
        out.push(c);
    }
}

// --- sort / search ----------------------------------------------------------------------------

/// `qsort` (a safe generic form): sort `slice` in place by `cmp`. The real `qsort` takes a raw
/// element size + comparator over `*const c_void`; this is the pure typed core the marshalling
/// layer drives.
pub fn qsort<T, F: FnMut(&T, &T) -> core::cmp::Ordering>(slice: &mut [T], mut cmp: F) {
    slice.sort_by(|a, b| cmp(a, b));
}

/// `bsearch`: binary search a sorted `slice` for `key` by `cmp`; returns the found index.
pub fn bsearch<T, F: FnMut(&T) -> core::cmp::Ordering>(slice: &[T], cmp: F) -> Option<usize> {
    slice.binary_search_by(cmp).ok()
}

// --- math (thin re-exports over libm-free approximations are out of scope; provide the trivial) --

/// `abs`.
pub fn abs(v: i32) -> i32 {
    v.wrapping_abs()
}

/// `labs`.
pub fn labs(v: i64) -> i64 {
    v.wrapping_abs()
}

// --- data exports -----------------------------------------------------------------------------

/// `NlsMbCodePageTag` — the ANSI code page is a multi-byte code page? For the ReactOS default
/// (1252), no (it's single-byte). Windows exports this `BOOLEAN`; `false` for 1252.
pub const NLS_MB_CODE_PAGE_TAG: bool = false;

/// `NlsMbOemCodePageTag` — the OEM code page multi-byte? For 437, no.
pub const NLS_MB_OEM_CODE_PAGE_TAG: bool = false;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cmp::Ordering;
    use std::vec;

    #[test]
    fn narrow_str_ops() {
        assert_eq!(strlen(b"hello\0world"), 5);
        assert_eq!(strcmp(b"abc\0", b"abd\0"), Ordering::Less);
        assert_eq!(stricmp(b"Foo\0", b"FOO\0"), Ordering::Equal);
        assert_eq!(strncmp(b"abcXYZ\0", b"abcQRS\0", 3), Ordering::Equal);
        assert_eq!(strchr(b"a/b/c\0", b'/'), Some(1));
        assert_eq!(strrchr(b"a/b/c\0", b'/'), Some(3));
        assert_eq!(strstr(b"hello world\0", b"world\0"), Some(6));
        assert_eq!(strstr(b"hello\0", b"xyz\0"), None);
    }

    #[test]
    fn wide_str_ops() {
        let w = |s: &str| -> Vec<u16> {
            let mut v: Vec<u16> = s.encode_utf16().collect();
            v.push(0);
            v
        };
        assert_eq!(wcslen(&w("system32")), 8);
        assert_eq!(wcscmp(&w("aaa"), &w("aab")), Ordering::Less);
        assert_eq!(wcsicmp(&w("Ntdll"), &w("NTDLL")), Ordering::Equal);
        assert_eq!(wcschr(&w("a\\b"), b'\\' as u16), Some(1));
        assert_eq!(wcspbrk(&w("system32"), &w("39")), Some(6));
        assert_eq!(wcspbrk(&w("system32"), &w("qz")), None);
        assert_eq!(wcsstr(&w("kernel32.dll"), &w(".dll")), Some(8));
    }

    #[test]
    fn parse() {
        assert_eq!(atoi(b"  -42abc\0"), -42);
        assert_eq!(atoi(b"2147483648\0"), i32::MAX); // saturates
        assert_eq!(strtoul(b"0xFF\0", 0), 255);
        assert_eq!(strtoul(b"777\0", 8), 0o777);
    }

    #[test]
    fn snprintf_core() {
        assert_eq!(
            format(b"pid=%d name=%s hex=%X", &[FmtArg::Int(42), FmtArg::Str(b"smss\0"), FmtArg::Hex(0xdead)]),
            b"pid=42 name=smss hex=DEAD"
        );
        assert_eq!(format(b"%u%%", &[FmtArg::Uint(100)]), b"100%");
        assert_eq!(format(b"neg %d", &[FmtArg::Int(-7)]), b"neg -7");
        assert_eq!(format(b"%c%c", &[FmtArg::Char(b'O'), FmtArg::Char(b'K')]), b"OK");
    }

    #[test]
    fn sort_and_search() {
        let mut v = vec![3u32, 1, 4, 1, 5, 9, 2, 6];
        qsort(&mut v, |a, b| a.cmp(b));
        assert_eq!(v, vec![1, 1, 2, 3, 4, 5, 6, 9]);
        assert!(bsearch(&v, |p| p.cmp(&5)).is_some());
        assert!(bsearch(&v, |p| p.cmp(&7)).is_none());
    }

    #[test]
    fn misc() {
        assert_eq!(abs(-5), 5);
        assert_eq!(labs(-5_000_000_000), 5_000_000_000);
        assert_eq!(memcmp(b"abc", b"abd", 3), Ordering::Less);
        assert_eq!(memchr(b"a-b-c", b'-', 5), Some(1));
        assert!(!NLS_MB_CODE_PAGE_TAG);
        assert!(!NLS_MB_OEM_CODE_PAGE_TAG);
    }
}
