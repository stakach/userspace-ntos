//! Printf-lite formatter for the `DbgPrint` family — the real backend for
//! `vDbgPrintExWithPrefix` (win32k's `DPRINT`/`DbgPrintEx` output). Parses a
//! narrow format string and pulls successive arguments from a caller-supplied
//! `va_list` walker, emitting formatted bytes to a caller-supplied sink. The
//! executive wires `next_arg` to walk win32k's `va_list`, `read_cstr` to copy a
//! guest C-string, and `out` to the serial port; host tests drive it with
//! closures (no real pointers) — so the format logic itself is unit-tested.
//!
//! Supported conversions: `%s` (C-string via `read_cstr`), `%c`, `%d`/`%i`
//! (signed), `%u` (unsigned), `%x`/`%X` (hex), `%p` (pointer), `%%`. Width,
//! precision, flag and length (`l`/`h`/`w`/`I64`) modifiers are consumed and
//! ignored (narrow best-effort — a wide string prints its low bytes). Unknown
//! conversions echo `%` + the char verbatim.

/// Maximum bytes read for one `%s` argument.
const CSTR_MAX: usize = 256;

fn emit_unsigned(mut v: u64, radix: u64, upper: bool, out: &mut dyn FnMut(u8)) {
    let mut buf = [0u8; 20]; // u64 max = 20 decimal digits
    let mut n = 0usize;
    if v == 0 {
        out(b'0');
        return;
    }
    while v != 0 && n < buf.len() {
        let d = (v % radix) as u8;
        buf[n] = if d < 10 {
            b'0' + d
        } else if upper {
            b'A' + (d - 10)
        } else {
            b'a' + (d - 10)
        };
        v /= radix;
        n += 1;
    }
    while n > 0 {
        n -= 1;
        out(buf[n]);
    }
}

fn emit_signed(v: i64, out: &mut dyn FnMut(u8)) {
    if v < 0 {
        out(b'-');
        // Negate as u64 to handle i64::MIN without overflow.
        emit_unsigned((v as i128).unsigned_abs() as u64, 10, false, out);
    } else {
        emit_unsigned(v as u64, 10, false, out);
    }
}

fn emit_ptr(v: u64, out: &mut dyn FnMut(u8)) {
    out(b'0');
    out(b'x');
    // Fixed 16-digit for a canonical pointer.
    let mut shift = 60i32;
    while shift >= 0 {
        let d = ((v >> shift) & 0xF) as u8;
        out(if d < 10 { b'0' + d } else { b'a' + (d - 10) });
        shift -= 4;
    }
}

/// Format `fmt` into `out`, pulling `%`-arguments from `next_arg` in order.
pub fn format_dbg(
    fmt: &[u8],
    next_arg: &mut dyn FnMut() -> u64,
    read_cstr: &mut dyn FnMut(u64, &mut [u8]) -> usize,
    out: &mut dyn FnMut(u8),
) {
    let mut i = 0usize;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            out(c);
            i += 1;
            continue;
        }
        // Consume '%' then skip flags/width/precision/length modifiers.
        i += 1;
        while i < fmt.len() {
            let m = fmt[i];
            if matches!(m, b'-' | b'+' | b' ' | b'#' | b'0'..=b'9' | b'.' | b'l' | b'h' | b'w' | b'I') {
                i += 1;
            } else {
                break;
            }
        }
        if i >= fmt.len() {
            out(b'%');
            break;
        }
        let spec = fmt[i];
        i += 1;
        match spec {
            b'%' => out(b'%'),
            b's' | b'S' => {
                let ptr = next_arg();
                if ptr == 0 {
                    for b in b"(null)" {
                        out(*b);
                    }
                } else {
                    let mut buf = [0u8; CSTR_MAX];
                    let n = read_cstr(ptr, &mut buf);
                    for b in &buf[..n.min(CSTR_MAX)] {
                        out(*b);
                    }
                }
            }
            b'c' => out(next_arg() as u8),
            b'd' | b'i' => emit_signed(next_arg() as i32 as i64, out),
            b'u' => emit_unsigned(next_arg() & 0xFFFF_FFFF, 10, false, out),
            b'x' => emit_unsigned(next_arg() & 0xFFFF_FFFF, 16, false, out),
            b'X' => emit_unsigned(next_arg() & 0xFFFF_FFFF, 16, true, out),
            b'p' => emit_ptr(next_arg(), out),
            other => {
                out(b'%');
                out(other);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::vec::Vec;

    fn run(fmt: &[u8], args: &[u64], strings: &[(u64, &[u8])]) -> Vec<u8> {
        let mut idx = 0usize;
        let mut next = move || {
            let v = args[idx];
            idx += 1;
            v
        };
        let strings = strings.to_vec();
        let mut read = move |ptr: u64, buf: &mut [u8]| -> usize {
            for (p, s) in &strings {
                if *p == ptr {
                    let n = s.len().min(buf.len());
                    buf[..n].copy_from_slice(&s[..n]);
                    return n;
                }
            }
            0
        };
        let mut out = Vec::new();
        format_dbg(fmt, &mut next, &mut read, &mut |b| out.push(b));
        out
    }

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(run(b"hello world", &[], &[]), b"hello world");
    }

    #[test]
    fn signed_unsigned_hex_pointer() {
        assert_eq!(run(b"%d", &[(-5i64) as u64], &[]), b"-5");
        assert_eq!(run(b"%u", &[42], &[]), b"42");
        assert_eq!(run(b"%x", &[0xdead_beef], &[]), b"deadbeef");
        assert_eq!(run(b"%X", &[0xabc], &[]), b"ABC");
        assert_eq!(run(b"%p", &[0x1000], &[]), b"0x0000000000001000");
    }

    #[test]
    fn cstring_and_null() {
        assert_eq!(
            run(b"file=%s", &[0x2000], &[(0x2000, b"win32k.c")]),
            b"file=win32k.c"
        );
        assert_eq!(run(b"%s", &[0], &[]), b"(null)");
    }

    #[test]
    fn the_reactos_dprint_shape() {
        // The exact "(%s:%d) err: %x" shape currently printed UNSUBSTITUTED.
        assert_eq!(
            run(
                b"(%s:%d) err: %x",
                &[0x3000, 264, 0xc0000001],
                &[(0x3000, b"usrheap.c")]
            ),
            b"(usrheap.c:264) err: c0000001"
        );
    }

    #[test]
    fn width_and_length_modifiers_are_skipped() {
        assert_eq!(run(b"%08x", &[0x1f], &[]), b"1f");
        assert_eq!(run(b"%ld", &[(-7i64) as u64], &[]), b"-7");
        assert_eq!(run(b"%-5u", &[3], &[]), b"3");
        assert_eq!(run(b"%I64x", &[0x10], &[]), b"10");
    }

    #[test]
    fn literal_percent_and_unknown_spec() {
        assert_eq!(run(b"100%%", &[], &[]), b"100%");
        assert_eq!(run(b"%q", &[], &[]), b"%q");
    }

    #[test]
    fn trailing_percent() {
        assert_eq!(run(b"abc%", &[], &[]), b"abc%");
    }
}
