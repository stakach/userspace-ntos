//! Bounded observations of actual missing values, not registry admission or lifetime authority.
//! Exhausting this budget means absence of a receipt cannot prove absence of later failures.
use core::sync::atomic::{AtomicU64, Ordering};

const RECEIPT_LIMIT: u64 = 128;
const PATH_BYTE_LIMIT: usize = 256;
const VALUE_UNIT_LIMIT: usize = 64;
const HEX: &[u8; 16] = b"0123456789abcdef";
static EMITTED: AtomicU64 = AtomicU64::new(0);

fn hex_escape(value: u16, wide: bool) {
    let mut bytes = [b'\\', b'u', b'0', b'0', b'0', b'0'];
    if wide {
        for index in 0..4 {
            bytes[index + 2] = HEX[((value >> ((3 - index) * 4)) & 15) as usize];
        }
        crate::print_str(&bytes);
    } else {
        bytes[1] = b'x';
        bytes[2] = HEX[((value >> 4) & 15) as usize];
        bytes[3] = HEX[(value & 15) as usize];
        crate::print_str(&bytes[..4]);
    }
}

fn path_bytes(path: &[u8]) {
    for &byte in path.iter().take(PATH_BYTE_LIMIT) {
        if (0x20..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\' {
            crate::print_str(&[byte]);
        } else {
            hex_escape(u16::from(byte), false);
        }
    }
}

fn value_units(value: &[u16]) {
    for &unit in value.iter().take(VALUE_UNIT_LIMIT) {
        if (0x20..=0x7e).contains(&unit) && unit != u16::from(b'"') && unit != u16::from(b'\\') {
            crate::print_str(&[unit as u8]);
        } else {
            hex_escape(unit, true);
        }
    }
}

/// All inputs are previously captured observations. The key target is not a reusable credential.
pub(crate) fn missing_value(
    pid: Option<u32>, tid: u64, pi: usize, key: u32, path: Option<&str>, name: &[u16],
) {
    let Ok(previous) = EMITTED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        (count < RECEIPT_LIMIT).then(|| count + 1)
    }) else { return; };
    crate::print_str(b"[registry-query-miss] receipt=");
    crate::print_u64(previous + 1);
    crate::print_str(b"/");
    crate::print_u64(RECEIPT_LIMIT);
    crate::print_str(b" pid=");
    match pid {
        Some(pid) => crate::print_u64(u64::from(pid)),
        None => crate::print_str(b"unavailable"),
    }
    crate::print_str(b" tid=");
    crate::print_u64(tid);
    crate::print_str(b" pi=");
    crate::print_u64(pi as u64);
    crate::print_str(b" key-target=");
    crate::print_u64(u64::from(key));
    crate::print_str(b" status=0xc0000034 path-present=");
    crate::print_u64(u64::from(path.is_some()));
    let path = path.unwrap_or("").as_bytes();
    crate::print_str(b" path-bytes=");
    crate::print_u64(path.len() as u64);
    crate::print_str(b" path-truncated=");
    crate::print_u64(u64::from(path.len() > PATH_BYTE_LIMIT));
    crate::print_str(b" path=\"");
    path_bytes(path);
    crate::print_str(b"\" value-units=");
    crate::print_u64(name.len() as u64);
    crate::print_str(b" value-truncated=");
    crate::print_u64(u64::from(name.len() > VALUE_UNIT_LIMIT));
    crate::print_str(b" value=\"");
    value_units(name);
    crate::print_str(b"\"\n");
}
