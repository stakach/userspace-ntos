//! Bounded observations of actual missing values, not registry admission or lifetime authority.
//! Exhausting this budget means absence of a receipt cannot prove absence of later failures.
use core::sync::atomic::{AtomicU64, Ordering};

const RECEIPT_LIMIT: u64 = 128;
const LIFETIME_RECEIPT_LIMIT: u64 = 8192;
const WINDOW_100NS: u64 = 60 * 10_000_000;
const PATH_BYTE_LIMIT: usize = 256;
const VALUE_UNIT_LIMIT: usize = 64;
const HEX: &[u8; 16] = b"0123456789abcdef";
const COUNT_BITS: u32 = 8;
const LIFETIME_BITS: u32 = 14;
const EPOCH_BITS: u32 = 35;
const COUNT_MASK: u64 = (1 << COUNT_BITS) - 1;
const LIFETIME_MASK: u64 = (1 << LIFETIME_BITS) - 1;
const EPOCH_MASK: u64 = (1 << EPOCH_BITS) - 1;
const EPOCH_SHIFT: u32 = COUNT_BITS + LIFETIME_BITS;
const CLOCK_KNOWN: u64 = 1 << (EPOCH_SHIFT + EPOCH_BITS);
const _: () = assert!(RECEIPT_LIMIT <= COUNT_MASK);
const _: () = assert!(LIFETIME_RECEIPT_LIMIT <= LIFETIME_MASK);
const _: () = assert!(u64::MAX / WINDOW_100NS <= EPOCH_MASK);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BudgetReceipt {
    pub(crate) receipt: u64,
    pub(crate) lifetime_receipt: u64,
    pub(crate) window: Option<u64>,
}

/// Window and lifetime claims share one CAS, so contention cannot consume a partial claim.
pub(crate) struct ReceiptBudget {
    state: AtomicU64,
}

impl ReceiptBudget {
    pub(crate) const fn new() -> Self {
        Self { state: AtomicU64::new(0) }
    }

    pub(crate) fn claim(&self, now: Option<u64>) -> Option<BudgetReceipt> {
        let previous = self.state.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
            next_claim(state, now).map(|(next, _)| next)
        }).ok()?;
        next_claim(previous, now).map(|(_, receipt)| receipt)
    }
}

fn next_claim(state: u64, now: Option<u64>) -> Option<(u64, BudgetReceipt)> {
    let mut count = state & COUNT_MASK;
    let lifetime = (state >> COUNT_BITS) & LIFETIME_MASK;
    let mut epoch = (state >> EPOCH_SHIFT) & EPOCH_MASK;
    let mut known = state & CLOCK_KNOWN != 0;
    if lifetime >= LIFETIME_RECEIPT_LIMIT { return None; }
    if let Some(now) = now {
        let observed = now / WINDOW_100NS;
        if !known || observed > epoch {
            count = 0;
            epoch = observed;
            known = true;
        }
    }
    if count >= RECEIPT_LIMIT { return None; }
    let receipt = BudgetReceipt {
        receipt: count + 1,
        lifetime_receipt: lifetime + 1,
        window: known.then_some(epoch),
    };
    let next = receipt.receipt
        | (receipt.lifetime_receipt << COUNT_BITS)
        | (epoch << EPOCH_SHIFT)
        | if known { CLOCK_KNOWN } else { 0 };
    Some((next, receipt))
}

static BUDGET: ReceiptBudget = ReceiptBudget::new();

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
    let Some(receipt) = BUDGET.claim(crate::registry_query_audit_time_100ns()) else { return; };
    crate::print_str(b"[registry-query-miss] receipt=");
    crate::print_u64(receipt.receipt);
    crate::print_str(b"/");
    crate::print_u64(RECEIPT_LIMIT);
    crate::print_str(b" lifetime-receipt=");
    crate::print_u64(receipt.lifetime_receipt);
    crate::print_str(b"/");
    crate::print_u64(LIFETIME_RECEIPT_LIMIT);
    crate::print_str(b" window=");
    match receipt.window {
        Some(window) => crate::print_u64(window),
        None => crate::print_str(b"unavailable"),
    }
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
