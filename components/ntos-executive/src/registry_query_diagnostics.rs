//! Bounded failure receipts from already-captured registry syscall scalars.

use super::*;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_address_space::copy::MemoryCopyFailure;

static FAILURES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn reject(
    handler: &ExecNtHandler,
    stage: &[u8],
    arguments: &[u64; 5],
    status: u32,
    failure: Option<MemoryCopyFailure>,
) {
    // Expected sizing/access results must not exhaust the fault evidence budget.
    if status != nt_address_space::STATUS_ACCESS_VIOLATION {
        return;
    }
    let receipt = FAILURES.fetch_add(1, Ordering::Relaxed);
    if receipt >= 32 {
        return;
    }
    print_str(b"[registry-query-failed] stage=");
    print_str(stage);
    print_str(b" pi=");
    print_u64(handler.pi as u64);
    print_str(b" tid=");
    print_u64(handler.current_tid);
    print_str(b" badge=");
    print_u64(handler.current_badge);
    print_str(b" sp=0x");
    print_hex_u64(handler.current_sp);
    print_str(b" handle=0x");
    print_hex_u64(arguments[0]);
    print_str(b" class=");
    print_u64(arguments[1] as u32 as u64);
    print_str(b" output=0x");
    print_hex_u64(arguments[2]);
    print_str(b" length=");
    print_u64(arguments[3] as u32 as u64);
    print_str(b" result-length=0x");
    print_hex_u64(arguments[4]);
    print_str(b" status=0x");
    print_hex(status);
    if let Some(failure) = failure {
        print_str(b" copy-origin=");
        print_str(match failure {
            MemoryCopyFailure::UserFault(_) => b"user-fault",
            MemoryCopyFailure::Retry(_) => b"retry",
        });
        print_str(b" copy-status=0x");
        print_hex(failure.status());
    }
    print_str(b"\n");
}
