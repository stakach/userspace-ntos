//! Runtime hosted-process metadata used by post-loop proof gates.
#![allow(clippy::all)]
use crate::*;

static HOSTED_GATE_EXPECTED_MASK: AtomicU64 = AtomicU64::new(0);
static HOSTED_GATE_USERINIT_PI: AtomicU64 = AtomicU64::new(u64::MAX);
static HOSTED_GATE_EXPLORER_PI: AtomicU64 = AtomicU64::new(u64::MAX);

pub(crate) fn reset_hosted_gate_metadata() {
    HOSTED_GATE_EXPECTED_MASK.store(0, Ordering::Relaxed);
    HOSTED_GATE_USERINIT_PI.store(u64::MAX, Ordering::Relaxed);
    HOSTED_GATE_EXPLORER_PI.store(u64::MAX, Ordering::Relaxed);
}

pub(crate) fn publish_hosted_gate_image(image: nt_exe_image::HostedProcessImageRef<'_>) {
    if image.pi < 64 {
        HOSTED_GATE_EXPECTED_MASK.fetch_or(1u64 << image.pi, Ordering::Relaxed);
    }
    if image.leaf.eq_ignore_ascii_case(b"userinit.exe") {
        HOSTED_GATE_USERINIT_PI.store(image.pi as u64, Ordering::Relaxed);
    } else if image.leaf.eq_ignore_ascii_case(b"explorer.exe") {
        HOSTED_GATE_EXPLORER_PI.store(image.pi as u64, Ordering::Relaxed);
    }
}

pub(crate) fn hosted_gate_pi(leaf: &[u8]) -> Option<usize> {
    let pi = if leaf.eq_ignore_ascii_case(b"userinit.exe") {
        HOSTED_GATE_USERINIT_PI.load(Ordering::Relaxed)
    } else if leaf.eq_ignore_ascii_case(b"explorer.exe") {
        HOSTED_GATE_EXPLORER_PI.load(Ordering::Relaxed)
    } else {
        u64::MAX
    };
    (pi != u64::MAX && (pi as usize) < MAX_PI).then_some(pi as usize)
}

pub(crate) fn hosted_gate_bit(leaf: &[u8]) -> u64 {
    match hosted_gate_pi(leaf) {
        Some(pi) if pi < 64 => 1u64 << pi,
        _ => 0,
    }
}

pub(crate) fn hosted_gate_mask() -> u64 {
    HOSTED_GATE_EXPECTED_MASK.load(Ordering::Relaxed)
}

pub(crate) fn hosted_gate_count() -> u64 {
    hosted_gate_mask().count_ones() as u64
}
