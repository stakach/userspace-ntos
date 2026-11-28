//! Small PE-entry check for recursive compiler CRT exports.
//!
//! A weak exported `memcpy`/`memset` body may be lowered to the same intrinsic symbol. The
//! resulting direct branch to its own entry spins forever when the DLL is loaded.

/// Recognize a direct near/short jump or call whose destination is this instruction's entry.
/// The PE verifier checks the actual exported RVA before a DLL is staged for native boot.
pub(super) fn directly_recurses(bytes: &[u8]) -> bool {
    match bytes.first().copied() {
        Some(0xe9 | 0xe8) => bytes.get(1..5).is_some_and(|disp| {
            let displacement = i32::from_le_bytes(disp.try_into().expect("five-byte instruction"));
            displacement == -5
        }),
        Some(0xeb) => bytes.get(1).is_some_and(|disp| *disp == 0xfe),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::directly_recurses;

    #[test]
    fn recognizes_self_branches_and_calls_without_rejecting_other_targets() {
        assert!(directly_recurses(&[0xe9, 0xfb, 0xff, 0xff, 0xff]));
        assert!(directly_recurses(&[0xe8, 0xfb, 0xff, 0xff, 0xff]));
        assert!(directly_recurses(&[0xeb, 0xfe]));
        assert!(!directly_recurses(&[0xe9, 0, 0, 0, 0]));
        assert!(!directly_recurses(&[0xeb, 0]));
        assert!(!directly_recurses(&[0x57, 0x48, 0x89, 0xc8, 0xf3]));
        assert!(!directly_recurses(&[0xe9, 0xfb]));
    }
}
