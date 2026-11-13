//! Completion verdict for the executive's startup acceptance snapshot.

pub(crate) fn complete(passed: u64, total: u64) -> bool {
    total != 0 && passed == total
}
