//! Named-pipe prefix-table matching — the pure logic behind the `RtlInsertUnicodePrefix` /
//! `RtlFindUnicodePrefix` primitives npfs uses to map a pipe NAME (a `UNICODE_STRING`, e.g.
//! `\ntsvcs`) to its FCB (File Control Block).
//!
//! npfs (references/reactos/drivers/filesystems/npfs) builds a `UNICODE_PREFIX_TABLE` in its VCB and:
//!   * `RtlInsertUnicodePrefix(&Table, &Fcb->FullName, &Fcb->PrefixTableEntry)` per created pipe
//!     (`NpCreateFcb`) + once for the root DCB (`NpCreateRootDcb`, name `\`).
//!   * `RtlFindUnicodePrefix(&Table, FullName, 1)` per create/open (`NpFindPrefix`), which returns
//!     the LONGEST inserted name that is a path-prefix of `FullName` (a NUL/`\`-terminated component
//!     boundary), then `NpFindPrefix` computes the residual `Prefix` from the matched length.
//!
//! The real ntoskrnl uses a splay tree of `UNICODE_STRING`s bucketed by name-component count. For a
//! single-threaded host the observable contract is just: **insert(name)** and **find(full) = the
//! longest inserted name that is a component-prefix of `full`**. This module implements that contract
//! over `&[u16]` (UTF-16, case-insensitive on ASCII) so it can be host-tested, and the npfs component
//! wraps it around a fixed-capacity static table (no `alloc` in the isolated component).
//!
//! "Component-prefix" (matching `RtlFindUnicodePrefix`): `cand` is a prefix of `full` iff `cand` is a
//! case-insensitive prefix of `full` AND the char in `full` right after `cand` is either absent (exact
//! match) or a path separator `\`. The single-char root `\` matches everything.

/// The path separator (`\`), as UTF-16.
pub const SEP: u16 = b'\\' as u16;

/// ASCII case-insensitive UTF-16 char compare (only A-Z/a-z folded; the pipe namespace is ASCII).
#[inline]
fn eq_ci(a: u16, b: u16) -> bool {
    let fold = |c: u16| -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&c) {
            c + 32
        } else {
            c
        }
    };
    fold(a) == fold(b)
}

/// Is `cand` a *component-prefix* of `full` (the `RtlFindUnicodePrefix` contract)?
///
/// True iff `cand` case-insensitively matches the leading chars of `full` and the following char in
/// `full` is either end-of-string or `\`. The lone root `\` is a prefix of every rooted name.
pub fn is_component_prefix(cand: &[u16], full: &[u16]) -> bool {
    if cand.is_empty() {
        return true;
    }
    if cand.len() > full.len() {
        return false;
    }
    for i in 0..cand.len() {
        if !eq_ci(cand[i], full[i]) {
            return false;
        }
    }
    // The lone root separator matches anything beginning with `\`.
    if cand.len() == 1 && cand[0] == SEP {
        return true;
    }
    // Exact match, or the next char is a component boundary.
    full.len() == cand.len() || full[cand.len()] == SEP
}

/// Given a set of inserted candidate names and a full name, return the index of the LONGEST candidate
/// that is a component-prefix of `full` (ties broken by first-seen — the root `\` is shortest so a
/// specific pipe name always wins). `None` if nothing matches (should never happen once the root `\`
/// is inserted — npfs bug-checks on a NULL find).
pub fn find_longest_prefix<'a>(cands: impl Iterator<Item = (usize, &'a [u16])>, full: &[u16]) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None; // (idx, matched-len)
    for (idx, cand) in cands {
        if is_component_prefix(cand, full) {
            let l = cand.len();
            match best {
                Some((_, bl)) if bl >= l => {}
                _ => best = Some((idx, l)),
            }
        }
    }
    best.map(|(idx, _)| idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(t: &str) -> alloc::vec::Vec<u16> {
        t.encode_utf16().collect()
    }

    #[test]
    fn root_matches_everything() {
        assert!(is_component_prefix(&s("\\"), &s("\\ntsvcs")));
        assert!(is_component_prefix(&s("\\"), &s("\\")));
    }

    #[test]
    fn exact_and_boundary() {
        assert!(is_component_prefix(&s("\\ntsvcs"), &s("\\ntsvcs")));
        assert!(is_component_prefix(&s("\\ntsvcs"), &s("\\ntsvcs\\sub")));
        // not a component boundary
        assert!(!is_component_prefix(&s("\\ntsvc"), &s("\\ntsvcs")));
        assert!(!is_component_prefix(&s("\\other"), &s("\\ntsvcs")));
    }

    #[test]
    fn case_insensitive() {
        assert!(is_component_prefix(&s("\\NtSvcs"), &s("\\ntsvcs")));
        assert!(is_component_prefix(&s("\\ntsvcs"), &s("\\NTSVCS")));
    }

    #[test]
    fn longest_wins_over_root() {
        let names = [s("\\"), s("\\ntsvcs")];
        let iter = names.iter().enumerate().map(|(i, v)| (i, v.as_slice()));
        let full = s("\\ntsvcs");
        assert_eq!(find_longest_prefix(iter, &full), Some(1));
    }

    #[test]
    fn only_root_matches_unknown() {
        let names = [s("\\"), s("\\ntsvcs")];
        let iter = names.iter().enumerate().map(|(i, v)| (i, v.as_slice()));
        let full = s("\\winreg");
        // only the root is a prefix of an unrelated name
        assert_eq!(find_longest_prefix(iter, &full), Some(0));
    }

    #[test]
    fn no_match_without_root() {
        let names = [s("\\ntsvcs")];
        let iter = names.iter().enumerate().map(|(i, v)| (i, v.as_slice()));
        assert_eq!(find_longest_prefix(iter, &s("\\winreg")), None);
    }
}
