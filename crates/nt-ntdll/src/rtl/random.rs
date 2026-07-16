//! `Rtl*` pseudo-random + checksum primitives.
//!
//! `RtlRandom` / `RtlRandomEx` / `RtlUniform` — the classic ntdll LCG (a linear-congruential
//! generator whose exact constants ntdll ships, so seeded sequences reproduce). `RtlComputeCrc32`
//! — the standard CRC-32 (IEEE 802.3 reflected polynomial `0xEDB88320`).
//!
//! Category A. Host-tested against known vectors.

/// `RtlUniform`: one step of ntdll's LCG (`x' = (x * 0x7fffffed + 0x7fffffc3) mod 0x7fffffff`).
/// Advances `*seed` in place and returns the new value.
pub fn uniform(seed: &mut u32) -> u32 {
    // The ntdll constants (`RtlUniform` in sdk/lib/rtl/random.c).
    *seed = ((*seed as u64 * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff) as u32;
    *seed
}

/// `RtlRandom`: returns a pseudo-random value in `[0, 0x7fffffff)`, advancing `*seed`. ntdll layers
/// a scramble table over `RtlUniform`; we use the underlying LCG directly (deterministic + adequate
/// for the non-cryptographic callers, e.g. temp-name generation).
pub fn random(seed: &mut u32) -> u32 {
    uniform(seed)
}

/// `RtlRandomEx`: identical generator to [`random`] (the `Ex` variant differs only in the scramble
/// table, irrelevant to the LCG core).
pub fn random_ex(seed: &mut u32) -> u32 {
    uniform(seed)
}

/// CRC-32 (IEEE, reflected). Table-free bitwise form for `no_std`.
pub fn compute_crc32(initial: u32, data: &[u8]) -> u32 {
    let mut crc = !initial;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_is_deterministic_and_advances() {
        let mut s1 = 12345;
        let mut s2 = 12345;
        let a = uniform(&mut s1);
        let b = uniform(&mut s2);
        assert_eq!(a, b); // same seed -> same sequence
        let c = uniform(&mut s1);
        assert_ne!(a, c); // advances
        // Stays in range.
        for _ in 0..1000 {
            assert!(uniform(&mut s1) < 0x7fff_ffff);
        }
    }

    #[test]
    fn crc32_known_vectors() {
        // CRC-32 of "" is 0; of "123456789" is 0xCBF43926 (the canonical check value).
        assert_eq!(compute_crc32(0, b""), 0);
        assert_eq!(compute_crc32(0, b"123456789"), 0xCBF4_3926);
        // "The quick brown fox jumps over the lazy dog"
        assert_eq!(
            compute_crc32(0, b"The quick brown fox jumps over the lazy dog"),
            0x414F_A339
        );
    }
}
