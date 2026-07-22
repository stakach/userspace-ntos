//! Pointer encode/decode `Rtl*` stragglers — `RtlEncodePointer`/`RtlDecodePointer` +
//! `RtlEncodeSystemPointer`/`RtlDecodeSystemPointer`.
//!
//! ntdll obfuscates stored function pointers (mitigation against pointer overwrites) by XOR-ing them
//! with a per-process **security cookie** (`PEB->Cookie`, `SharedUserData->Cookie` for the system
//! variants) and rotating. `EncodePointer`/`DecodePointer` are exact inverses. The cookie is
//! process state (set at PEB init from the loader); here the transform is pure over an explicit
//! cookie so it is fully host-tested, and the process-cookie source is the documented seam (arrives
//! from the Step-3 loader / `SharedUserData`).

/// The x64 rotate amount ntdll uses in the encode transform (`cookie & 0x3f`-style rotate; we use a
/// fixed rotate of the low cookie bits, matching the `_rotr64(value ^ cookie, cookie & 0x3F)`
/// shape — a bijection, so decode is the exact inverse).
#[inline]
fn rotate_bits(cookie: u64) -> u32 {
    (cookie & 0x3F) as u32
}

/// `RtlEncodePointer(Ptr)` — obfuscate `ptr` with the process `cookie`: `rotr64(ptr ^ cookie,
/// cookie & 0x3F)`.
pub fn encode_pointer(ptr: u64, cookie: u64) -> u64 {
    (ptr ^ cookie).rotate_right(rotate_bits(cookie))
}

/// `RtlDecodePointer(EncodedPtr)` — the exact inverse of [`encode_pointer`].
pub fn decode_pointer(encoded: u64, cookie: u64) -> u64 {
    encoded.rotate_left(rotate_bits(cookie)) ^ cookie
}

/// `RtlEncodeSystemPointer(Ptr)` — same transform with the system-wide cookie
/// (`SharedUserData->Cookie`).
pub fn encode_system_pointer(ptr: u64, system_cookie: u64) -> u64 {
    encode_pointer(ptr, system_cookie)
}

/// `RtlDecodeSystemPointer(EncodedPtr)` — the inverse of [`encode_system_pointer`].
pub fn decode_system_pointer(encoded: u64, system_cookie: u64) -> u64 {
    decode_pointer(encoded, system_cookie)
}

/// Select the nonzero byte seed used by `RtlRunEncodeUnicodeString`.
///
/// A caller-supplied nonzero hash wins. Otherwise ntdll scans bytes 1 through 7 of the current
/// system time in native little-endian order and falls back to one if the query failed or all
/// candidate bytes were zero.
pub fn run_encode_hash_with(hash: u8, query_system_time: impl FnOnce() -> Option<i64>) -> u8 {
    if hash != 0 {
        return hash;
    }
    query_system_time()
        .and_then(|time| {
            time.to_le_bytes()[1..]
                .iter()
                .copied()
                .find(|&byte| byte != 0)
        })
        .unwrap_or(1)
}

/// Encode the raw bytes covered by a `UNICODE_STRING.Length` in place.
pub fn run_encode_unicode_bytes(hash: u8, bytes: &mut [u8]) {
    let Some(first) = bytes.first_mut() else {
        return;
    };
    *first ^= hash | 0x43;
    for index in 1..bytes.len() {
        bytes[index] ^= bytes[index - 1] ^ hash;
    }
}

/// Decode the raw bytes covered by a `UNICODE_STRING.Length` in place.
pub fn run_decode_unicode_bytes(hash: u8, bytes: &mut [u8]) {
    for index in (1..bytes.len()).rev() {
        bytes[index] ^= bytes[index - 1] ^ hash;
    }
    if let Some(first) = bytes.first_mut() {
        *first ^= hash | 0x43;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_is_identity() {
        let cookie = 0x1234_5678_9ABC_DEF0;
        for &p in &[
            0u64,
            0x1000,
            0x7FFF_FFFF_0000,
            0xDEAD_BEEF_CAFE_BABE,
            u64::MAX,
        ] {
            assert_eq!(decode_pointer(encode_pointer(p, cookie), cookie), p);
        }
    }

    #[test]
    fn different_cookies_differ() {
        let p = 0x1400_1000;
        assert_ne!(encode_pointer(p, 0xAAAA), encode_pointer(p, 0xBBBB));
    }

    #[test]
    fn system_variants_round_trip() {
        let sc = 0xCAFE_F00D_1122_3344;
        let p = 0x7FFE_0000_ABCD;
        assert_eq!(decode_system_pointer(encode_system_pointer(p, sc), sc), p);
    }

    #[test]
    fn zero_cookie_is_still_bijective() {
        // A zero cookie degenerates to XOR-0 + rotate-0 = identity, still a valid bijection.
        assert_eq!(decode_pointer(encode_pointer(0x99, 0), 0), 0x99);
    }

    #[test]
    fn run_encode_matches_known_vectors() {
        let mut empty = [];
        run_encode_unicode_bytes(0x12, &mut empty);
        assert_eq!(empty, []);

        let mut one = [0xaa];
        run_encode_unicode_bytes(0x20, &mut one);
        assert_eq!(one, [0xc9]);

        let mut odd = [1, 2, 3];
        run_encode_unicode_bytes(5, &mut odd);
        assert_eq!(odd, [0x46, 0x41, 0x47]);

        let mut even = [0x10, 0x20, 0x30, 0x40];
        run_encode_unicode_bytes(0x12, &mut even);
        assert_eq!(even, [0x43, 0x71, 0x53, 0x01]);
    }

    #[test]
    fn run_encode_decode_round_trip_for_byte_lengths() {
        for length in 0..=9 {
            let mut value = [0u8; 9];
            for (index, byte) in value[..length].iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
            }
            let original = value;
            run_encode_unicode_bytes(0xa6, &mut value[..length]);
            run_decode_unicode_bytes(0xa6, &mut value[..length]);
            assert_eq!(value, original);
        }
    }

    #[test]
    fn run_encode_hash_uses_time_bytes_and_nonzero_fallback() {
        assert_eq!(
            run_encode_hash_with(0x7c, || panic!("unexpected query")),
            0x7c
        );
        assert_eq!(
            run_encode_hash_with(0, || Some(0x1122_3344_5566_7700)),
            0x77
        );
        assert_eq!(run_encode_hash_with(0, || Some(0xfe)), 1);
        assert_eq!(run_encode_hash_with(0, || Some(0)), 1);
        assert_eq!(run_encode_hash_with(0, || None), 1);
    }
}
