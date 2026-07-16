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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_is_identity() {
        let cookie = 0x1234_5678_9ABC_DEF0;
        for &p in &[0u64, 0x1000, 0x7FFF_FFFF_0000, 0xDEAD_BEEF_CAFE_BABE, u64::MAX] {
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
}
