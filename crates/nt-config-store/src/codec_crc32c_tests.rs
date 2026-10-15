use super::{crc32c, crc32c_combine};
use alloc::vec::Vec;

fn bitwise_crc(bytes: &[u8]) -> u32 {
    let mut value = u32::MAX;
    for &byte in bytes {
        value ^= u32::from(byte);
        for _ in 0..8 {
            value = (value >> 1) ^ if value & 1 != 0 { 0x82f6_3b78 } else { 0 };
        }
    }
    !value
}

// Independent oracle: ordinary (non-reflected) polynomial multiplication and
// modular exponentiation, not matrices or the production reflected CRC table.
fn polynomial_product(mut a: u32, mut b: u32) -> u32 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = (a << 1) ^ if a & 0x8000_0000 != 0 { 0x1edc_6f41 } else { 0 };
        b >>= 1;
    }
    product
}

fn zero_byte_power(mut byte_length: u64) -> u32 {
    let mut result = 1;
    let mut power = 0x100;
    while byte_length != 0 {
        if byte_length & 1 != 0 {
            result = polynomial_product(result, power);
        }
        power = polynomial_product(power, power);
        byte_length >>= 1;
    }
    result
}

fn append_zeros(crc: u32, count: u64) -> u32 {
    !polynomial_product((!crc).reverse_bits(), zero_byte_power(count)).reverse_bits()
}

#[test]
fn finalized_checksums_preserve_empty_and_known_vector() {
    assert_eq!(crc32c_combine(0, 0, 0), 0);
    assert_eq!(crc32c_combine(crc32c(b"1234"), 0, 0), crc32c(b"1234"));
    assert_eq!(crc32c_combine(0, crc32c(b"56789"), 5), crc32c(b"56789"));
    assert_eq!(
        crc32c_combine(crc32c(b"1234"), crc32c(b"56789"), 5),
        0xe306_9283
    );
}

#[test]
fn all_splits_match_independent_bitwise_oracle() {
    for length in [0, 1, 7, 31, 255, 511, 512, 513] {
        let bytes: Vec<_> = (0..length)
            .map(|i| ((i * 73 + i / 11) & 255) as u8)
            .collect();
        let expected = bitwise_crc(&bytes);
        for split in 0..=length {
            assert_eq!(
                crc32c_combine(
                    bitwise_crc(&bytes[..split]),
                    bitwise_crc(&bytes[split..]),
                    (length - split) as u64,
                ),
                expected,
                "length={length} split={split}"
            );
        }
    }
}

#[test]
fn sector_batch_boundaries_and_associativity_preserve_exact_bytes() {
    let bytes: Vec<_> = (0..8193).map(|i| ((i * 37 + i / 19) & 255) as u8).collect();
    let expected = bitwise_crc(&bytes);
    for split in [
        0, 1, 511, 512, 513, 2047, 2048, 2049, 4095, 4096, 4097, 8193,
    ] {
        for second in [split, (split + bytes.len()) / 2, bytes.len()] {
            let a = bitwise_crc(&bytes[..split]);
            let b = bitwise_crc(&bytes[split..second]);
            let c = bitwise_crc(&bytes[second..]);
            let ab = crc32c_combine(a, b, (second - split) as u64);
            let bc = crc32c_combine(b, c, (bytes.len() - second) as u64);
            assert_eq!(
                crc32c_combine(ab, c, (bytes.len() - second) as u64),
                expected
            );
            assert_eq!(
                crc32c_combine(a, bc, (bytes.len() - split) as u64),
                expected
            );
        }
    }
}

#[test]
fn huge_suffix_lengths_match_independent_polynomial_oracle() {
    // First validate the logarithmic oracle against actual zero bytes.
    for length in [0, 1, 7, 32, 511, 2049] {
        let mut bytes = b"prefix".to_vec();
        bytes.resize(bytes.len() + length, 0);
        assert_eq!(
            append_zeros(bitwise_crc(b"prefix"), length as u64),
            bitwise_crc(&bytes)
        );
    }
    for length in [
        0,
        1,
        255,
        65537,
        u32::MAX as u64,
        1u64 << 32,
        (1u64 << 32) + 1,
        1u64 << 63,
        (1u64 << 63) + 17,
        u64::MAX,
    ] {
        let suffix_crc = append_zeros(0, length);
        for prefix_crc in [0, u32::MAX, bitwise_crc(b"prefix"), 0x1234_5678] {
            assert_eq!(
                crc32c_combine(prefix_crc, suffix_crc, length),
                append_zeros(prefix_crc, length),
                "length={length} prefix_crc={prefix_crc:08x}"
            );
        }
    }
}
