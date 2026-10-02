use nt_config_store::codec::{crc32c, Crc32c};

// Deliberately independent of the production lookup table and update implementation.
fn bitwise_castagnoli(bytes: &[u8]) -> u32 {
    let mut remainder = u32::MAX;
    for &byte in bytes {
        remainder ^= u32::from(byte);
        for _ in 0..8 {
            let low_bit = remainder & 1;
            remainder >>= 1;
            if low_bit != 0 {
                remainder ^= 0x82f6_3b78;
            }
        }
    }
    !remainder
}

fn patterned_bytes(len: usize) -> Vec<u8> {
    let mut state = 0x17c9_34abu32;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn incremental(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finish()
}

#[test]
fn incremental_crc32c_preserves_known_castagnoli_vectors() {
    for (bytes, expected) in [(&b""[..], 0u32), (&b"123456789"[..], 0xe306_9283)] {
        assert_eq!(bitwise_castagnoli(bytes), expected);
        assert_eq!(crc32c(bytes), expected);
        assert_eq!(incremental(bytes), expected);
    }
    assert_eq!(Crc32c::new().finish(), 0);
}

#[test]
fn incremental_crc32c_matches_independent_oracle_for_all_bytes_and_long_inputs() {
    let all_bytes: Vec<u8> = (0..=255).collect();
    let long = patterned_bytes(8193);
    for bytes in [all_bytes.as_slice(), long.as_slice()] {
        let expected = bitwise_castagnoli(bytes);
        assert_eq!(crc32c(bytes), expected);
        assert_eq!(incremental(bytes), expected);
    }
    for byte in 0..=255u8 {
        assert_eq!(incremental(&[byte]), bitwise_castagnoli(&[byte]));
    }
}

#[test]
fn incremental_crc32c_every_split_preserves_state_across_empty_updates() {
    let bytes = patterned_bytes(513);
    let expected = bitwise_castagnoli(&bytes);
    for split in 0..=bytes.len() {
        let mut crc = Crc32c::new();
        crc.update(&[]);
        crc.update(&bytes[..split]);
        crc.update(&[]);
        crc.update(&[]);
        crc.update(&bytes[split..]);
        crc.update(&[]);
        assert_eq!(crc.finish(), expected, "split {split}");
    }
}

#[test]
fn incremental_crc32c_arbitrary_chunk_sizes_match_one_shot_and_oracle() {
    let bytes = patterned_bytes(8193);
    let expected = bitwise_castagnoli(&bytes);
    assert_eq!(crc32c(&bytes), expected);
    for chunk_size in [1, 2, 3, 7, 31, 255, 511, 512, 513, 2048, 4096, 8193, 8194] {
        let mut crc = Crc32c::new();
        for chunk in bytes.chunks(chunk_size) {
            crc.update(&[]);
            crc.update(chunk);
        }
        crc.update(&[]);
        assert_eq!(crc.finish(), expected, "chunk size {chunk_size}");
    }
}

#[test]
fn incremental_crc32c_checks_only_supplied_logical_bytes_at_sector_boundaries() {
    let bytes = patterned_bytes(4096);
    for logical_len in [0usize, 1, 511, 512, 513, 2047, 2048, 2049, 4095, 4096] {
        let expected = bitwise_castagnoli(&bytes[..logical_len]);
        let mut padded = bytes.clone();
        padded[logical_len..].fill(0xa5);
        let mut crc = Crc32c::new();
        for chunk in padded[..logical_len].chunks(2048) {
            crc.update(chunk);
        }
        assert_eq!(crc.finish(), expected, "logical length {logical_len}");
    }
}
