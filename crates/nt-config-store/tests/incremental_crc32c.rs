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
fn incremental_crc32c_all_block_tail_lengths_offsets_and_chunk_sizes_match_oracle() {
    let backing = patterned_bytes(257 + 7);
    for offset in 0..8 {
        for length in 0..=257 {
            let bytes = &backing[offset..offset + length];
            let expected = bitwise_castagnoli(bytes);
            assert_eq!(crc32c(bytes), expected, "offset {offset} length {length}");
            for chunk_size in 1..=17 {
                let mut crc = Crc32c::new();
                crc.update(&[]);
                for chunk in bytes.chunks(chunk_size) {
                    crc.update(chunk);
                    crc.update(&[]);
                }
                assert_eq!(
                    crc.finish(),
                    expected,
                    "offset {offset} length {length} chunk size {chunk_size}"
                );
            }
        }
    }
}

#[test]
fn incremental_crc32c_mixed_block_tail_and_empty_fragments_preserve_stream() {
    let backing = patterned_bytes(513 + 7);
    let fragments = [0usize, 1, 7, 8, 9, 0, 15, 16, 17, 31];
    for offset in 0..8 {
        for length in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 513] {
            let bytes = &backing[offset..offset + length];
            let expected = bitwise_castagnoli(bytes);
            for first_fragment in 0..fragments.len() {
                let mut crc = Crc32c::new();
                let mut consumed = 0;
                let mut step = first_fragment;
                while consumed < bytes.len() {
                    let count = fragments[step % fragments.len()].min(bytes.len() - consumed);
                    crc.update(&bytes[consumed..consumed + count]);
                    crc.update(&[]);
                    consumed += count;
                    step += 1;
                }
                crc.update(&[]);
                assert_eq!(
                    crc.finish(),
                    expected,
                    "offset {offset} length {length} first fragment {first_fragment}"
                );
            }
        }
    }
}

#[test]
fn incremental_crc32c_excludes_poisoned_prefix_and_suffix_at_block_boundaries() {
    let payload = patterned_bytes(257);
    for offset in 0..8 {
        for length in 0..=payload.len() {
            let expected = bitwise_castagnoli(&payload[..length]);
            for poison in [0x00, 0xa5, 0xff] {
                let mut backing = vec![poison; offset + length + 16];
                backing[offset..offset + length].copy_from_slice(&payload[..length]);
                let bytes = &backing[offset..offset + length];
                assert_eq!(
                    crc32c(bytes),
                    expected,
                    "offset {offset} length {length} poison {poison:02x}"
                );
                let mut crc = Crc32c::new();
                for chunk in bytes.chunks(9) {
                    crc.update(chunk);
                }
                crc.update(&[]);
                assert_eq!(
                    crc.finish(),
                    expected,
                    "fragmented offset {offset} length {length} poison {poison:02x}"
                );
            }
        }
    }
}

#[test]
fn incremental_crc32c_representative_snapshot_sized_stream_matches_oracle() {
    let bytes = patterned_bytes(1_469_377);
    let expected = bitwise_castagnoli(&bytes);
    assert_eq!(crc32c(&bytes), expected);
    for chunk_size in [2048, 4097, 65537] {
        let mut crc = Crc32c::new();
        for chunk in bytes.chunks(chunk_size) {
            crc.update(chunk);
            crc.update(&[]);
        }
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
