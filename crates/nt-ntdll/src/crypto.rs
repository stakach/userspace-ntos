//! Small compatibility crypto exports hosted by ntdll.
//!
//! ReactOS exposes the legacy `A_SHA*` SHA-1 routines from ntdll for Vista+ compatibility. The ABI
//! uses the `SHA_CTX` layout from `sdk/lib/cryptlib/sha1.h`; keep that layout byte-exact so the DLL
//! wrappers can pass caller-owned contexts directly into this core.

/// ReactOS/Windows `SHA_CTX`:
/// `UCHAR Buffer[64]; ULONG State[5]; ULONG Count[2];`
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShaContext {
    pub buffer: [u8; 64],
    pub state: [u32; 5],
    pub count: [u32; 2],
}

impl ShaContext {
    pub const fn zeroed() -> Self {
        Self {
            buffer: [0; 64],
            state: [0; 5],
            count: [0; 2],
        }
    }
}

/// `A_SHAInit(PSHA_CTX)`.
pub fn a_sha_init(context: &mut ShaContext) {
    context.state = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    context.count = [0, 0];
}

/// `A_SHAUpdate(PSHA_CTX, const unsigned char*, ULONG)`.
pub fn a_sha_update(context: &mut ShaContext, mut input: &[u8]) {
    let mut buffered = (context.count[1] & 63) as usize;
    let input_len = input.len() as u32;

    context.count[1] = context.count[1].wrapping_add(input_len);
    if context.count[1] < input_len {
        context.count[0] = context.count[0].wrapping_add(1);
    }
    context.count[0] = context.count[0].wrapping_add(input_len >> 29);

    if buffered + input.len() < 64 {
        context.buffer[buffered..buffered + input.len()].copy_from_slice(input);
        return;
    }

    if buffered != 0 {
        let fill = 64 - buffered;
        context.buffer[buffered..].copy_from_slice(&input[..fill]);
        sha1_transform(&mut context.state, &context.buffer);
        input = &input[fill..];
        buffered = 0;
    }

    while input.len() >= 64 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&input[..64]);
        sha1_transform(&mut context.state, &block);
        input = &input[64..];
    }

    context.buffer[buffered..buffered + input.len()].copy_from_slice(input);
}

/// `A_SHAFinal(PSHA_CTX, PULONG)`.
///
/// The result words are stored in the same byte order as ReactOS' `DWORD2BE(State[i])`: on little
/// endian targets, reading the `PULONG` memory as bytes yields the canonical SHA-1 digest.
pub fn a_sha_final(context: &mut ShaContext, result: &mut [u32; 5]) {
    let buffered = (context.count[1] & 63) as usize;
    let pad = if buffered >= 56 {
        56 + 64 - buffered
    } else {
        56 - buffered
    };

    let length_hi = (context.count[0] << 3) | (context.count[1] >> 29);
    let length_lo = context.count[1] << 3;

    let mut tail = [0u8; 72];
    tail[0] = 0x80;
    tail[pad..pad + 4].copy_from_slice(&length_hi.to_be_bytes());
    tail[pad + 4..pad + 8].copy_from_slice(&length_lo.to_be_bytes());
    a_sha_update(context, &tail[..pad + 8]);

    for (out, state) in result.iter_mut().zip(context.state.iter()) {
        *out = state.to_be();
    }

    context.buffer.fill(0);
    a_sha_init(context);
}

fn sha1_transform(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (i, chunk) in block.chunks_exact(4).take(16).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for (i, word) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(input: &[u8]) -> [u8; 20] {
        let mut context = ShaContext::zeroed();
        let mut words = [0u32; 5];
        a_sha_init(&mut context);
        a_sha_update(&mut context, input);
        a_sha_final(&mut context, &mut words);

        let mut out = [0u8; 20];
        for (chunk, word) in out.chunks_exact_mut(4).zip(words.iter()) {
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        out
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(
            digest(b""),
            [
                0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60,
                0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
            ]
        );
        assert_eq!(
            digest(b"abc"),
            [
                0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
                0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
            ]
        );
        assert_eq!(
            digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [
                0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51,
                0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1,
            ]
        );
    }

    #[test]
    fn sha1_chunking_matches_single_update() {
        let mut chunked = ShaContext::zeroed();
        let mut single = ShaContext::zeroed();
        let mut chunked_words = [0u32; 5];
        let mut single_words = [0u32; 5];

        a_sha_init(&mut chunked);
        for part in [b"a".as_slice(), b"b", b"c"] {
            a_sha_update(&mut chunked, part);
        }
        a_sha_final(&mut chunked, &mut chunked_words);

        a_sha_init(&mut single);
        a_sha_update(&mut single, b"abc");
        a_sha_final(&mut single, &mut single_words);

        assert_eq!(chunked_words, single_words);
    }

    #[test]
    fn final_resets_context_like_reactos() {
        let mut context = ShaContext::zeroed();
        let mut words = [0u32; 5];
        a_sha_init(&mut context);
        a_sha_update(&mut context, b"abc");
        a_sha_final(&mut context, &mut words);

        assert_eq!(context.count, [0, 0]);
        assert_eq!(
            context.state,
            [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ]
        );
        assert!(context.buffer.iter().all(|b| *b == 0));
    }
}
