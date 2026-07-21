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

/// ReactOS `MD4_CTX`: `buf[4]; i[2]; in[64]; digest[16]`.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Md4Context {
    pub buf: [u32; 4],
    pub i: [u32; 2],
    pub input: [u8; 64],
    pub digest: [u8; 16],
}

impl Md4Context {
    pub const fn zeroed() -> Self {
        Self {
            buf: [0; 4],
            i: [0; 2],
            input: [0; 64],
            digest: [0; 16],
        }
    }
}

/// ReactOS `MD5_CTX`: `i[2]; buf[4]; in[64]; digest[16]`.
#[repr(C)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Md5Context {
    pub i: [u32; 2],
    pub buf: [u32; 4],
    pub input: [u8; 64],
    pub digest: [u8; 16],
}

impl Md5Context {
    pub const fn zeroed() -> Self {
        Self {
            i: [0; 2],
            buf: [0; 4],
            input: [0; 64],
            digest: [0; 16],
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

pub fn md4_init(context: &mut Md4Context) {
    context.buf = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
    context.i = [0, 0];
}

pub fn md4_update(context: &mut Md4Context, input: &[u8]) {
    md_update(&mut context.buf, &mut context.i, &mut context.input, input, md4_transform);
}

pub fn md4_final(context: &mut Md4Context) {
    md_final(&mut context.buf, &mut context.i, &mut context.input, &mut context.digest, md4_transform);
}

pub fn md5_init(context: &mut Md5Context) {
    context.buf = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
    context.i = [0, 0];
}

pub fn md5_update(context: &mut Md5Context, input: &[u8]) {
    md_update(&mut context.buf, &mut context.i, &mut context.input, input, md5_transform);
}

pub fn md5_final(context: &mut Md5Context) {
    md_final(&mut context.buf, &mut context.i, &mut context.input, &mut context.digest, md5_transform);
}

fn md_update(
    state: &mut [u32; 4],
    count: &mut [u32; 2],
    buffer: &mut [u8; 64],
    mut input: &[u8],
    transform: fn(&mut [u32; 4], &[u8; 64]),
) {
    let old_low = count[0];
    let input_len = input.len() as u32;
    count[0] = count[0].wrapping_add(input_len << 3);
    if count[0] < old_low {
        count[1] = count[1].wrapping_add(1);
    }
    count[1] = count[1].wrapping_add(input_len >> 29);

    let buffered = ((old_low >> 3) & 0x3F) as usize;
    if buffered != 0 {
        let fill = 64 - buffered;
        if input.len() < fill {
            buffer[buffered..buffered + input.len()].copy_from_slice(input);
            return;
        }
        buffer[buffered..].copy_from_slice(&input[..fill]);
        transform(state, buffer);
        input = &input[fill..];
    }

    while input.len() >= 64 {
        let mut block = [0u8; 64];
        block.copy_from_slice(&input[..64]);
        transform(state, &block);
        input = &input[64..];
    }

    buffer[..input.len()].copy_from_slice(input);
}

fn md_final(
    state: &mut [u32; 4],
    count: &mut [u32; 2],
    buffer: &mut [u8; 64],
    digest: &mut [u8; 16],
    transform: fn(&mut [u32; 4], &[u8; 64]),
) {
    let used = ((count[0] >> 3) & 0x3F) as usize;
    buffer[used] = 0x80;

    if used + 1 > 56 {
        buffer[used + 1..].fill(0);
        transform(state, buffer);
        buffer[..56].fill(0);
    } else {
        buffer[used + 1..56].fill(0);
    }

    buffer[56..60].copy_from_slice(&count[0].to_le_bytes());
    buffer[60..64].copy_from_slice(&count[1].to_le_bytes());
    transform(state, buffer);

    for (chunk, word) in digest.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    buffer.fill(0);
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

fn md4_transform(state: &mut [u32; 4], block: &[u8; 64]) {
    const R2: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const R3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

    let mut x = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        x[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut r = *state;
    for i in 0..16 {
        let f = (r[1] & r[2]) | ((!r[1]) & r[3]);
        r[0] = r[0].wrapping_add(f).wrapping_add(x[i]).rotate_left([3, 7, 11, 19][i & 3]);
        r.rotate_right(1);
    }
    for i in 0..16 {
        let g = (r[1] & r[2]) | (r[1] & r[3]) | (r[2] & r[3]);
        r[0] = r[0]
            .wrapping_add(g)
            .wrapping_add(x[R2[i]])
            .wrapping_add(0x5A82_7999)
            .rotate_left([3, 5, 9, 13][i & 3]);
        r.rotate_right(1);
    }
    for i in 0..16 {
        let h = r[1] ^ r[2] ^ r[3];
        r[0] = r[0]
            .wrapping_add(h)
            .wrapping_add(x[R3[i]])
            .wrapping_add(0x6ED9_EBA1)
            .rotate_left([3, 9, 11, 15][i & 3]);
        r.rotate_right(1);
    }

    for (state, value) in state.iter_mut().zip(r.iter()) {
        *state = state.wrapping_add(*value);
    }
}

fn md5_transform(state: &mut [u32; 4], block: &[u8; 64]) {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6,
        10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE, 0xF57C_0FAF, 0x4787_C62A, 0xA830_4613,
        0xFD46_9501, 0x6980_98D8, 0x8B44_F7AF, 0xFFFF_5BB1, 0x895C_D7BE, 0x6B90_1122, 0xFD98_7193,
        0xA679_438E, 0x49B4_0821, 0xF61E_2562, 0xC040_B340, 0x265E_5A51, 0xE9B6_C7AA, 0xD62F_105D,
        0x0244_1453, 0xD8A1_E681, 0xE7D3_FBC8, 0x21E1_CDE6, 0xC337_07D6, 0xF4D5_0D87, 0x455A_14ED,
        0xA9E3_E905, 0xFCEF_A3F8, 0x676F_02D9, 0x8D2A_4C8A, 0xFFFA_3942, 0x8771_F681, 0x6D9D_6122,
        0xFDE5_380C, 0xA4BE_EA44, 0x4BDE_CFA9, 0xF6BB_4B60, 0xBEBF_BC70, 0x289B_7EC6, 0xEAA1_27FA,
        0xD4EF_3085, 0x0488_1D05, 0xD9D4_D039, 0xE6DB_99E5, 0x1FA2_7CF8, 0xC4AC_5665, 0xF429_2244,
        0x432A_FF97, 0xAB94_23A7, 0xFC93_A039, 0x655B_59C3, 0x8F0C_CC92, 0xFFEF_F47D, 0x8584_5DD1,
        0x6FA8_7E4F, 0xFE2C_E6E0, 0xA301_4314, 0x4E08_11A1, 0xF753_7E82, 0xBD3A_F235, 0x2AD7_D2BB,
        0xEB86_D391,
    ];

    let mut m = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    for i in 0..64 {
        let (f, g) = match i {
            0..=15 => ((b & c) | ((!b) & d), i),
            16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) & 15),
            32..=47 => (b ^ c ^ d, (3 * i + 5) & 15),
            _ => (c ^ (b | (!d)), (7 * i) & 15),
        };
        let next = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]),
        );
        a = d;
        d = c;
        c = b;
        b = next;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    fn sha1_digest(input: &[u8]) -> [u8; 20] {
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

    fn md4_digest(input: &[u8]) -> [u8; 16] {
        let mut context = Md4Context::zeroed();
        md4_init(&mut context);
        md4_update(&mut context, input);
        md4_final(&mut context);
        context.digest
    }

    fn md5_digest(input: &[u8]) -> [u8; 16] {
        let mut context = Md5Context::zeroed();
        md5_init(&mut context);
        md5_update(&mut context, input);
        md5_final(&mut context);
        context.digest
    }

    #[test]
    fn md_context_layouts_match_reactos() {
        assert_eq!(size_of::<Md4Context>(), 0x68);
        assert_eq!(size_of::<Md5Context>(), 0x68);
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(
            sha1_digest(b""),
            [
                0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60,
                0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09,
            ]
        );
        assert_eq!(
            sha1_digest(b"abc"),
            [
                0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
                0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
            ]
        );
        assert_eq!(
            sha1_digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [
                0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51,
                0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1,
            ]
        );
    }

    #[test]
    fn md4_known_vectors() {
        assert_eq!(
            md4_digest(b""),
            [0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0]
        );
        assert_eq!(
            md4_digest(b"abc"),
            [0xA4, 0x48, 0x01, 0x7A, 0xAF, 0x21, 0xD8, 0x52, 0x5F, 0xC1, 0x0A, 0xE8, 0x7A, 0xA6, 0x72, 0x9D]
        );
        assert_eq!(
            md4_digest(b"abcdefghijklmnopqrstuvwxyz"),
            [0xD7, 0x9E, 0x1C, 0x30, 0x8A, 0xA5, 0xBB, 0xCD, 0xEE, 0xA8, 0xED, 0x63, 0xDF, 0x41, 0x2D, 0xA9]
        );
    }

    #[test]
    fn md5_known_vectors() {
        assert_eq!(
            md5_digest(b""),
            [0xD4, 0x1D, 0x8C, 0xD9, 0x8F, 0x00, 0xB2, 0x04, 0xE9, 0x80, 0x09, 0x98, 0xEC, 0xF8, 0x42, 0x7E]
        );
        assert_eq!(
            md5_digest(b"abc"),
            [0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1, 0x7F, 0x72]
        );
        assert_eq!(
            md5_digest(b"abcdefghijklmnopqrstuvwxyz"),
            [0xC3, 0xFC, 0xD3, 0xD7, 0x61, 0x92, 0xE4, 0x00, 0x7D, 0xFB, 0x49, 0x6C, 0xCA, 0x67, 0xE1, 0x3B]
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
