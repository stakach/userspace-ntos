//! `Rtl*` compression helpers.
//!
//! ReactOS' ntdll implements the public compression exports for LZNT1. Its compressor emits valid
//! uncompressed LZNT1 chunks; its decompressor handles both uncompressed and compressed chunks,
//! including fragment offsets. This module keeps that logic host-testable and leaves the DLL shim to
//! perform raw pointer marshalling.

pub type NtStatus = u32;

pub const STATUS_SUCCESS: NtStatus = 0x0000_0000;
pub const STATUS_ACCESS_VIOLATION: NtStatus = 0xC000_0005;
pub const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
pub const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
pub const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BB;
pub const STATUS_BAD_COMPRESSION_BUFFER: NtStatus = 0xC000_0242;
pub const STATUS_UNSUPPORTED_COMPRESSION: NtStatus = 0xC000_025F;

pub const COMPRESSION_FORMAT_MASK: u16 = 0x00FF;
pub const COMPRESSION_ENGINE_MASK: u16 = 0xFF00;
pub const COMPRESSION_FORMAT_NONE: u16 = 0x0000;
pub const COMPRESSION_FORMAT_DEFAULT: u16 = 0x0001;
pub const COMPRESSION_FORMAT_LZNT1: u16 = 0x0002;
pub const COMPRESSION_ENGINE_STANDARD: u16 = 0x0000;
pub const COMPRESSION_ENGINE_MAXIMUM: u16 = 0x0100;

const LZNT1_CHUNK: usize = 0x1000;

pub fn compression_workspace_size(format_and_engine: u16) -> Result<(u32, u32), NtStatus> {
    let format = format_and_engine & COMPRESSION_FORMAT_MASK;
    let engine = format_and_engine & COMPRESSION_ENGINE_MASK;
    match format {
        COMPRESSION_FORMAT_NONE | COMPRESSION_FORMAT_DEFAULT => Err(STATUS_INVALID_PARAMETER),
        COMPRESSION_FORMAT_LZNT1 => match engine {
            COMPRESSION_ENGINE_STANDARD => Ok((0x8010, 0x1000)),
            COMPRESSION_ENGINE_MAXIMUM => Ok((0x10, 0x1000)),
            _ => Err(STATUS_NOT_SUPPORTED),
        },
        _ => Err(STATUS_UNSUPPORTED_COMPRESSION),
    }
}

pub fn compress_buffer(
    format_and_engine: u16,
    uncompressed: &[u8],
    compressed: &mut [u8],
    _chunk_size: u32,
) -> Result<usize, NtStatus> {
    let format = format_and_engine & COMPRESSION_FORMAT_MASK;
    match format {
        COMPRESSION_FORMAT_NONE | COMPRESSION_FORMAT_DEFAULT => Err(STATUS_INVALID_PARAMETER),
        COMPRESSION_FORMAT_LZNT1 => compress_lznt1_uncompressed_chunks(uncompressed, compressed),
        _ => Err(STATUS_UNSUPPORTED_COMPRESSION),
    }
}

pub fn decompress_buffer(
    format: u16,
    uncompressed: &mut [u8],
    compressed: &[u8],
) -> Result<usize, NtStatus> {
    decompress_fragment(format, uncompressed, compressed, 0, None)
}

pub fn decompress_fragment(
    format: u16,
    uncompressed: &mut [u8],
    compressed: &[u8],
    offset: u32,
    workspace: Option<&mut [u8]>,
) -> Result<usize, NtStatus> {
    match format & !COMPRESSION_ENGINE_MAXIMUM {
        COMPRESSION_FORMAT_LZNT1 => {
            lznt1_decompress(uncompressed, compressed, offset as usize, workspace)
        }
        COMPRESSION_FORMAT_NONE | COMPRESSION_FORMAT_DEFAULT => Err(STATUS_INVALID_PARAMETER),
        _ => Err(STATUS_UNSUPPORTED_COMPRESSION),
    }
}

fn compress_lznt1_uncompressed_chunks(src: &[u8], dst: &mut [u8]) -> Result<usize, NtStatus> {
    let mut src_pos = 0usize;
    let mut dst_pos = 0usize;
    while src_pos < src.len() {
        let block = (src.len() - src_pos).min(LZNT1_CHUNK);
        if dst_pos + 2 + block > dst.len() {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let header = 0x3000u16 | (block as u16 - 1);
        dst[dst_pos..dst_pos + 2].copy_from_slice(&header.to_le_bytes());
        dst_pos += 2;
        dst[dst_pos..dst_pos + block].copy_from_slice(&src[src_pos..src_pos + block]);
        dst_pos += block;
        src_pos += block;
    }
    Ok(dst_pos)
}

fn read_u16_le(src: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*src.get(pos)?, *src.get(pos + 1)?]))
}

fn lznt1_decompress_chunk(dst: &mut [u8], src: &[u8]) -> Option<usize> {
    let mut src_pos = 0usize;
    let mut dst_pos = 0usize;

    while src_pos < src.len() && dst_pos < dst.len() {
        let mut flags = 0x8000u16 | src[src_pos] as u16;
        src_pos += 1;

        while (flags & 0xFF00) != 0 && src_pos < src.len() {
            if (flags & 1) != 0 {
                let code = read_u16_le(src, src_pos)?;
                src_pos += 2;

                let mut displacement_bits = 12usize;
                while displacement_bits > 4 {
                    if (1usize << (displacement_bits - 1)) < dst_pos {
                        break;
                    }
                    displacement_bits -= 1;
                }
                let length_bits = 16 - displacement_bits;
                let code_length = (code as usize & ((1usize << length_bits) - 1)) + 3;
                let code_displacement = (code as usize >> length_bits) + 1;
                if dst_pos < code_displacement {
                    return None;
                }
                for _ in 0..code_length {
                    if dst_pos >= dst.len() {
                        return Some(dst_pos);
                    }
                    dst[dst_pos] = dst[dst_pos - code_displacement];
                    dst_pos += 1;
                }
            } else {
                if dst_pos >= dst.len() {
                    return Some(dst_pos);
                }
                dst[dst_pos] = src[src_pos];
                src_pos += 1;
                dst_pos += 1;
            }
            flags >>= 1;
        }
    }

    Some(dst_pos)
}

fn lznt1_decompress(
    dst: &mut [u8],
    src: &[u8],
    mut offset: usize,
    mut workspace: Option<&mut [u8]>,
) -> Result<usize, NtStatus> {
    let mut src_pos = 0usize;
    let mut dst_pos = 0usize;

    if src.len() < 2 {
        return Err(STATUS_BAD_COMPRESSION_BUFFER);
    }

    while offset >= LZNT1_CHUNK && src_pos + 2 <= src.len() {
        let chunk_header = read_u16_le(src, src_pos).unwrap();
        src_pos += 2;
        if chunk_header == 0 {
            return Ok(dst_pos);
        }
        let chunk_size = (chunk_header as usize & 0x0FFF) + 1;
        if src_pos + chunk_size > src.len() {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }
        src_pos += chunk_size;
        offset -= LZNT1_CHUNK;
    }

    if offset != 0 && src_pos + 2 <= src.len() {
        let chunk_header = read_u16_le(src, src_pos).unwrap();
        src_pos += 2;
        if chunk_header == 0 {
            return Ok(dst_pos);
        }
        let chunk_size = (chunk_header as usize & 0x0FFF) + 1;
        if src_pos + chunk_size > src.len() {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }
        if dst_pos >= dst.len() {
            return Ok(dst_pos);
        }
        if (chunk_header & 0x8000) != 0 {
            let Some(workspace) = workspace.as_deref_mut() else {
                return Err(STATUS_ACCESS_VIOLATION);
            };
            if workspace.len() < LZNT1_CHUNK {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            let decoded = lznt1_decompress_chunk(
                &mut workspace[..LZNT1_CHUNK],
                &src[src_pos..src_pos + chunk_size],
            )
            .ok_or(STATUS_BAD_COMPRESSION_BUFFER)?;
            if decoded > offset {
                let block = (decoded - offset).min(dst.len() - dst_pos);
                dst[dst_pos..dst_pos + block].copy_from_slice(&workspace[offset..offset + block]);
                dst_pos += block;
            }
        } else if chunk_size > offset {
            let block = (chunk_size - offset).min(dst.len() - dst_pos);
            dst[dst_pos..dst_pos + block]
                .copy_from_slice(&src[src_pos + offset..src_pos + offset + block]);
            dst_pos += block;
        }
        src_pos += chunk_size;
    }

    while src_pos + 2 <= src.len() {
        let chunk_header = read_u16_le(src, src_pos).unwrap();
        src_pos += 2;
        if chunk_header == 0 {
            return Ok(dst_pos);
        }
        let chunk_size = (chunk_header as usize & 0x0FFF) + 1;
        if src_pos + chunk_size > src.len() {
            return Err(STATUS_BAD_COMPRESSION_BUFFER);
        }

        let mut block = (dst_pos + offset) & 0x0FFF;
        if block != 0 {
            block = LZNT1_CHUNK - block;
            if dst_pos + block >= dst.len() {
                return Ok(dst_pos);
            }
            dst[dst_pos..dst_pos + block].fill(0);
            dst_pos += block;
        }

        if dst_pos >= dst.len() {
            return Ok(dst_pos);
        }

        if (chunk_header & 0x8000) != 0 {
            let written =
                lznt1_decompress_chunk(&mut dst[dst_pos..], &src[src_pos..src_pos + chunk_size])
                    .ok_or(STATUS_BAD_COMPRESSION_BUFFER)?;
            dst_pos += written;
        } else {
            let block = chunk_size.min(dst.len() - dst_pos);
            dst[dst_pos..dst_pos + block].copy_from_slice(&src[src_pos..src_pos + block]);
            dst_pos += block;
        }

        src_pos += chunk_size;
    }

    Ok(dst_pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_sizes_match_reactos_lznt1() {
        assert_eq!(
            compression_workspace_size(COMPRESSION_FORMAT_NONE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            compression_workspace_size(COMPRESSION_FORMAT_DEFAULT),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            compression_workspace_size(0x00FF),
            Err(STATUS_UNSUPPORTED_COMPRESSION)
        );
        assert_eq!(
            compression_workspace_size(COMPRESSION_FORMAT_LZNT1),
            Ok((0x8010, 0x1000))
        );
        assert_eq!(
            compression_workspace_size(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM),
            Ok((0x10, 0x1000))
        );
    }

    #[test]
    fn compressor_emits_uncompressed_lznt1_chunks() {
        let src = b"WineWineWine\0";
        let mut compressed = [0x11u8; 64];
        let size = compress_buffer(COMPRESSION_FORMAT_LZNT1, src, &mut compressed, 4096).unwrap();
        assert_eq!(
            u16::from_le_bytes([compressed[0], compressed[1]]) & 0x7000,
            0x3000
        );
        let mut out = [0x11u8; 64];
        let final_size =
            decompress_buffer(COMPRESSION_FORMAT_LZNT1, &mut out, &compressed[..size]).unwrap();
        assert_eq!(final_size, src.len());
        assert_eq!(&out[..src.len()], src);
        assert_eq!(out[src.len()], 0x11);
    }

    #[test]
    fn decompresses_back_reference_chunk() {
        let compressed = [0x06, 0xB0, 0x10, b'W', b'i', b'n', b'e', 0x01, 0x30];
        let mut out = [0x11u8; 32];
        let final_size =
            decompress_buffer(COMPRESSION_FORMAT_LZNT1, &mut out, &compressed).unwrap();
        assert_eq!(final_size, 8);
        assert_eq!(&out[..8], b"WineWine");
        assert_eq!(out[8], 0x11);
    }

    #[test]
    fn decompress_fragment_uses_offset() {
        let compressed = [0x07, 0x30, b'W', b'i', b'n', b'e', b'W', b'i', b'n', b'e'];
        let mut out = [0x11u8; 32];
        let mut workspace = [0u8; 0x1000];
        let final_size = decompress_fragment(
            COMPRESSION_FORMAT_LZNT1,
            &mut out,
            &compressed,
            1,
            Some(&mut workspace),
        )
        .unwrap();
        assert_eq!(final_size, 7);
        assert_eq!(&out[..7], b"ineWine");
    }

    #[test]
    fn rejects_invalid_and_incomplete_chunks() {
        let mut out = [0u8; 32];
        assert_eq!(
            decompress_buffer(COMPRESSION_FORMAT_LZNT1, &mut out, &[0x01]),
            Err(STATUS_BAD_COMPRESSION_BUFFER)
        );
        let bad_ref = [0x06, 0xB0, 0x10, b'W', b'i', b'n', b'e', 0x05, 0x40];
        assert_eq!(
            decompress_buffer(COMPRESSION_FORMAT_LZNT1, &mut out, &bad_ref),
            Err(STATUS_BAD_COMPRESSION_BUFFER)
        );
    }
}
