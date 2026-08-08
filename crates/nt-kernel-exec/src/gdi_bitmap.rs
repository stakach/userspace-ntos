//! GDI bitmap ABI helpers shared by the win32k transport.

pub const DIB_RGB_COLORS: u32 = 0;
pub const DIB_PAL_COLORS: u32 = 1;
pub const DIB_PAL_INDICES: u32 = 2;

pub const BI_RGB: u32 = 0;
pub const BI_BITFIELDS: u32 = 3;

const BITMAPCOREHEADER_SIZE: usize = 12;
const BITMAPINFOHEADER_SIZE: usize = 40;
const RGBQUAD_SIZE: usize = 4;
const WORD_SIZE: usize = 2;
const DWORD_SIZE: usize = 4;

fn le_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let slice = bytes.get(off..end)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn le_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = bytes.get(off..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Return the byte size ReactOS win32k's `DIB_BitmapInfoSize` probes for a `BITMAPINFO`.
///
/// `header` must contain the declared fixed header bytes (`biSize` worth for modern headers, or
/// `sizeof(BITMAPCOREHEADER)` for core headers). Color-table bytes are not inspected to compute the
/// size.
pub fn bitmap_info_size(header: &[u8], color_use: u32) -> Option<usize> {
    let bi_size = le_u32(header, 0)? as usize;
    let color_entry_size = match color_use {
        DIB_RGB_COLORS => RGBQUAD_SIZE,
        DIB_PAL_INDICES => 0,
        _ => WORD_SIZE,
    };

    if bi_size == BITMAPCOREHEADER_SIZE {
        let bit_count = le_u16(header, 10)? as usize;
        let colors = if bit_count <= 8 {
            1usize.checked_shl(bit_count as u32)?
        } else {
            0
        };
        return BITMAPCOREHEADER_SIZE.checked_add(colors.checked_mul(color_entry_size)?);
    }

    if bi_size < BITMAPINFOHEADER_SIZE || header.len() < bi_size {
        return None;
    }

    let bit_count = le_u16(header, 14)? as usize;
    let compression = le_u32(header, 16)?;
    let mut colors = le_u32(header, 32)? as usize;
    if colors > 256 {
        colors = 256;
    }
    if colors == 0 && bit_count <= 8 {
        colors = 1usize.checked_shl(bit_count as u32)?;
    }
    let masks = if compression == BI_BITFIELDS { 3 } else { 0 };
    let minimum = BITMAPINFOHEADER_SIZE.checked_add(masks * DWORD_SIZE)?;
    let fixed = if bi_size > minimum { bi_size } else { minimum };
    fixed.checked_add(colors.checked_mul(color_entry_size)?)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    fn info_header(bit_count: u16, compression: u32, clr_used: u32, size: u32) -> [u8; 124] {
        let mut header = [0u8; 124];
        header[0..4].copy_from_slice(&size.to_le_bytes());
        header[12..14].copy_from_slice(&1u16.to_le_bytes());
        header[14..16].copy_from_slice(&bit_count.to_le_bytes());
        header[16..20].copy_from_slice(&compression.to_le_bytes());
        header[32..36].copy_from_slice(&clr_used.to_le_bytes());
        header
    }

    #[test]
    fn rgb_indexed_info_includes_default_color_table() {
        let header = info_header(8, BI_RGB, 0, BITMAPINFOHEADER_SIZE as u32);
        assert_eq!(
            bitmap_info_size(&header[..BITMAPINFOHEADER_SIZE], DIB_RGB_COLORS),
            Some(BITMAPINFOHEADER_SIZE + 256 * RGBQUAD_SIZE)
        );
    }

    #[test]
    fn palette_colors_use_word_entries_and_clamp_color_count() {
        let header = info_header(4, BI_RGB, 300, BITMAPINFOHEADER_SIZE as u32);
        assert_eq!(
            bitmap_info_size(&header[..BITMAPINFOHEADER_SIZE], DIB_PAL_COLORS),
            Some(BITMAPINFOHEADER_SIZE + 256 * WORD_SIZE)
        );
    }

    #[test]
    fn bitfields_add_masks_for_v1_headers_but_not_v4_headers() {
        let v1 = info_header(16, BI_BITFIELDS, 0, BITMAPINFOHEADER_SIZE as u32);
        assert_eq!(
            bitmap_info_size(&v1[..BITMAPINFOHEADER_SIZE], DIB_RGB_COLORS),
            Some(BITMAPINFOHEADER_SIZE + 3 * DWORD_SIZE)
        );

        let v4 = info_header(32, BI_BITFIELDS, 0, 108);
        assert_eq!(bitmap_info_size(&v4[..108], DIB_RGB_COLORS), Some(108));
    }

    #[test]
    fn modern_header_must_include_declared_fixed_header_bytes() {
        let v4 = info_header(32, BI_RGB, 0, 108);
        assert_eq!(bitmap_info_size(&v4[..40], DIB_RGB_COLORS), None);
    }

    #[test]
    fn bitmap_core_header_uses_rgb_quads_for_win32k_rgb_colors() {
        let mut header = [0u8; BITMAPCOREHEADER_SIZE];
        header[0..4].copy_from_slice(&(BITMAPCOREHEADER_SIZE as u32).to_le_bytes());
        header[10..12].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(
            bitmap_info_size(&header, DIB_RGB_COLORS),
            Some(BITMAPCOREHEADER_SIZE + 2 * RGBQUAD_SIZE)
        );
        assert_eq!(
            bitmap_info_size(&header, DIB_PAL_COLORS),
            Some(BITMAPCOREHEADER_SIZE + 2 * WORD_SIZE)
        );
        assert_eq!(
            bitmap_info_size(&header, DIB_PAL_INDICES),
            Some(BITMAPCOREHEADER_SIZE)
        );
    }

    #[test]
    fn rejects_short_or_invalid_headers() {
        assert_eq!(bitmap_info_size(&[0; 8], DIB_RGB_COLORS), None);
        let header = info_header(32, BI_RGB, 0, 16);
        assert_eq!(
            bitmap_info_size(&header[..BITMAPINFOHEADER_SIZE], DIB_RGB_COLORS),
            None
        );
    }
}
