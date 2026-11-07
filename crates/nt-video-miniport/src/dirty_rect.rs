//! x64 wire header for LiberNT's DXGK present-dirty-rect control.

/// LiberNT's `DXGK_PRESENT_DIRTY_RECTS_INPUT` is inside `#pragma pack(push, 4)`.
/// Its header ends immediately before the variable `RECTL Rects[]` array.
#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct Header {
    struct_size: u32,
    flags: u32,
    rect_count: u32,
    source_pitch: u32,
    source_size: u32,
    source: u64,
}

const HEADER_BYTES: usize = core::mem::size_of::<Header>();
const RECT_BYTES: usize = 16;

/// Return only the source span described by a complete, internally consistent header.
pub fn dirty_rect_source(input: &[u8]) -> Option<(u64, u64)> {
    if input.len() < HEADER_BYTES { return None; }
    let declared = u32::from_le_bytes(input[0..4].try_into().ok()?) as usize;
    let rects = u32::from_le_bytes(input[8..12].try_into().ok()?) as usize;
    if declared != input.len() || rects.checked_mul(RECT_BYTES)?
        .checked_add(HEADER_BYTES)? != declared { return None; }
    let bytes = u32::from_le_bytes(input[16..20].try_into().ok()?) as u64;
    let source = u64::from_le_bytes(input[20..28].try_into().ok()?);
    if source == 0 || bytes == 0 { return None; }
    Some((source, bytes))
}

/// Replace only the x64 Source pointer after the caller's alias has been proved.
pub fn rewrite_dirty_rect_source(input: &mut [u8], source: u64) -> Option<()> {
    dirty_rect_source(input)?;
    input[20..28].copy_from_slice(&source.to_le_bytes());
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn released_dirty_rect_header_offsets_and_bounds() {
        assert_eq!(HEADER_BYTES, 28);
        assert_eq!(core::mem::offset_of!(Header, source_size), 16);
        assert_eq!(core::mem::offset_of!(Header, source), 20);
        let mut input = [0u8; 44];
        input[0..4].copy_from_slice(&44u32.to_le_bytes());
        input[8..12].copy_from_slice(&1u32.to_le_bytes());
        input[16..20].copy_from_slice(&0x300000u32.to_le_bytes());
        input[20..28].copy_from_slice(&0x1000_0900_0000u64.to_le_bytes());
        assert_eq!(dirty_rect_source(&input), Some((0x1000_0900_0000, 0x300000)));
        rewrite_dirty_rect_source(&mut input, 0x1000_17b0_0000).unwrap();
        assert_eq!(dirty_rect_source(&input), Some((0x1000_17b0_0000, 0x300000)));
        input[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(dirty_rect_source(&input), None);
    }
}
