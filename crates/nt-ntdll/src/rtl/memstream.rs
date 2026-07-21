//! Pure helpers for the `Rtl*MemoryStream` export family.

pub const S_OK: u32 = 0x0000_0000;
pub const E_INVALIDARG: u32 = 0x8007_0057;
pub const STG_E_INVALIDPOINTER: u32 = 0x8003_0009;

pub const STREAM_SEEK_SET: u32 = 0;
pub const STREAM_SEEK_CUR: u32 = 1;
pub const STREAM_SEEK_END: u32 = 2;

/// Bytes available from `current` to `end`, clamped to zero for malformed ranges.
pub fn available(current: usize, end: usize) -> usize {
    end.saturating_sub(current)
}

/// Length to read for an `IStream::Read` call.
pub fn read_length(current: usize, end: usize, requested: u32) -> usize {
    available(current, end).min(requested as usize)
}

/// Compute the new stream position for `RtlSeekMemoryStream`.
pub fn seek_position(
    start: usize,
    current: usize,
    end: usize,
    relative_offset: i64,
    origin: u32,
) -> Result<usize, u32> {
    let base = match origin {
        STREAM_SEEK_SET => start as i128,
        STREAM_SEEK_CUR => current as i128,
        STREAM_SEEK_END => end as i128,
        _ => return Err(E_INVALIDARG),
    };
    let offset = if origin == STREAM_SEEK_END {
        -(relative_offset as i128)
    } else {
        relative_offset as i128
    };
    let new_pos = base + offset;
    if new_pos < start as i128 || new_pos > end as i128 {
        return Err(STG_E_INVALIDPOINTER);
    }
    Ok(new_pos as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_length_is_clamped_to_available_bytes() {
        assert_eq!(read_length(10, 20, 64), 10);
        assert_eq!(read_length(10, 20, 4), 4);
        assert_eq!(read_length(20, 10, 4), 0);
    }

    #[test]
    fn seek_position_matches_reactos_origins() {
        assert_eq!(seek_position(100, 120, 200, 10, STREAM_SEEK_SET), Ok(110));
        assert_eq!(seek_position(100, 120, 200, 10, STREAM_SEEK_CUR), Ok(130));
        assert_eq!(seek_position(100, 120, 200, 10, STREAM_SEEK_END), Ok(190));
        assert_eq!(
            seek_position(100, 120, 200, -5, STREAM_SEEK_END),
            Err(STG_E_INVALIDPOINTER)
        );
    }

    #[test]
    fn seek_rejects_bad_origin_and_out_of_range_positions() {
        assert_eq!(seek_position(100, 120, 200, 0, 99), Err(E_INVALIDARG));
        assert_eq!(
            seek_position(100, 120, 200, -1, STREAM_SEEK_SET),
            Err(STG_E_INVALIDPOINTER)
        );
        assert_eq!(
            seek_position(100, 120, 200, 81, STREAM_SEEK_CUR),
            Err(STG_E_INVALIDPOINTER)
        );
    }
}
