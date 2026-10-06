//! NT image-header capture: one page, an optional NT window, and an optional section-table window.

use crate::{Headers, PeError, PeLayout};

const PAGE_SIZE: usize = 4096;
const HEADER_WINDOW: usize = 2 * PAGE_SIZE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageHeaderCaptureError<E> {
    Read(E),
    Parse(PeError),
    ShortRead { expected: usize, actual: usize },
}

impl<E> From<PeError> for ImageHeaderCaptureError<E> {
    fn from(error: PeError) -> Self {
        Self::Parse(error)
    }
}

fn read_window<E>(
    file_size: u64,
    offset: u64,
    buffer: &mut [u8],
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
) -> Result<usize, ImageHeaderCaptureError<E>> {
    let available = file_size.checked_sub(offset).ok_or(PeError::Truncated)?;
    let length = available.min(buffer.len() as u64) as usize;
    if length == 0 {
        return Err(PeError::Truncated.into());
    }
    let actual = read(offset, &mut buffer[..length]).map_err(ImageHeaderCaptureError::Read)?;
    if actual != length {
        return Err(ImageHeaderCaptureError::ShortRead {
            expected: length,
            actual,
        });
    }
    Ok(length)
}

fn table_end(headers: &Headers) -> Result<usize, PeError> {
    headers
        .section_table_offset()
        .checked_add(
            usize::from(headers.number_of_sections)
                .checked_mul(40)
                .ok_or(PeError::Truncated)?,
        )
        .ok_or(PeError::Truncated)
}

/// Read typed metadata without allocating the DOS gap, File EOF, or `SizeOfHeaders`.
/// The reader must read from one retained, identity-bound File source throughout capture.
pub fn capture_image_layout<E>(
    file_size: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
) -> Result<PeLayout, ImageHeaderCaptureError<E>> {
    let mut window = [0u8; HEADER_WINDOW];
    let initial_length = read_window(file_size, 0, &mut window[..PAGE_SIZE], &mut read)?;
    let nt_offset = Headers::capture_nt_offset(&window[..initial_length])?;
    if (nt_offset as u64)
        .checked_add(24)
        .is_none_or(|end| end > file_size)
    {
        return Err(PeError::Truncated.into());
    }
    match Headers::parse_nt_window(&window[..initial_length], nt_offset, nt_offset, file_size) {
        Ok(headers) if table_end(&headers)? <= initial_length => {
            return PeLayout::from_headers(&window[..initial_length], headers).map_err(Into::into);
        }
        Ok(_) | Err(PeError::Truncated) => {}
        Err(error) => return Err(error.into()),
    }

    let nt_window_offset = (nt_offset as u64) & !((PAGE_SIZE - 1) as u64);
    let length = read_window(file_size, nt_window_offset, &mut window, &mut read)?;
    let headers = Headers::parse_nt_window(
        &window[..length],
        (nt_offset as u64 - nt_window_offset) as usize,
        nt_offset,
        file_size,
    )?;
    let table = headers.section_table_offset();
    let end = table_end(&headers)?;
    if end as u64 > file_size {
        return Err(PeError::Truncated.into());
    }
    if end as u64 <= nt_window_offset + length as u64 {
        return PeLayout::from_section_window(
            &window[..length],
            headers,
            (table as u64 - nt_window_offset) as usize,
        )
        .map_err(Into::into);
    }

    // NT5 also reads a separate bounded table window when the NT window cannot hold every row.
    let table_window_offset = (table as u64) & !((PAGE_SIZE - 1) as u64);
    let length = read_window(file_size, table_window_offset, &mut window, &mut read)?;
    PeLayout::from_section_window(
        &window[..length],
        headers,
        (table as u64 - table_window_offset) as usize,
    )
    .map_err(Into::into)
}
