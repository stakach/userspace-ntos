//! NT image-header capture: one page, an optional NT window, and an optional section-table window.

use crate::{Headers, PeError, PeLayout};

const PAGE_SIZE: usize = 4096;
const HEADER_WINDOW: usize = 2 * PAGE_SIZE;

/// One bounded read needed to capture the typed layout of an image File.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageHeaderRead {
    pub offset: u64,
    pub length: usize,
}

enum CaptureStage {
    Initial,
    Nt { nt_offset: usize, window_offset: u64 },
    Table {
        headers: Headers,
        table: usize,
        window_offset: u64,
    },
    Complete,
}

/// Resumable sparse capture over one retained, identity-bound File source.
///
/// The caller retains the File and any pending read/ACK owner. Only the current window's bytes
/// need to be kept until `complete_window` accepts them; File EOF and DOS gaps are never stored.
pub struct IncrementalImageLayoutCapture {
    file_size: u64,
    stage: CaptureStage,
}

impl IncrementalImageLayoutCapture {
    pub const fn new(file_size: u64) -> Self {
        Self {
            file_size,
            stage: CaptureStage::Initial,
        }
    }

    pub fn next_window(&self) -> Option<ImageHeaderRead> {
        let (offset, capacity) = match &self.stage {
            CaptureStage::Initial => (0, PAGE_SIZE),
            CaptureStage::Nt { window_offset, .. }
            | CaptureStage::Table { window_offset, .. } => (*window_offset, HEADER_WINDOW),
            CaptureStage::Complete => return None,
        };
        let available = self.file_size.checked_sub(offset).unwrap_or(0);
        Some(ImageHeaderRead {
            offset,
            length: available.min(capacity as u64) as usize,
        })
    }

    /// Accept exactly the requested window after its read has completed. A short window or a
    /// parse error leaves the stage unchanged, so no later window is accidentally authorized.
    pub fn complete_window(&mut self, bytes: &[u8]) -> Result<Option<PeLayout>, PeError> {
        let request = self.next_window().ok_or(PeError::Truncated)?;
        if request.length == 0 || bytes.len() != request.length {
            return Err(PeError::Truncated);
        }
        match &self.stage {
            CaptureStage::Initial => {
                let nt_offset = Headers::capture_nt_offset(bytes)?;
                if (nt_offset as u64)
                    .checked_add(24)
                    .is_none_or(|end| end > self.file_size)
                {
                    return Err(PeError::Truncated);
                }
                match Headers::parse_nt_window(bytes, nt_offset, nt_offset, self.file_size) {
                    Ok(headers) if table_end(&headers)? <= bytes.len() => {
                        let layout = PeLayout::from_headers(bytes, headers)?;
                        self.stage = CaptureStage::Complete;
                        return Ok(Some(layout));
                    }
                    Ok(_) | Err(PeError::Truncated) => {}
                    Err(error) => return Err(error),
                }
                self.stage = CaptureStage::Nt {
                    nt_offset,
                    window_offset: (nt_offset as u64) & !((PAGE_SIZE - 1) as u64),
                };
                Ok(None)
            }
            CaptureStage::Nt {
                nt_offset,
                window_offset,
            } => {
                let headers = Headers::parse_nt_window(
                    bytes,
                    (*nt_offset as u64 - *window_offset) as usize,
                    *nt_offset,
                    self.file_size,
                )?;
                let table = headers.section_table_offset();
                let end = table_end(&headers)?;
                if end as u64 > self.file_size {
                    return Err(PeError::Truncated);
                }
                if end as u64 <= *window_offset + bytes.len() as u64 {
                    let layout = PeLayout::from_section_window(
                        bytes,
                        headers,
                        (table as u64 - *window_offset) as usize,
                    )?;
                    self.stage = CaptureStage::Complete;
                    return Ok(Some(layout));
                }
                self.stage = CaptureStage::Table {
                    headers,
                    table,
                    window_offset: (table as u64) & !((PAGE_SIZE - 1) as u64),
                };
                Ok(None)
            }
            CaptureStage::Table {
                headers,
                table,
                window_offset,
            } => {
                let layout = PeLayout::from_section_window(
                    bytes,
                    headers.clone(),
                    (*table as u64 - *window_offset) as usize,
                )?;
                self.stage = CaptureStage::Complete;
                Ok(Some(layout))
            }
            CaptureStage::Complete => Err(PeError::Truncated),
        }
    }
}

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
    let mut capture = IncrementalImageLayoutCapture::new(file_size);
    let mut window = [0u8; HEADER_WINDOW];
    loop {
        let request = capture.next_window().ok_or(PeError::Truncated)?;
        let length = read_window(
            file_size,
            request.offset,
            &mut window[..request.length],
            &mut read,
        )?;
        if let Some(layout) = capture.complete_window(&window[..length])? {
            return Ok(layout);
        }
    }
}
