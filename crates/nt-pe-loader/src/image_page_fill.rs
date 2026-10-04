//! Checked raw-file spans for one SEC_IMAGE demand page.

use crate::{headers, ImageProtection, PeError, PeLayout};

pub const IMAGE_PAGE_SIZE: usize = 0x1000;
const MAX_SPANS: usize = headers::MAX_SECTIONS + 1;

/// A file slice copied into a zero-initialized image page. Spans are applied in
/// order, matching header-then-section PE image construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImagePageFileSpan {
    pub file_offset: u64,
    pub page_offset: u16,
    pub length: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImagePageFillPlan {
    page_rva: u32,
    protection: ImageProtection,
    spans: [ImagePageFileSpan; MAX_SPANS],
    span_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImagePageReadError<E> {
    InvalidPageSize(usize),
    Read(E),
    ShortRead { expected: usize, actual: usize },
}

impl ImagePageFillPlan {
    pub const fn page_rva(&self) -> u32 {
        self.page_rva
    }

    pub const fn protection(&self) -> ImageProtection {
        self.protection
    }

    pub fn spans(&self) -> &[ImagePageFileSpan] {
        &self.spans[..self.span_count]
    }

    /// Fill exactly one image page from the validated File spans. On error the destination
    /// may already contain accepted writes; this method does not authorize publication or replay.
    pub fn read_into_page<E>(
        &self,
        page: &mut [u8],
        mut read: impl FnMut(u64, &mut [u8]) -> Result<usize, E>,
    ) -> Result<(), ImagePageReadError<E>> {
        if page.len() != IMAGE_PAGE_SIZE {
            return Err(ImagePageReadError::InvalidPageSize(page.len()));
        }
        page.fill(0);
        for span in self.spans() {
            let start = usize::from(span.page_offset);
            let length = usize::from(span.length);
            let actual = read(span.file_offset, &mut page[start..start + length])
                .map_err(ImagePageReadError::Read)?;
            if actual != length {
                return Err(ImagePageReadError::ShortRead {
                    expected: length,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn push(&mut self, file_offset: u64, image_rva: u64, length: u64) -> Result<(), PeError> {
        if length == 0 {
            return Ok(());
        }
        let page_offset = image_rva
            .checked_sub(u64::from(self.page_rva))
            .ok_or(PeError::SectionOutOfBounds)?;
        let end = page_offset
            .checked_add(length)
            .ok_or(PeError::SectionOutOfBounds)?;
        if end > IMAGE_PAGE_SIZE as u64 || self.span_count == MAX_SPANS {
            return Err(PeError::SectionOutOfBounds);
        }
        self.spans[self.span_count] = ImagePageFileSpan {
            file_offset,
            page_offset: page_offset as u16,
            length: length as u16,
        };
        self.span_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_spans() -> ImagePageFillPlan {
        let mut plan = ImagePageFillPlan {
            page_rva: 0,
            protection: ImageProtection::ReadOnly,
            spans: [ImagePageFileSpan::default(); MAX_SPANS],
            span_count: 0,
        };
        plan.push(0x400, 0, 4).unwrap();
        plan.push(0x900, 16, 8).unwrap();
        plan
    }

    #[test]
    fn checked_read_adapter_handles_two_spans_and_zero_gaps() {
        let plan = two_spans();
        let mut page = [0xff; IMAGE_PAGE_SIZE];
        let mut calls = 0;
        plan.read_into_page(&mut page, |offset, output: &mut [u8]| {
            assert_eq!(
                (offset, output.len()),
                if calls == 0 { (0x400, 4) } else { (0x900, 8) }
            );
            calls += 1;
            output.fill(calls as u8);
            Ok::<_, u32>(output.len())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(&page[..4], &[1; 4]);
        assert_eq!(&page[16..24], &[2; 8]);
        assert!(page[4..16]
            .iter()
            .chain(page[24..].iter())
            .all(|byte| *byte == 0));
    }

    #[test]
    fn later_span_short_read_preserves_prior_effect_and_refuses_success() {
        let mut page = [0xff; IMAGE_PAGE_SIZE];
        let mut calls = 0;
        assert_eq!(
            two_spans().read_into_page(&mut page, |_, output: &mut [u8]| {
                calls += 1;
                output.fill(calls as u8);
                Ok::<_, u32>(if calls == 1 {
                    output.len()
                } else {
                    output.len() - 1
                })
            }),
            Err(ImagePageReadError::ShortRead {
                expected: 8,
                actual: 7
            })
        );
        assert_eq!(calls, 2);
        assert_eq!(&page[..4], &[1; 4]);
    }

    #[test]
    fn later_span_error_preserves_exact_status_without_more_reads() {
        let mut page = [0xff; IMAGE_PAGE_SIZE];
        let mut calls = 0;
        assert_eq!(
            two_spans().read_into_page(&mut page, |_, output: &mut [u8]| {
                calls += 1;
                if calls == 2 {
                    return Err(0xc0000185u32);
                }
                output.fill(1);
                Ok(output.len())
            }),
            Err(ImagePageReadError::Read(0xc0000185))
        );
        assert_eq!(calls, 2);
        assert_eq!(&page[..4], &[1; 4]);
    }
}

pub(crate) fn plan(
    pe: &PeLayout,
    page_rva: u32,
    file_size: u64,
) -> Result<ImagePageFillPlan, PeError> {
    let image_size = u64::from(pe.size_of_image());
    let page_start = u64::from(page_rva);
    if page_rva as usize % IMAGE_PAGE_SIZE != 0 || page_start >= image_size || image_size == 0 {
        return Err(PeError::BadRva(page_rva));
    }
    let page_end = page_start + IMAGE_PAGE_SIZE as u64;
    let table_end = pe
        .headers()
        .section_table_offset()
        .checked_add(pe.sections().len() * 40)
        .ok_or(PeError::SectionOutOfBounds)?;
    if table_end as u64 > u64::from(pe.headers().size_of_headers)
        || u64::from(pe.headers().size_of_headers) > image_size
    {
        return Err(PeError::SectionOutOfBounds);
    }
    if table_end as u64 > file_size {
        return Err(PeError::Truncated);
    }

    let mut result = ImagePageFillPlan {
        page_rva,
        protection: pe.image_protection_at(page_rva),
        spans: [ImagePageFileSpan::default(); MAX_SPANS],
        span_count: 0,
    };
    let headers_end = u64::from(pe.headers().size_of_headers)
        .min(image_size)
        .min(file_size);
    let header_end = page_end.min(headers_end);
    if header_end > page_start {
        result.push(page_start, page_start, header_end - page_start)?;
    }

    let header_end_rounded = u64::from(pe.headers().size_of_headers)
        .saturating_add((IMAGE_PAGE_SIZE - 1) as u64)
        & !((IMAGE_PAGE_SIZE - 1) as u64);
    let header_page = page_start < header_end_rounded;
    let mut section_page = false;
    for section in pe.sections() {
        let start = u64::from(section.virtual_address);
        let virtual_end = start
            .checked_add(u64::from(
                section.virtual_size.max(section.size_of_raw_data),
            ))
            .filter(|end| *end <= image_size)
            .ok_or(PeError::SectionOutOfBounds)?;
        if virtual_end > start && start % IMAGE_PAGE_SIZE as u64 != 0 {
            return Err(PeError::UnsupportedImageAlignment(section.virtual_address));
        }
        let mapped_end = virtual_end.saturating_add((IMAGE_PAGE_SIZE - 1) as u64)
            & !((IMAGE_PAGE_SIZE - 1) as u64);
        if page_start >= start && page_start < mapped_end {
            if header_page || section_page {
                return Err(PeError::AmbiguousImagePage(page_rva));
            }
            section_page = true;
        }
        if virtual_end == start || section.is_uninitialized() || section.size_of_raw_data == 0 {
            continue;
        }
        let raw_start = u64::from(section.pointer_to_raw_data);
        let raw_end = raw_start
            .checked_add(u64::from(section.size_of_raw_data))
            .filter(|end| *end <= file_size)
            .ok_or(PeError::SectionOutOfBounds)?;
        let image_raw_end = start + u64::from(section.size_of_raw_data);
        let copy_start = page_start.max(start);
        let copy_end = page_end.min(image_raw_end);
        if copy_start < copy_end {
            let file_offset = raw_start + (copy_start - start);
            if file_offset + (copy_end - copy_start) > raw_end {
                return Err(PeError::SectionOutOfBounds);
            }
            result.push(file_offset, copy_start, copy_end - copy_start)?;
        }
    }
    Ok(result)
}
