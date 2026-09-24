//! Allocation-free, sealed transport for a domain's admitted mapped PE images.
//!
//! The envelope is packed and little-endian. Image descriptors and bytes must be ordered and
//! contiguous, with no spare bytes inside the declared extent. The native caller must separately
//! enforce read-only page rights for the entire lifetime of a parsed catalog.

use crate::{
    exception_images::{BorrowedExceptionImage, ImageAdmissionError, ScopeCursor, ScopeTableError},
    exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader},
    ImageReader, RuntimeFunction,
};

const MAGIC: &[u8; 8] = b"NTEXIMG1";
const VERSION: u16 = 1;
const HEADER_SIZE: usize = 24;
const DESCRIPTOR_SIZE: usize = 24;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    InvalidHeader,
    UnsupportedVersion,
    EmptyCatalog,
    InsufficientSpace,
    InsufficientImageSlots,
    ExtentOverflow,
    InvalidDescriptor,
    ImageOrder,
    ImageOverlap,
    ImageAdmission(ImageAdmissionError),
}

/// A mapped image at its actual load base. Encoding re-admits every image; this is not a bypass
/// around PE, exception-directory, or unwind-metadata validation.
pub struct SnapshotImage<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
}

pub fn encoded_len(images: &[SnapshotImage<'_>]) -> Result<usize, SnapshotError> {
    if images.is_empty() {
        return Err(SnapshotError::EmptyCatalog);
    }
    let _ = u32::try_from(images.len()).map_err(|_| SnapshotError::ExtentOverflow)?;
    let mut size = HEADER_SIZE
        .checked_add(
            images
                .len()
                .checked_mul(DESCRIPTOR_SIZE)
                .ok_or(SnapshotError::ExtentOverflow)?,
        )
        .ok_or(SnapshotError::ExtentOverflow)?;
    let mut previous_base = 0;
    let mut previous_end = 0;
    for image in images {
        let admitted = BorrowedExceptionImage::from_mapped_image(image.base, image.bytes)
            .map_err(SnapshotError::ImageAdmission)?;
        if previous_base != 0 && image.base <= previous_base {
            return Err(SnapshotError::ImageOrder);
        }
        if previous_end > image.base {
            return Err(SnapshotError::ImageOverlap);
        }
        previous_base = image.base;
        previous_end = image
            .base
            .checked_add(admitted.size() as u64)
            .ok_or(SnapshotError::ExtentOverflow)?;
        size = size
            .checked_add(image.bytes.len())
            .ok_or(SnapshotError::ExtentOverflow)?;
    }
    Ok(size)
}

/// Encode exactly one envelope into `output`. Bytes beyond the returned length are untouched and
/// are not part of the snapshot presented to the parser.
pub fn encode(images: &[SnapshotImage<'_>], output: &mut [u8]) -> Result<usize, SnapshotError> {
    let total = encoded_len(images)?;
    if output.len() < total {
        return Err(SnapshotError::InsufficientSpace);
    }
    let image_data_start = HEADER_SIZE + images.len() * DESCRIPTOR_SIZE;
    output[..8].copy_from_slice(MAGIC);
    put_u16(output, 8, VERSION);
    put_u16(output, 10, HEADER_SIZE as u16);
    put_u32(output, 12, images.len() as u32);
    put_u64(output, 16, total as u64);
    let mut offset = image_data_start;
    for (index, image) in images.iter().enumerate() {
        let descriptor = HEADER_SIZE + index * DESCRIPTOR_SIZE;
        put_u64(output, descriptor, image.base);
        put_u64(output, descriptor + 8, offset as u64);
        put_u64(output, descriptor + 16, image.bytes.len() as u64);
        output[offset..offset + image.bytes.len()].copy_from_slice(image.bytes);
        offset += image.bytes.len();
    }
    Ok(total)
}

/// Validated image views live in caller-owned slots, so parsing never allocates or imposes a
/// hidden image-count limit. Unused slots are cleared before parsing. The native caller must pass
/// precisely the encoded extent, not an entire page-rounded mapping with trailing slack.
pub struct SealedExceptionCatalog<'snapshot, 'slots> {
    images: &'slots [Option<BorrowedExceptionImage<'snapshot>>],
}

/// Validate one complete sealed envelope and pass admitted images to the caller in descriptor
/// order. The callback may retain the views or drop them; neither path allocates here.
fn parse_envelope<'snapshot>(
    bytes: &'snapshot [u8],
    slot_capacity: Option<usize>,
    mut admit: impl FnMut(usize, BorrowedExceptionImage<'snapshot>),
) -> Result<usize, SnapshotError> {
    if bytes.len() < HEADER_SIZE || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(SnapshotError::InvalidHeader);
    }
    if get_u16(bytes, 8) != Some(VERSION) {
        return Err(SnapshotError::UnsupportedVersion);
    }
    if get_u16(bytes, 10) != Some(HEADER_SIZE as u16) {
        return Err(SnapshotError::InvalidHeader);
    }
    let count = get_u32(bytes, 12).ok_or(SnapshotError::InvalidHeader)? as usize;
    if count == 0 {
        return Err(SnapshotError::EmptyCatalog);
    }
    if slot_capacity.is_some_and(|capacity| count > capacity) {
        return Err(SnapshotError::InsufficientImageSlots);
    }
    if get_u64(bytes, 16) != Some(bytes.len() as u64) {
        return Err(SnapshotError::InvalidHeader);
    }
    let descriptors_end = HEADER_SIZE
        .checked_add(
            count
                .checked_mul(DESCRIPTOR_SIZE)
                .ok_or(SnapshotError::ExtentOverflow)?,
        )
        .ok_or(SnapshotError::ExtentOverflow)?;
    if descriptors_end > bytes.len() {
        return Err(SnapshotError::InvalidDescriptor);
    }
    let mut expected_offset = descriptors_end;
    let mut previous_base = 0;
    let mut previous_end = 0;
    for index in 0..count {
        let descriptor = HEADER_SIZE + index * DESCRIPTOR_SIZE;
        let base = get_u64(bytes, descriptor).ok_or(SnapshotError::InvalidDescriptor)?;
        let offset = usize::try_from(
            get_u64(bytes, descriptor + 8).ok_or(SnapshotError::InvalidDescriptor)?,
        )
        .map_err(|_| SnapshotError::ExtentOverflow)?;
        let length = usize::try_from(
            get_u64(bytes, descriptor + 16).ok_or(SnapshotError::InvalidDescriptor)?,
        )
        .map_err(|_| SnapshotError::ExtentOverflow)?;
        if offset != expected_offset || length == 0 {
            return Err(SnapshotError::InvalidDescriptor);
        }
        expected_offset = offset
            .checked_add(length)
            .ok_or(SnapshotError::ExtentOverflow)?;
        let image_bytes = bytes
            .get(offset..expected_offset)
            .ok_or(SnapshotError::InvalidDescriptor)?;
        let admitted = BorrowedExceptionImage::from_mapped_image(base, image_bytes)
            .map_err(SnapshotError::ImageAdmission)?;
        if previous_base != 0 && base <= previous_base {
            return Err(SnapshotError::ImageOrder);
        }
        if previous_end > base {
            return Err(SnapshotError::ImageOverlap);
        }
        previous_base = base;
        previous_end = base
            .checked_add(admitted.size() as u64)
            .ok_or(SnapshotError::ExtentOverflow)?;
        admit(index, admitted);
    }
    if expected_offset != bytes.len() {
        return Err(SnapshotError::InvalidDescriptor);
    }
    Ok(count)
}

impl<'snapshot, 'slots> SealedExceptionCatalog<'snapshot, 'slots> {
    pub fn parse(
        bytes: &'snapshot [u8],
        slots: &'slots mut [Option<BorrowedExceptionImage<'snapshot>>],
    ) -> Result<Self, SnapshotError> {
        slots.fill_with(|| None);
        let count = parse_envelope(bytes, Some(slots.len()), |index, image| {
            slots[index] = Some(image);
        })?;
        Ok(Self {
            images: &slots[..count],
        })
    }

    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    pub fn read_c_scope_table(
        &self,
        image_base: u64,
        handler_data: u64,
    ) -> Result<ScopeCursor<'_>, ScopeTableError> {
        self.image_at_base(image_base)
            .ok_or(ScopeTableError::UnknownImage)?
            .read_c_scope_table(handler_data)
    }

    fn image_at_base(&self, base: u64) -> Option<&BorrowedExceptionImage<'snapshot>> {
        let index = self
            .images
            .binary_search_by_key(&base, |image| {
                image.as_ref().map_or(0, |image| image.base())
            })
            .ok()?;
        self.images.get(index)?.as_ref()
    }

    fn image_containing(&self, pc: u64) -> Option<&BorrowedExceptionImage<'snapshot>> {
        let index = self
            .images
            .partition_point(|image| image.as_ref().is_some_and(|image| image.base() <= pc))
            .checked_sub(1)?;
        let image = self.images.get(index)?.as_ref()?;
        (pc - image.base() < image.size() as u64).then_some(image)
    }
}

impl ExceptionImageReader for SealedExceptionCatalog<'_, '_> {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        self.image_containing(pc)
            .ok_or(ExceptionImageError::UnknownImage)?
            .lookup_exception_function(pc)
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        self.image_at_base(image_base)
            .is_some_and(|image| image.validate_collision_scope(image_base, handler_data, index))
    }
}

impl ImageReader for SealedExceptionCatalog<'_, '_> {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        self.image_containing(pc)?.lookup_function(pc)
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        self.image_at_base(base)?.read_u8(base, rva)
    }
}

/// A sealed image catalog requiring only the caller's immutable snapshot bytes. Parsing admits
/// every PE once; rare exception lookups re-admit only the selected image rather than retaining a
/// caller-sized array of `PeFile` section tables on the stack or heap.
pub struct SealedExceptionView<'snapshot> {
    bytes: &'snapshot [u8],
    count: usize,
}

impl<'snapshot> SealedExceptionView<'snapshot> {
    pub fn parse(bytes: &'snapshot [u8]) -> Result<Self, SnapshotError> {
        let count = parse_envelope(bytes, None, |_, _| {})?;
        Ok(Self { bytes, count })
    }

    pub fn image_count(&self) -> usize {
        self.count
    }

    pub fn read_c_scope_table(
        &self,
        image_base: u64,
        handler_data: u64,
    ) -> Result<ScopeCursor<'snapshot>, ScopeTableError> {
        let index = self
            .index_at_base(image_base)
            .ok_or(ScopeTableError::UnknownImage)?;
        self.image_at(index)
            .ok_or(ScopeTableError::UnknownImage)?
            .read_c_scope_table(handler_data)
    }

    fn descriptor(&self, index: usize) -> Option<(u64, usize, usize)> {
        if index >= self.count {
            return None;
        }
        let at = HEADER_SIZE.checked_add(index.checked_mul(DESCRIPTOR_SIZE)?)?;
        Some((
            get_u64(self.bytes, at)?,
            usize::try_from(get_u64(self.bytes, at + 8)?).ok()?,
            usize::try_from(get_u64(self.bytes, at + 16)?).ok()?,
        ))
    }

    fn image_at(&self, index: usize) -> Option<BorrowedExceptionImage<'snapshot>> {
        let (base, offset, length) = self.descriptor(index)?;
        let end = offset.checked_add(length)?;
        BorrowedExceptionImage::from_mapped_image(base, self.bytes.get(offset..end)?).ok()
    }

    fn index_at_base(&self, base: u64) -> Option<usize> {
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let candidate = self.descriptor(middle)?.0;
            if candidate < base {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        (low < self.count && self.descriptor(low)?.0 == base).then_some(low)
    }

    fn index_containing(&self, pc: u64) -> Option<usize> {
        let mut low = 0;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            if self.descriptor(middle)?.0 <= pc {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let index = low.checked_sub(1)?;
        let (base, _, length) = self.descriptor(index)?;
        (pc.checked_sub(base)? < length as u64).then_some(index)
    }
}

impl ExceptionImageReader for SealedExceptionView<'_> {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        let index = self
            .index_containing(pc)
            .ok_or(ExceptionImageError::UnknownImage)?;
        self.image_at(index)
            .ok_or(ExceptionImageError::UnreadableImage)?
            .lookup_exception_function(pc)
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        self.index_at_base(image_base)
            .and_then(|slot| self.image_at(slot))
            .is_some_and(|image| image.validate_collision_scope(image_base, handler_data, index))
    }
}

impl ImageReader for SealedExceptionView<'_> {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        self.image_at(self.index_containing(pc)?)?
            .lookup_function(pc)
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        self.image_at(self.index_at_base(base)?)?.read_u8(base, rva)
    }
}

fn get_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn get_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests;
