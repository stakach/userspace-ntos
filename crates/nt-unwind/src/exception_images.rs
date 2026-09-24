//! Immutable PE image snapshots admitted for exception walking.
//!
//! The supplied bytes are a complete, already mapped image at the supplied actual load base, not a
//! raw PE file. Header/section/directory parsing belongs to `nt-pe-loader`; runtime-function and
//! unwind-code decoding reuse this crate's readers. Admission never sorts or repairs function rows.
//! A missing row means Leaf only after both the image and executable PC range have been admitted.
//! Opcode 6/7 metadata is not admitted: the shared interpreter does not yet distinguish NT5 v1 XMM
//! saves from later version-specific epilogue/spare encodings. It must not silently omit restoration.
//!
//! Owning the bytes prevents later caller mutation from invalidating the parsed metadata. There are
//! no removal or replacement operations: a native execution domain must retain its catalog for all
//! active walks and separately prove that its live mappings match this snapshot. This module does
//! not authenticate a physical provider lane, install native exports, or complete collision linkage.

use alloc::{boxed::Box, vec::Vec};
use core::ops::Range;
use nt_pe_loader::{image_directory_entry, PeError, PeFile, Section};

use crate::{
    exception_walk::{ExceptionFunction, ExceptionImageError, ExceptionImageReader},
    op_slots, read_runtime_function, read_unwind_header, uwop, ImageReader, RuntimeFunction,
    ScopeRecord, DIRECTORY_ENTRY_EXCEPTION,
};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImageAdmissionError {
    Pe(PeError),
    NotExecutable,
    SnapshotSize,
    AddressRange,
    HeaderExtent,
    SectionExtent,
    SectionOverlap,
    ExceptionDirectory,
    FunctionTable,
    UnwindMetadata,
    ImageOverlap,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ScopeTableError {
    UnknownImage,
    InvalidAddress,
    InvalidExtent,
    InvalidCount,
    InsufficientResources,
    InvalidScope,
    InvalidHandler,
    InvalidTarget,
}

#[derive(Debug)]
pub struct AdmittedExceptionImage {
    base: u64,
    end: u64,
    bytes: Box<[u8]>,
    sections: Vec<Range<u32>>,
    executable: Vec<Range<u32>>,
    functions: Vec<RuntimeFunction>,
}

/// A validated view of a sealed, complete mapped PE image. The caller must keep the backing
/// mapping read-only for the entire lifetime of this view; admission cannot enforce page rights.
/// Unlike `AdmittedExceptionImage`, construction and lookup perform no heap allocation.
pub struct BorrowedExceptionImage<'a> {
    base: u64,
    end: u64,
    pe: PeFile<'a>,
}

impl<'a> BorrowedExceptionImage<'a> {
    pub fn from_mapped_image(base: u64, bytes: &'a [u8]) -> Result<Self, ImageAdmissionError> {
        let pe = PeFile::parse(bytes).map_err(ImageAdmissionError::Pe)?;
        let headers = pe.headers();
        if !headers.is_executable() {
            return Err(ImageAdmissionError::NotExecutable);
        }
        let size = headers.size_of_image;
        if size == 0 || bytes.len() != size as usize {
            return Err(ImageAdmissionError::SnapshotSize);
        }
        let end = base
            .checked_add(u64::from(size))
            .filter(|_| base != 0)
            .ok_or(ImageAdmissionError::AddressRange)?;
        let section_table_end = headers
            .section_table_offset()
            .checked_add(
                pe.sections()
                    .len()
                    .checked_mul(40)
                    .ok_or(ImageAdmissionError::HeaderExtent)?,
            )
            .ok_or(ImageAdmissionError::HeaderExtent)?;
        if section_table_end > headers.size_of_headers as usize || headers.size_of_headers > size {
            return Err(ImageAdmissionError::HeaderExtent);
        }
        for (index, section) in pe.sections().iter().enumerate() {
            let Some(range) = section_range(section) else {
                if section.virtual_size.max(section.size_of_raw_data) != 0 {
                    return Err(ImageAdmissionError::SectionExtent);
                }
                continue;
            };
            if range.start < headers.size_of_headers || range.end > size {
                return Err(ImageAdmissionError::SectionExtent);
            }
            for prior in &pe.sections()[..index] {
                if let Some(other) = section_range(prior) {
                    if range.start < other.end && other.start < range.end {
                        return Err(ImageAdmissionError::SectionOverlap);
                    }
                }
            }
        }
        let entry = headers.data_directory(DIRECTORY_ENTRY_EXCEPTION);
        if (entry.virtual_address == 0) != (entry.size == 0) || entry.size % 12 != 0 {
            return Err(ImageAdmissionError::ExceptionDirectory);
        }
        if let Some((offset, length)) =
            image_directory_entry(bytes, true, DIRECTORY_ENTRY_EXCEPTION)
                .map_err(ImageAdmissionError::Pe)?
        {
            if offset & 3 != 0 {
                return Err(ImageAdmissionError::ExceptionDirectory);
            }
            let reader = SnapshotReader { base, bytes };
            let executable = |range| covers_pe_executable(pe.sections(), range);
            let mut previous_end = 0;
            for index in 0..length / 12 {
                let rva = entry
                    .virtual_address
                    .checked_add(index * 12)
                    .ok_or(ImageAdmissionError::ExceptionDirectory)?;
                let function = read_runtime_function(&reader, base, rva)
                    .ok_or(ImageAdmissionError::FunctionTable)?;
                if !executable(function.begin..function.end)
                    || (index != 0 && previous_end > function.begin)
                {
                    return Err(ImageAdmissionError::FunctionTable);
                }
                validate_metadata(&reader, &executable, function)?;
                previous_end = function.end;
            }
        }
        Ok(Self { base, end, pe })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> usize {
        self.pe.bytes().len()
    }

    pub fn read_c_scope_table(
        &self,
        handler_data: u64,
    ) -> Result<ScopeCursor<'_>, ScopeTableError> {
        read_scope_cursor(
            self.base,
            self.pe.bytes(),
            handler_data,
            |rva| section_containing(self.pe.sections(), rva),
            |range| covers_pe_executable(self.pe.sections(), range),
        )
    }
}

impl ExceptionImageReader for BorrowedExceptionImage<'_> {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        let rva = u32::try_from(
            pc.checked_sub(self.base)
                .ok_or(ExceptionImageError::UnknownImage)?,
        )
        .map_err(|_| ExceptionImageError::UnknownImage)?;
        if pc >= self.end || !covers_pe_executable(self.pe.sections(), rva..rva.saturating_add(1)) {
            return Err(ExceptionImageError::UnknownImage);
        }
        let entry = self.pe.headers().data_directory(DIRECTORY_ENTRY_EXCEPTION);
        let reader = SnapshotReader {
            base: self.base,
            bytes: self.pe.bytes(),
        };
        let mut low = 0u32;
        let mut high = entry.size / 12;
        while low < high {
            let middle = low + (high - low) / 2;
            let row =
                read_runtime_function(&reader, self.base, entry.virtual_address + middle * 12)
                    .ok_or(ExceptionImageError::CorruptFunctionTable)?;
            if row.begin <= rva {
                low = middle + 1
            } else {
                high = middle
            }
        }
        if low != 0 {
            let function =
                read_runtime_function(&reader, self.base, entry.virtual_address + (low - 1) * 12)
                    .ok_or(ExceptionImageError::CorruptFunctionTable)?;
            if function.covers(rva) {
                return Ok(ExceptionFunction::Function {
                    image_base: self.base,
                    function,
                });
            }
        }
        Ok(ExceptionFunction::Leaf)
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        image_base == self.base
            && (index == 0
                || self
                    .read_c_scope_table(handler_data)
                    .is_ok_and(|scopes| index <= scopes.len()))
    }
}

impl ImageReader for BorrowedExceptionImage<'_> {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        match self.lookup_exception_function(pc).ok()? {
            ExceptionFunction::Function {
                image_base,
                function,
            } => Some((image_base, function)),
            ExceptionFunction::Leaf => None,
        }
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        (base == self.base)
            .then(|| self.pe.bytes().get(rva as usize).copied())
            .flatten()
    }
}

/// An already validated C scope table. Iteration has no allocation or failure path.
#[derive(Clone)]
pub struct ScopeCursor<'a> {
    raw: &'a [u8],
    index: usize,
}

impl ScopeCursor<'_> {
    pub fn len(&self) -> u32 {
        (self.raw.len() / 16) as u32
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

impl Iterator for ScopeCursor<'_> {
    type Item = ScopeRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.raw.get(self.index * 16..self.index * 16 + 16)?;
        self.index += 1;
        Some(scope_record(raw))
    }
}

impl AdmittedExceptionImage {
    /// Consume, rather than copy, a complete mapped-image snapshot. Sections are interpreted by RVA;
    /// `PointerToRawData` is deliberately not a source of bytes in this layout.
    pub fn from_mapped_image(base: u64, bytes: Box<[u8]>) -> Result<Self, ImageAdmissionError> {
        BorrowedExceptionImage::from_mapped_image(base, &bytes)?;
        let pe = PeFile::parse(&bytes).map_err(ImageAdmissionError::Pe)?;
        let headers = pe.headers();
        if !headers.is_executable() {
            return Err(ImageAdmissionError::NotExecutable);
        }
        let size = headers.size_of_image;
        if size == 0 || bytes.len() != size as usize {
            return Err(ImageAdmissionError::SnapshotSize);
        }
        let end = base
            .checked_add(u64::from(size))
            .ok_or(ImageAdmissionError::AddressRange)?;
        if base == 0 {
            return Err(ImageAdmissionError::AddressRange);
        }
        let section_table_end = headers
            .section_table_offset()
            .checked_add(
                pe.sections()
                    .len()
                    .checked_mul(40)
                    .ok_or(ImageAdmissionError::HeaderExtent)?,
            )
            .ok_or(ImageAdmissionError::HeaderExtent)?;
        if section_table_end > headers.size_of_headers as usize || headers.size_of_headers > size {
            return Err(ImageAdmissionError::HeaderExtent);
        }

        let mut sections = Vec::with_capacity(pe.sections().len());
        let mut executable = Vec::new();
        for section in pe.sections() {
            let length = section.virtual_size.max(section.size_of_raw_data);
            if length == 0 {
                continue;
            }
            let range = section.virtual_address
                ..section
                    .virtual_address
                    .checked_add(length)
                    .ok_or(ImageAdmissionError::SectionExtent)?;
            if range.start < headers.size_of_headers || range.end > size {
                return Err(ImageAdmissionError::SectionExtent);
            }
            if section.is_executable() {
                executable.push(range.clone());
            }
            sections.push(range);
        }
        sections.sort_unstable_by_key(|range| range.start);
        if sections.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(ImageAdmissionError::SectionOverlap);
        }
        executable.sort_unstable_by_key(|range| range.start);

        let entry = headers.data_directory(DIRECTORY_ENTRY_EXCEPTION);
        if (entry.virtual_address == 0) != (entry.size == 0) || entry.size % 12 != 0 {
            return Err(ImageAdmissionError::ExceptionDirectory);
        }
        let mut functions = Vec::new();
        if let Some((offset, length)) =
            image_directory_entry(&bytes, true, DIRECTORY_ENTRY_EXCEPTION)
                .map_err(ImageAdmissionError::Pe)?
        {
            if offset & 3 != 0 {
                return Err(ImageAdmissionError::ExceptionDirectory);
            }
            let reader = SnapshotReader {
                base,
                bytes: &bytes,
            };
            functions.reserve(length as usize / 12);
            for index in 0..length / 12 {
                let rva = entry
                    .virtual_address
                    .checked_add(index * 12)
                    .ok_or(ImageAdmissionError::ExceptionDirectory)?;
                let function = read_runtime_function(&reader, base, rva)
                    .ok_or(ImageAdmissionError::FunctionTable)?;
                if !covers_range(&executable, function.begin..function.end)
                    || functions
                        .last()
                        .is_some_and(|previous: &RuntimeFunction| previous.end > function.begin)
                {
                    return Err(ImageAdmissionError::FunctionTable);
                }
                functions.push(function);
            }
        }
        Ok(Self {
            base,
            end,
            bytes,
            sections,
            executable,
            functions,
        })
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Copy a C language-handler table out of admitted mapped-image metadata. The caller must
    /// supply the exact image base from its unwind invocation; an address in another image cannot
    /// be silently reinterpreted using this image's RVAs.
    pub fn read_c_scope_table(
        &self,
        handler_data: u64,
    ) -> Result<Vec<ScopeRecord>, ScopeTableError> {
        let cursor = read_scope_cursor(
            self.base,
            &self.bytes,
            handler_data,
            |rva| {
                self.sections
                    .iter()
                    .find(|section| section.contains(&rva))
                    .cloned()
            },
            |range| covers_range(&self.executable, range),
        )?;
        let mut scopes = Vec::new();
        scopes
            .try_reserve_exact(cursor.len() as usize)
            .map_err(|_| ScopeTableError::InsufficientResources)?;
        scopes.extend(cursor);
        Ok(scopes)
    }

    fn lookup(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        let rva = u32::try_from(
            pc.checked_sub(self.base)
                .ok_or(ExceptionImageError::UnknownImage)?,
        )
        .map_err(|_| ExceptionImageError::UnknownImage)?;
        if !self.executable.iter().any(|range| range.contains(&rva)) {
            return Err(ExceptionImageError::UnknownImage);
        }
        let index = self
            .functions
            .partition_point(|function| function.begin <= rva);
        if let Some(function) = index
            .checked_sub(1)
            .and_then(|index| self.functions.get(index))
        {
            if function.covers(rva) {
                return Ok(ExceptionFunction::Function {
                    image_base: self.base,
                    function: *function,
                });
            }
        }
        Ok(ExceptionFunction::Leaf)
    }
}

/// A fixed set of non-overlapping admitted image snapshots. Every lookup and byte read borrows this
/// owner; moving the catalog cannot invalidate its bytes, and no live metadata can be replaced.
#[derive(Debug)]
pub struct ExceptionImageCatalog {
    images: Vec<AdmittedExceptionImage>,
}

impl ExceptionImageCatalog {
    pub fn new(mut images: Vec<AdmittedExceptionImage>) -> Result<Self, ImageAdmissionError> {
        images.sort_unstable_by_key(|image| image.base);
        if images.windows(2).any(|pair| pair[0].end > pair[1].base) {
            return Err(ImageAdmissionError::ImageOverlap);
        }
        Ok(Self { images })
    }

    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    pub fn read_c_scope_table(
        &self,
        image_base: u64,
        handler_data: u64,
    ) -> Result<Vec<ScopeRecord>, ScopeTableError> {
        let image = self
            .images
            .binary_search_by_key(&image_base, |image| image.base)
            .ok()
            .and_then(|index| self.images.get(index))
            .ok_or(ScopeTableError::UnknownImage)?;
        image.read_c_scope_table(handler_data)
    }

    fn image_containing(&self, pc: u64) -> Option<&AdmittedExceptionImage> {
        let index = self
            .images
            .partition_point(|image| image.base <= pc)
            .checked_sub(1)?;
        self.images.get(index).filter(|image| pc < image.end)
    }
}

impl ExceptionImageReader for ExceptionImageCatalog {
    fn lookup_exception_function(&self, pc: u64) -> Result<ExceptionFunction, ExceptionImageError> {
        self.image_containing(pc)
            .ok_or(ExceptionImageError::UnknownImage)?
            .lookup(pc)
    }

    fn validate_collision_scope(&self, image_base: u64, handler_data: u64, index: u32) -> bool {
        index == 0
            || self
                .read_c_scope_table(image_base, handler_data)
                .is_ok_and(|scopes| index <= scopes.len() as u32)
    }
}

impl ImageReader for ExceptionImageCatalog {
    fn lookup_function(&self, pc: u64) -> Option<(u64, RuntimeFunction)> {
        match self.lookup_exception_function(pc).ok()? {
            ExceptionFunction::Function {
                image_base,
                function,
            } => Some((image_base, function)),
            ExceptionFunction::Leaf => None,
        }
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        let index = self
            .images
            .binary_search_by_key(&base, |image| image.base)
            .ok()?;
        self.images[index].bytes.get(rva as usize).copied()
    }
}

struct SnapshotReader<'a> {
    base: u64,
    bytes: &'a [u8],
}

impl ImageReader for SnapshotReader<'_> {
    fn lookup_function(&self, _: u64) -> Option<(u64, RuntimeFunction)> {
        None
    }

    fn read_u8(&self, base: u64, rva: u32) -> Option<u8> {
        if base != self.base {
            return None;
        }
        self.bytes.get(rva as usize).copied()
    }
}

fn section_range(section: &Section) -> Option<Range<u32>> {
    let length = section.virtual_size.max(section.size_of_raw_data);
    (length != 0).then_some(())?;
    Some(section.virtual_address..section.virtual_address.checked_add(length)?)
}

fn scope_record(raw: &[u8]) -> ScopeRecord {
    let field = |offset: usize| u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap());
    ScopeRecord {
        begin: field(0),
        end: field(4),
        handler: field(8),
        target: field(12),
    }
}

fn read_scope_cursor<'a>(
    base: u64,
    bytes: &'a [u8],
    handler_data: u64,
    containing_section: impl Fn(u32) -> Option<Range<u32>>,
    executable: impl Fn(Range<u32>) -> bool,
) -> Result<ScopeCursor<'a>, ScopeTableError> {
    let rva = u32::try_from(
        handler_data
            .checked_sub(base)
            .ok_or(ScopeTableError::InvalidAddress)?,
    )
    .map_err(|_| ScopeTableError::InvalidAddress)?;
    if rva & 3 != 0 {
        return Err(ScopeTableError::InvalidAddress);
    }
    let section = containing_section(rva).ok_or(ScopeTableError::InvalidAddress)?;
    let header_end = rva.checked_add(4).ok_or(ScopeTableError::InvalidExtent)?;
    if header_end > section.end {
        return Err(ScopeTableError::InvalidExtent);
    }
    let count = u32::from_le_bytes(
        bytes
            .get(rva as usize..header_end as usize)
            .ok_or(ScopeTableError::InvalidExtent)?
            .try_into()
            .map_err(|_| ScopeTableError::InvalidExtent)?,
    );
    if count > 4096 {
        return Err(ScopeTableError::InvalidCount);
    }
    let end = count
        .checked_mul(16)
        .and_then(|length| header_end.checked_add(length))
        .ok_or(ScopeTableError::InvalidExtent)?;
    if end > section.end {
        return Err(ScopeTableError::InvalidExtent);
    }
    let raw = bytes
        .get(header_end as usize..end as usize)
        .ok_or(ScopeTableError::InvalidExtent)?;
    for row in raw.chunks_exact(16) {
        let scope = scope_record(row);
        if !executable(scope.begin..scope.end) {
            return Err(ScopeTableError::InvalidScope);
        }
        if scope.handler != 1
            && !scope
                .handler
                .checked_add(1)
                .is_some_and(|end| executable(scope.handler..end))
        {
            return Err(ScopeTableError::InvalidHandler);
        }
        if scope.target == 0 {
            if scope.handler == 1 {
                return Err(ScopeTableError::InvalidHandler);
            }
        } else if !scope
            .target
            .checked_add(1)
            .is_some_and(|end| executable(scope.target..end))
        {
            return Err(ScopeTableError::InvalidTarget);
        }
    }
    Ok(ScopeCursor { raw, index: 0 })
}

fn section_containing(sections: &[Section], rva: u32) -> Option<Range<u32>> {
    sections
        .iter()
        .filter_map(section_range)
        .find(|range| range.contains(&rva))
}

fn covers_pe_executable(sections: &[Section], range: Range<u32>) -> bool {
    if range.start >= range.end {
        return false;
    }
    let mut covered = range.start;
    while covered < range.end {
        let Some(next) = sections
            .iter()
            .filter(|section| section.is_executable())
            .filter_map(section_range)
            .find(|section| section.contains(&covered))
        else {
            return false;
        };
        covered = next.end;
    }
    true
}

fn covers_range(executable: &[Range<u32>], range: Range<u32>) -> bool {
    if range.start >= range.end {
        return false;
    }
    let mut covered = range.start;
    for section in executable {
        if section.end <= covered {
            continue;
        }
        if section.start > covered {
            return false;
        }
        covered = section.end;
        if covered >= range.end {
            return true;
        }
    }
    false
}

fn validate_metadata(
    reader: &SnapshotReader<'_>,
    executable: &impl Fn(Range<u32>) -> bool,
    mut function: RuntimeFunction,
) -> Result<(), ImageAdmissionError> {
    let invalid = ImageAdmissionError::UnwindMetadata;
    // One combined bound covers indirect runtime entries and CHAININFO tails, as virtual_unwind.
    let mut links = 32u8;
    let mut chained_frame = None;
    loop {
        if !executable(function.begin..function.end) {
            return Err(invalid);
        }
        if function.is_chained_ptr() {
            links = links.checked_sub(1).ok_or(invalid)?;
            let rva = function.unwind_info & !1;
            if rva & 3 != 0 {
                return Err(invalid);
            }
            function = read_runtime_function(reader, reader.base, rva).ok_or(invalid)?;
            continue;
        }
        let rva = function.unwind_info;
        if rva & 3 != 0 {
            return Err(invalid);
        }
        let header = read_unwind_header(reader, reader.base, rva).ok_or(invalid)?;
        let frame = (header.frame_register, header.frame_offset);
        if (header.frame_register == 0 && header.frame_offset != 0)
            || (header.frame_register != 0 && !nonvolatile_gpr(header.frame_register))
            || chained_frame.is_some_and(|expected| expected != frame)
        {
            return Err(invalid);
        }
        let tail = rva
            .checked_add(header.tail_offset() as u32)
            .ok_or(invalid)?;
        // Check all padded code bytes, not only operations that a particular control PC executes.
        if reader.bytes.get(rva as usize..tail as usize).is_none() {
            return Err(invalid);
        }
        let mut slot = 0;
        let mut previous_offset = header.size_of_prolog;
        while slot < header.count_of_codes {
            let at = rva.checked_add(4 + u32::from(slot) * 2).ok_or(invalid)?;
            let code_offset = reader.read_u8(reader.base, at).ok_or(invalid)?;
            if code_offset > previous_offset {
                return Err(invalid);
            }
            previous_offset = code_offset;
            let encoded = reader.read_u8(reader.base, at + 1).ok_or(invalid)?;
            let op = encoded & 15;
            if matches!(op, 6 | 7) {
                return Err(invalid);
            }
            let info = encoded >> 4;
            // PUSH/SAVE_NONVOL encode any GPR ordinal despite their names. Real stack-probe
            // assembly saves RAX/RCX this way; only the separate frame-register role is restricted.
            if (op == uwop::SET_FPREG && (info != 0 || header.frame_register == 0))
                || (matches!(op, uwop::SAVE_XMM128 | uwop::SAVE_XMM128_FAR) && info < 6)
            {
                return Err(invalid);
            }
            let slots = op_slots(op, info).ok_or(invalid)?;
            let next = usize::from(slot) + slots;
            if next > usize::from(header.count_of_codes)
                || (op == uwop::PUSH_MACHFRAME
                    && (header.is_chained() || next != usize::from(header.count_of_codes)))
            {
                return Err(invalid);
            }
            slot = next as u8;
        }
        if header.is_chained() {
            chained_frame = Some(frame);
            links = links.checked_sub(1).ok_or(invalid)?;
            function = read_runtime_function(reader, reader.base, tail).ok_or(invalid)?;
        } else {
            if header.has_handler() {
                let handler = reader.read_u32(reader.base, tail).ok_or(invalid)?;
                if !handler
                    .checked_add(1)
                    .is_some_and(|end| executable(handler..end))
                {
                    return Err(invalid);
                }
                let data = tail.checked_add(4).ok_or(invalid)?;
                reader.read_u8(reader.base, data).ok_or(invalid)?;
            }
            return Ok(());
        }
    }
}

fn nonvolatile_gpr(register: u8) -> bool {
    matches!(register, 3 | 5 | 6 | 7 | 12..=15)
}

#[cfg(test)]
mod tests;
