//! Prepared canonical page aliases for synchronous coherent file operations.
use super::*;
use nt_memory_manager::section_scratch::SectionAliasHandle;
use nt_memory_manager::{
    SectionFilePage, SectionFileReadIo, SectionFileResizeIo, SectionFileWriteIo,
};

struct PreparedFileIo<'a> {
    owner: &'a mut SectionScratch,
    file: u64,
    scratch_base: u64,
    context: Option<ExecLoopCtx>,
    access: SectionAliasAccess,
    pages: Vec<(SectionFilePage, SectionAliasHandle)>,
}

impl PreparedFileIo<'_> {
    fn begin(&mut self) -> Result<(), u32> {
        self.owner.begin(&mut ScratchIo)
    }

    fn prepare(&mut self, page: SectionFilePage) -> Result<(), u32> {
        if self.pages.iter().any(|(prior, _)| *prior == page) {
            return Err(nt_fs::STATUS_INVALID_PARAMETER);
        }
        let address = EXECUTIVE_SCRATCH_LAYOUT
            .prepared_address(self.scratch_base, self.pages.len() as u64)
            .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        self.pages
            .try_reserve(1)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        let handle = {
            // Unlike this operation's tokens, retained cap ownership outlives transient scopes.
            let _durable = allocator::enter_durable();
            self.owner
                .prepare(page.frame, address, self.access, &mut ScratchIo)?
        };
        self.pages.push((page, handle));
        Ok(())
    }

    fn address(
        &self,
        page: SectionFilePage,
        offset: usize,
        length: usize,
        access: SectionAliasAccess,
    ) -> u64 {
        let handle = self
            .pages
            .iter()
            .find(|(prior, _)| *prior == page)
            .expect("canonical transfer must have a prepared page")
            .1;
        self.owner
            .resolve(handle, offset, length, access)
            .expect("prepared canonical alias must remain valid through transfer")
    }

    fn finish(&mut self) -> Result<(), u32> {
        self.pages.clear();
        self.owner.finish(&mut ScratchIo)
    }
}

impl SectionFileReadIo for PreparedFileIo<'_> {
    fn begin(&mut self) -> Result<(), u32> {
        self.begin()
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.prepare(page)
    }
    fn read_backing(&mut self, offset: u64, output: &mut [u8]) -> (u32, usize) {
        unsafe { crate::writable_fs::read_backing_into(self.file, offset, output) }
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, output: &mut [u8]) {
        let address = self.address(page, offset, output.len(), SectionAliasAccess::ReadOnly);
        unsafe {
            core::ptr::copy_nonoverlapping(address as *const u8, output.as_mut_ptr(), output.len());
        }
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.finish()
    }
}

impl SectionFileWriteIo for PreparedFileIo<'_> {
    fn begin(&mut self) -> Result<(), u32> {
        self.begin()
    }
    fn rearm_alias(
        &mut self,
        alias: nt_memory_manager::writeback::SectionPageAlias,
    ) -> Result<(), u32> {
        section_writeback::rearm_section_alias(alias, self.context)
    }
    fn prepare_page(&mut self, page: SectionFilePage) -> Result<(), u32> {
        self.prepare(page)
    }
    fn write_backing(&mut self, offset: u64, data: &[u8]) -> (u32, usize) {
        unsafe { crate::writable_fs::write(self.file, Some(offset), data) }
    }
    fn copy_resident(&mut self, page: SectionFilePage, offset: usize, data: &[u8]) {
        let address = self.address(page, offset, data.len(), SectionAliasAccess::ReadWrite);
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), address as *mut u8, data.len());
        }
    }
    fn zero_resident(&mut self, page: SectionFilePage, offset: usize, length: usize) {
        let address = self.address(page, offset, length, SectionAliasAccess::ReadWrite);
        unsafe {
            core::ptr::write_bytes(address as *mut u8, 0, length);
        }
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.finish()
    }
}

impl SectionFileResizeIo for PreparedFileIo<'_> {
    fn resize_backing(&mut self, new_eof: u64) -> u32 {
        unsafe {
            crate::writable_fs::set_information(
                self.file,
                nt_fs::FILE_END_OF_FILE_INFORMATION,
                &new_eof.to_le_bytes(),
            )
        }
    }
}

/// Data-section mechanism only. The mutation owner must check image sections before calling and
/// retain the FILE_OBJECT throughout. Native activation waits for that shared mutation boundary.
pub(crate) unsafe fn service_resize_file_coherent(
    table: &mut GenericSectionTable,
    file: u64,
    new_eof: u64,
    context: ExecLoopCtx,
) -> u32 {
    let backing = match crate::writable_fs::section_backing(file) {
        Ok(backing) => backing,
        Err(status) => return status,
    };
    let _borrow = match ScratchBorrow::acquire() {
        Ok(guard) => guard,
        Err(status) => return status,
    };
    let mut io = PreparedFileIo {
        owner: &mut *core::ptr::addr_of_mut!(SECTION_SCRATCH),
        file,
        scratch_base: context.scratch_base,
        context: Some(context),
        access: SectionAliasAccess::ReadWrite,
        pages: Vec::new(),
    };
    table.resize_file_coherent(backing, new_eof, &mut io)
}

/// The caller retains the FILE_OBJECT, owns user completion, and supplies nonfaultable storage.
/// These adapters remain opt-in until all competing native/internal mutations are coherent.
pub(crate) unsafe fn service_read_file_coherent(
    table: &mut GenericSectionTable,
    file: u64,
    offset: u64,
    output: &mut [u8],
    context: ExecLoopCtx,
) -> (u32, usize) {
    let backing = match crate::writable_fs::section_backing(file) {
        Ok(b) => b,
        Err(status) => return (status, 0),
    };
    let _borrow = match ScratchBorrow::acquire() {
        Ok(g) => g,
        Err(status) => return (status, 0),
    };
    let mut io = PreparedFileIo {
        owner: &mut *core::ptr::addr_of_mut!(SECTION_SCRATCH),
        file,
        scratch_base: context.scratch_base,
        context: Some(context),
        access: SectionAliasAccess::ReadOnly,
        pages: Vec::new(),
    };
    table.read_file_coherent(backing, offset, output, &mut io)
}

pub(crate) unsafe fn service_write_file_coherent(
    table: &mut GenericSectionTable,
    file: u64,
    offset: u64,
    data: &[u8],
    context: ExecLoopCtx,
) -> (u32, usize) {
    let backing = match crate::writable_fs::section_backing(file) {
        Ok(b) => b,
        Err(status) => return (status, 0),
    };
    let _borrow = match ScratchBorrow::acquire() {
        Ok(g) => g,
        Err(status) => return (status, 0),
    };
    let mut io = PreparedFileIo {
        owner: &mut *core::ptr::addr_of_mut!(SECTION_SCRATCH),
        file,
        scratch_base: context.scratch_base,
        context: Some(context),
        access: SectionAliasAccess::ReadWrite,
        pages: Vec::new(),
    };
    table.write_file_coherent(backing, offset, data, &mut io)
}
