//! Minimal ELF64 parser (ported from the rust-micro kernel's `src/elf.rs`).
//!
//! The driver-host acts as a loader for the separate `driver-host-um` driver
//! binary: it walks the program-header table for `PT_LOAD` segments, then (in
//! `main.rs`) allocates private frames, copies each segment's bytes, and maps
//! them at the linker-chosen vaddrs in the isolated driver's fresh VSpace.
//!
//! Only the subset we need: ELF64, little-endian, x86_64, static (no dynamic
//! relocation, no interpreter).

#![allow(dead_code)]

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

const ELFMAG0: u8 = 0x7f;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;

/// Segment flag bits (program-header `p_flags`).
pub const PF_X: u32 = 0x1;
pub const PF_W: u32 = 0x2;
pub const PF_R: u32 = 0x4;

#[repr(C, packed)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C, packed)]
struct Elf64Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// A parsed ELF image. `entry` is the user-mode entry point (`e_entry`).
#[derive(Copy, Clone, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
    pub entry: u64,
    phoff: u64,
    phnum: u16,
}

/// One loadable segment.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub flags: u32,
}

impl LoadSegment {
    pub fn writable(&self) -> bool {
        (self.flags & PF_W) != 0
    }
    pub fn executable(&self) -> bool {
        (self.flags & PF_X) != 0
    }
    pub fn readable(&self) -> bool {
        (self.flags & PF_R) != 0
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ElfError {
    NotEnoughBytes,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    BadVersion,
    NotX86_64,
    NotExecutable,
    BadPhdrSize,
}

pub fn parse(bytes: &[u8]) -> Result<Image<'_>, ElfError> {
    if bytes.len() < core::mem::size_of::<Elf64Ehdr>() {
        return Err(ElfError::NotEnoughBytes);
    }
    let h_ptr = bytes.as_ptr() as *const Elf64Ehdr;
    // SAFETY: `bytes` is at least an ehdr long; fields read unaligned.
    let ident: [u8; 16] =
        unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_ident)) };
    if ident[EI_MAG0] != ELFMAG0
        || ident[EI_MAG1] != ELFMAG1
        || ident[EI_MAG2] != ELFMAG2
        || ident[EI_MAG3] != ELFMAG3
    {
        return Err(ElfError::BadMagic);
    }
    if ident[EI_CLASS] != ELFCLASS64 {
        return Err(ElfError::NotElf64);
    }
    if ident[EI_DATA] != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if ident[EI_VERSION] != EV_CURRENT {
        return Err(ElfError::BadVersion);
    }
    // SAFETY: header present; unaligned reads of scalar fields.
    unsafe {
        let e_machine = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_machine));
        if e_machine != EM_X86_64 {
            return Err(ElfError::NotX86_64);
        }
        let e_type = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_type));
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(ElfError::NotExecutable);
        }
        let e_phentsize = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phentsize));
        if e_phentsize as usize != core::mem::size_of::<Elf64Phdr>() {
            return Err(ElfError::BadPhdrSize);
        }
        let entry = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_entry));
        let phoff = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phoff));
        let phnum = core::ptr::read_unaligned(core::ptr::addr_of!((*h_ptr).e_phnum));
        let need_end = phoff
            .checked_add(phnum as u64 * e_phentsize as u64)
            .ok_or(ElfError::NotEnoughBytes)?;
        if (need_end as usize) > bytes.len() {
            return Err(ElfError::NotEnoughBytes);
        }
        Ok(Image { bytes, entry, phoff, phnum })
    }
}

impl<'a> Image<'a> {
    pub fn load_segments(&self) -> LoadSegments<'a> {
        LoadSegments { bytes: self.bytes, phoff: self.phoff, remaining: self.phnum }
    }
}

pub struct LoadSegments<'a> {
    bytes: &'a [u8],
    phoff: u64,
    remaining: u16,
}

impl Iterator for LoadSegments<'_> {
    type Item = LoadSegment;

    fn next(&mut self) -> Option<Self::Item> {
        let phdr_size = core::mem::size_of::<Elf64Phdr>();
        while self.remaining > 0 {
            let off = self.phoff as usize;
            self.phoff += phdr_size as u64;
            self.remaining -= 1;
            if off + phdr_size > self.bytes.len() {
                return None;
            }
            // SAFETY: bounds checked above; unaligned scalar reads.
            let p_ptr = unsafe { self.bytes.as_ptr().add(off) as *const Elf64Phdr };
            let p_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_type)) };
            if p_type != PT_LOAD {
                continue;
            }
            // SAFETY: as above.
            unsafe {
                return Some(LoadSegment {
                    vaddr: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_vaddr)),
                    file_off: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_offset)),
                    file_size: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_filesz)),
                    mem_size: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_memsz)),
                    flags: core::ptr::read_unaligned(core::ptr::addr_of!((*p_ptr).p_flags)),
                });
            }
        }
        None
    }
}
