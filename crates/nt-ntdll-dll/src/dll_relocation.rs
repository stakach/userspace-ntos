//! Owned, in-process relocation of an acknowledged DLL image view.

use super::alloc::vec::Vec;
use core::ptr;
use nt_pe_loader::{Headers, PeError, Section};

use super::{syscall4, syscall6, NT_CURRENT_PROCESS, SSN_NT_PROTECT_VIRTUAL_MEMORY};

const INVALID_IMAGE: u32 = 0xc000_007b;
const NO_MEMORY: u32 = 0xc000_0017;
const CONFLICT: u32 = 0xc000_0018;
const IMAGE_NOT_AT_BASE: u32 = 0x4000_0003;

struct ViewOwner {
    next: *mut ViewOwner,
    name: [u8; 180],
    name_len: usize,
    base: u64,
    size: u64,
    protections: Vec<ProtectionChange>,
}

// The loader lock serializes mutations; no borrowed list entry crosses a syscall.
static mut VIEWS: *mut ViewOwner = ptr::null_mut();

/// No Drop: failed or interrupted native effects retain the owner and prohibit delta replay.
pub(super) struct DllLoad {
    owner: *mut ViewOwner,
}

impl DllLoad {
    pub(super) unsafe fn reserve(name: &[u8]) -> Result<Self, u32> {
        if name.len() > 180 {
            return Err(INVALID_IMAGE);
        }
        let mut cursor = unsafe { VIEWS };
        while !cursor.is_null() {
            let matches = unsafe {
                (*cursor).name_len == name.len() && (&(*cursor).name)[..name.len()] == *name
            };
            if matches {
                return Err(CONFLICT);
            }
            cursor = unsafe { (*cursor).next };
        }
        let owner = unsafe { crate::process_heap_alloc(core::mem::size_of::<ViewOwner>()) }
            .cast::<ViewOwner>();
        if owner.is_null() {
            return Err(NO_MEMORY);
        }
        let mut captured_name = [0; 180];
        captured_name[..name.len()].copy_from_slice(name);
        unsafe {
            ptr::write(
                owner,
                ViewOwner {
                    next: VIEWS,
                    name: captured_name,
                    name_len: name.len(),
                    base: 0,
                    size: 0,
                    protections: Vec::new(),
                },
            );
            VIEWS = owner;
        }
        Ok(Self { owner })
    }

    unsafe fn forget(self) {
        let mut link = ptr::addr_of_mut!(VIEWS);
        while !unsafe { *link }.is_null() {
            if unsafe { *link } == self.owner {
                unsafe {
                    *link = (*self.owner).next;
                    ptr::drop_in_place(self.owner);
                    crate::process_heap_free(self.owner.cast());
                }
                return;
            }
            link = unsafe { ptr::addr_of_mut!((**link).next) };
        }
    }

    pub(super) unsafe fn finish(self, base: u64, size: u64, status: u32) -> Result<(), u32> {
        // Preserve observed output slots without interpreting them as a mapping ACK.
        unsafe {
            (*self.owner).base = base;
            (*self.owner).size = size;
        }
        if status != 0 && status != IMAGE_NOT_AT_BASE {
            // Negative status can follow a committed map and a failed output store too.
            return Err(status);
        }
        let result = if base == 0 || size == 0 || base.checked_add(size).is_none() {
            Err(Failure {
                status: INVALID_IMAGE,
                uncertain: true,
            })
        } else if status == IMAGE_NOT_AT_BASE {
            unsafe { relocate(self.owner, base, size) }
        } else {
            Ok(())
        };
        match result {
            Ok(()) => {
                unsafe { self.forget() };
                Ok(())
            }
            Err(failure) => {
                if !failure.uncertain {
                    let unmap = unsafe { super::nt_unmap_view_of_section(base) };
                    if unmap == 0 {
                        unsafe { self.forget() };
                    }
                }
                Err(failure.status)
            }
        }
    }
}

struct Failure {
    status: u32,
    uncertain: bool,
}

impl From<PeError> for Failure {
    fn from(error: PeError) -> Self {
        Self {
            status: match error {
                PeError::InsufficientResources => NO_MEMORY,
                PeError::RelocationsStripped => CONFLICT,
                _ => INVALID_IMAGE,
            },
            uncertain: false,
        }
    }
}

fn acknowledged(status: u32) -> Result<(), Failure> {
    if status == 0 {
        Ok(())
    } else {
        Err(Failure {
            status,
            uncertain: (status as i32) >= 0,
        })
    }
}

unsafe fn capture(base: u64, offset: u64, length: usize, extent: u64) -> Result<Vec<u8>, PeError> {
    let end = offset
        .checked_add(length as u64)
        .ok_or(PeError::Truncated)?;
    if end > extent || base.checked_add(end).is_none() {
        return Err(PeError::Truncated);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| PeError::InsufficientResources)?;
    // Read only the proven header/directory range, not the full virtual image.
    bytes.extend_from_slice(unsafe {
        core::slice::from_raw_parts((base + offset) as *const u8, length)
    });
    Ok(bytes)
}

#[derive(Copy, Clone)]
struct ProtectionChange {
    base: u64,
    size: u64,
    original: u32,
    restored: bool,
}

unsafe fn relocate(owner: *mut ViewOwner, base: u64, extent: u64) -> Result<(), Failure> {
    let dos = unsafe { capture(base, 0, 64, extent) }?;
    let nt = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    let prefix = unsafe { capture(base, nt, 24, extent) }?;
    let optional_size = u16::from_le_bytes(prefix[20..22].try_into().unwrap()) as u64;
    let optional_end = nt
        .checked_add(24)
        .and_then(|n| n.checked_add(optional_size))
        .ok_or(PeError::Truncated)?;
    let optional_len = usize::try_from(optional_end).map_err(|_| PeError::Truncated)?;
    let optional_headers = unsafe { capture(base, 0, optional_len, extent) }?;
    // The shared parser validates AMD64/PE32+ and bounded section count before table capture.
    let headers = Headers::parse(&optional_headers)?;
    let header_end = optional_end
        .checked_add(u64::from(headers.number_of_sections) * 40)
        .ok_or(PeError::Truncated)?;
    let header_len = usize::try_from(header_end).map_err(|_| PeError::Truncated)?;
    let captured_headers = unsafe { capture(base, 0, header_len, extent) }?;
    if u64::from(headers.size_of_image) > extent || header_end > u64::from(headers.size_of_headers)
    {
        return Err(PeError::BadImageSize.into());
    }
    let directory = headers.data_directory(5);
    let captured_directory = if directory.virtual_address == 0 || directory.size == 0 {
        Vec::new()
    } else {
        unsafe {
            capture(
                base,
                u64::from(directory.virtual_address),
                directory.size as usize,
                u64::from(headers.size_of_image),
            )
        }?
    };
    let plan = nt_pe_loader::plan_mapped_relocations(&headers, &captured_directory, base)?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(headers.number_of_sections as usize)
        .map_err(|_| PeError::InsufficientResources)?;
    let section_start = headers.nt_offset + 24 + headers.size_of_optional_header as usize;
    for index in 0..headers.number_of_sections as usize {
        let section = Section::parse(&captured_headers, section_start + index * 40)?;
        if section
            .virtual_address
            .checked_add(section.size_of_raw_data)
            .is_none_or(|end| end > headers.size_of_image)
        {
            return Err(PeError::SectionOutOfBounds.into());
        }
        sections.push(section);
    }
    plan.validate_writable_targets(&sections)?;
    unsafe { (*owner).protections.try_reserve_exact(sections.len()) }
        .map_err(|_| PeError::InsufficientResources)?;
    for section in &sections {
        if section.size_of_raw_data == 0 || section.is_writable() {
            continue;
        }
        let mut start = base + u64::from(section.virtual_address);
        let mut length = u64::from(section.size_of_raw_data);
        let mut original = 0u32;
        acknowledged(unsafe {
            syscall6(
                SSN_NT_PROTECT_VIRTUAL_MEMORY,
                NT_CURRENT_PROCESS,
                ptr::addr_of_mut!(start) as u64,
                ptr::addr_of_mut!(length) as u64,
                4,
                ptr::addr_of_mut!(original) as u64,
                0,
            )
        } as u32)?;
        // Rounded native ranges and their old protection are the restoration receipt.
        unsafe {
            (*owner).protections.push(ProtectionChange {
                base: start,
                size: length,
                original,
                restored: false,
            })
        };
    }
    for fixup in plan.fixups() {
        let width = fixup.kind.width();
        if width == 0 {
            continue;
        }
        let target = (base + u64::from(fixup.rva)) as *mut u8;
        let mut value = [0u8; 8];
        unsafe { ptr::copy_nonoverlapping(target, value.as_mut_ptr(), width) };
        fixup.kind.apply_delta(&mut value[..width], plan.delta())?;
        unsafe { ptr::copy_nonoverlapping(value.as_ptr(), target, width) };
    }
    let count = unsafe { (*owner).protections.len() };
    for index in (0..count).rev() {
        let mut change = unsafe { (&(*owner).protections)[index] };
        let mut discarded = 0u32;
        acknowledged(unsafe {
            syscall6(
                SSN_NT_PROTECT_VIRTUAL_MEMORY,
                NT_CURRENT_PROCESS,
                ptr::addr_of_mut!(change.base) as u64,
                ptr::addr_of_mut!(change.size) as u64,
                u64::from(change.original),
                ptr::addr_of_mut!(discarded) as u64,
                0,
            )
        } as u32)?;
        unsafe { (&mut (*owner).protections)[index].restored = true };
    }
    acknowledged(unsafe { syscall4(82, NT_CURRENT_PROCESS, 0, 0, 0) } as u32)
}
