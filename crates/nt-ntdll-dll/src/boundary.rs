//! LiberNT private-namespace boundary descriptors.
//!
//! The byte layout and return contracts follow the pinned LiberNT
//! `sdk/lib/rtl/boundary.c` and `sdk/include/ndk/obtypes.h`. Descriptors are
//! process-heap allocations containing a 16-byte header and 8-byte entries;
//! each entry owns a four-byte-aligned copy of its name or SID.

use core::ffi::c_void;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const VERSION: u32 = 1;
const ADD_APPCONTAINER_SID: u32 = 1;
const NAME: u32 = 1;
const SID: u32 = 2;
const INTEGRITY_LABEL: u32 = 3;
const HEADER_SIZE: usize = 16;
const ENTRY_SIZE: usize = 8;
const MAX_SID_SUB_AUTHORITIES: u8 = 15;
const MANDATORY_LABEL_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 16];

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[inline]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

#[inline]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn entry_size(data_len: usize) -> Option<usize> {
    let padded = data_len.checked_add(3)? & !3;
    let size = ENTRY_SIZE.checked_add(padded)?;
    (size <= u32::MAX as usize).then_some(size)
}

fn total_after_append(old_size: usize, data_len: usize) -> Option<usize> {
    let total = old_size.checked_add(entry_size(data_len)?)?;
    (total <= u32::MAX as usize).then_some(total)
}

fn write_entry(bytes: &mut [u8], offset: usize, kind: u32, data: &[u8]) -> Option<()> {
    let size = entry_size(data.len())?;
    let entry = bytes.get_mut(offset..offset.checked_add(size)?)?;
    entry.fill(0);
    write_u32(entry, 0, kind);
    write_u32(entry, 4, size as u32);
    entry[ENTRY_SIZE..ENTRY_SIZE + data.len()].copy_from_slice(data);
    Some(())
}

fn write_new_descriptor(bytes: &mut [u8], name: &[u8], flags: u32) -> Option<()> {
    let size = total_after_append(HEADER_SIZE, name.len())?;
    if bytes.len() != size || name.is_empty() || flags & !ADD_APPCONTAINER_SID != 0 {
        return None;
    }
    bytes.fill(0);
    write_u32(bytes, 0, VERSION);
    write_u32(bytes, 4, 1);
    write_u32(bytes, 8, size as u32);
    write_u32(bytes, 12, flags);
    write_entry(bytes, HEADER_SIZE, NAME, name)
}

fn valid_descriptor(bytes: &[u8]) -> bool {
    if bytes.len() < HEADER_SIZE
        || read_u32(bytes, 0) != Some(VERSION)
        || read_u32(bytes, 8) != Some(bytes.len() as u32)
        || read_u32(bytes, 12).is_none_or(|flags| flags & !ADD_APPCONTAINER_SID != 0)
    {
        return false;
    }
    let Some(items) = read_u32(bytes, 4) else {
        return false;
    };
    let mut offset = HEADER_SIZE;
    for _ in 0..items {
        if offset.checked_add(ENTRY_SIZE).is_none_or(|end| end > bytes.len()) {
            return false;
        }
        let Some(size) = read_u32(bytes, offset + 4).map(|size| size as usize) else {
            return false;
        };
        if size < ENTRY_SIZE || size & 3 != 0 {
            return false;
        }
        let Some(end) = offset.checked_add(size) else {
            return false;
        };
        if end > bytes.len() {
            return false;
        }
        offset = end;
    }
    offset == bytes.len()
}

fn has_integrity_label(bytes: &[u8]) -> bool {
    let mut offset = HEADER_SIZE;
    let items = read_u32(bytes, 4).unwrap_or(0);
    for _ in 0..items {
        if read_u32(bytes, offset) == Some(INTEGRITY_LABEL) {
            return true;
        }
        offset += read_u32(bytes, offset + 4).unwrap_or(0) as usize;
    }
    false
}

fn append_size(old: &[u8], kind: u32, data_len: usize) -> Option<usize> {
    if !valid_descriptor(old)
        || read_u32(old, 4)? == u32::MAX
        || (kind == INTEGRITY_LABEL && has_integrity_label(old))
    {
        return None;
    }
    total_after_append(old.len(), data_len)
}

fn append_entry(old: &[u8], new: &mut [u8], kind: u32, data: &[u8]) -> Option<()> {
    if new.len() != append_size(old, kind, data.len())? {
        return None;
    }
    new[..old.len()].copy_from_slice(old);
    write_entry(new, old.len(), kind, data)?;
    write_u32(new, 4, read_u32(old, 4)? + 1);
    let new_len = new.len() as u32;
    write_u32(new, 8, new_len);
    Some(())
}

/// The caller must supply a readable SID allocation of its declared length.
unsafe fn sid_length(sid: *const u8) -> Option<usize> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: a caller-supplied PSID provides at least the fixed eight-byte SID header.
    let revision = unsafe { *sid };
    let count = unsafe { *sid.add(1) };
    if revision & 0x0f != 1 || count > MAX_SID_SUB_AUTHORITIES {
        return None;
    }
    Some(8 + 4 * count as usize)
}

/// The caller must supply a readable SID allocation of its declared length.
unsafe fn is_integrity_sid(sid: *const u8) -> Option<usize> {
    let len = unsafe { sid_length(sid) }?;
    if len != 12 {
        return None;
    }
    // SAFETY: a valid one-subauthority SID has all six authority bytes readable.
    let authority = unsafe { core::slice::from_raw_parts(sid.add(2), 6) };
    (authority == MANDATORY_LABEL_AUTHORITY).then_some(len)
}

#[cfg(not(test))]
unsafe fn allocate(size: usize) -> *mut u8 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the process heap owns every boundary descriptor allocation.
        unsafe { crate::process_heap_alloc(size) }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = size;
        core::ptr::null_mut()
    }
}

#[cfg(not(test))]
unsafe fn free(ptr: *mut u8) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: callers pass only a descriptor allocated by `allocate`.
        let _ = unsafe { crate::process_heap_free(ptr) };
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = ptr;
    }
}

/// `PVOID RtlCreateBoundaryDescriptor(PUNICODE_STRING Name, ULONG Flags)`.
///
/// # Safety
/// `name` and its counted UTF-16 buffer must remain readable during this call.
#[cfg(not(test))]
#[export_name = "RtlCreateBoundaryDescriptor"]
pub unsafe extern "system" fn rtl_create_boundary_descriptor(
    name: *const UnicodeString,
    flags: u32,
) -> *mut c_void {
    if name.is_null() || flags & !ADD_APPCONTAINER_SID != 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: caller supplies a readable counted Unicode string.
    let name = unsafe { &*name };
    if name.buffer.is_null() || name.length == 0 || name.length > name.maximum_length {
        return core::ptr::null_mut();
    }
    let Some(size) = total_after_append(HEADER_SIZE, name.length as usize) else {
        return core::ptr::null_mut();
    };
    // SAFETY: allocation and caller's counted UTF-16 buffer have the declared sizes.
    let descriptor = unsafe { allocate(size) };
    if descriptor.is_null() {
        return core::ptr::null_mut();
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(descriptor, size) };
    let name_bytes = unsafe { core::slice::from_raw_parts(name.buffer.cast::<u8>(), name.length as usize) };
    if write_new_descriptor(bytes, name_bytes, flags).is_none() {
        // SAFETY: `descriptor` was just allocated from this heap.
        unsafe { free(descriptor) };
        return core::ptr::null_mut();
    }
    descriptor.cast()
}

/// Append a copied SID, moving the heap allocation only after construction succeeds.
///
/// # Safety
/// `descriptor` points to a live descriptor allocated by this module, and `data` is readable.
#[cfg(not(test))]
unsafe fn append_owned(
    descriptor: *mut *mut c_void,
    kind: u32,
    data: &[u8],
) -> u32 {
    if descriptor.is_null() || unsafe { (*descriptor).is_null() } {
        return STATUS_INVALID_PARAMETER;
    }
    let old_ptr = unsafe { *descriptor }.cast::<u8>();
    // Check heap ownership before dereferencing even the fixed descriptor header.
    let allocation_size = {
        #[cfg(target_arch = "x86_64")]
        {
            let Some(size) = (unsafe { crate::process_heap_size(old_ptr) }) else {
                return STATUS_INVALID_PARAMETER;
            };
            size
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            return STATUS_INVALID_PARAMETER;
        }
    };
    if allocation_size < HEADER_SIZE || allocation_size > u32::MAX as usize {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the heap confirms the complete fixed header is part of a live allocation.
    let old_len = unsafe { core::ptr::read_unaligned(old_ptr.add(8).cast::<u32>()) as usize };
    if old_len != allocation_size {
        return STATUS_INVALID_PARAMETER;
    }
    let old = unsafe { core::slice::from_raw_parts(old_ptr, old_len) };
    let Some(new_len) = append_size(old, kind, data.len()) else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: allocation is owned by this process heap.
    let new_ptr = unsafe { allocate(new_len) };
    if new_ptr.is_null() {
        return STATUS_NO_MEMORY;
    }
    let new = unsafe { core::slice::from_raw_parts_mut(new_ptr, new_len) };
    if append_entry(old, new, kind, data).is_none() {
        unsafe { free(new_ptr) };
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the old pointer remains live until the complete replacement exists.
    unsafe { free(old_ptr) };
    unsafe { *descriptor = new_ptr.cast() };
    STATUS_SUCCESS
}

/// `NTSTATUS RtlAddSIDToBoundaryDescriptor(PVOID *BoundaryDescriptor, PSID RequiredSid)`.
///
/// # Safety
/// Both pointer arguments follow the native API contract.
#[cfg(not(test))]
#[export_name = "RtlAddSIDToBoundaryDescriptor"]
pub unsafe extern "system" fn rtl_add_sid_to_boundary_descriptor(
    descriptor: *mut *mut c_void,
    sid: *const c_void,
) -> u32 {
    let Some(length) = (unsafe { sid_length(sid.cast()) }) else {
        return STATUS_INVALID_SID;
    };
    // SAFETY: validated SID count determines its byte length.
    let bytes = unsafe { core::slice::from_raw_parts(sid.cast::<u8>(), length) };
    unsafe { append_owned(descriptor, SID, bytes) }
}

/// `NTSTATUS RtlAddIntegrityLabelToBoundaryDescriptor(PVOID *, PSID)`.
///
/// # Safety
/// Both pointer arguments follow the native API contract.
#[cfg(not(test))]
#[export_name = "RtlAddIntegrityLabelToBoundaryDescriptor"]
pub unsafe extern "system" fn rtl_add_integrity_label_to_boundary_descriptor(
    descriptor: *mut *mut c_void,
    sid: *const c_void,
) -> u32 {
    let Some(length) = (unsafe { is_integrity_sid(sid.cast()) }) else {
        return STATUS_INVALID_SID;
    };
    // SAFETY: a valid mandatory-label SID has exactly twelve bytes.
    let bytes = unsafe { core::slice::from_raw_parts(sid.cast::<u8>(), length) };
    unsafe { append_owned(descriptor, INTEGRITY_LABEL, bytes) }
}

/// `VOID RtlDeleteBoundaryDescriptor(PVOID BoundaryDescriptor)`.
///
/// # Safety
/// A nonnull argument must be an allocation returned by this module.
#[cfg(not(test))]
#[export_name = "RtlDeleteBoundaryDescriptor"]
pub unsafe extern "system" fn rtl_delete_boundary_descriptor(descriptor: *mut c_void) {
    if !descriptor.is_null() {
        // SAFETY: caller owns the descriptor allocation.
        unsafe { free(descriptor.cast()) };
    }
}

#[cfg(not(test))]
#[used]
pub static BOUNDARY_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = boundary_export_anchor;

#[cfg(not(test))]
pub unsafe extern "C" fn boundary_export_anchor() {
    core::hint::black_box([
        rtl_create_boundary_descriptor as *const () as usize,
        rtl_add_sid_to_boundary_descriptor as *const () as usize,
        rtl_add_integrity_label_to_boundary_descriptor as *const () as usize,
        rtl_delete_boundary_descriptor as *const () as usize,
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_sids_have_pinned_libernt_layout() {
        let name = [b'T', 0, b'e', 0, b's', 0, b't', 0];
        let mut first = [0_u8; 32];
        write_new_descriptor(&mut first, &name, 1).unwrap();
        assert_eq!(&first[..16], &[1, 0, 0, 0, 1, 0, 0, 0, 32, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(read_u32(&first, 16), Some(NAME));
        assert_eq!(&first[24..], &name);
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut second = [0_u8; 52];
        append_entry(&first, &mut second, SID, &sid).unwrap();
        assert!(valid_descriptor(&second));
        assert_eq!(read_u32(&second, 4), Some(2));
        assert_eq!(read_u32(&second, 32), Some(SID));
        assert_eq!(&second[40..52], &sid);
    }

    #[test]
    fn integrity_label_requires_mandatory_authority_and_single_rid() {
        let good = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];
        assert_eq!(unsafe { is_integrity_sid(good.as_ptr()) }, Some(12));
        let mut bad_authority = good;
        bad_authority[7] = 5;
        assert_eq!(unsafe { is_integrity_sid(bad_authority.as_ptr()) }, None);
        let mut bad_count = good;
        bad_count[1] = 0;
        assert_eq!(unsafe { is_integrity_sid(bad_count.as_ptr()) }, None);
        assert_eq!(unsafe { sid_length(core::ptr::null()) }, None);
    }

    #[test]
    fn malformed_entry_and_duplicate_integrity_label_are_rejected() {
        let mut first = [0_u8; 28];
        write_new_descriptor(&mut first, &[b'X', 0, 0, 0], 0).unwrap();
        let sid = [1, 1, 0, 0, 0, 0, 0, 16, 0, 0x20, 0, 0];
        let mut second = [0_u8; 48];
        append_entry(&first, &mut second, INTEGRITY_LABEL, &sid).unwrap();
        assert!(has_integrity_label(&second));
        let mut third = [0_u8; 68];
        assert_eq!(append_entry(&second, &mut third, INTEGRITY_LABEL, &sid), None);
        let mut corrupt = second;
        write_u32(&mut corrupt, 32, 0);
        assert!(!valid_descriptor(&corrupt));
        assert_eq!(entry_size(usize::MAX), None);
    }
}
