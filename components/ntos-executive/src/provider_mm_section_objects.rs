//! Exact kernel Section pointers and physical provider-VSpace views of canonical backing.

use crate::*;
use alloc::{boxed::Box, vec::Vec};
use crate::exec_handler::section_create::ReservedGenericDataSection;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::win32k_subsystem::RootProviderPoolAllocation;
use nt_memory_manager::{ProviderSectionView, ProviderVspaceIdentity, SectionReference};

const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const NO_MEMORY: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const FAILED: u32 = 0xc000_0001;
const NOT_SUPPORTED: u32 = 0xc000_00bb;
const BUSY: u32 = 0x8000_0011;
const VIEW_START: u64 = 0x0000_0100_2000_0000;
const VIEW_END: u64 = 0x0000_0100_3000_0000;
const TABLE_SIZE: u64 = 0x20_0000;
const DESCRIPTOR_SIZE: u64 = 8;

#[derive(Clone, Copy, Default)]
struct Cap {
    slot: u64,
    created: bool,
    mapped: bool,
    uncertain: bool,
}

struct Mapping {
    view: ProviderSectionView,
    span: u64,
    frames: Vec<Cap>,
    tables: Vec<Cap>,
    published: bool,
    retiring: bool,
    uncertain: bool,
}

struct Object {
    allocation: Option<RootProviderPoolAllocation>,
    address: u64,
    physical: runtime::PhysicalSource,
    vspace: Cap,
    references: Vec<SectionReference>,
    maps: Vec<Box<Mapping>>,
    published: bool,
    retiring: bool,
    uncertain: bool,
}

static mut OBJECTS: Vec<Box<Object>> = Vec::new();

unsafe fn table(handler: *mut ExecNtHandler) -> Result<*mut GenericSectionTable, u32> {
    if handler.is_null() { return Err(INVALID); }
    (*handler).loop_ctx.map(|ctx| ctx.generic_sections).ok_or(0xc000_00a3)
}

unsafe fn object(address: u64, physical: runtime::PhysicalSource) -> Result<*mut Object, u32> {
    (&mut *core::ptr::addr_of_mut!(OBJECTS)).iter_mut()
        .find(|row| address != 0 && row.address == address
            && row.physical.domain == physical.domain && row.physical.pml4 == physical.pml4)
        .map(|row| &mut **row as *mut Object).ok_or(INVALID)
}

fn provider_identity(physical: runtime::PhysicalSource) -> Result<ProviderVspaceIdentity, u32> {
    match physical.domain {
        runtime::PhysicalDomain::Provider { domain, .. } if domain.is_valid() => {
            Ok(ProviderVspaceIdentity { domain: domain.domain, generation: domain.generation })
        }
        _ => Err(NOT_SUPPORTED),
    }
}

/// Ownership is durably recorded before copying the physical VSpace capability.
pub(crate) unsafe fn prepare(
    handler: &mut ExecNtHandler,
    mut reserved: ReservedGenericDataSection,
    physical: runtime::PhysicalSource,
) -> Result<u64, u32> {
    let _durable = crate::allocator::enter_durable();
    if provider_identity(physical).is_err() || physical.pml4 == 0 {
        reserved.abort(handler);
        return Err(NOT_SUPPORTED);
    }
    let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
    if rows.try_reserve(1).is_err() {
        reserved.abort(handler);
        return Err(NO_MEMORY);
    }
    let mut references = Vec::new();
    if references.try_reserve(1).is_err() {
        reserved.abort(handler);
        return Err(NO_MEMORY);
    }
    let allocation = match crate::win32k_subsystem::try_allocate_root_provider_pool_allocation(DESCRIPTOR_SIZE) {
        Ok(allocation) => allocation,
        Err(error) => {
            reserved.abort(handler);
            return Err(match error {
                crate::win32k_subsystem::RootPoolError::BusyNoEffect => BUSY,
                crate::win32k_subsystem::RootPoolError::InvalidIdentity => INVALID,
                crate::win32k_subsystem::RootPoolError::InsufficientResources => NO_MEMORY,
                crate::win32k_subsystem::RootPoolError::Indeterminate => FAILED,
            });
        }
    };
    let address = allocation.address();
    rows.push(Box::new(Object {
        allocation: Some(allocation), address, physical, vspace: Cap::default(), references,
        maps: Vec::new(), published: false, retiring: false, uncertain: false,
    }));
    let row = &mut **rows.last_mut().unwrap() as *mut Object;
    let (reference, _, _) = match reserved.into_object_reference(handler) {
        Ok(value) => value,
        Err(status) => {
            (*row).retiring = true;
            let _ = retire_object(row);
            return Err(status);
        }
    };
    (*row).references.push(reference);
    let Some(slot) = try_alloc_slot() else {
        let _ = abort(handler as *mut _, address, physical);
        return Err(NO_MEMORY);
    };
    (*row).vspace.slot = slot;
    (*row).uncertain = true;
    let error = copy_cap_into_r(physical.pml4, slot);
    if error != 0 { return Err(FAILED); }
    (*row).vspace.created = true;
    (*row).uncertain = false;
    Ok(address)
}

pub(crate) unsafe fn publish(address: u64, physical: runtime::PhysicalSource) -> Result<(), u32> {
    let row = object(address, physical)?;
    if (*row).published || (*row).retiring || (*row).uncertain || (*row).references.len() != 1 {
        return Err(INVALID);
    }
    (*row).published = true;
    Ok(())
}

pub(crate) unsafe fn reference(
    handler: *mut ExecNtHandler, address: u64, physical: runtime::PhysicalSource,
) -> Result<u64, u32> {
    let row = object(address, physical)?;
    if !(*row).published || (*row).retiring || (*row).uncertain { return Err(INVALID); }
    let source = (*row).references.last().copied().ok_or(INVALID)?;
    (*row).references.try_reserve(1).map_err(|_| NO_MEMORY)?;
    let token = (&mut *table(handler)?).retain_section_reference(source).ok_or(NO_MEMORY)?;
    (*row).references.push(token);
    Ok((*row).references.len() as u64)
}

pub(crate) unsafe fn dereference(
    handler: *mut ExecNtHandler, address: u64, physical: runtime::PhysicalSource,
) -> Result<u64, u32> {
    let row = object(address, physical)?;
    if !(*row).published || (*row).retiring || (*row).uncertain { return Err(INVALID); }
    let token = (*row).references.last().copied().ok_or(INVALID)?;
    if !(&mut *table(handler)?).release_section_reference(token) { return Err(INVALID); }
    let _ = (*row).references.pop();
    let remaining = (*row).references.len() as u64;
    if remaining == 0 {
        (*row).retiring = true;
        // The lease is consumed. Deferred physical cleanup stays owned, never asks for replay.
        let _ = retire_object(row);
    }
    Ok(remaining)
}

pub(crate) unsafe fn abort(
    handler: *mut ExecNtHandler, address: u64, physical: runtime::PhysicalSource,
) -> Result<(), u32> {
    let row = object(address, physical)?;
    if (*row).published || (*row).uncertain || !(*row).maps.is_empty() { return Err(BUSY); }
    let sections = table(handler)?;
    while let Some(token) = (*row).references.last().copied() {
        if !(&mut *sections).release_section_reference(token) { return Err(INVALID); }
        let _ = (*row).references.pop();
    }
    (*row).retiring = true;
    let _ = retire_object(row);
    Ok(())
}

unsafe fn choose_base(physical: runtime::PhysicalSource, span: u64) -> Option<u64> {
    let mut base = VIEW_START;
    loop {
        let end = base.checked_add(span).filter(|end| *end <= VIEW_END)?;
        let next = (&*core::ptr::addr_of!(OBJECTS)).iter()
            .filter(|object| object.physical.domain == physical.domain)
            .flat_map(|object| object.maps.iter())
            .filter(|mapping| mapping.view.base < end && base < mapping.view.base + mapping.span)
            .map(|mapping| mapping.view.base + mapping.span).max();
        match next { Some(next) => base = next, None => return Some(base) }
    }
}

fn rights(protection: u32) -> Result<u64, u32> {
    match protection & 0xff {
        0x02 => Ok(RO_NX),
        0x04 => Ok(RW_NX),
        0x20 => Ok(2),
        0x40 => Ok(3),
        _ => Err(NOT_SUPPORTED), // No silent read-only substitute for COW/no-access views.
    }
}

pub(crate) unsafe fn map(
    handler: *mut ExecNtHandler, address: u64, physical: runtime::PhysicalSource, requested_size: u64,
) -> Result<(u64, u64), u32> {
    let _durable = crate::allocator::enter_durable();
    let row = object(address, physical)?;
    if !(*row).published || (*row).retiring || (*row).uncertain { return Err(INVALID); }
    let identity = (*row).references.last().copied().ok_or(INVALID)?.identity();
    let sections = table(handler)?;
    let section = (&*sections).section(identity.index()).filter(|_| {
        (&*sections).section_identity(identity.index()) == Some(identity)
    }).ok_or(INVALID)?;
    let size = if requested_size == 0 { section.size } else { requested_size };
    if size == 0 || size > section.size { return Err(0xc000_001f); }
    let rights = rights(section.protection)?;
    let rounded = size.checked_add(0xfff).ok_or(NO_MEMORY)? & !0xfff;
    let span = rounded.checked_add(TABLE_SIZE - 1).ok_or(NO_MEMORY)? & !(TABLE_SIZE - 1);
    let base = choose_base(physical, span).ok_or(NO_MEMORY)?;
    let mut frames = Vec::new();
    frames.try_reserve_exact((rounded / 0x1000) as usize).map_err(|_| NO_MEMORY)?;
    frames.resize((rounded / 0x1000) as usize, Cap::default());
    let mut tables = Vec::new();
    tables.try_reserve_exact((span / TABLE_SIZE) as usize).map_err(|_| NO_MEMORY)?;
    tables.resize((span / TABLE_SIZE) as usize, Cap::default());
    (*row).maps.try_reserve(1).map_err(|_| NO_MEMORY)?;
    // The canonical view fences source frames before any map capability or native effect exists.
    let view = (&mut *sections).map_provider_view(provider_identity(physical)?, identity, base, rounded, 0)
        .ok_or(NO_MEMORY)?;
    (*row).maps.push(Box::new(Mapping {
        view, span, frames, tables, published: false, retiring: false, uncertain: false,
    }));
    let mapping = &mut **(*row).maps.last_mut().unwrap() as *mut Mapping;
    let result = (|| -> Result<(), u32> {
        for index in 0..(*mapping).tables.len() {
            let slot = try_alloc_slot().ok_or(NO_MEMORY)?;
            (&mut (*mapping).tables)[index].slot = slot;
            (*mapping).uncertain = true;
            if untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, slot) != 0 { return Err(FAILED); }
            (&mut (*mapping).tables)[index].created = true;
            (*mapping).uncertain = false;
            (*mapping).uncertain = true;
            if paging_struct_map_r(slot, LBL_X86_PAGE_TABLE_MAP, base + index as u64 * TABLE_SIZE, (*row).vspace.slot) != 0 {
                return Err(FAILED);
            }
            (&mut (*mapping).tables)[index].mapped = true;
            (*mapping).uncertain = false;
        }
        for index in 0..(*mapping).frames.len() {
            // No table, registry, or handler borrow spans routed file I/O/callbacks.
            let frame = crate::service_sec_image::service_generic_section_frame(
                sections, identity.index(), identity, section, index as u64,
                EXECUTIVE_WIN32K_SCRATCH_BASE, false,
            )?;
            if (&*sections).section_identity(identity.index()) != Some(identity)
                || (&*sections).provider_view_for_page(view.owner, base + index as u64 * 0x1000) != Some(view) {
                return Err(INVALID);
            }
            let slot = try_alloc_slot().ok_or(NO_MEMORY)?;
            (&mut (*mapping).frames)[index].slot = slot;
            (*mapping).uncertain = true;
            if copy_cap_into_r(frame, slot) != 0 { return Err(FAILED); }
            (&mut (*mapping).frames)[index].created = true;
            (*mapping).uncertain = false;
            (*mapping).uncertain = true;
            if page_map_r(slot, base + index as u64 * 0x1000, rights, (*row).vspace.slot) != 0 { return Err(FAILED); }
            (&mut (*mapping).frames)[index].mapped = true;
            (*mapping).uncertain = false;
        }
        Ok(())
    })();
    if let Err(status) = result {
        (*mapping).retiring = true;
        if retire_mapping(sections, mapping).is_ok() {
            let index = (*row).maps.iter().position(|candidate| core::ptr::eq(&**candidate, mapping))
                .expect("owned Section map rollback");
            (*row).maps.swap_remove(index);
            if (*row).retiring { let _ = retire_object(row); }
        }
        return Err(status);
    }
    (*mapping).published = true;
    print_str(b"[kernel-section-map] pointer=0x"); print_hex_u64(address);
    print_str(b" native-generation=");
    print_u64((*row).allocation.unwrap().packet_lease().native_identity().allocation_generation);
    print_str(b" view-generation="); print_u64(view.generation);
    print_str(b" base=0x"); print_hex_u64(base);
    print_str(b" bytes="); print_u64(size);
    print_str(b" pages="); print_u64(rounded / 0x1000); print_str(b"\n");
    Ok((base, size))
}

unsafe fn retire_cap(cap: &mut Cap) -> Result<(), u32> {
    if cap.uncertain { return Err(BUSY); }
    if cap.slot == 0 { return Ok(()); }
    if cap.created {
        cap.uncertain = true;
        if cnode_delete_recycle_r(cap.slot) != 0 { return Err(FAILED); }
    } else {
        recycle_deleted_root_slot(cap.slot);
    }
    *cap = Cap::default();
    Ok(())
}

unsafe fn retire_mapping(sections: *mut GenericSectionTable, mapping: *mut Mapping) -> Result<(), u32> {
    if (*mapping).uncertain { return Err(BUSY); }
    for cap in (*mapping).frames.iter_mut().rev() {
        if cap.mapped {
            (*mapping).uncertain = true;
            if page_unmap_r(cap.slot) != 0 { return Err(FAILED); }
            cap.mapped = false;
            (*mapping).uncertain = false;
        }
        (*mapping).uncertain = true;
        retire_cap(cap)?;
        (*mapping).uncertain = false;
    }
    for cap in (*mapping).tables.iter_mut().rev() {
        (*mapping).uncertain = true;
        retire_cap(cap)?;
        (*mapping).uncertain = false;
    }
    if (&mut *sections).unmap_provider_view_exact((*mapping).view) != Some((*mapping).view) {
        return Err(INVALID);
    }
    Ok(())
}

pub(crate) unsafe fn unmap(
    handler: *mut ExecNtHandler, base: u64, physical: runtime::PhysicalSource,
) -> Result<(), u32> {
    let sections = table(handler)?;
    let (row, index) = (&mut *core::ptr::addr_of_mut!(OBJECTS)).iter_mut()
        .filter(|row| row.physical.domain == physical.domain && row.physical.pml4 == physical.pml4)
        .find_map(|row| row.maps.iter().position(|mapping| mapping.view.base == base && mapping.published && !mapping.retiring)
            .map(|index| (&mut **row as *mut Object, index))).ok_or(INVALID)?;
    let mapping = &mut *(&mut (*row).maps)[index] as *mut Mapping;
    (*mapping).retiring = true;
    retire_mapping(sections, mapping)?;
    (*row).maps.swap_remove(index);
    if (*row).retiring { let _ = retire_object(row); }
    Ok(())
}

unsafe fn retire_object(row: *mut Object) -> Result<(), u32> {
    if !(*row).retiring || (*row).uncertain || !(*row).references.is_empty() || !(*row).maps.is_empty() {
        return Err(BUSY);
    }
    (*row).uncertain = true;
    retire_cap(&mut (*row).vspace)?;
    (*row).uncertain = false;
    if let Some(allocation) = (*row).allocation {
        match crate::win32k_subsystem::try_retire_root_provider_pool_allocation(allocation) {
            Ok(()) => {},
            Err(crate::win32k_subsystem::RootPoolError::BusyNoEffect) => return Err(BUSY),
            Err(_) => { (*row).uncertain = true; return Err(FAILED); }
        }
        (*row).allocation = None;
    }
    let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
    let index = rows.iter().position(|candidate| core::ptr::eq(&**candidate, row)).ok_or(INVALID)?;
    rows.swap_remove(index);
    Ok(())
}

pub(crate) unsafe fn blocks_domain_retirement(domain: runtime::PhysicalDomain) -> bool {
    (&*core::ptr::addr_of!(OBJECTS)).iter().any(|row| row.physical.domain == domain)
}

/// Retry known incomplete cleanup only; uncertain effects keep every exact owner quarantined.
pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let Ok(sections) = table(handler) else { return; };
    let mut cursor = 0;
    while cursor < (&*core::ptr::addr_of!(OBJECTS)).len() {
        let row = &mut *(&mut *core::ptr::addr_of_mut!(OBJECTS))[cursor] as *mut Object;
        let mut index = 0;
        while index < (*row).maps.len() {
            let mapping = &mut *(&mut (*row).maps)[index] as *mut Mapping;
            if (*mapping).retiring && !(*mapping).uncertain && retire_mapping(sections, mapping).is_ok() {
                (*row).maps.swap_remove(index);
            } else { index += 1; }
        }
        if retire_object(row).is_err() { cursor += 1; }
    }
}
