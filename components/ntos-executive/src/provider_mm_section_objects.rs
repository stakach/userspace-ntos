//! Exact kernel Section pointers and physical provider-VSpace views of canonical backing.

use crate::*;
use alloc::{boxed::Box, vec::Vec};
use crate::exec_handler::section_create::ReservedGenericDataSection;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use crate::win32k_subsystem::RootProviderPoolAllocation;
use nt_memory_manager::{ProviderClientSectionAlias, ProviderSectionView, ProviderVspaceIdentity,
    SectionReference};
use nt_user_host::provider_alias_bank::{ProviderAliasHandle, ProviderAliasRequest};

const INVALID: u32 = nt_process::STATUS_INVALID_HANDLE;
const NO_MEMORY: u32 = nt_process::STATUS_INSUFFICIENT_RESOURCES;
const FAILED: u32 = 0xc000_0001;
const NOT_SUPPORTED: u32 = 0xc000_00bb;
const BUSY: u32 = 0x8000_0011;
const VIEW_START: u64 = crate::allocator::HEAP_BASE as u64
    + crate::allocator::HEAP_FRAMES * 0x1000;
const VIEW_END: u64 = 0x0000_0100_3000_0000;
const TABLE_SIZE: u64 = 0x20_0000;
const DESCRIPTOR_SIZE: u64 = 8;
const _: () = assert!(VIEW_START & (TABLE_SIZE - 1) == 0);
const _: () = assert!(VIEW_START < VIEW_END);

#[derive(Clone, Copy, Default)]
struct Cap {
    slot: u64,
    created: bool,
    mapped: bool,
    uncertain: bool,
}

struct Mapping {
    view: ProviderSectionView,
    provenance: crate::provider_section_receipts::MappingProvenance,
    span: u64,
    frames: Vec<Cap>,
    tables: Vec<Cap>,
    published: bool,
    retiring: bool,
    uncertain: bool,
}

struct ClientPage {
    request: ProviderAliasRequest,
    handle: Option<ProviderAliasHandle>,
}

struct ClientMapping {
    eprocess: u64,
    pi: usize,
    process: nt_types::ProcessIdentity,
    pml4: u64,
    base: u64,
    size: u64,
    alias: Option<ProviderClientSectionAlias>,
    pages: Vec<ClientPage>,
    references: u64,
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
    clients: Vec<Box<ClientMapping>>,
    published: bool,
    retiring: bool,
    uncertain: bool,
}

static mut OBJECTS: Vec<Box<Object>> = Vec::new();

fn map_failure(stage: &[u8], address: u64, status: u32) -> u32 {
    print_str(b"[kernel-section-map-failed] stage="); print_str(stage);
    print_str(b" pointer=0x"); print_hex_u64(address);
    print_str(b" status=0x"); print_hex(status); print_str(b"\n");
    status
}

unsafe fn table(handler: *mut ExecNtHandler) -> Result<*mut GenericSectionTable, u32> {
    if handler.is_null() {
        crate::service_sec_image::bootstrap_section_table()
    } else {
        crate::service_sec_image::registered_section_table_for_handler(handler)
    }
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
    if (&mut *core::ptr::addr_of_mut!(OBJECTS)).try_reserve(1).is_err() {
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
    let row = {
        let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
        rows.push(Box::new(Object {
            allocation: Some(allocation), address, physical, vspace: Cap::default(), references,
            maps: Vec::new(), clients: Vec::new(), published: false, retiring: false, uncertain: false,
        }));
        &mut **rows.last_mut().unwrap() as *mut Object
    };
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

/// DriverEntry owns no ExecNtHandler or native process handle. Its authenticated physical
/// provider creates the same canonical Section object and exact table reference that the live
/// service will later adopt in place. Failure after a native effect keeps this object pinned.
pub(crate) unsafe fn prepare_bootstrap(
    identity: nt_memory_manager::SectionIdentity,
    physical: runtime::PhysicalSource,
) -> Result<u64, u32> {
    let _durable = crate::allocator::enter_durable();
    let sections = table(core::ptr::null_mut())?;
    if provider_identity(physical).is_err() || physical.pml4 == 0 {
        (&mut *sections).clear_section(identity.index());
        return Err(NOT_SUPPORTED);
    }
    let Some(reference) = (&mut *sections).retain_section(identity) else {
        (&mut *sections).clear_section(identity.index());
        return Err(NO_MEMORY);
    };
    if (&mut *core::ptr::addr_of_mut!(OBJECTS)).try_reserve(1).is_err() {
        assert!((&mut *sections).release_section_reference(reference));
        return Err(NO_MEMORY);
    }
    let mut references = Vec::new();
    if references.try_reserve(1).is_err() {
        assert!((&mut *sections).release_section_reference(reference));
        return Err(NO_MEMORY);
    }
    let allocation = match crate::win32k_subsystem::try_allocate_root_provider_pool_allocation(DESCRIPTOR_SIZE) {
        Ok(allocation) => allocation,
        Err(error) => {
            assert!((&mut *sections).release_section_reference(reference));
            return Err(match error {
                crate::win32k_subsystem::RootPoolError::BusyNoEffect => BUSY,
                crate::win32k_subsystem::RootPoolError::InvalidIdentity => INVALID,
                crate::win32k_subsystem::RootPoolError::InsufficientResources => NO_MEMORY,
                crate::win32k_subsystem::RootPoolError::Indeterminate => FAILED,
            });
        }
    };
    let address = allocation.address();
    references.push(reference);
    let row = {
        let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
        rows.push(Box::new(Object {
            allocation: Some(allocation), address, physical, vspace: Cap::default(), references,
            maps: Vec::new(), clients: Vec::new(), published: false, retiring: false, uncertain: false,
        }));
        &mut **rows.last_mut().unwrap() as *mut Object
    };
    let Some(slot) = try_alloc_slot() else {
        let _ = abort(core::ptr::null_mut(), address, physical);
        return Err(NO_MEMORY);
    };
    (*row).vspace.slot = slot;
    (*row).uncertain = true;
    if copy_cap_into_r(physical.pml4, slot) != 0 { return Err(FAILED); }
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
    let _durable = crate::allocator::enter_durable();
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
    if (*row).published || (*row).uncertain || !(*row).maps.is_empty()
        || !(*row).clients.is_empty() { return Err(BUSY); }
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
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Result<(u64, u64), u32> {
    let _durable = crate::allocator::enter_durable();
    let row = object(address, physical).map_err(|status| map_failure(b"object-owner", address, status))?;
    if !(*row).published || (*row).retiring || (*row).uncertain {
        return Err(map_failure(b"publication-state", address, INVALID));
    }
    let identity = (*row).references.last().copied()
        .ok_or_else(|| map_failure(b"object-reference", address, INVALID))?.identity();
    let sections = table(handler).map_err(|status| map_failure(b"section-table", address, status))?;
    let section = (&*sections).section(identity.index()).filter(|_| {
        (&*sections).section_identity(identity.index()) == Some(identity)
    }).ok_or_else(|| map_failure(b"section-identity", address, INVALID))?;
    let provenance = if handler.is_null() {
        crate::provider_section_receipts::capture_bootstrap_mapping_provenance(identity, section)
    } else {
        crate::provider_section_receipts::capture_mapping_provenance(
            &*handler, caller, identity, section,
        )
    };
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
        view, provenance, span, frames, tables, published: false, retiring: false, uncertain: false,
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
            ).map_err(|status| map_failure(b"frame-fill", address, status))?;
            if (&*sections).section_identity(identity.index()) != Some(identity)
                || (&*sections).provider_view_for_page(view.owner, base + index as u64 * 0x1000) != Some(view) {
                return Err(map_failure(b"frame-view-identity", address, INVALID));
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
    crate::provider_section_receipts::map_published(capture_retirement(row, mapping), size, rounded / 0x1000);
    Ok((base, size))
}

/// Map the exact canonical provider Section pages into a live GUI process. This is a separate
/// client alias from the provider's kernel VA; its VAD, copied leaf caps, and Section lease remain
/// owned together until an exact unmap or process-generation retirement.
pub(crate) unsafe fn map_client(
    handler: *mut ExecNtHandler,
    address: u64,
    physical: runtime::PhysicalSource,
    eprocess: u64,
    requested_size: u64,
    protection: u32,
) -> Result<(u64, u64), u32> {
    let _durable = crate::allocator::enter_durable();
    let row = object(address, physical)?;
    if !(*row).published || (*row).retiring || (*row).uncertain || eprocess == 0 {
        return Err(INVALID);
    }
    let pid = (*handler).pm.pid_for_kernel_process_object(eprocess).ok_or(INVALID)?;
    let pi = (*handler).pi_for_pid(pid).ok_or(INVALID)?;
    let process = (*handler).capture_process_identity(pi).ok_or(INVALID)?;
    let source = (*row).maps.iter().find(|mapping| mapping.published && !mapping.retiring
        && !mapping.uncertain).ok_or(INVALID)?;
    let source = &**source as *const Mapping;
    let sections = table(handler)?;
    let identity = (*source).view.section;
    let section = (&*sections).section(identity.index()).filter(|_| {
        (&*sections).section_identity(identity.index()) == Some(identity)
    }).ok_or(INVALID)?;
    if requested_size != 0 && requested_size != section.size {
        return Err(0xc000_001f); // Partial views need their own offset/extent ledger.
    }
    if protection != 0x02 && protection != 0x04 {
        return Err(NOT_SUPPORTED);
    }
    if protection == 0x04 && section.protection != 0x04 {
        return Err(NOT_SUPPORTED);
    }
    let client_rights = rights(protection)?;
    if let Some(existing) = (*row).clients.iter_mut().find(|client| client.pi == pi
        && client.process == process && client.eprocess == eprocess) {
        if !existing.retiring && !existing.uncertain && existing.alias.is_some()
            && existing.pages.first().is_some_and(|page| page.request.rights == client_rights)
            && existing.references != u64::MAX {
            existing.references += 1;
            return Ok((existing.base, existing.size));
        }
        return Err(BUSY);
    }
    let rounded = section.size.checked_add(0xfff).ok_or(NO_MEMORY)? & !0xfff;
    if rounded == 0 || rounded > (*source).view.size
        || (*source).frames.len() < (rounded / 0x1000) as usize
    { return Err(0xc000_001f); }
    let clients = &mut (*row).clients;
    clients.try_reserve(1).map_err(|_| NO_MEMORY)?;
    let mut pages = Vec::new();
    pages.try_reserve_exact((rounded / 0x1000) as usize).map_err(|_| NO_MEMORY)?;
    clients.push(Box::new(ClientMapping {
        eprocess, pi, process, pml4: 0, base: 0, size: 0, alias: None,
        pages, references: 0, retiring: false, uncertain: false,
    }));
    let client = &mut **clients.last_mut().unwrap() as *mut ClientMapping;
    let (target_pi, target_process, pml4, base, span) =
        match (*handler).reserve_provider_section_client_view(eprocess, rounded, protection) {
            Ok(value) => value,
            Err(status) => {
                clients.pop();
                return Err(status);
            }
        };
    (*client).pml4 = pml4;
    (*client).base = base;
    (*client).size = span;
    if target_pi != pi || target_process != process || span != rounded {
        // The VAD belongs to the identity returned by the reservation authority, even if
        // process lookup changed between the two reads. Retire that exact owner now or leave
        // it for its generation's process cleanup.
        (*client).pi = target_pi;
        (*client).process = target_process;
        (*client).retiring = true;
        if retire_client(handler, sections, client, false).is_ok() { clients.pop(); }
        return Err(INVALID);
    }
    let Some(alias) = (&mut *sections).map_client_alias_of_provider_view(
        (*source).view, pi, process, base, span,
    ) else {
        (*client).retiring = true;
        if retire_client(handler, sections, client, false).is_ok() {
            clients.pop();
        }
        return Err(NO_MEMORY);
    };
    (*client).alias = Some(alias);
    for index in 0..(rounded / 0x1000) as usize {
        let frame = (&(*source).frames)[index].slot;
        if frame == 0 || !(&(*source).frames)[index].mapped {
            (*client).retiring = true;
            if retire_client(handler, sections, client, false).is_ok() { clients.pop(); }
            return Err(INVALID);
        }
        let page = base + index as u64 * 0x1000;
        let request = ProviderAliasRequest {
            pi, process, page, pml4, source_frame: frame, rights: client_rights,
        };
        (*client).pages.push(ClientPage { request, handle: None });
        // Page tables cover aligned 2 MiB ranges; the VAD base need not be 2 MiB aligned.
        if index == 0 || (page & !0x1f_ffff) != ((page - 0x1000) & !0x1f_ffff) {
            if crate::ensure_process_user_page_table(&mut *handler, pi, page, pml4).is_err() {
                (*client).retiring = true;
                if retire_client(handler, sections, client, false).is_ok() { clients.pop(); }
                return Err(NO_MEMORY);
            }
        }
        match crate::win32k_glue::map_provider_section_client_page(request) {
            Ok(handle) => (&mut (*client).pages)[index].handle = Some(handle),
            Err(_) => {
                (&mut (*client).pages)[index].handle =
                    crate::win32k_glue::provider_section_client_page_handle(request);
                (*client).retiring = true;
                (*client).uncertain = (&(*client).pages)[index].handle.is_none();
                if !(*client).uncertain && retire_client(handler, sections, client, false).is_ok() {
                    clients.pop();
                }
                return Err(NO_MEMORY);
            }
        }
    }
    (*client).references = 1;
    Ok((base, section.size))
}

unsafe fn retire_client(
    handler: *mut ExecNtHandler,
    sections: *mut GenericSectionTable,
    client: *mut ClientMapping,
    caps_released_with_process: bool,
) -> Result<(), u32> {
    // A page-map failure without a recoverable exact handle may have taken effect.
    // Only whole-process cap-bank retirement can prove its leaves have gone away.
    if (*client).uncertain && !caps_released_with_process { return Err(BUSY); }
    (*client).retiring = true;
    for page in (*client).pages.iter_mut().rev() {
        if !caps_released_with_process {
            let handle = page.handle.or_else(|| {
                crate::win32k_glue::provider_section_client_page_handle(page.request)
            });
            if let Some(handle) = handle {
                crate::win32k_glue::unmap_provider_section_client_page(page.request, handle)
                    .map_err(|_| BUSY)?;
            }
        }
        page.handle = None;
    }
    if (*client).base != 0 {
        (*handler).retire_provider_section_client_view(
            (*client).pi, (*client).process, (*client).base, (*client).size,
        )?;
        (*client).base = 0;
    }
    // The Section lease outlives the client VAD even when VAD retirement fails. Once the
    // VAD is gone, the retained alias can be retired without leaving a live mapping unleased.
    if let Some(alias) = (*client).alias {
        if (&mut *sections).unmap_provider_client_alias_exact(alias) != Some(alias) {
            return Err(INVALID);
        }
        (*client).alias = None;
    }
    Ok(())
}

pub(crate) unsafe fn unmap_client(
    handler: *mut ExecNtHandler,
    physical: runtime::PhysicalSource,
    eprocess: u64,
    base: u64,
) -> Result<(), u32> {
    let sections = table(handler)?;
    let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
    let (row, index) = rows.iter_mut().filter(|row| row.physical.domain == physical.domain
        && row.physical.pml4 == physical.pml4)
        .find_map(|row| row.clients.iter().position(|client| client.eprocess == eprocess
            && client.base == base && client.base != 0)
            .map(|index| (&mut **row as *mut Object, index))).ok_or(INVALID)?;
    let client = &mut *(&mut (*row).clients)[index] as *mut ClientMapping;
    let pid = (*handler).pm.pid_for_kernel_process_object(eprocess).ok_or(INVALID)?;
    if (*handler).pm_pid_for_pi((*client).pi) != Some(pid)
        || (*handler).capture_process_identity((*client).pi) != Some((*client).process)
    { return Err(INVALID); }
    if (*client).references > 1 && !(*client).retiring {
        (*client).references -= 1;
        return Ok(());
    }
    retire_client(handler, sections, client, false)?;
    (*row).clients.swap_remove(index);
    if (*row).retiring { let _ = retire_object(row); }
    Ok(())
}

/// Resolve a pointer read from the real client's PEB to its exact mapped Section. The return
/// value is the coherent provider server view, never inferred from the client's VA or byte size.
pub(crate) unsafe fn server_view_for_client_alias(
    handler: *const ExecNtHandler,
    pi: usize,
    client_base: u64,
) -> Option<(u64, u64)> {
    let process = (*handler).capture_process_identity(pi)?;
    let sections = table(handler as *mut ExecNtHandler).ok()?;
    (&*core::ptr::addr_of!(OBJECTS)).iter().find_map(|row| {
        row.clients.iter().find_map(|client| {
            let alias = client.alias?;
            if client.pi != pi || client.process != process || client.base != client_base
                || client.retiring || client.uncertain
                || (&*sections).provider_client_alias_at(pi, process, client_base) != Some(alias)
            { return None; }
            row.maps.iter().find(|mapping| mapping.view == alias.source
                && mapping.published && !mapping.retiring && !mapping.uncertain)
                .and_then(|mapping| (&*sections).section(alias.source.section.index())
                    .map(|section| (mapping.view.base, section.size)))
        })
    })
}

/// Called after the process-generation cap bank proves every copied alias leaf retired.
/// The Section and VAD ledgers can then release their matching exact client lease.
pub(crate) unsafe fn retire_client_aliases_for_process(
    handler: *mut ExecNtHandler,
    pi: usize,
    process: nt_types::ProcessIdentity,
) -> Result<(), u32> {
    if !crate::win32k_glue::win32k_client_cap_bank_is_empty(pi)
        || (*handler).capture_process_identity(pi) != Some(process)
    { return Err(INVALID); }
    let sections = table(handler)?;
    loop {
        let rows = &mut *core::ptr::addr_of_mut!(OBJECTS);
        let Some((row, index)) = rows.iter_mut().find_map(|row| {
            row.clients.iter().position(|client| client.pi == pi && client.process == process)
                .map(|index| (&mut **row as *mut Object, index))
        }) else { return Ok(()); };
        let client = &mut *(&mut (*row).clients)[index] as *mut ClientMapping;
        retire_client(handler, sections, client, true)?;
        (*row).clients.swap_remove(index);
        if (*row).retiring { let _ = retire_object(row); }
    }
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

unsafe fn capture_retirement(
    row: *const Object,
    mapping: *const Mapping,
) -> Option<crate::provider_section_receipts::RetirementReceipt> {
    if !(*mapping).published { return None; }
    let native = (*row).allocation?.packet_lease().native_identity();
    let provider = provider_identity((*row).physical).ok()?;
    Some(crate::provider_section_receipts::RetirementReceipt {
        pointer: (*row).address,
        native_generation: native.allocation_generation,
        view_generation: (*mapping).view.generation,
        provider_domain: provider.domain,
        provider_generation: provider.generation,
        base: (*mapping).view.base,
        remaining_references: (*row).references.len() as u64,
        provenance: (*mapping).provenance,
    })
}

pub(crate) unsafe fn unmap(
    handler: *mut ExecNtHandler, base: u64, physical: runtime::PhysicalSource,
) -> Result<Option<crate::provider_section_receipts::RetirementReceipt>, u32> {
    let sections = table(handler)?;
    let (row, index) = (&mut *core::ptr::addr_of_mut!(OBJECTS)).iter_mut()
        .filter(|row| row.physical.domain == physical.domain && row.physical.pml4 == physical.pml4)
        .find_map(|row| row.maps.iter().position(|mapping| mapping.view.base == base && mapping.published && !mapping.retiring)
            .map(|index| (&mut **row as *mut Object, index))).ok_or(INVALID)?;
    let mapping = &mut *(&mut (*row).maps)[index] as *mut Mapping;
    if (*row).clients.iter().any(|client| client.alias.is_some_and(|alias| {
        alias.source == (*mapping).view
    })) { return Err(BUSY); }
    (*mapping).retiring = true;
    let receipt = capture_retirement(row, mapping);
    retire_mapping(sections, mapping)?;
    crate::provider_section_receipts::unmap_retired(receipt);
    (*row).maps.swap_remove(index);
    if (*row).retiring { let _ = retire_object(row); }
    Ok(receipt)
}

unsafe fn retire_object(row: *mut Object) -> Result<(), u32> {
    if !(*row).retiring || (*row).uncertain || !(*row).references.is_empty()
        || !(*row).maps.is_empty() || !(*row).clients.is_empty() {
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

/// Retry known incomplete cleanup only; uncertain effects keep every exact owner quarantined.
pub(crate) unsafe fn redrive(handler: *mut ExecNtHandler) {
    let Ok(sections) = table(handler) else { return; };
    let mut cursor = 0;
    while cursor < (&*core::ptr::addr_of!(OBJECTS)).len() {
        let row = &mut *(&mut *core::ptr::addr_of_mut!(OBJECTS))[cursor] as *mut Object;
        let mut index = 0;
        while index < (*row).maps.len() {
            let mapping = &mut *(&mut (*row).maps)[index] as *mut Mapping;
            let receipt = capture_retirement(row, mapping);
            if (*mapping).retiring && !(*mapping).uncertain && retire_mapping(sections, mapping).is_ok() {
                crate::provider_section_receipts::unmap_retired(receipt);
                (*row).maps.swap_remove(index);
            } else { index += 1; }
        }
        if retire_object(row).is_err() { cursor += 1; }
    }
}
