//! Retained canonical Ps pool-page aliases for exact hosted provider lifetimes.

use super::*;
use nt_memory_manager::alias_transition::{AliasTransition, AliasTransitionIo};
use nt_memory_manager::retained_alias::AliasRetirementIo;

struct Row {
    domain: HostedDomainIdentity,
    pml4: u64,
    page: u64,
    source: u64,
    alias: AliasTransition,
    retiring: bool,
}
static mut ROWS: Vec<Row> = Vec::new();

pub(super) fn contains(body: u64, bytes: usize) -> bool {
    let base = crate::win32k_subsystem::WIN32K_POOL_VADDR;
    let limit = base + crate::win32k_subsystem::WIN32K_POOL_FRAMES * 0x1000;
    body >= base && body.checked_add(bytes as u64).is_some_and(|end| end <= limit)
}

/// The caller has validated these exact body addresses against a retained canonical PM actor.
pub(super) unsafe fn grant(inst: DriverInstance, body: u64, bytes: usize) -> Result<(), u32> {
    let invalid = nt_process::STATUS_INVALID_HANDLE;
    if !contains(body, bytes) { return Err(invalid); }
    let domain = instance_domain_identity(inst).ok_or(invalid)?;
    if !matches_ps_provider_root(domain, inst.pml4) { return Err(invalid); }
    let base = crate::WIN32K_POOL_FRAME_BASE.load(Ordering::Acquire);
    if base == 0 { return Err(invalid); }
    let mut page = body & !0xfff;
    while page < body + bytes as u64 {
        let source = base + (page - crate::win32k_subsystem::WIN32K_POOL_VADDR) / 0x1000;
        let rows = &mut *core::ptr::addr_of_mut!(ROWS);
        let index = match rows.iter().position(|row| row.domain == domain && row.pml4 == inst.pml4 && row.page == page) {
            Some(index) => index,
            None => {
                rows.try_reserve(1).map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
                rows.push(Row { domain, pml4: inst.pml4, page, source, alias: AliasTransition::empty(), retiring: false });
                rows.len() - 1
            }
        };
        let row = &mut rows[index];
        if row.retiring || row.source != source { return Err(invalid); }
        if row.alias.live().is_none() {
            let mut io = Io { domain, pml4: inst.pml4, page, source };
            if !row.alias.is_empty() { row.alias.recover(&mut io)?; }
            row.alias.replace(RW_NX, &mut io)?;
        }
        page += 0x1000;
    }
    Ok(())
}

pub(super) unsafe fn retire(inst: DriverInstance) -> Result<(), u32> {
    let domain = instance_domain_identity(inst).ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    for row in &mut *core::ptr::addr_of_mut!(ROWS) {
        if row.domain != domain || row.pml4 != inst.pml4 { continue; }
        row.retiring = true;
        row.alias.retire(&mut Io { domain, pml4: row.pml4, page: row.page, source: row.source })?;
    }
    Ok(())
}

pub(super) fn owns_cap(cap: u64) -> bool {
    unsafe { (&*core::ptr::addr_of!(ROWS)).iter().any(|row| row.alias.snapshot().capabilities().any(|owned| owned == cap)) }
}

struct Io { domain: HostedDomainIdentity, pml4: u64, page: u64, source: u64 }
fn status(value: u64) -> Result<(), u32> {
    if value == 0 { Ok(()) } else { Err(value as u32) }
}
impl AliasTransitionIo for Io {
    fn copy(&mut self) -> (u64, u32) {
        let Some(slot) = (unsafe { crate::try_alloc_slot() }) else {
            return (0, nt_process::STATUS_INSUFFICIENT_RESOURCES);
        };
        (slot, unsafe { copy_cap_into_r(self.source, slot) } as u32)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        if !matches_ps_provider_root(self.domain, self.pml4)
            || !unsafe { ensure_paging(self.page, self.pml4, self.domain) }
        { return Err(nt_process::STATUS_INVALID_HANDLE); }
        status(unsafe { page_map_r(cap, self.page, rights, self.pml4) })
    }
}
impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> { status(unsafe { page_unmap_r(cap) }) }
    fn delete(&mut self, cap: u64) -> Result<(), u32> { status(unsafe { cnode_delete_r(cap) }) }
    fn recycle_slot(&mut self, cap: u64) -> Result<(), u32> { self.recycle_unretyped_slot(cap) }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        unsafe { crate::root_slot_recycle::publish_unretyped(cap) }.map_err(|_| nt_process::STATUS_INVALID_HANDLE)
    }
}
