//! One shared win32k client window with retained per-page mapping transactions.
use super::*;
use nt_memory_manager::alias_transition::AliasTransitionIo;
use nt_memory_manager::retained_alias::AliasRetirementIo;
use nt_user_host::thread_alias_journal::ThreadAliasMapping as Mapping;

pub(crate) static W32_CONNECTED_MASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static W32_ATTACHED_PI: AtomicU64 = AtomicU64::new(u32::MAX as u64);
pub(crate) static W32_CLIENT_PI: AtomicU64 = AtomicU64::new(u64::MAX);

static mut MAPPINGS: Vec<Mapping> = Vec::new();

#[path = "win32k_thread_aliases.rs"]
mod thread_aliases;
pub(crate) use thread_aliases::ThreadAliasCleanup;

pub(crate) unsafe fn attachment_owns_cap(cap: u64) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS)).iter()
        .flat_map(|mapping| mapping.snapshot().capabilities()).any(|owned| owned == cap)
}

fn checked(label: u64) -> Result<(), u32> {
    if label == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

struct Backend {
    page: u64,
    pml4: u64,
    source: u64,
}

impl AliasRetirementIo for Backend {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { page_unmap_r(cap) })
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { cnode_delete_r(cap) })
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.recycle_unretyped_slot(slot)
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

impl AliasTransitionIo for Backend {
    fn copy(&mut self) -> (u64, u32) {
        if self.source == 0 {
            return (0, nt_fs::STATUS_INVALID_HANDLE);
        }
        let Some(cap) = try_alloc_slot() else {
            return (0, nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        };
        let label = unsafe { copy_cap_into_r(self.source, cap) };
        (cap, checked(label).err().unwrap_or(0))
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        if self.pml4 == 0 {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        unsafe {
            if !ensure_w32_client_paging(self.page, self.pml4) {
                return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
            }
            let mut label = page_map_r(cap, self.page, rights, self.pml4);
            if label == SEL4_FAILED_LOOKUP {
                w32_forget_client_paging(self.page);
                if ensure_w32_client_paging(self.page, self.pml4) {
                    // Failed mapping leaves this exact retained cap unmapped. No recopy is needed.
                    label = page_map_r(cap, self.page, rights, self.pml4);
                    if label == 0 {
                        W32_PAGING_REPAIR_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            checked(label)
        }
    }
}

pub(crate) unsafe fn w32_attach_mapped(page: u64) -> bool {
    (&*core::ptr::addr_of!(MAPPINGS))
        .iter()
        .any(|mapping| mapping.page() == page && mapping.live().is_some())
}

unsafe fn admit(pi: u64, page: u64) -> Result<(), u32> {
    if W32_ATTACHED_PI.load(Ordering::Acquire) != pi || page & 0xfff != 0 {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    hosted_thread_memory_access(pi, page, 4096)?;
    if (&*core::ptr::addr_of!(MAPPINGS))
        .iter()
        .any(|mapping| mapping.page() == page && mapping.live().is_none())
    {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    Ok(())
}

unsafe fn replace(pi: u64, page: u64, source: u64, rights: u64, pml4: u64) -> Result<(), u32> {
    admit(pi, page)?;
    if source == 0 || pml4 == 0 {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let mappings = &mut *core::ptr::addr_of_mut!(MAPPINGS);
    let index = match mappings.iter().position(|mapping| mapping.page() == page) {
        Some(index) => index,
        None => {
            mappings
                .try_reserve(1)
                .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
            let index = mappings.len();
            mappings.push(Mapping::new(page).ok_or(nt_fs::STATUS_INVALID_HANDLE)?);
            index
        }
    };
    // Admission and source selection precede this borrow; the backend never reenters the table.
    let result = mappings[index].replace(rights, &mut Backend { page, pml4, source });
    if mappings[index].is_empty() {
        mappings.swap_remove(index);
    }
    result
}

pub(crate) unsafe fn detach_attached_client_page(pi: u64, page: u64) -> Result<(), u32> {
    if W32_ATTACHED_PI.load(Ordering::Acquire) != pi {
        return Ok(());
    }
    hosted_thread_memory_access(pi, page, 4096)?;
    let mappings = &mut *core::ptr::addr_of_mut!(MAPPINGS);
    let Some(index) = mappings.iter().position(|mapping| mapping.page() == page) else {
        return Ok(());
    };
    mappings[index].retire(&mut Backend {
        page,
        pml4: 0,
        source: 0,
    })?;
    mappings.swap_remove(index);
    Ok(())
}

pub(crate) unsafe fn detach_attached_client_process(pi: u64) -> Result<(), u32> {
    if W32_ATTACHED_PI.load(Ordering::Acquire) != pi {
        return Ok(());
    }
    // Preflight the entire attachment before detaching any unrelated page.
    if (&*core::ptr::addr_of!(MAPPINGS)).iter().any(|mapping| {
        mapping.is_claimed() || hosted_thread_memory_access(pi, mapping.page(), 4096).is_err()
    }) {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    loop {
        let page = (&*core::ptr::addr_of!(MAPPINGS))
            .last()
            .map(|mapping| mapping.page());
        let Some(page) = page else {
            break;
        };
        detach_attached_client_page(pi, page)?;
    }
    W32_ATTACHED_PI.store(u32::MAX as u64, Ordering::Release);
    Ok(())
}

pub(crate) unsafe fn w32_client_attach(pi: u64) -> bool {
    let prev = W32_ATTACHED_PI.load(Ordering::Acquire);
    let mappings = &*core::ptr::addr_of!(MAPPINGS);
    if mappings.iter().any(|mapping| {
        mapping.is_claimed() || hosted_thread_memory_access(prev, mapping.page(), 4096).is_err()
    }) {
        return false;
    }
    let detached = mappings.len();
    if prev == pi {
        let mappings = &mut *core::ptr::addr_of_mut!(MAPPINGS);
        let mut index = 0;
        while index < mappings.len() {
            let page = mappings[index].page();
            if mappings[index]
                .recover(&mut Backend {
                    page,
                    pml4: WIN32K_HOST_PML4.load(Ordering::Relaxed),
                    source: 0,
                })
                .is_err()
            {
                return false;
            }
            if mappings[index].is_empty() {
                mappings.swap_remove(index);
            } else {
                index += 1;
            }
        }
        return true;
    }
    if detach_attached_client_process(prev).is_err() {
        return false;
    }
    print_str(b"[w32attach] client ");
    print_u64(prev);
    print_str(b" -> ");
    print_u64(pi);
    print_str(b" (detached ");
    print_u64(detached as u64);
    print_str(b" client pages)\n");
    W32_ATTACHED_PI.store(pi, Ordering::Release);
    true
}

pub(crate) unsafe fn remap_attached_client_frame_in_win32k(
    page: u64,
    pi: u64,
    rights: u64,
) -> bool {
    if admit(pi, page).is_err() {
        return false;
    }
    let pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if pml4 == 0 {
        return false;
    }
    let index = (&*core::ptr::addr_of!(MAPPINGS))
        .iter()
        .position(|mapping| mapping.page() == page);
    let result = if let Some(index) = index {
        (&mut *core::ptr::addr_of_mut!(MAPPINGS))[index].remap(
            rights,
            &mut Backend {
                page,
                pml4,
                source: 0,
            },
        )
    } else {
        let Some(source) =
            csrss_frame_get_exact_record(pi, page).and_then(|record| record.clone_source_cap())
        else {
            return false;
        };
        replace(pi, page, source, rights, pml4)
    };
    if result.is_err() {
        return false;
    }
    if W32_CLIENT_TEB_TAIL_PROTECTED && rights == RO_NX && is_teb_tail_page(page) {
        W32_TEB_TAIL_RO_MAPS.fetch_add(1, Ordering::Relaxed);
    }
    true
}

pub(crate) unsafe fn w32_teb_tail_cow(page: u64, pi: u64, pml4: u64, ip: u64) -> bool {
    if admit(pi, page).is_err() {
        return false;
    }
    let seen = W32_TEB_TAIL_WRITE_FAULTS.fetch_add(1, Ordering::Relaxed);
    let rva = ip.wrapping_sub(win32k_subsystem::WIN32K_CODE_VA);
    let _ = W32_TEB_TAIL_FIRST_WRITER_RVA.compare_exchange(
        0,
        rva,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    let source = teb_tail_shadow(pi, page);
    if source == 0 || replace(pi, page, source, RW_NX, pml4).is_err() {
        return false;
    }
    if seen < 6 {
        print_str(b"[teb-tail] private shadow attached pi=");
        print_u64(pi);
        print_str(b" page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" writer-rva=0x");
        print_hex(rva as u32);
        print_str(b"\n");
        win32k_dispatch_backtrace();
    }
    true
}

pub(crate) unsafe fn map_csrss_page_into_win32k(
    page: u64,
    pi: u64,
    generation: u64,
    pml4: u64,
    write: bool,
) -> Result<bool, u32> {
    admit(pi, page)?;
    if process_committed_mapping_basic_information(pi, page)
        .is_some_and(|info| info.type_ == nt_address_space::MEM_MAPPED)
    {
        // Section admission can change canonical backing; revoke the old alias first.
        detach_attached_client_page(pi, page)?;
        let rights =
            service_sec_image::service_admit_section_alias(pi, page, write, Some(generation))?
                .ok_or(nt_memory_manager::STATUS_NOT_MAPPED_VIEW)?;
        let source = csrss_frame_get_exact_record(pi, page)
            .and_then(|record| record.clone_source_cap())
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
        replace(pi, page, source, rights, pml4)?;
        return Ok(true);
    }
    if w32_attach_mapped(page) {
        return Ok(true);
    }
    let source = if let Some(record) = csrss_frame_get_exact_record(pi, page) {
        record
            .clone_source_cap()
            .ok_or(nt_fs::STATUS_INVALID_HANDLE)?
    } else {
        csrss_frame_get(pi, page)
    };
    if source == 0 {
        return Ok(false);
    }
    let protect_tail = W32_CLIENT_TEB_TAIL_PROTECTED && is_teb_tail_page(page);
    let rights = if protect_tail { RO_NX } else { RW_NX };
    replace(pi, page, source, rights, pml4)?;
    if protect_tail {
        W32_TEB_TAIL_RO_MAPS.fetch_add(1, Ordering::Relaxed);
    }
    Ok(true)
}
