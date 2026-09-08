//! Transition backing remains in PagefileStore until checked physical ownership publication.
use super::*;
use nt_memory_manager::PagefileRetirementIo;

struct Io;
fn checked(label: u64) -> Result<(), u32> {
    if label == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl PagefileRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { page_unmap_r(cap) })
    }
    fn revoke(&mut self, cap: u64) -> Result<(), u32> {
        checked(unsafe { cnode_revoke_r(cap) })
    }
}

pub(super) unsafe fn discard(pi: u64, page: u64) -> Result<(), u32> {
    discard_with_access(pi, page, &retirement_memory_access::Access::Ordinary)
}

pub(super) unsafe fn discard_with_access(
    pi: u64,
    page: u64,
    access: &retirement_memory_access::Access<'_>,
) -> Result<(), u32> {
    access.check(pi, page)?;
    if !(&*core::ptr::addr_of!(PROCESS_PAGEFILE)).contains(pi, page) {
        return Ok(());
    }
    if hosted_thread_retains_page_backing(pi, page)
        || !service_sec_image::section_scratch_is_quiescent()
    {
        return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
    }
    win32k_glue::detach_attached_client_page_with_access(pi, page, access)?;
    let store = &mut *core::ptr::addr_of_mut!(PROCESS_PAGEFILE);
    let Some(mut retained) = store.begin_retirement(pi, page)? else {
        return Ok(());
    };
    frame_recycle::prepare(retained.page().backing)?;
    retained = store.cleanup_retirement_exact(retained, &mut Io)?;
    store.complete_retirement_with(retained, |backing| frame_recycle::publish(backing))
}

pub(super) unsafe fn retire_owner(pi: u64) -> Result<(), u32> {
    while let Some(page) = (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).first_for_owner(pi) {
        discard(pi, page.page)?;
    }
    Ok(())
}

pub(super) unsafe fn retry_pending() {
    if (&*core::ptr::addr_of!(PROCESS_PAGEFILE)).retiring_count() == 0 {
        return;
    }
    let mut index = 0;
    loop {
        let Some(retained) = (&*core::ptr::addr_of!(PROCESS_PAGEFILE))
            .retirements()
            .nth(index)
        else {
            break;
        };
        let page = retained.page();
        if let Err(status) = discard(page.owner, page.page) {
            let count = RETRY_FAILURES
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            if count <= 16 || count.is_power_of_two() {
                print_str(b"[pagefile-retire] retained #");
                print_u64(count);
                print_str(b" pi=");
                print_u64(page.owner);
                print_str(b" page=0x");
                print_hex_u64(page.page);
                print_str(b" backing=0x");
                print_hex_u64(page.backing);
                print_str(b" status=0x");
                print_hex(status);
                print_str(b"\n");
            }
            index += 1;
        }
    }
}
static RETRY_FAILURES: AtomicU64 = AtomicU64::new(0);
