//! NtAllocateVirtualMemory retains its native prefix rollback until it settles (#288).
//!
//! The outer rollback discarded the unmap and reprotect results with `let _ =` and returned the
//! map status as if the prefix had been reversed. The prefix is now a retained owner whose
//! reversal outcome is authoritative; the behavior is covered in
//! `nt_memory_manager::private_allocation_prefix`.

fn allocation() -> &'static str {
    include_str!("../../../components/ntos-executive/src/exec_handler.rs")
        .split("pub(crate) unsafe fn allocate_private_virtual_memory(")
        .nth(1)
        .expect("one private allocation effect")
        .split("\n    pub(crate) unsafe fn ")
        .next()
        .unwrap()
}

#[test]
fn rollback_results_are_never_discarded() {
    let source = allocation();
    for discarded in ["let _ = vm_unmap_private_page", "let _ = vm_reprotect_private_page"] {
        assert!(!source.contains(discarded), "{discarded} drops a rollback effect");
    }
    assert!(!source.contains("vm_unmap_private_page"), "rollback belongs to the retained owner");
}

#[test]
fn every_page_effect_enters_the_retained_prefix_before_publication() {
    let source = allocation();
    let admit = source.find("hosted_private_allocation_prefix::admit_allocation(self)?").unwrap();
    let begin = source.find("hosted_private_allocation_prefix::begin(").unwrap();
    let apply = source.find("hosted_private_allocation_prefix::apply(").unwrap();
    let fail = source.find("hosted_private_allocation_prefix::fail(self, map_status)").unwrap();
    let commit = source.find("hosted_private_allocation_prefix::commit();").unwrap();
    let publish = source.find("*vm_map = *after;").unwrap();
    assert!(admit < begin && begin < apply && apply < fail && fail < commit && commit < publish);
    assert_eq!(source.matches("vm_map_private_page(").count(), 1);
    assert_eq!(source.matches("vm_reprotect_private_page(").count(), 1);
}

#[test]
fn retained_prefix_fences_vm_changes_and_retirement() {
    let handler = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let free = handler
        .split("pub(crate) unsafe fn free_private_virtual_memory(")
        .nth(1)
        .unwrap();
    assert!(free[..free.find("process_vm_region_map_mut").unwrap()]
        .contains("hosted_private_allocation_prefix::admit_process_change(self, target_pi)?"));
    let protect =
        include_str!("../../../components/ntos-executive/src/exec_virtual_memory_protect.rs");
    assert!(protect.contains("hosted_private_allocation_prefix::admit_process_change(self, target_pi)"));
    let retirement =
        include_str!("../../../components/ntos-executive/src/client_frame_retirement.rs");
    assert!(retirement.contains("hosted_private_allocation_prefix::drain_for_process(handler, process)?"));
    assert!(retirement.contains("!hosted_private_allocation_prefix::process_available(pi)"));
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    assert!(main.contains("&& hosted_private_allocation_prefix::process_available(pi)"));
    let maintenance =
        include_str!("../../../components/ntos-executive/src/executor/maintenance.rs");
    assert!(maintenance.contains("crate::hosted_private_allocation_prefix::retry_pending(&*nt_handler);"));
}
