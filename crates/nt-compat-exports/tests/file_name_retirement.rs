//! Executes the native File storage finalizer against two distinct live pool allocations.
//! A driver's mutable FILE_OBJECT field cannot transfer ownership of the constructor name.

use core::ptr::{read_unaligned, read_volatile, write_unaligned, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use std::cell::RefCell;

const FSD_DATA_VADDR: u64 = 0;
const FSD_DATA_FILE_OBJECT_STORE_OFF: u64 = 0;
const FSD_SHARED_VADDR: u64 = 0;
const SH_FILE_RETIREMENTS: u64 = 0;
const FSD_SERVICE_FILE_LABEL: u64 = 0;
const STATUS_INVALID_HANDLE: i32 = -1;
const STATUS_INVALID_PARAMETER: i32 = -2;
const STATUS_UNSUCCESSFUL: i32 = -3;
const STATUS_SUCCESS: i32 = 0;
static FSD_FO_TABLE_EXHAUSTED: AtomicU64 = AtomicU64::new(0);
static FSD_FO_OPENS: AtomicU64 = AtomicU64::new(0);
const FILE_ID: u64 = 41;

mod provider_bugcheck {
    pub unsafe fn report(_code: u32, _parameters: [u64; 4]) -> ! {
        panic!("provider bugcheck")
    }
}

fn yield_now() { std::thread::yield_now(); }

mod allocator {
    pub struct Durable;
    pub fn enter_durable() -> Durable { Durable }
}

thread_local! {
    static LIVE: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static FREED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static ORIGINAL: RefCell<u64> = const { RefCell::new(0) };
    static GENERATIONS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    static REFUSED_FILE: RefCell<u64> = const { RefCell::new(0) };
}

fn component_pool_allocation_capacity(address: u64) -> Option<u64> {
    LIVE.with(|live| live.borrow().contains(&address).then_some(0x100))
}

fn component_pool_allocation_generation(address: u64) -> Option<u64> {
    GENERATIONS.with(|generations| generations.borrow().iter()
        .find(|(candidate, _)| *candidate == address).map(|(_, generation)| *generation))
}

unsafe fn pool_free(address: u64) {
    LIVE.with(|live| {
        let mut live = live.borrow_mut();
        if let Some(index) = live.iter().position(|candidate| *candidate == address) {
            live.swap_remove(index);
        }
    });
    FREED.with(|freed| freed.borrow_mut().push(address));
}

unsafe fn pool_free_exact(address: u64, generation: u64) -> bool {
    if REFUSED_FILE.with(|refused| *refused.borrow() == address) {
        return false;
    }
    if !GENERATIONS.with(|generations| generations.borrow().contains(&(address, generation))) {
        return false;
    }
    unsafe { pool_free(address) };
    true
}

#[test]
fn partial_constructor_release_retains_each_exact_member_for_retry() {
    let mut file = Box::new([0u8; 0x80]);
    let mut constructor_name = Box::new([0u8; 0x20]);
    let file_address = file.as_mut_ptr() as u64;
    let original = constructor_name.as_mut_ptr() as u64;
    LIVE.with(|live| *live.borrow_mut() = vec![file_address, original]);
    FREED.with(|freed| freed.borrow_mut().clear());
    GENERATIONS.with(|generations| *generations.borrow_mut() =
        vec![(original, 31), (file_address, 30)]);
    unsafe {
        write_unaligned((file_address + 0x60) as *mut u64, original);
        let captured = native::capture_created_file_storage(file_address).unwrap();
        let mut retained = vec![captured];
        let mut next = 0;
        REFUSED_FILE.with(|refused| *refused.borrow_mut() = file_address);
        assert_eq!(native::drain_created_file_storage_rows(&mut retained, &mut next), 0);
        assert_eq!(retained.len(), 1);
        assert!(retained[0].name_released);
        assert!(!retained[0].file_released);
        FREED.with(|freed| assert_eq!(&*freed.borrow(), &[original]));
        REFUSED_FILE.with(|refused| *refused.borrow_mut() = 0);
        assert_eq!(native::drain_created_file_storage_rows(&mut retained, &mut next), 1);
        assert!(retained.is_empty());
        FREED.with(|freed| assert_eq!(&*freed.borrow(), &[original, file_address]));
    }
}

unsafe fn call_on4_raw(label: u64, operation: u64, request: u64, file: u64, address: u64)
    -> (u64, u64, u64, u64, u64)
{
    assert_eq!(label, (FSD_SERVICE_FILE_LABEL << 12) | 4);
    assert_eq!((operation, request, file), (9, 0, FILE_ID));
    let original = ORIGINAL.with(|name| *name.borrow());
    assert_ne!(original, 0);
    unsafe {
        pool_free(original);
        pool_free(address);
    }
    (4, 0, 0, 0, 0)
}

#[path = "../../../components/ntos-executive/src/hosted_file_objects.rs"]
mod native;

#[test]
fn file_retirement_releases_constructor_name_not_driver_replacement() {
    let mut file = Box::new([0u8; 0x80]);
    let mut constructor_name = Box::new([0u8; 0x20]);
    let mut replacement_name = Box::new([0u8; 0x20]);
    let file_address = file.as_mut_ptr() as u64;
    let original = constructor_name.as_mut_ptr() as u64;
    let replacement = replacement_name.as_mut_ptr() as u64;
    assert_ne!(original, replacement);
    LIVE.with(|live| *live.borrow_mut() = vec![file_address, original, replacement]);
    FREED.with(|freed| freed.borrow_mut().clear());
    ORIGINAL.with(|name| *name.borrow_mut() = original);
    GENERATIONS.with(|generations| *generations.borrow_mut() = vec![(original, 31), (file_address, 30)]);

    // The constructor installs A. The driver later changes the mutable FileName.Buffer to B.
    unsafe {
        write_unaligned((file_address + 0x60) as *mut u64, original);
        write_unaligned((file_address + 0x60) as *mut u64, replacement);
        assert_eq!(native::retire_file_storage_result(FILE_ID, file_address), Some(Ok(())));
    }

    let freed = FREED.with(|freed| freed.borrow().clone());
    assert_eq!(freed, vec![original, file_address], "retirement must free the original name and File");
    LIVE.with(|live| assert_eq!(&*live.borrow(), &[replacement]));
}

#[test]
fn pre_entry_refusal_frees_only_exact_constructor_allocations() {
    let mut file = Box::new([0u8; 0x80]);
    let mut constructor_name = Box::new([0u8; 0x20]);
    let mut replacement_name = Box::new([0u8; 0x20]);
    let file_address = file.as_mut_ptr() as u64;
    let original = constructor_name.as_mut_ptr() as u64;
    let replacement = replacement_name.as_mut_ptr() as u64;
    LIVE.with(|live| *live.borrow_mut() = vec![file_address, original, replacement]);
    FREED.with(|freed| freed.borrow_mut().clear());
    GENERATIONS.with(|generations| *generations.borrow_mut() = vec![(original, 31), (file_address, 30)]);
    unsafe { write_unaligned((file_address + 0x60) as *mut u64, original) };
    let captured = unsafe { native::capture_created_file_storage(file_address).unwrap() };
    unsafe { write_unaligned((file_address + 0x60) as *mut u64, replacement) };
    assert!(native::pre_entry_no_root_owner(4, 0xc000_009a, 0, 1, 0));
    assert!(!native::pre_entry_no_root_owner(4, 0xc000_009a, 0, 0, 0));
    assert!(!native::pre_entry_no_root_owner(4, 0xc000_009a, 1, 1, 0));
    let mut retained = vec![captured];
    let mut next = 0;
    GENERATIONS.with(|generations| *generations.borrow_mut() =
        vec![(original, 32), (file_address, 30)]);
    unsafe { assert_eq!(native::drain_created_file_storage_rows(&mut retained, &mut next), 0) };
    assert_eq!(retained.len(), 1, "stale Name generation remains owned for reconciliation");
    FREED.with(|freed| assert!(freed.borrow().is_empty()));
    GENERATIONS.with(|generations| *generations.borrow_mut() =
        vec![(original, 31), (file_address, 30)]);
    unsafe { assert_eq!(native::drain_created_file_storage_rows(&mut retained, &mut next), 1) };
    assert!(retained.is_empty());
    let freed = FREED.with(|freed| freed.borrow().clone());
    assert_eq!(freed, vec![original, file_address]);
    LIVE.with(|live| assert_eq!(&*live.borrow(), &[replacement]));
}

#[test]
fn unticketed_file_cleanup_keeps_the_constructor_name_identity() {
    let mut file = Box::new([0u8; 0x80]);
    let mut constructor_name = Box::new([0u8; 0x20]);
    let mut replacement_name = Box::new([0u8; 0x20]);
    let file_address = file.as_mut_ptr() as u64;
    let original = constructor_name.as_mut_ptr() as u64;
    let replacement = replacement_name.as_mut_ptr() as u64;
    LIVE.with(|live| *live.borrow_mut() = vec![file_address, original, replacement]);
    FREED.with(|freed| freed.borrow_mut().clear());
    GENERATIONS.with(|generations| *generations.borrow_mut() =
        vec![(original, 31), (file_address, 30), (replacement, 32)]);
    unsafe {
        write_unaligned((file_address + 0x60) as *mut u64, original);
        let mut captured = native::capture_created_file_storage(file_address).unwrap();
        write_unaligned((file_address + 0x60) as *mut u64, replacement);
        assert!(native::free_file_storage(&mut captured));
    }
    FREED.with(|freed| assert_eq!(&*freed.borrow(), &[original, file_address]));
    LIVE.with(|live| assert_eq!(&*live.borrow(), &[replacement]));
}

#[test]
fn unticketed_file_cleanup_rejects_reused_name_generation() {
    let mut file = Box::new([0u8; 0x80]);
    let mut constructor_name = Box::new([0u8; 0x20]);
    let file_address = file.as_mut_ptr() as u64;
    let original = constructor_name.as_mut_ptr() as u64;
    LIVE.with(|live| *live.borrow_mut() = vec![file_address, original]);
    FREED.with(|freed| freed.borrow_mut().clear());
    GENERATIONS.with(|generations| *generations.borrow_mut() =
        vec![(original, 31), (file_address, 30)]);
    unsafe {
        write_unaligned((file_address + 0x60) as *mut u64, original);
        let mut captured = native::capture_created_file_storage(file_address).unwrap();
        GENERATIONS.with(|generations| *generations.borrow_mut() =
            vec![(original, 32), (file_address, 30)]);
        assert!(!native::free_file_storage(&mut captured));
    }
    FREED.with(|freed| assert!(freed.borrow().is_empty()));
}

#[test]
fn definite_partial_root_file_refusal_remains_retryable() {
    let component = include_str!("../../../components/ntos-executive/src/hosted_file_objects.rs");
    let root = include_str!("../../../components/ntos-executive/src/hosted_device_allocations.rs");
    assert!(component.contains("Some(Err(_)) => {")
        && component.contains("row.storage_retirement_attempted = false;"),
        "a definite partial refusal must permit the exact root receipt to resume");
    assert!(root.contains("if !row.name_freed") && root.contains("if !row.file_freed"),
        "root retry must skip an already acknowledged Name and free only the remaining File");
}

#[test]
fn pre_ticket_constructor_free_refusal_keeps_a_retained_owner() {
    let native = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(!native.contains("let _ = hosted_file_objects::free_file_storage("),
        "pre-ticket error exits must not discard a partial constructor free");
    assert!(native.contains("unsafe fn free_pre_entry_created_file_storage(")
        && native.contains("free_pre_entry_created_file_storage("),
        "each error exit must use the checked constructor release");
    let helper = native.split("unsafe fn free_pre_entry_created_file_storage(")
        .nth(1).unwrap().split("unsafe fn release_pending_irp_graph_component").next().unwrap();
    assert!(helper.contains("retire_created_file_storage(storage)"),
        "pre-ticket cleanup must transfer the owner before attempting either free");
    let store = include_str!("../../../components/ntos-executive/src/hosted_file_objects.rs");
    assert!(store.contains("retired_constructors: Vec<CreatedFileStorage>")
        && store.contains("retained.push(storage);")
        && store.contains("drain_created_file_storage()"),
        "a partial constructor release must retain the exact remaining member for later drain");
}

#[test]
fn constructor_retirement_is_serialized_bounded_and_durable() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_file_objects.rs");
    let retirement = source.split("pub(super) unsafe fn retire_created_file_storage(")
        .nth(1).unwrap().split("pub(super) unsafe fn free_file_storage").next().unwrap();
    assert!(retirement.contains("crate::allocator::enter_durable()")
        && retirement.contains("lock_created_files()"),
        "retained constructor Vec must survive transient scopes and concurrent worker lanes");
    assert!(source.contains("scanned < RETIREMENT_BUDGET")
        && source.contains("next_constructor_retirement"),
        "repeated refused frees must not starve later constructors or monopolize a callback");
}
