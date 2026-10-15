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

thread_local! {
    static LIVE: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static FREED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static ORIGINAL: RefCell<u64> = const { RefCell::new(0) };
    static GENERATIONS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
}

fn component_pool_allocation_capacity(address: u64) -> Option<u64> {
    LIVE.with(|live| live.borrow().contains(&address).then_some(0x100))
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
    if !GENERATIONS.with(|generations| generations.borrow().contains(&(address, generation))) {
        return false;
    }
    unsafe { pool_free(address) };
    true
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
        assert!(native::retire_file_storage(FILE_ID, file_address));
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
    unsafe { write_unaligned((file_address + 0x60) as *mut u64, replacement) };
    assert!(native::pre_entry_no_root_owner(4, 0xc000_009a, 0, 1, 0));
    assert!(!native::pre_entry_no_root_owner(4, 0xc000_009a, 0, 0, 0));
    assert!(!native::pre_entry_no_root_owner(4, 0xc000_009a, 1, 1, 0));
    unsafe {
        assert!(!native::retire_unpublished_file_storage(original, 32, file_address, 30));
        assert!(native::retire_unpublished_file_storage(original, 31, file_address, 30));
    }
    let freed = FREED.with(|freed| freed.borrow().clone());
    assert_eq!(freed, vec![original, file_address]);
    LIVE.with(|live| assert_eq!(&*live.borrow(), &[replacement]));
}
