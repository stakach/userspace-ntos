//! win32k user-mode memory belongs to the attached client (#406).
//!
//! `EngAllocUserMem` and `GdiPoolAllocateSection` call `ZwAllocateVirtualMemory(NtCurrentProcess())`
//! and `DIB_CreateDIBSection` then secures the bits with `MmSecureVirtualMemory`. The executive
//! answers the secure request from the client's own VADs, so the allocation must be made there.

use nt_address_space::secure_range::{secure_access_for_protection, validate_secure_range};
use nt_address_space::*;

const USER_LIMIT: u64 = 0x0000_07ff_ffff_0000;
const CLIENT: u64 = 8;
/// The address the provider-private arena returned for winlogon's DIB in boot 44038636280.
const ARENA_DIB_BITS: u64 = 0x0000_0100_0c05_0000;

fn client_map() -> VmRegionMap<16> {
    VmRegionMap::new(0x1_0000, USER_LIMIT)
}

fn secure(
    map: &VmRegionMap<16>,
    address: u64,
    size: u64,
    protection: u32,
) -> Result<(), u32> {
    let access = secure_access_for_protection(protection)?;
    validate_secure_range(address, size, access, USER_LIMIT, |va| {
        map.query_basic(va, USER_LIMIT)
    })
}

#[test]
fn memory_outside_the_client_vads_cannot_be_secured() {
    // The arena slot was never a VAD of the client, so the client reports it MEM_FREE and the
    // refusal matches `[win32k-secure-refused] ... status=0xc0000005`.
    let map = client_map();
    assert_eq!(
        map.query_basic(ARENA_DIB_BITS, USER_LIMIT).unwrap().state,
        MEM_FREE
    );
    assert_eq!(
        secure(&map, ARENA_DIB_BITS, 0x80, PAGE_READWRITE),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        secure(&map, ARENA_DIB_BITS, 0x1000, PAGE_READWRITE),
        Err(STATUS_ACCESS_VIOLATION)
    );
}

#[test]
fn eng_alloc_user_mem_in_the_client_can_be_secured_and_is_fenced_until_unsecured() {
    let mut map = client_map();
    let bits = map
        .allocate(None, 0x80, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        .unwrap();
    assert_eq!(bits.size, PAGE_SIZE);
    let information = map.query_basic(bits.base, USER_LIMIT).unwrap();
    assert_eq!(information.state, MEM_COMMIT);
    assert_eq!(information.type_, MEM_PRIVATE);
    assert_eq!(information.allocation_base, bits.base);
    let mut page = bits.base;
    while page < bits.base + bits.size {
        assert!(vm_access_page_plan(page, information, FaultAccess::Write).is_ok());
        page += PAGE_SIZE;
    }

    // DIB_CreateDIBSection secures the whole bitmap read/write.
    assert_eq!(secure(&map, bits.base, 0x80, PAGE_READWRITE), Ok(()));
    assert_eq!(secure(&map, bits.base, 0x1000, PAGE_READWRITE), Ok(()));
    let mut leases = SecuredVirtualMemoryTable::new();
    let handle = leases
        .secure(CLIENT, bits.base, 0x1000, SecuredVirtualMemoryAccess::ReadWrite)
        .unwrap();

    // EngFreeUserMem: MEM_RELEASE with a zero size cannot retire a secured allocation.
    let mut after = map;
    let release = after.free(bits.base, 0, MEM_RELEASE).unwrap();
    assert!(!leases.permits_free(CLIENT, &map, release));
    leases.unsecure(CLIENT, handle).unwrap();
    assert!(leases.permits_free(CLIENT, &map, release));
    assert_eq!(
        after.query_basic(bits.base, USER_LIMIT).unwrap().state,
        MEM_FREE
    );
}

#[test]
fn gdi_pool_section_secures_only_its_committed_pages() {
    let mut map = client_map();
    let section = map
        .allocate(None, 0x1_0000, MEM_RESERVE, PAGE_READWRITE)
        .unwrap();
    assert_eq!(section.size, 0x1_0000);
    let commit = map
        .allocate(Some(section.base), PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE)
        .unwrap();
    assert_eq!(commit.base, section.base);
    assert_eq!(secure(&map, section.base, PAGE_SIZE, PAGE_READWRITE), Ok(()));
    assert_eq!(
        secure(&map, section.base, 2 * PAGE_SIZE, PAGE_READWRITE),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(
        secure(&map, section.base, PAGE_SIZE, PAGE_EXECUTE_READWRITE),
        Err(STATUS_INVALID_PAGE_PROTECTION)
    );
}
