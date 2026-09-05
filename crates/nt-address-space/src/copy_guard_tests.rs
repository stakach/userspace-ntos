use super::*;
use crate::*;
use alloc::{collections::BTreeMap, vec::Vec};

struct Page {
    info: VmBasicInformation,
    bytes: [u8; PAGE_SIZE as usize],
    attached: bool,
    resident: bool,
}

#[derive(Default)]
struct Memory {
    pages: BTreeMap<u64, Page>,
    accesses: Vec<(FaultAccess, u64)>,
}

impl Memory {
    fn add(&mut self, address: u64, protect: u32, attached: bool, value: u8) {
        self.pages.insert(
            address,
            Page {
                info: VmBasicInformation {
                    base_address: address,
                    allocation_base: address,
                    region_size: PAGE_SIZE,
                    allocation_protect: protect,
                    state: MEM_COMMIT,
                    protect,
                    type_: MEM_PRIVATE,
                },
                bytes: [value; PAGE_SIZE as usize],
                attached,
                resident: false,
            },
        );
    }

    fn access(&mut self, address: u64, access: FaultAccess) -> Result<&mut Page, u32> {
        self.accesses.push((access, address));
        let base = address & !(PAGE_SIZE - 1);
        let page = self.pages.get_mut(&base).ok_or(STATUS_ACCESS_VIOLATION)?;
        match copy_page_plan(base, page.info, access, page.attached)? {
            CopyPagePlan::Resident(_) => {
                page.resident = true;
                Ok(page)
            }
            CopyPagePlan::ConsumeGuard(plan) => {
                page.info.protect = plan.protection;
                Err(STATUS_GUARD_PAGE_VIOLATION)
            }
        }
    }
}

impl WriteProbeMemory for Memory {
    fn read_byte(&mut self, address: u64) -> Result<u8, u32> {
        Ok(self.access(address, FaultAccess::Read)?.bytes[(address % PAGE_SIZE) as usize])
    }
    fn write_byte(&mut self, address: u64, value: u8) -> Result<(), u32> {
        self.access(address, FaultAccess::Write)?.bytes[(address % PAGE_SIZE) as usize] = value;
        Ok(())
    }
}

impl VirtualMemoryCopy for Memory {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), u32> {
        let page = self.access(address, FaultAccess::Read)?;
        let offset = (address % PAGE_SIZE) as usize;
        output.copy_from_slice(&page.bytes[offset..offset + output.len()]);
        Ok(())
    }
    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), u32> {
        let page = self.access(address, FaultAccess::Write)?;
        let offset = (address % PAGE_SIZE) as usize;
        page.bytes[offset..offset + input.len()].copy_from_slice(input);
        Ok(())
    }
    fn probe_write(&mut self, address: u64, length: u64) -> Result<(), u32> {
        probe_write_range(self, address, length)
    }
}

#[test]
fn guarded_source_is_partial_copy_and_only_local_guard_is_consumed() {
    for attached in [false, true] {
        let mut memory = Memory::default();
        memory.add(0x1000, PAGE_READWRITE | PAGE_GUARD, attached, 0x11);
        memory.add(0x3000, PAGE_READWRITE, false, 0x22);
        assert_eq!(
            copy_virtual_memory(&mut memory, 0x1000, 0x3000, 32),
            CopyResult {
                status: STATUS_PARTIAL_COPY,
                transferred: 0
            }
        );
        assert_eq!(
            memory.pages[&0x1000].info.protect & PAGE_GUARD != 0,
            attached
        );
        assert!(!memory.pages[&0x1000].resident);
        assert!(!memory.pages[&0x3000].resident);
        assert_eq!(memory.pages[&0x3000].bytes, [0x22; PAGE_SIZE as usize]);
    }
}

#[test]
fn destination_guard_probe_preserves_status_and_never_copies_source_bytes() {
    for attached in [false, true] {
        let mut memory = Memory::default();
        memory.add(0x1000, PAGE_READONLY, false, 0x11);
        memory.add(0x3000, PAGE_READWRITE | PAGE_GUARD, attached, 0x22);
        assert_eq!(
            copy_virtual_memory(&mut memory, 0x1000, 0x3000, 32),
            CopyResult {
                status: if attached {
                    STATUS_ACCESS_VIOLATION
                } else {
                    STATUS_GUARD_PAGE_VIOLATION
                },
                transferred: 0,
            }
        );
        assert_eq!(
            memory.pages[&0x3000].info.protect & PAGE_GUARD != 0,
            attached
        );
        assert!(!memory.pages[&0x3000].resident);
        assert_eq!(memory.pages[&0x3000].bytes, [0x22; PAGE_SIZE as usize]);
    }
}

#[test]
fn readonly_guard_probe_reads_before_testing_write_permission() {
    let mut memory = Memory::default();
    memory.add(0x3000, PAGE_READONLY | PAGE_GUARD, false, 0x22);
    assert_eq!(
        memory.write_byte(0x3000, 0x33),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_ne!(memory.pages[&0x3000].info.protect & PAGE_GUARD, 0);
    assert_eq!(
        probe_write_range(&mut memory, 0x3000, 8),
        Err(STATUS_GUARD_PAGE_VIOLATION)
    );
    assert_eq!(memory.pages[&0x3000].info.protect, PAGE_READONLY);
    assert!(!memory.pages[&0x3000].resident);
    assert_eq!(
        probe_write_range(&mut memory, 0x3000, 8),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(memory.pages[&0x3000].bytes, [0x22; PAGE_SIZE as usize]);
}

#[test]
fn later_destination_guard_leaves_successfully_probed_pages_unchanged() {
    let mut memory = Memory::default();
    memory.add(0x1000, PAGE_READONLY, false, 0x11);
    memory.add(0x3000, PAGE_READWRITE, false, 0x22);
    memory.add(0x4000, PAGE_READWRITE | PAGE_GUARD, false, 0x33);
    assert_eq!(
        copy_virtual_memory(&mut memory, 0x1000, 0x3000, 0x1001),
        CopyResult {
            status: STATUS_GUARD_PAGE_VIOLATION,
            transferred: 0
        }
    );
    assert!(memory.pages[&0x3000].resident);
    assert!(!memory.pages[&0x4000].resident);
    assert_eq!(memory.pages[&0x3000].bytes, [0x22; PAGE_SIZE as usize]);
    assert_eq!(memory.pages[&0x4000].bytes, [0x33; PAGE_SIZE as usize]);
}

#[test]
fn later_source_guard_reports_only_the_completed_prefix() {
    let mut memory = Memory::default();
    memory.add(0x1000, PAGE_READONLY, false, 0x11);
    memory.add(0x2000, PAGE_READONLY | PAGE_GUARD, false, 0x33);
    memory.add(0x4000, PAGE_READWRITE, false, 0x22);
    assert_eq!(
        copy_virtual_memory(&mut memory, 0x1ff0, 0x4000, 32),
        CopyResult {
            status: STATUS_PARTIAL_COPY,
            transferred: 16
        }
    );
    assert_eq!(&memory.pages[&0x4000].bytes[..16], &[0x11; 16]);
    assert_eq!(&memory.pages[&0x4000].bytes[16..32], &[0x22; 16]);
    assert_eq!(memory.pages[&0x2000].info.protect, PAGE_READONLY);
}

#[test]
fn probe_touches_each_page_in_read_write_order_without_changing_bytes() {
    let mut memory = Memory::default();
    memory.add(0x1000, PAGE_READWRITE, false, 0x11);
    memory.add(0x2000, PAGE_READWRITE, false, 0x22);
    assert_eq!(probe_write_range(&mut memory, 0x1ffc, 8), Ok(()));
    assert_eq!(
        memory.accesses,
        [
            (FaultAccess::Read, 0x1ffc),
            (FaultAccess::Write, 0x1ffc),
            (FaultAccess::Read, 0x2000),
            (FaultAccess::Write, 0x2000),
        ]
    );
    assert_eq!(memory.pages[&0x1000].bytes, [0x11; PAGE_SIZE as usize]);
    assert_eq!(memory.pages[&0x2000].bytes, [0x22; PAGE_SIZE as usize]);
}

#[test]
fn count_probe_reads_the_whole_value_before_any_write() {
    let mut memory = Memory::default();
    memory.add(0x1000, PAGE_READWRITE, false, 0x11);
    memory.add(0x2000, PAGE_READWRITE | PAGE_GUARD, false, 0x22);
    assert_eq!(
        probe_write_u64(&mut memory, 0x1ffc),
        Err(STATUS_GUARD_PAGE_VIOLATION)
    );
    assert!(memory
        .accesses
        .iter()
        .all(|(access, _)| *access == FaultAccess::Read));
    assert_eq!(memory.pages[&0x2000].info.protect, PAGE_READWRITE);
    assert_eq!(memory.pages[&0x1000].bytes, [0x11; PAGE_SIZE as usize]);
    assert_eq!(memory.pages[&0x2000].bytes, [0x22; PAGE_SIZE as usize]);
    memory.accesses.clear();
    assert_eq!(probe_write_u64(&mut memory, 0x1ffc), Ok(()));
    assert_eq!(memory.accesses.len(), 16);
    assert!(memory.accesses[..8]
        .iter()
        .all(|(access, _)| *access == FaultAccess::Read));
    assert!(memory.accesses[8..]
        .iter()
        .all(|(access, _)| *access == FaultAccess::Write));
}

#[test]
fn count_probe_failure_does_not_overwrite_the_previous_value() {
    for attached in [false, true] {
        let mut memory = Memory::default();
        memory.add(0x1000, PAGE_READONLY | PAGE_GUARD, attached, 0x7f);
        assert_eq!(
            probe_write_u64(&mut memory, 0x1000),
            Err(if attached {
                STATUS_ACCESS_VIOLATION
            } else {
                STATUS_GUARD_PAGE_VIOLATION
            })
        );
        assert_eq!(memory.pages[&0x1000].bytes, [0x7f; PAGE_SIZE as usize]);
        assert_eq!(
            memory.pages[&0x1000].info.protect & PAGE_GUARD != 0,
            attached
        );
        assert!(memory
            .accesses
            .iter()
            .all(|(access, _)| *access == FaultAccess::Read));
    }
}

#[test]
fn invalid_and_empty_probes_never_touch_memory() {
    let mut memory = Memory::default();
    assert_eq!(
        probe_write_range(&mut memory, u64::MAX, 1),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(probe_write_range(&mut memory, u64::MAX, 0), Ok(()));
    assert!(memory.accesses.is_empty());
    assert_eq!(
        probe_write_u64(&mut memory, u64::MAX - 7),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert!(memory.accesses.is_empty());
}

#[test]
fn guard_permission_precedence_and_writecopy_identity_cover_all_backings() {
    for type_ in [MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE] {
        let info = VmBasicInformation {
            base_address: 0x1000,
            allocation_base: 0x1000,
            region_size: PAGE_SIZE,
            state: MEM_COMMIT,
            type_,
            protect: PAGE_NOACCESS | PAGE_GUARD,
            allocation_protect: PAGE_NOACCESS | PAGE_GUARD,
        };
        for access in [FaultAccess::Read, FaultAccess::Write] {
            for attached in [false, true] {
                assert_eq!(
                    copy_page_plan(0x1000, info, access, attached),
                    Err(STATUS_ACCESS_VIOLATION)
                );
            }
        }
        let readonly = VmBasicInformation {
            protect: PAGE_READONLY | PAGE_GUARD,
            ..info
        };
        assert_eq!(
            copy_page_plan(0x1000, readonly, FaultAccess::Write, false),
            Err(STATUS_ACCESS_VIOLATION)
        );
        if type_ != MEM_PRIVATE {
            for protect in [PAGE_WRITECOPY, PAGE_EXECUTE_WRITECOPY] {
                let cow = VmBasicInformation {
                    protect: protect | PAGE_GUARD,
                    ..info
                };
                for access in [FaultAccess::Read, FaultAccess::Write] {
                    let CopyPagePlan::ConsumeGuard(plan) =
                        copy_page_plan(0x1000, cow, access, false).unwrap()
                    else {
                        panic!("guard fault must precede residency");
                    };
                    assert_eq!(plan.protection, protect);
                    assert_eq!(
                        copy_page_plan(0x1000, cow, access, true),
                        Err(STATUS_ACCESS_VIOLATION)
                    );
                }
            }
        }
    }
}

#[test]
fn guard_planning_covers_all_backings_without_changing_unrelated_attributes() {
    for type_ in [MEM_PRIVATE, MEM_MAPPED, MEM_IMAGE] {
        let info = VmBasicInformation {
            base_address: 0x1000,
            allocation_base: 0x1000,
            region_size: PAGE_SIZE,
            state: MEM_COMMIT,
            type_,
            protect: PAGE_READWRITE | PAGE_GUARD | PAGE_NOCACHE,
            allocation_protect: PAGE_READWRITE | PAGE_GUARD | PAGE_NOCACHE,
        };
        let CopyPagePlan::ConsumeGuard(plan) =
            copy_page_plan(0x1000, info, FaultAccess::Read, false).unwrap()
        else {
            panic!("local guard must be consumed");
        };
        assert_eq!(plan.protection, PAGE_READWRITE | PAGE_NOCACHE);
        assert_eq!(
            copy_page_plan(0x1000, info, FaultAccess::Read, true),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            copy_page_plan(0x2000, info, FaultAccess::Read, false),
            Err(STATUS_ACCESS_VIOLATION)
        );
        let reserved = VmBasicInformation {
            state: MEM_RESERVE,
            ..info
        };
        assert_eq!(
            copy_page_plan(0x1000, reserved, FaultAccess::Read, false),
            Err(STATUS_NOT_COMMITTED)
        );
    }
}
