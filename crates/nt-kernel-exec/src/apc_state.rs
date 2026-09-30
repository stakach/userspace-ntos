//! ReactOS x64 KAPC_STATE list transfer used by the Ke process-attach family.

use core::ptr::{copy_nonoverlapping, read_volatile, write_volatile};

pub const KAPC_STATE_BYTES: usize = 0x30;
pub const KAPC_PROCESS_OFFSET: usize = 0x20;
const KAPC_FLAGS_OFFSET: usize = 0x28;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApcStateError {
    Null,
    Overlap,
    BrokenList,
}

fn checked_distinct(source: u64, destination: u64) -> Result<(), ApcStateError> {
    if source == 0 || destination == 0 {
        return Err(ApcStateError::Null);
    }
    let source_end = source.checked_add(KAPC_STATE_BYTES as u64).ok_or(ApcStateError::Overlap)?;
    let destination_end = destination.checked_add(KAPC_STATE_BYTES as u64).ok_or(ApcStateError::Overlap)?;
    if source < destination_end && destination < source_end {
        return Err(ApcStateError::Overlap);
    }
    Ok(())
}

/// Caller owns both live, writable native ranges and every APC list node. Validate before copy,
/// then repair the first/last node links to the destination list heads as KiMoveApcState does.
pub unsafe fn move_state(source: u64, destination: u64) -> Result<(), ApcStateError> {
    checked_distinct(source, destination)?;
    for offset in [0, 0x10] {
        let head = source + offset;
        let first = unsafe { read_volatile(head as *const u64) };
        let last = unsafe { read_volatile((head + 8) as *const u64) };
        if (first == head) != (last == head) || first == 0 || last == 0 {
            return Err(ApcStateError::BrokenList);
        }
        if first != head && unsafe {
            read_volatile((first + 8) as *const u64) != head
                || read_volatile(last as *const u64) != head
        } {
            return Err(ApcStateError::BrokenList);
        }
    }
    unsafe {
        copy_nonoverlapping(source as *const u8, destination as *mut u8, KAPC_STATE_BYTES);
    }
    for offset in [0, 0x10] {
        let old_head = source + offset;
        let new_head = destination + offset;
        let first = unsafe { read_volatile(new_head as *const u64) };
        let last = unsafe { read_volatile((new_head + 8) as *const u64) };
        unsafe {
            if first == old_head {
                write_volatile(new_head as *mut u64, new_head);
                write_volatile((new_head + 8) as *mut u64, new_head);
            } else {
                write_volatile((first + 8) as *mut u64, new_head);
                write_volatile(last as *mut u64, new_head);
            }
        }
    }
    Ok(())
}

/// Caller owns a writable KAPC_STATE at `state`.
pub unsafe fn initialize(state: u64, process: u64) {
    for offset in [0, 0x10] {
        let head = state + offset;
        unsafe {
            write_volatile(head as *mut u64, head);
            write_volatile((head + 8) as *mut u64, head);
        }
    }
    unsafe {
        write_volatile((state + KAPC_PROCESS_OFFSET as u64) as *mut u64, process);
        for offset in 0..3 {
            write_volatile((state + KAPC_FLAGS_OFFSET as u64 + offset) as *mut u8, 0);
        }
    }
}

/// Caller owns a readable KAPC_STATE at `state`.
pub unsafe fn can_detach(state: u64) -> bool {
    [0, 0x10].iter().all(|offset| {
        let head = state + offset;
        unsafe {
            read_volatile(head as *const u64) == head
                && read_volatile((head + 8) as *const u64) == head
        }
    }) && unsafe { read_volatile((state + KAPC_FLAGS_OFFSET as u64) as *const u8) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_moves_with_rebased_list_heads() {
        let mut source = [0u64; 6];
        let mut destination = [0u64; 6];
        let source_va = source.as_mut_ptr() as u64;
        let destination_va = destination.as_mut_ptr() as u64;
        unsafe {
            initialize(source_va, 0x1234);
            move_state(source_va, destination_va).unwrap();
            assert!(can_detach(destination_va));
        }
        assert_eq!(destination[0], destination_va);
        assert_eq!(destination[1], destination_va);
        assert_eq!(destination[2], destination_va + 0x10);
        assert_eq!(destination[3], destination_va + 0x10);
        assert_eq!(destination[4], 0x1234);
    }

    #[test]
    fn populated_list_repairs_node_links() {
        let mut source = [0u64; 6];
        let mut destination = [0u64; 6];
        let mut node = [0u64; 2];
        let source_va = source.as_mut_ptr() as u64;
        let destination_va = destination.as_mut_ptr() as u64;
        let node_va = node.as_mut_ptr() as u64;
        unsafe { initialize(source_va, 0x5678); }
        unsafe { write_volatile(source_va as *mut u64, node_va); }
        unsafe { write_volatile((source_va + 8) as *mut u64, node_va); }
        node[0] = source_va;
        node[1] = source_va;
        unsafe { move_state(source_va, destination_va).unwrap(); }
        assert_eq!(destination[0], node_va);
        assert_eq!(destination[1], node_va);
        assert_eq!(node[0], destination_va);
        assert_eq!(node[1], destination_va);
    }

    #[test]
    fn rejects_overlap_and_broken_head_before_mutation() {
        let mut source = [0u64; 6];
        let mut destination = [0u64; 6];
        let source_va = source.as_mut_ptr() as u64;
        let destination_va = destination.as_mut_ptr() as u64;
        unsafe { initialize(source_va, 1); }
        assert_eq!(unsafe { move_state(source_va, source_va) }, Err(ApcStateError::Overlap));
        unsafe { write_volatile((source_va + 8) as *mut u64, 0); }
        assert_eq!(unsafe { move_state(source_va, destination_va) }, Err(ApcStateError::BrokenList));
        assert_eq!(destination, [0; 6]);
    }

    #[test]
    fn rejects_broken_reciprocal_links_before_mutation() {
        let mut source = [0u64; 6];
        let mut destination = [0u64; 6];
        let mut node = [0u64; 2];
        let source_va = source.as_mut_ptr() as u64;
        let destination_va = destination.as_mut_ptr() as u64;
        let node_va = node.as_mut_ptr() as u64;
        unsafe { initialize(source_va, 2); }
        unsafe { write_volatile(source_va as *mut u64, node_va); }
        unsafe { write_volatile((source_va + 8) as *mut u64, node_va); }
        node[0] = source_va;
        node[1] = 0;
        assert_eq!(unsafe { move_state(source_va, destination_va) }, Err(ApcStateError::BrokenList));
        assert_eq!(destination, [0; 6]);
        assert_eq!(node[0], source_va);
    }
}
