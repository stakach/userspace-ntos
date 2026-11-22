//! Root maintenance runs before the received syscall's native tail is captured (#420, #427).
//!
//! Boot 44957371959: maintenance resumed a parked condrv dispatch (`drain_root_restores`). That
//! resume really receives on the root TCB, so condrv's next Call overwrote the root IPC buffer
//! that still held conhost's NtMapViewOfSection/NtCreateSection tail arguments. Their first
//! buffer-borne checks then failed (0xC0000045 for Win32Protect, 0xC00000F4 for
//! AllocationAttributes), and conhost died loading sechost.dll/iphlpapi.dll.
//!
//! The executive's maintenance prologue runs inside `preserving_message_buffer`. This test drives
//! that contract with the real native-request capture. The ordering inside the native service
//! loop itself (`executor/maintenance.rs`) can only be exercised on target.

use core::cell::RefCell;
use nt_component_suspension::{preserving_message_buffer, IPC_BUFFER_WORDS};
use nt_syscall_abi::{NativeSyscallRequest, NT_NATIVE_SYSCALL_LABEL};

const MAP_VIEW_ARGS: usize = 12;

fn received_map_view(bank: &RefCell<[u64; IPC_BUFFER_WORDS]>) -> u64 {
    // NtMapViewOfSection: words 4.. carry args[2..]; args[9] (Win32Protect) is word 11.
    let mut bank = bank.borrow_mut();
    for index in 4..MAP_VIEW_ARGS {
        bank[index] = 0x1000 + index as u64;
    }
    bank[11] = 0x20; // PAGE_EXECUTE_READ
    (NT_NATIVE_SYSCALL_LABEL << 12) | MAP_VIEW_ARGS as u64
}

/// A kept dispatch's resume receives the provider's next Call into the same buffer.
fn resume_parked_dispatch(bank: &RefCell<[u64; IPC_BUFFER_WORDS]>) {
    bank.borrow_mut().iter_mut().for_each(|word| *word = 0xdead_beef);
}

fn capture(info: u64, bank: &RefCell<[u64; IPC_BUFFER_WORDS]>) -> NativeSyscallRequest {
    NativeSyscallRequest::capture(info, [0x28, 0, 0, 0], |index| bank.borrow()[index]).unwrap()
}

#[test]
fn a_resume_during_maintenance_leaves_the_received_tail_arguments_intact() {
    let bank = RefCell::new([0u64; IPC_BUFFER_WORDS]);
    let info = received_map_view(&bank);
    preserving_message_buffer(
        |index| bank.borrow()[index],
        |index, word| bank.borrow_mut()[index] = word,
        || resume_parked_dispatch(&bank),
    );
    let request = capture(info, &bank);
    assert_eq!(request.word(11), Some(0x20), "Win32Protect was replaced by the provider's Call");
    for index in 4..MAP_VIEW_ARGS {
        if index != 11 {
            assert_eq!(request.word(index), Some(0x1000 + index as u64));
        }
    }
}

#[test]
fn an_unpreserved_resume_is_exactly_the_boot_failure() {
    let bank = RefCell::new([0u64; IPC_BUFFER_WORDS]);
    let info = received_map_view(&bank);
    resume_parked_dispatch(&bank);
    assert_eq!(capture(info, &bank).word(11), Some(0xdead_beef));
}

#[test]
fn the_preserved_work_still_returns_its_result() {
    let bank = RefCell::new([7u64; IPC_BUFFER_WORDS]);
    let progress = preserving_message_buffer(
        |index| bank.borrow()[index],
        |index, word| bank.borrow_mut()[index] = word,
        || { resume_parked_dispatch(&bank); 3usize },
    );
    assert_eq!(progress, 3);
    assert!(bank.borrow().iter().all(|word| *word == 7));
}

/// `drive()` and `await_at_root` guard themselves too, inside maintenance's guard. A nested
/// save restores the buffer its own scope found, and the outer one restores the received Call.
#[test]
fn a_kept_pump_drive_nested_in_maintenance_restores_in_stack_order() {
    let bank = RefCell::new([0u64; IPC_BUFFER_WORDS]);
    let info = received_map_view(&bank);
    let read = |index| bank.borrow()[index];
    let write = |index, word| bank.borrow_mut()[index] = word;
    preserving_message_buffer(read, write, || {
        // Maintenance's own work receives first.
        bank.borrow_mut()[11] = 0x5151;
        preserving_message_buffer(read, write, || resume_parked_dispatch(&bank));
        assert_eq!(bank.borrow()[11], 0x5151, "the inner drive restores what it found");
    });
    assert_eq!(capture(info, &bank).word(11), Some(0x20), "the outer scope restores the Call");
}

/// A root-level handler waits for its kept pump (`await_at_root`) and reads more of its own
/// request afterwards. The wait's receives must not replace it.
#[test]
fn a_root_wait_inside_a_handler_keeps_its_request_for_after_the_wait() {
    let bank = RefCell::new([0u64; IPC_BUFFER_WORDS]);
    let info = received_map_view(&bank);
    let early = capture(info, &bank).word(4);
    preserving_message_buffer(
        |index| bank.borrow()[index],
        |index, word| bank.borrow_mut()[index] = word,
        || { for _ in 0..3 { resume_parked_dispatch(&bank); } },
    );
    let late = capture(info, &bank);
    assert_eq!((early, late.word(4), late.word(11)), (Some(0x1004), Some(0x1004), Some(0x20)));
}
