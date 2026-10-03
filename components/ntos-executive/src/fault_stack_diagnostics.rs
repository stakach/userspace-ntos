//! Best-effort fault diagnostics must never fault the executive while inspecting a client.

use crate::{img_spawn::client_copyin_process_mapped_for, ExecNtHandler};
use nt_memory_manager::ProcessIdentity;

pub(crate) unsafe fn read_fault_stack_word(
    handler: &ExecNtHandler,
    pi: usize,
    process: Option<ProcessIdentity>,
    stack: u64,
    word_index: u64,
    scratch_base: u64,
) -> Option<u64> {
    let process = process?;
    if handler.capture_process_identity(pi) != Some(process) {
        return None;
    }
    let address = stack.checked_add(word_index.checked_mul(8)?)?;
    address.checked_add(8)?;
    let mut bytes = [0u8; 8];
    // Only generation-authenticated resident records/prefetch aliases are admissible. The
    // broad bootstrap mirrors and historical fill-order scratch pages are not residency proof.
    if !client_copyin_process_mapped_for(
        pi as u64,
        process,
        address,
        &mut bytes,
        scratch_base,
    ) {
        return None;
    }
    Some(u64::from_le_bytes(bytes))
}
