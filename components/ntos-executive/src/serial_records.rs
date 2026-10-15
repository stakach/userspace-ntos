//! Complete diagnostic records from the executive's single dispatch executor.

use core::sync::atomic::{AtomicBool, Ordering};
use nt_printf::record::LineBuffer;

static READY: AtomicBool = AtomicBool::new(false);
static mut ROOT_LINES: LineBuffer<4096> = LineBuffer::new();

const ANCHOR_OFFSET: usize = 4096 - core::mem::size_of::<usize>();
const _: () = assert!(ANCHOR_OFFSET >= sel4_rt::IPC_BUFFER_SIZE_BYTES);
const _: () = assert!(ANCHOR_OFFSET % core::mem::align_of::<usize>() == 0);

/// The IPC ABI occupies only its leading bytes. Every primary component has a fresh private
/// page at this common VA; workers retain that domain's primary page and its zero anchor.
pub(crate) unsafe fn initialize_root(actual_ipc_va: u64) {
    if actual_ipc_va != crate::IPCBUF_VADDR {
        let (frame, error) = crate::alloc_frame_r();
        assert_eq!(error, 0, "root diagnostic anchor frame allocation");
        crate::root_slot_pin_run(frame, 1);
        let mapped = crate::page_map_r(frame, crate::IPCBUF_VADDR, crate::RW_NX,
            crate::CAP_INIT_THREAD_VSPACE);
        assert_eq!(mapped, 0, "root diagnostic anchor mapping");
    }
    core::ptr::write_volatile(
        (crate::IPCBUF_VADDR as usize + ANCHOR_OFFSET) as *mut usize,
        core::ptr::addr_of_mut!(ROOT_LINES) as usize,
    );
    // Only Root writes shared image state, once, before any component is activated.
    READY.store(true, Ordering::Release);
}

pub fn print_str(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) {
        sel4_rt::print_str(bytes);
        return;
    }
    unsafe {
        let anchor = core::ptr::read_volatile(
            (crate::IPCBUF_VADDR as usize + ANCHOR_OFFSET) as *const usize,
        );
        if anchor == 0 {
            sel4_rt::print_str(bytes);
            return;
        }
        // Only Root's private page contains a pointer. The record syscall is non-IPC and
        // cannot reenter the single Root executor while its framing buffer is borrowed.
        (&mut *(anchor as *mut LineBuffer<4096>)).feed(bytes, sel4_rt::print_record);
    }
}

pub fn debug_put_char(byte: u8) {
    print_str(&[byte]);
}

pub fn print_u64(mut value: u64) {
    let mut bytes = [0u8; 20];
    let mut index = bytes.len();
    loop {
        index -= 1;
        bytes[index] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    print_str(&bytes[index..]);
}
