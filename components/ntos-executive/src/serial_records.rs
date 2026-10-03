//! Complete diagnostic records from the executive's single dispatch executor.

use core::sync::atomic::{AtomicBool, Ordering};
use nt_printf::record::LineBuffer;

static ROOT_EXECUTOR: AtomicBool = AtomicBool::new(false);
static mut ROOT_LINES: LineBuffer<4096> = LineBuffer::new();

pub(crate) fn initialize_root() {
    ROOT_EXECUTOR.store(true, Ordering::Release);
}

pub(crate) fn initialize_component() {
    ROOT_EXECUTOR.store(false, Ordering::Release);
}

pub fn print_str(bytes: &[u8]) {
    if !ROOT_EXECUTOR.load(Ordering::Acquire) {
        sel4_rt::print_str(bytes);
        return;
    }
    // Only the initial executive uses this buffer; cloned component entry clears the role
    // before any worker starts. The non-IPC record syscall cannot reenter its dispatch loop.
    unsafe {
        (&mut *core::ptr::addr_of_mut!(ROOT_LINES)).feed(bytes, sel4_rt::print_record);
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
