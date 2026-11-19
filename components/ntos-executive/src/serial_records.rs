//! Complete diagnostic records from the executive's single dispatch executor.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nt_printf::record::LineBuffer;

static READY: AtomicBool = AtomicBool::new(false);
static mut ROOT_LINES: LineBuffer<4096> = LineBuffer::new();
/// Bytes Root fed to its serial framing; components and workers never reach the counter.
static ROOT_SERIAL_BYTES: AtomicU64 = AtomicU64::new(0);

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
        ROOT_SERIAL_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
        // Only Root's private page contains a pointer. The record syscall is non-IPC and
        // cannot reenter the single Root executor while its framing buffer is borrowed.
        (&mut *(anchor as *mut LineBuffer<4096>)).feed(bytes, sel4_rt::print_record);
    }
}

/// Monotonic count of serial bytes Root has emitted, for per-dispatch cost attribution.
pub(crate) fn root_serial_bytes() -> u64 {
    ROOT_SERIAL_BYTES.load(Ordering::Relaxed)
}

/// Root's private IPC page alone carries the record anchor; components and workers see zero.
pub(crate) fn is_root_executor() -> bool {
    READY.load(Ordering::Acquire)
        && unsafe {
            core::ptr::read_volatile(
                (crate::IPCBUF_VADDR as usize + ANCHOR_OFFSET) as *const usize,
            )
        } != 0
}

static mut ROOT_SPIN_WATCH: nt_kernel_exec::spin_watch::SpinWatch =
    nt_kernel_exec::spin_watch::SpinWatch::new();

/// Yield the processor from a polling loop. Root's loops wait on threads it does not own; if
/// such a thread can never run, the loop is a livelock that prints nothing and starves the
/// census, so root names the exact site once the run of yields is long enough.
#[track_caller]
pub fn yield_now() {
    observe_root_yield(core::panic::Location::caller());
    sel4_rt::yield_now();
}

/// Count one processor handoff (plain or directed yield) from `site` on root's watch.
pub(crate) fn observe_root_yield(site: &'static core::panic::Location<'static>) {
    if is_root_executor() {
        // Root is the single writer: components and workers never pass the check above.
        let watch = unsafe { &mut *core::ptr::addr_of_mut!(ROOT_SPIN_WATCH) };
        if let Some(yields) = watch.observe(site as *const _ as usize) {
            print_str(b"[root-spin] site=");
            print_str(site.file().as_bytes());
            print_str(b":");
            print_u64(u64::from(site.line()));
            print_str(b" yields=");
            print_u64(yields);
            print_str(b"\n");
        }
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
