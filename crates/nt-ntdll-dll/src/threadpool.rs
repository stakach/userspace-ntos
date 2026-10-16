//! Native-backed object threadpool work exports.
//!
//! Work is submitted through the existing completion-port `RtlQueueWorkItem` worker. Each queued
//! callback owns its work record until it finishes; releasing a TP_WORK only drops the caller's
//! reference. Other Tp object kinds need their own timer, wait, and I/O completion lifetimes.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::threadpool_state::WorkState;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const WORK_MAGIC: u32 = 0x5750_5450;
const INSTANCE_MAGIC: u32 = 0x4950_5450;

type WorkCallback = unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void);
type SimpleCallback = unsafe extern "system" fn(*mut c_void, *mut c_void);

#[repr(C)]
struct CallbackEnvironment {
    version: u32,
    pool: *mut c_void,
    cleanup_group: *mut c_void,
    cancel_callback: *mut c_void,
    race_dll: *mut c_void,
    activation_context: *mut c_void,
    finalization_callback: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct CallbackEnvironmentV3 {
    version: u32,
    pool: *mut c_void,
    cleanup_group: *mut c_void,
    cancel_callback: *mut c_void,
    race_dll: *mut c_void,
    activation_context: *mut c_void,
    finalization_callback: *mut c_void,
    flags: u32,
    priority: u32,
    size: u32,
}

#[repr(C)]
struct CallbackInstance {
    magic: u32,
    work: *mut Work,
}

#[repr(C)]
struct Work {
    magic: u32,
    refs: AtomicU32,
    state: WorkState,
    callback: *mut c_void,
    context: *mut c_void,
    simple: bool,
}

#[repr(C)]
struct WorkTicket {
    work: *mut Work,
    sequence: u64,
}

fn succeeded(status: u32) -> bool {
    (status as i32) >= 0
}

unsafe fn environment_status(environment: *const CallbackEnvironment) -> u32 {
    if environment.is_null() {
        return STATUS_SUCCESS;
    }
    let env = unsafe { &*environment };
    if env.version != 1 && env.version != 3 {
        return STATUS_INVALID_PARAMETER;
    }
    let default_fields = env.pool.is_null()
        && env.cleanup_group.is_null()
        && env.cancel_callback.is_null()
        && env.race_dll.is_null()
        && env.activation_context.is_null()
        && env.finalization_callback.is_null()
        && env.flags == 0;
    if !default_fields {
        return STATUS_NOT_SUPPORTED;
    }
    if env.version == 3 {
        let v3 = unsafe { &*environment.cast::<CallbackEnvironmentV3>() };
        // The global native worker currently admits only normal-priority default environments.
        if v3.size as usize != core::mem::size_of::<CallbackEnvironmentV3>() {
            return STATUS_INVALID_PARAMETER;
        }
        if v3.priority > 2 {
            return STATUS_INVALID_PARAMETER;
        }
        if v3.priority != 1 {
            return STATUS_NOT_SUPPORTED;
        }
    }
    STATUS_SUCCESS
}

unsafe fn alloc_work(callback: *mut c_void, context: *mut c_void, simple: bool) -> *mut Work {
    let allocation = unsafe { crate::process_heap_alloc(core::mem::size_of::<Work>()) };
    if allocation.is_null() {
        return core::ptr::null_mut();
    }
    let work = allocation.cast::<Work>();
    unsafe {
        core::ptr::write(
            work,
            Work {
                magic: WORK_MAGIC,
                refs: AtomicU32::new(1),
                state: WorkState::new(),
                callback,
                context,
                simple,
            },
        )
    };
    work
}

unsafe fn release_ref(work: *mut Work) {
    if unsafe { (*work).refs.fetch_sub(1, Ordering::AcqRel) } == 1 {
        unsafe { (*work).magic = 0 };
        let _ = unsafe { crate::process_heap_free(work.cast()) };
    }
}

unsafe fn finish_submission(work: *mut Work) {
    unsafe { (*work).state.finish() };
    crate::wait_address::rtl_wake_address_all(unsafe {
        (*work).state.outstanding_address().cast()
    });
    unsafe { release_ref(work) };
}

unsafe extern "system" fn dispatch_ticket(context: *mut c_void) {
    let ticket = context.cast::<WorkTicket>();
    let work = unsafe { (*ticket).work };
    let sequence = unsafe { (*ticket).sequence };
    if unsafe { (*work).state.should_run(sequence) } {
        let mut instance = CallbackInstance {
            magic: INSTANCE_MAGIC,
            work,
        };
        let callback = unsafe { (*work).callback };
        let userdata = unsafe { (*work).context };
        if unsafe { (*work).simple } {
            let callback: SimpleCallback = unsafe { core::mem::transmute(callback) };
            unsafe { callback((&mut instance as *mut CallbackInstance).cast(), userdata) };
        } else {
            let callback: WorkCallback = unsafe { core::mem::transmute(callback) };
            unsafe {
                callback(
                    (&mut instance as *mut CallbackInstance).cast(),
                    userdata,
                    work.cast(),
                )
            };
        }
        instance.magic = 0;
    }
    let _ = unsafe { crate::process_heap_free(ticket.cast()) };
    unsafe { finish_submission(work) };
}

unsafe fn post(work: *mut Work) -> u32 {
    if work.is_null() || unsafe { (*work).magic } != WORK_MAGIC {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(sequence) = (unsafe { (*work).state.reserve() }) else {
        return STATUS_INVALID_PARAMETER;
    };
    unsafe { (*work).refs.fetch_add(1, Ordering::AcqRel) };
    let ticket = unsafe { crate::process_heap_alloc(core::mem::size_of::<WorkTicket>()) }
        .cast::<WorkTicket>();
    if ticket.is_null() {
        unsafe { finish_submission(work) };
        return STATUS_NO_MEMORY;
    }
    unsafe { core::ptr::write(ticket, WorkTicket { work, sequence }) };
    let status = unsafe {
        crate::exports::rtl_queue_work_item(dispatch_ticket as *mut c_void, ticket.cast(), 0)
    };
    // The existing queue API reports only NTSTATUS, not whether a failed native submission
    // definitely had no effect. A late completion may still enter `dispatch_ticket`, so retain the
    // ticket and work reference on error. They are quarantined until an actual callback consumes
    // them; native outcome tracking can later reclaim definitive no-effect submissions.
    status
}

/// # Safety
/// `out` is writable; `callback` is an executable TP_WORK_CALLBACK; `environment` is a readable
/// V1 or V3 callback environment when non-null.
#[export_name = "TpAllocWork"]
pub unsafe extern "system" fn tp_alloc_work(
    out: *mut *mut c_void,
    callback: *mut c_void,
    context: *mut c_void,
    environment: *const c_void,
) -> u32 {
    if out.is_null() || callback.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    unsafe { *out = core::ptr::null_mut() };
    let environment_status = unsafe { environment_status(environment.cast()) };
    if environment_status != STATUS_SUCCESS {
        return environment_status;
    }
    let work = unsafe { alloc_work(callback, context, false) };
    if work.is_null() {
        return STATUS_NO_MEMORY;
    }
    unsafe { *out = work.cast() };
    STATUS_SUCCESS
}

/// # Safety
/// `work` is a live TP_WORK allocated by `TpAllocWork`.
#[export_name = "TpPostWork"]
pub unsafe extern "system" fn tp_post_work(work: *mut c_void) {
    let status = unsafe { post(work.cast()) };
    if !succeeded(status) {
        // The native ABI returns void: surface a failed admission as an NT exception, not a
        // successful-looking dropped callback.
        unsafe { crate::exports::rtl_raise_status(status) };
        loop {
            core::hint::spin_loop();
        }
    }
}

/// # Safety
/// `work` is a live TP_WORK. Posting it after release is invalid.
#[export_name = "TpReleaseWork"]
pub unsafe extern "system" fn tp_release_work(work: *mut c_void) {
    if work.is_null() {
        return;
    }
    let work = work.cast::<Work>();
    unsafe { (*work).state.close() };
    unsafe { release_ref(work) };
}

/// # Safety
/// `work` is a live TP_WORK retained by the caller until this wait returns.
#[export_name = "TpWaitForWork"]
pub unsafe extern "system" fn tp_wait_for_work(work: *mut c_void, cancel_pending: u32) {
    let work = work.cast::<Work>();
    if work.is_null() || unsafe { (*work).magic } != WORK_MAGIC {
        unsafe { crate::exports::rtl_raise_status(STATUS_INVALID_PARAMETER) };
        return;
    }
    if cancel_pending != 0 {
        unsafe { (*work).state.cancel_pending() };
    }
    loop {
        let outstanding = unsafe { (*work).state.outstanding() };
        if outstanding == 0 {
            return;
        }
        let status = unsafe {
            crate::wait_address::rtl_wait_on_address(
                (*work).state.outstanding_address().cast(),
                (&outstanding as *const u32).cast(),
                core::mem::size_of::<u32>(),
                core::ptr::null(),
            )
        };
        if !succeeded(status) {
            unsafe { crate::exports::rtl_raise_status(status) };
            loop {
                core::hint::spin_loop();
            }
        }
    }
}

/// # Safety
/// `callback` is an executable TP_SIMPLE_CALLBACK; `environment` is a readable V1/V3 callback
/// environment when non-null.
#[export_name = "TpSimpleTryPost"]
pub unsafe extern "system" fn tp_simple_try_post(
    callback: *mut c_void,
    context: *mut c_void,
    environment: *const c_void,
) -> u32 {
    if callback.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let environment_status = unsafe { environment_status(environment.cast()) };
    if environment_status != STATUS_SUCCESS {
        return environment_status;
    }
    let work = unsafe { alloc_work(callback, context, true) };
    if work.is_null() {
        return STATUS_NO_MEMORY;
    }
    let status = unsafe { post(work) };
    unsafe { (*work).state.close() };
    unsafe { release_ref(work) };
    status
}

#[used]
pub static THREADPOOL_EXPORT_ANCHOR_FN: unsafe extern "C" fn() = threadpool_export_anchor;

/// Linker retention anchor; never called.
///
/// # Safety
/// Stored only in a `#[used]` static.
pub unsafe extern "C" fn threadpool_export_anchor() {
    core::hint::black_box([
        tp_alloc_work as *const () as usize,
        tp_post_work as *const () as usize,
        tp_release_work as *const () as usize,
        tp_wait_for_work as *const () as usize,
        tp_simple_try_post as *const () as usize,
    ]);
}
