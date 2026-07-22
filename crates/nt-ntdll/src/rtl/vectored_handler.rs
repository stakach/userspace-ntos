//! Process-local vectored exception and continue-handler registries.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
extern crate std;

/// `EXCEPTION_CONTINUE_EXECUTION`.
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
/// `EXCEPTION_CONTINUE_SEARCH`.
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;

/// The pair passed to a `PVECTORED_EXCEPTION_HANDLER`.
#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut c_void,
    pub context_record: *mut c_void,
}

/// `PVECTORED_EXCEPTION_HANDLER`.
pub type VectoredHandler = unsafe extern "system" fn(*mut ExceptionPointers) -> i32;

/// Select the independently ordered exception or continue list.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandlerList {
    Exception,
    Continue,
}

#[repr(C)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
struct HandlerEntry {
    list_entry: ListEntry,
    handler: VectoredHandler,
    references: u32,
}

struct HandlerState {
    exception_head: ListEntry,
    continue_head: ListEntry,
    initialized: bool,
}

/// Locked process handler lists. Methods require a pinned reference because each circular list
/// stores its sentinel's address.
pub struct VectoredHandlers {
    lock_state: AtomicU64,
    state: UnsafeCell<HandlerState>,
    _pin: PhantomPinned,
}

unsafe impl Sync for VectoredHandlers {}

struct HandlerGuard<'a> {
    handlers: &'a VectoredHandlers,
    owner: u64,
}

impl Drop for HandlerGuard<'_> {
    fn drop(&mut self) {
        loop {
            let state = self.handlers.lock_state.load(Ordering::Relaxed);
            debug_assert_eq!(state >> 16, self.owner);
            let recursion = state as u16;
            let next = if recursion == 1 { 0 } else { state - 1 };
            if self
                .handlers
                .lock_state
                .compare_exchange_weak(state, next, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
}

impl Default for VectoredHandlers {
    fn default() -> Self {
        Self::new()
    }
}

impl VectoredHandlers {
    pub const fn new() -> Self {
        Self {
            lock_state: AtomicU64::new(0),
            state: UnsafeCell::new(HandlerState {
                exception_head: ListEntry {
                    flink: ptr::null_mut(),
                    blink: ptr::null_mut(),
                },
                continue_head: ListEntry {
                    flink: ptr::null_mut(),
                    blink: ptr::null_mut(),
                },
                initialized: false,
            }),
            _pin: PhantomPinned,
        }
    }

    fn lock(&self) -> HandlerGuard<'_> {
        let owner = current_thread_key() & 0x0000_FFFF_FFFF_FFFF;
        let owner = owner.max(1);
        loop {
            let state = self.lock_state.load(Ordering::Acquire);
            let next = if state == 0 {
                (owner << 16) | 1
            } else if state >> 16 == owner {
                assert_ne!(
                    state as u16,
                    u16::MAX,
                    "vectored handler lock recursion overflow"
                );
                state + 1
            } else {
                core::hint::spin_loop();
                continue;
            };
            if self
                .lock_state
                .compare_exchange_weak(state, next, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return HandlerGuard {
                    handlers: self,
                    owner,
                };
            }
            core::hint::spin_loop();
        }
    }

    unsafe fn heads(&self) -> (*mut ListEntry, *mut ListEntry) {
        let state = unsafe { &mut *self.state.get() };
        let exception_head = ptr::addr_of_mut!(state.exception_head);
        let continue_head = ptr::addr_of_mut!(state.continue_head);
        if !state.initialized {
            state.exception_head.flink = exception_head;
            state.exception_head.blink = exception_head;
            state.continue_head.flink = continue_head;
            state.continue_head.blink = continue_head;
            state.initialized = true;
        }
        (exception_head, continue_head)
    }

    unsafe fn head(&self, list: HandlerList) -> *mut ListEntry {
        let (exception_head, continue_head) = unsafe { self.heads() };
        match list {
            HandlerList::Exception => exception_head,
            HandlerList::Continue => continue_head,
        }
    }

    /// Register at the head when `first` is nonzero, otherwise at the tail. The returned entry
    /// pointer is the opaque removal handle.
    pub fn add(
        self: Pin<&Self>,
        list: HandlerList,
        first: u32,
        handler: Option<VectoredHandler>,
    ) -> *mut c_void {
        let Some(handler) = handler else {
            return ptr::null_mut();
        };
        let layout = Layout::new::<HandlerEntry>();
        // SAFETY: a valid nonzero layout; null reports allocation failure.
        let entry = unsafe { alloc(layout) }.cast::<HandlerEntry>();
        if entry.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: fresh aligned allocation.
        unsafe {
            ptr::write(
                entry,
                HandlerEntry {
                    list_entry: ListEntry {
                        flink: ptr::null_mut(),
                        blink: ptr::null_mut(),
                    },
                    handler,
                    references: 1,
                },
            );
        }

        let this = self.get_ref();
        let _guard = this.lock();
        // SAFETY: list mutation is serialized and `entry` is uniquely owned.
        unsafe {
            let head = this.head(list);
            let link = ptr::addr_of_mut!((*entry).list_entry);
            if first != 0 {
                let next = (*head).flink;
                (*link).flink = next;
                (*link).blink = head;
                (*next).blink = link;
                (*head).flink = link;
            } else {
                let previous = (*head).blink;
                (*link).flink = head;
                (*link).blink = previous;
                (*previous).flink = link;
                (*head).blink = link;
            }
        }
        entry.cast()
    }

    /// Remove a previously returned handle from the selected list. A handler executing on another
    /// stack is marked for deletion and freed by the dispatcher after its callback returns.
    pub fn remove(self: Pin<&Self>, list: HandlerList, handle: *mut c_void) -> u32 {
        if handle.is_null() {
            return 0;
        }
        let this = self.get_ref();
        let guard = this.lock();
        let mut removed = ptr::null_mut();
        let mut found = false;
        // SAFETY: traversal and reference mutation are serialized by `guard`.
        unsafe {
            let head = this.head(list);
            let mut link = (*head).flink;
            while link != head {
                let entry = link.cast::<HandlerEntry>();
                if entry.cast::<c_void>() == handle {
                    found = true;
                    (*entry).references -= 1;
                    if (*entry).references == 0 {
                        unlink(link);
                        removed = entry;
                    }
                    break;
                }
                link = (*link).flink;
            }
        }
        drop(guard);
        if !removed.is_null() {
            // SAFETY: unlinked under the lock and no active dispatcher reference remains.
            unsafe { free_entry(removed) };
        }
        found as u32
    }

    /// Invoke handlers in order. Returns true only when one requests continued execution. Continue
    /// lists use the same traversal but callers ignore this return value.
    ///
    /// # Safety
    /// The record and context pointers remain valid for the duration of every callback.
    pub unsafe fn call(
        self: Pin<&Self>,
        list: HandlerList,
        exception_record: *mut c_void,
        context_record: *mut c_void,
    ) -> bool {
        let this = self.get_ref();
        let mut guard = Some(this.lock());
        let mut deferred_free: *mut HandlerEntry = ptr::null_mut();
        let mut handled = false;
        // SAFETY: protected by the held guard.
        let head = unsafe { this.head(list) };
        // SAFETY: initialized circular list.
        let mut current = unsafe { (*head).flink };
        let mut pointers = ExceptionPointers {
            exception_record,
            context_record,
        };

        while current != head {
            let entry = current.cast::<HandlerEntry>();
            // SAFETY: current is linked under the lock; the reference prevents callback removal
            // from freeing the entry while user code runs.
            let handler = unsafe {
                (*entry).references += 1;
                (*entry).handler
            };
            drop(guard.take());
            let result = unsafe { handler(&mut pointers) };
            guard = Some(this.lock());

            // SAFETY: the entry remained referenced and list mutation is locked again.
            unsafe {
                (*entry).references -= 1;
                if (*entry).references == 0 {
                    current = (*current).flink;
                    unlink(ptr::addr_of_mut!((*entry).list_entry));
                    (*entry).list_entry.flink = deferred_free.cast::<ListEntry>();
                    deferred_free = entry;
                } else {
                    current = (*current).flink;
                }
            }
            if result == EXCEPTION_CONTINUE_EXECUTION {
                handled = true;
                break;
            }
        }
        drop(guard.take());
        // SAFETY: deferred entries were unlinked under the lock and retained until traversal no
        // longer carries any list pointer across an unlocked interval.
        unsafe {
            while !deferred_free.is_null() {
                let entry = deferred_free;
                deferred_free = (*entry).list_entry.flink.cast::<HandlerEntry>();
                free_entry(entry);
            }
        }
        handled
    }
}

#[cfg(test)]
fn current_thread_key() -> u64 {
    use core::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish().max(1)
}

#[cfg(all(not(test), target_arch = "x86_64", target_os = "windows"))]
fn current_thread_key() -> u64 {
    let key: u64;
    // SAFETY: TEB.ClientId.UniqueThread is at GS:[0x48] on AMD64 NT.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x48]",
            out(reg) key,
            options(nostack, preserves_flags, readonly)
        );
    }
    key.max(1)
}

#[cfg(all(not(test), not(all(target_arch = "x86_64", target_os = "windows"))))]
fn current_thread_key() -> u64 {
    1
}

impl Drop for VectoredHandlers {
    fn drop(&mut self) {
        // SAFETY: `&mut self` excludes concurrent access.
        unsafe {
            let state = &mut *self.state.get();
            if !state.initialized {
                return;
            }
            for head in [
                ptr::addr_of_mut!(state.exception_head),
                ptr::addr_of_mut!(state.continue_head),
            ] {
                let mut link = (*head).flink;
                while link != head {
                    let entry = link.cast::<HandlerEntry>();
                    link = (*link).flink;
                    free_entry(entry);
                }
            }
        }
    }
}

unsafe fn unlink(link: *mut ListEntry) {
    unsafe {
        let previous = (*link).blink;
        let next = (*link).flink;
        (*previous).flink = next;
        (*next).blink = previous;
    }
}

unsafe fn free_entry(entry: *mut HandlerEntry) {
    unsafe { dealloc(entry.cast(), Layout::new::<HandlerEntry>()) };
}

static VECTORED_HANDLERS: VectoredHandlers = VectoredHandlers::new();

/// Pin the process-global handler registry at its static address.
pub fn vectored_handlers() -> Pin<&'static VectoredHandlers> {
    // SAFETY: statics never move.
    unsafe { Pin::new_unchecked(&VECTORED_HANDLERS) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::boxed::Box;

    struct CallState {
        order: [u32; 4],
        count: usize,
        handlers: *const VectoredHandlers,
        self_handle: *mut c_void,
    }

    unsafe fn state(info: *mut ExceptionPointers) -> &'static mut CallState {
        unsafe { &mut *((*info).exception_record.cast::<CallState>()) }
    }

    unsafe extern "system" fn handler_one(info: *mut ExceptionPointers) -> i32 {
        let state = unsafe { state(info) };
        state.order[state.count] = 1;
        state.count += 1;
        EXCEPTION_CONTINUE_SEARCH
    }

    unsafe extern "system" fn handler_two(info: *mut ExceptionPointers) -> i32 {
        let state = unsafe { state(info) };
        state.order[state.count] = 2;
        state.count += 1;
        EXCEPTION_CONTINUE_EXECUTION
    }

    unsafe extern "system" fn self_removing_handler(info: *mut ExceptionPointers) -> i32 {
        let state = unsafe { state(info) };
        state.order[state.count] = 3;
        state.count += 1;
        let handlers = unsafe { Pin::new_unchecked(&*state.handlers) };
        assert_eq!(
            handlers.remove(HandlerList::Exception, state.self_handle),
            1
        );
        EXCEPTION_CONTINUE_SEARCH
    }

    fn registry() -> Pin<Box<VectoredHandlers>> {
        Box::pin(VectoredHandlers::new())
    }

    fn call_state(handlers: Pin<&VectoredHandlers>) -> CallState {
        CallState {
            order: [0; 4],
            count: 0,
            handlers: handlers.get_ref(),
            self_handle: ptr::null_mut(),
        }
    }

    #[test]
    fn first_handler_runs_at_head_and_execution_stops() {
        let handlers = registry();
        let tail = handlers
            .as_ref()
            .add(HandlerList::Exception, 0, Some(handler_one));
        let head = handlers
            .as_ref()
            .add(HandlerList::Exception, 1, Some(handler_two));
        let mut state = call_state(handlers.as_ref());

        assert!(unsafe {
            handlers.as_ref().call(
                HandlerList::Exception,
                ptr::addr_of_mut!(state).cast(),
                ptr::null_mut(),
            )
        });
        assert_eq!(&state.order[..state.count], &[2]);
        assert_eq!(handlers.as_ref().remove(HandlerList::Exception, head), 1);
        assert_eq!(handlers.as_ref().remove(HandlerList::Exception, tail), 1);
    }

    #[test]
    fn removal_is_scoped_to_the_selected_list() {
        let handlers = registry();
        let handle = handlers
            .as_ref()
            .add(HandlerList::Continue, 0, Some(handler_one));
        assert_eq!(handlers.as_ref().remove(HandlerList::Exception, handle), 0);
        assert_eq!(handlers.as_ref().remove(HandlerList::Continue, handle), 1);
        assert_eq!(handlers.as_ref().remove(HandlerList::Continue, handle), 0);
    }

    #[test]
    fn callback_can_remove_itself() {
        let handlers = registry();
        let mut state = call_state(handlers.as_ref());
        state.self_handle =
            handlers
                .as_ref()
                .add(HandlerList::Exception, 0, Some(self_removing_handler));

        assert!(!unsafe {
            handlers.as_ref().call(
                HandlerList::Exception,
                ptr::addr_of_mut!(state).cast(),
                ptr::null_mut(),
            )
        });
        assert_eq!(&state.order[..state.count], &[3]);
        assert_eq!(
            handlers
                .as_ref()
                .remove(HandlerList::Exception, state.self_handle),
            0
        );
    }

    #[test]
    fn null_handler_is_rejected() {
        let handlers = registry();
        assert!(
            handlers
                .as_ref()
                .add(HandlerList::Exception, 0, None)
                .is_null()
        );
    }

    #[test]
    fn bookkeeping_lock_is_recursive_for_its_owner() {
        let handlers = registry();
        let first = handlers.as_ref().get_ref().lock();
        let second = handlers.as_ref().get_ref().lock();
        assert_eq!(
            handlers
                .as_ref()
                .get_ref()
                .lock_state
                .load(Ordering::Relaxed) as u16,
            2
        );
        drop(second);
        assert_eq!(
            handlers
                .as_ref()
                .get_ref()
                .lock_state
                .load(Ordering::Relaxed) as u16,
            1
        );
        drop(first);
        assert_eq!(
            handlers
                .as_ref()
                .get_ref()
                .lock_state
                .load(Ordering::Relaxed),
            0
        );
    }
}
