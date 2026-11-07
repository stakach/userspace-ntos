//! Loader function pointer block consumed by the released WOW64 bootstrap.
//!
//! The pinned DLL exports a 0xf0-byte writable data object. The documented first twelve
//! pointer-sized words use the Windows 10 2004 layout from Wine's `winternl.h`; the remainder
//! is reserved for loader state that this userspace does not publish.

use core::sync::atomic::{AtomicU64, Ordering};

#[repr(C)]
pub struct SystemDllInitBlock {
    version: AtomicU64,
    rest: [AtomicU64; 29],
}

impl SystemDllInitBlock {
    pub const fn new() -> Self {
        Self {
            version: AtomicU64::new(0xf0),
            rest: [const { AtomicU64::new(0) }; 29],
        }
    }

    fn set(&self, index: usize, value: usize) {
        debug_assert!((1..30).contains(&index));
        self.rest[index - 1].store(value as u64, Ordering::Release);
    }

    fn populate(&self, module: usize, entries: [usize; 5]) {
        for (index, entry) in entries.into_iter().enumerate() {
            self.set(index + 3, entry);
        }
        self.set(9, module);
        self.set(10, self as *const Self as usize);
    }

    #[cfg(test)]
    fn get(&self, index: usize) -> u64 {
        if index == 0 {
            self.version.load(Ordering::Acquire)
        } else {
            self.rest[index - 1].load(Ordering::Acquire)
        }
    }
}

const _: () = assert!(core::mem::size_of::<SystemDllInitBlock>() == 0xf0);

/// Data export, not a function. The object is initialized on DLL process attach.
#[unsafe(no_mangle)]
pub static LdrSystemDllInitBlock: SystemDllInitBlock = SystemDllInitBlock::new();

/// Publish the actual loaded image and implemented bootstrap entry points.
#[cfg(not(test))]
pub fn install(module: usize) {
    let block = &LdrSystemDllInitBlock;
    block.populate(
        module,
        [
            crate::exports::ldr_initialize_thunk as *const () as usize,
            crate::exports::ki_user_exception_dispatcher as *const () as usize,
            crate::exports::ki_user_apc_dispatcher as *const () as usize,
            crate::exports::ki_user_callback_dispatcher as *const () as usize,
            crate::user_thread_start::rtl_user_thread_start as *const () as usize,
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_has_released_size_and_reserved_words() {
        let block = SystemDllInitBlock::new();
        assert_eq!(core::mem::size_of_val(&block), 0xf0);
        assert_eq!(block.get(0), 0xf0);
        for index in 1..30 {
            assert_eq!(block.get(index), 0);
        }
        block.populate(0x1234, [3, 4, 5, 6, 7]);
        for index in 3..=7 {
            assert_eq!(block.get(index), index as u64);
        }
        assert_eq!(block.get(9), 0x1234);
        assert_eq!(block.get(10), &block as *const SystemDllInitBlock as u64);
        for index in [1, 2, 8, 11, 29] {
            assert_eq!(block.get(index), 0);
        }
    }
}
