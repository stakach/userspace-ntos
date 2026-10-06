//! Reproduce native alias admission with reusable storage smaller than one old slot chunk.
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_alias_bank::{
    BankError, ChildCap, ProviderAliasBank, ProviderAliasIo, ProviderAliasRequest,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static LIMIT: Cell<usize> = const { Cell::new(usize::MAX) };
    static REFUSED: Cell<usize> = const { Cell::new(0) };
    static FAIL_NTH: Cell<usize> = const { Cell::new(0) };
}

struct FragmentedAllocator;
#[global_allocator]
static ALLOCATOR: FragmentedAllocator = FragmentedAllocator;

fn admitted(size: usize) -> bool {
    let injected = FAIL_NTH
        .try_with(|remaining| {
            let current = remaining.get();
            if current != 0 {
                remaining.set(current - 1);
            }
            current == 1
        })
        .unwrap_or(false);
    let allowed = LIMIT.try_with(Cell::get).unwrap_or(usize::MAX);
    if injected || size > allowed {
        let _ = REFUSED.try_with(|value| value.set(size));
        false
    } else {
        true
    }
}

unsafe impl GlobalAlloc for FragmentedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if admitted(layout.size()) {
            unsafe { System.alloc(layout) }
        } else {
            std::ptr::null_mut()
        }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if admitted(layout.size()) {
            unsafe { System.alloc_zeroed(layout) }
        } else {
            std::ptr::null_mut()
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if admitted(size) {
            unsafe { System.realloc(pointer, layout, size) }
        } else {
            std::ptr::null_mut()
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn with_limit<T>(limit: usize, action: impl FnOnce() -> T) -> T {
    struct Reset(usize);
    impl Drop for Reset {
        fn drop(&mut self) {
            LIMIT.with(|limit| limit.set(self.0));
        }
    }
    let reset = Reset(LIMIT.with(|value| value.replace(limit)));
    REFUSED.with(|value| value.set(0));
    let result = action();
    drop(reset);
    result
}

fn fail_nth<T>(nth: usize, action: impl FnOnce() -> T) -> T {
    struct Reset(usize);
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_NTH.with(|value| value.set(self.0));
        }
    }
    let reset = Reset(FAIL_NTH.with(|value| value.replace(nth)));
    REFUSED.with(|value| value.set(0));
    let result = action();
    drop(reset);
    result
}

#[derive(Default)]
struct Io {
    copies: u64,
    effects: usize,
}
impl ProviderAliasIo for Io {
    fn copy(&mut self, _: u64) -> (u64, u32) {
        self.copies += 1;
        self.effects += 1;
        (100 + self.copies, 0)
    }
    fn map(&mut self, _: u64, _: u64, _: u64, _: u64) -> Result<(), u32> {
        self.effects += 1;
        Ok(())
    }
    fn ensure_segment(&mut self, segment: usize) -> Result<u64, u32> {
        self.effects += 1;
        Ok(1000 + segment as u64)
    }
    fn move_to_child(&mut self, _: u64, _: ChildCap) -> Result<(), u32> {
        self.effects += 1;
        Ok(())
    }
    fn recycle_empty_root(&mut self, _: u64) -> Result<(), u32> {
        self.effects += 1;
        Ok(())
    }
    fn delete_root(&mut self, _: u64) -> Result<(), u32> {
        self.effects += 1;
        Ok(())
    }
    fn delete_child(&mut self, _: ChildCap) -> Result<(), u32> {
        self.effects += 1;
        Ok(())
    }
}

fn request(index: u64) -> ProviderAliasRequest {
    ProviderAliasRequest {
        pi: 21,
        process: ProcessIdentity {
            pid: 592,
            generation: ProcessGeneration::Hosted(23),
        },
        page: (index + 1) * 4096,
        pml4: 10,
        source_frame: 100_000 + index,
        rights: 2,
    }
}

#[test]
fn alias_growth_fits_the_observed_reusable_span_without_relocating_live_handles() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let original = bank.map(request(0), &mut io).unwrap();
    for index in 1..256 {
        bank.map(request(index), &mut io).unwrap();
    }
    let effects_before = io.effects;
    let result = with_limit(41_848, || bank.map(request(256), &mut io));
    let refused = REFUSED.with(Cell::get);
    assert_eq!(bank.map(request(0), &mut io).unwrap(), original);
    if result == Err(BankError::InsufficientResources) {
        assert_eq!(
            io.effects, effects_before,
            "storage refusal must precede native effects"
        );
    }
    assert!(result.is_ok(), "bounded alias metadata must fit reusable spans; refused request={refused}, result={result:?}");
}

#[test]
fn process_page_index_growth_fits_the_observed_reusable_span() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let original = bank.map(request(0), &mut io).unwrap();
    for index in 1..1024 {
        bank.map(request(index), &mut io).unwrap();
    }
    let effects_before = io.effects;
    let result = with_limit(41_848, || bank.map(request(1024), &mut io));
    let refused = REFUSED.with(Cell::get);
    assert_eq!(bank.map(request(0), &mut io).unwrap(), original);
    if result == Err(BankError::InsufficientResources) {
        assert_eq!(io.effects, effects_before);
    }
    assert!(result.is_ok(), "bounded process index must fit reusable spans; refused request={refused}, result={result:?}");
}

#[test]
fn real_storage_exhaustion_refuses_before_native_effects() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let result = with_limit(0, || bank.map(request(0), &mut io));
    assert_eq!(result, Err(BankError::InsufficientResources));
    assert_eq!(io.effects, 0);
    assert!(bank.is_empty());
}

#[test]
fn all_alias_storage_layers_grow_with_page_bounded_allocations() {
    let mut bank = ProviderAliasBank::new(4096, 10).unwrap();
    let mut io = Io::default();
    let result = with_limit(4096, || {
        for index in 0..36_353 {
            bank.map(request(index), &mut io)?;
        }
        Ok::<(), BankError>(())
    });
    let refused = REFUSED.with(Cell::get);
    assert!(
        result.is_ok(),
        "all metadata layers must be page-bounded; refused={refused}, result={result:?}"
    );
    assert_eq!(bank.stats().live, 36_353);
}

#[test]
fn process_owner_directory_is_also_page_bounded() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let result = with_limit(4096, || {
        for index in 0..300 {
            let mut request = request(index);
            request.pi = index as usize;
            request.process.pid = 1000 + index as u32;
            bank.map(request, &mut io)?;
        }
        Ok::<(), BankError>(())
    });
    let refused = REFUSED.with(Cell::get);
    assert!(
        result.is_ok(),
        "process ownership storage must be page-bounded; refused={refused}, result={result:?}"
    );
    assert_eq!(bank.stats().live, 300);
}

#[test]
fn acknowledged_release_reuses_storage_without_reviving_old_generation() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let original_request = request(0);
    let original = bank.map(original_request, &mut io).unwrap();
    bank.release_process(original_request.pi, original_request.process, &mut io)
        .unwrap();
    assert!(bank.get(original).is_none());
    let mut replacement = original_request;
    replacement.process.generation = ProcessGeneration::Hosted(24);
    let current = with_limit(4096, || bank.map(replacement, &mut io)).unwrap();
    assert_eq!(current.index(), original.index());
    assert_ne!(current.generation(), original.generation());
    assert!(bank.get(original).is_none());
    assert_eq!(bank.get(current).unwrap().request, replacement);
}

#[test]
fn partial_directory_growth_refusal_retains_owners_and_can_retry() {
    let mut bank = ProviderAliasBank::new(4096, 2).unwrap();
    let mut io = Io::default();
    let original = bank.map(request(0), &mut io).unwrap();
    for index in 1..512 {
        let effects = io.effects;
        let entries = bank.entry_count();
        let result = fail_nth(2, || bank.map(request(index), &mut io));
        if result == Err(BankError::InsufficientResources) {
            assert_ne!(REFUSED.with(Cell::get), 0);
            assert_eq!(io.effects, effects);
            assert_eq!(bank.entry_count(), entries);
            assert_eq!(bank.stats().live, index as usize);
            assert_eq!(bank.get(original).unwrap().request, request(0));
            let current = bank.map(request(index), &mut io).unwrap();
            assert_eq!(current.index(), entries);
            let effects = io.effects;
            assert_eq!(
                with_limit(0, || bank.map(request(index), &mut io)),
                Ok(current)
            );
            assert_eq!(io.effects, effects);
            return;
        }
        result.unwrap();
    }
    panic!("fixture must exercise a multi-allocation directory promotion");
}
